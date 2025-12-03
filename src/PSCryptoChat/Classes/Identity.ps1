<#
.SYNOPSIS
    Identity management - pseudonymous and anonymous modes

.DESCRIPTION
    Manages cryptographic identities with SecretManagement integration.
    Supports hybrid mode: persistent pseudonymous identity or ephemeral anonymous.

.NOTES
    Based on research in docs/research/02-Hybrid-Identity-Architecture.md
#>

using namespace System.Security.Cryptography

enum IdentityMode {
    Pseudonymous  # Persistent identity stored in SecretManagement
    Anonymous     # Ephemeral identity, session-only
}

class CryptoIdentity {
    [string]$Id                      # Unique identifier (fingerprint of public key)
    [string]$PublicKey               # Base64 encoded public key
    [IdentityMode]$Mode              # Pseudonymous or Anonymous
    [DateTime]$Created               # Creation timestamp
    [bool]$IsLoaded                  # Whether private key is available

    hidden [ECDiffieHellman]$KeyPair # The actual key pair (hidden from output)

    # Constructor for new identity
    CryptoIdentity([IdentityMode]$Mode) {
        $this.Mode = $Mode
        $this.Created = [DateTime]::UtcNow
        $this.KeyPair = [CryptoProvider]::NewKeyPair()
        $this.PublicKey = [CryptoProvider]::ExportPublicKey($this.KeyPair)
        $this.Id = $this.ComputeFingerprint()
        $this.IsLoaded = $true
    }

    # Constructor from existing key data
    CryptoIdentity([string]$KeyJson, [IdentityMode]$Mode) {
        $this.Mode = $Mode
        $this.KeyPair = [CryptoProvider]::ImportKeyPair($KeyJson)
        $this.PublicKey = [CryptoProvider]::ExportPublicKey($this.KeyPair)
        $this.Id = $this.ComputeFingerprint()
        $this.IsLoaded = $true
        $this.Created = [DateTime]::UtcNow  # Will be overwritten if loading from store
    }

    # Compute fingerprint (SHA-256 of public key, first 16 chars)
    hidden [string]ComputeFingerprint() {
        $pubKeyBytes = [Convert]::FromBase64String($this.PublicKey)
        $hash = [SHA256]::HashData($pubKeyBytes)
        return [Convert]::ToBase64String($hash).Substring(0, 16).Replace('+', '-').Replace('/', '_')
    }

    # Get connection string for peer exchange
    [string]GetConnectionString([string]$Endpoint) {
        # Format: endpoint:publickey
        return "$Endpoint`:$($this.PublicKey)"
    }

    # Parse connection string
    static [hashtable]ParseConnectionString([string]$ConnectionString) {
        $parts = $ConnectionString -split ':', 3
        if ($parts.Count -lt 3) {
            throw "Invalid connection string format. Expected: host:port:publickey"
        }

        return @{
            Host      = $parts[0]
            Port      = [int]$parts[1]
            PublicKey = $parts[2]
        }
    }

    # Derive shared secret with peer
    [byte[]]DeriveSharedSecret([string]$PeerPublicKey) {
        if (-not $this.IsLoaded) {
            throw "Identity not loaded - cannot derive shared secret"
        }
        return [CryptoProvider]::DeriveSharedSecret($this.KeyPair, $PeerPublicKey)
    }

    # Export for storage (pseudonymous mode only)
    [string]Export() {
        if ($this.Mode -eq [IdentityMode]::Anonymous) {
            throw "Cannot export anonymous identity"
        }
        return [CryptoProvider]::ExportKeyPair($this.KeyPair)
    }

    # Securely dispose
    [void]Dispose() {
        if ($null -ne $this.KeyPair) {
            $this.KeyPair.Dispose()
            $this.KeyPair = $null
        }
        $this.IsLoaded = $false
    }

    # Safety number for identity verification (Signal-style)
    [string]GetSafetyNumber([string]$PeerPublicKey) {
        # Combine both public keys (sorted for consistency)
        $keys = @($this.PublicKey, $PeerPublicKey) | Sort-Object
        $combined = $keys[0] + $keys[1]
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)

        # Hash multiple times for safety number
        $hash = $bytes
        for ($i = 0; $i -lt 5200; $i++) {
            $hash = [SHA256]::HashData($hash)
        }

        # Format as 12 groups of 5 digits
        $numbers = @()
        for ($i = 0; $i -lt 12; $i++) {
            $chunk = [BitConverter]::ToUInt32($hash, ($i * 4) % 28) % 100000
            $numbers += $chunk.ToString("D5")
        }

        return $numbers -join " "
    }
}

class IdentityManager {
    static [string]$VaultName = "PSCryptoChat"
    static [string]$SecretPrefix = "PSCryptoChat-Identity-"

    # Check if SecretManagement is available
    static [bool]IsSecretManagementAvailable() {
        try {
            $null = Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement
            return $true
        }
        catch {
            return $false
        }
    }

    # Create new identity
    static [CryptoIdentity]CreateIdentity([IdentityMode]$Mode) {
        return [CryptoIdentity]::new($Mode)
    }

    # Save identity to SecretManagement (pseudonymous only)
    static [void]SaveIdentity([CryptoIdentity]$Identity, [string]$Name) {
        if ($Identity.Mode -eq [IdentityMode]::Anonymous) {
            throw "Cannot save anonymous identity"
        }

        if (-not [IdentityManager]::IsSecretManagementAvailable()) {
            throw "SecretManagement module not available. Install with: Install-Module Microsoft.PowerShell.SecretManagement"
        }

        $secretName = [IdentityManager]::SecretPrefix + $Name
        $secretData = @{
            KeyData = $Identity.Export()
            Created = $Identity.Created.ToString('o')
            Mode    = $Identity.Mode.ToString()
        } | ConvertTo-Json -Compress

        # Store as SecureString
        $secureData = ConvertTo-SecureString -String $secretData -AsPlainText -Force
        Set-Secret -Name $secretName -SecureStringSecret $secureData -Vault ([IdentityManager]::VaultName) -ErrorAction Stop
    }

    # Load identity from SecretManagement
    static [CryptoIdentity]LoadIdentity([string]$Name) {
        if (-not [IdentityManager]::IsSecretManagementAvailable()) {
            throw "SecretManagement module not available"
        }

        $secretName = [IdentityManager]::SecretPrefix + $Name
        $secureData = Get-Secret -Name $secretName -Vault ([IdentityManager]::VaultName) -AsPlainText -ErrorAction Stop

        $data = $secureData | ConvertFrom-Json
        $identity = [CryptoIdentity]::new($data.KeyData, [IdentityMode]::Pseudonymous)
        $identity.Created = [DateTime]::Parse($data.Created)

        return $identity
    }

    # List saved identities
    static [string[]]ListIdentities() {
        if (-not [IdentityManager]::IsSecretManagementAvailable()) {
            return @()
        }

        $secrets = Get-SecretInfo -Vault ([IdentityManager]::VaultName) -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "$([IdentityManager]::SecretPrefix)*" }

        return $secrets | ForEach-Object {
            $_.Name.Replace([IdentityManager]::SecretPrefix, '')
        }
    }

    # Remove identity
    static [void]RemoveIdentity([string]$Name) {
        $secretName = [IdentityManager]::SecretPrefix + $Name
        Remove-Secret -Name $secretName -Vault ([IdentityManager]::VaultName) -ErrorAction Stop
    }
}
