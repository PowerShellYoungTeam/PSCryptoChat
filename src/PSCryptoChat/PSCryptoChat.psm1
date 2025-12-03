#Requires -Version 7.0
#Requires -PSEdition Core

<#
.SYNOPSIS
    PSCryptoChat - Encrypted, decentralized, optionally anonymous messaging

.DESCRIPTION
    A PowerShell module for secure peer-to-peer messaging using:
    - P-256 ECDH key exchange
    - AES-GCM authenticated encryption
    - SecretManagement for identity storage
    - UDP P2P with STUN hole punching
    - Optional mDNS LAN discovery

.NOTES
    This is exploratory code - expect breaking changes.
#>

using namespace System.Security.Cryptography

#region Classes - Must be in .psm1 for type export

# ==============================================================================
# CryptoProvider - Core cryptographic operations
# ==============================================================================
class CryptoProvider {
    # Constants
    static [int]$KeySize = 256
    static [int]$NonceSize = 12
    static [int]$TagSize = 16
    static [string]$HkdfInfo = "PSCryptoChat-v1"

    #region Key Generation

    static [ECDiffieHellman]NewKeyPair() {
        # Use Windows CNG directly - ECDiffieHellman::Create() returns null on .NET 9/Windows
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            return [ECDiffieHellmanCng]::new(256)
        }
        else {
            # Try generic approach for Linux/macOS
            $ecdh = [ECDiffieHellman]::Create([ECCurve]::NamedCurves.nistP256)
            if ($null -eq $ecdh) {
                throw "Failed to create ECDiffieHellman key pair on this platform"
            }
            return $ecdh
        }
    }

    static [string]ExportPublicKey([ECDiffieHellman]$KeyPair) {
        $bytes = $KeyPair.ExportSubjectPublicKeyInfo()
        return [Convert]::ToBase64String($bytes)
    }

    static [ECDiffieHellman]ImportPublicKey([string]$Base64PublicKey) {
        $bytes = [Convert]::FromBase64String($Base64PublicKey)

        # Create new key pair and import the public key
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            $ecdh = [ECDiffieHellmanCng]::new(256)
        }
        else {
            $ecdh = [ECDiffieHellman]::Create([ECCurve]::NamedCurves.nistP256)
        }

        $bytesRead = 0
        $ecdh.ImportSubjectPublicKeyInfo($bytes, [ref]$bytesRead)
        return $ecdh
    }

    static [string]ExportKeyPair([ECDiffieHellman]$KeyPair) {
        $params = $KeyPair.ExportParameters($true)
        $data = @{
            Curve = $params.Curve.Oid.FriendlyName
            X     = [Convert]::ToBase64String($params.Q.X)
            Y     = [Convert]::ToBase64String($params.Q.Y)
            D     = [Convert]::ToBase64String($params.D)
        }
        return ($data | ConvertTo-Json -Compress)
    }

    static [ECDiffieHellman]ImportKeyPair([string]$Json) {
        $data = $Json | ConvertFrom-Json

        $params = [ECParameters]::new()
        $params.Curve = [ECCurve]::NamedCurves.nistP256
        $params.Q = [ECPoint]::new()
        $params.Q.X = [Convert]::FromBase64String($data.X)
        $params.Q.Y = [Convert]::FromBase64String($data.Y)
        $params.D = [Convert]::FromBase64String($data.D)

        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            $ecdh = [ECDiffieHellmanCng]::new(256)
        }
        else {
            $ecdh = [ECDiffieHellman]::Create()
        }
        $ecdh.ImportParameters($params)
        return $ecdh
    }

    #endregion

    #region Key Exchange

    static [byte[]]DeriveSharedSecret([ECDiffieHellman]$MyKeyPair, [string]$TheirPublicKeyBase64) {
        $theirKey = [CryptoProvider]::ImportPublicKey($TheirPublicKeyBase64)
        $rawSecret = $null
        try {
            $rawSecret = $MyKeyPair.DeriveKeyMaterial($theirKey.PublicKey)
            $derivedKey = [CryptoProvider]::HkdfDerive($rawSecret, 32)
            return $derivedKey
        }
        finally {
            if ($null -ne $rawSecret) {
                [Array]::Clear($rawSecret, 0, $rawSecret.Length)
            }
            $theirKey.Dispose()
        }
    }

    static [byte[]]HkdfDerive([byte[]]$InputKeyMaterial, [int]$OutputLength) {
        return [CryptoProvider]::HkdfDerive($InputKeyMaterial, $OutputLength, $null, $null)
    }

    static [byte[]]HkdfDerive([byte[]]$InputKeyMaterial, [int]$OutputLength, [byte[]]$Salt, [byte[]]$Info) {
        if ($null -eq $Salt) {
            $Salt = [byte[]]::new(32)
        }
        if ($null -eq $Info) {
            $Info = [System.Text.Encoding]::UTF8.GetBytes([CryptoProvider]::HkdfInfo)
        }

        return [HKDF]::DeriveKey(
            [HashAlgorithmName]::SHA256,
            $InputKeyMaterial,
            $OutputLength,
            $Salt,
            $Info
        )
    }

    #endregion

    #region Encryption

    static [byte[]]Encrypt([byte[]]$Plaintext, [byte[]]$Key) {
        $nonce = [byte[]]::new([CryptoProvider]::NonceSize)
        [RandomNumberGenerator]::Fill($nonce)

        $ciphertext = [byte[]]::new($Plaintext.Length)
        $tag = [byte[]]::new([CryptoProvider]::TagSize)

        $aesGcm = [AesGcm]::new($Key, [CryptoProvider]::TagSize)
        try {
            $aesGcm.Encrypt($nonce, $Plaintext, $ciphertext, $tag)

            $result = [byte[]]::new($nonce.Length + $tag.Length + $ciphertext.Length)
            [Array]::Copy($nonce, 0, $result, 0, $nonce.Length)
            [Array]::Copy($tag, 0, $result, $nonce.Length, $tag.Length)
            [Array]::Copy($ciphertext, 0, $result, $nonce.Length + $tag.Length, $ciphertext.Length)

            return $result
        }
        finally {
            $aesGcm.Dispose()
            [Array]::Clear($nonce, 0, $nonce.Length)
        }
    }

    static [byte[]]Decrypt([byte[]]$EncryptedData, [byte[]]$Key) {
        $nonceSz = 12
        $tagSz = 16

        $nonce = $EncryptedData[0..($nonceSz - 1)]
        $tag = $EncryptedData[$nonceSz..($nonceSz + $tagSz - 1)]
        $ciphertext = $EncryptedData[($nonceSz + $tagSz)..($EncryptedData.Length - 1)]

        $plaintext = [byte[]]::new($ciphertext.Length)

        $aesGcm = [AesGcm]::new($Key, $tagSz)
        try {
            $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plaintext)
            return $plaintext
        }
        finally {
            $aesGcm.Dispose()
        }
    }

    static [string]EncryptMessage([string]$Message, [byte[]]$Key) {
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        try {
            $encrypted = [CryptoProvider]::Encrypt($plainBytes, $Key)
            return [Convert]::ToBase64String($encrypted)
        }
        finally {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
    }

    static [string]DecryptMessage([string]$EncryptedBase64, [byte[]]$Key) {
        $encrypted = [Convert]::FromBase64String($EncryptedBase64)
        $decrypted = [CryptoProvider]::Decrypt($encrypted, $Key)
        try {
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        }
        finally {
            [Array]::Clear($decrypted, 0, $decrypted.Length)
        }
    }

    #endregion

    #region Secure Memory

    static [void]ClearBytes([byte[]]$Data) {
        if ($null -ne $Data -and $Data.Length -gt 0) {
            [Array]::Clear($Data, 0, $Data.Length)
        }
    }

    static [byte[]]GetRandomBytes([int]$Length) {
        $bytes = [byte[]]::new($Length)
        [RandomNumberGenerator]::Fill($bytes)
        return $bytes
    }

    #endregion
}

# ==============================================================================
# Identity - Pseudonymous and anonymous identity management
# ==============================================================================
enum IdentityMode {
    Pseudonymous
    Anonymous
}

class CryptoIdentity {
    [string]$Id
    [string]$PublicKey
    [IdentityMode]$Mode
    [DateTime]$Created
    [bool]$IsLoaded

    hidden [ECDiffieHellman]$KeyPair

    CryptoIdentity([IdentityMode]$Mode) {
        $this.Mode = $Mode
        $this.Created = [DateTime]::UtcNow
        $this.KeyPair = [CryptoProvider]::NewKeyPair()
        $this.PublicKey = [CryptoProvider]::ExportPublicKey($this.KeyPair)
        $this.Id = $this.ComputeFingerprint()
        $this.IsLoaded = $true
    }

    CryptoIdentity([string]$KeyJson, [IdentityMode]$Mode) {
        $this.Mode = $Mode
        $this.KeyPair = [CryptoProvider]::ImportKeyPair($KeyJson)
        $this.PublicKey = [CryptoProvider]::ExportPublicKey($this.KeyPair)
        $this.Id = $this.ComputeFingerprint()
        $this.IsLoaded = $true
        $this.Created = [DateTime]::UtcNow
    }

    hidden [string]ComputeFingerprint() {
        $pubKeyBytes = [Convert]::FromBase64String($this.PublicKey)
        $hash = [SHA256]::HashData($pubKeyBytes)
        return [Convert]::ToBase64String($hash).Substring(0, 16).Replace('+', '-').Replace('/', '_')
    }

    [string]GetConnectionString([string]$Endpoint) {
        return "$Endpoint`:$($this.PublicKey)"
    }

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

    [byte[]]DeriveSharedSecret([string]$PeerPublicKey) {
        if (-not $this.IsLoaded) {
            throw "Identity not loaded - cannot derive shared secret"
        }
        return [CryptoProvider]::DeriveSharedSecret($this.KeyPair, $PeerPublicKey)
    }

    [string]Export() {
        if ($this.Mode -eq [IdentityMode]::Anonymous) {
            throw "Cannot export anonymous identity"
        }
        return [CryptoProvider]::ExportKeyPair($this.KeyPair)
    }

    [void]Dispose() {
        if ($null -ne $this.KeyPair) {
            $this.KeyPair.Dispose()
            $this.KeyPair = $null
        }
        $this.IsLoaded = $false
    }

    [string]GetSafetyNumber([string]$PeerPublicKey) {
        $keys = @($this.PublicKey, $PeerPublicKey) | Sort-Object
        $combined = $keys[0] + $keys[1]
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)

        $hash = $bytes
        for ($i = 0; $i -lt 5200; $i++) {
            $hash = [SHA256]::HashData($hash)
        }

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

    static [bool]IsSecretManagementAvailable() {
        try {
            $null = Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement
            return $true
        }
        catch {
            return $false
        }
    }

    static [CryptoIdentity]CreateIdentity([IdentityMode]$Mode) {
        return [CryptoIdentity]::new($Mode)
    }

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

        # PSScriptAnalyzer suppression: This is intentional - we're storing identity data
        # in SecretManagement vault which requires SecureString input. The data is already
        # sensitive (private key) and the vault provides secure storage.
        # [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
        $secureData = ConvertTo-SecureString -String $secretData -AsPlainText -Force
        Set-Secret -Name $secretName -SecureStringSecret $secureData -Vault ([IdentityManager]::VaultName) -ErrorAction Stop
    }

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

    static [void]RemoveIdentity([string]$Name) {
        $secretName = [IdentityManager]::SecretPrefix + $Name
        Remove-Secret -Name $secretName -Vault ([IdentityManager]::VaultName) -ErrorAction Stop
    }
}

# ==============================================================================
# Session Management
# ==============================================================================
enum SessionState {
    Created
    Handshaking
    Established
    Closing
    Closed
}

class ChatSession {
    [string]$SessionId
    [SessionState]$State
    [CryptoIdentity]$LocalIdentity
    [string]$PeerPublicKey
    [DateTime]$Created
    [DateTime]$LastActivity
    [int]$TimeoutSeconds

    hidden [byte[]]$SharedSecret
    hidden [System.Timers.Timer]$TimeoutTimer

    ChatSession([CryptoIdentity]$Identity, [int]$TimeoutSeconds) {
        $this.SessionId = [Guid]::NewGuid().ToString("N").Substring(0, 16)
        $this.LocalIdentity = $Identity
        $this.TimeoutSeconds = $TimeoutSeconds
        $this.State = [SessionState]::Created
        $this.Created = [DateTime]::UtcNow
        $this.LastActivity = $this.Created
    }

    [void]CompleteHandshake([string]$PeerPublicKey) {
        $this.PeerPublicKey = $PeerPublicKey
        $this.SharedSecret = $this.LocalIdentity.DeriveSharedSecret($PeerPublicKey)
        $this.State = [SessionState]::Established
        $this.UpdateActivity()
        $this.StartTimeoutTimer()
    }

    [void]UpdateActivity() {
        $this.LastActivity = [DateTime]::UtcNow
        if ($null -ne $this.TimeoutTimer) {
            $this.TimeoutTimer.Stop()
            $this.TimeoutTimer.Start()
        }
    }

    hidden [void]StartTimeoutTimer() {
        if ($this.TimeoutSeconds -le 0) { return }

        $this.TimeoutTimer = [System.Timers.Timer]::new($this.TimeoutSeconds * 1000)
        $this.TimeoutTimer.AutoReset = $false

        # Store session ID for closure
        $sid = $this.SessionId
        $this.TimeoutTimer.add_Elapsed({
                Write-Warning "Session $sid timed out"
                [SessionManager]::CloseSession($sid)
            })
        $this.TimeoutTimer.Start()
    }

    [string]Encrypt([string]$Message) {
        if ($this.State -ne [SessionState]::Established) {
            throw "Session not established"
        }
        $this.UpdateActivity()
        return [CryptoProvider]::EncryptMessage($Message, $this.SharedSecret)
    }

    [string]Decrypt([string]$EncryptedMessage) {
        if ($this.State -ne [SessionState]::Established) {
            throw "Session not established"
        }
        $this.UpdateActivity()
        return [CryptoProvider]::DecryptMessage($EncryptedMessage, $this.SharedSecret)
    }

    [hashtable]GetInfo() {
        return @{
            SessionId    = $this.SessionId
            State        = $this.State.ToString()
            Created      = $this.Created
            LastActivity = $this.LastActivity
            Timeout      = $this.TimeoutSeconds
            PeerKey      = if ($this.PeerPublicKey) { $this.PeerPublicKey.Substring(0, 20) + "..." } else { $null }
        }
    }

    [void]Close() {
        $this.State = [SessionState]::Closing

        if ($null -ne $this.TimeoutTimer) {
            $this.TimeoutTimer.Stop()
            $this.TimeoutTimer.Dispose()
            $this.TimeoutTimer = $null
        }

        if ($null -ne $this.SharedSecret) {
            [CryptoProvider]::ClearBytes($this.SharedSecret)
            $this.SharedSecret = $null
        }

        $this.State = [SessionState]::Closed
    }
}

class SessionManager {
    static [hashtable]$Sessions = @{}

    static [ChatSession]CreateSession([CryptoIdentity]$Identity, [int]$TimeoutSeconds) {
        $session = [ChatSession]::new($Identity, $TimeoutSeconds)
        [SessionManager]::Sessions[$session.SessionId] = $session
        return $session
    }

    static [ChatSession]GetSession([string]$SessionId) {
        return [SessionManager]::Sessions[$SessionId]
    }

    static [void]CloseSession([string]$SessionId) {
        $session = [SessionManager]::Sessions[$SessionId]
        if ($null -ne $session) {
            $session.Close()
            [SessionManager]::Sessions.Remove($SessionId)
        }
    }

    static [void]CloseAllSessions() {
        foreach ($sid in @([SessionManager]::Sessions.Keys)) {
            [SessionManager]::CloseSession($sid)
        }
    }
}

# ==============================================================================
# Transport Layer - UDP Communication
# ==============================================================================
class UdpTransport {
    [int]$LocalPort
    [string]$RemoteHost
    [int]$RemotePort
    [bool]$IsListening

    hidden [System.Net.Sockets.UdpClient]$Client
    hidden [System.Threading.CancellationTokenSource]$CancelToken

    UdpTransport([int]$Port) {
        $this.LocalPort = $Port
        $this.IsListening = $false
    }

    [void]Start() {
        if ($this.LocalPort -eq 0) {
            $this.Client = [System.Net.Sockets.UdpClient]::new()
            $this.Client.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0))
            $this.LocalPort = ([System.Net.IPEndPoint]$this.Client.Client.LocalEndPoint).Port
        }
        else {
            $this.Client = [System.Net.Sockets.UdpClient]::new($this.LocalPort)
        }

        $this.CancelToken = [System.Threading.CancellationTokenSource]::new()
        $this.IsListening = $true
    }

    [void]Connect([string]$Host, [int]$Port) {
        $this.RemoteHost = $Host
        $this.RemotePort = $Port
        $this.Client.Connect($Host, $Port)
    }

    [void]SendBytes([byte[]]$Data) {
        if ($null -eq $this.Client) {
            throw "Transport not started"
        }

        if ($this.RemoteHost) {
            $null = $this.Client.Send($Data, $Data.Length)
        }
        else {
            throw "Not connected to remote host"
        }
    }

    [void]SendString([string]$Message) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        $this.SendBytes($bytes)
    }

    [byte[]]ReceiveBytes([int]$TimeoutMs) {
        if ($null -eq $this.Client) {
            throw "Transport not started"
        }

        $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $this.Client.Client.ReceiveTimeout = $TimeoutMs

        try {
            return $this.Client.Receive([ref]$endpoint)
        }
        catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                return $null
            }
            throw
        }
    }

    [string]ReceiveString([int]$TimeoutMs) {
        $bytes = $this.ReceiveBytes($TimeoutMs)
        if ($null -eq $bytes) { return $null }
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }

    [string]GetLocalEndpointString() {
        if ($null -eq $this.Client) {
            return "0.0.0.0:0"
        }

        # Get local IP (not 0.0.0.0)
        $localIp = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
        Select-Object -First 1

        if ($null -eq $localIp) {
            $localIp = [System.Net.IPAddress]::Loopback
        }

        return "$($localIp.ToString()):$($this.LocalPort)"
    }

    [void]Stop() {
        $this.IsListening = $false

        if ($null -ne $this.CancelToken) {
            $this.CancelToken.Cancel()
            $this.CancelToken.Dispose()
            $this.CancelToken = $null
        }

        if ($null -ne $this.Client) {
            $this.Client.Close()
            $this.Client.Dispose()
            $this.Client = $null
        }
    }
}

# ==============================================================================
# Message Protocol
# ==============================================================================
class MessageProtocol {
    static [string]$Version = "1.0"

    static [string]CreateHandshake([string]$PublicKey, [string]$SessionId) {
        $msg = @{
            type      = "handshake"
            version   = [MessageProtocol]::Version
            publicKey = $PublicKey
            sessionId = $SessionId
            timestamp = [DateTime]::UtcNow.ToString('o')
        }
        return ($msg | ConvertTo-Json -Compress)
    }

    static [string]CreateMessage([string]$EncryptedContent) {
        $msg = @{
            type      = "message"
            version   = [MessageProtocol]::Version
            content   = $EncryptedContent
            timestamp = [DateTime]::UtcNow.ToString('o')
        }
        return ($msg | ConvertTo-Json -Compress)
    }

    static [string]CreateAck([string]$MessageId) {
        $msg = @{
            type      = "ack"
            version   = [MessageProtocol]::Version
            messageId = $MessageId
            timestamp = [DateTime]::UtcNow.ToString('o')
        }
        return ($msg | ConvertTo-Json -Compress)
    }

    static [string]CreateDisconnect([string]$Reason) {
        $msg = @{
            type      = "disconnect"
            version   = [MessageProtocol]::Version
            reason    = $Reason
            timestamp = [DateTime]::UtcNow.ToString('o')
        }
        return ($msg | ConvertTo-Json -Compress)
    }

    static [hashtable]Parse([string]$Message) {
        try {
            return ($Message | ConvertFrom-Json -AsHashtable)
        }
        catch {
            return @{ type = "unknown"; raw = $Message }
        }
    }
}

# ==============================================================================
# Manual Discovery (Connection Strings)
# ==============================================================================
class ManualDiscovery {
    static [hashtable]ParseConnectionString([string]$ConnectionString) {
        # Format: host:port:base64publickey
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

    static [string]CreateConnectionString([string]$Host, [int]$Port, [string]$PublicKey) {
        return "${Host}:${Port}:${PublicKey}"
    }
}

# ==============================================================================
# mDNS Discovery (Placeholder - full implementation pending)
# ==============================================================================
class PeerDiscovery {
    [bool]$IsRunning
    hidden [bool]$UseMdns
    hidden [System.Collections.ArrayList]$DiscoveredPeers

    PeerDiscovery([bool]$UseMdns) {
        $this.UseMdns = $UseMdns
        $this.DiscoveredPeers = [System.Collections.ArrayList]::new()
        $this.IsRunning = $false
    }

    [void]Start() {
        $this.IsRunning = $true
        # mDNS implementation would go here
    }

    [void]Stop() {
        $this.IsRunning = $false
    }

    [void]Announce([string]$SessionId, [int]$Port, [string]$PublicKey) {
        # mDNS announce implementation
        Write-Verbose "Announcing session $SessionId on port $Port"
    }

    [System.Collections.ArrayList]FindPeers([int]$TimeoutMs) {
        # mDNS browse implementation would go here
        # For now, return empty list
        return $this.DiscoveredPeers
    }
}

#endregion

# Module-level variables
$script:ModuleRoot = $PSScriptRoot
$script:ActiveSessions = @{}
$script:CurrentIdentity = $null

# Import public functions (classes are already defined above)
. "$PSScriptRoot\Public\Identity.ps1"
. "$PSScriptRoot\Public\Session.ps1"
. "$PSScriptRoot\Public\Messaging.ps1"
. "$PSScriptRoot\Public\Discovery.ps1"

# Module initialization
Write-Verbose "PSCryptoChat module loaded from $PSScriptRoot"
