<#
.SYNOPSIS
    Core cryptographic operations using .NET cryptography

.DESCRIPTION
    Provides ECDH P-256 key exchange, AES-GCM encryption, and HKDF key derivation.
    Uses SecureString where possible with rapid clearing.

.NOTES
    Based on research in docs/research/01-ECDH-P256-Implementation.md
#>

using namespace System.Security.Cryptography

class CryptoProvider {
    # Constants
    static [int]$KeySize = 256
    static [int]$NonceSize = 12
    static [int]$TagSize = 16
    static [string]$HkdfInfo = "PSCryptoChat-v1"

    #region Key Generation

    <#
    .SYNOPSIS
        Generate a new ECDH P-256 key pair
    #>
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

    <#
    .SYNOPSIS
        Export public key as Base64 (SubjectPublicKeyInfo format)
    #>
    static [string]ExportPublicKey([ECDiffieHellman]$KeyPair) {
        $bytes = $KeyPair.ExportSubjectPublicKeyInfo()
        return [Convert]::ToBase64String($bytes)
    }

    <#
    .SYNOPSIS
        Import public key from Base64
    #>
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

    <#
    .SYNOPSIS
        Export full key pair as JSON (for secure storage)
    #>
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

    <#
    .SYNOPSIS
        Import full key pair from JSON
    #>
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

    <#
    .SYNOPSIS
        Derive shared secret from ECDH key exchange
    #>
    static [byte[]]DeriveSharedSecret([ECDiffieHellman]$MyKeyPair, [string]$TheirPublicKeyBase64) {
        $theirKey = [CryptoProvider]::ImportPublicKey($TheirPublicKeyBase64)
        try {
            $rawSecret = $MyKeyPair.DeriveKeyMaterial($theirKey.PublicKey)

            # Use HKDF to derive final key
            $derivedKey = [CryptoProvider]::HkdfDerive($rawSecret, 32)

            return $derivedKey
        }
        finally {
            # Clear raw secret
            if ($null -ne $rawSecret) {
                [Array]::Clear($rawSecret, 0, $rawSecret.Length)
            }
            $theirKey.Dispose()
        }
    }

    <#
    .SYNOPSIS
        HKDF key derivation (RFC 5869)
    #>
    static [byte[]]HkdfDerive([byte[]]$InputKeyMaterial, [int]$OutputLength) {
        return [CryptoProvider]::HkdfDerive($InputKeyMaterial, $OutputLength, $null, $null)
    }

    static [byte[]]HkdfDerive([byte[]]$InputKeyMaterial, [int]$OutputLength, [byte[]]$Salt, [byte[]]$Info) {
        if ($null -eq $Salt) {
            $Salt = [byte[]]::new(32)  # Zero salt
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

    <#
    .SYNOPSIS
        Encrypt data using AES-GCM
    #>
    static [byte[]]Encrypt([byte[]]$Plaintext, [byte[]]$Key) {
        # Generate random nonce
        $nonce = [byte[]]::new([CryptoProvider]::NonceSize)
        [RandomNumberGenerator]::Fill($nonce)

        $ciphertext = [byte[]]::new($Plaintext.Length)
        $tag = [byte[]]::new([CryptoProvider]::TagSize)

        $aesGcm = [AesGcm]::new($Key, [CryptoProvider]::TagSize)
        try {
            $aesGcm.Encrypt($nonce, $Plaintext, $ciphertext, $tag)

            # Return: nonce + tag + ciphertext
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

    <#
    .SYNOPSIS
        Decrypt data using AES-GCM
    #>
    static [byte[]]Decrypt([byte[]]$EncryptedData, [byte[]]$Key) {
        $nonceSz = 12  # [CryptoProvider]::NonceSize
        $tagSz = 16    # [CryptoProvider]::TagSize

        # Extract nonce, tag, and ciphertext
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

    <#
    .SYNOPSIS
        Encrypt string message, return Base64
    #>
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

    <#
    .SYNOPSIS
        Decrypt Base64 message to string
    #>
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

    <#
    .SYNOPSIS
        Securely clear a byte array
    #>
    static [void]ClearBytes([byte[]]$Data) {
        if ($null -ne $Data -and $Data.Length -gt 0) {
            [Array]::Clear($Data, 0, $Data.Length)
        }
    }

    <#
    .SYNOPSIS
        Generate cryptographically secure random bytes
    #>
    static [byte[]]GetRandomBytes([int]$Length) {
        $bytes = [byte[]]::new($Length)
        [RandomNumberGenerator]::Fill($bytes)
        return $bytes
    }

    #endregion
}
