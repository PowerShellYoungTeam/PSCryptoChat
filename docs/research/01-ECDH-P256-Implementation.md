# P-256 ECDH Implementation in PowerShell/.NET

## Executive Summary

.NET provides native, production-ready support for P-256 ECDH via the `ECDiffieHellmanCng` class on Windows. This document provides complete code examples for key generation, export/import, and shared secret derivation.

---

## 1. Core API Surface

### Classes and Namespaces
```powershell
# Required namespace
using namespace System.Security.Cryptography
```

| Class | Purpose | Platform |
|-------|---------|----------|
| `ECDiffieHellmanCng` | Windows CNG-backed ECDH | Windows |
| `ECDiffieHellman` | Cross-platform base class | .NET Core+ |
| `ECDiffieHellmanPublicKey` | Public key representation | All |
| `ECParameters` | Key parameter structure | All |
| `CngKey` | CNG key handle | Windows |

### Curve Options (via `ECCurve.NamedCurves`)
- `ECCurve.NamedCurves.nistP256` - **Recommended** (256-bit security)
- `ECCurve.NamedCurves.nistP384` - Higher security option
- `ECCurve.NamedCurves.nistP521` - Maximum security option

---

## 2. Key Generation

### Basic Key Generation
```powershell
# Generate a new P-256 ECDH key pair
$ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new()
$ecdh.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
$ecdh.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256

# Key is automatically generated on first use
Write-Host "Key Size: $($ecdh.KeySize) bits"  # 256 for P-256
```

### Explicit Curve Selection
```powershell
# Explicitly create with P-256 curve
$curve = [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256
$ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new($curve)
```

### Alternative: Size-based Construction
```powershell
# Create with key size (256 = P-256, 384 = P-384, 521 = P-521)
$ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new(256)
```

---

## 3. Key Export Formats

### Format Comparison

| Format | Method | Use Case | Interoperable |
|--------|--------|----------|---------------|
| EccPublicBlob | `PublicKey.ToByteArray()` | Windows CNG only | No |
| X.509 SubjectPublicKeyInfo | `ExportSubjectPublicKeyInfo()` | Standard exchange | Yes |
| PEM | `ExportSubjectPublicKeyInfoPem()` | Text-based exchange | Yes |
| ECParameters | `ExportParameters()` | .NET internal | Partial |
| PKCS#8 | `ExportPkcs8PrivateKey()` | Private key backup | Yes |

### Export Public Key (Recommended: SubjectPublicKeyInfo)
```powershell
function Export-ECDHPublicKey {
    param([System.Security.Cryptography.ECDiffieHellmanCng]$ECDH)

    # Standard X.509 SubjectPublicKeyInfo format - interoperable
    $publicKeyBytes = $ECDH.ExportSubjectPublicKeyInfo()
    return $publicKeyBytes
}

# Usage
$ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new(256)
$publicKeyBytes = Export-ECDHPublicKey -ECDH $ecdh
$publicKeyBase64 = [Convert]::ToBase64String($publicKeyBytes)
Write-Host "Public Key (Base64): $publicKeyBase64"
```

### Export Public Key (Windows-only: EccPublicBlob)
```powershell
function Export-ECDHPublicKeyBlob {
    param([System.Security.Cryptography.ECDiffieHellmanCng]$ECDH)

    # Windows CNG format - faster but Windows-only
    return $ECDH.PublicKey.ToByteArray()
}
```

### Export as PEM
```powershell
function Export-ECDHPublicKeyPem {
    param([System.Security.Cryptography.ECDiffieHellmanCng]$ECDH)

    # Human-readable PEM format
    return $ECDH.ExportSubjectPublicKeyInfoPem()
}

# Result:
# -----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
# -----END PUBLIC KEY-----
```

### Export ECParameters (Full Key Details)
```powershell
function Export-ECDHParameters {
    param(
        [System.Security.Cryptography.ECDiffieHellmanCng]$ECDH,
        [bool]$IncludePrivate = $false
    )

    $params = $ECDH.ExportParameters($IncludePrivate)

    return @{
        CurveName = $params.Curve.Oid.FriendlyName  # "nistP256"
        CurveOid = $params.Curve.Oid.Value          # "1.2.840.10045.3.1.7"
        PublicKeyX = $params.Q.X                     # 32 bytes
        PublicKeyY = $params.Q.Y                     # 32 bytes
        PrivateKey = if ($IncludePrivate) { $params.D } else { $null }  # 32 bytes
    }
}
```

---

## 4. Key Import

### Import from SubjectPublicKeyInfo (Recommended)
```powershell
function Import-ECDHPublicKey {
    param([byte[]]$PublicKeyBytes)

    $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new()
    $bytesRead = 0
    $ecdh.ImportSubjectPublicKeyInfo($PublicKeyBytes, [ref]$bytesRead)
    return $ecdh
}
```

### Import from EccPublicBlob (Windows CNG)
```powershell
function Import-ECDHPublicKeyBlob {
    param([byte[]]$BlobBytes)

    $cngKey = [System.Security.Cryptography.CngKey]::Import(
        $BlobBytes,
        [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
    )
    return [System.Security.Cryptography.ECDiffieHellmanCng]::new($cngKey)
}
```

### Import from ECParameters
```powershell
function Import-ECDHFromParameters {
    param(
        [byte[]]$PublicKeyX,
        [byte[]]$PublicKeyY,
        [byte[]]$PrivateKeyD = $null
    )

    $params = [System.Security.Cryptography.ECParameters]::new()
    $params.Curve = [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256
    $params.Q = [System.Security.Cryptography.ECPoint]::new()
    $params.Q.X = $PublicKeyX
    $params.Q.Y = $PublicKeyY

    if ($null -ne $PrivateKeyD) {
        $params.D = $PrivateKeyD
    }

    $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new()
    $ecdh.ImportParameters($params)
    return $ecdh
}
```

---

## 5. Shared Secret Derivation

### Basic Key Agreement
```powershell
function Get-SharedSecret {
    param(
        [System.Security.Cryptography.ECDiffieHellmanCng]$MyPrivateKey,
        [byte[]]$TheirPublicKeyBytes
    )

    # Configure KDF
    $MyPrivateKey.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
    $MyPrivateKey.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256

    # Import their public key
    $theirKey = [System.Security.Cryptography.CngKey]::Import(
        $TheirPublicKeyBytes,
        [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
    )

    # Derive shared secret (32 bytes for SHA-256)
    $sharedSecret = $MyPrivateKey.DeriveKeyMaterial($theirKey)

    return $sharedSecret
}
```

### Advanced: With HMAC KDF
```powershell
function Get-SharedSecretHMAC {
    param(
        [System.Security.Cryptography.ECDiffieHellmanCng]$MyPrivateKey,
        [byte[]]$TheirPublicKeyBytes,
        [byte[]]$HmacKey,
        [byte[]]$Label = $null,
        [byte[]]$Seed = $null
    )

    $MyPrivateKey.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hmac
    $MyPrivateKey.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256
    $MyPrivateKey.HmacKey = $HmacKey

    if ($null -ne $Label) { $MyPrivateKey.Label = $Label }
    if ($null -ne $Seed) { $MyPrivateKey.Seed = $Seed }

    $theirKey = [System.Security.Cryptography.CngKey]::Import(
        $TheirPublicKeyBytes,
        [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
    )

    return $MyPrivateKey.DeriveKeyMaterial($theirKey)
}
```

---

## 6. Complete Alice-Bob Example

```powershell
# ============================================================
# Complete ECDH Key Exchange Example
# ============================================================

# ----- ALICE'S SIDE -----
Write-Host "`n=== Alice generates her key pair ===" -ForegroundColor Cyan

$alice = [System.Security.Cryptography.ECDiffieHellmanCng]::new(256)
$alice.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
$alice.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256

# Alice exports her public key (to send to Bob)
$alicePublicKeyBlob = $alice.PublicKey.ToByteArray()
$alicePublicKeyBase64 = [Convert]::ToBase64String($alicePublicKeyBlob)
Write-Host "Alice's Public Key: $($alicePublicKeyBase64.Substring(0, 40))..."

# ----- BOB'S SIDE -----
Write-Host "`n=== Bob generates his key pair ===" -ForegroundColor Green

$bob = [System.Security.Cryptography.ECDiffieHellmanCng]::new(256)
$bob.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
$bob.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256

# Bob exports his public key (to send to Alice)
$bobPublicKeyBlob = $bob.PublicKey.ToByteArray()
$bobPublicKeyBase64 = [Convert]::ToBase64String($bobPublicKeyBlob)
Write-Host "Bob's Public Key: $($bobPublicKeyBase64.Substring(0, 40))..."

# ----- KEY EXCHANGE -----
Write-Host "`n=== Key Exchange ===" -ForegroundColor Yellow

# Alice imports Bob's public key and derives shared secret
$bobCngKey = [System.Security.Cryptography.CngKey]::Import(
    $bobPublicKeyBlob,
    [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
)
$aliceSharedSecret = $alice.DeriveKeyMaterial($bobCngKey)

# Bob imports Alice's public key and derives shared secret
$aliceCngKey = [System.Security.Cryptography.CngKey]::Import(
    $alicePublicKeyBlob,
    [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
)
$bobSharedSecret = $bob.DeriveKeyMaterial($aliceCngKey)

# ----- VERIFICATION -----
Write-Host "`n=== Verification ===" -ForegroundColor Magenta
Write-Host "Alice's shared secret: $([Convert]::ToBase64String($aliceSharedSecret))"
Write-Host "Bob's shared secret:   $([Convert]::ToBase64String($bobSharedSecret))"

$secretsMatch = [System.Linq.Enumerable]::SequenceEqual(
    [byte[]]$aliceSharedSecret,
    [byte[]]$bobSharedSecret
)
Write-Host "`nSecrets Match: $secretsMatch" -ForegroundColor $(if ($secretsMatch) { 'Green' } else { 'Red' })

# ----- ENCRYPT A MESSAGE -----
Write-Host "`n=== Using Shared Secret for AES Encryption ===" -ForegroundColor Cyan

$message = "Hello, Bob! This is a secret message from Alice."
$messageBytes = [System.Text.Encoding]::UTF8.GetBytes($message)

# Create AES with shared secret as key
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $aliceSharedSecret
$aes.GenerateIV()

# Encrypt
$encryptor = $aes.CreateEncryptor()
$encryptedBytes = $encryptor.TransformFinalBlock($messageBytes, 0, $messageBytes.Length)

Write-Host "Original: $message"
Write-Host "Encrypted (Base64): $([Convert]::ToBase64String($encryptedBytes))"

# Bob decrypts
$aes.Key = $bobSharedSecret  # Same shared secret
$decryptor = $aes.CreateDecryptor()
$decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
$decryptedMessage = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

Write-Host "Decrypted: $decryptedMessage"

# Cleanup
$alice.Dispose()
$bob.Dispose()
$aes.Dispose()
```

---

## 7. Key Serialization for Storage/Transmission

### JSON Serialization
```powershell
function ConvertTo-ECDHJson {
    param(
        [System.Security.Cryptography.ECDiffieHellmanCng]$ECDH,
        [bool]$IncludePrivate = $false
    )

    $params = $ECDH.ExportParameters($IncludePrivate)

    $keyData = @{
        curve = $params.Curve.Oid.FriendlyName
        x = [Convert]::ToBase64String($params.Q.X)
        y = [Convert]::ToBase64String($params.Q.Y)
    }

    if ($IncludePrivate -and $null -ne $params.D) {
        $keyData.d = [Convert]::ToBase64String($params.D)
    }

    return $keyData | ConvertTo-Json -Compress
}

function ConvertFrom-ECDHJson {
    param([string]$JsonString)

    $keyData = $JsonString | ConvertFrom-Json

    $params = [System.Security.Cryptography.ECParameters]::new()
    $params.Curve = [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256
    $params.Q = [System.Security.Cryptography.ECPoint]::new()
    $params.Q.X = [Convert]::FromBase64String($keyData.x)
    $params.Q.Y = [Convert]::FromBase64String($keyData.y)

    if ($keyData.d) {
        $params.D = [Convert]::FromBase64String($keyData.d)
    }

    $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new()
    $ecdh.ImportParameters($params)
    return $ecdh
}
```

---

## 8. Security Considerations

### Key Lifetime
- **Identity Keys**: Long-lived, stored securely
- **Session Keys**: Medium-lived, rotated periodically
- **Ephemeral Keys**: Single-use, discarded after exchange

### Best Practices
1. **Always derive keys through KDF** - Never use raw ECDH output directly
2. **Use SHA-256 or SHA-384** for key derivation hash
3. **Include context in key derivation** - Use Label/Seed parameters
4. **Validate public keys** before use (point-on-curve validation)
5. **Zero memory after use** - Call `Dispose()` and clear byte arrays

### Clearing Sensitive Data
```powershell
function Clear-SensitiveData {
    param([byte[]]$Data)

    if ($null -ne $Data) {
        [Array]::Clear($Data, 0, $Data.Length)
    }
}

# Usage
try {
    $sharedSecret = Get-SharedSecret -MyPrivateKey $ecdh -TheirPublicKeyBytes $theirKey
    # ... use the secret ...
}
finally {
    Clear-SensitiveData -Data $sharedSecret
    $ecdh.Dispose()
}
```

---

## 9. Cross-Platform Considerations

| Feature | Windows (CNG) | Linux/macOS (OpenSSL) |
|---------|---------------|----------------------|
| Class | `ECDiffieHellmanCng` | `ECDiffieHellmanOpenSsl` |
| Recommended | `ECDiffieHellman.Create()` | `ECDiffieHellman.Create()` |
| Key Storage | Windows Key Store | File-based |
| Performance | Excellent | Good |

### Cross-Platform Factory Method
```powershell
# Use this for cross-platform code
$ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create(
    [System.Security.Cryptography.ECCurve]::NamedCurves.nistP256
)
```

---

## 10. References

- [ECDiffieHellmanCng Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellmancng)
- [ECParameters Structure](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecparameters)
- [ECCurve.NamedCurves](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.eccurve.namedcurves)
- [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) - Pair-Wise Key Establishment
