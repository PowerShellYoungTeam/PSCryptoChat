# Hybrid Identity Model Architecture

## Executive Summary

This document outlines a hybrid identity architecture for PSCryptoChat that supports both **pseudonymous** (Signal-like) and **anonymous** (Session-like) modes. The design is based on the Signal X3DH protocol with adaptations for anonymous operation.

---

## 1. Identity Model Comparison

### Signal Protocol (Pseudonymous)
- Long-lived identity key tied to phone number
- Server stores public identity keys and prekeys
- Identity key provides continuity and trust verification
- Vulnerable to metadata collection

### Session Protocol (Anonymous)
- Identity based on Ed25519 public key (Session ID)
- No phone number or account registration
- Onion routing hides IP addresses
- Service nodes store messages, not identify users

### Matrix Protocol (Federated)
- User ID format: `@user:server.domain`
- Cross-signed device keys
- Server federation with identity servers
- Megolm for group encryption

---

## 2. PSCryptoChat Hybrid Model

### Operating Modes

| Mode | Identity | Persistence | Use Case |
|------|----------|-------------|----------|
| **Pseudonymous** | Long-term identity key | Full key hierarchy | Ongoing relationships |
| **Anonymous** | Ephemeral session key | Session-only | Single conversations |
| **Stealth** | One-time keys only | None | Maximum privacy |

### Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                     PSEUDONYMOUS MODE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                               │
│  │ Identity Key │ ─── Long-lived (~years)                       │
│  │    (IK)      │     Ed25519 for signing                       │
│  └──────┬───────┘     ECDH P-256 for key agreement              │
│         │                                                       │
│  ┌──────▼───────┐                                               │
│  │ Signed Pre-  │ ─── Medium-lived (~weekly rotation)           │
│  │  key (SPK)   │     Signed by IK                              │
│  └──────┬───────┘                                               │
│         │                                                       │
│  ┌──────▼───────┐                                               │
│  │ One-Time     │ ─── Single-use (consumed on contact)          │
│  │ Prekeys(OPK) │     Pool of 100 keys                          │
│  └──────┬───────┘                                               │
│         │                                                       │
│  ┌──────▼───────┐                                               │
│  │ Session Keys │ ─── Per-conversation                          │
│  │  (Ratchet)   │     Double Ratchet chains                     │
│  └──────────────┘                                               │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                      ANONYMOUS MODE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                               │
│  │ Session Key  │ ─── Generated per conversation                │
│  │    (SK)      │     No persistent identity                    │
│  └──────┬───────┘                                               │
│         │                                                       │
│  ┌──────▼───────┐                                               │
│  │ Ephemeral    │ ─── Per-message or per-session                │
│  │ Keys (EK)    │                                               │
│  └──────────────┘                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. X3DH Key Agreement (Pseudonymous Mode)

### Key Types

```powershell
# Identity Key Pair - stored persistently
class IdentityKeyPair {
    [byte[]]$PublicKey      # 65 bytes (uncompressed P-256 point)
    [byte[]]$PrivateKey     # 32 bytes
    [DateTime]$Created
    [string]$Fingerprint    # SHA-256 of public key, Base64
}

# Signed Pre-Key - rotated weekly
class SignedPreKey {
    [int]$Id
    [byte[]]$PublicKey
    [byte[]]$PrivateKey
    [byte[]]$Signature      # Ed25519 signature by identity key
    [DateTime]$Created
    [DateTime]$Expires
}

# One-Time Pre-Key - consumed on use
class OneTimePreKey {
    [int]$Id
    [byte[]]$PublicKey
    [byte[]]$PrivateKey
    [bool]$Used
}
```

### X3DH Protocol Flow

```
Alice (Initiator)                          Bob (Responder)
─────────────────                          ────────────────

Has: IK_A                                  Has: IK_B, SPK_B, OPK_B[n]

1. Fetches Bob's prekey bundle:
   - IK_B (identity public key)
   - SPK_B (signed prekey + signature)
   - OPK_B (one-time prekey, optional)

2. Verifies SPK_B signature using IK_B

3. Generates ephemeral key EK_A

4. Computes DH values:
   DH1 = DH(IK_A, SPK_B)    # Identity authentication
   DH2 = DH(EK_A, IK_B)     # Forward secrecy for IK_B
   DH3 = DH(EK_A, SPK_B)    # Forward secrecy for SPK_B
   DH4 = DH(EK_A, OPK_B)    # (Optional) One-time forward secrecy

5. Derives shared secret:
   SK = KDF(DH1 || DH2 || DH3 || DH4)

6. Sends initial message:          ──────────────►
   - IK_A public
   - EK_A public
   - OPK_B id (if used)
   - Encrypted payload (using SK)

                                           7. Bob reconstructs:
                                              DH1 = DH(SPK_B, IK_A)
                                              DH2 = DH(IK_B, EK_A)
                                              DH3 = DH(SPK_B, EK_A)
                                              DH4 = DH(OPK_B, EK_A)
                                              SK = KDF(DH1 || DH2 || DH3 || DH4)

                                           8. Deletes OPK_B (used)
```

### PowerShell Implementation Sketch

```powershell
function New-X3DHKeyBundle {
    param([IdentityKeyPair]$IdentityKey)

    # Generate signed prekey
    $spk = New-ECDHKeyPair
    $spkSignature = Sign-Data -Data $spk.PublicKey -Key $IdentityKey.SigningKey

    # Generate one-time prekeys (pool of 100)
    $otpks = 1..100 | ForEach-Object {
        [OneTimePreKey]@{
            Id = $_
            PublicKey = (New-ECDHKeyPair).PublicKey
            PrivateKey = (New-ECDHKeyPair).PrivateKey
            Used = $false
        }
    }

    return @{
        IdentityKey = $IdentityKey.PublicKey
        SignedPreKey = @{
            Id = 1
            PublicKey = $spk.PublicKey
            Signature = $spkSignature
        }
        OneTimePreKeys = $otpks | Select-Object Id, PublicKey
    }
}

function Start-X3DHSession {
    param(
        [IdentityKeyPair]$MyIdentity,
        [hashtable]$TheirBundle  # Their prekey bundle
    )

    # Verify signed prekey signature
    $valid = Verify-Signature `
        -Data $TheirBundle.SignedPreKey.PublicKey `
        -Signature $TheirBundle.SignedPreKey.Signature `
        -PublicKey $TheirBundle.IdentityKey

    if (-not $valid) {
        throw "Invalid prekey signature"
    }

    # Generate ephemeral key
    $ephemeral = New-ECDHKeyPair

    # Compute DH values
    $dh1 = Get-SharedSecret -MyKey $MyIdentity -TheirKey $TheirBundle.SignedPreKey.PublicKey
    $dh2 = Get-SharedSecret -MyKey $ephemeral -TheirKey $TheirBundle.IdentityKey
    $dh3 = Get-SharedSecret -MyKey $ephemeral -TheirKey $TheirBundle.SignedPreKey.PublicKey

    $dhConcat = $dh1 + $dh2 + $dh3

    # If one-time prekey available
    if ($TheirBundle.OneTimePreKey) {
        $dh4 = Get-SharedSecret -MyKey $ephemeral -TheirKey $TheirBundle.OneTimePreKey.PublicKey
        $dhConcat += $dh4
    }

    # Derive shared secret with HKDF
    $sharedSecret = Invoke-HKDF `
        -InputKeyMaterial $dhConcat `
        -Salt ([byte[]]::new(32)) `
        -Info ([System.Text.Encoding]::UTF8.GetBytes("PSCryptoChat X3DH")) `
        -OutputLength 32

    return @{
        SharedSecret = $sharedSecret
        EphemeralPublicKey = $ephemeral.PublicKey
        UsedOneTimePreKeyId = $TheirBundle.OneTimePreKey?.Id
    }
}
```

---

## 4. Anonymous Mode Design

### Key Principles
1. **No persistent identity** - Keys generated per session
2. **No prekey servers** - Direct peer exchange only
3. **Session binding** - Keys tied to transport session
4. **Plausible deniability** - No cryptographic proof of participation

### Anonymous Session Establishment

```
Alice (Anonymous)                          Bob (Anonymous)
─────────────────                          ────────────────

1. Generate session keypair                1. Generate session keypair
   SK_A = random()                            SK_B = random()

2. Exchange via rendezvous:    ◄─────────►
   - SK_A public
   - SK_B public
   (Could be via bootstrap server, QR code, etc.)

3. Both compute:
   SharedSecret = ECDH(SK_A, SK_B)
   SessionKey = HKDF(SharedSecret, "anon-session")

4. Optional: Upgrade to ratchet
   RatchetKey = HKDF(SharedSecret, "ratchet-init")
```

### PowerShell Implementation

```powershell
class AnonymousSession {
    [byte[]]$MyPublicKey
    [byte[]]$TheirPublicKey
    [byte[]]$SessionKey
    hidden [System.Security.Cryptography.ECDiffieHellmanCng]$KeyPair

    AnonymousSession() {
        $this.KeyPair = [System.Security.Cryptography.ECDiffieHellmanCng]::new(256)
        $this.MyPublicKey = $this.KeyPair.PublicKey.ToByteArray()
    }

    [void]CompleteHandshake([byte[]]$TheirPublicKey) {
        $this.TheirPublicKey = $TheirPublicKey

        $cngKey = [System.Security.Cryptography.CngKey]::Import(
            $TheirPublicKey,
            [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob
        )

        $this.KeyPair.KeyDerivationFunction = [System.Security.Cryptography.ECDiffieHellmanKeyDerivationFunction]::Hash
        $this.KeyPair.HashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha256

        $sharedSecret = $this.KeyPair.DeriveKeyMaterial($cngKey)

        # Additional KDF for session key
        $this.SessionKey = Invoke-HKDF -IKM $sharedSecret -Info "anon-session"
    }

    [void]Destroy() {
        $this.KeyPair.Dispose()
        [Array]::Clear($this.SessionKey, 0, $this.SessionKey.Length)
    }
}
```

---

## 5. Key Rotation Policies

### Pseudonymous Mode

| Key Type | Rotation Period | Trigger |
|----------|-----------------|---------|
| Identity Key | Never (or compromise) | Manual |
| Signed Prekey | 7 days | Timer |
| One-Time Prekeys | On use | Consumption |
| Ratchet Keys | Per message | Protocol |

### Anonymous Mode

| Key Type | Lifetime | Note |
|----------|----------|------|
| Session Key | Until disconnect | Memory only |
| Ephemeral Keys | Per message | If using ratchet |

### Rotation Implementation

```powershell
class KeyRotationManager {
    [hashtable]$Config = @{
        SignedPreKeyRotationDays = 7
        OneTimePreKeyMinPool = 20
        OneTimePreKeyReplenishTo = 100
    }

    [bool]ShouldRotateSignedPreKey([SignedPreKey]$SPK) {
        $age = (Get-Date) - $SPK.Created
        return $age.TotalDays -ge $this.Config.SignedPreKeyRotationDays
    }

    [bool]ShouldReplenishOneTimePreKeys([OneTimePreKey[]]$OTPKs) {
        $unused = @($OTPKs | Where-Object { -not $_.Used }).Count
        return $unused -lt $this.Config.OneTimePreKeyMinPool
    }

    [void]PerformRotation([KeyStore]$Store) {
        # Rotate signed prekey if needed
        if ($this.ShouldRotateSignedPreKey($Store.SignedPreKey)) {
            $newSPK = New-SignedPreKey -IdentityKey $Store.IdentityKey
            $Store.ArchiveSignedPreKey($Store.SignedPreKey)
            $Store.SignedPreKey = $newSPK
        }

        # Replenish one-time prekeys
        if ($this.ShouldReplenishOneTimePreKeys($Store.OneTimePreKeys)) {
            $needed = $this.Config.OneTimePreKeyReplenishTo -
                      @($Store.OneTimePreKeys | Where-Object { -not $_.Used }).Count

            $newOTPKs = 1..$needed | ForEach-Object {
                New-OneTimePreKey -Id (New-Guid).ToString()
            }

            $Store.OneTimePreKeys += $newOTPKs
        }
    }
}
```

---

## 6. Identity Verification

### Pseudonymous Mode - Safety Numbers

Based on Signal's safety number protocol:

```powershell
function Get-SafetyNumber {
    param(
        [byte[]]$MyIdentityKey,
        [string]$MyUserId,
        [byte[]]$TheirIdentityKey,
        [string]$TheirUserId
    )

    # Sort to ensure same result regardless of which side computes
    $pairs = @(
        @{ Id = $MyUserId; Key = $MyIdentityKey },
        @{ Id = $TheirUserId; Key = $TheirIdentityKey }
    ) | Sort-Object { $_.Id }

    # Hash each identity with user ID
    $hash1 = Get-IdentityHash -Key $pairs[0].Key -Id $pairs[0].Id -Iterations 5200
    $hash2 = Get-IdentityHash -Key $pairs[1].Key -Id $pairs[1].Id -Iterations 5200

    # Combine and format as groups of 5 digits
    $combined = $hash1 + $hash2
    $numbers = for ($i = 0; $i -lt 60; $i += 5) {
        $chunk = [BitConverter]::ToUInt32($combined, ($i % $combined.Length) * 4) % 100000
        $chunk.ToString("D5")
    }

    return $numbers -join " "
}

function Get-IdentityHash {
    param(
        [byte[]]$Key,
        [string]$Id,
        [int]$Iterations
    )

    $idBytes = [System.Text.Encoding]::UTF8.GetBytes($Id)
    $data = $Key + $idBytes

    for ($i = 0; $i -lt $Iterations; $i++) {
        $data = [System.Security.Cryptography.SHA512]::HashData($data)
    }

    return $data[0..29]  # First 30 bytes
}
```

### Anonymous Mode - Session Verification

For anonymous sessions, provide session-specific verification:

```powershell
function Get-SessionVerificationCode {
    param(
        [byte[]]$MyPublicKey,
        [byte[]]$TheirPublicKey
    )

    # Sort keys for consistency
    $sorted = @($MyPublicKey, $TheirPublicKey) | Sort-Object { [Convert]::ToBase64String($_) }
    $combined = $sorted[0] + $sorted[1]

    $hash = [System.Security.Cryptography.SHA256]::HashData($combined)

    # Format as emoji or words for easier verbal verification
    $words = @("alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
               "golf", "hotel", "india", "juliet", "kilo", "lima",
               "mike", "november", "oscar", "papa", "quebec", "romeo",
               "sierra", "tango", "uniform", "victor", "whiskey", "xray",
               "yankee", "zulu")

    $verification = for ($i = 0; $i -lt 4; $i++) {
        $words[$hash[$i] % $words.Count]
    }

    return $verification -join "-"  # e.g., "delta-kilo-romeo-tango"
}
```

---

## 7. Storage Architecture

### Pseudonymous Mode - Key Store

```powershell
class SecureKeyStore {
    hidden [string]$StorePath
    hidden [byte[]]$MasterKey

    SecureKeyStore([string]$Path, [SecureString]$Password) {
        $this.StorePath = $Path
        $this.MasterKey = Derive-MasterKey -Password $Password
    }

    [IdentityKeyPair]GetIdentityKey() {
        $encrypted = Get-Content "$($this.StorePath)\identity.key" -Raw
        $decrypted = Decrypt-Data -Data $encrypted -Key $this.MasterKey
        return [IdentityKeyPair]($decrypted | ConvertFrom-Json)
    }

    [void]SaveIdentityKey([IdentityKeyPair]$Key) {
        $json = $Key | ConvertTo-Json
        $encrypted = Encrypt-Data -Data $json -Key $this.MasterKey
        Set-Content "$($this.StorePath)\identity.key" -Value $encrypted
    }

    # ... similar methods for prekeys, sessions, etc.
}
```

### Anonymous Mode - Memory Only

```powershell
class EphemeralKeyStore {
    hidden [hashtable]$Sessions = @{}

    [void]AddSession([string]$SessionId, [AnonymousSession]$Session) {
        $this.Sessions[$SessionId] = $Session
    }

    [AnonymousSession]GetSession([string]$SessionId) {
        return $this.Sessions[$SessionId]
    }

    [void]DestroySession([string]$SessionId) {
        if ($this.Sessions.ContainsKey($SessionId)) {
            $this.Sessions[$SessionId].Destroy()
            $this.Sessions.Remove($SessionId)
        }
    }

    [void]DestroyAll() {
        foreach ($session in $this.Sessions.Values) {
            $session.Destroy()
        }
        $this.Sessions.Clear()
    }
}
```

---

## 8. Mode Selection UX

```powershell
function Show-IdentityModeSelector {
    Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       PSCryptoChat Identity Mode         ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                          ║"
    Write-Host "║  [1] Pseudonymous Mode                   ║"
    Write-Host "║      • Persistent identity               ║" -ForegroundColor DarkGray
    Write-Host "║      • Contact verification              ║" -ForegroundColor DarkGray
    Write-Host "║      • Message history                   ║" -ForegroundColor DarkGray
    Write-Host "║                                          ║"
    Write-Host "║  [2] Anonymous Mode                      ║"
    Write-Host "║      • No persistent identity            ║" -ForegroundColor DarkGray
    Write-Host "║      • Session-only keys                 ║" -ForegroundColor DarkGray
    Write-Host "║      • Maximum privacy                   ║" -ForegroundColor DarkGray
    Write-Host "║                                          ║"
    Write-Host "║  [3] Stealth Mode                        ║"
    Write-Host "║      • One-time conversation             ║" -ForegroundColor DarkGray
    Write-Host "║      • No traces left                    ║" -ForegroundColor DarkGray
    Write-Host "║                                          ║"
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan

    $choice = Read-Host "Select mode"

    switch ($choice) {
        "1" { return [IdentityMode]::Pseudonymous }
        "2" { return [IdentityMode]::Anonymous }
        "3" { return [IdentityMode]::Stealth }
        default { return $null }
    }
}
```

---

## 9. Security Properties Matrix

| Property | Pseudonymous | Anonymous | Stealth |
|----------|-------------|-----------|---------|
| Forward Secrecy | ✅ Full | ✅ Partial | ✅ Full |
| Post-Compromise Security | ✅ Yes | ❌ No | N/A |
| Identity Continuity | ✅ Yes | ❌ No | ❌ No |
| Deniability | ⚠️ Partial | ✅ Full | ✅ Full |
| Metadata Protection | ⚠️ Partial | ✅ Better | ✅ Best |
| Offline Messages | ✅ Yes | ❌ No | ❌ No |
| Multi-Device | ✅ Possible | ❌ No | ❌ No |

---

## 10. Future Considerations

### Post-Quantum Migration Path

Signal's PQXDH adds Kyber-1024 key encapsulation:

```
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)
KEM = Kyber1024.Decapsulate(PQPK_B, CT)  # New!

SK = KDF(DH1 || DH2 || DH3 || DH4 || KEM)
```

### Recommended Migration Strategy
1. Add optional Kyber key in prekey bundle
2. Use hybrid derivation when both sides support
3. Maintain backward compatibility with classic X3DH

---

## 11. References

- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [Session Whitepaper](https://getsession.org/whitepaper)
- [Matrix Olm/Megolm](https://matrix.org/docs/guides/end-to-end-encryption-implementation-guide)
- [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/)
