# PSCryptoChat Research Summary & Implementation Status

> **Updated:** December 2025 - Reflects v0.1.0 implementation

## Research Completed

This research phase covered four key areas to refine the PSCryptoChat design:

| Document | Focus Area | Implementation Status |
|----------|------------|----------------------|
| [01-ECDH-P256-Implementation.md](./01-ECDH-P256-Implementation.md) | P-256 ECDH in .NET/PowerShell | ✅ **Implemented** |
| [02-Hybrid-Identity-Architecture.md](./02-Hybrid-Identity-Architecture.md) | Pseudonymous + Anonymous modes | ✅ **Implemented** (simplified) |
| [03-Bootstrap-Server-Design.md](./03-Bootstrap-Server-Design.md) | Portable bootstrap servers | 🔮 **Future** |
| [04-P2P-Libraries-NAT-Traversal.md](./04-P2P-Libraries-NAT-Traversal.md) | .NET P2P libraries | ⚠️ **Partial** (UDP only, no STUN) |

---

## Implementation Summary (v0.1.0)

### What's Built

| Component | Status | Notes |
|-----------|--------|-------|
| `CryptoProvider` class | ✅ Complete | P-256 ECDH, AES-256-GCM, HKDF-SHA256 |
| `CryptoIdentity` class | ✅ Complete | Pseudonymous + Anonymous modes |
| `ChatSession` class | ✅ Complete | Session state, encryption, timeout |
| `SessionManager` class | ✅ Complete | Multi-session support |
| `UdpTransport` class | ✅ Complete | Basic UDP send/receive |
| `MessageProtocol` class | ✅ Complete | JSON protocol (handshake, message, ack, disconnect) |
| `ManualDiscovery` class | ✅ Complete | Connection string parsing |
| `PeerDiscovery` class | 🚧 Stub | mDNS placeholder only |
| `IdentityManager` class | ✅ Complete | SecretManagement integration |
| Safety numbers | ✅ Complete | Signal-style 60-digit verification |
| Public cmdlets | ✅ Complete | 10+ exported functions |

### What's NOT Built (Future)

| Component | Status | Notes |
|-----------|--------|-------|
| Bootstrap servers | 🔮 Not started | Research docs still valid |
| STUN/TURN NAT traversal | 🔮 Not started | SIPSorcery integration planned |
| mDNS discovery | 🔮 Placeholder | Class exists but not functional |
| Double Ratchet | 🔮 Not started | Single shared secret per session |
| X3DH key agreement | 🔮 Not started | Simple ECDH used instead |
| Prekey bundles | 🔮 Not started | No SPK/OPK infrastructure |
| Group chat | 🔮 Not started | 1:1 only |

---

## Key Findings vs Implementation

### 1. Cryptography (P-256 ECDH) — ✅ IMPLEMENTED

**Research Finding:** .NET provides excellent native support for P-256 ECDH via `ECDiffieHellmanCng`.

**Implementation:**
- ✅ `ECDiffieHellmanCng` for Windows (primary target)
- ✅ `ExportSubjectPublicKeyInfo()` for X.509 public key format
- ✅ HKDF-SHA256 for key derivation (via `System.Security.Cryptography.HKDF`)
- ✅ AES-256-GCM for authenticated encryption
- ❌ Cross-platform support deferred (Linux/macOS)

**Actual Classes:**
```powershell
[CryptoProvider]::NewKeyPair()           # Generate ECDH key pair
[CryptoProvider]::ExportPublicKey()      # Export to Base64
[CryptoProvider]::DeriveSharedSecret()   # ECDH + HKDF derivation
[CryptoProvider]::EncryptMessage()       # AES-GCM encrypt
[CryptoProvider]::DecryptMessage()       # AES-GCM decrypt
```

### 2. Identity Model — ✅ IMPLEMENTED (Simplified)

**Research Finding:** Signal's X3DH provides strong security; Session-like ephemeral keys for anonymous mode.

**Implementation:**
- ✅ Dual-mode: `Pseudonymous` and `Anonymous` via `[IdentityMode]` enum
- ✅ Simple ECDH exchange (not X3DH)
- ✅ Safety number verification (Signal-style 60-digit format)
- ✅ SecretManagement integration for persistent identities
- ❌ X3DH key agreement (not implemented)
- ❌ Prekey rotation (not implemented)
- ❌ Double Ratchet (not implemented)

**Actual Classes:**
```powershell
[CryptoIdentity]::new([IdentityMode]::Anonymous)
[CryptoIdentity]::new([IdentityMode]::Pseudonymous)
$identity.GetSafetyNumber($peerPublicKey)
$identity.Export() / Import via constructor
[IdentityManager]::SaveIdentity() / LoadIdentity()
```

### 3. Bootstrap Servers — 🔮 NOT IMPLEMENTED

**Research Finding:** Simple HTTP/UDP servers sufficient; BitTorrent DHT patterns inform fallback.

**Implementation:**
- ❌ No bootstrap server code in module
- ❌ No peer discovery beyond manual connection strings
- 📋 Research docs remain valid for future implementation

**Current Discovery:**
```powershell
# Manual only - exchange connection strings out-of-band
Get-ConnectionString -SessionId $session.SessionId
# Returns: "10.0.0.1:9000:MFkwEwYHKoZIzj0..."
```

### 4. P2P Networking — ⚠️ PARTIAL

**Research Finding:** SIPSorcery provides NAT traversal; custom UDP hole punching needed.

**Implementation:**
- ✅ Basic UDP transport (`UdpTransport` class)
- ✅ Send/receive strings and bytes
- ❌ STUN client (not implemented)
- ❌ UDP hole punching (not implemented)
- ❌ TURN relay fallback (not implemented)

**Actual Classes:**
```powershell
$transport = [UdpTransport]::new(9000)
$transport.Start()
$transport.Connect($host, $port)
$transport.SendString($message)
$transport.ReceiveString(5000)
```

---

## Technology Stack (Actual)

| Component | Technology | Status |
|-----------|------------|--------|
| ECDH | `ECDiffieHellmanCng` | ✅ Used |
| AES | `AesGcm` (.NET 5+) | ✅ Used |
| HKDF | `HKDF.DeriveKey()` | ✅ Used |
| UDP | `System.Net.Sockets.UdpClient` | ✅ Used |
| JSON | `ConvertTo-Json` / `ConvertFrom-Json` | ✅ Used |
| Key Storage | `Microsoft.PowerShell.SecretManagement` | ✅ Optional |
| STUN/TURN | SIPSorcery | ❌ Not integrated |
| mDNS | - | ❌ Not implemented |
| Bootstrap | - | ❌ Not implemented |

---

## Current Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Windows-only | Can't run on Linux/macOS | Use Windows or WSL |
| No NAT traversal | Direct IP required | Port forwarding or same LAN |
| Manual discovery | No automatic peer finding | Share connection strings manually |
| No forward secrecy | Single session key | New session = new keys |
| No message persistence | Messages not stored | Real-time only |

---

## Files Structure (Current)

```
PSCryptoChat/
├── src/PSCryptoChat/
│   ├── PSCryptoChat.psd1          # Module manifest
│   ├── PSCryptoChat.psm1          # All classes + module logic
│   └── Public/
│       ├── Identity.ps1           # New-CryptoIdentity, Get-CryptoIdentity
│       ├── Session.ps1            # Start-ChatSession, Stop-ChatSession
│       ├── Messaging.ps1          # Send-ChatMessage, Receive-ChatMessage
│       └── Discovery.ps1          # Get-ConnectionString, Find-ChatPeers
├── tests/
│   └── PSCryptoChat.Tests.ps1     # 85 Pester tests (81 pass, 4 skip)
├── examples/
│   ├── Basic-Chat-Host.ps1
│   ├── Basic-Chat-Peer.ps1
│   ├── Anonymous-Session.ps1
│   └── Verify-SafetyNumbers.ps1
├── docs/
│   ├── Connection-Flow.md         # Mermaid sequence diagrams
│   ├── Azure-Trusted-Signing-Setup.md
│   └── research/                  # This folder
└── Chat.ps1                       # Interactive CLI demo
```

---

## Future Roadmap

### Phase 1: v0.2.0 - NAT Traversal
- [ ] Integrate SIPSorcery for STUN
- [ ] Implement UDP hole punching
- [ ] Add public STUN server list
- [ ] TURN fallback (optional)

### Phase 2: v0.3.0 - Discovery
- [ ] mDNS local peer discovery
- [ ] Bootstrap server (self-hostable)
- [ ] Peer exchange protocol

### Phase 3: v0.4.0 - Enhanced Security
- [ ] Double Ratchet protocol
- [ ] X3DH key agreement
- [ ] Prekey rotation
- [ ] Cross-platform support (Linux/macOS)

### Phase 4: v1.0.0 - Production Ready
- [ ] Group chat support
- [ ] Message persistence (optional)
- [ ] GUI application
- [ ] Mobile considerations

---

## Questions Answered

| Question | Decision |
|----------|----------|
| Anonymous mode priority? | ✅ MVP includes both modes |
| TURN server? | 🔮 Deferred - not in v0.1.0 |
| Key backup? | ✅ Yes via SecretManagement |
| Group chat? | 🔮 1:1 only for now |
| Cross-platform? | 🔮 Windows-only for v0.1.0 |
