# PSCryptoChat Research Summary & Recommendations

## Research Completed

This research phase covered four key areas to refine the PSCryptoChat design:

| Document | Focus Area | Status |
|----------|------------|--------|
| [01-ECDH-P256-Implementation.md](./01-ECDH-P256-Implementation.md) | P-256 ECDH in .NET/PowerShell | ✅ Complete |
| [02-Hybrid-Identity-Architecture.md](./02-Hybrid-Identity-Architecture.md) | Pseudonymous + Anonymous modes | ✅ Complete |
| [03-Bootstrap-Server-Design.md](./03-Bootstrap-Server-Design.md) | Portable bootstrap servers | ✅ Complete |
| [04-P2P-Libraries-NAT-Traversal.md](./04-P2P-Libraries-NAT-Traversal.md) | .NET P2P libraries | ✅ Complete |

---

## Key Findings

### 1. Cryptography (P-256 ECDH)

**Finding:** .NET provides excellent native support for P-256 ECDH via `ECDiffieHellmanCng`.

**Recommendations:**
- ✅ Use `ECDiffieHellmanCng` for Windows, `ECDiffieHellman.Create()` for cross-platform
- ✅ Use `ExportSubjectPublicKeyInfo()` for interoperable key exchange (X.509 format)
- ✅ Use SHA-256 KDF for key derivation
- ⚠️ Plan for post-quantum migration (Kyber-1024 hybrid) in architecture

**Code Ready:**
- Complete PowerShell wrappers for key generation, export, import
- Alice-Bob key exchange example
- AES encryption integration

### 2. Identity Model

**Finding:** Signal's X3DH provides strong security for pseudonymous mode; Session-like ephemeral keys work for anonymous mode.

**Recommendations:**
- ✅ Implement dual-mode architecture: Pseudonymous + Anonymous
- ✅ Use X3DH key agreement for initial contact (pseudonymous)
- ✅ Simple ECDH exchange for anonymous sessions
- ✅ Implement key rotation: SPK weekly, OPK on consumption
- ⚠️ Consider "Stealth Mode" for maximum anonymity

**Architecture Ready:**
- Key hierarchy design (Identity → Signed Prekey → One-Time Prekey → Session)
- Safety number verification algorithm
- Key storage patterns (persistent vs. memory-only)

### 3. Bootstrap Servers

**Finding:** Simple HTTP/UDP servers are sufficient; BitTorrent DHT patterns inform fallback design.

**Recommendations:**
- ✅ Start with PowerShell HTTP server (single file, portable)
- ✅ Docker container for cloud deployment
- ✅ Implement fallback chain: Bootstrap → Hardcoded Seeds → Local mDNS
- ⚠️ Consider Azure Functions for serverless scale

**Code Ready:**
- HTTP Bootstrap server (PowerShell)
- UDP Bootstrap server (BitTorrent-style)
- Client bootstrap logic with fallback
- Docker/compose configuration

### 4. P2P Networking

**Finding:** SIPSorcery provides the most complete NAT traversal solution; no direct UDP hole punching library exists.

**Recommendations:**
- ✅ Use **SIPSorcery** for STUN/TURN/ICE
- ✅ Implement custom UDP hole punching (provided in docs)
- ✅ Use public STUN servers (Google's stun.l.google.com)
- ⚠️ Plan TURN fallback for symmetric NAT (self-hosted Coturn or Metered.ca)

**Code Ready:**
- STUN client implementation
- UDP hole puncher class
- ICE candidate gathering
- P2P connection manager

---

## Recommended Implementation Order

### Phase 1: Core Crypto (Week 1)
```
1. Implement ECDHKeyPair class
2. Implement key serialization (JSON, PEM)
3. Implement shared secret derivation
4. Add AES-GCM encryption layer
5. Write unit tests
```

### Phase 2: Identity System (Week 2)
```
1. Implement IdentityKey, SignedPreKey, OneTimePreKey classes
2. Implement X3DH key agreement
3. Implement Double Ratchet (simplified)
4. Add key storage (file-based, encrypted)
5. Implement safety number verification
```

### Phase 3: Bootstrap & Discovery (Week 3)
```
1. Deploy HTTP bootstrap server
2. Implement bootstrap client
3. Add mDNS local discovery
4. Implement peer announcement
5. Add fallback chain logic
```

### Phase 4: P2P Networking (Week 4)
```
1. Integrate SIPSorcery for STUN
2. Implement UDP hole punching
3. Build connection manager
4. Add TURN fallback
5. Implement reconnection logic
```

### Phase 5: Integration (Week 5)
```
1. Connect crypto layer to transport
2. Implement message protocol
3. Add CLI interface
4. End-to-end testing
5. Documentation
```

---

## Technology Stack Summary

| Component | Technology | Package/Source |
|-----------|------------|----------------|
| ECDH | ECDiffieHellmanCng | .NET BCL |
| AES | Aes.Create() | .NET BCL |
| HKDF | HKDF.DeriveKey() | .NET 5+ / Custom |
| STUN/TURN | SIPSorcery | NuGet |
| UDP | System.Net.Sockets.UdpClient | .NET BCL |
| HTTP Server | System.Net.HttpListener | .NET BCL |
| JSON | System.Text.Json | .NET BCL |
| Bootstrap | Custom PowerShell | Provided |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Symmetric NAT blocking P2P | TURN relay fallback |
| Bootstrap server unavailable | Hardcoded seed list + mDNS |
| Key compromise | Forward secrecy via Double Ratchet |
| Post-quantum threat | Hybrid KEM architecture prepared |
| Message interception | End-to-end encryption |

---

## Next Steps

1. **Review this research** and validate decisions
2. **Create project structure** based on Phase 1
3. **Implement core crypto module** with tests
4. **Set up development bootstrap server** locally

---

## Files Created

```
PSCryptoChat/
└── docs/
    └── research/
        ├── 01-ECDH-P256-Implementation.md    (P-256 ECDH code examples)
        ├── 02-Hybrid-Identity-Architecture.md (Identity system design)
        ├── 03-Bootstrap-Server-Design.md      (Bootstrap patterns & code)
        ├── 04-P2P-Libraries-NAT-Traversal.md  (NAT traversal options)
        └── 00-Research-Summary.md             (This file)
```

---

## Questions for Consideration

1. **Anonymous mode priority:** Should anonymous mode be MVP or Phase 2?
2. **TURN server:** Self-host Coturn or use Metered.ca free tier?
3. **Key backup:** Should identity keys be exportable for backup?
4. **Group chat:** Prioritize 1:1 first, or design for groups from start?
5. **Mobile support:** Any plans for cross-platform beyond Windows?
