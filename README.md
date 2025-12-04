# PSCryptoChat

An encrypted, decentralized, optionally anonymous messaging application built with PowerShell/.NET.

## Project Status

✅ **v0.1.0 Released** - Core functionality complete and tested.

| Feature | Status |
|---------|--------|
| ECDH Key Exchange | ✅ Complete |
| AES-256-GCM Encryption | ✅ Complete |
| UDP Transport | ✅ Complete |
| Identity Management | ✅ Complete |
| Safety Numbers | ✅ Complete |
| LAN Connectivity | ✅ Working |
| Internet (NAT Traversal) | 🚧 Planned v0.2.0 |
| mDNS Discovery | 🚧 Planned |

## Quick Start

### From PowerShell Gallery (Recommended)

```powershell
# Install the module
Install-Module PSCryptoChat -Scope CurrentUser

# Terminal 1 - Start as host
Start-CryptoChat -Listen -Port 9000

# Terminal 2 - Connect as peer
Start-CryptoChat -Connect -Peer localhost -Port 9000
# Or for LAN: Start-CryptoChat -Connect -Peer 192.168.1.100 -Port 9000
```

### From Repository (Development)

There are two ways to use PSCryptoChat from the repo:

#### Option 1: Interactive Chat Script

The easiest way - use `Chat.ps1` for a full interactive experience:

**Terminal 1 (Host):**

```powershell
.\Chat.ps1 -Listen -Port 9000
```

**Terminal 2 (Peer):**

```powershell
.\Chat.ps1 -Connect -Peer localhost -Port 9000
# Or for LAN: .\Chat.ps1 -Connect -Peer 192.168.1.100 -Port 9000
```

Both terminals show safety numbers to verify, then you can type messages back and forth. Type `quit` to exit.

#### Option 2: Module Cmdlets (Programmatic)

For scripting or building your own chat interface:

**Terminal 1 (Host):**

```powershell
Import-Module .\src\PSCryptoChat\PSCryptoChat.psd1
New-CryptoIdentity -Anonymous
Start-ChatSession -Listen -Port 9000
# Copy the connection string shown
Receive-ChatMessage -Continuous   # Wait for peer + receive messages
```

**Terminal 2 (Peer):**

```powershell
Import-Module .\src\PSCryptoChat\PSCryptoChat.psd1
New-CryptoIdentity -Anonymous
Start-ChatSession -Peer "<connection-string-from-host>"
Send-ChatMessage "Hello!"
Receive-ChatMessage -Continuous
```

### Comparison

| Feature | Chat.ps1 | Module Cmdlets |
|---------|----------|----------------|
| **Best for** | Interactive chat | Scripts/automation |
| **Input mode** | Real-time typing | Command-by-command |
| **Bidirectional** | Automatic | Manual (call Send/Receive) |
| **Session handling** | Automatic | Manual cleanup needed |
| **Customization** | Limited | Full control |

## Features

- **End-to-End Encryption**: P-256 ECDH key exchange + AES-256-GCM authenticated encryption
- **Zero Persistence**: Messages never written to disk
- **Anonymous Mode**: Ephemeral identities that vanish when session ends
- **Secure Memory**: Keys cleared from memory on session close
- **No Servers**: Direct peer-to-peer UDP communication
- **Safety Numbers**: Verify peer identity out-of-band (Signal-style)

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Crypto Curve** | P-256 (NIST) | Native .NET support, cross-platform |
| **Encryption** | AES-256-GCM | Authenticated encryption with 16-byte tag |
| **Key Derivation** | HKDF-SHA256 | Standard key derivation |
| **Identity** | Hybrid (Pseudonymous + Anonymous) | User choice per session |
| **Key Storage** | SecretManagement | Vault-protected identity keys |
| **Discovery** | Manual + mDNS | Zero infrastructure, LAN convenience |
| **Persistence** | Ephemeral only | Messages never written to disk |
| **Memory** | Array.Clear + Dispose | Minimize forensic exposure |
| **Session** | Auto-timeout + key clearing | Prevents abandoned sessions |

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    PSCryptoChat                             │
├─────────────────────────────────────────────────────────────┤
│  CLI (New-CryptoIdentity, Start-ChatSession, Send/Receive) │
├─────────────────────────────────────────────────────────────┤
│  Session Manager (Auto-timeout, key clearing)              │
├─────────────────────────────────────────────────────────────┤
│  Message Protocol (JSON framing, ephemeral encryption)     │
├─────────────────────────────────────────────────────────────┤
│  Identity (SecretStore persistence / Anonymous ephemeral)  │
├─────────────────────────────────────────────────────────────┤
│  Crypto (P-256 ECDH + AES-GCM + HKDF-SHA256)               │
├─────────────────────────────────────────────────────────────┤
│  P2P Transport (UDP direct)                                │
├─────────────────────────────────────────────────────────────┤
│  Discovery (Manual exchange + mDNS LAN broadcast)          │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```text
PSCryptoChat/
├── src/PSCryptoChat/
│   ├── PSCryptoChat.psd1      # Module manifest
│   ├── PSCryptoChat.psm1      # Root module (all classes)
│   └── Public/                # Exported cmdlets
│       ├── Identity.ps1       # New-CryptoIdentity, etc.
│       ├── Session.ps1        # Start-ChatSession, etc.
│       ├── Messaging.ps1      # Send/Receive-ChatMessage
│       └── Discovery.ps1      # Find-ChatPeer
├── tests/
│   ├── QuickTest.ps1          # Rapid crypto validation
│   ├── PeerTest.ps1           # P2P handshake/encryption test
│   ├── UdpTest.ps1            # UDP transport loopback test
│   ├── IntegrationTest.ps1    # Full integration tests
│   └── ModuleTest.ps1         # Module import/cmdlet test
├── docs/                      # Documentation
│   ├── Connection-Flow.md     # How connections work
│   └── research/              # Technical research docs
└── examples/                  # Usage examples
```

## Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `New-CryptoIdentity` | Create new identity (pseudonymous or anonymous) |
| `Get-CryptoIdentity` | Get current or saved identity |
| `Remove-CryptoIdentity` | Remove saved identity |
| `Start-ChatSession` | Start listening or connect to peer |
| `Stop-ChatSession` | Close session and clear keys |
| `Get-ChatSession` | Get session info |
| `Get-ConnectionString` | Get connection string to share |
| `Send-ChatMessage` | Send encrypted message |
| `Receive-ChatMessage` | Receive and decrypt messages |
| `Find-ChatPeer` | Discover peers on LAN via mDNS |

## Requirements

- PowerShell 7.0+
- .NET 6.0+ (tested with .NET 9)
- **Windows** (required - uses CNG crypto via ECDiffieHellmanCng)
- Optional: `Microsoft.PowerShell.SecretManagement` for persistent identity storage

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Windows** | ✅ Supported | Full support via ECDiffieHellmanCng (CNG) |
| **Linux** | 🚧 Planned | Future release - requires OpenSSL backend implementation |
| **macOS** | 🚧 Planned | Future release - requires OpenSSL backend implementation |

> **Note**: The current implementation uses Windows CNG (Cryptography Next Generation) APIs directly. Cross-platform support using .NET's platform-agnostic crypto APIs is on the roadmap.

## Running Tests

```powershell
# Quick crypto validation (5 tests)
.\tests\QuickTest.ps1

# P2P encryption test
.\tests\PeerTest.ps1

# UDP transport test
.\tests\UdpTest.ps1

# Full integration tests (8 tests)
.\tests\IntegrationTest.ps1
```

## Example: Verify Safety Numbers

```powershell
# After handshake, verify safety numbers with your peer
$identity = Get-CryptoIdentity
$peerKey = "MFkwEwYHKoZIzj0CAQ..."  # From peer

$safetyNumber = $identity.GetSafetyNumber($peerKey)
# Output: 57446 08198 05416 21563 59671 38492 ...

# Both peers should see the same number - compare out of band!
```

## Security Considerations

- **Forward Secrecy**: New keys per session (anonymous mode)
- **No Message History**: Ephemeral by design
- **Key Clearing**: `Array.Clear()` and `Dispose()` on session end
- **No Metadata Storage**: Connection strings are transient

## Known Limitations

### Network Connectivity

- **LAN Only**: v0.1.0 works on local networks, localhost, or VPN tunnels
- **No NAT Traversal**: Direct internet connections require manual port forwarding
- **Why?**: Connection strings contain private LAN IPs (e.g., `192.168.x.x`) which are unreachable from the public internet

### Supported Scenarios

| Scenario | Works? |
|----------|--------|
| Same machine (localhost) | ✅ Yes |
| Same LAN (192.168.x.x) | ✅ Yes |
| VPN/Tailscale/ZeroTier | ✅ Yes |
| Port forwarding configured | ✅ Yes |
| Direct internet (no NAT bypass) | ❌ No |

### Planned for v0.2.0

- STUN integration for public IP discovery
- ICE candidate exchange for NAT traversal
- See [Internet Connectivity Analysis](./docs/Internet-Connectivity-Analysis.md) for technical details

### Platform

- **Windows only** - Uses CNG (ECDiffieHellmanCng). Linux/macOS support planned.

## Documentation

- [Connection Flow](./docs/Connection-Flow.md) - How Host and Peer connect and exchange messages
- [Research Documentation](./docs/research/) - Technical design decisions and implementation details

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
