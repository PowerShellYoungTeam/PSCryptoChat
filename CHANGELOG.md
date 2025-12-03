# Changelog

All notable changes to PSCryptoChat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

## [0.1.0] - 2025-12-03

### Added
- Initial release of PSCryptoChat
- **Cryptographic Foundation**
  - ECDH P-256 key exchange using Windows CNG (ECDiffieHellmanCng)
  - AES-256-GCM authenticated encryption with 16-byte authentication tags
  - HKDF-SHA256 key derivation for secure session keys
  - Secure memory clearing with `Array.Clear()` on session close
- **Identity Management**
  - Anonymous (ephemeral) identities that exist only in memory
  - Pseudonymous identities with optional SecretManagement vault storage
  - Signal-style safety numbers for out-of-band peer verification
  - Unique identity fingerprints derived from public keys
- **Session Management**
  - Encrypted peer-to-peer chat sessions
  - Configurable session timeouts with automatic key clearing
  - Connection strings for easy peer sharing (format: `host:port:publickey`)
  - Session state machine (Created → Handshaking → Established → Closed)
- **Transport Layer**
  - UDP-based peer-to-peer communication
  - JSON message protocol with handshake, message, and disconnect types
  - Local network endpoint detection
- **Discovery**
  - Manual connection via connection strings
  - mDNS LAN discovery (placeholder implementation)
- **Interactive CLI**
  - `Chat.ps1` script for interactive encrypted chat between terminals
  - Real-time message display with timestamps
- **Cmdlets**
  - `New-CryptoIdentity` - Create new identity (anonymous or pseudonymous)
  - `Get-CryptoIdentity` - Retrieve current or saved identity
  - `Remove-CryptoIdentity` - Remove saved identity from vault
  - `Export-CryptoIdentity` - Export identity for backup
  - `Start-ChatSession` - Initiate or accept encrypted chat session
  - `Stop-ChatSession` - Close session and securely clear keys
  - `Get-ChatSession` - Get session information
  - `Get-ConnectionString` - Get shareable connection string
  - `Send-ChatMessage` - Send encrypted message to peer
  - `Receive-ChatMessage` - Receive and decrypt messages from peer
  - `Find-ChatPeer` - Discover peers on local network

### Security
- End-to-end encryption for all messages
- No message persistence (ephemeral by design)
- Forward secrecy in anonymous mode (new keys per session)
- Keys cleared from memory on session close

### Platform Support
- Windows (required) - uses CNG cryptographic APIs
- PowerShell 7.0+ required
- .NET 6.0+ required

### Known Limitations
- **LAN connectivity only** - Works on localhost, same LAN, or VPN tunnels
- NAT traversal not implemented - direct internet connections require port forwarding
- See [Internet Connectivity Analysis](./docs/Internet-Connectivity-Analysis.md) for details

[Unreleased]: https://github.com/PowerShellYoungTeam/PSCryptoChat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PowerShellYoungTeam/PSCryptoChat/releases/tag/v0.1.0
