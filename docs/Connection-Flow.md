# PSCryptoChat Connection Flow

This document describes the complete journey of establishing an encrypted P2P chat session between a Host and Peer, including which components handle each step.

## Overview

PSCryptoChat uses a direct peer-to-peer architecture where two parties (Host and Peer) establish an encrypted channel without any central server.

```mermaid
flowchart LR
    subgraph Host["Host Terminal"]
        H1[Identity]
        H2[Session]
        H3[Transport]
    end

    subgraph Peer["Peer Terminal"]
        P1[Identity]
        P2[Session]
        P3[Transport]
    end

    H3 <-->|UDP + AES-GCM| P3
```

## Component Responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| **CryptoProvider** | `PSCryptoChat.psm1` | ECDH key generation, shared secret derivation, AES-GCM encrypt/decrypt, HKDF key derivation |
| **CryptoIdentity** | `PSCryptoChat.psm1` | Key pair management, public key export, safety number generation, optional SecretManagement persistence |
| **ChatSession** | `PSCryptoChat.psm1` | Session state machine, handshake orchestration, message encryption/decryption using derived keys |
| **UdpTransport** | `PSCryptoChat.psm1` | UDP socket management, packet send/receive, connection handling |
| **MessageProtocol** | `PSCryptoChat.psm1` | JSON message framing, message type handling (handshake, message, disconnect) |

## Connection Sequence

### Phase 1: Identity Creation

Both Host and Peer create cryptographic identities before connecting.

```mermaid
sequenceDiagram
    participant User
    participant Identity as CryptoIdentity
    participant Crypto as CryptoProvider

    User->>Identity: New-CryptoIdentity [-Anonymous]
    Identity->>Crypto: Generate ECDH P-256 key pair
    Crypto-->>Identity: ECDiffieHellmanCng instance
    Identity->>Identity: Export public key (Base64)
    Identity->>Identity: Generate unique ID (SHA256 hash)
    Identity-->>User: Identity ready (PublicKey, Id)

    Note over Identity: Anonymous mode: Keys exist only in memory
    Note over Identity: Pseudonymous mode: Keys stored in SecretManagement vault
```

**Tech Stack:**
- `ECDiffieHellmanCng` (.NET CNG) - P-256 elliptic curve key generation
- `SHA256` - Identity ID derivation from public key
- `SecretManagement` (optional) - Persistent key storage

### Phase 2: Session Setup

```mermaid
sequenceDiagram
    participant Host as Host Terminal
    participant HSession as Host ChatSession
    participant HTransport as Host UdpTransport
    participant Network as UDP Network
    participant PTransport as Peer UdpTransport
    participant PSession as Peer ChatSession
    participant Peer as Peer Terminal

    Host->>HSession: Start-ChatSession -Listen -Port 9000
    HSession->>HTransport: Create UDP listener on port 9000
    HTransport-->>HSession: Listening...
    HSession-->>Host: Connection string (IP:Port:PublicKey)

    Note over Host,Peer: Host shares connection string out-of-band

    Peer->>PSession: Start-ChatSession -Peer "IP:Port:PublicKey"
    PSession->>PTransport: Create UDP client
    PTransport-->>PSession: Ready to send
```

**Tech Stack:**
- `UdpClient` (.NET) - UDP socket creation and binding
- Connection string format: `{IP}:{Port}:{Base64PublicKey}`

### Phase 3: ECDH Handshake

This is where the cryptographic magic happens - both parties exchange public keys and derive a shared secret.

```mermaid
sequenceDiagram
    participant HSession as Host Session
    participant HCrypto as Host CryptoProvider
    participant Network as UDP Network
    participant PCrypto as Peer CryptoProvider
    participant PSession as Peer Session

    Note over PSession: State: Created → Handshaking
    PSession->>Network: Handshake {type, publicKey, sessionId}
    Network->>HSession: Receive handshake

    Note over HSession: State: Created → Handshaking
    HSession->>HCrypto: DeriveSharedSecret(peerPublicKey)
    HCrypto->>HCrypto: ECDH P-256 key agreement
    HCrypto->>HCrypto: HKDF-SHA256 expand (32 bytes)
    HCrypto-->>HSession: Shared AES-256 key

    HSession->>Network: Handshake response {type, publicKey, sessionId}
    Network->>PSession: Receive response

    PSession->>PCrypto: DeriveSharedSecret(hostPublicKey)
    PCrypto->>PCrypto: ECDH P-256 key agreement
    PCrypto->>PCrypto: HKDF-SHA256 expand (32 bytes)
    PCrypto-->>PSession: Shared AES-256 key (identical!)

    Note over HSession,PSession: State: Handshaking → Established
    Note over HSession,PSession: Both parties now have identical symmetric keys
```

**Tech Stack:**
- `ECDiffieHellman.DeriveKeyMaterial()` - Raw shared secret derivation
- `HKDF` (.NET) - Key derivation function with SHA-256
- JSON - Handshake message serialization

**Key Derivation Details:**
```
Raw Secret = ECDH(myPrivateKey, peerPublicKey)  // 32 bytes
AES Key = HKDF-Expand(Raw Secret, info="pscryptochat-v1", length=32)
```

### Phase 4: Safety Number Verification

Optional but recommended - users verify they're talking to the right person.

```mermaid
sequenceDiagram
    participant Host as Host User
    participant HIdentity as Host Identity
    participant PIdentity as Peer Identity
    participant Peer as Peer User

    Host->>HIdentity: GetSafetyNumber(peerPublicKey)
    HIdentity->>HIdentity: SHA256(sort(myPubKey, peerPubKey))
    HIdentity->>HIdentity: Format as 12 groups of 5 digits
    HIdentity-->>Host: "57446 08198 05416..."

    Peer->>PIdentity: GetSafetyNumber(hostPublicKey)
    PIdentity->>PIdentity: SHA256(sort(myPubKey, peerPubKey))
    PIdentity->>PIdentity: Format as 12 groups of 5 digits
    PIdentity-->>Peer: "57446 08198 05416..."

    Note over Host,Peer: Compare numbers via voice call, in person, etc.
    Note over Host,Peer: Matching numbers = secure connection (no MITM)
```

**Tech Stack:**
- `SHA256` - Combined key fingerprint
- Signal Protocol-style safety numbers for human verification

### Phase 5: Encrypted Messaging

Once established, all messages are encrypted with AES-256-GCM.

```mermaid
sequenceDiagram
    participant User as Sender
    participant Session as ChatSession
    participant Crypto as CryptoProvider
    participant Transport as UdpTransport
    participant Network as UDP Network

    User->>Session: Send-ChatMessage "Hello!"
    Session->>Crypto: Encrypt("Hello!", sharedKey)

    Note over Crypto: AES-256-GCM Encryption
    Crypto->>Crypto: Generate random 12-byte nonce
    Crypto->>Crypto: AES-GCM encrypt with 16-byte auth tag
    Crypto-->>Session: Base64(nonce + ciphertext + tag)

    Session->>Transport: Send {type:"message", content:encrypted}
    Transport->>Network: UDP packet

    Network->>Transport: Receive UDP packet
    Transport->>Session: {type:"message", content:encrypted}
    Session->>Crypto: Decrypt(encrypted, sharedKey)

    Note over Crypto: AES-256-GCM Decryption
    Crypto->>Crypto: Extract nonce, ciphertext, tag
    Crypto->>Crypto: Verify auth tag + decrypt
    Crypto-->>Session: "Hello!"

    Session-->>User: Display message
```

**Tech Stack:**
- `AesGcm` (.NET) - Authenticated encryption
- 12-byte nonce (random per message)
- 16-byte authentication tag (integrity + authenticity)
- JSON message protocol over UDP

**Message Format:**
```json
{
  "type": "message",
  "content": "BASE64(nonce || ciphertext || tag)",
  "timestamp": "2025-12-03T19:00:00Z"
}
```

### Phase 6: Session Termination

Secure cleanup ensures keys don't persist in memory.

```mermaid
sequenceDiagram
    participant User
    participant Session as ChatSession
    participant Transport as UdpTransport
    participant Identity as CryptoIdentity

    User->>Session: Stop-ChatSession (or type 'quit')
    Session->>Transport: Send {type:"disconnect", reason:"User quit"}
    Session->>Session: Array.Clear(sharedKey)
    Session->>Session: State → Closed
    Transport->>Transport: Close UDP socket

    alt Anonymous Mode
        Identity->>Identity: Dispose() - clear private key
        Identity->>Identity: Keys permanently destroyed
    else Pseudonymous Mode
        Note over Identity: Keys remain in SecretManagement vault
    end

    Session-->>User: Session closed securely
```

**Tech Stack:**
- `Array.Clear()` - Zero out key material
- `IDisposable` pattern - Deterministic cleanup
- `SecretManagement` - Vault-based persistence (pseudonymous only)

## Complete Flow Diagram

```mermaid
stateDiagram-v2
    [*] --> Created: New-CryptoIdentity
    Created --> Listening: Start-ChatSession -Listen
    Created --> Connecting: Start-ChatSession -Peer

    Listening --> Handshaking: Receive peer handshake
    Connecting --> Handshaking: Send handshake

    Handshaking --> Established: Key exchange complete

    Established --> Established: Send/Receive messages
    Established --> Closing: Stop-ChatSession or disconnect

    Closing --> Closed: Keys cleared
    Closed --> [*]
```

## Security Properties

| Property | Implementation |
|----------|----------------|
| **Confidentiality** | AES-256-GCM encryption |
| **Integrity** | GCM authentication tag |
| **Authenticity** | ECDH key agreement + safety numbers |
| **Forward Secrecy** | New keys per session (anonymous mode) |
| **No Persistence** | Messages never written to disk |
| **Memory Safety** | Keys cleared with Array.Clear() on session end |

## Troubleshooting

### Handshake Fails
- Check firewall allows UDP on the specified port
- Verify both parties can reach each other's IP
- Ensure connection string was copied correctly

### Safety Numbers Don't Match
- Possible man-in-the-middle attack
- Terminate session immediately
- Re-establish on a trusted network

### Messages Not Received
- UDP is connectionless - no delivery guarantee
- Check network connectivity
- Verify session state is "Established"
