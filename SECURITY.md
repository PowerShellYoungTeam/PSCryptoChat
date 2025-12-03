# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model

PSCryptoChat is designed with the following security properties:

### Cryptographic Guarantees

- **Confidentiality**: AES-256-GCM encryption protects message content
- **Integrity**: GCM authentication tags detect any message tampering
- **Authenticity**: ECDH key exchange ensures only the intended peer can decrypt
- **Forward Secrecy**: Anonymous mode uses ephemeral keys per session

### Trust Model

- **No Central Authority**: Direct peer-to-peer communication
- **Manual Verification**: Safety numbers allow out-of-band identity verification
- **User Responsibility**: Users must verify safety numbers to prevent MITM attacks

### Known Limitations

1. **Windows Only**: Currently requires Windows CNG APIs (ECDiffieHellmanCng)
2. **No Perfect Forward Secrecy in Pseudonymous Mode**: Persistent identities reuse keys
3. **UDP Transport**: No delivery guarantees, messages may be lost
4. **No Replay Protection**: Basic implementation doesn't include sequence numbers
5. **Local Network Exposure**: mDNS discovery exposes presence on LAN

## Threat Model

### In Scope

- Passive network eavesdropping
- Message tampering in transit
- Peer impersonation (mitigated by safety number verification)
- Memory forensics after session close (keys are cleared)

### Out of Scope

- Malware on endpoint devices
- Side-channel attacks
- Denial of service attacks
- Traffic analysis / metadata protection
- Quantum computing attacks

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send details to the repository owner via GitHub's private contact feature
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### Disclosure Policy

- We follow coordinated disclosure
- We will credit reporters (unless anonymity is requested)
- Public disclosure after fix is released and users have time to update

## Security Best Practices for Users

### Before Use

1. Verify you downloaded from the official repository
2. Check module signature (when available)
3. Review the code if handling sensitive data

### During Use

1. **Always verify safety numbers** with your peer through a separate channel
2. Use **anonymous mode** for sensitive conversations
3. Don't share connection strings over insecure channels
4. Close sessions when done to clear keys from memory

### Network Security

1. Use on trusted networks when possible
2. Be aware that mDNS discovery exposes your presence
3. Consider firewall rules to limit exposure

## Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Exchange | ECDH | P-256 (secp256r1) |
| Encryption | AES-GCM | 256-bit key, 96-bit nonce, 128-bit tag |
| Key Derivation | HKDF | SHA-256, info="PSCryptoChat-v1" |
| Safety Numbers | SHA-256 | 5200 iterations, formatted as 12×5 digits |

## Dependencies

- **.NET Cryptography**: System.Security.Cryptography (AesGcm, ECDiffieHellmanCng, HKDF)
- **SecretManagement** (optional): Microsoft.PowerShell.SecretManagement for identity storage

## Audit Status

This project has **not** undergone a formal security audit. Use at your own risk for sensitive communications.

## Contact

For security concerns, contact the repository maintainers through GitHub.
