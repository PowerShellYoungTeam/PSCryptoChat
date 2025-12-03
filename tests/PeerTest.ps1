using module ..\src\PSCryptoChat\PSCryptoChat.psm1

<#
.SYNOPSIS
    Tests peer-to-peer encrypted communication between Alice and Bob
#>

Write-Host "=== PSCryptoChat P2P Test ===" -ForegroundColor Cyan

# Create identities
Write-Host "`n[Setup] Creating identities..." -ForegroundColor Yellow
$alice = [CryptoIdentity]::new([IdentityMode]::Anonymous)
$bob = [CryptoIdentity]::new([IdentityMode]::Anonymous)

Write-Host "  Alice ID: $($alice.Id)" -ForegroundColor Gray
Write-Host "  Bob ID: $($bob.Id)" -ForegroundColor Gray

# Create sessions
Write-Host "`n[Setup] Creating sessions..." -ForegroundColor Yellow
$aliceSession = [ChatSession]::new($alice, 300)
$bobSession = [ChatSession]::new($bob, 300)

Write-Host "  Alice Session: $($aliceSession.SessionId)" -ForegroundColor Gray
Write-Host "  Bob Session: $($bobSession.SessionId)" -ForegroundColor Gray

# Simulate handshake
Write-Host "`n[Test] Handshake..." -ForegroundColor Yellow

# Alice sends her public key to Bob, Bob responds with his
$aliceSession.CompleteHandshake($bob.PublicKey)
$bobSession.CompleteHandshake($alice.PublicKey)

Write-Host "  Alice state: $($aliceSession.State)" -ForegroundColor Green
Write-Host "  Bob state: $($bobSession.State)" -ForegroundColor Green

# Verify safety numbers match (out-of-band verification)
Write-Host "`n[Test] Safety Number Verification..." -ForegroundColor Yellow
$aliceSafetyNum = $alice.GetSafetyNumber($bob.PublicKey)
$bobSafetyNum = $bob.GetSafetyNumber($alice.PublicKey)

if ($aliceSafetyNum -eq $bobSafetyNum) {
    Write-Host "  Safety numbers MATCH!" -ForegroundColor Green
    Write-Host "  Number: $($aliceSafetyNum.Substring(0, 30))..." -ForegroundColor Gray
}
else {
    Write-Host "  Safety numbers DO NOT MATCH - potential MITM!" -ForegroundColor Red
    exit 1
}

# Test encrypted messaging
Write-Host "`n[Test] Encrypted Messaging..." -ForegroundColor Yellow

# Alice sends message to Bob
$originalMessage = "Hello Bob! This is a secret message from Alice."
$encrypted = $aliceSession.Encrypt($originalMessage)
Write-Host "  Original: $originalMessage" -ForegroundColor Gray
Write-Host "  Encrypted: $($encrypted.Substring(0, 50))..." -ForegroundColor Gray

# Bob decrypts message
$decrypted = $bobSession.Decrypt($encrypted)
Write-Host "  Decrypted: $decrypted" -ForegroundColor Gray

if ($decrypted -eq $originalMessage) {
    Write-Host "  Message decrypted correctly!" -ForegroundColor Green
}
else {
    Write-Host "  DECRYPTION FAILED!" -ForegroundColor Red
    exit 1
}

# Bob replies
Write-Host "`n[Test] Bob replies..." -ForegroundColor Yellow
$bobMessage = "Hi Alice! Message received. Here's some sensitive data: 🔐"
$encrypted2 = $bobSession.Encrypt($bobMessage)
$decrypted2 = $aliceSession.Decrypt($encrypted2)

if ($decrypted2 -eq $bobMessage) {
    Write-Host "  Bob's reply decrypted correctly!" -ForegroundColor Green
    Write-Host "  Message: $decrypted2" -ForegroundColor Gray
}
else {
    Write-Host "  DECRYPTION FAILED!" -ForegroundColor Red
    exit 1
}

# Test message protocol
Write-Host "`n[Test] Message Protocol..." -ForegroundColor Yellow
$handshake = [MessageProtocol]::CreateHandshake($alice.PublicKey, $aliceSession.SessionId)
$parsed = [MessageProtocol]::Parse($handshake)
Write-Host "  Handshake type: $($parsed.type)" -ForegroundColor Gray
Write-Host "  Version: $($parsed.version)" -ForegroundColor Gray

$msgPacket = [MessageProtocol]::CreateMessage($encrypted)
$parsedMsg = [MessageProtocol]::Parse($msgPacket)
Write-Host "  Message packet created" -ForegroundColor Green

# Test session cleanup
Write-Host "`n[Test] Session Cleanup..." -ForegroundColor Yellow
$aliceSession.Close()
$bobSession.Close()
Write-Host "  Alice state: $($aliceSession.State)" -ForegroundColor Gray
Write-Host "  Bob state: $($bobSession.State)" -ForegroundColor Gray

# Verify keys were cleared
try {
    $null = $aliceSession.Encrypt("test")
    Write-Host "  ERROR: Should not be able to encrypt after close!" -ForegroundColor Red
}
catch {
    Write-Host "  Keys properly cleared after close" -ForegroundColor Green
}

# Cleanup identities
$alice.Dispose()
$bob.Dispose()

Write-Host "`n=== All P2P Tests Passed! ===" -ForegroundColor Green
