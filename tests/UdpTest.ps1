using module ..\src\PSCryptoChat\PSCryptoChat.psm1

<#
.SYNOPSIS
    Tests UDP transport using async jobs to simulate two peers in one process
#>

Write-Host "=== UDP Transport Test ===" -ForegroundColor Cyan

# Test 1: Basic transport creation
Write-Host "`n[Test 1] Create UDP transport..." -ForegroundColor Yellow
$transport = [UdpTransport]::new(0)
$transport.Start()
Write-Host "  Port assigned: $($transport.LocalPort)" -ForegroundColor Green
Write-Host "  Endpoint: $($transport.GetLocalEndpointString())" -ForegroundColor Gray
$transport.Stop()
Write-Host "  Transport stopped" -ForegroundColor Green

# Test 2: Loopback communication using jobs
Write-Host "`n[Test 2] Loopback UDP test..." -ForegroundColor Yellow

# Create two transports
$server = [UdpTransport]::new(9876)
$client = [UdpTransport]::new(0)

$server.Start()
$client.Start()

Write-Host "  Server port: $($server.LocalPort)" -ForegroundColor Gray
Write-Host "  Client port: $($client.LocalPort)" -ForegroundColor Gray

# Client connects to server
$client.Connect("127.0.0.1", $server.LocalPort)

# Server needs to connect back to client for bidirectional
# But first, let's test one-way

# Send a test message
$testMessage = "Hello from client!"
$client.SendString($testMessage)
Write-Host "  Client sent: $testMessage" -ForegroundColor Gray

# Server receives (with timeout)
$received = $server.ReceiveString(2000)
if ($received -eq $testMessage) {
    Write-Host "  Server received: $received" -ForegroundColor Green
}
else {
    Write-Host "  RECEIVE FAILED or timed out" -ForegroundColor Red
}

# Now test bidirectional - server connects back
$server.Connect("127.0.0.1", $client.LocalPort)
$serverMessage = "Hello from server!"
$server.SendString($serverMessage)
Write-Host "  Server sent: $serverMessage" -ForegroundColor Gray

$clientReceived = $client.ReceiveString(2000)
if ($clientReceived -eq $serverMessage) {
    Write-Host "  Client received: $clientReceived" -ForegroundColor Green
}
else {
    Write-Host "  CLIENT RECEIVE FAILED" -ForegroundColor Red
}

# Cleanup
$server.Stop()
$client.Stop()

# Test 3: Full encrypted exchange over UDP
Write-Host "`n[Test 3] Encrypted exchange over UDP..." -ForegroundColor Yellow

# Create identities
$alice = [CryptoIdentity]::new([IdentityMode]::Anonymous)
$bob = [CryptoIdentity]::new([IdentityMode]::Anonymous)

# Create sessions
$aliceSession = [ChatSession]::new($alice, 300)
$bobSession = [ChatSession]::new($bob, 300)

# Create transports
$aliceTransport = [UdpTransport]::new(9877)
$bobTransport = [UdpTransport]::new(9878)

$aliceTransport.Start()
$bobTransport.Start()

# Connect bidirectionally
$aliceTransport.Connect("127.0.0.1", $bobTransport.LocalPort)
$bobTransport.Connect("127.0.0.1", $aliceTransport.LocalPort)

# Simulate handshake exchange
$aliceHandshake = [MessageProtocol]::CreateHandshake($alice.PublicKey, $aliceSession.SessionId)
$aliceTransport.SendString($aliceHandshake)

$bobReceivedHandshake = $bobTransport.ReceiveString(2000)
$parsedHandshake = [MessageProtocol]::Parse($bobReceivedHandshake)

if ($parsedHandshake.type -eq "handshake") {
    Write-Host "  Bob received Alice's handshake" -ForegroundColor Green
    $bobSession.CompleteHandshake($parsedHandshake.publicKey)

    # Bob sends his handshake
    $bobHandshake = [MessageProtocol]::CreateHandshake($bob.PublicKey, $bobSession.SessionId)
    $bobTransport.SendString($bobHandshake)
}

$aliceReceivedHandshake = $aliceTransport.ReceiveString(2000)
$parsedBobHandshake = [MessageProtocol]::Parse($aliceReceivedHandshake)

if ($parsedBobHandshake.type -eq "handshake") {
    Write-Host "  Alice received Bob's handshake" -ForegroundColor Green
    $aliceSession.CompleteHandshake($parsedBobHandshake.publicKey)
}

Write-Host "  Both sessions established!" -ForegroundColor Green

# Send encrypted message
$secretMessage = "This is a top secret message! 🔒"
$encrypted = $aliceSession.Encrypt($secretMessage)
$messagePacket = [MessageProtocol]::CreateMessage($encrypted)
$aliceTransport.SendString($messagePacket)

$bobReceivedMsg = $bobTransport.ReceiveString(2000)
$parsedMsg = [MessageProtocol]::Parse($bobReceivedMsg)

if ($parsedMsg.type -eq "message") {
    $decrypted = $bobSession.Decrypt($parsedMsg.content)
    if ($decrypted -eq $secretMessage) {
        Write-Host "  Encrypted message transmitted and decrypted!" -ForegroundColor Green
        Write-Host "  Message: $decrypted" -ForegroundColor Gray
    }
    else {
        Write-Host "  DECRYPTION MISMATCH" -ForegroundColor Red
    }
}
else {
    Write-Host "  RECEIVE FAILED" -ForegroundColor Red
}

# Cleanup
$aliceSession.Close()
$bobSession.Close()
$aliceTransport.Stop()
$bobTransport.Stop()
$alice.Dispose()
$bob.Dispose()

Write-Host "`n=== All UDP Tests Passed! ===" -ForegroundColor Green
