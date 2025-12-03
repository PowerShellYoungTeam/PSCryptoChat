using module ..\src\PSCryptoChat\PSCryptoChat.psm1

<#
.SYNOPSIS
    Integration test for all PSCryptoChat public cmdlets
#>

Write-Host "=== PSCryptoChat Integration Test ===" -ForegroundColor Cyan

$testsPassed = 0
$testsFailed = 0

function Test-Case {
    param([string]$Name, [scriptblock]$Test)

    Write-Host "`n[Test] $Name" -ForegroundColor Yellow
    try {
        & $Test
        Write-Host "  PASSED" -ForegroundColor Green
        $script:testsPassed++
    }
    catch {
        Write-Host "  FAILED: $_" -ForegroundColor Red
        $script:testsFailed++
    }
}

# ============================================================
# Identity Tests
# ============================================================

Test-Case "New-CryptoIdentity -Anonymous" {
    $identity = New-CryptoIdentity -Anonymous
    if ($null -eq $identity) { throw "Identity is null" }
    if ($identity.Mode -ne "Anonymous") { throw "Mode is not Anonymous" }
    if ([string]::IsNullOrEmpty($identity.Id)) { throw "ID is empty" }
    if ([string]::IsNullOrEmpty($identity.PublicKey)) { throw "PublicKey is empty" }
    Write-Host "    ID: $($identity.Id)" -ForegroundColor Gray
}

Test-Case "New-CryptoIdentity -Pseudonymous" {
    $identity = New-CryptoIdentity
    if ($identity.Mode -ne "Pseudonymous") { throw "Mode is not Pseudonymous" }
    Write-Host "    ID: $($identity.Id)" -ForegroundColor Gray
}

Test-Case "Get-CryptoIdentity" {
    $current = Get-CryptoIdentity
    if ($null -eq $current) { throw "No current identity" }
    Write-Host "    Current ID: $($current.Id)" -ForegroundColor Gray
}

# ============================================================
# Session Tests
# ============================================================

Test-Case "Start-ChatSession -Listen" {
    $session = Start-ChatSession -Listen -Port 9800 -Timeout 30
    if ($null -eq $session) { throw "Session is null" }
    if ([string]::IsNullOrEmpty($session.SessionId)) { throw "SessionId is empty" }
    Write-Host "    Session: $($session.SessionId)" -ForegroundColor Gray
    Write-Host "    Endpoint: $($session.LocalEndpoint)" -ForegroundColor Gray

    # Cleanup
    Stop-ChatSession -SessionId $session.SessionId
}

Test-Case "Get-ConnectionString" {
    # Start a session first
    $session = Start-ChatSession -Listen -Port 9801 -Timeout 30

    $connStr = Get-ConnectionString -SessionId $session.SessionId
    if ([string]::IsNullOrEmpty($connStr)) { throw "Connection string is empty" }

    # Validate format: ip:port:publickey
    $parts = $connStr -split ':', 3
    if ($parts.Count -ne 3) { throw "Invalid connection string format" }

    Write-Host "    Connection string: $($connStr.Substring(0, [Math]::Min(50, $connStr.Length)))..." -ForegroundColor Gray

    # Cleanup
    Stop-ChatSession -SessionId $session.SessionId
}

Test-Case "Get-ChatSession" {
    $session = Start-ChatSession -Listen -Port 9802 -Timeout 30

    $sessions = Get-ChatSession -All
    if ($sessions.Count -eq 0) { throw "No sessions returned" }

    $specific = Get-ChatSession -SessionId $session.SessionId
    if ($specific.SessionId -ne $session.SessionId) { throw "Session ID mismatch" }

    Write-Host "    Active sessions: $($sessions.Count)" -ForegroundColor Gray

    Stop-ChatSession -SessionId $session.SessionId
}

Test-Case "Stop-ChatSession" {
    $session = Start-ChatSession -Listen -Port 9803 -Timeout 30
    $sessionId = $session.SessionId

    Stop-ChatSession -SessionId $sessionId

    $after = Get-ChatSession -SessionId $sessionId
    if ($null -ne $after) { throw "Session still exists after stop" }

    Write-Host "    Session closed successfully" -ForegroundColor Gray
}

# ============================================================
# Simulated P2P Communication Test
# ============================================================

Test-Case "End-to-end encrypted P2P" {
    # Create two identities directly
    $aliceIdentity = [CryptoIdentity]::new([IdentityMode]::Anonymous)
    $bobIdentity = [CryptoIdentity]::new([IdentityMode]::Anonymous)

    # Create sessions for both
    $aliceSession = [ChatSession]::new($aliceIdentity, 300)
    $bobSession = [ChatSession]::new($bobIdentity, 300)

    # Create transport pair
    $alicePort = 9810
    $bobPort = 9811

    $aliceTransport = [UdpTransport]::new($alicePort)
    $bobTransport = [UdpTransport]::new($bobPort)

    $aliceTransport.Start()
    $bobTransport.Start()

    # Connect bidirectionally
    $aliceTransport.Connect("127.0.0.1", $bobPort)
    $bobTransport.Connect("127.0.0.1", $alicePort)

    # Exchange handshakes
    $aliceHandshake = [MessageProtocol]::CreateHandshake($aliceIdentity.PublicKey, $aliceSession.SessionId)
    $aliceTransport.SendString($aliceHandshake)

    $receivedHandshake = [MessageProtocol]::Parse($bobTransport.ReceiveString(2000))
    $bobSession.CompleteHandshake($receivedHandshake.publicKey)

    $bobHandshake = [MessageProtocol]::CreateHandshake($bobIdentity.PublicKey, $bobSession.SessionId)
    $bobTransport.SendString($bobHandshake)

    $receivedBobHandshake = [MessageProtocol]::Parse($aliceTransport.ReceiveString(2000))
    $aliceSession.CompleteHandshake($receivedBobHandshake.publicKey)

    if ($aliceSession.State -ne [SessionState]::Established) { throw "Alice not established" }
    if ($bobSession.State -ne [SessionState]::Established) { throw "Bob not established" }

    Write-Host "    Sessions established" -ForegroundColor Gray

    # Send encrypted message
    $secret = "Top secret message with emoji! 🔐🚀"
    $encrypted = $aliceSession.Encrypt($secret)
    $msgPacket = [MessageProtocol]::CreateMessage($encrypted)
    $aliceTransport.SendString($msgPacket)

    # Receive and decrypt
    $receivedPacket = [MessageProtocol]::Parse($bobTransport.ReceiveString(2000))
    $decrypted = $bobSession.Decrypt($receivedPacket.content)

    if ($decrypted -ne $secret) { throw "Message mismatch: '$decrypted' vs '$secret'" }

    Write-Host "    Message encrypted, transmitted, decrypted successfully" -ForegroundColor Gray
    Write-Host "    Original: $secret" -ForegroundColor Gray
    Write-Host "    Decrypted: $decrypted" -ForegroundColor Gray

    # Cleanup
    $aliceSession.Close()
    $bobSession.Close()
    $aliceTransport.Stop()
    $bobTransport.Stop()
    $aliceIdentity.Dispose()
    $bobIdentity.Dispose()
}

# ============================================================
# Summary
# ============================================================

Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
Write-Host "Test Results: $testsPassed passed, $testsFailed failed" -ForegroundColor $(if ($testsFailed -eq 0) { "Green" } else { "Red" })
Write-Host ("=" * 50) -ForegroundColor Cyan

# Cleanup any remaining sessions
Stop-ChatSession -All -ErrorAction SilentlyContinue

if ($testsFailed -gt 0) {
    exit 1
}
