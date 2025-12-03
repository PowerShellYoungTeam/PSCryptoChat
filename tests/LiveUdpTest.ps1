using module ..\src\PSCryptoChat\PSCryptoChat.psm1

<#
.SYNOPSIS
    Live UDP test - Run this in two terminals to test real networking

.DESCRIPTION
    Terminal 1: .\LiveUdpTest.ps1 -Listen -Port 9000
    Terminal 2: .\LiveUdpTest.ps1 -Connect -Host localhost -Port 9000

.PARAMETER Listen
    Start in listen mode (server)

.PARAMETER Connect
    Start in connect mode (client)

.PARAMETER Host
    Remote host to connect to

.PARAMETER Port
    Port to listen on or connect to
#>
param(
    [switch]$Listen,
    [switch]$Connect,
    [string]$RemoteHost = "localhost",
    [int]$Port = 9000
)

if (-not $Listen -and -not $Connect) {
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  Listen mode:  .\LiveUdpTest.ps1 -Listen -Port 9000" -ForegroundColor Gray
    Write-Host "  Connect mode: .\LiveUdpTest.ps1 -Connect -Host localhost -Port 9000" -ForegroundColor Gray
    exit
}

# Create identity and session
$identity = [CryptoIdentity]::new([IdentityMode]::Anonymous)
$session = [ChatSession]::new($identity, 300)

Write-Host "=== PSCryptoChat Live UDP Test ===" -ForegroundColor Cyan
Write-Host "Your ID: $($identity.Id)" -ForegroundColor Gray
Write-Host "Session: $($session.SessionId)" -ForegroundColor Gray

# Create transport
$transport = [UdpTransport]::new($(if ($Listen) { $Port } else { 0 }))
$transport.Start()

Write-Host "Local endpoint: $($transport.GetLocalEndpointString())" -ForegroundColor Gray

if ($Listen) {
    Write-Host "`nListening on port $Port..." -ForegroundColor Green
    Write-Host "Waiting for peer connection..." -ForegroundColor Yellow

    # Wait for handshake
    while ($true) {
        $data = $transport.ReceiveString(5000)
        if ($data) {
            $msg = [MessageProtocol]::Parse($data)
            if ($msg.type -eq "handshake") {
                Write-Host "`nReceived handshake from peer!" -ForegroundColor Green

                # Store peer info for reply
                $peerKey = $msg.publicKey
                $peerSession = $msg.sessionId

                # Complete our handshake
                $session.CompleteHandshake($peerKey)

                # Send our handshake back (need to connect to their address)
                # Note: In real impl, we'd extract their address from the UDP packet
                Write-Host "  Peer public key: $($peerKey.Substring(0, 30))..." -ForegroundColor Gray
                Write-Host "  Session established!" -ForegroundColor Green

                # Send response handshake
                $response = [MessageProtocol]::CreateHandshake($identity.PublicKey, $session.SessionId)
                $transport.Connect($RemoteHost, $Port + 1)  # Reply port
                $transport.SendString($response)

                break
            }
        }
        else {
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
    }
}
else {
    # Connect mode
    Write-Host "`nConnecting to $RemoteHost`:$Port..." -ForegroundColor Green
    $transport.Connect($RemoteHost, $Port)

    # Send handshake
    $handshake = [MessageProtocol]::CreateHandshake($identity.PublicKey, $session.SessionId)
    $transport.SendString($handshake)
    Write-Host "Handshake sent, waiting for response..." -ForegroundColor Yellow

    # For demo, we'd need a separate receive port
    # This is simplified - real impl would handle bidirectional UDP
}

# Interactive message loop (simplified)
Write-Host "`n=== Chat Mode ===" -ForegroundColor Cyan
Write-Host "Type messages to send (Ctrl+C to exit)" -ForegroundColor Gray
Write-Host ""

try {
    while ($true) {
        # Check for incoming messages (non-blocking would be better)
        $incoming = $transport.ReceiveString(100)
        if ($incoming) {
            $msg = [MessageProtocol]::Parse($incoming)
            if ($msg.type -eq "message") {
                try {
                    $decrypted = $session.Decrypt($msg.content)
                    Write-Host "`n[Peer] $decrypted" -ForegroundColor Cyan
                }
                catch {
                    Write-Host "`n[Encrypted message received but cannot decrypt]" -ForegroundColor Red
                }
            }
        }

        # Check for user input (this blocks, need async in real impl)
        if ([Console]::KeyAvailable) {
            $input = Read-Host "You"
            if ($input) {
                $encrypted = $session.Encrypt($input)
                $packet = [MessageProtocol]::CreateMessage($encrypted)
                $transport.SendString($packet)
            }
        }

        Start-Sleep -Milliseconds 100
    }
}
finally {
    Write-Host "`nClosing session..." -ForegroundColor Yellow
    $session.Close()
    $transport.Stop()
    $identity.Dispose()
    Write-Host "Goodbye!" -ForegroundColor Green
}
