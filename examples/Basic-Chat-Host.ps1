<#
.SYNOPSIS
    Basic encrypted chat example - Host side

.DESCRIPTION
    This example shows how to set up a basic encrypted chat session as the host.
    The host listens for incoming connections and waits for a peer to connect.

.EXAMPLE
    # Terminal 1 (Host)
    .\examples\Basic-Chat-Host.ps1 -Port 9000

    # Terminal 2 (Peer) - on same or different machine
    .\examples\Basic-Chat-Peer.ps1 -ConnectionString "<from host output>"

.NOTES
    Run this script first, then share the connection string with your peer.
    Verify safety numbers match on both sides before exchanging sensitive messages!
#>
param(
    [int]$Port = 9000
)

# Import the module
$modulePath = Join-Path $PSScriptRoot "..\src\PSCryptoChat\PSCryptoChat.psd1"
Import-Module $modulePath -Force

Write-Host "=== PSCryptoChat Basic Example - Host ===" -ForegroundColor Cyan
Write-Host ""

# Create an anonymous identity (keys only exist in memory)
Write-Host "[1] Creating anonymous identity..." -ForegroundColor Yellow
$identity = New-CryptoIdentity -Anonymous
Write-Host "    Identity ID: $($identity.Id)" -ForegroundColor Gray

# Start listening
Write-Host "[2] Starting chat session on port $Port..." -ForegroundColor Yellow
$session = Start-ChatSession -Listen -Port $Port

Write-Host ""
Write-Host "Share the connection string above with your peer." -ForegroundColor Green
Write-Host "Waiting for peer to connect..." -ForegroundColor Gray
Write-Host ""

# In a real implementation, you would:
# 1. Wait for the peer's handshake
# 2. Complete the ECDH key exchange
# 3. Verify safety numbers
# 4. Start sending/receiving messages

Write-Host "Session Info:" -ForegroundColor Yellow
$session | Format-List

Write-Host ""
Write-Host "To send messages after peer connects:" -ForegroundColor Cyan
Write-Host '  Send-ChatMessage "Hello, peer!"' -ForegroundColor White
Write-Host ""
Write-Host "To receive messages:" -ForegroundColor Cyan
Write-Host '  Receive-ChatMessage -Continuous' -ForegroundColor White
Write-Host ""
Write-Host "To close the session:" -ForegroundColor Cyan
Write-Host '  Stop-ChatSession' -ForegroundColor White
