<#
.SYNOPSIS
    Basic encrypted chat example - Peer side

.DESCRIPTION
    This example shows how to connect to an existing chat session as a peer.
    The peer connects using a connection string provided by the host.

.EXAMPLE
    .\examples\Basic-Chat-Peer.ps1 -ConnectionString "192.168.1.100:9000:MFkw..."

.NOTES
    Get the connection string from the host before running this script.
    Verify safety numbers match on both sides before exchanging sensitive messages!
#>
param(
    [Parameter(Mandatory)]
    [string]$ConnectionString
)

# Import the module
$modulePath = Join-Path $PSScriptRoot "..\src\PSCryptoChat\PSCryptoChat.psd1"
Import-Module $modulePath -Force

Write-Host "=== PSCryptoChat Basic Example - Peer ===" -ForegroundColor Cyan
Write-Host ""

# Create an anonymous identity
Write-Host "[1] Creating anonymous identity..." -ForegroundColor Yellow
$identity = New-CryptoIdentity -Anonymous
Write-Host "    Identity ID: $($identity.Id)" -ForegroundColor Gray

# Connect to host
Write-Host "[2] Connecting to host..." -ForegroundColor Yellow
$session = Start-ChatSession -Peer $ConnectionString

Write-Host ""
Write-Host "Connected!" -ForegroundColor Green
Write-Host ""

# Display session info
Write-Host "Session Info:" -ForegroundColor Yellow
$session | Format-List

Write-Host ""
Write-Host "[!] IMPORTANT: Verify safety numbers with your peer!" -ForegroundColor Red
Write-Host "    Both sides should see the same number." -ForegroundColor Yellow
Write-Host ""

Write-Host "To send messages:" -ForegroundColor Cyan
Write-Host '  Send-ChatMessage "Hello, host!"' -ForegroundColor White
Write-Host ""
Write-Host "To receive messages:" -ForegroundColor Cyan
Write-Host '  Receive-ChatMessage -Continuous' -ForegroundColor White
Write-Host ""
Write-Host "To close the session:" -ForegroundColor Cyan
Write-Host '  Stop-ChatSession' -ForegroundColor White
