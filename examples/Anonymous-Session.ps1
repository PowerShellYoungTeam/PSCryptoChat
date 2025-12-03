<#
.SYNOPSIS
    Demonstrates anonymous vs pseudonymous identity modes

.DESCRIPTION
    PSCryptoChat supports two identity modes:

    - Anonymous: Ephemeral keys that exist only in memory. Perfect for
      one-time conversations where you don't want any trace left behind.

    - Pseudonymous: Persistent keys stored in SecretManagement vault.
      Allows others to verify they're talking to the same person across
      multiple sessions.

.EXAMPLE
    .\examples\Anonymous-Session.ps1

.NOTES
    Pseudonymous mode requires Microsoft.PowerShell.SecretManagement
    to be installed and a vault configured.
#>

# Import the module
$modulePath = Join-Path $PSScriptRoot "..\src\PSCryptoChat\PSCryptoChat.psd1"
Import-Module $modulePath -Force

Write-Host "=== PSCryptoChat Identity Modes ===" -ForegroundColor Cyan
Write-Host ""

# ============================================
# Anonymous Identity
# ============================================
Write-Host "--- Anonymous Identity ---" -ForegroundColor Yellow
Write-Host "Keys exist only in memory and are destroyed when disposed." -ForegroundColor Gray
Write-Host ""

$anonIdentity = New-CryptoIdentity -Anonymous
Write-Host "Created anonymous identity:" -ForegroundColor Green
Write-Host "  ID: $($anonIdentity.Id)" -ForegroundColor White
Write-Host "  Mode: $($anonIdentity.Mode)" -ForegroundColor White
Write-Host "  Public Key: $($anonIdentity.PublicKey.Substring(0, 40))..." -ForegroundColor White
Write-Host ""

# Create a second anonymous identity - completely different
$anonIdentity2 = New-CryptoIdentity -Anonymous
Write-Host "Second anonymous identity (different keys!):" -ForegroundColor Green
Write-Host "  ID: $($anonIdentity2.Id)" -ForegroundColor White
Write-Host ""

Write-Host "Anonymous identities cannot be saved:" -ForegroundColor Yellow
Write-Host '  Export-CryptoIdentity $anonIdentity -Name "test"  # This would fail' -ForegroundColor Gray
Write-Host ""

# ============================================
# Pseudonymous Identity
# ============================================
Write-Host "--- Pseudonymous Identity ---" -ForegroundColor Yellow
Write-Host "Keys can be saved to SecretManagement vault for reuse." -ForegroundColor Gray
Write-Host ""

# Check if SecretManagement is available
$secretMgmtAvailable = Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement

if ($secretMgmtAvailable) {
    Write-Host "SecretManagement is available." -ForegroundColor Green
    Write-Host ""
    Write-Host "To create and save a pseudonymous identity:" -ForegroundColor Cyan
    Write-Host '  $identity = New-CryptoIdentity -Name "MyIdentity"' -ForegroundColor White
    Write-Host '  # Identity is automatically saved to vault' -ForegroundColor Gray
    Write-Host ""
    Write-Host "To retrieve it later:" -ForegroundColor Cyan
    Write-Host '  $identity = Get-CryptoIdentity -Name "MyIdentity"' -ForegroundColor White
    Write-Host ""
    Write-Host "To list saved identities:" -ForegroundColor Cyan
    Write-Host '  Get-CryptoIdentity -List' -ForegroundColor White
}
else {
    Write-Host "SecretManagement is NOT installed." -ForegroundColor Red
    Write-Host "To enable pseudonymous identities, install it:" -ForegroundColor Yellow
    Write-Host '  Install-Module Microsoft.PowerShell.SecretManagement' -ForegroundColor White
    Write-Host '  Install-Module Microsoft.PowerShell.SecretStore  # or another vault' -ForegroundColor White
}

Write-Host ""
Write-Host "--- When to Use Each Mode ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "Use ANONYMOUS when:" -ForegroundColor Green
Write-Host "  - You want maximum privacy" -ForegroundColor White
Write-Host "  - One-time conversations" -ForegroundColor White
Write-Host "  - You don't need the peer to recognize you later" -ForegroundColor White
Write-Host ""
Write-Host "Use PSEUDONYMOUS when:" -ForegroundColor Green
Write-Host "  - You chat with the same people regularly" -ForegroundColor White
Write-Host "  - You want peers to verify your identity across sessions" -ForegroundColor White
Write-Host "  - Building ongoing trusted relationships" -ForegroundColor White

# Cleanup
$anonIdentity.Dispose()
$anonIdentity2.Dispose()

Write-Host ""
Write-Host "Identities disposed - keys cleared from memory." -ForegroundColor Gray
