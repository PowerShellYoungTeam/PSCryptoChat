<#
.SYNOPSIS
    Demonstrates safety number verification between peers

.DESCRIPTION
    Safety numbers are a critical security feature that allows two peers
    to verify they have established a secure connection without a
    man-in-the-middle (MITM) attack.

    Both peers compute the same safety number from their combined public
    keys. If the numbers match (verified out-of-band, e.g., voice call),
    the connection is secure.

.EXAMPLE
    .\examples\Verify-SafetyNumbers.ps1

.NOTES
    Always verify safety numbers through a separate communication channel!
    If they don't match, someone may be intercepting your connection.
#>

# Import the module
$modulePath = Join-Path $PSScriptRoot "..\src\PSCryptoChat\PSCryptoChat.psd1"
Import-Module $modulePath -Force

Write-Host "=== PSCryptoChat Safety Number Verification ===" -ForegroundColor Cyan
Write-Host ""

# Simulate two peers
Write-Host "Simulating two peers (Alice and Bob)..." -ForegroundColor Yellow
Write-Host ""

# Create identities for both peers
$alice = New-CryptoIdentity -Anonymous
$bob = New-CryptoIdentity -Anonymous

Write-Host "Alice's Identity:" -ForegroundColor Green
Write-Host "  ID: $($alice.Id)" -ForegroundColor White
Write-Host "  Public Key: $($alice.PublicKey.Substring(0, 50))..." -ForegroundColor Gray
Write-Host ""

Write-Host "Bob's Identity:" -ForegroundColor Green
Write-Host "  ID: $($bob.Id)" -ForegroundColor White
Write-Host "  Public Key: $($bob.PublicKey.Substring(0, 50))..." -ForegroundColor Gray
Write-Host ""

# Generate safety numbers
Write-Host "--- Computing Safety Numbers ---" -ForegroundColor Yellow
Write-Host ""

# Alice computes safety number using Bob's public key
$aliceSafetyNumber = $alice.GetSafetyNumber($bob.PublicKey)

# Bob computes safety number using Alice's public key
$bobSafetyNumber = $bob.GetSafetyNumber($alice.PublicKey)

Write-Host "Alice's view of safety number:" -ForegroundColor Green
Write-Host "  $aliceSafetyNumber" -ForegroundColor White
Write-Host ""

Write-Host "Bob's view of safety number:" -ForegroundColor Green
Write-Host "  $bobSafetyNumber" -ForegroundColor White
Write-Host ""

# Verify they match
if ($aliceSafetyNumber -eq $bobSafetyNumber) {
    Write-Host "✓ Safety numbers MATCH!" -ForegroundColor Green
    Write-Host "  The connection is secure (no MITM attack)." -ForegroundColor Gray
}
else {
    Write-Host "✗ Safety numbers DO NOT MATCH!" -ForegroundColor Red
    Write-Host "  WARNING: Possible man-in-the-middle attack!" -ForegroundColor Red
}

Write-Host ""
Write-Host "--- How to Verify in Practice ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. After connecting, both peers run:" -ForegroundColor White
Write-Host '   $identity.GetSafetyNumber($session.PeerPublicKey)' -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Compare the numbers through a SEPARATE channel:" -ForegroundColor White
Write-Host "   - Voice/video call (you recognize their voice)" -ForegroundColor Gray
Write-Host "   - In person" -ForegroundColor Gray
Write-Host "   - Pre-established secure channel" -ForegroundColor Gray
Write-Host ""
Write-Host "3. If numbers match: Connection is secure!" -ForegroundColor Green
Write-Host "   If numbers differ: STOP! Possible attack." -ForegroundColor Red
Write-Host ""

# Demonstrate what happens with a MITM
Write-Host "--- Simulating a Man-in-the-Middle Attack ---" -ForegroundColor Yellow
Write-Host ""

$mallory = New-CryptoIdentity -Anonymous
Write-Host "Mallory (attacker) interposes between Alice and Bob..." -ForegroundColor Red
Write-Host ""

# In a MITM, Alice thinks she's talking to Bob but has Mallory's key
$aliceMitmSafetyNumber = $alice.GetSafetyNumber($mallory.PublicKey)

# Bob thinks he's talking to Alice but has Mallory's key
$bobMitmSafetyNumber = $bob.GetSafetyNumber($mallory.PublicKey)

Write-Host "With MITM attack:" -ForegroundColor Red
Write-Host "  Alice sees: $aliceMitmSafetyNumber" -ForegroundColor White
Write-Host "  Bob sees:   $bobMitmSafetyNumber" -ForegroundColor White
Write-Host ""

if ($aliceMitmSafetyNumber -ne $bobMitmSafetyNumber) {
    Write-Host "✓ Safety numbers are DIFFERENT - attack detected!" -ForegroundColor Green
    Write-Host "  This is why verification is critical." -ForegroundColor Gray
}

# Cleanup
$alice.Dispose()
$bob.Dispose()
$mallory.Dispose()

Write-Host ""
Write-Host "Remember: Always verify safety numbers!" -ForegroundColor Cyan
