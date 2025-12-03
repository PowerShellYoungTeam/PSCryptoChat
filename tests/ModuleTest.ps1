using module ..\src\PSCryptoChat\PSCryptoChat.psm1

Write-Host "=== PSCryptoChat Module Test ===" -ForegroundColor Cyan

# Test: Create anonymous identity
Write-Host "`n[Test] New-CryptoIdentity -Anonymous" -ForegroundColor Yellow
$identity = New-CryptoIdentity -Anonymous
Write-Host "  ID: $($identity.Id)" -ForegroundColor Green
Write-Host "  Mode: $($identity.Mode)" -ForegroundColor Green

# Test: Get current identity
Write-Host "`n[Test] Get-CryptoIdentity" -ForegroundColor Yellow
$current = Get-CryptoIdentity
Write-Host "  Current ID: $($current.Id)" -ForegroundColor Green

# Test: Start session (listen mode)
Write-Host "`n[Test] Start-ChatSession -Listen" -ForegroundColor Yellow
try {
    $session = Start-ChatSession -Listen -Port 9999 -Timeout 30
    Write-Host "  Session ID: $($session.SessionId)" -ForegroundColor Green
    Write-Host "  State: $($session.State)" -ForegroundColor Green
    Write-Host "  Local Endpoint: $($session.LocalEndpoint)" -ForegroundColor Green

    # Get connection string
    $connStr = Get-ConnectionString -SessionId $session.SessionId
    Write-Host "  Connection String: $($connStr.Substring(0, [Math]::Min(60, $connStr.Length)))..." -ForegroundColor Gray

    # Stop session
    Stop-ChatSession -SessionId $session.SessionId
    Write-Host "  Session stopped" -ForegroundColor Green
}
catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}

Write-Host "`n=== Module Test Complete ===" -ForegroundColor Cyan
