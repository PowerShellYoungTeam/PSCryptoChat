using module ..\src\PSCryptoChat\PSCryptoChat.psm1

Write-Host "=== PSCryptoChat Quick Test ===" -ForegroundColor Cyan

# Test 1: Key Generation
Write-Host "`n[Test 1] Key Generation" -ForegroundColor Yellow
try {
    $keyPair = [CryptoProvider]::NewKeyPair()
    Write-Host "  Key pair created, size: $($keyPair.KeySize) bits" -ForegroundColor Green
    $keyPair.Dispose()
}
catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
}

# Test 2: Key Export/Import
Write-Host "`n[Test 2] Key Export/Import" -ForegroundColor Yellow
try {
    $kp = [CryptoProvider]::NewKeyPair()
    $exported = [CryptoProvider]::ExportPublicKey($kp)
    Write-Host "  Exported public key: $($exported.Substring(0, 40))..." -ForegroundColor Green

    $imported = [CryptoProvider]::ImportPublicKey($exported)
    Write-Host "  Imported successfully" -ForegroundColor Green

    $kp.Dispose()
    $imported.Dispose()
}
catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
}

# Test 3: Key Exchange
Write-Host "`n[Test 3] Key Exchange (Alice & Bob)" -ForegroundColor Yellow
try {
    $alice = [CryptoProvider]::NewKeyPair()
    $bob = [CryptoProvider]::NewKeyPair()

    $alicePublic = [CryptoProvider]::ExportPublicKey($alice)
    $bobPublic = [CryptoProvider]::ExportPublicKey($bob)

    $aliceSecret = [CryptoProvider]::DeriveSharedSecret($alice, $bobPublic)
    $bobSecret = [CryptoProvider]::DeriveSharedSecret($bob, $alicePublic)

    $match = [Convert]::ToBase64String($aliceSecret) -eq [Convert]::ToBase64String($bobSecret)

    if ($match) {
        Write-Host "  Shared secrets MATCH" -ForegroundColor Green
    } else {
        Write-Host "  Shared secrets DO NOT MATCH" -ForegroundColor Red
    }

    [CryptoProvider]::ClearBytes($aliceSecret)
    [CryptoProvider]::ClearBytes($bobSecret)
    $alice.Dispose()
    $bob.Dispose()
}
catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
}

# Test 4: Encryption/Decryption
Write-Host "`n[Test 4] Encryption/Decryption" -ForegroundColor Yellow
try {
    $key = [CryptoProvider]::GetRandomBytes(32)
    $message = "Hello, PSCryptoChat!"

    $encrypted = [CryptoProvider]::EncryptMessage($message, $key)
    Write-Host "  Encrypted: $($encrypted.Substring(0, 40))..." -ForegroundColor Gray

    $decrypted = [CryptoProvider]::DecryptMessage($encrypted, $key)

    if ($message -eq $decrypted) {
        Write-Host "  Decrypted correctly: $decrypted" -ForegroundColor Green
    } else {
        Write-Host "  Decryption MISMATCH" -ForegroundColor Red
    }

    [CryptoProvider]::ClearBytes($key)
}
catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
}

# Test 5: Identity Creation
Write-Host "`n[Test 5] Identity Creation" -ForegroundColor Yellow
try {
    $identity = [CryptoIdentity]::new([IdentityMode]::Anonymous)
    Write-Host "  Identity ID: $($identity.Id)" -ForegroundColor Green
    Write-Host "  Mode: $($identity.Mode)" -ForegroundColor Green
    Write-Host "  Public Key: $($identity.PublicKey.Substring(0, 40))..." -ForegroundColor Gray
    $identity.Dispose()
}
catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
}

Write-Host "`n=== All Tests Complete ===" -ForegroundColor Cyan
