# Test different ECDH creation methods
Write-Host "=== Testing ECDiffieHellman Creation ===" -ForegroundColor Cyan

# Method 1: Generic Create with curve
Write-Host "`n[1] ECDiffieHellman::Create(curve)" -ForegroundColor Yellow
$ec1 = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256)
Write-Host "    Result: $($null -ne $ec1) - $(if($ec1){$ec1.GetType().Name}else{'NULL'})"

# Method 2: Generic Create() then generate
Write-Host "`n[2] ECDiffieHellman::Create() then GenerateKey" -ForegroundColor Yellow
try {
    $ec2 = [System.Security.Cryptography.ECDiffieHellman]::Create()
    Write-Host "    Create() result: $($null -ne $ec2) - $(if($ec2){$ec2.GetType().Name}else{'NULL'})"
    if ($ec2) {
        $ec2.GenerateKey([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256)
        Write-Host "    After GenerateKey - KeySize: $($ec2.KeySize)"
    }
}
catch {
    Write-Host "    Error: $_" -ForegroundColor Red
}

# Method 3: Windows CNG specific
Write-Host "`n[3] ECDiffieHellmanCng (Windows)" -ForegroundColor Yellow
try {
    $ec3 = [System.Security.Cryptography.ECDiffieHellmanCng]::new(256)
    Write-Host "    Result: KeySize=$($ec3.KeySize)"
    $ec3.Dispose()
}
catch {
    Write-Host "    Error: $_" -ForegroundColor Red
}

# Method 4: CNG with explicit curve
Write-Host "`n[4] ECDiffieHellmanCng with curve" -ForegroundColor Yellow
try {
    $ec4 = [System.Security.Cryptography.ECDiffieHellmanCng]::new([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256)
    Write-Host "    Result: KeySize=$($ec4.KeySize)"
    $ec4.Dispose()
}
catch {
    Write-Host "    Error: $_" -ForegroundColor Red
}

# Check .NET version
Write-Host "`n=== Environment ===" -ForegroundColor Cyan
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
Write-Host ".NET: $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)"
Write-Host "OS: $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
