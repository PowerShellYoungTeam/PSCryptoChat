# Simple crypto test
$ec = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve]::NamedCurves.nistP256)
Write-Host "Created: $($null -ne $ec)"
Write-Host "Type: $($ec.GetType().FullName)"
Write-Host "KeySize: $($ec.KeySize)"
