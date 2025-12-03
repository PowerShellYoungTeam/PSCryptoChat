<#
.SYNOPSIS
    Public functions for peer discovery

.DESCRIPTION
    Cmdlets for finding peers via manual exchange or mDNS.
#>

function Find-ChatPeer {
    <#
    .SYNOPSIS
        Discover peers on local network via mDNS

    .PARAMETER Timeout
        Discovery timeout in seconds (default: 5)

    .EXAMPLE
        Find-ChatPeer
        Discovers peers on local network
    #>
    [CmdletBinding()]
    param(
        [int]$Timeout = 5
    )

    Write-Host "Scanning local network for PSCryptoChat peers..." -ForegroundColor Cyan

    $discovery = [PeerDiscovery]::new($true)
    try {
        $discovery.Start()
        $peers = $discovery.FindPeers($Timeout * 1000)
    }
    finally {
        $discovery.Stop()
    }

    if ($peers.Count -eq 0) {
        Write-Host "No peers found" -ForegroundColor Yellow
        return @()
    }

    Write-Host "Found $($peers.Count) peer(s):" -ForegroundColor Green

    return $peers | ForEach-Object {
        [PSCustomObject]@{
            Name             = $_.Name
            HostAddress      = $_.Host
            Port             = $_.Port
            ConnectionString = "$($_.Host):$($_.Port):$($_.PublicKey)"
        }
    }
}
