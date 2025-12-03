<#
.SYNOPSIS
    Peer discovery - Manual and mDNS

.DESCRIPTION
    Supports two discovery modes:
    1. Manual: Exchange connection strings out-of-band
    2. mDNS: Discover peers on local network

.NOTES
    No bootstrap servers - fully decentralized
#>

using namespace System.Net
using namespace System.Net.Sockets

class ManualDiscovery {
    <#
    .SYNOPSIS
        Generate connection string for manual exchange
    #>
    static [string]CreateConnectionString([string]$Endpoint, [string]$PublicKey) {
        # Format: host:port:base64publickey
        return "$Endpoint`:$PublicKey"
    }

    <#
    .SYNOPSIS
        Parse connection string from peer
    #>
    static [hashtable]ParseConnectionString([string]$ConnectionString) {
        # Expected format: host:port:base64publickey
        $lastColonIndex = $ConnectionString.LastIndexOf(':')

        if ($lastColonIndex -lt 0) {
            throw "Invalid connection string format"
        }

        # Find the second-to-last colon (between host:port and publickey)
        $endpointPart = $ConnectionString.Substring(0, $lastColonIndex)
        $publicKey = $ConnectionString.Substring($lastColonIndex + 1)

        # Now parse host:port
        $colonIndex = $endpointPart.LastIndexOf(':')
        if ($colonIndex -lt 0) {
            throw "Invalid connection string format - missing port"
        }

        $host = $endpointPart.Substring(0, $colonIndex)
        $port = [int]$endpointPart.Substring($colonIndex + 1)

        return @{
            Host      = $host
            Port      = $port
            PublicKey = $publicKey
        }
    }
}

class MdnsDiscovery {
    static [string]$ServiceType = "_pscryptochat._udp.local"
    static [int]$MdnsPort = 5353
    static [string]$MdnsAddress = "224.0.0.251"

    hidden [UdpClient]$Client
    hidden [bool]$IsRunning

    # Start mDNS discovery
    [void]Start() {
        $this.Client = [UdpClient]::new()
        $this.Client.Client.SetSocketOption(
            [SocketOptionLevel]::Socket,
            [SocketOptionName]::ReuseAddress,
            $true
        )
        $this.Client.Client.Bind([IPEndPoint]::new([IPAddress]::Any, [MdnsDiscovery]::MdnsPort))

        # Join multicast group
        $this.Client.JoinMulticastGroup([IPAddress]::Parse([MdnsDiscovery]::MdnsAddress))
        $this.IsRunning = $true
    }

    # Stop mDNS discovery
    [void]Stop() {
        $this.IsRunning = $false
        if ($null -ne $this.Client) {
            $this.Client.DropMulticastGroup([IPAddress]::Parse([MdnsDiscovery]::MdnsAddress))
            $this.Client.Close()
            $this.Client = $null
        }
    }

    # Announce presence on network
    [void]Announce([string]$ServiceName, [int]$Port, [string]$PublicKey) {
        # Simplified mDNS announcement (full implementation would use proper DNS packet format)
        $announcement = @{
            Service   = [MdnsDiscovery]::ServiceType
            Name      = $ServiceName
            Port      = $Port
            PublicKey = $PublicKey
            Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        } | ConvertTo-Json -Compress

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($announcement)
        $endpoint = [IPEndPoint]::new(
            [IPAddress]::Parse([MdnsDiscovery]::MdnsAddress),
            [MdnsDiscovery]::MdnsPort
        )

        $this.Client.Send($bytes, $bytes.Length, $endpoint) | Out-Null
    }

    # Listen for announcements (returns array of discovered peers)
    [hashtable[]]Listen([int]$TimeoutMs = 5000) {
        $peers = @()
        $endTime = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)

        $this.Client.Client.ReceiveTimeout = [Math]::Min($TimeoutMs, 1000)

        while ([DateTime]::UtcNow -lt $endTime) {
            try {
                $remoteEP = [IPEndPoint]::new([IPAddress]::Any, 0)
                $data = $this.Client.Receive([ref]$remoteEP)
                $message = [System.Text.Encoding]::UTF8.GetString($data)

                $parsed = $message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -ne $parsed -and $parsed.Service -eq [MdnsDiscovery]::ServiceType) {
                    $peers += @{
                        Name      = $parsed.Name
                        Host      = $remoteEP.Address.ToString()
                        Port      = $parsed.Port
                        PublicKey = $parsed.PublicKey
                    }
                }
            }
            catch [SocketException] {
                # Timeout - continue
            }
        }

        return $peers
    }
}

class PeerDiscovery {
    [MdnsDiscovery]$Mdns
    [bool]$MdnsEnabled

    PeerDiscovery([bool]$EnableMdns = $true) {
        $this.MdnsEnabled = $EnableMdns
        if ($EnableMdns) {
            $this.Mdns = [MdnsDiscovery]::new()
        }
    }

    # Start discovery services
    [void]Start() {
        if ($this.MdnsEnabled -and $null -ne $this.Mdns) {
            $this.Mdns.Start()
        }
    }

    # Stop discovery services
    [void]Stop() {
        if ($null -ne $this.Mdns) {
            $this.Mdns.Stop()
        }
    }

    # Announce ourselves
    [void]Announce([string]$Name, [int]$Port, [string]$PublicKey) {
        if ($this.MdnsEnabled -and $null -ne $this.Mdns) {
            $this.Mdns.Announce($Name, $Port, $PublicKey)
        }
    }

    # Find peers (combines manual + mDNS)
    [hashtable[]]FindPeers([int]$TimeoutMs = 5000) {
        $peers = @()

        if ($this.MdnsEnabled -and $null -ne $this.Mdns) {
            $peers += $this.Mdns.Listen($TimeoutMs)
        }

        return $peers
    }

    # Parse manual connection string
    [hashtable]ParseManualConnection([string]$ConnectionString) {
        return [ManualDiscovery]::ParseConnectionString($ConnectionString)
    }
}
