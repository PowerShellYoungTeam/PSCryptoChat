# .NET P2P Libraries and NAT Traversal

## Executive Summary

This document evaluates NuGet packages for peer-to-peer networking, NAT traversal (STUN/TURN/ICE), and DHT implementations suitable for PSCryptoChat.

---

## 1. Library Evaluation Matrix

### NAT Traversal / STUN Libraries

| Library | Downloads | STUN | TURN | ICE | UDP Hole Punch | .NET Version | Active |
|---------|-----------|------|------|-----|----------------|--------------|--------|
| **SIPSorcery** | 898K | ✅ | ✅ | ✅ | ✅ | .NET 6+ | ✅ Yes |
| **Stun.Net** | 27K | ✅ | ❌ | ❌ | ⚠️ Manual | .NET Standard 2.0 | ⚠️ Limited |
| **Libplanet.Stun** | 704K | ✅ | ✅ | ❌ | ❌ | .NET 6+ | ✅ Yes |

### P2P / DHT Libraries

| Library | Downloads | DHT | P2P TCP | P2P UDP | Protocol | Active |
|---------|-----------|-----|---------|---------|----------|--------|
| **MonoTorrent** | 673K | ✅ Kademlia | ✅ | ✅ | BitTorrent | ✅ Yes |
| **Waher.Networking.PeerToPeer** | 151K | ❌ | ✅ | ✅ | Custom | ✅ Yes |
| **SocketJack** | <10K | ❌ | ✅ | ❌ | Custom | ⚠️ Limited |

---

## 2. Recommended: SIPSorcery

### Overview
SIPSorcery is a mature, full-featured library originally designed for VoIP/WebRTC but provides excellent NAT traversal capabilities that can be repurposed for general P2P communication.

### Installation
```powershell
Install-Package SIPSorcery
```

### Key Features
- Full ICE implementation (RFC 8445)
- STUN client and server
- TURN client support
- UDP and TCP transports
- WebRTC data channels

### STUN Client Example
```powershell
# Using SIPSorcery STUN Client
Add-Type -Path "path\to\SIPSorcery.dll"

function Get-PublicEndpoint {
    param(
        [string]$StunServer = "stun.l.google.com",
        [int]$StunPort = 19302
    )

    $stunClient = [SIPSorcery.Net.STUNClient]::new("stun:$StunServer`:$StunPort")

    try {
        $iceServer = $stunClient.ResolveStunServer(5000) | Wait-Task

        if ($null -eq $iceServer -or $null -eq $iceServer.ServerEndPoint) {
            throw "Could not resolve STUN server"
        }

        $publicIP = [SIPSorcery.Net.STUNClient]::GetPublicIPEndPoint(
            $StunServer,
            $StunPort
        )

        return @{
            PublicIP = $publicIP.Address.ToString()
            PublicPort = $publicIP.Port
            StunServer = $StunServer
        }
    }
    catch {
        Write-Error "STUN request failed: $_"
        return $null
    }
}

# Usage
$myPublicEndpoint = Get-PublicEndpoint -StunServer "stun.l.google.com"
Write-Host "My public endpoint: $($myPublicEndpoint.PublicIP):$($myPublicEndpoint.PublicPort)"
```

### ICE Candidate Gathering
```powershell
function Start-ICECandidateGathering {
    param(
        [string[]]$IceServers = @(
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302"
        )
    )

    # Create ICE servers list
    $rtcIceServers = [System.Collections.Generic.List[SIPSorcery.Net.RTCIceServer]]::new()
    foreach ($server in $IceServers) {
        $rtcIceServers.Add([SIPSorcery.Net.RTCIceServer]::Parse($server))
    }

    # Create RTP ICE channel
    $iceChannel = [SIPSorcery.Net.RtpIceChannel]::new(
        $null,  # Bind address (null = any)
        [SIPSorcery.Net.RTCIceComponent]::rtp,
        $rtcIceServers,
        [SIPSorcery.Net.RTCIceTransportPolicy]::all,
        $false  # Include all interface addresses
    )

    # Event handlers
    $iceChannel.add_OnIceCandidate({
        param($candidate)
        Write-Host "ICE Candidate: $($candidate.type) $($candidate.address):$($candidate.port)" -ForegroundColor Cyan
    })

    $iceChannel.add_OnIceGatheringStateChange({
        param($state)
        Write-Host "ICE Gathering State: $state" -ForegroundColor Yellow
    })

    $iceChannel.add_OnIceConnectionStateChange({
        param($state)
        Write-Host "ICE Connection State: $state" -ForegroundColor Green
    })

    # Start gathering
    $iceChannel.StartGathering()

    return $iceChannel
}
```

### Full NAT Traversal with ICE
```powershell
class ICENatTraversal {
    [SIPSorcery.Net.RtpIceChannel]$IceChannel
    [string]$LocalUfrag
    [string]$LocalPwd
    [System.Collections.Generic.List[SIPSorcery.Net.RTCIceCandidate]]$LocalCandidates

    ICENatTraversal() {
        $this.LocalCandidates = [System.Collections.Generic.List[SIPSorcery.Net.RTCIceCandidate]]::new()

        $this.IceChannel = [SIPSorcery.Net.RtpIceChannel]::new(
            $null,
            [SIPSorcery.Net.RTCIceComponent]::rtp,
            $null,
            [SIPSorcery.Net.RTCIceTransportPolicy]::all,
            $false
        )

        $this.LocalUfrag = $this.IceChannel.LocalIceUser
        $this.LocalPwd = $this.IceChannel.LocalIcePassword

        $self = $this
        $this.IceChannel.add_OnIceCandidate({
            param($candidate)
            $self.LocalCandidates.Add($candidate)
        })
    }

    [void]StartGathering() {
        $this.IceChannel.StartGathering()
    }

    [hashtable]GetLocalDescription() {
        return @{
            ufrag = $this.LocalUfrag
            pwd = $this.LocalPwd
            candidates = @($this.LocalCandidates | ForEach-Object {
                @{
                    type = $_.type.ToString()
                    address = $_.address
                    port = $_.port
                    protocol = $_.protocol.ToString()
                    priority = $_.priority
                }
            })
        }
    }

    [void]AddRemoteCandidate([hashtable]$CandidateInfo) {
        $candidate = [SIPSorcery.Net.RTCIceCandidateInit]::new()
        $candidate.candidate = "candidate:1 1 $($CandidateInfo.protocol) $($CandidateInfo.priority) $($CandidateInfo.address) $($CandidateInfo.port) typ $($CandidateInfo.type)"

        $this.IceChannel.AddRemoteCandidate($candidate)
    }

    [void]SetRemoteCredentials([string]$Ufrag, [string]$Pwd) {
        $this.IceChannel.SetRemoteCredentials($Ufrag, $Pwd)
    }

    [void]StartConnectivity() {
        # Trigger connectivity checks
        $this.IceChannel.SetRole([SIPSorcery.Net.IceRoleEnum]::controlled)
    }
}
```

---

## 3. Alternative: Stun.Net

### Overview
Lighter-weight STUN-only library, good for simple NAT detection.

### Installation
```powershell
Install-Package Stun.Net
```

### Basic Usage
```powershell
Add-Type -Path "path\to\Stun.Net.dll"

function Test-StunBinding {
    param(
        [string]$Server = "stun.l.google.com",
        [int]$Port = 19302
    )

    $client = [Stun.StunClient]::new($Server, $Port)
    $result = $client.Query()

    return @{
        Success = $result.NatType -ne [Stun.NatType]::Unknown
        NatType = $result.NatType.ToString()
        PublicEndpoint = $result.PublicEndPoint
        LocalEndpoint = $result.LocalEndPoint
    }
}

# NAT Types detected:
# - OpenInternet
# - FullCone
# - RestrictedCone
# - PortRestrictedCone
# - Symmetric
# - UdpBlocked
```

### NAT Type Detection
```powershell
function Get-NatType {
    $servers = @(
        @{ Host = "stun.l.google.com"; Port = 19302 },
        @{ Host = "stun1.l.google.com"; Port = 19302 },
        @{ Host = "stun.stunprotocol.org"; Port = 3478 }
    )

    foreach ($server in $servers) {
        $result = Test-StunBinding -Server $server.Host -Port $server.Port

        if ($result.Success) {
            Write-Host "NAT Type: $($result.NatType)"
            Write-Host "Public: $($result.PublicEndpoint)"
            Write-Host "Local: $($result.LocalEndpoint)"

            # Determine connectivity capability
            $canPeerToPeer = $result.NatType -in @(
                'OpenInternet',
                'FullCone',
                'RestrictedCone',
                'PortRestrictedCone'
            )

            return @{
                NatType = $result.NatType
                CanDirectP2P = $canPeerToPeer
                NeedsTurn = -not $canPeerToPeer
                PublicEndpoint = $result.PublicEndpoint
            }
        }
    }

    return @{
        NatType = "Unknown"
        CanDirectP2P = $false
        NeedsTurn = $true
    }
}
```

---

## 4. DHT: MonoTorrent

### Overview
MonoTorrent provides a Kademlia DHT implementation that can be repurposed for peer discovery.

### Installation
```powershell
Install-Package MonoTorrent
```

### DHT Node Example
```powershell
# Note: MonoTorrent DHT is tightly coupled to BitTorrent
# For PSCryptoChat, consider a simplified Kademlia implementation

Add-Type -Path "path\to\MonoTorrent.dll"

# Using MonoTorrent's DHT engine
$dhtListener = [MonoTorrent.Dht.DhtListener]::new(
    [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 6881)
)

$dhtEngine = [MonoTorrent.Dht.DhtEngine]::new($dhtListener)

# Bootstrap from known nodes
$bootstrapNodes = @(
    [System.Net.IPEndPoint]::new(
        [System.Net.IPAddress]::Parse("67.215.246.10"),
        6881
    )  # router.bittorrent.com
)

$dhtEngine.Start($bootstrapNodes)

# Wait for nodes
Start-Sleep -Seconds 10
Write-Host "DHT nodes: $($dhtEngine.State)"
```

---

## 5. Custom UDP Hole Punching

Since no direct UDP hole punching library exists, here's a custom implementation:

```powershell
class UdpHolePuncher {
    [System.Net.Sockets.UdpClient]$Client
    [System.Net.IPEndPoint]$LocalEndpoint
    [System.Net.IPEndPoint]$PublicEndpoint
    [System.Net.IPEndPoint]$PeerPublicEndpoint
    [int]$PunchAttempts = 10
    [int]$PunchInterval = 100  # ms

    UdpHolePuncher([int]$LocalPort = 0) {
        $this.Client = [System.Net.Sockets.UdpClient]::new($LocalPort)
        $this.LocalEndpoint = $this.Client.Client.LocalEndPoint
    }

    [bool]DiscoverPublicEndpoint([string]$StunServer = "stun.l.google.com", [int]$StunPort = 19302) {
        # Send STUN binding request
        $stunRequest = $this.CreateStunBindingRequest()

        $serverEP = [System.Net.IPEndPoint]::new(
            [System.Net.Dns]::GetHostAddresses($StunServer)[0],
            $StunPort
        )

        $this.Client.Send($stunRequest, $stunRequest.Length, $serverEP) | Out-Null

        # Wait for response
        $this.Client.Client.ReceiveTimeout = 3000
        $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

        try {
            $response = $this.Client.Receive([ref]$remoteEP)
            $this.PublicEndpoint = $this.ParseStunResponse($response)
            return $null -ne $this.PublicEndpoint
        }
        catch {
            return $false
        }
    }

    [void]PunchHole([System.Net.IPEndPoint]$PeerEndpoint) {
        $this.PeerPublicEndpoint = $PeerEndpoint

        # Send multiple packets to punch hole
        $punchPacket = [System.Text.Encoding]::UTF8.GetBytes("PUNCH")

        for ($i = 0; $i -lt $this.PunchAttempts; $i++) {
            $this.Client.Send($punchPacket, $punchPacket.Length, $PeerEndpoint) | Out-Null
            Start-Sleep -Milliseconds $this.PunchInterval
        }
    }

    [bool]WaitForConnection([int]$TimeoutMs = 5000) {
        $this.Client.Client.ReceiveTimeout = $TimeoutMs
        $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

        try {
            $data = $this.Client.Receive([ref]$remoteEP)
            $message = [System.Text.Encoding]::UTF8.GetString($data)

            if ($message -eq "PUNCH" -or $message -eq "PONG") {
                # Send confirmation
                $pong = [System.Text.Encoding]::UTF8.GetBytes("PONG")
                $this.Client.Send($pong, $pong.Length, $remoteEP) | Out-Null
                return $true
            }
        }
        catch {
            return $false
        }

        return $false
    }

    hidden [byte[]]CreateStunBindingRequest() {
        # STUN binding request header
        $header = [byte[]]@(
            0x00, 0x01,  # Binding Request
            0x00, 0x00,  # Message length
            0x21, 0x12, 0xa4, 0x42  # Magic cookie
        )

        # Transaction ID (12 bytes)
        $txId = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($txId)

        return $header + $txId
    }

    hidden [System.Net.IPEndPoint]ParseStunResponse([byte[]]$Response) {
        if ($Response.Length -lt 20) { return $null }

        # Check for success response
        if ($Response[0] -ne 0x01 -or $Response[1] -ne 0x01) { return $null }

        # Parse XOR-MAPPED-ADDRESS attribute
        $offset = 20  # Skip header
        while ($offset -lt $Response.Length - 4) {
            $attrType = [BitConverter]::ToUInt16([byte[]]@($Response[$offset + 1], $Response[$offset]), 0)
            $attrLen = [BitConverter]::ToUInt16([byte[]]@($Response[$offset + 3], $Response[$offset + 2]), 0)

            if ($attrType -eq 0x0020) {  # XOR-MAPPED-ADDRESS
                $family = $Response[$offset + 5]
                $port = [BitConverter]::ToUInt16([byte[]]@($Response[$offset + 7], $Response[$offset + 6]), 0) -bxor 0x2112

                if ($family -eq 0x01) {  # IPv4
                    $ip = [byte[]]@(
                        $Response[$offset + 8] -bxor 0x21,
                        $Response[$offset + 9] -bxor 0x12,
                        $Response[$offset + 10] -bxor 0xa4,
                        $Response[$offset + 11] -bxor 0x42
                    )
                    return [System.Net.IPEndPoint]::new(
                        [System.Net.IPAddress]::new($ip),
                        $port
                    )
                }
            }

            $offset += 4 + $attrLen
            if ($attrLen % 4 -ne 0) { $offset += 4 - ($attrLen % 4) }  # Padding
        }

        return $null
    }
}

# Usage example
$puncher = [UdpHolePuncher]::new(9000)

# Discover our public endpoint
if ($puncher.DiscoverPublicEndpoint()) {
    Write-Host "Our public endpoint: $($puncher.PublicEndpoint)"

    # Exchange endpoints with peer (via bootstrap server, etc.)
    # Then punch hole to peer
    # $puncher.PunchHole($peerPublicEndpoint)
    # $puncher.WaitForConnection()
}
```

---

## 6. P2P Connection Manager

Combining all components:

```powershell
class P2PConnectionManager {
    [UdpHolePuncher]$Puncher
    [BootstrapClient]$Bootstrap
    [hashtable]$ConnectedPeers = @{}
    [string]$MyPeerId

    P2PConnectionManager([string[]]$BootstrapUrls) {
        $this.MyPeerId = [guid]::NewGuid().ToString("N")
        $this.Puncher = [UdpHolePuncher]::new()
        $this.Bootstrap = [BootstrapClient]::new($BootstrapUrls)
    }

    [void]Start() {
        # Discover our public endpoint
        if (-not $this.Puncher.DiscoverPublicEndpoint()) {
            throw "Could not discover public endpoint via STUN"
        }

        Write-Host "Public endpoint: $($this.Puncher.PublicEndpoint)" -ForegroundColor Green

        # Announce to bootstrap
        $this.Bootstrap.Announce($this.MyPeerId, @(
            "udp://$($this.Puncher.PublicEndpoint)"
        ))

        # Start listening for connections
        $this.StartListening()
    }

    [void]ConnectToPeer([hashtable]$PeerInfo) {
        Write-Host "Connecting to peer $($PeerInfo.id)..." -ForegroundColor Cyan

        # Parse peer endpoint
        $endpoint = $PeerInfo.endpoints | Where-Object { $_ -like "udp://*" } | Select-Object -First 1
        if (-not $endpoint) { throw "No UDP endpoint for peer" }

        $uri = [System.Uri]::new($endpoint)
        $peerEP = [System.Net.IPEndPoint]::new(
            [System.Net.IPAddress]::Parse($uri.Host),
            $uri.Port
        )

        # Punch hole
        $this.Puncher.PunchHole($peerEP)

        # Wait for connection
        if ($this.Puncher.WaitForConnection(10000)) {
            Write-Host "Connected to peer!" -ForegroundColor Green
            $this.ConnectedPeers[$PeerInfo.id] = @{
                Endpoint = $peerEP
                Connected = $true
            }
        }
        else {
            Write-Host "Failed to connect to peer" -ForegroundColor Red
        }
    }

    hidden [void]StartListening() {
        # Background listener for incoming connections
        $job = Start-ThreadJob -ScriptBlock {
            param($Puncher)

            while ($true) {
                if ($Puncher.WaitForConnection(1000)) {
                    Write-Output "Incoming connection accepted"
                }
            }
        } -ArgumentList $this.Puncher
    }
}
```

---

## 7. TURN Fallback (via SIPSorcery)

For symmetric NAT situations:

```powershell
function Connect-ViaTurn {
    param(
        [string]$TurnServer,
        [string]$Username,
        [string]$Password,
        [System.Net.IPEndPoint]$PeerEndpoint
    )

    # Parse TURN URI
    $turnUri = [SIPSorcery.Net.STUNUri]::ParseSTUNUri("turn:$TurnServer")

    # Create TURN client
    $turnClient = [SIPSorcery.Net.TurnClient]::new(
        $turnUri,
        $Username,
        $Password
    )

    # Allocate relay
    $allocateResult = $turnClient.Allocate() | Wait-Task

    if ($allocateResult -ne [System.Net.Sockets.SocketError]::Success) {
        throw "TURN allocation failed: $allocateResult"
    }

    Write-Host "TURN relay allocated: $($turnClient.RelayEndPoint)"

    # Create permission for peer
    $turnClient.CreatePermission($PeerEndpoint) | Wait-Task

    # Send data through relay
    return $turnClient
}
```

---

## 8. Public STUN/TURN Servers

### Free STUN Servers
```powershell
$stunServers = @(
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
    "stun:stun3.l.google.com:19302",
    "stun:stun4.l.google.com:19302",
    "stun:stun.stunprotocol.org:3478",
    "stun:stun.voip.blackberry.com:3478"
)
```

### Free TURN Servers (Limited)
```powershell
# Metered TURN (requires account, free tier available)
# https://www.metered.ca/tools/openrelay/

$turnServers = @(
    @{
        urls = "turn:a.relay.metered.ca:80"
        username = "your-username"
        credential = "your-credential"
    }
)
```

### Self-Hosted TURN (Coturn)
```bash
# Docker
docker run -d --network=host coturn/coturn \
    -n --log-file=stdout \
    --min-port=49152 --max-port=65535 \
    --realm=pscryptochat.local \
    --user=pschat:password123
```

---

## 9. Recommended Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   PSCryptoChat P2P Stack                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │               Application Layer                          │   │
│  │  • Message encryption/decryption                        │   │
│  │  • Double Ratchet protocol                              │   │
│  └────────────────────────────┬────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼────────────────────────────┐   │
│  │            Connection Manager                            │   │
│  │  • Peer lifecycle management                            │   │
│  │  • Connection state machine                             │   │
│  │  • Reconnection logic                                   │   │
│  └────────────────────────────┬────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼────────────────────────────┐   │
│  │             NAT Traversal Layer                          │   │
│  │  ┌──────────────┬──────────────┬──────────────────┐     │   │
│  │  │ Direct UDP   │ UDP Hole     │ TURN Relay       │     │   │
│  │  │ (Open NAT)   │ Punch        │ (Fallback)       │     │   │
│  │  └──────────────┴──────────────┴──────────────────┘     │   │
│  └────────────────────────────┬────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼────────────────────────────┐   │
│  │              Discovery Layer                             │   │
│  │  ┌──────────────┬──────────────┬──────────────────┐     │   │
│  │  │ Bootstrap    │ mDNS Local   │ Peer Exchange    │     │   │
│  │  │ Servers      │ Discovery    │ (PEX)            │     │   │
│  │  └──────────────┴──────────────┴──────────────────┘     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Libraries Used:                                                │
│  • SIPSorcery: STUN/TURN/ICE                                   │
│  • Custom: UDP hole punching, Bootstrap client                 │
│  • System.Net.Sockets: Core networking                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. References

- [SIPSorcery GitHub](https://github.com/sipsorcery-org/sipsorcery)
- [MonoTorrent GitHub](https://github.com/alanmcgovern/monotorrent)
- [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
- [RFC 5389 - STUN](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 5766 - TURN](https://datatracker.ietf.org/doc/html/rfc5766)
- [NuGet - SIPSorcery](https://www.nuget.org/packages/SIPSorcery)
- [NuGet - Stun.Net](https://www.nuget.org/packages/Stun.Net)
