# Portable Bootstrap Server Design

## Executive Summary

This document outlines design options for portable, disposable bootstrap servers that enable peer discovery without centralized infrastructure. The design draws from BitTorrent DHT, Tor directory authorities, and serverless patterns.

---

## 1. Bootstrap Requirements

### Functional Requirements
- **Peer Introduction**: Help new nodes find existing peers
- **Minimal State**: Store only ephemeral connection info
- **Fast Startup**: Deploy in seconds
- **Graceful Degradation**: Clients work without bootstrap

### Non-Functional Requirements
- **Portable**: Single file/container deployment
- **Disposable**: No persistent data required
- **Secure**: No trust required from clients
- **Low Resources**: Run on minimal hardware

---

## 2. Bootstrap Patterns Comparison

### BitTorrent DHT (BEP 5)

**How it works:**
- Torrent files contain `nodes` key with K closest nodes
- Fallback to hardcoded `router.bittorrent.com:6881`
- Kademlia DHT with 160-bit node IDs
- UDP-based KRPC protocol

**Strengths:**
- Truly decentralized after bootstrap
- Resilient to node churn
- Well-proven at scale

**Weaknesses:**
- Complex to implement
- UDP can be blocked
- Bootstrap nodes see all new joiners

### Tor Directory Authorities

**How it works:**
- 9 hardcoded directory authorities
- Publish relay descriptors and consensus
- Clients fetch via HTTP/HTTPS
- Consensus voting every hour

**Strengths:**
- Strong identity verification
- Detailed relay metadata
- Sophisticated trust model

**Weaknesses:**
- Requires trusted authorities
- Complex infrastructure
- Not suitable for ad-hoc networks

### Matrix Homeserver Discovery

**How it works:**
- `.well-known` delegation at domain root
- SRV records for server discovery
- Identity servers for user lookup

**Strengths:**
- Standard web infrastructure
- DNS-based resilience
- Federation support

**Weaknesses:**
- Requires domain ownership
- DNS can be blocked/poisoned

---

## 3. PSCryptoChat Bootstrap Architecture

### Design Goals

```
┌─────────────────────────────────────────────────────────────────┐
│                    BOOTSTRAP HIERARCHY                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Level 0: Hardcoded Seeds                                │   │
│  │ • Compiled into client                                   │   │
│  │ • Last resort only                                       │   │
│  │ • Well-known community nodes                            │   │
│  └────────────────────────────┬────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼────────────────────────────┐   │
│  │ Level 1: Portable Bootstrap Servers                     │   │
│  │ • User-deployed                                          │   │
│  │ • Ephemeral / disposable                                │   │
│  │ • Provides initial peer list                            │   │
│  └────────────────────────────┬────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼────────────────────────────┐   │
│  │ Level 2: Peer Exchange (PEX)                            │   │
│  │ • Learn peers from connected peers                      │   │
│  │ • Gossip protocol                                       │   │
│  │ • No central infrastructure                             │   │
│  └────────────────────────────┬────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼────────────────────────────┐   │
│  │ Level 3: Direct Connection                              │   │
│  │ • QR code / link sharing                                │   │
│  │ • Local network discovery (mDNS)                        │   │
│  │ • Manual IP entry                                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Bootstrap Protocol

```
Client                          Bootstrap Server
──────                          ────────────────

1. HELLO                   ──────────────────►
   { client_id: <random>,
     supports: ["tcp", "udp"],
     version: "1.0" }

                           ◄──────────────────  2. PEERS
                                                   { peers: [
                                                     { id: ...,
                                                       endpoints: [...],
                                                       last_seen: ... },
                                                     ...
                                                   ],
                                                   bootstrap_id: <id>,
                                                   ttl: 300 }

3. (Connect to peers)

4. ANNOUNCE (optional)     ──────────────────►
   { client_id: ...,
     endpoints: [...] }

                           ◄──────────────────  5. ACK
                                                   { registered: true,
                                                     expires: 300 }
```

---

## 4. Implementation Options

### Option A: PowerShell HTTP Server

**Simplest deployment - single script**

```powershell
# Bootstrap-Server.ps1
param(
    [int]$Port = 8080,
    [int]$PeerTTL = 300,
    [int]$MaxPeers = 100
)

$peers = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:$Port/")
$listener.Start()

Write-Host "Bootstrap server running on port $Port" -ForegroundColor Green

while ($true) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response

    try {
        switch ($request.HttpMethod) {
            "GET" {
                # Return current peer list
                if ($request.Url.LocalPath -eq "/peers") {
                    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

                    # Clean expired peers
                    $expired = $peers.Keys | Where-Object {
                        ($now - $peers[$_].last_seen) -gt $PeerTTL
                    }
                    $expired | ForEach-Object { $peers.TryRemove($_, [ref]$null) }

                    # Return active peers (limit to 50 random)
                    $activePeers = $peers.Values | Get-Random -Count ([Math]::Min(50, $peers.Count))

                    $body = @{
                        peers = @($activePeers)
                        server_time = $now
                        ttl = $PeerTTL
                    } | ConvertTo-Json

                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                elseif ($request.Url.LocalPath -eq "/health") {
                    $body = @{ status = "ok"; peers = $peers.Count } | ConvertTo-Json
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
            }

            "POST" {
                if ($request.Url.LocalPath -eq "/announce") {
                    $reader = [System.IO.StreamReader]::new($request.InputStream)
                    $json = $reader.ReadToEnd()
                    $peer = $json | ConvertFrom-Json

                    # Add/update peer
                    $peerData = @{
                        id = $peer.id
                        endpoints = $peer.endpoints
                        last_seen = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                        ip = $request.RemoteEndPoint.Address.ToString()
                    }

                    if ($peers.Count -lt $MaxPeers) {
                        $peers[$peer.id] = $peerData
                    }

                    $body = @{ registered = $true; expires = $PeerTTL } | ConvertTo-Json
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
            }
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
    finally {
        $response.Close()
    }
}
```

**Usage:**
```powershell
# Start bootstrap server
.\Bootstrap-Server.ps1 -Port 8080

# Or as background job
Start-Job -FilePath .\Bootstrap-Server.ps1 -ArgumentList 8080
```

---

### Option B: Docker Container

**For cloud/serverless deployment**

```dockerfile
# Dockerfile
FROM mcr.microsoft.com/powershell:latest

WORKDIR /app
COPY Bootstrap-Server.ps1 .

EXPOSE 8080
ENV PORT=8080
ENV PEER_TTL=300
ENV MAX_PEERS=100

CMD ["pwsh", "-File", "./Bootstrap-Server.ps1", "-Port", "8080"]
```

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  bootstrap:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - PEER_TTL=300
      - MAX_PEERS=100
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.5'
    restart: unless-stopped
```

**Deployment:**
```bash
# Build and run
docker-compose up -d

# Or direct
docker run -d -p 8080:8080 pscryptochat-bootstrap
```

---

### Option C: Azure Functions / AWS Lambda

**Serverless - scales to zero**

```powershell
# Azure Function: run.ps1
using namespace System.Net

param($Request, $TriggerMetadata)

# Use Azure Table Storage for peer state
$storageAccount = $env:AzureWebJobsStorage
$tableName = "peers"

Import-Module Az.Storage

$ctx = New-AzStorageContext -ConnectionString $storageAccount
$table = Get-AzStorageTable -Name $tableName -Context $ctx -ErrorAction SilentlyContinue

if (-not $table) {
    $table = New-AzStorageTable -Name $tableName -Context $ctx
}

switch ($Request.Method) {
    "GET" {
        # Query peers from table storage
        $query = [Microsoft.Azure.Cosmos.Table.TableQuery]::new()
        $query.FilterString = "Timestamp gt datetime'$((Get-Date).AddMinutes(-5).ToString('o'))'"
        $query.TakeCount = 50

        $peers = Get-AzTableRow -Table $table.CloudTable -CustomFilter $query.FilterString

        $body = @{
            peers = @($peers | ForEach-Object {
                @{
                    id = $_.RowKey
                    endpoints = ($_.Endpoints | ConvertFrom-Json)
                    last_seen = $_.Timestamp.ToUnixTimeSeconds()
                }
            })
            ttl = 300
        } | ConvertTo-Json

        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body = $body
            ContentType = "application/json"
        })
    }

    "POST" {
        $peer = $Request.Body | ConvertFrom-Json

        # Upsert to table storage
        Add-AzTableRow -Table $table.CloudTable `
            -PartitionKey "peers" `
            -RowKey $peer.id `
            -Property @{
                Endpoints = ($peer.endpoints | ConvertTo-Json)
                IP = $Request.Headers["X-Forwarded-For"]
            } `
            -UpdateExisting

        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body = (@{ registered = $true; expires = 300 } | ConvertTo-Json)
            ContentType = "application/json"
        })
    }
}
```

**function.json:**
```json
{
  "bindings": [
    {
      "authLevel": "anonymous",
      "type": "httpTrigger",
      "direction": "in",
      "name": "Request",
      "methods": ["get", "post"],
      "route": "{*path}"
    },
    {
      "type": "http",
      "direction": "out",
      "name": "Response"
    }
  ]
}
```

---

### Option D: UDP Bootstrap (BitTorrent-style)

**Minimal bandwidth, firewall-friendly**

```powershell
# UDP-Bootstrap-Server.ps1
param(
    [int]$Port = 6881,
    [int]$MaxPeers = 200
)

$peers = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()
$udpClient = [System.Net.Sockets.UdpClient]::new($Port)

Write-Host "UDP Bootstrap listening on port $Port" -ForegroundColor Green

while ($true) {
    try {
        $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $data = $udpClient.Receive([ref]$remoteEP)

        # Parse KRPC-like message
        $msg = [System.Text.Encoding]::UTF8.GetString($data) | ConvertFrom-Json

        switch ($msg.type) {
            "ping" {
                # Respond with pong
                $response = @{
                    type = "pong"
                    id = $msg.id
                    server_id = [guid]::NewGuid().ToString("N")
                } | ConvertTo-Json

                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($response)
                $udpClient.Send($responseBytes, $responseBytes.Length, $remoteEP)
            }

            "find_peers" {
                # Return peer list
                $activePeers = $peers.Values | Get-Random -Count ([Math]::Min(8, $peers.Count))

                $response = @{
                    type = "peers"
                    id = $msg.id
                    peers = @($activePeers | ForEach-Object {
                        "$($_.ip):$($_.port)"
                    })
                } | ConvertTo-Json

                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($response)
                $udpClient.Send($responseBytes, $responseBytes.Length, $remoteEP)
            }

            "announce" {
                # Add peer
                $peerId = $msg.peer_id ?? [guid]::NewGuid().ToString("N")
                $peers[$peerId] = @{
                    ip = $remoteEP.Address.ToString()
                    port = $msg.port ?? $remoteEP.Port
                    last_seen = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                }

                $response = @{
                    type = "ack"
                    id = $msg.id
                    peer_id = $peerId
                } | ConvertTo-Json

                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($response)
                $udpClient.Send($responseBytes, $responseBytes.Length, $remoteEP)
            }
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Yellow
    }
}
```

---

## 5. Client Bootstrap Logic

```powershell
class BootstrapClient {
    [string[]]$BootstrapUrls
    [hashtable[]]$KnownPeers = @()
    [int]$Timeout = 5000

    BootstrapClient([string[]]$Urls) {
        $this.BootstrapUrls = $Urls
    }

    [hashtable[]]GetPeers() {
        $allPeers = @()

        # Try each bootstrap server
        foreach ($url in $this.BootstrapUrls) {
            try {
                $response = Invoke-RestMethod `
                    -Uri "$url/peers" `
                    -TimeoutSec ($this.Timeout / 1000) `
                    -ErrorAction Stop

                $allPeers += $response.peers
                Write-Host "Got $($response.peers.Count) peers from $url" -ForegroundColor Gray
            }
            catch {
                Write-Host "Bootstrap $url failed: $_" -ForegroundColor Yellow
            }
        }

        # Deduplicate by ID
        $uniquePeers = $allPeers | Group-Object -Property id | ForEach-Object {
            $_.Group | Select-Object -First 1
        }

        $this.KnownPeers = $uniquePeers
        return $uniquePeers
    }

    [void]Announce([string]$PeerId, [string[]]$Endpoints) {
        $body = @{
            id = $PeerId
            endpoints = $Endpoints
        }

        foreach ($url in $this.BootstrapUrls) {
            try {
                Invoke-RestMethod `
                    -Uri "$url/announce" `
                    -Method Post `
                    -Body ($body | ConvertTo-Json) `
                    -ContentType "application/json" `
                    -TimeoutSec ($this.Timeout / 1000) `
                    -ErrorAction Stop

                Write-Host "Announced to $url" -ForegroundColor Gray
            }
            catch {
                Write-Host "Announce to $url failed: $_" -ForegroundColor Yellow
            }
        }
    }
}

# Usage
$bootstrap = [BootstrapClient]::new(@(
    "http://localhost:8080",
    "http://bootstrap.example.com:8080"
))

$peers = $bootstrap.GetPeers()
Write-Host "Found $($peers.Count) peers"

# Announce ourselves
$bootstrap.Announce(
    [guid]::NewGuid().ToString("N"),
    @("tcp://192.168.1.100:9000", "udp://192.168.1.100:9001")
)
```

---

## 6. Fallback Chain

```powershell
class PeerDiscovery {
    [BootstrapClient]$Bootstrap
    [hashtable[]]$HardcodedSeeds
    [bool]$EnableMDNS = $true

    [hashtable[]]DiscoverPeers() {
        $peers = @()

        # Level 1: Try bootstrap servers
        if ($this.Bootstrap) {
            $peers += $this.Bootstrap.GetPeers()
        }

        # Level 2: Use hardcoded seeds if bootstrap failed
        if ($peers.Count -eq 0 -and $this.HardcodedSeeds) {
            Write-Host "Using hardcoded seeds" -ForegroundColor Yellow
            $peers += $this.HardcodedSeeds
        }

        # Level 3: Local network discovery
        if ($this.EnableMDNS) {
            $localPeers = Find-LocalPeers
            $peers += $localPeers
        }

        return $peers
    }
}

function Find-LocalPeers {
    # mDNS/DNS-SD query for _pscryptochat._tcp.local
    try {
        $results = Resolve-DnsName "_pscryptochat._tcp.local" -Type SRV -ErrorAction Stop
        return $results | ForEach-Object {
            @{
                id = $_.NameTarget
                endpoints = @("tcp://$($_.NameTarget):$($_.Port)")
                local = $true
            }
        }
    }
    catch {
        return @()
    }
}
```

---

## 7. Security Considerations

### Threats

| Threat | Mitigation |
|--------|------------|
| Malicious peer injection | Verify peer signatures before connecting |
| Bootstrap enumeration | Rate limiting, proof-of-work |
| Eclipse attack | Use multiple bootstrap servers |
| Sybil attack | Require proof-of-work for announce |
| DoS on bootstrap | Low resource requirements, easy to redeploy |

### Rate Limiting

```powershell
# Simple rate limiter
$rateLimiter = @{}
$maxRequestsPerMinute = 60

function Test-RateLimit {
    param([string]$IP)

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $windowStart = $now - 60

    if (-not $rateLimiter.ContainsKey($IP)) {
        $rateLimiter[$IP] = @()
    }

    # Clean old requests
    $rateLimiter[$IP] = $rateLimiter[$IP] | Where-Object { $_ -gt $windowStart }

    if ($rateLimiter[$IP].Count -ge $maxRequestsPerMinute) {
        return $false  # Rate limited
    }

    $rateLimiter[$IP] += $now
    return $true
}
```

### Proof of Work (Optional)

```powershell
function Test-ProofOfWork {
    param(
        [string]$Challenge,
        [int]$Nonce,
        [int]$Difficulty = 16
    )

    $data = "$Challenge$Nonce"
    $hash = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($data)
    )

    # Check if first N bits are zero
    $requiredZeros = [Math]::Ceiling($Difficulty / 8)
    for ($i = 0; $i -lt $requiredZeros; $i++) {
        if ($hash[$i] -ne 0) {
            return $false
        }
    }

    return $true
}

function Get-ProofOfWork {
    param(
        [string]$Challenge,
        [int]$Difficulty = 16
    )

    $nonce = 0
    while (-not (Test-ProofOfWork -Challenge $Challenge -Nonce $nonce -Difficulty $Difficulty)) {
        $nonce++
    }
    return $nonce
}
```

---

## 8. Deployment Recommendations

### Development/Testing
```powershell
# Local PowerShell script
.\Bootstrap-Server.ps1 -Port 8080
```

### Small Groups (< 50 users)
```bash
# Docker on any VPS
docker run -d -p 8080:8080 pscryptochat-bootstrap
```

### Medium Groups (50-500 users)
```bash
# Multiple containers with load balancer
docker-compose -f docker-compose.prod.yml up -d
```

### Large Scale
- Azure Functions / AWS Lambda
- Geographic distribution
- CDN for peer list caching

---

## 9. Configuration Schema

```json
{
  "bootstrap": {
    "servers": [
      {
        "url": "https://bootstrap1.pscryptochat.example.com",
        "priority": 1
      },
      {
        "url": "https://bootstrap2.pscryptochat.example.com",
        "priority": 2
      }
    ],
    "fallback": {
      "enabled": true,
      "seeds": [
        "tcp://seed1.example.com:9000",
        "tcp://seed2.example.com:9000"
      ]
    },
    "local_discovery": {
      "enabled": true,
      "mdns_service": "_pscryptochat._tcp.local"
    },
    "announce": {
      "enabled": true,
      "interval_seconds": 300
    }
  }
}
```

---

## 10. Monitoring

```powershell
# Health check endpoint response
@{
    status = "healthy"
    uptime_seconds = (Get-Date) - $startTime
    peers = @{
        total = $peers.Count
        active_5m = ($peers.Values | Where-Object {
            ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $_.last_seen) -lt 300
        }).Count
    }
    requests = @{
        total = $totalRequests
        rate_per_minute = $requestsPerMinute
    }
    memory_mb = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
}
```

---

## 11. References

- [BEP 5: DHT Protocol](https://www.bittorrent.org/beps/bep_0005.html)
- [Tor Directory Protocol](https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt)
- [Matrix Server Discovery](https://spec.matrix.org/v1.4/server-server-api/#server-discovery)
- [mDNS/DNS-SD RFC 6762/6763](https://datatracker.ietf.org/doc/html/rfc6762)
