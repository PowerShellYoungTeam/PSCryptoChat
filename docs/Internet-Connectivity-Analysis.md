# Internet Connectivity Analysis & Test Plan

## Can PSCryptoChat Work Over the Internet?

### Short Answer: **Yes, BUT** with significant limitations

The current implementation **can work over the internet** if:
1. ✅ At least one party has a **public IP address** (no NAT), OR
2. ✅ Both parties have **port forwarding** configured on their routers, OR
3. ✅ Both parties are on the **same VPN** (acts like LAN)

The current implementation **will NOT work** if:
1. ❌ Both parties are behind NAT without port forwarding (most home networks)
2. ❌ Either party is behind symmetric NAT (carrier-grade NAT, mobile networks)
3. ❌ Firewall blocks incoming UDP traffic

---

## Technical Analysis

### Current Implementation

```
┌─────────────────────────────────────────────────────────────────┐
│                    Current Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Host Machine                        Peer Machine               │
│  ┌─────────────────┐                ┌─────────────────┐        │
│  │ PSCryptoChat    │                │ PSCryptoChat    │        │
│  │ Port: 9000      │ ◄─── UDP ───► │ Port: random    │        │
│  │ IP: 10.0.0.5    │                │ IP: 10.0.0.10   │        │
│  └─────────────────┘                └─────────────────┘        │
│                                                                 │
│  Connection String: 10.0.0.5:9000:MFkwEwYHKoZI...              │
│                                                                 │
│  ✅ Works: Same LAN (10.0.0.x)                                  │
│  ✅ Works: Public IPs or port forwarding                        │
│  ❌ Fails: NAT to NAT without port forwarding                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### The NAT Problem

```
┌─────────────────────────────────────────────────────────────────┐
│                    Internet NAT Scenario                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Alice's Home                         Bob's Home                │
│  ┌──────────────┐                    ┌──────────────┐          │
│  │ PC: 192.168.1.5│                  │ PC: 192.168.1.10│        │
│  │ Port: 9000     │                  │ Port: 9000     │        │
│  └───────┬────────┘                  └───────┬────────┘        │
│          │                                   │                  │
│  ┌───────▼────────┐                  ┌───────▼────────┐        │
│  │ Router (NAT)   │                  │ Router (NAT)   │        │
│  │ Public: 1.2.3.4│                  │ Public: 5.6.7.8│        │
│  └───────┬────────┘                  └───────┬────────┘        │
│          │                                   │                  │
│          └────────────┬──────────────────────┘                  │
│                       │                                         │
│               ┌───────▼────────┐                                │
│               │    Internet    │                                │
│               └────────────────┘                                │
│                                                                 │
│  Problem: Alice's connection string shows 192.168.1.5:9000      │
│           Bob cannot reach 192.168.1.5 from the internet!       │
│                                                                 │
│  Even with public IP in connection string:                      │
│           Bob sends to 1.2.3.4:9000                             │
│           Alice's router doesn't know where to forward it       │
│           (no port forwarding configured)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Current Code Issues

1. **`GetLocalEndpointString()` returns LAN IP:**
   ```powershell
   # From PSCryptoChat.psm1 line 563
   $localIp = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
       Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
       Select-Object -First 1
   ```
   This returns the local network IP (192.168.x.x), not the public IP.

2. **No STUN for public IP discovery:**
   The module doesn't use STUN to discover the public IP/port.

3. **No UDP hole punching:**
   There's no mechanism to coordinate simultaneous connection attempts.

---

## What Needs to Change for Internet Support

### Option A: Manual Public IP Entry (Quick Fix)

Add a parameter to specify public IP:

```powershell
Start-ChatSession -Listen -Port 9000 -PublicAddress "1.2.3.4"
# Requires user to know their public IP and configure port forwarding
```

### Option B: STUN Integration (Proper Fix)

1. Query STUN server to discover public IP:port
2. Use public endpoint in connection string
3. Implement UDP hole punching for NAT traversal

See `docs/research/04-P2P-Libraries-NAT-Traversal.md` for implementation details.

---

## Test Plan: Internet Connectivity

### Prerequisites

| Item | Machine A (Host) | Machine B (Peer) |
|------|------------------|------------------|
| OS | Windows 10/11 | Windows 10/11 |
| PowerShell | 7.0+ | 7.0+ |
| Network | Public IP or port forward | Any internet |
| Firewall | UDP port open | Outbound UDP allowed |

### Scenario 1: VPS/Cloud with Public IP

**Setup:**
- Machine A: Azure/AWS VM with public IP (e.g., 20.30.40.50)
- Machine B: Home PC behind NAT

**Test Steps:**

```powershell
# === Machine A (VPS with public IP) ===
Import-Module PSCryptoChat

# Create identity
New-CryptoIdentity -Anonymous

# Start listening
$session = Start-ChatSession -Listen -Port 9000

# Get connection string - NOTE: This will show private IP!
# You need to manually replace with public IP
$connStr = Get-ConnectionString
Write-Host "Connection string (edit IP): $connStr"

# Manual fix: Replace private IP with public IP
$publicConnStr = $connStr -replace '^\d+\.\d+\.\d+\.\d+', '20.30.40.50'
Write-Host "Share this: $publicConnStr"
```

```powershell
# === Machine B (Home PC) ===
Import-Module PSCryptoChat

# Connect using public IP connection string
Start-ChatSession -Peer "20.30.40.50:9000:MFkwEwYHKoZI..."

# Test messaging
Send-ChatMessage "Hello from home!"
```

### Scenario 2: Port Forwarding

**Setup:**
- Machine A: Home PC with router port forward (external:9000 → internal:9000)
- Machine B: Different home PC

**Test Steps:**

1. **Configure Port Forwarding on Machine A's Router:**
   - Log into router (usually 192.168.1.1)
   - Port Forwarding / Virtual Server section
   - Add rule: External Port 9000 → Internal IP:9000 (UDP)

2. **Find Public IP:**
   ```powershell
   (Invoke-WebRequest -Uri "https://api.ipify.org").Content
   ```

3. **Run Same Test as Scenario 1**

### Scenario 3: Both Behind NAT (Expected to Fail)

**Setup:**
- Machine A: Home PC behind NAT (no port forwarding)
- Machine B: Different home PC behind NAT

**Test Steps:**

```powershell
# === Machine A ===
$session = Start-ChatSession -Listen -Port 9000
$connStr = Get-ConnectionString
# connStr shows: 192.168.1.5:9000:MFkwEwYHKoZI...
# This is a PRIVATE IP - unreachable from internet!
```

```powershell
# === Machine B ===
# This will FAIL - cannot reach private IP
Start-ChatSession -Peer "192.168.1.5:9000:MFkwEwYHKoZI..."
# Error: No response from peer (timeout)
```

**Expected Result:** Connection timeout / failure

---

## Quick Internet Test Script

Save this as `Test-InternetConnectivity.ps1`:

```powershell
<#
.SYNOPSIS
    Test PSCryptoChat internet connectivity

.PARAMETER Mode
    'Host' to listen, 'Peer' to connect

.PARAMETER PublicIP
    Your public IP (for Host mode)

.PARAMETER ConnectionString
    Connection string (for Peer mode)

.EXAMPLE
    # On host machine (with public IP or port forward)
    .\Test-InternetConnectivity.ps1 -Mode Host -PublicIP "1.2.3.4"

    # On peer machine
    .\Test-InternetConnectivity.ps1 -Mode Peer -ConnectionString "1.2.3.4:9000:MFkw..."
#>
param(
    [ValidateSet('Host', 'Peer')]
    [string]$Mode = 'Host',

    [string]$PublicIP,
    [string]$ConnectionString,
    [int]$Port = 9000
)

Import-Module PSCryptoChat -Force

if ($Mode -eq 'Host') {
    # Get public IP if not provided
    if (-not $PublicIP) {
        Write-Host "Detecting public IP..." -ForegroundColor Cyan
        try {
            $PublicIP = (Invoke-WebRequest -Uri "https://api.ipify.org" -TimeoutSec 5).Content
            Write-Host "Public IP: $PublicIP" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not detect public IP. Please provide -PublicIP parameter."
            return
        }
    }

    # Create identity and start listening
    New-CryptoIdentity -Anonymous
    $session = Start-ChatSession -Listen -Port $Port

    # Build connection string with public IP
    $localConnStr = Get-ConnectionString
    $parts = $localConnStr -split ':', 3
    $publicConnStr = "${PublicIP}:${Port}:$($parts[2])"

    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "SHARE THIS CONNECTION STRING:" -ForegroundColor Yellow
    Write-Host $publicConnStr -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Yellow

    Write-Host "Waiting for peer connection..." -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to cancel`n"

    # Wait for incoming message
    $sessionData = $script:ActiveSessions[$session.SessionId]
    $startTime = Get-Date

    while ($true) {
        $data = $sessionData.Transport.ReceiveString(1000)
        if ($data) {
            Write-Host "Received: $data" -ForegroundColor Green

            $msg = [MessageProtocol]::Parse($data)
            if ($msg.type -eq 'handshake') {
                Write-Host "Handshake received from peer!" -ForegroundColor Green
                $sessionData.Session.CompleteHandshake($msg.publicKey)

                # Send response
                $response = [MessageProtocol]::CreateMessage(
                    $sessionData.Session.Encrypt("Connection successful!")
                )
                $sessionData.Transport.SendString($response)
                Write-Host "Response sent!" -ForegroundColor Green
            }
            elseif ($msg.type -eq 'message') {
                $decrypted = $sessionData.Session.Decrypt($msg.content)
                Write-Host "Message: $decrypted" -ForegroundColor Cyan
            }
        }

        # Timeout after 5 minutes
        if (((Get-Date) - $startTime).TotalMinutes -gt 5) {
            Write-Warning "Timeout waiting for connection"
            break
        }
    }
}
else {
    # Peer mode
    if (-not $ConnectionString) {
        Write-Error "Connection string required for Peer mode"
        return
    }

    Write-Host "Connecting to peer..." -ForegroundColor Cyan
    New-CryptoIdentity -Anonymous

    try {
        $session = Start-ChatSession -Peer $ConnectionString
        Write-Host "Connected!" -ForegroundColor Green

        # Wait for response
        $sessionData = $script:ActiveSessions[$session.SessionId]
        $data = $sessionData.Transport.ReceiveString(10000)

        if ($data) {
            $msg = [MessageProtocol]::Parse($data)
            if ($msg.type -eq 'message') {
                $decrypted = $sessionData.Session.Decrypt($msg.content)
                Write-Host "Response from host: $decrypted" -ForegroundColor Green
            }
        }
        else {
            Write-Warning "No response from host"
        }
    }
    catch {
        Write-Error "Connection failed: $_"
    }
}

# Cleanup
Stop-ChatSession -All
```

---

## Recommendations

### For v0.1.0 (Current)

Document the limitation clearly:
- Works on LAN
- Works with public IP or port forwarding
- Does NOT work NAT-to-NAT

### For v0.2.0 (Future)

1. Add `-PublicAddress` parameter to `Start-ChatSession`
2. Integrate STUN for automatic public IP discovery
3. Implement UDP hole punching
4. Add TURN relay fallback

### Priority Implementation Order

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | `-PublicAddress` parameter | Low | Enables manual internet use |
| 2 | STUN public IP discovery | Medium | Auto-detect public endpoint |
| 3 | UDP hole punching | High | NAT-to-NAT connectivity |
| 4 | TURN relay | High | Works through any NAT |

---

## Summary

| Scenario | Works? | Notes |
|----------|--------|-------|
| Localhost | ✅ Yes | Fully tested |
| Same LAN | ✅ Yes | Fully tested |
| VPS with public IP | ✅ Yes* | Requires manual IP substitution |
| Port forwarding | ✅ Yes* | Requires router config + manual IP |
| NAT to NAT | ❌ No | Needs STUN/hole punching |
| Symmetric NAT | ❌ No | Needs TURN relay |

*With workarounds documented above
