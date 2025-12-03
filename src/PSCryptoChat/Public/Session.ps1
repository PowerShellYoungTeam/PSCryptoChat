<#
.SYNOPSIS
    Public functions for session management

.DESCRIPTION
    Cmdlets for starting, stopping, and managing chat sessions.
#>

function Start-ChatSession {
    <#
    .SYNOPSIS
        Start a new encrypted chat session

    .DESCRIPTION
        Initiates or accepts an encrypted chat session with a peer.
        Uses manual connection string or mDNS discovery.

    .PARAMETER Peer
        Connection string from peer (format: host:port:publickey)

    .PARAMETER Listen
        Start listening for incoming connections

    .PARAMETER Port
        Local port to use (default: random)

    .PARAMETER Anonymous
        Use anonymous (ephemeral) identity for this session

    .PARAMETER Timeout
        Session idle timeout in seconds (default: 300)

    .PARAMETER Discover
        Use mDNS to discover peers on local network

    .EXAMPLE
        Start-ChatSession -Peer "192.168.1.100:9000:BASE64KEY..."
        Connect to peer using connection string

    .EXAMPLE
        Start-ChatSession -Listen -Port 9000
        Listen for incoming connections on port 9000

    .EXAMPLE
        Start-ChatSession -Discover
        Discover and connect to peers on local network
    #>
    [CmdletBinding(DefaultParameterSetName = 'Connect')]
    param(
        [Parameter(ParameterSetName = 'Connect', Position = 0)]
        [string]$Peer,

        [Parameter(ParameterSetName = 'Listen')]
        [switch]$Listen,

        [Parameter()]
        [int]$Port = 0,

        [Parameter()]
        [switch]$Anonymous,

        [Parameter()]
        [int]$Timeout = 300,

        [Parameter(ParameterSetName = 'Discover')]
        [switch]$Discover
    )

    # Get or create identity
    $identity = $script:CurrentIdentity
    if ($Anonymous -or $null -eq $identity) {
        Write-Verbose "Creating anonymous identity for session"
        $identity = [IdentityManager]::CreateIdentity([IdentityMode]::Anonymous)
    }

    # Create session
    $session = [SessionManager]::CreateSession($identity, $Timeout)
    Write-Verbose "Created session: $($session.SessionId)"

    # Create transport
    $transport = [UdpTransport]::new($Port)
    $transport.Start()

    # Store transport in session (using script scope for now)
    $script:ActiveSessions[$session.SessionId] = @{
        Session   = $session
        Transport = $transport
    }

    if ($Discover) {
        # mDNS discovery
        Write-Host "Discovering peers on local network..." -ForegroundColor Cyan
        $discovery = [PeerDiscovery]::new($true)
        $discovery.Start()

        # Announce ourselves
        $discovery.Announce($session.SessionId, $transport.LocalPort, $identity.PublicKey)

        # Listen for peers
        $peers = $discovery.FindPeers(5000)
        $discovery.Stop()

        if ($peers.Count -eq 0) {
            Write-Warning "No peers found on local network"
            return Get-ChatSession -SessionId $session.SessionId
        }

        Write-Host "Found $($peers.Count) peer(s):" -ForegroundColor Green
        $peers | ForEach-Object { Write-Host "  - $($_.Name) at $($_.Host):$($_.Port)" }

        # Connect to first peer (TODO: selection UI)
        $peerInfo = $peers[0]
        $transport.Connect($peerInfo.Host, $peerInfo.Port)
        $session.CompleteHandshake($peerInfo.PublicKey)
    }
    elseif ($Listen) {
        # Listen mode
        $endpoint = $transport.GetLocalEndpointString()
        $connectionString = "${endpoint}:$($identity.PublicKey)"

        Write-Host "Listening for connections..." -ForegroundColor Cyan
        Write-Host "Share this connection string with peer:" -ForegroundColor Yellow
        Write-Host $connectionString -ForegroundColor White
        Write-Host ""

        # Send handshake when we receive connection
        # (Simplified - real impl would wait for incoming handshake)
    }
    elseif ($Peer) {
        # Connect to peer
        $peerInfo = [ManualDiscovery]::ParseConnectionString($Peer)

        Write-Verbose "Connecting to $($peerInfo.Host):$($peerInfo.Port)"
        $transport.Connect($peerInfo.Host, $peerInfo.Port)

        # Send handshake
        $handshake = [MessageProtocol]::CreateHandshake($identity.PublicKey, $session.SessionId)
        $transport.SendString($handshake)

        # Complete our side
        $session.CompleteHandshake($peerInfo.PublicKey)

        Write-Host "Connected to peer!" -ForegroundColor Green
    }

    return Get-ChatSession -SessionId $session.SessionId
}

function Stop-ChatSession {
    <#
    .SYNOPSIS
        Stop and clean up a chat session

    .PARAMETER SessionId
        ID of session to stop

    .PARAMETER All
        Stop all active sessions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$SessionId,

        [switch]$All
    )

    if ($All) {
        foreach ($sid in @($script:ActiveSessions.Keys)) {
            Stop-ChatSession -SessionId $sid
        }
        return
    }

    if (-not $SessionId) {
        # Use most recent session
        $SessionId = @($script:ActiveSessions.Keys)[-1]
        if (-not $SessionId) {
            Write-Warning "No active sessions"
            return
        }
    }

    $sessionData = $script:ActiveSessions[$SessionId]
    if ($null -eq $sessionData) {
        Write-Warning "Session not found: $SessionId"
        return
    }

    # Close session
    [SessionManager]::CloseSession($SessionId)

    # Close transport
    $sessionData.Transport.Stop()

    # Remove from active sessions
    $script:ActiveSessions.Remove($SessionId)

    Write-Host "Session $SessionId closed" -ForegroundColor Yellow
}

function Get-ChatSession {
    <#
    .SYNOPSIS
        Get information about chat sessions

    .PARAMETER SessionId
        Specific session ID

    .PARAMETER All
        List all sessions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$SessionId,

        [switch]$All
    )

    if ($All -or (-not $SessionId)) {
        $sessions = $script:ActiveSessions.Values | ForEach-Object {
            $info = $_.Session.GetInfo()
            $info.LocalEndpoint = $_.Transport.GetLocalEndpointString()
            [PSCustomObject]$info
        }
        return $sessions
    }

    $sessionData = $script:ActiveSessions[$SessionId]
    if ($null -eq $sessionData) {
        Write-Warning "Session not found: $SessionId"
        return $null
    }

    $info = $sessionData.Session.GetInfo()
    $info.LocalEndpoint = $sessionData.Transport.GetLocalEndpointString()
    return [PSCustomObject]$info
}

function Get-ConnectionString {
    <#
    .SYNOPSIS
        Get connection string for current session

    .PARAMETER SessionId
        Session ID (defaults to most recent)
    #>
    [CmdletBinding()]
    param(
        [string]$SessionId
    )

    if (-not $SessionId) {
        $SessionId = @($script:ActiveSessions.Keys)[-1]
    }

    if (-not $SessionId) {
        throw "No active session"
    }

    $sessionData = $script:ActiveSessions[$SessionId]
    if ($null -eq $sessionData) {
        throw "Session not found: $SessionId"
    }

    $endpoint = $sessionData.Transport.GetLocalEndpointString()
    $publicKey = $script:CurrentIdentity.PublicKey

    return "${endpoint}:$publicKey"
}
