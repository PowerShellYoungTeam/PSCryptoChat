<#
.SYNOPSIS
    P2P transport layer - UDP communication

.DESCRIPTION
    Handles UDP socket communication for peer-to-peer messaging.
    Supports manual peer connection via connection strings.

.NOTES
    Based on research in docs/research/04-P2P-Libraries-NAT-Traversal.md
    STUN/ICE integration planned for future phase.
#>

using namespace System.Net
using namespace System.Net.Sockets

enum TransportState {
    Stopped
    Listening
    Connected
    Error
}

class UdpTransport {
    [int]$LocalPort
    [IPEndPoint]$LocalEndpoint
    [IPEndPoint]$RemoteEndpoint
    [TransportState]$State

    hidden [UdpClient]$Client
    hidden [bool]$IsListening

    # Constructor
    UdpTransport([int]$Port = 0) {
        $this.LocalPort = $Port
        $this.State = [TransportState]::Stopped
        $this.IsListening = $false
    }

    # Start listening
    [void]Start() {
        if ($this.State -eq [TransportState]::Listening) {
            return
        }

        try {
            $this.Client = [UdpClient]::new($this.LocalPort)
            $this.LocalEndpoint = $this.Client.Client.LocalEndPoint
            $this.LocalPort = $this.LocalEndpoint.Port
            $this.State = [TransportState]::Listening
            Write-Verbose "UDP transport listening on port $($this.LocalPort)"
        }
        catch {
            $this.State = [TransportState]::Error
            throw "Failed to start UDP transport: $_"
        }
    }

    # Stop listening
    [void]Stop() {
        $this.IsListening = $false
        if ($null -ne $this.Client) {
            $this.Client.Close()
            $this.Client.Dispose()
            $this.Client = $null
        }
        $this.State = [TransportState]::Stopped
    }

    # Connect to peer
    [void]Connect([string]$Host, [int]$Port) {
        if ($this.State -ne [TransportState]::Listening) {
            $this.Start()
        }

        $addresses = [Dns]::GetHostAddresses($Host)
        if ($addresses.Count -eq 0) {
            throw "Could not resolve host: $Host"
        }

        $this.RemoteEndpoint = [IPEndPoint]::new($addresses[0], $Port)
        $this.State = [TransportState]::Connected
    }

    # Send data
    [void]Send([byte[]]$Data) {
        if ($null -eq $this.RemoteEndpoint) {
            throw "Not connected to peer"
        }

        $this.Client.Send($Data, $Data.Length, $this.RemoteEndpoint) | Out-Null
    }

    # Send string
    [void]SendString([string]$Message) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        $this.Send($bytes)
    }

    # Receive data (blocking with timeout)
    [byte[]]Receive([int]$TimeoutMs = 5000) {
        $this.Client.Client.ReceiveTimeout = $TimeoutMs
        $remoteEP = [IPEndPoint]::new([IPAddress]::Any, 0)

        try {
            return $this.Client.Receive([ref]$remoteEP)
        }
        catch [SocketException] {
            if ($_.Exception.SocketErrorCode -eq [SocketError]::TimedOut) {
                return $null
            }
            throw
        }
    }

    # Receive string
    [string]ReceiveString([int]$TimeoutMs = 5000) {
        $data = $this.Receive($TimeoutMs)
        if ($null -eq $data) {
            return $null
        }
        return [System.Text.Encoding]::UTF8.GetString($data)
    }

    # Get local endpoint string
    [string]GetLocalEndpointString() {
        if ($null -eq $this.LocalEndpoint) {
            return $null
        }

        # Try to get external IP (simplified - would use STUN in production)
        $localIP = $this.GetLocalIPAddress()
        return "$localIP`:$($this.LocalEndpoint.Port)"
    }

    # Get best local IP address
    hidden [string]GetLocalIPAddress() {
        try {
            # Try to find non-loopback IPv4 address
            $addresses = [Dns]::GetHostAddresses([Dns]::GetHostName()) |
                Where-Object { $_.AddressFamily -eq [AddressFamily]::InterNetwork -and
                              -not [IPAddress]::IsLoopback($_) }

            if ($addresses.Count -gt 0) {
                return $addresses[0].ToString()
            }
        }
        catch { }

        return "127.0.0.1"
    }
}

class MessageProtocol {
    # Message types
    static [string]$TypeHandshake = "HANDSHAKE"
    static [string]$TypeMessage = "MSG"
    static [string]$TypeAck = "ACK"
    static [string]$TypeDisconnect = "BYE"

    # Create handshake message
    static [string]CreateHandshake([string]$PublicKey, [string]$SessionId) {
        return (@{
            Type      = [MessageProtocol]::TypeHandshake
            PublicKey = $PublicKey
            SessionId = $SessionId
            Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        } | ConvertTo-Json -Compress)
    }

    # Create encrypted message
    static [string]CreateMessage([string]$EncryptedPayload, [string]$SessionId) {
        return (@{
            Type      = [MessageProtocol]::TypeMessage
            Payload   = $EncryptedPayload
            SessionId = $SessionId
            Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        } | ConvertTo-Json -Compress)
    }

    # Create disconnect message
    static [string]CreateDisconnect([string]$SessionId) {
        return (@{
            Type      = [MessageProtocol]::TypeDisconnect
            SessionId = $SessionId
            Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        } | ConvertTo-Json -Compress)
    }

    # Parse incoming message
    static [hashtable]Parse([string]$RawMessage) {
        try {
            return ($RawMessage | ConvertFrom-Json -AsHashtable)
        }
        catch {
            return $null
        }
    }
}
