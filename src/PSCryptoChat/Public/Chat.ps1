<#
.SYNOPSIS
    Interactive chat cmdlet for PSCryptoChat

.DESCRIPTION
    Provides an interactive encrypted chat experience.
    Can run as host (listening) or peer (connecting).
#>

function Start-CryptoChat {
    <#
    .SYNOPSIS
        Start an interactive encrypted chat session

    .DESCRIPTION
        Launches an interactive chat interface for encrypted peer-to-peer messaging.
        Run as host (-Listen) to wait for connections, or as peer (-Connect) to join.

    .PARAMETER Listen
        Run as host, listening for incoming connections

    .PARAMETER Connect
        Run as peer, connecting to a host

    .PARAMETER Peer
        Hostname or IP of the host to connect to (used with -Connect)

    .PARAMETER Port
        Port number for the connection (default: 9000)

    .EXAMPLE
        Start-CryptoChat -Listen -Port 9000
        # Starts listening for connections on port 9000

    .EXAMPLE
        Start-CryptoChat -Connect -Peer 192.168.1.100 -Port 9000
        # Connects to a host at 192.168.1.100:9000

    .EXAMPLE
        Start-CryptoChat -Connect -Peer localhost -Port 9000
        # Connects to a host on the same machine
    #>
    [CmdletBinding(DefaultParameterSetName = 'Listen')]
    param(
        [Parameter(ParameterSetName = 'Listen', Mandatory)]
        [switch]$Listen,

        [Parameter(ParameterSetName = 'Connect', Mandatory)]
        [switch]$Connect,

        [Parameter(ParameterSetName = 'Connect')]
        [Alias('Server', 'HostName')]
        [string]$Peer = "localhost",

        [Parameter()]
        [int]$Port = 9000
    )

    # Banner
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       PSCryptoChat v0.1.1             ║" -ForegroundColor Cyan
    Write-Host "  ║   End-to-End Encrypted P2P Chat      ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Create anonymous identity
    $identity = [CryptoIdentity]::new([IdentityMode]::Anonymous)
    Write-Host "[*] Your ID: $($identity.Id)" -ForegroundColor DarkGray

    # Create session
    $session = [ChatSession]::new($identity, 0)  # No timeout for interactive
    Write-Host "[*] Session: $($session.SessionId)" -ForegroundColor DarkGray

    # Create UDP client directly
    $localPort = if ($Listen) { $Port } else { 0 }
    $udp = $null
    try {
        $udp = [System.Net.Sockets.UdpClient]::new($localPort)
    }
    catch {
        Write-Host "[!] Failed to bind to port $localPort" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "    $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
        else {
            Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "[*] The port may already be in use. Try a different port with -Port <number>" -ForegroundColor Yellow
        $session.Close()
        $identity.Dispose()
        return
    }

    $localEndpoint = [System.Net.IPEndPoint]$udp.Client.LocalEndPoint
    $actualPort = $localEndpoint.Port

    # Get local IP
    $localIp = ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
        Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
        Select-Object -First 1).IPAddressToString

    Write-Host "[*] Local: ${localIp}:${actualPort}" -ForegroundColor DarkGray
    Write-Host ""

    # Track peer endpoint for sending
    $peerEndpoint = $null

    try {
        if ($Listen) {
            # === HOST MODE ===
            Write-Host "[+] Waiting for connection on port $Port..." -ForegroundColor Green
            Write-Host ""

            # Wait for handshake
            $udp.Client.ReceiveTimeout = 0  # Block indefinitely
            $remoteEp = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

            while ($true) {
                try {
                    $data = $udp.Receive([ref]$remoteEp)
                    try {
                        $text = [System.Text.Encoding]::UTF8.GetString($data)
                        $msg = $text | ConvertFrom-Json -AsHashtable
                    }
                    catch {
                        Write-Warning "Received malformed data during handshake"
                        continue
                    }

                    if ($msg.type -eq "handshake") {
                        $peerKey = $msg.publicKey

                        Write-Host "[+] Peer connected from $($remoteEp.Address):$($remoteEp.Port)!" -ForegroundColor Green
                        Write-Host "[*] Peer key: $($peerKey.Substring(0, 40))..." -ForegroundColor DarkGray

                        # Store peer endpoint for replies
                        $peerEndpoint = $remoteEp

                        # Complete handshake
                        $session.CompleteHandshake($peerKey)

                        # Send our handshake back to the peer
                        $response = @{
                            type      = "handshake"
                            version   = "1.0"
                            publicKey = $identity.PublicKey
                            sessionId = $session.SessionId
                            timestamp = [DateTime]::UtcNow.ToString('o')
                        } | ConvertTo-Json -Compress
                        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($response)
                        $null = $udp.Send($responseBytes, $responseBytes.Length, $peerEndpoint)

                        Write-Host "[*] Handshake response sent" -ForegroundColor DarkGray
                        break
                    }
                }
                catch [System.Net.Sockets.SocketException] {
                    # Timeout, continue waiting
                }
            }
        }
        else {
            # === CLIENT MODE ===
            Write-Host "[+] Connecting to ${Peer}:${Port}..." -ForegroundColor Green

            # Resolve peer address
            $peerIp = [System.Net.Dns]::GetHostAddresses($Peer) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                Select-Object -First 1
            $peerEndpoint = [System.Net.IPEndPoint]::new($peerIp, $Port)

            # Send handshake
            $handshake = @{
                type      = "handshake"
                version   = "1.0"
                publicKey = $identity.PublicKey
                sessionId = $session.SessionId
                timestamp = [DateTime]::UtcNow.ToString('o')
            } | ConvertTo-Json -Compress
            $handshakeBytes = [System.Text.Encoding]::UTF8.GetBytes($handshake)
            $null = $udp.Send($handshakeBytes, $handshakeBytes.Length, $peerEndpoint)

            Write-Host "[*] Handshake sent, waiting for response..." -ForegroundColor DarkGray

            # Wait for response
            $udp.Client.ReceiveTimeout = 2000
            $remoteEp = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $maxAttempts = 10
            $connected = $false

            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                try {
                    $data = $udp.Receive([ref]$remoteEp)
                    try {
                        $text = [System.Text.Encoding]::UTF8.GetString($data)
                        $msg = $text | ConvertFrom-Json -AsHashtable
                    }
                    catch {
                        Write-Warning "Received malformed data during handshake"
                        continue
                    }

                    if ($msg.type -eq "handshake") {
                        # Compute fingerprint of received public key
                        $pubKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($msg.publicKey)
                        $sha256 = [System.Security.Cryptography.SHA256]::Create()
                        $fingerprintBytes = $sha256.ComputeHash($pubKeyBytes)
                        $fingerprint = ($fingerprintBytes | ForEach-Object { $_.ToString("x2") }) -join ""

                        Write-Host "[*] Peer public key fingerprint (SHA256): $fingerprint" -ForegroundColor Yellow
                        $confirmation = Read-Host "Do you trust this peer and wish to continue? (y/n)"
                        if ($confirmation -eq "y" -or $confirmation -eq "Y") {
                            $session.CompleteHandshake($msg.publicKey)
                            # Update peer endpoint to where response came from
                            $peerEndpoint = $remoteEp
                            Write-Host "[+] Connected!" -ForegroundColor Green
                            Write-Host "[*] Peer key: $($msg.publicKey.Substring(0, 40))..." -ForegroundColor DarkGray
                            $connected = $true
                            break
                        }
                        else {
                            Write-Host "[!] Connection rejected by user." -ForegroundColor Red
                            $connected = $false
                            break
                        }
                    }
                }
                catch [System.Net.Sockets.SocketException] {
                    if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                        Write-Host "[*] Waiting... ($attempt/$maxAttempts)" -ForegroundColor DarkGray
                        if ($attempt % 3 -eq 0) {
                            $null = $udp.Send($handshakeBytes, $handshakeBytes.Length, $peerEndpoint)
                            Write-Host "[*] Resending handshake..." -ForegroundColor DarkGray
                        }
                    }
                    else {
                        throw
                    }
                }
            }

            if (-not $connected) {
                Write-Host "[!] No response from host after $maxAttempts attempts" -ForegroundColor Red
                return
            }
        }

        # Show safety number
        $safetyNum = $identity.GetSafetyNumber($session.PeerPublicKey)
        Write-Host ""
        Write-Host "[!] SAFETY NUMBER (verify with peer!):" -ForegroundColor Yellow
        Write-Host "    $safetyNum" -ForegroundColor White
        Write-Host ""
        Write-Host "═══════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host "  Type messages and press Enter to send" -ForegroundColor Gray
        Write-Host "  Type 'quit' to exit" -ForegroundColor Gray
        Write-Host "═══════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""

        # Chat loop - use short timeout for non-blocking receive
        $udp.Client.ReceiveTimeout = 100
        $remoteEp = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $running = $true

        while ($running) {
            # Check for incoming messages
            try {
                $data = $udp.Receive([ref]$remoteEp)
                try {
                    $text = [System.Text.Encoding]::UTF8.GetString($data)
                    $msg = $text | ConvertFrom-Json -AsHashtable
                }
                catch {
                    Write-Warning "Received malformed data"
                    continue
                }

                    if ($msg.type -eq "message") {
                        $decrypted = $session.Decrypt($msg.content)
                        $time = Get-Date -Format "HH:mm:ss"
                        Write-Host "`r[$time] Peer: $decrypted" -ForegroundColor Cyan
                    }
                    elseif ($msg.type -eq "disconnect") {
                        Write-Host "`r[!] Peer disconnected: $($msg.reason)" -ForegroundColor Yellow
                        $running = $false
                    }
                }
                catch {
                    Write-Warning "Received invalid or malformed message. Ignoring."
                }
            }
            catch [System.Net.Sockets.SocketException] {
                # Timeout - no message, continue
            }

            # Check for user input
            if ([Console]::KeyAvailable) {
                $userInput = Read-Host "You"

                if ($userInput -eq 'quit') {
                    $disconnect = @{
                        type      = "disconnect"
                        reason    = "User quit"
                        timestamp = [DateTime]::UtcNow.ToString('o')
                    } | ConvertTo-Json -Compress
                    $disconnectBytes = [System.Text.Encoding]::UTF8.GetBytes($disconnect)
                    $null = $udp.Send($disconnectBytes, $disconnectBytes.Length, $peerEndpoint)
                    $running = $false
                }
                elseif (-not [string]::IsNullOrWhiteSpace($userInput)) {
                    $encrypted = $session.Encrypt($userInput)
                    $packet = @{
                        type      = "message"
                        content   = $encrypted
                        timestamp = [DateTime]::UtcNow.ToString('o')
                    } | ConvertTo-Json -Compress
                    $packetBytes = [System.Text.Encoding]::UTF8.GetBytes($packet)
                    $null = $udp.Send($packetBytes, $packetBytes.Length, $peerEndpoint)
                }
            }

            Start-Sleep -Milliseconds 50
        }
    }
    finally {
        Write-Host ""
        Write-Host "[*] Closing session..." -ForegroundColor DarkGray
        $session.Close()
        if ($null -ne $udp) {
            $udp.Close()
            $udp.Dispose()
        }
        $identity.Dispose()
        Write-Host "[+] Goodbye!" -ForegroundColor Green
    }
}
