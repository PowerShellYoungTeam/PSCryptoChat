<#
.SYNOPSIS
    Public functions for sending and receiving messages

.DESCRIPTION
    Cmdlets for encrypted messaging within active sessions.
    Messages are ephemeral - never persisted to disk.
#>

function Send-ChatMessage {
    <#
    .SYNOPSIS
        Send an encrypted message to connected peer

    .PARAMETER Message
        The message to send

    .PARAMETER SessionId
        Session to send on (defaults to most recent)

    .EXAMPLE
        Send-ChatMessage "Hello, world!"

    .EXAMPLE
        "Hello" | Send-ChatMessage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Message,

        [string]$SessionId
    )

    process {
        if (-not $SessionId) {
            $SessionId = @($script:ActiveSessions.Keys)[-1]
        }

        if (-not $SessionId) {
            throw "No active session. Use Start-ChatSession first."
        }

        $sessionData = $script:ActiveSessions[$SessionId]
        if ($null -eq $sessionData) {
            throw "Session not found: $SessionId"
        }

        $session = $sessionData.Session
        $transport = $sessionData.Transport

        if ($session.State -ne [SessionState]::Established) {
            throw "Session not established (current state: $($session.State))"
        }

        # Encrypt message
        $encrypted = $session.Encrypt($Message)

        # Create protocol message
        $protocolMsg = [MessageProtocol]::CreateMessage($encrypted)

        # Send
        $transport.SendString($protocolMsg)

        Write-Verbose "Sent encrypted message ($($Message.Length) chars)"
    }
}

function Receive-ChatMessage {
    <#
    .SYNOPSIS
        Receive messages from connected peer

    .PARAMETER SessionId
        Session to receive from (defaults to most recent)

    .PARAMETER Timeout
        Receive timeout in milliseconds (default: 5000)

    .PARAMETER Continuous
        Keep receiving until cancelled

    .EXAMPLE
        Receive-ChatMessage

    .EXAMPLE
        Receive-ChatMessage -Continuous
    #>
    [CmdletBinding()]
    param(
        [string]$SessionId,

        [int]$Timeout = 5000,

        [switch]$Continuous
    )

    if (-not $SessionId) {
        $SessionId = @($script:ActiveSessions.Keys)[-1]
    }

    if (-not $SessionId) {
        throw "No active session. Use Start-ChatSession first."
    }

    $sessionData = $script:ActiveSessions[$SessionId]
    if ($null -eq $sessionData) {
        throw "Session not found: $SessionId"
    }

    $session = $sessionData.Session
    $transport = $sessionData.Transport

    do {
        try {
            $rawMessage = $transport.ReceiveString($Timeout)

            if ($null -eq $rawMessage) {
                if (-not $Continuous) {
                    Write-Verbose "No message received (timeout)"
                }
                continue
            }

            # Parse protocol message
            $parsed = [MessageProtocol]::Parse($rawMessage)

            if ($null -eq $parsed -or $parsed.type -eq "unknown") {
                Write-Warning "Received invalid message"
                continue
            }

            switch ($parsed.type) {
                "message" {
                    # Decrypt and output
                    $decrypted = $session.Decrypt($parsed.content)

                    # Output as object with metadata
                    [PSCustomObject]@{
                        Timestamp = [DateTime]::Parse($parsed.timestamp)
                        From      = "Peer"
                        Message   = $decrypted
                    }
                }

                "handshake" {
                    Write-Verbose "Received handshake from $($parsed.sessionId)"

                    if ($session.State -ne [SessionState]::Established) {
                        $session.CompleteHandshake($parsed.publicKey)
                        Write-Host "Peer connected!" -ForegroundColor Green
                    }
                }

                "disconnect" {
                    Write-Host "Peer disconnected: $($parsed.reason)" -ForegroundColor Yellow
                    Stop-ChatSession -SessionId $SessionId
                    return
                }

                default {
                    Write-Verbose "Unknown message type: $($parsed.type)"
                }
            }
        }
        catch {
            if ($Continuous) {
                Write-Warning "Error receiving: $_"
            }
            else {
                throw
            }
        }
    } while ($Continuous)
}

