<#
.SYNOPSIS
    Session management with auto-timeout and secure clearing

.DESCRIPTION
    Manages encrypted chat sessions with ephemeral keys,
    auto-disconnect on idle, and secure memory clearing.

.NOTES
    Based on design decisions: ephemeral messages, auto-disconnect,
    SecureString with rapid clearing.
#>

enum SessionState {
    Initializing
    Handshaking
    Connected
    Disconnecting
    Disconnected
    Error
}

class ChatSession {
    [string]$SessionId
    [string]$PeerId                    # Peer's identity fingerprint
    [string]$PeerPublicKey             # Peer's public key
    [SessionState]$State
    [DateTime]$Created
    [DateTime]$LastActivity
    [int]$TimeoutSeconds               # Auto-disconnect timeout
    [bool]$IsAnonymous                 # Anonymous session flag

    hidden [byte[]]$SessionKey         # Derived shared secret
    hidden [CryptoIdentity]$Identity   # Our identity for this session
    hidden [System.Timers.Timer]$TimeoutTimer

    # Constructor
    ChatSession([CryptoIdentity]$Identity, [int]$TimeoutSeconds = 300) {
        $this.SessionId = [guid]::NewGuid().ToString("N").Substring(0, 16)
        $this.Identity = $Identity
        $this.IsAnonymous = ($Identity.Mode -eq [IdentityMode]::Anonymous)
        $this.TimeoutSeconds = $TimeoutSeconds
        $this.State = [SessionState]::Initializing
        $this.Created = [DateTime]::UtcNow
        $this.LastActivity = $this.Created

        # Setup timeout timer
        $this.SetupTimeoutTimer()
    }

    # Setup auto-disconnect timer
    hidden [void]SetupTimeoutTimer() {
        $this.TimeoutTimer = [System.Timers.Timer]::new(($this.TimeoutSeconds * 1000))
        $this.TimeoutTimer.AutoReset = $false

        $session = $this
        $this.TimeoutTimer.add_Elapsed({
            Write-Warning "Session $($session.SessionId) timed out - disconnecting"
            $session.Disconnect("Idle timeout")
        })
    }

    # Reset timeout timer on activity
    [void]ResetTimeout() {
        $this.LastActivity = [DateTime]::UtcNow
        if ($null -ne $this.TimeoutTimer) {
            $this.TimeoutTimer.Stop()
            $this.TimeoutTimer.Start()
        }
    }

    # Complete handshake with peer
    [void]CompleteHandshake([string]$PeerPublicKey) {
        $this.State = [SessionState]::Handshaking
        $this.PeerPublicKey = $PeerPublicKey

        # Compute peer ID from their public key
        $peerKeyBytes = [Convert]::FromBase64String($PeerPublicKey)
        $hash = [System.Security.Cryptography.SHA256]::HashData($peerKeyBytes)
        $this.PeerId = [Convert]::ToBase64String($hash).Substring(0, 16).Replace('+', '-').Replace('/', '_')

        # Derive session key
        $this.SessionKey = $this.Identity.DeriveSharedSecret($PeerPublicKey)

        $this.State = [SessionState]::Connected
        $this.TimeoutTimer.Start()
        $this.ResetTimeout()
    }

    # Encrypt message for sending
    [string]EncryptMessage([string]$Message) {
        if ($this.State -ne [SessionState]::Connected) {
            throw "Session not connected"
        }

        $this.ResetTimeout()
        return [CryptoProvider]::EncryptMessage($Message, $this.SessionKey)
    }

    # Decrypt received message
    [string]DecryptMessage([string]$EncryptedMessage) {
        if ($this.State -ne [SessionState]::Connected) {
            throw "Session not connected"
        }

        $this.ResetTimeout()
        return [CryptoProvider]::DecryptMessage($EncryptedMessage, $this.SessionKey)
    }

    # Get session verification code for out-of-band verification
    [string]GetVerificationCode() {
        if ($null -eq $this.PeerPublicKey) {
            throw "Session not completed - no peer"
        }
        return $this.Identity.GetSafetyNumber($this.PeerPublicKey)
    }

    # Disconnect session
    [void]Disconnect([string]$Reason) {
        Write-Verbose "Disconnecting session $($this.SessionId): $Reason"

        $this.State = [SessionState]::Disconnecting

        # Stop timer
        if ($null -ne $this.TimeoutTimer) {
            $this.TimeoutTimer.Stop()
            $this.TimeoutTimer.Dispose()
            $this.TimeoutTimer = $null
        }

        # Clear session key
        $this.ClearSessionKey()

        # Dispose anonymous identity
        if ($this.IsAnonymous -and $null -ne $this.Identity) {
            $this.Identity.Dispose()
            $this.Identity = $null
        }

        $this.State = [SessionState]::Disconnected
    }

    # Securely clear session key from memory
    hidden [void]ClearSessionKey() {
        if ($null -ne $this.SessionKey) {
            [CryptoProvider]::ClearBytes($this.SessionKey)
            $this.SessionKey = $null
        }
    }

    # Get session info (safe for display)
    [hashtable]GetInfo() {
        return @{
            SessionId    = $this.SessionId
            PeerId       = $this.PeerId
            State        = $this.State.ToString()
            IsAnonymous  = $this.IsAnonymous
            Created      = $this.Created
            LastActivity = $this.LastActivity
            IdleSeconds  = ([DateTime]::UtcNow - $this.LastActivity).TotalSeconds
            TimeoutIn    = $this.TimeoutSeconds - ([DateTime]::UtcNow - $this.LastActivity).TotalSeconds
        }
    }
}

class SessionManager {
    static [hashtable]$Sessions = @{}

    # Create new session
    static [ChatSession]CreateSession([CryptoIdentity]$Identity, [int]$TimeoutSeconds = 300) {
        $session = [ChatSession]::new($Identity, $TimeoutSeconds)
        [SessionManager]::Sessions[$session.SessionId] = $session
        return $session
    }

    # Get session by ID
    static [ChatSession]GetSession([string]$SessionId) {
        return [SessionManager]::Sessions[$SessionId]
    }

    # List active sessions
    static [ChatSession[]]GetActiveSessions() {
        return [SessionManager]::Sessions.Values | Where-Object {
            $_.State -eq [SessionState]::Connected
        }
    }

    # Close session
    static [void]CloseSession([string]$SessionId, [string]$Reason = "User requested") {
        $session = [SessionManager]::Sessions[$SessionId]
        if ($null -ne $session) {
            $session.Disconnect($Reason)
            [SessionManager]::Sessions.Remove($SessionId)
        }
    }

    # Close all sessions
    static [void]CloseAllSessions() {
        foreach ($sessionId in @([SessionManager]::Sessions.Keys)) {
            [SessionManager]::CloseSession($sessionId, "Shutdown")
        }
    }
}
