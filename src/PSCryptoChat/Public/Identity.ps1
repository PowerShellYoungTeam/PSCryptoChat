<#
.SYNOPSIS
    Public functions for identity management

.DESCRIPTION
    Cmdlets for creating, loading, and managing cryptographic identities.
#>

function New-CryptoIdentity {
    <#
    .SYNOPSIS
        Create a new cryptographic identity

    .DESCRIPTION
        Creates a new ECDH P-256 key pair for use in encrypted chat sessions.
        In pseudonymous mode, the identity can be saved to SecretManagement.
        In anonymous mode, the identity is ephemeral and session-only.

    .PARAMETER Name
        Name for the identity (required for pseudonymous mode)

    .PARAMETER Anonymous
        Create an ephemeral anonymous identity

    .PARAMETER Save
        Save the identity to SecretManagement vault

    .EXAMPLE
        New-CryptoIdentity -Name "MyIdentity" -Save
        Creates and saves a pseudonymous identity

    .EXAMPLE
        New-CryptoIdentity -Anonymous
        Creates an ephemeral anonymous identity
    #>
    [CmdletBinding(DefaultParameterSetName = 'Pseudonymous')]
    param(
        [Parameter(ParameterSetName = 'Pseudonymous', Position = 0)]
        [string]$Name,

        [Parameter(ParameterSetName = 'Anonymous', Mandatory)]
        [switch]$Anonymous,

        [Parameter(ParameterSetName = 'Pseudonymous')]
        [switch]$Save
    )

    if ($Anonymous) {
        $identity = [IdentityManager]::CreateIdentity([IdentityMode]::Anonymous)
        Write-Verbose "Created anonymous identity: $($identity.Id)"
    }
    else {
        $identity = [IdentityManager]::CreateIdentity([IdentityMode]::Pseudonymous)
        Write-Verbose "Created pseudonymous identity: $($identity.Id)"

        if ($Save -and $Name) {
            [IdentityManager]::SaveIdentity($identity, $Name)
            Write-Verbose "Saved identity as '$Name'"
        }
        elseif ($Save -and -not $Name) {
            Write-Warning "Cannot save identity without a name. Use -Name parameter."
        }
    }

    # Set as current identity
    $script:CurrentIdentity = $identity

    # Return safe info
    return [PSCustomObject]@{
        Id        = $identity.Id
        PublicKey = $identity.PublicKey
        Mode      = $identity.Mode.ToString()
        Created   = $identity.Created
    }
}

function Get-CryptoIdentity {
    <#
    .SYNOPSIS
        Get or load a cryptographic identity

    .PARAMETER Name
        Name of saved identity to load

    .PARAMETER Current
        Get the currently active identity

    .PARAMETER List
        List all saved identities

    .EXAMPLE
        Get-CryptoIdentity -List
        Lists all saved identities

    .EXAMPLE
        Get-CryptoIdentity -Name "MyIdentity"
        Loads a saved identity
    #>
    [CmdletBinding(DefaultParameterSetName = 'Current')]
    param(
        [Parameter(ParameterSetName = 'Load', Position = 0)]
        [string]$Name,

        [Parameter(ParameterSetName = 'Current')]
        [switch]$Current,

        [Parameter(ParameterSetName = 'List')]
        [switch]$List
    )

    if ($List) {
        $identities = [IdentityManager]::ListIdentities()
        return $identities
    }

    if ($Name) {
        $identity = [IdentityManager]::LoadIdentity($Name)
        $script:CurrentIdentity = $identity

        return [PSCustomObject]@{
            Id        = $identity.Id
            PublicKey = $identity.PublicKey
            Mode      = $identity.Mode.ToString()
            Created   = $identity.Created
        }
    }

    # Return current identity
    if ($null -eq $script:CurrentIdentity) {
        Write-Warning "No current identity. Use New-CryptoIdentity or Get-CryptoIdentity -Name to load one."
        return $null
    }

    return [PSCustomObject]@{
        Id        = $script:CurrentIdentity.Id
        PublicKey = $script:CurrentIdentity.PublicKey
        Mode      = $script:CurrentIdentity.Mode.ToString()
        Created   = $script:CurrentIdentity.Created
    }
}

function Remove-CryptoIdentity {
    <#
    .SYNOPSIS
        Remove a saved identity

    .PARAMETER Name
        Name of the identity to remove

    .PARAMETER Force
        Skip confirmation prompt
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [switch]$Force
    )

    if ($Force -or $PSCmdlet.ShouldProcess($Name, "Remove identity")) {
        [IdentityManager]::RemoveIdentity($Name)
        Write-Verbose "Removed identity '$Name'"
    }
}

function Export-CryptoIdentity {
    <#
    .SYNOPSIS
        Export identity public key for sharing

    .PARAMETER Identity
        Identity to export (defaults to current)

    .PARAMETER Format
        Export format: Base64 (default) or ConnectionString
    #>
    [CmdletBinding()]
    param(
        [string]$Format = "Base64"
    )

    if ($null -eq $script:CurrentIdentity) {
        throw "No current identity. Use New-CryptoIdentity first."
    }

    switch ($Format) {
        "Base64" {
            return $script:CurrentIdentity.PublicKey
        }
        "ConnectionString" {
            # Need endpoint - this will be filled in by session
            return "endpoint:$($script:CurrentIdentity.PublicKey)"
        }
        default {
            throw "Unknown format: $Format"
        }
    }
}
