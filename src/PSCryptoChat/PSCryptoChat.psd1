@{
    # Module manifest for PSCryptoChat
    RootModule        = 'PSCryptoChat.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'PSCryptoChat Contributors'
    Description       = 'Encrypted, decentralized, optionally anonymous messaging for PowerShell'

    # Minimum PowerShell version
    PowerShellVersion = '7.0'

    # .NET version requirement
    CompatiblePSEditions = @('Core')

    # Functions to export
    FunctionsToExport = @(
        # Identity
        'New-CryptoIdentity',
        'Get-CryptoIdentity',
        'Remove-CryptoIdentity',
        'Export-CryptoIdentity',

        # Session
        'Start-ChatSession',
        'Stop-ChatSession',
        'Get-ChatSession',

        # Messaging
        'Send-ChatMessage',
        'Receive-ChatMessage',

        # Discovery
        'Find-ChatPeer',
        'Get-ConnectionString'
    )

    # Cmdlets to export (none - pure PowerShell module)
    CmdletsToExport   = @()

    # Variables to export
    VariablesToExport = @()

    # Aliases to export
    AliasesToExport   = @()

    # Private data
    PrivateData       = @{
        PSData = @{
            Tags         = @('encryption', 'messaging', 'p2p', 'privacy', 'chat')
            ProjectUri   = 'https://github.com/yourusername/PSCryptoChat'
            ReleaseNotes = 'Initial exploratory release'
        }
    }
}
