@{
    # Module manifest for PSCryptoChat
    RootModule           = 'PSCryptoChat.psm1'
    ModuleVersion        = '0.1.1'
    GUID                 = '2091ae77-a86d-4026-b9bb-7068cb019280'
    Author               = 'PowerShellYoungTeam'
    CompanyName          = 'PowerShellYoungTeam'
    Copyright            = '(c) 2025 PowerShellYoungTeam. All rights reserved.'
    Description          = 'Encrypted, decentralized, optionally anonymous peer-to-peer messaging for PowerShell. Features ECDH P-256 key exchange, AES-256-GCM encryption, ephemeral sessions, and safety number verification.'

    # Minimum PowerShell version
    PowerShellVersion    = '7.0'

    # .NET version requirement
    CompatiblePSEditions = @('Core')

    # Functions to export
    FunctionsToExport    = @(
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
        'Get-ConnectionString',

        # Interactive Chat
        'Start-CryptoChat'
    )

    # Cmdlets to export (none - pure PowerShell module)
    CmdletsToExport      = @()

    # Variables to export
    VariablesToExport    = @()

    # Aliases to export
    AliasesToExport      = @()

    # Private data for PowerShell Gallery
    PrivateData          = @{
        PSData = @{
            Tags                       = @('encryption', 'messaging', 'p2p', 'privacy', 'chat', 'security', 'cryptography', 'PSEdition_Core', 'Windows')
            LicenseUri                 = 'https://github.com/PowerShellYoungTeam/PSCryptoChat/blob/main/LICENSE'
            ProjectUri                 = 'https://github.com/PowerShellYoungTeam/PSCryptoChat'
            ReleaseNotes               = 'v0.1.1 - Added Start-CryptoChat cmdlet for interactive chat sessions. Fixed GitHub Actions workflow permissions for automated releases.'
            ExternalModuleDependencies = @('Microsoft.PowerShell.SecretManagement')
        }
    }
}
