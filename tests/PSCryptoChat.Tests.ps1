#Requires -Version 7.0
<#
.SYNOPSIS
    Pester tests for PSCryptoChat crypto functions

.DESCRIPTION
    Run with: Invoke-Pester -Path .\tests\PSCryptoChat.Tests.ps1
#>

# Import module before Pester discovers tests - this loads the classes
$modulePath = "$PSScriptRoot\..\src\PSCryptoChat\PSCryptoChat.psd1"
Import-Module $modulePath -Force -ErrorAction Stop

Describe "CryptoProvider" {
    Context "Key Generation" {
        It "Should generate a valid ECDH key pair" {
            $keyPair = [CryptoProvider]::NewKeyPair()
            $keyPair | Should -Not -BeNullOrEmpty
            $keyPair.KeySize | Should -Be 256
            $keyPair.Dispose()
        }

        It "Should export and import public key" {
            $keyPair = [CryptoProvider]::NewKeyPair()
            $exported = [CryptoProvider]::ExportPublicKey($keyPair)

            $exported | Should -Not -BeNullOrEmpty
            $exported.Length | Should -BeGreaterThan 50  # Base64 encoded

            $imported = [CryptoProvider]::ImportPublicKey($exported)
            $imported | Should -Not -BeNullOrEmpty

            $keyPair.Dispose()
            $imported.Dispose()
        }
    }

    Context "Key Exchange" {
        It "Should derive same shared secret for both parties" {
            # Alice
            $alice = [CryptoProvider]::NewKeyPair()
            $alicePublic = [CryptoProvider]::ExportPublicKey($alice)

            # Bob
            $bob = [CryptoProvider]::NewKeyPair()
            $bobPublic = [CryptoProvider]::ExportPublicKey($bob)

            # Derive secrets
            $aliceSecret = [CryptoProvider]::DeriveSharedSecret($alice, $bobPublic)
            $bobSecret = [CryptoProvider]::DeriveSharedSecret($bob, $alicePublic)

            # Should match
            $aliceSecret.Length | Should -Be 32
            [Convert]::ToBase64String($aliceSecret) | Should -Be ([Convert]::ToBase64String($bobSecret))

            # Cleanup
            [CryptoProvider]::ClearBytes($aliceSecret)
            [CryptoProvider]::ClearBytes($bobSecret)
            $alice.Dispose()
            $bob.Dispose()
        }
    }

    Context "Encryption" {
        It "Should encrypt and decrypt a message" {
            $key = [CryptoProvider]::GetRandomBytes(32)
            $message = "Hello, secure world!"

            $encrypted = [CryptoProvider]::EncryptMessage($message, $key)
            $encrypted | Should -Not -Be $message

            $decrypted = [CryptoProvider]::DecryptMessage($encrypted, $key)
            $decrypted | Should -Be $message

            [CryptoProvider]::ClearBytes($key)
        }

        It "Should fail decryption with wrong key" {
            $key1 = [CryptoProvider]::GetRandomBytes(32)
            $key2 = [CryptoProvider]::GetRandomBytes(32)
            $message = "Secret message"

            $encrypted = [CryptoProvider]::EncryptMessage($message, $key1)

            { [CryptoProvider]::DecryptMessage($encrypted, $key2) } | Should -Throw

            [CryptoProvider]::ClearBytes($key1)
            [CryptoProvider]::ClearBytes($key2)
        }
    }
}

Describe "Identity" {
    Context "Creation" {
        It "Should create pseudonymous identity" {
            $identity = [CryptoIdentity]::new([IdentityMode]::Pseudonymous)

            $identity.Mode | Should -Be ([IdentityMode]::Pseudonymous)
            $identity.Id | Should -Not -BeNullOrEmpty
            $identity.PublicKey | Should -Not -BeNullOrEmpty
            $identity.IsLoaded | Should -Be $true

            $identity.Dispose()
        }

        It "Should create anonymous identity" {
            $identity = [CryptoIdentity]::new([IdentityMode]::Anonymous)

            $identity.Mode | Should -Be ([IdentityMode]::Anonymous)
            $identity.IsLoaded | Should -Be $true

            $identity.Dispose()
        }
    }

    Context "Key Exchange" {
        It "Should derive shared secret between two identities" {
            $alice = [CryptoIdentity]::new([IdentityMode]::Anonymous)
            $bob = [CryptoIdentity]::new([IdentityMode]::Anonymous)

            $aliceSecret = $alice.DeriveSharedSecret($bob.PublicKey)
            $bobSecret = $bob.DeriveSharedSecret($alice.PublicKey)

            [Convert]::ToBase64String($aliceSecret) | Should -Be ([Convert]::ToBase64String($bobSecret))

            $alice.Dispose()
            $bob.Dispose()
        }
    }

    Context "Safety Number" {
        It "Should generate consistent safety number" {
            $alice = [CryptoIdentity]::new([IdentityMode]::Pseudonymous)
            $bob = [CryptoIdentity]::new([IdentityMode]::Pseudonymous)

            $aliceSafety = $alice.GetSafetyNumber($bob.PublicKey)
            $bobSafety = $bob.GetSafetyNumber($alice.PublicKey)

            $aliceSafety | Should -Be $bobSafety
            $aliceSafety.Length | Should -BeGreaterThan 50  # 12 groups of 5 digits + spaces

            $alice.Dispose()
            $bob.Dispose()
        }
    }
}
