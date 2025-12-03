# Contributing to PSCryptoChat

Thank you for your interest in contributing to PSCryptoChat! This document provides guidelines for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building security-focused software, so thoughtful discussion is essential.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - PowerShell version (`$PSVersionTable`)
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages (if any)

### Suggesting Features

1. Open an issue with the "feature request" label
2. Describe the use case
3. Explain why it benefits the project
4. Consider security implications

### Security Vulnerabilities

**Do not report security issues publicly.** See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`.\tests\IntegrationTest.ps1`)
5. Run PSScriptAnalyzer (`Invoke-ScriptAnalyzer -Path .\src -Recurse`)
6. Commit with clear messages
7. Push and create a Pull Request

## Development Setup

### Prerequisites

- PowerShell 7.0+
- Windows (for CNG cryptography)
- Git
- Optional: Pester 5.x for testing

### Getting Started

```powershell
# Clone your fork
git clone https://github.com/YOUR-USERNAME/PSCryptoChat.git
cd PSCryptoChat

# Import the module
Import-Module .\src\PSCryptoChat\PSCryptoChat.psd1 -Force

# Run quick validation
.\tests\QuickTest.ps1
```

### Running Tests

```powershell
# Quick crypto validation
.\tests\QuickTest.ps1

# Full integration tests
.\tests\IntegrationTest.ps1

# Pester tests
Invoke-Pester .\tests\PSCryptoChat.Tests.ps1

# Code analysis
Invoke-ScriptAnalyzer -Path .\src\PSCryptoChat -Recurse -Severity Warning
```

## Coding Standards

### PowerShell Style

- Use **PascalCase** for function names and parameters
- Use **approved verbs** (`Get-Verb` for list)
- Include **comment-based help** for all public functions
- Follow [PowerShell Best Practices](https://poshcode.gitbook.io/powershell-practice-and-style/)

### Security Requirements

- **Never log sensitive data** (keys, messages, etc.)
- **Clear sensitive data** from memory when done
- **Validate all input** from peers
- **Use constant-time comparisons** for cryptographic values where applicable
- **Document security implications** of any changes

### Example Function

```powershell
function Get-ExampleData {
    <#
    .SYNOPSIS
        Brief description of what the function does

    .DESCRIPTION
        Detailed description including security considerations

    .PARAMETER Name
        Description of the parameter

    .EXAMPLE
        Get-ExampleData -Name "test"
        Shows how to use the function

    .OUTPUTS
        [PSCustomObject] Description of output
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    # Implementation
}
```

### Commit Messages

Use clear, descriptive commit messages:

```
Add session timeout configuration

- Add -Timeout parameter to Start-ChatSession
- Implement automatic key clearing on timeout
- Update help documentation
```

## Project Structure

```
PSCryptoChat/
├── src/PSCryptoChat/
│   ├── PSCryptoChat.psd1    # Module manifest
│   ├── PSCryptoChat.psm1    # Classes and core logic
│   └── Public/              # Exported cmdlets
├── tests/                   # Test files
├── docs/                    # Documentation
└── examples/                # Usage examples
```

## Areas for Contribution

### High Priority

- [ ] Linux/macOS support (OpenSSL backend)
- [ ] Additional Pester test coverage
- [ ] mDNS discovery implementation
- [ ] NAT traversal (STUN/ICE)

### Documentation

- [ ] More usage examples
- [ ] Video tutorials
- [ ] API documentation

### Testing

- [ ] Edge case tests
- [ ] Fuzz testing for message parsing
- [ ] Performance benchmarks

## Review Process

1. All PRs require review before merging
2. Security-related changes require additional scrutiny
3. Tests must pass
4. PSScriptAnalyzer warnings should be addressed or justified

## Questions?

- Open a GitHub Discussion for general questions
- Check existing issues and discussions first

Thank you for contributing! 🔐
