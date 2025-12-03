# Repository Setup Checklist

Complete these steps to prepare PSCryptoChat for public release on PowerShell Gallery.

## Pre-Release Checklist

### ✅ Completed (via cleanup-and-docs branch)

- [x] License updated to MIT
- [x] Module manifest has real GUID, ProjectUri, LicenseUri
- [x] Platform support documented in README
- [x] Connection flow documentation created
- [x] Codebase cleaned (PSScriptAnalyzer passes)
- [x] Test coverage expanded (81 pass, 4 skip)
- [x] Community files created (CHANGELOG, SECURITY, CONTRIBUTING)
- [x] Example scripts created
- [x] Research docs updated with implementation status
- [x] CI workflow created (.github/workflows/ci.yml)
- [x] Publish workflow created (.github/workflows/publish.yml)
- [x] Azure Trusted Signing guide created

---

## Step 1: Merge cleanup-and-docs Branch

```bash
# In GitHub or locally:
git checkout main
git merge cleanup-and-docs
git push origin main
```

Or create a Pull Request from `cleanup-and-docs` → `main` and merge.

---

## Step 2: Make Repository Public

1. Go to: **GitHub → Repository → Settings → General**
2. Scroll to **Danger Zone**
3. Click **Change visibility**
4. Select **Public**
5. Type repository name to confirm
6. Click **I understand, change visibility**

---

## Step 3: Add GitHub Secrets

Go to: **Settings → Secrets and variables → Actions → Secrets tab**

| Secret Name | Description | How to Get |
|-------------|-------------|------------|
| `AZURE_TENANT_ID` | Azure AD tenant ID | Azure Portal → Entra ID → Overview |
| `AZURE_CLIENT_ID` | Service principal app ID | Azure Portal → App registrations |
| `AZURE_CLIENT_SECRET` | Service principal secret | Azure Portal → App registration → Certificates & secrets |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID | Azure Portal → Subscriptions |
| `PSGALLERY_API_KEY` | PowerShell Gallery API key | [powershellgallery.com](https://www.powershellgallery.com) → API Keys |

### Get PowerShell Gallery API Key

1. Go to https://www.powershellgallery.com/account/apikeys
2. Sign in (or create account)
3. Click **Create**
4. Name: `PSCryptoChat-Publish`
5. Glob Pattern: `PSCryptoChat`
6. Scopes: ✅ Push new packages and package versions
7. Expiration: 365 days
8. Copy the key immediately

---

## Step 4: Add GitHub Variables

Go to: **Settings → Secrets and variables → Actions → Variables tab**

| Variable Name | Value | Notes |
|---------------|-------|-------|
| `ENABLE_CODE_SIGNING` | `false` | Set to `true` after Azure setup |
| `TRUSTED_SIGNING_ENDPOINT` | `https://eus.codesigning.azure.net/` | Adjust for your region |
| `TRUSTED_SIGNING_ACCOUNT` | `pscryptochat-signing` | Your account name |
| `TRUSTED_SIGNING_PROFILE` | `pscryptochat-private` | Your profile name |

> **Note:** Start with `ENABLE_CODE_SIGNING=false` to test publishing without signing first.

---

## Step 5: Create Production Environment

1. Go to: **Settings → Environments**
2. Click **New environment**
3. Name: `production`
4. Click **Configure environment**
5. Optional protections:
   - ✅ Required reviewers (add yourself)
   - ✅ Wait timer: 5 minutes

---

## Step 6: Enable Branch Protection

1. Go to: **Settings → Branches**
2. Click **Add branch protection rule**
3. Branch name pattern: `main`
4. Enable:
   - ✅ Require a pull request before merging
   - ✅ Require status checks to pass before merging
     - Search and add: `Test on Windows`
   - ✅ Require branches to be up to date before merging
   - ✅ Do not allow bypassing the above settings
5. Click **Create**

---

## Step 7: Test CI Workflow

1. Create a test branch:
   ```bash
   git checkout -b test-ci
   echo "# Test" >> test.md
   git add test.md
   git commit -m "Test CI workflow"
   git push origin test-ci
   ```

2. Create Pull Request to `main`

3. Verify CI workflow runs:
   - ✅ PSScriptAnalyzer passes
   - ✅ Pester tests pass
   - ✅ Module manifest validates

4. Delete test branch after verification

---

## Step 8: Test Publish Workflow (Dry Run)

First publish without code signing:

1. Ensure `ENABLE_CODE_SIGNING` variable is `false`
2. Update version in `PSCryptoChat.psd1` if needed
3. Create and push tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. Watch **Actions → Publish** workflow
5. Verify module appears on PowerShell Gallery

---

## Step 9: Set Up Azure Trusted Signing (Optional)

See [Azure-Trusted-Signing-Setup.md](./Azure-Trusted-Signing-Setup.md) for detailed steps.

After Azure setup:
1. Add Azure secrets (Step 3)
2. Set `ENABLE_CODE_SIGNING` to `true`
3. Next release will be signed

---

## Post-Release Checklist

After first successful publish:

- [ ] Verify module installs: `Install-Module PSCryptoChat -Scope CurrentUser`
- [ ] Verify module imports: `Import-Module PSCryptoChat`
- [ ] Test basic functionality: `New-CryptoIdentity -Anonymous`
- [ ] Check PowerShell Gallery page looks correct
- [ ] Add topics to GitHub repository (powershell, encryption, chat, p2p)
- [ ] Update repository description
- [ ] Consider creating a GitHub Release with release notes

---

## Troubleshooting

### CI Workflow Fails

- Check PSScriptAnalyzer output for errors
- Ensure all test files exist
- Verify module manifest is valid

### Publish Workflow Fails

- Verify `PSGALLERY_API_KEY` secret is set correctly
- Check API key hasn't expired
- Ensure version number is incremented (can't republish same version)

### Code Signing Fails

- Verify all Azure secrets are correct
- Check service principal has correct permissions
- Ensure Trusted Signing endpoint matches your region

---

## Quick Reference

| Action | Command/URL |
|--------|-------------|
| Install module | `Install-Module PSCryptoChat` |
| Import module | `Import-Module PSCryptoChat` |
| View on Gallery | https://www.powershellgallery.com/packages/PSCryptoChat |
| Repository | https://github.com/PowerShellYoungTeam/PSCryptoChat |
| CI Status | Check Actions tab in GitHub |
