# Azure Trusted Signing Setup Guide

This guide walks through setting up Azure Trusted Signing (formerly Azure Code Signing) for code signing PSCryptoChat module releases.

## Prerequisites

- Azure account (free tier is sufficient)
- GitHub repository configured with GitHub Actions
- Azure CLI installed (optional, for local testing)

## Step 1: Create Azure Free Account

If you don't have an Azure account:

1. Go to [Azure Free Account](https://azure.microsoft.com/free/)
2. Click **Start free**
3. Sign in with Microsoft account or create one
4. Complete verification (phone + credit card for identity verification only)
5. Accept terms and create account

> **Note:** Azure Trusted Signing has a free tier that includes 5,000 signatures per month.

## Step 2: Create Trusted Signing Account

### Via Azure Portal

1. Go to [Azure Portal](https://portal.azure.com)
2. Search for **"Trusted Signing"** in the search bar
3. Click **Create**
4. Fill in the form:
   - **Subscription:** Your subscription
   - **Resource group:** Create new or use existing (e.g., `rg-codesigning`)
   - **Account name:** e.g., `pscryptochat-signing`
   - **Region:** Choose closest to you
   - **SKU:** Basic (free tier)
5. Click **Review + create**, then **Create**

### Via Azure CLI

```bash
# Login to Azure
az login

# Create resource group (if needed)
az group create --name rg-codesigning --location eastus

# Create Trusted Signing account
az resource create \
  --resource-group rg-codesigning \
  --name pscryptochat-signing \
  --resource-type Microsoft.CodeSigning/codeSigningAccounts \
  --location eastus \
  --properties '{"sku": {"name": "Basic"}}'
```

## Step 3: Create Certificate Profile

### For Private Trust (Recommended for Pre-Release)

Private Trust certificates are:
- Free and instant
- Not publicly trusted (requires manual trust on user machines)
- Good for development, testing, and private distribution

1. In your Trusted Signing account, go to **Certificate profiles**
2. Click **Add**
3. Select **Private Trust** profile type
4. Fill in:
   - **Profile name:** `pscryptochat-private`
   - **Subject name:** `CN=PowerShellYoungTeam, O=PSCryptoChat`
5. Click **Create**

### For Public Trust (Future Production)

Public Trust certificates are:
- Automatically trusted by Windows
- Require identity verification
- May have costs after free tier

## Step 4: Create Service Principal for GitHub Actions

1. Go to **Microsoft Entra ID** (Azure Active Directory)
2. Click **App registrations** → **New registration**
3. Fill in:
   - **Name:** `github-actions-signing`
   - **Supported account types:** Single tenant
4. Click **Register**
5. Note down:
   - **Application (client) ID** → `AZURE_CLIENT_ID`
   - **Directory (tenant) ID** → `AZURE_TENANT_ID`

### Create Client Secret

1. In your app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Description: `GitHub Actions`
4. Expiration: Choose appropriate (e.g., 12 months)
5. Click **Add**
6. Copy the **Value** immediately → `AZURE_CLIENT_SECRET`

### Assign Permissions

1. Go back to your Trusted Signing account
2. Click **Access control (IAM)**
3. Click **Add** → **Add role assignment**
4. Select role: **Code Signing Certificate Profile Signer**
5. Members: Select your `github-actions-signing` app
6. Click **Review + assign**

## Step 5: Configure GitHub Repository

### Add Repository Secrets

Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions**

Add these **Secrets**:
| Name | Value |
|------|-------|
| `AZURE_TENANT_ID` | Your Azure tenant ID |
| `AZURE_CLIENT_ID` | App registration client ID |
| `AZURE_CLIENT_SECRET` | App registration client secret |
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID |
| `PSGALLERY_API_KEY` | Your PowerShell Gallery API key |

### Add Repository Variables

Go to **Variables** tab and add:
| Name | Value |
|------|-------|
| `ENABLE_CODE_SIGNING` | `true` |
| `TRUSTED_SIGNING_ENDPOINT` | `https://eus.codesigning.azure.net/` (adjust for your region) |
| `TRUSTED_SIGNING_ACCOUNT` | `pscryptochat-signing` |
| `TRUSTED_SIGNING_PROFILE` | `pscryptochat-private` |

### Endpoint URLs by Region

| Region | Endpoint URL |
|--------|-------------|
| East US | `https://eus.codesigning.azure.net/` |
| West US | `https://wus.codesigning.azure.net/` |
| West Central US | `https://wcus.codesigning.azure.net/` |
| West US 2 | `https://wus2.codesigning.azure.net/` |
| North Europe | `https://neu.codesigning.azure.net/` |
| West Europe | `https://weu.codesigning.azure.net/` |

## Step 6: Create GitHub Environment

1. Go to **Settings** → **Environments**
2. Click **New environment**
3. Name: `production`
4. Configure protection rules:
   - ✅ Required reviewers (optional)
   - ✅ Wait timer (optional)

## Step 7: Get PowerShell Gallery API Key

1. Go to [PowerShell Gallery](https://www.powershellgallery.com/)
2. Sign in (or create account)
3. Click your username → **API Keys**
4. Click **Create**
5. Fill in:
   - **Key Name:** `PSCryptoChat-Publish`
   - **Glob Pattern:** `PSCryptoChat`
   - **Scopes:** Push new packages and package versions
6. Click **Create**
7. Copy the key → `PSGALLERY_API_KEY`

## Verification

### Test Azure Connection (Local)

```powershell
# Install Azure CLI if needed
winget install Microsoft.AzureCLI

# Login with service principal
az login --service-principal `
  --username $env:AZURE_CLIENT_ID `
  --password $env:AZURE_CLIENT_SECRET `
  --tenant $env:AZURE_TENANT_ID

# List Trusted Signing accounts
az resource list --resource-type Microsoft.CodeSigning/codeSigningAccounts
```

### Test Workflow

1. Create a test tag:
   ```bash
   git tag v0.1.0-test
   git push origin v0.1.0-test
   ```
2. Check GitHub Actions → Publish workflow
3. Delete test tag after verification:
   ```bash
   git tag -d v0.1.0-test
   git push origin :refs/tags/v0.1.0-test
   ```

## Troubleshooting

### "Certificate profile not found"
- Verify profile name matches exactly
- Check service principal has correct role assignment
- Ensure endpoint URL matches your account's region

### "Unauthorized" errors
- Client secret may have expired
- Service principal may lack required permissions
- Subscription ID may be incorrect

### Signature not trusted
- Private Trust signatures require manual trust installation
- For public trust, complete identity verification in Azure Portal

## Security Considerations

1. **Rotate client secrets** regularly (at least annually)
2. **Use environment protection** rules in GitHub for production deploys
3. **Audit signing operations** via Azure Monitor
4. **Limit API key scope** to specific packages in PSGallery

## Resources

- [Azure Trusted Signing Documentation](https://learn.microsoft.com/en-us/azure/trusted-signing/)
- [GitHub Actions for Azure](https://learn.microsoft.com/en-us/azure/developer/github/github-actions)
- [PowerShell Gallery Publishing](https://learn.microsoft.com/en-us/powershell/scripting/gallery/how-to/publishing-packages/publishing-a-package)
