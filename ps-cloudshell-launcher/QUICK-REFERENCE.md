# Aviatrix CloudShell Launcher - Quick Reference

## 🚀 One-Line Commands

### Download and Run Interactively
```powershell
iex (irm https://raw.githubusercontent.com/yourusername/yourrepo/main/ps-cloudshell-launcher/deploy-aviatrix-controlplane.ps1)
```

### Quick Deploy (Basic Controller)
```powershell
iex (irm https://your-github-url/deploy-aviatrix-controlplane.ps1) -DeploymentName "quick-ctrl" -Location "East US" -AdminEmail "admin@company.com" -AdminPassword "Secure123!" -CustomerID "aviatrix-abc-123456"
```

### Quick Deploy (With CoPilot)
```powershell
iex (irm https://your-github-url/deploy-aviatrix-controlplane.ps1) -DeploymentName "full-ctrl" -IncludeCopilot $true
```

## 📋 Common Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-DeploymentName` | Deployment identifier | `"my-controller"` |
| `-Location` | Azure region | `"East US"` |
| `-AdminEmail` | Admin email address | `"admin@company.com"` |
| `-AdminPassword` | Secure password | `"MySecure123!"` |
| `-CustomerID` | Aviatrix license ID | `"aviatrix-abc-123456"` |
| `-IncludeCopilot` | Deploy analytics | `$true` or `$false` |
| `-SkipConfirmation` | No interactive prompts | Switch |
| `-TerraformAction` | Action to perform | `"plan"`, `"apply"`, `"destroy"` |

## 🔧 Management Commands

### Plan Before Deploy
```powershell
./deploy-aviatrix-controlplane.ps1 -TerraformAction "plan" -DeploymentName "my-ctrl"
```

### Destroy Deployment
```powershell
./deploy-aviatrix-controlplane.ps1 -TerraformAction "destroy" -SkipConfirmation
```

### Check Status
```powershell
cd ./aviatrix-deployment
terraform show
terraform output
```

## 🌍 Popular Azure Regions

| Region Code | Location | Best For |
|-------------|----------|----------|
| `East US` | Virginia | General use (US) |
| `East US 2` | Virginia | Backup/DR |
| `West US 2` | Washington | West Coast |
| `Central US` | Iowa | Central location |
| `West Europe` | Netherlands | Europe primary |
| `North Europe` | Ireland | Europe backup |
| `Southeast Asia` | Singapore | Asia Pacific |
| `Japan East` | Tokyo | Japan/Asia |
| `Australia East` | Sydney | Australia |
| `UK South` | London | United Kingdom |

## 🔒 Security Checklist

- ✅ Password: 8+ chars, letter+number+symbol
- ✅ Email: Valid corporate email address
- ✅ Customer ID: Format `aviatrix-abc-123456`
- ✅ IP Access: Script auto-detects your public IP
- ✅ HTTPS: All connections encrypted

## ⏱️ Expected Timings

| Component | Time | Notes |
|-----------|------|-------|
| Prerequisites | 1-2 min | Terraform install, validation |
| Controller Deploy | 5-8 min | VM creation, networking |
| Controller Init | 3-5 min | Software setup, API config |
| Account Onboarding | 1-2 min | Azure subscription link |
| CoPilot (optional) | 3-5 min | Additional VM |
| **Total** | **10-15 min** | **Complete deployment** |

## 🏗️ Post-Deployment URLs

After deployment, access your services:

```
Controller:  https://[controller-ip]
CoPilot:     https://[copilot-ip]     (if deployed)
Username:    admin
Password:    [your-configured-password]
```

## 🛠️ Troubleshooting

### Quick Fixes
```powershell
# Re-authenticate Azure
az login

# Check subscription
az account show

# Verify Terraform
terraform version

# Clean restart
Remove-Item ./aviatrix-deployment -Recurse -Force
```

### Common Errors
| Error | Solution |
|-------|----------|
| "Not authenticated" | Run `az login` |
| "Azure AD permissions required" | Run `az login` again or contact Azure AD admin |
| "Invalid customer ID" | Check format: `aviatrix-abc-123456` |
| "Password validation" | 8+ chars, letter+number+symbol |
| "Region unavailable" | Try different Azure region |
| "Quota exceeded" | Choose different region or contact Azure support |

## 📞 Support Resources

- **Documentation**: https://docs.aviatrix.com
- **Support Portal**: https://support.aviatrix.com  
- **Community**: https://community.aviatrix.com
- **GitHub Issues**: [Your repository]/issues

## 🔄 Version Updates

To get the latest version:
```powershell
# Always downloads latest from GitHub
iex (irm https://your-github-url/deploy-aviatrix-controlplane.ps1)
```

## 📝 Example Scenarios

### Development Environment
```powershell
# Quick dev setup
./deploy-aviatrix-controlplane.ps1 -DeploymentName "dev" -Location "Central US"
```

### Production Environment  
```powershell
# Full production with CoPilot
./deploy-aviatrix-controlplane.ps1 -DeploymentName "prod" -Location "East US 2" -IncludeCopilot $true
```

### Disaster Recovery
```powershell
# Secondary region deployment
./deploy-aviatrix-controlplane.ps1 -DeploymentName "dr" -Location "West US 3"
```

---

💡 **Pro Tip**: Bookmark this reference for quick access to commands and troubleshooting!
