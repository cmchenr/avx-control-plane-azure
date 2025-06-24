# Aviatrix Control Plane CloudShell Launcher

A PowerShell script that provides a user-friendly wrapper around the [terraform-aviatrix-azure-controlplane](../terraform-aviatrix-azure-controlplane-main/) Terraform module for deploying Aviatrix control plane infrastructure in Azure.

## 🚀 Quick Start - One-Line Deployment

Execute directly from GitHub (replace with your actual GitHub URL):

```powershell
iex (irm https://raw.githubusercontent.com/cmchenr/avx-control-plane-azure/refs/heads/main/ps-cloudshell-launcher/deploy-aviatrix-controlplane.ps1)
```

## 📋 Prerequisites

- **Azure Cloud Shell** (PowerShell mode required)
- **Azure CLI** authenticated (automatic in Cloud Shell)
- **Valid Aviatrix license** (customer ID)
- **Appropriate Azure permissions** (Contributor role or equivalent)

## 🎯 What This Script Deploys

### Core Components (Always Deployed)
- ✅ **Aviatrix Controller VM** - The main control plane
- ✅ **Controller Initialization** - Automated setup and configuration  
- ✅ **Azure AD App Registration** - For API access permissions
- ✅ **Azure Account Onboarding** - Connects your subscription to the controller
- ✅ **Network Security Groups** - Secure access from your IP only
- ✅ **Azure Marketplace Agreements** - Automatic acceptance of terms

### Optional Components
- 🔹 **Aviatrix CoPilot** - Advanced analytics and monitoring platform

## 📖 Usage Examples

### Interactive Mode (Recommended for First-Time Users)
```powershell
./deploy-aviatrix-controlplane.ps1
```
The script will prompt you for all required information with helpful guidance.

### Automated Mode (For Experienced Users)
```powershell
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "my-avx-ctrl" `
  -Location "East US" `
  -AdminEmail "admin@company.com" `
  -AdminPassword "MySecure123!" `
  -CustomerID "aviatrix-abc-123456"
```

### Deploy with CoPilot
```powershell
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "my-avx-ctrl" `
  -IncludeCopilot $true `
  -SkipConfirmation
```

### Planning Mode (Review Before Deploy)
```powershell
./deploy-aviatrix-controlplane.ps1 `
  -TerraformAction "plan" `
  -DeploymentName "my-avx-ctrl"
```

### Destroy Deployment
```powershell
./deploy-aviatrix-controlplane.ps1 `
  -TerraformAction "destroy" `
  -DeploymentName "my-avx-ctrl"
```

## 🔧 Parameters Reference

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `DeploymentName` | No* | Unique name for deployment (3-20 chars) | `"my-avx-ctrl"` |
| `Location` | No* | Azure region | `"East US"` |
| `AdminEmail` | No* | Controller admin email | `"admin@company.com"` |
| `AdminPassword` | No* | Secure admin password | `"MySecure123!"` |
| `CustomerID` | No* | Aviatrix license ID | `"aviatrix-abc-123456"` |
| `IncludeCopilot` | No | Deploy CoPilot analytics | `$true` or `$false` |
| `YourPublicIP` | No | Your public IP (auto-detected) | `"203.0.113.1"` |
| `SkipConfirmation` | No | Skip interactive prompts | Switch parameter |
| `TerraformAction` | No | Terraform action | `"plan"`, `"apply"`, `"destroy"` |

*\* Required if not running in interactive mode*

## 🔒 Security Features

- **IP Whitelisting**: Controller access restricted to your public IP
- **Secure Credentials**: Passwords handled securely with validation
- **Azure AD Integration**: Proper RBAC roles and permissions
- **HTTPS Only**: All web interfaces use SSL/TLS
- **Input Validation**: Comprehensive parameter validation

## ⏱️ Deployment Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Prerequisites | 1-2 min | Terraform install, Azure auth check |
| Terraform Plan | 1-2 min | Configuration validation |
| Infrastructure | 5-8 min | VM deployment, networking |
| Controller Init | 3-5 min | Software setup, API configuration |
| Account Onboarding | 1-2 min | Azure subscription connection |
| CoPilot (if enabled) | 3-5 min | Additional VM and configuration |
| **Total** | **10-15 min** | **Complete deployment** |

## 📊 Post-Deployment

### Accessing Your Controller
After successful deployment, you'll receive:
- **Controller URL**: `https://[controller-ip]`
- **Username**: `admin`
- **Password**: Your configured password
- **CoPilot URL**: `https://[copilot-ip]` (if deployed)

### Next Steps
1. Log in to the controller web interface
2. Explore the dashboard and verify account onboarding
3. Review the [Aviatrix Getting Started Guide](https://docs.aviatrix.com/StartUpGuides/aviatrix-cloud-controller-startup-guide.html)
4. Begin creating your multi-cloud network architecture

## 🛠️ Managing Your Deployment

### Terraform Files Location
All Terraform configuration is saved in: `./aviatrix-deployment/`

### Making Changes
```powershell
cd ./aviatrix-deployment
# Edit main.tf as needed
terraform plan
terraform apply
```

### Adding CoPilot Later
Re-run the script with `-IncludeCopilot $true` to add CoPilot to an existing deployment.

### Cleanup
```powershell
./deploy-aviatrix-controlplane.ps1 -TerraformAction destroy
```

## ❓ Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Not authenticated" | Run `az login` in Cloud Shell |
| "Terraform not found" | Script auto-installs - ensure ~/bin is in PATH |
| "Invalid customer ID" | Contact Aviatrix support for license |
| "Password validation failed" | Use 8+ chars with letter+number+symbol |
| "Region not available" | Try different Azure region |
| "IP detection failed" | Manually specify `-YourPublicIP` parameter |

### Getting Help
- **Aviatrix Documentation**: https://docs.aviatrix.com
- **Support Portal**: https://support.aviatrix.com
- **Community**: https://community.aviatrix.com

### Debug Mode
Add `-Verbose` to any command for detailed logging:
```powershell
./deploy-aviatrix-controlplane.ps1 -Verbose
```

## 🔄 Comparison with Terraform Module

This script wraps the [terraform-aviatrix-azure-controlplane](../terraform-aviatrix-azure-controlplane-main/) module and provides:

| Feature | Direct Terraform | This Script |
|---------|------------------|-------------|
| Terraform Knowledge Required | ✅ Required | ❌ Not needed |
| Azure CLI Setup | Manual | ✅ Automated |
| IP Detection | Manual | ✅ Automated |
| Input Validation | Limited | ✅ Comprehensive |
| Error Handling | Basic | ✅ User-friendly |
| Interactive Mode | No | ✅ Yes |
| One-line Deploy | No | ✅ Yes |

## 📝 Examples Directory

See the [examples](examples/) directory for additional deployment scenarios:
- Basic controller-only deployment
- Full stack with CoPilot
- Custom networking scenarios
- Multi-region deployments

## 🤝 Contributing

This script is designed to be simple and self-contained. For enhancements:
1. Test thoroughly in Azure Cloud Shell
2. Maintain backward compatibility
3. Update documentation
4. Follow PowerShell best practices

## 📄 License

This script is provided under the same license as the Aviatrix Terraform modules. Use in accordance with your Aviatrix license agreement.
