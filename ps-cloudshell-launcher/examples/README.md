# Deployment Examples

This directory contains example scripts and configurations for various Aviatrix control plane deployment scenarios.

## Basic Examples

### 1. Controller Only (Minimal Deployment)
```powershell
# Deploy just the controller with minimum configuration
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "basic-ctrl" `
  -Location "East US" `
  -AdminEmail "admin@company.com" `
  -AdminPassword "MySecure123!" `
  -CustomerID "aviatrix-abc-123456" `
  -IncludeCopilot $false `
  -SkipConfirmation
```

### 2. Full Stack with CoPilot
```powershell
# Deploy complete control plane with analytics
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "full-stack" `
  -Location "West US 2" `
  -AdminEmail "admin@company.com" `
  -AdminPassword "MySecure123!" `
  -CustomerID "aviatrix-abc-123456" `
  -IncludeCopilot $true `
  -SkipConfirmation
```

### 3. Development Environment
```powershell
# Quick deployment for testing/development
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "dev-env" `
  -Location "Central US" `
  -AdminEmail "developer@company.com" `
  -AdminPassword "DevSecure123!" `
  -CustomerID "aviatrix-abc-123456" `
  -SkipConfirmation
```

### 4. Production Environment
```powershell
# Production deployment with specific IP restriction
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "prod-ctrl" `
  -Location "East US 2" `
  -AdminEmail "ops@company.com" `
  -AdminPassword "ProdSecure123!" `
  -CustomerID "aviatrix-abc-123456" `
  -IncludeCopilot $true `
  -IncomingMgmtCIDRs "203.0.113.100" `
  -SkipConfirmation
```

## Advanced Examples

### 5. Multi-Region Planning
```powershell
# Plan deployment in different regions
$regions = @("East US", "West Europe", "Southeast Asia")

foreach ($region in $regions) {
    Write-Host "Planning deployment in $region..."
    ./deploy-aviatrix-controlplane.ps1 `
      -DeploymentName "global-$($region.Replace(' ', '').ToLower())" `
      -Location $region `
      -AdminEmail "global-ops@company.com" `
      -AdminPassword "GlobalSecure123!" `
      -CustomerID "aviatrix-abc-123456" `
      -TerraformAction "plan" `
      -SkipConfirmation
}
```

### 6. Automated Deployment Pipeline
```powershell
# Example for CI/CD pipeline
param(
    [string]$Environment = "dev",
    [string]$CustomerID = $env:AVIATRIX_CUSTOMER_ID,
    [string]$AdminPassword = $env:AVIATRIX_ADMIN_PASSWORD
)

$config = @{
    "dev" = @{
        Location = "Central US"
        IncludeCopilot = $false
    }
    "staging" = @{
        Location = "East US"
        IncludeCopilot = $true
    }
    "prod" = @{
        Location = "East US 2"
        IncludeCopilot = $true
    }
}

./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "$Environment-avx-ctrl" `
  -Location $config[$Environment].Location `
  -AdminEmail "ops@company.com" `
  -AdminPassword $AdminPassword `
  -CustomerID $CustomerID `
  -IncludeCopilot $config[$Environment].IncludeCopilot `
  -SkipConfirmation
```

### 7. Disaster Recovery Setup
```powershell
# Deploy backup controller in different region
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "dr-ctrl" `
  -Location "West US 3" `
  -AdminEmail "dr-ops@company.com" `
  -AdminPassword "DRSecure123!" `
  -CustomerID "aviatrix-abc-123456" `
  -IncludeCopilot $false `
  -SkipConfirmation
```

## Maintenance Examples

### 8. Update Existing Deployment
```powershell
# Add CoPilot to existing controller-only deployment
cd ./aviatrix-deployment

# Edit main.tf to enable CoPilot
(Get-Content main.tf) -replace 'copilot_deployment            = false', 'copilot_deployment            = true' |
Set-Content main.tf

(Get-Content main.tf) -replace 'copilot_initialization        = false', 'copilot_initialization        = true' |
Set-Content main.tf

# Apply changes
terraform plan
terraform apply
```

### 9. Scale Testing
```powershell
# Deploy multiple test environments
1..3 | ForEach-Object {
    $name = "test-env-$_"
    Write-Host "Deploying $name..."
    
    ./deploy-aviatrix-controlplane.ps1 `
      -DeploymentName $name `
      -Location "South Central US" `
      -AdminEmail "test@company.com" `
      -AdminPassword "TestSecure123!" `
      -CustomerID "aviatrix-abc-123456" `
      -SkipConfirmation
}
```

### 10. Clean Up Multiple Deployments
```powershell
# Clean up test environments
$testDeployments = @("test-env-1", "test-env-2", "test-env-3")

foreach ($deployment in $testDeployments) {
    Write-Host "Destroying $deployment..."
    
    # Assuming each deployment has its own directory
    $deployDir = "./aviatrix-deployment-$deployment"
    if (Test-Path $deployDir) {
        Push-Location $deployDir
        terraform destroy -auto-approve
        Pop-Location
        Remove-Item $deployDir -Recurse -Force
    }
}
```

## Error Handling Examples

### 11. Retry on Failure
```powershell
# Deployment with retry logic
$maxAttempts = 3
$attempt = 1

do {
    try {
        Write-Host "Deployment attempt $attempt of $maxAttempts"
        
        ./deploy-aviatrix-controlplane.ps1 `
          -DeploymentName "retry-ctrl" `
          -Location "North Europe" `
          -AdminEmail "admin@company.com" `
          -AdminPassword "RetrySecure123!" `
          -CustomerID "aviatrix-abc-123456" `
          -SkipConfirmation
        
        $success = $true
        break
    }
    catch {
        Write-Warning "Attempt $attempt failed: $($_.Exception.Message)"
        $attempt++
        
        if ($attempt -le $maxAttempts) {
            Write-Host "Waiting 60 seconds before retry..."
            Start-Sleep 60
        }
    }
} while ($attempt -le $maxAttempts -and -not $success)

if (-not $success) {
    Write-Error "All deployment attempts failed"
}
```

### 12. Validation Before Deployment
```powershell
# Pre-deployment validation
param(
    [string]$CustomerID,
    [string]$AdminEmail,
    [string]$Location
)

# Validate Azure quota
$quota = az vm list-usage --location $Location --query "[?name.value=='cores'].{current:currentValue,limit:limit}" -o json | ConvertFrom-Json
if ($quota.current + 8 -gt $quota.limit) {
    throw "Insufficient CPU quota in $Location. Need 8 cores, available: $($quota.limit - $quota.current)"
}

# Validate customer ID format
if ($CustomerID -notmatch '^aviatrix-[a-zA-Z0-9-]+$') {
    throw "Invalid customer ID format. Should be: aviatrix-abc-123456"
}

# Validate email domain
$domain = $AdminEmail.Split('@')[1]
$mxRecord = Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue
if (-not $mxRecord) {
    Write-Warning "Email domain $domain does not have MX record. Proceeding anyway..."
}

Write-Host "Pre-deployment validation passed" -ForegroundColor Green

# Proceed with deployment
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "validated-ctrl" `
  -Location $Location `
  -AdminEmail $AdminEmail `
  -AdminPassword "ValidatedSecure123!" `
  -CustomerID $CustomerID `
  -SkipConfirmation
```

## Custom Configuration Examples

### 13. Custom Terraform Variables
```powershell
# For advanced users who want to modify Terraform directly
./deploy-aviatrix-controlplane.ps1 `
  -DeploymentName "custom-ctrl" `
  -Location "UK South" `
  -AdminEmail "admin@company.com" `
  -AdminPassword "CustomSecure123!" `
  -CustomerID "aviatrix-abc-123456" `
  -TerraformAction "plan"

# Then manually edit the generated main.tf file before applying
cd ./aviatrix-deployment

# Add custom variables (example)
$customConfig = @"

  # Custom VM size
  controller_virtual_machine_size = "Standard_D4s_v3"
  
  # Custom VNET CIDR
  controlplane_vnet_cidr = "10.10.0.0/24"
  
  # Additional incoming CIDRs
  # incoming_ssl_cidrs = ["203.0.113.0/24", "198.51.100.0/24"]
"@

Add-Content -Path main.tf -Value $customConfig

# Apply with custom configuration
terraform apply
```

These examples demonstrate the flexibility of the deployment script for various scenarios from simple development environments to complex production deployments.
