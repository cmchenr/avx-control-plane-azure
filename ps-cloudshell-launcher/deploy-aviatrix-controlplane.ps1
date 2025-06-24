#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Deploy Aviatrix Control Plane in Azure using Terraform - CloudShell Launcher
    
.DESCRIPTION
    This PowerShell script provides a user-friendly wrapper around the terraform-aviatrix-azure-controlplane
    Terraform module. It guides users through deploying a complete Aviatrix control plane in Azure including:
    - Aviatrix Controller VM
    - Controller initialization and configuration
    - Azure AD app registration for API access
    - Azure account onboarding
    - Optional CoPilot deployment for analytics
    - Azure Marketplace agreement acceptance
    
    Designed for execution in Azure Cloud Shell by users who don't know Terraform.
    
.PARAMETER DeploymentName
    Unique name for this deployment (used for controller and resource naming)
    
.PARAMETER Location
    Azure region for deployment (e.g., "East US", "West Europe")
    
.PARAMETER AdminEmail
    Email address for the Aviatrix controller admin
    
.PARAMETER AdminPassword
    Secure password for the controller admin (8+ chars, letter+number+symbol)
    
.PARAMETER CustomerID
    Aviatrix customer license ID (format: aviatrix-abc-123456)
    
.PARAMETER IncludeCopilot
    Deploy optional CoPilot for advanced analytics (default: false)
    
.PARAMETER YourPublicIP
    Your public IP address for controller access (auto-detected if not provided)
    
.PARAMETER SkipConfirmation
    Skip interactive confirmation prompts (for automation)
    
.PARAMETER TerraformAction
    Terraform action to perform: plan, apply, or destroy (default: apply)
    
.EXAMPLE
    # Interactive deployment with prompts
    ./deploy-aviatrix-controlplane.ps1
    
.EXAMPLE
    # Automated deployment with parameters
    ./deploy-aviatrix-controlplane.ps1 -DeploymentName "my-avx-ctrl" -Location "East US" -AdminEmail "admin@company.com" -AdminPassword "MySecure123!" -CustomerID "aviatrix-abc-123456"
    
.EXAMPLE
    # Deploy with CoPilot included
    ./deploy-aviatrix-controlplane.ps1 -DeploymentName "my-avx-ctrl" -IncludeCopilot $true
    
.EXAMPLE
    # One-liner download and execute (replace URL with your GitHub raw URL)
    iex (irm https://raw.githubusercontent.com/yourusername/yourrepo/main/ps-cloudshell-launcher/deploy-aviatrix-controlplane.ps1)
    
.NOTES
    - Requires Azure Cloud Shell (PowerShell)
    - Terraform will be automatically installed if not present
    - Azure CLI authentication is handled by Cloud Shell
    - All sensitive values are handled securely
    - Comprehensive validation and error handling included
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[a-zA-Z0-9-]{3,20}$")]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$Location,
    
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")]
    [string]$AdminEmail,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and $_.Length -lt 8) {
            throw "Password must be at least 8 characters long"
        }
        if ($_ -and $_ -notmatch '\d') {
            throw "Password must contain at least one number"
        }
        if ($_ -and $_ -notmatch '[a-zA-Z]') {
            throw "Password must contain at least one letter"
        }
        if ($_ -and $_ -notmatch '[^a-zA-Z0-9]') {
            throw "Password must contain at least one symbol"
        }
        return $true
    })]
    [string]$AdminPassword,
    
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^aviatrix-[a-zA-Z0-9-]+$")]
    [string]$CustomerID,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeCopilot = $false,
    
    [Parameter(Mandatory = $false)]
    [string]$YourPublicIP,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipConfirmation,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("plan", "apply", "destroy")]
    [string]$TerraformAction = "apply"
)

# Set strict mode and error preferences
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Global variables
$ModuleSource = "terraform-aviatrix-modules/azure-controlplane/aviatrix"
$ModuleVersion = "1.1.0"
$TerraformDir = "./aviatrix-deployment"
$AvailableLocations = @(
    "East US", "East US 2", "West US", "West US 2", "West US 3", "Central US", "North Central US", "South Central US",
    "Canada Central", "Canada East", "Brazil South", "North Europe", "West Europe", "UK South", "UK West",
    "France Central", "Germany West Central", "Switzerland North", "Norway East", "Sweden Central",
    "Australia East", "Australia Southeast", "Japan East", "Japan West", "Korea Central", "Southeast Asia",
    "East Asia", "India Central", "UAE North", "South Africa North"
)

# Helper Functions
function Write-Banner {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor $Color
    Write-Host " $Message" -ForegroundColor $Color
    Write-Host "=" * 80 -ForegroundColor $Color
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "▶ $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$DefaultValue = "",
        [bool]$IsPassword = $false,
        [string[]]$ValidValues = @(),
        [string]$ValidationPattern = ""
    )
    
    do {
        if ($DefaultValue) {
            $displayPrompt = "$Prompt [$DefaultValue]"
        } else {
            $displayPrompt = $Prompt
        }
        
        if ($ValidValues.Count -gt 0) {
            Write-Host "Valid options: $($ValidValues -join ', ')" -ForegroundColor Gray
        }
        
        if ($IsPassword) {
            $secureInput = Read-Host -Prompt $displayPrompt -AsSecureString
            $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput))
        } else {
            $input = Read-Host -Prompt $displayPrompt
        }
        
        if (-not $input -and $DefaultValue) {
            $input = $DefaultValue
        }
        
        # Validation
        $isValid = $true
        $errorMessage = ""
        
        if ($ValidValues.Count -gt 0 -and $input -notin $ValidValues) {
            $isValid = $false
            $errorMessage = "Please enter one of: $($ValidValues -join ', ')"
        }
        
        if ($ValidationPattern -and $input -notmatch $ValidationPattern) {
            $isValid = $false
            $errorMessage = "Input format is invalid"
        }
        
        if (-not $isValid) {
            Write-Error $errorMessage
        }
        
    } while (-not $isValid)
    
    return $input
}

function Test-Prerequisites {
    Write-Step "Checking prerequisites..."
    
    # Check if running in Azure Cloud Shell
    if (-not $env:ACC_CLOUD) {
        Write-Error "This script must be run in Azure Cloud Shell"
        throw "Azure Cloud Shell required"
    }
    
    # Check Azure CLI authentication
    try {
        $account = az account show --query "id" -o tsv 2>$null
        if (-not $account) {
            throw "Not authenticated"
        }
        Write-Success "Azure CLI authenticated (Subscription: $account)"
    } catch {
        Write-Error "Azure CLI not authenticated. Please run 'az login' first."
        throw "Authentication required"
    }
    
    # Install Terraform if needed
    if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
        Write-Step "Installing Terraform..."
        # Download and install Terraform in Cloud Shell
        $terraformUrl = "https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip"
        Invoke-WebRequest -Uri $terraformUrl -OutFile terraform.zip
        Expand-Archive terraform.zip -DestinationPath ~/bin -Force
        Remove-Item terraform.zip
        $env:PATH = "$env:PATH:$HOME/bin"
        Write-Success "Terraform installed"
    } else {
        Write-Success "Terraform already available"
    }
}

function Get-PublicIP {
    if ($YourPublicIP) {
        return $YourPublicIP
    }
    
    Write-Step "Detecting your public IP address..."
    try {
        $ip = Invoke-RestMethod -Uri "https://ipinfo.io/ip" -TimeoutSec 10
        $ip = $ip.Trim()
        Write-Success "Detected public IP: $ip"
        return $ip
    } catch {
        Write-Warning "Could not auto-detect public IP"
        return Get-UserInput -Prompt "Enter your public IP address for controller access" -ValidationPattern "^(\d{1,3}\.){3}\d{1,3}$"
    }
}

function Get-DeploymentParameters {
    Write-Banner "Aviatrix Control Plane Deployment Configuration"
    
    if (-not $DeploymentName) {
        $DeploymentName = Get-UserInput -Prompt "Enter deployment name (3-20 chars, alphanumeric and hyphens only)" -ValidationPattern "^[a-zA-Z0-9-]{3,20}$"
    }
    
    if (-not $Location) {
        Write-Host "Available Azure regions:" -ForegroundColor Gray
        for ($i = 0; $i -lt $AvailableLocations.Count; $i += 4) {
            $line = $AvailableLocations[$i..([math]::Min($i + 3, $AvailableLocations.Count - 1))] -join ", "
            Write-Host "  $line" -ForegroundColor Gray
        }
        $Location = Get-UserInput -Prompt "Enter Azure region" -ValidValues $AvailableLocations
    }
    
    if (-not $AdminEmail) {
        $AdminEmail = Get-UserInput -Prompt "Enter admin email address" -ValidationPattern "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    }
    
    if (-not $AdminPassword) {
        Write-Host "Password requirements: 8+ characters, at least one letter, number, and symbol" -ForegroundColor Gray
        $AdminPassword = Get-UserInput -Prompt "Enter admin password" -IsPassword $true
        
        # Validate password
        if ($AdminPassword.Length -lt 8 -or $AdminPassword -notmatch '\d' -or $AdminPassword -notmatch '[a-zA-Z]' -or $AdminPassword -notmatch '[^a-zA-Z0-9]') {
            Write-Error "Password does not meet requirements"
            throw "Invalid password"
        }
    }
    
    if (-not $CustomerID) {
        Write-Host "Format: aviatrix-abc-123456 (contact Aviatrix support if you don't have this)" -ForegroundColor Gray
        $CustomerID = Get-UserInput -Prompt "Enter Aviatrix customer license ID" -ValidationPattern "^aviatrix-[a-zA-Z0-9-]+$"
    }
    
    if (-not $PSBoundParameters.ContainsKey('IncludeCopilot')) {
        $copilotChoice = Get-UserInput -Prompt "Deploy CoPilot for analytics? (y/n)" -ValidValues @("y", "n", "yes", "no") -DefaultValue "n"
        $IncludeCopilot = $copilotChoice -in @("y", "yes")
    }
    
    $script:UserPublicIP = Get-PublicIP
    
    return @{
        DeploymentName = $DeploymentName
        Location = $Location
        AdminEmail = $AdminEmail
        AdminPassword = $AdminPassword
        CustomerID = $CustomerID
        IncludeCopilot = $IncludeCopilot
        UserPublicIP = $script:UserPublicIP
    }
}

function New-TerraformConfiguration {
    param($Config)
    
    Write-Step "Creating Terraform configuration..."
    
    # Create deployment directory
    if (Test-Path $TerraformDir) {
        Remove-Item $TerraformDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $TerraformDir -Force | Out-Null
    
    # Create main.tf
    $mainTf = @"
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  skip_provider_registration = true
}

module "aviatrix_controlplane" {
  source  = "$ModuleSource"
  version = "$ModuleVersion"

  # Basic Configuration
  controller_name           = "$($Config.DeploymentName)-controller"
  location                  = "$($Config.Location)"
  customer_id              = "$($Config.CustomerID)"
  controller_admin_email    = "$($Config.AdminEmail)"
  controller_admin_password = "$($Config.AdminPassword)"
  
  # Network Security
  incoming_ssl_cidrs = ["$($Config.UserPublicIP)/32"]
  
  # Account Configuration  
  access_account_name = "Azure-Primary"
  account_email      = "$($Config.AdminEmail)"
  
  # Deployment Configuration
  module_config = {
    accept_controller_subscription = true
    accept_copilot_subscription    = $($Config.IncludeCopilot.ToString().ToLower())
    controller_deployment          = true
    controller_initialization      = true
    copilot_deployment            = $($Config.IncludeCopilot.ToString().ToLower())
    copilot_initialization        = $($Config.IncludeCopilot.ToString().ToLower())
    app_registration              = true
    account_onboarding            = true
  }
"@

    if ($Config.IncludeCopilot) {
        $mainTf += @"

  # CoPilot Configuration
  copilot_name = "$($Config.DeploymentName)-copilot"
"@
    }

    $mainTf += @"
}
"@

    # Create outputs.tf
    $outputsTf = @"
output "deployment_summary" {
  description = "Summary of deployed resources"
  value = {
    controller_public_ip  = module.aviatrix_controlplane.controller_public_ip
    controller_private_ip = module.aviatrix_controlplane.controller_private_ip
    controller_url       = "https://`${module.aviatrix_controlplane.controller_public_ip}"
    copilot_public_ip    = module.aviatrix_controlplane.copilot_public_ip
    copilot_url         = module.aviatrix_controlplane.copilot_public_ip != null ? "https://`${module.aviatrix_controlplane.copilot_public_ip}" : null
    app_registration = {
      client_id     = module.aviatrix_controlplane.client_id
      directory_id  = module.aviatrix_controlplane.directory_id
    }
    deployment_name     = "$($Config.DeploymentName)"
    location           = "$($Config.Location)"
    admin_email        = "$($Config.AdminEmail)"
  }
  sensitive = false
}

output "connection_info" {
  description = "Connection information for accessing deployed services"
  value = {
    controller_login_url = "https://`${module.aviatrix_controlplane.controller_public_ip}"
    controller_username  = "admin"
    copilot_login_url   = module.aviatrix_controlplane.copilot_public_ip != null ? "https://`${module.aviatrix_controlplane.copilot_public_ip}" : "Not deployed"
    next_steps = [
      "1. Access controller at https://`${module.aviatrix_controlplane.controller_public_ip}",
      "2. Login with username 'admin' and your configured password",
      "3. Your Azure account is already onboarded and ready to use",
      $($Config.IncludeCopilot ? '"4. Access CoPilot at https://${module.aviatrix_controlplane.copilot_public_ip}"' : '"4. CoPilot not deployed - can be added later if needed"')
    ]
  }
}
"@

    # Write files
    Set-Content -Path "$TerraformDir/main.tf" -Value $mainTf
    Set-Content -Path "$TerraformDir/outputs.tf" -Value $outputsTf
    
    Write-Success "Terraform configuration created in $TerraformDir"
}

function Invoke-TerraformDeployment {
    param($Config)
    
    Push-Location $TerraformDir
    try {
        Write-Step "Initializing Terraform..."
        terraform init
        if ($LASTEXITCODE -ne 0) { throw "Terraform init failed" }
        Write-Success "Terraform initialized"
        
        if ($TerraformAction -eq "plan") {
            Write-Step "Running Terraform plan..."
            terraform plan
            return
        }
        
        if ($TerraformAction -eq "destroy") {
            Write-Step "Running Terraform destroy..."
            if (-not $SkipConfirmation) {
                $confirm = Read-Host "Are you sure you want to destroy the deployment? (yes/no)"
                if ($confirm -ne "yes") {
                    Write-Warning "Destroy cancelled"
                    return
                }
            }
            terraform destroy -auto-approve
            return
        }
        
        # Apply (default)
        Write-Step "Validating Terraform configuration..."
        terraform validate
        if ($LASTEXITCODE -ne 0) { throw "Terraform validation failed" }
        
        Write-Step "Planning deployment..."
        terraform plan -out=tfplan
        if ($LASTEXITCODE -ne 0) { throw "Terraform plan failed" }
        
        if (-not $SkipConfirmation) {
            Write-Host ""
            Write-Host "Review the plan above. This will deploy:" -ForegroundColor Yellow
            Write-Host "  • Aviatrix Controller VM in $($Config.Location)" -ForegroundColor Gray
            Write-Host "  • Azure AD App Registration for API access" -ForegroundColor Gray
            Write-Host "  • Controller initialization and account onboarding" -ForegroundColor Gray
            if ($Config.IncludeCopilot) {
                Write-Host "  • Aviatrix CoPilot VM for analytics" -ForegroundColor Gray
            }
            Write-Host "  • Network security groups (allowing access from $($Config.UserPublicIP))" -ForegroundColor Gray
            Write-Host ""
            
            $confirm = Read-Host "Proceed with deployment? (yes/no)"
            if ($confirm -ne "yes") {
                Write-Warning "Deployment cancelled"
                return
            }
        }
        
        Write-Banner "Starting Aviatrix Control Plane Deployment" "Green"
        Write-Host "This will take approximately 10-15 minutes..." -ForegroundColor Yellow
        Write-Host ""
        
        $startTime = Get-Date
        terraform apply tfplan
        $endTime = Get-Date
        
        if ($LASTEXITCODE -ne 0) { 
            throw "Terraform apply failed" 
        }
        
        $duration = $endTime - $startTime
        Write-Success "Deployment completed in $($duration.Minutes) minutes $($duration.Seconds) seconds"
        
        # Show outputs
        Write-Banner "Deployment Summary" "Green"
        terraform output -json | ConvertFrom-Json | ForEach-Object {
            if ($_.deployment_summary) {
                $summary = $_.deployment_summary.value
                Write-Host "Controller URL: " -NoNewline -ForegroundColor Yellow
                Write-Host $summary.controller_url -ForegroundColor White
                Write-Host "Controller IP:  " -NoNewline -ForegroundColor Yellow  
                Write-Host $summary.controller_public_ip -ForegroundColor White
                
                if ($summary.copilot_url) {
                    Write-Host "CoPilot URL:    " -NoNewline -ForegroundColor Yellow
                    Write-Host $summary.copilot_url -ForegroundColor White
                }
            }
            
            if ($_.connection_info) {
                $info = $_.connection_info.value
                Write-Host ""
                Write-Host "Next Steps:" -ForegroundColor Yellow
                foreach ($step in $info.next_steps) {
                    Write-Host "  $step" -ForegroundColor Gray
                }
            }
        }
        
        Write-Host ""
        Write-Success "Aviatrix Control Plane deployment completed successfully!"
        Write-Host "You can now log in to your controller and start building your multi-cloud network." -ForegroundColor White
        
    } finally {
        Pop-Location
    }
}

function Show-PostDeploymentInfo {
    Write-Banner "Important Information" "Magenta"
    
    Write-Host "🔐 Security Notes:" -ForegroundColor Yellow
    Write-Host "  • Controller is accessible only from your IP: $script:UserPublicIP" -ForegroundColor Gray
    Write-Host "  • Change the admin password after first login if desired" -ForegroundColor Gray
    Write-Host "  • Consider setting up additional admin users" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "📚 Resources:" -ForegroundColor Yellow
    Write-Host "  • Aviatrix Documentation: https://docs.aviatrix.com" -ForegroundColor Gray
    Write-Host "  • Getting Started Guide: https://docs.aviatrix.com/StartUpGuides/aviatrix-cloud-controller-startup-guide.html" -ForegroundColor Gray
    Write-Host "  • Support Portal: https://support.aviatrix.com" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "🛠️  Managing This Deployment:" -ForegroundColor Yellow
    Write-Host "  • Terraform files are in: $TerraformDir" -ForegroundColor Gray
    Write-Host "  • To modify: Edit main.tf and run 'terraform apply'" -ForegroundColor Gray
    Write-Host "  • To destroy: Run this script with -TerraformAction destroy" -ForegroundColor Gray
    Write-Host ""
}

# Main execution
try {
    Write-Banner "Aviatrix Control Plane Deployment - Azure Cloud Shell" "Cyan"
    Write-Host "This script will deploy a complete Aviatrix control plane in your Azure subscription." -ForegroundColor White
    Write-Host "The deployment includes controller, initialization, and account onboarding." -ForegroundColor White
    Write-Host ""
    
    # Check prerequisites
    Test-Prerequisites
    
    # Get deployment parameters
    $config = Get-DeploymentParameters
    
    # Show configuration summary
    if (-not $SkipConfirmation) {
        Write-Banner "Deployment Configuration Summary"
        Write-Host "Deployment Name:    $($config.DeploymentName)" -ForegroundColor Gray
        Write-Host "Location:           $($config.Location)" -ForegroundColor Gray
        Write-Host "Admin Email:        $($config.AdminEmail)" -ForegroundColor Gray
        Write-Host "Customer ID:        $($config.CustomerID)" -ForegroundColor Gray
        Write-Host "Include CoPilot:    $($config.IncludeCopilot)" -ForegroundColor Gray
        Write-Host "Your Public IP:     $($config.UserPublicIP)" -ForegroundColor Gray
        Write-Host "Terraform Action:   $TerraformAction" -ForegroundColor Gray
        Write-Host ""
    }
    
    # Create Terraform configuration
    New-TerraformConfiguration -Config $config
    
    # Execute Terraform
    Invoke-TerraformDeployment -Config $config
    
    # Show post-deployment information
    if ($TerraformAction -eq "apply") {
        Show-PostDeploymentInfo
    }
    
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  • Check your Azure subscription permissions" -ForegroundColor Gray
    Write-Host "  • Verify all input parameters are correct" -ForegroundColor Gray
    Write-Host "  • Check Azure resource quotas in the selected region" -ForegroundColor Gray
    Write-Host "  • Ensure your Aviatrix customer ID is valid" -ForegroundColor Gray
    Write-Host "  • Review any Terraform error messages above" -ForegroundColor Gray
    Write-Host ""
    Write-Host "For support, visit: https://support.aviatrix.com" -ForegroundColor Gray
    
    exit 1
}
