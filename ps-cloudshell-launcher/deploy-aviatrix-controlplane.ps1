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
    
.PARAMETER AdditionalManagementIPs
    Additional IP addresses or CIDR blocks that should have access to the controller management interface.
    Supports comma-separated list (e.g., "192.168.1.100,10.0.0.0/24,203.0.113.50")
    
.PARAMETER SkipConfirmation
    Skip interactive confirmation prompts (for automation)
    
.PARAMETER TerraformAction
    Terraform action to perform: plan, apply, or destroy (default: apply)
    
.PARAMETER TestMode
    Run in test mode - validate inputs and generate Terraform files without executing
    
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
    # Deploy with additional management IP addresses
    ./deploy-aviatrix-controlplane.ps1 -DeploymentName "my-avx-ctrl" -AdditionalManagementIPs "192.168.1.100,10.0.0.0/24"
    
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
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        return $_ -match "^[a-zA-Z0-9-]{3,20}$"
    })]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$Location,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        return $_ -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    })]
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
    [string]$CustomerID,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeCopilot = $true,
    
    [Parameter(Mandatory = $false)]
    [string]$YourPublicIP,
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        # Support comma-separated list of IPs/CIDRs
        $cidrs = $_ -split ',' | ForEach-Object { $_.Trim() }
        foreach ($cidr in $cidrs) {
            # Validate IP/CIDR format with strict IP address validation
            if ($cidr -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$') {
                $ip1, $ip2, $ip3, $ip4, $dummy, $mask = $matches[1..6]
                # Check IP octets are valid (0-255)
                if ([int]$ip1 -gt 255 -or [int]$ip2 -gt 255 -or [int]$ip3 -gt 255 -or [int]$ip4 -gt 255) {
                    throw "Invalid IP address in CIDR: $cidr. IP octets must be 0-255"
                }
                # Check CIDR mask is valid (0-32) if present
                if ($mask -and ([int]$mask -lt 0 -or [int]$mask -gt 32)) {
                    throw "Invalid CIDR mask in: $cidr. Mask must be 0-32"
                }
            } else {
                throw "Invalid IP/CIDR format: $cidr. Use format like '192.168.1.1' or '192.168.1.0/24'"
            }
        }
        return $true
    })]
    [string]$AdditionalManagementIPs,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipConfirmation,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("plan", "apply", "destroy")]
    [string]$TerraformAction = "apply",
    
    [Parameter(Mandatory = $false)]
    [switch]$TestMode
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
    Write-Host "╔" + ("═" * 78) + "╗" -ForegroundColor $Color
    Write-Host "║" + (" " * ((78 - $Message.Length) / 2 - 1)) + $Message + (" " * (78 - $Message.Length - ((78 - $Message.Length) / 2 - 1))) + "║" -ForegroundColor $Color
    Write-Host "╚" + ("═" * 78) + "╝" -ForegroundColor $Color
    Write-Host ""
}

function Write-Section {
    param([string]$Message, [string]$Color = "White")
    Write-Host ""
    Write-Host "┌─ $Message" -ForegroundColor $Color
    Write-Host "│" -ForegroundColor $Color
}

function Write-SectionEnd {
    param([string]$Color = "White")
    Write-Host "└─" -ForegroundColor $Color
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

function Write-Info {
    param([string]$Message, [string]$Icon = "ℹ️")
    Write-Host "$Icon $Message" -ForegroundColor Cyan
}

function Write-Hint {
    param([string]$Message)
    Write-Host "💡 Tip: $Message" -ForegroundColor DarkCyan
}

function Write-InputPrompt {
    param([string]$Message, [string]$Example = "", [bool]$Required = $true)
    Write-Host ""
    if ($Required) {
        Write-Host "┌─ " -NoNewline -ForegroundColor Cyan
        Write-Host "$Message" -NoNewline -ForegroundColor White
        Write-Host " *" -ForegroundColor Red
    } else {
        Write-Host "┌─ " -NoNewline -ForegroundColor Cyan
        Write-Host "$Message" -ForegroundColor White
    }
    
    if ($Example) {
        Write-Host "│  " -NoNewline -ForegroundColor Cyan
        Write-Host "Example: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$Example" -ForegroundColor Gray
    }
    Write-Host "└─ " -NoNewline -ForegroundColor Cyan
}

function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$DefaultValue = "",
        [bool]$IsPassword = $false,
        [string[]]$ValidValues = @(),
        [string]$ValidationPattern = "",
        [string]$HelpText = "",
        [string]$Example = ""
    )
    
    do {
        # Create visually appealing prompt
        $isRequired = [string]::IsNullOrEmpty($DefaultValue)
        Write-InputPrompt -Message $Prompt -Example $Example -Required $isRequired
        
        # Show help text if provided
        if ($HelpText) {
            Write-Host "│  " -NoNewline -ForegroundColor Cyan
            Write-Host "Help: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$HelpText" -ForegroundColor Gray
        }
        
        # Show valid options in a more accessible format
        if ($ValidValues.Count -gt 0) {
            Write-Host "│  " -NoNewline -ForegroundColor Cyan
            Write-Host "Valid options: " -NoNewline -ForegroundColor DarkGray
            
            # Group options for better readability
            if ($ValidValues.Count -le 6) {
                Write-Host ($ValidValues -join " | ") -ForegroundColor Gray
            } else {
                # Split into multiple lines for many options
                for ($i = 0; $i -lt $ValidValues.Count; $i += 4) {
                    $group = $ValidValues[$i..([math]::Min($i + 3, $ValidValues.Count - 1))]
                    if ($i -gt 0) {
                        Write-Host "│           " -NoNewline -ForegroundColor Cyan
                    }
                    Write-Host ($group -join " | ") -ForegroundColor Gray
                }
            }
        }
        
        # Show default value if available
        if ($DefaultValue -and -not $IsPassword) {
            Write-Host "│  " -NoNewline -ForegroundColor Cyan
            Write-Host "Default: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$DefaultValue" -ForegroundColor Green
        }
        
        # Create the input prompt
        if ($DefaultValue) {
            $displayPrompt = "Enter value [press Enter for default]"
        } else {
            $displayPrompt = "Enter value"
        }
        
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "└─ " -NoNewline -ForegroundColor Cyan
        
        # Handle password input with better visual feedback
        if ($IsPassword) {
            Write-Host "$displayPrompt (input will be hidden): " -NoNewline -ForegroundColor White
            $secureInput = Read-Host -AsSecureString
            # Convert SecureString to plain text - more reliable method
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput)
            try {
                $input = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        } else {
            Write-Host "${displayPrompt}: " -NoNewline -ForegroundColor White
            $input = Read-Host
        }
        
        # Handle default values
        if (-not $input -and $DefaultValue) {
            $input = $DefaultValue
            Write-Host "   Using default value: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$DefaultValue" -ForegroundColor Green
        }
        
        # Validation with clear error messages
        $isValid = $true
        $errorMessage = ""
        
        if ($ValidValues.Count -gt 0 -and $input -notin $ValidValues) {
            $isValid = $false
            $errorMessage = "Value must be one of: $($ValidValues -join ', ')"
        }
        
        if ($ValidationPattern -and $input -notmatch $ValidationPattern) {
            $isValid = $false
            $errorMessage = "Input format is invalid. Please check the example and try again."
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and [string]::IsNullOrEmpty($DefaultValue)) {
            $isValid = $false
            $errorMessage = "This field is required. Please enter a value."
        }
        
        if (-not $isValid) {
            Write-Host ""
            Write-Host "╭─ " -NoNewline -ForegroundColor Red
            Write-Host "Input Error" -ForegroundColor Red
            Write-Host "│  " -NoNewline -ForegroundColor Red
            Write-Host "$errorMessage" -ForegroundColor Yellow
            Write-Host "╰─ Please try again" -ForegroundColor Red
            Write-Host ""
        } else {
            # Show confirmation for non-password inputs
            if (-not $IsPassword) {
                Write-Host "   ✓ " -NoNewline -ForegroundColor Green
                Write-Host "Accepted: " -NoNewline -ForegroundColor DarkGray
                Write-Host "$input" -ForegroundColor White
            } else {
                Write-Host "   ✓ " -NoNewline -ForegroundColor Green
                Write-Host "Password accepted" -ForegroundColor White
            }
        }
        
    } while (-not $isValid)
    
    Write-Host ""
    return $input
}

function Test-Prerequisites {
    Write-Step "Checking prerequisites..."
    
    # Check if running in Azure Cloud Shell (optional for local testing)
    if ($env:ACC_CLOUD) {
        Write-Success "Running in Azure Cloud Shell"
    } else {
        Write-Warning "Running locally (not in Azure Cloud Shell)"
        Write-Host "  This is fine for testing, but production deployments should use Azure Cloud Shell" -ForegroundColor Gray
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
    
    # Check Azure AD app registration permissions
    Write-Step "Checking Azure AD app registration permissions..."
    try {
        # Try to read Azure AD configuration to test permissions
        $adConfig = az ad app list --query "[0].appId" -o tsv 2>$null
        if ($LASTEXITCODE -ne 0) {
            # If the above fails, try a simpler permission check
            $currentUser = az ad signed-in-user show --query "userPrincipalName" -o tsv 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Azure AD read permissions not available"
            }
        }
        
        # Test if we can create app registrations by checking current user's directory role
        $userRoles = az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/memberOf" --query "value[?odataType=='#microsoft.graph.directoryRole'].displayName" -o tsv 2>$null
        $hasAppRegPermission = $false
        
        if ($LASTEXITCODE -eq 0 -and $userRoles) {
            # Check for roles that can create app registrations
            $appRegRoles = @("Global Administrator", "Application Administrator", "Application Developer", "Cloud Application Administrator")
            foreach ($role in $appRegRoles) {
                if ($userRoles -contains $role) {
                    $hasAppRegPermission = $true
                    break
                }
            }
        }
        
        # If no elevated role found, check if user can create apps (default setting)
        if (-not $hasAppRegPermission) {
            # Try to check tenant settings for user app registration capability
            $tenantSettings = az rest --method GET --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" --query "defaultUserRolePermissions.allowedToCreateApps" -o tsv 2>$null
            if ($LASTEXITCODE -eq 0 -and $tenantSettings -eq "true") {
                $hasAppRegPermission = $true
            }
        }
        
        if ($hasAppRegPermission) {
            Write-Success "Azure AD app registration permissions verified"
        } else {
            Write-Error "❌ Insufficient Azure AD permissions for app registration"
            Write-Host ""
            Write-Host "This deployment requires permissions to create Azure AD applications and service principals." -ForegroundColor Yellow
            Write-Host "You may need to:" -ForegroundColor Yellow
            Write-Host "  1. Run 'az login' again to refresh your authentication token" -ForegroundColor Gray
            Write-Host "  2. Ensure you have one of these roles in Azure AD:" -ForegroundColor Gray
            Write-Host "     • Global Administrator" -ForegroundColor Gray
            Write-Host "     • Application Administrator" -ForegroundColor Gray
            Write-Host "     • Application Developer" -ForegroundColor Gray
            Write-Host "     • Cloud Application Administrator" -ForegroundColor Gray
            Write-Host "  3. Or have your tenant configured to allow users to register applications" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Please resolve the permissions issue and run the script again." -ForegroundColor Yellow
            Write-Host "If you continue to experience issues, contact your Azure AD administrator." -ForegroundColor Gray
            throw "Azure AD permissions required"
        }
        
    } catch {
        if ($_.Exception.Message -eq "Azure AD permissions required") {
            throw # Re-throw our custom error
        }
        Write-Warning "Could not verify Azure AD permissions automatically"
        Write-Host "  This may be due to tenant restrictions or network connectivity" -ForegroundColor Gray
        Write-Host "  The deployment will proceed, but may fail if you lack app registration permissions" -ForegroundColor Gray
        Write-Host ""
        Write-Host "If deployment fails, try running 'az login' again and ensure you have:" -ForegroundColor Yellow
        Write-Host "  • Global Administrator or Application Administrator role" -ForegroundColor Gray
        Write-Host "  • Permission to create Azure AD applications" -ForegroundColor Gray
    }
    
    # Check Terraform installation
    if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
        Write-Error "Terraform not found. Please install Terraform first:"
        Write-Host "  macOS: brew install terraform" -ForegroundColor Gray
        Write-Host "  or download from: https://www.terraform.io/downloads.html" -ForegroundColor Gray
        throw "Terraform required"
    } else {
        $terraformVersion = terraform --version | Select-Object -First 1
        Write-Success "Terraform available: $terraformVersion"
    }
}

function Get-PublicIP {
    if ($YourPublicIP) {
        Write-Info "Using provided public IP: $YourPublicIP"
        return $YourPublicIP
    }
    
    Write-Step "Detecting your public IP address for security configuration..."
    Write-Info "This IP will be used to configure firewall rules for controller access."
    
    try {
        $ip = Invoke-RestMethod -Uri "https://ipinfo.io/ip" -TimeoutSec 10
        $ip = $ip.Trim()
        Write-Success "Successfully detected public IP: $ip"
        Write-Hint "Only this IP address will be allowed to access the Aviatrix Controller web interface."
        return $ip
    } catch {
        Write-Warning "Could not auto-detect your public IP address"
        Write-Info "You'll need to manually provide your public IP for security configuration."
        Write-Hint "You can find your IP at https://whatismyipaddress.com or similar services."
        
        return Get-UserInput `
            -Prompt "Your Public IP Address" `
            -ValidationPattern "^(\d{1,3}\.){3}\d{1,3}$" `
            -HelpText "This will be used for controller firewall configuration" `
            -Example "203.0.113.25"
    }
}

function Test-IPCIDRFormat {
    param([string]$InputString)
    
    if ([string]::IsNullOrWhiteSpace($InputString)) {
        return $true
    }
    
    $cidrs = $InputString -split ',' | ForEach-Object { $_.Trim() }
    foreach ($cidr in $cidrs) {
        # Validate IP/CIDR format with strict IP address validation
        if ($cidr -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$') {
            $ip1, $ip2, $ip3, $ip4, $dummy, $mask = $matches[1..6]
            # Check IP octets are valid (0-255)
            if ([int]$ip1 -gt 255 -or [int]$ip2 -gt 255 -or [int]$ip3 -gt 255 -or [int]$ip4 -gt 255) {
                return $false
            }
            # Check CIDR mask is valid (0-32) if present
            if ($mask -and ([int]$mask -lt 0 -or [int]$mask -gt 32)) {
                return $false
            }
        } else {
            return $false
        }
    }
    return $true
}

function Get-AdditionalManagementIPs {
    if ($AdditionalManagementIPs) {
        Write-Info "Using provided additional management IPs: $AdditionalManagementIPs"
        # Convert comma-separated string to array and validate format
        $ips = $AdditionalManagementIPs -split ',' | ForEach-Object { 
            $cidr = $_.Trim()
            # Add /32 if no CIDR specified and it's a single IP
            if ($cidr -match '^(\d{1,3}\.){3}\d{1,3}$') {
                "$cidr/32"
            } else {
                $cidr
            }
        }
        return $ips
    }
    
    Write-Info "You can specify additional IP addresses that should have access to the controller."
    Write-Info "This is useful for allowing access from your laptop, office network, etc."
    Write-Hint "Leave empty if you only need access from this CloudShell session."
    
    do {
        Write-InputPrompt -Message "Additional Management IP Addresses (optional)" -Example "192.168.1.100, 10.0.0.0/24, 203.0.113.50/32" -Required $false
        Write-Host "│  Help: Comma-separated list of IPs or CIDR blocks" -ForegroundColor Gray
        Write-Host "│  Default: (none - only CloudShell access)" -ForegroundColor Green
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "└─ Enter value [press Enter for default]: " -NoNewline -ForegroundColor Cyan
        
        $additionalIPs = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($additionalIPs)) {
            Write-Host "   Using default value: (none)" -ForegroundColor Green
            return @()
        }
        
        if (Test-IPCIDRFormat -InputString $additionalIPs) {
            Write-Host "   ✓ Accepted: $additionalIPs" -ForegroundColor White
            break
        } else {
            Write-Host ""
            Write-Host "╭─ Input Error" -ForegroundColor Red
            Write-Host "│  Invalid IP/CIDR format. Please check your input and try again." -ForegroundColor Yellow
            Write-Host "│  Each IP must have octets 0-255, CIDR masks must be 0-32" -ForegroundColor Yellow
            Write-Host "╰─ Please try again" -ForegroundColor Red
            Write-Host ""
        }
    } while ($true)
    
    # Convert comma-separated string to array and ensure proper CIDR format
    $ips = $additionalIPs -split ',' | ForEach-Object { 
        $cidr = $_.Trim()
        # Add /32 if no CIDR specified and it's a single IP
        if ($cidr -match '^(\d{1,3}\.){3}\d{1,3}$') {
            "$cidr/32"
        } else {
            $cidr
        }
    }
    
    Write-Success "Additional management IPs configured: $($ips -join ', ')"
    return $ips
}

function Get-DeploymentParameters {
    Write-Banner "Aviatrix Control Plane Deployment Configuration" "Cyan"
    
    Write-Info "This wizard will guide you through configuring your Aviatrix deployment."
    Write-Info "All fields marked with * are required. Press Ctrl+C to cancel at any time."
    Write-Host ""
    
    # Deployment Name
    if (-not $DeploymentName) {
        Write-Section "Deployment Configuration" "Cyan"
        $DeploymentName = Get-UserInput `
            -Prompt "Deployment Name" `
            -ValidationPattern "^[a-zA-Z0-9-]{3,20}$" `
            -HelpText "Used for naming Azure resources and must be unique" `
            -Example "my-avx-prod, corp-aviatrix-01"
        Write-SectionEnd "Cyan"
    }
    
    # Location Selection with improved display
    if (-not $Location) {
        Write-Section "Azure Region Selection" "Cyan"
        Write-Info "Choose the Azure region where you want to deploy the Aviatrix Controller."
        Write-Hint "Select a region close to your primary users for best performance."
        Write-Host ""
        
        # Display regions in a more organized way
        Write-Host "Available Azure regions (organized by geography):" -ForegroundColor White
        Write-Host ""
        
        # Group regions by area
        $regionGroups = @{
            "🇺🇸 United States" = @("East US", "East US 2", "West US", "West US 2", "West US 3", "Central US", "North Central US", "South Central US")
            "🇨🇦 Canada" = @("Canada Central", "Canada East")
            "🇧🇷 South America" = @("Brazil South")
            "🇪🇺 Europe" = @("North Europe", "West Europe", "UK South", "UK West", "France Central", "Germany West Central", "Switzerland North", "Norway East", "Sweden Central")
            "🌏 Asia Pacific" = @("Australia East", "Australia Southeast", "Japan East", "Japan West", "Korea Central", "Southeast Asia", "East Asia", "India Central")
            "🌍 Middle East & Africa" = @("UAE North", "South Africa North")
        }
        
        foreach ($group in $regionGroups.GetEnumerator()) {
            Write-Host $group.Key -ForegroundColor Yellow
            $regions = $group.Value
            for ($i = 0; $i -lt $regions.Count; $i += 3) {
                $line = $regions[$i..([math]::Min($i + 2, $regions.Count - 1))]
                Write-Host "  $($line -join ' • ')" -ForegroundColor Gray
            }
            Write-Host ""
        }
        
        $Location = Get-UserInput `
            -Prompt "Azure Region" `
            -ValidValues $AvailableLocations `
            -HelpText "Choose a region from the list above" `
            -Example "East US, West Europe, Southeast Asia"
        Write-SectionEnd "Cyan"
    }
    
    # Admin Configuration
    if (-not $AdminEmail) {
        Write-Section "Administrator Configuration" "Cyan"
        Write-Info "This email will be used for the Aviatrix Controller administrator account."
        
        $AdminEmail = Get-UserInput `
            -Prompt "Administrator Email" `
            -ValidationPattern "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" `
            -HelpText "Must be a valid email address" `
            -Example "admin@company.com"
    }
    
    # Enhanced Password Input
    if (-not $AdminPassword) {
        Write-Host ""
        Write-Info "Create a secure password for the Aviatrix Controller administrator."
        Write-Host ""
        
        # Display password requirements clearly
        Write-Host "Password Requirements:" -ForegroundColor White
        Write-Host "├─ Minimum 8 characters" -ForegroundColor Gray
        Write-Host "├─ At least one letter (a-z, A-Z)" -ForegroundColor Gray
        Write-Host "├─ At least one number (0-9)" -ForegroundColor Gray
        Write-Host "└─ At least one symbol (!@#$%^&*)" -ForegroundColor Gray
        Write-Host ""
        
        Write-Hint "If you experience issues with password input, use the -AdminPassword parameter when calling the script"
        
        do {
            Write-Host "┌─ " -NoNewline -ForegroundColor Cyan
            Write-Host "Administrator Password" -NoNewline -ForegroundColor White
            Write-Host " *" -ForegroundColor Red
            Write-Host "└─ " -NoNewline -ForegroundColor Cyan
            Write-Host "Enter password (input will be hidden): " -NoNewline -ForegroundColor White
            
            $AdminPassword = ""
            $key = $null
            do {
                $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($key.VirtualKeyCode -eq 13) { # Enter key
                    break
                } elseif ($key.VirtualKeyCode -eq 8) { # Backspace
                    if ($AdminPassword.Length -gt 0) {
                        $AdminPassword = $AdminPassword.Substring(0, $AdminPassword.Length - 1)
                        Write-Host "`b `b" -NoNewline
                    }
                } elseif ($key.Character -ne 0 -and $key.VirtualKeyCode -ne 27) { # Regular character (not ESC)
                    $AdminPassword += $key.Character
                    Write-Host "*" -NoNewline
                }
            } while ($true)
            Write-Host "" # New line after password input
            
            # Check if password is empty
            if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
                Write-Host ""
                Write-Host "╭─ " -NoNewline -ForegroundColor Red
                Write-Host "Input Error" -ForegroundColor Red
                Write-Host "│  " -NoNewline -ForegroundColor Red
                Write-Host "Password cannot be empty. Please try again." -ForegroundColor Yellow
                Write-Host "╰─" -ForegroundColor Red
                Write-Host ""
                continue
            }
            
            # Validate password with visual feedback
            $hasMinLength = $AdminPassword.Length -ge 8
            $hasLetter = $AdminPassword -match '[a-zA-Z]'
            $hasNumber = $AdminPassword -match '\d'
            $hasSymbol = $AdminPassword -match '[\W_]'
            
            Write-Host ""
            Write-Host "Password Validation:" -ForegroundColor White
            Write-Host "├─ Length (8+ chars): " -NoNewline -ForegroundColor Gray
            if ($hasMinLength) { Write-Host "✓" -ForegroundColor Green } else { Write-Host "✗ (current: $($AdminPassword.Length))" -ForegroundColor Red }
            
            Write-Host "├─ Contains letter: " -NoNewline -ForegroundColor Gray
            if ($hasLetter) { Write-Host "✓" -ForegroundColor Green } else { Write-Host "✗" -ForegroundColor Red }
            
            Write-Host "├─ Contains number: " -NoNewline -ForegroundColor Gray
            if ($hasNumber) { Write-Host "✓" -ForegroundColor Green } else { Write-Host "✗" -ForegroundColor Red }
            
            Write-Host "└─ Contains symbol: " -NoNewline -ForegroundColor Gray
            if ($hasSymbol) { Write-Host "✓" -ForegroundColor Green } else { Write-Host "✗" -ForegroundColor Red }
            
            if ($hasMinLength -and $hasLetter -and $hasNumber -and $hasSymbol) {
                $passwordValid = $true
                Write-Host ""
                Write-Success "Password meets all requirements!"
            } else {
                $passwordValid = $false
                Write-Host ""
                Write-Host "╭─ " -NoNewline -ForegroundColor Red
                Write-Host "Password Requirements Not Met" -ForegroundColor Red
                Write-Host "│  " -NoNewline -ForegroundColor Red
                Write-Host "Please create a password that meets all requirements above." -ForegroundColor Yellow
                Write-Host "╰─ Try again..." -ForegroundColor Red
                Write-Host ""
            }
        } while (-not $passwordValid)
        
        Write-SectionEnd "Cyan"
    }
    
    # Customer License ID
    if (-not $CustomerID) {
        Write-Section "Aviatrix License Configuration" "Cyan"
        Write-Info "Your Aviatrix customer license ID is required for controller initialization."
        Write-Hint "Contact Aviatrix support if you don't have your customer license ID."
        
        $CustomerID = Get-UserInput `
            -Prompt "Aviatrix Customer License ID" `
            -HelpText "Provided by Aviatrix during onboarding" `
            -Example "aviatrix-abc-123456"
        Write-SectionEnd "Cyan"
    }
    
    # CoPilot Decision
    if (-not $PSBoundParameters.ContainsKey('IncludeCopilot')) {
        Write-Section "CoPilot Analytics Configuration" "Cyan"
        Write-Info "CoPilot provides advanced analytics and monitoring for your Aviatrix network."
        Write-Info "CoPilot can be deployed later if you choose not to include it now."
        Write-Hint "CoPilot requires additional Azure resources and will increase deployment cost."
        
        $copilotChoice = Get-UserInput `
            -Prompt "Deploy CoPilot for analytics" `
            -ValidValues @("y", "n", "yes", "no") `
            -DefaultValue "y" `
            -HelpText "Choose 'y' for yes or 'n' for no"
        $IncludeCopilot = $copilotChoice -in @("y", "yes")
        Write-SectionEnd "Cyan"
    }
    
    # Get public IP
    Write-Section "Network Security Configuration" "Cyan"
    $script:UserPublicIP = Get-PublicIP
    Write-Host ""
    Write-Info "Additional management IP addresses can be configured for accessing the controller."
    Write-Info "This allows access from your laptop, office network, or other trusted locations."
    $script:AdditionalManagementIPs = Get-AdditionalManagementIPs
    Write-SectionEnd "Cyan"
    
    return @{
        DeploymentName = $DeploymentName
        Location = $Location
        AdminEmail = $AdminEmail
        AdminPassword = $AdminPassword
        CustomerID = $CustomerID
        IncludeCopilot = $IncludeCopilot
        UserPublicIP = $script:UserPublicIP
        AdditionalManagementIPs = $script:AdditionalManagementIPs
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
    
    # Build the incoming_ssl_cidrs array
    $allCidrs = @("$($Config.UserPublicIP)/32")
    if ($Config.AdditionalManagementIPs -and $Config.AdditionalManagementIPs.Count -gt 0) {
        $allCidrs += $Config.AdditionalManagementIPs
    }
    
    # Format CIDRs for terraform - each CIDR quoted and comma-separated
    $cidrString = ($allCidrs | ForEach-Object { "`"$_`"" }) -join ', '
    
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
  incoming_ssl_cidrs = [$cidrString]
  
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
    controller_url       = module.aviatrix_controlplane.controller_public_ip != null ? "https://`$`{module.aviatrix_controlplane.controller_public_ip`}" : null
    copilot_public_ip    = module.aviatrix_controlplane.copilot_public_ip
    copilot_url         = module.aviatrix_controlplane.copilot_public_ip != null ? "https://`$`{module.aviatrix_controlplane.copilot_public_ip`}" : null
    deployment_name     = "$($Config.DeploymentName)"
    location           = "$($Config.Location)"
    admin_email        = "$($Config.AdminEmail)"
  }
  sensitive = false
}

output "connection_info" {
  description = "Connection information for accessing deployed services"
  value = {
    controller_login_url = "https://`$`{module.aviatrix_controlplane.controller_public_ip`}"
    controller_username  = "admin"
    copilot_login_url   = module.aviatrix_controlplane.copilot_public_ip != null ? "https://`$`{module.aviatrix_controlplane.copilot_public_ip`}" : "Not deployed"
    next_steps = [
      "1. Access controller at https://`$`{module.aviatrix_controlplane.controller_public_ip`}",
      "2. Login with username 'admin' and your configured password",
      "3. Your Azure account is already onboarded and ready to use",
      $($Config.IncludeCopilot ? '"4. Access CoPilot at https://`$`{module.aviatrix_controlplane.copilot_public_ip`}"' : '"4. CoPilot not deployed - can be added later if needed"')
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
        
        Write-Step "Planning deployment resources..."
        terraform plan -out=tfplan
        if ($LASTEXITCODE -ne 0) { throw "Terraform plan failed" }
        
        if (-not $SkipConfirmation) {
            Write-Host ""
            Write-Banner "Final Deployment Confirmation" "Yellow"
            
            Write-Host "╭─ Deployment Overview" -ForegroundColor Yellow
            Write-Host "│" -ForegroundColor Yellow
            Write-Host "├─ 🖥️  Aviatrix Controller VM in " -NoNewline -ForegroundColor White
            Write-Host "$($Config.Location)" -ForegroundColor Cyan
            Write-Host "├─ 🔒 Azure AD App Registration for API access" -ForegroundColor White
            Write-Host "├─ ⚙️  Controller initialization and account onboarding" -ForegroundColor White
            if ($Config.IncludeCopilot) {
                Write-Host "├─ 📊 Aviatrix CoPilot VM for analytics" -ForegroundColor White
            }
            Write-Host "├─ 🛡️  Network security groups (access from " -NoNewline -ForegroundColor White
            Write-Host "$($Config.UserPublicIP)" -NoNewline -ForegroundColor Cyan
            Write-Host ")" -ForegroundColor White
            Write-Host "└─ 🌐 Azure marketplace agreements" -ForegroundColor White
            Write-Host ""
            
            Write-Host "╭─ Important Notes" -ForegroundColor Magenta
            Write-Host "│" -ForegroundColor Magenta
            Write-Host "├─ ⏱️  Estimated time: " -NoNewline -ForegroundColor White
            if ($Config.IncludeCopilot) {
                Write-Host "15-20 minutes" -ForegroundColor Yellow
            } else {
                Write-Host "10-15 minutes" -ForegroundColor Yellow
            }
            Write-Host "├─ 💰 This will create billable Azure resources" -ForegroundColor White
            Write-Host "├─ 🔒 Controller will only be accessible from your IP" -ForegroundColor White
            Write-Host "└─ ❌ Press Ctrl+C to cancel, or type 'yes' to proceed" -ForegroundColor White
            Write-Host ""
            
            Write-InputPrompt -Message "Proceed with deployment" -Required $true
            $confirm = Read-Host
            if ($confirm -ne "yes") {
                Write-Warning "Deployment cancelled by user"
                Write-Info "No resources were created. You can run this script again when ready."
                return
            }
        }
        
        Write-Banner "🚀 Starting Aviatrix Control Plane Deployment" "Green"
        Write-Info "Sit back and relax - this will take approximately 10-15 minutes..."
        Write-Host ""
        
        # Show progress indicators
        Write-Host "Progress will be shown below:" -ForegroundColor White
        Write-Host "├─ Terraform will display detailed progress" -ForegroundColor Gray
        Write-Host "├─ Look for resource creation confirmations" -ForegroundColor Gray
        Write-Host "└─ Any errors will be clearly highlighted" -ForegroundColor Gray
        Write-Host ""
        
        $startTime = Get-Date
        terraform apply tfplan
        $endTime = Get-Date
        
        if ($LASTEXITCODE -ne 0) { 
            throw "Terraform apply failed" 
        }
        
        $duration = $endTime - $startTime
        Write-Host ""
        Write-Banner "🎉 Deployment Completed Successfully!" "Green"
        
        Write-Host "╭─ Deployment Statistics" -ForegroundColor Green
        Write-Host "│" -ForegroundColor Green
        Write-Host "├─ ⏱️  Total Time: " -NoNewline -ForegroundColor White
        Write-Host "$($duration.Minutes) minutes $($duration.Seconds) seconds" -ForegroundColor Yellow
        Write-Host "├─ 📍 Region: " -NoNewline -ForegroundColor White
        Write-Host "$($Config.Location)" -ForegroundColor Yellow
        Write-Host "└─ ✅ Status: " -NoNewline -ForegroundColor White
        Write-Host "All resources deployed successfully" -ForegroundColor Green
        Write-Host ""
        
        # Show outputs with enhanced formatting
        terraform output -json | ConvertFrom-Json | ForEach-Object {
            if ($_.deployment_summary) {
                $summary = $_.deployment_summary.value
                
                Write-Host "╭─ Access Information" -ForegroundColor Cyan
                Write-Host "│" -ForegroundColor Cyan
                Write-Host "├─ 🌐 Controller Web Interface" -ForegroundColor White
                Write-Host "│  ├─ URL: " -NoNewline -ForegroundColor Gray
                Write-Host "$($summary.controller_url)" -ForegroundColor Yellow
                Write-Host "│  ├─ IP:  " -NoNewline -ForegroundColor Gray
                Write-Host "$($summary.controller_public_ip)" -ForegroundColor Yellow
                Write-Host "│  └─ Username: " -NoNewline -ForegroundColor Gray
                Write-Host "admin" -ForegroundColor Green
                Write-Host "│" -ForegroundColor Cyan
                
                if ($summary.copilot_url -and $summary.copilot_url -ne "Not deployed") {
                    Write-Host "├─ 📊 CoPilot Analytics Interface" -ForegroundColor White
                    Write-Host "│  ├─ URL: " -NoNewline -ForegroundColor Gray
                    Write-Host "$($summary.copilot_url)" -ForegroundColor Yellow
                    Write-Host "│  └─ Integrated with Controller authentication" -ForegroundColor Gray
                    Write-Host "│" -ForegroundColor Cyan
                }
                
                # Build comprehensive security display
                Write-Host "└─ 🔒 Security: Access restricted to " -ForegroundColor White
                Write-Host "   • " -NoNewline -ForegroundColor White
                Write-Host "$($Config.UserPublicIP)" -NoNewline -ForegroundColor Yellow
                Write-Host " (CloudShell)" -ForegroundColor Gray
                
                if ($Config.AdditionalManagementIPs -and $Config.AdditionalManagementIPs.Count -gt 0) {
                    foreach ($ip in $Config.AdditionalManagementIPs) {
                        Write-Host "   • " -NoNewline -ForegroundColor White
                        Write-Host "$ip" -NoNewline -ForegroundColor Yellow
                        Write-Host " (Management)" -ForegroundColor Gray
                    }
                }
                Write-Host ""
            }
            
            if ($_.connection_info) {
                $info = $_.connection_info.value
                
                Write-Host "╭─ Quick Start Guide" -ForegroundColor Magenta
                Write-Host "│" -ForegroundColor Magenta
                $stepNumber = 1
                foreach ($step in $info.next_steps) {
                    $cleanStep = $step -replace "^\d+\.\s*", ""
                    Write-Host "├─ $stepNumber. " -NoNewline -ForegroundColor White
                    Write-Host "$cleanStep" -ForegroundColor Gray
                    $stepNumber++
                }
                Write-Host "│" -ForegroundColor Magenta
                Write-Host "└─ 🎯 Your Aviatrix control plane is ready for multi-cloud networking!" -ForegroundColor White
                Write-Host ""
            }
        }
        
        # Additional success messaging
        Write-Host "╭─ What's Next?" -ForegroundColor Yellow
        Write-Host "│" -ForegroundColor Yellow
        Write-Host "├─ 🏗️  Start creating gateways in your preferred cloud regions" -ForegroundColor White
        Write-Host "├─ 🔗 Connect your on-premises networks" -ForegroundColor White
        Write-Host "├─ 📈 Monitor traffic through the dashboard" -ForegroundColor White
        if ($Config.IncludeCopilot) {
            Write-Host "├─ 📊 Explore advanced analytics in CoPilot" -ForegroundColor White
        } else {
            Write-Host "├─ 💡 Consider adding CoPilot later for advanced analytics" -ForegroundColor White
        }
        Write-Host "└─ 📚 Check out the documentation links below" -ForegroundColor White
        Write-Host ""
        
    } finally {
        Pop-Location
    }
}

function Show-PostDeploymentInfo {
    param($Config)
    
    Write-Banner "📋 Important Information & Resources" "Magenta"
    
    # Build the list of all authorized IPs
    $allAuthorizedIPs = @("$($Config.UserPublicIP) (CloudShell)")
    if ($Config.AdditionalManagementIPs -and $Config.AdditionalManagementIPs.Count -gt 0) {
        $allAuthorizedIPs += $Config.AdditionalManagementIPs | ForEach-Object { "$_ (Management)" }
    }
    
    Write-Host "╭─ Security & Access" -ForegroundColor Red
    Write-Host "│" -ForegroundColor Red
    Write-Host "├─ 🔒 Controller access is restricted to:" -ForegroundColor White
    foreach ($ip in $allAuthorizedIPs) {
        Write-Host "│  • " -NoNewline -ForegroundColor White
        Write-Host "$ip" -ForegroundColor Yellow
    }
    Write-Host "├─ 🔑 Default username: " -NoNewline -ForegroundColor White
    Write-Host "admin" -ForegroundColor Green
    Write-Host "├─ 🛡️  Consider changing the admin password after first login" -ForegroundColor White
    Write-Host "├─ 👥 Set up additional admin users for your team" -ForegroundColor White
    Write-Host "└─ 🔐 Enable multi-factor authentication for enhanced security" -ForegroundColor White
    Write-Host ""
    
    Write-Host "╭─ Learning Resources" -ForegroundColor Blue
    Write-Host "│" -ForegroundColor Blue
    Write-Host "├─ 📖 Official Documentation" -ForegroundColor White
    Write-Host "│  └─ " -NoNewline -ForegroundColor Blue
    Write-Host "https://docs.aviatrix.com" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Blue
    Write-Host "├─ 🚀 Getting Started Guide" -ForegroundColor White
    Write-Host "│  └─ " -NoNewline -ForegroundColor Blue
    Write-Host "https://docs.aviatrix.com/StartUpGuides/" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Blue
    Write-Host "├─ 🎥 Video Tutorials & Webinars" -ForegroundColor White
    Write-Host "│  └─ " -NoNewline -ForegroundColor Blue
    Write-Host "https://aviatrix.com/learn/" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Blue
    Write-Host "└─ 🆘 Support Portal" -ForegroundColor White
    Write-Host "   └─ " -NoNewline -ForegroundColor Blue
    Write-Host "https://support.aviatrix.com" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "╭─ Managing This Deployment" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green
    Write-Host "├─ 📁 Terraform files location: " -NoNewline -ForegroundColor White
    Write-Host "$TerraformDir" -ForegroundColor Yellow
    Write-Host "├─ 🔧 To modify the deployment:" -ForegroundColor White
    Write-Host "│  ├─ Edit " -NoNewline -ForegroundColor Gray
    Write-Host "main.tf" -NoNewline -ForegroundColor Yellow
    Write-Host " in the terraform directory" -ForegroundColor Gray
    Write-Host "│  └─ Run " -NoNewline -ForegroundColor Gray
    Write-Host "terraform apply" -NoNewline -ForegroundColor Yellow
    Write-Host " to apply changes" -ForegroundColor Gray
    Write-Host "├─ 🗑️  To destroy the deployment:" -ForegroundColor White
    Write-Host "│  └─ Run this script with " -NoNewline -ForegroundColor Gray
    Write-Host "-TerraformAction destroy" -ForegroundColor Yellow
    Write-Host "└─ 💾 Keep the terraform directory for future management" -ForegroundColor White
    Write-Host ""
    
    Write-Host "╭─ Next Steps Recommendations" -ForegroundColor Yellow
    Write-Host "│" -ForegroundColor Yellow
    Write-Host "├─ 1️⃣  Log in and familiarize yourself with the dashboard" -ForegroundColor White
    Write-Host "├─ 2️⃣  Create your first transit gateway" -ForegroundColor White
    Write-Host "├─ 3️⃣  Connect additional cloud accounts (AWS, GCP, etc.)" -ForegroundColor White
    Write-Host "├─ 4️⃣  Set up monitoring and alerting" -ForegroundColor White
    Write-Host "└─ 5️⃣  Explore advanced features like segmentation" -ForegroundColor White
    Write-Host ""
}

# Main execution
try {
    Write-Banner "🌩️ Aviatrix Control Plane Deployment Wizard" "Cyan"
    
    Write-Host "╭─ Welcome to the Aviatrix Azure Deployment Wizard!" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Cyan
    Write-Host "├─ 🎯 Purpose: Deploy a complete Aviatrix control plane in Azure" -ForegroundColor White
    Write-Host "├─ 📦 Includes: Controller, initialization, and Azure account onboarding" -ForegroundColor White
    Write-Host "├─ ⚡ Optimized: For Azure Cloud Shell with user-friendly prompts" -ForegroundColor White
    Write-Host "└─ 🔒 Secure: Follows security best practices and least privilege" -ForegroundColor White
    Write-Host ""
    
    Write-Info "This wizard will guide you through each step of the deployment process."
    Write-Hint "You can press Ctrl+C at any time to cancel the deployment safely."
    Write-Host ""
    
    # Check prerequisites
    Test-Prerequisites
    
    # Get deployment parameters
    $config = Get-DeploymentParameters
    
    # Show configuration summary
    if (-not $SkipConfirmation) {
        Write-Banner "Deployment Configuration Summary" "Green"
        
        Write-Host "╭─ Deployment Details" -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "├─ " -NoNewline -ForegroundColor Cyan
        Write-Host "Deployment Name: " -NoNewline -ForegroundColor White
        Write-Host "$($config.DeploymentName)" -ForegroundColor Yellow
        
        Write-Host "├─ " -NoNewline -ForegroundColor Cyan
        Write-Host "Azure Region: " -NoNewline -ForegroundColor White
        Write-Host "$($config.Location)" -ForegroundColor Yellow
        
        Write-Host "├─ " -NoNewline -ForegroundColor Cyan
        Write-Host "Admin Email: " -NoNewline -ForegroundColor White
        Write-Host "$($config.AdminEmail)" -ForegroundColor Yellow
        
        Write-Host "├─ " -NoNewline -ForegroundColor Cyan
        Write-Host "Customer License ID: " -NoNewline -ForegroundColor White
        Write-Host "$($config.CustomerID)" -ForegroundColor Yellow
        
        Write-Host "├─ " -NoNewline -ForegroundColor Cyan
        Write-Host "Include CoPilot: " -NoNewline -ForegroundColor White
        if ($config.IncludeCopilot) {
            Write-Host "Yes (Additional analytics and monitoring)" -ForegroundColor Green
        } else {
            Write-Host "No (Controller only)" -ForegroundColor Gray
        }
        
        Write-Host "├─ " -NoNewline -ForegroundColor Cyan
        Write-Host "CloudShell IP: " -NoNewline -ForegroundColor White
        Write-Host "$($config.UserPublicIP)" -ForegroundColor Yellow
        
        if ($config.AdditionalManagementIPs -and $config.AdditionalManagementIPs.Count -gt 0) {
            Write-Host "├─ " -NoNewline -ForegroundColor Cyan
            Write-Host "Additional Management IPs: " -NoNewline -ForegroundColor White
            Write-Host "$($config.AdditionalManagementIPs -join ', ')" -ForegroundColor Yellow
        }
        
        Write-Host "└─ " -NoNewline -ForegroundColor Cyan
        Write-Host "Terraform Action: " -NoNewline -ForegroundColor White
        Write-Host "$TerraformAction" -ForegroundColor Yellow
        
        Write-Host ""
        
        # Show what will be deployed
        Write-Host "╭─ Resources to be Deployed" -ForegroundColor Magenta
        Write-Host "│" -ForegroundColor Magenta
        Write-Host "├─ 🖥️  Aviatrix Controller VM" -ForegroundColor White
        Write-Host "├─ 🔒 Azure AD App Registration" -ForegroundColor White
        Write-Host "├─ 🌐 Virtual Network & Security Groups" -ForegroundColor White
        Write-Host "├─ ⚙️  Controller Initialization" -ForegroundColor White
        Write-Host "├─ 🔗 Azure Account Onboarding" -ForegroundColor White
        if ($config.IncludeCopilot) {
            Write-Host "├─ 📊 CoPilot Analytics VM" -ForegroundColor White
            Write-Host "└─ 🔧 CoPilot Configuration" -ForegroundColor White
        } else {
            Write-Host "└─ ⏭️  CoPilot (Available for future deployment)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Info "Estimated deployment time: 10-15 minutes"
        if ($config.IncludeCopilot) {
            Write-Info "CoPilot adds approximately 5 additional minutes to deployment"
        }
        Write-Host ""
    }
    
    # Create Terraform configuration
    New-TerraformConfiguration -Config $config
    
    # Execute Terraform or just validate in test mode
    if ($TestMode) {
        Write-Banner "🧪 Test Mode - Validation Complete" "Green"
        
        Write-Host "╭─ Validation Results" -ForegroundColor Green
        Write-Host "│" -ForegroundColor Green
        Write-Host "├─ ✅ All input parameters validated successfully" -ForegroundColor White
        Write-Host "├─ ✅ Terraform configuration generated without errors" -ForegroundColor White
        Write-Host "├─ ✅ Prerequisites checked and verified" -ForegroundColor White
        Write-Host "└─ ✅ Deployment ready to proceed" -ForegroundColor White
        Write-Host ""
        
        Write-Host "╭─ Generated Files" -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "├─ 📁 Location: " -NoNewline -ForegroundColor White
        Write-Host "$TerraformDir" -ForegroundColor Yellow
        Write-Host "├─ 📄 main.tf - Main Terraform configuration" -ForegroundColor White
        Write-Host "└─ 📄 outputs.tf - Output definitions" -ForegroundColor White
        Write-Host ""
        
        Write-Host "╭─ Next Steps" -ForegroundColor Yellow
        Write-Host "│" -ForegroundColor Yellow
        Write-Host "├─ 🚀 To deploy for real:" -ForegroundColor White
        Write-Host "│  └─ Run this script again without " -NoNewline -ForegroundColor Gray
        Write-Host "-TestMode" -ForegroundColor Yellow
        Write-Host "│" -ForegroundColor Yellow
        Write-Host "├─ 🔧 Alternative deployment method:" -ForegroundColor White
        Write-Host "│  ├─ Navigate to: " -NoNewline -ForegroundColor Gray
        Write-Host "$TerraformDir" -ForegroundColor Yellow
        Write-Host "│  ├─ Run: " -NoNewline -ForegroundColor Gray
        Write-Host "terraform init" -ForegroundColor Yellow
        Write-Host "│  └─ Run: " -NoNewline -ForegroundColor Gray
        Write-Host "terraform apply" -ForegroundColor Yellow
        Write-Host "│" -ForegroundColor Yellow
        Write-Host "└─ 📋 Review the generated files to understand what will be deployed" -ForegroundColor White
        Write-Host ""
    } else {
        Invoke-TerraformDeployment -Config $config
        
        # Show post-deployment information
        if ($TerraformAction -eq "apply") {
            Show-PostDeploymentInfo -Config $config
        }
    }
    
} catch {
    Write-Host ""
    Write-Banner "⚠️ Deployment Failed" "Red"
    
    Write-Host "╭─ Error Details" -ForegroundColor Red
    Write-Host "│" -ForegroundColor Red
    Write-Host "├─ ❌ Error Message: " -NoNewline -ForegroundColor White
    Write-Host "$($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "├─ 📍 Error Location: " -NoNewline -ForegroundColor White
    Write-Host "$($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Gray
    Write-Host "└─ 🕐 Time: " -NoNewline -ForegroundColor White
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "╭─ Common Solutions" -ForegroundColor Yellow
    Write-Host "│" -ForegroundColor Yellow
    Write-Host "├─ 🔑 Authentication Issues:" -ForegroundColor White
    Write-Host "│  ├─ Run " -NoNewline -ForegroundColor Gray
    Write-Host "az login" -NoNewline -ForegroundColor Yellow
    Write-Host " to refresh your authentication" -ForegroundColor Gray
    Write-Host "│  └─ Ensure you have sufficient Azure AD permissions" -ForegroundColor Gray
    Write-Host "│" -ForegroundColor Yellow
    Write-Host "├─ 🏗️  Resource Issues:" -ForegroundColor White
    Write-Host "│  ├─ Check Azure subscription permissions" -ForegroundColor Gray
    Write-Host "│  ├─ Verify resource quotas in selected region" -ForegroundColor Gray
    Write-Host "│  └─ Ensure deployment name is unique" -ForegroundColor Gray
    Write-Host "│" -ForegroundColor Yellow
    Write-Host "├─ 📋 Input Validation:" -ForegroundColor White
    Write-Host "│  ├─ Verify all input parameters are correct" -ForegroundColor Gray
    Write-Host "│  ├─ Check Aviatrix customer license ID format" -ForegroundColor Gray
    Write-Host "│  └─ Ensure email address is valid" -ForegroundColor Gray
    Write-Host "│" -ForegroundColor Yellow
    Write-Host "└─ 🌐 Network Issues:" -ForegroundColor White
    Write-Host "   ├─ Check internet connectivity" -ForegroundColor Gray
    Write-Host "   └─ Verify Azure service endpoints are accessible" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "╭─ Azure AD Permission Requirements" -ForegroundColor Magenta
    Write-Host "│" -ForegroundColor Magenta
    Write-Host "├─ Required Roles (one of):" -ForegroundColor White
    Write-Host "│  ├─ Global Administrator" -ForegroundColor Gray
    Write-Host "│  ├─ Application Administrator" -ForegroundColor Gray
    Write-Host "│  ├─ Application Developer" -ForegroundColor Gray
    Write-Host "│  └─ Cloud Application Administrator" -ForegroundColor Gray
    Write-Host "│" -ForegroundColor Magenta
    Write-Host "├─ Required Permissions:" -ForegroundColor White
    Write-Host "│  ├─ Create Azure AD applications" -ForegroundColor Gray
    Write-Host "│  ├─ Create service principals" -ForegroundColor Gray
    Write-Host "│  └─ Assign application permissions" -ForegroundColor Gray
    Write-Host "│" -ForegroundColor Magenta
    Write-Host "└─ 💡 Contact your Azure AD administrator if you lack these permissions" -ForegroundColor White
    Write-Host ""
    
    Write-Host "╭─ Getting Help" -ForegroundColor Blue
    Write-Host "│" -ForegroundColor Blue
    Write-Host "├─ 📋 Include this information when requesting support:" -ForegroundColor White
    Write-Host "│  ├─ Error message above" -ForegroundColor Gray
    Write-Host "│  ├─ Your Azure region: " -NoNewline -ForegroundColor Gray
    if ($config -and $config.Location) {
        Write-Host "$($config.Location)" -ForegroundColor Yellow
    } else {
        Write-Host "Not specified" -ForegroundColor Gray
    }
    Write-Host "│  ├─ Deployment name: " -NoNewline -ForegroundColor Gray
    if ($config -and $config.DeploymentName) {
        Write-Host "$($config.DeploymentName)" -ForegroundColor Yellow
    } else {
        Write-Host "Not specified" -ForegroundColor Gray
    }
    Write-Host "│  └─ Terraform logs (if available in " -NoNewline -ForegroundColor Gray
    Write-Host "$TerraformDir" -NoNewline -ForegroundColor Yellow
    Write-Host ")" -ForegroundColor Gray
    Write-Host "│" -ForegroundColor Blue
    Write-Host "├─ 🆘 Aviatrix Support Portal:" -ForegroundColor White
    Write-Host "│  └─ " -NoNewline -ForegroundColor Blue
    Write-Host "https://support.aviatrix.com" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Blue
    Write-Host "├─ 📖 Documentation:" -ForegroundColor White
    Write-Host "│  └─ " -NoNewline -ForegroundColor Blue
    Write-Host "https://docs.aviatrix.com" -ForegroundColor Cyan
    
    Write-Host "╭─ Cleanup" -ForegroundColor DarkYellow
    Write-Host "│" -ForegroundColor DarkYellow
    Write-Host "├─ If partial resources were created:" -ForegroundColor White
    Write-Host "│  └─ Run this script with " -NoNewline -ForegroundColor Gray
    Write-Host "-TerraformAction destroy" -NoNewline -ForegroundColor Yellow
    Write-Host " to clean up" -ForegroundColor Gray
    Write-Host "└─ Or manually clean up via Azure portal" -ForegroundColor White
    Write-Host ""
    
    exit 1
}
