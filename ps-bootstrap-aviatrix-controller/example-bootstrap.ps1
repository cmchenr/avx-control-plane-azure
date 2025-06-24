#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Example usage of the Aviatrix Controller Bootstrap script
    
.DESCRIPTION
    This example script demonstrates how to use the bootstrap-aviatrix-controller.ps1 script
    with sample parameters. Modify the variables below with your actual values.
    
.NOTES  
    This is an example script. DO NOT run this with the sample values.
    Update all variables with your actual controller and account information.
#>

# WARNING: Replace these sample values with your actual configuration
$ControllerPublicIP = "1.2.3.4"          # Replace with your controller's public IP
$ControllerPrivateIP = "10.1.1.123"      # Replace with your controller's private IP  
$ControllerAdminEmail = "admin@domain.com" # Replace with your admin email
$ControllerAdminPassword = "MySecure123!" # Replace with your desired secure password
$CustomerID = "aviatrix-abu-123456"       # Replace with your Aviatrix customer ID

# Optional parameters (uncomment and modify as needed)
# $ControllerVersion = "7.1"              # Specific version instead of "latest"
# $WaitDurationMinutes = 15               # Wait longer for setup if needed
# $MaxRetries = 5                         # More retries for unstable networks

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "EXAMPLE SCRIPT - DO NOT RUN AS-IS" -ForegroundColor Yellow  
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "This script shows example usage of the Aviatrix Controller Bootstrap script." -ForegroundColor White
Write-Host "Before running, you must update the variables with your actual values:" -ForegroundColor White
Write-Host ""
Write-Host "Required updates:" -ForegroundColor Red
Write-Host "  - ControllerPublicIP: Your controller's public IP address" -ForegroundColor Gray
Write-Host "  - ControllerPrivateIP: Your controller's private IP address" -ForegroundColor Gray
Write-Host "  - ControllerAdminEmail: Your admin email address" -ForegroundColor Gray
Write-Host "  - ControllerAdminPassword: Your secure admin password" -ForegroundColor Gray
Write-Host "  - CustomerID: Your Aviatrix customer license ID" -ForegroundColor Gray
Write-Host ""

# Validate that sample values haven't been used
if ($ControllerPublicIP -eq "1.2.3.4" -or 
    $ControllerPrivateIP -eq "10.1.1.123" -or
    $ControllerAdminEmail -eq "admin@domain.com" -or
    $ControllerAdminPassword -eq "MySecure123!" -or
    $CustomerID -eq "aviatrix-abu-123456") {
    
    Write-Host "ERROR: Sample values detected!" -ForegroundColor Red
    Write-Host "Please update all variables with your actual values before running." -ForegroundColor Red
    Write-Host ""
    Write-Host "To run the bootstrap script with your values:" -ForegroundColor Yellow
    Write-Host "  1. Edit this file and replace all sample values" -ForegroundColor Gray
    Write-Host "  2. Run this script, or" -ForegroundColor Gray
    Write-Host "  3. Run the bootstrap script directly with parameters:" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Direct usage example:" -ForegroundColor White
    Write-Host "./bootstrap-aviatrix-controller.ps1 \`" -ForegroundColor Gray
    Write-Host "  -ControllerPublicIP `"YOUR_PUBLIC_IP`" \`" -ForegroundColor Gray
    Write-Host "  -ControllerPrivateIP `"YOUR_PRIVATE_IP`" \`" -ForegroundColor Gray
    Write-Host "  -ControllerAdminEmail `"your-email@domain.com`" \`" -ForegroundColor Gray
    Write-Host "  -ControllerAdminPassword `"YourSecurePassword123!`" \`" -ForegroundColor Gray
    Write-Host "  -CustomerID `"your-customer-id`"" -ForegroundColor Gray
    
    exit 1
}

# If we get here, the values have been updated
Write-Host "Values have been updated. Proceeding with bootstrap..." -ForegroundColor Green
Write-Host ""

# Check if the bootstrap script exists
$bootstrapScript = Join-Path (Get-Location) "bootstrap-aviatrix-controller.ps1"
if (-not (Test-Path $bootstrapScript)) {
    Write-Host "ERROR: bootstrap-aviatrix-controller.ps1 not found in current directory!" -ForegroundColor Red
    Write-Host "Please ensure both scripts are in the same directory." -ForegroundColor Red
    exit 1
}

# Run the bootstrap script with the configured parameters
try {
    & $bootstrapScript `
        -ControllerPublicIP $ControllerPublicIP `
        -ControllerPrivateIP $ControllerPrivateIP `
        -ControllerAdminEmail $ControllerAdminEmail `
        -ControllerAdminPassword $ControllerAdminPassword `
        -CustomerID $CustomerID
        # -ControllerVersion $ControllerVersion `      # Uncomment if using specific version
        # -WaitDurationMinutes $WaitDurationMinutes `  # Uncomment if using custom wait time
        # -MaxRetries $MaxRetries                      # Uncomment if using custom retry count
}
catch {
    Write-Host "Bootstrap script failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
