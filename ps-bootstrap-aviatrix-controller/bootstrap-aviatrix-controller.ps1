#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Bootstrap Aviatrix Controller using Azure Cloud Shell
    
.DESCRIPTION
    This PowerShell script provides equivalent functionality to the terraform-aviatrix-controller-init
    Terraform module. It initializes a freshly deployed Aviatrix controller by performing the following steps:
    1. Initial login using admin/private_ip credentials
    2. Set admin email address  
    3. Set notification email
    4. Set customer ID (license)
    5. Change admin password
    6. Initialize controller
    7. Verify setup completion
    
.PARAMETER ControllerPublicIP
    Public IP address of the Aviatrix controller (required)
    
.PARAMETER ControllerPrivateIP
    Private IP address of the Aviatrix controller (required)
    
.PARAMETER ControllerAdminEmail
    Email address for the controller admin (required)
    
.PARAMETER ControllerAdminPassword
    Desired password for the controller admin (required)
    Must be at least 8 characters and contain at least one letter, number, and symbol
    
.PARAMETER CustomerID
    Aviatrix customer license ID (required)
    
.PARAMETER ControllerVersion
    Target controller version (optional, defaults to "latest")
    
.PARAMETER WaitDurationMinutes
    Minutes to wait for controller setup completion (optional, defaults to 10)
    
.PARAMETER MaxRetries
    Maximum number of retries for API calls (optional, defaults to 3)
    
.EXAMPLE
    ./bootstrap-aviatrix-controller.ps1 -ControllerPublicIP "1.2.3.4" -ControllerPrivateIP "10.1.1.123" -ControllerAdminEmail "admin@domain.com" -ControllerAdminPassword "MySecure123!" -CustomerID "aviatrix-abu-123456"

.NOTES
    This script is designed to run in Azure Cloud Shell and requires PowerShell 7+
    The controller must be running and accessible on the provided public IP
    Requires a g3 based controller image for API v2 compatibility
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ControllerPublicIP,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ControllerPrivateIP,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")]
    [string]$ControllerAdminEmail,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if ($_.Length -lt 8) {
            throw "Password must be at least 8 characters long"
        }
        if ($_ -notmatch '\d') {
            throw "Password must contain at least one number"
        }
        if ($_ -notmatch '[a-zA-Z]') {
            throw "Password must contain at least one letter"
        }
        if ($_ -notmatch '[^a-zA-Z0-9]') {
            throw "Password must contain at least one symbol"
        }
        return $true
    })]
    [string]$ControllerAdminPassword,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CustomerID,
    
    [Parameter(Mandatory = $false)]
    [string]$ControllerVersion = "latest",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$WaitDurationMinutes = 10,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3
)

# Set strict mode and error action preference
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Global variables
$BaseUrl = "https://$ControllerPublicIP/v2/api"
$Headers = @{
    "Content-Type" = "application/json"
}
$CID = $null

# Function to make HTTP requests with retry logic
function Invoke-AviatrixAPI {
    param(
        [string]$Action,
        [hashtable]$Body,
        [int]$MaxRetries = 3,
        [int]$RetryIntervalSeconds = 3,
        [int]$TimeoutSeconds = 30
    )
    
    $bodyJson = $Body | ConvertTo-Json -Depth 10
    Write-Host "Making API call: $Action" -ForegroundColor Yellow
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-Host "Attempt $attempt of $MaxRetries..." -ForegroundColor Gray
            
            $response = Invoke-RestMethod -Uri $BaseUrl -Method POST -Body $bodyJson -Headers $Headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds
            
            if ($response.return -eq $true) {
                Write-Host "✓ $Action completed successfully" -ForegroundColor Green
                return $response
            } else {
                throw "API returned false: $($response.reason)"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Host "✗ Attempt $attempt failed: $errorMessage" -ForegroundColor Red
            
            if ($attempt -eq $MaxRetries) {
                throw "Failed after $MaxRetries attempts. Last error: $errorMessage"
            }
            
            Write-Host "Waiting $RetryIntervalSeconds seconds before retry..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryIntervalSeconds
        }
    }
}

# Function to wait with progress indicator
function Wait-WithProgress {
    param(
        [int]$Minutes,
        [string]$Message = "Waiting for controller setup"
    )
    
    $totalSeconds = $Minutes * 60
    Write-Host "$Message ($Minutes minutes)..." -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $totalSeconds; $i += 10) {
        $remaining = $totalSeconds - $i
        $progress = [math]::Round((($i / $totalSeconds) * 100), 0)
        Write-Progress -Activity $Message -Status "$remaining seconds remaining" -PercentComplete $progress
        Start-Sleep -Seconds 10
    }
    
    Write-Progress -Activity $Message -Completed
    Write-Host "✓ Wait period completed" -ForegroundColor Green
}

# Function to validate controller connectivity
function Test-ControllerConnectivity {
    Write-Host "Testing controller connectivity..." -ForegroundColor Yellow
    
    try {
        $testResponse = Invoke-WebRequest -Uri "https://$ControllerPublicIP" -Method HEAD -SkipCertificateCheck -TimeoutSec 10
        Write-Host "✓ Controller is reachable" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Controller is not reachable: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution flow
try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Aviatrix Controller Bootstrap Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "  Controller Public IP: $ControllerPublicIP" -ForegroundColor Gray
    Write-Host "  Controller Private IP: $ControllerPrivateIP" -ForegroundColor Gray
    Write-Host "  Admin Email: $ControllerAdminEmail" -ForegroundColor Gray
    Write-Host "  Customer ID: $CustomerID" -ForegroundColor Gray
    Write-Host "  Target Version: $ControllerVersion" -ForegroundColor Gray
    Write-Host "  Wait Duration: $WaitDurationMinutes minutes" -ForegroundColor Gray
    Write-Host ""
    
    # Step 1: Test connectivity
    if (-not (Test-ControllerConnectivity)) {
        throw "Controller is not accessible. Please verify the public IP and network connectivity."
    }
    
    # Step 2: Initial login to obtain CID
    Write-Host "Step 1: Performing initial login..." -ForegroundColor Cyan
    $loginBody = @{
        action   = "login"
        username = "admin"
        password = $ControllerPrivateIP
    }
    
    $loginResponse = Invoke-AviatrixAPI -Action "Initial Login" -Body $loginBody -MaxRetries 120 -RetryIntervalSeconds 10
    $CID = $loginResponse.CID
    Write-Host "✓ Obtained CID: $CID" -ForegroundColor Green
    Write-Host ""
    
    # Step 3: Set admin email address
    Write-Host "Step 2: Setting admin email address..." -ForegroundColor Cyan
    $emailBody = @{
        action      = "add_admin_email_addr"
        CID         = $CID
        admin_email = $ControllerAdminEmail
    }
    
    Invoke-AviatrixAPI -Action "Set Admin Email" -Body $emailBody -MaxRetries $MaxRetries
    Write-Host ""
    
    # Step 4: Set notification email
    Write-Host "Step 3: Setting notification email..." -ForegroundColor Cyan
    $notificationBody = @{
        action             = "add_notif_email_addr"
        CID                = $CID
        notif_email_args = (@{
            admin_alert = @{
                address = $ControllerAdminEmail
            }
        } | ConvertTo-Json -Depth 3)
    }
    
    Invoke-AviatrixAPI -Action "Set Notification Email" -Body $notificationBody -MaxRetries $MaxRetries
    Write-Host ""
    
    # Step 5: Set customer ID
    Write-Host "Step 4: Setting customer ID..." -ForegroundColor Cyan
    $customerBody = @{
        action      = "setup_customer_id"
        CID         = $CID
        customer_id = $CustomerID
    }
    
    Invoke-AviatrixAPI -Action "Set Customer ID" -Body $customerBody -MaxRetries $MaxRetries
    Write-Host ""
    
    # Step 6: Set admin password
    Write-Host "Step 5: Setting admin password..." -ForegroundColor Cyan
    $passwordBody = @{
        action       = "edit_account_user"
        CID          = $CID
        username     = "admin"
        what         = "password"
        old_password = $ControllerPrivateIP
        new_password = $ControllerAdminPassword
    }
    
    Invoke-AviatrixAPI -Action "Set Admin Password" -Body $passwordBody -MaxRetries $MaxRetries
    Write-Host ""
    
    # Step 7: Initialize controller
    Write-Host "Step 6: Initializing controller..." -ForegroundColor Cyan
    $initBody = @{
        action         = "initial_setup"
        CID            = $CID
        subaction      = "run"
        target_version = $ControllerVersion
    }
    
    Invoke-AviatrixAPI -Action "Initialize Controller" -Body $initBody -MaxRetries 1 -TimeoutSeconds 300
    Write-Host ""
    
    # Step 8: Wait for setup completion
    Write-Host "Step 7: Waiting for setup completion..." -ForegroundColor Cyan
    Wait-WithProgress -Minutes $WaitDurationMinutes -Message "Waiting for controller initialization"
    Write-Host ""
    
    # Step 9: Verify setup completion
    Write-Host "Step 8: Verifying setup completion..." -ForegroundColor Cyan
    $verifyBody = @{
        action   = "login"
        username = "admin"
        password = $ControllerAdminPassword
    }
    
    $verifyResponse = Invoke-AviatrixAPI -Action "Verify Setup" -Body $verifyBody -MaxRetries 10 -RetryIntervalSeconds 10
    Write-Host ""
    
    # Success message
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ CONTROLLER BOOTSTRAP COMPLETED!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Controller Details:" -ForegroundColor White
    Write-Host "  Public IP: $ControllerPublicIP" -ForegroundColor Gray
    Write-Host "  Admin Username: admin" -ForegroundColor Gray
    Write-Host "  Admin Email: $ControllerAdminEmail" -ForegroundColor Gray
    Write-Host "  Controller URL: https://$ControllerPublicIP" -ForegroundColor Gray
    Write-Host ""
    Write-Host "You can now log in to the controller using the admin credentials." -ForegroundColor White
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "✗ BOOTSTRAP FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Verify the controller is running and accessible" -ForegroundColor Gray
    Write-Host "2. Check that the public and private IPs are correct" -ForegroundColor Gray
    Write-Host "3. Ensure the controller is using a g3 based image" -ForegroundColor Gray
    Write-Host "4. Verify network connectivity and firewall rules" -ForegroundColor Gray
    Write-Host "5. Check the customer ID is valid and correctly formatted" -ForegroundColor Gray
    
    exit 1
}
