#!/usr/bin/env pwsh

<#
.SYNOPSIS
    One-liner deployment example for Aviatrix Control Plane
    
.DESCRIPTION
    This script demonstrates how to deploy Aviatrix control plane with a single command.
    It sets up a basic controller deployment suitable for getting started.
    
.EXAMPLE
    # Interactive mode - script will prompt for all required values
    iex (irm https://raw.githubusercontent.com/yourusername/yourrepo/main/ps-cloudshell-launcher/examples/one-liner-example.ps1)
    
.EXAMPLE
    # Pre-configured deployment (update variables below)
    iex (irm https://raw.githubusercontent.com/yourusername/yourrepo/main/ps-cloudshell-launcher/examples/one-liner-example.ps1) -DeploymentName "my-ctrl"
    
.NOTES
    This is an example - update the GitHub URL and parameters below for your environment
#>

param(
    [string]$DeploymentName = "",
    [string]$Location = "East US",
    [string]$AdminEmail = "",
    [string]$AdminPassword = "",
    [string]$CustomerID = "",
    [bool]$IncludeCopilot = $false
)

# Step 1: Download the main deployment script
Write-Host "📥 Downloading Aviatrix deployment script..." -ForegroundColor Cyan
$scriptUrl = "https://raw.githubusercontent.com/yourusername/yourrepo/main/ps-cloudshell-launcher/deploy-aviatrix-controlplane.ps1"

try {
    $scriptContent = Invoke-RestMethod -Uri $scriptUrl -ErrorAction Stop
    $scriptPath = "./deploy-aviatrix-controlplane.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent
    Write-Host "✅ Script downloaded successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to download deployment script from $scriptUrl"
    Write-Host "Please check the URL and try again, or download manually." -ForegroundColor Yellow
    exit 1
}

# Step 2: Prepare deployment parameters
$deployParams = @{}

if ($DeploymentName) { $deployParams['DeploymentName'] = $DeploymentName }
if ($Location) { $deployParams['Location'] = $Location }
if ($AdminEmail) { $deployParams['AdminEmail'] = $AdminEmail }
if ($AdminPassword) { $deployParams['AdminPassword'] = $AdminPassword }
if ($CustomerID) { $deployParams['CustomerID'] = $CustomerID }
if ($PSBoundParameters.ContainsKey('IncludeCopilot')) { $deployParams['IncludeCopilot'] = $IncludeCopilot }

# Step 3: Execute deployment
Write-Host "🚀 Starting Aviatrix control plane deployment..." -ForegroundColor Cyan

if ($deployParams.Count -gt 0) {
    # Run with provided parameters
    & $scriptPath @deployParams
} else {
    # Run in interactive mode
    & $scriptPath
}

# Step 4: Cleanup
Remove-Item $scriptPath -ErrorAction SilentlyContinue

Write-Host "🎉 One-liner deployment completed!" -ForegroundColor Green
