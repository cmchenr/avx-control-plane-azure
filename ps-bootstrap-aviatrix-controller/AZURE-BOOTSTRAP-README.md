# Aviatrix Controller Bootstrap - PowerShell Script

## Overview

This PowerShell script (`bootstrap-aviatrix-controller.ps1`) provides equivalent functionality to the `terraform-aviatrix-controller-init` Terraform module. It's designed to run in Azure Cloud Shell and bootstrap a freshly deployed Aviatrix controller.

## Prerequisites

- Azure Cloud Shell with PowerShell 7+
- A deployed Aviatrix controller (g3 based image required for API v2 compatibility)
- Controller must be accessible via its public IP address
- Valid Aviatrix customer license ID

## Usage

### Basic Usage

```powershell
./bootstrap-aviatrix-controller.ps1 `
  -ControllerPublicIP "1.2.3.4" `
  -ControllerPrivateIP "10.1.1.123" `
  -ControllerAdminEmail "admin@domain.com" `
  -ControllerAdminPassword "MySecure123!" `
  -CustomerID "aviatrix-abu-123456"
```

### Advanced Usage with Optional Parameters

```powershell
./bootstrap-aviatrix-controller.ps1 `
  -ControllerPublicIP "1.2.3.4" `
  -ControllerPrivateIP "10.1.1.123" `
  -ControllerAdminEmail "admin@domain.com" `
  -ControllerAdminPassword "MySecure123!" `
  -CustomerID "aviatrix-abu-123456" `
  -ControllerVersion "7.1" `
  -WaitDurationMinutes 15 `
  -MaxRetries 5
```

## Parameters

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `ControllerPublicIP` | Public IP address of the Aviatrix controller | `"1.2.3.4"` |
| `ControllerPrivateIP` | Private IP address of the Aviatrix controller | `"10.1.1.123"` |
| `ControllerAdminEmail` | Email address for the controller admin | `"admin@domain.com"` |
| `ControllerAdminPassword` | Desired password for the controller admin | `"MySecure123!"` |
| `CustomerID` | Aviatrix customer license ID | `"aviatrix-abu-123456"` |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ControllerVersion` | `"latest"` | Target controller version |
| `WaitDurationMinutes` | `10` | Minutes to wait for controller setup completion |
| `MaxRetries` | `3` | Maximum number of retries for API calls |

## Password Requirements

The controller admin password must meet the following criteria:
- At least 8 characters long
- Contain at least one letter
- Contain at least one number  
- Contain at least one symbol

## What the Script Does

The script performs the following steps in sequence:

1. **Connectivity Test** - Verifies the controller is reachable
2. **Initial Login** - Logs in using `admin` username and private IP as password
3. **Set Admin Email** - Sets the admin email address
4. **Set Notification Email** - Configures notification email settings
5. **Set Customer ID** - Applies the Aviatrix license
6. **Set Admin Password** - Changes the admin password from private IP to desired password
7. **Initialize Controller** - Starts the controller initialization process
8. **Wait for Setup** - Waits for the specified duration for setup completion
9. **Verify Setup** - Confirms the setup by logging in with new credentials

## Running in Azure Cloud Shell

1. Upload the script to your Azure Cloud Shell environment
2. Make the script executable:
   ```bash
   chmod +x bootstrap-aviatrix-controller.ps1
   ```
3. Run the script with required parameters:
   ```powershell
   ./bootstrap-aviatrix-controller.ps1 -ControllerPublicIP "x.x.x.x" -ControllerPrivateIP "y.y.y.y" -ControllerAdminEmail "admin@domain.com" -ControllerAdminPassword "password" -CustomerID "customer-id"
   ```

## Error Handling

The script includes comprehensive error handling and will:
- Retry failed API calls up to the specified maximum retries
- Provide detailed error messages for troubleshooting
- Validate input parameters before execution
- Test controller connectivity before attempting bootstrap

## Troubleshooting

If the script fails, check the following:

1. **Controller Accessibility**: Ensure the controller is running and accessible via the public IP
2. **IP Addresses**: Verify both public and private IP addresses are correct
3. **Controller Image**: Confirm the controller is using a g3 based image for API v2 compatibility
4. **Network Connectivity**: Check firewall rules and network security groups
5. **Customer ID**: Ensure the customer license ID is valid and correctly formatted
6. **Password Policy**: Verify the admin password meets all requirements

## Comparison with Terraform Module

| Feature | Terraform Module | PowerShell Script |
|---------|------------------|-------------------|
| **Environment** | Any Terraform environment | Azure Cloud Shell |
| **Dependencies** | Terraform, terracurl provider | PowerShell 7+ |
| **Retry Logic** | Built-in with terracurl | Custom retry implementation |
| **State Management** | Terraform state | Stateless execution |
| **Idempotency** | Terraform lifecycle management | Manual re-run required |
| **Error Handling** | Terraform postconditions | Try-catch blocks |
| **Progress Tracking** | Terraform output | Real-time console output |

## Output

Upon successful completion, the script will display:
- Controller public IP and URL
- Admin username and email
- Confirmation that the controller is ready for use

## Security Considerations

- The script skips TLS certificate verification (same as Terraform module)
- Sensitive parameters like passwords are handled securely
- API calls are made over HTTPS
- No credentials are logged or stored permanently

## License

This script is provided as-is for bootstrapping Aviatrix controllers. Use in accordance with your Aviatrix license agreement.
