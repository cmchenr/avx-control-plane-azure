# Terraform Aviatrix Azure Control Plane Module Structure

## Overview

This repository contains a comprehensive Terraform module for deploying and managing the Aviatrix control plane in Microsoft Azure. The module is designed to provide a complete infrastructure-as-code solution for setting up Aviatrix's multi-cloud networking platform.

## Main Module: terraform-aviatrix-azure-controlplane-main

### Description
The primary module that orchestrates the deployment of the Aviatrix control plane, including the controller, optional copilot, and Azure account onboarding. This module can deploy individual components or the complete stack based on configuration.

### Key Files
- **`main.tf`**: Primary orchestration file that coordinates all submodules
- **`variables.tf`**: Input variable definitions for the entire module
- **`output.tf`**: Output definitions for accessing deployed resources
- **`locals.tf`**: Local variable calculations and transformations
- **`versions.tf`**: Terraform and provider version constraints
- **`preconditions.tf`**: Validation logic and prerequisites

### Module Configuration Structure
The module uses a `module_config` variable to control which components are deployed:
- `controller_deployment`: Deploys the Aviatrix controller VM
- `controller_initialization`: Initializes the controller via API
- `copilot_deployment`: Deploys the optional Copilot VM
- `copilot_initialization`: Initializes Copilot and links to controller
- `app_registration`: Creates Azure AD app registration
- `account_onboarding`: Onboards Azure account to the controller
- `accept_controller_subscription`: Accepts Azure Marketplace terms for controller
- `accept_copilot_subscription`: Accepts Azure Marketplace terms for copilot

## Submodules

### 1. azure_marketplace_agreement
**Location**: `modules/azure_marketplace_agreement/`

**Purpose**: Manages Azure Marketplace subscription agreements for Aviatrix products.

**Key Files**:
- `main.tf`: Handles marketplace agreement acceptance
- `variables.tf`: Toggle flags for controller and copilot subscriptions

**Function**: Ensures the Azure subscription has accepted the marketplace terms for Aviatrix controller and copilot images before deployment.

### 2. controller_build
**Location**: `modules/controller_build/`

**Purpose**: Deploys the core Aviatrix controller virtual machine and supporting Azure infrastructure.

**Key Files**:
- `main.tf`: Creates VM, networking, storage, and security components
- `cloud-init.tftpl`: Cloud-init template for controller initialization
- `variables.tf`: Controller-specific configuration parameters
- `outputs.tf`: Exposes controller IP addresses, resource group, and subnet information

**Function**: 
- Creates Azure resource group (optional, can use existing)
- Deploys virtual network and subnet (optional, can use existing)
- Provisions controller VM with proper sizing and storage
- Configures network security groups and public IP
- Applies cloud-init configuration for initial setup

### 3. app_registration
**Location**: `modules/app_registration/`

**Purpose**: Creates and configures Azure Active Directory application registration for Aviatrix controller access to Azure APIs.

**Key Files**:
- `main.tf`: Creates AD app registration and service principal
- `service_role.json`: Standard Azure contributor role definition
- `read_only_role.json`: Read-only role definition for limited access
- `backup_addon.json`: Additional permissions for backup operations
- `transit_gw_addon.json`: Additional permissions for transit gateway operations
- `outputs.tf`: Provides app credentials for controller configuration

**Function**:
- Creates Azure AD application registration
- Generates application secret/key
- Assigns appropriate RBAC roles to service principal
- Supports custom role creation for minimal permissions

### 4. account_onboarding
**Location**: `modules/account_onboarding/`

**Purpose**: Onboards the Azure subscription as the first cloud account in the Aviatrix controller.

**Key Files**:
- `main.tf`: Uses Aviatrix Terraform provider to create cloud account
- `variables.tf`: Account configuration parameters

**Function**:
- Connects to the deployed controller via API
- Creates the initial Azure cloud account using app registration credentials
- Establishes the foundation for multi-cloud networking

### 5. copilot_build
**Location**: `modules/copilot_build/`

**Purpose**: Deploys the optional Aviatrix CoPilot virtual machine for advanced monitoring and analytics.

**Key Files**:
- `main.tf`: Creates CoPilot VM and associated resources
- `variables.tf`: CoPilot-specific configuration
- `outputs.tf`: Exposes CoPilot IP and connection information

**Function**:
- Deploys CoPilot VM in the same network as the controller
- Configures storage disks for analytics data
- Sets up network security rules for controller communication
- Provisions public IP for web interface access

## External Dependencies

### terraform-aviatrix-controller-init (Referenced Module)
**Location**: `terraform-aviatrix-controller-init-main/`

**Purpose**: This is the external Terraform module used for controller initialization. It's referenced in the main module as:
```hcl
source  = "terraform-aviatrix-modules/controller-init/aviatrix"
version = "v1.0.4"
```

**Function**:
- Performs initial API-based setup of the controller
- Configures admin credentials
- Applies licensing and customer ID
- Validates controller readiness

**Key Files**:
- `main.tf`: Controller initialization logic
- `variables.tf`: Initialization parameters
- `output.tf`: Setup results and status

### PowerShell Alternative: ps-bootstrap-aviatrix-controller
**Location**: `ps-bootstrap-aviatrix-controller/`

**Purpose**: PowerShell equivalent of the controller-init module for environments that prefer script-based automation.

**Key Files**:
- `bootstrap-aviatrix-controller.ps1`: Main PowerShell script
- `example-bootstrap.ps1`: Usage example
- `AZURE-BOOTSTRAP-README.md`: Detailed documentation

**Function**:
- Provides the same controller initialization as the Terraform module
- Designed for Azure Cloud Shell execution
- Offers more flexibility for custom workflows
- Can be used independently of Terraform

## Deployment Workflows

### Complete Deployment
1. **Marketplace Agreement**: Accept Azure Marketplace terms
2. **Controller Build**: Deploy controller VM and infrastructure
3. **Controller Init**: Initialize controller via API
4. **App Registration**: Create Azure AD app for permissions
5. **Account Onboarding**: Add Azure subscription to controller
6. **Copilot Build** (optional): Deploy CoPilot VM
7. **Copilot Init** (optional): Initialize CoPilot and link to controller

### Modular Deployment
The module supports selective deployment of components by configuring the `module_config` variable, allowing for:
- Controller-only deployments
- Bring-your-own-network scenarios
- Existing resource group integration
- Staged deployments with manual steps

## Key Integration Points

### Dependencies Between Modules
- **controller_build** → **controller_init**: VM must exist before API initialization
- **app_registration** → **account_onboarding**: Credentials needed for account creation
- **controller_init** → **account_onboarding**: Controller must be initialized first
- **controller_build** → **copilot_build**: Copilot needs controller network information
- **controller_init** → **copilot_init**: Controller must be ready before CoPilot setup

### External System Integration
- **Azure Resource Manager**: For infrastructure provisioning
- **Azure Active Directory**: For identity and access management
- **Aviatrix Controller API**: For configuration and onboarding
- **Azure Marketplace**: For image licensing and terms

## Configuration Examples

### Minimal Configuration
```hcl
module "control_plane" {
  source = "./terraform-aviatrix-azure-controlplane-main"
  
  controller_name           = "my-controller"
  controller_admin_email    = "admin@example.com"
  controller_admin_password = "SecurePassword123!"
  customer_id              = "aviatrix-abc-123456"
  incoming_ssl_cidrs       = ["203.0.113.0/24"]
  location                 = "East US"
  
  # Deploy only controller and initialize
  module_config = {
    controller_deployment     = true
    controller_initialization = true
    # All other components disabled
  }
}
```

### Full Stack Configuration
```hcl
module "control_plane" {
  source = "./terraform-aviatrix-azure-controlplane-main"
  
  # ... basic parameters ...
  
  # Deploy everything
  module_config = {
    controller_deployment      = true
    controller_initialization  = true
    copilot_deployment        = true
    copilot_initialization    = true
    app_registration          = true
    account_onboarding        = true
    accept_controller_subscription = true
    accept_copilot_subscription   = true
  }
}
```

This modular approach provides flexibility for different deployment scenarios while maintaining consistency and reliability across the Aviatrix control plane infrastructure.
