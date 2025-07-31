# AD Audit Tool - Comprehensive Usage Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Core Components](#core-components)
6. [Common Audit Scenarios](#common-audit-scenarios)
7. [Advanced Features](#advanced-features)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)
10. [SOX Compliance](#sox-compliance)

## Introduction

The AD Audit Tool is a comprehensive PowerShell-based solution designed to automate security audits across Active Directory, Entra ID (Azure AD), and Exchange environments. This tool is specifically built to meet SOX compliance requirements and provides detailed evidence of all audit activities.

### Key Capabilities
- **Active Directory**: Group membership, permissions, user status
- **Entra ID**: Admin roles, PIM assignments, Conditional Access
- **Exchange**: RBAC roles (Online and On-Premise)
- **Compliance**: Automated reporting, screenshot capture, command evidence
- **Integration**: Workday termination validation, email automation

## Prerequisites

### Required Permissions
1. **Active Directory**
   - Domain Admin or delegated permissions to read AD objects
   - Rights to query group memberships and user properties
   - For multi-domain forests: Enterprise Admin or Domain Admin in each domain

2. **Entra ID / Microsoft Graph**
   - App Registration with following API permissions:
     - Directory.Read.All
     - RoleManagement.Read.All
     - AuditLog.Read.All
     - Policy.Read.All
     - User.Read.All

3. **Exchange**
   - Exchange Administrator role
   - For Exchange Online: Exchange.ManageAsApp permission
   - For Exchange 2019: Local Exchange management permissions

### Required Software
- Windows PowerShell 5.1 or PowerShell 7+
- Active Directory PowerShell module
- Exchange Online Management module (for Exchange audits)
- MSAL.PS module (auto-installed if needed)
- Microsoft Excel (for Excel export features)

### System Requirements
- Windows 10/11 or Windows Server 2016+
- Network access to domain controllers
- Internet access for Microsoft Graph API
- SMTP access for email features

## Installation

1. **Download the Tool**
   ```powershell
   # Clone or download to your audit workstation
   cd C:\Users\YourUsername\Documents
   git clone <repository-url> AD-Audit-Tool
   ```

2. **Verify Prerequisites**
   ```powershell
   # Check PowerShell version
   $PSVersionTable.PSVersion

   # Check for AD module
   Get-Module -ListAvailable ActiveDirectory

   # Install Exchange Online module if needed
   Install-Module -Name ExchangeOnlineManagement
   ```

3. **Configure Initial Settings**
   ```powershell
   # Navigate to tool directory
   cd AD-Audit-Tool

   # Review and edit configuration files
   notepad audit-config.json
   notepad privileged-access-config.json
   ```

## Quick Start

### Scenario 1: Basic AD Group Audit
```powershell
# Audit specific AD groups with screenshots
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins", "Enterprise Admins" -CaptureScreenshots

# Using configuration file
.\Run-ADCompleteAudit.ps1 -ConfigFile .\audit-config.json
```

### Scenario 2: Privileged Access Audit
```powershell
# First-time setup for Graph API
.\Setup-GraphAppRegistration.ps1

# Run privileged access audit
.\Run-PrivilegedAccessAudit.ps1 -IncludePIM -IncludeConditionalAccess
```

### Scenario 3: Audit with Evidence Capture
```powershell
# PowerShell commands are captured automatically for SOX evidence
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins"
```

## Core Components

### 1. AD Group Auditing (`AD-AuditModule.psm1`)

**Purpose**: Collects detailed information about AD groups and their members.

**Key Functions**:
- `Get-ADGroupAuditData`: Retrieves group and member information
- `Get-ADPermissionsAudit`: Audits OU-level permissions
- `Export-ADGroupMembers`: Creates Excel reports

**Example Usage**:
```powershell
# Import module
Import-Module .\AD-AuditModule.psm1

# Get group data
$groupData = Get-ADGroupAuditData -GroupNames @("Domain Admins", "Enterprise Admins") -IncludeNestedGroups

# Export to Excel
Export-ADGroupMembers -GroupAuditData $groupData -OutputPath "C:\Audits\groups.xlsx"
```

### 2. Entra ID Role Auditing (`EntraID-RoleAudit.ps1`)

**Purpose**: Audits administrative roles in Entra ID using Microsoft Graph API.

**Key Functions**:
- `Get-EntraIDAdminRoles`: Retrieves all admin roles and members
- `Get-EntraIDPIMRoles`: Gets PIM eligible and active assignments
- `Get-EntraIDRoleAssignmentHistory`: Retrieves role change history

**Example Usage**:
```powershell
# Load functions
. .\EntraID-RoleAudit.ps1

# Connect to Graph
Connect-MSGraphWithSecret -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret $secret

# Get admin roles
$roles = Get-EntraIDAdminRoles -IncludeCustomRoles
```

### 3. Exchange RBAC Auditing (`Exchange-RBACaudit.ps1`)

**Purpose**: Audits Exchange role assignments for both Online and On-Premise.

**Key Functions**:
- `Get-ExchangeOnlineRBACRoles`: Exchange Online roles
- `Get-Exchange2019OnPremRBACRoles`: On-premise Exchange roles
- `Get-ExchangeAdminAuditLog`: Admin action history

**Example Usage**:
```powershell
# Load functions
. .\Exchange-RBACaudit.ps1

# Get Exchange Online roles
$exoRoles = Get-ExchangeOnlineRBACRoles -UseModernAuth

# Get On-Premise roles
$onPremRoles = Get-Exchange2019OnPremRBACRoles -ExchangeServer "exch2019.company.local"
```

### 4. Evidence Capture (`Audit-CodeCapture.ps1`)

**Purpose**: Documents PowerShell commands for compliance evidence.

**Key Functions**:
- `Start-AuditCodeCapture`: Begins evidence collection
- `Add-AuditCommand`: Records a command execution
- `Stop-AuditCodeCapture`: Generates evidence report

**Example Usage**:
```powershell
# Start capture session
Start-AuditCodeCapture -AuditName "Monthly SOX Audit"

# Your audit commands will be automatically captured
# ...

# Generate evidence report
$evidence = Stop-AuditCodeCapture
```

## Common Audit Scenarios

### Multi-Domain Forest Audit

For environments with a forest root domain and child domains:

1. **Configure Forest Settings**
   ```json
   {
     "MultiDomainSettings": {
       "AuditAllDomains": true,
       "ForestRootDomain": "corp.company.com",
       "ChildDomains": ["users.corp.company.com"],
       "IncludeForestRootGroups": true,
       "ResolveForeignSecurityPrincipals": true
     }
   }
   ```

2. **Run Forest-Wide Audit**
   ```powershell
   # Audit all domains including Enterprise/Schema Admins
   .\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains -CaptureCommands
   ```

3. **Review Cross-Domain Memberships**
   - Check for users from child domains in forest root groups
   - Verify Foreign Security Principal resolution
   - Identify any unexpected cross-domain access

### Monthly SOX Compliance Audit

1. **Prepare Configuration**
   ```json
   {
     "Groups": [
       "Domain Admins",
       "Enterprise Admins",
       "Schema Admins",
       "Account Operators"
     ],
     "IncludeNestedGroups": true,
     "IncludeDisabledUsers": false
   }
   ```

2. **Run Complete Audit**
   ```powershell
   # Evidence capture is automatic for SOX compliance
   .\Run-ADCompleteAudit.ps1 `
       -ConfigFile .\audit-config.json `
       -CaptureScreenshots `
       -SendEmail
   ```

3. **Review Output**
   - HTML report with interactive tables
   - Excel workbook with detailed membership
   - Screenshot evidence
   - Command execution log

### Quarterly Privileged Access Review

1. **Setup Graph API Access**
   ```powershell
   # One-time setup
   .\Setup-GraphAppRegistration.ps1
   
   # Test connection
   $cred = Get-Credential
   Connect-MSGraphWithSecret -TenantId "tenant-id" -ClientId "app-id" -ClientSecret $cred.Password
   ```

2. **Run Privileged Access Audit**
   ```powershell
   .\Run-PrivilegedAccessAudit.ps1 `
       -IncludePIM `
       -IncludeConditionalAccess `
       -IncludeAuditLogs `
       -AuditDaysBack 90
   ```

### User Termination Validation

1. **Configure Workday Integration**
   ```powershell
   # Edit workday configuration
   notepad workday-config-example.json
   ```

2. **Run Termination Audit**
   ```powershell
   .\Run-TerminationAudit.ps1 `
       -WorkdayTenant "https://wd.company.com" `
       -DaysBack 30 `
       -CheckAzureAD
   ```

### Ad-Hoc Group Analysis

```powershell
# Quick check of specific group
Import-Module .\AD-AuditModule.psm1
$data = Get-ADGroupAuditData -GroupNames "VPN Users" -IncludeNestedGroups
$data.Members | Format-Table DisplayName, EmailAddress, Enabled, LastLogonDate
```

## Advanced Features

### Custom Report Generation

```powershell
# Load modules
Import-Module .\AD-AuditModule.psm1
. .\AD-ReportGenerator.ps1

# Get data
$groups = Get-ADGroupAuditData -GroupNames (Get-Content .\critical-groups.txt)

# Custom metadata
$metadata = @{
    "Audit Period" = "Q4 2024"
    "Compliance Framework" = "SOX Section 404"
    "Reviewed By" = "Security Team"
}

# Generate report
New-ADHtmlReport `
    -GroupAuditData $groups `
    -OutputPath ".\Q4_Audit.html" `
    -ReportTitle "Q4 2024 Security Audit" `
    -CustomMetadata $metadata
```

### Job Management (Save and Reuse Parameters)

```powershell
# Run an audit and save the parameters
.\Run-ADCompleteAudit.ps1 `
    -Groups "Domain Admins", "Enterprise Admins" `
    -CaptureScreenshots `
    -SendEmail `
    -SaveJob monthly-sox-audit.json

# Later, re-run the same audit
.\Run-ADCompleteAudit.ps1 -Job monthly-sox-audit.json

# Override specific parameters from the job
.\Run-ADCompleteAudit.ps1 -Job monthly-sox-audit.json -SendEmail:$false

# Build a library of different audit scenarios
.\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains -SaveJob quarterly-forest.json
.\Run-PrivilegedAccessAudit.ps1 -IncludePIM -SaveJob monthly-priv.json
```

### Automated Scheduling

```powershell
# Create scheduled task using a saved job
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\AD-Audit-Tool\Run-ADCompleteAudit.ps1 -Job monthly-sox-audit.json"

$trigger = New-ScheduledTaskTrigger -Monthly -At 8am -DaysOfMonth 1

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

Register-ScheduledTask `
    -TaskName "Monthly AD SOX Audit" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal
```

### Baseline Comparison

```powershell
# First audit - create baseline
$baseline = Get-ADGroupAuditData -GroupNames "Domain Admins"
$baseline | ConvertTo-Json -Depth 10 | Out-File .\baseline.json

# Later audit - compare
$current = Get-ADGroupAuditData -GroupNames "Domain Admins"
$baseline = Get-Content .\baseline.json | ConvertFrom-Json

# Find differences
Compare-Object $baseline.Members $current.Members -Property SamAccountName
```

## Troubleshooting

### Common Issues and Solutions

1. **"Access Denied" Errors**
   ```powershell
   # Verify permissions
   whoami /groups | findstr "Domain Admins"
   
   # Test AD access
   Get-ADUser -Identity $env:USERNAME
   ```

2. **Graph API Connection Failures**
   ```powershell
   # Test Graph connection
   $token = Get-MsalToken -ClientId "app-id" -TenantId "tenant-id" -Scopes "https://graph.microsoft.com/.default"
   
   # Verify app permissions
   .\Test-GraphPermissions.ps1
   ```

3. **Exchange Connection Issues**
   ```powershell
   # For Exchange Online
   Connect-ExchangeOnline -ShowBanner:$false
   Get-OrganizationConfig | Select Name
   
   # For On-Premise
   $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://exchange/PowerShell/
   Import-PSSession $session
   ```

4. **Excel Export Failures**
   ```powershell
   # Check Excel COM object
   $excel = New-Object -ComObject Excel.Application
   $excel.Quit()
   
   # Alternative: Export to CSV
   $groupData | Export-Csv -Path .\audit.csv -NoTypeInformation
   ```

### Debug Mode

```powershell
# Enable verbose output
$VerbosePreference = "Continue"

# Run with debug info
.\Run-ADCompleteAudit.ps1 -Groups "Test Group" -Verbose

# Check error details
$Error[0] | Format-List -Force
```

## Best Practices

### 1. Security
- Store configuration files securely
- Use certificate-based authentication when possible
- Rotate Graph API secrets regularly
- Run audits from dedicated admin workstations
- Enable PowerShell logging

### 2. Performance
- Limit group queries to necessary groups
- Use `-IncludeNestedGroups` only when required
- Schedule intensive audits during off-hours
- Archive old reports regularly

### 3. Compliance
- Always use `-CaptureCommands` for SOX audits
- Maintain audit trails for 7 years
- Document any manual interventions
- Review and sign-off on reports

### 4. Maintenance
- Test scripts after Windows updates
- Update modules quarterly
- Review and update group lists
- Validate email delivery

## SOX Compliance

### Evidence Requirements
1. **Command Documentation**: All scripts automatically capture commands (disable with `-CaptureCommands:$false`)
2. **Screenshot Evidence**: Use `-CaptureScreenshots` for visual proof
3. **Timestamp Tracking**: All operations are timestamped
4. **Change Tracking**: Role history and audit logs included

### Audit Workflow
1. **Planning**
   - Define scope (groups, roles, timeframe)
   - Update configuration files
   - Schedule audit window

2. **Execution**
   - Run audit with evidence capture
   - Review for completeness
   - Address any errors

3. **Review**
   - Analyze compliance issues
   - Document exceptions
   - Prepare remediation plans

4. **Reporting**
   - Generate executive summary
   - Archive evidence
   - Distribute to stakeholders

### Retention Policy
- HTML Reports: 7 years
- Excel Exports: 7 years
- Command Evidence: 7 years
- Screenshots: 3 years
- Audit Logs: Indefinite

## Getting Help

### Built-in Help
```powershell
# View script help
Get-Help .\Run-ADCompleteAudit.ps1 -Full

# View function help
Get-Help Get-ADGroupAuditData -Examples
```

### Support Resources
- GitHub Issues: Report bugs and request features
- Documentation: This guide and README files
- Scripts: All include inline comments
- Logs: Check Windows Event Log for errors

### Contact Information
- Tool Maintainer: IT Security Team
- Email: it-security@company.com
- Internal Wiki: /wiki/AD-Audit-Tool

## Appendix: Quick Reference

### Essential Commands
```powershell
# AD Group Audit
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins" -CaptureScreenshots

# Save common audit as job
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins", "Enterprise Admins" -SaveJob monthly.json

# Re-run saved job
.\Run-ADCompleteAudit.ps1 -Job monthly.json

# Privileged Access Audit  
.\Run-PrivilegedAccessAudit.ps1 -IncludePIM -IncludeConditionalAccess

# Termination Validation
.\Run-TerminationAudit.ps1 -DaysBack 30

# Evidence Capture (automatic)
.\Run-ADCompleteAudit.ps1  # Evidence capture is enabled by default
```

### Configuration Files
- `audit-config.json` - AD group audit settings
- `privileged-access-config.json` - Entra ID/Exchange settings
- `workday-config-example.json` - Workday integration

### Job Files (Saved Parameters)
- `*.json` - Any saved job file created with `-SaveJob`
- Common patterns:
  - `monthly-audit.json` - Monthly SOX audit
  - `quarterly-forest.json` - Quarterly forest review
  - `weekly-priv.json` - Weekly privileged access check

### Output Locations
- Reports: `.\Output\[timestamp]\`
- Screenshots: `.\Output\[timestamp]\Screenshots\`
- Evidence: `.\Output\[timestamp]\CodeEvidence\`
- Logs: `.\Output\[timestamp]\*.log`

---
*Last Updated: [Current Date]*
*Version: 1.0*