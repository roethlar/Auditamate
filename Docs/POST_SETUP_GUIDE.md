# Post-Setup Configuration Guide

This guide helps you configure additional settings after running the initial setup wizard.

## Table of Contents
1. [Verifying Installation](#verifying-installation)
2. [Manual Configuration Updates](#manual-configuration-updates)
3. [Adding Server Groups](#adding-server-groups)
4. [Configuring AuditBoard](#configuring-auditboard)
5. [Setting Up Scheduled Tasks](#setting-up-scheduled-tasks)
6. [Advanced Email Configuration](#advanced-email-configuration)
7. [Multi-Domain Forest Setup](#multi-domain-forest-setup)

## Verifying Installation

After setup, verify everything is working:

```powershell
# 1. Check prerequisites
.\Setup-AuditTool.ps1 -Mode Check

# 2. Test basic AD audit
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins"

# 3. Test Azure connection (if configured)
.\Test-AuditBoardConnection.ps1
```

## Manual Configuration Updates

All configuration files are in the `Config` folder:

### audit-config.json
Main AD audit settings:
```json
{
  "Groups": ["Domain Admins", "Enterprise Admins"],
  "EmailSettings": {
    "Recipients": ["security@company.com"],
    "SmtpServer": "smtp.company.com"
  }
}
```

### server-audit-config.json
Server groups for local admin auditing:
```json
{
  "ServerGroups": {
    "WebServers": {
      "Servers": ["WEB01", "WEB02", "WEB03"],
      "AuditFrequency": "Weekly"
    }
  }
}
```

To edit any configuration:
```powershell
# Use the update wizard
.\Setup-AuditTool.ps1 -Mode Update

# Or edit directly
notepad Config\audit-config.json
```

## Adding Server Groups

To add new server groups for local admin auditing:

1. Edit `Config\server-audit-config.json`
2. Add a new group under `ServerGroups`:

```json
"DatabaseServers": {
  "Description": "SQL and Oracle Database Servers",
  "Servers": [
    "SQL01.corp.company.com",
    "SQL02.corp.company.com",
    "ORA01.corp.company.com"
  ],
  "AuditFrequency": "Weekly",
  "ComplianceLevel": "High"
}
```

3. Test the new group:
```powershell
.\Run-LocalAdminAudit.ps1 -ServerGroup "DatabaseServers"
```

## Configuring AuditBoard

If you have AuditBoard API access:

1. Edit `Config\auditboard-config.json`:
```json
{
  "AuditBoardSettings": {
    "BaseUrl": "https://yourcompany.auditboard.com",
    "ApiKey": "your-api-key-here"
  }
}
```

2. Test the connection:
```powershell
.\Test-AuditBoardConnection.ps1
```

3. Enable automatic uploads:
```json
"EnableAutoUpload": true
```

## Setting Up Scheduled Tasks

Create automated audit schedules:

### Weekly AD Audit
```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"$PWD\Run-ADCompleteAudit.ps1`" -Job weekly-ad.json"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am

Register-ScheduledTask -TaskName "Weekly AD Audit" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

### Monthly Privileged Access Review
```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"$PWD\Run-PrivilegedAccessAudit.ps1`" -Job monthly-priv.json"

$trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At 8am

Register-ScheduledTask -TaskName "Monthly Privileged Access Audit" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

## Advanced Email Configuration

### Using Authenticated SMTP
Update email settings in configs:
```json
"EmailSettings": {
  "Recipients": ["security@company.com"],
  "From": "ad-audit@company.com",
  "SmtpServer": "smtp.office365.com",
  "Port": 587,
  "UseSSL": true,
  "RequiresAuthentication": true,
  "Username": "ad-audit@company.com"
}
```

### Email Templates
Create custom email templates in `Modules\Send-AuditReport.ps1`

## Multi-Domain Forest Setup

For complex forest environments:

1. Update `Config\audit-config.json`:
```json
"MultiDomainSettings": {
  "ForestRootDomain": "corp.company.com",
  "ChildDomains": [
    "users.corp.company.com",
    "resources.corp.company.com"
  ],
  "TrustedDomains": [
    "partner.company.com"
  ],
  "IncludeForestRootGroups": true,
  "ResolveForeignSecurityPrincipals": true
}
```

2. Test cross-domain resolution:
```powershell
.\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains
```

## Troubleshooting Common Issues

### WinRM Issues
```powershell
# Enable WinRM on target servers
Enable-PSRemoting -Force

# Test connectivity
Test-WSMan -ComputerName SERVER01
```

### Graph API Authentication
```powershell
# Re-run app registration
.\New-AzureAppRegistration.ps1

# Or manually update credentials
.\Setup-AuditTool.ps1 -Mode Update
```

### Performance Tuning
For large environments, adjust in configs:
```json
"ServerAuditSettings": {
  "MaxConcurrentAudits": 20,
  "TimeoutSeconds": 600
}
```

## Getting Help

- Built-in help: `Get-Help .\Run-ADCompleteAudit.ps1 -Full`
- Update wizard: `.\Setup-AuditTool.ps1 -Mode Update`
- Check prerequisites: `.\Setup-AuditTool.ps1 -Mode Check`
- Main documentation: See `README.md` and `Docs\USAGE_GUIDE.md`