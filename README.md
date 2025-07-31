# Active Directory SOX Compliance Audit Tool

A comprehensive PowerShell-based solution for automating Active Directory audits for SOX compliance requirements.

## 🚀 Quick Start (5 Minutes)

### First Time Setup
```powershell
# 1. Check prerequisites
.\Test-Prerequisites.ps1

# 2. Basic AD audit (evidence capture is automatic)
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins", "Enterprise Admins"

# 3. Save for reuse
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins" -SaveJob monthly-audit.json

# 4. Re-run saved job
.\Run-ADCompleteAudit.ps1 -Job monthly-audit.json
```

## Features

- **Automated AD Group Analysis**: Collect detailed membership data for security groups
- **User Status Tracking**: Monitor enabled/disabled users, last logon times, password ages
- **Screenshot Capture**: Interactive screenshot tool for documenting AD console views
- **Multi-Format Reporting**: Generate both HTML and Excel reports
- **Email Automation**: Send reports directly to audit teams
- **Job Management**: Save and reuse audit configurations
- **Multi-Domain Support**: Audit forest root and child domains
- **Entra ID/Exchange**: Audit cloud admin roles and Exchange RBAC
- **SOX Evidence**: Automatic capture of PowerShell commands for compliance
- **AuditBoard Integration**: Upload results directly to AuditBoard platform
- **Local Admin Auditing**: Check administrator access on critical servers

## Prerequisites

- Windows PowerShell 5.1 or higher
- Active Directory PowerShell module
- Domain Admin or appropriate AD read permissions
- Excel COM object support (for Excel exports)

## Installation

### Quick Install (Recommended)
```powershell
# Run the installer - it will handle everything!
.\INSTALL.ps1
```

The installer will:
- Check and install prerequisites
- Create configuration files
- Set up Azure app registration (optional)
- Configure email settings
- Test the installation

### Manual Installation
1. Clone or download this repository to your audit workstation
2. Run setup wizard:
   ```powershell
   .\Setup-AuditTool.ps1
   ```
3. Follow the prompts to configure your environment

### Update Existing Installation
```powershell
# Check prerequisites
.\Setup-AuditTool.ps1 -Mode Check

# Update configurations
.\Setup-AuditTool.ps1 -Mode Update
```

## Common Audit Scenarios

### 📊 Monthly SOX Audit
```powershell
# Standard monthly audit (evidence capture is automatic)
.\Run-ADCompleteAudit.ps1 `
    -Groups "Domain Admins", "Enterprise Admins", "Schema Admins" `
    -SendEmail

# With AuditBoard upload
.\Run-ADCompleteAudit.ps1 `
    -Groups "Domain Admins", "Enterprise Admins" `
    -SendEmail -UploadToAuditBoard
```

### 🌲 Multi-Domain Forest Audit
```powershell
# Audit forest root + child domains
.\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains
```

### 🔐 Privileged Access Review (Cloud + Exchange)
```powershell
# First time: Setup Azure app (requires Global Admin)
.\New-AzureAppRegistration.ps1

# Run privileged access audit
.\Run-PrivilegedAccessAudit.ps1 -IncludePIM -IncludeConditionalAccess
```

### 🖥️ Local Administrator Audit
```powershell
# Audit specific servers
.\Run-LocalAdminAudit.ps1 -Servers "DC01", "EXCH01", "SQL01"

# Audit configured server groups
.\Run-LocalAdminAudit.ps1 -ServerGroup "CriticalServers"

# Audit all configured servers with email alert
.\Run-LocalAdminAudit.ps1 -SendEmail -UploadToAuditBoard
```

## Understanding the Output

### Report Locations
```
AD-Audit-Tool\
└── Output\
    └── 2024-01-15_143022\          # Timestamp folder
        ├── AD_Audit_Report.html     # Main report (open in browser)
        ├── AD_Audit_20240115.xlsx  # Excel data
        ├── Screenshots\             # Visual evidence
        ├── CodeEvidence\            # Command documentation
        ├── audit.log               # Execution log
        └── audit-transcript.log    # Full PowerShell transcript
```

### What to Review
- **HTML Report**: Interactive tables, member counts, search functionality
- **Excel File**: Raw data for pivot tables and analysis
- **Command Evidence**: Proof of data collection methods (SOX requirement)
- **Screenshots**: Visual confirmation of PowerShell execution

## Output

The tool generates:
- **HTML Report**: Interactive web-based report with search and filtering
- **Excel Workbook**: Detailed member lists with separate sheets per group
- **Screenshots**: Captured AD console views (when enabled)
- **Command Evidence**: Documentation of all PowerShell commands used (for SOX compliance)

## Security Notes

- Run only from authorized audit workstations
- Reports contain sensitive security information
- Follow your organization's data handling policies
- Email transmission should use encrypted channels

## Scheduling

To schedule monthly audits, create a Windows Task Scheduler job:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Path\To\Run-ADCompleteAudit.ps1 -SendEmail"
$trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At 8am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AD SOX Audit" -RunLevel Highest
```

## Job Management (Save & Reuse)

```powershell
# Save audit configuration after successful run
.\Run-ADCompleteAudit.ps1 -Groups "Domain Admins" -SendEmail -SaveJob monthly-sox.json

# Create job library
.\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains -SaveJob quarterly-forest.json
.\Run-PrivilegedAccessAudit.ps1 -IncludePIM -SaveJob monthly-priv.json

# Schedule with saved job
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\AD-Audit-Tool\Run-ADCompleteAudit.ps1 -Job monthly-sox.json"
$trigger = New-ScheduledTaskTrigger -Monthly -At 6am -DaysOfMonth 1
Register-ScheduledTask -TaskName "Monthly SOX Audit" -Action $action -Trigger $trigger
```

## Configuration

### Email Settings (Config/audit-config.json)
```json
{
  "EmailSettings": {
    "Recipients": ["security@company.com", "audit@company.com"],
    "SmtpServer": "smtp.company.com",
    "Port": 587,
    "UseSSL": true
  }
}
```

### Multi-Domain Settings
```json
{
  "MultiDomainSettings": {
    "ForestRootDomain": "corp.company.com",
    "ChildDomains": ["users.corp.company.com"],
    "IncludeForestRootGroups": true
  }
}
```

### AuditBoard Integration (Config/auditboard-config.json)
```json
{
  "AuditBoardSettings": {
    "BaseUrl": "https://yourcompany.auditboard.com",
    "ApiKey": "your-api-key-here",
    "EnableAutoUpload": false
  }
}
```

## Troubleshooting

```powershell
# Check prerequisites
.\Test-Prerequisites.ps1

# Common fixes:
# Access Denied: Run as Administrator, verify domain admin membership
# Module errors: Install-Module ActiveDirectory, ExchangeOnlineManagement
# Excel errors: Reports still work - use HTML/CSV format
# Graph errors: Run .\New-AzureAppRegistration.ps1 for setup
```

## Built-in Help

```powershell
# View all parameters and examples
Get-Help .\Run-ADCompleteAudit.ps1 -Full

# Just examples
Get-Help .\Run-ADCompleteAudit.ps1 -Examples
```

## Folder Structure

```
AD-Audit-Tool/
├── Run-ADCompleteAudit.ps1      # Main AD audit script
├── Run-ForestAudit.ps1          # Multi-domain forest audit
├── Run-PrivilegedAccessAudit.ps1 # Entra ID & Exchange audit
├── Run-TerminationAudit.ps1     # Workday termination validation
├── Run-LocalAdminAudit.ps1      # Server local admin audit
├── New-AzureAppRegistration.ps1 # Azure app setup
├── Setup-GraphAppRegistration.ps1 # Manual Graph setup
├── Test-Prerequisites.ps1       # Environment checker
├── Setup-AuditTool.ps1          # Configuration wizard
├── INSTALL.ps1                  # Quick installer
├── README.md                    # This file
├── Config/                      # Configuration files
│   ├── audit-config.json
│   ├── privileged-access-config.json
│   ├── workday-config-example.json
│   ├── auditboard-config-template.json
│   └── server-audit-config-template.json
├── Modules/                     # Component scripts
│   ├── AD-AuditModule.psm1
│   ├── AD-MultiDomainAudit.ps1
│   ├── AD-ReportGenerator.ps1
│   ├── AD-ScreenCapture.ps1
│   ├── Audit-CodeCapture.ps1
│   ├── EntraID-RoleAudit.ps1
│   ├── Exchange-RBACaudit.ps1
│   ├── MSGraph-Authentication.ps1
│   ├── PrivilegedAccess-UnifiedReport.ps1
│   ├── Send-AuditReport.ps1
│   ├── Workday-Integration.ps1
│   ├── AuditBoard-Integration.ps1
│   └── LocalAdmin-Audit.ps1
├── Docs/                        # Advanced documentation
│   ├── USAGE_GUIDE.md           # Comprehensive guide
│   └── ARCHIVED_DOCS.md         # Legacy documentation
└── Output/                      # All output files (created automatically)
    └── yyyy-MM-dd_HHmmss/       # Timestamped folders for each audit run
        ├── AD_Audit_Report.html # Main report
        ├── AD_Audit_yyyyMMdd.xlsx # Excel data
        ├── Screenshots/         # Visual evidence
        ├── CodeEvidence/        # Command documentation
        ├── audit.log           # Audit execution log
        └── audit-transcript.log # Full PowerShell transcript
```

## Advanced Usage

For comprehensive documentation including:
- Multi-domain forest architecture details
- Entra ID and Exchange RBAC auditing
- Custom report generation
- Workday integration
- Baseline comparisons
- SOX compliance workflows

See: `Docs\USAGE_GUIDE.md`

---
**Note**: Command evidence is captured automatically for all audits. Use `-CaptureCommands:$false` to disable if needed.