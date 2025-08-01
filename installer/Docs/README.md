# AD Audit Tool

A comprehensive PowerShell-based solution for auditing Active Directory, Entra ID (Azure AD), and Exchange environments.

## Quick Start

To run an audit:
```powershell
.\Start-ADAudit.ps1
```

This will launch the interactive menu where you can select from:
- AD Complete Audit (Groups & Users)
- Forest-Wide Audit
- Privileged Access Audit (AD + Azure)
- Termination Audit
- Exchange RBAC Audit

## Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Comprehensive guide with examples and best practices
- **[POST_SETUP_GUIDE.md](POST_SETUP_GUIDE.md)** - Configuration and customization after installation

## Directory Structure

- **Config/** - Configuration files (global and per-user)
- **Scripts/** - All audit scripts
- **Modules/** - PowerShell modules
- **Logs/** - Audit execution logs
- **Reports/** - Generated audit reports

## Configuration

Your personal configuration is stored in: `Config\<username>\user-config.json`

Global settings are in:
- `Config\global-config.json` - Domain and organization settings
- `Config\smtp-config.json` - Email server settings
- `Config\azure-app-config.json` - Azure app registration

## Common Tasks

### Run a quick AD group audit
```powershell
.\Scripts\Run-ADCompleteAudit.ps1 -Groups "Domain Admins" -SkipEmail
```

### Check specific terminations
```powershell
.\Scripts\Run-TerminationAudit.ps1 -UserList "jsmith,mjones"
```

### Generate forest-wide compliance report
```powershell
.\Scripts\Run-ForestAudit.ps1 -SOXCompliance
```

## Support

For issues or feature requests, contact your IT Security team.