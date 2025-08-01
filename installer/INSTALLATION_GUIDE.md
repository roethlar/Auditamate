# AD Audit Tool Installer

## Quick Start

1. Run as Administrator:
   ```powershell
   .\INSTALL.ps1
   ```

2. Follow the setup wizard prompts

3. After installation, navigate to your installation directory and run:
   ```powershell
   .\Start-ADAudit.ps1
   ```

## What Gets Installed

The installer will create this structure in your chosen directory:
- Scripts/ - All audit scripts
- Modules/ - PowerShell modules
- Config/ - Configuration files (global and per-user)
- Logs/ - Audit logs
- Reports/ - Generated reports

## First Time Setup

The setup wizard will:
- Check prerequisites
- Configure your AD domain settings
- Set up email notifications
- Optionally configure Azure app registration
- Create user preferences

## Support

For issues or questions, contact your IT Security team.
