# AD Audit Tool Installer

## Quick Start

1. Run the installer:
   ```powershell
   .\INSTALL.ps1
   ```
   Note: Administrator privileges are only required if installing to Program Files

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

## Updating an Existing Installation

If you already have the AD Audit Tool installed, the installer will detect it and offer these options:

1. **Update files only** - Replace program files with newer versions, keeping all configurations
2. **Update configuration only** - Modify settings without changing program files  
3. **Complete reinstall** - Fresh installation with option to preserve or delete existing configurations

## Support

For issues or questions, contact your IT Security team.
