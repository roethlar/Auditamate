# AD Audit Tool - Logging Guide

## Where Logs Are Saved

### Forest Audit Logs
- **Location**: `[Installation Directory]\Scripts\Output\Forest_[timestamp]\`
- **Files**:
  - `forest-audit.log` - Main audit log with all operations
  - `forest-audit-transcript.log` - Complete PowerShell transcript
  - `ERROR_[timestamp].txt` - Error details if audit fails

### Complete AD Audit Logs
- **Location**: `[Installation Directory]\Output\ADGroupAudit_[timestamp]\`
- **Files**:
  - `audit.log` - Main audit log
  - `transcript.log` - PowerShell transcript

### Privileged Access Audit Logs
- **Location**: `[Installation Directory]\Reports\`
- **Files**:
  - Logs are embedded in the HTML report

### Local Admin Audit Logs
- **Location**: `[Installation Directory]\Output\LocalAdmin_[timestamp]\`
- **Files**:
  - `localadmin-audit.log` - Main audit log
  - `transcript.log` - PowerShell transcript

### Installation Logs
- **Location**: `[Installation Directory]\Logs\`
- **Files**:
  - `install_[date].log` - Installation process log

## Viewing Logs

1. **During Execution**: Logs are displayed in the console
2. **After Execution**: Navigate to the appropriate output directory
3. **From Main Menu**: Select option 8 to open the reports folder

## Log Retention

Logs are kept indefinitely. Clean up old logs periodically:
- Keep audit logs for compliance (recommended: 1 year)
- Archive old logs to a secure location
- Delete test run logs as needed

## Troubleshooting

If an audit fails:
1. Check the ERROR_[timestamp].txt file in the output directory
2. Review the transcript log for complete execution history
3. Look for "ERROR" or "CRITICAL" entries in the main log file

## Important Notes

- **Never use Clear-Host or screen clearing** - This prevents users from seeing errors
- All errors are logged to files even if they disappear from screen
- Transcript logs capture everything displayed in the console