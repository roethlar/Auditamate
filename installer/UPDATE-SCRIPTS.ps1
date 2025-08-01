<#
.SYNOPSIS
    Updates scripts in an existing AD Audit Tool installation.

.DESCRIPTION
    This patch script updates only the PowerShell scripts in an existing
    installation without requiring a full reinstall.

.PARAMETER TargetDirectory
    The installation directory to update (default: tries common locations)

.EXAMPLE
    .\UPDATE-SCRIPTS.ps1
    Updates scripts in the default installation location

.EXAMPLE
    .\UPDATE-SCRIPTS.ps1 -TargetDirectory "D:\ADAuditTool"
    Updates scripts in a custom installation location
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetDirectory
)

Write-Host "`n=== AD Audit Tool Script Updater ===" -ForegroundColor Cyan
Write-Host "This will update the scripts in your existing installation.`n" -ForegroundColor Gray

# Try to find installation directory if not specified
if (-not $TargetDirectory) {
    $possiblePaths = @(
        "C:\Program Files\ADAuditTool",
        "D:\ADAuditTool",
        "$env:ProgramFiles\ADAuditTool",
        "C:\ADAuditTool"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\Start-ADAudit.ps1") {
            $TargetDirectory = $path
            Write-Host "Found installation at: $TargetDirectory" -ForegroundColor Green
            break
        }
    }
    
    if (-not $TargetDirectory) {
        $TargetDirectory = Read-Host "Please enter your AD Audit Tool installation directory"
    }
}

# Verify it's a valid installation
if (-not (Test-Path "$TargetDirectory\Scripts")) {
    Write-Host "ERROR: Not a valid AD Audit Tool installation directory." -ForegroundColor Red
    Write-Host "Could not find Scripts folder in: $TargetDirectory" -ForegroundColor Red
    exit 1
}

Write-Host "`nUpdating scripts in: $TargetDirectory" -ForegroundColor Yellow

# Backup current scripts
$backupDir = "$TargetDirectory\Scripts_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Write-Host "Creating backup at: $backupDir" -ForegroundColor Gray
Copy-Item -Path "$TargetDirectory\Scripts" -Destination $backupDir -Recurse -Force

# Update scripts
try {
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    
    # Copy all scripts
    Write-Host "`nUpdating scripts..." -ForegroundColor Yellow
    $scripts = Get-ChildItem -Path "$scriptPath\Scripts\*.ps1"
    
    foreach ($script in $scripts) {
        Copy-Item -Path $script.FullName -Destination "$TargetDirectory\Scripts\" -Force
        Write-Host "  Updated: $($script.Name)" -ForegroundColor Green
    }
    
    # Also update the main launcher if it exists
    if (Test-Path "$scriptPath\Scripts\Start-ADAudit.ps1") {
        Copy-Item -Path "$scriptPath\Scripts\Start-ADAudit.ps1" -Destination "$TargetDirectory\" -Force
        Write-Host "  Updated: Start-ADAudit.ps1 (main launcher)" -ForegroundColor Green
    }
    
    Write-Host "`n=== Update Complete ===" -ForegroundColor Green
    Write-Host "Your scripts have been updated successfully." -ForegroundColor Green
    Write-Host "`nBackup saved to: $backupDir" -ForegroundColor Gray
    Write-Host "If you encounter any issues, you can restore from the backup." -ForegroundColor Gray
    
} catch {
    Write-Host "`nERROR: Failed to update scripts" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "`nRestoring from backup..." -ForegroundColor Yellow
    
    # Restore backup
    Remove-Item -Path "$TargetDirectory\Scripts" -Recurse -Force -ErrorAction SilentlyContinue
    Move-Item -Path $backupDir -Destination "$TargetDirectory\Scripts" -Force
    
    Write-Host "Backup restored." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")