<#
.SYNOPSIS
    Quick installer for AD Audit Tool.

.DESCRIPTION
    Simple entry point for first-time setup. Launches the setup wizard
    with appropriate permissions and settings.

.EXAMPLE
    .\INSTALL.ps1
    Runs the setup wizard
#>

# Note: Admin privileges only needed if installing to Program Files
# The installer will check and prompt only if needed

# Set location to script directory
Set-Location $PSScriptRoot

Write-Host "`nWelcome to the AD Audit Tool installer!" -ForegroundColor Green
Write-Host "This wizard will guide you through the setup process.`n" -ForegroundColor Gray

# Prompt for installation directory
$defaultPath = "$env:ProgramFiles\ADAuditTool"
Write-Host "Default installation path: $defaultPath" -ForegroundColor Gray
$customPath = Read-Host "Press Enter to accept default or enter custom path"
$targetDir = if ($customPath) { $customPath } else { $defaultPath }

# Check if this is first run at the target directory
$isFirstRun = -not (Test-Path "$targetDir\Config\global-config.json")

if ($isFirstRun) {
    Write-Host "First-time installation detected." -ForegroundColor Yellow
    Write-Host "The setup wizard will:`n" -ForegroundColor Gray
    Write-Host "  * Check and install prerequisites" -ForegroundColor White
    Write-Host "  * Create configuration files" -ForegroundColor White
    Write-Host "  * Set up Azure app registration (optional)" -ForegroundColor White
    Write-Host "  * Configure email and audit settings" -ForegroundColor White
    Write-Host "  * Test the installation`n" -ForegroundColor White
} else {
    Write-Host "Existing installation detected." -ForegroundColor Yellow
    Write-Host "The setup wizard will help you:`n" -ForegroundColor Gray
    Write-Host "  * Check prerequisites" -ForegroundColor White
    Write-Host "  * Update configurations" -ForegroundColor White
    Write-Host "  * Add new integrations`n" -ForegroundColor White
}

$continue = Read-Host "Continue with setup? (Y/N)"

if ($continue -ne 'Y') {
    Write-Host "`nSetup cancelled." -ForegroundColor Yellow
    exit
}

# Run the enhanced setup wizard
try {
    if ($isFirstRun) {
        & "$PSScriptRoot\Scripts\Setup-AuditTool.ps1" -Mode Install -TargetDirectory $targetDir
    } else {
        Write-Host "`nExisting installation detected at: $targetDir" -ForegroundColor Yellow
        Write-Host "`nWhat would you like to do?" -ForegroundColor Cyan
        Write-Host "1. Check prerequisites only"
        Write-Host "2. Update existing configuration"
        Write-Host "3. Update scripts and configuration"
        Write-Host "4. Complete reinstall"
        
        $choice = Read-Host "`nSelect option (1-4)"
        
        switch ($choice) {
            "1" { & "$PSScriptRoot\Scripts\Setup-AuditTool.ps1" -Mode Check -TargetDirectory $targetDir }
            "2" { & "$PSScriptRoot\Scripts\Setup-AuditTool.ps1" -Mode UpdateConfig -TargetDirectory $targetDir }
            "3" { & "$PSScriptRoot\Scripts\Setup-AuditTool.ps1" -Mode Update -TargetDirectory $targetDir }
            "4" { & "$PSScriptRoot\Scripts\Setup-AuditTool.ps1" -Mode Install -TargetDirectory $targetDir }
            default { 
                Write-Host "Invalid option selected." -ForegroundColor Red
                exit
            }
        }
    }
} catch {
    Write-Host "`nSetup failed: $_" -ForegroundColor Red
    Write-Host "Please check the error message and try again." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

