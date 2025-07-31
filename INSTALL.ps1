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

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This installer requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Restarting as Administrator..." -ForegroundColor Yellow
    
    # Relaunch as administrator
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Set location to script directory
Set-Location $PSScriptRoot

Write-Host "`nWelcome to the AD Audit Tool installer!" -ForegroundColor Green
Write-Host "This wizard will guide you through the setup process.`n" -ForegroundColor Gray

# Check if this is first run
$isFirstRun = -not (Test-Path "$PSScriptRoot\Config\audit-config.json")

if ($isFirstRun) {
    Write-Host "First-time installation detected." -ForegroundColor Yellow
    Write-Host "The setup wizard will:`n" -ForegroundColor Gray
    Write-Host "  • Check and install prerequisites" -ForegroundColor White
    Write-Host "  • Create configuration files" -ForegroundColor White
    Write-Host "  • Set up Azure app registration (optional)" -ForegroundColor White
    Write-Host "  • Configure email and audit settings" -ForegroundColor White
    Write-Host "  • Test the installation`n" -ForegroundColor White
} else {
    Write-Host "Existing installation detected." -ForegroundColor Yellow
    Write-Host "The setup wizard will help you:`n" -ForegroundColor Gray
    Write-Host "  • Check prerequisites" -ForegroundColor White
    Write-Host "  • Update configurations" -ForegroundColor White
    Write-Host "  • Add new integrations`n" -ForegroundColor White
}

$continue = Read-Host "Continue with setup? (Y/N)"

if ($continue -ne 'Y') {
    Write-Host "`nSetup cancelled." -ForegroundColor Yellow
    exit
}

# Run the setup wizard
try {
    if ($isFirstRun) {
        & "$PSScriptRoot\Setup-AuditTool.ps1" -Mode Install
    } else {
        Write-Host "`nWhat would you like to do?" -ForegroundColor Cyan
        Write-Host "1. Check prerequisites only"
        Write-Host "2. Update existing configuration"
        Write-Host "3. Run full setup wizard"
        
        $choice = Read-Host "`nSelect option (1-3)"
        
        switch ($choice) {
            "1" { & "$PSScriptRoot\Setup-AuditTool.ps1" -Mode Check }
            "2" { & "$PSScriptRoot\Setup-AuditTool.ps1" -Mode Update }
            "3" { & "$PSScriptRoot\Setup-AuditTool.ps1" -Mode Install }
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