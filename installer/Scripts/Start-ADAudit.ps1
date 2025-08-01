<#
.SYNOPSIS
    Active Directory Audit Tool
    Main entry point for running audits

.DESCRIPTION
    This is the main launcher for AD Audit Tool. Use this script to run various
    types of AD audits. It provides a menu-driven interface for easy access
    to all audit functions.

.EXAMPLE
    .\Start-ADAudit.ps1
    Launch the interactive menu

.EXAMPLE
    .\Start-ADAudit.ps1 -QuickAudit "Domain Admins"
    Run a quick audit of Domain Admins group
#>

param(
    [string]$QuickAudit = ""
)

# Set location to script directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

# Display header
function Show-Header {
    Clear-Host
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "        AD AUDIT TOOL                          " -ForegroundColor Cyan
    Write-Host "     Active Directory Audit Tool               " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
}

# Quick audit if parameter provided
if ($QuickAudit) {
    Write-Host "Running quick audit for: $QuickAudit" -ForegroundColor Yellow
    & "$scriptPath\Scripts\Run-ADCompleteAudit.ps1" -Groups $QuickAudit
    exit
}

# Main menu loop
do {
    Show-Header
    
    # Check if configurations exist
    $configPath = "$scriptPath\Config"
    $globalConfig = "$configPath\global-config.json"
    $userConfig = "$configPath\$env:USERNAME\user-config.json"
    
    if (-not (Test-Path $globalConfig) -or -not (Test-Path $userConfig)) {
        Write-Host "Configuration not found. Please run setup first." -ForegroundColor Yellow
        Write-Host "`nRun: .\Setup-AuditTool.ps1" -ForegroundColor White
        Write-Host "`nPress any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }
    
    # Load user preferences
    try {
        $userSettings = Get-Content $userConfig | ConvertFrom-Json
        Write-Host "User: $($userSettings.Username)" -ForegroundColor Gray
        Write-Host "Reports: $($userSettings.OutputSettings.DefaultReportPath)" -ForegroundColor Gray
    } catch {
        Write-Host "Error loading user configuration" -ForegroundColor Red
    }
    
    Write-Host "`n=== MAIN MENU ===" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. AD Complete Audit (Groups & Users)" -ForegroundColor White
    Write-Host "2. Forest-Wide Audit" -ForegroundColor White
    Write-Host "3. Privileged Access Audit (AD + Azure)" -ForegroundColor White
    Write-Host "4. Local Administrator Audit" -ForegroundColor White
    Write-Host "5. Termination Audit" -ForegroundColor White
    Write-Host ""
    Write-Host "6. Test Prerequisites" -ForegroundColor Gray
    Write-Host "7. Update Configuration" -ForegroundColor Gray
    Write-Host "8. View Recent Reports" -ForegroundColor Gray
    Write-Host ""
    Write-Host "0. Exit" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Select option (0-8)"
    
    switch ($choice) {
        "1" {
            Write-Host "`n=== AD Complete Audit ===" -ForegroundColor Cyan
            $defaultGroups = try {
                $gc = Get-Content $globalConfig | ConvertFrom-Json
                $gc.DefaultAuditGroups -join ", "
            } catch { "Domain Admins, Enterprise Admins" }
            
            Write-Host "Default groups: $defaultGroups" -ForegroundColor Gray
            $groups = Read-Host "Enter groups to audit (comma-separated) or press Enter for defaults"
            if (-not $groups) { $groups = $defaultGroups }
            
            Write-Host "`nStarting audit..." -ForegroundColor Yellow
            & "$scriptPath\Scripts\Run-ADCompleteAudit.ps1" -Groups $groups.Split(',').Trim()
        }
        
        "2" {
            Write-Host "`n=== Forest-Wide Audit ===" -ForegroundColor Cyan
            Write-Host "This will audit all domains in the forest." -ForegroundColor Gray
            $confirm = Read-Host "Continue? (Y/N)"
            if ($confirm -eq 'Y') {
                & "$scriptPath\Scripts\Run-ForestAudit.ps1"
            }
        }
        
        "3" {
            Write-Host "`n=== Privileged Access Audit ===" -ForegroundColor Cyan
            Write-Host "This will audit AD privileged groups and Azure admin roles." -ForegroundColor Gray
            $includeAzure = Read-Host "Include Azure audit? (Y/N)"
            
            if ($includeAzure -eq 'Y') {
                & "$scriptPath\Scripts\Run-PrivilegedAccessAudit.ps1" -IncludeAzure
            } else {
                & "$scriptPath\Scripts\Run-PrivilegedAccessAudit.ps1"
            }
        }
        
        "4" {
            Write-Host "`n=== Local Administrator Audit ===" -ForegroundColor Cyan
            $servers = Read-Host "Enter server names (comma-separated) or 'config' to use configured list"
            
            if ($servers -eq 'config') {
                & "$scriptPath\Scripts\Run-LocalAdminAudit.ps1" -UseConfig
            } else {
                & "$scriptPath\Scripts\Run-LocalAdminAudit.ps1" -Servers $servers.Split(',').Trim()
            }
        }
        
        "5" {
            Write-Host "`n=== Termination Audit ===" -ForegroundColor Cyan
            $users = Read-Host "Enter usernames to audit (comma-separated)"
            if ($users) {
                & "$scriptPath\Scripts\Run-TerminationAudit.ps1" -Users $users.Split(',').Trim()
            }
        }
        
        "6" {
            Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
            & "$scriptPath\Test-Prerequisites.ps1"
        }
        
        "7" {
            Write-Host "`nLaunching configuration update..." -ForegroundColor Yellow
            & "$scriptPath\Setup-AuditTool.ps1" -Mode UpdateConfig
        }
        
        "8" {
            Write-Host "`nOpening reports folder..." -ForegroundColor Yellow
            $reportsPath = try {
                $us = Get-Content $userConfig | ConvertFrom-Json
                $us.OutputSettings.DefaultReportPath
            } catch { "$scriptPath\Reports" }
            
            if (Test-Path $reportsPath) {
                Start-Process explorer.exe $reportsPath
            } else {
                Write-Host "Reports folder not found: $reportsPath" -ForegroundColor Red
            }
        }
        
        "0" {
            Write-Host "`nExiting..." -ForegroundColor Gray
            exit
        }
        
        default {
            Write-Host "`nInvalid option!" -ForegroundColor Red
        }
    }
    
    if ($choice -ne "0") {
        Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
} while ($true)