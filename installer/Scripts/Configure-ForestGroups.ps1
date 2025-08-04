<#
.SYNOPSIS
    Quick configuration tool for forest audit groups.

.DESCRIPTION
    Allows configuration of which privileged groups to audit in each domain
    without going through the full setup process.

.EXAMPLE
    .\Configure-ForestGroups.ps1
    Interactive configuration of forest audit groups
#>

# Get installation directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$installPath = Split-Path $scriptPath -Parent

Write-Host "`n=== Forest Audit Group Configuration Tool ===" -ForegroundColor Cyan
Write-Host "This tool configures which privileged groups to audit in each domain." -ForegroundColor Gray

# Run the setup tool in forest group configuration mode
& "$installPath\Setup-AuditTool.ps1" -Mode ConfigureForestGroups -TargetDirectory $installPath