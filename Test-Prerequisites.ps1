<#
.SYNOPSIS
    Tests system prerequisites for AD Audit Tool.

.DESCRIPTION
    Validates that all required modules, permissions, and configurations are in place
    before running audit scripts. Helps new administrators identify missing components.

.EXAMPLE
    .\Test-Prerequisites.ps1
    Runs all prerequisite checks and provides recommendations.

.NOTES
    Run this before first use of the audit tools.
#>

[CmdletBinding()]
param()

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD Audit Tool - Prerequisites Check" -ForegroundColor Cyan  
Write-Host "========================================`n" -ForegroundColor Cyan

$results = @{
    Passed = 0
    Failed = 0
    Warnings = 0
}

function Test-Requirement {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$FailureMessage,
        [string]$SuccessMessage = "OK",
        [switch]$Warning
    )
    
    Write-Host -NoNewline "Checking $Name... "
    
    try {
        $result = & $Test
        if ($result) {
            Write-Host $SuccessMessage -ForegroundColor Green
            $script:results.Passed++
        } else {
            if ($Warning) {
                Write-Host "WARNING" -ForegroundColor Yellow
                Write-Host "  $FailureMessage" -ForegroundColor Yellow
                $script:results.Warnings++
            } else {
                Write-Host "FAILED" -ForegroundColor Red
                Write-Host "  $FailureMessage" -ForegroundColor Red
                $script:results.Failed++
            }
        }
    } catch {
        Write-Host "ERROR" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        $script:results.Failed++
    }
}

# PowerShell Version
Test-Requirement -Name "PowerShell Version" -Test {
    $PSVersionTable.PSVersion.Major -ge 5
} -FailureMessage "PowerShell 5.1 or higher required. Current: $($PSVersionTable.PSVersion)"

# Administrator Rights
Test-Requirement -Name "Administrator Rights" -Test {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} -FailureMessage "Script must be run as Administrator. Right-click and 'Run as Administrator'"

# Active Directory Module
Test-Requirement -Name "Active Directory Module" -Test {
    Get-Module -ListAvailable -Name ActiveDirectory
} -FailureMessage "AD PowerShell module not found. Install RSAT or run on Domain Controller"

# Domain Connectivity
Test-Requirement -Name "Domain Connectivity" -Test {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $true
    } catch {
        $false
    }
} -FailureMessage "Not connected to domain. Ensure you're on domain-joined machine" -SuccessMessage "Connected to $($domain.Name)"

# Domain Admin Check
Test-Requirement -Name "Domain Permissions" -Test {
    $groups = whoami /groups /fo csv | ConvertFrom-Csv
    $adminGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
    $hasAdmin = $false
    foreach ($group in $adminGroups) {
        if ($groups."Group Name" -match $group) {
            $hasAdmin = $true
            break
        }
    }
    $hasAdmin
} -Warning -FailureMessage "No Domain Admin rights detected. You may have limited access"

# Excel COM Object
Test-Requirement -Name "Microsoft Excel" -Test {
    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        $true
    } catch {
        $false
    }
} -Warning -FailureMessage "Excel not installed. Excel exports will fail, but CSV will work"

# Exchange Online Module
Test-Requirement -Name "Exchange Online Module" -Test {
    Get-Module -ListAvailable -Name ExchangeOnlineManagement
} -Warning -FailureMessage "Exchange Online module not found. Run: Install-Module ExchangeOnlineManagement"

# Check for Graph modules
Test-Requirement -Name "MSAL.PS Module" -Test {
    Get-Module -ListAvailable -Name MSAL.PS
} -Warning -FailureMessage "MSAL.PS not found. Will be auto-installed when needed"

# Network connectivity
Test-Requirement -Name "Internet Connectivity" -Test {
    Test-Connection -ComputerName "graph.microsoft.com" -Count 1 -Quiet
} -Warning -FailureMessage "Cannot reach Microsoft Graph. Online features may not work"

# Check configuration files
Test-Requirement -Name "Configuration Files" -Test {
    Test-Path ".\Config\audit-config.json"
} -Warning -FailureMessage "audit-config.json not found. Using defaults or specify groups manually"

# File system permissions
Test-Requirement -Name "Write Permissions" -Test {
    try {
        $testFile = ".\Output\test-write.tmp"
        New-Item -Path ".\Output" -ItemType Directory -Force | Out-Null
        "test" | Out-File $testFile
        Remove-Item $testFile -Force
        $true
    } catch {
        $false
    }
} -FailureMessage "Cannot write to Output directory. Check permissions"

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "Passed: " -NoNewline
Write-Host $results.Passed -ForegroundColor Green

if ($results.Warnings -gt 0) {
    Write-Host "Warnings: " -NoNewline
    Write-Host $results.Warnings -ForegroundColor Yellow
}

if ($results.Failed -gt 0) {
    Write-Host "Failed: " -NoNewline
    Write-Host $results.Failed -ForegroundColor Red
}

# Recommendations
if ($results.Failed -gt 0) {
    Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "1. Fix all FAILED items before running audits" -ForegroundColor White
    Write-Host "2. Run this script as Domain Administrator" -ForegroundColor White
    Write-Host "3. Ensure you're on a domain-joined machine" -ForegroundColor White
}

if ($results.Warnings -gt 0) {
    Write-Host "`nOPTIONAL IMPROVEMENTS:" -ForegroundColor Yellow
    Write-Host "1. Install Excel for better reporting" -ForegroundColor White
    Write-Host "2. Install Exchange module for Exchange audits" -ForegroundColor White
    Write-Host "3. Create audit-config.json for easier operation" -ForegroundColor White
}

if ($results.Failed -eq 0) {
    Write-Host "`n✓ System ready for AD auditing!" -ForegroundColor Green
    
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "1. Review README.md for usage examples" -ForegroundColor White
    Write-Host "2. Edit audit-config.json for your environment" -ForegroundColor White
    Write-Host '3. Run: .\Run-ADCompleteAudit.ps1 -Groups "Domain Admins"' -ForegroundColor White
}

Write-Host ""