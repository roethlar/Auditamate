#Requires -Version 5.1
# Note: Requires write access to audit tool installation directory

<#
.SYNOPSIS
    Migrates AD Audit Tool to use secure modules

.DESCRIPTION
    Updates existing scripts to use the new secure modules with input validation,
    proper error handling, and security enhancements.

.PARAMETER BackupPath
    Path to store backups of original files

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    .\Migrate-ToSecureModules.ps1 -BackupPath "C:\Backups\ADAudit"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = (Join-Path $PSScriptRoot "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Create backup directory
if (-not (Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

Write-Host "`nAD Audit Tool Security Migration" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "`nThis script will update your AD Audit Tool to use secure modules with:" -ForegroundColor Yellow
Write-Host "  - Input validation to prevent injection attacks" -ForegroundColor White
Write-Host "  - Secure credential management" -ForegroundColor White
Write-Host "  - Centralized error handling with retry logic" -ForegroundColor White
Write-Host "  - Structured logging with rotation" -ForegroundColor White
Write-Host "  - Performance optimizations" -ForegroundColor White

if (-not $Force) {
    $confirm = Read-Host "`nDo you want to continue? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Migration cancelled." -ForegroundColor Yellow
        exit
    }
}

# Files to update
$filesToUpdate = @{
    'Run-ADCompleteAudit.ps1' = @{
        UpdateRequired = $true
        Changes = @(
            @{
                Find = '[string[]]$Groups,'
                Replace = @'
[ValidateScript({ 
    $_ | ForEach-Object { 
        Import-Module "$PSScriptRoot\Modules\InputValidation.psm1" -Force
        if (-not (Test-ADGroupName $_)) {
            throw "Invalid group name: $_"
        }
    }
    return $true
})]
[string[]]$Groups,
'@
            }
            @{
                Find = 'Import-Module "$PSScriptRoot\Modules\AD-AuditModule.psm1"'
                Replace = @'
# Import secure modules
Import-Module "$PSScriptRoot\Modules\InputValidation.psm1" -Force
Import-Module "$PSScriptRoot\Modules\SecureCredentialManager.psm1" -Force
Import-Module "$PSScriptRoot\Modules\ErrorHandler.psm1" -Force
Import-Module "$PSScriptRoot\Modules\ConfigurationManager.psm1" -Force
Import-Module "$PSScriptRoot\Modules\StructuredLogging.psm1" -Force
Import-Module "$PSScriptRoot\Modules\AD-AuditModule-Secure.psm1" -Force
'@
            }
            @{
                Find = 'Get-ADGroupAuditData'
                Replace = 'Get-ADGroupAuditDataSecure'
            }
            @{
                Find = 'Export-ADGroupMembers'
                Replace = 'Export-ADGroupMembersSecure'
            }
        )
    }
    'Run-ForestAudit.ps1' = @{
        UpdateRequired = $true
        Changes = @(
            @{
                Find = '[string]$Domain'
                Replace = @'
[ValidateScript({
    if ($_ -and $_ -notmatch '^[a-zA-Z0-9.-]+$') {
        throw "Invalid domain name format"
    }
    return $true
})]
[string]$Domain
'@
            }
        )
    }
    'Run-PrivilegedAccessAudit.ps1' = @{
        UpdateRequired = $true
        Changes = @(
            @{
                Find = '[string]$ClientSecret,'
                Replace = '[SecureString]$ClientSecret,'
            }
            @{
                Find = '$config.ClientSecret'
                Replace = '(ConvertTo-SecureString $config.ClientSecret -AsPlainText -Force)'
            }
        )
    }
}

# Process each file
foreach ($file in $filesToUpdate.Keys) {
    $filePath = Join-Path $PSScriptRoot $file
    
    if (Test-Path $filePath) {
        Write-Host "`nProcessing: $file" -ForegroundColor Green
        
        # Backup original
        $backupFile = Join-Path $BackupPath $file
        Copy-Item $filePath $backupFile -Force
        Write-Host "  - Backed up to: $backupFile" -ForegroundColor Gray
        
        # Read content
        $content = Get-Content $filePath -Raw
        $originalContent = $content
        
        # Apply changes
        foreach ($change in $filesToUpdate[$file].Changes) {
            if ($content -match [regex]::Escape($change.Find)) {
                $content = $content -replace [regex]::Escape($change.Find), $change.Replace
                Write-Host "  - Applied: $($change.Find -split "`n" | Select-Object -First 1)..." -ForegroundColor Gray
            }
        }
        
        # Add module imports at the beginning if not present
        if ($content -notmatch 'Import-Module.*InputValidation') {
            $moduleImports = @'
# Import security modules
$modulePath = Split-Path $PSScriptRoot -Parent
Import-Module "$modulePath\Modules\InputValidation.psm1" -Force
Import-Module "$modulePath\Modules\SecureCredentialManager.psm1" -Force
Import-Module "$modulePath\Modules\ErrorHandler.psm1" -Force
Import-Module "$modulePath\Modules\ConfigurationManager.psm1" -Force
Import-Module "$modulePath\Modules\StructuredLogging.psm1" -Force

'@
            # Insert after param block
            if ($content -match '(param\s*\([^)]+\))') {
                $paramBlock = $matches[0]
                $insertPoint = $content.IndexOf($paramBlock) + $paramBlock.Length
                # Update module imports to use parent directory
                $moduleImports = $moduleImports -replace '\$PSScriptRoot "Modules"', '(Split-Path \$PSScriptRoot -Parent) "Modules"'
                $content = $content.Insert($insertPoint, "`n`n$moduleImports")
            }
        }
        
        # Save updated file
        if ($content -ne $originalContent) {
            Set-Content $filePath -Value $content -Encoding UTF8
            Write-Host "  - Updated successfully" -ForegroundColor Green
        } else {
            Write-Host "  - No changes needed" -ForegroundColor Yellow
        }
    }
}

# Create sample secure configuration
$sampleConfig = @{
    Groups = @('Domain Admins', 'Enterprise Admins')
    EmailSettings = @{
        Recipients = @('admin@company.com')
        From = 'adaudit@company.com'
        SmtpServer = 'smtp.company.com'
        Port = 587
        UseSSL = $true
    }
    OutputSettings = @{
        GenerateHtml = $true
        GenerateExcel = $true
        GenerateCsv = $false
        OutputPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'ADAudit\Reports'
    }
    Security = @{
        MinTLSVersion = 'Tls12'
        ValidateCertificates = $true
        EnableAuditLog = $true
        LogLevel = 'Info'
    }
}

$configPath = Join-Path $PSScriptRoot "Config\audit-config-secure.json"
$sampleConfig | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
Write-Host "`nCreated secure configuration template: $configPath" -ForegroundColor Green

# Create README for new modules
$readmeContent = @'
# Secure Modules Documentation

## Overview
These modules provide security-hardened functionality for the AD Audit Tool:

### InputValidation.psm1
- `Test-ADGroupName`: Validates AD group names to prevent injection
- `Test-FilePath`: Validates file paths to prevent traversal attacks
- `Test-EmailAddress`: Validates email addresses

### SecureCredentialManager.psm1
- `Get-SecureCredential`: Securely stores and retrieves credentials using DPAPI
- `ConvertTo-SecureStringFromPlainText`: Migration helper for converting plain text

### ErrorHandler.psm1
- `Write-AuditError`: Logs errors with sanitization
- `Invoke-AuditCommand`: Executes commands with retry logic and proper error handling

### ConfigurationManager.psm1
- `Get-AuditConfiguration`: Loads and validates configuration with schema
- `Set-AuditConfiguration`: Saves configuration with validation

### StructuredLogging.psm1
- `Initialize-AuditLogger`: Sets up structured logging with rotation
- `Write-AuditLog`: Writes structured log entries with context

### AD-AuditModule-Secure.psm1
- `Get-ADGroupAuditDataSecure`: Secure version with input validation and performance optimizations
- `Get-ADPermissionsAuditSecure`: Secure permissions auditing
- `Export-ADGroupMembersSecure`: Streaming Excel export for large datasets

## Migration Notes
- All group names are now validated to prevent injection
- Credentials are stored securely using Windows DPAPI
- Parallel processing improves performance for large audits
- Structured logging provides better troubleshooting

## Security Best Practices
1. Always validate user input
2. Use SecureString for sensitive data
3. Implement proper error handling
4. Enable audit logging
5. Review logs regularly
'@

$readmePath = Join-Path $PSScriptRoot "Modules\README-SecureModules.md"
Set-Content $readmePath -Value $readmeContent -Encoding UTF8
Write-Host "Created module documentation: $readmePath" -ForegroundColor Green

Write-Host "`n==============================" -ForegroundColor Cyan
Write-Host "Migration completed successfully!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Review the changes in your backed up files" -ForegroundColor White
Write-Host "2. Update the configuration file with your settings" -ForegroundColor White
Write-Host "3. Test the updated scripts in a non-production environment" -ForegroundColor White
Write-Host "4. Run Test-Prerequisites.ps1 to verify the setup" -ForegroundColor White

Write-Host "`nFor more information, see: $readmePath" -ForegroundColor Gray