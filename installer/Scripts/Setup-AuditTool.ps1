<#
.SYNOPSIS
    Enhanced setup wizard for AD Audit Tool with proper installation directory structure.

.DESCRIPTION
    Interactive setup wizard that implements proper installation patterns with
    global and per-user configurations in a target installation directory.

.PARAMETER Mode
    Setup mode: "Install", "Update", "UpdateConfig", or "Check"

.PARAMETER TargetDirectory
    Installation directory (default: C:\Program Files\ADAuditTool)

.PARAMETER SkipAzureApp
    Skip Azure app registration setup

.PARAMETER SkipWorkday
    Skip Workday configuration

.PARAMETER NonInteractive
    Run without prompts using defaults

.EXAMPLE
    .\Setup-AuditTool.ps1
    Run interactive setup wizard

.EXAMPLE
    .\Setup-AuditTool.ps1 -TargetDirectory "D:\Tools\ADAuditTool"
    Install to custom directory

.NOTES
    Author: IT Security Team
    Version: 2.0
#>

# No admin requirement - will check only if installing to Program Files

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Update", "UpdateConfig", "Check")]
    [string]$Mode = "Install",
    
    [Parameter(Mandatory=$false)]
    [string]$TargetDirectory = "$env:ProgramFiles\ADAuditTool",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAzureApp,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipWorkday,
    
    [Parameter(Mandatory=$false)]
    [switch]$NonInteractive,
    
    [Parameter(Mandatory=$false)]
    [switch]$PreserveConfig,
    
    [Parameter(Mandatory=$false)]
    [switch]$CleanInstall
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Current user
$script:CurrentUser = $env:USERNAME

function Write-SetupHeader {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   AD Audit Tool - Enhanced Setup Wizard" -ForegroundColor Cyan
    Write-Host "   Version 2.0" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Success", "Error", "Warning", "Info", "Progress")]
        [string]$Status = "Info"
    )
    
    switch ($Status) {
        "Success" { Write-Host "[OK] $Message" -ForegroundColor Green }
        "Error" { Write-Host "[X] $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "Progress" { Write-Host "[...] $Message" -ForegroundColor Cyan -NoNewline }
        default { Write-Host "[i] $Message" -ForegroundColor White }
    }
}

function Test-ExistingInstallation {
    param([string]$Path)
    
    if (Test-Path $Path) {
        # Check for key files that indicate a valid installation
        $requiredFiles = @(
            "$Path\Modules",
            "$Path\Config"
        )
        
        $isValid = $true
        foreach ($file in $requiredFiles) {
            if (-not (Test-Path $file)) {
                $isValid = $false
                break
            }
        }
        
        return @{
            Exists = $true
            IsValid = $isValid
            Version = if (Test-Path "$Path\version.txt") { Get-Content "$Path\version.txt" } else { "Unknown" }
        }
    }
    
    return @{ Exists = $false }
}

function Get-GlobalConfig {
    param([string]$ConfigPath)
    
    $globalConfigPath = "$ConfigPath\global-config.json"
    if (Test-Path $globalConfigPath) {
        try {
            return Get-Content $globalConfigPath | ConvertFrom-Json
        } catch {
            Write-Status "Failed to read global config: $_" "Error"
            return $null
        }
    }
    return $null
}

function Get-UserConfig {
    param(
        [string]$ConfigPath,
        [string]$Username = $env:USERNAME
    )
    
    $userConfigPath = "$ConfigPath\$Username\user-config.json"
    if (Test-Path $userConfigPath) {
        try {
            return Get-Content $userConfigPath | ConvertFrom-Json
        } catch {
            Write-Status "Failed to read user config: $_" "Error"
            return $null
        }
    }
    return $null
}

function Backup-ExistingConfig {
    param([string]$ConfigPath)
    
    if (Test-Path $ConfigPath) {
        $backupPath = "$ConfigPath.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Write-Status "Backing up existing configuration..." "Progress"
        Copy-Item -Path $ConfigPath -Destination $backupPath -Recurse -Force
        Write-Status "Configuration backed up to: $backupPath" "Success"
        return $backupPath
    }
    return $null
}

function Initialize-DirectoryStructure {
    param(
        [string]$TargetPath,
        [bool]$PreserveConfig = $true
    )
    
    Write-Status "Creating directory structure..." "Progress"
    
    # If doing complete reinstall and deleting config
    if (-not $PreserveConfig -and (Test-Path "$TargetPath\Config")) {
        Backup-ExistingConfig -ConfigPath "$TargetPath\Config" | Out-Null
        Write-Status "Removing existing configuration..." "Warning"
        Remove-Item -Path "$TargetPath\Config" -Recurse -Force
    }
    
    $directories = @(
        $TargetPath,
        "$TargetPath\Modules",
        "$TargetPath\Config",
        "$TargetPath\Config\$script:CurrentUser",
        "$TargetPath\Config\$script:CurrentUser\saved-jobs",
        "$TargetPath\Logs",
        "$TargetPath\Scripts",
        "$TargetPath\Reports",
        "$TargetPath\Docs"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Status "Created: $dir" "Success"
        }
    }
    
    # Create or update version file
    "2.0" | Out-File "$TargetPath\version.txt" -Encoding UTF8
}

function Copy-ScriptFiles {
    param(
        [string]$SourcePath,
        [string]$TargetPath
    )
    
    Write-Status "Copying script files..." "Progress"
    
    # Copy PowerShell scripts from Scripts folder
    if (Test-Path "$SourcePath\Scripts") {
        $scripts = Get-ChildItem -Path "$SourcePath\Scripts" -Filter "*.ps1" | 
            Where-Object { $_.Name -notlike "Setup-*" }
        
        foreach ($script in $scripts) {
            Copy-Item -Path $script.FullName -Destination "$TargetPath\Scripts\" -Force
            Write-Status "Copied: $($script.Name)" "Success"
        }
    }
    
    # Copy modules
    if (Test-Path "$SourcePath\Modules") {
        Copy-Item -Path "$SourcePath\Modules\*" -Destination "$TargetPath\Modules\" -Recurse -Force
        Write-Status "Copied modules" "Success"
    }
    
    # Config templates are created dynamically during setup, not copied
    
    # Copy documentation
    if (Test-Path "$SourcePath\Docs") {
        Copy-Item -Path "$SourcePath\Docs\*" -Destination "$TargetPath\Docs\" -Recurse -Force
        Write-Status "Copied documentation" "Success"
    }
    
    # Copy the installer to root of target for future updates
    if (Test-Path "$SourcePath\INSTALL.ps1") {
        Copy-Item -Path "$SourcePath\INSTALL.ps1" -Destination "$TargetPath\" -Force
    } elseif (Test-Path "$SourcePath\..\INSTALL.ps1") {
        Copy-Item -Path "$SourcePath\..\INSTALL.ps1" -Destination "$TargetPath\" -Force
    }
    
    # Copy the setup script (it's in the same directory as this script)
    Copy-Item -Path "$PSScriptRoot\Setup-AuditTool.ps1" -Destination "$TargetPath\" -Force
    
    # Copy the main entry point script
    if (Test-Path "$PSScriptRoot\Start-ADAudit.ps1") {
        Copy-Item -Path "$PSScriptRoot\Start-ADAudit.ps1" -Destination "$TargetPath\" -Force
        Write-Status "Copied main launcher (Start-ADAudit.ps1)" "Success"
    }
}

function Set-GlobalSettings {
    param(
        [string]$ConfigPath,
        [bool]$IsUpdate = $false
    )
    
    $globalConfigPath = "$ConfigPath\global-config.json"
    $azureConfigPath = "$ConfigPath\azure-app-config.json"
    $smtpConfigPath = "$ConfigPath\smtp-config.json"
    
    # Load existing configs if updating
    $globalConfig = if ($IsUpdate -and (Test-Path $globalConfigPath)) {
        Get-Content $globalConfigPath | ConvertFrom-Json
    } else {
        @{
            OrganizationName = ""
            PrimaryDomain = ""
            ForestRoot = ""
            ChildDomains = @()
            DefaultAuditGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
            InstallDate = (Get-Date -Format "yyyy-MM-dd")
            LastUpdated = (Get-Date -Format "yyyy-MM-dd")
        }
    }
    
    $azureConfig = if ($IsUpdate -and (Test-Path $azureConfigPath)) {
        Get-Content $azureConfigPath | ConvertFrom-Json
    } else {
        @{
            TenantId = ""
            ApplicationId = ""
            CertificateThumbprint = ""
            UseCertificateAuth = $false
            CreatedDate = ""
            CreatedBy = ""
        }
    }
    
    $smtpConfig = if ($IsUpdate -and (Test-Path $smtpConfigPath)) {
        Get-Content $smtpConfigPath | ConvertFrom-Json
    } else {
        @{
            SmtpServer = ""
            SmtpPort = 25
            UseSSL = $false
            RequiresAuthentication = $false
            DefaultFromAddress = ""
        }
    }
    
    Write-Host "`n=== Global Configuration ===" -ForegroundColor Yellow
    
    # Domain settings
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = $domain.Forest
        
        if ($IsUpdate -and $globalConfig.PrimaryDomain) {
            Write-Host "`nCurrent Domain Settings:" -ForegroundColor Cyan
            Write-Host "  Primary Domain: $($globalConfig.PrimaryDomain)" -ForegroundColor Gray
            Write-Host "  Forest Root: $($globalConfig.ForestRoot)" -ForegroundColor Gray
            if ($globalConfig.ChildDomains -and $globalConfig.ChildDomains.Count -gt 0) {
                Write-Host "  Child Domains: $($globalConfig.ChildDomains -join ', ')" -ForegroundColor Gray
            }
            
            $updateDomain = Read-Host "`nUpdate domain settings? (Y/N)"
            if ($updateDomain -eq 'Y') {
                $globalConfig.PrimaryDomain = $domain.Name
                $globalConfig.ForestRoot = $forest.RootDomain.Name
                $childDomains = $forest.Domains | Where-Object { $_.Name -ne $forest.RootDomain.Name } | Select-Object -ExpandProperty Name
                $globalConfig.ChildDomains = @($childDomains)
            }
        } else {
            Write-Status "Detected domain: $($domain.Name)" "Info"
            Write-Status "Forest root: $($forest.RootDomain.Name)" "Info"
            
            $globalConfig.PrimaryDomain = $domain.Name
            $globalConfig.ForestRoot = $forest.RootDomain.Name
            $childDomains = $forest.Domains | Where-Object { $_.Name -ne $forest.RootDomain.Name } | Select-Object -ExpandProperty Name
            $globalConfig.ChildDomains = @($childDomains)
            
            if ($childDomains) {
                Write-Status "Child domains: $($childDomains -join ', ')" "Info"
            }
        }
    } catch {
        Write-Status "Could not detect domain information" "Warning"
    }
    
    # Organization name
    if (-not $globalConfig.OrganizationName -or ($IsUpdate -and -not $NonInteractive)) {
        if ($globalConfig.OrganizationName) {
            Write-Host "`nCurrent organization: $($globalConfig.OrganizationName)" -ForegroundColor Gray
        }
        $orgName = Read-Host "Organization name (Enter to keep current)"
        if ($orgName) { $globalConfig.OrganizationName = $orgName }
    }
    
    # Azure App Configuration
    if (-not $SkipAzureApp) {
        Write-Host "`n=== Azure App Registration ===" -ForegroundColor Yellow
        
        if ($IsUpdate -and $azureConfig.ApplicationId) {
            Write-Host "`nExisting Azure App Configuration:" -ForegroundColor Cyan
            Write-Host "  Application ID: $($azureConfig.ApplicationId)" -ForegroundColor Gray
            Write-Host "  Tenant ID: $($azureConfig.TenantId)" -ForegroundColor Gray
            if ($azureConfig.CreatedDate) {
                Write-Host "  Created: $($azureConfig.CreatedDate) by $($azureConfig.CreatedBy)" -ForegroundColor Gray
            }
            
            $keepExisting = Read-Host "`nKeep existing Azure app registration? (Y/N)"
            if ($keepExisting -eq 'Y') {
                Write-Status "Keeping existing Azure app registration" "Success"
            } else {
                $createNew = Read-Host "Create NEW Azure app registration? (Y/N)"
                if ($createNew -eq 'Y') {
                    # Call Azure app creation script
                    Write-Status "Launching Azure app registration wizard..." "Info"
                    & "$PSScriptRoot\Scripts\New-AzureAppRegistration.ps1" -ConfigPath $ConfigPath
                    # Reload the config as it was updated by the script
                    $azureConfig = Get-Content $azureConfigPath | ConvertFrom-Json
                }
            }
        } else {
            Write-Host "`nNo Azure app registration found." -ForegroundColor Yellow
            $createApp = Read-Host "Create Azure app registration for Entra ID auditing? (Y/N)"
            if ($createApp -eq 'Y') {
                Write-Status "Launching Azure app registration wizard..." "Info"
                & "$PSScriptRoot\Scripts\New-AzureAppRegistration.ps1" -ConfigPath $ConfigPath
                # Reload the config
                if (Test-Path $azureConfigPath) {
                    $azureConfig = Get-Content $azureConfigPath | ConvertFrom-Json
                }
            }
        }
    }
    
    # SMTP Configuration
    Write-Host "`n=== Email Configuration ===" -ForegroundColor Yellow
    
    if ($IsUpdate -and $smtpConfig.SmtpServer) {
        Write-Host "`nCurrent SMTP Settings:" -ForegroundColor Cyan
        Write-Host "  Server: $($smtpConfig.SmtpServer):$($smtpConfig.SmtpPort)" -ForegroundColor Gray
        Write-Host "  From: $($smtpConfig.DefaultFromAddress)" -ForegroundColor Gray
        Write-Host "  SSL: $($smtpConfig.UseSSL)" -ForegroundColor Gray
        
        $updateSmtp = Read-Host "`nUpdate SMTP settings? (Y/N)"
        if ($updateSmtp -ne 'Y') {
            Write-Status "Keeping existing SMTP configuration" "Success"
        }
    }
    
    if (-not $smtpConfig.SmtpServer -or ($IsUpdate -and $updateSmtp -eq 'Y')) {
        $smtpServer = Read-Host "SMTP Server (e.g., smtp.company.com)"
        if ($smtpServer) {
            $smtpConfig.SmtpServer = $smtpServer
            
            $smtpPort = Read-Host "SMTP Port (default: 25)"
            if ($smtpPort) { $smtpConfig.SmtpPort = [int]$smtpPort }
            
            $useSSL = Read-Host "Use SSL? (Y/N)"
            $smtpConfig.UseSSL = ($useSSL -eq 'Y')
            
            $fromAddress = Read-Host "Default from address (e.g., audit@company.com)"
            if ($fromAddress) { $smtpConfig.DefaultFromAddress = $fromAddress }
        }
    }
    
    # Default audit groups
    if ($IsUpdate -and $globalConfig.DefaultAuditGroups) {
        Write-Host "`nCurrent default audit groups:" -ForegroundColor Cyan
        Write-Host "  $($globalConfig.DefaultAuditGroups -join ', ')" -ForegroundColor Gray
        
        $updateGroups = Read-Host "`nUpdate default groups? (Y/N)"
        if ($updateGroups -eq 'Y') {
            $groups = Read-Host "Enter group names (comma-separated)"
            if ($groups) {
                $globalConfig.DefaultAuditGroups = $groups -split ',' | ForEach-Object { $_.Trim() }
            }
        }
    } else {
        Write-Host "`nDefault AD groups to audit:" -ForegroundColor Cyan
        Write-Host "  Suggested: Domain Admins, Enterprise Admins, Schema Admins" -ForegroundColor Gray
        $groups = Read-Host "Enter group names (comma-separated)"
        if ($groups) {
            $globalConfig.DefaultAuditGroups = $groups -split ',' | ForEach-Object { $_.Trim() }
        }
    }
    
    # Save configurations
    $globalConfig.LastUpdated = (Get-Date -Format "yyyy-MM-dd")
    $globalConfig | ConvertTo-Json -Depth 10 | Out-File $globalConfigPath -Encoding UTF8
    Write-Status "Saved global configuration" "Success"
    
    $azureConfig | ConvertTo-Json -Depth 10 | Out-File $azureConfigPath -Encoding UTF8
    Write-Status "Saved Azure configuration" "Success"
    
    $smtpConfig | ConvertTo-Json -Depth 10 | Out-File $smtpConfigPath -Encoding UTF8
    Write-Status "Saved SMTP configuration" "Success"
}

function Set-UserSettings {
    param(
        [string]$ConfigPath,
        [string]$Username = $env:USERNAME,
        [bool]$IsUpdate = $false
    )
    
    $userConfigPath = "$ConfigPath\$Username\user-config.json"
    
    # Load existing config if updating
    $userConfig = if ($IsUpdate -and (Test-Path $userConfigPath)) {
        Get-Content $userConfigPath | ConvertFrom-Json
    } else {
        @{
            Username = $Username
            EmailSettings = @{
                SendToSelf = $true
                PersonalEmail = ""
                CCList = @()
            }
            OutputSettings = @{
                DefaultReportPath = "$env:USERPROFILE\Documents\AuditReports"
                PreferredFormat = "HTML"
                IncludeExcel = $true
                AutoOpenReports = $true
            }
            Preferences = @{
                ConfirmBeforeSend = $true
                SaveJobsAutomatically = $true
                VerboseLogging = $false
            }
            LastLogin = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }
    
    Write-Host "`n=== User Configuration ($Username) ===" -ForegroundColor Yellow
    
    if ($IsUpdate -and $userConfig.PersonalEmail) {
        Write-Host "`nCurrent user settings:" -ForegroundColor Cyan
        Write-Host "  Report output: $($userConfig.OutputSettings.DefaultReportPath)" -ForegroundColor Gray
        Write-Host "  Email to: $($userConfig.EmailSettings.PersonalEmail)" -ForegroundColor Gray
        Write-Host "  Preferred format: $($userConfig.OutputSettings.PreferredFormat)" -ForegroundColor Gray
        
        $updateUser = Read-Host "`nUpdate user settings? (Y/N)"
        if ($updateUser -ne 'Y') {
            Write-Status "Keeping existing user configuration" "Success"
            $userConfig.LastLogin = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            $userConfig | ConvertTo-Json -Depth 10 | Out-File $userConfigPath -Encoding UTF8
            return
        }
    }
    
    # Email preferences
    Write-Host "`nEmail Preferences:" -ForegroundColor Cyan
    $currentEmail = if ($userConfig.EmailSettings.PersonalEmail) { " (current: $($userConfig.EmailSettings.PersonalEmail))" } else { "" }
    $personalEmail = Read-Host "Your email address for report delivery$currentEmail"
    if ($personalEmail) { 
        $userConfig.EmailSettings.PersonalEmail = $personalEmail 
        $userConfig.EmailSettings.SendToSelf = $true
    }
    
    $currentCC = if ($userConfig.EmailSettings.CCList -and $userConfig.EmailSettings.CCList.Count -gt 0) { 
        " (current: $($userConfig.EmailSettings.CCList -join ', '))" 
    } else { "" }
    $ccList = Read-Host "Additional CC recipients (comma-separated)$currentCC"
    if ($ccList) {
        $userConfig.EmailSettings.CCList = $ccList -split ',' | ForEach-Object { $_.Trim() }
    }
    
    # Output preferences
    Write-Host "`nOutput Preferences:" -ForegroundColor Cyan
    $reportPath = Read-Host "Default report output path (Enter for: $($userConfig.OutputSettings.DefaultReportPath))"
    if ($reportPath) { $userConfig.OutputSettings.DefaultReportPath = $reportPath }
    
    # Create report directory if it doesn't exist
    if (-not (Test-Path $userConfig.OutputSettings.DefaultReportPath)) {
        New-Item -ItemType Directory -Path $userConfig.OutputSettings.DefaultReportPath -Force | Out-Null
        Write-Status "Created report directory" "Success"
    }
    
    Write-Host "Report format options: HTML, CSV, Excel" -ForegroundColor Gray
    $format = Read-Host "Preferred report format (current: $($userConfig.OutputSettings.PreferredFormat))"
    if ($format -and $format -in @('HTML', 'CSV', 'Excel')) {
        $userConfig.OutputSettings.PreferredFormat = $format
    }
    
    # Update last login
    $userConfig.LastLogin = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    
    # Save user configuration
    $userConfig | ConvertTo-Json -Depth 10 | Out-File $userConfigPath -Encoding UTF8
    Write-Status "Saved user configuration" "Success"
}

function Test-Prerequisites {
    Write-Host "`n=== Checking Prerequisites ===" -ForegroundColor Yellow
    
    $results = @{
        PowerShell = @{
            Name = "PowerShell 5.1+"
            Status = $PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1
            Required = $true
        }
        ADModule = @{
            Name = "Active Directory Module"
            Status = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)
            Required = $true
        }
        ExchangeModule = @{
            Name = "Exchange Online Management"
            Status = $null -ne (Get-Module -ListAvailable -Name ExchangeOnlineManagement)
            Required = $false
        }
        MSALModule = @{
            Name = "MSAL.PS Module"
            Status = $null -ne (Get-Module -ListAvailable -Name MSAL.PS)
            Required = $false
        }
        # WinRM removed - not needed for AD queries
    }
    
    $allPassed = $true
    $missingRequired = @()
    
    foreach ($key in $results.Keys) {
        $item = $results[$key]
        if ($item.Status) {
            Write-Status $item.Name "Success"
        } else {
            if ($item.Required) {
                Write-Status "$($item.Name) - MISSING (Required)" "Error"
                $allPassed = $false
                $missingRequired += $item.Name
            } else {
                Write-Status "$($item.Name) - MISSING (Optional)" "Warning"
            }
        }
    }
    
    if (-not $allPassed) {
        Write-Host "`nMissing required prerequisites:" -ForegroundColor Red
        foreach ($missing in $missingRequired) {
            Write-Host "  - $missing" -ForegroundColor Red
        }
        
        if ($Mode -ne "Check") {
            Write-Host "`nSetup cannot continue without required prerequisites." -ForegroundColor Red
            Write-Host "Please install the missing components and run setup again." -ForegroundColor Yellow
            exit 1
        }
    }
    
    return $results
}

# Main setup flow
Write-SetupHeader

# Test prerequisites first
$prereqs = Test-Prerequisites
if ($Mode -eq "Check") {
    Write-Host "`nPrerequisite check complete." -ForegroundColor Green
    exit 0
}

# Determine installation status
$installation = Test-ExistingInstallation -Path $TargetDirectory

if ($installation.Exists -and $installation.IsValid) {
    Write-Host "`nExisting installation found at: $TargetDirectory" -ForegroundColor Yellow
    Write-Host "Version: $($installation.Version)" -ForegroundColor Gray
    
    # For existing installations, offer update options
    if ($Mode -eq "Install") {
        Write-Host "`nAn installation already exists at this location." -ForegroundColor Yellow
        Write-Host "`nOptions:" -ForegroundColor Cyan
        Write-Host "1. Update - Copy only new/changed files (preserves configurations)" -ForegroundColor White
        Write-Host "2. Reinstall - Complete fresh installation" -ForegroundColor White
        Write-Host "3. Cancel" -ForegroundColor White
        
        $choice = Read-Host "`nSelect option (1-3)"
        
        switch ($choice) {
            "1" { 
                $Mode = "Update"
                Write-Host "`nSwitching to Update mode..." -ForegroundColor Green
            }
            "2" {
                # Handle based on parameters passed from INSTALL.ps1
                if ($CleanInstall) {
                    $script:DeleteExistingConfig = $true
                    Write-Host "Clean installation - all data will be removed." -ForegroundColor Red
                } elseif ($PreserveConfig) {
                    $script:DeleteExistingConfig = $false
                    Write-Host "Reinstalling while preserving configurations." -ForegroundColor Green
                } else {
                    # Legacy behavior if called directly
                    Write-Host "`nComplete reinstall selected." -ForegroundColor Yellow
                    $deleteConfig = Read-Host "Delete existing configuration files? (Y/N)"
                    $script:DeleteExistingConfig = ($deleteConfig -eq 'Y')
                }
            }
            default {
                Write-Host "Setup cancelled." -ForegroundColor Red
                exit 0
            }
        }
    }
} elseif ($installation.Exists -and -not $installation.IsValid) {
    Write-Status "Installation appears to be incomplete or corrupted" "Warning"
    $repair = Read-Host "Attempt to repair installation? (Y/N)"
    if ($repair -ne 'Y') {
        Write-Host "Setup cancelled." -ForegroundColor Red
        exit 1
    }
    $Mode = "Install"  # Force reinstall
} else {
    # New installation
    if ($Mode -ne "Install") {
        Write-Host "No installation found at: $TargetDirectory" -ForegroundColor Yellow
        Write-Host "Switching to installation mode..." -ForegroundColor Yellow
        $Mode = "Install"
    }
    
    Write-Host "`nNew installation to: $TargetDirectory" -ForegroundColor Green
    
    if ($TargetDirectory -like "*Program Files*") {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
            Write-Host "`nNote: Installing to Program Files requires Administrator privileges." -ForegroundColor Yellow
            Write-Host "Consider using a different directory like D:\ADAuditTool or C:\ADAuditTool" -ForegroundColor Yellow
            $changeDir = Read-Host "`nWould you like to choose a different directory? (Y/N)"
            if ($changeDir -eq 'Y') {
                $TargetDirectory = Read-Host "Enter new installation directory"
                Write-Host "New installation directory: $TargetDirectory" -ForegroundColor Green
            } else {
                Write-Host "Please run as Administrator to install to Program Files." -ForegroundColor Red
                exit 1
            }
        }
    }
    
    if (-not $NonInteractive) {
        $confirm = Read-Host "`nProceed with installation? (Y/N)"
        if ($confirm -ne 'Y') {
            Write-Host "Setup cancelled." -ForegroundColor Red
            exit 0
        }
    }
}

# Create directory structure
if ($Mode -eq "Install") {
    # Pass config preservation choice
    $preserveConfig = -not ($script:DeleteExistingConfig -eq $true)
    Initialize-DirectoryStructure -TargetPath $TargetDirectory -PreserveConfig $preserveConfig
}

# Copy script files
if ($Mode -in @("Install", "Update")) {
    Copy-ScriptFiles -SourcePath (Split-Path $PSScriptRoot -Parent) -TargetPath $TargetDirectory
}

# Configure settings
if ($Mode -ne "Check") {
    # Skip configuration if just updating files
    if ($Mode -eq "Update") {
        Write-Host "`nSkipping configuration (update mode - files only)" -ForegroundColor Yellow
    } else {
        # Configure global settings
        $isUpdate = $Mode -eq "UpdateConfig" -or ($installation.Exists -and $installation.IsValid -and $Mode -ne "Install")
        Set-GlobalSettings -ConfigPath "$TargetDirectory\Config" -IsUpdate $isUpdate
        
        # Configure user settings
        Set-UserSettings -ConfigPath "$TargetDirectory\Config" -IsUpdate $isUpdate
    }
}

# Final summary
Write-Host "`n=== Setup Complete ===" -ForegroundColor Green
Write-Host "`nInstallation directory: $TargetDirectory" -ForegroundColor White
Write-Host "User config directory: $TargetDirectory\Config\$env:USERNAME" -ForegroundColor White
Write-Host "`nTo start using the AD Audit Tool:" -ForegroundColor Yellow
Write-Host "  1. Navigate to: $TargetDirectory" -ForegroundColor White
Write-Host "  2. Run: .\Start-ADAudit.ps1" -ForegroundColor White

if ($Mode -eq "Install") {
    Write-Host "`nFirst time setup tips:" -ForegroundColor Cyan
    Write-Host "  1. Review your configuration files in: $TargetDirectory\Config" -ForegroundColor Gray
    Write-Host "  2. Test with a small audit first" -ForegroundColor Gray
    Write-Host "  3. Check the Logs folder for any issues" -ForegroundColor Gray
}