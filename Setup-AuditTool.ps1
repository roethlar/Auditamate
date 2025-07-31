<#
.SYNOPSIS
    Comprehensive setup wizard for AD Audit Tool.

.DESCRIPTION
    Interactive setup wizard that tests prerequisites, installs missing components,
    configures Azure app registration, and creates configuration files.

.PARAMETER Mode
    Setup mode: "Install" (first time), "Update" (modify existing), or "Check" (verify only)

.PARAMETER SkipAzureApp
    Skip Azure app registration setup

.PARAMETER SkipWorkday
    Skip Workday configuration

.PARAMETER NonInteractive
    Run without prompts using defaults where possible

.EXAMPLE
    .\Setup-AuditTool.ps1
    Run interactive setup wizard

.EXAMPLE
    .\Setup-AuditTool.ps1 -Mode Check
    Check prerequisites without making changes

.EXAMPLE
    .\Setup-AuditTool.ps1 -SkipAzureApp -SkipWorkday
    Quick setup for AD-only auditing

.NOTES
    Author: IT Security Team
    Version: 1.0
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Update", "Check")]
    [string]$Mode = "Install",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAzureApp,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipWorkday,
    
    [Parameter(Mandatory=$false)]
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Setup colors and formatting
$script:CheckMark = [char]0x2713
$script:CrossMark = [char]0x2717
$script:WarningSign = [char]0x26A0

function Write-SetupHeader {
    Clear-Host
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   AD Audit Tool - Setup Wizard" -ForegroundColor Cyan
    Write-Host "   Version 1.0" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Success", "Error", "Warning", "Info", "Progress")]
        [string]$Status = "Info"
    )
    
    switch ($Status) {
        "Success" { Write-Host "[$script:CheckMark] $Message" -ForegroundColor Green }
        "Error" { Write-Host "[$script:CrossMark] $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[$script:WarningSign] $Message" -ForegroundColor Yellow }
        "Progress" { Write-Host "[...] $Message" -ForegroundColor Cyan -NoNewline }
        default { Write-Host "[i] $Message" -ForegroundColor White }
    }
}

function Test-Prerequisite {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Install,
        [string]$InstallMessage,
        [bool]$Required = $true
    )
    
    Write-Status "$Name" "Progress"
    
    try {
        $result = & $Test
        if ($result) {
            Write-Host "`r" -NoNewline
            Write-Status "$Name" "Success"
            return $true
        }
    } catch {
        # Test failed
    }
    
    Write-Host "`r" -NoNewline
    
    if ($Mode -eq "Check") {
        if ($Required) {
            Write-Status "$Name - MISSING (Required)" "Error"
        } else {
            Write-Status "$Name - MISSING (Optional)" "Warning"
        }
        return $false
    }
    
    if ($Required) {
        Write-Status "$Name - MISSING" "Error"
    } else {
        Write-Status "$Name - MISSING" "Warning"
    }
    
    if ($Install -and -not $NonInteractive) {
        $response = Read-Host "`n  Install $Name? (Y/N)"
        if ($response -eq 'Y') {
            Write-Status "Installing $Name..." "Progress"
            try {
                & $Install
                Write-Host "`r" -NoNewline
                Write-Status "$InstallMessage" "Success"
                return $true
            } catch {
                Write-Host "`r" -NoNewline
                Write-Status "Failed to install $Name`: $_" "Error"
                return $false
            }
        }
    } elseif ($Install -and $NonInteractive -and $Required) {
        Write-Status "Installing $Name..." "Progress"
        try {
            & $Install
            Write-Host "`r" -NoNewline
            Write-Status "$InstallMessage" "Success"
            return $true
        } catch {
            Write-Host "`r" -NoNewline
            Write-Status "Failed to install $Name`: $_" "Error"
            return $false
        }
    }
    
    return $false
}

function Initialize-Configuration {
    Write-Host "`n=== Configuration Setup ===" -ForegroundColor Yellow
    
    # Create config directory if needed
    $configPath = "$PSScriptRoot\Config"
    if (-not (Test-Path $configPath)) {
        New-Item -ItemType Directory -Path $configPath -Force | Out-Null
        Write-Status "Created Config directory" "Success"
    }
    
    # Main audit config
    $auditConfigPath = "$configPath\audit-config.json"
    if (-not (Test-Path $auditConfigPath)) {
        Write-Status "Creating audit configuration..." "Info"
        
        $config = @{
            Groups = @()
            IncludeNestedGroups = $true
            IncludeDisabledUsers = $false
            EmailSettings = @{
                Recipients = @()
                From = ""
                SmtpServer = ""
                Port = 587
                UseSSL = $true
            }
            OutputSettings = @{
                GenerateHtml = $true
                GenerateExcel = $true
                GenerateCsv = $false
            }
            MultiDomainSettings = @{
                AuditAllDomains = $false
                ForestRootDomain = ""
                ChildDomains = @()
                IncludeForestRootGroups = $true
                ResolveForeignSecurityPrincipals = $true
            }
        }
        
        # Get basic info
        if (-not $NonInteractive) {
            Write-Host "`nLet's configure basic settings:" -ForegroundColor Cyan
            
            # Get current domain info
            try {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $forest = $domain.Forest
                
                Write-Status "Detected domain: $($domain.Name)" "Info"
                Write-Status "Forest root: $($forest.RootDomain.Name)" "Info"
                
                $config.MultiDomainSettings.ForestRootDomain = $forest.RootDomain.Name
                
                # Find child domains
                $childDomains = $forest.Domains | Where-Object { $_.Name -ne $forest.RootDomain.Name } | Select-Object -ExpandProperty Name
                if ($childDomains) {
                    Write-Status "Child domains found: $($childDomains -join ', ')" "Info"
                    $config.MultiDomainSettings.ChildDomains = @($childDomains)
                }
            } catch {
                Write-Status "Could not detect domain information" "Warning"
            }
            
            # Email settings
            Write-Host "`nEmail Configuration:" -ForegroundColor Cyan
            $smtpServer = Read-Host "SMTP Server (e.g., smtp.company.com)"
            if ($smtpServer) {
                $config.EmailSettings.SmtpServer = $smtpServer
                
                $emailFrom = Read-Host "From address (e.g., ad-audit@company.com)"
                if ($emailFrom) { $config.EmailSettings.From = $emailFrom }
                
                $recipients = Read-Host "Recipient emails (comma-separated)"
                if ($recipients) {
                    $config.EmailSettings.Recipients = $recipients -split ',' | ForEach-Object { $_.Trim() }
                }
            }
            
            # Default groups to audit
            Write-Host "`nDefault AD groups to audit:" -ForegroundColor Cyan
            Write-Host "  Suggested: Domain Admins, Enterprise Admins, Schema Admins" -ForegroundColor Gray
            $groups = Read-Host "Enter group names (comma-separated)"
            if ($groups) {
                $config.Groups = $groups -split ',' | ForEach-Object { $_.Trim() }
            } else {
                $config.Groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
            }
        }
        
        $config | ConvertTo-Json -Depth 10 | Out-File $auditConfigPath -Encoding UTF8
        Write-Status "Created audit-config.json" "Success"
    } else {
        Write-Status "audit-config.json already exists" "Info"
    }
    
    # Server audit config
    $serverConfigPath = "$configPath\server-audit-config.json"
    if (-not (Test-Path $serverConfigPath)) {
        Write-Status "Creating server audit configuration..." "Info"
        
        # Check if template exists, otherwise create default config
        $templatePath = "$configPath\server-audit-config-template.json"
        if (Test-Path $templatePath) {
            $serverConfig = Get-Content $templatePath | ConvertFrom-Json
        } else {
            # Create default server config
            $serverConfig = @{
                ServerGroups = @{
                    CriticalServers = @{
                        Name = "Critical Servers"
                        Servers = @()
                    }
                    DomainControllers = @{
                        Name = "Domain Controllers"
                        AutoDetect = $true
                    }
                }
            }
        }
        
        if (-not $NonInteractive) {
            Write-Host "`nServer Audit Configuration:" -ForegroundColor Cyan
            Write-Host "Enter critical servers to audit (one per line, blank to finish):" -ForegroundColor Gray
            
            $servers = @()
            while ($true) {
                $server = Read-Host "Server"
                if ([string]::IsNullOrWhiteSpace($server)) { break }
                $servers += $server
            }
            
            if ($servers.Count -gt 0) {
                $serverConfig.ServerGroups.CriticalServers.Servers = $servers
            }
        }
        
        $serverConfig | ConvertTo-Json -Depth 10 | Out-File $serverConfigPath -Encoding UTF8
        Write-Status "Created server-audit-config.json" "Success"
    } else {
        Write-Status "server-audit-config.json already exists" "Info"
    }
    
    # Privileged access config
    $privConfigPath = "$configPath\privileged-access-config.json"
    if (-not (Test-Path $privConfigPath)) {
        $templatePath = "$configPath\privileged-access-config-template.json"
        if (Test-Path $templatePath) {
            Copy-Item $templatePath $privConfigPath -Force
        } else {
            # Create default privileged access config
            @{
                TenantId = ""
                ClientId = ""
                ClientSecret = ""
                CertificateThumbprint = ""
                UseCertificateAuth = $false
                CriticalRoles = @("Global Administrator", "Privileged Role Administrator", "Security Administrator")
            } | ConvertTo-Json -Depth 10 | Out-File $privConfigPath -Encoding UTF8
        }
        Write-Status "Created privileged-access-config.json" "Success"
    }
    
    # AuditBoard config
    $abConfigPath = "$configPath\auditboard-config.json"
    if (-not (Test-Path $abConfigPath)) {
        $templatePath = "$configPath\auditboard-config-template.json"
        if (Test-Path $templatePath) {
            Copy-Item $templatePath $abConfigPath -Force
        } else {
            # Create default AuditBoard config
            @{
                AuditBoardSettings = @{
                    ApiUrl = "https://api.auditboard.com"
                    ApiKey = ""
                    WorkspaceId = ""
                    Enabled = $false
                }
            } | ConvertTo-Json -Depth 10 | Out-File $abConfigPath -Encoding UTF8
        }
        Write-Status "Created auditboard-config.json (requires API key)" "Warning"
    }
}

function Update-Configuration {
    Write-Host "`n=== Configuration Update Wizard ===" -ForegroundColor Yellow
    
    $configFiles = @(
        @{Name = "Main Audit Configuration"; Path = "$PSScriptRoot\Config\audit-config.json"},
        @{Name = "Server Audit Configuration"; Path = "$PSScriptRoot\Config\server-audit-config.json"},
        @{Name = "Privileged Access Configuration"; Path = "$PSScriptRoot\Config\privileged-access-config.json"},
        @{Name = "AuditBoard Configuration"; Path = "$PSScriptRoot\Config\auditboard-config.json"},
        @{Name = "Workday Configuration"; Path = "$PSScriptRoot\Config\workday-config.json"}
    )
    
    Write-Host "`nWhich configuration would you like to update?" -ForegroundColor Cyan
    for ($i = 0; $i -lt $configFiles.Count; $i++) {
        $exists = Test-Path $configFiles[$i].Path
        $status = if ($exists) { "(Configured)" } else { "(Not configured)" }
        Write-Host "$($i + 1). $($configFiles[$i].Name) $status"
    }
    Write-Host "0. Exit"
    
    $choice = Read-Host "`nSelect option"
    
    if ($choice -eq "0") { return }
    
    $selectedConfig = $configFiles[[int]$choice - 1]
    
    if (-not (Test-Path $selectedConfig.Path)) {
        Write-Status "Configuration file not found" "Error"
        return
    }
    
    Write-Host "`nOpening configuration in default editor..." -ForegroundColor Cyan
    Start-Process notepad.exe -ArgumentList $selectedConfig.Path -Wait
    
    Write-Status "Configuration updated" "Success"
}

# Main setup flow
Write-SetupHeader

if ($Mode -eq "Update") {
    Update-Configuration
    exit 0
}

Write-Host "Mode: $Mode" -ForegroundColor Gray
Write-Host "This wizard will help you set up the AD Audit Tool.`n" -ForegroundColor Gray

# Step 1: Check PowerShell version
Write-Host "=== Checking Prerequisites ===" -ForegroundColor Yellow

$psVersion = Test-Prerequisite -Name "PowerShell 5.1+" -Test {
    $PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1
} -Required $true

# Step 2: Check required modules
$adModule = Test-Prerequisite -Name "Active Directory Module" -Test {
    Get-Module -ListAvailable -Name ActiveDirectory
} -Install {
    # Try to install RSAT
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1) {
        # Workstation
        Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell -All
    } else {
        # Server
        Install-WindowsFeature -Name RSAT-AD-PowerShell
    }
} -InstallMessage "Installed AD PowerShell module" -Required $true

$exchangeModule = Test-Prerequisite -Name "Exchange Online Management" -Test {
    Get-Module -ListAvailable -Name ExchangeOnlineManagement
} -Install {
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
} -InstallMessage "Installed Exchange Online module" -Required $false

$msalModule = Test-Prerequisite -Name "MSAL.PS Module" -Test {
    Get-Module -ListAvailable -Name MSAL.PS
} -Install {
    Install-Module -Name MSAL.PS -Force -AllowClobber -Scope CurrentUser
} -InstallMessage "Installed MSAL.PS module" -Required $false

# Step 3: Check WinRM
$winrm = Test-Prerequisite -Name "WinRM Service" -Test {
    (Get-Service -Name WinRM).Status -eq 'Running'
} -Install {
    Enable-PSRemoting -Force
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM
} -InstallMessage "Enabled WinRM for remote server auditing" -Required $true

# Step 4: Check execution policy
$execPolicy = Test-Prerequisite -Name "PowerShell Execution Policy" -Test {
    $policy = Get-ExecutionPolicy -Scope CurrentUser
    $policy -in @('RemoteSigned', 'Unrestricted', 'Bypass')
} -Install {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
} -InstallMessage "Set execution policy to RemoteSigned" -Required $true

# Step 5: Check Excel
$excel = Test-Prerequisite -Name "Microsoft Excel" -Test {
    try {
        $xl = New-Object -ComObject Excel.Application
        $xl.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($xl) | Out-Null
        $true
    } catch {
        $false
    }
} -Required $false

# Check write permissions
$writePermissions = Test-Prerequisite -Name "Output directory permissions" -Test {
    try {
        $testFile = "$PSScriptRoot\Output\test.tmp"
        New-Item -Path "$PSScriptRoot\Output" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        "test" | Out-File $testFile -Force
        Remove-Item $testFile -Force
        $true
    } catch {
        $false
    }
} -Install {
    # Try to create directory and set permissions
    try {
        New-Item -Path "$PSScriptRoot\Output" -ItemType Directory -Force | Out-Null
        $acl = Get-Acl "$PSScriptRoot\Output"
        $permission = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        Set-Acl "$PSScriptRoot\Output" $acl
    } catch {
        throw "Cannot set permissions on Output directory"
    }
} -InstallMessage "Created Output directory with proper permissions" -Required $true

# Check if all required prerequisites passed
$requiredPrereqs = @{
    "PowerShell 5.1+" = $psVersion
    "Active Directory Module" = $adModule
    "WinRM Service" = $winrm
    "PowerShell Execution Policy" = $execPolicy
    "Output Directory Permissions" = $writePermissions
}

$failedPrereqs = $requiredPrereqs.GetEnumerator() | Where-Object { -not $_.Value }

if ($failedPrereqs) {
    Write-Host "`n=== Setup Cannot Continue ===" -ForegroundColor Red
    Write-Host "The following required prerequisites are missing:" -ForegroundColor Yellow
    foreach ($prereq in $failedPrereqs) {
        Write-Host "  - $($prereq.Key)" -ForegroundColor Red
    }
    Write-Host "`nPlease install these prerequisites and run setup again." -ForegroundColor Yellow
    exit 1
}

# Check optional prerequisites
$optionalPrereqs = @{
    "Exchange Online Management" = $exchangeModule
    "MSAL.PS Module" = $msalModule
    "Microsoft Excel" = $excel
}

$missingOptional = $optionalPrereqs.GetEnumerator() | Where-Object { -not $_.Value }

if ($missingOptional) {
    Write-Host "`n=== Optional Components Missing ===" -ForegroundColor Yellow
    Write-Host "The following optional components are not installed:" -ForegroundColor Yellow
    foreach ($prereq in $missingOptional) {
        Write-Host "  - $($prereq.Key)" -ForegroundColor Yellow
    }
    Write-Host "Some features may not be available." -ForegroundColor Gray
}

if ($Mode -eq "Check") {
    Write-Host "`n=== Prerequisite Check Complete ===" -ForegroundColor Cyan
    if (-not $failedPrereqs) {
        Write-Host "All required prerequisites are installed!" -ForegroundColor Green
    }
    exit 0
}

# Step 6: Initialize configurations
Write-Host "`nAll required prerequisites passed. Continuing with setup..." -ForegroundColor Green
Initialize-Configuration

# Step 7: Azure App Registration
if (-not $SkipAzureApp) {
    Write-Host "`n=== Azure App Registration ===" -ForegroundColor Yellow
    
    if (-not $NonInteractive) {
        $setupAzure = Read-Host "Set up Azure app registration for Entra ID auditing? (Y/N)"
        
        if ($setupAzure -eq 'Y') {
            Write-Host "`nYou have two options:" -ForegroundColor Cyan
            Write-Host "1. Automatic setup (requires Global Admin)"
            Write-Host "2. Manual setup with instructions"
            
            $azureChoice = Read-Host "`nSelect option (1 or 2)"
            
            if ($azureChoice -eq "1") {
                Write-Status "Launching automatic Azure app setup..." "Info"
                & "$PSScriptRoot\New-AzureAppRegistration.ps1"
            } else {
                Write-Status "Launching manual setup guide..." "Info"
                & "$PSScriptRoot\Setup-GraphAppRegistration.ps1"
            }
            
            # Update privileged access config with app details
            $privConfig = Get-Content "$PSScriptRoot\Config\privileged-access-config.json" | ConvertFrom-Json
            
            $tenantId = Read-Host "`nEnter your Azure Tenant ID"
            $clientId = Read-Host "Enter the App (Client) ID"
            
            if ($tenantId -and $clientId) {
                $privConfig.TenantId = $tenantId
                $privConfig.ClientId = $clientId
                $privConfig | ConvertTo-Json -Depth 10 | Out-File "$PSScriptRoot\Config\privileged-access-config.json" -Encoding UTF8
                Write-Status "Updated privileged-access-config.json" "Success"
            }
        }
    }
}

# Step 8: Workday configuration
if (-not $SkipWorkday -and -not $NonInteractive) {
    Write-Host "`n=== Workday Configuration ===" -ForegroundColor Yellow
    
    $setupWorkday = Read-Host "Configure Workday integration? (Y/N)"
    
    if ($setupWorkday -eq 'Y') {
        $wdConfig = @{
            WorkdaySettings = @{
                TenantUrl = ""
                Username = ""
                ReportUrl = ""
                UseIntegrationUser = $true
            }
            TerminationSettings = @{
                GracePeriodDays = 1
                CheckFields = @("TerminationDate", "LastDayOfWork")
                IncludeContractors = $false
            }
        }
        
        Write-Host "`nWorkday API Configuration:" -ForegroundColor Cyan
        $wdConfig.WorkdaySettings.TenantUrl = Read-Host "Workday tenant URL (e.g., https://wd.company.com)"
        $wdConfig.WorkdaySettings.Username = Read-Host "Integration username"
        $wdConfig.WorkdaySettings.ReportUrl = Read-Host "Termination report URL (RaaS)"
        
        $wdConfig | ConvertTo-Json -Depth 10 | Out-File "$PSScriptRoot\Config\workday-config.json" -Encoding UTF8
        Write-Status "Created workday-config.json" "Success"
        Write-Status "Note: You'll need to securely store the integration password" "Warning"
    }
}

# Step 9: Test installation
Write-Host "`n=== Testing Installation ===" -ForegroundColor Yellow

Write-Status "Running prerequisite test..." "Progress"
$testResult = & "$PSScriptRoot\Test-Prerequisites.ps1" -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
Write-Host "`r" -NoNewline
Write-Status "Prerequisite test completed" "Success"

# Step 10: Create shortcuts
if (-not $NonInteractive) {
    Write-Host "`n=== Create Desktop Shortcuts ===" -ForegroundColor Yellow
    $createShortcuts = Read-Host "Create desktop shortcuts for common audits? (Y/N)"
    
    if ($createShortcuts -eq 'Y') {
        $desktop = [Environment]::GetFolderPath("Desktop")
        
        # AD Audit shortcut
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$desktop\AD Security Audit.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $scriptPath = Join-Path $PSScriptRoot 'Run-ADCompleteAudit.ps1'
        $configPath = Join-Path $PSScriptRoot 'Config\audit-config.json'
        $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -ConfigFile `"$configPath`""
        $Shortcut.WorkingDirectory = $PSScriptRoot
        $Shortcut.IconLocation = "powershell.exe"
        $Shortcut.Description = "Run AD Security Audit"
        $Shortcut.Save()
        
        Write-Status "Created 'AD Security Audit' desktop shortcut" "Success"
    }
}

# Final summary
Write-Host "`n===============================================" -ForegroundColor Green
Write-Host "   Setup Complete!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review and update configuration files in the Config folder"
Write-Host "2. Test basic AD audit: .\Run-ADCompleteAudit.ps1 -Groups 'Domain Admins'"
Write-Host "3. Set up scheduled tasks for automated audits"
Write-Host "4. Configure AuditBoard API key if using AuditBoard integration"

Write-Host "`nTo update configurations later, run:" -ForegroundColor Gray
Write-Host "  .\Setup-AuditTool.ps1 -Mode Update" -ForegroundColor White

Write-Host "`nFor help, see README.md or run:" -ForegroundColor Gray
Write-Host "  Get-Help .\Run-ADCompleteAudit.ps1 -Full" -ForegroundColor White

Write-Host "`n"