<#
.SYNOPSIS
    Performs comprehensive AD audit across multi-domain forest environment.

.DESCRIPTION
    Audits Active Directory groups across forest root and child domains, handling
    cross-domain memberships, Enterprise Admins, Schema Admins, and Foreign Security
    Principals. Designed for environments with separate forest root and user domains.

.PARAMETER ConfigFile
    Path to JSON configuration file. Default: .\audit-config.json

.PARAMETER ForestRootGroups
    Include forest-level groups (Enterprise Admins, Schema Admins).

.PARAMETER AllDomains
    Audit all domains in the forest.

.PARAMETER Domains
    Specific domains to audit.

.PARAMETER CaptureCommands
    Capture PowerShell commands for compliance evidence.

.PARAMETER Job
    Path to a saved job file to load parameters from a previous run.

.PARAMETER SaveJob
    Path to save current parameters as a job file for future reuse.

.EXAMPLE
    .\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains
    Audits all domains including forest-level groups.

.EXAMPLE
    .\Run-ForestAudit.ps1 -Domains "corp.company.com", "users.corp.company.com"
    Audits specific domains only.

.EXAMPLE
    .\Run-ForestAudit.ps1 -ForestRootGroups -AllDomains -SaveJob forest-audit.json
    Runs forest-wide audit and saves parameters for reuse.

.EXAMPLE
    .\Run-ForestAudit.ps1 -Job forest-audit.json
    Re-runs a previously saved forest audit job.

.NOTES
    Requires Domain Admin in child domain or Enterprise Admin for full access.
#>

# No admin rights needed for AD queries
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "$(Split-Path $PSScriptRoot -Parent)\Config\forest-audit-config.json",
    
    [Parameter(Mandatory=$false)]
    [switch]$ForestRootGroups,
    
    [Parameter(Mandatory=$false)]
    [switch]$AllDomains,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Domains,
    
    [Parameter(Mandatory=$false)]
    [switch]$CaptureCommands = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\Forest_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$Job,
    
    [Parameter(Mandatory=$false)]
    [string]$SaveJob
)

$ErrorActionPreference = 'Stop'

# Start logging and timing
$auditStartTime = Get-Date

if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$logFile = "$OutputDirectory\forest-audit.log"
$transcript = "$OutputDirectory\forest-audit-transcript.log"
Start-Transcript -Path $transcript -Force

function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

Write-AuditLog "`n===============================================" "INFO"
Write-AuditLog "  Multi-Domain Forest AD Audit Tool" "INFO"
Write-AuditLog "===============================================`n" "INFO"
Write-AuditLog "Output Directory: $OutputDirectory" "INFO"

try {
    # Load job if specified
    if ($Job) {
        if (Test-Path $Job) {
            Write-Host "Loading job configuration from: $Job" -ForegroundColor Green
            $jobConfig = Get-Content $Job | ConvertFrom-Json
            
            # Override parameters with job config
            if ($jobConfig.PSObject.Properties["ForestRootGroups"]) { $ForestRootGroups = $jobConfig.ForestRootGroups }
            if ($jobConfig.PSObject.Properties["AllDomains"]) { $AllDomains = $jobConfig.AllDomains }
            if ($jobConfig.Domains) { $Domains = $jobConfig.Domains }
            if ($jobConfig.PSObject.Properties["CaptureCommands"]) { $CaptureCommands = $jobConfig.CaptureCommands }
            if ($jobConfig.PSObject.Properties["SendEmail"]) { $SendEmail = $jobConfig.SendEmail }
            if ($jobConfig.ConfigFile) { $ConfigFile = $jobConfig.ConfigFile }
        } else {
            Write-Warning "Job file not found: $Job"
        }
    }
    
    # Create output directory
    if (!(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    # Import modules (modules are in parent directory)
    $modulePath = Split-Path $PSScriptRoot -Parent
    Import-Module "$modulePath\Modules\AD-AuditModule.psm1" -Force
    . "$modulePath\Modules\AD-MultiDomainAudit.ps1"
    . "$modulePath\Modules\AD-ReportGenerator.ps1"
    . "$modulePath\Modules\Send-AuditReport.ps1"
    . "$modulePath\Modules\Audit-OutputCapture.ps1"
    . "$modulePath\Modules\Audit-EnhancedCapture.ps1"
    
    # Create output directory
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    # Load configuration
    $config = @{
        Groups = @()
        MultiDomainSettings = @{
            AuditAllDomains = $false
            SpecificDomains = @()
            IncludeForestRootGroups = $false
            ResolveForeignSecurityPrincipals = $true
        }
    }
    
    if (Test-Path $ConfigFile) {
        Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor Green
        $loadedConfig = Get-Content $ConfigFile | ConvertFrom-Json
        foreach ($key in $loadedConfig.PSObject.Properties.Name) {
            $config[$key] = $loadedConfig.$key
        }
    }
    
    # Override with parameters
    if ($ForestRootGroups) {
        $config.MultiDomainSettings.IncludeForestRootGroups = $true
    }
    
    # Display forest information
    Write-Host "`nEnumerating forest structure..." -ForegroundColor Yellow
    $forestDomains = Get-ADForestDomains
    
    Write-Host "`nForest Domains Found:" -ForegroundColor Cyan
    foreach ($domain in $forestDomains) {
        $marker = if ($domain.IsRoot) { "[ROOT]" } else { "[CHILD]" }
        Write-Host "  $marker $($domain.Name) (NetBIOS: $($domain.NetBIOSName))" -ForegroundColor White
    }
    
    # Determine which domains to audit
    $auditDomains = @()
    if ($AllDomains -or $config.MultiDomainSettings.AuditAllDomains) {
        $auditDomains = $forestDomains.Name
    } elseif ($Domains) {
        $auditDomains = $Domains
    } elseif ($config.MultiDomainSettings.SpecificDomains.Count -gt 0) {
        $auditDomains = $config.MultiDomainSettings.SpecificDomains
    } else {
        # Default to all domains
        $auditDomains = $forestDomains.Name
    }
    
    Write-Host "`nDomains to audit: $($auditDomains -join ', ')" -ForegroundColor Yellow
    
    # Check current user's domain membership
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "Running as: $($currentUser.Name) from domain: $currentDomain" -ForegroundColor Gray
    
    # Step 1: Get privileged groups across forest
    Write-Host "`nStep 1: Identifying privileged groups across forest..." -ForegroundColor Yellow
    
    $privilegedGroups = Get-ADForestPrivilegedGroups
    Write-Host "Found $($privilegedGroups.Count) privileged groups across all domains" -ForegroundColor Green
    
    # Display summary
    $forestGroups = $privilegedGroups | Where-Object { $_.Scope -eq "Forest" }
    $domainGroups = $privilegedGroups | Where-Object { $_.Scope -eq "Domain" }
    Write-Host "  Forest-level groups: $($forestGroups.Count)" -ForegroundColor Gray
    Write-Host "  Domain-level groups: $($domainGroups.Count)" -ForegroundColor Gray
    
    # Step 2: Collect group data
    Write-Host "`nStep 2: Collecting detailed group membership data..." -ForegroundColor Yellow
    Write-Host "Note: Some groups may be skipped if the service account lacks permissions." -ForegroundColor Gray
    
    # Get groups to audit based on configuration
    $groupsToAudit = @()
    
    if ($config.DomainGroups) {
        Write-Host "`nUsing domain-specific group configuration..." -ForegroundColor Yellow
        
        # Get configured groups for each domain
        foreach ($domain in $auditDomains) {
            $domainGroups = @()
            
            # Check for domain-specific configuration
            if ($config.DomainGroups.$domain) {
                $domainGroups = $config.DomainGroups.$domain
                Write-Host "  $domain : $($domainGroups -join ', ')" -ForegroundColor Gray
            }
            # Use default groups if no specific config
            elseif ($config.DomainGroups._default) {
                $domainGroups = $config.DomainGroups._default
                Write-Host "  $domain : Using default groups" -ForegroundColor Gray
            }
            
            $groupsToAudit += $domainGroups
        }
        
        # Remove duplicates and excluded groups
        $groupsToAudit = $groupsToAudit | Select-Object -Unique
        if ($config.ExcludeGroups) {
            $groupsToAudit = $groupsToAudit | Where-Object { $_ -notin $config.ExcludeGroups }
        }
    } else {
        Write-Host "`nNo domain group configuration found, using discovered privileged groups..." -ForegroundColor Yellow
        # Fall back to discovered privileged groups
        foreach ($group in $privilegedGroups) {
            $groupsToAudit += $group.GroupName
        }
        $groupsToAudit = $groupsToAudit | Select-Object -Unique
    }
    
    Write-Host "`nWill audit these groups: $($groupsToAudit -join ', ')" -ForegroundColor Cyan
    
    $groupData = Get-ADGroupAuditDataMultiDomain `
        -GroupNames $groupsToAudit `
        -Domains $auditDomains `
        -IncludeForestRootGroups:$config.MultiDomainSettings.IncludeForestRootGroups `
        -IncludeNestedGroups:$config.IncludeNestedGroups `
        -ResolveForeignSecurityPrincipals:$config.MultiDomainSettings.ResolveForeignSecurityPrincipals `
        -OutputDirectory $OutputDirectory
    
    Write-Host "Collected data for $($groupData.Count) groups" -ForegroundColor Green
    
    # Display any groups with errors
    $errorGroups = $groupData | Where-Object { $_.Status -like "*Error*" }
    if ($errorGroups) {
        Write-Host "`nGroups with access errors ($($errorGroups.Count)):" -ForegroundColor Yellow
        foreach ($group in $errorGroups) {
            Write-Host "  - $($group.GroupName) ($($group.Domain)): $($group.ErrorDetails)" -ForegroundColor Gray
        }
        Write-Host "Note: These groups will be included in the report with error status." -ForegroundColor Gray
    }
    
    # Display cross-domain membership summary
    $crossDomainGroups = $groupData | Where-Object { $_.CrossDomainMembers -gt 0 }
    if ($crossDomainGroups) {
        Write-Host "`nCross-domain memberships detected:" -ForegroundColor Yellow
        foreach ($group in $crossDomainGroups) {
            Write-Host "  $($group.GroupName) ($($group.Domain)): $($group.CrossDomainMembers) cross-domain members" -ForegroundColor White
        }
    }
    
    # Step 3: Generate enhanced web report with embedded content
    Write-Host "`nStep 3: Generating enhanced web report..." -ForegroundColor Yellow
    
    # Import the enhanced web report generator
    . "$PSScriptRoot\..\Modules\Enhanced-WebReportGenerator.ps1"
    
    # Collect all screenshots from group folders
    $allScreenshots = @()
    Get-ChildItem "$OutputDirectory\*" -Directory | ForEach-Object {
        $groupFolder = $_
        Get-ChildItem "$($groupFolder.FullName)\*.png" -ErrorAction SilentlyContinue | ForEach-Object {
            $allScreenshots += $_.FullName
        }
    }
    
    # Collect all CSV files
    $allCsvFiles = @()
    Get-ChildItem "$OutputDirectory" -Recurse -Filter "*.csv" | ForEach-Object {
        $allCsvFiles += $_.FullName
    }
    
    # Prepare metadata
    $forestRoot = ($forestDomains | Where-Object { $_.IsRoot }).Name
    $metadata = @{
        "Audit Type" = "Multi-Domain Forest Audit"
        "Forest Root" = $forestRoot
        "Domains Audited" = "$($auditDomains.Count)"
        "Groups Analyzed" = "$($groupData.Count)"
        "Total Members" = "$(($groupData | Measure-Object -Property MemberCount -Sum).Sum)"
        "Cross-Domain Groups" = "$($crossDomainGroups.Count)"
        "Audit Duration" = "$('{0:mm\:ss}' -f ([datetime]$(Get-Date) - [datetime]$auditStartTime))"
        "Command Capture" = if ($CaptureCommands) { "Enabled" } else { "Disabled" }
    }
    
    # Generate the enhanced web report
    $htmlPath = "$OutputDirectory\Forest_Audit_Report.html"
    $reportResult = New-EnhancedWebReport -AuditData $groupData -ScreenshotPaths $allScreenshots -CsvFiles $allCsvFiles -OutputPath $htmlPath -ReportTitle "Multi-Domain Forest AD Audit Report" -CompanyName $env:USERDNSDOMAIN -CustomMetadata $metadata
    
    Write-Host "Enhanced web report created: $htmlPath" -ForegroundColor Green
    Write-Host "  Report includes $($reportResult.EmbeddedImages) embedded screenshots" -ForegroundColor Cyan
    Write-Host "  Report includes $($reportResult.EmbeddedDataFiles) embedded data files" -ForegroundColor Cyan
    Write-Host "  Report file size: $([math]::Round($reportResult.FileSize / 1MB, 2)) MB" -ForegroundColor Cyan
    
    # Step 5: Send email if requested
    if ($SendEmail -and $config.EmailSettings.Recipients.Count -gt 0) {
        Write-Host "`nStep 5: Sending email report..." -ForegroundColor Yellow
        
        # Get HTML for attachment
        $attachments = @($htmlPath)
        
        if (Test-Path $htmlPath) {
            # Use Send-MailMessage or your email function
            # This is a simplified example - adjust based on your Send-AuditReport function
            Write-Host "Email would be sent to: $($config.EmailSettings.Recipients -join ', ')" -ForegroundColor Gray
            Write-Host "Attachments: $($csvFiles.Count) CSV files" -ForegroundColor Gray
        }
    }
    
    # Summary
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  Forest Audit Complete!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "`nReports saved to: $OutputDirectory" -ForegroundColor Cyan
    Write-Host "  - Enhanced Web Report: Forest_Audit_Report.html" -ForegroundColor White
    Write-Host "  - Complete self-contained report with embedded images and data" -ForegroundColor White
    Write-Host "  - Group Folders: $($groupData.Count) individual group folders with:" -ForegroundColor White
    Write-Host "    - members.csv (raw membership)" -ForegroundColor Gray
    Write-Host "    - member_details.csv (detailed info)" -ForegroundColor Gray
    Write-Host "    - transcript.log (audit log)" -ForegroundColor Gray
    Write-Host "    - screenshots (audit evidence)" -ForegroundColor Gray
    
    # Save job if requested
    if ($SaveJob) {
        $jobConfig = @{
            JobName = [System.IO.Path]::GetFileNameWithoutExtension($SaveJob)
            SavedDate = Get-Date
            ForestRootGroups = $ForestRootGroups
            AllDomains = $AllDomains
            Domains = $auditDomains
            CaptureCommands = $CaptureCommands
            SendEmail = $SendEmail
            ConfigFile = $ConfigFile
            Groups = $groupsToAudit
        }
        
        $jobConfig | ConvertTo-Json | Out-File $SaveJob -Encoding UTF8
        Write-Host "`n* Job saved to: $SaveJob" -ForegroundColor Green
    }
    
    Write-Host "`nAudit Summary:" -ForegroundColor Yellow
    Write-Host "  Domains Audited: $($auditDomains.Count)" -ForegroundColor White
    Write-Host "  Groups Analyzed: $($groupData.Count)" -ForegroundColor White
    Write-Host "  Total Members: $(($groupData | Measure-Object -Property MemberCount -Sum).Sum)" -ForegroundColor White
    Write-Host "  Cross-Domain Groups: $($crossDomainGroups.Count)" -ForegroundColor White
    
    $openReport = Read-Host "`nOpen output directory now? (Y/N)"
    if ($openReport -eq 'Y') {
        Start-Process $OutputDirectory
    }
    
} catch {
    $errorMsg = "`nERROR: $($_.Exception.Message)`nStack Trace: $($_.ScriptStackTrace)"
    
    # Display error
    Write-Host $errorMsg -ForegroundColor Red
    
    # Log error to file
    if ($logFile) {
        Write-AuditLog "CRITICAL ERROR: $($_.Exception.Message)" "ERROR"
        Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    }
    
    # Save error details
    if ($OutputDirectory) {
        $errorFile = "$OutputDirectory\ERROR_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $errorMsg | Out-File $errorFile -Encoding UTF8
        Write-Host "`nError details saved to: $errorFile" -ForegroundColor Yellow
    }
    
    Write-Host "`nLogs are saved in: $OutputDirectory" -ForegroundColor Yellow
    Write-Host "  - Transcript: forest-audit-transcript.log" -ForegroundColor Gray
    Write-Host "  - Log file: forest-audit.log" -ForegroundColor Gray
    
    # Don't prompt here - let the calling script handle it
    exit 1
} finally {
    Stop-Transcript | Out-Null
}