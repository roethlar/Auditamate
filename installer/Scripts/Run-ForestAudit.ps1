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
    [string]$ConfigFile = "$PSScriptRoot\Config\audit-config.json",
    
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
    [string]$OutputDirectory = "$PSScriptRoot\Output\Forest_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$Job,
    
    [Parameter(Mandatory=$false)]
    [string]$SaveJob
)

$ErrorActionPreference = 'Stop'

# Start logging
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
    
    # Import modules
    Import-Module "$PSScriptRoot\Modules\AD-AuditModule.psm1" -Force
    . "$PSScriptRoot\Modules\AD-MultiDomainAudit.ps1"
    . "$PSScriptRoot\Modules\AD-ReportGenerator.ps1"
    . "$PSScriptRoot\Modules\Send-AuditReport.ps1"
    . "$PSScriptRoot\Modules\Audit-CodeCapture.ps1"
    
    # Start code capture
    if ($CaptureCommands) {
        Write-Host "Starting command evidence capture..." -ForegroundColor Yellow
        Start-AuditCodeCapture -AuditName "Multi-Domain Forest AD Audit" -OutputPath "$OutputDirectory\CodeEvidence"
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
    if ($CaptureCommands) {
        $cmd = "Get-ADForestPrivilegedGroups"
        Add-AuditCommand -CommandName "Get-ForestPrivilegedGroups" -CommandText $cmd -Description "Retrieving all privileged groups across the forest" -CaptureScreenshot
    }
    
    $privilegedGroups = Get-ADForestPrivilegedGroups
    Write-Host "Found $($privilegedGroups.Count) privileged groups across all domains" -ForegroundColor Green
    
    # Display summary
    $forestGroups = $privilegedGroups | Where-Object { $_.Scope -eq "Forest" }
    $domainGroups = $privilegedGroups | Where-Object { $_.Scope -eq "Domain" }
    Write-Host "  Forest-level groups: $($forestGroups.Count)" -ForegroundColor Gray
    Write-Host "  Domain-level groups: $($domainGroups.Count)" -ForegroundColor Gray
    
    # Step 2: Collect group data
    Write-Host "`nStep 2: Collecting detailed group membership data..." -ForegroundColor Yellow
    
    # Get groups to audit
    $groupsToAudit = $config.Groups
    if ($config.MultiDomainSettings.IncludeForestRootGroups) {
        $groupsToAudit = $groupsToAudit + @("Enterprise Admins", "Schema Admins") | Select-Object -Unique
    }
    
    if ($CaptureCommands) {
        $cmd = "Get-ADGroupAuditDataMultiDomain -GroupNames @('$($groupsToAudit -join "', '")') -Domains @('$($auditDomains -join "', '")') -IncludeForestRootGroups -ResolveForeignSecurityPrincipals"
        Add-AuditCommand -CommandName "Get-MultiDomainGroupData" -CommandText $cmd -Description "Retrieving group memberships across multiple domains" -CaptureScreenshot
    }
    
    $groupData = Get-ADGroupAuditDataMultiDomain `
        -GroupNames $groupsToAudit `
        -Domains $auditDomains `
        -IncludeForestRootGroups:$config.MultiDomainSettings.IncludeForestRootGroups `
        -IncludeNestedGroups:$config.IncludeNestedGroups `
        -ResolveForeignSecurityPrincipals:$config.MultiDomainSettings.ResolveForeignSecurityPrincipals `
        -CaptureCommands:$CaptureCommands
    
    Write-Host "Collected data for $($groupData.Count) groups" -ForegroundColor Green
    
    # Display cross-domain membership summary
    $crossDomainGroups = $groupData | Where-Object { $_.CrossDomainMembers -gt 0 }
    if ($crossDomainGroups) {
        Write-Host "`nCross-domain memberships detected:" -ForegroundColor Yellow
        foreach ($group in $crossDomainGroups) {
            Write-Host "  $($group.GroupName) ($($group.Domain)): $($group.CrossDomainMembers) cross-domain members" -ForegroundColor White
        }
    }
    
    # Step 3: Generate Excel report
    Write-Host "`nStep 3: Generating Excel report..." -ForegroundColor Yellow
    $excelPath = "$OutputDirectory\Forest_AD_Audit_$(Get-Date -Format 'yyyyMMdd').xlsx"
    Export-ADGroupMembers -GroupAuditData $groupData -OutputPath $excelPath
    
    # Step 4: Generate HTML report
    Write-Host "`nStep 4: Generating HTML report..." -ForegroundColor Yellow
    $htmlPath = "$OutputDirectory\Forest_AD_Audit_Report_$(Get-Date -Format 'yyyyMMdd').html"
    
    # Add forest-specific metadata
    $reportMetadata = @{
        "Audit Type" = "Multi-Domain Forest Audit"
        "Forest Root" = ($forestDomains | Where-Object { $_.IsRoot }).Name
        "Domains Audited" = $auditDomains.Count
        "Cross-Domain Groups" = $crossDomainGroups.Count
        "Total Groups" = $groupData.Count
        "Total Members" = ($groupData | Measure-Object -Property MemberCount -Sum).Sum
    }
    
    New-ADHtmlReport -GroupAuditData $groupData -OutputPath $htmlPath -CustomMetadata $reportMetadata -ReportTitle "Multi-Domain Forest Security Audit"
    
    # Step 5: Stop code capture
    if ($CaptureCommands) {
        Write-Host "`nStep 5: Generating command evidence documentation..." -ForegroundColor Yellow
        $codeDocs = Stop-AuditCodeCapture
    }
    
    # Step 6: Send email if requested
    if ($SendEmail -and $config.EmailSettings.Recipients.Count -gt 0) {
        Write-Host "`nStep 6: Sending email report..." -ForegroundColor Yellow
        
        $attachments = @($excelPath)
        if ($CaptureCommands -and $codeDocs) {
            $attachments += $codeDocs.HtmlPath
        }
        
        $emailResult = Send-ADComplianceReport `
            -Recipients $config.EmailSettings.Recipients `
            -Subject "Multi-Domain Forest AD Audit - $(Get-Date -Format 'MMMM yyyy')" `
            -HtmlReportPath $htmlPath `
            -Attachments $attachments `
            -SmtpServer $config.EmailSettings.SmtpServer `
            -UseSSL:$config.EmailSettings.UseSSL
    }
    
    # Summary
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  Forest Audit Complete!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "`nReports saved to: $OutputDirectory" -ForegroundColor Cyan
    Write-Host "  - HTML Report: $(Split-Path $htmlPath -Leaf)" -ForegroundColor White
    Write-Host "  - Excel Report: $(Split-Path $excelPath -Leaf)" -ForegroundColor White
    if ($CaptureCommands) {
        Write-Host "  - Command Evidence: $(Split-Path $codeDocs.HtmlPath -Leaf)" -ForegroundColor White
    }
    
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
        Write-Host "`n*" Job saved to: $SaveJob" -ForegroundColor Green
    }
    
    Write-Host "`nAudit Summary:" -ForegroundColor Yellow
    Write-Host "  Domains Audited: $($auditDomains.Count)" -ForegroundColor White
    Write-Host "  Groups Analyzed: $($groupData.Count)" -ForegroundColor White
    Write-Host "  Total Members: $(($groupData | Measure-Object -Property MemberCount -Sum).Sum)" -ForegroundColor White
    Write-Host "  Cross-Domain Groups: $($crossDomainGroups.Count)" -ForegroundColor White
    
    $openReport = Read-Host "`nOpen HTML report now? (Y/N)"
    if ($openReport -eq 'Y') {
        Start-Process $htmlPath
    }
    
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    
    # Stop code capture if error occurs
    if ($CaptureCommands) {
        Stop-AuditCodeCapture | Out-Null
    }
    
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
