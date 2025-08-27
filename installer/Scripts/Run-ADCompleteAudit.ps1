<#
.SYNOPSIS
    Performs a comprehensive Active Directory group audit for SOX compliance.

.DESCRIPTION
    This script automates the auditing of Active Directory security groups, collecting membership data,
    user status, and generating detailed reports in CSV (primary), HTML and Excel formats. It supports 
    screenshot capture and email delivery of audit results.

.PARAMETER ConfigFile
    Path to JSON configuration file containing audit settings. Default: .\audit-config.json

.PARAMETER Groups
    Array of AD group names to audit. Overrides groups specified in config file.

.PARAMETER SendEmail
    Send audit report via email to recipients specified in configuration.

.PARAMETER CaptureScreenshots
    Enable interactive screenshot capture during audit process.

.PARAMETER OutputDirectory
    Directory to save audit reports. Default: .\Output\[timestamp]

.PARAMETER Job
    Path to a saved job file to load parameters from a previous run.

.PARAMETER SaveJob
    Path to save current parameters as a job file for future reuse.

.PARAMETER CaptureCommands
    Capture PowerShell commands for SOX compliance evidence. Default: $true

.PARAMETER UploadToAuditBoard
    Upload audit results to AuditBoard platform.

.PARAMETER AuditBoardConfig
    Path to AuditBoard configuration file. Default: .\Config\auditboard-config.json

.EXAMPLE
    .\Run-ADCompleteAudit.ps1 -Groups "Domain Admins", "Enterprise Admins"
    Audits specific groups without using config file.

.EXAMPLE
    .\Run-ADCompleteAudit.ps1 -ConfigFile .\audit-config.json -SendEmail
    Runs audit using configuration file and sends results via email.

.EXAMPLE
    .\Run-ADCompleteAudit.ps1 -CaptureScreenshots
    Runs audit with interactive screenshot capture for documentation.

.EXAMPLE
    .\Run-ADCompleteAudit.ps1 -Groups "Domain Admins" -SendEmail -SaveJob monthly-audit.json
    Runs audit and saves parameters for future use.

.EXAMPLE
    .\Run-ADCompleteAudit.ps1 -Job monthly-audit.json
    Re-runs a previously saved audit job.

.NOTES
    Author: IT Security Team
    Version: 2.0
    Requires: Domain Admin or delegated AD read permissions
#>

# No admin rights needed for AD queries
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "$(Split-Path $PSScriptRoot -Parent)\Config\audit-config.json",
    
    [Parameter(Mandatory=$false)]
    [string[]]$Groups,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [switch]$CaptureScreenshots,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\ADGroups_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$Job,
    
    [Parameter(Mandatory=$false)]
    [string]$SaveJob,
    
    [Parameter(Mandatory=$false)]
    [switch]$CaptureCommands = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$UploadToAuditBoard,
    
    [Parameter(Mandatory=$false)]
    [string]$AuditBoardConfig = "$(Split-Path $PSScriptRoot -Parent)\Config\auditboard-config.json"
)

$ErrorActionPreference = 'Stop'

# Create output directory early
if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# Create log file
$logFile = "$OutputDirectory\audit.log"
$transcript = "$OutputDirectory\audit-transcript.log"
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
Write-AuditLog "  Active Directory SOX Compliance Audit Tool" "INFO"
Write-AuditLog "===============================================`n" "INFO"
Write-AuditLog "Output Directory: $OutputDirectory" "INFO"

try {
    # Load job if specified
    if ($Job) {
        if (Test-Path $Job) {
            Write-AuditLog "Loading job configuration from: $Job" "SUCCESS"
            $jobConfig = Get-Content $Job | ConvertFrom-Json
            
            # Override parameters with job config
            if ($jobConfig.Groups) { $Groups = $jobConfig.Groups }
            if ($jobConfig.PSObject.Properties["SendEmail"]) { $SendEmail = $jobConfig.SendEmail }
            if ($jobConfig.PSObject.Properties["CaptureScreenshots"]) { $CaptureScreenshots = $jobConfig.CaptureScreenshots }
            if ($jobConfig.PSObject.Properties["CaptureCommands"]) { $CaptureCommands = $jobConfig.CaptureCommands }
            if ($jobConfig.PSObject.Properties["UploadToAuditBoard"]) { $UploadToAuditBoard = $jobConfig.UploadToAuditBoard }
            if ($jobConfig.ConfigFile) { $ConfigFile = $jobConfig.ConfigFile }
            if ($jobConfig.OutputDirectory) { $OutputDirectory = $jobConfig.OutputDirectory }
        } else {
            Write-AuditLog "Job file not found: $Job" "WARNING"
        }
    }
    
    # Import modules (modules are in parent directory)
    $modulePath = Split-Path $PSScriptRoot -Parent
    Import-Module "$modulePath\Modules\AD-AuditModule.psm1" -Force
    . "$modulePath\Modules\AD-ScreenCapture.ps1"
    . "$modulePath\Modules\AD-ReportGenerator.ps1"
    . "$modulePath\Modules\Send-AuditReport.ps1"
    . "$modulePath\Modules\Audit-CodeCapture.ps1"
    . "$modulePath\Modules\Audit-StandardOutput.ps1"
    . "$modulePath\Modules\Audit-OutputCapture.ps1"
    
    $config = @{
        Groups = @()
        IncludeNestedGroups = $true
        IncludeDisabledUsers = $false
        EmailSettings = @{
            Recipients = @()
            SmtpServer = "smtp.company.com"
            UseSSL = $true
        }
    }
    
    if (Test-Path $ConfigFile) {
        Write-AuditLog "Loading configuration from: $ConfigFile" "SUCCESS"
        $loadedConfig = Get-Content $ConfigFile | ConvertFrom-Json
        foreach ($key in $loadedConfig.PSObject.Properties.Name) {
            $config[$key] = $loadedConfig.$key
        }
    }
    
    # Get list of groups to audit
    if ($Groups) {
        $auditGroups = $Groups
    } elseif ($config.Groups.Count -gt 0) {
        $auditGroups = $config.Groups
    } else {
        Write-AuditLog "Enter AD group names to audit (comma-separated):" "INFO"
        $input = Read-Host
        $auditGroups = $input -split ',' | ForEach-Object { $_.Trim() }
    }
    
    Write-AuditLog "`nStarting audit for groups: $($auditGroups -join ', ')" "INFO"
    
    # Initialize standardized output structure
    $outputPaths = Initialize-AuditOutput -OutputDirectory $OutputDirectory -AuditType "ADGroups"
    Start-AuditOutputCapture -OutputDirectory $OutputDirectory
    
    # Start command evidence capture
    if ($CaptureCommands) {
        Write-AuditLog "Starting command evidence capture..." "INFO"
        Start-AuditCodeCapture -AuditName "AD Group Compliance Audit" -OutputPath "$OutputDirectory\CodeEvidence"
    }
    
    Write-AuditLog "`nStep 1: Collecting AD group data..." "INFO"
    
    # Add domain information to group data
    $currentDomain = Get-ADDomain
    $forestRoot = Get-ADForest
    $isForestRoot = $currentDomain.Name -eq $forestRoot.RootDomain
    
    # Define forest-level groups that only exist in root domain
    $forestLevelGroups = @('Enterprise Admins', 'Schema Admins', 'Enterprise Key Admins')
    
    $groupData = @()
    
    foreach ($groupName in $auditGroups) {
        # Skip forest-level groups if not in root domain
        if (-not $isForestRoot -and $groupName -in $forestLevelGroups) {
            Write-AuditLog "  Skipping $groupName (only exists in forest root domain)" "WARNING"
            continue
        }
        
        Write-AuditLog "  Processing: $groupName" "INFO"
        
        try {
            # Temporarily disable code capture to avoid warnings
            $originalCaptureState = $global:AuditCodeCapture
            if ($CaptureCommands -and $originalCaptureState) {
                $global:AuditCodeCapture.IsCapturing = $false
            }
            
            $data = Get-ADGroupAuditData -GroupNames @($groupName) -IncludeNestedGroups:$config.IncludeNestedGroups -IncludeDisabledUsers:$config.IncludeDisabledUsers -CaptureCommands:$false
            
            # Re-enable code capture
            if ($CaptureCommands -and $originalCaptureState) {
                $global:AuditCodeCapture.IsCapturing = $true
                
                # Manually add the audit command
                $cmd = "Get-ADGroupAuditData -GroupNames @('$groupName') -IncludeNestedGroups:`$$($config.IncludeNestedGroups) -IncludeDisabledUsers:`$$($config.IncludeDisabledUsers)"
                Add-AuditCommand -CommandName "Get-ADGroupAuditData" -CommandText $cmd -Description "Auditing group: $groupName"
            }
        } catch {
            Write-AuditLog "  ERROR: Failed to audit $groupName - $_" "ERROR"
            continue
        }
        
        # Add domain property if missing
        foreach ($group in $data) {
            if (-not $group.PSObject.Properties["Domain"]) {
                $group | Add-Member -NotePropertyName "Domain" -NotePropertyValue $currentDomain.Name
            }
            if (-not $group.PSObject.Properties["Status"]) {
                $group | Add-Member -NotePropertyName "Status" -NotePropertyValue "Success"
            }
            if (-not $group.PSObject.Properties["ErrorDetails"]) {
                $group | Add-Member -NotePropertyName "ErrorDetails" -NotePropertyValue $null
            }
        }
        
        $groupData += $data
    }
    
    Write-AuditLog "Found $($groupData.Count) groups with $(($groupData | Measure-Object -Property MemberCount -Sum).Sum) total members" "SUCCESS"
    
    $screenshots = @()
    if ($CaptureScreenshots) {
        Write-AuditLog "`nStep 2: Capturing screenshots..." "INFO"
        Write-AuditLog "Starting interactive screenshot capture session" "INFO"
        $screenshots = Start-InteractiveADScreenCapture -SessionName "SOX_Audit" -OutputPath "$OutputDirectory\Screenshots"
    }
    
    # Step 3: Generate CSV reports (primary format)
    Write-AuditLog "`nStep 3: Generating CSV reports (primary format)..." "INFO"
    Export-StandardAuditCSV -AuditData $groupData -OutputPaths $outputPaths -DataType "Groups"
    
    # Also export individual group CSVs with evidence
    foreach ($group in $groupData) {
        $groupIdentifier = "$($group.Domain)_$($group.GroupName)" -replace '[^\w\-]', '_'
        
        # Create evidence folder
        $evidenceFolder = New-AuditEvidenceFolder -ItemIdentifier $groupIdentifier -OutputPaths $outputPaths
        
        # Export group members to CSV
        if ($group.Members.Count -gt 0) {
            $csvPath = Export-AuditItemCSV -ItemData $group -ItemIdentifier $groupIdentifier -OutputPaths $outputPaths
            Write-AuditLog "  Exported: $groupIdentifier ($($group.Members.Count) members)" "INFO"
        }
    }
    
    # Step 4: Generate Excel report (legacy format)
    Write-AuditLog "`nStep 4: Generating Excel report (legacy format)..." "INFO"
    $excelPath = "$OutputDirectory\AD_Audit_$(Get-Date -Format 'yyyyMMdd').xlsx"
    
    if ($CaptureCommands) {
        $cmd = "Export-ADGroupMembers -GroupAuditData `$groupData -OutputPath '$excelPath'"
        Add-AuditCommand -CommandName "Export-ADGroupMembers" -CommandText $cmd -Description "Exporting audit data to Excel format" -CaptureScreenshot
    }
    
    Export-ADGroupMembers -GroupAuditData $groupData -OutputPath $excelPath
    
    # Step 5: Generate enhanced web report with embedded content
    Write-AuditLog "`nStep 5: Generating enhanced web report..." "INFO"
    
    # Import the enhanced web report generator
    . "$PSScriptRoot\..\Modules\Enhanced-WebReportGenerator.ps1"
    
    # Collect all CSV files for embedding
    $csvFiles = Get-ChildItem -Path $outputPaths.CSVDirectory -Filter "*.csv" | Select-Object -ExpandProperty FullName
    
    # Prepare comprehensive metadata
    $reportMetadata = @{
        "Audit Type" = "Active Directory Complete Audit"
        "Compliance Framework" = "SOX"
        "Auditor" = $env:USERNAME
        "Groups Audited" = "$($auditGroups.Count)"
        "Total Members Found" = "$(($groupData | Measure-Object -Property MemberCount -Sum).Sum)"
        "Enabled Members" = "$(($groupData | Measure-Object -Property EnabledMemberCount -Sum).Sum)"
        "Disabled Members" = "$(($groupData | Measure-Object -Property DisabledMemberCount -Sum).Sum)"
        "Domain" = $env:USERDNSDOMAIN
        "Command Capture" = if ($CaptureCommands) { "Enabled" } else { "Disabled" }
    }
    
    # Generate the enhanced web report
    $htmlPath = "$($outputPaths.HTMLDirectory)\AD_Complete_Audit_Report_$(Get-Date -Format 'yyyyMMdd').html"
    
    if ($CaptureCommands) {
        $cmd = "New-EnhancedWebReport -AuditData `$groupData -ScreenshotPaths `$screenshots -CsvFiles `$csvFiles -OutputPath '$htmlPath' -ReportTitle 'AD Complete Audit Report' -CompanyName `$env:USERDNSDOMAIN -CustomMetadata `$reportMetadata"
        Add-AuditCommand -CommandName "New-EnhancedWebReport" -CommandText $cmd -Description "Generating enhanced web audit report with embedded content" -CaptureScreenshot
    }
    
    $reportResult = New-EnhancedWebReport -AuditData $groupData -ScreenshotPaths $screenshots -CsvFiles $csvFiles -OutputPath $htmlPath -ReportTitle "Active Directory Complete Audit Report" -CompanyName $env:USERDNSDOMAIN -CustomMetadata $reportMetadata
    
    Write-AuditLog "Enhanced web report created: $htmlPath" "SUCCESS"
    Write-AuditLog "Report includes $($reportResult.EmbeddedImages) embedded screenshots and $($reportResult.EmbeddedDataFiles) data files" "INFO"
    
    # Stop code capture and generate documentation
    if ($CaptureCommands) {
        Write-AuditLog "Generating command evidence documentation..." "INFO"
        $codeDocs = Stop-AuditCodeCapture
    }
    
    if ($SendEmail -and $config.EmailSettings.Recipients.Count -gt 0) {
        Write-AuditLog "Sending email report..." "INFO"
        
        # Include CSV files as primary attachments
        $csvFiles = Get-ChildItem -Path $outputPaths.CSVDirectory -Filter "00_*.csv"
        $attachments = @($csvFiles.FullName)
        
        # Also include Excel for compatibility
        $attachments += $excelPath
        
        if ($screenshots) {
            $screenshotZip = "$OutputDirectory\Screenshots.zip"
            Compress-Archive -Path "$OutputDirectory\Screenshots\*" -DestinationPath $screenshotZip -Force
            $attachments += $screenshotZip
        }
        if ($CaptureCommands -and $codeDocs) {
            $attachments += $codeDocs.HtmlPath
        }
        
        $emailResult = Send-ADComplianceReport `
            -Recipients $config.EmailSettings.Recipients `
            -Subject "SOX AD Audit Report - $(Get-Date -Format 'MMMM yyyy')" `
            -HtmlReportPath $htmlPath `
            -Attachments $attachments `
            -SmtpServer $config.EmailSettings.SmtpServer `
            -UseSSL:$config.EmailSettings.UseSSL
        
        if ($emailResult.Success) {
            Write-AuditLog "Email sent successfully!" "SUCCESS"
        }
    }
    
    # Save job if requested
    if ($SaveJob) {
        $jobConfig = @{
            JobName = [System.IO.Path]::GetFileNameWithoutExtension($SaveJob)
            SavedDate = Get-Date
            Groups = $auditGroups
            ConfigFile = $ConfigFile
            SendEmail = $SendEmail
            CaptureScreenshots = $CaptureScreenshots
            CaptureCommands = $CaptureCommands
            UploadToAuditBoard = $UploadToAuditBoard
            OutputDirectory = $null  # Don't save output directory
        }
        
        $jobConfig | ConvertTo-Json | Out-File $SaveJob -Encoding UTF8
        Write-AuditLog "Job saved to: $SaveJob" "SUCCESS"
    }
    
    Write-AuditLog "`n===============================================" "SUCCESS"
    Write-AuditLog "  Audit Complete!" "SUCCESS"
    Write-AuditLog "===============================================" "SUCCESS"
    
    # Show standardized output summary
    Complete-AuditOutput -OutputPaths $outputPaths -HTMLReportPath $htmlPath
    
    # Also show legacy formats
    Write-AuditLog "`nLegacy Formats:" "INFO"
    Write-AuditLog "  - Excel Report: $(Split-Path $excelPath -Leaf)" "INFO"
    if ($screenshots) {
        Write-AuditLog "  - Screenshots: $($screenshots.Count) captured" "INFO"
    }
    if ($CaptureCommands -and $codeDocs) {
        Write-AuditLog "  - Command Evidence: $(Split-Path $codeDocs.HtmlPath -Leaf)" "INFO"
    }
    
    # Upload to AuditBoard if requested
    if ($UploadToAuditBoard) {
        Write-AuditLog "`nUploading results to AuditBoard..." "INFO"
        
        try {
            # Load AuditBoard module
            . "$modulePath\Modules\AuditBoard-Integration.ps1"
            
            # Load AuditBoard config
            if (Test-Path $AuditBoardConfig) {
                $abConfig = Get-Content $AuditBoardConfig | ConvertFrom-Json
                
                # Connect to AuditBoard
                if ($abConfig.AuditBoardSettings.AuthType -eq "ApiKey") {
                    Connect-AuditBoard -BaseUrl $abConfig.AuditBoardSettings.BaseUrl `
                        -ApiKey $abConfig.AuditBoardSettings.ApiKey
                } else {
                    Write-AuditLog "OAuth authentication not implemented in this example" "WARNING"
                }
                
                # Prepare audit results
                $auditResults = @{
                    GroupsAudited = $groupData.Count
                    TotalMembers = ($groupData | Measure-Object -Property MemberCount -Sum).Sum
                    DisabledUsersWithAccess = ($groupData.Members | Where-Object {$_.Enabled -eq $false}).Count
                    ExpiredPasswords = ($groupData.Members | Where-Object {$_.PasswordExpired -eq $true}).Count
                    InactiveUsers = ($groupData.Members | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}).Count
                    CrossDomainMembers = ($groupData | Where-Object {$_.CrossDomainMembers -gt 0}).Count
                    ComplianceIssues = 0
                }
                
                # Determine files to upload - include CSV files
                $uploadFiles = @()
                $uploadFiles += (Get-ChildItem -Path $outputPaths.CSVDirectory -Filter "00_*.csv").FullName
                $uploadFiles += @($htmlPath, $excelPath)
                if ($CaptureCommands -and $codeDocs) {
                    $uploadFiles += $codeDocs.HtmlPath
                }
                
                # Upload to AuditBoard
                $abRecord = Export-ADToAuditBoard -AuditResults $auditResults `
                    -ReportFiles $uploadFiles `
                    -ProjectId $abConfig.AuditTypeMappings.AD_Group_Audit.ProjectId
                
                Write-AuditLog "Successfully uploaded to AuditBoard (Record ID: $($abRecord.id))" "SUCCESS"
            } else {
                Write-AuditLog "AuditBoard config not found: $AuditBoardConfig" "WARNING"
            }
        } catch {
            Write-AuditLog "Failed to upload to AuditBoard: $_" "ERROR"
        }
    }
    
    Write-AuditLog "Audit log saved to: $logFile" "INFO"
    
    $openReport = Read-Host "`nOpen output directory? (Y/N)"
    if ($openReport -eq 'Y') {
        Start-Process $OutputDirectory
    }
    
} catch {
    Write-AuditLog "ERROR: $($_.Exception.Message)" "ERROR"
    Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    
    # Stop code capture if error occurs
    if ($CaptureCommands) {
        try {
            Stop-AuditCodeCapture | Out-Null
        } catch {
            # Ignore errors during cleanup
        }
    }
    
    exit 1
} finally {
    # Stop transcript
    Stop-Transcript | Out-Null
}