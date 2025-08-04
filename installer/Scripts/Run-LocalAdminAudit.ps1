<#
.SYNOPSIS
    Audits local administrator group membership on Windows servers.

.DESCRIPTION
    Performs comprehensive audit of local administrator access across specified servers.
    Supports both configuration-based server lists and command-line specified servers.
    Generates detailed reports for SOX compliance.

.PARAMETER Servers
    Array of server names to audit. Overrides configuration file.

.PARAMETER ServerGroup
    Name of server group from configuration to audit (e.g., "CriticalServers").

.PARAMETER ConfigFile
    Path to server audit configuration file. Default: .\Config\server-audit-config.json

.PARAMETER Credential
    PSCredential object for server authentication.

.PARAMETER ResolveDomainGroups
    Expand domain group memberships to show individual users.

.PARAMETER IncludeOffline
    Include offline/unreachable servers in the report.

.PARAMETER SendEmail
    Send audit report via email to configured recipients.

.PARAMETER CaptureCommands
    Capture PowerShell commands for SOX evidence. Default: $true

.PARAMETER OutputDirectory
    Directory to save audit reports. Default: .\Output\[timestamp]

.PARAMETER UploadToAuditBoard
    Upload audit results to AuditBoard platform.

.PARAMETER Job
    Path to a saved job file to load parameters from a previous run.

.PARAMETER SaveJob
    Path to save current parameters as a job file for future reuse.

.EXAMPLE
    .\Run-LocalAdminAudit.ps1 -Servers "SERVER01", "SERVER02"
    Audits specific servers.

.EXAMPLE
    .\Run-LocalAdminAudit.ps1 -ServerGroup "CriticalServers"
    Audits all servers in the CriticalServers group.

.EXAMPLE
    .\Run-LocalAdminAudit.ps1 -ConfigFile .\server-config.json -SendEmail
    Audits all configured servers and sends email report.

.EXAMPLE
    .\Run-LocalAdminAudit.ps1 -ServerGroup "CriticalServers" -SaveJob critical-audit.json
    Runs audit and saves parameters for reuse.

.NOTES
    Author: IT Security Team
    Version: 1.0
    Requires: Admin access to target servers, WinRM enabled
#>

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$Servers,
    
    [Parameter(Mandatory=$false)]
    [string]$ServerGroup,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "$PSScriptRoot\Config\server-audit-config.json",
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$ResolveDomainGroups = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeOffline,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [switch]$CaptureCommands = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\LocalAdmin_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$UploadToAuditBoard,
    
    [Parameter(Mandatory=$false)]
    [string]$AuditBoardConfig = "$PSScriptRoot\Config\auditboard-config.json",
    
    [Parameter(Mandatory=$false)]
    [string]$Job,
    
    [Parameter(Mandatory=$false)]
    [string]$SaveJob
)

$ErrorActionPreference = 'Stop'

# Import logging module
$modulePath = Split-Path $PSScriptRoot -Parent
. "$modulePath\Modules\Audit-Logging.ps1"

# Initialize logging
Initialize-AuditLog -OutputDirectory $OutputDirectory -LogName "localadmin-audit"

Write-AuditLog "===============================================" "INFO"
Write-AuditLog "Local Administrator Audit Tool" "INFO"
Write-AuditLog "===============================================" "INFO"

try {
    # Load job if specified
    if ($Job) {
        if (Test-Path $Job) {
            Write-AuditLog "Loading job configuration from: $Job" "SUCCESS"
            $jobConfig = Get-Content $Job | ConvertFrom-Json
            
            # Override parameters with job config
            if ($jobConfig.Servers) { $Servers = $jobConfig.Servers }
            if ($jobConfig.ServerGroup) { $ServerGroup = $jobConfig.ServerGroup }
            if ($jobConfig.PSObject.Properties["ResolveDomainGroups"]) { $ResolveDomainGroups = $jobConfig.ResolveDomainGroups }
            if ($jobConfig.PSObject.Properties["IncludeOffline"]) { $IncludeOffline = $jobConfig.IncludeOffline }
            if ($jobConfig.PSObject.Properties["SendEmail"]) { $SendEmail = $jobConfig.SendEmail }
            if ($jobConfig.PSObject.Properties["CaptureCommands"]) { $CaptureCommands = $jobConfig.CaptureCommands }
            if ($jobConfig.PSObject.Properties["UploadToAuditBoard"]) { $UploadToAuditBoard = $jobConfig.UploadToAuditBoard }
            if ($jobConfig.ConfigFile) { $ConfigFile = $jobConfig.ConfigFile }
        } else {
            Write-AuditLog "Job file not found: $Job" "WARNING"
        }
    }
    
    # Import modules
    Write-AuditLog "Loading audit modules..." "INFO"
    . "$modulePath\Modules\LocalAdmin-Audit.ps1"
    . "$modulePath\Modules\Send-AuditReport.ps1"
    . "$modulePath\Modules\Audit-CodeCapture.ps1"
    Write-AuditLog "Modules loaded successfully" "SUCCESS"
    
    # Load configuration
    $config = @{
        ServerAuditSettings = @{
            MaxConcurrentAudits = 10
            ResolveDomainGroups = $true
        }
        ServerGroups = @{}
        ComplianceRules = @{}
        EmailAlerts = @{}
    }
    
    if (Test-Path $ConfigFile) {
        Write-AuditLog "Loading configuration from: $ConfigFile" "SUCCESS"
        $loadedConfig = Get-Content $ConfigFile | ConvertFrom-Json
        
        # Merge configurations
        foreach ($key in $loadedConfig.PSObject.Properties.Name) {
            $config[$key] = $loadedConfig.$key
        }
    }
    
    # Determine servers to audit
    $auditServers = @()
    
    if ($Servers) {
        # Use command-line specified servers
        $auditServers = $Servers
        Write-AuditLog "Using command-line specified servers: $($Servers -join ', ')" "INFO"
    }
    elseif ($ServerGroup) {
        # Use server group from config
        if ($config.ServerGroups.PSObject.Properties[$ServerGroup]) {
            $auditServers = $config.ServerGroups.$ServerGroup.Servers
            Write-AuditLog "Using server group '$ServerGroup': $($auditServers.Count) servers" "INFO"
        } else {
            throw "Server group '$ServerGroup' not found in configuration"
        }
    }
    else {
        # Audit all configured servers
        foreach ($group in $config.ServerGroups.PSObject.Properties.Name) {
            $auditServers += $config.ServerGroups.$group.Servers
        }
        Write-AuditLog "Auditing all configured servers: $($auditServers.Count) servers" "INFO"
    }
    
    if ($auditServers.Count -eq 0) {
        throw "No servers specified for audit. Use -Servers parameter or configure server groups."
    }
    
    # Get credentials if not provided
    if (-not $Credential -and $config.ServerAuditSettings.DefaultCredential) {
        Write-AuditLog "Enter credentials for server access:" "INFO"
        $Credential = Get-Credential -Message "Enter credentials for server access"
    }
    
    # Start command evidence capture
    if ($CaptureCommands) {
        Write-AuditLog "Starting command evidence capture..." "INFO"
        Start-AuditCodeCapture -AuditName "Local Administrator Audit" -OutputPath "$OutputDirectory\CodeEvidence"
    }
    
    # Perform audit
    Write-AuditLog "`nStarting audit of $($auditServers.Count) servers..." "INFO"
    
    if ($CaptureCommands) {
        $cmd = "Get-LocalAdminAuditData -ServerList @('$($auditServers -join ""', '"")') -ResolveDomainGroups:`$$ResolveDomainGroups -IncludeOffline:`$$IncludeOffline"
        Add-AuditCommand -CommandName "Get-LocalAdminAuditData" -CommandText $cmd -Description "Auditing local administrators across servers" -CaptureScreenshot
    }
    
    $auditParams = @{
        ServerList = $auditServers
        ResolveDomainGroups = $ResolveDomainGroups
        IncludeOffline = $IncludeOffline
        MaxConcurrent = $config.ServerAuditSettings.MaxConcurrentAudits
        CaptureCommands = $CaptureCommands
    }
    
    if ($Credential) {
        $auditParams.Credential = $Credential
    }
    
    $auditData = Get-LocalAdminAuditData @auditParams
    
    Write-AuditLog "`nAudit completed:" "SUCCESS"
    Write-AuditLog "  - Servers audited: $($auditData.ServersAudited)" "INFO"
    Write-AuditLog "  - Successful: $($auditData.ServersSuccessful)" "INFO"
    Write-AuditLog "  - Failed: $($auditData.ServersFailed)" "INFO"
    Write-AuditLog "  - Total administrators found: $($auditData.TotalAdmins)" "INFO"
    Write-AuditLog "  - Compliance issues: $($auditData.ComplianceIssues.Count)" $(if ($auditData.ComplianceIssues.Count -gt 0) { "WARNING" } else { "SUCCESS" })
    
    # Generate HTML report
    Write-AuditLog "`nGenerating HTML report..." "INFO"
    $htmlPath = "$OutputDirectory\LocalAdmin_Audit_Report.html"
    
    $reportMetadata = @{
        "Audit Type" = "Local Administrator Access"
        "Server Count" = $auditServers.Count
        "Compliance Level" = if ($ServerGroup) { $config.ServerGroups.$ServerGroup.ComplianceLevel } else { "Standard" }
    }
    
    if ($CaptureCommands) {
        $cmd = "New-LocalAdminHtmlReport -AuditData `$auditData -OutputPath '$htmlPath' -CustomMetadata `$reportMetadata"
        Add-AuditCommand -CommandName "New-LocalAdminHtmlReport" -CommandText $cmd -Description "Generating HTML audit report" -CaptureScreenshot
    }
    
    New-LocalAdminHtmlReport -AuditData $auditData -OutputPath $htmlPath -CustomMetadata $reportMetadata
    
    # Export to Excel
    Write-AuditLog "Generating Excel report..." "INFO"
    $excelPath = "$OutputDirectory\LocalAdmin_Audit_$(Get-Date -Format 'yyyyMMdd').xlsx"
    
    # Create Excel workbook
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $workbook = $excel.Workbooks.Add()
    
    # Summary sheet
    $summarySheet = $workbook.Worksheets.Item(1)
    $summarySheet.Name = "Summary"
    
    $row = 1
    $summarySheet.Cells.Item($row, 1) = "Local Administrator Audit Summary"
    $summarySheet.Cells.Item($row, 1).Font.Bold = $true
    $summarySheet.Cells.Item($row, 1).Font.Size = 14
    
    $row = 3
    $summarySheet.Cells.Item($row, 1) = "Audit Date:"
    $summarySheet.Cells.Item($row, 2) = $auditData.AuditDate
    $row++
    $summarySheet.Cells.Item($row, 1) = "Servers Audited:"
    $summarySheet.Cells.Item($row, 2) = $auditData.ServersAudited
    $row++
    $summarySheet.Cells.Item($row, 1) = "Successful:"
    $summarySheet.Cells.Item($row, 2) = $auditData.ServersSuccessful
    $row++
    $summarySheet.Cells.Item($row, 1) = "Failed:"
    $summarySheet.Cells.Item($row, 2) = $auditData.ServersFailed
    $row++
    $summarySheet.Cells.Item($row, 1) = "Total Administrators:"
    $summarySheet.Cells.Item($row, 2) = $auditData.TotalAdmins
    $row++
    $summarySheet.Cells.Item($row, 1) = "Compliance Issues:"
    $summarySheet.Cells.Item($row, 2) = $auditData.ComplianceIssues.Count
    
    # Admin details sheet
    $detailSheet = $workbook.Worksheets.Add()
    $detailSheet.Name = "Administrator Details"
    
    # Headers
    $headers = @("Server", "Account Name", "Type", "Source", "Enabled", "Last Logon", "Password Last Set")
    for ($i = 0; $i -lt $headers.Count; $i++) {
        $detailSheet.Cells.Item(1, $i + 1) = $headers[$i]
        $detailSheet.Cells.Item(1, $i + 1).Font.Bold = $true
    }
    
    # Data
    $row = 2
    foreach ($admin in $auditData.Results | Sort-Object Server, Name) {
        $detailSheet.Cells.Item($row, 1) = $admin.Server
        $detailSheet.Cells.Item($row, 2) = $admin.Name
        $detailSheet.Cells.Item($row, 3) = $admin.ObjectClass
        $detailSheet.Cells.Item($row, 4) = $admin.PrincipalSource
        $detailSheet.Cells.Item($row, 5) = if ($admin.Enabled) { "Yes" } else { "No" }
        $detailSheet.Cells.Item($row, 6) = if ($admin.LastLogon) { $admin.LastLogon.ToString('yyyy-MM-dd') } else { "Never" }
        $detailSheet.Cells.Item($row, 7) = if ($admin.PasswordLastSet) { $admin.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }
        $row++
    }
    
    # Auto-fit columns
    $detailSheet.UsedRange.EntireColumn.AutoFit() | Out-Null
    $summarySheet.UsedRange.EntireColumn.AutoFit() | Out-Null
    
    # Save and close
    $workbook.SaveAs($excelPath)
    $excel.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
    
    Write-AuditLog "Excel report saved: $excelPath" "SUCCESS"
    
    # Stop code capture
    if ($CaptureCommands) {
        Write-AuditLog "Generating command evidence documentation..." "INFO"
        $codeDocs = Stop-AuditCodeCapture
    }
    
    # Send email if requested
    if ($SendEmail -and $config.EmailAlerts.AlertRecipients.Count -gt 0) {
        Write-AuditLog "Sending email report..." "INFO"
        
        $attachments = @($excelPath)
        if ($CaptureCommands -and $codeDocs) {
            $attachments += $codeDocs.HtmlPath
        }
        
        # Check for high severity issues
        $highSeverityIssues = $auditData.ComplianceIssues | Where-Object { $_.Severity -eq "High" }
        $subject = if ($highSeverityIssues) {
            "ALERT: Local Admin Audit - High Severity Issues Found"
        } else {
            "Local Admin Audit Report - $(Get-Date -Format 'MMMM yyyy')"
        }
        
        $emailResult = Send-ADComplianceReport `
            -Recipients $config.EmailAlerts.AlertRecipients `
            -Subject $subject `
            -HtmlReportPath $htmlPath `
            -Attachments $attachments `
            -SmtpServer "smtp.company.com" `
            -UseSSL
        
        if ($emailResult.Success) {
            Write-AuditLog "Email sent successfully!" "SUCCESS"
        }
    }
    
    # Upload to AuditBoard if requested
    if ($UploadToAuditBoard) {
        Write-AuditLog "`nUploading results to AuditBoard..." "INFO"
        
        try {
            . "$modulePath\Modules\AuditBoard-Integration.ps1"
            
            if (Test-Path $AuditBoardConfig) {
                $abConfig = Get-Content $AuditBoardConfig | ConvertFrom-Json
                
                # Connect to AuditBoard
                if ($abConfig.AuditBoardSettings.AuthType -eq "ApiKey") {
                    Connect-AuditBoard -BaseUrl $abConfig.AuditBoardSettings.BaseUrl `
                        -ApiKey $abConfig.AuditBoardSettings.ApiKey
                }
                
                # Prepare audit results
                $auditResults = @{
                    ServersAudited = $auditData.ServersAudited
                    TotalAdmins = $auditData.TotalAdmins
                    LocalAdmins = ($auditData.Results | Where-Object { $_.PrincipalSource -eq 'Local' }).Count
                    DomainAdmins = ($auditData.Results | Where-Object { $_.PrincipalSource -eq 'ActiveDirectory' }).Count
                    DisabledAccounts = ($auditData.Results | Where-Object { $_.Enabled -eq $false }).Count
                    ComplianceIssues = $auditData.ComplianceIssues.Count
                }
                
                # Upload files
                $uploadFiles = @($htmlPath, $excelPath)
                if ($CaptureCommands -and $codeDocs) {
                    $uploadFiles += $codeDocs.HtmlPath
                }
                
                $abRecord = Export-ADToAuditBoard -AuditResults $auditResults `
                    -ReportFiles $uploadFiles `
                    -ProjectId $abConfig.AuditTypeMappings.Local_Admin_Audit.ProjectId
                
                Write-AuditLog "Successfully uploaded to AuditBoard (Record ID: $($abRecord.id))" "SUCCESS"
            }
        } catch {
            Write-AuditLog "Failed to upload to AuditBoard: $_" "ERROR"
        }
    }
    
    # Save job if requested
    if ($SaveJob) {
        $jobConfig = @{
            JobName = [System.IO.Path]::GetFileNameWithoutExtension($SaveJob)
            SavedDate = Get-Date
            Servers = $Servers
            ServerGroup = $ServerGroup
            ResolveDomainGroups = $ResolveDomainGroups
            IncludeOffline = $IncludeOffline
            SendEmail = $SendEmail
            CaptureCommands = $CaptureCommands
            UploadToAuditBoard = $UploadToAuditBoard
            ConfigFile = $ConfigFile
        }
        
        $jobConfig | ConvertTo-Json | Out-File $SaveJob -Encoding UTF8
        Write-AuditLog "Job saved to: $SaveJob" "SUCCESS"
    }
    
    # Summary
    Write-AuditLog "`n===============================================" "SUCCESS"
    Write-AuditLog "Audit Complete!" "SUCCESS"
    Write-AuditLog "===============================================" "SUCCESS"
    Write-AuditLog "Reports saved to: $OutputDirectory" "INFO"
    Write-AuditLog "  - HTML Report: $(Split-Path $htmlPath -Leaf)" "INFO"
    Write-AuditLog "  - Excel Report: $(Split-Path $excelPath -Leaf)" "INFO"
    if ($CaptureCommands -and $codeDocs) {
        Write-AuditLog "  - Command Evidence: $(Split-Path $codeDocs.HtmlPath -Leaf)" "INFO"
    }
    
    $logs = Stop-AuditLog
    Write-Host "`nLogs saved to:" -ForegroundColor Cyan
    Write-Host "  - Audit Log: $(Split-Path $logs.LogFile -Leaf)" -ForegroundColor White
    Write-Host "  - Transcript: $(Split-Path $logs.TranscriptFile -Leaf)" -ForegroundColor White
    
    $openReport = Read-Host "`nOpen HTML report now? (Y/N)"
    if ($openReport -eq 'Y') {
        Start-Process $htmlPath
        if ($CaptureCommands -and $codeDocs) {
            Start-Process $codeDocs.HtmlPath
        }
    }
    
} catch {
    Write-AuditLog "ERROR: $($_.Exception.Message)" "ERROR"
    Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    
    # Stop code capture if error occurs
    if ($CaptureCommands) {
        Stop-AuditCodeCapture | Out-Null
    }
    
    exit 1
} finally {
    # Ensure logging is stopped
    if (Get-Command Stop-AuditLog -ErrorAction SilentlyContinue) {
        Stop-AuditLog | Out-Null
    }
}