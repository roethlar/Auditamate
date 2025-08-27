<#
.SYNOPSIS
    Validates user terminations between Workday and Active Directory/Azure AD.

.DESCRIPTION
    Compares terminated users from Workday HR system with their account status in Active Directory
    and Azure AD/Entra ID. Identifies compliance issues where accounts remain active after the
    termination date, supporting SOX compliance requirements.

.PARAMETER WorkdayTenant
    URL of your Workday tenant API endpoint.

.PARAMETER WorkdayCredential
    PSCredential object for Workday API authentication.

.PARAMETER DaysBack
    Number of days to look back for terminations. Default: 30

.PARAMETER CheckAzureAD
    Include Azure AD/Entra ID account status in validation.

.PARAMETER OutputPath
    Path for HTML compliance report. Default: .\Output\Termination_Audit_[timestamp].html

.EXAMPLE
    .\Run-TerminationAudit.ps1 -WorkdayTenant "https://wd.company.com" -DaysBack 30
    Checks terminations from last 30 days against AD.

.EXAMPLE
    .\Run-TerminationAudit.ps1 -CheckAzureAD -DaysBack 90
    Validates 90 days of terminations including Azure AD status.

.NOTES
    Author: IT Security Team
    Version: 1.0
    Requires: Workday API access, AD read permissions
#>

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$WorkdayTenant,
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$WorkdayCredential,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$CheckAzureAD,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\Termination_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

Write-Host "`n=== User Termination Compliance Audit ===" -ForegroundColor Cyan
Write-Host "Checking terminations from last $DaysBack days`n" -ForegroundColor Yellow

try {
    # Import required modules
    $modulePath = Split-Path $PSScriptRoot -Parent
    . "$modulePath\Modules\Workday-Integration.ps1"
    . "$modulePath\Modules\Audit-StandardOutput.ps1"
    
    # Get Workday credentials if not provided
    if (!$WorkdayCredential) {
        Write-Host "Enter Workday API credentials:" -ForegroundColor Yellow
        $WorkdayCredential = Get-Credential -Message "Enter Workday Integration User credentials"
    }
    
    if (!$WorkdayTenant) {
        $WorkdayTenant = Read-Host "Enter Workday tenant URL (e.g., https://wd2-impl-services1.workday.com/ccx/service/tenantname)"
    }
    
    # Step 1: Get terminated users from Workday
    Write-Host "Retrieving terminated users from Workday..." -ForegroundColor Yellow
    $startDate = (Get-Date).AddDays(-$DaysBack)
    $terminatedUsers = Get-WorkdayTerminatedUsers -TenantUrl $WorkdayTenant -Credential $WorkdayCredential -StartDate $startDate
    
    Write-Host "Found $($terminatedUsers.Count) terminations in the last $DaysBack days" -ForegroundColor Green
    
    if ($terminatedUsers.Count -eq 0) {
        Write-Host "No terminations found in the specified period." -ForegroundColor Yellow
        return
    }
    
    # Step 2: Check AD/Azure AD compliance
    Write-Host "`nChecking AD account status for terminated users..." -ForegroundColor Yellow
    $complianceResults = Compare-WorkdayADTerminations -WorkdayTerminations $terminatedUsers -CheckAzureAD:$CheckAzureAD
    
    # Display summary
    $compliant = ($complianceResults | Where-Object {$_.ComplianceStatus -eq 'Compliant'}).Count
    $nonCompliant = ($complianceResults | Where-Object {$_.ComplianceStatus -eq 'Non-Compliant'}).Count
    
    Write-Host "`nCompliance Summary:" -ForegroundColor Cyan
    Write-Host "  Compliant: $compliant" -ForegroundColor Green
    Write-Host "  Non-Compliant: $nonCompliant" -ForegroundColor Red
    
    # Show non-compliant accounts
    if ($nonCompliant -gt 0) {
        Write-Host "`nNon-Compliant Accounts:" -ForegroundColor Red
        $complianceResults | Where-Object {$_.ComplianceStatus -eq 'Non-Compliant'} | ForEach-Object {
            Write-Host "  - $($_.Name) ($($_.Email)): $($_.Issues -join ', ')" -ForegroundColor Yellow
        }
    }
    
    # Step 3: Generate reports
    Write-Host "`nGenerating compliance reports..." -ForegroundColor Yellow
    
    # Create output directory
    if (!(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    # Detailed compliance results CSV
    $detailPath = "$OutputDirectory\termination_compliance_details.csv"
    $complianceResults | Export-Csv -Path $detailPath -NoTypeInformation
    Write-Host "Detailed CSV saved: $detailPath" -ForegroundColor Green
    
    # Non-compliant accounts CSV (if any)
    $nonCompliantAccounts = $complianceResults | Where-Object { $_.ComplianceStatus -eq 'Non-Compliant' }
    if ($nonCompliantAccounts.Count -gt 0) {
        $nonCompliantPath = "$OutputDirectory\non_compliant_accounts.csv"
        $nonCompliantAccounts | Export-Csv -Path $nonCompliantPath -NoTypeInformation
        Write-Host "Non-compliant accounts CSV: $nonCompliantPath" -ForegroundColor Yellow
    }
    
    # Generate enhanced web report with embedded content
    Write-Host "`nGenerating enhanced web report..." -ForegroundColor Yellow
    
    # Import the enhanced web report generator
    . "$PSScriptRoot\..\Modules\Enhanced-WebReportGenerator.ps1"
    
    # Collect all CSV files for embedding
    $csvFiles = Get-ChildItem -Path $OutputDirectory -Filter "*.csv" | Select-Object -ExpandProperty FullName
    
    # Collect any screenshots (if available)
    $screenshots = @()
    if (Test-Path "$OutputDirectory\Screenshots") {
        $screenshots = Get-ChildItem -Path "$OutputDirectory\Screenshots" -Filter "*.png" | Select-Object -ExpandProperty FullName
    }
    
    # Prepare comprehensive metadata
    $reportMetadata = @{
        "Audit Type" = "Employee Termination Audit"
        "Compliance Framework" = "SOX / IT Governance"
        "User Audited" = $Username
        "Access Reviews" = "$($complianceResults.AccessReviews.Count)"
        "Compliance Issues" = "$($complianceResults.ComplianceIssues.Count)"
        "Critical Findings" = "$(($complianceResults.ComplianceIssues | Where-Object { $_.Severity -eq 'Critical' }).Count)"
        "System Coverage" = "$($complianceResults.SystemsCovered.Count) systems"
        "Auditor" = $env:USERNAME
        "Remediation Required" = if ($complianceResults.ComplianceIssues.Count -gt 0) { "YES" } else { "NO" }
    }
    
    # Generate the enhanced web report
    $htmlPath = "$OutputDirectory\Termination_Audit_Report.html"
    $reportResult = New-EnhancedWebReport -AuditData $complianceResults.AccessReviews -ScreenshotPaths $screenshots -CsvFiles $csvFiles -OutputPath $htmlPath -ReportTitle "Employee Termination Audit Report" -CompanyName $env:USERDNSDOMAIN -CustomMetadata $reportMetadata
    
    Write-Host "Enhanced termination audit report created: $htmlPath" -ForegroundColor Green
    Write-Host "Report includes $($reportResult.EmbeddedDataFiles) embedded data files" -ForegroundColor Cyan
    
    # Display summary using standardized output
    Show-AuditSummary -AuditType "Termination Compliance" -OutputDirectory $OutputDirectory
    
    # Open report
    $openReport = Read-Host "`nOpen output directory now? (Y/N)"
    if ($openReport -eq 'Y') {
        Start-Process $OutputDirectory
    }
    
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}