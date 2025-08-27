<#
.SYNOPSIS
    Comprehensive Sarbanes-Oxley (SOX) compliance audit for financial controls and IT governance.

.DESCRIPTION
    Performs SOX compliance audits focused on IT controls, access management, and financial
    system security. Covers key SOX sections 302, 404, and 906 requirements for IT controls.

.PARAMETER Section
    Specific SOX section to audit (302, 404, 906)

.PARAMETER Complete
    Run complete SOX audit covering all sections

.PARAMETER OutputDirectory
    Directory for audit reports (default: timestamped folder)

.PARAMETER SendEmail
    Send audit report via email

.EXAMPLE
    .\Run-SOXAudit.ps1 -Section 404
    Audit SOX Section 404 internal controls

.EXAMPLE
    .\Run-SOXAudit.ps1 -Complete
    Run complete SOX compliance audit

.NOTES
    SOX IT Controls Focus Areas:
    - Access Management and Segregation of Duties
    - Change Management and Version Control
    - Data Integrity and Security
    - System Availability and Business Continuity
    - Financial Application Controls
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("302", "404", "906")]
    [string]$Section,
    
    [Parameter(Mandatory=$false)]
    [switch]$Complete,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\SOX_Audit_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail
)

$ErrorActionPreference = 'Stop'

# Create output directory
if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$logFile = "$OutputDirectory\sox-audit.log"
$transcript = "$OutputDirectory\sox-audit-transcript.log"
Start-Transcript -Path $transcript -Force

function Write-SOXLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "COMPLIANCE" { Write-Host $Message -ForegroundColor Magenta }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Test-SOXSection302 {
    Write-SOXLog "`n=== SOX Section 302: Management Certification ===" "COMPLIANCE"
    Write-SOXLog "Auditing controls for management certification of financial reports" "INFO"
    
    $results = @()
    
    # 1. Financial System Administrator Access
    Write-SOXLog "Checking financial system administrator access..." "INFO"
    $financialAdmins = @(
        "Domain Admins",
        "adi_server_admins",
        "WW_NT_DBA",
        "CORPIS_TIER2_MSSQLDBA",
        "HPE_AMS_SERVER_ADMINS",
        "ADMINISTRATORS",
        "ENTERPRISE_ADMINS",
        "SAP Administrators",
        "Oracle Administrators", 
        "Finance System Admins",
        "ERP Administrators",
        "QuickBooks Administrators"
    )
    
    foreach ($group in $financialAdmins) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-302-001"
                    Description = "Financial System Administrator Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "HIGH"
                    Requirement = "Limit administrative access to financial systems"
                }
                Write-SOXLog "Found $($members.Count) members in $group" "WARNING"
            }
        } catch {
            $results += @{
                Control = "SOX-302-001"
                Description = "Financial System Administrator Access: $group"
                Status = "NOT_FOUND"
                MemberCount = 0
                Members = "Group not found"
                RiskLevel = "INFO"
                Requirement = "Limit administrative access to financial systems"
            }
        }
    }
    
    # 2. Segregation of Duties - Finance vs IT
    Write-SOXLog "Checking segregation of duties between Finance and IT..." "INFO"
    $financeGroups = @("Finance Users", "Accounting", "Financial Analysts", "Controllers")
    $itGroups = @("Domain Admins", "adi_server_admins", "HPE_AMS_SERVER_ADMINS", "SERVER OPERATORS", "Server Operators", "IT Administrators", "ADMINISTRATORS")
    
    foreach ($finGroup in $financeGroups) {
        try {
            $finMembers = Get-ADGroupMember -Identity $finGroup -ErrorAction SilentlyContinue
            if ($finMembers) {
                foreach ($itGroup in $itGroups) {
                    try {
                        $itMembers = Get-ADGroupMember -Identity $itGroup -ErrorAction SilentlyContinue
                        $overlap = $finMembers | Where-Object { $_.SamAccountName -in $itMembers.SamAccountName }
                        
                        if ($overlap) {
                            $results += @{
                                Control = "SOX-302-002"
                                Description = "Segregation of Duties Violation: $finGroup + $itGroup"
                                Status = "VIOLATION"
                                MemberCount = $overlap.Count
                                Members = ($overlap.Name -join "; ")
                                RiskLevel = "CRITICAL"
                                Requirement = "Segregate finance and IT administrative duties"
                            }
                            Write-SOXLog "VIOLATION: $($overlap.Count) users have both finance and IT access" "ERROR"
                        }
                    } catch { }
                }
            }
        } catch { }
    }
    
    # 3. Financial Application Database Access
    Write-SOXLog "Checking direct database access to financial systems..." "INFO"
    $dbGroups = @(
        "WW_NT_DBA",
        "CORPIS_TIER2_MSSQLDBA",
        "SQL Server Administrators",
        "Database Administrators", 
        "Oracle DBA",
        "Finance Database Users"
    )
    
    foreach ($group in $dbGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-302-003"
                    Description = "Financial Database Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "HIGH"
                    Requirement = "Restrict direct database access to financial data"
                }
            }
        } catch { }
    }
    
    return $results
}

function Test-SOXSection404 {
    Write-SOXLog "`n=== SOX Section 404: Internal Controls Assessment ===" "COMPLIANCE"
    Write-SOXLog "Auditing internal controls over financial reporting" "INFO"
    
    $results = @()
    
    # 1. Change Management Controls
    Write-SOXLog "Checking change management controls..." "INFO"
    $changeGroups = @(
        "Change Managers",
        "Release Managers", 
        "Production Deployment",
        "Code Deployment"
    )
    
    foreach ($group in $changeGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-404-001"
                    Description = "Change Management Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "MEDIUM"
                    Requirement = "Documented change management process"
                }
            }
        } catch { }
    }
    
    # 2. Production System Access
    Write-SOXLog "Checking production system access controls..." "INFO"
    $prodGroups = @(
        "Production Administrators",
        "Production Support",
        "Financial System Production",
        "ERP Production Access"
    )
    
    foreach ($group in $prodGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-404-002"
                    Description = "Production System Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "HIGH"
                    Requirement = "Limit production access with approval process"
                }
            }
        } catch { }
    }
    
    # 3. Financial Reporting System Access
    Write-SOXLog "Checking financial reporting system access..." "INFO"
    $reportGroups = @(
        "Financial Reporting",
        "Business Intelligence",
        "Finance Analysts",
        "CFO Direct Reports"
    )
    
    foreach ($group in $reportGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-404-003"
                    Description = "Financial Reporting Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "MEDIUM"
                    Requirement = "Role-based access to financial reporting"
                }
            }
        } catch { }
    }
    
    # 4. Backup and Recovery Access
    Write-SOXLog "Checking backup and recovery controls..." "INFO"
    $backupGroups = @(
        "Backup Operators",
        "Backup Administrators",
        "Disaster Recovery Team"
    )
    
    foreach ($group in $backupGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-404-004"
                    Description = "Backup and Recovery Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "MEDIUM"
                    Requirement = "Secured backup access with data integrity controls"
                }
            }
        } catch { }
    }
    
    return $results
}

function Test-SOXSection906 {
    Write-SOXLog "`n=== SOX Section 906: CEO/CFO Certification ===" "COMPLIANCE"
    Write-SOXLog "Auditing executive access and certification controls" "INFO"
    
    $results = @()
    
    # 1. Executive Level Access
    Write-SOXLog "Checking executive level system access..." "INFO"
    $execGroups = @(
        "CEO Direct Reports",
        "CFO Direct Reports", 
        "Executive Team",
        "C-Level Executives",
        "Board of Directors"
    )
    
    foreach ($group in $execGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-906-001"
                    Description = "Executive Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "HIGH"
                    Requirement = "Executive access must be logged and monitored"
                }
            }
        } catch { }
    }
    
    # 2. Financial Disclosure Access
    Write-SOXLog "Checking financial disclosure system access..." "INFO"
    $disclosureGroups = @(
        "SEC Reporting",
        "Financial Disclosure",
        "Investor Relations",
        "External Auditor Access"
    )
    
    foreach ($group in $disclosureGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            if ($members) {
                $results += @{
                    Control = "SOX-906-002"
                    Description = "Financial Disclosure Access: $group"
                    Status = "FOUND"
                    MemberCount = $members.Count
                    Members = ($members.Name -join "; ")
                    RiskLevel = "CRITICAL"
                    Requirement = "Disclosure access requires executive approval"
                }
            }
        } catch { }
    }
    
    return $results
}

try {
    Write-SOXLog "`n===============================================" "INFO"
    Write-SOXLog "  SOX COMPLIANCE AUDIT TOOL" "INFO"
    Write-SOXLog "===============================================`n" "INFO"
    Write-SOXLog "Output Directory: $OutputDirectory" "INFO"
    
    # Import required modules
    $modulePath = Split-Path $PSScriptRoot -Parent
    Import-Module "$modulePath\Modules\AD-AuditModule-Secure.psm1" -Force
    
    $allResults = @()
    
    # Determine which sections to audit
    if ($Complete) {
        Write-SOXLog "Running complete SOX compliance audit..." "COMPLIANCE"
        $allResults += Test-SOXSection302
        $allResults += Test-SOXSection404
        $allResults += Test-SOXSection906
    } elseif ($Section) {
        Write-SOXLog "Running SOX Section $Section audit..." "COMPLIANCE"
        switch ($Section) {
            "302" { $allResults += Test-SOXSection302 }
            "404" { $allResults += Test-SOXSection404 }
            "906" { $allResults += Test-SOXSection906 }
        }
    } else {
        Write-SOXLog "No section specified. Use -Section or -Complete parameter." "ERROR"
        exit 1
    }
    
    # Generate CSV report
    Write-SOXLog "`nGenerating SOX compliance report..." "INFO"
    $csvPath = "$OutputDirectory\sox_compliance_report.csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation
    
    # Generate enhanced web report with embedded content
    Write-SOXLog "`nGenerating enhanced SOX compliance report..." "INFO"
    
    # Import the enhanced web report generator
    . "$PSScriptRoot\..\Modules\Enhanced-WebReportGenerator.ps1"
    
    # Collect all CSV files for embedding
    $csvFiles = @($csvPath)
    
    # Collect any screenshots (if available)
    $screenshots = @()
    if (Test-Path "$OutputDirectory\Screenshots") {
        $screenshots = Get-ChildItem -Path "$OutputDirectory\Screenshots" -Filter "*.png" | Select-Object -ExpandProperty FullName
    }
    
    # Prepare comprehensive metadata
    $criticalCount = ($allResults | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highCount = ($allResults | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumCount = ($allResults | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    
    $reportMetadata = @{
        "Audit Type" = "SOX Compliance Audit"
        "Compliance Framework" = "Sarbanes-Oxley Act"
        "Audit Scope" = if ($Complete) { "Complete SOX Audit" } else { "SOX Section $Section" }
        "Total Controls Assessed" = "$($allResults.Count)"
        "Critical Findings" = "$criticalCount"
        "High Risk Findings" = "$highCount"  
        "Medium Risk Findings" = "$mediumCount"
        "Compliance Status" = if ($criticalCount -eq 0 -and $highCount -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        "Auditor" = $env:USERNAME
        "Legal Review Required" = if ($criticalCount -gt 0) { "YES" } else { "NO" }
    }
    
    # Generate the enhanced web report
    $htmlPath = "$OutputDirectory\SOX_Compliance_Report.html"
    $reportResult = New-EnhancedWebReport -AuditData $allResults -ScreenshotPaths $screenshots -CsvFiles $csvFiles -OutputPath $htmlPath -ReportTitle "SOX Compliance Audit Report" -CompanyName $env:USERDNSDOMAIN -CustomMetadata $reportMetadata
    
    Write-SOXLog "Enhanced SOX compliance report created: $htmlPath" "SUCCESS"
    Write-SOXLog "Report includes $($reportResult.EmbeddedDataFiles) embedded data files" "INFO"
    
    # Summary
    Write-SOXLog "`n===============================================" "SUCCESS"
    Write-SOXLog "  SOX COMPLIANCE AUDIT COMPLETE!" "SUCCESS"
    Write-SOXLog "===============================================" "SUCCESS"
    Write-SOXLog "`nReports saved to: $OutputDirectory" "INFO"
    Write-SOXLog "  - CSV Report: sox_compliance_report.csv" "INFO"
    Write-SOXLog "  - HTML Summary: sox_compliance_summary.html" "INFO"
    
    # Display summary statistics
    $criticalCount = ($allResults | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highCount = ($allResults | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumCount = ($allResults | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    
    Write-SOXLog "`nCompliance Summary:" "COMPLIANCE"
    Write-SOXLog "  Total Controls Assessed: $($allResults.Count)" "INFO"
    Write-SOXLog "  Critical Risk Findings: $criticalCount" $(if ($criticalCount -gt 0) { "ERROR" } else { "SUCCESS" })
    Write-SOXLog "  High Risk Findings: $highCount" $(if ($highCount -gt 0) { "WARNING" } else { "SUCCESS" })
    Write-SOXLog "  Medium Risk Findings: $mediumCount" "INFO"
    
    if ($criticalCount -gt 0) {
        Write-SOXLog "`nCRITICAL: Immediate attention required for SOX compliance!" "ERROR"
    }
    
} catch {
    $errorMsg = "`nERROR: $($_.Exception.Message)`nStack Trace: $($_.ScriptStackTrace)"
    Write-SOXLog $errorMsg "ERROR"
    
    if ($OutputDirectory) {
        $errorFile = "$OutputDirectory\ERROR_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $errorMsg | Out-File $errorFile -Encoding UTF8
        Write-SOXLog "`nError details saved to: $errorFile" "WARNING"
    }
    
    exit 1
} finally {
    Stop-Transcript | Out-Null
}