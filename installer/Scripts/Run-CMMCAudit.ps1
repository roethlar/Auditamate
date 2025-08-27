<#
.SYNOPSIS
    Comprehensive Cybersecurity Maturity Model Certification (CMMC) audit tool.

.DESCRIPTION
    Performs CMMC compliance audits for Department of Defense (DoD) contractors.
    Assesses cybersecurity maturity across all CMMC levels and domains.

.PARAMETER Level
    CMMC maturity level to audit (1-5)

.PARAMETER Complete
    Run complete CMMC assessment across all levels

.PARAMETER Domain
    Specific CMMC domain to focus on (AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PS, RA, SA, SC, SI, SR)

.PARAMETER OutputDirectory
    Directory for audit reports (default: timestamped folder)

.PARAMETER SendEmail
    Send audit report via email

.EXAMPLE
    .\Run-CMMCAudit.ps1 -Level 2
    Audit CMMC Level 2 requirements

.EXAMPLE
    .\Run-CMMCAudit.ps1 -Complete
    Run complete CMMC assessment

.EXAMPLE
    .\Run-CMMCAudit.ps1 -Level 3 -Domain "AC"
    Audit Level 3 Access Control domain

.NOTES
    CMMC Domains:
    AC - Access Control
    AT - Awareness and Training  
    AU - Audit and Accountability
    CA - Assessment, Authorization, and Monitoring
    CM - Configuration Management
    CP - Contingency Planning
    IA - Identification and Authentication
    IR - Incident Response
    MA - Maintenance
    MP - Media Protection
    PE - Physical Protection
    PS - Personnel Security
    RA - Risk Assessment
    SA - System and Services Acquisition
    SC - System and Communications Protection
    SI - System and Information Integrity
    SR - Supply Chain Risk Management
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,5)]
    [int]$Level,
    
    [Parameter(Mandatory=$false)]
    [switch]$Complete,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "SA", "SC", "SI", "SR")]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\CMMC_Audit_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail
)

$ErrorActionPreference = 'Stop'

# Create output directory
if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$logFile = "$OutputDirectory\cmmc-audit.log"
$transcript = "$OutputDirectory\cmmc-audit-transcript.log"
Start-Transcript -Path $transcript -Force

function Write-CMMCLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "CMMC" { Write-Host $Message -ForegroundColor Cyan }
        "DOMAIN" { Write-Host $Message -ForegroundColor Magenta }
        default { Write-Host $Message -ForegroundColor White }
    }
}

# CMMC Domain Assessment Functions
function Test-AccessControl {
    param([int]$CMMCLevel)
    
    Write-CMMCLog "`n=== CMMC Domain: Access Control (AC) ===" "DOMAIN"
    $results = @()
    
    # AC.L1-3.1.1 - Limit system access to authorized users
    if ($CMMCLevel -ge 1) {
        Write-CMMCLog "AC.L1-3.1.1: Checking system access controls..." "INFO"
        $privilegedGroups = @("Domain Admins", "adi_server_admins", "WW_NT_DBA", "CORPIS_TIER2_MSSQLDBA", "HPE_AMS_SERVER_ADMINS", "CERT PUBLISHERS", "SERVER OPERATORS", "ADMINISTRATORS", "ENTERPRISE_ADMINS", "SCHEMA_ADMINS", "Enterprise Admins", "Schema Admins", "Administrators", "Server Operators")
        
        foreach ($group in $privilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "AC.L1-3.1.1"
                        Domain = "Access Control"
                        Level = 1
                        Description = "System Access Control: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members have privileged access"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = if ($members.Count -gt 5) { "HIGH" } else { "MEDIUM" }
                        Requirement = "Limit system access to authorized users, processes, and devices"
                    }
                }
            } catch { }
        }
    }
    
    # AC.L2-3.1.2 - Limit system access to authorized functions
    if ($CMMCLevel -ge 2) {
        Write-CMMCLog "AC.L2-3.1.2: Checking functional access controls..." "INFO"
        $functionalGroups = @(
            "adi_server_admins", "HPE_AMS_SERVER_ADMINS", "SERVER OPERATORS",
            "Power Users", "Remote Desktop Users", "Backup Operators", 
            "Print Operators", "Account Operators", "Server Operators"
        )
        
        foreach ($group in $functionalGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "AC.L2-3.1.2"
                        Domain = "Access Control"
                        Level = 2
                        Description = "Functional Access Control: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members have functional access"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = "MEDIUM"
                        Requirement = "Limit system access to authorized functions, data, and services"
                    }
                }
            } catch { }
        }
    }
    
    # AC.L2-3.1.3 - Control CUI flow
    if ($CMMCLevel -ge 2) {
        Write-CMMCLog "AC.L2-3.1.3: Checking CUI flow controls..." "INFO"
        $cuiGroups = @("CERT PUBLISHERS", "Document Managers", "File Share Admins", "SharePoint Admins")
        
        foreach ($group in $cuiGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "AC.L2-3.1.3"
                        Domain = "Access Control"
                        Level = 2
                        Description = "CUI Flow Control: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members can control information flow"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = "HIGH"
                        Requirement = "Control the flow of Controlled Unclassified Information (CUI)"
                    }
                }
            } catch { }
        }
    }
    
    return $results
}

function Test-IdentificationAuthentication {
    param([int]$CMMCLevel)
    
    Write-CMMCLog "`n=== CMMC Domain: Identification and Authentication (IA) ===" "DOMAIN"
    $results = @()
    
    # IA.L1-3.5.1 - Identify system users
    if ($CMMCLevel -ge 1) {
        Write-CMMCLog "IA.L1-3.5.1: Checking user identification..." "INFO"
        
        # Check for service accounts and shared accounts
        $serviceAccounts = Get-ADUser -Filter 'Name -like "*service*" -or Name -like "*svc*"' -Properties Description
        $sharedAccounts = Get-ADUser -Filter 'Name -like "*shared*" -or Name -like "*admin*"' -Properties Description
        
        $results += @{
            Control = "IA.L1-3.5.1"
            Domain = "Identification and Authentication"
            Level = 1
            Description = "Service Account Identification"
            Status = "REVIEW_REQUIRED"
            Finding = "$($serviceAccounts.Count) service accounts found"
            MemberCount = $serviceAccounts.Count
            Members = ($serviceAccounts.Name -join "; ")
            Risk = if ($serviceAccounts.Count -gt 10) { "MEDIUM" } else { "LOW" }
            Requirement = "Identify system users, processes acting on behalf of users, and devices"
        }
        
        if ($sharedAccounts.Count -gt 0) {
            $results += @{
                Control = "IA.L1-3.5.1"
                Domain = "Identification and Authentication"
                Level = 1
                Description = "Shared Account Detection"
                Status = "NON_COMPLIANT"
                Finding = "$($sharedAccounts.Count) potential shared accounts found"
                MemberCount = $sharedAccounts.Count
                Members = ($sharedAccounts.Name -join "; ")
                Risk = "HIGH"
                Requirement = "Eliminate shared/group authenticators"
            }
        }
    }
    
    # IA.L2-3.5.2 - Authenticate users, processes, and devices
    if ($CMMCLevel -ge 2) {
        Write-CMMCLog "IA.L2-3.5.2: Checking authentication requirements..." "INFO"
        
        # Check for accounts with password never expires
        $neverExpire = Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Properties PasswordNeverExpires
        
        if ($neverExpire.Count -gt 0) {
            $results += @{
                Control = "IA.L2-3.5.2"
                Domain = "Identification and Authentication"
                Level = 2
                Description = "Password Policy Compliance"
                Status = "NON_COMPLIANT"
                Finding = "$($neverExpire.Count) accounts with non-expiring passwords"
                MemberCount = $neverExpire.Count
                Members = ($neverExpire.Name -join "; ")
                Risk = "HIGH"
                Requirement = "Authenticate users, processes, and devices before granting access"
            }
        }
    }
    
    return $results
}

function Test-SystemProtection {
    param([int]$CMMCLevel)
    
    Write-CMMCLog "`n=== CMMC Domain: System and Communications Protection (SC) ===" "DOMAIN"
    $results = @()
    
    # SC.L1-3.13.1 - Monitor communications at external boundaries
    if ($CMMCLevel -ge 1) {
        Write-CMMCLog "SC.L1-3.13.1: Checking boundary protection..." "INFO"
        $boundaryGroups = @("Firewall Administrators", "Network Administrators", "Security Operations")
        
        foreach ($group in $boundaryGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "SC.L1-3.13.1"
                        Domain = "System and Communications Protection"
                        Level = 1
                        Description = "Boundary Protection: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members manage boundary protection"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = "MEDIUM"
                        Requirement = "Monitor communications at external network boundaries"
                    }
                }
            } catch { }
        }
    }
    
    # SC.L2-3.13.2 - Employ architectural designs and protection mechanisms
    if ($CMMCLevel -ge 2) {
        Write-CMMCLog "SC.L2-3.13.2: Checking architectural protections..." "INFO"
        $archGroups = @("Security Architects", "System Architects", "Infrastructure Architects")
        
        foreach ($group in $archGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "SC.L2-3.13.2"
                        Domain = "System and Communications Protection"
                        Level = 2
                        Description = "Architectural Protection: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members design security architecture"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = "MEDIUM"
                        Requirement = "Employ architectural designs and protection mechanisms"
                    }
                }
            } catch { }
        }
    }
    
    return $results
}

function Test-AuditAccountability {
    param([int]$CMMCLevel)
    
    Write-CMMCLog "`n=== CMMC Domain: Audit and Accountability (AU) ===" "DOMAIN"
    $results = @()
    
    # AU.L2-3.3.1 - Create and retain system audit logs
    if ($CMMCLevel -ge 2) {
        Write-CMMCLog "AU.L2-3.3.1: Checking audit log management..." "INFO"
        $auditGroups = @("Log Administrators", "SIEM Administrators", "Audit Administrators")
        
        foreach ($group in $auditGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "AU.L2-3.3.1"
                        Domain = "Audit and Accountability"
                        Level = 2
                        Description = "Audit Log Management: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members manage audit logs"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = "MEDIUM"
                        Requirement = "Create and retain system audit logs and records"
                    }
                }
            } catch { }
        }
    }
    
    return $results
}

function Test-ConfigurationManagement {
    param([int]$CMMCLevel)
    
    Write-CMMCLog "`n=== CMMC Domain: Configuration Management (CM) ===" "DOMAIN"
    $results = @()
    
    # CM.L2-3.4.1 - Establish configuration baselines
    if ($CMMCLevel -ge 2) {
        Write-CMMCLog "CM.L2-3.4.1: Checking configuration management..." "INFO"
        $configGroups = @("Configuration Managers", "Change Control Board", "System Administrators")
        
        foreach ($group in $configGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                if ($members) {
                    $results += @{
                        Control = "CM.L2-3.4.1"
                        Domain = "Configuration Management"
                        Level = 2
                        Description = "Configuration Management: $group"
                        Status = "REVIEW_REQUIRED"
                        Finding = "$($members.Count) members manage system configurations"
                        MemberCount = $members.Count
                        Members = ($members.Name -join "; ")
                        Risk = "MEDIUM"
                        Requirement = "Establish and maintain baseline configurations"
                    }
                }
            } catch { }
        }
    }
    
    return $results
}

try {
    Write-CMMCLog "`n===============================================" "INFO"
    Write-CMMCLog "  CMMC COMPLIANCE AUDIT TOOL" "INFO"
    Write-CMMCLog "===============================================`n" "INFO"
    Write-CMMCLog "Output Directory: $OutputDirectory" "INFO"
    
    # Import required modules
    $modulePath = Split-Path $PSScriptRoot -Parent
    Import-Module "$modulePath\Modules\AD-AuditModule-Secure.psm1" -Force
    
    $allResults = @()
    
    # Determine scope of audit
    if ($Complete) {
        Write-CMMCLog "Running complete CMMC assessment (Levels 1-5)..." "CMMC"
        for ($i = 1; $i -le 5; $i++) {
            Write-CMMCLog "`nAssessing CMMC Level $i requirements..." "CMMC"
            $allResults += Test-AccessControl -CMMCLevel $i
            $allResults += Test-IdentificationAuthentication -CMMCLevel $i
            $allResults += Test-SystemProtection -CMMCLevel $i
            $allResults += Test-AuditAccountability -CMMCLevel $i
            $allResults += Test-ConfigurationManagement -CMMCLevel $i
        }
    } elseif ($Level) {
        Write-CMMCLog "Running CMMC Level $Level assessment..." "CMMC"
        
        if ($Domain) {
            Write-CMMCLog "Focusing on domain: $Domain" "DOMAIN"
            switch ($Domain) {
                "AC" { $allResults += Test-AccessControl -CMMCLevel $Level }
                "IA" { $allResults += Test-IdentificationAuthentication -CMMCLevel $Level }
                "SC" { $allResults += Test-SystemProtection -CMMCLevel $Level }
                "AU" { $allResults += Test-AuditAccountability -CMMCLevel $Level }
                "CM" { $allResults += Test-ConfigurationManagement -CMMCLevel $Level }
                default { Write-CMMCLog "Domain $Domain assessment not implemented yet" "WARNING" }
            }
        } else {
            # Assess all domains for the specified level
            $allResults += Test-AccessControl -CMMCLevel $Level
            $allResults += Test-IdentificationAuthentication -CMMCLevel $Level
            $allResults += Test-SystemProtection -CMMCLevel $Level
            $allResults += Test-AuditAccountability -CMMCLevel $Level
            $allResults += Test-ConfigurationManagement -CMMCLevel $Level
        }
    } else {
        Write-CMMCLog "No level specified. Use -Level or -Complete parameter." "ERROR"
        exit 1
    }
    
    # Generate CSV report
    Write-CMMCLog "`nGenerating CMMC compliance report..." "INFO"
    $csvPath = "$OutputDirectory\cmmc_compliance_report.csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation
    
    # Generate enhanced web report with embedded content
    Write-CMMCLog "`nGenerating enhanced CMMC compliance report..." "INFO"
    
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
    $scope = if ($Complete) { "Complete CMMC Assessment (Levels 1-5)" } 
             elseif ($Domain) { "CMMC Level $Level - Domain $Domain" }
             else { "CMMC Level $Level Assessment" }
             
    $highRiskCount = ($allResults | Where-Object { $_.Risk -eq "HIGH" }).Count
    $mediumRiskCount = ($allResults | Where-Object { $_.Risk -eq "MEDIUM" }).Count
    $nonCompliantCount = ($allResults | Where-Object { $_.Status -eq "NON_COMPLIANT" }).Count
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>CMMC Compliance Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #1e40af; }
        h2 { color: #7c3aed; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .high { background-color: #fee2e2; }
        .medium { background-color: #fef3c7; }
        .low { background-color: #ecfdf5; }
        .summary { background-color: #eff6ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .level { font-weight: bold; color: #1e40af; }
    </style>
</head>
<body>
    <h1>CMMC Compliance Audit Report</h1>
    <div class="summary">
        <p><strong>Audit Date:</strong> $(Get-Date -Format 'MMMM dd, yyyy HH:mm')</p>
        <p><strong>Scope:</strong> $scope</p>
        <p><strong>Total Controls Assessed:</strong> $($allResults.Count)</p>
        <p><strong>High Risk Findings:</strong> $(($allResults | Where-Object { $_.Risk -eq "HIGH" }).Count)</p>
        <p><strong>Medium Risk Findings:</strong> $(($allResults | Where-Object { $_.Risk -eq "MEDIUM" }).Count)</p>
        <p><strong>Non-Compliant Controls:</strong> $(($allResults | Where-Object { $_.Status -eq "NON_COMPLIANT" }).Count)</p>
    </div>
    
    <h2>CMMC Control Assessment Results</h2>
    <table>
        <tr>
            <th>Control ID</th>
            <th>Domain</th>
            <th>Level</th>
            <th>Description</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Finding</th>
            <th>Member Count</th>
        </tr>
$(foreach ($result in $allResults | Sort-Object Level, Domain, Control) {
    $rowClass = switch ($result.Risk) {
        "HIGH" { "high" }
        "MEDIUM" { "medium" }
        "LOW" { "low" }
        default { "" }
    }
    @"
        <tr class="$rowClass">
            <td>$($result.Control)</td>
            <td>$($result.Domain)</td>
            <td class="level">$($result.Level)</td>
            <td>$($result.Description)</td>
            <td>$($result.Status)</td>
            <td>$($result.Risk)</td>
            <td>$($result.Finding)</td>
            <td>$($result.MemberCount)</td>
        </tr>
"@
})
    </table>
    
    <h2>CMMC Maturity Levels</h2>
    <p><strong>Level 1 - Basic Cyber Hygiene:</strong> Fundamental cybersecurity practices</p>
    <p><strong>Level 2 - Intermediate Cyber Hygiene:</strong> Transition practices serving as a bridge to Level 3</p>
    <p><strong>Level 3 - Good Cyber Hygiene:</strong> Good cybersecurity practices for protecting CUI</p>
    <p><strong>Level 4 - Proactive:</strong> Proactive practices for advanced persistent threats</p>
    <p><strong>Level 5 - Advanced/Progressive:</strong> Advanced practices for sophisticated threats</p>
    
    <h2>CMMC Domains Assessed</h2>
    <ul>
        <li><strong>AC</strong> - Access Control</li>
        <li><strong>IA</strong> - Identification and Authentication</li>
        <li><strong>SC</strong> - System and Communications Protection</li>
        <li><strong>AU</strong> - Audit and Accountability</li>
        <li><strong>CM</strong> - Configuration Management</li>
    </ul>
    
    <p style="margin-top: 20px; font-size: 0.9em; color: #666;">
        This assessment provides a technical evaluation of CMMC controls. 
        Additional documentation review and process assessment may be required for full compliance.
    </p>
</body>
</html>
"@
    
    $reportMetadata = @{
        "Audit Type" = "CMMC Compliance Assessment"
        "Compliance Framework" = "Cybersecurity Maturity Model Certification"
        "Assessment Scope" = $scope
        "Target Level" = if ($Level) { "Level $Level" } else { "Levels 1-5" }
        "Domain Focus" = if ($Domain) { $Domain } else { "All Domains" }
        "Total Controls Assessed" = "$($allResults.Count)"
        "High Risk Findings" = "$highRiskCount"
        "Medium Risk Findings" = "$mediumRiskCount"  
        "Non-Compliant Controls" = "$nonCompliantCount"
        "Compliance Status" = if ($nonCompliantCount -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
        "DoD Contractor" = $env:USERDNSDOMAIN
        "Auditor" = $env:USERNAME
        "Assessment Authority" = "CMMC Third-Party Assessment Organization (C3PAO)"
    }
    
    # Generate the enhanced web report
    $htmlPath = "$OutputDirectory\CMMC_Compliance_Report.html"
    $reportResult = New-EnhancedWebReport -AuditData $allResults -ScreenshotPaths $screenshots -CsvFiles $csvFiles -OutputPath $htmlPath -ReportTitle "CMMC Compliance Assessment Report" -CompanyName $env:USERDNSDOMAIN -CustomMetadata $reportMetadata
    
    Write-CMMCLog "Enhanced CMMC compliance report created: $htmlPath" "SUCCESS"
    Write-CMMCLog "Report includes $($reportResult.EmbeddedDataFiles) embedded data files" "INFO"
    
    # Summary
    Write-CMMCLog "`n===============================================" "SUCCESS"
    Write-CMMCLog "  CMMC COMPLIANCE AUDIT COMPLETE!" "SUCCESS"
    Write-CMMCLog "===============================================" "SUCCESS"
    Write-CMMCLog "`nReports saved to: $OutputDirectory" "INFO"
    Write-CMMCLog "  - CSV Report: cmmc_compliance_report.csv" "INFO"
    Write-CMMCLog "  - Enhanced Web Report: CMMC_Compliance_Report.html" "INFO"
    
    # Display summary statistics
    $highCount = ($allResults | Where-Object { $_.Risk -eq "HIGH" }).Count
    $mediumCount = ($allResults | Where-Object { $_.Risk -eq "MEDIUM" }).Count
    $nonCompliant = ($allResults | Where-Object { $_.Status -eq "NON_COMPLIANT" }).Count
    
    Write-CMMCLog "`nCMMC Assessment Summary:" "CMMC"
    Write-CMMCLog "  Total Controls Assessed: $($allResults.Count)" "INFO"
    Write-CMMCLog "  High Risk Findings: $highCount" $(if ($highCount -gt 0) { "ERROR" } else { "SUCCESS" })
    Write-CMMCLog "  Medium Risk Findings: $mediumCount" $(if ($mediumCount -gt 0) { "WARNING" } else { "SUCCESS" })
    Write-CMMCLog "  Non-Compliant Controls: $nonCompliant" $(if ($nonCompliant -gt 0) { "ERROR" } else { "SUCCESS" })
    
    if ($nonCompliant -gt 0) {
        Write-CMMCLog "`nATTENTION: Non-compliant controls require remediation for CMMC certification!" "ERROR"
    }
    
} catch {
    $errorMsg = "`nERROR: $($_.Exception.Message)`nStack Trace: $($_.ScriptStackTrace)"
    Write-CMMCLog $errorMsg "ERROR"
    
    if ($OutputDirectory) {
        $errorFile = "$OutputDirectory\ERROR_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $errorMsg | Out-File $errorFile -Encoding UTF8
        Write-CMMCLog "`nError details saved to: $errorFile" "WARNING"
    }
    
    exit 1
} finally {
    Stop-Transcript | Out-Null
}