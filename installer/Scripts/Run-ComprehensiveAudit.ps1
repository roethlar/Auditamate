# Comprehensive Active Directory and Azure Audit
# Complete security audit covering AD, Azure AD, Service Accounts, Trusts, and GPOs

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$IncludeAzureAD,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeServiceAccounts,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeTrusts,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeGPOs,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeAll,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\Comprehensive_Audit_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerList = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [switch]$CaptureScreenshots = $true
)

$ErrorActionPreference = 'Stop'

Write-Host "Starting Comprehensive Active Directory and Cloud Audit..." -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# Set all switches if IncludeAll is specified
if ($IncludeAll) {
    $IncludeAzureAD = $true
    $IncludeServiceAccounts = $true
    $IncludeTrusts = $true
    $IncludeGPOs = $true
}

# Create output directory
if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$auditStartTime = Get-Date
$allAuditData = @()
$allCsvFiles = @()
$allScreenshots = @()
$auditSummary = @{
    TotalComponents = 0
    CompletedComponents = 0
    FailedComponents = 0
    ComponentResults = @{}
}

# Start transcript
$transcript = "$OutputDirectory\comprehensive-audit-transcript.log"
Start-Transcript -Path $transcript -Force

try {
    # 1. Core AD Groups Audit (Always included)
    Write-Host "`n=== CORE AD GROUPS AUDIT ===" -ForegroundColor Yellow
    $auditSummary.TotalComponents++
    
    try {
        . "$PSScriptRoot\Run-ADCompleteAudit.ps1"
        # Note: This will generate its own enhanced web report
        $auditSummary.CompletedComponents++
        $auditSummary.ComponentResults["Core AD Groups"] = "Success"
        Write-Host "✓ Core AD Groups audit completed" -ForegroundColor Green
    } catch {
        Write-Error "Core AD Groups audit failed: $_"
        $auditSummary.FailedComponents++
        $auditSummary.ComponentResults["Core AD Groups"] = "Failed: $_"
    }
    
    # 2. Service Accounts Discovery
    if ($IncludeServiceAccounts) {
        Write-Host "`n=== SERVICE ACCOUNTS DISCOVERY ===" -ForegroundColor Yellow
        $auditSummary.TotalComponents++
        
        try {
            . "$PSScriptRoot\..\Modules\ServiceAccount-Discovery.ps1"
            
            $serviceAccountResults = Get-ServiceAccountInventory -Domain $env:USERDNSDOMAIN -ComputerList $ComputerList -CaptureScreenshots:$CaptureScreenshots
            
            if ($serviceAccountResults) {
                $serviceAccountReports = Export-ServiceAccountReport -ServiceAccountData $serviceAccountResults -OutputDirectory $OutputDirectory
                $allCsvFiles += $serviceAccountReports.DetailedReport, $serviceAccountReports.SummaryReport, $serviceAccountReports.HighRiskReport
                $allAuditData += $serviceAccountResults.ServiceAccounts
                
                $auditSummary.CompletedComponents++
                $auditSummary.ComponentResults["Service Accounts"] = "Success - $($serviceAccountResults.ServiceAccounts.Count) accounts found"
                Write-Host "✓ Service Accounts discovery completed" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Service Accounts discovery failed: $_"
            $auditSummary.FailedComponents++
            $auditSummary.ComponentResults["Service Accounts"] = "Failed: $_"
        }
    }
    
    # 3. Azure AD Audit
    if ($IncludeAzureAD) {
        Write-Host "`n=== AZURE AD AUDIT ===" -ForegroundColor Yellow
        $auditSummary.TotalComponents++
        
        try {
            . "$PSScriptRoot\..\Modules\AzureAD-EnhancedAudit.ps1"
            
            $azureADParams = @{
                IncludePIM = $true
                IncludeConditionalAccess = $true
                IncludeServicePrincipals = $true
                CaptureScreenshots = $CaptureScreenshots
            }
            if ($TenantId) { $azureADParams.TenantId = $TenantId }
            if ($ClientId) { $azureADParams.ClientId = $ClientId }
            
            $azureADResults = Start-AzureADEnhancedAudit @azureADParams
            
            if ($azureADResults) {
                $azureADReports = Export-AzureADAuditReports -AuditResults $azureADResults -OutputDirectory $OutputDirectory
                $allCsvFiles += $azureADReports
                $allAuditData += $azureADResults.DirectoryRoles + $azureADResults.PIMRoles
                
                $auditSummary.CompletedComponents++
                $auditSummary.ComponentResults["Azure AD"] = "Success - $($azureADResults.Statistics.TotalDirectoryRoleAssignments) role assignments"
                Write-Host "✓ Azure AD audit completed" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Azure AD audit failed: $_"
            $auditSummary.FailedComponents++
            $auditSummary.ComponentResults["Azure AD"] = "Failed: $_"
        }
    }
    
    # 4. AD Trusts Audit
    if ($IncludeTrusts) {
        Write-Host "`n=== AD TRUSTS AUDIT ===" -ForegroundColor Yellow
        $auditSummary.TotalComponents++
        
        try {
            . "$PSScriptRoot\..\Modules\ADTrusts-Audit.ps1"
            
            $trustResults = Get-ADTrustAudit -Domain $env:USERDNSDOMAIN -IncludeDelegation -IncludeForeignSecurityPrincipals -CaptureScreenshots:$CaptureScreenshots
            
            if ($trustResults) {
                $trustReports = Export-ADTrustAuditReports -AuditResults $trustResults -OutputDirectory $OutputDirectory
                $allCsvFiles += $trustReports
                $allAuditData += $trustResults.Trusts + $trustResults.Delegation + $trustResults.ForeignSecurityPrincipals
                
                $auditSummary.CompletedComponents++
                $auditSummary.ComponentResults["AD Trusts"] = "Success - $($trustResults.Statistics.TotalTrusts) trusts, $($trustResults.Statistics.CriticalDelegations) critical delegations"
                Write-Host "✓ AD Trusts audit completed" -ForegroundColor Green
            }
        } catch {
            Write-Warning "AD Trusts audit failed: $_"
            $auditSummary.FailedComponents++
            $auditSummary.ComponentResults["AD Trusts"] = "Failed: $_"
        }
    }
    
    # 5. GPO Security Audit
    if ($IncludeGPOs) {
        Write-Host "`n=== GPO SECURITY AUDIT ===" -ForegroundColor Yellow
        $auditSummary.TotalComponents++
        
        try {
            . "$PSScriptRoot\..\Modules\GPO-SecurityAudit.ps1"
            
            $gpoResults = Get-GPOSecurityAudit -Domain $env:USERDNSDOMAIN -IncludeSettings -IncludeWMIFilters -CaptureScreenshots:$CaptureScreenshots
            
            if ($gpoResults) {
                $gpoReports = Export-GPOSecurityAuditReports -AuditResults $gpoResults -OutputDirectory $OutputDirectory
                $allCsvFiles += $gpoReports
                $allAuditData += $gpoResults.GPOPermissions + $gpoResults.UnlinkedGPOs + $gpoResults.OrphanedGPOs
                
                $auditSummary.CompletedComponents++
                $auditSummary.ComponentResults["GPO Security"] = "Success - $($gpoResults.Statistics.TotalGPOs) GPOs, $($gpoResults.Statistics.HighRiskPermissions) high-risk permissions"
                Write-Host "✓ GPO Security audit completed" -ForegroundColor Green
            }
        } catch {
            Write-Warning "GPO Security audit failed: $_"
            $auditSummary.FailedComponents++
            $auditSummary.ComponentResults["GPO Security"] = "Failed: $_"
        }
    }
    
    # 6. Generate Comprehensive Report
    Write-Host "`n=== GENERATING COMPREHENSIVE REPORT ===" -ForegroundColor Yellow
    
    # Import the enhanced web report generator
    . "$PSScriptRoot\..\Modules\Enhanced-WebReportGenerator.ps1"
    
    # Collect all screenshots
    Get-ChildItem -Path $OutputDirectory -Recurse -Filter "*.png" -ErrorAction SilentlyContinue | ForEach-Object {
        $allScreenshots += $_.FullName
    }
    
    # Prepare comprehensive metadata
    $comprehensiveMetadata = @{
        "Audit Type" = "Comprehensive AD and Cloud Security Audit"
        "Audit Scope" = "Active Directory + " + (@($IncludeAzureAD ? "Azure AD" : $null, $IncludeServiceAccounts ? "Service Accounts" : $null, $IncludeTrusts ? "Trusts" : $null, $IncludeGPOs ? "GPOs" : $null) | Where-Object { $_ }) -join " + "
        "Components Audited" = "$($auditSummary.CompletedComponents)/$($auditSummary.TotalComponents)"
        "Success Rate" = "$([math]::Round(($auditSummary.CompletedComponents / $auditSummary.TotalComponents) * 100, 1))%"
        "Failed Components" = "$($auditSummary.FailedComponents)"
        "Total Data Points" = "$($allAuditData.Count)"
        "CSV Files Generated" = "$($allCsvFiles.Count)"
        "Screenshots Captured" = "$($allScreenshots.Count)"
        "Audit Duration" = "$('{0:hh\:mm\:ss}' -f ([datetime]$(Get-Date) - [datetime]$auditStartTime))"
        "Domain" = $env:USERDNSDOMAIN
        "Auditor" = $env:USERNAME
        "Compliance Frameworks" = "SOX, CMMC, NIST"
    }
    
    # Generate the comprehensive enhanced web report
    $htmlPath = "$OutputDirectory\Comprehensive_Security_Audit_Report.html"
    $reportResult = New-EnhancedWebReport -AuditData $allAuditData -ScreenshotPaths $allScreenshots -CsvFiles $allCsvFiles -OutputPath $htmlPath -ReportTitle "Comprehensive Security Audit Report" -CompanyName $env:USERDNSDOMAIN -CustomMetadata $comprehensiveMetadata
    
    Write-Host "✓ Comprehensive web report generated: $htmlPath" -ForegroundColor Green
    Write-Host "  Report includes $($reportResult.EmbeddedImages) embedded screenshots" -ForegroundColor Cyan
    Write-Host "  Report includes $($reportResult.EmbeddedDataFiles) embedded data files" -ForegroundColor Cyan
    Write-Host "  Report file size: $([math]::Round($reportResult.FileSize / 1MB, 2)) MB" -ForegroundColor Cyan
    
    # Generate summary CSV
    $summaryPath = "$OutputDirectory\Comprehensive_Audit_Summary.csv"
    $auditSummary.ComponentResults.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Component = $_.Key
            Result = $_.Value
            AuditDate = Get-Date
        }
    } | Export-Csv -Path $summaryPath -NoTypeInformation
    
    Write-Host "✓ Audit summary generated: $summaryPath" -ForegroundColor Green
    
    # Final Summary
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  COMPREHENSIVE SECURITY AUDIT COMPLETE!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    
    Write-Host "`nAudit Summary:" -ForegroundColor Cyan
    Write-Host "  Components Completed: $($auditSummary.CompletedComponents)/$($auditSummary.TotalComponents)" -ForegroundColor White
    Write-Host "  Success Rate: $([math]::Round(($auditSummary.CompletedComponents / $auditSummary.TotalComponents) * 100, 1))%" -ForegroundColor $(if ($auditSummary.FailedComponents -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  Total Data Points: $($allAuditData.Count)" -ForegroundColor White
    Write-Host "  Reports Generated: $($allCsvFiles.Count + 1) files" -ForegroundColor White
    Write-Host "  Screenshots: $($allScreenshots.Count) captured" -ForegroundColor White
    Write-Host "  Duration: $('{0:hh\:mm\:ss}' -f ([datetime]$(Get-Date) - [datetime]$auditStartTime))" -ForegroundColor White
    
    Write-Host "`nComponent Results:" -ForegroundColor Cyan
    foreach ($component in $auditSummary.ComponentResults.GetEnumerator()) {
        $status = if ($component.Value -match "Success") { "✓" } else { "✗" }
        $color = if ($component.Value -match "Success") { "Green" } else { "Red" }
        Write-Host "  $status $($component.Key): $($component.Value)" -ForegroundColor $color
    }
    
    Write-Host "`nMain Report: Comprehensive_Security_Audit_Report.html" -ForegroundColor Yellow
    Write-Host "Output Directory: $OutputDirectory" -ForegroundColor Cyan
    
    if ($SendEmail) {
        Write-Host "`nEmail functionality would be triggered here..." -ForegroundColor Gray
    }
    
} catch {
    Write-Error "Comprehensive audit failed: $_"
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} finally {
    Stop-Transcript | Out-Null
}