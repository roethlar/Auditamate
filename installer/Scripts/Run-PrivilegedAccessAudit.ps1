<#
.SYNOPSIS
    Audits privileged access across Entra ID and Exchange environments.

.DESCRIPTION
    Comprehensive audit tool for administrative roles and privileged access across Microsoft 365
    and on-premise systems. Retrieves Entra ID admin roles, PIM assignments, Exchange RBAC roles,
    Conditional Access policies, and role assignment history.

.PARAMETER ConfigFile
    Path to JSON configuration file. Default: .\privileged-access-config.json

.PARAMETER TenantId
    Azure AD Tenant ID for Microsoft Graph connection.

.PARAMETER ClientId
    Application (client) ID for Microsoft Graph authentication.

.PARAMETER ExchangeServer
    FQDN of on-premise Exchange 2019 server to audit.

.PARAMETER IncludePIM
    Include Privileged Identity Management (PIM) role assignments.

.PARAMETER IncludeConditionalAccess
    Include Conditional Access policies affecting admin roles.

.PARAMETER IncludeAuditLogs
    Include role assignment history from audit logs.

.PARAMETER AuditDaysBack
    Number of days to look back for audit logs. Default: 30

.PARAMETER SendEmail
    Send audit report via email to configured recipients.

.PARAMETER OutputDirectory
    Directory to save audit reports. Default: .\Reports

.PARAMETER Job
    Path to a saved job file to load parameters from a previous run.

.PARAMETER SaveJob
    Path to save current parameters as a job file for future reuse.

.EXAMPLE
    .\Run-PrivilegedAccessAudit.ps1 -IncludePIM -IncludeConditionalAccess
    Runs full privileged access audit including PIM and CA policies.

.EXAMPLE
    .\Run-PrivilegedAccessAudit.ps1 -TenantId "abc-123" -ClientId "def-456" -AuditDaysBack 90
    Runs audit with specific tenant/app IDs, checking 90 days of history.

.EXAMPLE
    .\Run-PrivilegedAccessAudit.ps1 -IncludePIM -SaveJob quarterly-priv-audit.json
    Runs PIM audit and saves parameters for quarterly reuse.

.EXAMPLE
    .\Run-PrivilegedAccessAudit.ps1 -Job quarterly-priv-audit.json
    Re-runs a previously saved privileged access audit.

.NOTES
    Author: IT Security Team
    Version: 1.0
    Requires: Microsoft Graph API permissions (see documentation)
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "$(Split-Path $PSScriptRoot -Parent)\Config\privileged-access-config.json",
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$ExchangeServer,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludePIM,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeConditionalAccess,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeAuditLogs,
    
    [Parameter(Mandatory=$false)]
    [int]$AuditDaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "$(Split-Path $PSScriptRoot -Parent)\Output\PrivilegedAccess_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$Job,
    
    [Parameter(Mandatory=$false)]
    [string]$SaveJob
)

Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "  Privileged Access Audit Tool" -ForegroundColor Cyan
Write-Host "  Auditing Entra ID & Exchange RBAC Roles" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Cyan

try {
    # Load job if specified
    if ($Job) {
        if (Test-Path $Job) {
            Write-Host "Loading job configuration from: $Job" -ForegroundColor Green
            $jobConfig = Get-Content $Job | ConvertFrom-Json
            
            # Override parameters with job config
            if ($jobConfig.TenantId) { $TenantId = $jobConfig.TenantId }
            if ($jobConfig.ClientId) { $ClientId = $jobConfig.ClientId }
            if ($jobConfig.ExchangeServer) { $ExchangeServer = $jobConfig.ExchangeServer }
            if ($jobConfig.PSObject.Properties["IncludePIM"]) { $IncludePIM = $jobConfig.IncludePIM }
            if ($jobConfig.PSObject.Properties["IncludeConditionalAccess"]) { $IncludeConditionalAccess = $jobConfig.IncludeConditionalAccess }
            if ($jobConfig.PSObject.Properties["IncludeAuditLogs"]) { $IncludeAuditLogs = $jobConfig.IncludeAuditLogs }
            if ($jobConfig.AuditDaysBack) { $AuditDaysBack = $jobConfig.AuditDaysBack }
            if ($jobConfig.PSObject.Properties["SendEmail"]) { $SendEmail = $jobConfig.SendEmail }
            if ($jobConfig.ConfigFile) { $ConfigFile = $jobConfig.ConfigFile }
        } else {
            Write-Warning "Job file not found: $Job"
        }
    }
    
    # Load configuration
    $config = @{
        TenantId = $TenantId
        ClientId = $ClientId
        ExchangeServer = $ExchangeServer
        IncludePIM = $IncludePIM
        IncludeConditionalAccess = $IncludeConditionalAccess
        IncludeAuditLogs = $IncludeAuditLogs
        AuditDaysBack = $AuditDaysBack
    }
    
    if (Test-Path $ConfigFile) {
        Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor Green
        $loadedConfig = Get-Content $ConfigFile | ConvertFrom-Json
        
        # Override with loaded config if not specified in parameters
        if (!$TenantId -and $loadedConfig.TenantId) { $config.TenantId = $loadedConfig.TenantId }
        if (!$ClientId -and $loadedConfig.ClientId) { $config.ClientId = $loadedConfig.ClientId }
        if (!$ExchangeServer -and $loadedConfig.ExchangeServer) { $config.ExchangeServer = $loadedConfig.ExchangeServer }
        if ($loadedConfig.IncludePIM) { $config.IncludePIM = $true }
        if ($loadedConfig.IncludeConditionalAccess) { $config.IncludeConditionalAccess = $true }
        if ($loadedConfig.IncludeAuditLogs) { $config.IncludeAuditLogs = $true }
    }
    
    # Get credentials if needed
    if (!$config.TenantId -or !$config.ClientId) {
        Write-Host "Microsoft Graph configuration required:" -ForegroundColor Yellow
        if (!$config.TenantId) {
            $config.TenantId = Read-Host "Enter Tenant ID"
        }
        if (!$config.ClientId) {
            $config.ClientId = Read-Host "Enter Client ID (App Registration)"
        }
    }
    
    # Get client secret
    Write-Host "`nEnter Client Secret for App Registration:" -ForegroundColor Yellow
    $clientSecret = Read-Host -AsSecureString
    
    # Import modules
    $modulePath = Split-Path $PSScriptRoot -Parent
    . "$modulePath\Modules\PrivilegedAccess-UnifiedReport.ps1"
    . "$modulePath\Modules\Audit-StandardOutput.ps1"
    
    # Create output directory
    if (!(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    $reportPath = "$OutputDirectory\Privileged_Access_Report.html"
    
    $auditParams = @{
        TenantId = $config.TenantId
        ClientId = $config.ClientId
        ClientSecret = $clientSecret
        OutputPath = $reportPath
        IncludePIM = $config.IncludePIM
        IncludeConditionalAccess = $config.IncludeConditionalAccess
        IncludeAuditLogs = $config.IncludeAuditLogs
        AuditDaysBack = $config.AuditDaysBack
    }
    
    if ($config.ExchangeServer) {
        $auditParams.ExchangeServer = $config.ExchangeServer
    }
    
    $auditResults = New-UnifiedPrivilegedAccessReport @auditParams
    
    # Generate CSV reports (primary output)
    Write-Host "`nGenerating CSV reports..." -ForegroundColor Yellow
    
    # No summary CSV needed - data goes directly to role-specific CSVs
    
    # Entra ID roles CSV
    if ($auditResults.EntraIDRoles) {
        $entraPath = "$OutputDirectory\entra_id_roles.csv"
        $auditResults.EntraIDRoles | Export-Csv -Path $entraPath -NoTypeInformation
        Write-Host "Entra ID roles CSV: $entraPath" -ForegroundColor Green
    }
    
    # PIM assignments CSV
    if ($auditResults.PIMAssignments -and $auditResults.PIMAssignments.Count -gt 0) {
        $pimPath = "$OutputDirectory\pim_assignments.csv"
        $auditResults.PIMAssignments | Export-Csv -Path $pimPath -NoTypeInformation
        Write-Host "PIM assignments CSV: $pimPath" -ForegroundColor Green
    }
    
    # Exchange roles CSV
    if ($auditResults.ExchangeRoles -and $auditResults.ExchangeRoles.Count -gt 0) {
        $exchangePath = "$OutputDirectory\exchange_rbac_roles.csv"
        $auditResults.ExchangeRoles | Export-Csv -Path $exchangePath -NoTypeInformation
        Write-Host "Exchange RBAC roles CSV: $exchangePath" -ForegroundColor Green
    }
    
    # Conditional Access CSV
    if ($auditResults.ConditionalAccessPolicies -and $auditResults.ConditionalAccessPolicies.Count -gt 0) {
        $caPath = "$OutputDirectory\conditional_access_policies.csv"
        $auditResults.ConditionalAccessPolicies | Export-Csv -Path $caPath -NoTypeInformation
        Write-Host "Conditional Access policies CSV: $caPath" -ForegroundColor Green
    }
    
    # Audit logs CSV
    if ($auditResults.AuditLogs -and $auditResults.AuditLogs.Count -gt 0) {
        $auditLogPath = "$OutputDirectory\role_assignment_history.csv"
        $auditResults.AuditLogs | Export-Csv -Path $auditLogPath -NoTypeInformation
        Write-Host "Role assignment history CSV: $auditLogPath" -ForegroundColor Green
    }
    
    Write-Host "HTML report saved: $reportPath" -ForegroundColor Green
    
    # Send email if requested
    if ($SendEmail -and $loadedConfig.EmailSettings) {
        Write-Host "`nSending audit report via email..." -ForegroundColor Yellow
        
        . "$modulePath\Modules\Send-AuditReport.ps1"
        
        $emailParams = @{
            Recipients = $loadedConfig.EmailSettings.Recipients
            Subject = "Privileged Access Audit Report - $(Get-Date -Format 'MMMM yyyy')"
            HtmlReportPath = $reportPath
            SmtpServer = $loadedConfig.EmailSettings.SmtpServer
            UseSSL = $loadedConfig.EmailSettings.UseSSL
            Attachments = @()
        }
        
        # Add available CSV files as attachments
        if (Test-Path "$OutputDirectory\entra_id_roles.csv") { $emailParams.Attachments += "$OutputDirectory\entra_id_roles.csv" }
        if (Test-Path "$OutputDirectory\pim_assignments.csv") { $emailParams.Attachments += "$OutputDirectory\pim_assignments.csv" }
        if (Test-Path "$OutputDirectory\exchange_rbac_roles.csv") { $emailParams.Attachments += "$OutputDirectory\exchange_rbac_roles.csv" }
        
        if ($loadedConfig.EmailSettings.From) {
            $emailParams.From = $loadedConfig.EmailSettings.From
        }
        
        Send-ADComplianceReport @emailParams
    }
    
    # Save job if requested
    if ($SaveJob) {
        $jobConfig = @{
            JobName = [System.IO.Path]::GetFileNameWithoutExtension($SaveJob)
            SavedDate = Get-Date
            TenantId = $config.TenantId
            ClientId = $config.ClientId
            ExchangeServer = $config.ExchangeServer
            IncludePIM = $config.IncludePIM
            IncludeConditionalAccess = $config.IncludeConditionalAccess
            IncludeAuditLogs = $config.IncludeAuditLogs
            AuditDaysBack = $config.AuditDaysBack
            SendEmail = $SendEmail
            ConfigFile = $ConfigFile
        }
        
        $jobConfig | ConvertTo-Json | Out-File $SaveJob -Encoding UTF8
        Write-Host "`n* Job saved to: $SaveJob" -ForegroundColor Green
    }
    
    # Display summary using standardized output
    Show-AuditSummary -AuditType "Privileged Access" -OutputDirectory $OutputDirectory
    
    # Open output directory
    $openReport = Read-Host "`nOpen output directory now? (Y/N)"
    if ($openReport -eq 'Y') {
        Start-Process $OutputDirectory
    }
    
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}
