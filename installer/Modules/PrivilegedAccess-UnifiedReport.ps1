# Unified Privileged Access Report Generator

. "$PSScriptRoot\MSGraph-Authentication.ps1"
. "$PSScriptRoot\EntraID-RoleAudit.ps1"
. "$PSScriptRoot\Exchange-RBACaudit.ps1"

function New-UnifiedPrivilegedAccessReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$false)]
        [SecureString]$ClientSecret,
        
        [Parameter(Mandatory=$false)]
        [string]$ExchangeServer,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$PSScriptRoot\..\Output\Privileged_Access_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludePIM,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeConditionalAccess,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeAuditLogs,
        
        [Parameter(Mandatory=$false)]
        [int]$AuditDaysBack = 30
    )
    
    Write-Host "`n=== Unified Privileged Access Audit ===" -ForegroundColor Cyan
    Write-Host "Collecting privileged access data across all platforms...`n" -ForegroundColor Yellow
    
    $auditData = @{
        Timestamp = Get-Date
        TenantId = $TenantId
        EntraIDRoles = $null
        PIMAssignments = $null
        ExchangeOnlineRoles = $null
        ExchangeOnPremRoles = $null
        ConditionalAccessPolicies = $null
        RoleHistory = $null
        ExchangeAuditLogs = $null
        ComplianceIssues = @()
        Statistics = @{}
    }
    
    try {
        # Connect to Microsoft Graph
        if ($ClientId -and $ClientSecret) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MSGraphWithSecret -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        }
        
        # Get Entra ID roles
        Write-Host "Retrieving Entra ID admin roles..." -ForegroundColor Yellow
        $auditData.EntraIDRoles = Get-EntraIDAdminRoles -IncludeCustomRoles
        Write-Host "Found $($auditData.EntraIDRoles.Count) Entra ID roles" -ForegroundColor Green
        
        # Get PIM assignments if requested
        if ($IncludePIM) {
            Write-Host "Retrieving PIM role assignments..." -ForegroundColor Yellow
            $auditData.PIMAssignments = Get-EntraIDPIMRoles
            Write-Host "Found $($auditData.PIMAssignments.Count) PIM assignments" -ForegroundColor Green
        }
        
        # Get Conditional Access policies if requested
        if ($IncludeConditionalAccess) {
            Write-Host "Retrieving Conditional Access policies for admins..." -ForegroundColor Yellow
            $auditData.ConditionalAccessPolicies = Get-EntraIDConditionalAccessForAdmins
            Write-Host "Found $($auditData.ConditionalAccessPolicies.Count) relevant CA policies" -ForegroundColor Green
        }
        
        # Get role assignment history
        if ($IncludeAuditLogs) {
            Write-Host "Retrieving role assignment history..." -ForegroundColor Yellow
            $auditData.RoleHistory = Get-EntraIDRoleAssignmentHistory -DaysBack $AuditDaysBack
            Write-Host "Found $($auditData.RoleHistory.Count) role changes in last $AuditDaysBack days" -ForegroundColor Green
        }
        
        # Get Exchange Online roles
        Write-Host "Retrieving Exchange Online RBAC roles..." -ForegroundColor Yellow
        try {
            $auditData.ExchangeOnlineRoles = Get-ExchangeOnlineRBACRoles -UseModernAuth
            Write-Host "Found $($auditData.ExchangeOnlineRoles.TotalRoleGroups) Exchange Online role groups" -ForegroundColor Green
            
            if ($IncludeAuditLogs) {
                Write-Host "Retrieving Exchange admin audit logs..." -ForegroundColor Yellow
                $auditData.ExchangeAuditLogs = Get-ExchangeAdminAuditLog -StartDate (Get-Date).AddDays(-$AuditDaysBack)
                Write-Host "Found $($auditData.ExchangeAuditLogs.Count) Exchange admin actions" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to retrieve Exchange Online data: $_"
            $auditData.ComplianceIssues += "Failed to audit Exchange Online roles"
        }
        
        # Get Exchange on-premise roles if server specified
        if ($ExchangeServer) {
            Write-Host "Retrieving Exchange 2019 on-premise RBAC roles..." -ForegroundColor Yellow
            try {
                $auditData.ExchangeOnPremRoles = Get-Exchange2019OnPremRBACRoles -ExchangeServer $ExchangeServer
                Write-Host "Found $($auditData.ExchangeOnPremRoles.TotalRoleGroups) Exchange on-premise role groups" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to retrieve Exchange on-premise data: $_"
                $auditData.ComplianceIssues += "Failed to audit Exchange on-premise roles"
            }
        }
        
        # Calculate statistics
        $auditData.Statistics = Get-PrivilegedAccessStatistics -AuditData $auditData
        
        # Check for compliance issues
        $auditData.ComplianceIssues += Find-PrivilegedAccessComplianceIssues -AuditData $auditData
        
        # Generate HTML report
        Write-Host "`nGenerating unified privileged access report..." -ForegroundColor Yellow
        $reportPath = New-PrivilegedAccessHTMLReport -AuditData $auditData -OutputPath $OutputPath
        
        Write-Host "`n=== Audit Complete ===" -ForegroundColor Green
        Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan
        
        # Display summary
        Write-Host "`nSummary:" -ForegroundColor Yellow
        Write-Host "  Total Entra ID Admins: $($auditData.Statistics.TotalEntraIDAdmins)" -ForegroundColor White
        Write-Host "  Total Exchange Admins: $($auditData.Statistics.TotalExchangeAdmins)" -ForegroundColor White
        Write-Host "  Critical Roles: $($auditData.Statistics.CriticalRoleCount)" -ForegroundColor White
        Write-Host "  Compliance Issues: $($auditData.ComplianceIssues.Count)" -ForegroundColor $(if ($auditData.ComplianceIssues.Count -gt 0) { 'Red' } else { 'Green' })
        
        $openReport = Read-Host "`nOpen HTML report now? (Y/N)"
        if ($openReport -eq 'Y') {
            Start-Process $reportPath
        }
        
        return $auditData
        
    } catch {
        Write-Error "Failed to generate privileged access report: $_"
        throw
    } finally {
        # Disconnect sessions
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
}

function Get-PrivilegedAccessStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$AuditData
    )
    
    $stats = @{
        TotalEntraIDAdmins = 0
        TotalExchangeAdmins = 0
        TotalUniqueAdmins = @()
        CriticalRoleCount = 0
        HighRiskRoleCount = 0
        PIMEligibleCount = 0
        PIMActiveCount = 0
        RolesWithoutMFA = 0
        DirectAssignments = 0
        GroupAssignments = 0
        ServiceAccountAdmins = 0
        StaleAdminAccounts = 0
        AdminsWithoutCA = 0
    }
    
    # Entra ID statistics
    if ($AuditData.EntraIDRoles) {
        foreach ($role in $AuditData.EntraIDRoles) {
            $stats.TotalEntraIDAdmins += $role.MemberCount
            
            if ($role.CriticalityLevel -eq "Critical") {
                $stats.CriticalRoleCount++
            } elseif ($role.CriticalityLevel -eq "High") {
                $stats.HighRiskRoleCount++
            }
            
            foreach ($member in $role.Members) {
                if ($member.UserPrincipalName) {
                    $stats.TotalUniqueAdmins += $member.UserPrincipalName
                }
            }
        }
    }
    
    # PIM statistics
    if ($AuditData.PIMAssignments) {
        $stats.PIMEligibleCount = ($AuditData.PIMAssignments | Where-Object { $_.AssignmentType -eq "Eligible" }).Count
        $stats.PIMActiveCount = ($AuditData.PIMAssignments | Where-Object { $_.AssignmentType -eq "Activated" }).Count
    }
    
    # Exchange statistics
    if ($AuditData.ExchangeOnlineRoles) {
        foreach ($roleGroup in $AuditData.ExchangeOnlineRoles.RoleGroups) {
            $stats.TotalExchangeAdmins += $roleGroup.MemberCount
            
            foreach ($member in $roleGroup.Members) {
                if ($member.Name) {
                    $stats.TotalUniqueAdmins += $member.Name
                }
            }
        }
        
        $stats.DirectAssignments += $AuditData.ExchangeOnlineRoles.TotalDirectAssignments
    }
    
    if ($AuditData.ExchangeOnPremRoles) {
        foreach ($roleGroup in $AuditData.ExchangeOnPremRoles.RoleGroups) {
            $stats.TotalExchangeAdmins += $roleGroup.MemberCount
        }
    }
    
    $stats.TotalUniqueAdmins = ($stats.TotalUniqueAdmins | Select-Object -Unique).Count
    
    return $stats
}

function Find-PrivilegedAccessComplianceIssues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$AuditData
    )
    
    $issues = @()
    
    # Check for accounts in multiple critical roles
    $adminRoleMembership = @{}
    
    if ($AuditData.EntraIDRoles) {
        foreach ($role in $AuditData.EntraIDRoles | Where-Object { $_.CriticalityLevel -in @("Critical", "High") }) {
            foreach ($member in $role.Members) {
                if ($member.UserPrincipalName) {
                    if (-not $adminRoleMembership[$member.UserPrincipalName]) {
                        $adminRoleMembership[$member.UserPrincipalName] = @()
                    }
                    $adminRoleMembership[$member.UserPrincipalName] += $role.DisplayName
                }
            }
        }
    }
    
    foreach ($admin in $adminRoleMembership.Keys) {
        if ($adminRoleMembership[$admin].Count -gt 2) {
            $issues += "User $admin has excessive role assignments: $($adminRoleMembership[$admin] -join ', ')"
        }
    }
    
    # Check for service accounts with admin roles
    $serviceAccountPatterns = @('svc', 'service', 'app', 'daemon', 'system')
    foreach ($role in $AuditData.EntraIDRoles) {
        foreach ($member in $role.Members) {
            foreach ($pattern in $serviceAccountPatterns) {
                if ($member.UserPrincipalName -match $pattern) {
                    $issues += "Potential service account in admin role: $($member.UserPrincipalName) in $($role.DisplayName)"
                    break
                }
            }
        }
    }
    
    # Check for disabled accounts with roles
    foreach ($role in $AuditData.EntraIDRoles) {
        foreach ($member in $role.Members | Where-Object { $_.AccountEnabled -eq $false }) {
            $issues += "Disabled account has admin role: $($member.UserPrincipalName) in $($role.DisplayName)"
        }
    }
    
    # Check Exchange direct assignments
    if ($AuditData.ExchangeOnlineRoles -and $AuditData.ExchangeOnlineRoles.DirectAssignments.Count -gt 0) {
        $issues += "Found $($AuditData.ExchangeOnlineRoles.DirectAssignments.Count) direct Exchange role assignments (should use role groups)"
    }
    
    # Check for roles without Conditional Access
    if ($AuditData.ConditionalAccessPolicies) {
        $protectedRoles = $AuditData.ConditionalAccessPolicies | ForEach-Object { $_.IncludedRoles } | Select-Object -Unique
        
        foreach ($role in $AuditData.EntraIDRoles | Where-Object { $_.CriticalityLevel -in @("Critical", "High") }) {
            if ($role.DisplayName -notin $protectedRoles) {
                $issues += "Critical role without Conditional Access protection: $($role.DisplayName)"
            }
        }
    }
    
    return $issues
}

function New-PrivilegedAccessHTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$AuditData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Privileged Access Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 40px 0; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .metadata { background: #1e293b; color: white; padding: 20px; margin-bottom: 30px; border-radius: 8px; }
        .metadata table { width: 100%; }
        .metadata td { padding: 8px; }
        .metadata td:first-child { font-weight: bold; width: 200px; }
        .section { background: white; padding: 30px; margin-bottom: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .section h2 { color: #1e3a8a; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #3b82f6; }
        .section h3 { color: #334155; margin: 20px 0 15px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #cbd5e1; }
        .stat-card.critical { background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-color: #f87171; }
        .stat-card.warning { background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border-color: #fbbf24; }
        .stat-card.success { background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%); border-color: #34d399; }
        .stat-card h3 { color: #1e293b; font-size: 2.5em; margin: 10px 0; }
        .stat-card p { color: #64748b; font-size: 1.1em; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #3b82f6; color: white; padding: 12px; text-align: left; position: sticky; top: 0; z-index: 10; }
        td { padding: 10px; border-bottom: 1px solid #e5e7eb; }
        tr:hover { background: #f8fafc; }
        .critical-role { background: #fee2e2; }
        .high-role { background: #fef3c7; }
        .status-enabled { color: #059669; font-weight: bold; }
        .status-disabled { color: #dc2626; font-weight: bold; }
        .compliance-issue { background: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .tabs { display: flex; border-bottom: 2px solid #e5e7eb; margin-bottom: 20px; }
        .tab { padding: 10px 20px; cursor: pointer; background: #f3f4f6; border: none; font-size: 16px; transition: all 0.3s; }
        .tab:hover { background: #e5e7eb; }
        .tab.active { background: #3b82f6; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-critical { background: #dc2626; color: white; }
        .badge-high { background: #f59e0b; color: white; }
        .badge-medium { background: #3b82f6; color: white; }
        .badge-low { background: #6b7280; color: white; }
        .timeline { position: relative; padding: 20px 0; }
        .timeline-item { display: flex; margin-bottom: 20px; }
        .timeline-time { width: 150px; text-align: right; padding-right: 20px; color: #6b7280; }
        .timeline-content { flex: 1; padding-left: 20px; border-left: 2px solid #e5e7eb; position: relative; }
        .timeline-content::before { content: ''; position: absolute; left: -6px; top: 5px; width: 10px; height: 10px; border-radius: 50%; background: #3b82f6; }
        @media print {
            .no-print { display: none; }
            .section { page-break-inside: avoid; }
            body { background: white; }
        }
    </style>
</head>
<body>
    <header>
        <h1>Unified Privileged Access Report</h1>
        <p>Comprehensive audit of administrative roles across Microsoft 365 and on-premise systems</p>
    </header>
    
    <div class="container">
        <div class="metadata">
            <table>
                <tr>
                    <td>Report Generated:</td>
                    <td>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</td>
                </tr>
                <tr>
                    <td>Tenant ID:</td>
                    <td>$(if ($AuditData.TenantId) { $AuditData.TenantId } else { "Not specified" })</td>
                </tr>
                <tr>
                    <td>Generated By:</td>
                    <td>$env:USERNAME</td>
                </tr>
                <tr>
                    <td>Audit Scope:</td>
                    <td>Entra ID, Exchange Online$(if ($AuditData.ExchangeOnPremRoles) { ", Exchange On-Premise" })</td>
                </tr>
            </table>
        </div>
"@

    # Add compliance issues if any
    if ($AuditData.ComplianceIssues.Count -gt 0) {
        $htmlContent += @"
        <section class="section">
            <h2>* Compliance Issues ($($AuditData.ComplianceIssues.Count))</h2>
"@
        foreach ($issue in $AuditData.ComplianceIssues) {
            $htmlContent += "<div class='compliance-issue'>$issue</div>"
        }
        $htmlContent += "</section>"
    }

    # Add statistics
    $htmlContent += @"
        <section class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <p>Total Unique Admins</p>
                    <h3>$($AuditData.Statistics.TotalUniqueAdmins)</h3>
                </div>
                <div class="stat-card $(if ($AuditData.Statistics.CriticalRoleCount -gt 0) { 'critical' })">
                    <p>Critical Roles</p>
                    <h3>$($AuditData.Statistics.CriticalRoleCount)</h3>
                </div>
                <div class="stat-card">
                    <p>Entra ID Admins</p>
                    <h3>$($AuditData.Statistics.TotalEntraIDAdmins)</h3>
                </div>
                <div class="stat-card">
                    <p>Exchange Admins</p>
                    <h3>$($AuditData.Statistics.TotalExchangeAdmins)</h3>
                </div>
"@

    if ($AuditData.PIMAssignments) {
        $htmlContent += @"
                <div class="stat-card">
                    <p>PIM Eligible</p>
                    <h3>$($AuditData.Statistics.PIMEligibleCount)</h3>
                </div>
                <div class="stat-card warning">
                    <p>PIM Active</p>
                    <h3>$($AuditData.Statistics.PIMActiveCount)</h3>
                </div>
"@
    }

    $htmlContent += @"
            </div>
        </section>
        
        <section class="section">
            <h2>Administrative Roles</h2>
            <div class="tabs no-print">
                <button class="tab active" onclick="showTab('entra-roles')">Entra ID Roles</button>
                <button class="tab" onclick="showTab('exchange-roles')">Exchange Roles</button>
"@

    if ($AuditData.PIMAssignments) {
        $htmlContent += "<button class=`"tab`" onclick=`"showTab('pim-assignments')`">PIM Assignments</button>"
    }
    
    if ($AuditData.RoleHistory) {
        $htmlContent += "<button class=`"tab`" onclick=`"showTab('role-history')`">Role History</button>"
    }

    $htmlContent += @"
            </div>
            
            <div id="entra-roles" class="tab-content active">
                <h3>Entra ID Directory Roles</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Role Name</th>
                            <th>Criticality</th>
                            <th>Members</th>
                            <th>Type</th>
                            <th>Created</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    foreach ($role in $AuditData.EntraIDRoles | Sort-Object -Property @{Expression={
        switch ($_.CriticalityLevel) {
            "Critical" { 1 }
            "High" { 2 }
            "Medium" { 3 }
            "Low" { 4 }
            default { 5 }
        }
    }}, DisplayName) {
        $rowClass = switch ($role.CriticalityLevel) {
            "Critical" { "critical-role" }
            "High" { "high-role" }
            default { "" }
        }
        
        $htmlContent += @"
                        <tr class="$rowClass">
                            <td><strong>$($role.DisplayName)</strong></td>
                            <td><span class="badge badge-$($role.CriticalityLevel.ToLower())">$($role.CriticalityLevel)</span></td>
                            <td>$($role.MemberCount)</td>
                            <td>$(if ($role.IsBuiltIn) { "Built-in" } else { "Custom" })</td>
                            <td>$($role.CreatedDateTime)</td>
                        </tr>
"@
        
        if ($role.Members.Count -gt 0) {
            $htmlContent += @"
                        <tr>
                            <td colspan="5" style="padding-left: 40px;">
                                <details>
                                    <summary style="cursor: pointer;">View Members ($($role.MemberCount))</summary>
                                    <table style="margin: 10px 0;">
                                        <tr>
                                            <th>Display Name</th>
                                            <th>UPN</th>
                                            <th>Type</th>
                                            <th>Status</th>
                                        </tr>
"@
            foreach ($member in $role.Members) {
                $statusClass = if ($member.AccountEnabled) { "status-enabled" } else { "status-disabled" }
                $statusText = if ($member.AccountEnabled) { "Enabled" } else { "Disabled" }
                
                $htmlContent += @"
                                        <tr>
                                            <td>$($member.DisplayName)</td>
                                            <td>$($member.UserPrincipalName)</td>
                                            <td>$($member.Type)</td>
                                            <td class="$statusClass">$statusText</td>
                                        </tr>
"@
            }
            $htmlContent += @"
                                    </table>
                                </details>
                            </td>
                        </tr>
"@
        }
    }

    $htmlContent += @"
                    </tbody>
                </table>
            </div>
            
            <div id="exchange-roles" class="tab-content">
"@

    if ($AuditData.ExchangeOnlineRoles) {
        $htmlContent += @"
                <h3>Exchange Online Role Groups</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Role Group</th>
                            <th>Description</th>
                            <th>Members</th>
                            <th>Type</th>
                            <th>Assigned Roles</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($roleGroup in $AuditData.ExchangeOnlineRoles.RoleGroups) {
            $htmlContent += @"
                        <tr>
                            <td><strong>$($roleGroup.Name)</strong></td>
                            <td>$($roleGroup.Description)</td>
                            <td>$($roleGroup.MemberCount)</td>
                            <td>$(if ($roleGroup.IsBuiltIn) { "Built-in" } else { "Custom" })</td>
                            <td>$($roleGroup.AssignedRoles.Count) roles</td>
                        </tr>
"@
        }
        $htmlContent += "</tbody></table>"
        
        if ($AuditData.ExchangeOnlineRoles.DirectAssignments.Count -gt 0) {
            $htmlContent += @"
                <h3>Direct Role Assignments (Non-Compliant)</h3>
                <div class="compliance-issue">
                    Found $($AuditData.ExchangeOnlineRoles.DirectAssignments.Count) direct role assignments. Best practice is to use role groups.
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Role</th>
                            <th>Assignee</th>
                            <th>Type</th>
                            <th>Enabled</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            foreach ($assignment in $AuditData.ExchangeOnlineRoles.DirectAssignments) {
                $htmlContent += @"
                        <tr>
                            <td>$($assignment.Role)</td>
                            <td>$($assignment.RoleAssignee)</td>
                            <td>$($assignment.RoleAssigneeType)</td>
                            <td>$($assignment.Enabled)</td>
                        </tr>
"@
            }
            $htmlContent += "</tbody></table>"
        }
    }

    if ($AuditData.ExchangeOnPremRoles) {
        $htmlContent += @"
                <h3>Exchange On-Premise Role Groups ($($AuditData.ExchangeOnPremRoles.ServerName))</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Role Group</th>
                            <th>Members</th>
                            <th>Type</th>
                            <th>Linked Group</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($roleGroup in $AuditData.ExchangeOnPremRoles.RoleGroups) {
            $htmlContent += @"
                        <tr>
                            <td><strong>$($roleGroup.Name)</strong></td>
                            <td>$($roleGroup.MemberCount)</td>
                            <td>$($roleGroup.RoleGroupType)</td>
                            <td>$(if ($roleGroup.LinkedGroup) { $roleGroup.LinkedGroup } else { "N/A" })</td>
                        </tr>
"@
        }
        $htmlContent += "</tbody></table>"
    }

    $htmlContent += "</div>"

    # PIM Assignments tab
    if ($AuditData.PIMAssignments) {
        $htmlContent += @"
            <div id="pim-assignments" class="tab-content">
                <h3>Privileged Identity Management (PIM) Assignments</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Role</th>
                            <th>Principal</th>
                            <th>Type</th>
                            <th>Assignment</th>
                            <th>Status</th>
                            <th>Start</th>
                            <th>End</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($pim in $AuditData.PIMAssignments | Sort-Object RoleDisplayName, PrincipalName) {
            $statusClass = switch ($pim.Status) {
                "Active" { "status-enabled" }
                "Expired" { "status-disabled" }
                default { "" }
            }
            
            $htmlContent += @"
                        <tr>
                            <td>$($pim.RoleDisplayName)</td>
                            <td>$($pim.PrincipalName)</td>
                            <td>$($pim.PrincipalType)</td>
                            <td>$($pim.AssignmentType)</td>
                            <td class="$statusClass">$($pim.Status)</td>
                            <td>$($pim.StartDateTime)</td>
                            <td>$($pim.EndDateTime)</td>
                        </tr>
"@
        }
        $htmlContent += "</tbody></table></div>"
    }

    # Role History tab
    if ($AuditData.RoleHistory) {
        $htmlContent += @"
            <div id="role-history" class="tab-content">
                <h3>Role Assignment History (Last $AuditDaysBack Days)</h3>
                <div class="timeline">
"@
        foreach ($change in $AuditData.RoleHistory | Select-Object -First 50) {
            $htmlContent += @"
                    <div class="timeline-item">
                        <div class="timeline-time">$($change.Timestamp)</div>
                        <div class="timeline-content">
                            <strong>$($change.Activity)</strong><br>
                            Initiated by: $($change.InitiatedBy)<br>
"@
            if ($change.TargetResources.Count -gt 0) {
                $htmlContent += "Target: $($change.TargetResources[0].DisplayName)<br>"
            }
            $htmlContent += "Result: $($change.Result)</div></div>"
        }
        $htmlContent += "</div></div>"
    }

    $htmlContent += @"
        </section>
    </div>
    
    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }
    </script>
</body>
</html>
"@

    $reportDir = Split-Path $OutputPath -Parent
    if (!(Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Also save JSON data for baseline comparison
    $jsonPath = $OutputPath -replace '\.html$', '_data.json'
    $AuditData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    return $OutputPath
}

Export-ModuleMember -Function New-UnifiedPrivilegedAccessReport
