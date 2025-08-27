# Enhanced Azure AD Audit Module  
# Comprehensive Azure AD/Entra ID privileged access and security auditing

function Start-AzureADEnhancedAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludePIM,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeConditionalAccess,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeServicePrincipals,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeAuditLogs,
        
        [Parameter(Mandatory=$false)]
        [int]$AuditDaysBack = 30,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshots
    )
    
    Write-Host "Starting Enhanced Azure AD Audit..." -ForegroundColor Cyan
    
    $auditResults = @{
        DirectoryRoles = @()
        PIMRoles = @()
        ConditionalAccessPolicies = @()
        ServicePrincipals = @()
        Applications = @()
        AuditLogs = @()
        Users = @()
        Groups = @()
        Statistics = @{}
        Screenshots = @()
    }
    
    $auditStartTime = Get-Date
    
    try {
        # Check if AzureAD/Microsoft.Graph modules are available
        $graphAvailable = Get-Module -ListAvailable -Name "Microsoft.Graph*"
        $azureADAvailable = Get-Module -ListAvailable -Name "AzureAD"
        
        if (!$graphAvailable -and !$azureADAvailable) {
            Write-Warning "Neither Microsoft.Graph nor AzureAD PowerShell modules are installed."
            Write-Host "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
            return $null
        }
        
        # Connect to Microsoft Graph or Azure AD
        if ($graphAvailable) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
            $connectParams = @{
                Scopes = @(
                    "Directory.Read.All",
                    "RoleManagement.Read.All", 
                    "Policy.Read.All",
                    "Application.Read.All",
                    "AuditLog.Read.All",
                    "PrivilegedAccess.Read.AzureAD"
                )
            }
            if ($TenantId) { $connectParams.TenantId = $TenantId }
            if ($ClientId) { $connectParams.ClientId = $ClientId }
            
            Connect-MgGraph @connectParams
            $useGraph = $true
        } else {
            Write-Host "Connecting to Azure AD..." -ForegroundColor Yellow
            $connectParams = @{}
            if ($TenantId) { $connectParams.TenantId = $TenantId }
            
            Connect-AzureAD @connectParams
            $useGraph = $false
        }
        
        # 1. Directory Roles Audit
        Write-Host "`nAuditing Azure AD Directory Roles..." -ForegroundColor Yellow
        
        if ($useGraph) {
            $directoryRoles = Get-MgDirectoryRole -All | ForEach-Object {
                $role = $_
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                
                foreach ($member in $members) {
                    $memberDetails = $null
                    if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                        $memberDetails = Get-MgUser -UserId $member.Id
                    } elseif ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                        $memberDetails = Get-MgServicePrincipal -ServicePrincipalId $member.Id
                    }
                    
                    [PSCustomObject]@{
                        RoleName = $role.DisplayName
                        RoleId = $role.Id
                        MemberId = $member.Id
                        MemberName = if ($memberDetails) { $memberDetails.DisplayName } else { "Unknown" }
                        MemberType = if ($member.AdditionalProperties.'@odata.type') { $member.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' } else { "Unknown" }
                        MemberUPN = if ($memberDetails.UserPrincipalName) { $memberDetails.UserPrincipalName } else { "N/A" }
                        MemberEnabled = if ($memberDetails.AccountEnabled -ne $null) { $memberDetails.AccountEnabled } else { $true }
                        AssignmentType = "Permanent"
                        RiskLevel = Get-AzureADRoleRisk -RoleName $role.DisplayName
                        AuditDate = Get-Date
                    }
                }
            }
        } else {
            $directoryRoles = Get-AzureADDirectoryRole | ForEach-Object {
                $role = $_
                $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
                
                foreach ($member in $members) {
                    [PSCustomObject]@{
                        RoleName = $role.DisplayName
                        RoleId = $role.ObjectId
                        MemberId = $member.ObjectId
                        MemberName = $member.DisplayName
                        MemberType = $member.ObjectType
                        MemberUPN = $member.UserPrincipalName
                        MemberEnabled = $member.AccountEnabled
                        AssignmentType = "Permanent"
                        RiskLevel = Get-AzureADRoleRisk -RoleName $role.DisplayName
                        AuditDate = Get-Date
                    }
                }
            }
        }
        
        $auditResults.DirectoryRoles = $directoryRoles
        Write-Host "Found $($directoryRoles.Count) directory role assignments" -ForegroundColor Green
        
        # 2. PIM Roles Audit (if requested and available)
        if ($IncludePIM -and $useGraph) {
            Write-Host "`nAuditing PIM Role Assignments..." -ForegroundColor Yellow
            
            try {
                $pimRoles = Get-MgRoleManagementDirectoryRoleAssignment -All | ForEach-Object {
                    $assignment = $_
                    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId
                    $principal = $null
                    
                    try {
                        if ($assignment.PrincipalId) {
                            $principal = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
                            if (!$principal) {
                                $principal = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue
                            }
                        }
                    } catch { }
                    
                    [PSCustomObject]@{
                        RoleName = $roleDefinition.DisplayName
                        RoleId = $assignment.RoleDefinitionId
                        MemberId = $assignment.PrincipalId
                        MemberName = if ($principal) { $principal.DisplayName } else { "Unknown Principal" }
                        MemberType = if ($principal.UserPrincipalName) { "User" } else { "ServicePrincipal" }
                        MemberUPN = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } else { "N/A" }
                        MemberEnabled = if ($principal.AccountEnabled -ne $null) { $principal.AccountEnabled } else { $true }
                        AssignmentType = "PIM"
                        StartDateTime = $assignment.ScheduleInfo.StartDateTime
                        EndDateTime = $assignment.ScheduleInfo.Expiration.EndDateTime
                        RiskLevel = Get-AzureADRoleRisk -RoleName $roleDefinition.DisplayName
                        AuditDate = Get-Date
                    }
                }
                
                $auditResults.PIMRoles = $pimRoles
                Write-Host "Found $($pimRoles.Count) PIM role assignments" -ForegroundColor Green
                
            } catch {
                Write-Warning "PIM audit failed: $_"
            }
        }
        
        # 3. Conditional Access Policies
        if ($IncludeConditionalAccess -and $useGraph) {
            Write-Host "`nAuditing Conditional Access Policies..." -ForegroundColor Yellow
            
            try {
                $caPolicies = Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {
                    $policy = $_
                    
                    [PSCustomObject]@{
                        PolicyName = $policy.DisplayName
                        PolicyId = $policy.Id
                        State = $policy.State
                        CreatedDateTime = $policy.CreatedDateTime
                        ModifiedDateTime = $policy.ModifiedDateTime
                        IncludeUsers = ($policy.Conditions.Users.IncludeUsers -join "; ")
                        ExcludeUsers = ($policy.Conditions.Users.ExcludeUsers -join "; ")
                        IncludeGroups = ($policy.Conditions.Users.IncludeGroups -join "; ")
                        ExcludeGroups = ($policy.Conditions.Users.ExcludeGroups -join "; ")
                        IncludeRoles = ($policy.Conditions.Users.IncludeRoles -join "; ")
                        ExcludeRoles = ($policy.Conditions.Users.ExcludeRoles -join "; ")
                        Applications = ($policy.Conditions.Applications.IncludeApplications -join "; ")
                        GrantControls = ($policy.GrantControls.BuiltInControls -join "; ")
                        SessionControls = if ($policy.SessionControls) { "Configured" } else { "None" }
                        RiskLevel = if ($policy.State -eq "enabled" -and $policy.Conditions.Users.IncludeUsers -contains "All") { "High" } else { "Medium" }
                        AuditDate = Get-Date
                    }
                }
                
                $auditResults.ConditionalAccessPolicies = $caPolicies
                Write-Host "Found $($caPolicies.Count) Conditional Access policies" -ForegroundColor Green
                
            } catch {
                Write-Warning "Conditional Access audit failed: $_"
            }
        }
        
        # 4. Service Principals and Applications
        if ($IncludeServicePrincipals) {
            Write-Host "`nAuditing Service Principals and Applications..." -ForegroundColor Yellow
            
            if ($useGraph) {
                $servicePrincipals = Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -ne "ManagedIdentity" } | ForEach-Object {
                    $sp = $_
                    
                    [PSCustomObject]@{
                        DisplayName = $sp.DisplayName
                        AppId = $sp.AppId
                        ObjectId = $sp.Id
                        ServicePrincipalType = $sp.ServicePrincipalType
                        AccountEnabled = $sp.AccountEnabled
                        CreatedDateTime = $sp.AdditionalProperties.createdDateTime
                        PublisherName = $sp.PublisherName
                        Homepage = $sp.Homepage
                        ReplyUrls = ($sp.ReplyUrls -join "; ")
                        AppRoles = ($sp.AppRoles | ForEach-Object { $_.DisplayName }) -join "; "
                        OAuth2Permissions = ($sp.Oauth2PermissionScopes | ForEach-Object { $_.Value }) -join "; "
                        PasswordCredentials = if ($sp.PasswordCredentials) { $sp.PasswordCredentials.Count } else { 0 }
                        KeyCredentials = if ($sp.KeyCredentials) { $sp.KeyCredentials.Count } else { 0 }
                        RiskLevel = Get-ServicePrincipalRisk -ServicePrincipal $sp
                        AuditDate = Get-Date
                    }
                }
            } else {
                $servicePrincipals = Get-AzureADServicePrincipal -All $true | ForEach-Object {
                    $sp = $_
                    
                    [PSCustomObject]@{
                        DisplayName = $sp.DisplayName
                        AppId = $sp.AppId
                        ObjectId = $sp.ObjectId
                        ServicePrincipalType = $sp.ServicePrincipalType
                        AccountEnabled = $sp.AccountEnabled
                        CreatedDateTime = "N/A"
                        PublisherName = "N/A"
                        Homepage = $sp.Homepage
                        ReplyUrls = ($sp.ReplyUrls -join "; ")
                        AppRoles = ($sp.AppRoles | ForEach-Object { $_.DisplayName }) -join "; "
                        OAuth2Permissions = ($sp.Oauth2Permissions | ForEach-Object { $_.Value }) -join "; "
                        PasswordCredentials = if ($sp.PasswordCredentials) { $sp.PasswordCredentials.Count } else { 0 }
                        KeyCredentials = if ($sp.KeyCredentials) { $sp.KeyCredentials.Count } else { 0 }
                        RiskLevel = Get-ServicePrincipalRisk -ServicePrincipal $sp
                        AuditDate = Get-Date
                    }
                }
            }
            
            $auditResults.ServicePrincipals = $servicePrincipals
            Write-Host "Found $($servicePrincipals.Count) service principals" -ForegroundColor Green
        }
        
        # 5. Generate Statistics
        $auditResults.Statistics = @{
            TotalDirectoryRoles = ($auditResults.DirectoryRoles | Select-Object -Property RoleName -Unique).Count
            TotalDirectoryRoleAssignments = $auditResults.DirectoryRoles.Count
            TotalPIMAssignments = $auditResults.PIMRoles.Count
            HighRiskRoleAssignments = ($auditResults.DirectoryRoles + $auditResults.PIMRoles | Where-Object { $_.RiskLevel -eq "High" }).Count
            DisabledMembers = ($auditResults.DirectoryRoles + $auditResults.PIMRoles | Where-Object { $_.MemberEnabled -eq $false }).Count
            ConditionalAccessPolicies = $auditResults.ConditionalAccessPolicies.Count
            EnabledCAPolicies = ($auditResults.ConditionalAccessPolicies | Where-Object { $_.State -eq "enabled" }).Count
            ServicePrincipals = $auditResults.ServicePrincipals.Count
            HighRiskServicePrincipals = ($auditResults.ServicePrincipals | Where-Object { $_.RiskLevel -eq "High" }).Count
            AuditDuration = (Get-Date) - $auditStartTime
        }
        
        Write-Host "`nAzure AD Audit Summary:" -ForegroundColor Cyan
        Write-Host "  Directory Role Assignments: $($auditResults.Statistics.TotalDirectoryRoleAssignments)" -ForegroundColor White
        Write-Host "  PIM Assignments: $($auditResults.Statistics.TotalPIMAssignments)" -ForegroundColor White
        Write-Host "  High Risk Assignments: $($auditResults.Statistics.HighRiskRoleAssignments)" -ForegroundColor $(if ($auditResults.Statistics.HighRiskRoleAssignments -gt 0) { "Red" } else { "Green" })
        Write-Host "  Conditional Access Policies: $($auditResults.Statistics.EnabledCAPolicies)/$($auditResults.Statistics.ConditionalAccessPolicies) enabled" -ForegroundColor White
        Write-Host "  Service Principals: $($auditResults.Statistics.ServicePrincipals)" -ForegroundColor White
        Write-Host "  High Risk Service Principals: $($auditResults.Statistics.HighRiskServicePrincipals)" -ForegroundColor $(if ($auditResults.Statistics.HighRiskServicePrincipals -gt 0) { "Yellow" } else { "Green" })
        
        return $auditResults
        
    } catch {
        Write-Error "Azure AD audit failed: $_"
        return $null
    }
}

function Get-AzureADRoleRisk {
    param([string]$RoleName)
    
    $highRiskRoles = @(
        "Global Administrator",
        "Privileged Role Administrator", 
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Security Administrator",
        "Conditional Access Administrator",
        "Authentication Administrator",
        "Privileged Authentication Administrator"
    )
    
    if ($RoleName -in $highRiskRoles) {
        return "High"
    } elseif ($RoleName -match "Administrator|Admin") {
        return "Medium"
    } else {
        return "Low"
    }
}

function Get-ServicePrincipalRisk {
    param($ServicePrincipal)
    
    $risk = "Low"
    
    # High-risk indicators
    if ($ServicePrincipal.AppRoles -match "RoleManagement|Directory|Application" -or
        $ServicePrincipal.OAuth2Permissions -match "Directory.ReadWrite.All|RoleManagement.ReadWrite.Directory") {
        $risk = "High"
    }
    
    # Multiple credentials
    if (($ServicePrincipal.PasswordCredentials + $ServicePrincipal.KeyCredentials) -gt 3) {
        $risk = "Medium"
    }
    
    # Disabled but has credentials
    if (!$ServicePrincipal.AccountEnabled -and ($ServicePrincipal.PasswordCredentials -gt 0 -or $ServicePrincipal.KeyCredentials -gt 0)) {
        $risk = "High"
    }
    
    return $risk
}

function Export-AzureADAuditReports {
    param(
        [Parameter(Mandatory=$true)]
        $AuditResults,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reports = @()
    
    # Export Directory Roles
    if ($AuditResults.DirectoryRoles.Count -gt 0) {
        $path = "$OutputDirectory\AzureAD_DirectoryRoles_$timestamp.csv"
        $AuditResults.DirectoryRoles | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export PIM Roles  
    if ($AuditResults.PIMRoles.Count -gt 0) {
        $path = "$OutputDirectory\AzureAD_PIMRoles_$timestamp.csv"
        $AuditResults.PIMRoles | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Conditional Access
    if ($AuditResults.ConditionalAccessPolicies.Count -gt 0) {
        $path = "$OutputDirectory\AzureAD_ConditionalAccess_$timestamp.csv"
        $AuditResults.ConditionalAccessPolicies | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Service Principals
    if ($AuditResults.ServicePrincipals.Count -gt 0) {
        $path = "$OutputDirectory\AzureAD_ServicePrincipals_$timestamp.csv"
        $AuditResults.ServicePrincipals | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Statistics
    $statsPath = "$OutputDirectory\AzureAD_Statistics_$timestamp.csv"
    $AuditResults.Statistics.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Metric = $_.Key
            Value = $_.Value
        }
    } | Export-Csv -Path $statsPath -NoTypeInformation
    $reports += $statsPath
    
    Write-Host "Azure AD audit reports exported:" -ForegroundColor Green
    $reports | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    
    return $reports
}