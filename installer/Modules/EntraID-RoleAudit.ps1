# Entra ID (Azure AD) Role Audit Module

. "$PSScriptRoot\MSGraph-Authentication.ps1"

function Get-EntraIDAdminRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$IncludeBuiltInOnly,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeCustomRoles,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands
    )
    
    try {
        # Import code capture module if needed
        if ($CaptureCommands -and (Test-Path "$PSScriptRoot\Audit-CodeCapture.ps1")) {
            . "$PSScriptRoot\Audit-CodeCapture.ps1"
        }
        
        Write-Verbose "Retrieving Entra ID directory roles..."
        
        # Get all directory roles
        if ($CaptureCommands) {
            $cmd = 'Invoke-MSGraphRequest -Uri "directoryRoles"'
            Add-AuditCommand -CommandName "Get-DirectoryRoles" -CommandText $cmd -Description "Retrieving all Entra ID directory roles via Microsoft Graph API" -CaptureScreenshot
        }
        $roles = Invoke-MSGraphRequest -Uri "directoryRoles"
        
        # Get role templates for additional info
        $roleTemplates = Invoke-MSGraphRequest -Uri "directoryRoleTemplates"
        $templateLookup = @{}
        foreach ($template in $roleTemplates) {
            $templateLookup[$template.id] = $template
        }
        
        $roleDetails = @()
        
        foreach ($role in $roles) {
            $template = $templateLookup[$role.roleTemplateId]
            
            $roleInfo = [PSCustomObject]@{
                RoleId = $role.id
                RoleTemplateId = $role.roleTemplateId
                DisplayName = $role.displayName
                Description = $role.description
                IsBuiltIn = $true
                IsActivated = $true
                CreatedDateTime = $role.createdDateTime
                Members = @()
                MemberCount = 0
                CriticalityLevel = Get-RoleCriticalityLevel -RoleName $role.displayName
            }
            
            # Get role members
            try {
                if ($CaptureCommands -and $roleDetails.Count -eq 0) {  # Capture once as example
                    $cmd = "Invoke-MSGraphRequest -Uri `"directoryRoles/$($role.id)/members`""
                    Add-AuditCommand -CommandName "Get-RoleMembers" -CommandText $cmd -Description "Retrieving members for role: $($role.displayName)" -CaptureScreenshot
                }
                $members = Invoke-MSGraphRequest -Uri "directoryRoles/$($role.id)/members"
                
                foreach ($member in $members) {
                    $memberDetails = [PSCustomObject]@{
                        Id = $member.id
                        DisplayName = $member.displayName
                        UserPrincipalName = $member.userPrincipalName
                        Type = $member.'@odata.type' -replace '#microsoft.graph.', ''
                        AssignedDateTime = $null
                        AccountEnabled = $member.accountEnabled
                    }
                    
                    $roleInfo.Members += $memberDetails
                }
                
                $roleInfo.MemberCount = $roleInfo.Members.Count
            } catch {
                Write-Warning "Failed to get members for role: $($role.displayName)"
            }
            
            $roleDetails += $roleInfo
        }
        
        # Get custom roles if requested
        if ($IncludeCustomRoles) {
            Write-Verbose "Retrieving custom role definitions..."
            $customRoles = Invoke-MSGraphRequest -Uri "roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false"
            
            foreach ($customRole in $customRoles) {
                $roleInfo = [PSCustomObject]@{
                    RoleId = $customRole.id
                    RoleTemplateId = $customRole.templateId
                    DisplayName = $customRole.displayName
                    Description = $customRole.description
                    IsBuiltIn = $customRole.isBuiltIn
                    IsActivated = $customRole.isEnabled
                    CreatedDateTime = $customRole.createdDateTime
                    Members = @()
                    MemberCount = 0
                    CriticalityLevel = "Custom"
                    Permissions = $customRole.rolePermissions
                }
                
                # Get assignments for custom role
                $assignments = Invoke-MSGraphRequest -Uri "roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($customRole.id)'"
                
                foreach ($assignment in $assignments) {
                    try {
                        $principal = Invoke-MSGraphRequest -Uri "directoryObjects/$($assignment.principalId)"
                        
                        $memberDetails = [PSCustomObject]@{
                            Id = $principal.id
                            DisplayName = $principal.displayName
                            UserPrincipalName = $principal.userPrincipalName
                            Type = $principal.'@odata.type' -replace '#microsoft.graph.', ''
                            AssignedDateTime = $assignment.createdDateTime
                            AccountEnabled = $principal.accountEnabled
                        }
                        
                        $roleInfo.Members += $memberDetails
                    } catch {
                        Write-Warning "Failed to get principal details for assignment"
                    }
                }
                
                $roleInfo.MemberCount = $roleInfo.Members.Count
                $roleDetails += $roleInfo
            }
        }
        
        return $roleDetails
        
    } catch {
        Write-Error "Failed to retrieve Entra ID roles: $_"
        throw
    }
}

function Get-EntraIDPIMRoles {
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Retrieving PIM eligible role assignments..."
        
        # Get eligible role assignments
        $eligibleAssignments = Invoke-MSGraphRequest -Uri "roleManagement/directory/roleEligibilityScheduleInstances"
        
        $pimDetails = @()
        
        foreach ($assignment in $eligibleAssignments) {
            # Get role definition
            $roleDefinition = Invoke-MSGraphRequest -Uri "roleManagement/directory/roleDefinitions/$($assignment.roleDefinitionId)"
            
            # Get principal details
            $principal = Invoke-MSGraphRequest -Uri "directoryObjects/$($assignment.principalId)"
            
            $pimInfo = [PSCustomObject]@{
                AssignmentId = $assignment.id
                RoleDisplayName = $roleDefinition.displayName
                RoleDescription = $roleDefinition.description
                PrincipalId = $principal.id
                PrincipalName = $principal.displayName
                PrincipalUPN = $principal.userPrincipalName
                PrincipalType = $principal.'@odata.type' -replace '#microsoft.graph.', ''
                AssignmentType = "Eligible"
                StartDateTime = $assignment.startDateTime
                EndDateTime = $assignment.endDateTime
                MemberType = $assignment.memberType
                Status = if ($assignment.endDateTime -lt (Get-Date)) { "Expired" } else { "Active" }
            }
            
            $pimDetails += $pimInfo
        }
        
        # Get active PIM assignments
        $activeAssignments = Invoke-MSGraphRequest -Uri "roleManagement/directory/roleAssignmentScheduleInstances"
        
        foreach ($assignment in $activeAssignments) {
            if ($assignment.assignmentType -eq "Activated") {
                $roleDefinition = Invoke-MSGraphRequest -Uri "roleManagement/directory/roleDefinitions/$($assignment.roleDefinitionId)"
                $principal = Invoke-MSGraphRequest -Uri "directoryObjects/$($assignment.principalId)"
                
                $pimInfo = [PSCustomObject]@{
                    AssignmentId = $assignment.id
                    RoleDisplayName = $roleDefinition.displayName
                    RoleDescription = $roleDefinition.description
                    PrincipalId = $principal.id
                    PrincipalName = $principal.displayName
                    PrincipalUPN = $principal.userPrincipalName
                    PrincipalType = $principal.'@odata.type' -replace '#microsoft.graph.', ''
                    AssignmentType = "Activated"
                    StartDateTime = $assignment.startDateTime
                    EndDateTime = $assignment.endDateTime
                    MemberType = $assignment.memberType
                    Status = "Active"
                    ActivatedDateTime = $assignment.activatedUsing.activatedDateTime
                }
                
                $pimDetails += $pimInfo
            }
        }
        
        return $pimDetails
        
    } catch {
        Write-Error "Failed to retrieve PIM roles: $_"
        throw
    }
}

function Get-EntraIDRoleAssignmentHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$DaysBack = 30
    )
    
    try {
        Write-Verbose "Retrieving role assignment audit logs..."
        
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
        $filter = "activityDateTime ge $startDate and category eq 'RoleManagement'"
        
        $auditLogs = Invoke-MSGraphRequest -Uri "auditLogs/directoryAudits?`$filter=$filter&`$orderby=activityDateTime desc"
        
        $roleChanges = @()
        
        foreach ($log in $auditLogs) {
            if ($log.activityDisplayName -match "Add member to role|Remove member from role|Activate role|Deactivate role") {
                $change = [PSCustomObject]@{
                    Timestamp = $log.activityDateTime
                    Activity = $log.activityDisplayName
                    InitiatedBy = if ($log.initiatedBy.user.displayName) { $log.initiatedBy.user.displayName } else { $log.initiatedBy.app.displayName }
                    InitiatedByUPN = $log.initiatedBy.user.userPrincipalName
                    Result = $log.result
                    TargetResources = @()
                    ModifiedProperties = @()
                    CorrelationId = $log.correlationId
                }
                
                foreach ($target in $log.targetResources) {
                    $change.TargetResources += [PSCustomObject]@{
                        Type = $target.type
                        DisplayName = $target.displayName
                        UserPrincipalName = $target.userPrincipalName
                        Id = $target.id
                    }
                }
                
                foreach ($prop in $log.targetResources.modifiedProperties) {
                    $change.ModifiedProperties += [PSCustomObject]@{
                        DisplayName = $prop.displayName
                        OldValue = $prop.oldValue
                        NewValue = $prop.newValue
                    }
                }
                
                $roleChanges += $change
            }
        }
        
        return $roleChanges
        
    } catch {
        Write-Error "Failed to retrieve role assignment history: $_"
        throw
    }
}

function Get-RoleCriticalityLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleName
    )
    
    $criticalRoles = @{
        "Global Administrator" = "Critical"
        "Privileged Role Administrator" = "Critical"
        "Security Administrator" = "Critical"
        "Exchange Administrator" = "High"
        "SharePoint Administrator" = "High"
        "User Administrator" = "High"
        "Billing Administrator" = "High"
        "Conditional Access Administrator" = "High"
        "Authentication Administrator" = "High"
        "Helpdesk Administrator" = "Medium"
        "Password Administrator" = "Medium"
        "Global Reader" = "Medium"
        "Reports Reader" = "Low"
        "Directory Readers" = "Low"
    }
    
    return if ($criticalRoles[$RoleName]) { $criticalRoles[$RoleName] } else { "Standard" }
}

function Get-EntraIDConditionalAccessForAdmins {
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Checking Conditional Access policies for admin roles..."
        
        $policies = Invoke-MSGraphRequest -Uri "identity/conditionalAccess/policies"
        
        $adminPolicies = @()
        
        foreach ($policy in $policies) {
            if ($policy.conditions.users.includeRoles -or $policy.conditions.users.excludeRoles) {
                $adminPolicy = [PSCustomObject]@{
                    PolicyId = $policy.id
                    PolicyName = $policy.displayName
                    State = $policy.state
                    CreatedDateTime = $policy.createdDateTime
                    ModifiedDateTime = $policy.modifiedDateTime
                    IncludedRoles = @()
                    ExcludedRoles = @()
                    GrantControls = $policy.grantControls
                    SessionControls = $policy.sessionControls
                    Conditions = $policy.conditions
                }
                
                # Resolve role names
                foreach ($roleId in $policy.conditions.users.includeRoles) {
                    try {
                        $role = Invoke-MSGraphRequest -Uri "directoryRoleTemplates/$roleId"
                        $adminPolicy.IncludedRoles += $role.displayName
                    } catch {
                        $adminPolicy.IncludedRoles += $roleId
                    }
                }
                
                foreach ($roleId in $policy.conditions.users.excludeRoles) {
                    try {
                        $role = Invoke-MSGraphRequest -Uri "directoryRoleTemplates/$roleId"
                        $adminPolicy.ExcludedRoles += $role.displayName
                    } catch {
                        $adminPolicy.ExcludedRoles += $roleId
                    }
                }
                
                $adminPolicies += $adminPolicy
            }
        }
        
        return $adminPolicies
        
    } catch {
        Write-Error "Failed to retrieve Conditional Access policies: $_"
        throw
    }
}

# Functions are automatically available when script is dot-sourced