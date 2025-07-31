# Exchange RBAC Audit Module (Online and On-Premise)

function Get-ExchangeOnlineRBACRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseModernAuth,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands
    )
    
    try {
        # Import code capture module if needed
        if ($CaptureCommands -and (Test-Path "$PSScriptRoot\Audit-CodeCapture.ps1")) {
            . "$PSScriptRoot\Audit-CodeCapture.ps1"
        }
        
        # Connect to Exchange Online
        if (-not (Get-Command Get-ManagementRole -ErrorAction SilentlyContinue)) {
            Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
            
            if ($UseModernAuth) {
                Connect-ExchangeOnline -ShowBanner:$false
            } else {
                Connect-ExchangeOnline -Credential $Credential -ShowBanner:$false
            }
        }
        
        Write-Verbose "Retrieving Exchange Online management roles..."
        
        # Get all management roles
        if ($CaptureCommands) {
            Add-AuditCommand -CommandName "Get-ManagementRole" -CommandText "Get-ManagementRole" -Description "Retrieving all Exchange Online management roles" -CaptureScreenshot
        }
        $roles = Get-ManagementRole
        
        # Get all role groups
        if ($CaptureCommands) {
            Add-AuditCommand -CommandName "Get-RoleGroup" -CommandText "Get-RoleGroup" -Description "Retrieving all Exchange Online role groups" -CaptureScreenshot
        }
        $roleGroups = Get-RoleGroup
        
        # Get all management role assignments
        $roleAssignments = Get-ManagementRoleAssignment
        
        $exchangeRoles = @()
        
        foreach ($roleGroup in $roleGroups) {
            $roleGroupInfo = [PSCustomObject]@{
                Name = $roleGroup.Name
                DisplayName = $roleGroup.DisplayName
                Description = $roleGroup.Description
                Type = "RoleGroup"
                WhenCreated = $roleGroup.WhenCreated
                WhenChanged = $roleGroup.WhenChanged
                IsBuiltIn = $roleGroup.RoleGroupType -eq "BuiltIn"
                Members = @()
                MemberCount = 0
                AssignedRoles = @()
                CriticalityLevel = Get-ExchangeRoleCriticalityLevel -RoleName $roleGroup.Name
            }
            
            # Get members
            if ($CaptureCommands -and $exchangeRoles.Count -eq 0) {  # Capture once as example
                $cmd = "Get-RoleGroupMember -Identity '$($roleGroup.Name)'"
                Add-AuditCommand -CommandName "Get-RoleGroupMember" -CommandText $cmd -Description "Retrieving members of Exchange role group: $($roleGroup.Name)" -CaptureScreenshot
            }
            $members = Get-RoleGroupMember -Identity $roleGroup.Name
            foreach ($member in $members) {
                $memberInfo = [PSCustomObject]@{
                    Name = $member.Name
                    DisplayName = $member.DisplayName
                    RecipientType = $member.RecipientType
                    Identity = $member.Identity
                    Guid = $member.Guid
                }
                $roleGroupInfo.Members += $memberInfo
            }
            $roleGroupInfo.MemberCount = $roleGroupInfo.Members.Count
            
            # Get assigned roles
            $assignedRoles = $roleAssignments | Where-Object { $_.RoleAssignee -eq $roleGroup.Name }
            foreach ($assignment in $assignedRoles) {
                $roleGroupInfo.AssignedRoles += $assignment.Role
            }
            
            $exchangeRoles += $roleGroupInfo
        }
        
        # Get direct role assignments (not through role groups)
        $directAssignments = $roleAssignments | Where-Object { 
            $_.RoleAssigneeType -eq "User" -or $_.RoleAssigneeType -eq "SecurityGroup"
        }
        
        $directRoleAssignments = @()
        foreach ($assignment in $directAssignments) {
            $assignmentInfo = [PSCustomObject]@{
                Role = $assignment.Role
                RoleAssignee = $assignment.RoleAssignee
                RoleAssigneeType = $assignment.RoleAssigneeType
                AssignmentMethod = $assignment.AssignmentMethod
                CustomRecipientWriteScope = $assignment.CustomRecipientWriteScope
                CustomConfigWriteScope = $assignment.CustomConfigWriteScope
                RecipientWriteScope = $assignment.RecipientWriteScope
                ConfigWriteScope = $assignment.ConfigWriteScope
                Enabled = $assignment.Enabled
                WhenCreated = $assignment.WhenCreated
                WhenChanged = $assignment.WhenChanged
            }
            $directRoleAssignments += $assignmentInfo
        }
        
        # Get management role entries (permissions)
        $criticalRoles = @("Organization Management", "Recipient Management", "Discovery Management", "Compliance Management")
        $rolePermissions = @{}
        
        foreach ($criticalRole in $criticalRoles) {
            try {
                $entries = Get-ManagementRoleEntry "$criticalRole\*" -ErrorAction SilentlyContinue
                $rolePermissions[$criticalRole] = $entries | Select-Object -ExpandProperty Name -Unique
            } catch {
                Write-Warning "Could not retrieve permissions for role: $criticalRole"
            }
        }
        
        return [PSCustomObject]@{
            RoleGroups = $exchangeRoles
            DirectAssignments = $directRoleAssignments
            RolePermissions = $rolePermissions
            TotalRoleGroups = $roleGroups.Count
            TotalDirectAssignments = $directAssignments.Count
        }
        
    } catch {
        Write-Error "Failed to retrieve Exchange Online RBAC roles: $_"
        throw
    }
}

function Get-Exchange2019OnPremRBACRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ExchangeServer,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    try {
        # Create remote PowerShell session to Exchange 2019
        $sessionParams = @{
            ConfigurationName = "Microsoft.Exchange"
            ConnectionUri = "http://$ExchangeServer/PowerShell/"
            Authentication = "Kerberos"
        }
        
        if ($Credential) {
            $sessionParams.Credential = $Credential
        }
        
        $session = New-PSSession @sessionParams
        Import-PSSession $session -DisableNameChecking -AllowClobber
        
        Write-Verbose "Retrieving Exchange 2019 on-premise management roles..."
        
        # Get management roles and groups
        $roles = Get-ManagementRole
        $roleGroups = Get-RoleGroup
        $roleAssignments = Get-ManagementRoleAssignment
        
        $onPremRoles = @()
        
        foreach ($roleGroup in $roleGroups) {
            $roleGroupInfo = [PSCustomObject]@{
                Name = $roleGroup.Name
                DisplayName = $roleGroup.DisplayName
                Description = $roleGroup.Description
                Type = "OnPremRoleGroup"
                ServerName = $ExchangeServer
                WhenCreated = $roleGroup.WhenCreated
                WhenChanged = $roleGroup.WhenChanged
                Members = @()
                MemberCount = 0
                AssignedRoles = @()
                LinkedGroup = $roleGroup.LinkedGroup
                RoleGroupType = $roleGroup.RoleGroupType
            }
            
            # Get members
            $members = Get-RoleGroupMember -Identity $roleGroup.Name
            foreach ($member in $members) {
                # Get additional AD info
                $adUser = $null
                try {
                    $adUser = Get-ADUser -Identity $member.Name -Properties EmailAddress, Title, Department, Manager -ErrorAction SilentlyContinue
                } catch {}
                
                $memberInfo = [PSCustomObject]@{
                    Name = $member.Name
                    DisplayName = $member.DisplayName
                    RecipientType = $member.RecipientType
                    Identity = $member.Identity
                    EmailAddress = if ($adUser.EmailAddress) { $adUser.EmailAddress } else { $member.PrimarySmtpAddress }
                    Title = $adUser.Title
                    Department = $adUser.Department
                }
                $roleGroupInfo.Members += $memberInfo
            }
            $roleGroupInfo.MemberCount = $roleGroupInfo.Members.Count
            
            # Get assigned roles
            $assignedRoles = $roleAssignments | Where-Object { $_.RoleAssignee -eq $roleGroup.Name }
            foreach ($assignment in $assignedRoles) {
                $roleGroupInfo.AssignedRoles += $assignment.Role
            }
            
            $onPremRoles += $roleGroupInfo
        }
        
        # Get Exchange administrators from AD
        $exchangeAdmins = @()
        try {
            # Check Exchange security groups in AD
            $exchangeGroups = @(
                "Exchange Organization Administrators",
                "Exchange Recipient Administrators",
                "Exchange Public Folder Administrators",
                "Exchange Servers",
                "Exchange Trusted Subsystem",
                "Exchange Windows Permissions"
            )
            
            foreach ($groupName in $exchangeGroups) {
                try {
                    $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                    if ($group) {
                        $members = Get-ADGroupMember -Identity $group -Recursive
                        $exchangeAdmins += [PSCustomObject]@{
                            GroupName = $groupName
                            GroupDN = $group.DistinguishedName
                            Members = $members | Where-Object { $_.objectClass -eq 'user' }
                            MemberCount = ($members | Where-Object { $_.objectClass -eq 'user' }).Count
                        }
                    }
                } catch {
                    Write-Warning "Could not retrieve members for group: $groupName"
                }
            }
        } catch {
            Write-Warning "Could not retrieve Exchange AD groups"
        }
        
        # Clean up session
        Remove-PSSession $session
        
        return [PSCustomObject]@{
            RoleGroups = $onPremRoles
            ExchangeADGroups = $exchangeAdmins
            ServerName = $ExchangeServer
            TotalRoleGroups = $onPremRoles.Count
        }
        
    } catch {
        Write-Error "Failed to retrieve Exchange 2019 RBAC roles: $_"
        if ($session) { Remove-PSSession $session }
        throw
    }
}

function Get-ExchangeRoleCriticalityLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleName
    )
    
    $criticalRoles = @{
        "Organization Management" = "Critical"
        "Recipient Management" = "High"
        "Discovery Management" = "High"
        "Compliance Management" = "High"
        "Security Administrator" = "High"
        "Server Management" = "High"
        "Delegated Setup" = "Medium"
        "Help Desk" = "Medium"
        "Hygiene Management" = "Medium"
        "Records Management" = "Medium"
        "View-Only Organization Management" = "Low"
        "Public Folder Management" = "Low"
    }
    
    return if ($criticalRoles[$RoleName]) { $criticalRoles[$RoleName] } else { "Standard" }
}

function Get-ExchangeAdminAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        
        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = (Get-Date),
        
        [Parameter(Mandatory=$false)]
        [string[]]$Cmdlets,
        
        [Parameter(Mandatory=$false)]
        [switch]$OnlineOnly,
        
        [Parameter(Mandatory=$false)]
        [switch]$OnPremOnly
    )
    
    try {
        $auditLogs = @()
        
        if (-not $OnPremOnly) {
            Write-Verbose "Retrieving Exchange Online admin audit logs..."
            
            $searchParams = @{
                StartDate = $StartDate
                EndDate = $EndDate
                ResultSize = 5000
            }
            
            if ($Cmdlets) {
                $searchParams.Cmdlets = $Cmdlets
            }
            
            $onlineLogs = Search-AdminAuditLog @searchParams
            
            foreach ($log in $onlineLogs) {
                $auditEntry = [PSCustomObject]@{
                    Environment = "Exchange Online"
                    RunDate = $log.RunDate
                    Caller = $log.Caller
                    Cmdlet = $log.CmdletName
                    Parameters = ($log.CmdletParameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "; "
                    Succeeded = $log.Succeeded
                    Error = $log.Error
                    ObjectModified = $log.ObjectModified
                    OriginatingServer = $log.OriginatingServer
                    ClientIP = $log.ClientIP
                }
                $auditLogs += $auditEntry
            }
        }
        
        return $auditLogs | Sort-Object RunDate -Descending
        
    } catch {
        Write-Error "Failed to retrieve Exchange admin audit logs: $_"
        throw
    }
}

function Compare-ExchangeRBACCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$CurrentRoles,
        
        [Parameter(Mandatory=$true)]
        [string]$BaselineFile
    )
    
    try {
        # Load baseline
        $baseline = Get-Content $BaselineFile | ConvertFrom-Json
        
        $complianceResults = @()
        
        # Compare role groups
        foreach ($currentRole in $CurrentRoles.RoleGroups) {
            $baselineRole = $baseline.RoleGroups | Where-Object { $_.Name -eq $currentRole.Name }
            
            if ($baselineRole) {
                # Check for member changes
                $currentMembers = $currentRole.Members | Select-Object -ExpandProperty Name | Sort-Object
                $baselineMembers = $baselineRole.Members | Select-Object -ExpandProperty Name | Sort-Object
                
                $added = $currentMembers | Where-Object { $_ -notin $baselineMembers }
                $removed = $baselineMembers | Where-Object { $_ -notin $currentMembers }
                
                if ($added -or $removed) {
                    $complianceResults += [PSCustomObject]@{
                        RoleGroup = $currentRole.Name
                        Type = "Membership Change"
                        AddedMembers = $added -join ", "
                        RemovedMembers = $removed -join ", "
                        CurrentCount = $currentRole.MemberCount
                        BaselineCount = $baselineRole.MemberCount
                        ComplianceStatus = "Changed"
                    }
                }
            } else {
                $complianceResults += [PSCustomObject]@{
                    RoleGroup = $currentRole.Name
                    Type = "New Role Group"
                    AddedMembers = $currentRole.Members | Select-Object -ExpandProperty Name -join ", "
                    RemovedMembers = ""
                    CurrentCount = $currentRole.MemberCount
                    BaselineCount = 0
                    ComplianceStatus = "New"
                }
            }
        }
        
        # Check for removed role groups
        foreach ($baselineRole in $baseline.RoleGroups) {
            if ($baselineRole.Name -notin $CurrentRoles.RoleGroups.Name) {
                $complianceResults += [PSCustomObject]@{
                    RoleGroup = $baselineRole.Name
                    Type = "Removed Role Group"
                    AddedMembers = ""
                    RemovedMembers = $baselineRole.Members | Select-Object -ExpandProperty Name -join ", "
                    CurrentCount = 0
                    BaselineCount = $baselineRole.MemberCount
                    ComplianceStatus = "Removed"
                }
            }
        }
        
        return $complianceResults
        
    } catch {
        Write-Error "Failed to compare Exchange RBAC compliance: $_"
        throw
    }
}

Export-ModuleMember -Function Get-ExchangeOnlineRBACRoles, Get-Exchange2019OnPremRBACRoles, Get-ExchangeRoleCriticalityLevel, Get-ExchangeAdminAuditLog, Compare-ExchangeRBACCompliance