<#
.SYNOPSIS
    Active Directory multi-domain forest audit functions.

.DESCRIPTION
    Provides enhanced functions for auditing AD groups across forest root and child domains.
    Handles cross-domain group memberships and Enterprise Admin auditing.
#>

function Get-ADForestDomains {
    <#
    .SYNOPSIS
        Retrieves all domains in the current forest.
    
    .DESCRIPTION
        Gets forest root domain and all child domains with their details.
    
    .EXAMPLE
        $domains = Get-ADForestDomains
    #>
    [CmdletBinding()]
    param()
    
    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $domains = @()
        
        # Get forest root domain
        $rootDomain = $forest.RootDomain
        $domains += [PSCustomObject]@{
            Name = $rootDomain.Name
            NetBIOSName = (Get-ADDomain -Server $rootDomain.Name).NetBIOSName
            DomainController = $rootDomain.DomainControllers[0].Name
            IsRoot = $true
            DistinguishedName = (Get-ADDomain -Server $rootDomain.Name).DistinguishedName
        }
        
        # Get child domains
        foreach ($domain in $forest.Domains) {
            if ($domain.Name -ne $rootDomain.Name) {
                $domains += [PSCustomObject]@{
                    Name = $domain.Name
                    NetBIOSName = (Get-ADDomain -Server $domain.Name).NetBIOSName
                    DomainController = $domain.DomainControllers[0].Name
                    IsRoot = $false
                    DistinguishedName = (Get-ADDomain -Server $domain.Name).DistinguishedName
                }
            }
        }
        
        return $domains
    } catch {
        Write-Error "Failed to enumerate forest domains: $_"
        throw
    }
}

function Get-ADGroupAuditDataMultiDomain {
    <#
    .SYNOPSIS
        Retrieves AD group data across multiple domains in a forest.
    
    .DESCRIPTION
        Enhanced version of Get-ADGroupAuditData that handles cross-domain memberships,
        Enterprise Admins, Schema Admins, and other forest-level groups.
    
    .PARAMETER GroupNames
        Array of group names to audit.
    
    .PARAMETER Domains
        Specific domains to audit. If not specified, audits all domains.
    
    .PARAMETER IncludeForestRootGroups
        Include forest-level groups like Enterprise Admins, Schema Admins.
    
    .PARAMETER IncludeNestedGroups
        Include members from nested groups.
    
    .PARAMETER ResolveForeignSecurityPrincipals
        Resolve FSPs to show actual user names from trusted domains.
    
    .EXAMPLE
        Get-ADGroupAuditDataMultiDomain -IncludeForestRootGroups -GroupNames "Domain Admins"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$GroupNames,
        
        [Parameter(Mandatory=$false)]
        [string[]]$Domains,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeForestRootGroups,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeNestedGroups,
        
        [Parameter(Mandatory=$false)]
        [switch]$ResolveForeignSecurityPrincipals,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands
    )
    
    $results = @()
    
    try {
        # Import code capture if needed
        if ($CaptureCommands -and (Test-Path "$PSScriptRoot\Audit-CodeCapture.ps1")) {
            . "$PSScriptRoot\Audit-CodeCapture.ps1"
        }
        
        # Get all domains if not specified
        if (!$Domains) {
            Write-Verbose "Enumerating forest domains..."
            $forestDomains = Get-ADForestDomains
            $Domains = $forestDomains.Name
        } else {
            $forestDomains = @()
            foreach ($domain in $Domains) {
                $forestDomains += [PSCustomObject]@{
                    Name = $domain
                    DomainController = (Get-ADDomainController -DomainName $domain -Discover).HostName[0]
                }
            }
        }
        
        # Add forest root groups if requested
        $groupsToAudit = $GroupNames
        if ($IncludeForestRootGroups) {
            $forestRootGroups = @(
                "Enterprise Admins",
                "Schema Admins",
                "Enterprise Key Admins",
                "Enterprise Read-only Domain Controllers"
            )
            $groupsToAudit = $groupsToAudit + $forestRootGroups | Select-Object -Unique
        }
        
        # Process each domain
        foreach ($domain in $forestDomains) {
            Write-Host "Processing domain: $($domain.Name)" -ForegroundColor Cyan
            
            # Get groups from this domain
            $domainGroups = @()
            
            if ($groupsToAudit) {
                foreach ($groupName in $groupsToAudit) {
                    try {
                        if ($CaptureCommands) {
                            $cmd = "Get-ADGroup -Identity '$groupName' -Server '$($domain.DomainController)' -Properties *"
                            Add-AuditCommand -CommandName "Get-ADGroup" -CommandText $cmd -Description "Retrieving group from domain: $($domain.Name)" -CaptureScreenshot
                        }
                        
                        $group = Get-ADGroup -Identity $groupName -Server $domain.DomainController -Properties * -ErrorAction Stop
                        $domainGroups += $group
                    } catch {
                        Write-Verbose "Group '$groupName' not found in domain $($domain.Name)"
                    }
                }
            } else {
                # Get all groups
                $domainGroups = Get-ADGroup -Filter * -Server $domain.DomainController -Properties *
            }
            
            # Process each group
            foreach ($group in $domainGroups) {
                Write-Verbose "Processing group: $($group.Name) in domain $($domain.Name)"
                
                $groupData = [PSCustomObject]@{
                    GroupName = $group.Name
                    GroupDN = $group.DistinguishedName
                    Domain = $domain.Name
                    GroupCategory = $group.GroupCategory
                    GroupScope = $group.GroupScope
                    Description = $group.Description
                    Created = $group.Created
                    Modified = $group.Modified
                    ManagedBy = $null
                    Members = @()
                    MemberCount = 0
                    CrossDomainMembers = 0
                    EnabledMemberCount = 0
                    DisabledMemberCount = 0
                    LastAuditDate = Get-Date
                    Status = "Success"
                    ErrorDetails = $null
                }
                
                # Get group members
                try {
                    if ($CaptureCommands) {
                        $cmd = "Get-ADGroupMember -Identity '$($group.DistinguishedName)' -Server '$($domain.DomainController)'$(if ($IncludeNestedGroups) { ' -Recursive' })"
                        Add-AuditCommand -CommandName "Get-ADGroupMember" -CommandText $cmd -Description "Retrieving members of $($group.Name)" -CaptureScreenshot
                    }
                    
                    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Server $domain.DomainController -Recursive:$IncludeNestedGroups
                } catch {
                    Write-Warning "Unable to retrieve members for group '$($group.Name)' in domain '$($domain.Name)': $_"
                    Write-Warning "This may be due to insufficient permissions. Skipping this group."
                    
                    # Add to results with error status
                    $groupData.Status = "Error - Access Denied"
                    $groupData.ErrorDetails = $_.Exception.Message
                    $results += $groupData
                    continue
                }
                
                foreach ($member in $members) {
                    # Handle Foreign Security Principals (cross-domain members)
                    if ($member.objectClass -eq 'foreignSecurityPrincipal' -and $ResolveForeignSecurityPrincipals) {
                        try {
                            # Extract SID from the FSP
                            $sid = $member.objectSid
                            
                            # Try to resolve in each domain
                            $resolved = $false
                            foreach ($searchDomain in $forestDomains) {
                                try {
                                    $user = Get-ADUser -Identity $sid -Server $searchDomain.DomainController -Properties DisplayName, EmailAddress, Title, Department, Manager, Enabled, LastLogonDate -ErrorAction Stop
                                    
                                    $memberData = [PSCustomObject]@{
                                        DisplayName = $user.DisplayName
                                        SamAccountName = $user.SamAccountName
                                        Domain = $searchDomain.Name
                                        EmailAddress = $user.EmailAddress
                                        Title = $user.Title
                                        Department = $user.Department
                                        Manager = $null
                                        Enabled = $user.Enabled
                                        LastLogonDate = $user.LastLogonDate
                                        MemberType = 'User (Cross-Domain)'
                                        OriginalDomain = $searchDomain.Name
                                    }
                                    
                                    $groupData.Members += $memberData
                                    $groupData.CrossDomainMembers++
                                    if ($user.Enabled) { $groupData.EnabledMemberCount++ } else { $groupData.DisabledMemberCount++ }
                                    
                                    $resolved = $true
                                    break
                                } catch {
                                    continue
                                }
                            }
                            
                            if (!$resolved) {
                                # Couldn't resolve FSP
                                $memberData = [PSCustomObject]@{
                                    DisplayName = "Unresolved FSP"
                                    SamAccountName = $member.Name
                                    Domain = "Unknown"
                                    EmailAddress = ""
                                    Title = ""
                                    Department = ""
                                    Manager = ""
                                    Enabled = "Unknown"
                                    LastLogonDate = $null
                                    MemberType = 'Foreign Security Principal'
                                    OriginalDomain = "Unknown"
                                }
                                $groupData.Members += $memberData
                            }
                        } catch {
                            Write-Warning "Failed to resolve FSP: $($member.Name)"
                        }
                    }
                    elseif ($member.objectClass -eq 'user') {
                        try {
                            # Determine which domain the user is from
                            $userDomain = $domain.DomainController
                            if ($member.DistinguishedName -notmatch $domain.Name) {
                                # User is from different domain, find correct DC
                                foreach ($searchDomain in $forestDomains) {
                                    if ($member.DistinguishedName -match $searchDomain.Name) {
                                        $userDomain = $searchDomain.DomainController
                                        break
                                    }
                                }
                            }
                            
                            $user = Get-ADUser -Identity $member -Server $userDomain -Properties DisplayName, EmailAddress, Title, Department, Manager, Enabled, LastLogonDate, PasswordLastSet, AccountExpirationDate
                            
                            $memberData = [PSCustomObject]@{
                                DisplayName = $user.DisplayName
                                SamAccountName = $user.SamAccountName
                                Domain = ($member.DistinguishedName -split ',DC=' | Select-Object -Skip 1) -join '.'
                                EmailAddress = $user.EmailAddress
                                Title = $user.Title
                                Department = $user.Department
                                Manager = $null
                                Enabled = $user.Enabled
                                LastLogonDate = $user.LastLogonDate
                                PasswordLastSet = $user.PasswordLastSet
                                AccountExpires = $user.AccountExpirationDate
                                MemberType = 'User'
                                OriginalDomain = $domain.Name
                            }
                            
                            if ($user.Manager) {
                                try {
                                    $mgr = Get-ADUser -Identity $user.Manager -Server $userDomain -Properties DisplayName
                                    $memberData.Manager = "$($mgr.DisplayName) ($($mgr.SamAccountName))"
                                } catch {
                                    $memberData.Manager = $user.Manager
                                }
                            }
                            
                            $groupData.Members += $memberData
                            if ($user.Enabled) { $groupData.EnabledMemberCount++ } else { $groupData.DisabledMemberCount++ }
                            
                            # Track cross-domain membership
                            if ($memberData.Domain -ne $domain.Name) {
                                $groupData.CrossDomainMembers++
                            }
                            
                        } catch {
                            Write-Warning "Failed to get details for user: $($member.SamAccountName)"
                        }
                    }
                    elseif ($member.objectClass -eq 'group') {
                        # Handle nested groups
                        $memberData = [PSCustomObject]@{
                            DisplayName = $member.Name
                            SamAccountName = $member.SamAccountName
                            Domain = ($member.DistinguishedName -split ',DC=' | Select-Object -Skip 1) -join '.'
                            EmailAddress = ''
                            Title = 'Nested Group'
                            Department = ''
                            Manager = ''
                            Enabled = $true
                            LastLogonDate = $null
                            MemberType = 'Group'
                            OriginalDomain = $domain.Name
                        }
                        $groupData.Members += $memberData
                    }
                }
                
                $groupData.MemberCount = $groupData.Members.Count
                $results += $groupData
            }
        }
        
        return $results
        
    } catch {
        Write-Error "Failed to retrieve multi-domain AD group data: $_"
        throw
    }
}

function Get-ADForestPrivilegedGroups {
    <#
    .SYNOPSIS
        Gets all privileged groups across the forest.
    
    .DESCRIPTION
        Retrieves Domain Admins from each domain plus forest-level admin groups.
    
    .EXAMPLE
        $privGroups = Get-ADForestPrivilegedGroups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands
    )
    
    $privilegedGroups = @()
    $domains = Get-ADForestDomains
    
    # Forest root groups
    $forestGroups = @(
        "Enterprise Admins",
        "Schema Admins",
        "Enterprise Key Admins"
    )
    
    # Domain-specific groups
    $domainGroups = @(
        "Domain Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators"
    )
    
    # Get forest root groups
    $rootDomain = $domains | Where-Object { $_.IsRoot }
    foreach ($groupName in $forestGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -Server $rootDomain.DomainController -Properties Description
            $privilegedGroups += [PSCustomObject]@{
                GroupName = $group.Name
                Domain = $rootDomain.Name
                Scope = "Forest"
                Description = $group.Description
                DN = $group.DistinguishedName
            }
        } catch {
            Write-Warning "Forest group not found: $groupName"
        }
    }
    
    # Get domain groups from each domain
    foreach ($domain in $domains) {
        foreach ($groupName in $domainGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -Server $domain.DomainController -Properties Description -ErrorAction Stop
                $privilegedGroups += [PSCustomObject]@{
                    GroupName = $group.Name
                    Domain = $domain.Name
                    Scope = "Domain"
                    Description = $group.Description
                    DN = $group.DistinguishedName
                }
            } catch {
                Write-Verbose "Group '$groupName' not found in domain $($domain.Name)"
            }
        }
    }
    
    return $privilegedGroups
}

# Functions are automatically available when script is dot-sourced