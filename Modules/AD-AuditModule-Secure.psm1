<#
.SYNOPSIS
    Active Directory audit module for group membership and permissions analysis.

.DESCRIPTION
    Provides functions to audit AD groups, memberships, and permissions for compliance reporting.
    Supports nested group analysis, user status tracking, and permission auditing.
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Import required modules
Import-Module "$PSScriptRoot\InputValidation.psm1" -Force
Import-Module "$PSScriptRoot\ErrorHandler.psm1" -Force

<#
.SYNOPSIS
    Retrieves comprehensive audit data for specified AD groups.

.DESCRIPTION
    Collects detailed information about AD groups including all members, their properties,
    enabled/disabled status, last logon times, and organizational details.

.PARAMETER GroupNames
    Array of AD group names to audit. Must contain only alphanumeric characters, spaces, hyphens, and underscores.

.PARAMETER SearchBase
    Distinguished name of OU to search for groups.

.PARAMETER IncludeNestedGroups
    Include members of nested groups in results.

.PARAMETER IncludeDisabledUsers
    Include disabled user accounts in results.

.PARAMETER CaptureCommands
    Capture PowerShell commands for compliance evidence.

.PARAMETER ThrottleLimit
    Number of parallel threads for processing (default: 10)

.PARAMETER BatchSize
    Number of users to process in each batch (default: 100)

.EXAMPLE
    Get-ADGroupAuditDataSecure -GroupNames @("Domain Admins", "Enterprise Admins") -IncludeNestedGroups

.EXAMPLE
    Get-ADGroupAuditDataSecure -SearchBase "OU=Security Groups,DC=company,DC=com" -IncludeDisabledUsers
#>
function Get-ADGroupAuditDataSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateScript({ 
            foreach ($name in $_) {
                if (-not (Test-ADGroupName $name)) {
                    throw "Invalid group name format: $name. Only alphanumeric characters, spaces, hyphens, and underscores are allowed."
                }
            }
            return $true
        })]
        [string[]]$GroupNames,
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeNestedGroups,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabledUsers,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands,
        
        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 50)]
        [int]$ThrottleLimit = 10,
        
        [Parameter(Mandatory=$false)]
        [ValidateRange(10, 1000)]
        [int]$BatchSize = 100
    )
    
    begin {
        # Define only required properties to improve performance
        $groupProperties = @(
            'Name', 'DistinguishedName', 'GroupCategory', 'GroupScope',
            'Description', 'Created', 'Modified', 'ManagedBy', 'Members'
        )
        
        $userProperties = @(
            'SamAccountName', 'DisplayName', 'EmailAddress', 'Enabled',
            'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
            'PasswordExpired', 'LockedOut', 'Description', 'Title',
            'Department', 'Manager', 'whenCreated', 'whenChanged',
            'AccountExpirationDate'
        )
        
        $results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
        
        # Import code capture module if needed
        if ($CaptureCommands -and (Test-Path "$PSScriptRoot\Audit-CodeCapture.ps1")) {
            . "$PSScriptRoot\Audit-CodeCapture.ps1"
        }
    }
    
    process {
        Invoke-AuditCommand -Context "Get-ADGroupAuditDataSecure" -ScriptBlock {
            # Get groups efficiently
            $groups = if ($GroupNames) {
                $GroupNames | ForEach-Object -Parallel {
                    $groupName = $_
                    $localGroupProperties = $using:groupProperties
                    $localCaptureCommands = $using:CaptureCommands
                    
                    try {
                        if ($localCaptureCommands) {
                            # Safe command logging - no injection possible
                            $safeCmd = "Get-ADGroup -Identity [ValidatedGroupName] -Properties $($localGroupProperties -join ',')"
                            Add-AuditCommand -CommandName "Get-ADGroup" -CommandText $safeCmd -Description "Retrieving AD group details for validated group" -CaptureScreenshot
                        }
                        Get-ADGroup -Identity $groupName -Properties $localGroupProperties -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Failed to get group '$groupName': $_"
                    }
                } -ThrottleLimit $ThrottleLimit
            }
            else {
                $ldapFilter = '(objectClass=group)'
                $params = @{
                    LDAPFilter = $ldapFilter
                    Properties = $groupProperties
                }
                if ($SearchBase) { 
                    # Validate SearchBase is a valid DN
                    if ($SearchBase -notmatch '^(CN|OU|DC)=.+') {
                        throw "Invalid SearchBase format"
                    }
                    $params.SearchBase = $SearchBase 
                }
                
                if ($CaptureCommands) {
                    $safeCmd = "Get-ADGroup -LDAPFilter '$ldapFilter' -Properties $($groupProperties -join ',')"
                    Add-AuditCommand -CommandName "Get-ADGroup" -CommandText $safeCmd -Description "Retrieving all AD groups" -CaptureScreenshot
                }
                
                Get-ADGroup @params
            }
            
            # Process groups in parallel with proper error handling
            $groups | ForEach-Object -Parallel {
                $group = $_
                $localResults = $using:results
                $localUserProperties = $using:userProperties
                $localIncludeNested = $using:IncludeNestedGroups
                $localIncludeDisabled = $using:IncludeDisabledUsers
                $localBatchSize = $using:BatchSize
                $localCaptureCommands = $using:CaptureCommands
                
                try {
                    # Create group data object
                    $groupData = [PSCustomObject]@{
                        GroupName = $group.Name
                        GroupDN = $group.DistinguishedName
                        GroupCategory = $group.GroupCategory
                        GroupScope = $group.GroupScope
                        Description = $group.Description
                        Created = $group.Created
                        Modified = $group.Modified
                        ManagedBy = $null
                        Members = [System.Collections.ArrayList]::new()
                        MemberCount = 0
                        EnabledMemberCount = 0
                        DisabledMemberCount = 0
                        AuditDate = Get-Date
                    }
                    
                    # Get manager information safely
                    if ($group.ManagedBy) {
                        try {
                            $manager = Get-ADUser -Identity $group.ManagedBy -Properties DisplayName
                            $groupData.ManagedBy = "$($manager.DisplayName) ($($manager.SamAccountName))"
                        } catch {
                            $groupData.ManagedBy = $group.ManagedBy
                        }
                    }
                    
                    # Get members efficiently
                    if ($localCaptureCommands) {
                        $safeCmd = "Get-ADGroupMember -Identity [GroupDN] -Recursive:$localIncludeNested"
                        Add-AuditCommand -CommandName "Get-ADGroupMember" -CommandText $safeCmd -Description "Retrieving members of group" -CaptureScreenshot
                    }
                    
                    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive:$localIncludeNested
                    
                    # Batch process members for better performance
                    $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }
                    
                    for ($i = 0; $i -lt $userMembers.Count; $i += $localBatchSize) {
                        $batch = $userMembers[$i..([Math]::Min($i + $localBatchSize - 1, $userMembers.Count - 1))]
                        
                        # Build optimized LDAP filter for batch
                        $samAccountNames = $batch | ForEach-Object { 
                            $sam = $_.SamAccountName -replace '[\(\)\\\*]', '\$0'  # Escape special LDAP characters
                            "(sAMAccountName=$sam)" 
                        }
                        
                        if ($samAccountNames) {
                            $ldapFilter = "(|$($samAccountNames -join ''))"
                            if (-not $localIncludeDisabled) {
                                # Filter out disabled accounts (userAccountControl bit 2)
                                $ldapFilter = "(&$ldapFilter(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                            }
                            
                            try {
                                $users = Get-ADUser -LDAPFilter $ldapFilter -Properties $localUserProperties
                                
                                foreach ($user in $users) {
                                    $memberData = [PSCustomObject]@{
                                        DisplayName = $user.DisplayName
                                        SamAccountName = $user.SamAccountName
                                        EmailAddress = $user.EmailAddress
                                        Title = $user.Title
                                        Department = $user.Department
                                        Manager = $null
                                        Enabled = $user.Enabled
                                        LastLogonDate = $user.LastLogonDate
                                        PasswordLastSet = $user.PasswordLastSet
                                        AccountExpires = $user.AccountExpirationDate
                                        MemberType = 'User'
                                    }
                                    
                                    if ($user.Manager) {
                                        try {
                                            $mgr = Get-ADUser -Identity $user.Manager -Properties DisplayName
                                            $memberData.Manager = "$($mgr.DisplayName) ($($mgr.SamAccountName))"
                                        } catch {
                                            $memberData.Manager = $user.Manager
                                        }
                                    }
                                    
                                    [void]$groupData.Members.Add($memberData)
                                    
                                    if ($user.Enabled) {
                                        $groupData.EnabledMemberCount++
                                    } else {
                                        $groupData.DisabledMemberCount++
                                    }
                                }
                            }
                            catch {
                                Write-Warning "Error processing batch of users for group '$($group.Name)': $_"
                            }
                        }
                    }
                    
                    # Process group members
                    $groupMembers = $members | Where-Object { $_.objectClass -eq 'group' }
                    foreach ($grpMember in $groupMembers) {
                        $memberData = [PSCustomObject]@{
                            DisplayName = $grpMember.Name
                            SamAccountName = $grpMember.SamAccountName
                            EmailAddress = ''
                            Title = 'Nested Group'
                            Department = ''
                            Manager = ''
                            Enabled = $true
                            LastLogonDate = $null
                            PasswordLastSet = $null
                            AccountExpires = $null
                            MemberType = 'Group'
                        }
                        [void]$groupData.Members.Add($memberData)
                    }
                    
                    $groupData.MemberCount = $groupData.Members.Count
                    $localResults.Add($groupData)
                }
                catch {
                    Write-Warning "Error processing group '$($group.Name)': $_"
                }
            } -ThrottleLimit $ThrottleLimit
        }
    }
    
    end {
        return $results
    }
}

<#
.SYNOPSIS
    Audits Active Directory permissions on organizational units.

.DESCRIPTION
    Retrieves and analyzes access control lists (ACLs) for specified OUs,
    identifying who has what permissions for compliance reporting.

.PARAMETER TargetOU
    Distinguished name of the OU to audit.

.PARAMETER IncludeInherited
    Include inherited permissions in the audit.

.EXAMPLE
    Get-ADPermissionsAuditSecure -TargetOU "OU=Servers,DC=company,DC=com" -IncludeInherited
#>
function Get-ADPermissionsAuditSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -notmatch '^(CN|OU|DC)=.+') {
                throw "Invalid OU format. Must be a valid distinguished name."
            }
            return $true
        })]
        [string]$TargetOU,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeInherited
    )
    
    Invoke-AuditCommand -Context "Get-ADPermissionsAuditSecure" -ScriptBlock {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $ou = Get-ADOrganizationalUnit -Identity $TargetOU -Properties *
        $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
        
        $permissions = @()
        
        foreach ($access in $acl.Access) {
            if (!$access.IsInherited -or $IncludeInherited) {
                $principal = $null
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($access.IdentityReference.Value)
                    $principal = $sid.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $principal = $access.IdentityReference.Value
                }
                
                $permission = [PSCustomObject]@{
                    OU = $ou.Name
                    OUDN = $ou.DistinguishedName
                    Principal = $principal
                    AccessControlType = $access.AccessControlType
                    ActiveDirectoryRights = $access.ActiveDirectoryRights
                    InheritanceType = $access.InheritanceType
                    ObjectType = $access.ObjectType
                    InheritedObjectType = $access.InheritedObjectType
                    IsInherited = $access.IsInherited
                    InheritanceFlags = $access.InheritanceFlags
                    PropagationFlags = $access.PropagationFlags
                }
                
                $permissions += $permission
            }
        }
        
        return $permissions
    }
}

<#
.SYNOPSIS
    Exports AD group audit data to Excel format with streaming support.

.DESCRIPTION
    Creates a formatted Excel workbook with group summaries and detailed member lists.
    Uses streaming to handle large datasets efficiently.

.PARAMETER GroupAuditData
    Output from Get-ADGroupAuditDataSecure function.

.PARAMETER OutputPath
    Path for the Excel file to create.

.PARAMETER BufferSize
    Number of rows to buffer before writing to Excel (default: 1000)

.PARAMETER OpenAfterExport
    Open the Excel file after creation.

.EXAMPLE
    Export-ADGroupMembersSecure -GroupAuditData $auditData -OutputPath "C:\Audits\groups.xlsx"
#>
function Export-ADGroupMembersSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject[]]$GroupAuditData,
        
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-FilePath $_ })]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [ValidateRange(100, 10000)]
        [int]$BufferSize = 1000,
        
        [Parameter(Mandatory=$false)]
        [switch]$OpenAfterExport
    )
    
    begin {
        # Initialize Excel COM object with optimization
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $excel.ScreenUpdating = $false
        
        $workbook = $excel.Workbooks.Add()
        $worksheet = $workbook.Worksheets.Item(1)
        $worksheet.Name = "AD Group Members"
        
        # Headers
        $headers = @(
            'Group Name', 'Member Name', 'Display Name', 'Email',
            'Enabled', 'Last Logon', 'Password Last Set', 'Title',
            'Department', 'Manager', 'Created', 'Modified'
        )
        
        for ($i = 0; $i -lt $headers.Count; $i++) {
            $worksheet.Cells.Item(1, $i + 1) = $headers[$i]
        }
        
        $row = 2
        $buffer = [System.Collections.ArrayList]::new($BufferSize)
    }
    
    process {
        foreach ($group in $GroupAuditData) {
            foreach ($member in $group.Members) {
                $memberData = @(
                    $group.GroupName,
                    $member.SamAccountName,
                    $member.DisplayName,
                    $member.EmailAddress,
                    $member.Enabled,
                    $member.LastLogonDate,
                    $member.PasswordLastSet,
                    $member.Title,
                    $member.Department,
                    $member.Manager,
                    $member.whenCreated,
                    $member.whenChanged
                )
                
                $buffer.Add($memberData) | Out-Null
                
                # Flush buffer when full
                if ($buffer.Count -ge $BufferSize) {
                    Write-Progress -Activity "Exporting to Excel" -Status "Writing rows $row to $($row + $buffer.Count)"
                    
                    # Bulk write to Excel
                    $range = $worksheet.Range(
                        $worksheet.Cells.Item($row, 1),
                        $worksheet.Cells.Item($row + $buffer.Count - 1, $headers.Count)
                    )
                    $range.Value2 = $buffer.ToArray()
                    
                    $row += $buffer.Count
                    $buffer.Clear()
                }
            }
        }
    }
    
    end {
        try {
            # Flush remaining buffer
            if ($buffer.Count -gt 0) {
                $range = $worksheet.Range(
                    $worksheet.Cells.Item($row, 1),
                    $worksheet.Cells.Item($row + $buffer.Count - 1, $headers.Count)
                )
                $range.Value2 = $buffer.ToArray()
            }
            
            # Format as table
            $lastRow = $worksheet.UsedRange.Rows.Count
            $lastCol = $worksheet.UsedRange.Columns.Count
            $range = $worksheet.Range($worksheet.Cells.Item(1, 1), $worksheet.Cells.Item($lastRow, $lastCol))
            $listObject = $worksheet.ListObjects.Add(
                [Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange,
                $range,
                $null,
                [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes
            )
            $listObject.Name = "ADGroupMembersTable"
            $listObject.TableStyle = "TableStyleMedium2"
            
            # Auto-fit columns
            $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
            
            # Save and cleanup
            $workbook.SaveAs($OutputPath)
            $workbook.Close($false)
            $excel.Quit()
            
            # Release COM objects
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            
            Write-Progress -Activity "Exporting to Excel" -Completed
            
            if ($OpenAfterExport) {
                Start-Process $OutputPath
            }
            
            Write-Host "Excel report saved to: $OutputPath" -ForegroundColor Green
        }
        catch {
            # Ensure cleanup even on error
            if ($excel) {
                $excel.Quit()
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
            }
            throw
        }
    }
}

Export-ModuleMember -Function Get-ADGroupAuditDataSecure, Get-ADPermissionsAuditSecure, Export-ADGroupMembersSecure