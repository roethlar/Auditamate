<#
.SYNOPSIS
    Active Directory audit module for group membership and permissions analysis.

.DESCRIPTION
    Provides functions to audit AD groups, memberships, and permissions for compliance reporting.
    Supports nested group analysis, user status tracking, and permission auditing.
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Retrieves comprehensive audit data for specified AD groups.

.DESCRIPTION
    Collects detailed information about AD groups including all members, their properties,
    enabled/disabled status, last logon times, and organizational details.

.PARAMETER GroupNames
    Array of AD group names to audit.

.PARAMETER SearchBase
    Distinguished name of OU to search for groups.

.PARAMETER IncludeNestedGroups
    Include members of nested groups in results.

.PARAMETER IncludeDisabledUsers
    Include disabled user accounts in results.

.PARAMETER CaptureCommands
    Capture PowerShell commands for compliance evidence.

.EXAMPLE
    Get-ADGroupAuditData -GroupNames @("Domain Admins", "Enterprise Admins") -IncludeNestedGroups

.EXAMPLE
    Get-ADGroupAuditData -SearchBase "OU=Security Groups,DC=company,DC=com" -IncludeDisabledUsers
#>
function Get-ADGroupAuditData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$GroupNames,
        
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeNestedGroups,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabledUsers,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands
    )
    
    $results = @()
    
    try {
        # Import code capture module if needed
        if ($CaptureCommands -and (Test-Path "$PSScriptRoot\Audit-CodeCapture.ps1")) {
            . "$PSScriptRoot\Audit-CodeCapture.ps1"
        }
        
        $groups = if ($GroupNames) {
            foreach ($name in $GroupNames) {
                if ($CaptureCommands) {
                    $cmd = "Get-ADGroup -Identity '$name' -Properties *"
                    Add-AuditCommand -CommandName "Get-ADGroup" -CommandText $cmd -Description "Retrieving AD group details for: $name" -CaptureScreenshot
                }
                Get-ADGroup -Identity $name -Properties * -ErrorAction Stop
            }
        } else {
            $params = @{Properties = '*'}
            if ($SearchBase) { $params.SearchBase = $SearchBase }
            if ($CaptureCommands) {
                $cmd = "Get-ADGroup -Filter * -Properties *$(if ($SearchBase) { " -SearchBase '$SearchBase'" })"
                Add-AuditCommand -CommandName "Get-ADGroup" -CommandText $cmd -Description "Retrieving all AD groups" -CaptureScreenshot
            }
            Get-ADGroup -Filter * @params
        }
        
        foreach ($group in $groups) {
            Write-Verbose "Processing group: $($group.Name)"
            
            $groupData = [PSCustomObject]@{
                GroupName = $group.Name
                GroupDN = $group.DistinguishedName
                GroupCategory = $group.GroupCategory
                GroupScope = $group.GroupScope
                Description = $group.Description
                Created = $group.Created
                Modified = $group.Modified
                ManagedBy = $null
                Members = @()
                MemberCount = 0
                EnabledMemberCount = 0
                DisabledMemberCount = 0
                LastAuditDate = Get-Date
            }
            
            if ($group.ManagedBy) {
                try {
                    $manager = Get-ADUser -Identity $group.ManagedBy -Properties DisplayName
                    $groupData.ManagedBy = "$($manager.DisplayName) ($($manager.SamAccountName))"
                } catch {
                    $groupData.ManagedBy = $group.ManagedBy
                }
            }
            
            if ($CaptureCommands) {
                $cmd = "Get-ADGroupMember -Identity '$($group.Name)'$(if ($IncludeNestedGroups) { ' -Recursive' })"
                Add-AuditCommand -CommandName "Get-ADGroupMember" -CommandText $cmd -Description "Retrieving members of group: $($group.Name)" -CaptureScreenshot
            }
            $members = Get-ADGroupMember -Identity $group -Recursive:$IncludeNestedGroups
            
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    try {
                        if ($CaptureCommands -and $results.Count -eq 0) {  # Capture once as example
                            $cmd = "Get-ADUser -Identity '$($member.SamAccountName)' -Properties DisplayName, EmailAddress, Title, Department, Manager, Enabled, LastLogonDate, PasswordLastSet, AccountExpirationDate"
                            Add-AuditCommand -CommandName "Get-ADUser" -CommandText $cmd -Description "Retrieving user details for group member" -CaptureScreenshot
                        }
                        $user = Get-ADUser -Identity $member -Properties DisplayName, EmailAddress, Title, Department, Manager, Enabled, LastLogonDate, PasswordLastSet, AccountExpirationDate
                        
                        if ($user.Enabled -or $IncludeDisabledUsers) {
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
                            
                            $groupData.Members += $memberData
                            
                            if ($user.Enabled) {
                                $groupData.EnabledMemberCount++
                            } else {
                                $groupData.DisabledMemberCount++
                            }
                        }
                    } catch {
                        Write-Warning "Failed to get details for user: $($member.SamAccountName)"
                    }
                } elseif ($member.objectClass -eq 'group') {
                    $memberData = [PSCustomObject]@{
                        DisplayName = $member.Name
                        SamAccountName = $member.SamAccountName
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
                    $groupData.Members += $memberData
                }
            }
            
            $groupData.MemberCount = $groupData.Members.Count
            $results += $groupData
        }
        
        return $results
        
    } catch {
        Write-Error "Failed to retrieve AD group data: $_"
        throw
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
    Get-ADPermissionsAudit -TargetOU "OU=Servers,DC=company,DC=com" -IncludeInherited
#>
function Get-ADPermissionsAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetOU,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeInherited
    )
    
    try {
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
        
    } catch {
        Write-Error "Failed to audit permissions: $_"
        throw
    }
}

<#
.SYNOPSIS
    Exports AD group audit data to Excel format.

.DESCRIPTION
    Creates a formatted Excel workbook with group summaries and detailed member lists.
    Each group gets its own worksheet with sortable tables.

.PARAMETER GroupAuditData
    Output from Get-ADGroupAuditData function.

.PARAMETER OutputPath
    Path for the Excel file to create.

.PARAMETER OpenAfterExport
    Open the Excel file after creation.

.EXAMPLE
    Export-ADGroupMembers -GroupAuditData $auditData -OutputPath "C:\\Audits\\groups.xlsx"
#>
function Export-ADGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$GroupAuditData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$OpenAfterExport
    )
    
    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $workbook = $excel.Workbooks.Add()
        
        $summarySheet = $workbook.Worksheets.Item(1)
        $summarySheet.Name = "Group Summary"
        
        $summaryHeaders = @("Group Name", "Description", "Type", "Scope", "Managed By", "Total Members", "Enabled Users", "Disabled Users", "Created", "Modified", "Last Audit")
        for ($i = 0; $i -lt $summaryHeaders.Count; $i++) {
            $summarySheet.Cells.Item(1, $i + 1) = $summaryHeaders[$i]
            $summarySheet.Cells.Item(1, $i + 1).Font.Bold = $true
        }
        
        $row = 2
        foreach ($group in $GroupAuditData) {
            $summarySheet.Cells.Item($row, 1) = $group.GroupName
            $summarySheet.Cells.Item($row, 2) = $group.Description
            $summarySheet.Cells.Item($row, 3) = $group.GroupCategory
            $summarySheet.Cells.Item($row, 4) = $group.GroupScope
            $summarySheet.Cells.Item($row, 5) = $group.ManagedBy
            $summarySheet.Cells.Item($row, 6) = $group.MemberCount
            $summarySheet.Cells.Item($row, 7) = $group.EnabledMemberCount
            $summarySheet.Cells.Item($row, 8) = $group.DisabledMemberCount
            $summarySheet.Cells.Item($row, 9) = $group.Created
            $summarySheet.Cells.Item($row, 10) = $group.Modified
            $summarySheet.Cells.Item($row, 11) = $group.LastAuditDate
            $row++
        }
        
        $summarySheet.UsedRange.EntireColumn.AutoFit() | Out-Null
        
        foreach ($group in $GroupAuditData) {
            if ($group.Members.Count -gt 0) {
                $sheet = $workbook.Worksheets.Add([System.Reflection.Missing]::Value, $workbook.Worksheets.Item($workbook.Worksheets.Count))
                $sheetName = $group.GroupName -replace '[^\w\s-]', ''
                $sheetName = $sheetName.Substring(0, [Math]::Min(31, $sheetName.Length))
                $sheet.Name = $sheetName
                
                $headers = @("Display Name", "Username", "Email", "Title", "Department", "Manager", "Type", "Enabled", "Last Logon", "Password Last Set", "Account Expires")
                for ($i = 0; $i -lt $headers.Count; $i++) {
                    $sheet.Cells.Item(1, $i + 1) = $headers[$i]
                    $sheet.Cells.Item(1, $i + 1).Font.Bold = $true
                }
                
                $row = 2
                foreach ($member in $group.Members) {
                    $sheet.Cells.Item($row, 1) = $member.DisplayName
                    $sheet.Cells.Item($row, 2) = $member.SamAccountName
                    $sheet.Cells.Item($row, 3) = $member.EmailAddress
                    $sheet.Cells.Item($row, 4) = $member.Title
                    $sheet.Cells.Item($row, 5) = $member.Department
                    $sheet.Cells.Item($row, 6) = $member.Manager
                    $sheet.Cells.Item($row, 7) = $member.MemberType
                    $sheet.Cells.Item($row, 8) = $member.Enabled
                    $sheet.Cells.Item($row, 9) = $member.LastLogonDate
                    $sheet.Cells.Item($row, 10) = $member.PasswordLastSet
                    $sheet.Cells.Item($row, 11) = $member.AccountExpires
                    $row++
                }
                
                $sheet.UsedRange.EntireColumn.AutoFit() | Out-Null
                
                $listObject = $sheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $sheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes)
                $listObject.TableStyle = "TableStyleMedium2"
            }
        }
        
        $workbook.SaveAs($OutputPath)
        $workbook.Close()
        $excel.Quit()
        
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        
        if ($OpenAfterExport) {
            Start-Process $OutputPath
        }
        
        Write-Host "Excel report saved to: $OutputPath" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to export to Excel: $_"
        if ($excel) {
            $excel.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        }
        throw
    }
}

Export-ModuleMember -Function Get-ADGroupAuditData, Get-ADPermissionsAudit, Export-ADGroupMembers