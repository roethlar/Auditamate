# Local Administrator Audit Module
# Audits local administrator group membership on Windows servers

<#
.SYNOPSIS
    Gets local administrator group members from a remote server.

.DESCRIPTION
    Retrieves members of the local Administrators group on specified servers.
    Handles both local accounts and domain accounts/groups.

.PARAMETER ComputerName
    Name of the computer to audit

.PARAMETER Credential
    PSCredential object for authentication (if needed)

.PARAMETER IncludeDisabled
    Include disabled accounts in the results

.PARAMETER ResolveDomainGroups
    Recursively resolve domain group memberships
#>
function Get-LocalAdminMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabled,
        
        [Parameter(Mandatory=$false)]
        [switch]$ResolveDomainGroups
    )
    
    try {
        Write-Verbose "Querying local administrators on $ComputerName"
        
        # Test connectivity
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            throw "Cannot reach server: $ComputerName"
        }
        
        # Build script block to run remotely
        $scriptBlock = {
            $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
            $members = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop
            
            $memberDetails = @()
            foreach ($member in $members) {
                $memberInfo = @{
                    Name = $member.Name
                    SID = $member.SID.Value
                    PrincipalSource = $member.PrincipalSource
                    ObjectClass = $member.ObjectClass
                    Server = $env:COMPUTERNAME
                    Enabled = $true
                    LastLogon = $null
                    PasswordLastSet = $null
                    Description = ""
                }
                
                # Get additional details based on type
                if ($member.PrincipalSource -eq "Local") {
                    try {
                        $localUser = Get-LocalUser -SID $member.SID -ErrorAction Stop
                        $memberInfo.Enabled = $localUser.Enabled
                        $memberInfo.LastLogon = $localUser.LastLogon
                        $memberInfo.PasswordLastSet = $localUser.PasswordLastSet
                        $memberInfo.Description = $localUser.Description
                    } catch {
                        # Not a user, might be a group
                    }
                }
                
                $memberDetails += [PSCustomObject]$memberInfo
            }
            
            return $memberDetails
        }
        
        # Execute remotely
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock = $scriptBlock
            ErrorAction = 'Stop'
        }
        
        if ($Credential) {
            $invokeParams.Credential = $Credential
        }
        
        $members = Invoke-Command @invokeParams
        
        # Filter disabled if requested
        if (-not $IncludeDisabled) {
            $members = $members | Where-Object { $_.Enabled -ne $false }
        }
        
        # Resolve domain groups if requested
        if ($ResolveDomainGroups) {
            $resolvedMembers = @()
            foreach ($member in $members) {
                if ($member.ObjectClass -eq 'Group' -and $member.PrincipalSource -eq 'ActiveDirectory') {
                    Write-Verbose "Resolving domain group: $($member.Name)"
                    
                    # Extract domain and group name
                    $parts = $member.Name -split '\\'
                    if ($parts.Count -eq 2) {
                        $domain = $parts[0]
                        $groupName = $parts[1]
                        
                        try {
                            $groupMembers = Get-ADGroupMember -Identity $groupName -Server $domain -Recursive
                            foreach ($groupMember in $groupMembers) {
                                $adUser = Get-ADUser -Identity $groupMember.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet, Description -Server $domain
                                
                                $resolvedMembers += [PSCustomObject]@{
                                    Name = "$domain\$($adUser.SamAccountName)"
                                    SID = $adUser.SID.Value
                                    PrincipalSource = 'ActiveDirectory'
                                    ObjectClass = 'User'
                                    Server = $ComputerName
                                    Enabled = $adUser.Enabled
                                    LastLogon = $adUser.LastLogonDate
                                    PasswordLastSet = $adUser.PasswordLastSet
                                    Description = $adUser.Description
                                    MemberOf = $member.Name
                                    ResolvedFrom = "DomainGroup"
                                }
                            }
                        } catch {
                            Write-Warning "Failed to resolve group $($member.Name): $_"
                            $resolvedMembers += $member
                        }
                    } else {
                        $resolvedMembers += $member
                    }
                } else {
                    $resolvedMembers += $member
                }
            }
            $members = $resolvedMembers
        }
        
        return $members
        
    } catch {
        Write-Error "Failed to audit $ComputerName : $_"
        return @{
            Server = $ComputerName
            Error = $_.Exception.Message
            Status = "Failed"
        }
    }
}

<#
.SYNOPSIS
    Audits local administrators across multiple servers.

.PARAMETER ServerList
    Array of server names to audit

.PARAMETER Credential
    PSCredential for authentication

.PARAMETER MaxConcurrent
    Maximum concurrent server queries (default: 10)

.PARAMETER IncludeOffline
    Include offline/unreachable servers in results

.PARAMETER CaptureCommands
    Capture PowerShell commands for evidence
#>
function Get-LocalAdminAuditData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ServerList,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrent = 10,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeOffline,
        
        [Parameter(Mandatory=$false)]
        [switch]$ResolveDomainGroups,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureCommands
    )
    
    Write-Host "Starting local administrator audit for $($ServerList.Count) servers..." -ForegroundColor Cyan
    
    # Initialize results
    $results = @()
    $failed = @()
    
    # Create runspace pool for parallel execution
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrent)
    $runspacePool.Open()
    
    $jobs = @()
    
    foreach ($server in $ServerList) {
        $powershell = [powershell]::Create()
        $powershell.RunspacePool = $runspacePool
        
        # Add script
        [void]$powershell.AddScript({
            param($Server, $Credential, $ResolveDomainGroups, $Functions)
            
            # Import functions
            . ([scriptblock]::Create($Functions))
            
            # Get admin members
            $params = @{
                ComputerName = $Server
                ResolveDomainGroups = $ResolveDomainGroups
            }
            
            if ($Credential) {
                $params.Credential = $Credential
            }
            
            Get-LocalAdminMembers @params
        })
        
        # Add parameters
        [void]$powershell.AddParameter('Server', $server)
        [void]$powershell.AddParameter('Credential', $Credential)
        [void]$powershell.AddParameter('ResolveDomainGroups', $ResolveDomainGroups)
        [void]$powershell.AddParameter('Functions', ${function:Get-LocalAdminMembers}.ToString())
        
        # Start job
        $jobs += @{
            PowerShell = $powershell
            Handle = $powershell.BeginInvoke()
            Server = $server
        }
    }
    
    # Wait for jobs and collect results
    $completed = 0
    while ($jobs.Count -gt 0) {
        $completedJobs = $jobs | Where-Object { $_.Handle.IsCompleted }
        
        foreach ($job in $completedJobs) {
            try {
                $result = $job.PowerShell.EndInvoke($job.Handle)
                
                if ($result -and $result[0].PSObject.Properties['Error']) {
                    $failed += $result[0]
                    Write-Host "Failed: $($job.Server) - $($result[0].Error)" -ForegroundColor Red
                } else {
                    $results += $result
                    $completed++
                    Write-Progress -Activity "Auditing Local Administrators" -Status "$completed of $($ServerList.Count) completed" -PercentComplete (($completed / $ServerList.Count) * 100)
                }
            } catch {
                $failed += @{
                    Server = $job.Server
                    Error = $_.Exception.Message
                    Status = "Failed"
                }
                Write-Host "Failed: $($job.Server) - $_" -ForegroundColor Red
            } finally {
                $job.PowerShell.Dispose()
            }
        }
        
        $jobs = $jobs | Where-Object { -not $_.Handle.IsCompleted }
        Start-Sleep -Milliseconds 100
    }
    
    Write-Progress -Activity "Auditing Local Administrators" -Completed
    
    # Close runspace pool
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    # Compile audit summary
    $summary = @{
        AuditDate = Get-Date
        ServersAudited = $ServerList.Count
        ServersSuccessful = $completed
        ServersFailed = $failed.Count
        TotalAdmins = ($results | Measure-Object).Count
        Results = $results
        Failed = $failed
    }
    
    # Group by server
    $serverGroups = $results | Group-Object -Property Server
    $summary.ByServer = @()
    
    foreach ($group in $serverGroups) {
        $serverSummary = @{
            Server = $group.Name
            AdminCount = $group.Count
            LocalAdmins = ($group.Group | Where-Object { $_.PrincipalSource -eq 'Local' }).Count
            DomainAdmins = ($group.Group | Where-Object { $_.PrincipalSource -eq 'ActiveDirectory' }).Count
            DisabledAccounts = ($group.Group | Where-Object { $_.Enabled -eq $false }).Count
            Members = $group.Group
        }
        $summary.ByServer += $serverSummary
    }
    
    # Find common admins across servers
    $adminNames = $results | Select-Object -ExpandProperty Name -Unique
    $summary.CommonAdmins = @()
    
    foreach ($admin in $adminNames) {
        $servers = $results | Where-Object { $_.Name -eq $admin } | Select-Object -ExpandProperty Server -Unique
        if ($servers.Count -gt 1) {
            $summary.CommonAdmins += @{
                Admin = $admin
                ServerCount = $servers.Count
                Servers = $servers
            }
        }
    }
    
    # Compliance checks
    $summary.ComplianceIssues = @()
    
    # Check for disabled accounts with access
    $disabledWithAccess = $results | Where-Object { $_.Enabled -eq $false }
    if ($disabledWithAccess) {
        $summary.ComplianceIssues += @{
            Type = "Disabled Accounts"
            Severity = "High"
            Count = $disabledWithAccess.Count
            Details = $disabledWithAccess | Select-Object Name, Server
        }
    }
    
    # Check for local accounts (potential security risk)
    $localAccounts = $results | Where-Object { $_.PrincipalSource -eq 'Local' -and $_.Name -notlike '*\Administrator' }
    if ($localAccounts) {
        $summary.ComplianceIssues += @{
            Type = "Non-default Local Accounts"
            Severity = "Medium"
            Count = $localAccounts.Count
            Details = $localAccounts | Select-Object Name, Server
        }
    }
    
    # Check for stale accounts (no login in 90 days)
    $staleAccounts = $results | Where-Object { 
        $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) 
    }
    if ($staleAccounts) {
        $summary.ComplianceIssues += @{
            Type = "Stale Accounts (>90 days)"
            Severity = "Medium"
            Count = $staleAccounts.Count
            Details = $staleAccounts | Select-Object Name, Server, LastLogon
        }
    }
    
    return $summary
}

<#
.SYNOPSIS
    Generates HTML report for local admin audit results.
#>
function New-LocalAdminHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AuditData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportTitle = "Local Administrator Audit Report",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$CustomMetadata = @{}
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportTitle</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #0066cc; margin-top: 30px; }
        .summary { background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .summary-stat { display: inline-block; margin: 10px 20px 10px 0; }
        .summary-stat .value { font-size: 24px; font-weight: bold; color: #0066cc; }
        .summary-stat .label { color: #666; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0066cc; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-success { color: green; }
        .status-failed { color: red; }
        .issue-high { background-color: #ffcccc; }
        .issue-medium { background-color: #fff3cd; }
        .issue-low { background-color: #d4edda; }
        .metadata { background-color: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .metadata-item { margin: 5px 0; }
        .filter-box { margin: 20px 0; padding: 10px; background-color: #f0f0f0; border-radius: 5px; }
        .filter-box input { margin: 0 10px; padding: 5px; }
    </style>
    <script>
        function filterTable(tableId, searchValue) {
            var table = document.getElementById(tableId);
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {
                var cells = rows[i].getElementsByTagName('td');
                var found = false;
                
                for (var j = 0; j < cells.length; j++) {
                    if (cells[j].innerHTML.toLowerCase().indexOf(searchValue.toLowerCase()) > -1) {
                        found = true;
                        break;
                    }
                }
                
                rows[i].style.display = found * '' : 'none';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>$ReportTitle</h1>
        
        <div class="metadata">
            <div class="metadata-item"><strong>Audit Date:</strong> $($AuditData.AuditDate)</div>
            <div class="metadata-item"><strong>Auditor:</strong> $env:USERNAME</div>
"@
    
    # Add custom metadata
    foreach ($key in $CustomMetadata.Keys) {
        $html += "            <div class='metadata-item'><strong>$key :</strong> $($CustomMetadata[$key])</div>`n"
    }
    
    $html += @"
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-stat">
                <div class="value">$($AuditData.ServersAudited)</div>
                <div class="label">Servers Audited</div>
            </div>
            <div class="summary-stat">
                <div class="value">$($AuditData.ServersSuccessful)</div>
                <div class="label">Successful</div>
            </div>
            <div class="summary-stat">
                <div class="value">$($AuditData.ServersFailed)</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-stat">
                <div class="value">$($AuditData.TotalAdmins)</div>
                <div class="label">Total Admin Accounts</div>
            </div>
            <div class="summary-stat">
                <div class="value">$($AuditData.ComplianceIssues.Count)</div>
                <div class="label">Compliance Issues</div>
            </div>
        </div>
        
        <h2>Server Summary</h2>
        <div class="filter-box">
            Search: <input type="text" onkeyup="filterTable('serverTable', this.value)" placeholder="Filter servers...">
        </div>
        <table id="serverTable">
            <tr>
                <th>Server</th>
                <th>Admin Count</th>
                <th>Local Admins</th>
                <th>Domain Admins</th>
                <th>Disabled Accounts</th>
                <th>Status</th>
            </tr>
"@
    
    # Add server rows
    foreach ($server in $AuditData.ByServer) {
        $html += @"
            <tr>
                <td>$($server.Server)</td>
                <td>$($server.AdminCount)</td>
                <td>$($server.LocalAdmins)</td>
                <td>$($server.DomainAdmins)</td>
                <td>$($server.DisabledAccounts)</td>
                <td class="status-success">Success</td>
            </tr>
"@
    }
    
    # Add failed servers
    foreach ($failed in $AuditData.Failed) {
        $html += @"
            <tr>
                <td>$($failed.Server)</td>
                <td colspan="4">Error: $($failed.Error)</td>
                <td class="status-failed">Failed</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <h2>All Administrator Accounts</h2>
        <div class="filter-box">
            Search: <input type="text" onkeyup="filterTable('adminTable', this.value)" placeholder="Filter administrators...">
        </div>
        <table id="adminTable">
            <tr>
                <th>Server</th>
                <th>Account Name</th>
                <th>Type</th>
                <th>Source</th>
                <th>Enabled</th>
                <th>Last Logon</th>
                <th>Password Last Set</th>
            </tr>
"@
    
    # Add admin account rows
    foreach ($admin in $AuditData.Results | Sort-Object Server, Name) {
        $enabled = if ($admin.Enabled) { "Yes" } else { "<span style='color:red'>No</span>" }
        $lastLogon = if ($admin.LastLogon) { $admin.LastLogon.ToString('yyyy-MM-dd') } else { "Never" }
        $pwdLastSet = if ($admin.PasswordLastSet) { $admin.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }
        
        $html += @"
            <tr>
                <td>$($admin.Server)</td>
                <td>$($admin.Name)</td>
                <td>$($admin.ObjectClass)</td>
                <td>$($admin.PrincipalSource)</td>
                <td>$enabled</td>
                <td>$lastLogon</td>
                <td>$pwdLastSet</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <h2>Common Administrators (Access to Multiple Servers)</h2>
        <table>
            <tr>
                <th>Administrator</th>
                <th>Server Count</th>
                <th>Servers</th>
            </tr>
"@
    
    # Add common admins
    foreach ($common in $AuditData.CommonAdmins | Sort-Object -Property ServerCount -Descending) {
        $serverList = $common.Servers -join ", "
        $html += @"
            <tr>
                <td>$($common.Admin)</td>
                <td>$($common.ServerCount)</td>
                <td>$serverList</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <h2>Compliance Issues</h2>
"@
    
    # Add compliance issues
    if ($AuditData.ComplianceIssues.Count -eq 0) {
        $html += "<p style='color: green;'>No compliance issues found.</p>"
    } else {
        foreach ($issue in $AuditData.ComplianceIssues) {
            $cssClass = "issue-$($issue.Severity.ToLower())"
            $html += @"
        <div class="$cssClass" style="padding: 10px; margin: 10px 0; border-radius: 5px;">
            <h3>$($issue.Type) (Severity: $($issue.Severity))</h3>
            <p>Found $($issue.Count) instance(s)</p>
            <table>
                <tr>
"@
            # Add headers based on issue type
            $headers = $issue.Details[0].PSObject.Properties.Name
            foreach ($header in $headers) {
                $html += "<th>$header</th>"
            }
            $html += "</tr>"
            
            # Add detail rows
            foreach ($detail in $issue.Details) {
                $html += "<tr>"
                foreach ($header in $headers) {
                    $value = $detail.$header
                    if ($value -is [DateTime]) {
                        $value = $value.ToString('yyyy-MM-dd')
                    }
                    $html += "<td>$value</td>"
                }
                $html += "</tr>"
            }
            
            $html += @"
            </table>
        </div>
"@
        }
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    # Save report
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
}

# Export functions
Export-ModuleMember -Function Get-LocalAdminMembers, Get-LocalAdminAuditData, New-LocalAdminHtmlReport