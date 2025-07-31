function New-ADHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$GroupAuditData,
        
        [Parameter(Mandatory=$false)]
        [object[]]$PermissionAuditData,
        
        [Parameter(Mandatory=$false)]
        [object[]]$Screenshots,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportTitle = "Active Directory Security Audit Report",
        
        [Parameter(Mandatory=$false)]
        [string]$CompanyName = "Your Company",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$CustomMetadata = @{}
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ReportTitle</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: #2c3e50; color: white; padding: 30px 0; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .metadata { background: #34495e; color: white; padding: 20px; margin-bottom: 30px; border-radius: 8px; }
        .metadata table { width: 100%; }
        .metadata td { padding: 8px; }
        .metadata td:first-child { font-weight: bold; width: 200px; }
        .section { background: white; padding: 30px; margin-bottom: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .section h2 { color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #3498db; }
        .section h3 { color: #34495e; margin: 20px 0 15px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #3498db; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .group-header { background: #ecf0f1; font-weight: bold; }
        .status-enabled { color: #27ae60; font-weight: bold; }
        .status-disabled { color: #e74c3c; font-weight: bold; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #e9ecef; }
        .stat-card h3 { color: #3498db; font-size: 2.5em; margin: 10px 0; }
        .stat-card p { color: #7f8c8d; font-size: 1.1em; }
        .permission-table { font-size: 0.9em; }
        .permission-allow { background: #d4edda; }
        .permission-deny { background: #f8d7da; }
        .screenshot-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin: 20px 0; }
        .screenshot-item { border: 1px solid #ddd; padding: 10px; border-radius: 8px; background: #f8f9fa; }
        .screenshot-item img { width: 100%; height: auto; border-radius: 4px; cursor: pointer; }
        .screenshot-item p { margin-top: 10px; font-size: 0.9em; color: #666; }
        .toc { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .toc ul { list-style: none; padding-left: 20px; }
        .toc a { color: #3498db; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .search-box { margin: 20px 0; padding: 10px; width: 100%; border: 2px solid #3498db; border-radius: 4px; font-size: 16px; }
        .export-buttons { margin: 20px 0; }
        .export-buttons button { background: #3498db; color: white; border: none; padding: 10px 20px; margin-right: 10px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .export-buttons button:hover { background: #2980b9; }
        @media print {
            .no-print { display: none; }
            .section { page-break-inside: avoid; }
            body { background: white; }
        }
        .filter-controls { margin: 20px 0; display: flex; gap: 10px; flex-wrap: wrap; }
        .filter-controls select, .filter-controls input { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .hidden { display: none; }
        .summary-table { margin: 20px 0; }
        .summary-table td, .summary-table th { text-align: center; }
        .highlight { background-color: #fff3cd !important; }
    </style>
</head>
<body>
    <header>
        <h1>$ReportTitle</h1>
        <p>$CompanyName - SOX Compliance Audit</p>
    </header>
    
    <div class="container">
        <div class="metadata">
            <table>
                <tr>
                    <td>Report Generated:</td>
                    <td>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</td>
                </tr>
                <tr>
                    <td>Generated By:</td>
                    <td>$env:USERNAME</td>
                </tr>
                <tr>
                    <td>Domain:</td>
                    <td>$env:USERDNSDOMAIN</td>
                </tr>
                <tr>
                    <td>Audit Period:</td>
                    <td>$(Get-Date -Format "yyyy-MM-dd")</td>
                </tr>
"@

    foreach ($key in $CustomMetadata.Keys) {
        $htmlContent += @"
                <tr>
                    <td>$key</td>
                    <td>$($CustomMetadata[$key])</td>
                </tr>
"@
    }

    $htmlContent += @"
            </table>
        </div>
        
        <nav class="toc section">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#executive-summary">Executive Summary</a></li>
                <li><a href="#group-analysis">Group Analysis</a></li>
"@

    if ($PermissionAuditData) {
        $htmlContent += '<li><a href="#permissions-audit">Permissions Audit</a></li>'
    }
    
    if ($Screenshots) {
        $htmlContent += '<li><a href="#screenshots">Screenshots</a></li>'
    }

    $htmlContent += @"
                <li><a href="#detailed-membership">Detailed Membership Data</a></li>
            </ul>
        </nav>
        
        <section id="executive-summary" class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <p>Total Groups Audited</p>
                    <h3>$($GroupAuditData.Count)</h3>
                </div>
                <div class="stat-card">
                    <p>Total Unique Users</p>
                    <h3>$($GroupAuditData.Members | Select-Object -ExpandProperty SamAccountName -Unique | Measure-Object).Count)</h3>
                </div>
                <div class="stat-card">
                    <p>Enabled Users</p>
                    <h3>$(($GroupAuditData | Measure-Object -Property EnabledMemberCount -Sum).Sum)</h3>
                </div>
                <div class="stat-card">
                    <p>Disabled Users</p>
                    <h3>$(($GroupAuditData | Measure-Object -Property DisabledMemberCount -Sum).Sum)</h3>
                </div>
            </div>
        </section>
        
        <section id="group-analysis" class="section">
            <h2>Group Analysis</h2>
            <div class="export-buttons no-print">
                <button onclick="exportTableToCSV('group-summary-table', 'group_summary.csv')">Export to CSV</button>
            </div>
            <table id="group-summary-table" class="summary-table">
                <thead>
                    <tr>
                        <th>Group Name</th>
                        <th>Type</th>
                        <th>Scope</th>
                        <th>Total Members</th>
                        <th>Enabled</th>
                        <th>Disabled</th>
                        <th>Managed By</th>
                        <th>Last Modified</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($group in $GroupAuditData) {
        $htmlContent += @"
                    <tr>
                        <td><strong>$($group.GroupName)</strong></td>
                        <td>$($group.GroupCategory)</td>
                        <td>$($group.GroupScope)</td>
                        <td>$($group.MemberCount)</td>
                        <td class="status-enabled">$($group.EnabledMemberCount)</td>
                        <td class="status-disabled">$($group.DisabledMemberCount)</td>
                        <td>$($group.ManagedBy)</td>
                        <td>$($group.Modified)</td>
                    </tr>
"@
    }

    $htmlContent += @"
                </tbody>
            </table>
        </section>
"@

    if ($PermissionAuditData) {
        $htmlContent += @"
        <section id="permissions-audit" class="section">
            <h2>Permissions Audit</h2>
            <table class="permission-table">
                <thead>
                    <tr>
                        <th>OU</th>
                        <th>Principal</th>
                        <th>Access Type</th>
                        <th>Rights</th>
                        <th>Inheritance</th>
                        <th>Inherited</th>
                    </tr>
                </thead>
                <tbody>
"@
        foreach ($perm in $PermissionAuditData) {
            $rowClass = if ($perm.AccessControlType -eq 'Allow') { 'permission-allow' } else { 'permission-deny' }
            $htmlContent += @"
                    <tr class="$rowClass">
                        <td>$($perm.OU)</td>
                        <td>$($perm.Principal)</td>
                        <td>$($perm.AccessControlType)</td>
                        <td>$($perm.ActiveDirectoryRights)</td>
                        <td>$($perm.InheritanceType)</td>
                        <td>$($perm.IsInherited)</td>
                    </tr>
"@
        }
        $htmlContent += @"
                </tbody>
            </table>
        </section>
"@
    }

    if ($Screenshots) {
        $htmlContent += @"
        <section id="screenshots" class="section">
            <h2>Audit Screenshots</h2>
            <div class="screenshot-grid">
"@
        foreach ($screenshot in $Screenshots) {
            $imgData = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($screenshot.FilePath))
            $htmlContent += @"
                <div class="screenshot-item">
                    <img src="data:image/png;base64,$imgData" alt="$($screenshot.FileName)" onclick="window.open(this.src)">
                    <p><strong>$($screenshot.FileName)</strong><br>Captured: $($screenshot.Timestamp)</p>
                </div>
"@
        }
        $htmlContent += @"
            </div>
        </section>
"@
    }

    $htmlContent += @"
        <section id="detailed-membership" class="section">
            <h2>Detailed Membership Data</h2>
            <input type="text" class="search-box no-print" id="memberSearch" placeholder="Search members..." onkeyup="searchMembers()">
            <div class="filter-controls no-print">
                <select id="groupFilter" onchange="filterMembers()">
                    <option value="">All Groups</option>
"@

    foreach ($group in $GroupAuditData) {
        $htmlContent += "<option value='$($group.GroupName)'>$($group.GroupName)</option>"
    }

    $htmlContent += @"
                </select>
                <select id="statusFilter" onchange="filterMembers()">
                    <option value="">All Status</option>
                    <option value="true">Enabled Only</option>
                    <option value="false">Disabled Only</option>
                </select>
            </div>
"@

    foreach ($group in $GroupAuditData) {
        if ($group.Members.Count -gt 0) {
            $htmlContent += @"
            <h3>$($group.GroupName) - Members ($($group.MemberCount))</h3>
            <table class="member-table" data-group="$($group.GroupName)">
                <thead>
                    <tr>
                        <th>Display Name</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Title</th>
                        <th>Department</th>
                        <th>Manager</th>
                        <th>Status</th>
                        <th>Last Logon</th>
                    </tr>
                </thead>
                <tbody>
"@
            foreach ($member in $group.Members) {
                $statusClass = if ($member.Enabled) { 'status-enabled' } else { 'status-disabled' }
                $statusText = if ($member.Enabled) { 'Enabled' } else { 'Disabled' }
                $htmlContent += @"
                    <tr data-enabled="$($member.Enabled)">
                        <td>$($member.DisplayName)</td>
                        <td>$($member.SamAccountName)</td>
                        <td>$($member.EmailAddress)</td>
                        <td>$($member.Title)</td>
                        <td>$($member.Department)</td>
                        <td>$($member.Manager)</td>
                        <td class="$statusClass">$statusText</td>
                        <td>$($member.LastLogonDate)</td>
                    </tr>
"@
            }
            $htmlContent += @"
                </tbody>
            </table>
"@
        }
    }

    $htmlContent += @"
        </section>
    </div>
    
    <script>
        function searchMembers() {
            const searchTerm = document.getElementById('memberSearch').value.toLowerCase();
            const tables = document.querySelectorAll('.member-table');
            
            tables.forEach(table => {
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    if (text.includes(searchTerm)) {
                        row.classList.remove('hidden');
                        if (searchTerm.length > 0) {
                            row.classList.add('highlight');
                        }
                    } else {
                        row.classList.add('hidden');
                        row.classList.remove('highlight');
                    }
                });
            });
        }
        
        function filterMembers() {
            const groupFilter = document.getElementById('groupFilter').value;
            const statusFilter = document.getElementById('statusFilter').value;
            const tables = document.querySelectorAll('.member-table');
            
            tables.forEach(table => {
                const tableGroup = table.getAttribute('data-group');
                if (groupFilter && tableGroup !== groupFilter) {
                    table.style.display = 'none';
                    table.previousElementSibling.style.display = 'none';
                } else {
                    table.style.display = 'table';
                    table.previousElementSibling.style.display = 'block';
                    
                    const rows = table.querySelectorAll('tbody tr');
                    rows.forEach(row => {
                        const isEnabled = row.getAttribute('data-enabled');
                        if (statusFilter && isEnabled !== statusFilter) {
                            row.classList.add('hidden');
                        } else {
                            row.classList.remove('hidden');
                        }
                    });
                }
            });
        }
        
        function exportTableToCSV(tableId, filename) {
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tr');
            let csv = [];
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td, th');
                const rowData = Array.from(cells).map(cell => '"' + cell.textContent.replace(/"/g, '""') + '"');
                csv.push(rowData.join(','));
            });
            
            const csvContent = csv.join('\\n');
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            window.URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
    
    return [PSCustomObject]@{
        FilePath = $OutputPath
        GroupCount = $GroupAuditData.Count
        TotalMembers = ($GroupAuditData | Measure-Object -Property MemberCount -Sum).Sum
        GeneratedAt = Get-Date
    }
}

Export-ModuleMember -Function New-ADHtmlReport