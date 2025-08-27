# Enhanced Web Report Generator - Self-contained browseable reports
# Creates complete HTML reports with embedded images, data, and interactive features

function New-EnhancedWebReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$AuditData,
        
        [Parameter(Mandatory=$false)]
        [string[]]$ScreenshotPaths = @(),
        
        [Parameter(Mandatory=$false)]
        [string[]]$CsvFiles = @(),
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportTitle = "Active Directory Audit Report",
        
        [Parameter(Mandatory=$false)]
        [string]$CompanyName = "Your Organization",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$CustomMetadata = @{},
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeCharts
    )
    
    Write-Host "Generating enhanced web report..." -ForegroundColor Yellow
    
    # Embed all images as base64
    $embeddedImages = @()
    foreach ($imagePath in $ScreenshotPaths) {
        if (Test-Path $imagePath) {
            try {
                $imageBytes = [System.IO.File]::ReadAllBytes($imagePath)
                $base64 = [Convert]::ToBase64String($imageBytes)
                $fileName = Split-Path $imagePath -Leaf
                $fileExt = [System.IO.Path]::GetExtension($imagePath).ToLower()
                
                $mimeType = switch ($fileExt) {
                    '.png' { 'image/png' }
                    '.jpg' { 'image/jpeg' }
                    '.jpeg' { 'image/jpeg' }
                    '.gif' { 'image/gif' }
                    '.bmp' { 'image/bmp' }
                    default { 'image/png' }
                }
                
                $embeddedImages += @{
                    FileName = $fileName
                    MimeType = $mimeType
                    Base64Data = $base64
                    OriginalPath = $imagePath
                    Timestamp = (Get-Item $imagePath).LastWriteTime
                }
            } catch {
                Write-Warning "Failed to embed image $imagePath : $_"
            }
        }
    }
    
    # Embed CSV data as JSON
    $embeddedData = @{}
    foreach ($csvFile in $CsvFiles) {
        if (Test-Path $csvFile) {
            try {
                $csvData = Import-Csv $csvFile
                $fileName = Split-Path $csvFile -Leaf
                $embeddedData[$fileName] = $csvData
            } catch {
                Write-Warning "Failed to embed CSV $csvFile : $_"
            }
        }
    }
    
    # Calculate statistics
    $stats = Get-AuditStatistics -AuditData $AuditData
    
    # Generate the complete HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ReportTitle</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary-color: #1e40af;
            --secondary-color: #3b82f6;
            --success-color: #059669;
            --warning-color: #d97706;
            --danger-color: #dc2626;
            --light-bg: #f8fafc;
            --dark-bg: #1e293b;
            --border-color: #e2e8f0;
            --text-color: #334155;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
            line-height: 1.6; 
            color: var(--text-color); 
            background: var(--light-bg);
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: var(--shadow);
        }
        
        .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; font-weight: 700; }
        .header p { font-size: 1.2rem; opacity: 0.9; }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        
        .nav-tabs {
            display: flex;
            background: white;
            border-radius: 8px;
            box-shadow: var(--shadow);
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .nav-tab {
            flex: 1;
            padding: 1rem 2rem;
            background: white;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            transition: all 0.3s ease;
            border-right: 1px solid var(--border-color);
        }
        
        .nav-tab:last-child { border-right: none; }
        .nav-tab:hover { background: var(--light-bg); }
        .nav-tab.active { background: var(--primary-color); color: white; }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .section {
            background: white;
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 12px;
            box-shadow: var(--shadow);
        }
        
        .section h2 {
            color: var(--primary-color);
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 3px solid var(--secondary-color);
            font-size: 1.8rem;
        }
        
        .section h3 {
            color: var(--text-color);
            margin: 1.5rem 0 1rem 0;
            font-size: 1.4rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            padding: 2rem;
            border-radius: 12px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px -5px rgba(0, 0, 0, 0.1);
        }
        
        .stat-card.critical {
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            border-color: var(--danger-color);
        }
        
        .stat-card.warning {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border-color: var(--warning-color);
        }
        
        .stat-card.success {
            background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
            border-color: var(--success-color);
        }
        
        .stat-card h3 {
            font-size: 3rem;
            font-weight: 700;
            margin: 0.5rem 0;
            color: var(--primary-color);
        }
        
        .stat-card p {
            color: var(--text-color);
            font-size: 1.1rem;
            font-weight: 500;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        
        .data-table th {
            background: var(--primary-color);
            color: white;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .data-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .data-table tr:hover {
            background: var(--light-bg);
        }
        
        .data-table tr:last-child td {
            border-bottom: none;
        }
        
        .image-gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }
        
        .image-item {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            transition: transform 0.3s ease;
        }
        
        .image-item:hover {
            transform: translateY(-2px);
        }
        
        .image-item img {
            width: 100%;
            height: auto;
            border-radius: 8px;
            cursor: pointer;
            transition: transform 0.3s ease;
        }
        
        .image-item img:hover {
            transform: scale(1.02);
        }
        
        .image-caption {
            margin-top: 1rem;
            font-weight: 500;
            color: var(--text-color);
        }
        
        .image-timestamp {
            font-size: 0.9rem;
            color: #64748b;
            margin-top: 0.5rem;
        }
        
        .search-controls {
            display: flex;
            gap: 1rem;
            margin: 1.5rem 0;
            flex-wrap: wrap;
        }
        
        .search-input, .filter-select {
            padding: 0.75rem 1rem;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        
        .search-input:focus, .filter-select:focus {
            outline: none;
            border-color: var(--secondary-color);
        }
        
        .search-input {
            flex: 1;
            min-width: 300px;
        }
        
        .btn {
            padding: 0.75rem 1.5rem;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn:hover {
            background: var(--secondary-color);
            transform: translateY(-1px);
        }
        
        .btn-secondary {
            background: #6b7280;
        }
        
        .btn-secondary:hover {
            background: #4b5563;
        }
        
        .metadata-table {
            background: var(--dark-bg);
            color: white;
            border-radius: 8px;
            margin-bottom: 2rem;
        }
        
        .metadata-table td {
            border-color: #374151;
        }
        
        .metadata-table td:first-child {
            font-weight: 600;
            width: 200px;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }
        
        .badge-success { background: var(--success-color); color: white; }
        .badge-warning { background: var(--warning-color); color: white; }
        .badge-danger { background: var(--danger-color); color: white; }
        .badge-info { background: var(--secondary-color); color: white; }
        
        .hidden { display: none !important; }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
        }
        
        .modal-content {
            margin: 5% auto;
            display: block;
            max-width: 90%;
            max-height: 80%;
        }
        
        .close {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover { color: #bbb; }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header h1 { font-size: 2rem; }
            .nav-tabs { flex-direction: column; }
            .stats-grid { grid-template-columns: 1fr; }
            .image-gallery { grid-template-columns: 1fr; }
            .search-controls { flex-direction: column; }
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            width: 100%;
            margin: 2rem 0;
            background: white;
            border-radius: 8px;
            padding: 1rem;
            box-shadow: var(--shadow);
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }
        
        @media print {
            .nav-tabs, .search-controls, .btn { display: none; }
            .section { page-break-inside: avoid; }
            body { background: white; }
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>$ReportTitle</h1>
        <p>$CompanyName - Generated $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
    </header>
    
    <div class="container">
        <!-- Metadata Section -->
        <section class="section">
            <table class="data-table metadata-table">
"@

    # Add metadata
    foreach ($key in $CustomMetadata.Keys) {
        $htmlContent += @"
                <tr>
                    <td>$key</td>
                    <td>$($CustomMetadata[$key])</td>
                </tr>
"@
    }

    $htmlContent += @"
                <tr>
                    <td>Report Generated</td>
                    <td>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</td>
                </tr>
                <tr>
                    <td>Generated By</td>
                    <td>$env:USERNAME</td>
                </tr>
                <tr>
                    <td>Domain</td>
                    <td>$env:USERDNSDOMAIN</td>
                </tr>
                <tr>
                    <td>Total Data Points</td>
                    <td>$($AuditData.Count)</td>
                </tr>
                <tr>
                    <td>Screenshots Embedded</td>
                    <td>$($embeddedImages.Count)</td>
                </tr>
                <tr>
                    <td>Data Files Embedded</td>
                    <td>$($embeddedData.Keys.Count)</td>
                </tr>
            </table>
        </section>
        
        <!-- Navigation Tabs -->
        <nav class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('summary')">Executive Summary</button>
            <button class="nav-tab" onclick="showTab('data')">Detailed Data</button>
"@

    if ($embeddedImages.Count -gt 0) {
        $htmlContent += '<button class="nav-tab" onclick="showTab(' + "'screenshots'" + ')">Screenshots</button>'
    }
    
    if ($embeddedData.Keys.Count -gt 0) {
        $htmlContent += '<button class="nav-tab" onclick="showTab(' + "'exports'" + ')">Data Exports</button>'
    }

    $htmlContent += @"
        </nav>
        
        <!-- Summary Tab -->
        <div id="summary" class="tab-content active">
            <section class="section">
                <h2>Executive Summary</h2>
                <div class="stats-grid">
"@

    # Add statistics cards
    foreach ($stat in $stats.GetEnumerator()) {
        $cardClass = ""
        if ($stat.Name -match "Error|Failed|Critical") {
            $cardClass = "critical"
        } elseif ($stat.Name -match "Warning|Issue") {
            $cardClass = "warning"
        } elseif ($stat.Name -match "Success|Complete|Valid") {
            $cardClass = "success"
        }
        
        $htmlContent += @"
                    <div class="stat-card $cardClass">
                        <p>$($stat.Name -replace '([A-Z])', ' $1' -replace '^ ', '')</p>
                        <h3>$($stat.Value)</h3>
                    </div>
"@
    }

    $htmlContent += @"
                </div>
                
                <div class="charts-grid">
                    <div class="chart-container">
                        <canvas id="memberDistributionChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="domainBreakdownChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="groupSizeChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="enabledDisabledChart"></canvas>
                    </div>
                </div>
            </section>
        </div>
        
        <!-- Data Tab -->
        <div id="data" class="tab-content">
            <section class="section">
                <h2>Audit Results</h2>
                <div class="search-controls">
                    <input type="text" class="search-input" id="dataSearch" placeholder="Search audit data..." onkeyup="searchData()">
                    <button class="btn" onclick="exportTableToCSV('audit-data-table', 'audit-results.csv')">Export CSV</button>
                </div>
                
                <table class="data-table" id="audit-data-table">
                    <thead>
                        <tr>
"@

    # Add table headers based on first data item
    if ($AuditData.Count -gt 0) {
        $firstItem = $AuditData[0]
        if ($firstItem -is [PSCustomObject]) {
            foreach ($prop in $firstItem.PSObject.Properties) {
                $htmlContent += "<th>$($prop.Name)</th>"
            }
        } else {
            $htmlContent += "<th>Group</th><th>Domain</th><th>Members</th><th>Status</th>"
        }
    }

    $htmlContent += @"
                        </tr>
                    </thead>
                    <tbody>
"@

    # Add data rows
    foreach ($item in $AuditData) {
        $htmlContent += "<tr>"
        if ($item -is [PSCustomObject]) {
            foreach ($prop in $item.PSObject.Properties) {
                $value = if ($prop.Value) { $prop.Value } else { "N/A" }
                $htmlContent += "<td>$value</td>"
            }
        } else {
            $htmlContent += "<td>$item</td><td>N/A</td><td>N/A</td><td>N/A</td>"
        }
        $htmlContent += "</tr>"
    }

    $htmlContent += @"
                    </tbody>
                </table>
            </section>
        </div>
"@

    # Screenshots Tab
    if ($embeddedImages.Count -gt 0) {
        $htmlContent += @"
        <div id="screenshots" class="tab-content">
            <section class="section">
                <h2>Audit Screenshots</h2>
                <div class="image-gallery">
"@
        foreach ($image in $embeddedImages) {
            $htmlContent += @"
                    <div class="image-item">
                        <img src="data:$($image.MimeType);base64,$($image.Base64Data)" 
                             alt="$($image.FileName)" 
                             onclick="openModal(this)">
                        <div class="image-caption">$($image.FileName)</div>
                        <div class="image-timestamp">Captured: $($image.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))</div>
                    </div>
"@
        }
        $htmlContent += @"
                </div>
            </section>
        </div>
"@
    }

    # Data Exports Tab
    if ($embeddedData.Keys.Count -gt 0) {
        $htmlContent += @"
        <div id="exports" class="tab-content">
            <section class="section">
                <h2>Embedded Data Files</h2>
"@
        foreach ($dataFile in $embeddedData.Keys) {
            $data = $embeddedData[$dataFile]
            $htmlContent += @"
                <h3>$dataFile</h3>
                <button class="btn btn-secondary" onclick="downloadCSV('$dataFile', '$($dataFile -replace '\.csv$', '')')">Download CSV</button>
                <table class="data-table" style="margin-top: 1rem;">
                    <thead>
                        <tr>
"@
            if ($data.Count -gt 0) {
                foreach ($prop in $data[0].PSObject.Properties) {
                    $htmlContent += "<th>$($prop.Name)</th>"
                }
                $htmlContent += @"
                        </tr>
                    </thead>
                    <tbody>
"@
                foreach ($row in $data | Select-Object -First 100) {  # Limit display to first 100 rows
                    $htmlContent += "<tr>"
                    foreach ($prop in $row.PSObject.Properties) {
                        $value = if ($prop.Value) { $prop.Value } else { "" }
                        $htmlContent += "<td>$value</td>"
                    }
                    $htmlContent += "</tr>"
                }
            }
            $htmlContent += "</tbody></table>"
        }
        $htmlContent += "</section></div>"
    }

    $htmlContent += @"
    </div>
    
    <!-- Image Modal -->
    <div id="imageModal" class="modal">
        <span class="close" onclick="closeModal()">&times;</span>
        <img class="modal-content" id="modalImage">
    </div>
    
    <!-- Chart.js Library -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
        // Audit data for charts
        const auditData = $(($AuditData | ConvertTo-Json -Depth 3 -Compress) -replace '"', '\"');
        const auditStats = $(($stats | ConvertTo-Json -Depth 2 -Compress) -replace '"', '\"');
        
        // Embedded data for JavaScript access
        const embeddedData = {
"@

    # Add embedded data as JSON for JavaScript
    foreach ($dataFile in $embeddedData.Keys) {
        $jsonData = $embeddedData[$dataFile] | ConvertTo-Json -Depth 5 -Compress
        $htmlContent += "'$dataFile': $jsonData,"
    }

    $htmlContent += @"
        };
        
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
        
        function searchData() {
            const searchTerm = document.getElementById('dataSearch').value.toLowerCase();
            const table = document.getElementById('audit-data-table');
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        function exportTableToCSV(tableId, filename) {
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tr:not([style*="display: none"])');
            let csv = [];
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td, th');
                const rowData = Array.from(cells).map(cell => 
                    '"' + cell.textContent.replace(/"/g, '""') + '"'
                );
                csv.push(rowData.join(','));
            });
            
            downloadCSVContent(csv.join('\n'), filename);
        }
        
        function downloadCSV(dataKey, filename) {
            const data = embeddedData[dataKey];
            if (!data || data.length === 0) return;
            
            const headers = Object.keys(data[0]);
            let csv = headers.map(h => '"' + h + '"').join(',') + '\n';
            
            data.forEach(row => {
                const values = headers.map(header => {
                    const value = row[header] || '';
                    return '"' + String(value).replace(/"/g, '""') + '"';
                });
                csv += values.join(',') + '\n';
            });
            
            downloadCSVContent(csv, filename + '.csv');
        }
        
        function downloadCSVContent(csvContent, filename) {
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
        
        function openModal(img) {
            const modal = document.getElementById('imageModal');
            const modalImg = document.getElementById('modalImage');
            modal.style.display = 'block';
            modalImg.src = img.src;
        }
        
        function closeModal() {
            document.getElementById('imageModal').style.display = 'none';
        }
        
        // Close modal when clicking outside the image
        document.getElementById('imageModal').onclick = function(event) {
            if (event.target === this) {
                closeModal();
            }
        }
        
        // Keyboard navigation
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
        
        // Auto-resize tables for mobile
        window.addEventListener('resize', function() {
            // Add responsive table handling if needed
        });
        
        // Generate charts when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            generateCharts();
        });
        
        function generateCharts() {
            // Member Distribution Chart
            if (document.getElementById('memberDistributionChart')) {
                generateMemberDistributionChart();
            }
            
            // Domain Breakdown Chart  
            if (document.getElementById('domainBreakdownChart')) {
                generateDomainBreakdownChart();
            }
            
            // Group Size Chart
            if (document.getElementById('groupSizeChart')) {
                generateGroupSizeChart();
            }
            
            // Enabled/Disabled Chart
            if (document.getElementById('enabledDisabledChart')) {
                generateEnabledDisabledChart();
            }
        }
        
        function generateMemberDistributionChart() {
            try {
                const ctx = document.getElementById('memberDistributionChart').getContext('2d');
                const memberCounts = auditData.map(item => item.MemberCount || 0);
                const groupNames = auditData.map(item => item.GroupName || 'Unknown');
                
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: groupNames,
                        datasets: [{
                            label: 'Members per Group',
                            data: memberCounts,
                            backgroundColor: 'rgba(59, 130, 246, 0.8)',
                            borderColor: 'rgb(59, 130, 246)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Member Distribution Across Groups'
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            } catch (e) {
                console.warn('Could not generate member distribution chart:', e);
            }
        }
        
        function generateDomainBreakdownChart() {
            try {
                const ctx = document.getElementById('domainBreakdownChart').getContext('2d');
                const domains = {};
                
                auditData.forEach(item => {
                    const domain = item.Domain || 'Unknown';
                    domains[domain] = (domains[domain] || 0) + (item.MemberCount || 0);
                });
                
                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(domains),
                        datasets: [{
                            label: 'Members by Domain',
                            data: Object.values(domains),
                            backgroundColor: [
                                'rgba(59, 130, 246, 0.8)',
                                'rgba(16, 185, 129, 0.8)', 
                                'rgba(245, 158, 11, 0.8)',
                                'rgba(239, 68, 68, 0.8)',
                                'rgba(139, 92, 246, 0.8)',
                                'rgba(236, 72, 153, 0.8)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Member Distribution by Domain'
                            }
                        }
                    }
                });
            } catch (e) {
                console.warn('Could not generate domain breakdown chart:', e);
            }
        }
        
        function generateGroupSizeChart() {
            try {
                const ctx = document.getElementById('groupSizeChart').getContext('2d');
                const sizes = { 'Small (1-10)': 0, 'Medium (11-50)': 0, 'Large (51-200)': 0, 'XLarge (200+)': 0 };
                
                auditData.forEach(item => {
                    const count = item.MemberCount || 0;
                    if (count <= 10) sizes['Small (1-10)']++;
                    else if (count <= 50) sizes['Medium (11-50)']++;
                    else if (count <= 200) sizes['Large (51-200)']++;
                    else sizes['XLarge (200+)']++;
                });
                
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(sizes),
                        datasets: [{
                            label: 'Groups by Size',
                            data: Object.values(sizes),
                            backgroundColor: [
                                'rgba(34, 197, 94, 0.8)',
                                'rgba(59, 130, 246, 0.8)',
                                'rgba(245, 158, 11, 0.8)',
                                'rgba(239, 68, 68, 0.8)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Group Size Distribution'
                            }
                        }
                    }
                });
            } catch (e) {
                console.warn('Could not generate group size chart:', e);
            }
        }
        
        function generateEnabledDisabledChart() {
            try {
                const ctx = document.getElementById('enabledDisabledChart').getContext('2d');
                let totalEnabled = 0;
                let totalDisabled = 0;
                
                auditData.forEach(item => {
                    totalEnabled += item.EnabledMemberCount || 0;
                    totalDisabled += item.DisabledMemberCount || 0;
                });
                
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['Enabled Users', 'Disabled Users'],
                        datasets: [{
                            label: 'User Status',
                            data: [totalEnabled, totalDisabled],
                            backgroundColor: [
                                'rgba(34, 197, 94, 0.8)',
                                'rgba(239, 68, 68, 0.8)'
                            ],
                            borderColor: [
                                'rgb(34, 197, 94)',
                                'rgb(239, 68, 68)'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Enabled vs Disabled Users'
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            } catch (e) {
                console.warn('Could not generate enabled/disabled chart:', e);
            }
        }
    </script>
</body>
</html>
"@

    # Write the file
    $reportDir = Split-Path $OutputPath -Parent
    if (!(Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "Enhanced web report generated: $OutputPath" -ForegroundColor Green
    Write-Host "  - Embedded $($embeddedImages.Count) images" -ForegroundColor Cyan
    Write-Host "  - Embedded $($embeddedData.Keys.Count) data files" -ForegroundColor Cyan
    Write-Host "  - Report size: $([math]::Round((Get-Item $OutputPath).Length / 1MB, 2)) MB" -ForegroundColor Cyan
    
    return @{
        FilePath = $OutputPath
        EmbeddedImages = $embeddedImages.Count
        EmbeddedDataFiles = $embeddedData.Keys.Count
        AuditDataCount = $AuditData.Count
        GeneratedAt = Get-Date
        FileSize = (Get-Item $OutputPath).Length
    }
}

function Get-AuditStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$AuditData
    )
    
    $stats = @{
        TotalItems = $AuditData.Count
        UniqueGroups = 0
        TotalMembers = 0
        EnabledMembers = 0
        DisabledMembers = 0
        DomainsAudited = 0
        CriticalGroups = 0
        WarningItems = 0
    }
    
    $domains = @()
    
    foreach ($item in $AuditData) {
        if ($item.PSObject.Properties.Name -contains 'Domain') {
            $domains += $item.Domain
        }
        
        if ($item.PSObject.Properties.Name -contains 'MemberCount') {
            $stats.TotalMembers += [int]$item.MemberCount
        }
        
        if ($item.PSObject.Properties.Name -contains 'EnabledMemberCount') {
            $stats.EnabledMembers += [int]$item.EnabledMemberCount
        }
        
        if ($item.PSObject.Properties.Name -contains 'DisabledMemberCount') {
            $stats.DisabledMembers += [int]$item.DisabledMemberCount
        }
        
        if ($item.PSObject.Properties.Name -contains 'GroupName') {
            $stats.UniqueGroups++
            
            # Check for critical groups
            if ($item.GroupName -match 'Admin|Root|Enterprise|Schema') {
                $stats.CriticalGroups++
            }
        }
        
        # Check for warnings
        if ($item.PSObject.Properties.Name -contains 'Status' -and $item.Status -match 'Warning|Error') {
            $stats.WarningItems++
        }
    }
    
    $stats.DomainsAudited = ($domains | Select-Object -Unique).Count
    
    return $stats
}

# Functions are automatically available when dot-sourced
# Export-ModuleMember -Function New-EnhancedWebReport, Get-AuditStatistics