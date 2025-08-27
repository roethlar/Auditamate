# Service Account Discovery Module
# Comprehensive discovery of service accounts across AD and Windows systems

function Get-ServiceAccountInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = $env:USERDNSDOMAIN,
        
        [Parameter(Mandatory=$false)]
        [string[]]$ComputerList = @(),
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeBuiltIn,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshots
    )
    
    Write-Host "Starting Service Account Discovery..." -ForegroundColor Cyan
    
    $serviceAccounts = @()
    $auditStartTime = Get-Date
    
    # 1. AD Service Principal Names (SPNs) Discovery
    Write-Host "`nDiscovering AD Service Principal Names..." -ForegroundColor Yellow
    
    try {
        $spnAccounts = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName, LastLogonDate, PasswordLastSet, Enabled, Description, MemberOf |
            ForEach-Object {
                foreach ($spn in $_.ServicePrincipalName) {
                    [PSCustomObject]@{
                        AccountName = $_.SamAccountName
                        AccountType = "AD Service Account"
                        ServiceType = ($spn -split '/')[0]
                        ServiceTarget = ($spn -split '/')[1]
                        SPN = $spn
                        Enabled = $_.Enabled
                        LastLogon = $_.LastLogonDate
                        PasswordLastSet = $_.PasswordLastSet
                        PasswordAge = if ($_.PasswordLastSet) { (Get-Date) - $_.PasswordLastSet } else { $null }
                        Description = $_.Description
                        GroupMemberships = ($_.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name) -join "; "
                        Domain = $Domain
                        DiscoveryMethod = "SPN Query"
                        RiskLevel = Get-ServiceAccountRisk -Account $_ -Type "SPN"
                    }
                }
            }
        
        $serviceAccounts += $spnAccounts
        Write-Host "Found $($spnAccounts.Count) SPN-based service accounts" -ForegroundColor Green
        
        if ($CaptureScreenshots) {
            $screenshot = "$env:TEMP\ServiceAccounts_SPN_$(Get-Date -Format 'yyyyMMdd_HHmmss').png"
            Add-Type -AssemblyName System.Windows.Forms
            $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
            $bitmap.Save($screenshot, [System.Drawing.Imaging.ImageFormat]::Png)
            $graphics.Dispose()
            $bitmap.Dispose()
        }
        
    } catch {
        Write-Warning "SPN discovery failed: $_"
    }
    
    # 2. Computer Service Accounts Discovery
    Write-Host "`nDiscovering computer service accounts..." -ForegroundColor Yellow
    
    try {
        $computerAccounts = Get-ADComputer -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled, Description, MemberOf |
            Where-Object { $_.Name -notmatch '^[A-Z0-9-]+$' -or $_.Description -match 'service|sql|web|app' } |
            ForEach-Object {
                [PSCustomObject]@{
                    AccountName = $_.Name + "$"
                    AccountType = "Computer Service Account"
                    ServiceType = "Computer Account"
                    ServiceTarget = $_.DNSHostName
                    SPN = "N/A"
                    Enabled = $_.Enabled
                    LastLogon = $_.LastLogonDate
                    PasswordLastSet = $_.PasswordLastSet
                    PasswordAge = if ($_.PasswordLastSet) { (Get-Date) - $_.PasswordLastSet } else { $null }
                    Description = $_.Description
                    GroupMemberships = ($_.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name) -join "; "
                    Domain = $Domain
                    DiscoveryMethod = "Computer Account Analysis"
                    RiskLevel = Get-ServiceAccountRisk -Account $_ -Type "Computer"
                }
            }
        
        $serviceAccounts += $computerAccounts
        Write-Host "Found $($computerAccounts.Count) computer service accounts" -ForegroundColor Green
        
    } catch {
        Write-Warning "Computer account discovery failed: $_"
    }
    
    # 3. Windows Service Discovery (if computer list provided)
    if ($ComputerList.Count -gt 0) {
        Write-Host "`nDiscovering Windows services across $($ComputerList.Count) computers..." -ForegroundColor Yellow
        
        foreach ($computer in $ComputerList) {
            try {
                $services = Get-WmiObject -Class Win32_Service -ComputerName $computer |
                    Where-Object { $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService' -and $_.StartName -ne $null } |
                    ForEach-Object {
                        [PSCustomObject]@{
                            AccountName = $_.StartName
                            AccountType = "Windows Service Account"
                            ServiceType = $_.Name
                            ServiceTarget = $computer
                            SPN = "N/A"
                            Enabled = ($_.State -eq "Running")
                            LastLogon = "N/A"
                            PasswordLastSet = "N/A"
                            PasswordAge = "N/A"
                            Description = $_.Description
                            GroupMemberships = "Unknown"
                            Domain = if ($_.StartName -match '\\') { ($_.StartName -split '\\')[0] } else { "Local" }
                            DiscoveryMethod = "WMI Service Query"
                            RiskLevel = Get-ServiceAccountRisk -ServiceName $_.Name -StartName $_.StartName
                        }
                    }
                
                $serviceAccounts += $services
                Write-Host "  $computer: Found $($services.Count) service accounts" -ForegroundColor Gray
                
            } catch {
                Write-Warning "Failed to query services on $computer : $_"
            }
        }
    }
    
    # 4. Scheduled Task Service Accounts (local computer only)
    Write-Host "`nDiscovering scheduled task accounts..." -ForegroundColor Yellow
    
    try {
        $taskAccounts = Get-ScheduledTask | Where-Object { $_.Principal.UserId -notmatch 'SYSTEM|USERS|BUILTIN' -and $_.Principal.UserId } |
            ForEach-Object {
                [PSCustomObject]@{
                    AccountName = $_.Principal.UserId
                    AccountType = "Scheduled Task Account"
                    ServiceType = "Scheduled Task"
                    ServiceTarget = $_.TaskName
                    SPN = "N/A"
                    Enabled = ($_.State -eq "Ready")
                    LastLogon = "N/A"
                    PasswordLastSet = "N/A"
                    PasswordAge = "N/A"
                    Description = $_.Description
                    GroupMemberships = "Unknown"
                    Domain = if ($_.Principal.UserId -match '\\') { ($_.Principal.UserId -split '\\')[0] } else { "Local" }
                    DiscoveryMethod = "Scheduled Task Query"
                    RiskLevel = "Medium"
                }
            }
        
        $serviceAccounts += $taskAccounts
        Write-Host "Found $($taskAccounts.Count) scheduled task accounts" -ForegroundColor Green
        
    } catch {
        Write-Warning "Scheduled task discovery failed: $_"
    }
    
    # 5. Generate summary statistics
    $stats = @{
        TotalServiceAccounts = $serviceAccounts.Count
        SPNAccounts = ($serviceAccounts | Where-Object { $_.AccountType -eq "AD Service Account" }).Count
        ComputerAccounts = ($serviceAccounts | Where-Object { $_.AccountType -eq "Computer Service Account" }).Count
        WindowsServiceAccounts = ($serviceAccounts | Where-Object { $_.AccountType -eq "Windows Service Account" }).Count
        ScheduledTaskAccounts = ($serviceAccounts | Where-Object { $_.AccountType -eq "Scheduled Task Account" }).Count
        HighRiskAccounts = ($serviceAccounts | Where-Object { $_.RiskLevel -eq "High" }).Count
        DisabledAccounts = ($serviceAccounts | Where-Object { $_.Enabled -eq $false }).Count
        OldPasswordAccounts = ($serviceAccounts | Where-Object { $_.PasswordAge -and $_.PasswordAge.Days -gt 90 }).Count
        AuditDuration = (Get-Date) - $auditStartTime
    }
    
    Write-Host "`nService Account Discovery Summary:" -ForegroundColor Cyan
    Write-Host "  Total Service Accounts: $($stats.TotalServiceAccounts)" -ForegroundColor White
    Write-Host "  SPN-based Accounts: $($stats.SPNAccounts)" -ForegroundColor White
    Write-Host "  Computer Accounts: $($stats.ComputerAccounts)" -ForegroundColor White
    Write-Host "  Windows Service Accounts: $($stats.WindowsServiceAccounts)" -ForegroundColor White
    Write-Host "  Scheduled Task Accounts: $($stats.ScheduledTaskAccounts)" -ForegroundColor White
    Write-Host "  High Risk Accounts: $($stats.HighRiskAccounts)" -ForegroundColor $(if ($stats.HighRiskAccounts -gt 0) { "Red" } else { "Green" })
    Write-Host "  Disabled Accounts: $($stats.DisabledAccounts)" -ForegroundColor Yellow
    Write-Host "  Old Password Accounts (>90 days): $($stats.OldPasswordAccounts)" -ForegroundColor Yellow
    
    return @{
        ServiceAccounts = $serviceAccounts
        Statistics = $stats
        AuditMetadata = @{
            Domain = $Domain
            AuditDate = Get-Date
            ComputersScanned = $ComputerList.Count
            AuditDuration = $stats.AuditDuration
        }
    }
}

function Get-ServiceAccountRisk {
    param(
        $Account,
        $Type,
        $ServiceName,
        $StartName
    )
    
    # Risk assessment logic
    $risk = "Low"
    
    if ($Type -eq "SPN") {
        # High-risk SPNs
        if ($Account.ServicePrincipalName -match 'MSSQLSvc|HTTP|TERMSRV|WSMAN|HOST') {
            $risk = "High"
        }
        # Never logged on
        if (!$Account.LastLogonDate -or $Account.LastLogonDate -lt (Get-Date).AddDays(-365)) {
            $risk = "High"
        }
        # Old password
        if ($Account.PasswordLastSet -and (Get-Date) - $Account.PasswordLastSet -gt [TimeSpan]::FromDays(365)) {
            $risk = "High"
        }
        # Privileged groups
        if ($Account.MemberOf -match 'Admin|Power|Backup|Replicator') {
            $risk = "High"
        }
    } elseif ($Type -eq "Computer") {
        # Computers with unusual group memberships
        if ($Account.MemberOf -match 'Admin|Power|Backup') {
            $risk = "High"
        }
    } else {
        # Windows services and scheduled tasks
        if ($ServiceName -match 'SQL|Oracle|Apache|IIS|Exchange' -or $StartName -match 'admin|root|sa|dba') {
            $risk = "High"
        }
    }
    
    return $risk
}

function Export-ServiceAccountReport {
    param(
        [Parameter(Mandatory=$true)]
        $ServiceAccountData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    # Export detailed CSV
    $csvPath = "$OutputDirectory\ServiceAccounts_Detailed_$timestamp.csv"
    $ServiceAccountData.ServiceAccounts | Export-Csv -Path $csvPath -NoTypeInformation
    
    # Export summary CSV
    $summaryPath = "$OutputDirectory\ServiceAccounts_Summary_$timestamp.csv"
    $ServiceAccountData.Statistics.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Metric = $_.Key
            Value = $_.Value
        }
    } | Export-Csv -Path $summaryPath -NoTypeInformation
    
    # Export high-risk accounts
    $highRiskPath = "$OutputDirectory\ServiceAccounts_HighRisk_$timestamp.csv"
    $ServiceAccountData.ServiceAccounts | Where-Object { $_.RiskLevel -eq "High" } | 
        Export-Csv -Path $highRiskPath -NoTypeInformation
    
    Write-Host "Service account reports exported:" -ForegroundColor Green
    Write-Host "  Detailed: $csvPath" -ForegroundColor Cyan
    Write-Host "  Summary: $summaryPath" -ForegroundColor Cyan  
    Write-Host "  High Risk: $highRiskPath" -ForegroundColor Cyan
    
    return @{
        DetailedReport = $csvPath
        SummaryReport = $summaryPath
        HighRiskReport = $highRiskPath
    }
}