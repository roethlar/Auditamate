# Group Policy Objects (GPO) Security Audit Module  
# Comprehensive audit of GPO permissions, settings, and security configurations

function Get-GPOSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = $env:USERDNSDOMAIN,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeSettings,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeWMIFilters,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshots
    )
    
    Write-Host "Starting GPO Security Audit..." -ForegroundColor Cyan
    
    $auditResults = @{
        GPOPermissions = @()
        GPOSettings = @()
        WMIFilters = @()
        OrphanedGPOs = @()
        UnlinkedGPOs = @()
        Statistics = @{}
        Screenshots = @()
    }
    
    $auditStartTime = Get-Date
    
    try {
        # Check if GroupPolicy module is available
        if (!(Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Warning "GroupPolicy PowerShell module is not available. Install RSAT Group Policy Management Tools."
            return $null
        }
        
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        
        # Get all GPOs in the domain
        Write-Host "`nDiscovering Group Policy Objects..." -ForegroundColor Yellow
        $allGPOs = Get-GPO -All -Domain $Domain
        Write-Host "Found $($allGPOs.Count) GPOs in domain $Domain" -ForegroundColor Green
        
        # 1. GPO Permissions Audit
        Write-Host "`nAuditing GPO Permissions..." -ForegroundColor Yellow
        
        foreach ($gpo in $allGPOs) {
            try {
                $gpoPermissions = Get-GPPermissions -Guid $gpo.Id -All -Domain $Domain | ForEach-Object {
                    $permission = $_
                    
                    [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOID = $gpo.Id
                        GPOCreated = $gpo.CreationTime
                        GPOModified = $gpo.ModificationTime
                        Trustee = $permission.Trustee.Name
                        TrusteeType = $permission.Trustee.SidType
                        TrusteeDomain = $permission.Trustee.Domain
                        Permission = $permission.Permission
                        Inherited = $permission.Inherited
                        RiskLevel = Get-GPOPermissionRisk -Permission $permission -GPOName $gpo.DisplayName
                        AuditDate = Get-Date
                    }
                }
                
                $auditResults.GPOPermissions += $gpoPermissions
                
            } catch {
                Write-Warning "Failed to get permissions for GPO $($gpo.DisplayName): $_"
            }
        }
        
        Write-Host "Analyzed permissions for $($allGPOs.Count) GPOs" -ForegroundColor Green
        
        # 2. GPO Settings Audit (if requested)
        if ($IncludeSettings) {
            Write-Host "`nAuditing GPO Security Settings..." -ForegroundColor Yellow
            
            foreach ($gpo in $allGPOs) {
                try {
                    # Get GPO report in XML format for detailed analysis
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain
                    $xmlReport = [xml]$gpoReport
                    
                    # Analyze security settings
                    $securitySettings = Analyze-GPOSecuritySettings -XMLReport $xmlReport -GPO $gpo
                    $auditResults.GPOSettings += $securitySettings
                    
                } catch {
                    Write-Warning "Failed to analyze settings for GPO $($gpo.DisplayName): $_"
                }
            }
            
            Write-Host "Analyzed security settings for $($auditResults.GPOSettings.Count) GPOs" -ForegroundColor Green
        }
        
        # 3. WMI Filters Audit (if requested)
        if ($IncludeWMIFilters) {
            Write-Host "`nAuditing WMI Filters..." -ForegroundColor Yellow
            
            try {
                # Get WMI filters using WMI query
                $wmiFilters = Get-WmiObject -Namespace "root\rsop\computer" -Class "RSOP_WMIFilter" -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [PSCustomObject]@{
                            FilterName = $_.Name
                            FilterID = $_.ID
                            FilterQuery = $_.Query
                            FilterNamespace = $_.Namespace
                            Created = $_.CreationTime
                            Modified = $_.ModificationTime
                            RiskLevel = Get-WMIFilterRisk -Filter $_
                            AuditDate = Get-Date
                        }
                    }
                
                # Also check for WMI filters linked to GPOs
                foreach ($gpo in $allGPOs) {
                    try {
                        $gpoObject = [ADSI]"LDAP://CN={$($gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain -Domain $Domain).DistinguishedName)"
                        if ($gpoObject.gPCWQLFilter) {
                            $filterGuid = $gpoObject.gPCWQLFilter -replace '^\[', '' -replace '\]$', ''
                            
                            $linkedFilter = [PSCustomObject]@{
                                GPOName = $gpo.DisplayName
                                GPOID = $gpo.Id
                                LinkedWMIFilter = $filterGuid
                                AuditDate = Get-Date
                            }
                            
                            $wmiFilters += $linkedFilter
                        }
                    } catch {
                        # Ignore errors for individual GPOs
                    }
                }
                
                $auditResults.WMIFilters = $wmiFilters
                Write-Host "Found $($wmiFilters.Count) WMI filter configurations" -ForegroundColor Green
                
            } catch {
                Write-Warning "WMI Filter audit failed: $_"
            }
        }
        
        # 4. Identify Orphaned and Unlinked GPOs
        Write-Host "`nIdentifying Orphaned and Unlinked GPOs..." -ForegroundColor Yellow
        
        foreach ($gpo in $allGPOs) {
            try {
                # Check if GPO is linked anywhere
                $gpoLinks = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain
                $xmlReport = [xml]$gpoLinks
                
                $hasLinks = $false
                if ($xmlReport.GPO.LinksTo) {
                    $hasLinks = $true
                }
                
                if (!$hasLinks) {
                    $unlinkedGPO = [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOID = $gpo.Id
                        Created = $gpo.CreationTime
                        Modified = $gpo.ModificationTime
                        Owner = $gpo.Owner
                        Status = "Unlinked"
                        RiskLevel = "Medium"
                        AuditDate = Get-Date
                    }
                    
                    $auditResults.UnlinkedGPOs += $unlinkedGPO
                }
                
                # Check for orphaned GPOs (missing SYSVOL folder or AD object)
                $sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}"
                if (!(Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
                    $orphanedGPO = [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOID = $gpo.Id
                        Created = $gpo.CreationTime
                        Modified = $gpo.ModificationTime
                        Owner = $gpo.Owner
                        Status = "Missing SYSVOL"
                        RiskLevel = "High"
                        AuditDate = Get-Date
                    }
                    
                    $auditResults.OrphanedGPOs += $orphanedGPO
                }
                
            } catch {
                Write-Warning "Failed to analyze links for GPO $($gpo.DisplayName): $_"
            }
        }
        
        Write-Host "Found $($auditResults.UnlinkedGPOs.Count) unlinked GPOs and $($auditResults.OrphanedGPOs.Count) orphaned GPOs" -ForegroundColor Green
        
        # 5. Generate Statistics
        $auditResults.Statistics = @{
            TotalGPOs = $allGPOs.Count
            TotalPermissions = $auditResults.GPOPermissions.Count
            HighRiskPermissions = ($auditResults.GPOPermissions | Where-Object { $_.RiskLevel -eq "High" }).Count
            UnlinkedGPOs = $auditResults.UnlinkedGPOs.Count
            OrphanedGPOs = $auditResults.OrphanedGPOs.Count
            WMIFilters = $auditResults.WMIFilters.Count
            GPOsWithSettings = $auditResults.GPOSettings.Count
            PrivilegedGPOEditors = ($auditResults.GPOPermissions | Where-Object { $_.Permission -match "Edit|Full" -and $_.Trustee -notmatch "Domain Admins|Enterprise Admins|SYSTEM" }).Count
            AuditDuration = (Get-Date) - $auditStartTime
        }
        
        Write-Host "`nGPO Security Audit Summary:" -ForegroundColor Cyan
        Write-Host "  Total GPOs: $($auditResults.Statistics.TotalGPOs)" -ForegroundColor White
        Write-Host "  High Risk Permissions: $($auditResults.Statistics.HighRiskPermissions)" -ForegroundColor $(if ($auditResults.Statistics.HighRiskPermissions -gt 0) { "Red" } else { "Green" })
        Write-Host "  Unlinked GPOs: $($auditResults.Statistics.UnlinkedGPOs)" -ForegroundColor $(if ($auditResults.Statistics.UnlinkedGPOs -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  Orphaned GPOs: $($auditResults.Statistics.OrphanedGPOs)" -ForegroundColor $(if ($auditResults.Statistics.OrphanedGPOs -gt 0) { "Red" } else { "Green" })
        Write-Host "  Privileged GPO Editors: $($auditResults.Statistics.PrivilegedGPOEditors)" -ForegroundColor $(if ($auditResults.Statistics.PrivilegedGPOEditors -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  WMI Filters: $($auditResults.Statistics.WMIFilters)" -ForegroundColor White
        
        return $auditResults
        
    } catch {
        Write-Error "GPO Security audit failed: $_"
        return $null
    }
}

function Get-GPOPermissionRisk {
    param($Permission, $GPOName)
    
    $risk = "Low"
    
    # High-risk permissions
    if ($Permission.Permission -match "Edit|Full Control|Write") {
        $risk = "Medium"
    }
    
    # Non-standard trustees with high permissions
    if ($Permission.Permission -match "Edit|Full Control" -and 
        $Permission.Trustee.Name -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Group Policy Creator Owners") {
        $risk = "High"
    }
    
    # Everyone or Authenticated Users with edit rights
    if ($Permission.Trustee.Name -match "Everyone|Authenticated Users" -and 
        $Permission.Permission -match "Edit|Write") {
        $risk = "High"
    }
    
    # Critical GPOs with non-standard permissions
    if ($GPOName -match "Default Domain|Default Domain Controllers|Security|Password" -and
        $Permission.Permission -match "Edit|Write" -and
        $Permission.Trustee.Name -notmatch "Domain Admins|Enterprise Admins|SYSTEM") {
        $risk = "High"
    }
    
    return $risk
}

function Get-WMIFilterRisk {
    param($Filter)
    
    $risk = "Low"
    
    # Filters with broad queries
    if ($Filter.Query -match "SELECT \* FROM" -or $Filter.Query -match "Win32_ComputerSystem") {
        $risk = "Medium"
    }
    
    # Filters that could be used for privilege escalation
    if ($Filter.Query -match "Administrator|Admin|Domain|Enterprise") {
        $risk = "High"
    }
    
    return $risk
}

function Analyze-GPOSecuritySettings {
    param($XMLReport, $GPO)
    
    $settings = @()
    
    try {
        # Password Policy Settings
        if ($XMLReport.GPO.Computer.ExtensionData.Extension.Account) {
            $passwordSettings = $XMLReport.GPO.Computer.ExtensionData.Extension.Account
            
            $settings += [PSCustomObject]@{
                GPOName = $GPO.DisplayName
                GPOID = $GPO.Id
                SettingType = "Password Policy"
                SettingName = "Password Complexity"
                SettingValue = if ($passwordSettings.PasswordComplexity) { $passwordSettings.PasswordComplexity } else { "Not Configured" }
                RiskLevel = if ($passwordSettings.PasswordComplexity -eq "0") { "High" } else { "Low" }
                AuditDate = Get-Date
            }
        }
        
        # User Rights Assignment
        if ($XMLReport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment) {
            foreach ($userRight in $XMLReport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment) {
                $settings += [PSCustomObject]@{
                    GPOName = $GPO.DisplayName
                    GPOID = $GPO.Id
                    SettingType = "User Rights Assignment"
                    SettingName = $userRight.Name
                    SettingValue = ($userRight.Member.Name -join "; ")
                    RiskLevel = Get-UserRightRisk -UserRight $userRight.Name -Members $userRight.Member.Name
                    AuditDate = Get-Date
                }
            }
        }
        
        # Registry Settings
        if ($XMLReport.GPO.Computer.ExtensionData.Extension.RegistrySettings) {
            foreach ($regSetting in $XMLReport.GPO.Computer.ExtensionData.Extension.RegistrySettings.Registry) {
                $settings += [PSCustomObject]@{
                    GPOName = $GPO.DisplayName
                    GPOID = $GPO.Id
                    SettingType = "Registry"
                    SettingName = "$($regSetting.Properties.Key)\$($regSetting.Properties.Name)"
                    SettingValue = $regSetting.Properties.Value
                    RiskLevel = Get-RegistrySettingRisk -Key $regSetting.Properties.Key -Name $regSetting.Properties.Name
                    AuditDate = Get-Date
                }
            }
        }
        
    } catch {
        Write-Warning "Failed to analyze settings for GPO $($GPO.DisplayName): $_"
    }
    
    return $settings
}

function Get-UserRightRisk {
    param($UserRight, $Members)
    
    $highRiskRights = @(
        "SeDebugPrivilege",
        "SeTcbPrivilege", 
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege"
    )
    
    if ($UserRight -in $highRiskRights) {
        if ($Members -match "Everyone|Users|Authenticated Users") {
            return "High"
        } else {
            return "Medium"
        }
    }
    
    return "Low"
}

function Get-RegistrySettingRisk {
    param($Key, $Name)
    
    $highRiskKeys = @(
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
    )
    
    foreach ($riskKey in $highRiskKeys) {
        if ($Key -match [regex]::Escape($riskKey)) {
            return "Medium"
        }
    }
    
    return "Low"
}

function Export-GPOSecurityAuditReports {
    param(
        [Parameter(Mandatory=$true)]
        $AuditResults,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reports = @()
    
    # Export GPO Permissions
    if ($AuditResults.GPOPermissions.Count -gt 0) {
        $path = "$OutputDirectory\GPO_Permissions_$timestamp.csv"
        $AuditResults.GPOPermissions | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export GPO Settings
    if ($AuditResults.GPOSettings.Count -gt 0) {
        $path = "$OutputDirectory\GPO_SecuritySettings_$timestamp.csv"
        $AuditResults.GPOSettings | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Unlinked GPOs
    if ($AuditResults.UnlinkedGPOs.Count -gt 0) {
        $path = "$OutputDirectory\GPO_Unlinked_$timestamp.csv"
        $AuditResults.UnlinkedGPOs | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Orphaned GPOs
    if ($AuditResults.OrphanedGPOs.Count -gt 0) {
        $path = "$OutputDirectory\GPO_Orphaned_$timestamp.csv"
        $AuditResults.OrphanedGPOs | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export WMI Filters
    if ($AuditResults.WMIFilters.Count -gt 0) {
        $path = "$OutputDirectory\GPO_WMIFilters_$timestamp.csv"
        $AuditResults.WMIFilters | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Statistics
    $statsPath = "$OutputDirectory\GPO_Audit_Statistics_$timestamp.csv"
    $AuditResults.Statistics.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Metric = $_.Key
            Value = $_.Value
        }
    } | Export-Csv -Path $statsPath -NoTypeInformation
    $reports += $statsPath
    
    Write-Host "GPO Security audit reports exported:" -ForegroundColor Green
    $reports | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    
    return $reports
}