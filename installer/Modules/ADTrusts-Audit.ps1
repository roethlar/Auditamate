# Active Directory Trusts Audit Module
# Comprehensive audit of domain trusts, delegation rights, and cross-domain security

function Get-ADTrustAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = $env:USERDNSDOMAIN,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDelegation,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeForeignSecurityPrincipals,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshots
    )
    
    Write-Host "Starting AD Trusts Security Audit..." -ForegroundColor Cyan
    
    $auditResults = @{
        Trusts = @()
        Delegation = @()
        ForeignSecurityPrincipals = @()
        TrustAccounts = @()
        Statistics = @{}
        Screenshots = @()
    }
    
    $auditStartTime = Get-Date
    
    try {
        # 1. Domain Trust Relationships
        Write-Host "`nAuditing Domain Trust Relationships..." -ForegroundColor Yellow
        
        $trusts = Get-ADTrust -Filter * | ForEach-Object {
            $trust = $_
            
            # Get additional trust details
            $trustDetails = nltest /domain_trusts /v 2>$null | Where-Object { $_ -match $trust.Target }
            
            [PSCustomObject]@{
                SourceDomain = $Domain
                TargetDomain = $trust.Target
                TrustType = $trust.TrustType
                TrustDirection = $trust.Direction
                TrustAttributes = $trust.TrustAttributes
                ForestTransitive = $trust.ForestTransitive
                SelectiveAuthentication = $trust.SelectiveAuthentication
                SIDFilteringEnabled = $trust.SIDFilteringQuarantined
                Created = $trust.Created
                Modified = $trust.Modified
                TrustedDomainInformation = if ($trustDetails) { $trustDetails -join "; " } else { "N/A" }
                RiskLevel = Get-TrustRiskLevel -Trust $trust
                TrustStatus = Test-ADTrustConnection -Trust $trust
                AuditDate = Get-Date
            }
        }
        
        $auditResults.Trusts = $trusts
        Write-Host "Found $($trusts.Count) trust relationships" -ForegroundColor Green
        
        # 2. Trust Account Analysis
        Write-Host "`nAuditing Trust Accounts..." -ForegroundColor Yellow
        
        $trustAccounts = Get-ADUser -Filter "Name -like '*$*' -and Name -notlike '*krbtgt*'" -Properties LastLogonDate, PasswordLastSet, AccountExpirationDate, TrustedForDelegation | 
            Where-Object { $_.Name -match '\$$' -and $_.Name -notmatch '^[A-Z0-9-]+\$$' } |
            ForEach-Object {
                [PSCustomObject]@{
                    AccountName = $_.Name
                    DistinguishedName = $_.DistinguishedName
                    Enabled = $_.Enabled
                    LastLogon = $_.LastLogonDate
                    PasswordLastSet = $_.PasswordLastSet
                    PasswordAge = if ($_.PasswordLastSet) { (Get-Date) - $_.PasswordLastSet } else { $null }
                    AccountExpiration = $_.AccountExpirationDate
                    TrustedForDelegation = $_.TrustedForDelegation
                    RiskLevel = Get-TrustAccountRisk -Account $_
                    AuditDate = Get-Date
                }
            }
        
        $auditResults.TrustAccounts = $trustAccounts
        Write-Host "Found $($trustAccounts.Count) trust-related accounts" -ForegroundColor Green
        
        # 3. Delegation Rights Analysis (if requested)
        if ($IncludeDelegation) {
            Write-Host "`nAuditing Kerberos Delegation Rights..." -ForegroundColor Yellow
            
            # Constrained Delegation
            $constrainedDelegation = Get-ADUser -Filter "msDS-AllowedToDelegateTo -like '*'" -Properties msDS-AllowedToDelegateTo, TrustedForDelegation |
                ForEach-Object {
                    foreach ($service in $_."msDS-AllowedToDelegateTo") {
                        [PSCustomObject]@{
                            DelegationType = "Constrained"
                            PrincipalName = $_.Name
                            PrincipalType = "User"
                            ServicePrincipalName = $service
                            TrustedForDelegation = $_.TrustedForDelegation
                            RiskLevel = "High"
                            AuditDate = Get-Date
                        }
                    }
                }
            
            # Computer Constrained Delegation
            $computerConstrainedDelegation = Get-ADComputer -Filter "msDS-AllowedToDelegateTo -like '*'" -Properties msDS-AllowedToDelegateTo, TrustedForDelegation |
                ForEach-Object {
                    foreach ($service in $_."msDS-AllowedToDelegateTo") {
                        [PSCustomObject]@{
                            DelegationType = "Constrained"
                            PrincipalName = $_.Name
                            PrincipalType = "Computer"
                            ServicePrincipalName = $service
                            TrustedForDelegation = $_.TrustedForDelegation
                            RiskLevel = "High"
                            AuditDate = Get-Date
                        }
                    }
                }
            
            # Unconstrained Delegation (High Risk)
            $unconstrainedDelegation = Get-ADUser -Filter "TrustedForDelegation -eq 'True'" -Properties TrustedForDelegation |
                ForEach-Object {
                    [PSCustomObject]@{
                        DelegationType = "Unconstrained"
                        PrincipalName = $_.Name
                        PrincipalType = "User"
                        ServicePrincipalName = "All Services"
                        TrustedForDelegation = $_.TrustedForDelegation
                        RiskLevel = "Critical"
                        AuditDate = Get-Date
                    }
                }
            
            $computerUnconstrainedDelegation = Get-ADComputer -Filter "TrustedForDelegation -eq 'True'" -Properties TrustedForDelegation |
                Where-Object { $_.Name -notmatch '^[A-Z0-9-]+-DC[0-9]*$' } |  # Exclude domain controllers
                ForEach-Object {
                    [PSCustomObject]@{
                        DelegationType = "Unconstrained"
                        PrincipalName = $_.Name
                        PrincipalType = "Computer"
                        ServicePrincipalName = "All Services"
                        TrustedForDelegation = $_.TrustedForDelegation
                        RiskLevel = "Critical"
                        AuditDate = Get-Date
                    }
                }
            
            # Resource-Based Constrained Delegation
            $resourceBasedDelegation = Get-ADComputer -Filter "msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
                ForEach-Object {
                    [PSCustomObject]@{
                        DelegationType = "Resource-Based Constrained"
                        PrincipalName = $_.Name
                        PrincipalType = "Computer"
                        ServicePrincipalName = "Resource-Based"
                        TrustedForDelegation = $false
                        RiskLevel = "Medium"
                        AuditDate = Get-Date
                    }
                }
            
            $auditResults.Delegation = $constrainedDelegation + $computerConstrainedDelegation + $unconstrainedDelegation + $computerUnconstrainedDelegation + $resourceBasedDelegation
            Write-Host "Found $($auditResults.Delegation.Count) delegation configurations" -ForegroundColor Green
        }
        
        # 4. Foreign Security Principals (if requested)
        if ($IncludeForeignSecurityPrincipals) {
            Write-Host "`nAuditing Foreign Security Principals..." -ForegroundColor Yellow
            
            $foreignSecurityPrincipals = Get-ADObject -Filter "ObjectClass -eq 'foreignSecurityPrincipal'" -Properties * |
                ForEach-Object {
                    $fsp = $_
                    
                    # Try to resolve the foreign principal
                    $resolvedPrincipal = $null
                    try {
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($fsp.Name)
                        $resolvedPrincipal = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    } catch {
                        $resolvedPrincipal = "Unable to resolve"
                    }
                    
                    # Check group memberships
                    $groupMemberships = Get-ADPrincipalGroupMembership -Identity $fsp.DistinguishedName -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty Name
                    
                    [PSCustomObject]@{
                        Name = $fsp.Name
                        DistinguishedName = $fsp.DistinguishedName
                        ResolvedName = $resolvedPrincipal
                        Created = $fsp.Created
                        Modified = $fsp.Modified
                        GroupMemberships = ($groupMemberships -join "; ")
                        MemberOfPrivilegedGroups = if ($groupMemberships -match "Admin|Power|Backup|Replicator") { $true } else { $false }
                        RiskLevel = if ($groupMemberships -match "Admin|Power|Backup|Replicator") { "High" } else { "Medium" }
                        AuditDate = Get-Date
                    }
                }
            
            $auditResults.ForeignSecurityPrincipals = $foreignSecurityPrincipals
            Write-Host "Found $($foreignSecurityPrincipals.Count) foreign security principals" -ForegroundColor Green
        }
        
        # 5. Generate Statistics
        $auditResults.Statistics = @{
            TotalTrusts = $auditResults.Trusts.Count
            ExternalTrusts = ($auditResults.Trusts | Where-Object { $_.TrustType -eq "External" }).Count
            ForestTrusts = ($auditResults.Trusts | Where-Object { $_.TrustType -eq "Forest" }).Count
            HighRiskTrusts = ($auditResults.Trusts | Where-Object { $_.RiskLevel -eq "High" }).Count
            TrustAccounts = $auditResults.TrustAccounts.Count
            DelegationConfigurations = $auditResults.Delegation.Count
            CriticalDelegations = ($auditResults.Delegation | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            ForeignSecurityPrincipals = $auditResults.ForeignSecurityPrincipals.Count
            PrivilegedForeignPrincipals = ($auditResults.ForeignSecurityPrincipals | Where-Object { $_.MemberOfPrivilegedGroups -eq $true }).Count
            AuditDuration = (Get-Date) - $auditStartTime
        }
        
        Write-Host "`nAD Trusts Security Audit Summary:" -ForegroundColor Cyan
        Write-Host "  Trust Relationships: $($auditResults.Statistics.TotalTrusts)" -ForegroundColor White
        Write-Host "  High Risk Trusts: $($auditResults.Statistics.HighRiskTrusts)" -ForegroundColor $(if ($auditResults.Statistics.HighRiskTrusts -gt 0) { "Red" } else { "Green" })
        Write-Host "  Trust Accounts: $($auditResults.Statistics.TrustAccounts)" -ForegroundColor White
        Write-Host "  Delegation Configurations: $($auditResults.Statistics.DelegationConfigurations)" -ForegroundColor White
        Write-Host "  Critical Delegations: $($auditResults.Statistics.CriticalDelegations)" -ForegroundColor $(if ($auditResults.Statistics.CriticalDelegations -gt 0) { "Red" } else { "Green" })
        Write-Host "  Foreign Security Principals: $($auditResults.Statistics.ForeignSecurityPrincipals)" -ForegroundColor White
        Write-Host "  Privileged Foreign Principals: $($auditResults.Statistics.PrivilegedForeignPrincipals)" -ForegroundColor $(if ($auditResults.Statistics.PrivilegedForeignPrincipals -gt 0) { "Yellow" } else { "Green" })
        
        return $auditResults
        
    } catch {
        Write-Error "AD Trusts audit failed: $_"
        return $null
    }
}

function Get-TrustRiskLevel {
    param($Trust)
    
    $risk = "Low"
    
    # External trusts are higher risk
    if ($Trust.TrustType -eq "External") {
        $risk = "Medium"
    }
    
    # Bidirectional trusts are higher risk
    if ($Trust.Direction -eq "Bidirectional") {
        $risk = "Medium"
    }
    
    # Forest trusts without selective authentication
    if ($Trust.TrustType -eq "Forest" -and !$Trust.SelectiveAuthentication) {
        $risk = "High"
    }
    
    # SID filtering disabled
    if (!$Trust.SIDFilteringQuarantined -and $Trust.TrustType -eq "External") {
        $risk = "High"
    }
    
    return $risk
}

function Get-TrustAccountRisk {
    param($Account)
    
    $risk = "Low"
    
    # Never logged on
    if (!$Account.LastLogon -or $Account.LastLogon -lt (Get-Date).AddDays(-365)) {
        $risk = "Medium"
    }
    
    # Old password
    if ($Account.PasswordLastSet -and (Get-Date) - $Account.PasswordLastSet -gt [TimeSpan]::FromDays(365)) {
        $risk = "High"
    }
    
    # Trusted for delegation
    if ($Account.TrustedForDelegation) {
        $risk = "High"
    }
    
    # Account expired but still enabled
    if ($Account.AccountExpiration -and $Account.AccountExpiration -lt (Get-Date) -and $Account.Enabled) {
        $risk = "High"
    }
    
    return $risk
}

function Test-ADTrustConnection {
    param($Trust)
    
    try {
        $result = nltest /sc_query:$($Trust.Target) 2>$null
        if ($LASTEXITCODE -eq 0) {
            return "Connected"
        } else {
            return "Connection Failed"
        }
    } catch {
        return "Unknown"
    }
}

function Export-ADTrustAuditReports {
    param(
        [Parameter(Mandatory=$true)]
        $AuditResults,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reports = @()
    
    # Export Trusts
    if ($AuditResults.Trusts.Count -gt 0) {
        $path = "$OutputDirectory\AD_Trusts_$timestamp.csv"
        $AuditResults.Trusts | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Trust Accounts
    if ($AuditResults.TrustAccounts.Count -gt 0) {
        $path = "$OutputDirectory\AD_TrustAccounts_$timestamp.csv"
        $AuditResults.TrustAccounts | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Delegation
    if ($AuditResults.Delegation.Count -gt 0) {
        $path = "$OutputDirectory\AD_Delegation_$timestamp.csv"
        $AuditResults.Delegation | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Foreign Security Principals
    if ($AuditResults.ForeignSecurityPrincipals.Count -gt 0) {
        $path = "$OutputDirectory\AD_ForeignSecurityPrincipals_$timestamp.csv"
        $AuditResults.ForeignSecurityPrincipals | Export-Csv -Path $path -NoTypeInformation
        $reports += $path
    }
    
    # Export Statistics
    $statsPath = "$OutputDirectory\AD_TrustAudit_Statistics_$timestamp.csv"
    $AuditResults.Statistics.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Metric = $_.Key
            Value = $_.Value
        }
    } | Export-Csv -Path $statsPath -NoTypeInformation
    $reports += $statsPath
    
    Write-Host "AD Trust audit reports exported:" -ForegroundColor Green
    $reports | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    
    return $reports
}