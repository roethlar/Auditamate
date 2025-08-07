<#
.SYNOPSIS
    Standardized output functions for all audit types.

.DESCRIPTION
    Provides consistent CSV output structure with evidence organization
    for all audit scripts while preserving HTML reports.
#>

function Initialize-AuditOutput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,
        
        [Parameter(Mandatory=$true)]
        [string]$AuditType
    )
    
    # Create standard directory structure
    $dirs = @(
        "$OutputDirectory\CSV",
        "$OutputDirectory\Evidence",
        "$OutputDirectory\HTML"
    )
    
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Host "Initialized $AuditType audit output structure at: $OutputDirectory" -ForegroundColor Gray
    
    return @{
        OutputDirectory = $OutputDirectory
        CSVDirectory = "$OutputDirectory\CSV"
        EvidenceDirectory = "$OutputDirectory\Evidence"
        HTMLDirectory = "$OutputDirectory\HTML"
        AuditType = $AuditType
    }
}

function Export-StandardAuditCSV {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$AuditData,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$OutputPaths,
        
        [Parameter(Mandatory=$true)]
        [string]$DataType  # e.g., "Groups", "LocalAdmins", "Terminations"
    )
    
    # Export summary CSV
    $summaryPath = "$($OutputPaths.CSVDirectory)\00_SUMMARY_$DataType.csv"
    
    # Create summary based on data type
    switch ($DataType) {
        "Groups" {
            $summary = foreach ($item in $AuditData) {
                [PSCustomObject]@{
                    Domain = $item.Domain
                    GroupName = $item.GroupName
                    MemberCount = $item.MemberCount
                    EnabledCount = $item.EnabledMemberCount
                    DisabledCount = $item.DisabledMemberCount
                    Status = $item.Status
                    ErrorDetails = $item.ErrorDetails
                    LastAudit = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
            }
        }
        "LocalAdmins" {
            $summary = foreach ($item in $AuditData) {
                [PSCustomObject]@{
                    ComputerName = $item.ComputerName
                    Domain = $item.Domain
                    AdminCount = $item.LocalAdmins.Count
                    Status = $item.Status
                    ErrorDetails = $item.ErrorDetails
                    LastAudit = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
            }
        }
        "Terminations" {
            $summary = foreach ($item in $AuditData) {
                [PSCustomObject]@{
                    UserName = $item.SamAccountName
                    DisplayName = $item.DisplayName
                    TerminationDate = $item.TerminationDate
                    AccountStatus = $item.AccountStatus
                    GroupMemberships = $item.GroupMemberships.Count
                    Status = $item.Status
                    LastAudit = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
            }
        }
        default {
            # Generic summary
            $summary = $AuditData
        }
    }
    
    $summary | Export-Csv -Path $summaryPath -NoTypeInformation
    Write-Host "Summary CSV created: $summaryPath" -ForegroundColor Green
    
    # Export detailed CSV
    Export-DetailedAuditCSV -AuditData $AuditData -OutputPaths $OutputPaths -DataType $DataType
}

function Export-DetailedAuditCSV {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$AuditData,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$OutputPaths,
        
        [Parameter(Mandatory=$true)]
        [string]$DataType
    )
    
    $detailsPath = "$($OutputPaths.CSVDirectory)\00_DETAILS_All$DataType.csv"
    
    switch ($DataType) {
        "Groups" {
            $details = foreach ($group in $AuditData) {
                foreach ($member in $group.Members) {
                    [PSCustomObject]@{
                        GroupDomain = $group.Domain
                        GroupName = $group.GroupName
                        MemberDisplayName = $member.DisplayName
                        MemberSamAccountName = $member.SamAccountName
                        MemberDomain = $member.Domain
                        MemberType = $member.MemberType
                        EmailAddress = $member.EmailAddress
                        Title = $member.Title
                        Department = $member.Department
                        Manager = $member.Manager
                        Enabled = $member.Enabled
                        LastLogon = $member.LastLogonDate
                        PasswordLastSet = $member.PasswordLastSet
                    }
                }
            }
        }
        "LocalAdmins" {
            $details = foreach ($computer in $AuditData) {
                foreach ($admin in $computer.LocalAdmins) {
                    [PSCustomObject]@{
                        ComputerName = $computer.ComputerName
                        ComputerDomain = $computer.Domain
                        AdminName = $admin.Name
                        AdminDomain = $admin.Domain
                        AdminType = $admin.ObjectClass
                        SID = $admin.SID
                        Source = $admin.Source
                    }
                }
            }
        }
        "Terminations" {
            $details = foreach ($user in $AuditData) {
                foreach ($group in $user.GroupMemberships) {
                    [PSCustomObject]@{
                        UserName = $user.SamAccountName
                        DisplayName = $user.DisplayName
                        TerminationDate = $user.TerminationDate
                        GroupName = $group.Name
                        GroupDN = $group.DistinguishedName
                        GroupType = $group.GroupCategory
                        GroupScope = $group.GroupScope
                    }
                }
            }
        }
        default {
            $details = $AuditData
        }
    }
    
    if ($details) {
        $details | Export-Csv -Path $detailsPath -NoTypeInformation
        Write-Host "Detailed CSV created: $detailsPath" -ForegroundColor Green
    }
}

function Export-AuditItemCSV {
    param(
        [Parameter(Mandatory=$true)]
        [object]$ItemData,
        
        [Parameter(Mandatory=$true)]
        [string]$ItemIdentifier,  # e.g., "DOMAIN_GroupName" or "ComputerName"
        
        [Parameter(Mandatory=$true)]
        [hashtable]$OutputPaths
    )
    
    # Sanitize identifier for filename
    $safeIdentifier = $ItemIdentifier -replace '[^\w\-]', '_'
    $csvPath = "$($OutputPaths.CSVDirectory)\$safeIdentifier.csv"
    
    # Export based on data type
    if ($ItemData.Members) {
        # Group data
        $ItemData.Members | Export-Csv -Path $csvPath -NoTypeInformation
    } elseif ($ItemData.LocalAdmins) {
        # Local admin data
        $ItemData.LocalAdmins | Export-Csv -Path $csvPath -NoTypeInformation
    } else {
        # Generic data
        $ItemData | Export-Csv -Path $csvPath -NoTypeInformation
    }
    
    return $csvPath
}

function New-AuditEvidenceFolder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ItemIdentifier,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$OutputPaths
    )
    
    $safeIdentifier = $ItemIdentifier -replace '[^\w\-]', '_'
    $evidencePath = "$($OutputPaths.EvidenceDirectory)\$safeIdentifier"
    
    if (-not (Test-Path $evidencePath)) {
        New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null
    }
    
    return $evidencePath
}

function Complete-AuditOutput {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$OutputPaths,
        
        [Parameter(Mandatory=$false)]
        [string]$HTMLReportPath
    )
    
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  Audit Output Complete" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "`nOutput Directory: $($OutputPaths.OutputDirectory)" -ForegroundColor Cyan
    
    # Show CSV files
    $csvFiles = Get-ChildItem -Path $OutputPaths.CSVDirectory -Filter "*.csv"
    Write-Host "`nCSV Reports ($($csvFiles.Count) files):" -ForegroundColor Yellow
    foreach ($file in $csvFiles | Sort-Object Name) {
        Write-Host "  - $($file.Name)" -ForegroundColor White
    }
    
    # Show evidence folders
    $evidenceFolders = Get-ChildItem -Path $OutputPaths.EvidenceDirectory -Directory
    if ($evidenceFolders) {
        Write-Host "`nEvidence Folders ($($evidenceFolders.Count)):" -ForegroundColor Yellow
        Write-Host "  - Screenshots and transcripts organized by item" -ForegroundColor Gray
    }
    
    # Show HTML report if exists
    if ($HTMLReportPath -and (Test-Path $HTMLReportPath)) {
        Write-Host "`nHTML Report:" -ForegroundColor Yellow
        Write-Host "  - $(Split-Path $HTMLReportPath -Leaf)" -ForegroundColor White
    }
}

# Functions are automatically available when script is dot-sourced