<#
.SYNOPSIS
    Enhanced audit capture with proper window management and clean screenshots.

.DESCRIPTION
    Provides clean capture of each group's data with maximized window, clear screens,
    and organized output per group.
#>

function Set-ConsoleMaximized {
    <#
    .SYNOPSIS
        Maximizes the PowerShell console window.
    #>
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        public const int SW_MAXIMIZE = 3;
    }
"@
    $consolePtr = [Win32]::GetConsoleWindow()
    [Win32]::ShowWindow($consolePtr, [Win32]::SW_MAXIMIZE) | Out-Null
    Start-Sleep -Milliseconds 500  # Let window settle
}

function Start-GroupAuditCapture {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    # Create clean folder name
    $folderName = "$($Domain)_$($GroupName)" -replace '[^\w\-]', '_'
    $groupOutputDir = "$OutputDirectory\$folderName"
    
    if (-not (Test-Path $groupOutputDir)) {
        New-Item -ItemType Directory -Path $groupOutputDir -Force | Out-Null
    }
    
    # Start transcript for this group only
    $transcriptPath = "$groupOutputDir\transcript.log"
    Start-Transcript -Path $transcriptPath -Force | Out-Null
    
    # Clear screen for clean capture
    Clear-Host
    
    # Display group header
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host " AUDITING GROUP: $GroupName" -ForegroundColor Yellow
    Write-Host " Domain: $Domain" -ForegroundColor Yellow
    Write-Host " Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "===================================================`n" -ForegroundColor Cyan
    
    return @{
        GroupOutputDir = $groupOutputDir
        TranscriptPath = $transcriptPath
        Domain = $Domain
        GroupName = $GroupName
    }
}

function Invoke-GroupMemberRetrieval {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupDN,
        
        [Parameter(Mandatory=$true)]
        [string]$Server,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$CaptureInfo,
        
        [Parameter(Mandatory=$false)]
        [switch]$Recursive
    )
    
    # Display the command being executed
    Write-Host "Executing Command:" -ForegroundColor Green
    Write-Host "Get-ADGroupMember -Identity '$GroupDN' -Server '$Server'$(if ($Recursive) { ' -Recursive' })" -ForegroundColor Cyan
    Write-Host "`n--- RETRIEVING MEMBERS ---" -ForegroundColor Yellow
    
    # Take before screenshot showing the command
    Write-Host "`nCapturing command screenshot..." -ForegroundColor Magenta
    Start-Sleep -Seconds 1
    . "$PSScriptRoot\AD-ScreenCapture.ps1"
    $beforeScreenshot = Get-ScreenCapture -OutputPath $CaptureInfo.GroupOutputDir -FilePrefix "01_command"
    Write-Host "Command screenshot saved: $($beforeScreenshot.FileName)" -ForegroundColor Green
    
    try {
        # Get members
        Write-Host "`nExecuting..." -ForegroundColor Yellow
        $members = Get-ADGroupMember -Identity $GroupDN -Server $Server -Recursive:$Recursive -ErrorAction Stop
        
        if ($members) {
            Write-Host "`nFound $($members.Count) members:" -ForegroundColor Green
            
            # Display members in a table
            $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName | 
                Format-Table -AutoSize | Out-String | Write-Host
            
            # Export to CSV in the group's folder
            $csvPath = "$($CaptureInfo.GroupOutputDir)\members.csv"
            $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName | 
                Export-Csv -Path $csvPath -NoTypeInformation
            
            Write-Host "`nMembers exported to: $csvPath" -ForegroundColor Green
        } else {
            Write-Host "`nNo members found in this group." -ForegroundColor Yellow
        }
        
        # Take after screenshot showing results
        Write-Host "`n--- CAPTURING RESULTS SCREENSHOT ---" -ForegroundColor Magenta
        Start-Sleep -Seconds 1
        $resultsScreenshot = Get-ScreenCapture -OutputPath $CaptureInfo.GroupOutputDir -FilePrefix "02_results"
        Write-Host "Results screenshot saved: $($resultsScreenshot.FileName)" -ForegroundColor Green
        
        return $members
        
    } catch {
        Write-Host "`nERROR: Failed to retrieve members - $_" -ForegroundColor Red
        
        # Still take screenshot of error
        Start-Sleep -Seconds 1
        . "$PSScriptRoot\AD-ScreenCapture.ps1"
        $screenshot = Get-ScreenCapture -OutputPath $CaptureInfo.GroupOutputDir -FilePrefix "02_error"
        
        throw
    }
}

function Get-GroupMemberDetails {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Members,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$CaptureInfo,
        
        [Parameter(Mandatory=$true)]
        [object[]]$ForestDomains
    )
    
    Clear-Host
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host " PROCESSING MEMBER DETAILS: $($CaptureInfo.GroupName)" -ForegroundColor Yellow
    Write-Host " Domain: $($CaptureInfo.Domain)" -ForegroundColor Yellow
    Write-Host "===================================================`n" -ForegroundColor Cyan
    
    $memberDetails = @()
    $processedCount = 0
    
    foreach ($member in $Members) {
        $processedCount++
        Write-Host "Processing member $processedCount of $($Members.Count): $($member.Name)" -ForegroundColor Gray
        
        try {
            if ($member.objectClass -eq 'user') {
                # Find correct domain controller
                $userDomain = $CaptureInfo.Domain
                foreach ($domain in $ForestDomains) {
                    if ($member.DistinguishedName -match $domain.Name) {
                        $userDomain = $domain.DomainController
                        break
                    }
                }
                
                $user = Get-ADUser -Identity $member.SamAccountName -Server $userDomain -Properties * -ErrorAction Stop
                
                $memberDetail = [PSCustomObject]@{
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
                    Domain = ($member.DistinguishedName -split ',DC=' | Select-Object -Skip 1) -join '.'
                }
                
                if ($user.Manager) {
                    try {
                        $mgr = Get-ADUser -Identity $user.Manager -Properties DisplayName
                        $memberDetail.Manager = "$($mgr.DisplayName) ($($mgr.SamAccountName))"
                    } catch {
                        $memberDetail.Manager = $user.Manager
                    }
                }
                
                $memberDetails += $memberDetail
            }
            elseif ($member.objectClass -eq 'group') {
                $memberDetail = [PSCustomObject]@{
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
                    Domain = ($member.DistinguishedName -split ',DC=' | Select-Object -Skip 1) -join '.'
                }
                
                $memberDetails += $memberDetail
            }
        } catch {
            Write-Warning "Failed to get details for $($member.SamAccountName): $_"
        }
    }
    
    # Export detailed member information
    if ($memberDetails.Count -gt 0) {
        $detailsPath = "$($CaptureInfo.GroupOutputDir)\member_details.csv"
        $memberDetails | Export-Csv -Path $detailsPath -NoTypeInformation
        
        Write-Host "`nMember details exported to: $detailsPath" -ForegroundColor Green
        Write-Host "Total members processed: $($memberDetails.Count)" -ForegroundColor Green
        
        # Show summary
        Write-Host "`n--- MEMBER SUMMARY ---" -ForegroundColor Yellow
        $enabledUsers = ($memberDetails | Where-Object { $_.MemberType -eq 'User' -and $_.Enabled -eq $true }).Count
        $disabledUsers = ($memberDetails | Where-Object { $_.MemberType -eq 'User' -and $_.Enabled -eq $false }).Count
        $groups = ($memberDetails | Where-Object { $_.MemberType -eq 'Group' }).Count
        
        Write-Host "Enabled Users: $enabledUsers" -ForegroundColor Green
        Write-Host "Disabled Users: $disabledUsers" -ForegroundColor Yellow
        Write-Host "Nested Groups: $groups" -ForegroundColor Cyan
        
        # Take screenshot of summary
        Start-Sleep -Seconds 1
        . "$PSScriptRoot\AD-ScreenCapture.ps1"
        $screenshot = Get-ScreenCapture -OutputPath $CaptureInfo.GroupOutputDir -FilePrefix "03_summary"
        Write-Host "`nSummary screenshot saved: $($screenshot.FileName)" -ForegroundColor Green
    }
    
    return $memberDetails
}

function Complete-GroupAuditCapture {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$CaptureInfo
    )
    
    Write-Host "`n===================================================" -ForegroundColor Green
    Write-Host " COMPLETED: $($CaptureInfo.GroupName)" -ForegroundColor Green
    Write-Host "===================================================" -ForegroundColor Green
    
    # Stop transcript
    Stop-Transcript | Out-Null
    
    # Create summary file
    $summaryPath = "$($CaptureInfo.GroupOutputDir)\audit_summary.txt"
    @"
Group Audit Summary
==================
Group: $($CaptureInfo.GroupName)
Domain: $($CaptureInfo.Domain)
Audit Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Files in this directory:
- members.csv: Raw group membership
- member_details.csv: Detailed member information
- transcript.log: Full audit transcript
- *.png: Screenshots of audit process

This audit was performed by: $env:USERNAME
"@ | Out-File $summaryPath -Encoding UTF8
    
    # Brief pause before next group
    Start-Sleep -Seconds 2
    Clear-Host
}

# All functions are automatically available when script is dot-sourced