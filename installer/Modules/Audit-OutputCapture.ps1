<#
.SYNOPSIS
    Captures command execution with full output for audit purposes.

.DESCRIPTION
    Creates organized output structure with CSV data, command transcripts, and screenshots.
    Organizes by domain and group for easy review.
#>

$script:AuditOutputPath = $null

function Start-AuditOutputCapture {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )
    
    $script:AuditOutputPath = $OutputDirectory
    
    # Create main directories
    $dirs = @(
        "$OutputDirectory\CSV",
        "$OutputDirectory\Evidence"
    )
    
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Host "Audit output capture started. Base directory: $OutputDirectory" -ForegroundColor Gray
}

function Export-GroupAuditData {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$GroupData,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    # Create domain-group specific directory
    $safeDomain = $Domain -replace '[^\w\-]', '_'
    $safeGroup = $GroupName -replace '[^\w\-]', '_'
    $evidenceDir = "$script:AuditOutputPath\Evidence\${safeDomain}_${safeGroup}"
    
    if (-not (Test-Path $evidenceDir)) {
        New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    }
    
    # Start transcript for this group
    $transcriptPath = "$evidenceDir\audit_transcript.txt"
    Start-Transcript -Path $transcriptPath -Force | Out-Null
    
    # Export group data to CSV
    $csvPath = "$script:AuditOutputPath\CSV\${safeDomain}_${safeGroup}.csv"
    $GroupData | Export-Csv -Path $csvPath -NoTypeInformation
    
    # Return paths for reference
    return @{
        Domain = $Domain
        Group = $GroupName
        CSVPath = $csvPath
        EvidenceDir = $evidenceDir
        TranscriptPath = $transcriptPath
    }
}

function Invoke-AuditCommand {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$Command,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [string]$EvidenceDir,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshot,
        
        [Parameter(Mandatory=$false)]
        [object[]]$ArgumentList
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $commandName = ($Description -replace '[^\w\-]', '_').Substring(0, [Math]::Min(30, $Description.Length))
    
    # Display what we're about to run
    Write-Host "`n=== EXECUTING: $Description ===" -ForegroundColor Yellow
    Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Command: $($Command.ToString())" -ForegroundColor Cyan
    Write-Host "`n--- OUTPUT ---" -ForegroundColor Green
    
    # Execute and capture output
    if ($ArgumentList) {
        $output = & $Command @ArgumentList
    } else {
        $output = & $Command
    }
    
    # Display output
    if ($output) {
        $output | Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host "(No output returned)" -ForegroundColor Gray
    }
    
    Write-Host "--- END OUTPUT ---`n" -ForegroundColor Green
    
    # Take screenshot AFTER output is displayed
    if ($CaptureScreenshot) {
        Start-Sleep -Milliseconds 500  # Brief pause for display to render
        
        . "$PSScriptRoot\AD-ScreenCapture.ps1"
        $screenshot = Get-ScreenCapture -OutputPath $EvidenceDir -FilePrefix "${timestamp}_${commandName}"
        Write-Host "Screenshot saved: $($screenshot.FileName)" -ForegroundColor Gray
    }
    
    # Save output to file
    $outputFile = "$EvidenceDir\${timestamp}_${commandName}_output.txt"
    @"
Command: $Description
Executed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Block: $($Command.ToString())

OUTPUT:
$($output | Out-String)
"@ | Out-File $outputFile -Encoding UTF8
    
    return $output
}

function Complete-GroupAuditCapture {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AuditInfo
    )
    
    # Stop transcript
    Stop-Transcript | Out-Null
    
    Write-Host "Group audit complete: $($AuditInfo.Domain)\$($AuditInfo.Group)" -ForegroundColor Green
    Write-Host "  CSV: $($AuditInfo.CSVPath)" -ForegroundColor Gray
    Write-Host "  Evidence: $($AuditInfo.EvidenceDir)" -ForegroundColor Gray
}

function Export-AuditSummaryCSV {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$AllGroupData,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = $script:AuditOutputPath
    )
    
    # Validate output path
    if (-not $OutputPath) {
        throw "Output path not specified. Call Start-AuditOutputCapture first or provide OutputPath parameter."
    }
    
    # Create summary CSV with all groups
    $summaryPath = "$OutputPath\CSV\00_SUMMARY_AllGroups.csv"
    
    $summary = foreach ($group in $AllGroupData) {
        [PSCustomObject]@{
            Domain = $group.Domain
            GroupName = $group.GroupName
            MemberCount = $group.MemberCount
            EnabledCount = $group.EnabledMemberCount
            DisabledCount = $group.DisabledMemberCount
            Status = $group.Status
            ErrorDetails = $group.ErrorDetails
            LastAudit = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
    }
    
    $summary | Export-Csv -Path $summaryPath -NoTypeInformation
    Write-Host "`nSummary CSV created: $summaryPath" -ForegroundColor Green
    
    # Create detailed members CSV
    $membersPath = "$OutputPath\CSV\00_DETAILS_AllMembers.csv"
    
    $allMembers = foreach ($group in $AllGroupData) {
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
    
    if ($allMembers) {
        $allMembers | Export-Csv -Path $membersPath -NoTypeInformation
        Write-Host "Detailed members CSV created: $membersPath" -ForegroundColor Green
    }
}

# Functions are automatically available when script is dot-sourced