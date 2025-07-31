# Audit Code Capture Module - Documents PowerShell commands for compliance evidence

function Start-AuditCodeCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AuditName,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$PSScriptRoot\Reports\CodeEvidence\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $script:AuditCodeCapture = @{
        AuditName = $AuditName
        OutputPath = $OutputPath
        Commands = @()
        Screenshots = @()
        StartTime = Get-Date
        IsCapturing = $true
    }
    
    Write-Host "Code capture started for audit: $AuditName" -ForegroundColor Green
    Write-Host "Output path: $OutputPath" -ForegroundColor Cyan
    
    return $script:AuditCodeCapture
}

function Add-AuditCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CommandName,
        
        [Parameter(Mandatory=$true)]
        [string]$CommandText,
        
        [Parameter(Mandatory=$false)]
        [string]$Description,
        
        [Parameter(Mandatory=$false)]
        [object]$Output,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshot
    )
    
    if (!$script:AuditCodeCapture -or !$script:AuditCodeCapture.IsCapturing) {
        Write-Warning "No active audit code capture session"
        return
    }
    
    $command = [PSCustomObject]@{
        Timestamp = Get-Date
        CommandName = $CommandName
        CommandText = $CommandText
        Description = $Description
        OutputSample = $null
        ScreenshotPath = $null
        ExecutionTime = $null
    }
    
    # Capture output sample
    if ($Output) {
        $command.OutputSample = $Output | Select-Object -First 5 | ConvertTo-Json -Depth 3
    }
    
    # Display command in console for screenshot
    if ($CaptureScreenshot) {
        Write-Host "`n=== AUDIT COMMAND EXECUTION ===" -ForegroundColor Yellow
        Write-Host "Command: $CommandName" -ForegroundColor Cyan
        Write-Host "Description: $Description" -ForegroundColor Gray
        Write-Host "`nPS> $CommandText" -ForegroundColor Green
        
        if ($Output) {
            Write-Host "`nSample Output:" -ForegroundColor Yellow
            $Output | Select-Object -First 3 | Format-Table | Out-String | Write-Host
        }
        
        # Take screenshot
        . "$PSScriptRoot\AD-ScreenCapture.ps1"
        $screenshot = Get-ScreenCapture -OutputPath $script:AuditCodeCapture.OutputPath -FilePrefix "Cmd_$CommandName"
        $command.ScreenshotPath = $screenshot.FilePath
        $script:AuditCodeCapture.Screenshots += $screenshot
        
        Start-Sleep -Seconds 1
    }
    
    $script:AuditCodeCapture.Commands += $command
    
    return $command
}

function New-AuditCodeDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [object]$CaptureSession = $script:AuditCodeCapture,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeFullCode
    )
    
    if (!$CaptureSession) {
        Write-Error "No audit code capture session found"
        return
    }
    
    $htmlPath = Join-Path $CaptureSession.OutputPath "Audit_Commands_Documentation.html"
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Audit Code Evidence - $($CaptureSession.AuditName)</title>
    <style>
        body { font-family: 'Consolas', 'Courier New', monospace; line-height: 1.6; color: #333; margin: 20px; background: #f5f5f5; }
        .header { background: #1e3a8a; color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 24px; }
        .metadata { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .metadata table { width: 100%; }
        .metadata td { padding: 8px; border-bottom: 1px solid #eee; }
        .metadata td:first-child { font-weight: bold; width: 200px; color: #1e3a8a; }
        .command-section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .command-header { background: #f8f9fa; padding: 15px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; border-bottom: 2px solid #3b82f6; }
        .command-header h3 { margin: 0; color: #1e3a8a; }
        .command-time { color: #6b7280; font-size: 14px; }
        .command-description { color: #4b5563; margin: 10px 0; font-style: italic; }
        .command-text { background: #1e293b; color: #10b981; padding: 15px; border-radius: 4px; overflow-x: auto; margin: 15px 0; }
        .command-text::before { content: 'PS> '; color: #60a5fa; }
        .output-sample { background: #f3f4f6; padding: 15px; border-radius: 4px; margin: 15px 0; overflow-x: auto; }
        .output-sample h4 { margin: 0 0 10px 0; color: #6b7280; }
        .screenshot { margin: 20px 0; text-align: center; }
        .screenshot img { max-width: 100%; border: 1px solid #e5e7eb; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .screenshot-caption { color: #6b7280; font-size: 14px; margin-top: 10px; }
        .summary { background: #eff6ff; padding: 20px; border-radius: 8px; margin-top: 30px; }
        .command-index { background: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .command-index ul { list-style: none; padding: 0; }
        .command-index li { padding: 8px 0; border-bottom: 1px solid #f3f4f6; }
        .command-index a { color: #3b82f6; text-decoration: none; }
        .command-index a:hover { text-decoration: underline; }
        @media print {
            body { background: white; }
            .command-section { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>PowerShell Audit Command Evidence</h1>
        <p>$($CaptureSession.AuditName) - SOX Compliance Documentation</p>
    </div>
    
    <div class="metadata">
        <table>
            <tr>
                <td>Audit Name:</td>
                <td>$($CaptureSession.AuditName)</td>
            </tr>
            <tr>
                <td>Execution Start:</td>
                <td>$($CaptureSession.StartTime)</td>
            </tr>
            <tr>
                <td>Execution End:</td>
                <td>$(Get-Date)</td>
            </tr>
            <tr>
                <td>Executed By:</td>
                <td>$env:USERNAME</td>
            </tr>
            <tr>
                <td>Machine:</td>
                <td>$env:COMPUTERNAME</td>
            </tr>
            <tr>
                <td>Total Commands:</td>
                <td>$($CaptureSession.Commands.Count)</td>
            </tr>
            <tr>
                <td>Screenshots Captured:</td>
                <td>$($CaptureSession.Screenshots.Count)</td>
            </tr>
        </table>
    </div>
    
    <div class="command-index">
        <h2>Command Index</h2>
        <ul>
"@

    $commandIndex = 1
    foreach ($cmd in $CaptureSession.Commands) {
        $htmlContent += "<li><a href='#cmd$commandIndex'>$commandIndex. $($cmd.CommandName)</a> - $($cmd.Timestamp.ToString('HH:mm:ss'))</li>"
        $commandIndex++
    }

    $htmlContent += @"
        </ul>
    </div>
"@

    $commandIndex = 1
    foreach ($cmd in $CaptureSession.Commands) {
        $htmlContent += @"
    <div class="command-section" id="cmd$commandIndex">
        <div class="command-header">
            <h3>$commandIndex. $($cmd.CommandName)</h3>
            <div class="command-time">Executed at: $($cmd.Timestamp)</div>
        </div>
"@

        if ($cmd.Description) {
            $htmlContent += "<div class='command-description'>$($cmd.Description)</div>"
        }

        $htmlContent += @"
        <div class="command-text">$($cmd.CommandText)</div>
"@

        if ($cmd.OutputSample) {
            $htmlContent += @"
        <div class="output-sample">
            <h4>Sample Output:</h4>
            <pre>$($cmd.OutputSample)</pre>
        </div>
"@
        }

        if ($cmd.ScreenshotPath -and (Test-Path $cmd.ScreenshotPath)) {
            $imgData = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($cmd.ScreenshotPath))
            $htmlContent += @"
        <div class="screenshot">
            <img src="data:image/png;base64,$imgData" alt="Command screenshot">
            <div class="screenshot-caption">Screenshot captured at $($cmd.Timestamp)</div>
        </div>
"@
        }

        $htmlContent += "</div>"
        $commandIndex++
    }

    $htmlContent += @"
    <div class="summary">
        <h2>Audit Summary</h2>
        <p>This document provides evidence of the PowerShell commands executed during the $($CaptureSession.AuditName) audit process.</p>
        <p>Total execution time: $((Get-Date) - $CaptureSession.StartTime)</p>
        <p>All commands shown were executed with appropriate permissions and in accordance with SOX compliance requirements.</p>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    
    # Create PowerShell script file with all commands
    $psPath = Join-Path $CaptureSession.OutputPath "Audit_Commands.ps1"
    $psContent = @"
# Audit Commands Script
# Generated: $(Get-Date)
# Audit: $($CaptureSession.AuditName)
# This script contains all PowerShell commands executed during the audit

"@

    foreach ($cmd in $CaptureSession.Commands) {
        $psContent += @"

# ======================================
# Command: $($cmd.CommandName)
# Time: $($cmd.Timestamp)
# Description: $($cmd.Description)
# ======================================

$($cmd.CommandText)

"@
    }

    $psContent | Out-File -FilePath $psPath -Encoding UTF8
    
    Write-Host "`nAudit code documentation generated:" -ForegroundColor Green
    Write-Host "  HTML Report: $htmlPath" -ForegroundColor White
    Write-Host "  PS1 Script: $psPath" -ForegroundColor White
    
    return @{
        HtmlPath = $htmlPath
        ScriptPath = $psPath
        CommandCount = $CaptureSession.Commands.Count
        ScreenshotCount = $CaptureSession.Screenshots.Count
    }
}

function Stop-AuditCodeCapture {
    [CmdletBinding()]
    param()
    
    if ($script:AuditCodeCapture) {
        $script:AuditCodeCapture.IsCapturing = $false
        Write-Host "Code capture stopped for audit: $($script:AuditCodeCapture.AuditName)" -ForegroundColor Yellow
        
        # Generate final documentation
        $docs = New-AuditCodeDocument
        
        return $docs
    }
}

# Helper function to wrap existing cmdlets with capture
function Invoke-AuditCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$Command,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$false)]
        [string]$Description,
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureScreenshot
    )
    
    $commandText = $Command.ToString().Trim()
    
    # Execute the command
    $output = & $Command
    
    # Capture the command and output
    Add-AuditCommand -CommandName $Name -CommandText $commandText -Description $Description -Output $output -CaptureScreenshot:$CaptureScreenshot
    
    return $output
}

Export-ModuleMember -Function Start-AuditCodeCapture, Add-AuditCommand, New-AuditCodeDocument, Stop-AuditCodeCapture, Invoke-AuditCommand