Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-ScreenCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$PSScriptRoot\Screenshots",
        
        [Parameter(Mandatory=$false)]
        [string]$FilePrefix = "AD_Audit",
        
        [Parameter(Mandatory=$false)]
        [switch]$CaptureActiveWindow
    )
    
    try {
        if (!(Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $fileName = "${FilePrefix}_${timestamp}.png"
        $filePath = Join-Path $OutputPath $fileName
        
        if ($CaptureActiveWindow) {
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class Win32 {
                    [DllImport("user32.dll")]
                    public static extern IntPtr GetForegroundWindow();
                    [DllImport("user32.dll")]
                    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
                    public struct RECT {
                        public int Left;
                        public int Top;
                        public int Right;
                        public int Bottom;
                    }
                }
"@
            
            $activeWindow = [Win32]::GetForegroundWindow()
            $rect = New-Object Win32+RECT
            [Win32]::GetWindowRect($activeWindow, [ref]$rect) | Out-Null
            
            $bounds = [Drawing.Rectangle]::FromLTRB($rect.Left, $rect.Top, $rect.Right, $rect.Bottom)
        } else {
            $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        }
        
        $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        
        $bitmap.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
        
        $graphics.Dispose()
        $bitmap.Dispose()
        
        return [PSCustomObject]@{
            FilePath = $filePath
            FileName = $fileName
            Timestamp = Get-Date
            Width = $bounds.Width
            Height = $bounds.Height
        }
        
    } catch {
        Write-Error "Failed to capture screenshot: $_"
        throw
    }
}

function Get-ADConsoleScreenshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$PSScriptRoot\Screenshots",
        
        [Parameter(Mandatory=$false)]
        [int]$DelaySeconds = 2
    )
    
    Write-Host "`nPreparing to capture screenshot: $Title" -ForegroundColor Yellow
    Write-Host "Please ensure the relevant window is visible and in focus..." -ForegroundColor Cyan
    
    for ($i = $DelaySeconds; $i -gt 0; $i--) {
        Write-Host "Capturing in $i seconds..." -NoNewline
        Start-Sleep -Seconds 1
        Write-Host "`r" -NoNewline
    }
    
    $screenshot = Get-ScreenCapture -OutputPath $OutputPath -FilePrefix $Title.Replace(' ', '_') -CaptureActiveWindow
    
    Write-Host "Screenshot captured: $($screenshot.FileName)" -ForegroundColor Green
    
    return $screenshot
}

function Start-InteractiveADScreenCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SessionName = "AD_Audit_Session",
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$PSScriptRoot\Screenshots"
    )
    
    $screenshots = @()
    $continue = $true
    
    Write-Host "`n=== Interactive AD Screenshot Capture Session ===" -ForegroundColor Green
    Write-Host "Session: $SessionName" -ForegroundColor Cyan
    Write-Host "Output: $OutputPath" -ForegroundColor Cyan
    Write-Host "`nCommands:" -ForegroundColor Yellow
    Write-Host "  [C] Capture current window" -ForegroundColor White
    Write-Host "  [F] Capture full screen" -ForegroundColor White
    Write-Host "  [L] List captured screenshots" -ForegroundColor White
    Write-Host "  [Q] Quit session" -ForegroundColor White
    
    while ($continue) {
        $choice = Read-Host "`nEnter command"
        
        switch ($choice.ToUpper()) {
            'C' {
                $title = Read-Host "Enter screenshot title"
                $screenshot = Get-ScreenCapture -OutputPath $OutputPath -FilePrefix "${SessionName}_${title}" -CaptureActiveWindow
                $screenshots += $screenshot
                Write-Host "Captured: $($screenshot.FileName)" -ForegroundColor Green
            }
            'F' {
                $title = Read-Host "Enter screenshot title"
                $screenshot = Get-ScreenCapture -OutputPath $OutputPath -FilePrefix "${SessionName}_${title}"
                $screenshots += $screenshot
                Write-Host "Captured: $($screenshot.FileName)" -ForegroundColor Green
            }
            'L' {
                Write-Host "`nCaptured Screenshots:" -ForegroundColor Yellow
                $screenshots | ForEach-Object {
                    Write-Host "  - $($_.FileName) ($($_.Width)x$($_.Height)) at $($_.Timestamp)" -ForegroundColor Cyan
                }
            }
            'Q' {
                $continue = $false
                Write-Host "`nSession ended. Total screenshots: $($screenshots.Count)" -ForegroundColor Green
            }
            default {
                Write-Host "Invalid command. Please try again." -ForegroundColor Red
            }
        }
    }
    
    return $screenshots
}

# Functions are automatically available when script is dot-sourced