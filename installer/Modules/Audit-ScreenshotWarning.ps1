<#
.SYNOPSIS
    Provides standardized warning about screenshot capture for audit compliance.

.DESCRIPTION
    Displays warning to users about full-screen screenshots and gets consent.
    Used across all audit scripts to ensure consistent messaging.
#>

function Show-ScreenshotWarning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    if (-not $Force) {
        Write-Host "`n=== SCREENSHOT CAPTURE NOTICE ===" -ForegroundColor Yellow
        Write-Host "This audit tool will capture full-screen screenshots for compliance purposes." -ForegroundColor Red
        Write-Host ""
        Write-Host "Why full-screen screenshots are required:" -ForegroundColor Cyan
        Write-Host "  - System timestamps must be visible for audit evidence" -ForegroundColor White
        Write-Host "  - Taskbar clock provides non-tamperable time verification" -ForegroundColor White
        Write-Host "  - Required for regulatory compliance and audit trails" -ForegroundColor White
        Write-Host ""
        Write-Host "IMPORTANT: Close or minimize any sensitive information before continuing." -ForegroundColor Yellow
        Write-Host "Screenshots will be saved to the audit output directory." -ForegroundColor Gray
        
        $response = Read-Host "`nDo you consent to screenshot capture? (Y/N)"
        
        if ($response -ne 'Y') {
            Write-Host "`nScreenshot capture disabled. Continuing without visual evidence." -ForegroundColor Yellow
            Write-Host "Note: This may not meet all audit compliance requirements." -ForegroundColor Red
            return $false
        }
    }
    
    return $true
}

# Function is automatically available when script is dot-sourced