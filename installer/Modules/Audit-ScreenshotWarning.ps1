<#
.SYNOPSIS
    Provides standardized warning about screenshot capture for audit compliance.

.DESCRIPTION
    Displays warning to users about full-screen screenshots and gets consent.
    Used across all audit scripts to ensure consistent messaging.
#>

function Show-ScreenshotWarning {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== AUDIT COMPLIANCE NOTICE ===" -ForegroundColor Yellow
    Write-Host "Full-screen screenshots will be captured for audit compliance." -ForegroundColor Cyan
    Write-Host "These include system timestamps required for regulatory evidence." -ForegroundColor White
    Write-Host "`nIMPORTANT: Close any sensitive information now." -ForegroundColor Red
    Start-Sleep -Seconds 3
}

# Function is automatically available when script is dot-sourced