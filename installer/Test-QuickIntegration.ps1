# Quick integration test for audit modules
Write-Host "Quick Audit Module Integration Test..." -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath = "$scriptPath\Modules"
$success = $true

# Test Enhanced Web Report Generator
try {
    . "$ModulesPath\Enhanced-WebReportGenerator.ps1"
    Write-Host "✓ Enhanced-WebReportGenerator loaded" -ForegroundColor Green
} catch {
    Write-Host "✗ Enhanced-WebReportGenerator failed: $_" -ForegroundColor Red
    $success = $false
}

# Test Service Account Discovery
try {
    . "$ModulesPath\ServiceAccount-Discovery.ps1"
    Write-Host "✓ ServiceAccount-Discovery loaded" -ForegroundColor Green
} catch {
    Write-Host "✗ ServiceAccount-Discovery failed: $_" -ForegroundColor Red
    $success = $false
}

# Test Azure AD Enhanced Audit
try {
    . "$ModulesPath\AzureAD-EnhancedAudit.ps1"
    Write-Host "✓ AzureAD-EnhancedAudit loaded" -ForegroundColor Green
} catch {
    Write-Host "✗ AzureAD-EnhancedAudit failed: $_" -ForegroundColor Red
    $success = $false
}

# Test AD Trusts Audit
try {
    . "$ModulesPath\ADTrusts-Audit.ps1"
    Write-Host "✓ ADTrusts-Audit loaded" -ForegroundColor Green
} catch {
    Write-Host "✗ ADTrusts-Audit failed: $_" -ForegroundColor Red
    $success = $false
}

# Test GPO Security Audit
try {
    . "$ModulesPath\GPO-SecurityAudit.ps1"
    Write-Host "✓ GPO-SecurityAudit loaded" -ForegroundColor Green
} catch {
    Write-Host "✗ GPO-SecurityAudit failed: $_" -ForegroundColor Red
    $success = $false
}

if ($success) {
    Write-Host "`n✓ All modules loaded successfully!" -ForegroundColor Green
} else {
    Write-Host "`n✗ Some modules failed to load" -ForegroundColor Red
}