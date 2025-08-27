# Test script to verify all audit modules can be loaded and their functions are available
param(
    [switch]$Verbose
)

Write-Host "Testing Audit Module Integration..." -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath = "$scriptPath\Modules"
$errors = @()
$warnings = @()

# Test 1: Enhanced Web Report Generator
Write-Host "`n1. Testing Enhanced Web Report Generator..." -ForegroundColor Yellow
try {
    . "$ModulesPath\Enhanced-WebReportGenerator.ps1"
    if (Get-Command "New-EnhancedWebReport" -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ Enhanced-WebReportGenerator loaded successfully" -ForegroundColor Green
    } else {
        $errors += "Enhanced-WebReportGenerator: Function New-EnhancedWebReport not found"
    }
} catch {
    $errors += "Enhanced-WebReportGenerator: $_"
}

# Test 2: Service Account Discovery
Write-Host "`n2. Testing Service Account Discovery..." -ForegroundColor Yellow
try {
    . "$ModulesPath\ServiceAccount-Discovery.ps1"
    if (Get-Command "Get-ServiceAccountInventory" -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ ServiceAccount-Discovery loaded successfully" -ForegroundColor Green
    } else {
        $errors += "ServiceAccount-Discovery: Function Get-ServiceAccountInventory not found"
    }
} catch {
    $errors += "ServiceAccount-Discovery: $_"
}

# Test 3: Azure AD Enhanced Audit
Write-Host "`n3. Testing Azure AD Enhanced Audit..." -ForegroundColor Yellow
try {
    . "$ModulesPath\AzureAD-EnhancedAudit.ps1"
    if (Get-Command "Start-AzureADEnhancedAudit" -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ AzureAD-EnhancedAudit loaded successfully" -ForegroundColor Green
    } else {
        $errors += "AzureAD-EnhancedAudit: Function Start-AzureADEnhancedAudit not found"
    }
} catch {
    $errors += "AzureAD-EnhancedAudit: $_"
}

# Test 4: AD Trusts Audit
Write-Host "`n4. Testing AD Trusts Audit..." -ForegroundColor Yellow
try {
    . "$ModulesPath\ADTrusts-Audit.ps1"
    if (Get-Command "Get-ADTrustAudit" -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ ADTrusts-Audit loaded successfully" -ForegroundColor Green
    } else {
        $errors += "ADTrusts-Audit: Function Get-ADTrustAudit not found"
    }
} catch {
    $errors += "ADTrusts-Audit: $_"
}

# Test 5: GPO Security Audit
Write-Host "`n5. Testing GPO Security Audit..." -ForegroundColor Yellow
try {
    . "$ModulesPath\GPO-SecurityAudit.ps1"
    if (Get-Command "Get-GPOSecurityAudit" -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ GPO-SecurityAudit loaded successfully" -ForegroundColor Green
    } else {
        $errors += "GPO-SecurityAudit: Function Get-GPOSecurityAudit not found"
    }
} catch {
    $errors += "GPO-SecurityAudit: $_"
}

# Test 6: Required PowerShell Modules
Write-Host "`n6. Testing Required PowerShell Modules..." -ForegroundColor Yellow

$requiredModules = @("ActiveDirectory", "GroupPolicy")
foreach ($module in $requiredModules) {
    if (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ $module module available" -ForegroundColor Green
    } else {
        $warnings += "$module module not available (may affect functionality)"
    }
}

# Optional modules
$optionalModules = @("Microsoft.Graph", "Microsoft.Graph.Authentication")
foreach ($module in $optionalModules) {
    if (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue) {
        Write-Host "   ✓ $module module available (optional)" -ForegroundColor Green
    } else {
        Write-Host "   • $module module not available (Azure AD features will be limited)" -ForegroundColor Gray
    }
}

# Results Summary
Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "         MODULE INTEGRATION TEST RESULTS        " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

if ($errors.Count -eq 0) {
    Write-Host "`n✓ All core modules loaded successfully!" -ForegroundColor Green
    Write-Host "  The comprehensive audit system is ready for use." -ForegroundColor White
} else {
    Write-Host "`n✗ Errors found:" -ForegroundColor Red
    foreach ($error in $errors) {
        Write-Host "  - $error" -ForegroundColor Red
    }
}

if ($warnings.Count -gt 0) {
    Write-Host "`nWarnings:" -ForegroundColor Yellow
    foreach ($warning in $warnings) {
        Write-Host "  - $warning" -ForegroundColor Yellow
    }
}

Write-Host "`nTest completed." -ForegroundColor Cyan