# Test script for Enhanced Web Report Generator
param(
    [string]$OutputPath = ".\test-output\Enhanced_Web_Report_Test.html"
)

Write-Host "Testing Enhanced Web Report Generator..." -ForegroundColor Cyan

# Import the module
. "$PSScriptRoot\..\Modules\Enhanced-WebReportGenerator.ps1"

# Create test data that mimics forest audit results
$testAuditData = @(
    @{
        GroupName = "Domain Admins"
        Domain = "winroot.analog.com"
        MemberCount = 5
        EnabledMemberCount = 4
        DisabledMemberCount = 1
        Status = "Active"
        GroupScope = "Global"
    },
    @{
        GroupName = "Enterprise Admins"
        Domain = "winroot.analog.com"
        MemberCount = 2
        EnabledMemberCount = 2
        DisabledMemberCount = 0
        Status = "Active"
        GroupScope = "Universal"
    },
    @{
        GroupName = "Schema Admins"
        Domain = "winroot.analog.com"
        MemberCount = 1
        EnabledMemberCount = 1
        DisabledMemberCount = 0
        Status = "Active"
        GroupScope = "Universal"
    },
    @{
        GroupName = "Domain Admins"
        Domain = "ad.analog.com"
        MemberCount = 8
        EnabledMemberCount = 7
        DisabledMemberCount = 1
        Status = "Active"
        GroupScope = "Global"
    },
    @{
        GroupName = "Backup Operators"
        Domain = "ad.analog.com"
        MemberCount = 12
        EnabledMemberCount = 10
        DisabledMemberCount = 2
        Status = "Active"
        GroupScope = "Local"
    }
)

# Convert to PSCustomObjects for better compatibility
$testData = $testAuditData | ForEach-Object { [PSCustomObject]$_ }

# Create test metadata
$testMetadata = @{
    "Test Environment" = "Development"
    "Forest Root" = "winroot.analog.com"
    "Domains Tested" = "2"
    "Groups Analyzed" = "$($testData.Count)"
    "Test Date" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

# Create output directory if it doesn't exist
$outputDir = Split-Path $OutputPath -Parent
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

try {
    Write-Host "Generating test report..." -ForegroundColor Yellow
    
    $result = New-EnhancedWebReport -AuditData $testData -OutputPath $OutputPath -ReportTitle "Enhanced Web Report Test" -CompanyName "Auditamate Test" -CustomMetadata $testMetadata
    
    Write-Host "✓ Test report generated successfully!" -ForegroundColor Green
    Write-Host "  File: $($result.FilePath)" -ForegroundColor Cyan
    Write-Host "  Size: $([math]::Round($result.FileSize / 1KB, 2)) KB" -ForegroundColor Cyan
    Write-Host "  Data points: $($result.AuditDataCount)" -ForegroundColor Cyan
    
    # Ask user if they want to open the report
    $openReport = Read-Host "`nOpen the test report now? [Y/N]"
    if ($openReport -eq 'Y' -or $openReport -eq 'y') {
        Start-Process $result.FilePath
    }
    
    Write-Host "`n✓ Enhanced Web Report Generator test completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor Red
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}