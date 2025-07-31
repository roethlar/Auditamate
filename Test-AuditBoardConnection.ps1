<#
.SYNOPSIS
    Tests connection to AuditBoard API and validates configuration.

.DESCRIPTION
    Verifies AuditBoard API connectivity and authentication settings.
    Useful for troubleshooting integration issues.

.PARAMETER ConfigFile
    Path to AuditBoard configuration file. Default: .\Config\auditboard-config.json

.EXAMPLE
    .\Test-AuditBoardConnection.ps1
    Tests connection using default config file.

.EXAMPLE
    .\Test-AuditBoardConnection.ps1 -ConfigFile .\custom-config.json
    Tests connection using custom config file.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "$PSScriptRoot\Config\auditboard-config.json"
)

Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "  AuditBoard Connection Test" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Cyan

try {
    # Load AuditBoard module
    . "$PSScriptRoot\Modules\AuditBoard-Integration.ps1"
    
    # Check if config exists
    if (-not (Test-Path $ConfigFile)) {
        Write-Host "Configuration file not found: $ConfigFile" -ForegroundColor Red
        Write-Host "`nTo set up AuditBoard integration:" -ForegroundColor Yellow
        Write-Host "1. Copy Config\auditboard-config-template.json to Config\auditboard-config.json"
        Write-Host "2. Update with your AuditBoard URL and API credentials"
        Write-Host "3. Run this test again to verify connection"
        exit 1
    }
    
    # Load configuration
    Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor White
    $config = Get-Content $ConfigFile | ConvertFrom-Json
    
    # Display configuration (without sensitive data)
    Write-Host "`nConfiguration:" -ForegroundColor Yellow
    Write-Host "  Base URL: $($config.AuditBoardSettings.BaseUrl)" -ForegroundColor White
    Write-Host "  Auth Type: $($config.AuditBoardSettings.AuthType)" -ForegroundColor White
    Write-Host "  Project ID: $($config.AuditBoardSettings.ProjectId)" -ForegroundColor White
    
    # Test connection
    Write-Host "`nTesting connection..." -ForegroundColor Yellow
    
    if ($config.AuditBoardSettings.AuthType -eq "ApiKey") {
        if ([string]::IsNullOrWhiteSpace($config.AuditBoardSettings.ApiKey)) {
            Write-Host "API Key is not configured!" -ForegroundColor Red
            Write-Host "Please add your API key to the configuration file." -ForegroundColor Yellow
            exit 1
        }
        
        $connectionResult = Connect-AuditBoard -BaseUrl $config.AuditBoardSettings.BaseUrl `
                                               -ApiKey $config.AuditBoardSettings.ApiKey
    } else {
        Write-Host "OAuth authentication not implemented in this example" -ForegroundColor Yellow
        Write-Host "Using API Key authentication is recommended" -ForegroundColor Yellow
        exit 1
    }
    
    if ($connectionResult) {
        Write-Host "✓ Successfully connected to AuditBoard!" -ForegroundColor Green
    } else {
        Write-Host "✗ Failed to connect to AuditBoard" -ForegroundColor Red
        exit 1
    }
    
    # Test API functionality
    Write-Host "`nTesting API functionality..." -ForegroundColor Yellow
    
    # Try to create a test record
    if ($config.AuditTypeMappings -and $config.AuditTypeMappings.PSObject.Properties.Count -gt 0) {
        Write-Host "Creating test record..." -ForegroundColor White
        
        $testData = @{
            Title = "Connection Test - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Description = "This is a test record created by the AD Audit Tool connection test"
            Status = "Test"
        }
        
        $testRecord = New-AuditBoardRecord -AuditData $testData `
            -AuditType "Connection_Test" `
            -ProjectId $config.AuditBoardSettings.ProjectId
        
        Write-Host "`n✓ Test record created successfully!" -ForegroundColor Green
        Write-Host "Record ID: $($testRecord.id)" -ForegroundColor White
    }
    
    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  AuditBoard integration is ready!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Verify your AuditBoard URL is correct"
    Write-Host "2. Check that your API key/credentials are valid"
    Write-Host "3. Ensure your account has API access enabled"
    Write-Host "4. Check network connectivity to AuditBoard"
    Write-Host "5. Review AuditBoard API documentation for your instance"
    exit 1
}