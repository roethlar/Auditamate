# Remove #Requires -RunAsAdministrator from audit scripts
param(
    [string]$TargetDirectory = "D:\ADAuditTool"
)

Write-Host "`n=== Removing Admin Requirement from Audit Scripts ===" -ForegroundColor Cyan
Write-Host "Note: Only do this if your account already has necessary AD permissions!" -ForegroundColor Yellow

$scripts = @(
    "$TargetDirectory\Scripts\Run-ForestAudit.ps1",
    "$TargetDirectory\Scripts\Run-ADCompleteAudit.ps1",
    "$TargetDirectory\Scripts\Run-PrivilegedAccessAudit.ps1",
    "$TargetDirectory\Scripts\Run-LocalAdminAudit.ps1"
)

foreach ($script in $scripts) {
    if (Test-Path $script) {
        Write-Host "  Processing: $(Split-Path -Leaf $script)" -ForegroundColor Gray
        
        $content = Get-Content $script -Raw
        $content = $content -replace '#Requires\s+-RunAsAdministrator', '# #Requires -RunAsAdministrator  # Disabled for service account'
        
        Set-Content -Path $script -Value $content -Encoding UTF8
    }
}

Write-Host "`n=== Complete ===" -ForegroundColor Green
Write-Host "Admin requirements have been commented out." -ForegroundColor Green
Write-Host "The scripts will now run without elevation." -ForegroundColor Green