# Quick fix for Run-ForestAudit.ps1 unicode issue
param(
    [string]$TargetPath = "D:\ADAuditTool\Scripts\Run-ForestAudit.ps1"
)

Write-Host "Fixing Run-ForestAudit.ps1 unicode issue..." -ForegroundColor Yellow

if (-not (Test-Path $TargetPath)) {
    Write-Host "ERROR: File not found at $TargetPath" -ForegroundColor Red
    exit 1
}

# Read the file
$content = Get-Content $TargetPath -Raw -Encoding UTF8

# Replace any smart quotes with regular quotes
$content = $content -replace '[\u2018\u2019]', "'"  # Smart single quotes
$content = $content -replace '[\u201C\u201D]', '"'  # Smart double quotes
$content = $content -replace '[\u2013\u2014]', '-'  # Em dash and en dash
$content = $content -replace '\u2022', '*'          # Bullet
$content = $content -replace '\u2026', '...'        # Ellipsis

# Specifically fix line 341 if it has issues
$lines = $content -split "`r?`n"
if ($lines[340] -match 'Stack Trace:') {
    # Reconstruct the line with proper quotes
    $lines[340] = '    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red'
    Write-Host "Fixed line 341" -ForegroundColor Green
}

# Join lines back and save
$content = $lines -join "`r`n"
Set-Content -Path $TargetPath -Value $content -Encoding UTF8 -NoNewline

Write-Host "File fixed successfully!" -ForegroundColor Green
Write-Host "You can now run the Forest Audit without syntax errors." -ForegroundColor Green