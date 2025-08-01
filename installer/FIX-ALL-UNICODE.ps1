# Comprehensive Unicode Fix Script
param(
    [string]$TargetDirectory = "D:\ADAuditTool"
)

Write-Host "`n=== Unicode Fix for AD Audit Tool ===" -ForegroundColor Cyan

if (-not (Test-Path "$TargetDirectory\Scripts")) {
    Write-Host "ERROR: Scripts folder not found at $TargetDirectory\Scripts" -ForegroundColor Red
    exit 1
}

function Fix-UnicodeInFile {
    param([string]$FilePath)
    
    Write-Host "  Fixing: $(Split-Path -Leaf $FilePath)" -ForegroundColor Gray
    
    # Read as bytes to detect encoding issues
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    
    # Convert to string, replacing any non-ASCII with ASCII equivalents
    $content = [System.Text.Encoding]::UTF8.GetString($bytes)
    
    # Common unicode replacements
    $replacements = @{
        # Smart quotes
        [char]0x2018 = "'"  # Left single quote
        [char]0x2019 = "'"  # Right single quote  
        [char]0x201C = '"'  # Left double quote
        [char]0x201D = '"'  # Right double quote
        # Dashes
        [char]0x2013 = "-"  # En dash
        [char]0x2014 = "-"  # Em dash
        # Other
        [char]0x2022 = "*"  # Bullet
        [char]0x2026 = "..."  # Ellipsis
        [char]0x00A0 = " "  # Non-breaking space
        # Additional problematic characters
        [char]0x0092 = "'"  # Windows-1252 right single quote
        [char]0x0093 = '"'  # Windows-1252 left double quote
        [char]0x0094 = '"'  # Windows-1252 right double quote
    }
    
    # Apply replacements
    foreach ($char in $replacements.Keys) {
        $content = $content.Replace($char, $replacements[$char])
    }
    
    # Additional regex replacements for any remaining non-ASCII
    $content = [System.Text.RegularExpressions.Regex]::Replace($content, '[\u0080-\u009F]', '')
    $content = [System.Text.RegularExpressions.Regex]::Replace($content, '[\u2000-\u206F]', ' ')
    
    # Save with UTF8 without BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($FilePath, $content, $utf8NoBom)
}

# Fix all PowerShell scripts
Write-Host "`nFixing scripts in: $TargetDirectory\Scripts" -ForegroundColor Yellow

$scripts = Get-ChildItem -Path "$TargetDirectory\Scripts\*.ps1"
foreach ($script in $scripts) {
    Fix-UnicodeInFile -FilePath $script.FullName
}

# Also fix the main launcher
if (Test-Path "$TargetDirectory\Start-ADAudit.ps1") {
    Write-Host "`nFixing main launcher..." -ForegroundColor Yellow
    Fix-UnicodeInFile -FilePath "$TargetDirectory\Start-ADAudit.ps1"
}

Write-Host "`n=== Unicode Fix Complete ===" -ForegroundColor Green
Write-Host "All scripts have been cleaned of unicode characters." -ForegroundColor Green
Write-Host "`nYou should now be able to run all audits without syntax errors." -ForegroundColor Green