# PowerShell Linting Report Generator
# Performs comprehensive code quality checks on PowerShell files

$script:LintingResults = @{
    Summary = @{
        TotalFiles = 0
        TotalIssues = 0
        Errors = 0
        Warnings = 0
        Information = 0
        StartTime = Get-Date
    }
    Files = @()
}

function Test-PowerShellFile {
    param([string]$FilePath)
    
    $fileResults = @{
        FilePath = $FilePath
        FileName = Split-Path $FilePath -Leaf
        Issues = @()
        Statistics = @{
            Lines = 0
            Functions = 0
            Commands = 0
            Variables = 0
            Comments = 0
        }
    }
    
    try {
        $content = Get-Content $FilePath -Raw
        $lines = Get-Content $FilePath
        $fileResults.Statistics.Lines = $lines.Count
        
        # Check 1: Syntax validation
        $errors = $null
        $tokens = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors)
        
        if ($errors.Count -gt 0) {
            foreach ($error in $errors) {
                $fileResults.Issues += @{
                    Type = "Error"
                    Category = "Syntax"
                    Line = $error.Token.StartLine
                    Message = $error.Message
                    Rule = "PS0001-SyntaxError"
                }
                $script:LintingResults.Summary.Errors++
            }
        }
        
        # Check 2: Function naming conventions
        $functions = [regex]::Matches($content, 'function\s+([A-Za-z0-9-_]+)')
        $fileResults.Statistics.Functions = $functions.Count
        foreach ($func in $functions) {
            $funcName = $func.Groups[1].Value
            if ($funcName -notmatch '^[A-Z][a-z]+-[A-Z][a-zA-Z0-9]+$') {
                if ($funcName -notmatch '^(Write|Get|Set|New|Remove|Test|Invoke|Start|Stop|Enable|Disable)-') {
                    $lineNum = ($content.Substring(0, $func.Index) -split "`n").Count
                    $fileResults.Issues += @{
                        Type = "Warning"
                        Category = "Naming"
                        Line = $lineNum
                        Message = "Function '$funcName' doesn't follow Verb-Noun naming convention"
                        Rule = "PS0002-FunctionNaming"
                    }
                    $script:LintingResults.Summary.Warnings++
                }
            }
        }
        
        # Check 3: Variable naming conventions
        $variables = [regex]::Matches($content, '\$([A-Za-z0-9_]+)')
        $uniqueVars = $variables | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        $fileResults.Statistics.Variables = $uniqueVars.Count
        
        # Check 4: Mandatory parameter validation
        $paramBlocks = [regex]::Matches($content, 'param\s*\(([\s\S]*?)\)', [System.Text.RegularExpressions.RegexOptions]::Multiline)
        foreach ($paramBlock in $paramBlocks) {
            $mandatoryParams = [regex]::Matches($paramBlock.Value, '\[Parameter\([^)]*Mandatory\s*=\s*\$true[^)]*\)\]')
            foreach ($param in $mandatoryParams) {
                if ($param.Value -notmatch 'HelpMessage') {
                    $lineNum = ($content.Substring(0, $param.Index) -split "`n").Count
                    $fileResults.Issues += @{
                        Type = "Information"
                        Category = "BestPractice"
                        Line = $lineNum
                        Message = "Mandatory parameter missing HelpMessage attribute"
                        Rule = "PS0003-MandatoryHelpMessage"
                    }
                    $script:LintingResults.Summary.Information++
                }
            }
        }
        
        # Check 5: Comment ratio
        $commentLines = ($lines | Where-Object { $_ -match '^\s*#' }).Count
        $fileResults.Statistics.Comments = $commentLines
        $commentRatio = if ($lines.Count -gt 0) { [math]::Round(($commentLines / $lines.Count) * 100, 2) } else { 0 }
        
        if ($commentRatio -lt 10 -and $lines.Count -gt 50) {
            $fileResults.Issues += @{
                Type = "Information"
                Category = "Documentation"
                Line = 0
                Message = "Low comment ratio: $commentRatio% (recommended: >10% for files over 50 lines)"
                Rule = "PS0004-InsufficientComments"
            }
            $script:LintingResults.Summary.Information++
        }
        
        # Check 6: Line length
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Length -gt 120) {
                $fileResults.Issues += @{
                    Type = "Information"
                    Category = "Style"
                    Line = $i + 1
                    Message = "Line exceeds 120 characters (length: $($lines[$i].Length))"
                    Rule = "PS0005-LineTooLong"
                }
                $script:LintingResults.Summary.Information++
            }
        }
        
        # Check 7: Use of aliases
        $commonAliases = @('?', '%', 'cd', 'cls', 'copy', 'del', 'dir', 'echo', 'gc', 'gi', 'gl', 'gm', 'gp', 'gps', 'group', 'gsv', 'gv', 'iex', 'ii', 'iwr', 'kill', 'ls', 'measure', 'mi', 'move', 'mp', 'mv', 'nal', 'ndr', 'ni', 'nv', 'oh', 'popd', 'ps', 'pushd', 'pwd', 'r', 'rbp', 'rd', 'rdr', 'ren', 'ri', 'rm', 'rmdir', 'rni', 'rnp', 'rp', 'rv', 'rvpa', 'rwmi', 'sal', 'saps', 'sasv', 'sbp', 'sc', 'select', 'set', 'shcm', 'si', 'sl', 'sleep', 'sls', 'sort', 'sp', 'spps', 'spsv', 'start', 'sv', 'swmi', 'tee', 'trcm', 'type', 'where', 'wjb', 'write')
        
        foreach ($alias in $commonAliases) {
            $pattern = "\b$alias\b"
            $matches = [regex]::Matches($content, $pattern)
            foreach ($match in $matches) {
                $lineNum = ($content.Substring(0, $match.Index) -split "`n").Count
                # Skip if it's in a comment
                $lineContent = $lines[$lineNum - 1]
                if ($lineContent -notmatch '^\s*#') {
                    $fileResults.Issues += @{
                        Type = "Warning"
                        Category = "Style"
                        Line = $lineNum
                        Message = "Use of alias '$alias' detected. Use full cmdlet name for better readability"
                        Rule = "PS0006-AvoidAlias"
                    }
                    $script:LintingResults.Summary.Warnings++
                }
            }
        }
        
        # Check 8: Error handling
        $tryBlocks = [regex]::Matches($content, '\btry\s*{')
        $catchBlocks = [regex]::Matches($content, '\bcatch\s*{')
        
        if ($tryBlocks.Count -ne $catchBlocks.Count) {
            $fileResults.Issues += @{
                Type = "Warning"
                Category = "ErrorHandling"
                Line = 0
                Message = "Mismatched try/catch blocks (try: $($tryBlocks.Count), catch: $($catchBlocks.Count))"
                Rule = "PS0007-ErrorHandling"
            }
            $script:LintingResults.Summary.Warnings++
        }
        
        # Check 9: Write-Host usage
        $writeHosts = [regex]::Matches($content, 'Write-Host')
        foreach ($writeHost in $writeHosts) {
            $lineNum = ($content.Substring(0, $writeHost.Index) -split "`n").Count
            $fileResults.Issues += @{
                Type = "Information"
                Category = "Output"
                Line = $lineNum
                Message = "Consider using Write-Output or Write-Information instead of Write-Host for better pipeline support"
                Rule = "PS0008-AvoidWriteHost"
            }
            $script:LintingResults.Summary.Information++
        }
        
        # Check 10: Backticks for line continuation
        $backticks = [regex]::Matches($content, '`\s*$', [System.Text.RegularExpressions.RegexOptions]::Multiline)
        foreach ($backtick in $backticks) {
            $lineNum = ($content.Substring(0, $backtick.Index) -split "`n").Count
            $fileResults.Issues += @{
                Type = "Information"
                Category = "Style"
                Line = $lineNum
                Message = "Avoid using backticks for line continuation. Consider using splatting or natural line breaks"
                Rule = "PS0009-AvoidBackticks"
            }
            $script:LintingResults.Summary.Information++
        }
        
    } catch {
        $fileResults.Issues += @{
            Type = "Error"
            Category = "Processing"
            Line = 0
            Message = "Failed to analyze file: $_"
            Rule = "PS0000-ProcessingError"
        }
        $script:LintingResults.Summary.Errors++
    }
    
    $script:LintingResults.Summary.TotalIssues += $fileResults.Issues.Count
    return $fileResults
}

# Get all PowerShell files
$files = @()

$moduleFiles = Get-ChildItem -Path "installer\Modules" -Filter "*.ps*1" | Where-Object {
    $_.Name -match 'AD-AuditModule|AD-MultiDomainAudit|AD-ReportGenerator|Audit-CodeCapture|Audit-Logging|AuditBoard-Integration|EntraID-RoleAudit|Exchange-RBACaudit|LocalAdmin-Audit|MSGraph-Authentication|PrivilegedAccess-UnifiedReport|Workday-Integration|Audit-EnhancedCapture|Audit-OutputCapture|Audit-StandardOutput'
}

$scriptFiles = Get-ChildItem -Path "installer\Scripts" -Filter "*.ps1" | Where-Object {
    $_.Name -match 'Run-ADCompleteAudit|Run-ForestAudit|Run-LocalAdminAudit|Run-PrivilegedAccessAudit|Run-TerminationAudit'
}

$files = $moduleFiles + $scriptFiles

Write-Host "`n================================" -ForegroundColor Cyan
Write-Host " PowerShell Linting Report" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Starting analysis at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

foreach ($file in $files) {
    Write-Host "Analyzing: $($file.Name)..." -NoNewline
    $result = Test-PowerShellFile -FilePath $file.FullName
    $script:LintingResults.Files += $result
    $script:LintingResults.Summary.TotalFiles++
    
    if ($result.Issues.Count -eq 0) {
        Write-Host " ✓ PASS" -ForegroundColor Green
    } else {
        $errors = ($result.Issues | Where-Object { $_.Type -eq "Error" }).Count
        $warnings = ($result.Issues | Where-Object { $_.Type -eq "Warning" }).Count
        $info = ($result.Issues | Where-Object { $_.Type -eq "Information" }).Count
        
        Write-Host " Issues: " -NoNewline
        if ($errors -gt 0) { Write-Host "$errors errors " -ForegroundColor Red -NoNewline }
        if ($warnings -gt 0) { Write-Host "$warnings warnings " -ForegroundColor Yellow -NoNewline }
        if ($info -gt 0) { Write-Host "$info info" -ForegroundColor Cyan -NoNewline }
        Write-Host ""
    }
}

$script:LintingResults.Summary.EndTime = Get-Date
$script:LintingResults.Summary.Duration = $script:LintingResults.Summary.EndTime - $script:LintingResults.Summary.StartTime

# Display detailed results
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host " Detailed Issues" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

foreach ($file in $script:LintingResults.Files | Where-Object { $_.Issues.Count -gt 0 }) {
    Write-Host "`n$($file.FileName):" -ForegroundColor White
    foreach ($issue in $file.Issues | Sort-Object Line) {
        $color = switch ($issue.Type) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Information" { "Cyan" }
            default { "Gray" }
        }
        $lineInfo = if ($issue.Line -gt 0) { "Line $($issue.Line): " } else { "" }
        Write-Host "  [$($issue.Rule)] $lineInfo$($issue.Message)" -ForegroundColor $color
    }
}

# Display summary
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Total Files Analyzed: $($script:LintingResults.Summary.TotalFiles)"
Write-Host "Total Issues Found: $($script:LintingResults.Summary.TotalIssues)"
Write-Host "  Errors: $($script:LintingResults.Summary.Errors)" -ForegroundColor Red
Write-Host "  Warnings: $($script:LintingResults.Summary.Warnings)" -ForegroundColor Yellow
Write-Host "  Information: $($script:LintingResults.Summary.Information)" -ForegroundColor Cyan
Write-Host "Duration: $([math]::Round($script:LintingResults.Summary.Duration.TotalSeconds, 2)) seconds"

# Export results to JSON
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = "PowerShell-Linting-Report-$timestamp.json"
$script:LintingResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "Detailed JSON report saved" -ForegroundColor Green
