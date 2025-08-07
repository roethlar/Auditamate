# Audit Logging Functions

function Initialize-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,
        
        [Parameter(Mandatory=$true)]
        [string]$LogName
    )
    
    # Ensure output directory exists
    if (!(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    # Setup log files
    $script:LogFile = "$OutputDirectory\$LogName.log"
    $script:TranscriptFile = "$OutputDirectory\$LogName-transcript.log"
    
    # Start transcript
    Start-Transcript -Path $script:TranscriptFile -Force | Out-Null
    
    # Initial log entry
    Write-AuditLog "Audit logging initialized" "INFO"
    Write-AuditLog "Output Directory: $OutputDirectory" "INFO"
}

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file if initialized
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logEntry
    }
    
    # Console output with color
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "DEBUG" { Write-Host $Message -ForegroundColor Gray }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Stop-AuditLog {
    [CmdletBinding()]
    param()
    
    Write-AuditLog "Audit logging stopped" "INFO"
    
    # Stop transcript
    Stop-Transcript | Out-Null
    
    # Return log paths
    return @{
        LogFile = $script:LogFile
        TranscriptFile = $script:TranscriptFile
    }
}

# Functions are automatically available when script is dot-sourced