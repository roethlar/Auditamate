#Requires -Version 5.1

enum LogLevel {
    Debug = 0
    Info = 1
    Warning = 2
    Error = 3
    Critical = 4
}

class AuditLogger {
    [string]$LogPath
    [LogLevel]$MinLevel
    [int64]$MaxSizeBytes
    [int]$MaxFiles
    [System.Threading.Mutex]$Mutex
    
    AuditLogger([string]$logPath, [LogLevel]$minLevel) {
        $this.LogPath = $logPath
        $this.MinLevel = $minLevel
        $this.MaxSizeBytes = 10MB
        $this.MaxFiles = 10
        $this.Mutex = New-Object System.Threading.Mutex($false, "ADAuditLogger")
        
        # Ensure log directory exists
        $dir = Split-Path $logPath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    [void] Write([LogLevel]$level, [string]$message, [hashtable]$properties) {
        if ($level -lt $this.MinLevel) { return }
        
        $logEntry = [ordered]@{
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
            Level = $level.ToString()
            Message = $message
            Properties = $properties
            ProcessId = $PID
            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
            User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Computer = $env:COMPUTERNAME
        }
        
        try {
            $this.Mutex.WaitOne() | Out-Null
            
            # Check rotation
            if ((Test-Path $this.LogPath) -and (Get-Item $this.LogPath).Length -gt $this.MaxSizeBytes) {
                $this.RotateLog()
            }
            
            # Write log entry
            $logEntry | ConvertTo-Json -Compress | Add-Content -Path $this.LogPath -Encoding UTF8
        }
        finally {
            $this.Mutex.ReleaseMutex()
        }
    }
    
    [void] RotateLog() {
        # Rotate existing logs
        for ($i = $this.MaxFiles - 1; $i -ge 1; $i--) {
            $oldFile = "$($this.LogPath).$i"
            $newFile = "$($this.LogPath).$($i + 1)"
            
            if (Test-Path $oldFile) {
                if (Test-Path $newFile) {
                    Remove-Item $newFile -Force
                }
                Rename-Item $oldFile $newFile
            }
        }
        
        # Rotate current log
        if (Test-Path $this.LogPath) {
            Rename-Item $this.LogPath "$($this.LogPath).1"
        }
    }
}

# Global logger instance
$script:Logger = $null

function Initialize-AuditLogger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ADAudit\Logs\audit.log'),
        
        [Parameter(Mandatory = $false)]
        [LogLevel]$MinLevel = [LogLevel]::Info
    )
    
    $script:Logger = [AuditLogger]::new($LogPath, $MinLevel)
}

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [LogLevel]$Level = [LogLevel]::Info,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Properties = @{},
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    if (-not $script:Logger) {
        Initialize-AuditLogger
    }
    
    # Add caller information
    $callStack = Get-PSCallStack
    if ($callStack.Count -gt 1) {
        $Properties['Caller'] = $callStack[1].Command
        $Properties['ScriptName'] = $callStack[1].ScriptName
        $Properties['LineNumber'] = $callStack[1].ScriptLineNumber
    }
    
    $script:Logger.Write($Level, $Message, $Properties)
    
    if ($PassThru) {
        # Also write to appropriate stream
        switch ($Level) {
            'Debug' { Write-Debug $Message }
            'Info' { Write-Information $Message -InformationAction Continue }
            'Warning' { Write-Warning $Message }
            'Error' { Write-Error $Message }
            'Critical' { Write-Error $Message; throw $Message }
        }
    }
}

Export-ModuleMember -Function Initialize-AuditLogger, Write-AuditLog