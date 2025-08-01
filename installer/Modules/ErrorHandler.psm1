#Requires -Version 5.1

<#
.SYNOPSIS
    Centralized error handling for AD Audit Tool
#>

# Error categories
enum ErrorCategory {
    Authentication
    Authorization
    Validation
    Configuration
    Network
    Resource
    Unknown
}

class AuditError : System.Exception {
    [ErrorCategory]$Category
    [string]$Context
    [hashtable]$Details
    
    AuditError([string]$message, [ErrorCategory]$category, [string]$context) : base($message) {
        $this.Category = $category
        $this.Context = $context
        $this.Details = @{}
    }
    
    AuditError([string]$message, [ErrorCategory]$category, [string]$context, [hashtable]$details) : base($message) {
        $this.Category = $category
        $this.Context = $context
        $this.Details = $details
    }
}

function Write-AuditError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        
        [Parameter(Mandatory = $false)]
        [string]$Context = $MyInvocation.MyCommand.Name,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AdditionalInfo = @{}
    )
    
    $errorInfo = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Context = $Context
        ErrorType = $ErrorRecord.Exception.GetType().FullName
        Message = $ErrorRecord.Exception.Message
        ScriptLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
        ScriptName = $ErrorRecord.InvocationInfo.ScriptName
        Command = $ErrorRecord.InvocationInfo.MyCommand.Name
        TargetObject = $ErrorRecord.TargetObject
        AdditionalInfo = $AdditionalInfo
    }
    
    # Sanitize sensitive information
    $sanitized = $errorInfo.Message -replace '(password|secret|key|token)=([^;\s]+)', '$1=***'
    $errorInfo.Message = $sanitized
    
    # Log to file
    $logPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ADAudit\Logs'
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    
    $logFile = Join-Path $logPath "errors_$(Get-Date -Format 'yyyy-MM-dd').log"
    $errorInfo | ConvertTo-Json -Compress | Add-Content -Path $logFile
    
    # Return sanitized error for display
    return $errorInfo
}

function Invoke-AuditCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [string]$Context,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter(Mandatory = $false)]
        [scriptblock]$FinallyBlock
    )
    
    $attempt = 0
    $lastError = $null
    
    while ($attempt -lt $MaxRetries) {
        try {
            $attempt++
            return & $ScriptBlock
        }
        catch [System.UnauthorizedAccessException] {
            $lastError = $_
            Write-AuditError -ErrorRecord $_ -Context $Context
            throw [AuditError]::new(
                "Access denied in $Context",
                [ErrorCategory]::Authorization,
                $Context,
                @{ Attempt = $attempt }
            )
        }
        catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException] {
            $lastError = $_
            if ($attempt -lt $MaxRetries) {
                Write-Warning "AD operation failed, retrying in $RetryDelaySeconds seconds... (Attempt $attempt of $MaxRetries)"
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }
        }
        catch {
            $lastError = $_
            $errorDetails = Write-AuditError -ErrorRecord $_ -Context $Context
            
            # Check if retryable
            $retryableErrors = @(
                'System.Net.WebException',
                'System.Net.Http.HttpRequestException',
                'System.TimeoutException'
            )
            
            if ($attempt -lt $MaxRetries -and $_.Exception.GetType().FullName -in $retryableErrors) {
                Write-Warning "Transient error, retrying in $RetryDelaySeconds seconds... (Attempt $attempt of $MaxRetries)"
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }
            
            throw
        }
        finally {
            if ($FinallyBlock) {
                & $FinallyBlock
            }
        }
    }
    
    # Max retries exceeded
    throw [AuditError]::new(
        "Operation failed after $MaxRetries attempts: $($lastError.Exception.Message)",
        [ErrorCategory]::Unknown,
        $Context,
        @{ Attempts = $MaxRetries; LastError = $lastError.Exception.Message }
    )
}

Export-ModuleMember -Function Write-AuditError, Invoke-AuditCommand -Cmdlet *