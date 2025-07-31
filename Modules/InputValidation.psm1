#Requires -Version 5.1

<#
.SYNOPSIS
    Provides centralized input validation for AD Audit Tool
.DESCRIPTION
    Implements secure input validation to prevent injection attacks and ensure data integrity
#>

class ADGroupNameValidator : System.Management.Automation.IValidateSetValuesGenerator {
    [string[]] GetValidValues() {
        # Dynamically get valid AD groups if needed
        return @()
    }
}

function Test-ADGroupName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$GroupName
    )
    
    process {
        # Check for null or empty
        if ([string]::IsNullOrWhiteSpace($GroupName)) {
            return $false
        }
        
        # Check length
        if ($GroupName.Length -gt 256) {
            return $false
        }
        
        # Check for valid characters only (alphanumeric, spaces, hyphens, underscores)
        if ($GroupName -notmatch '^[a-zA-Z0-9\s\-_]+$') {
            return $false
        }
        
        # Check for injection patterns
        $injectionPatterns = @(
            '.*\$\(.*\).*',  # Command substitution
            '.*`.*',         # Backtick escape
            '.*;.*',         # Command chaining
            '.*\|.*',        # Pipe
            '.*>.*',         # Redirection
            '.*<.*',         # Input redirection
            '.*&.*',         # Background job
            '.*\{.*\}.*'     # Script block
        )
        
        foreach ($pattern in $injectionPatterns) {
            if ($GroupName -match $pattern) {
                return $false
            }
        }
        
        return $true
    }
}

function Test-FilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path
    )
    
    # Prevent path traversal
    if ($Path -match '\.\.[\\\/]') {
        return $false
    }
    
    # Check for invalid characters
    $invalidChars = [System.IO.Path]::GetInvalidPathChars()
    foreach ($char in $invalidChars) {
        if ($Path.Contains($char)) {
            return $false
        }
    }
    
    # Ensure path is within allowed directories
    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $allowedPaths = @(
            $PSScriptRoot,
            [System.IO.Path]::GetTempPath(),
            [Environment]::GetFolderPath('MyDocuments')
        )
        
        $isAllowed = $false
        foreach ($allowed in $allowedPaths) {
            if ($fullPath.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
                $isAllowed = $true
                break
            }
        }
        
        return $isAllowed
    }
    catch {
        return $false
    }
}

function Test-EmailAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$Email
    )
    
    process {
        if ([string]::IsNullOrWhiteSpace($Email)) {
            return $false
        }
        
        # RFC 5322 compliant email regex
        $emailRegex = '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        return $Email -match $emailRegex
    }
}

Export-ModuleMember -Function Test-ADGroupName, Test-FilePath, Test-EmailAddress