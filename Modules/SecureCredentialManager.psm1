#Requires -Version 5.1

<#
.SYNOPSIS
    Secure credential management for AD Audit Tool
#>

function Get-SecureCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,
        
        [Parameter(Mandatory = $false)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    $credPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ADAudit\Credentials'
    if (-not (Test-Path $credPath)) {
        New-Item -ItemType Directory -Path $credPath -Force | Out-Null
        # Set ACL to current user only
        $acl = Get-Acl $credPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            'FullControl',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $credPath -AclObject $acl
    }
    
    $credFile = Join-Path $credPath "$Target.xml"
    
    if ((Test-Path $credFile) -and -not $Force) {
        try {
            $cred = Import-Clixml $credFile
            # Validate credential is still valid
            $testPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
            )
            if ($testPassword.Length -gt 0) {
                return $cred
            }
        }
        catch {
            Write-Warning "Stored credential for $Target is invalid. Please re-enter."
            Remove-Item $credFile -Force
        }
    }
    
    # Prompt for new credential
    $promptMessage = if ($Username) {
        "Enter password for $Username @ $Target"
    } else {
        "Enter credentials for $Target"
    }
    
    $cred = Get-Credential -Message $promptMessage -UserName $Username
    
    if ($cred) {
        # Encrypt and save
        $cred | Export-Clixml $credFile
        # Encrypt the file using DPAPI
        $bytes = [System.IO.File]::ReadAllBytes($credFile)
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
            $bytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        [System.IO.File]::WriteAllBytes($credFile, $encrypted)
    }
    
    return $cred
}

function ConvertTo-SecureStringFromPlainText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText
    )
    
    Write-Warning "Converting plain text to SecureString. This should only be used during migration."
    
    $secureString = New-Object System.Security.SecureString
    foreach ($char in $PlainText.ToCharArray()) {
        $secureString.AppendChar($char)
    }
    $secureString.MakeReadOnly()
    
    return $secureString
}

Export-ModuleMember -Function Get-SecureCredential, ConvertTo-SecureStringFromPlainText