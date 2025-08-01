#Requires -Version 5.1

# Import required modules
Import-Module "$PSScriptRoot\InputValidation.psm1" -Force

function Get-AuditConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile = (Join-Path $PSScriptRoot '..\Config\audit-config.json'),
        
        [Parameter(Mandatory = $false)]
        [switch]$Validate
    )
    
    # Schema definition
    $configSchema = @{
        Groups = @{
            Type = 'String[]'
            Required = $false
            Validator = { $_ | ForEach-Object { Test-ADGroupName $_ } }
        }
        EmailSettings = @{
            Type = 'Hashtable'
            Required = $false
            Properties = @{
                Recipients = @{ Type = 'String[]'; Validator = { $_ | ForEach-Object { Test-EmailAddress $_ } } }
                From = @{ Type = 'String'; Validator = { Test-EmailAddress $_ } }
                SmtpServer = @{ Type = 'String' }
                Port = @{ Type = 'Int32'; Range = @(1, 65535) }
                UseSSL = @{ Type = 'Boolean' }
            }
        }
        OutputSettings = @{
            Type = 'Hashtable'
            Required = $false
            Properties = @{
                GenerateHtml = @{ Type = 'Boolean' }
                GenerateExcel = @{ Type = 'Boolean' }
                GenerateCsv = @{ Type = 'Boolean' }
                OutputPath = @{ Type = 'String'; Validator = { Test-FilePath $_ } }
            }
        }
    }
    
    if (-not (Test-Path $ConfigFile)) {
        throw "Configuration file not found: $ConfigFile"
    }
    
    try {
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json -AsHashtable
    }
    catch {
        throw "Invalid JSON in configuration file: $_"
    }
    
    if ($Validate) {
        # Validate against schema
        foreach ($key in $configSchema.Keys) {
            $schema = $configSchema[$key]
            
            if ($schema.Required -and -not $config.ContainsKey($key)) {
                throw "Required configuration key missing: $key"
            }
            
            if ($config.ContainsKey($key)) {
                $value = $config[$key]
                
                # Type validation
                if ($value -isnot [type]$schema.Type) {
                    throw "Configuration key '$key' must be of type $($schema.Type)"
                }
                
                # Custom validator
                if ($schema.Validator) {
                    $isValid = & $schema.Validator $value
                    if (-not $isValid) {
                        throw "Configuration key '$key' failed validation"
                    }
                }
                
                # Nested properties
                if ($schema.Properties) {
                    foreach ($prop in $schema.Properties.Keys) {
                        # Recursive validation for nested properties
                    }
                }
            }
        }
    }
    
    # Apply defaults
    $defaults = @{
        Groups = @('Domain Admins', 'Enterprise Admins')
        OutputSettings = @{
            GenerateHtml = $true
            GenerateExcel = $true
            GenerateCsv = $false
            OutputPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'ADAudit\Reports'
        }
    }
    
    foreach ($key in $defaults.Keys) {
        if (-not $config.ContainsKey($key)) {
            $config[$key] = $defaults[$key]
        }
    }
    
    return $config
}

function Set-AuditConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Configuration,
        
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile = (Join-Path $PSScriptRoot '..\Config\audit-config.json')
    )
    
    if ($PSCmdlet.ShouldProcess($ConfigFile, "Save configuration")) {
        # Validate before saving
        $null = Get-AuditConfiguration -ConfigFile $ConfigFile -Validate
        
        # Backup existing
        if (Test-Path $ConfigFile) {
            $backup = "$ConfigFile.$(Get-Date -Format 'yyyyMMddHHmmss').bak"
            Copy-Item $ConfigFile $backup
        }
        
        # Save new configuration
        $Configuration | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile -Encoding UTF8
    }
}

Export-ModuleMember -Function Get-AuditConfiguration, Set-AuditConfiguration