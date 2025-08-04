# AuditBoard Integration Module
# Provides functions to upload audit results to AuditBoard platform

<#
.SYNOPSIS
    Connects to AuditBoard API for authentication.

.DESCRIPTION
    Establishes connection to AuditBoard using provided credentials.
    Stores authentication token for subsequent API calls.

.PARAMETER BaseUrl
    AuditBoard instance URL (e.g., https://yourcompany.auditboard.com)

.PARAMETER ApiKey
    API key for authentication (if using API key auth)

.PARAMETER ClientId
    OAuth client ID (if using OAuth)

.PARAMETER ClientSecret
    OAuth client secret (if using OAuth)

.EXAMPLE
    Connect-AuditBoard -BaseUrl "https://company.auditboard.com" -ApiKey $apiKey
#>
function Connect-AuditBoard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaseUrl,
        
        [Parameter(Mandatory=$false)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$false)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$false)]
        [SecureString]$ClientSecret
    )
    
    $script:AuditBoardBaseUrl = $BaseUrl.TrimEnd('/')
    
    try {
        if ($ApiKey) {
            # API Key authentication
            $script:AuditBoardHeaders = @{
                'Authorization' = "Bearer $ApiKey"
                'Content-Type' = 'application/json'
                'Accept' = 'application/json'
            }
            
            Write-Host "Connected to AuditBoard using API key authentication" -ForegroundColor Green
        }
        elseif ($ClientId -and $ClientSecret) {
            # OAuth authentication
            $clientSecretText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            )
            
            $tokenBody = @{
                grant_type = 'client_credentials'
                client_id = $ClientId
                client_secret = $clientSecretText
            }
            
            $tokenResponse = Invoke-RestMethod -Uri "$script:AuditBoardBaseUrl/api/oauth/token" `
                -Method Post -Body ($tokenBody | ConvertTo-Json) -ContentType 'application/json'
            
            $script:AuditBoardHeaders = @{
                'Authorization' = "Bearer $($tokenResponse.access_token)"
                'Content-Type' = 'application/json'
                'Accept' = 'application/json'
            }
            
            Write-Host "Connected to AuditBoard using OAuth authentication" -ForegroundColor Green
        }
        else {
            throw "Either ApiKey or ClientId/ClientSecret must be provided"
        }
        
        # Test connection
        $testResponse = Invoke-RestMethod -Uri "$script:AuditBoardBaseUrl/api/v1/user" `
            -Headers $script:AuditBoardHeaders -Method Get
            
        Write-Host "Successfully authenticated as: $($testResponse.email)" -ForegroundColor Green
        
    } catch {
        Write-Host "Failed to connect to AuditBoard: $_" -ForegroundColor Red
        throw
    }
}

<#
.SYNOPSIS
    Creates or updates an audit record in AuditBoard.

.DESCRIPTION
    Uploads audit results to AuditBoard, creating a new record or updating existing one.

.PARAMETER AuditData
    Hashtable containing audit data to upload

.PARAMETER AuditType
    Type of audit (e.g., "AD_Group_Audit", "Privileged_Access_Audit")

.PARAMETER ProjectId
    AuditBoard project ID to associate the audit with

.PARAMETER UpdateExisting
    If true, updates existing audit record instead of creating new
#>
function New-AuditBoardRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AuditData,
        
        [Parameter(Mandatory=$true)]
        [string]$AuditType,
        
        [Parameter(Mandatory=$false)]
        [string]$ProjectId,
        
        [Parameter(Mandatory=$false)]
        [switch]$UpdateExisting
    )
    
    if (-not $script:AuditBoardHeaders) {
        throw "Not connected to AuditBoard. Run Connect-AuditBoard first."
    }
    
    try {
        # Prepare audit record
        $auditRecord = @{
            type = $AuditType
            title = "$AuditType - $(Get-Date -Format 'yyyy-MM-dd')"
            status = 'completed'
            completion_date = (Get-Date).ToString('yyyy-MM-dd')
            data = $AuditData
            metadata = @{
                source = 'PowerShell AD Audit Tool'
                version = '1.0'
                timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        }
        
        if ($ProjectId) {
            $auditRecord.project_id = $ProjectId
        }
        
        # Create or update record
        if ($UpdateExisting) {
            # Search for existing record
            $searchResponse = Invoke-RestMethod -Uri "$script:AuditBoardBaseUrl/api/v1/audits" `
                -Headers $script:AuditBoardHeaders `
                -Method Get `
                -Body @{
                    type = $AuditType
                    date = (Get-Date).ToString('yyyy-MM-dd')
                }
            
            if ($searchResponse.data.Count -gt 0) {
                $existingId = $searchResponse.data[0].id
                $response = Invoke-RestMethod -Uri "$script:AuditBoardBaseUrl/api/v1/audits/$existingId" `
                    -Headers $script:AuditBoardHeaders `
                    -Method Put `
                    -Body ($auditRecord | ConvertTo-Json -Depth 10)
                
                Write-Host "Updated existing audit record ID: $existingId" -ForegroundColor Green
            }
            else {
                Write-Host "No existing record found, creating new..." -ForegroundColor Yellow
                $UpdateExisting = $false
            }
        }
        
        if (-not $UpdateExisting) {
            $response = Invoke-RestMethod -Uri "$script:AuditBoardBaseUrl/api/v1/audits" `
                -Headers $script:AuditBoardHeaders `
                -Method Post `
                -Body ($auditRecord | ConvertTo-Json -Depth 10)
            
            Write-Host "Created new audit record ID: $($response.data.id)" -ForegroundColor Green
        }
        
        return $response.data
        
    } catch {
        Write-Host "Failed to create/update AuditBoard record: $_" -ForegroundColor Red
        throw
    }
}

<#
.SYNOPSIS
    Uploads a file attachment to an AuditBoard record.

.PARAMETER RecordId
    ID of the AuditBoard record to attach file to

.PARAMETER FilePath
    Path to the file to upload

.PARAMETER Description
    Description of the file attachment
#>
function Add-AuditBoardAttachment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RecordId,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$false)]
        [string]$Description = ""
    )
    
    if (-not $script:AuditBoardHeaders) {
        throw "Not connected to AuditBoard. Run Connect-AuditBoard first."
    }
    
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    try {
        $fileName = Split-Path $FilePath -Leaf
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileBase64 = [System.Convert]::ToBase64String($fileBytes)
        
        $attachmentData = @{
            file_name = $fileName
            file_data = $fileBase64
            description = $Description
            record_id = $RecordId
        }
        
        $response = Invoke-RestMethod -Uri "$script:AuditBoardBaseUrl/api/v1/attachments" `
            -Headers $script:AuditBoardHeaders `
            -Method Post `
            -Body ($attachmentData | ConvertTo-Json)
        
        Write-Host "Uploaded attachment: $fileName" -ForegroundColor Green
        return $response.data
        
    } catch {
        Write-Host "Failed to upload attachment: $_" -ForegroundColor Red
        throw
    }
}

<#
.SYNOPSIS
    Uploads AD audit results to AuditBoard.

.PARAMETER AuditResults
    Hashtable containing audit results from AD audit scripts

.PARAMETER ReportFiles
    Array of file paths to attach to the audit record

.PARAMETER ProjectId
    Optional AuditBoard project ID
#>
function Export-ADToAuditBoard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AuditResults,
        
        [Parameter(Mandatory=$false)]
        [string[]]$ReportFiles,
        
        [Parameter(Mandatory=$false)]
        [string]$ProjectId
    )
    
    try {
        # Create summary data for AuditBoard
        $auditData = @{
            audit_date = (Get-Date).ToString('yyyy-MM-dd')
            auditor = $env:USERNAME
            groups_audited = $AuditResults.GroupsAudited
            total_members = $AuditResults.TotalMembers
            findings = @{
                disabled_users_with_access = $AuditResults.DisabledUsersWithAccess
                expired_passwords = $AuditResults.ExpiredPasswords
                inactive_users = $AuditResults.InactiveUsers
                cross_domain_members = $AuditResults.CrossDomainMembers
            }
            compliance_status = if ($AuditResults.ComplianceIssues -gt 0) { 'Issues Found' } else { 'Compliant' }
        }
        
        # Create audit record
        $record = New-AuditBoardRecord -AuditData $auditData -AuditType 'AD_Group_Audit' -ProjectId $ProjectId
        
        # Upload attachments
        if ($ReportFiles) {
            foreach ($file in $ReportFiles) {
                if (Test-Path $file) {
                    Add-AuditBoardAttachment -RecordId $record.id -FilePath $file `
                        -Description "Audit report: $(Split-Path $file -Leaf)"
                }
            }
        }
        
        Write-Host "`nSuccessfully uploaded audit to AuditBoard" -ForegroundColor Green
        Write-Host "Record ID: $($record.id)" -ForegroundColor White
        Write-Host "View in AuditBoard: $script:AuditBoardBaseUrl/audits/$($record.id)" -ForegroundColor Cyan
        
        return $record
        
    } catch {
        Write-Host "Failed to export to AuditBoard: $_" -ForegroundColor Red
        throw
    }
}

# Export functions
# Functions are automatically available when script is dot-sourced