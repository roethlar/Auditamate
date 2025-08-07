# Microsoft Graph Authentication Module

function Connect-MSGraphWithCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$true)]
        [string]$CertificateThumbprint,
        
        [Parameter(Mandatory=$false)]
        [string[]]$Scopes = @("Directory.Read.All", "RoleManagement.Read.All", "AuditLog.Read.All")
    )
    
    try {
        # Install required module if not present
        if (!(Get-Module -ListAvailable -Name MSAL.PS)) {
            Write-Host "Installing MSAL.PS module..." -ForegroundColor Yellow
            Install-Module -Name MSAL.PS -Force -AllowClobber
        }
        
        Import-Module MSAL.PS
        
        # Get certificate from store
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My\$CertificateThumbprint
        if (!$cert) {
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My\$CertificateThumbprint
        }
        
        if (!$cert) {
            throw "Certificate with thumbprint $CertificateThumbprint not found"
        }
        
        # Get access token
        $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -ClientCertificate $cert -Scopes $Scopes
        
        # Create authentication header
        $script:GraphAuthHeader = @{
            'Authorization' = "Bearer $($token.AccessToken)"
            'Content-Type' = 'application/json'
        }
        
        # Store token info for refresh
        $script:GraphTokenInfo = @{
            Token = $token
            ClientId = $ClientId
            TenantId = $TenantId
            Certificate = $cert
            Scopes = $Scopes
            ExpiresOn = $token.ExpiresOn
        }
        
        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        throw
    }
}

function Connect-MSGraphWithSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$true)]
        [SecureString]$ClientSecret,
        
        [Parameter(Mandatory=$false)]
        [string[]]$Scopes = @("https://graph.microsoft.com/.default")
    )
    
    try {
        $body = @{
            grant_type    = "client_credentials"
            scope         = $Scopes -join " "
            client_id     = $ClientId
            client_secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
        }
        
        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
        
        $script:GraphAuthHeader = @{
            'Authorization' = "Bearer $($response.access_token)"
            'Content-Type' = 'application/json'
        }
        
        $script:GraphTokenInfo = @{
            AccessToken = $response.access_token
            ClientId = $ClientId
            TenantId = $TenantId
            ExpiresIn = $response.expires_in
            ExpiresOn = (Get-Date).AddSeconds($response.expires_in)
        }
        
        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        throw
    }
}

function Invoke-MSGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$false)]
        [string]$Method = "GET",
        
        [Parameter(Mandatory=$false)]
        [object]$Body,
        
        [Parameter(Mandatory=$false)]
        [switch]$FullResponse
    )
    
    # Check if token needs refresh
    if ($script:GraphTokenInfo.ExpiresOn -lt (Get-Date).AddMinutes(5)) {
        Write-Verbose "Token expires soon, refreshing..."
        if ($script:GraphTokenInfo.Certificate) {
            Connect-MSGraphWithCertificate -TenantId $script:GraphTokenInfo.TenantId -ClientId $script:GraphTokenInfo.ClientId -CertificateThumbprint $script:GraphTokenInfo.Certificate.Thumbprint -Scopes $script:GraphTokenInfo.Scopes
        }
    }
    
    try {
        $params = @{
            Uri = if ($Uri -match '^https://') { $Uri } else { "https://graph.microsoft.com/v1.0/$Uri" }
            Method = $Method
            Headers = $script:GraphAuthHeader
        }
        
        if ($Body) {
            $params.Body = $Body | ConvertTo-Json -Depth 10
        }
        
        $response = Invoke-RestMethod @params
        
        if ($FullResponse) {
            return $response
        } else {
            # Handle pagination automatically
            $results = @()
            $results += $response.value
            
            while ($response.'@odata.nextLink') {
                $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Headers $script:GraphAuthHeader
                $results += $response.value
            }
            
            return $results
        }
        
    } catch {
        Write-Error "Graph API request failed: $_"
        throw
    }
}

function Get-MSGraphBatchRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Requests,
        
        [Parameter(Mandatory=$false)]
        [int]$BatchSize = 20
    )
    
    $results = @()
    
    for ($i = 0; $i -lt $Requests.Count; $i += $BatchSize) {
        $batch = $Requests[$i..[Math]::Min($i + $BatchSize - 1, $Requests.Count - 1)]
        
        $batchBody = @{
            requests = @()
        }
        
        foreach ($request in $batch) {
            $batchBody.requests += @{
                id = $request.id
                method = $request.method
                url = $request.url
            }
        }
        
        $batchResponse = Invoke-MSGraphRequest -Uri "https://graph.microsoft.com/v1.0/`$batch" -Method POST -Body $batchBody -FullResponse
        
        foreach ($response in $batchResponse.responses) {
            $results += [PSCustomObject]@{
                id = $response.id
                status = $response.status
                body = $response.body
            }
        }
    }
    
    return $results
}

Export-ModuleMember -Function Connect-MSGraphWithCertificate, Connect-MSGraphWithSecret, Invoke-MSGraphRequest, Get-MSGraphBatchRequest