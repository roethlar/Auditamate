# Workday Integration Module for User Termination Validation

function Get-WorkdayTerminatedUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        
        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = (Get-Date)
    )
    
    try {
        # Workday REST API endpoint for workers
        $apiUrl = "$TenantUrl/ccx/api/v1/workers"
        
        # Build query parameters for terminated workers
        $query = @{
            'effectiveDate' = $EndDate.ToString('yyyy-MM-dd')
            'terminated' = 'true'
            'terminationStartDate' = $StartDate.ToString('yyyy-MM-dd')
            'terminationEndDate' = $EndDate.ToString('yyyy-MM-dd')
        }
        
        $headers = @{
            'Accept' = 'application/json'
            'Content-Type' = 'application/json'
        }
        
        # Make REST API call
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -Credential $Credential -Body $query
        
        $terminatedUsers = @()
        
        foreach ($worker in $response.workers) {
            $terminatedUser = [PSCustomObject]@{
                WorkerID = $worker.workerID
                EmployeeID = $worker.employeeID
                FirstName = $worker.firstName
                LastName = $worker.lastName
                Email = $worker.primaryWorkEmail
                TerminationDate = [datetime]$worker.terminationDate
                LastDayOfWork = [datetime]$worker.lastDayOfWork
                Username = $worker.userName
                Department = $worker.primarySupervisoryOrganization
                JobTitle = $worker.businessTitle
                TerminationReason = $worker.terminationReason
            }
            $terminatedUsers += $terminatedUser
        }
        
        return $terminatedUsers
        
    } catch {
        Write-Error "Failed to retrieve Workday data: $_"
        throw
    }
}

function Get-WorkdayUserViaSOAP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantUrl,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$EmployeeID
    )
    
    # SOAP envelope for Get_Workers request
    $soapBody = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wd="urn:com.workday/bsvc">
    <soapenv:Header>
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wsse:UsernameToken>
                <wsse:Username>$($Credential.UserName)</wsse:Username>
                <wsse:Password>$($Credential.GetNetworkCredential().Password)</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </soapenv:Header>
    <soapenv:Body>
        <wd:Get_Workers_Request wd:version="v42.0">
            <wd:Request_Criteria>
                <wd:Employee_ID>$EmployeeID</wd:Employee_ID>
            </wd:Request_Criteria>
            <wd:Response_Group>
                <wd:Include_Personal_Information>true</wd:Include_Personal_Information>
                <wd:Include_Employment_Information>true</wd:Include_Employment_Information>
            </wd:Response_Group>
        </wd:Get_Workers_Request>
    </soapenv:Body>
</soapenv:Envelope>
"@
    
    try {
        $headers = @{
            'Content-Type' = 'text/xml; charset=utf-8'
            'SOAPAction' = '""'
        }
        
        $response = Invoke-RestMethod -Uri "$TenantUrl/ccx/service/Human_Resources/v42.0" -Method Post -Headers $headers -Body $soapBody
        
        # Parse SOAP response
        $worker = $response.Envelope.Body.Get_Workers_Response.Response_Data.Worker
        
        return [PSCustomObject]@{
            WorkerID = $worker.Worker_ID
            EmployeeID = $worker.Employee_ID
            Email = $worker.Email_Address
            Status = $worker.Worker_Status
            TerminationDate = $worker.Termination_Date
            LastDayOfWork = $worker.Last_Day_of_Work
        }
        
    } catch {
        Write-Error "Failed to get worker details: $_"
        throw
    }
}

function Compare-WorkdayADTerminations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$WorkdayTerminations,
        
        [Parameter(Mandatory=$false)]
        [switch]$CheckAzureAD,
        
        [Parameter(Mandatory=$false)]
        [int]$GracePeriodDays = 1
    )
    
    $results = @()
    
    foreach ($termination in $WorkdayTerminations) {
        Write-Verbose "Checking termination status for: $($termination.Email)"
        
        $result = [PSCustomObject]@{
            EmployeeID = $termination.EmployeeID
            Name = "$($termination.FirstName) $($termination.LastName)"
            Email = $termination.Email
            TerminationDate = $termination.TerminationDate
            LastDayOfWork = $termination.LastDayOfWork
            ADAccount = $null
            ADEnabled = $null
            ADLastLogon = $null
            AzureADAccount = $null
            AzureADEnabled = $null
            ComplianceStatus = 'Unknown'
            Issues = @()
            DaysSinceTermination = (Get-Date) - $termination.LastDayOfWork
        }
        
        # Check on-premise AD
        try {
            $adUser = Get-ADUser -Filter "EmailAddress -eq '$($termination.Email)'" -Properties Enabled, LastLogonDate, AccountExpirationDate -ErrorAction SilentlyContinue
            
            if ($adUser) {
                $result.ADAccount = $adUser.SamAccountName
                $result.ADEnabled = $adUser.Enabled
                $result.ADLastLogon = $adUser.LastLogonDate
                
                # Check if account should be disabled
                $gracePeriodEnd = $termination.LastDayOfWork.AddDays($GracePeriodDays)
                
                if ((Get-Date) -gt $gracePeriodEnd -and $adUser.Enabled) {
                    $result.Issues += "AD account still enabled after grace period"
                    $result.ComplianceStatus = 'Non-Compliant'
                }
            } else {
                $result.ADAccount = "Not Found"
                $result.ComplianceStatus = 'Compliant'
            }
        } catch {
            Write-Warning "Failed to check AD for $($termination.Email): $_"
            $result.Issues += "AD check failed: $_"
        }
        
        # Check Azure AD/Entra ID
        if ($CheckAzureAD) {
            try {
                # Requires Azure AD PowerShell module or Microsoft Graph
                $azureUser = Get-AzureADUser -Filter "mail eq '$($termination.Email)'" -ErrorAction SilentlyContinue
                
                if ($azureUser) {
                    $result.AzureADAccount = $azureUser.UserPrincipalName
                    $result.AzureADEnabled = $azureUser.AccountEnabled
                    
                    $gracePeriodEnd = $termination.LastDayOfWork.AddDays($GracePeriodDays)
                    
                    if ((Get-Date) -gt $gracePeriodEnd -and $azureUser.AccountEnabled) {
                        $result.Issues += "Azure AD account still enabled after grace period"
                        $result.ComplianceStatus = 'Non-Compliant'
                    }
                } else {
                    $result.AzureADAccount = "Not Found"
                }
            } catch {
                Write-Warning "Failed to check Azure AD for $($termination.Email): $_"
                $result.Issues += "Azure AD check failed: $_"
            }
        }
        
        # Set compliance status
        if ($result.Issues.Count -eq 0 -and $result.ComplianceStatus -ne 'Non-Compliant') {
            $result.ComplianceStatus = 'Compliant'
        }
        
        $results += $result
    }
    
    return $results
}

function New-TerminationComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$ComplianceResults,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>User Termination Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        .summary { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .compliant { color: #27ae60; font-weight: bold; }
        .non-compliant { color: #e74c3c; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #3498db; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border: 1px solid #ddd; }
        tr:nth-child(even) { background: #f8f9fa; }
        .issues { color: #e74c3c; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>User Termination Compliance Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Total Terminations Checked: $($ComplianceResults.Count)</p>
        <p class="compliant">Compliant: $(($ComplianceResults | Where-Object {$_.ComplianceStatus -eq 'Compliant'}).Count)</p>
        <p class="non-compliant">Non-Compliant: $(($ComplianceResults | Where-Object {$_.ComplianceStatus -eq 'Non-Compliant'}).Count)</p>
    </div>
    
    <h2>Termination Details</h2>
    <table>
        <tr>
            <th>Employee ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Termination Date</th>
            <th>Days Since</th>
            <th>AD Status</th>
            <th>Azure AD Status</th>
            <th>Compliance</th>
            <th>Issues</th>
        </tr>
"@

    foreach ($result in $ComplianceResults) {
        $complianceClass = if ($result.ComplianceStatus -eq 'Compliant') { 'compliant' } else { 'non-compliant' }
        $adStatus = if ($result.ADEnabled -eq $true) { 'Enabled' } elseif ($result.ADEnabled -eq $false) { 'Disabled' } else { $result.ADAccount }
        $azureStatus = if ($result.AzureADEnabled -eq $true) { 'Enabled' } elseif ($result.AzureADEnabled -eq $false) { 'Disabled' } else { $result.AzureADAccount }
        
        $htmlContent += @"
        <tr>
            <td>$($result.EmployeeID)</td>
            <td>$($result.Name)</td>
            <td>$($result.Email)</td>
            <td>$($result.TerminationDate.ToString('yyyy-MM-dd'))</td>
            <td>$($result.DaysSinceTermination.Days)</td>
            <td>$adStatus</td>
            <td>$azureStatus</td>
            <td class="$complianceClass">$($result.ComplianceStatus)</td>
            <td class="issues">$($result.Issues -join '; ')</td>
        </tr>
"@
    }

    $htmlContent += @"
    </table>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Termination compliance report generated: $OutputPath" -ForegroundColor Green
}

# Export functions
Export-ModuleMember -Function Get-WorkdayTerminatedUsers, Get-WorkdayUserViaSOAP, Compare-WorkdayADTerminations, New-TerminationComplianceReport