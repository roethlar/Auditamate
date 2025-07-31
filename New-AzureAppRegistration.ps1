<#
.SYNOPSIS
    Automatically creates and configures an Azure App Registration for AD Audit Tool.

.DESCRIPTION
    Creates an Azure AD application with all required permissions for auditing Entra ID roles,
    Conditional Access policies, PIM assignments, and audit logs. Requires Global Administrator
    or Application Administrator role.

.PARAMETER AppName
    Name for the application registration. Default: "AD Audit Tool"

.PARAMETER CertificateAuth
    Use certificate authentication instead of client secret.

.PARAMETER ValidYears
    Number of years for credential validity. Default: 1

.PARAMETER SkipAdminConsent
    Skip granting admin consent (will need to be done manually).

.EXAMPLE
    .\New-AzureAppRegistration.ps1
    Creates app with client secret authentication.

.EXAMPLE
    .\New-AzureAppRegistration.ps1 -AppName "SOX Audit Tool" -CertificateAuth -ValidYears 2
    Creates app with certificate authentication valid for 2 years.

.NOTES
    Requires: Az PowerShell module
    Run: Install-Module -Name Az -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$AppName = "AD Audit Tool",
    
    [Parameter(Mandatory=$false)]
    [switch]$CertificateAuth,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,3)]
    [int]$ValidYears = 1,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAdminConsent
)

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  Azure App Registration Setup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check for Az module
if (!(Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Host "`nAz PowerShell module not found." -ForegroundColor Yellow
    $install = Read-Host "Install Az module now? (Y/N)"
    if ($install -eq 'Y') {
        Write-Host "Installing Az module..." -ForegroundColor Yellow
        Install-Module -Name Az -Force -AllowClobber
    } else {
        Write-Host "Az module is required. Exiting." -ForegroundColor Red
        exit 1
    }
}

try {
    # Connect to Azure
    Write-Host "`nConnecting to Azure AD..." -ForegroundColor Yellow
    $context = Get-AzContext
    if (!$context) {
        Connect-AzAccount
    } else {
        Write-Host "Already connected to tenant: $($context.Tenant.Id)" -ForegroundColor Green
    }
    
    # Import required modules
    Import-Module Az.Resources
    
    # Get current tenant info
    $tenant = Get-AzTenant
    Write-Host "Working in tenant: $($tenant.Name) ($($tenant.Id))" -ForegroundColor Cyan
    
    # Check if app already exists
    $existingApp = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue
    if ($existingApp) {
        Write-Host "`nApp '$AppName' already exists." -ForegroundColor Yellow
        $update = Read-Host "Update existing app? (Y/N)"
        if ($update -ne 'Y') {
            Write-Host "Exiting without changes." -ForegroundColor Yellow
            exit 0
        }
        $app = $existingApp
    } else {
        # Create new app
        Write-Host "`nCreating app registration: $AppName" -ForegroundColor Yellow
        $app = New-AzADApplication -DisplayName $AppName -IdentifierUris "api://$(New-Guid)"
        Write-Host "App created with ID: $($app.AppId)" -ForegroundColor Green
    }
    
    # Create service principal if needed
    $sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue
    if (!$sp) {
        Write-Host "Creating service principal..." -ForegroundColor Yellow
        $sp = New-AzADServicePrincipal -ApplicationId $app.AppId
    }
    
    # Define required permissions
    $requiredPermissions = @{
        # Microsoft Graph
        "00000003-0000-0000-c000-000000000000" = @{
            Name = "Microsoft Graph"
            Permissions = @(
                @{Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role"; Name = "User.Read.All"},
                @{Id = "62a82d76-70ea-41e2-9197-370581804d09"; Type = "Role"; Name = "Group.Read.All"},
                @{Id = "5b567255-7703-4780-807c-7be8301ae99b"; Type = "Role"; Name = "Directory.Read.All"},
                @{Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Type = "Role"; Name = "Application.Read.All"},
                @{Id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"; Type = "Role"; Name = "RoleManagement.Read.All"},
                @{Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Type = "Role"; Name = "AuditLog.Read.All"},
                @{Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Type = "Role"; Name = "Policy.Read.All"},
                @{Id = "4cdc2547-9148-4295-8d11-be0db1391d6b"; Type = "Role"; Name = "PrivilegedAccess.Read.AzureAD"},
                @{Id = "be74164b-cff1-491c-8741-e671cb536e13"; Type = "Role"; Name = "Reports.Read.All"},
                @{Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef"; Type = "Role"; Name = "Reports.Read.All"}
            )
        }
        # Office 365 Exchange Online
        "00000002-0000-0ff1-ce00-000000000000" = @{
            Name = "Office 365 Exchange Online"
            Permissions = @(
                @{Id = "dc50a0fb-09a3-484d-be87-e023b12c6440"; Type = "Role"; Name = "Exchange.ManageAsApp"}
            )
        }
    }
    
    Write-Host "`nConfiguring API permissions..." -ForegroundColor Yellow
    
    $appPermissions = @()
    
    foreach ($resourceId in $requiredPermissions.Keys) {
        $resource = $requiredPermissions[$resourceId]
        Write-Host "  Adding permissions for: $($resource.Name)" -ForegroundColor Gray
        
        foreach ($permission in $resource.Permissions) {
            $appPermissions += [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphRequiredResourceAccess]@{
                ResourceAppId = $resourceId
                ResourceAccess = @(
                    [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphResourceAccess]@{
                        Id = $permission.Id
                        Type = $permission.Type
                    }
                )
            }
            Write-Host "    - $($permission.Name)" -ForegroundColor DarkGray
        }
    }
    
    # Update app with permissions
    Update-AzADApplication -ApplicationId $app.AppId -RequiredResourceAccess $appPermissions
    Write-Host "Permissions configured successfully!" -ForegroundColor Green
    
    # Create credentials
    if ($CertificateAuth) {
        Write-Host "`nCreating self-signed certificate..." -ForegroundColor Yellow
        $certName = "$AppName Certificate"
        $cert = New-SelfSignedCertificate `
            -Subject "CN=$certName" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyExportPolicy Exportable `
            -KeySpec Signature `
            -KeyLength 2048 `
            -KeyAlgorithm RSA `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears($ValidYears)
        
        $keyCredential = @{
            Type = "AsymmetricX509Cert"
            Usage = "Verify"
            Value = [System.Convert]::ToBase64String($cert.RawData)
        }
        
        New-AzADAppCredential -ApplicationId $app.AppId -CertValue $keyCredential.Value -EndDate $cert.NotAfter
        
        Write-Host "Certificate created with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
        
        # Export certificate
        $pfxPath = ".\$AppName.pfx"
        $password = Read-Host "Enter password for PFX export" -AsSecureString
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password
        Write-Host "Certificate exported to: $pfxPath" -ForegroundColor Green
        
        $authInfo = @{
            AuthType = "Certificate"
            Thumbprint = $cert.Thumbprint
            PfxPath = $pfxPath
        }
    } else {
        Write-Host "`nCreating client secret..." -ForegroundColor Yellow
        $secretName = "$AppName Secret $(Get-Date -Format 'yyyy-MM-dd')"
        $endDate = (Get-Date).AddYears($ValidYears)
        
        $secret = New-AzADAppCredential -ApplicationId $app.AppId -DisplayName $secretName -EndDate $endDate
        
        Write-Host "Client secret created successfully!" -ForegroundColor Green
        Write-Host "`nIMPORTANT: Save this secret value, it won't be shown again:" -ForegroundColor Yellow
        Write-Host $secret.SecretText -ForegroundColor Red
        
        $authInfo = @{
            AuthType = "ClientSecret"
            SecretValue = $secret.SecretText
            SecretId = $secret.KeyId
            ExpiresOn = $endDate
        }
    }
    
    # Grant admin consent if requested
    if (!$SkipAdminConsent) {
        Write-Host "`nGranting admin consent..." -ForegroundColor Yellow
        Write-Host "This will open a browser window. Please sign in as Global Administrator." -ForegroundColor Cyan
        Start-Sleep -Seconds 2
        
        $consentUrl = "https://login.microsoftonline.com/$($tenant.Id)/adminconsent?client_id=$($app.AppId)"
        Start-Process $consentUrl
        
        Write-Host "`nAfter granting consent in the browser, press Enter to continue..." -ForegroundColor Yellow
        Read-Host
    }
    
    # Add to Exchange RBAC if requested
    Write-Host "`nDo you want to add this app to Exchange Online management roles? (Y/N)" -ForegroundColor Yellow
    $addExchange = Read-Host
    if ($addExchange -eq 'Y') {
        Write-Host @"

To complete Exchange Online setup, run these commands in Exchange Online PowerShell:

# Connect to Exchange Online
Connect-ExchangeOnline

# Create service principal
New-ServicePrincipal -AppId $($app.AppId) -ServiceId $($app.AppId) -DisplayName "$AppName"

# Add to Organization Management role
Add-RoleGroupMember -Identity "Organization Management" -Member "$AppName"

# Or for read-only access:
Add-RoleGroupMember -Identity "View-Only Organization Management" -Member "$AppName"

"@ -ForegroundColor Cyan
    }
    
    # Save configuration
    $configPath = ".\privileged-access-config.json"
    if (Test-Path $configPath) {
        Write-Host "`nUpdating configuration file..." -ForegroundColor Yellow
        $config = Get-Content $configPath | ConvertFrom-Json
        $config.TenantId = $tenant.Id
        $config.ClientId = $app.AppId
        $config | ConvertTo-Json -Depth 10 | Out-File $configPath
        Write-Host "Configuration updated: $configPath" -ForegroundColor Green
    }
    
    # Create summary file
    $summaryPath = ".\AppRegistration_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $summary = @{
        AppName = $AppName
        AppId = $app.AppId
        TenantId = $tenant.Id
        TenantName = $tenant.Name
        CreatedOn = Get-Date
        Authentication = $authInfo
        Permissions = $requiredPermissions
        ConfigurationFile = $configPath
    }
    
    $summary | ConvertTo-Json -Depth 10 | Out-File $summaryPath
    
    # Display summary
    Write-Host "`n==========================================" -ForegroundColor Green
    Write-Host "  App Registration Complete!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "`nApp Name: $AppName" -ForegroundColor White
    Write-Host "App ID: $($app.AppId)" -ForegroundColor White
    Write-Host "Tenant ID: $($tenant.Id)" -ForegroundColor White
    
    if ($CertificateAuth) {
        Write-Host "`nAuthentication: Certificate" -ForegroundColor White
        Write-Host "Thumbprint: $($authInfo.Thumbprint)" -ForegroundColor White
        Write-Host "PFX File: $($authInfo.PfxPath)" -ForegroundColor White
    } else {
        Write-Host "`nAuthentication: Client Secret" -ForegroundColor White
        Write-Host "Secret: $($authInfo.SecretValue)" -ForegroundColor Red
        Write-Host "Expires: $($authInfo.ExpiresOn)" -ForegroundColor White
    }
    
    Write-Host "`nSummary saved to: $summaryPath" -ForegroundColor Cyan
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "1. Test connection with Test-GraphConnection.ps1" -ForegroundColor White
    Write-Host "2. Run privileged access audit" -ForegroundColor White
    Write-Host "3. Configure Exchange Online permissions if needed" -ForegroundColor White
    
} catch {
    Write-Host "`nError creating app registration: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
} finally {
    # Disconnect if we connected
    if (!$context) {
        Disconnect-AzAccount -ErrorAction SilentlyContinue
    }
}