# Script to help set up Microsoft Graph App Registration for auditing

Write-Host @"

===============================================
Microsoft Graph App Registration Setup Guide
===============================================

This script will guide you through setting up an App Registration in Entra ID
for the Privileged Access Audit Tool.

Required Permissions:
- Directory.Read.All
- RoleManagement.Read.All
- AuditLog.Read.All
- Policy.Read.All (for Conditional Access)
- PrivilegedAccess.Read.AzureAD (for PIM)
- User.Read.All

Steps to complete in Azure Portal:

1. Navigate to Azure Portal > Azure Active Directory > App Registrations
2. Click "New Registration"
3. Name: "Privileged Access Audit Tool"
4. Supported account types: "Single tenant"
5. Click "Register"

6. Note down:
   - Application (client) ID
   - Directory (tenant) ID

7. Go to "Certificates & secrets"
8. Click "New client secret"
9. Description: "Audit Tool Secret"
10. Expiry: Choose appropriate duration
11. Click "Add" and copy the secret value immediately

12. Go to "API permissions"
13. Click "Add a permission"
14. Select "Microsoft Graph"
15. Select "Application permissions"
16. Add these permissions:
    - Directory.Read.All
    - RoleManagement.Read.All
    - AuditLog.Read.All
    - Policy.Read.All
    - PrivilegedAccess.Read.AzureAD
    - User.Read.All
    - Exchange.ManageAsApp (for Exchange Online)

17. Click "Grant admin consent for [tenant]"

For Exchange Online access:
18. Go to "API permissions" > "Add a permission"
19. Select "Office 365 Exchange Online"
20. Select "Application permissions"
21. Add: Exchange.ManageAsApp
22. Grant admin consent

Post-setup PowerShell commands:
"@ -ForegroundColor Cyan

Write-Host "`nWould you like to test the connection after setup? (Y/N)" -ForegroundColor Yellow
$test = Read-Host

if ($test -eq 'Y') {
    $tenantId = Read-Host "Enter Tenant ID"
    $clientId = Read-Host "Enter Client ID"
    $clientSecret = Read-Host "Enter Client Secret" -AsSecureString
    
    Write-Host "`nTesting connection..." -ForegroundColor Yellow
    
    try {
        . "$PSScriptRoot\MSGraph-Authentication.ps1"
        
        $connected = Connect-MSGraphWithSecret -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
        
        if ($connected) {
            Write-Host "Successfully connected to Microsoft Graph!" -ForegroundColor Green
            
            # Test a simple query
            Write-Host "Testing API access..." -ForegroundColor Yellow
            $testResult = Invoke-MSGraphRequest -Uri "organization" -ErrorAction Stop
            Write-Host "Organization: $($testResult.displayName)" -ForegroundColor Green
            
            # Save to config
            Write-Host "`nSave these settings to config file? (Y/N)" -ForegroundColor Yellow
            $save = Read-Host
            
            if ($save -eq 'Y') {
                $configPath = "$PSScriptRoot\privileged-access-config.json"
                $config = Get-Content $configPath | ConvertFrom-Json
                $config.TenantId = $tenantId
                $config.ClientId = $clientId
                $config | ConvertTo-Json -Depth 10 | Out-File $configPath
                Write-Host "Configuration saved to: $configPath" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "Connection failed: $_" -ForegroundColor Red
        Write-Host "`nPlease verify:" -ForegroundColor Yellow
        Write-Host "1. App registration is correctly configured" -ForegroundColor White
        Write-Host "2. Admin consent has been granted" -ForegroundColor White
        Write-Host "3. Client secret is correct" -ForegroundColor White
    }
}

Write-Host "`nFor Exchange Online RBAC access, you also need to run:" -ForegroundColor Yellow
Write-Host @"
# Connect to Exchange Online PowerShell first
Connect-ExchangeOnline

# Add the app to Exchange Administrator role
New-ServicePrincipal -AppId $clientId -ServiceId $clientId -DisplayName "Privileged Access Audit Tool"

# Grant Exchange.ManageAsApp permission
Add-RoleGroupMember -Identity "Organization Management" -Member "Privileged Access Audit Tool"
"@ -ForegroundColor White