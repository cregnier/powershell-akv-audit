<# .NOTES

    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 

    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 

    FITNESS FOR A PARTICULAR PURPOSE.

    This sample is not supported under any Microsoft standard support program or service. 

    The script is provided AS IS without warranty of any kind. Microsoft further disclaims all

    implied warranties including, without limitation, any implied warranties of merchantability

    or of fitness for a particular purpose. The entire risk arising out of the use or performance

    of the sample and documentation remains with you. In no event shall Microsoft, its authors,

    or anyone else involved in the creation, production, or delivery of the script be liable for 

    any damages whatsoever (including, without limitation, damages for loss of business profits, 

    business interruption, loss of business information, or other pecuniary loss) arising out of 

    the use of or inability to use the sample or documentation, even if Microsoft has been advised 

    of the possibility of such damages, rising out of the use of or inability to use the sample script, 

    even if Microsoft has been advised of the possibility of such damages.
 The script takes care of how identities, both human and non-human, are accessing Azure Key Vaults. 
 It achieves this by auditing two primary access control methods.
 1. Access Policies (Legacy Method) and 2. Azure RBAC (Recommended Modern Method)
 By combining the analysis of both Access Policies and RBAC roles, the script provides a comprehensive view 
 of how all types of identities are configured to access the Key Vault's secrets, keys, and certificates.
 This allows you to identify where older methods are in use and where you can transition to best practices 
 like using Managed Identities with Azure RBAC.
 Prerequisites: Ensure you have the Az.KeyVault and Az.Accounts modules installed.
 Install-Module -Name Az.KeyVault, Az.Accounts -Force
 Define the output file path and format

#>
 
# Connect to your Azure account
Connect-AzAccount -Identity

$report = @()
$keyvaultaccesslist = ''
# Get all subscriptions you have access to
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Write-Host "Processing Subscription: $($sub.Name) ($($sub.SubscriptionId))" -ForegroundColor Green
    # Select the current subscription
    Set-AzContext -Subscription $($sub.name)
 # Get all Key Vaults in the current subscription
$keyVaults = Get-AzKeyVault


foreach ($vault in $keyVaults) {
    # --- AUDIT ACCESS POLICIES ---
    $accessPolicies = Get-AzKeyVault -VaultName $vault.VaultName | Select-Object -ExpandProperty AccessPolicies
    if ($accessPolicies) {
        foreach ($policy in $accessPolicies) {
            $vaultobj = New-Object PSObject
            $principalId = $policy.ObjectId
            $principalName = "Unknown/Deleted Principal"
            try {
                $principal = Get-AzADServicePrincipal -ObjectId $principalId -ErrorAction SilentlyContinue
                if (!$principal) {
                    $principal = Get-AzADUser -ObjectId $principalId -ErrorAction SilentlyContinue
                }
                if ($principal) {
                    $principalName = $principal.DisplayName
                }
            } catch {}

            $vaultobj | Add-Member -MemberType NoteProperty -Name SubscriptionId -Value $($sub.SubscriptionId)
            $vaultobj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value $($sub.name)
            $vaultobj | Add-Member -MemberType NoteProperty -Name KeyVaultName -Value $vault.VaultName
            $vaultobj | Add-Member -MemberType NoteProperty -Name Location -Value $vault.Location
            $vaultobj | Add-Member -MemberType NoteProperty -Name PrincipalName -Value $($policy.DisplayName)
            $vaultobj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $principalId
            $vaultobj | Add-Member -MemberType NoteProperty -Name PermissionsToKeys -Value ($policy.PermissionsToKeys -join ", ")
            $vaultobj | Add-Member -MemberType NoteProperty -Name PermissionsToSecrets -Value ($policy.PermissionsToSecrets -join ", ")
            $vaultobj | Add-Member -MemberType NoteProperty -Name PermissionsToCertificates -Value ($policy.PermissionsToCertificates -join ", ")

            [array]$report += $vaultobj
        }
    }

    # --- AUDIT AZURE RBAC ROLES ---
    $roleAssignments = Get-AzRoleAssignment -Scope $vault.ResourceId

        foreach ($role in $roleAssignments) {
            $vaultobj = New-Object PSObject

            $vaultobj | Add-Member -MemberType NoteProperty -Name SubscriptionId -Value $($sub.SubscriptionId)
            $vaultobj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value $($sub.name)
            $vaultobj | Add-Member -MemberType NoteProperty -Name KeyVaultName -Value $vault.VaultName
            $vaultobj | Add-Member -MemberType NoteProperty -Name Location -Value $vault.Location
            $vaultobj | Add-Member -MemberType NoteProperty -Name RolePrincipalName -Value $($role.Displayname)
            $vaultobj | Add-Member -MemberType NoteProperty -Name RolesigninName -Value $($role.signinname)
            $vaultobj | Add-Member -MemberType NoteProperty -Name RBACROLESprincipal -Value $role.PrincipalName
            $vaultobj | Add-Member -MemberType NoteProperty -Name RBACROLESRoleDefinition -Value $role.RoleDefinitionName

            [array]$report += $vaultobj
        }
    
 }
}
# Output the report
$report  

######################################################################################################################
 
$CSS = @"
<style>
th {
    font: bold 11px "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    color: #FFFFFF;
    background: #5F9EA0;
    padding: 6px;
}
td {
    font: 11px "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    color: #0000FF;
    background: #fff;
    padding: 6px;
}
</style>
"@

$keyvaultaccessreport =  $report  | select SubscriptionId,`
SubscriptionName,`
KeyVaultName,`
Location,`
PrincipalName,`
PrincipalId,`
PermissionsToKeys,`
PermissionsToSecrets,`
PermissionsToCertificates,`
RBACROLESprincipal,`
RolesigninName,`
RBACROLESPrincipalId,`
RBACROLESRoleDefinition `
| ConvertTo-Html -Head $CSS -Title "kEYVAULT access AUDIT"


$keyvaultaccessreport | Out-File "C:\temp\keyvaultaccessreport.html"
Invoke-Item "C:\temp\keyvaultaccessreport.html"

 
 $report |  select SubscriptionId,`
SubscriptionName,`
KeyVaultName,`
Location,`
PrincipalName,`
PrincipalId,`
PermissionsToKeys,`
PermissionsToSecrets,`
PermissionsToCertificates,`
RBACROLESprincipal,`
RolesigninName,`
RBACROLESPrincipalId,`
RBACROLESRoleDefinition  | export-csv   c:\temp\keyvaultaccessreport.csv -NoTypeInformation



















