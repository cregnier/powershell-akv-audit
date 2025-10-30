<#
.NOTES

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
    
Description: his script automates the discovery and extraction of Azure Key Vault metadata across all 
        subscriptions accessible to the current identity. It flattens nested properties, including access policies
         and permissions, into a structured format suitable for reporting or auditing. The final output is a comprehensive 
         HTML report saved locally.

        ⚙️ Process Overview
        Modules & Identity Setup

        Imports Az and Az.ResourceGraph modules.
        Connects to Azure using a managed identity.
        Subscription Enumeration

        Retrieves all accessible subscriptions using Get-AzSubscription.
        Iterates through each subscription, setting context with Set-AzContext.
        Key Vault Discovery

        Executes a Resource Graph query to find all resources of type microsoft.keyvault/vaults.
        Property Extraction

        For each Key Vault:
        Creates a new PSObject.
        Uses Get-Member to extract all top-level NoteProperty fields.
        Flattens nested hashtables like properties and tags.
        Separately flattens properties fields using Get-Member.
        Access Policies Flattening

        Iterates through accessPolicies array.
        Extracts and flattens permissions for each policy (e.g., secrets, keys, certificates, storage).
        Adds each permission set to the object with indexed property names like accessPolicy0.secrets.
        Data Aggregation

        Appends each processed Key Vault object to an array $keyvaultprops.
        HTML Report Generation

        Converts the $keyvaultprops array to HTML using ConvertTo-Html.
        Saves the formatted output to C:\temp\keyvaultprops.html. 

#>
import-module -name az  -Force
import-module  Az.ResourceGraph -force



# Connect using managed identity
$context = Connect-AzAccount -Identity # -tenant   -Subscription    


# Define variables

 $keyvaultprops = ''

 ##################

  
 $subscriptions = get-azsubscription 

foreach($subscription in $subscriptions)
{
 
   #######  Add my current ip address to the network firewallrule if not there 

# Get your current public IP address
$myIp = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip
 

Write-Host "Tenant/sub : $($subscription.Name) - $($subscription.TenantId)" -ForegroundColor Green

# Connect to Microsoft Graph with admin privileges
 
Set-AzContext -Subscription $($subscription.Name) -Tenant $($subscription.TenantId)


#$keyvaults = get-azkeyvault -subscriptionid $($subscription.id)
 
$keyvaults = Search-AzGraph -Query 'Resources | where type == "microsoft.keyvault/vaults"'

# Initialize the array to hold all processed key vault objects


    foreach ($keyvault in $keyvaults) {

        # Create a new PSObject for each key vault
        $keyvaultobj = New-Object PSObject

        $propsgm = $($keyvault) | gm | where membertype -EQ noteproperty
     

        # Add top-level properties
        foreach ($key in  $($propsgm.name)) {
            $value = $($keyvault.$key)

            # Flatten nested hashtables (like properties and tags)
            if ($value -is [hashtable]) {
                foreach ($subKey in $($value.Keys) ) {
                    $subValue = $value[$subKey]
                    $keyvaultobj | Add-Member -MemberType NoteProperty -Name "$($key.$subKey)" -Value $($subValue)
                }
            } else {
                $keyvaultobj | Add-Member -MemberType NoteProperty -Name $($key) -Value $($value)
            }

        }
        ######## properties flattened out 
        $keyprops = $($keyvault.properties) | gm | where membertype -EQ noteproperty
     
        foreach($keyprop in $($keyprops)  | where-object {$_.membertype -eq 'noteproperty'})
        {

         $propkey = "$($keyprop.name)"
         $keypropvalue = $($keyvault.properties.$propkey)   

              if (-not ($keyvaultobj.PSObject.Properties.Name -contains $propkey))
                {             
                    $keyvaultobj | Add-Member -MemberType NoteProperty -Name $propkey -Value  $keypropvalue             
                 }
        }

  


        # Add the processed object to the array
        [array]$keyvaultprops += $keyvaultobj
     
 }

 }

$keyvaultprops



# Generate HTML Report
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

$report = $keyvaultprops | select extendedLocation,`
id,`
identity,`
kind,`
location,`
managedBy,`
name,`
plan,`
properties,`
resourceGroup,`
ResourceId,`
sku,`
subscriptionId,`
tags,`
tenantId,`
type,`
zones,`
enabledForDeployment,`
enabledForDiskEncryption,`
enabledForTemplateDeployment,`
enableSoftDelete,`
provisioningState,`
publicNetworkAccess,`
softDeleteRetentionInDays `
| ConvertTo-Html -Head $CSS -Title "kEYVAULT PROPERTIES AUDIT"


$report | Out-File "C:\temp\keyvaultprops.html"
Invoke-Item "C:\temp\keyvaultprops.html"

 
 $keyvaultprops | select extendedLocation,`
id,`
identity,`
kind,`
location,`
managedBy,`
name,`
plan,`
properties,`
resourceGroup,`
ResourceId,`
sku,`
subscriptionId,`
tags,`
tenantId,`
type,`
zones,`
enabledForDeployment,`
enabledForDiskEncryption,`
enabledForTemplateDeployment,`
enableSoftDelete,`
provisioningState,`
publicNetworkAccess,`
softDeleteRetentionInDays | export-csv   c:\temp\keyvaultprops.csv -NoTypeInformation










