 # Prerequisites: Ensure you have the Az.Monitor and Az.KeyVault modules installed.
#Install-Module -Name Az.Monitor, Az.KeyVault -Force

# Define the output file path and format
$outputFile = "C:\Users\kumara\Downloads\KeyVaultDiagnosticAudit.json"
$report = @()

# --- HARD CODED SINGLE SUBSCRIPTION ---
# Replace 'YOUR_SUBSCRIPTION_ID' with the actual Subscription ID you want to target
$subscriptionId = '9a861dc4-0c58-4a46-8332-7670111d8d07'
Write-Host "Processing subscription: $subscriptionId" -ForegroundColor Green
Set-AzContext -Subscription $subscriptionId

# Get all Key Vaults in the specified subscription
$keyVaults = Get-AzKeyVault

foreach ($vault in $keyVaults) {
    Write-Host "  - Auditing Key Vault: $($vault.VaultName)" -ForegroundColor Yellow

    $diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $vault.ResourceId -ErrorAction SilentlyContinue

    $vaultReport = [PSCustomObject]@{
        SubscriptionId    = $subscriptionId
        SubscriptionName  = (Get-AzSubscription -SubscriptionId $subscriptionId).Name
        KeyVaultName      = $vault.VaultName
        ResourceId        = $vault.ResourceId
        DiagnosticsEnabled = $false
        LogAnalyticsWorkspaceId = $null
        EnabledLogCategories = @()
        RecommendedLogCategories = @("AuditEvent") # Add more categories if needed
        ComplianceStatus = "Non-Compliant"
    }

    if ($diagnosticSetting) {
        $vaultReport.DiagnosticsEnabled = $true
        $vaultReport.LogAnalyticsWorkspaceId = $diagnosticSetting.WorkspaceId
        $enabledCategories = $diagnosticSetting.Log.Category -join ','
        $vaultReport.EnabledLogCategories = $enabledCategories.Split(',')

        # Check for compliance with recommendations
        $recommendedCategories = @("AuditEvent")
        $allRecommendedFound = $true
        foreach ($recCat in $recommendedCategories) {
            if ($vaultReport.EnabledLogCategories -notcontains $recCat) {
                $allRecommendedFound = $false
                break
            }
        }

        if ($allRecommendedFound) {
            $vaultReport.ComplianceStatus = "Compliant"
        }
    }

    $report += $vaultReport
}

# Convert the PowerShell object to JSON and save it to the file
$report | ConvertTo-Json -Depth 5 | Out-File -FilePath $outputFile

Write-Host "Audit completed. Output saved to: $outputFile" -ForegroundColor Green 
