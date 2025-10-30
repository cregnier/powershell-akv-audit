$csv='C:\Users\cregnier\OneDrive - Intel Corporation\Documents\KeyVaultGapAnalysis\KeyVaultGapAnalysis_2025-10-21_17-19-47.csv'
$d = Import-Csv -Path $csv
$path = $d[0].JsonFilePath
Write-Host "Per-vault JSON path: $path"
if (-not (Test-Path $path)) { Write-Host "Per-vault JSON not found: $path"; exit 1 }
$j = Get-Content -Path $path -Raw | ConvertFrom-Json
$o = [PSCustomObject]@{
    VaultName = $j.VaultName
    SubscriptionName = $j.SubscriptionName
    VaultScore = $j.VaultScore
    RoleAssignmentsResolved = $j.RoleAssignmentsResolved
    ManagedIdentityResolved = $j.ManagedIdentityResolved
    DiagnosticDestinationNames = $j.DiagnosticDestinationNames
    SkuName = $j.SkuName
    SecretRotationMostRecent = $j.SecretRotationMostRecent
    KeyRotationMostRecent = $j.KeyRotationMostRecent
}
$o | Format-List
