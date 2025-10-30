$csv='C:\Users\cregnier\OneDrive - Intel Corporation\Documents\KeyVaultGapAnalysis\KeyVaultGapAnalysis_2025-10-22_10-42-10.csv'
$data=Import-Csv -Path $csv
$fields=@('ManagedIdentityResolved','DiagnosticDestinationNames','SkuName','SecretRotationMostRecent','KeyRotationMostRecent','RoleAssignmentsResolved')
foreach ($f in $fields) {
    $count = ($data | Where-Object { $_.$f -and $_.$f -ne '' }).Count
    Write-Output "$f : $count / $($data.Count)"
}
