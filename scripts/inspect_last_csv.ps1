# Find the most recent KeyVaultGapAnalysis CSV in the user's Documents folder
$defaultDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'KeyVaultGapAnalysis'
if (-not (Test-Path $defaultDir)) { Write-Host "KeyVaultGapAnalysis output directory not found: $defaultDir"; exit 1 }
$csv = Get-ChildItem -Path $defaultDir -Filter 'KeyVaultGapAnalysis_*.csv' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $csv) { Write-Host "No KeyVaultGapAnalysis CSV files found in: $defaultDir"; exit 1 }
$csvPath = $csv.FullName
$data = Import-Csv -Path $csvPath
Write-Host "Inspecting CSV: $csvPath`n"
Write-Host "Columns:`n"
($data[0].psobject.properties | ForEach-Object { $_.Name }) -join ', ' | Write-Host
Write-Host "`nFirst row (trimmed):"
$data[0] | Select-Object -Property VaultName, SubscriptionName, SubscriptionId, ComplianceScore, VaultScore, RoleAssignmentsResolved, ManagedIdentityResolved, DiagnosticDestinationNames, SkuName, SecretRotationMostRecent, KeyRotationMostRecent, JsonFilePath | Format-List

Write-Host "`nJsonFilePath:`n$data[0].JsonFilePath"
