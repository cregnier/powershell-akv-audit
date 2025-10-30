# Simulation script to create per-worker incremental CSVs and merge them
$repo = 'C:\Source\Github\powershell-akv-audit'
$output = Join-Path $repo 'output'
if (-not (Test-Path $output)) { New-Item -ItemType Directory -Path $output -Force | Out-Null }
$dir = Join-Path $output 'incremental_temp'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$path1 = Join-Path $dir 'incremental_worker_HOST_111.csv'
'SubscriptionId,VaultName,ComplianceScore' | Out-File -FilePath $path1 -Encoding UTF8 -Force
'sub1,vaultA,90' | Out-File -FilePath $path1 -Encoding UTF8 -Append
$path2 = Join-Path $dir 'incremental_worker_HOST_222.csv'
'SubscriptionId,VaultName,ComplianceScore' | Out-File -FilePath $path2 -Encoding UTF8 -Force
'sub2,vaultB,80' | Out-File -FilePath $path2 -Encoding UTF8 -Append
$files = Get-ChildItem -Path $dir -File -Filter 'incremental_worker_*.csv' | Sort-Object Name
if (-not $files -or $files.Count -eq 0) { Write-Host 'No worker files found'; exit 0 }
$tmp = Join-Path $output 'KeyVaultGapAnalysis_incremental_test.csv.tmp'
$first = $files[0]
(Get-Content -Path $first.FullName -TotalCount 1) | Out-File -FilePath $tmp -Encoding UTF8 -Force
foreach ($f in $files) {
  $lines = Get-Content -Path $f.FullName
  if ($lines.Count -gt 1) { $lines | Select-Object -Skip 1 | Out-File -FilePath $tmp -Encoding UTF8 -Append }
}
Move-Item -Path $tmp -Destination (Join-Path $output 'KeyVaultGapAnalysis_incremental_test.csv') -Force
Write-Host '---Merged File---'
Get-Content (Join-Path $output 'KeyVaultGapAnalysis_incremental_test.csv') | ForEach-Object { Write-Host $_ }
Write-Host '---Temp Files---'
Get-ChildItem -Path $dir | ForEach-Object { Write-Host $_.FullName }
