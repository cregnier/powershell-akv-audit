# CI-friendly unit test for Append-IncrementalCsvRow + Merge-IncrementalTempFiles
# This test reimplements the minimal append/merge logic used by Get-AKVGapAnalysis.ps1
# so it can run in CI without dot-sourcing the full script.

$ErrorActionPreference = 'Stop'
$repo = 'C:\Source\Github\powershell-akv-audit'
$outputDir = Join-Path $repo 'output'
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
$dir = Join-Path $outputDir 'incremental_temp'
if (Test-Path $dir) { Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$global:incrementalCsvPath = Join-Path $outputDir 'KeyVaultGapAnalysis_incremental_ci.csv'
if (Test-Path $global:incrementalCsvPath) { Remove-Item -Path $global:incrementalCsvPath -Force -ErrorAction SilentlyContinue }

$UseParallelProcessing = $true

function Get-WorkerTempIncrementalPath {
    param([string]$WorkerId)
    if (-not $WorkerId) { $WorkerId = $global:WorkerId }
    $d = Join-Path $outputDir 'incremental_temp'
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    return Join-Path $d ("incremental_worker_{0}.csv" -f $WorkerId)
}

function Append-IncrementalCsvRow {
    param([Parameter(Mandatory=$true)][PSObject]$Row, [string]$WorkerId)
    if ($UseParallelProcessing) {
        $wp = Get-WorkerTempIncrementalPath -WorkerId ($WorkerId -or $global:WorkerId)
        if (-not (Test-Path $wp)) {
            $Row | Export-Csv -Path $wp -NoTypeInformation -Encoding UTF8
        } else {
            $csv = $Row | ConvertTo-Csv -NoTypeInformation
            $csv | Select-Object -Skip 1 | Out-File -FilePath $wp -Encoding UTF8 -Append
        }
    } else {
        if (-not (Test-Path $global:incrementalCsvPath)) {
            $Row | Export-Csv -Path $global:incrementalCsvPath -NoTypeInformation -Encoding UTF8
        } else {
            $csv = $Row | ConvertTo-Csv -NoTypeInformation
            $csv | Select-Object -Skip 1 | Out-File -FilePath $global:incrementalCsvPath -Encoding UTF8 -Append
        }
    }
}

function Merge-IncrementalTempFiles {
    param()
    if (-not $global:incrementalCsvPath) { throw 'incrementalCsvPath not set' }
    $d = Join-Path $outputDir 'incremental_temp'
    if (-not (Test-Path $d)) { return }
    $files = Get-ChildItem -Path $d -File -Filter 'incremental_worker_*.csv' | Sort-Object Name
    if (-not $files -or $files.Count -eq 0) { return }
    $tmpMaster = "$($global:incrementalCsvPath).tmp"
    $first = $files[0]
    (Get-Content -Path $first.FullName -TotalCount 1) | Out-File -FilePath $tmpMaster -Encoding UTF8 -Force
    foreach ($f in $files) {
        $lines = Get-Content -Path $f.FullName
        if ($lines.Count -gt 1) {
            $lines | Select-Object -Skip 1 | Out-File -FilePath $tmpMaster -Encoding UTF8 -Append
        }
    }
    Move-Item -Path $tmpMaster -Destination $global:incrementalCsvPath -Force
}

# Create sample rows and append with different WorkerIds
$row1 = [PSCustomObject]@{ SubscriptionId='sub1'; VaultName='vaultA'; ComplianceScore=90 }
$row2 = [PSCustomObject]@{ SubscriptionId='sub2'; VaultName='vaultB'; ComplianceScore=80 }
$row3 = [PSCustomObject]@{ SubscriptionId='sub3'; VaultName='vaultC'; ComplianceScore=70 }

Append-IncrementalCsvRow -Row $row1 -WorkerId 'HOST_111'
Append-IncrementalCsvRow -Row $row2 -WorkerId 'HOST_222'
Append-IncrementalCsvRow -Row $row3 -WorkerId 'HOST_111'

# Merge temp files
Merge-IncrementalTempFiles

# Assertions
if (-not (Test-Path $global:incrementalCsvPath)) {
    Write-Host 'Merged CSV not created' -ForegroundColor Red
    exit 1
}

$lines = Get-Content -Path $global:incrementalCsvPath
# Expect header + 3 data rows
if ($lines.Count -ne 4) {
    Write-Host "Unexpected merged row count: $($lines.Count)" -ForegroundColor Red
    Write-Host 'Merged CSV content:'; $lines | ForEach-Object { Write-Host $_ }
    exit 1
}

# Basic header check
$hdr = $lines[0]
if ($hdr -notlike '*SubscriptionId*' -or $hdr -notlike '*VaultName*') {
    Write-Host "Unexpected header: $hdr" -ForegroundColor Red
    exit 1
}

Write-Host 'TEST PASSED: append+merge produced expected merged CSV' -ForegroundColor Green
exit 0
