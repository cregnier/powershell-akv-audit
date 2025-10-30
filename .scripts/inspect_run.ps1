$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$outputDir = Join-Path $repoRoot 'output'

Write-Host '--- OUTPUT FILES ---'
if (Test-Path $outputDir) {
    Get-ChildItem -Path $outputDir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object Name,LastWriteTime,Length | Format-Table -AutoSize
} else {
    Write-Host "No output folder at $outputDir"
}

Write-Host "`n--- LATEST LOG TAIL ---"
$paths = @()
if (Test-Path $outputDir) { $paths += Get-ChildItem -Path $outputDir -Filter '*.log' -File -ErrorAction SilentlyContinue }
$docOut = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'KeyVaultGapAnalysis'
if (Test-Path $docOut) { $paths += Get-ChildItem -Path $docOut -Filter '*.log' -File -ErrorAction SilentlyContinue }
if ($paths.Count -eq 0) { Write-Host 'No logs found in output or My Documents KeyVaultGapAnalysis' } else {
    $latest = $paths | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host 'LATEST LOG:' $latest.FullName
    Write-Host '--- TAIL (last 200 lines) ---'
    Get-Content -Path $latest.FullName -Tail 200 | ForEach-Object { Write-Host $_ }
}

Write-Host "`n--- CHECKPOINT ---"
$cp = Join-Path $repoRoot 'checkpoint.json'
if (Test-Path $cp) { Write-Host 'FOUND checkpoint at' $cp; Get-Content $cp -Raw | Write-Host } else { Write-Host 'No checkpoint found at' $cp }

Write-Host "`n--- pwsh processes ---"
Get-Process -Name pwsh -ErrorAction SilentlyContinue | Select-Object Id,StartTime,CPU,MainWindowTitle | Format-Table -AutoSize
