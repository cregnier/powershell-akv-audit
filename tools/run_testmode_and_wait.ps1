$lock = Join-Path $env:TEMP 'akv_gap_analysis_running.lock'
# Start the script as a detached background job so we can poll its run-lock
Start-Job -ScriptBlock { & pwsh -NoProfile -File 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1' -TestMode -Limit 1 -MaxParallelJobs 3 -SuppressAzureWarnings -Resume } | Out-Null
Write-Host "Launched background job, monitoring lock..."
$timeout = 600
$elapsed = 0
while (Test-Path $lock -and ($elapsed -lt $timeout)) {
    Write-Host ("Lock present - waiting {0}s" -f $elapsed)
    Start-Sleep -Seconds 2
    $elapsed += 2
}
if (Test-Path $lock) {
    Write-Host 'Timeout waiting for lock to be removed'
    exit 2
} else {
    Write-Host 'Lock removed — run likely finished'
    exit 0
}