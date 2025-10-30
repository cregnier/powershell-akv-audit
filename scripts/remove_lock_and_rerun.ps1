$p = Join-Path $env:TEMP 'akv_gap_analysis_running.lock'
if (Test-Path $p) {
    try { Remove-Item -Path $p -Force; Write-Output "Removed lock: $p" } catch { Write-Output "Failed to remove lock: $($_.Exception.Message)" }
} else {
    Write-Output "No lock to remove at: $p"
}

# Re-run the single-vault test command
Write-Output "Re-running focused SingleVault TestMode run..."
& pwsh -NoProfile -File "c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1" -SingleVault -VaultName 'cluster061025a-hcikv' -SubscriptionId 'dc8b9d9c-0cf9-446c-9177-12921182f54a' -TestMode -Limit 1 -SuppressModuleWarnings
