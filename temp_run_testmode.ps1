$env:FORCE_FINAL_COERCION_MODE='inprocess'
$env:FINAL_COERCION_INPROCESS_MAX_SECONDS='120'
$env:DISABLE_PER_VAULT_JSON='1'
Remove-Item -Path (Join-Path $env:TEMP 'akv_gap_analysis_running.lock') -ErrorAction SilentlyContinue
.\Get-AKVGapAnalysis.ps1 -TestMode -Limit 1 -Verbose -SuppressAzureWarnings
