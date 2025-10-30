# Wrapper to run Get-AKVGapAnalysis TestMode with deterministic env and transcript
Remove-Item -Path "$env:TEMP\akv_html_child_*" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\akv_html_launcher_*" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\akv_gap_progress.txt" -ErrorAction SilentlyContinue

$env:FORCE_FINAL_COERCION_MODE = 'inprocess'
$env:FINAL_COERCION_INPROCESS_MAX_SECONDS = '120'
$env:DISABLE_PER_VAULT_JSON = '1'

$outDir = Join-Path -Path (Get-Location) -ChildPath 'output'
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$trans = Join-Path -Path $outDir -ChildPath ("testmode_transcript_{0}.txt" -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
Start-Transcript -Path $trans -Force
Write-Host "BEGIN_TESTMODE_TRANSCRIPT -> $trans"

try {
    & "$PSScriptRoot\..\Get-AKVGapAnalysis.ps1" -TestMode -Limit 1 -Verbose -SuppressAzureWarnings
} catch {
    Write-Host "Get-AKVGapAnalysis.ps1 failed: $($_.Exception.Message)"
}

Stop-Transcript
Write-Host "END_TESTMODE_TRANSCRIPT -> $trans"
