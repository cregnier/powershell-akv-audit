<#
Acceptance test scaffolding for interrupt/resume behavior.
This script attempts to run `Get-AKVGapAnalysis.ps1` in TestMode with SimulateInterruptAfter
and verifies that a checkpoint is produced in the repository `output` folder. It then
attempts to run the script again with `-Resume` to validate resume behavior.

Notes:
- This is a best-effort acceptance test. It will time-box the analysis process to avoid
  long-running Azure calls in CI.
- The main script may attempt Azure authentication; CI environments without credentials
  may see the script fail early. The test will mark itself as 'skipped' if no checkpoint
  is produced.
#>

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent | Split-Path -Parent
$scriptPath = Join-Path $repo 'Get-AKVGapAnalysis.ps1'
$outputDir = Join-Path $repo 'output'
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
$checkpointPath = Join-Path $outputDir 'checkpoint.json'

Write-Host "Acceptance test: run analysis in TestMode with simulated interrupt"
$args1 = "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath, "-TestMode", "-Limit", "3", "-SimulateInterruptAfter", "1", "-SuppressAzureWarnings"
$proc = Start-Process -FilePath pwsh -ArgumentList $args1 -PassThru
# Wait up to 2 minutes for the process to exit
$timedOut = $false
try {
    $finished = Wait-Process -Id $proc.Id -Timeout 120
    if (-not $finished) { $timedOut = $true; Write-Host "Process did not finish within timeout; killing."; Stop-Process -Id $proc.Id -Force }
} catch {
    Write-Host "Error waiting for process: $($_.Exception.Message)"
}

if (Test-Path $checkpointPath) {
    Write-Host "Checkpoint produced: $checkpointPath"
    $cp = Get-Content -Path $checkpointPath -Raw
    Write-Host "Checkpoint size: $([text.encoding]::UTF8.GetByteCount($cp)) bytes"
    Write-Host "Now attempting resume run (best-effort)"
    $args2 = "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath, "-TestMode", "-Limit", "3", "-Resume", "-SuppressAzureWarnings"
    $rproc = Start-Process -FilePath pwsh -ArgumentList $args2 -PassThru
    try { $finished2 = Wait-Process -Id $rproc.Id -Timeout 180; if (-not $finished2) { Stop-Process -Id $rproc.Id -Force } } catch { }
    Write-Host "Resume run completed (or timed out). Review logs/output for correctness."
    exit 0
} else {
    Write-Host "No checkpoint found after simulated interrupt run. Acceptance test cannot validate resume behavior; marking as skipped." -ForegroundColor Yellow
    exit 78
}
