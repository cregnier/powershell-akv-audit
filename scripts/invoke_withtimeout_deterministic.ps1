# Deterministic tests for Invoke-WithTimeout
$ErrorActionPreference = 'Stop'

function Invoke-WithTimeoutLocal {
    param(
        [ScriptBlock]$ScriptBlock,
        [object[]]$Args = @(),
        [int]$TimeoutSeconds = 30,
        [string]$CmdletName = ''
    )
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Args
    $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds
    if ($finished) {
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue
        return @{TimedOut=$false; Result=$result}
    } else {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue
        return @{TimedOut=$true; Result=$null}
    }
}

$passes = 0; $fails = 0
$iterations = 6
for ($i=1; $i -le $iterations; $i++) {
    # case success
    $r1 = Invoke-WithTimeoutLocal -ScriptBlock { Start-Sleep -Seconds 1; return 'ok' } -TimeoutSeconds 2
    if ($r1.TimedOut -eq $false) { Write-Host "Iter $i case success: PASS"; $passes++ } else { Write-Host "Iter $i case success: FAIL"; $fails++ }

    # case timeout
    $r2 = Invoke-WithTimeoutLocal -ScriptBlock { Start-Sleep -Seconds 4; return 'late' } -TimeoutSeconds 1
    if ($r2.TimedOut -eq $true) { Write-Host "Iter $i case timeout: PASS"; $passes++ } else { Write-Host "Iter $i case timeout: FAIL"; $fails++ }
}

# Optional Az cmdlet -- short timeout
$azAttempted = $false; $azPassed = $false
if (Get-Command -Name Get-AzSubscription -ErrorAction SilentlyContinue) {
    $azAttempted = $true
    Write-Host 'Testing Get-AzSubscription with 3s timeout'
    try {
        $r = Invoke-WithTimeoutLocal -ScriptBlock { Get-AzSubscription -ErrorAction SilentlyContinue } -TimeoutSeconds 3
        if ($r.TimedOut) { Write-Host 'Get-AzSubscription timed out' } else { Write-Host "Get-AzSubscription returned $($r.Result.Count) items"; $azPassed = $true }
    } catch {
        Write-Host "Get-AzSubscription test failed: $($_.Exception.Message)"
    }
} else { Write-Host 'Az not available; skipping Az test' }

Write-Host "Summary: passes=$passes fails=$fails AzAttempted=$azAttempted AzPassed=$azPassed"
if ($fails -eq 0) { Write-Host 'ALL DETERMINISTIC TESTS PASSED' -ForegroundColor Green; exit 0 } else { Write-Host 'DETERMINISTIC TESTS FAILED' -ForegroundColor Red; exit 2 }
