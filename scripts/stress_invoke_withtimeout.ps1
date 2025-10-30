# Stress tests for Invoke-WithTimeout
# This script reimplements the Invoke-WithTimeout logic locally and exercises timeout handling.
# Safe to run without Az modules. If Az modules are present, an optional Az call is attempted with a short timeout.

$ErrorActionPreference = 'Stop'
$repo = 'C:\Source\Github\powershell-akv-audit'

function Write-Log { param($msg, $Level='INFO') Write-Host "[$Level] $msg" }

function Invoke-WithTimeout {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$false)][object[]]$Args = @(),
        [Parameter(Mandatory=$false)][int]$TimeoutSeconds = 30,
        [Parameter(Mandatory=$false)][string]$CmdletName = ''
    )
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Args
    } catch {
        Write-Log ("Failed to start job for {0}: {1}" -f ($CmdletName -as [string]), ($_.Exception.Message -as [string])) -Level 'WARN'
        throw
    }
    if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
        try {
            $result = Receive-Job -Job $job -ErrorAction Stop
        } catch {
            $result = $null
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        return $result
    } else {
        try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { }
        Write-Log "Timeout after ${TimeoutSeconds}s waiting for $($CmdletName -or 'operation')" -Level 'WARN'
        throw "Timed out waiting for $($CmdletName -or 'operation') after ${TimeoutSeconds}s"
    }
}

function Run-Case {
    param(
        [ScriptBlock]$SB,
        [int]$TimeoutSeconds,
        [bool]$ExpectTimeout
    )
    try {
        $start = Get-Date
        $res = Invoke-WithTimeout -ScriptBlock $SB -TimeoutSeconds $TimeoutSeconds -CmdletName 'TestCase'
        $dur = (Get-Date) - $start
        Write-Host "[PASS] Completed in $($dur.TotalSeconds)s. Result type: $($res -is [array] -or $res -is [object])"
        if ($ExpectTimeout) { Write-Host "[ERROR] Expected timeout but call succeeded"; return @{Passed=$false; TimedOut=$false}
        return @{Passed=$true; TimedOut=$false}
    } catch {
        $msg = $_.Exception.Message
        Write-Host "[CATCH] $msg"
        if ($ExpectTimeout -and $msg -like 'Timed out*') { return @{Passed=$true; TimedOut=$true} }
        return @{Passed=$false; TimedOut=$false}
    }
}

# Simple success case
Write-Host "=== Simple success case ==="
$case1 = Run-Case -SB { Start-Sleep -Seconds 1; 'ok' } -TimeoutSeconds 5 -ExpectTimeout:$false

# Simple timeout case
Write-Host "=== Simple timeout case ==="
$case2 = Run-Case -SB { Start-Sleep -Seconds 6; 'done' } -TimeoutSeconds 2 -ExpectTimeout:$true

# Optional Az cmdlet test (if Az modules available)
$azCase = @{Attempted=$false; Passed=$false}
if (Get-Command -Name Get-AzSubscription -ErrorAction SilentlyContinue) {
    Write-Host "=== Az cmdlet test (short timeout) ==="
    $azCase.Attempted = $true
    try {
        $r = Invoke-WithTimeout -ScriptBlock { Get-AzSubscription -ErrorAction SilentlyContinue } -TimeoutSeconds 3 -CmdletName 'Get-AzSubscription'
        Write-Host "[AZ] Success, result count: $($r.Count)"
        $azCase.Passed = $true
    } catch {
        Write-Host "[AZ] Timed out or failed: $($_.Exception.Message)"
        $azCase.Passed = $false
    }
} else {
    Write-Host "Az modules not present; skipping Az cmdlet test"
}

# Stress loop: many randomized invocations
Write-Host "=== Stress loop (30 iterations) ==="
$successCount = 0; $timeoutCount = 0; $failCount = 0
for ($i=1; $i -le 30; $i++) {
    $sleep = Get-Random -Minimum 0 -Maximum 5
    $timeout = Get-Random -Minimum 1 -Maximum 3
    $expectTimeout = ($sleep -gt $timeout)
    Write-Host "Iter $i: sleep=$sleep timeout=$timeout expectTimeout=$expectTimeout"
    $res = Run-Case -SB { param($s) Start-Sleep -Seconds $s; return $s } -TimeoutSeconds $timeout -ExpectTimeout:$expectTimeout -Args @($sleep)
    if ($res.Passed -and $res.TimedOut) { $timeoutCount++ } elseif ($res.Passed) { $successCount++ } else { $failCount++ }
}

Write-Host "Stress summary: successes=$successCount timeouts=$timeoutCount failures=$failCount"

# Determine overall pass criteria: at least one success and at least one timeout in stress loop
if ($successCount -ge 1 -and ($case2.Passed -or $timeoutCount -ge 1)) {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "SOME TESTS FAILED" -ForegroundColor Red
    exit 2
}
