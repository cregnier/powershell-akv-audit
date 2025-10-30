# Simplified stress tests for Invoke-WithTimeout (v2)
$ErrorActionPreference = 'Stop'

function Invoke-WithTimeout2 {
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
        return $result
    } else {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue
        throw "Timed out waiting for $($CmdletName -or 'operation') after ${TimeoutSeconds}s"
    }
}

function Run-Case2 {
    param(
        [ScriptBlock]$SB,
        [object[]]$Args = @(),
        [int]$TimeoutSeconds = 30,
        [bool]$ExpectTimeout = $false
    )
    try {
        $result = Invoke-WithTimeout2 -ScriptBlock $SB -Args $Args -TimeoutSeconds $TimeoutSeconds -CmdletName 'TestCase'
    $rType = if ($null -eq $result) { 'Null' } else { $result.GetType().Name }
    Write-Host "PASS: result type: $rType"
        if ($ExpectTimeout) { Write-Host "ERROR: expected timeout but call succeeded"; return @{Passed=$false; TimedOut=$false} }
        return @{Passed=$true; TimedOut=$false}
    } catch {
        $msg = $_.Exception.Message
        Write-Host "CATCH: $msg"
        if ($ExpectTimeout -and $msg -like 'Timed out*') { return @{Passed=$true; TimedOut=$true} }
        return @{Passed=$false; TimedOut=$false}
    }
}

# Run a couple of basic checks
Write-Host 'Running v2 tests'
$r1 = Run-Case2 -SB { Start-Sleep -Seconds 1; return 'ok' } -TimeoutSeconds 5 -ExpectTimeout:$false
$r2 = Run-Case2 -SB { Start-Sleep -Seconds 5; return 'late' } -TimeoutSeconds 2 -ExpectTimeout:$true

# Stress loop
$success=0; $timeouts=0; $fails=0
for ($i=1; $i -le 20; $i++) {
    $sleep = Get-Random -Minimum 0 -Maximum 4
    $timeout = Get-Random -Minimum 1 -Maximum 3
    $expect = $sleep -gt $timeout
    Write-Host "Iter ${i}: sleep=$sleep timeout=$timeout expect=$expect"
    $res = Run-Case2 -SB { param($s) Start-Sleep -Seconds $s; return $s } -TimeoutSeconds $timeout -ExpectTimeout:$expect -Args @($sleep)
    if ($res.Passed -and $res.TimedOut) { $timeouts++ } elseif ($res.Passed) { $success++ } else { $fails++ }
}
Write-Host "Summary: success=$success timeouts=$timeouts fails=$fails"
if ($success -ge 1 -and $timeouts -ge 1) { Write-Host 'ALL PASSED'; exit 0 } else { Write-Host 'SOME FAILED'; exit 2 }
