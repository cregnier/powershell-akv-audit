# Test Lock Mechanism Scenarios
# Comprehensive validation of run-lock behavior across different execution modes

Write-Host "🔒 Testing Azure Key Vault Gap Analysis Lock Mechanism Scenarios" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

$scriptPath = ".\Get-AKVGapAnalysis.ps1"
$lockPath = "$env:TEMP\akv_gap_analysis_running.lock"

# Helper function to check if lock exists
function Test-LockExists {
    return Test-Path $lockPath
}

# Helper function to get lock content
function Get-LockContent {
    if (Test-LockExists) {
        try {
            $content = Get-Content $lockPath -Raw
            return $content | ConvertFrom-Json
        } catch {
            return $null
        }
    }
    return $null
}

# Helper function to remove lock
function Remove-Lock {
    if (Test-LockExists) {
        Remove-Item $lockPath -Force
        Write-Host "  🗑️ Removed existing lock file" -ForegroundColor Yellow
    }
}

# Helper function to create fake lock
function New-FakeLock {
    param([int]$FakePid = 99999, [string]$Owner = "testuser")
    $lockData = @{
        PID = $FakePid
        Owner = $Owner
        StartedUtc = (Get-Date).AddHours(-2).ToString('o')  # 2 hours ago (stale)
        Command = "Fake test command"
    }
    $lockData | ConvertTo-Json | Out-File $lockPath -Encoding UTF8
    Write-Host "  📝 Created fake lock file (PID: $FakePid, Owner: $Owner)" -ForegroundColor Yellow
}

# Test scenarios
$scenarios = @(
    @{
        Name = "1. Lock present, test run"
        Description = "Lock exists from previous run, trying TestMode"
        Setup = { New-FakeLock }
        Command = "& '$scriptPath' -TestMode -Limit 1"
        Expected = "Should succeed (TestMode bypasses lock)"
    },
    @{
        Name = "2. Lock present, full run"
        Description = "Lock exists, trying full analysis"
        Setup = { New-FakeLock }
        Command = "& '$scriptPath' -Limit 1"  # Without TestMode
        Expected = "Should fail (lock prevents concurrent runs)"
    },
    @{
        Name = "3. Lock present, resume"
        Description = "Lock exists, trying resume mode"
        Setup = { New-FakeLock }
        Command = "& '$scriptPath' -Resume"
        Expected = "Should succeed (Resume can remove stale locks)"
    },
    @{
        Name = "4. Lock not present, test run"
        Description = "No lock, running TestMode"
        Setup = { Remove-Lock }
        Command = "& '$scriptPath' -TestMode -Limit 1"
        Expected = "Should succeed (no lock to conflict)"
    },
    @{
        Name = "5. Lock not present, full run"
        Description = "No lock, running full analysis"
        Setup = { Remove-Lock }
        Command = "& '$scriptPath' -Limit 1"  # Without TestMode
        Expected = "Should succeed (creates new lock)"
    },
    @{
        Name = "6. Lock not present, resume"
        Description = "No lock, trying resume mode"
        Setup = { Remove-Lock }
        Command = "& '$scriptPath' -Resume"
        Expected = "Should fail (no checkpoint to resume from)"
    },
    @{
        Name = "7. Lock present, NoRunLock test run"
        Description = "Lock exists, but using -NoRunLock with TestMode"
        Setup = { New-FakeLock }
        Command = "& '$scriptPath' -TestMode -Limit 1 -NoRunLock"
        Expected = "Should succeed (-NoRunLock bypasses lock)"
    },
    @{
        Name = "8. Lock present, NoRunLock full run"
        Description = "Lock exists, but using -NoRunLock with full run"
        Setup = { New-FakeLock }
        Command = "& '$scriptPath' -Limit 1 -NoRunLock"
        Expected = "Should succeed (-NoRunLock bypasses lock)"
    }
)

Write-Host "`n📋 Test Scenarios:" -ForegroundColor White
for ($i = 0; $i -lt $scenarios.Count; $i++) {
    $scenario = $scenarios[$i]
    Write-Host "  $($i+1). $($scenario.Name)" -ForegroundColor White
    Write-Host "     $($scenario.Description)" -ForegroundColor Gray
    Write-Host "     Expected: $($scenario.Expected)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "⚠️  Note: These tests will attempt to run the actual script." -ForegroundColor Yellow
Write-Host "   They may prompt for Azure authentication and take time to complete." -ForegroundColor Yellow
Write-Host "   Press Ctrl+C to stop at any time." -ForegroundColor Yellow
Write-Host ""

$runTests = Read-Host "Do you want to run these tests? (y/N)"
if ($runTests -ne 'y' -and $runTests -ne 'Y') {
    Write-Host "Tests cancelled." -ForegroundColor Yellow
    exit
}

# Run each scenario
foreach ($scenario in $scenarios) {
    Write-Host "`n🧪 Running: $($scenario.Name)" -ForegroundColor Cyan
    Write-Host "   $($scenario.Description)" -ForegroundColor Gray

    # Setup
    Write-Host "   🔧 Setup: $($scenario.Setup.ToString())" -ForegroundColor Blue
    try {
        & $scenario.Setup
    } catch {
        Write-Host "   ❌ Setup failed: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }

    # Show lock status
    $lockExists = Test-LockExists
    $lockContent = Get-LockContent
    Write-Host "   🔒 Lock status: $(if ($lockExists) { 'Present' } else { 'Not present' })" -ForegroundColor $(if ($lockExists) { 'Yellow' } else { 'Green' })
    if ($lockContent) {
        Write-Host "      PID: $($lockContent.PID), Owner: $($lockContent.Owner), Started: $($lockContent.StartedUtc)" -ForegroundColor Gray
    }

    # Run command
    Write-Host "   ▶️  Running: $($scenario.Command)" -ForegroundColor Blue
    try {
        $startTime = Get-Date
        $result = Invoke-Expression $scenario.Command
        $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

        # Check exit code (if available)
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) {
            Write-Host "   ✅ Command completed successfully in ${duration}s" -ForegroundColor Green
        } elseif ($exitCode) {
            Write-Host "   ❌ Command failed with exit code $exitCode in ${duration}s" -ForegroundColor Red
        } else {
            Write-Host "   ⚠️  Command completed in ${duration}s (exit code unknown)" -ForegroundColor Yellow
        }

        # Check if lock was created/modified
        $newLockContent = Get-LockContent
        if ($newLockContent -and (-not $lockContent -or $newLockContent.PID -ne $lockContent.PID)) {
            Write-Host "   🆕 New lock created (PID: $($newLockContent.PID))" -ForegroundColor Cyan
        } elseif (-not $newLockContent -and $lockContent) {
            Write-Host "   🗑️ Lock was removed" -ForegroundColor Cyan
        }

    } catch {
        Write-Host "   ❌ Command failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host "   🎯 Expected: $($scenario.Expected)" -ForegroundColor Gray

    # Cleanup - remove any locks created during testing
    if (Test-LockExists) {
        $lockInfo = Get-LockContent
        if ($lockInfo -and $lockInfo.PID -eq $PID) {
            Remove-Lock
            Write-Host "   🧹 Cleaned up test lock" -ForegroundColor Gray
        }
    }

    Write-Host ""
}

Write-Host "🎉 Lock mechanism testing completed!" -ForegroundColor Green
Write-Host ""
Write-Host "📖 Lock Mechanism Documentation:" -ForegroundColor White
Write-Host "The script uses a run-lock mechanism to prevent concurrent full analysis runs:" -ForegroundColor White
Write-Host ""
Write-Host "🔒 Lock File Location: $env:TEMP\akv_gap_analysis_running.lock" -ForegroundColor White
Write-Host ""
Write-Host "📋 Lock Behavior by Scenario:" -ForegroundColor White
Write-Host "1. Lock present + TestMode: ✅ Succeeds (TestMode bypasses lock)" -ForegroundColor Green
Write-Host "2. Lock present + Full run: ❌ Fails (prevents concurrent runs)" -ForegroundColor Red
Write-Host "3. Lock present + Resume: ✅ Succeeds (Resume can remove stale locks)" -ForegroundColor Green
Write-Host "4. No lock + TestMode: ✅ Succeeds (no conflict)" -ForegroundColor Green
Write-Host "5. No lock + Full run: ✅ Succeeds (creates new lock)" -ForegroundColor Green
Write-Host "6. No lock + Resume: ❌ Fails (no checkpoint to resume)" -ForegroundColor Red
Write-Host "7. Lock present + NoRunLock: ✅ Succeeds (bypasses lock)" -ForegroundColor Green
Write-Host ""
Write-Host "🔧 Override Options:" -ForegroundColor White
Write-Host "• -NoRunLock: Completely bypasses lock creation and checking" -ForegroundColor White
Write-Host "• -Resume: Allows automatic removal of stale locks" -ForegroundColor White
Write-Host "• AKV_FORCE_BYPASS_LOCK=1: Forces bypass for testing" -ForegroundColor White
Write-Host ""
Write-Host "⏰ Lock TTL: Default 1 hour (configurable via `$global:RunLockTtlSeconds)" -ForegroundColor White