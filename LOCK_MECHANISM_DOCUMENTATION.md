# Azure Key Vault Gap Analysis - Lock Mechanism Documentation

## Overview

The Azure Key Vault Gap Analysis script implements a comprehensive run-lock mechanism to prevent concurrent full analysis runs while allowing safe parallel operation and test modes.

## Lock File Details

- **Location**: `$env:TEMP\akv_gap_analysis_running.lock`
- **Format**: JSON file containing metadata about the running analysis
- **TTL**: Default 1 hour (configurable via `$global:RunLockTtlSeconds`)

### Lock File Structure

```json
{
  "PID": 12345,
  "Owner": "username",
  "StartedUtc": "2025-10-28T17:04:29Z",
  "Command": "Get-AKVGapAnalysis.ps1 -TestMode -Limit 1"
}
```

## Lock Behavior by Scenario

### 1. Lock Present + TestMode Run

- **Behavior**: ✅ **Succeeds** - TestMode bypasses lock restrictions
- **Reasoning**: Test runs are safe to execute concurrently as they process limited data
- **Use Case**: Validation, development, and limited-scope testing

### 2. Lock Present + Full Analysis Run

- **Behavior**: ❌ **Fails** - Lock prevents concurrent full runs
- **Reasoning**: Full organizational scans can take hours and consume significant Azure API quotas
- **Use Case**: Prevents accidental concurrent resource-intensive operations

### 3. Lock Present + Resume Mode

- **Behavior**: ✅ **Succeeds** - Resume can remove stale locks and continue interrupted analysis
- **Reasoning**: Resume mode is designed to handle interrupted runs and can safely clean up stale locks
- **Use Case**: Continuing a previously interrupted analysis

### 4. No Lock Present + TestMode Run

- **Behavior**: ✅ **Succeeds** - No lock to conflict with
- **Reasoning**: Normal operation when no other analysis is running
- **Use Case**: Standard test mode execution

### 5. No Lock Present + Full Analysis Run

- **Behavior**: ✅ **Succeeds** - Creates new lock for the analysis
- **Reasoning**: Normal operation, establishes lock to prevent concurrent runs
- **Use Case**: Standard full analysis execution

### 6. No Lock Present + Resume Mode

- **Behavior**: ❌ **Fails** - No checkpoint file to resume from
- **Reasoning**: Resume requires a previous interrupted analysis with checkpoint data
- **Use Case**: Attempting to resume when no analysis was previously interrupted

### 7. Lock Present + NoRunLock Override + TestMode

- **Behavior**: ✅ **Succeeds** - `-NoRunLock` completely bypasses lock checking
- **Reasoning**: Administrative override for testing and troubleshooting
- **Use Case**: Forced execution when lock issues occur

### 8. Lock Present + NoRunLock Override + Full Run

- **Behavior**: ✅ **Succeeds** - `-NoRunLock` completely bypasses lock checking
- **Reasoning**: Administrative override for emergency situations
- **Use Case**: Bypassing locks for critical analysis needs

## Override Options

### Command Line Parameters

#### `-NoRunLock`

- **Purpose**: Completely bypasses lock creation and checking
- **Use Case**: Administrative override, testing, troubleshooting
- **Warning**: Allows concurrent full runs - use with caution

#### `-Resume`

- **Purpose**: Continues a previously interrupted analysis
- **Behavior**: Can automatically remove stale locks
- **Requirements**: Checkpoint file from previous interrupted run

### Environment Variables

#### `AKV_FORCE_BYPASS_LOCK=1`

- **Purpose**: Forces lock bypass for testing scenarios
- **Use Case**: Automated testing and CI/CD pipelines
- **Scope**: Global environment variable

## Lock Management Functions

### Automatic Lock Handling

- **Stale Lock Detection**: Locks older than TTL are automatically removed
- **Process Validation**: Checks if lock-owning process is still running
- **Interactive Prompts**: User can choose to remove stale locks or abort

### Manual Lock Management

```powershell
# Check lock status
Get-Content "$env:TEMP\akv_gap_analysis_running.lock" | ConvertFrom-Json

# Remove lock manually (use with caution)
Remove-Item "$env:TEMP\akv_gap_analysis_running.lock"
```

## Best Practices

### For Regular Users

1. **Use TestMode** for validation and limited testing
2. **Avoid concurrent full runs** - let one complete before starting another
3. **Use Resume** if an analysis was interrupted
4. **Check lock file** if you suspect issues

### For Administrators

1. **Use -NoRunLock** sparingly and only when necessary
2. **Monitor lock TTL** for long-running analyses
3. **Clean up stale locks** manually if needed
4. **Set appropriate TTL** for your environment

### For Automation

1. **Set AKV_FORCE_BYPASS_LOCK=1** in CI/CD pipelines
2. **Implement proper error handling** for lock conflicts
3. **Use TestMode** for automated validation
4. **Monitor lock files** in automated environments

## Troubleshooting

### Common Issues

#### "Analysis already running" Error

- **Cause**: Another full analysis is in progress
- **Solution**: Wait for completion, use TestMode, or use -NoRunLock if urgent

#### Stale Lock Files

- **Cause**: Process crashed or was killed without cleanup
- **Solution**: Manual removal or use Resume mode

#### Lock TTL Too Short

- **Cause**: Long-running analyses exceed default 1-hour TTL
- **Solution**: Increase `$global:RunLockTtlSeconds` before running

#### Permission Issues

- **Cause**: Cannot write to TEMP directory
- **Solution**: Check permissions or change TEMP location

### Diagnostic Commands

```powershell
# Check current lock status
$lockFile = "$env:TEMP\akv_gap_analysis_running.lock"
if (Test-Path $lockFile) {
    $lock = Get-Content $lockFile | ConvertFrom-Json
    Write-Host "Lock exists: PID $($lock.PID), Owner $($lock.Owner), Started $($lock.StartedUtc)"
} else {
    Write-Host "No lock file present"
}

# Check if lock-owning process is running
$lock = Get-Content $lockFile | ConvertFrom-Json
$process = Get-Process -Id $lock.PID -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "Process $($lock.PID) is still running"
} else {
    Write-Host "Process $($lock.PID) is not running - lock may be stale"
}
```

## Configuration

### Lock TTL Configuration

```powershell
# Set custom lock TTL (default: 3600 seconds = 1 hour)
$global:RunLockTtlSeconds = 7200  # 2 hours
```

### Lock File Location Override

```powershell
# Override lock file location (advanced users only)
$global:RunLockFilePath = "C:\Custom\Path\akv_gap_analysis_running.lock"
```

## Security Considerations

- Lock files contain metadata about running processes
- No sensitive data is stored in lock files
- Lock mechanism prevents resource exhaustion from concurrent runs
- Override options should be restricted in production environments

## Performance Impact

- Lock checking is lightweight (file I/O only)
- No performance impact on analysis execution
- Prevents resource contention from concurrent Azure API calls
- Minimal overhead for test mode operations
