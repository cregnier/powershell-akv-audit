# KeyVaultName Variable Initialization Fix

## Summary
Fixed critical issues in SingleVault mode where `$KeyVaultName` variable was referenced before being properly initialized, causing potential runtime errors.

## Issues Fixed

### 1. Uninitialized Variable References
**Problem:** Three instances in SingleVault mode where `$KeyVaultName` was used in logging functions but was undefined.

**Location:** Lines 9392, 9397, and 9411 in the SingleVault section

**Fix:** Changed all references from `$KeyVaultName` to `$kv.VaultName` which is properly initialized from the vault object.

**Before:**
```powershell
Write-DataIssuesLog "Identity" "System-assigned identity has no PrincipalId" $KeyVaultName
Write-DataIssuesLog "Identity" "Error processing system-assigned identity" $KeyVaultName $_.Exception.Message
Write-DataIssuesLog "Identity" "Error processing user-assigned identities" $KeyVaultName $_.Exception.Message
```

**After:**
```powershell
Write-DataIssuesLog "Identity" "System-assigned identity has no PrincipalId" $kv.VaultName
Write-DataIssuesLog "Identity" "Error processing system-assigned identity" $kv.VaultName $_.Exception.Message
Write-DataIssuesLog "Identity" "Error processing user-assigned identities" $kv.VaultName $_.Exception.Message
```

### 2. Defensive Checks Added
**Enhancement:** Added multiple layers of defensive programming to ensure vault names are always available for error logging.

#### 2.1 Parameter Validation
```powershell
# Defensive check: Ensure vault name is available for error logging
if (-not $VaultName) {
    Write-Host "❌ Error: VaultName not available for analysis" -ForegroundColor Red
    Write-ErrorLog "SingleVault" "VaultName parameter is null or empty" ""
    exit 1
}
```

#### 2.2 Vault Object Validation
```powershell
# Create vault object in expected format with defensive checks
if (-not $kvDetail.VaultName) {
    Write-Host "❌ Error: Retrieved vault has no name property" -ForegroundColor Red
    Write-ErrorLog "SingleVault" "Retrieved vault missing VaultName property" $VaultName
    exit 1
}

# Validate that vault name is consistently available for logging
if (-not $kv.VaultName) {
    Write-Host "❌ Error: Vault object has no VaultName property" -ForegroundColor Red
    Write-ErrorLog "SingleVault" "Vault object missing VaultName property" $VaultName
    exit 1
}
```

#### 2.3 Fallback Logic for Error Handling
```powershell
# Helper function to get vault name for logging (fallback logic)
function Get-VaultNameForLogging {
    param([string]$FallbackName = "")
    
    if ($kv -and $kv.VaultName) {
        return $kv.VaultName
    } elseif ($VaultName) {
        return $VaultName
    } elseif ($FallbackName) {
        return $FallbackName
    } else {
        return "<unknown>"
    }
}
```

#### 2.4 Enhanced Error Catch Block
```powershell
} catch {
    # Use fallback vault name if kv.VaultName is available, otherwise use parameter VaultName
    $errorVaultName = if ($kv -and $kv.VaultName) { $kv.VaultName } else { $VaultName }
    $displayVaultName = if ($errorVaultName) { "'$errorVaultName'" } else { "<unknown>" }
    
    Write-Host "❌ Failed to analyze vault $displayVaultName`: $($_.Exception.Message)" -ForegroundColor Red
    Write-ErrorLog "SingleVault" "Failed to analyze vault: $($_.Exception.Message)" $errorVaultName
    
    # Provide helpful troubleshooting guidance
    Write-Host ""
    Write-Host "💡 Troubleshooting guidance:" -ForegroundColor Yellow
    Write-Host "   - Verify you have the required permissions (Reader role on subscription/vault)" -ForegroundColor Gray
    Write-Host "   - Check that the vault is accessible from your current network location" -ForegroundColor Gray
    Write-Host "   - Ensure Azure PowerShell modules are up to date" -ForegroundColor Gray
    Write-Host "   - Review error logs: $global:errPath" -ForegroundColor Gray
    
    exit 1
}
```

## Variable Usage Consistency

### Verified Correct Usage
All function calls in SingleVault mode correctly pass the vault name parameter:

```powershell
$diagnostics = Get-DiagnosticsConfiguration -ResourceId $kv.ResourceId -KeyVaultName $kv.VaultName
$rbacAssignments = Get-RBACAssignments -ResourceId $kv.ResourceId -KeyVaultName $kv.VaultName
$workloadAnalysis = Get-KeyVaultWorkloadAnalysis -KeyVault $kv -KeyVaultName $kv.VaultName
```

### Function Parameter Definitions
The functions that require KeyVaultName parameter are properly defined:
- `Get-DiagnosticsConfiguration($ResourceId, $KeyVaultName)`
- `Get-RBACAssignments($ResourceId, $KeyVaultName)`
- `Get-KeyVaultWorkloadAnalysis($KeyVault, $KeyVaultName)`

## Best Practices Implemented

### 1. Explicit Error Messages
- Clear error messages when vault name is not available
- Explicit validation at each step where vault name is needed
- Helpful troubleshooting guidance in error scenarios

### 2. Fallback Logic
- Multiple fallback mechanisms for vault name retrieval
- Graceful degradation when preferred sources are unavailable
- Helper functions for consistent logging behavior

### 3. Interactive Prompting (Already Existed)
The script already had proper interactive prompting for vault name:

```powershell
# Prompt for vault name if not provided
if (-not $VaultName) {
    Write-Host ""
    Write-Host "Please provide the Key Vault name for diagnostics scan:" -ForegroundColor Yellow
    do {
        $VaultName = Read-Host "Key Vault Name"
        if (-not $VaultName) {
            Write-Host "❌ Vault name cannot be empty. Please try again." -ForegroundColor Red
        }
    } while (-not $VaultName)
}
```

## Testing
Comprehensive test suite (`Test-KeyVaultNameFix.ps1`) validates:
- PowerShell syntax validation
- Help system functionality
- Parameter validation 
- Specific fix implementations
- Defensive check implementations

All tests pass successfully, confirming the fixes are working correctly.

## Impact
- **Eliminated runtime errors** from undefined variable references
- **Improved error handling** with explicit error messages and troubleshooting guidance
- **Enhanced robustness** through defensive programming practices
- **Maintained compatibility** with existing functionality
- **Added fallback mechanisms** for edge cases

## Files Modified
- `Get-AKV_Roles&SecAuditCompliance.ps1` - Core script with fixes
- `Test-KeyVaultNameFix.ps1` - New comprehensive test suite

## Validation
- All PowerShell syntax validation passes
- Help system functionality confirmed
- Parameter validation works as expected
- All specific fixes verified through automated testing
- Defensive checks confirmed to be in place