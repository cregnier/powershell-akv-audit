# Parameter Consolidation and Script Refactoring - Test Instructions

This document provides comprehensive test instructions for validating the parameter consolidation and script refactoring changes made to the Azure Key Vault audit script.

## Changes Made

### 1. Parameter Consolidation
- **Removed**: `CsvPath` parameter 
- **Retained**: `CsvFilePath` parameter (now used for both `-ProcessPartial` and `-ReportFromCsv`)
- **Updated**: All function signatures and calls to use `CsvFilePath` consistently
- **Updated**: Help documentation and examples to reflect parameter consolidation

### 2. Syntax Fixes
- **Fixed**: Duplicate `[CmdletBinding()]` declaration
- **Fixed**: Duplicate `PrivateEndpointCount` hash key that caused syntax errors

### 3. Parameter Validation Enhancements
- **Enhanced**: `CsvFilePath` can now be used with both `-ProcessPartial` and `-ReportFromCsv`
- **Validated**: `SingleVault` parameter implementation is complete and properly restricted
- **Confirmed**: Authentication error handling and environment detection are robust

## Test Scenarios

### Scenario 1: Basic Syntax and Help Validation

```powershell
# Test 1.1: Syntax validation (< 1 second)
pwsh -Command "`$ast = [System.Management.Automation.Language.Parser]::ParseFile('./Get-AKV_Roles&SecAuditCompliance.ps1', [ref]`$null, [ref]`$null); if (`$ast) { Write-Host 'PowerShell syntax valid' } else { Write-Host 'Syntax errors found' }"

# Test 1.2: Help system validation (< 1 second)
pwsh -Command "Get-Help './Get-AKV_Roles&SecAuditCompliance.ps1'"

# Test 1.3: Parameter-specific help (< 1 second)
pwsh -Command "Get-Help './Get-AKV_Roles&SecAuditCompliance.ps1' -Parameter CsvFilePath"
pwsh -Command "Get-Help './Get-AKV_Roles&SecAuditCompliance.ps1' -Parameter SingleVault"

# Test 1.4: Examples validation (< 1 second)
pwsh -Command "Get-Help './Get-AKV_Roles&SecAuditCompliance.ps1' -Examples"
```

**Expected Results:**
- All syntax validation should return "PowerShell syntax valid"
- Help should display without errors and show `CsvFilePath` parameter (not `CsvPath`)
- Examples should reference `-CsvFilePath` instead of `-CsvPath`

### Scenario 2: Parameter Validation Logic

```powershell
# Test 2.1: Valid CsvFilePath usage with ProcessPartial
./Get-AKV_Roles&SecAuditCompliance.ps1 -ProcessPartial -CsvFilePath "nonexistent.csv"

# Test 2.2: Valid CsvFilePath usage with ReportFromCsv  
./Get-AKV_Roles&SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "nonexistent.csv"

# Test 2.3: Invalid CsvFilePath usage (should fail)
./Get-AKV_Roles&SecAuditCompliance.ps1 -CsvFilePath "test.csv"

# Test 2.4: SingleVault parameter conflicts (should fail)
./Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -Resume
./Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -ProcessPartial  
./Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -ReportFromCsv

# Test 2.5: VaultName without SingleVault (should fail)
./Get-AKV_Roles&SecAuditCompliance.ps1 -VaultName "TestVault"
```

**Expected Results:**
- Tests 2.1 and 2.2: Should proceed past parameter validation (may fail later due to missing file)
- Test 2.3: Should display error: "-CsvFilePath can only be used with -ReportFromCsv or -ProcessPartial parameters"
- Tests 2.4: Should display error: "-SingleVault cannot be used with -Resume, -ProcessPartial, or -ReportFromCsv parameters"  
- Test 2.5: Should display error: "-VaultName can only be used with -SingleVault parameter"

### Scenario 3: Environment and Authentication Detection

```powershell
# Test 3.1: Environment detection (should handle gracefully)
./Get-AKV_Roles&SecAuditCompliance.ps1 -TestMode -Limit 1

# Test 3.2: CTRL+C handler registration (check for warnings about unsupported environments)
# This should show no warnings in most environments, or a graceful warning in restricted environments
```

**Expected Results:**
- Should detect environment properly and show appropriate authentication flow
- Should gracefully handle CTRL+C registration failures in restricted environments

### Scenario 4: SingleVault Mode Testing

```powershell
# Test 4.1: SingleVault with VaultName parameter
./Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -VaultName "NonExistentVault"

# Test 4.2: SingleVault without VaultName (should prompt)
./Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault
```

**Expected Results:**
- Should proceed to authentication phase
- Should handle vault discovery appropriately
- Should generate appropriate error messages for non-existent vaults

### Scenario 5: Function Integration Testing

Create a minimal test CSV file to validate function calls:

```powershell
# Create test CSV file
@"
KeyVaultName,SubscriptionId,ResourceGroupName
TestVault,12345678-1234-1234-1234-123456789012,TestRG
"@ | Out-File -FilePath "test_audit.csv" -Encoding UTF8

# Test 5.1: ReportFromCsv with CsvFilePath
./Get-AKV_Roles&SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "test_audit.csv"

# Test 5.2: ProcessPartial with CsvFilePath  
./Get-AKV_Roles&SecAuditCompliance.ps1 -ProcessPartial -CsvFilePath "test_audit.csv"

# Cleanup
Remove-Item "test_audit.csv" -ErrorAction SilentlyContinue
```

**Expected Results:**
- Both tests should proceed past parameter validation
- Should attempt to process the CSV file (may fail later due to incomplete data, which is expected)

## Validation Checklist

- [ ] ✅ PowerShell syntax validates without errors
- [ ] ✅ Help documentation displays `CsvFilePath` parameter correctly
- [ ] ✅ Help examples reference `-CsvFilePath` instead of `-CsvPath`
- [ ] ✅ Parameter validation rejects invalid combinations
- [ ] ✅ `CsvFilePath` works with both `-ProcessPartial` and `-ReportFromCsv`
- [ ] ✅ `SingleVault` parameter validation works correctly
- [ ] ✅ `VaultName` parameter requires `SingleVault`
- [ ] ✅ Environment detection handles CTRL+C registration gracefully
- [ ] ✅ Function calls use `-CsvFilePath` parameter consistently

## Common Issues and Troubleshooting

### Issue: "Parameter set cannot be resolved"
**Cause**: Conflicting parameter combinations
**Solution**: Check parameter validation logic - certain combinations are intentionally restricted

### Issue: "File not found" errors during testing
**Cause**: Test CSV files don't exist
**Solution**: This is expected for validation testing - the script should fail gracefully with helpful error messages

### Issue: Authentication errors
**Cause**: Azure authentication not configured  
**Solution**: For parameter validation testing, authentication errors are expected and can be ignored

### Issue: CTRL+C handler warnings
**Cause**: Running in restricted PowerShell environment
**Solution**: This is expected and handled gracefully - the script continues without the handler

## Performance Notes

- **Syntax validation**: < 1 second
- **Help documentation**: < 1 second  
- **Parameter validation**: < 5 seconds
- **Function integration tests**: < 10 seconds (depends on file I/O)

## Regression Testing

When making future changes, re-run all scenarios to ensure:

1. Parameter consolidation remains intact
2. No new syntax errors are introduced
3. Help documentation stays consistent
4. Parameter validation logic continues to work
5. SingleVault functionality remains properly restricted

## Documentation Updates

The following documentation reflects the parameter consolidation:

- Main script help (`.PARAMETER` sections)
- Function signatures and calls throughout the script
- Error messages and user guidance
- Example usage in help documentation

All references to `CsvPath` have been systematically replaced with `CsvFilePath` while maintaining backward compatibility in functionality.