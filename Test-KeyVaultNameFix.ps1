#!/usr/bin/env pwsh
<#
.SYNOPSIS
Test script to validate KeyVaultName variable initialization fixes in SingleVault mode

.DESCRIPTION
This test script validates that:
1. PowerShell syntax is valid
2. Help system works correctly  
3. Parameter validation works as expected
4. SingleVault mode doesn't have undefined variable references

.NOTES
Author: GitHub Copilot
Version: 1.0
#>

[CmdletBinding()]
param()

Write-Host "🧪 Testing KeyVaultName variable initialization fixes..." -ForegroundColor Cyan
Write-Host "=" * 60

$scriptPath = "./Get-AKV_Roles-SecAuditCompliance.ps1"
$testsPassed = 0
$totalTests = 0

function Test-Result {
    param($TestName, $Condition, $ErrorMessage = "")
    $script:totalTests++
    if ($Condition) {
        Write-Host "✅ $TestName" -ForegroundColor Green
        $script:testsPassed++
        return $true
    } else {
        Write-Host "❌ $TestName" -ForegroundColor Red
        if ($ErrorMessage) {
            Write-Host "   Error: $ErrorMessage" -ForegroundColor Yellow
        }
        return $false
    }
}

# Test 1: PowerShell syntax validation
Write-Host "`n📋 Test 1: PowerShell Syntax Validation" -ForegroundColor Yellow
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    Test-Result "PowerShell syntax is valid" ($ast -ne $null)
} catch {
    Test-Result "PowerShell syntax is valid" $false $_.Exception.Message
}

# Test 2: Help system functionality
Write-Host "`n📋 Test 2: Help System Functionality" -ForegroundColor Yellow
try {
    $help = Get-Help $scriptPath -ErrorAction Stop
    Test-Result "Help system loads successfully" ($help -ne $null)
    
    $vaultNameHelp = Get-Help $scriptPath -Parameter VaultName -ErrorAction Stop
    Test-Result "VaultName parameter help is available" ($vaultNameHelp -ne $null)
    
    $singleVaultHelp = Get-Help $scriptPath -Parameter SingleVault -ErrorAction Stop  
    Test-Result "SingleVault parameter help is available" ($singleVaultHelp -ne $null)
} catch {
    Test-Result "Help system functionality" $false $_.Exception.Message
}

# Test 3: Parameter validation
Write-Host "`n📋 Test 3: Parameter Validation" -ForegroundColor Yellow
try {
    # Test invalid parameter combination: VaultName without SingleVault
    $result = & pwsh -Command "& '$scriptPath' -VaultName 'TestVault' 2>&1"
    $hasExpectedError = $result -match "VaultName can only be used with -SingleVault"
    Test-Result "VaultName without SingleVault shows expected error" $hasExpectedError
    
    # Test invalid parameter combination: SingleVault with Resume
    $result = & pwsh -Command "& '$scriptPath' -SingleVault -Resume 2>&1"
    $hasExpectedError = $result -match "SingleVault cannot be used with.*Resume"
    Test-Result "SingleVault with Resume shows expected error" $hasExpectedError
} catch {
    Test-Result "Parameter validation" $false $_.Exception.Message
}

# Test 4: Code analysis for specific KeyVaultName fixes
Write-Host "`n📋 Test 4: Specific KeyVaultName Fix Validation" -ForegroundColor Yellow
try {
    $content = Get-Content $scriptPath -Raw
    
    # Check that the 3 specific problematic lines have been fixed
    $systemAssignedFix = $content -match 'Write-DataIssuesLog "Identity" "System-assigned identity has no PrincipalId" \$kv\.VaultName'
    Test-Result "System-assigned identity PrincipalId error uses kv.VaultName" $systemAssignedFix
    
    $systemAssignedErrorFix = $content -match 'Write-DataIssuesLog "Identity" "Error processing system-assigned identity" \$kv\.VaultName'
    Test-Result "System-assigned identity processing error uses kv.VaultName" $systemAssignedErrorFix
    
    $userAssignedFix = $content -match 'Write-DataIssuesLog "Identity" "Error processing user-assigned identities" \$kv\.VaultName'
    Test-Result "User-assigned identities error uses kv.VaultName" $userAssignedFix
    
    # Check that function calls pass the correct parameter
    $rbacCallFix = $content -match 'Get-RBACAssignments -ResourceId \$kv\.ResourceId -KeyVaultName \$kv\.VaultName'
    Test-Result "RBAC function call passes kv.VaultName correctly" $rbacCallFix
    
    $workloadCallFix = $content -match 'Get-KeyVaultWorkloadAnalysis -KeyVault \$kv -KeyVaultName \$kv\.VaultName'
    Test-Result "Workload analysis function call passes kv.VaultName correctly" $workloadCallFix
    
} catch {
    Test-Result "Specific KeyVaultName fix validation" $false $_.Exception.Message
}

# Test 5: Verify defensive check implementations
Write-Host "`n📋 Test 5: Defensive Check Implementations" -ForegroundColor Yellow
try {
    $content = Get-Content $scriptPath -Raw
    
    # Check for vault name validation
    $hasVaultNameValidation = $content -match "VaultName.*not available for analysis"
    Test-Result "Vault name validation check exists" $hasVaultNameValidation
    
    # Check for kv.VaultName validation  
    $hasKvVaultNameValidation = $content -match "Vault object.*VaultName property"
    Test-Result "Vault object VaultName validation exists" $hasKvVaultNameValidation
    
    # Check for fallback error handling
    $hasFallbackLogic = $content -match "Get-VaultNameForLogging"
    Test-Result "Fallback vault name logic exists" $hasFallbackLogic
} catch {
    Test-Result "Defensive check implementations" $false $_.Exception.Message
}

# Summary
Write-Host "`n" + "=" * 60
Write-Host "🏆 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "Tests Passed: $testsPassed/$totalTests" -ForegroundColor $(if ($testsPassed -eq $totalTests) { "Green" } else { "Yellow" })

if ($testsPassed -eq $totalTests) {
    Write-Host "✅ ALL TESTS PASSED - KeyVaultName initialization fixes are working correctly!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "⚠️ Some tests failed - please review the issues above" -ForegroundColor Yellow
    exit 1
}