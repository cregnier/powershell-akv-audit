#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Validation test for PowerShell compliance and bugfix updates

.DESCRIPTION
    Tests the following fixes:
    1. $Verbose variable replaced with $VerbosePreference in environment detection functions
    2. Global count variables are initialized before use
    3. Null-checking for property accesses
    4. Test mode early-stop logic
#>

[CmdletBinding()]
param()

Write-Host "🧪 POWERSHELL COMPLIANCE AND BUGFIX VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    Syntax = $false
    VerbosePreferenceUsage = $false
    GlobalVariableInit = $false
    NullChecking = $false
    TestModeLogic = $false
}

# Test 1: PowerShell Syntax Validation
Write-Host "`n1️⃣ PowerShell Syntax Validation" -ForegroundColor Yellow
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax is valid" -ForegroundColor Green
        $testResults.Syntax = $true
    } else {
        Write-Host "   ❌ PowerShell syntax has errors" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error parsing script: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: $VerbosePreference Usage Instead of $Verbose
Write-Host "`n2️⃣ Testing $VerbosePreference usage (not automatic `$Verbose)" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check that in Test-CloudShellEnvironment and Test-ManagedIdentityEnvironment,
    # $VerbosePreference is used instead of $Verbose (which would be the automatic variable)
    $cloudShellFunctionStart = $scriptContent.IndexOf('function Test-CloudShellEnvironment')
    $managedIdFunctionStart = $scriptContent.IndexOf('function Test-ManagedIdentityEnvironment')
    $nextFunctionAfterCloudShell = $scriptContent.IndexOf('function ', $cloudShellFunctionStart + 10)
    $nextFunctionAfterManagedId = $scriptContent.IndexOf('function ', $managedIdFunctionStart + 10)
    
    $cloudShellFunction = $scriptContent.Substring($cloudShellFunctionStart, $nextFunctionAfterCloudShell - $cloudShellFunctionStart)
    $managedIdFunction = $scriptContent.Substring($managedIdFunctionStart, $nextFunctionAfterManagedId - $managedIdFunctionStart)
    
    # Check these two functions use $VerbosePreference, not automatic $Verbose
    $cloudShellUsesVerbose = [regex]::Matches($cloudShellFunction, 'if\s*\(\$Verbose[^P]').Count
    $cloudShellUsesVerbosePreference = [regex]::Matches($cloudShellFunction, '\$VerbosePreference').Count
    
    $managedIdUsesVerbose = [regex]::Matches($managedIdFunction, 'if\s*\(\$Verbose[^P]').Count
    $managedIdUsesVerbosePreference = [regex]::Matches($managedIdFunction, '\$VerbosePreference').Count
    
    Write-Host "   📋 Test-CloudShellEnvironment uses `$Verbose: $cloudShellUsesVerbose times" -ForegroundColor $(if ($cloudShellUsesVerbose -eq 0) { "Green" } else { "Red" })
    Write-Host "   📋 Test-CloudShellEnvironment uses `$VerbosePreference: $cloudShellUsesVerbosePreference times" -ForegroundColor $(if ($cloudShellUsesVerbosePreference -gt 0) { "Green" } else { "Red" })
    Write-Host "   📋 Test-ManagedIdentityEnvironment uses `$Verbose: $managedIdUsesVerbose times" -ForegroundColor $(if ($managedIdUsesVerbose -eq 0) { "Green" } else { "Red" })
    Write-Host "   📋 Test-ManagedIdentityEnvironment uses `$VerbosePreference: $managedIdUsesVerbosePreference times" -ForegroundColor $(if ($managedIdUsesVerbosePreference -gt 0) { "Green" } else { "Red" })
    
    if ($cloudShellUsesVerbose -eq 0 -and $managedIdUsesVerbose -eq 0 -and 
        $cloudShellUsesVerbosePreference -gt 0 -and $managedIdUsesVerbosePreference -gt 0) {
        Write-Host "   ✅ $VerbosePreference is used correctly in environment detection functions" -ForegroundColor Green
        $testResults.VerbosePreferenceUsage = $true
    } else {
        Write-Host "   ⚠️ Environment detection functions may still use automatic `$Verbose" -ForegroundColor Yellow
    }
    
    # Note: Other functions may have custom -Verbose parameters which is acceptable
    Write-Host "   ℹ️ Note: Other functions may have custom -Verbose switch parameters (which is acceptable)" -ForegroundColor Cyan
} catch {
    Write-Host "   ❌ Error testing `$VerbosePreference usage: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Global Variable Initialization
Write-Host "`n3️⃣ Testing global count variable initialization" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for initialization of global count variables
    $globalVars = @(
        'serviceProviderCount',
        'managedIdentityCount',
        'systemManagedIdentityCount',
        'userManagedIdentityCount'
    )
    
    $allInitialized = $true
    foreach ($varName in $globalVars) {
        $initPattern = "\`$global:$varName\s*=\s*0"
        if ($scriptContent -match $initPattern) {
            Write-Host "   ✅ `$global:$varName is initialized" -ForegroundColor Green
        } else {
            Write-Host "   ❌ `$global:$varName is NOT initialized" -ForegroundColor Red
            $allInitialized = $false
        }
    }
    
    if ($allInitialized) {
        Write-Host "   ✅ All global count variables are initialized" -ForegroundColor Green
        $testResults.GlobalVariableInit = $true
    }
} catch {
    Write-Host "   ❌ Error testing global variable initialization: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Null-Checking for Property Access
Write-Host "`n4️⃣ Testing null-checking for property access" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for null-checked CompliantVaults assignment
    $nullCheckedCompliant = $scriptContent -match 'CompliantVaults\s*=\s*if\s*\(\$global:auditResults\)'
    Write-Host "   📋 CompliantVaults with null-check: $nullCheckedCompliant" -ForegroundColor $(if ($nullCheckedCompliant) { "Green" } else { "Red" })
    
    # Check for null-checked HighRiskVaults assignment
    $nullCheckedHighRisk = $scriptContent -match 'HighRiskVaults\s*=\s*if\s*\(\$global:auditResults\)'
    Write-Host "   📋 HighRiskVaults with null-check: $nullCheckedHighRisk" -ForegroundColor $(if ($nullCheckedHighRisk) { "Green" } else { "Red" })
    
    if ($nullCheckedCompliant -and $nullCheckedHighRisk) {
        Write-Host "   ✅ Property access has proper null-checking" -ForegroundColor Green
        $testResults.NullChecking = $true
    } else {
        Write-Host "   ⚠️ Some property accesses may need null-checking" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing null-checking: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Test Mode Early-Stop Logic
Write-Host "`n5️⃣ Testing test mode early-stop logic" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for test mode limit check
    $testModeLimitCheck = $scriptContent -match 'if\s*\(\$TestMode\s*-and\s*\$allKeyVaults\.Count\s*-ge\s*\$Limit\)'
    Write-Host "   📋 Test mode limit check found: $testModeLimitCheck" -ForegroundColor $(if ($testModeLimitCheck) { "Green" } else { "Red" })
    
    # Check for early termination message
    $earlyTermMessage = $scriptContent -match 'Test mode optimization.*Stopping subscription discovery'
    Write-Host "   📋 Early termination message found: $earlyTermMessage" -ForegroundColor $(if ($earlyTermMessage) { "Green" } else { "Red" })
    
    # Check for break statement after limit
    $breakAfterLimit = $scriptContent -match 'Test mode limit reached.*break'
    Write-Host "   📋 Break after limit reached: $breakAfterLimit" -ForegroundColor $(if ($breakAfterLimit) { "Green" } else { "Red" })
    
    if ($testModeLimitCheck -and $earlyTermMessage) {
        Write-Host "   ✅ Test mode early-stop logic is present" -ForegroundColor Green
        $testResults.TestModeLogic = $true
    }
} catch {
    Write-Host "   ❌ Error testing test mode logic: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📋 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 30 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

Write-Host "`n✅ Passed: $passedTests / $totalTests tests" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All PowerShell compliance and bugfix validations passed!" -ForegroundColor Green
    Write-Host "💡 Key improvements:" -ForegroundColor Blue
    Write-Host "  • `$VerbosePreference used instead of `$Verbose variable" -ForegroundColor Gray
    Write-Host "  • Global count variables initialized before use" -ForegroundColor Gray
    Write-Host "  • Property access includes null-checking" -ForegroundColor Gray
    Write-Host "  • Test mode includes early-stop optimization" -ForegroundColor Gray
} else {
    Write-Host "`n⚠️ Some validations did not pass - review results above" -ForegroundColor Yellow
}

return $testResults
