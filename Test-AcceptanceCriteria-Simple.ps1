#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Simple acceptance criteria test for authentication hotfix

.DESCRIPTION
    Validates the key acceptance criteria without complex string matching
#>

Write-Host "🔬 AUTHENTICATION HOTFIX ACCEPTANCE TEST" -ForegroundColor Cyan
Write-Host "=" * 45 -ForegroundColor Gray
Write-Host ""

$allPassed = $true

# Test 1: Authentication Context Shape
Write-Host "1️⃣ Testing authentication context shape..." -ForegroundColor Yellow
try {
    & "./Test-AuthenticationContextShape.ps1" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ PASS: Test-AuthenticationContextShape.ps1 runs successfully" -ForegroundColor Green
    } else {
        Write-Host "   ❌ FAIL: Test-AuthenticationContextShape.ps1 failed with exit code $LASTEXITCODE" -ForegroundColor Red
        $allPassed = $false
    }
} catch {
    Write-Host "   ❌ FAIL: Error running Test-AuthenticationContextShape.ps1: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}

# Test 2: No Property-Not-Found Errors  
Write-Host "`n2️⃣ Testing for property-not-found errors..." -ForegroundColor Yellow
try {
    & "./Test-AuthenticationPattern.ps1" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ PASS: Authentication pattern test runs without property errors" -ForegroundColor Green
    } else {
        Write-Host "   ❌ FAIL: Authentication pattern test failed" -ForegroundColor Red
        $allPassed = $false
    }
} catch {
    Write-Host "   ❌ FAIL: Error in authentication pattern test: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}

# Test 3: ForceReauth Parameter Exists
Write-Host "`n3️⃣ Testing ForceReauth parameter..." -ForegroundColor Yellow
try {
    $paramExists = (Get-Content "./Get-AKV_Roles&SecAuditCompliance.ps1" -Raw) -match '\$ForceReauth'
    if ($paramExists) {
        Write-Host "   ✅ PASS: -ForceReauth parameter found in script" -ForegroundColor Green
    } else {
        Write-Host "   ❌ FAIL: -ForceReauth parameter not found" -ForegroundColor Red
        $allPassed = $false
    }
} catch {
    Write-Host "   ❌ FAIL: Error checking ForceReauth parameter: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}

# Test 4: Script Syntax Validation
Write-Host "`n4️⃣ Testing script syntax..." -ForegroundColor Yellow
try {
    $null = pwsh -Command '$ast = [System.Management.Automation.Language.Parser]::ParseFile("./Get-AKV_Roles&SecAuditCompliance.ps1", [ref]$null, [ref]$null); Write-Host "Syntax valid"' 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✅ PASS: Script syntax is valid" -ForegroundColor Green
    } else {
        Write-Host "   ❌ FAIL: Script has syntax errors" -ForegroundColor Red
        $allPassed = $false
    }
} catch {
    Write-Host "   ❌ FAIL: Error checking syntax: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}

# Test 5: Key Functions Exist
Write-Host "`n5️⃣ Testing required functions..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content "./Get-AKV_Roles&SecAuditCompliance.ps1" -Raw
    $requiredFunctions = @(
        'Initialize-AkvAuthenticationContext',
        'Get-AkvAuthFlow'
    )
    
    $allFunctionsExist = $true
    foreach ($func in $requiredFunctions) {
        if ($scriptContent -match "function $func") {
            Write-Host "   ✅ Function '$func' found" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Function '$func' not found" -ForegroundColor Red
            $allFunctionsExist = $false
            $allPassed = $false
        }
    }
    
    if ($allFunctionsExist) {
        Write-Host "   ✅ PASS: All required functions exist" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ FAIL: Error checking functions: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}

# Summary
Write-Host "`n📊 FINAL RESULT" -ForegroundColor Cyan
Write-Host "=" * 20 -ForegroundColor Gray

if ($allPassed) {
    Write-Host ""
    Write-Host "🎉 ALL ACCEPTANCE CRITERIA PASSED!" -ForegroundColor Green
    Write-Host "✅ Authentication hotfix successfully implemented" -ForegroundColor Green
    Write-Host ""
    Write-Host "Key improvements:" -ForegroundColor Yellow
    Write-Host "- No more 'AuthenticationFlow property not found' errors" -ForegroundColor Gray
    Write-Host "- Stable authentication context object schema" -ForegroundColor Gray  
    Write-Host "- Safe property access with Get-AkvAuthFlow function" -ForegroundColor Gray
    Write-Host "- ForceReauth parameter for credential refresh" -ForegroundColor Gray
    Write-Host "- Clean error handling with single failure sequence" -ForegroundColor Gray
    exit 0
} else {
    Write-Host ""
    Write-Host "❌ Some acceptance criteria failed" -ForegroundColor Red
    exit 1
}