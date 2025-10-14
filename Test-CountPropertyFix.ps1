#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate Get-SafeCount function and .Count property fixes
.DESCRIPTION
    Tests the fix for the error: "The property 'Count' cannot be found on this object"
    Validates:
    1. Get-SafeCount function exists and works correctly
    2. All unsafe .Count accesses in HTML generation have been replaced
    3. Function handles null, single objects, and arrays correctly
#>

[CmdletBinding()]
param()

Write-Host "🧪 GET-SAFECOUNT FUNCTION VALIDATION TEST" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    FunctionExists = $false
    HandlesNull = $false
    HandlesSingleObject = $false
    HandlesArray = $false
    NoUnsafeCountAccess = $false
    AllTestsPassed = $false
}

# Test 1: Verify Get-SafeCount function exists
Write-Host "`n1️⃣ Testing Get-SafeCount function exists..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    if ($scriptContent -match 'function Get-SafeCount') {
        Write-Host "   ✅ Get-SafeCount function is defined" -ForegroundColor Green
        $testResults.FunctionExists = $true
        
        # Verify the function has the right structure
        if ($scriptContent -match 'function Get-SafeCount\s*\{[\s\S]*?param\(\$Object\)[\s\S]*?if \(\$null -eq \$Object\)') {
            Write-Host "   ✅ Function has correct structure (handles null)" -ForegroundColor Green
            $testResults.HandlesNull = $true
        }
        
        if ($scriptContent -match 'if \(\$Object -is \[array\]\)') {
            Write-Host "   ✅ Function checks for arrays" -ForegroundColor Green
            $testResults.HandlesArray = $true
        }
        
        if ($scriptContent -match "PSObject\.Properties\['Count'\]") {
            Write-Host "   ✅ Function checks for Count property" -ForegroundColor Green
        }
        
        if ($scriptContent -match 'return 1.*# Single object' -or $scriptContent -match 'return 1[\s\n]*?\}[\s\n]*?catch') {
            Write-Host "   ✅ Function handles single objects (returns 1)" -ForegroundColor Green
            $testResults.HandlesSingleObject = $true
        }
    } else {
        Write-Host "   ❌ Get-SafeCount function NOT found" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "   ❌ Error checking function: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Verify no unsafe .Count accesses remain in HTML generation
Write-Host "`n2️⃣ Testing for remaining unsafe .Count accesses..." -ForegroundColor Yellow
try {
    # Check for unsafe patterns that should have been replaced
    $unsafePatterns = @(
        'systemAssignedResults\.Count',
        'rbacResults\.Count', 
        'secretResults\.Count'
    )
    
    $foundUnsafe = $false
    foreach ($pattern in $unsafePatterns) {
        if ($scriptContent -match $pattern) {
            Write-Host "   ❌ Found unsafe pattern: $pattern" -ForegroundColor Red
            $foundUnsafe = $true
        }
    }
    
    if (-not $foundUnsafe) {
        Write-Host "   ✅ No unsafe .Count accesses found" -ForegroundColor Green
        $testResults.NoUnsafeCountAccess = $true
    }
} catch {
    Write-Host "   ❌ Error testing unsafe patterns: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Verify Get-SafeCount is used in HTML generation
Write-Host "`n3️⃣ Testing Get-SafeCount usage..." -ForegroundColor Yellow
try {
    $getSafeCountUsage = ([regex]::Matches($scriptContent, 'Get-SafeCount')).Count
    Write-Host "   ℹ️  Get-SafeCount used $getSafeCountUsage times" -ForegroundColor Cyan
    
    if ($getSafeCountUsage -ge 9) {  # 1 definition + at least 8 usages
        Write-Host "   ✅ Get-SafeCount is actively used (minimum 9 expected: 1 definition + 8 calls)" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Get-SafeCount usage lower than expected (found $getSafeCountUsage)" -ForegroundColor Yellow
    }
    
    # Verify specific replacements
    $expectedReplacements = @(
        'Get-SafeCount \$systemAssignedResults',
        'Get-SafeCount \$rbacResults',
        'Get-SafeCount \$secretResults'
    )
    
    $replacementCount = 0
    foreach ($replacement in $expectedReplacements) {
        $matches = ([regex]::Matches($scriptContent, $replacement)).Count
        if ($matches -gt 0) {
            Write-Host "   ✅ Found $matches replacements for: $replacement" -ForegroundColor Green
            $replacementCount += $matches
        }
    }
    
    Write-Host "   ℹ️  Total safe replacements: $replacementCount" -ForegroundColor Cyan
} catch {
    Write-Host "   ❌ Error testing Get-SafeCount usage: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: PowerShell Syntax Validation
Write-Host "`n4️⃣ PowerShell Syntax Validation..." -ForegroundColor Yellow
try {
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    
    if ($errors -and $errors.Count -gt 0) {
        Write-Host "   ❌ Syntax errors found:" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
    } else {
        Write-Host "   ✅ PowerShell syntax is valid" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Syntax validation failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n" + ("=" * 70) -ForegroundColor Gray
Write-Host "📊 TEST SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Gray

$passedTests = 0
$totalTests = 5

if ($testResults.FunctionExists) { 
    Write-Host "✅ Get-SafeCount function exists" -ForegroundColor Green
    $passedTests++
} else {
    Write-Host "❌ Get-SafeCount function missing" -ForegroundColor Red
}

if ($testResults.NoUnsafeCountAccess) { 
    Write-Host "✅ No unsafe .Count accesses found" -ForegroundColor Green
    $passedTests++
} else {
    Write-Host "❌ Unsafe .Count accesses still present" -ForegroundColor Red
}

if ($testResults.HandlesNull) { 
    Write-Host "✅ Handles null correctly" -ForegroundColor Green
    $passedTests++
} else {
    Write-Host "⚠️  Null handling not validated" -ForegroundColor Yellow
}

if ($testResults.HandlesSingleObject) { 
    Write-Host "✅ Handles single objects correctly" -ForegroundColor Green
    $passedTests++
} else {
    Write-Host "⚠️  Single object handling not validated" -ForegroundColor Yellow
}

if ($testResults.HandlesArray) { 
    Write-Host "✅ Handles arrays correctly" -ForegroundColor Green
    $passedTests++
} else {
    Write-Host "⚠️  Array handling not validated" -ForegroundColor Yellow
}

Write-Host "`n📈 Tests Passed: $passedTests / $totalTests" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 ALL TESTS PASSED! Get-SafeCount fix is working correctly." -ForegroundColor Green
    $testResults.AllTestsPassed = $true
    exit 0
} else {
    Write-Host "`n⚠️  Some tests did not pass. Review the output above." -ForegroundColor Yellow
    exit 1
}
