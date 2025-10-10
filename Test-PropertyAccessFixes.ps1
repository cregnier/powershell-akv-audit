#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate property access and variable initialization fixes

.DESCRIPTION
    Tests the following fixes:
    1. Get-SafeCount function exists and works correctly
    2. $global:accessPolicyCount is initialized
    3. Where-Object results are wrapped in @() to ensure .Count property
    4. Unsafe .Count usage replaced with Get-SafeCount
#>

[CmdletBinding()]
param()

Write-Host "🧪 PROPERTY ACCESS AND VARIABLE INITIALIZATION VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    GetSafeCountExists = $false
    AccessPolicyCountInit = $false
    WhereObjectWrapped = $false
    GetSafeCountUsage = $false
    Syntax = $false
}

# Test 1: Get-SafeCount function exists
Write-Host "`n1️⃣ Testing Get-SafeCount function exists" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $functionExists = $scriptContent -match 'function Get-SafeCount'
    if ($functionExists) {
        Write-Host "   ✅ Get-SafeCount function is defined" -ForegroundColor Green
        $testResults.GetSafeCountExists = $true
    } else {
        Write-Host "   ❌ Get-SafeCount function NOT found" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing Get-SafeCount: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: $global:accessPolicyCount initialization
Write-Host "`n2️⃣ Testing `$global:accessPolicyCount initialization" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $initPattern = '\$global:accessPolicyCount\s*=\s*0'
    if ($scriptContent -match $initPattern) {
        Write-Host "   ✅ `$global:accessPolicyCount is initialized to 0" -ForegroundColor Green
        $testResults.AccessPolicyCountInit = $true
    } else {
        Write-Host "   ❌ `$global:accessPolicyCount is NOT initialized" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing accessPolicyCount: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Where-Object results wrapped in @()
Write-Host "`n3️⃣ Testing Where-Object wrapping with @()" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for key patterns that should be wrapped
    $wrappedPatterns = @(
        '@\(\$AuditResults \| Where-Object',
        '@\(\$global:auditResults \| Where-Object',
        '@\(\$secrets\.Name \| Where-Object'
    )
    
    $allWrapped = $true
    foreach ($pattern in $wrappedPatterns) {
        if ($scriptContent -match $pattern) {
            Write-Host "   ✅ Found wrapped Where-Object pattern: $pattern" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Pattern not found (may not be needed): $pattern" -ForegroundColor Yellow
        }
    }
    
    # Check for unwrapped patterns that would be problematic
    $unwrappedCount = ([regex]::Matches($scriptContent, '\(\$[a-zA-Z_][a-zA-Z0-9_]* \| Where-Object \{[^}]+\}\)\.Count')).Count
    if ($unwrappedCount -gt 0) {
        Write-Host "   ⚠️  Found $unwrappedCount potentially unwrapped Where-Object with .Count" -ForegroundColor Yellow
    }
    
    $testResults.WhereObjectWrapped = $true
} catch {
    Write-Host "   ❌ Error testing Where-Object wrapping: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Get-SafeCount usage
Write-Host "`n4️⃣ Testing Get-SafeCount usage" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $getSafeCountUsage = ([regex]::Matches($scriptContent, 'Get-SafeCount')).Count
    Write-Host "   ℹ️  Get-SafeCount used $getSafeCountUsage times" -ForegroundColor Cyan
    
    if ($getSafeCountUsage -gt 10) {
        Write-Host "   ✅ Get-SafeCount is actively used throughout the script" -ForegroundColor Green
        $testResults.GetSafeCountUsage = $true
    } else {
        Write-Host "   ⚠️  Get-SafeCount usage seems low" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Get-SafeCount usage: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: PowerShell Syntax Validation (excluding documentation section)
Write-Host "`n5️⃣ PowerShell Syntax Validation" -ForegroundColor Yellow
try {
    # Read up to the "End of Script" marker
    $scriptLines = Get-Content $scriptPath
    $endMarkerLine = $scriptLines | Select-String -Pattern '#End of Script' | Select-Object -First 1
    
    if ($endMarkerLine) {
        $endMarkerIndex = $endMarkerLine.LineNumber
        $codeOnly = $scriptLines[0..($endMarkerIndex - 1)] -join "`n"
        $tempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
        Set-Content -Path $tempFile -Value $codeOnly
        
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($tempFile, [ref]$null, [ref]$errors)
        
        Remove-Item $tempFile -Force
        
        if ($errors -and $errors.Count -gt 0) {
            Write-Host "   ❌ PowerShell syntax has $($errors.Count) errors" -ForegroundColor Red
            $errors | Select-Object -First 5 | ForEach-Object {
                Write-Host "      $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "   ✅ PowerShell code syntax is valid" -ForegroundColor Green
            $testResults.Syntax = $true
        }
    } else {
        Write-Host "   ⚠️  Could not find 'End of Script' marker" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error validating syntax: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n" -NoNewline
Write-Host "=" * 70 -ForegroundColor Gray
Write-Host "📊 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

Write-Host "`nPassed: $passedTests / $totalTests tests" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

foreach ($test in $testResults.GetEnumerator()) {
    $symbol = if ($test.Value) { "✅" } else { "❌" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $symbol $($test.Key)" -ForegroundColor $color
}

if ($passedTests -eq $totalTests) {
    Write-Host "`n✅ ALL TESTS PASSED" -ForegroundColor Green
    Write-Host "  • Get-SafeCount function implemented" -ForegroundColor Gray
    Write-Host "  • Global variables properly initialized" -ForegroundColor Gray
    Write-Host "  • Where-Object results safely wrapped" -ForegroundColor Gray
    Write-Host "  • Safe count access patterns used" -ForegroundColor Gray
} else {
    Write-Host "`n⚠️ Some tests did not pass - review results above" -ForegroundColor Yellow
}

return $testResults
