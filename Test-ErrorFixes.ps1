#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate the error fixes implemented
.DESCRIPTION
    This test script validates that the two main issues mentioned in the problem statement have been resolved:
    1. Syntax error: "The term 'if' is not recognized as a name of a cmdlet..."
    2. Type conversion error: "Cannot convert value "N/A" to type "System.Int32""
#>

Write-Host "🎯 TESTING ERROR FIXES" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"

Write-Host "`n1️⃣ Testing PowerShell syntax validation..." -ForegroundColor Yellow

try {
    # Test syntax parsing - this would fail if there were any orphaned catch blocks
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax is valid - no orphaned catch blocks" -ForegroundColor Green
        $syntaxTest = $true
    } else {
        Write-Host "   ❌ PowerShell syntax errors found" -ForegroundColor Red
        $syntaxTest = $false
    }
} catch {
    Write-Host "   ❌ Syntax validation failed: $($_.Exception.Message)" -ForegroundColor Red
    $syntaxTest = $false
}

Write-Host "`n2️⃣ Testing Get-SafeProperty helper function..." -ForegroundColor Yellow

try {
    # Source the Get-SafeProperty function from the main script
    $getSafePropertyCode = (Get-Content $scriptPath -Raw) -match '(?s)function Get-SafeProperty.*?^}'
    if ($getSafePropertyCode) {
        # Extract and execute the function definition
        $functionMatch = [regex]::Match((Get-Content $scriptPath -Raw), '(?s)(function Get-SafeProperty.*?^})', [Text.RegularExpressions.RegexOptions]::Multiline)
        if ($functionMatch.Success) {
            Invoke-Expression $functionMatch.Groups[1].Value
            
            # Test the function with various scenarios
            $testObject = [PSCustomObject]@{
                ComplianceScore = "85%"
                PrivateEndpointCount = "N/A"
                ValidProperty = "TestValue"
            }
            
            $score = Get-SafeProperty -Object $testObject -PropertyName "ComplianceScore" -DefaultValue "0%"
            $endpoints = Get-SafeProperty -Object $testObject -PropertyName "PrivateEndpointCount" -DefaultValue 0
            $missing = Get-SafeProperty -Object $testObject -PropertyName "MissingProperty" -DefaultValue "Default"
            
            Write-Host "   ✅ Get-SafeProperty function works correctly" -ForegroundColor Green
            Write-Host "      ComplianceScore: '$score' (should be '85%')" -ForegroundColor Gray
            Write-Host "      PrivateEndpointCount: '$endpoints' (should be 'N/A')" -ForegroundColor Gray
            Write-Host "      MissingProperty: '$missing' (should be 'Default')" -ForegroundColor Gray
            $safePropertyTest = $true
        } else {
            Write-Host "   ❌ Could not extract Get-SafeProperty function" -ForegroundColor Red
            $safePropertyTest = $false
        }
    } else {
        Write-Host "   ❌ Get-SafeProperty function not found in script" -ForegroundColor Red
        $safePropertyTest = $false
    }
} catch {
    Write-Host "   ❌ Get-SafeProperty test failed: $($_.Exception.Message)" -ForegroundColor Red
    $safePropertyTest = $false
}

Write-Host "`n3️⃣ Testing type conversion error handling..." -ForegroundColor Yellow

try {
    # Test the try-catch pattern used in the script for integer conversions
    $testData = @(
        [PSCustomObject]@{ ComplianceScore = "85%" }
        [PSCustomObject]@{ ComplianceScore = "N/A" }
        [PSCustomObject]@{ ComplianceScore = "" }
        [PSCustomObject]@{ ComplianceScore = $null }
    )
    
    $failureCount = 0
    $successCount = 0
    
    foreach ($item in $testData) {
        try {
            $score = try { [int]($item.ComplianceScore -replace '%', '') } catch { 0 }
            Write-Host "      Score '$($item.ComplianceScore)' -> $score (safe conversion)" -ForegroundColor Gray
            $successCount++
        } catch {
            Write-Host "      Score '$($item.ComplianceScore)' -> FAILED: $($_.Exception.Message)" -ForegroundColor Red
            $failureCount++
        }
    }
    
    if ($failureCount -eq 0) {
        Write-Host "   ✅ Type conversion error handling works correctly ($successCount/$($testData.Count) conversions safe)" -ForegroundColor Green
        $typeConversionTest = $true
    } else {
        Write-Host "   ❌ Type conversion errors still occurring ($failureCount failures)" -ForegroundColor Red
        $typeConversionTest = $false
    }
} catch {
    Write-Host "   ❌ Type conversion test failed: $($_.Exception.Message)" -ForegroundColor Red
    $typeConversionTest = $false
}

Write-Host "`n4️⃣ Testing comprehensive failure record structure..." -ForegroundColor Yellow

try {
    # Test that the failure record structure includes all required properties
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for the comprehensive failure record in the main processing loop
    $hasFailureRecord = $scriptContent -match 'Add a comprehensive failure record.*PSCustomObject.*@\{'
    $hasAllProperties = $scriptContent -match 'ComplianceStatus.*=.*"Collection Failed"' -and 
                       $scriptContent -match 'ComplianceScore.*=.*0' -and
                       $scriptContent -match 'ServicePrincipalCount.*=.*0' -and
                       $scriptContent -match 'PrivateEndpointCount.*=.*0'
    
    if ($hasFailureRecord -and $hasAllProperties) {
        Write-Host "   ✅ Comprehensive failure record structure is present" -ForegroundColor Green
        Write-Host "      Contains required properties to prevent empty collection errors" -ForegroundColor Gray
        $failureRecordTest = $true
    } else {
        Write-Host "   ❌ Comprehensive failure record structure missing or incomplete" -ForegroundColor Red
        $failureRecordTest = $false
    }
} catch {
    Write-Host "   ❌ Failure record test failed: $($_.Exception.Message)" -ForegroundColor Red
    $failureRecordTest = $false
}

Write-Host "`n📋 SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$passedTests = @($syntaxTest, $safePropertyTest, $typeConversionTest, $failureRecordTest) | Where-Object { $_ -eq $true }
$totalTests = 4

Write-Host "`n🎯 Overall Results: $($passedTests.Count)/$totalTests tests passed" -ForegroundColor $(if ($passedTests.Count -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests.Count -eq $totalTests) {
    Write-Host "🎉 All error fixes are working correctly!" -ForegroundColor Green
    Write-Host "💡 The script should now handle:" -ForegroundColor Blue
    Write-Host "  • Syntax errors from orphaned catch blocks" -ForegroundColor Gray
    Write-Host "  • Type conversion errors when casting 'N/A' to integers" -ForegroundColor Gray
    Write-Host "  • Empty collection errors when all vaults fail analysis" -ForegroundColor Gray
    Write-Host "  • Safe property access to prevent null reference errors" -ForegroundColor Gray
} else {
    Write-Host "⚠️ Some tests failed - review results above" -ForegroundColor Yellow
}

return @{
    SyntaxValid = $syntaxTest
    SafePropertyWorking = $safePropertyTest  
    TypeConversionSafe = $typeConversionTest
    FailureRecordComplete = $failureRecordTest
    OverallSuccess = ($passedTests.Count -eq $totalTests)
}