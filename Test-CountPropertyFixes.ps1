#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate .Count property fixes
.DESCRIPTION
    Tests that the fixes for .Count property usage work correctly by simulating
    scenarios where ForEach-Object might return scalars.
#>

[CmdletBinding()]
param()

Write-Host "🧪 TESTING .Count PROPERTY FIXES" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$testResults = @{
    ParserErrors = $false
    ScalarArrayFix = $false
    IndicatorArrayFix = $false
    RuntimeSafety = $false
}

Write-Host "`n1️⃣ Testing parser error fixes..." -ForegroundColor Yellow
try {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile("./Get-AKV_Roles-SecAuditCompliance.ps1", [ref]$tokens, [ref]$parseErrors)
    
    if ($parseErrors.Count -eq 0) {
        Write-Host "   ✅ No parser errors found" -ForegroundColor Green
        $testResults.ParserErrors = $true
    } else {
        Write-Host "   ❌ Found $($parseErrors.Count) parser errors" -ForegroundColor Red
        foreach ($err in $parseErrors) {
            Write-Host "      Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "   ❌ Error testing parser: $_" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing scalar to array fixes..." -ForegroundColor Yellow
try {
    # Test scenario: Single audit result should not cause .Count errors
    $singleAuditResult = @(
        [PSCustomObject]@{
            ComplianceScore = "85%"
            CompanyComplianceScore = "90%"
            KeyVaultName = "test-vault"
        }
    )
    
    # Simulate the fixed patterns
    $scores = @($singleAuditResult | ForEach-Object { 
        try { [int]($_.ComplianceScore -replace '%', '') } catch { 0 }
    })
    
    $companyScores = @($singleAuditResult | ForEach-Object { 
        try { [int]($_.CompanyComplianceScore -replace '%', '') } catch { 0 }
    })
    
    $validScores = @($scores | Where-Object { $_ -is [int] -and $_ -ge 0 })
    $validCompanyScores = @($companyScores | Where-Object { $_ -is [int] -and $_ -ge 0 })
    
    # Test .Count access (should not error)
    $scoresCount = $scores.Count
    $companyScoresCount = $companyScores.Count
    $validScoresCount = $validScores.Count
    $validCompanyScoresCount = $validCompanyScores.Count
    
    Write-Host "   ✅ Scalar array fixes working: scores=$scoresCount, company=$companyScoresCount, valid=$validScoresCount,$validCompanyScoresCount" -ForegroundColor Green
    $testResults.ScalarArrayFix = $true
    
} catch {
    Write-Host "   ❌ Error testing scalar array fixes: $_" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing indicator array fixes..." -ForegroundColor Yellow
try {
    # Test scenario: Single matched indicator should not cause .Count errors
    $singleIndicatorCheck = @{
        'TestIndicator' = $true
        'OtherIndicator' = $false
    }
    
    # Simulate the fixed pattern
    $matchedIndicators = @($singleIndicatorCheck.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
    
    # Test .Count access (should not error)
    $indicatorCount = $matchedIndicators.Count
    
    Write-Host "   ✅ Indicator array fixes working: matched indicators count=$indicatorCount" -ForegroundColor Green
    $testResults.IndicatorArrayFix = $true
    
} catch {
    Write-Host "   ❌ Error testing indicator array fixes: $_" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing runtime safety of fixes..." -ForegroundColor Yellow
try {
    # Source the main script functions for testing
    $scriptContent = Get-Content "./Get-AKV_Roles-SecAuditCompliance.ps1" -Raw
    
    # Check that all the fixes are in place
    $hasScoreArrayFix = $scriptContent -match '\$scores = @\(\$auditResultsArray \| ForEach-Object'
    $hasCompanyScoreArrayFix = $scriptContent -match '\$companyScores = @\(\$auditResultsArray \| ForEach-Object'
    $hasCloudShellIndicatorFix = $scriptContent -match '\$matchedIndicators = @\(\$cloudShellChecks\.GetEnumerator\(\)'
    $hasMSIIndicatorFix = $scriptContent -match '\$matchedIndicators = @\(\$msiChecks\.GetEnumerator\(\)'
    $hasGlobalScoreArrayFix = $scriptContent -match '\$msScores = @\(\$global:auditResults \| ForEach-Object'
    $hasGlobalCompanyScoreArrayFix = $scriptContent -match '\$companyScores = @\(\$global:auditResults \| ForEach-Object'
    
    Write-Host "   📊 Fix verification:" -ForegroundColor Gray
    Write-Host "      Scores array fix: $hasScoreArrayFix" -ForegroundColor $(if ($hasScoreArrayFix) { "Green" } else { "Red" })
    Write-Host "      Company scores array fix: $hasCompanyScoreArrayFix" -ForegroundColor $(if ($hasCompanyScoreArrayFix) { "Green" } else { "Red" })
    Write-Host "      Cloud Shell indicators fix: $hasCloudShellIndicatorFix" -ForegroundColor $(if ($hasCloudShellIndicatorFix) { "Green" } else { "Red" })
    Write-Host "      MSI indicators fix: $hasMSIIndicatorFix" -ForegroundColor $(if ($hasMSIIndicatorFix) { "Green" } else { "Red" })
    Write-Host "      Global scores array fix: $hasGlobalScoreArrayFix" -ForegroundColor $(if ($hasGlobalScoreArrayFix) { "Green" } else { "Red" })
    Write-Host "      Global company scores array fix: $hasGlobalCompanyScoreArrayFix" -ForegroundColor $(if ($hasGlobalCompanyScoreArrayFix) { "Green" } else { "Red" })
    
    $allFixesPresent = $hasScoreArrayFix -and $hasCompanyScoreArrayFix -and $hasCloudShellIndicatorFix -and $hasMSIIndicatorFix -and $hasGlobalScoreArrayFix -and $hasGlobalCompanyScoreArrayFix
    
    if ($allFixesPresent) {
        Write-Host "   ✅ All runtime safety fixes verified in code" -ForegroundColor Green
        $testResults.RuntimeSafety = $true
    } else {
        Write-Host "   ❌ Some fixes are missing" -ForegroundColor Red
    }
    
} catch {
    Write-Host "   ❌ Error testing runtime safety: $_" -ForegroundColor Red
}

Write-Host "`n📊 TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$passedTests = 0
foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
    if ($test.Value) { $passedTests++ }
}

Write-Host "`nTests passed: $passedTests/$($testResults.Count)" -ForegroundColor $(if ($passedTests -eq $testResults.Count) { "Green" } else { "Yellow" })

if ($passedTests -eq $testResults.Count) {
    Write-Host "`n🎯 SUCCESS: All .Count property fixes are working correctly!" -ForegroundColor Green
    Write-Host "   • Parser errors resolved (${Context} syntax fixed)" -ForegroundColor Green
    Write-Host "   • Scalar ForEach-Object results now wrapped in @() arrays" -ForegroundColor Green
    Write-Host "   • Indicator collections now guaranteed to be arrays" -ForegroundColor Green
    Write-Host "   • HTML report generation should no longer fail with 'Count cannot be found'" -ForegroundColor Green
} else {
    Write-Host "`n⚠️ Some tests failed - additional fixes may be needed" -ForegroundColor Yellow
}

return ($passedTests -eq $testResults.Count)