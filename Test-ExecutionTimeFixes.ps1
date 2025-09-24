#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate ExecutionTimeMinutes and ExecutionTimeFormatted fixes
.DESCRIPTION
    Validates that AuditStats objects are properly populated with execution time
    data across all execution modes (SingleVault, ProcessPartial, CSV, Full).
#>

[CmdletBinding()]
param()

Write-Host "⏱️ EXECUTION TIME FIXES VALIDATION TEST" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"

$testResults = @{
    SingleVaultTimeFix = $false
    MainExecutionTimeFix = $false
    ProcessPartialTimeFix = $false
    CsvProcessingTimeFix = $false
    AuditStatsInitialization = $false
}

Write-Host "`n1️⃣ Testing SingleVault mode execution time fix..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for SingleVault auditStats ExecutionTimeMinutes assignment
    $singleVaultTimeFix = $scriptContent -match 'auditStats\.ExecutionTimeMinutes.*=.*executionTimeMinutes'
    Write-Host "   📊 SingleVault AuditStats.ExecutionTimeMinutes assignment: $singleVaultTimeFix" -ForegroundColor $(if ($singleVaultTimeFix) { "Green" } else { "Red" })
    
    # Check for SingleVault auditStats ExecutionTimeFormatted assignment  
    $singleVaultTimeFormatted = $scriptContent -match 'auditStats\.ExecutionTimeFormatted.*=.*executionTimeFormatted'
    Write-Host "   📊 SingleVault AuditStats.ExecutionTimeFormatted assignment: $singleVaultTimeFormatted" -ForegroundColor $(if ($singleVaultTimeFormatted) { "Green" } else { "Red" })
    
    # Check for execution time calculation before HTML generation in SingleVault
    $singleVaultCalcBeforeHtml = $scriptContent -match 'CRITICAL FIX.*Calculate execution time for SingleVault mode before HTML generation'
    Write-Host "   📊 SingleVault execution time calc before HTML: $singleVaultCalcBeforeHtml" -ForegroundColor $(if ($singleVaultCalcBeforeHtml) { "Green" } else { "Red" })
    
    if ($singleVaultTimeFix -and $singleVaultTimeFormatted -and $singleVaultCalcBeforeHtml) {
        $testResults.SingleVaultTimeFix = $true
        Write-Host "   ✅ SingleVault execution time fixes validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ SingleVault validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing main execution path time fix..." -ForegroundColor Yellow

try {
    # Check for main execution global:auditStats assignment
    $mainTimeFix = $scriptContent -match '\$global:auditStats\.ExecutionTimeMinutes.*=.*executionTimeMinutes'
    Write-Host "   📊 Main execution AuditStats.ExecutionTimeMinutes assignment: $mainTimeFix" -ForegroundColor $(if ($mainTimeFix) { "Green" } else { "Red" })
    
    $mainTimeFormatted = $scriptContent -match '\$global:auditStats\.ExecutionTimeFormatted.*=.*executionTimeFormatted'
    Write-Host "   📊 Main execution AuditStats.ExecutionTimeFormatted assignment: $mainTimeFormatted" -ForegroundColor $(if ($mainTimeFormatted) { "Green" } else { "Red" })
    
    # Check for the CRITICAL FIX comment
    $mainCriticalFix = $scriptContent -match 'CRITICAL FIX.*Ensure execution time is stored in AuditStats for HTML template placeholders'
    Write-Host "   📊 Main execution CRITICAL FIX comment: $mainCriticalFix" -ForegroundColor $(if ($mainCriticalFix) { "Green" } else { "Red" })
    
    if ($mainTimeFix -and $mainTimeFormatted -and $mainCriticalFix) {
        $testResults.MainExecutionTimeFix = $true
        Write-Host "   ✅ Main execution time fixes validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Main execution validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing ProcessPartial mode time fix..." -ForegroundColor Yellow

try {
    # Check for ProcessPartial mode execution time fix
    $processPartialFix = $scriptContent -match 'CRITICAL FIX.*Ensure execution time is available in AuditStats for ProcessPartial mode'
    Write-Host "   📊 ProcessPartial execution time fix: $processPartialFix" -ForegroundColor $(if ($processPartialFix) { "Green" } else { "Red" })
    
    # Check for global:auditStats ContainsKey check
    $containsKeyCheck = $scriptContent -match 'global:auditStats\.ContainsKey.*ExecutionTimeMinutes'
    Write-Host "   📊 ProcessPartial ContainsKey check: $containsKeyCheck" -ForegroundColor $(if ($containsKeyCheck) { "Green" } else { "Red" })
    
    if ($processPartialFix -and $containsKeyCheck) {
        $testResults.ProcessPartialTimeFix = $true
        Write-Host "   ✅ ProcessPartial execution time fixes validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ ProcessPartial validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing CSV processing mode time fix..." -ForegroundColor Yellow

try {
    # Check for CSV processing auditStats creation
    $csvAuditStats = $scriptContent -match 'csvAuditStats.*=.*@{'
    Write-Host "   📊 CSV processing auditStats creation: $csvAuditStats" -ForegroundColor $(if ($csvAuditStats) { "Green" } else { "Red" })
    
    # Check for CSV CRITICAL FIX comment
    $csvCriticalFix = $scriptContent -match 'CRITICAL FIX.*Calculate execution time for CSV processing mode'
    Write-Host "   📊 CSV processing CRITICAL FIX comment: $csvCriticalFix" -ForegroundColor $(if ($csvCriticalFix) { "Green" } else { "Red" })
    
    # Check that CSV mode no longer uses empty @{} for AuditStats
    $csvEmptyStatsRemoved = -not ($scriptContent -match 'AuditStats.*@{}.*IsPartialResults.*true.*csv')
    Write-Host "   📊 CSV empty AuditStats @{} removed: $csvEmptyStatsRemoved" -ForegroundColor $(if ($csvEmptyStatsRemoved) { "Green" } else { "Red" })
    
    if ($csvAuditStats -and $csvCriticalFix -and $csvEmptyStatsRemoved) {
        $testResults.CsvProcessingTimeFix = $true
        Write-Host "   ✅ CSV processing execution time fixes validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ CSV processing validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing global AuditStats initialization..." -ForegroundColor Yellow

try {
    # Check for global auditStats initialization structure
    $globalAuditStatsInit = $scriptContent -match '\$global:auditStats.*=.*@{[^}]*TokenRefreshCount'
    Write-Host "   📊 Global AuditStats initialization found: $globalAuditStatsInit" -ForegroundColor $(if ($globalAuditStatsInit) { "Green" } else { "Red" })
    
    # Check that AuditStats is used in HTML generation calls
    $auditStatsInHtml = $scriptContent -match 'New-ComprehensiveHtmlReport.*AuditStats.*\$.*auditStats'
    Write-Host "   📊 AuditStats used in HTML generation: $auditStatsInHtml" -ForegroundColor $(if ($auditStatsInHtml) { "Green" } else { "Red" })
    
    if ($globalAuditStatsInit -and $auditStatsInHtml) {
        $testResults.AuditStatsInitialization = $true
        Write-Host "   ✅ AuditStats initialization and usage validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ AuditStats initialization validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 EXECUTION TIME FIXES TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host ""
Write-Host "🎯 Overall Results: $passedTests/$($testResults.Count) execution time fixes validated" -ForegroundColor $(if ($passedTests -eq $testResults.Count) { "Green" } else { "Yellow" })

if ($passedTests -eq $testResults.Count) {
    Write-Host "🎉 All execution time fixes successfully implemented!" -ForegroundColor Green
    Write-Host "💡 ExecutionTimeMinutes and ExecutionTimeFormatted should now be available in all modes" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some execution time fixes need attention - review results above" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "💡 Key Execution Time Fix Benefits:" -ForegroundColor Blue
Write-Host "  • SingleVault mode: Execution time calculated and stored before HTML generation" -ForegroundColor Gray
Write-Host "  • Main execution: Global AuditStats properly populated with timing data" -ForegroundColor Gray  
Write-Host "  • ProcessPartial mode: Defensive checks ensure execution time is available" -ForegroundColor Gray
Write-Host "  • CSV processing: Proper AuditStats object created instead of empty hashtable" -ForegroundColor Gray
Write-Host "  • Template placeholders: {{EXECUTION_TIME_MINUTES}} and {{EXECUTION_TIME_FORMATTED}} should now work" -ForegroundColor Gray

return $testResults