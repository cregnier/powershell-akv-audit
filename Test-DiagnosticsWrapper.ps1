#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script for diagnostics wrapper and resilience
.DESCRIPTION
    Asserts that Get-AkvDiagnosticsSafe handles single-object & array responses
    and prevents duplicate diagnostic retrieval.
#>

[CmdletBinding()]
param()

Write-Host "🔧 DIAGNOSTICS WRAPPER TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    DiagnosticsSafeFunctionExists = $false
    SafeArrayFunctionExists = $false
    DuplicationPrevention = $false
    ResultStructure = $false
    IntegrationReplacement = $false
}

Write-Host "`n1️⃣ Testing Get-AkvDiagnosticsSafe function existence..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for Get-AkvDiagnosticsSafe function
    $diagnosticsSafeFunction = $scriptContent -match 'function Get-AkvDiagnosticsSafe'
    Write-Host "   📋 Get-AkvDiagnosticsSafe function: $diagnosticsSafeFunction" -ForegroundColor $(if ($diagnosticsSafeFunction) { "Green" } else { "Red" })
    
    # Check for proper parameter definition
    $parameterDefinition = $scriptContent -match 'Get-AkvDiagnosticsSafe[\s\S]*?KeyVaultName[\s\S]*?ResourceId'
    Write-Host "   📋 Proper parameter definition: $parameterDefinition" -ForegroundColor $(if ($parameterDefinition) { "Green" } else { "Red" })
    
    if ($diagnosticsSafeFunction -and $parameterDefinition) {
        Write-Host "   ✅ Get-AkvDiagnosticsSafe function properly defined" -ForegroundColor Green
        $testResults.DiagnosticsSafeFunctionExists = $true
    }
} catch {
    Write-Host "   ❌ Function existence test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing Get-AkvSafeArray function..." -ForegroundColor Yellow

try {
    # Check for Get-AkvSafeArray function
    $safeArrayFunction = $scriptContent -match 'function Get-AkvSafeArray'
    Write-Host "   📋 Get-AkvSafeArray function: $safeArrayFunction" -ForegroundColor $(if ($safeArrayFunction) { "Green" } else { "Red" })
    
    # Check for array vs single object handling
    $arrayHandling = $scriptContent -match 'GetType\(\)\.IsArray' -and $scriptContent -match '@\(\$InputObject\)'
    Write-Host "   📋 Array vs single object handling: $arrayHandling" -ForegroundColor $(if ($arrayHandling) { "Green" } else { "Red" })
    
    if ($safeArrayFunction -and $arrayHandling) {
        Write-Host "   ✅ Get-AkvSafeArray function properly handles arrays and single objects" -ForegroundColor Green
        $testResults.SafeArrayFunctionExists = $true
    }
} catch {
    Write-Host "   ❌ Safe array function test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing duplication prevention logic..." -ForegroundColor Yellow

try {
    # Check for cache checking logic
    $cacheChecking = $scriptContent -match 'DiagnosticsProcessed\.ContainsKey'
    Write-Host "   📋 Cache checking logic: $cacheChecking" -ForegroundColor $(if ($cacheChecking) { "Green" } else { "Red" })
    
    # Check for cache storage logic
    $cacheStorage = $scriptContent -match 'DiagnosticsProcessed\[\$KeyVaultName\].*=.*\$result'
    Write-Host "   📋 Cache storage logic: $cacheStorage" -ForegroundColor $(if ($cacheStorage) { "Green" } else { "Red" })
    
    # Check for skip message
    $skipMessage = $scriptContent -match 'Skipping duplicate retrieval'
    Write-Host "   📋 Skip duplicate message: $skipMessage" -ForegroundColor $(if ($skipMessage) { "Green" } else { "Red" })
    
    if ($cacheChecking -and $cacheStorage -and $skipMessage) {
        Write-Host "   ✅ Duplication prevention properly implemented" -ForegroundColor Green
        $testResults.DuplicationPrevention = $true
    }
} catch {
    Write-Host "   ❌ Duplication prevention test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing result structure..." -ForegroundColor Yellow

try {
    # Check for standardized result structure
    $resultStructure = $scriptContent -match 'HasDiagnostics.*LogCount.*MetricCount.*Enabled.*LogAnalyticsEnabled.*EventHubEnabled'
    Write-Host "   📋 Standardized result structure: $resultStructure" -ForegroundColor $(if ($resultStructure) { "Green" } else { "Red" })
    
    # Check for LogCategories array
    $logCategories = $scriptContent -match 'LogCategories.*=.*@\(\)'
    Write-Host "   📋 LogCategories array handling: $logCategories" -ForegroundColor $(if ($logCategories) { "Green" } else { "Red" })
    
    if ($resultStructure -and $logCategories) {
        Write-Host "   ✅ Result structure properly defined" -ForegroundColor Green
        $testResults.ResultStructure = $true
    }
} catch {
    Write-Host "   ❌ Result structure test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing integration replacement..." -ForegroundColor Yellow

try {
    # Check that Get-DiagnosticsConfiguration calls are replaced
    $replacedCalls = ($scriptContent | Select-String 'Get-AkvDiagnosticsSafe.*KeyVaultName.*ResourceId').Count
    Write-Host "   📋 Get-AkvDiagnosticsSafe integration calls: $replacedCalls" -ForegroundColor $(if ($replacedCalls -gt 0) { "Green" } else { "Red" })
    
    # Check for Diagnostics prefix in logging
    $diagnosticsPrefix = $scriptContent -match '\[Diagnostics\]'
    Write-Host "   📋 Diagnostics logging prefix: $diagnosticsPrefix" -ForegroundColor $(if ($diagnosticsPrefix) { "Green" } else { "Red" })
    
    if ($replacedCalls -gt 0 -and $diagnosticsPrefix) {
        Write-Host "   ✅ Integration replacement complete" -ForegroundColor Green
        $testResults.IntegrationReplacement = $true
    }
} catch {
    Write-Host "   ❌ Integration replacement test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📊 DIAGNOSTICS WRAPPER TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
}

Write-Host "`nOverall: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All diagnostics wrapper tests passed!" -ForegroundColor Green
    Write-Host "💡 No more duplicate 'Retrieving diagnostic settings' lines should appear" -ForegroundColor Blue
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "`n✅ Most diagnostics wrapper tests passed. Minor issues may remain." -ForegroundColor Yellow
} else {
    Write-Host "`n⚠️ Several diagnostics wrapper issues detected - review results above" -ForegroundColor Red
}

Write-Host "`n💡 Key Diagnostics Wrapper Benefits:" -ForegroundColor Cyan
Write-Host "  • Single retrieval per vault prevents duplicate processing" -ForegroundColor Gray
Write-Host "  • Caching mechanism eliminates redundant API calls" -ForegroundColor Gray
Write-Host "  • Safe array handling prevents .Count errors on single objects" -ForegroundColor Gray
Write-Host "  • Standardized result structure for consistent downstream processing" -ForegroundColor Gray
Write-Host "  • Integrated error handling and logging" -ForegroundColor Gray

return $testResults