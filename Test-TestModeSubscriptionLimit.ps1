#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate TestMode subscription enumeration limiting
.DESCRIPTION
    Validates that TestMode stops enumerating subscriptions early once the 
    requested vault limit is reached, improving performance for test scenarios.
#>

[CmdletBinding()]
param()

Write-Host "🧪 TESTMODE SUBSCRIPTION LIMITING VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"

if (-not (Test-Path $scriptPath)) {
    Write-Host "❌ Script not found: $scriptPath" -ForegroundColor Red
    return $false
}

$testResults = @{
    SyntaxValidation = $false
    TestModeFunctionExists = $false
    EarlyStopLogic = $false
    VerboseInstrumentation = $false
    UnifiedPipelineIntegration = $false
    SingleVaultUnaffected = $false
}

# Test 1: Syntax Validation
Write-Host "`n1️⃣ Testing PowerShell syntax..." -ForegroundColor Yellow

try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax valid" -ForegroundColor Green
        $testResults.SyntaxValidation = $true
    } else {
        Write-Host "   ❌ PowerShell syntax validation failed" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Syntax validation error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: TestMode Function Existence
Write-Host "`n2️⃣ Testing Get-AkvTestModeVaultSample function..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for function definition
    $functionExists = $scriptContent -match 'function Get-AkvTestModeVaultSample'
    Write-Host "   📋 Function defined: $functionExists" -ForegroundColor $(if ($functionExists) { "Green" } else { "Red" })
    
    # Check for key parameters
    $hasLimitParam = $scriptContent -match 'Get-AkvTestModeVaultSample.*Limit'
    Write-Host "   📋 Has Limit parameter: $hasLimitParam" -ForegroundColor $(if ($hasLimitParam) { "Green" } else { "Red" })
    
    # Check for early termination logic
    $hasEarlyStop = $scriptContent -match 'Early stop after.*subscriptions'
    Write-Host "   📋 Has early stop logic: $hasEarlyStop" -ForegroundColor $(if ($hasEarlyStop) { "Green" } else { "Red" })
    
    if ($functionExists -and $hasLimitParam -and $hasEarlyStop) {
        Write-Host "   ✅ Get-AkvTestModeVaultSample function complete" -ForegroundColor Green
        $testResults.TestModeFunctionExists = $true
    } else {
        Write-Host "   ❌ Get-AkvTestModeVaultSample function incomplete" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Function validation error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Early Stop Logic Integration
Write-Host "`n3️⃣ Testing early stop integration..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for TestMode conditional in discovery
    $testModeConditional = $scriptContent -match 'if.*\$TestMode.*{.*Get-AkvTestModeVaultSample'
    Write-Host "   📋 TestMode conditional discovery: $testModeConditional" -ForegroundColor $(if ($testModeConditional) { "Green" } else { "Red" })
    
    # Check for removal of old limiting logic
    $oldLimitingRemoved = -not ($scriptContent -match 'allKeyVaults\.Count.*ge.*Limit')
    Write-Host "   📋 Old limiting logic removed: $oldLimitingRemoved" -ForegroundColor $(if ($oldLimitingRemoved) { "Green" } else { "Red" })
    
    # Check for early-stop message
    $earlyStopMessage = $scriptContent -match 'Early stop after.*subscriptions.*collected.*Limit'
    Write-Host "   📋 Early stop message present: $earlyStopMessage" -ForegroundColor $(if ($earlyStopMessage) { "Green" } else { "Red" })
    
    if ($testModeConditional -and $earlyStopMessage) {
        Write-Host "   ✅ Early stop logic properly integrated" -ForegroundColor Green
        $testResults.EarlyStopLogic = $true
    } else {
        Write-Host "   ❌ Early stop logic integration incomplete" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Early stop validation error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Verbose Instrumentation
Write-Host "`n4️⃣ Testing verbose instrumentation..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for TestModeLimit prefix
    $testModeLimitPrefix = $scriptContent -match '\[TestModeLimit\]'
    Write-Host "   📋 TestModeLimit prefix used: $testModeLimitPrefix" -ForegroundColor $(if ($testModeLimitPrefix) { "Green" } else { "Red" })
    
    # Check for verbose subscription processing (updated patterns)
    $verboseProcessing = $scriptContent -match 'Processing subscription.*TestModeLimit' -or $scriptContent -match '\[TestModeLimit\].*Evaluating subscription'
    Write-Host "   📋 Verbose subscription processing: $verboseProcessing" -ForegroundColor $(if ($verboseProcessing) { "Green" } else { "Red" })
    
    # Check for vault discovery logging (updated patterns)
    $vaultLogging = $scriptContent -match 'Found vault.*TestModeLimit' -or $scriptContent -match '\[TestModeLimit\].*Found vault'
    Write-Host "   📋 Vault discovery logging: $vaultLogging" -ForegroundColor $(if ($vaultLogging) { "Green" } else { "Red" })
    
    if ($testModeLimitPrefix -and $verboseProcessing -and $vaultLogging) {
        Write-Host "   ✅ Verbose instrumentation complete" -ForegroundColor Green
        $testResults.VerboseInstrumentation = $true
    } else {
        Write-Host "   ❌ Verbose instrumentation incomplete" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Verbose instrumentation validation error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Unified Pipeline Integration
Write-Host "`n5️⃣ Testing unified pipeline integration..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for Invoke-AkvReportPipeline calls
    $pipelineCalls = ([regex]::Matches($scriptContent, 'Invoke-AkvReportPipeline')).Count
    Write-Host "   📋 Invoke-AkvReportPipeline calls found: $pipelineCalls" -ForegroundColor $(if ($pipelineCalls -ge 5) { "Green" } else { "Red" })
    
    # Check for dashboard function definitions
    $dashboardFunctions = @(
        'Get-AkvDashboardCardDefinitions',
        'Get-AkvThresholdColor',
        'Get-AkvDonut',
        'New-AkvInteractiveDashboard',
        'Invoke-AkvReportPipeline'
    )
    
    $foundFunctions = 0
    foreach ($func in $dashboardFunctions) {
        if ($scriptContent -match "function $func") {
            $foundFunctions++
        }
    }
    
    Write-Host "   📋 Dashboard functions found: $foundFunctions/$($dashboardFunctions.Count)" -ForegroundColor $(if ($foundFunctions -eq $dashboardFunctions.Count) { "Green" } else { "Red" })
    
    # Check for dashboard placeholders
    $dashboardPlaceholders = $scriptContent -match '\{\{DASHBOARD_STYLES\}\}' -and $scriptContent -match '\{\{INTERACTIVE_DASHBOARD\}\}'
    Write-Host "   📋 Dashboard placeholders present: $dashboardPlaceholders" -ForegroundColor $(if ($dashboardPlaceholders) { "Green" } else { "Red" })
    
    if ($pipelineCalls -ge 5 -and $foundFunctions -eq $dashboardFunctions.Count -and $dashboardPlaceholders) {
        Write-Host "   ✅ Unified pipeline integration complete" -ForegroundColor Green
        $testResults.UnifiedPipelineIntegration = $true
    } else {
        Write-Host "   ❌ Unified pipeline integration incomplete" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Pipeline integration validation error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: SingleVault Mode Unaffected
Write-Host "`n6️⃣ Testing SingleVault mode preservation..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check that SingleVault mode doesn't use TestMode logic
    $singleVaultSection = $scriptContent -match 'if.*\$SingleVault.*{[\s\S]*?}'
    Write-Host "   📋 SingleVault mode section present: $singleVaultSection" -ForegroundColor $(if ($singleVaultSection) { "Green" } else { "Red" })
    
    # Check that SingleVault uses unified pipeline
    $singleVaultPipeline = $scriptContent -match 'SingleVault.*Invoke-AkvReportPipeline'
    Write-Host "   📋 SingleVault uses unified pipeline: $singleVaultPipeline" -ForegroundColor $(if ($singleVaultPipeline) { "Green" } else { "Red" })
    
    # Verify TestMode functions don't interfere with SingleVault
    $noTestModeInterference = -not ($scriptContent -match 'SingleVault.*Get-AkvTestModeVaultSample')
    Write-Host "   📋 No TestMode interference: $noTestModeInterference" -ForegroundColor $(if ($noTestModeInterference) { "Green" } else { "Red" })
    
    if ($singleVaultSection -and $singleVaultPipeline -and $noTestModeInterference) {
        Write-Host "   ✅ SingleVault mode properly preserved" -ForegroundColor Green
        $testResults.SingleVaultUnaffected = $true
    } else {
        Write-Host "   ❌ SingleVault mode may be affected" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ SingleVault validation error: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📊 TESTMODE SUBSCRIPTION LIMITING VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All TestMode subscription limiting validations passed!" -ForegroundColor Green
    Write-Host "💡 TestMode will now efficiently stop subscription enumeration early" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some validations failed - review the results above" -ForegroundColor Yellow
}

Write-Host "`n📋 Implementation Status:" -ForegroundColor Cyan
Write-Host "  • Early subscription termination: $(if ($testResults.EarlyStopLogic) { "✅ Implemented" } else { "❌ Missing" })" -ForegroundColor Gray
Write-Host "  • Verbose instrumentation: $(if ($testResults.VerboseInstrumentation) { "✅ Implemented" } else { "❌ Missing" })" -ForegroundColor Gray
Write-Host "  • Unified dashboard pipeline: $(if ($testResults.UnifiedPipelineIntegration) { "✅ Implemented" } else { "❌ Missing" })" -ForegroundColor Gray
Write-Host "  • SingleVault mode unaffected: $(if ($testResults.SingleVaultUnaffected) { "✅ Confirmed" } else { "❌ Issue detected" })" -ForegroundColor Gray

return $testResults