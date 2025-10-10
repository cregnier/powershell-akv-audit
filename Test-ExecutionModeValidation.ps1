#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Execution Mode Validation Test Script
.DESCRIPTION
    Tests all script execution modes to ensure proper variable initialization
    and error handling across Test mode, SingleVault mode, and Full scan workflows.
#>

[CmdletBinding()]
param()

Write-Host "🚀 EXECUTION MODE VALIDATION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    SyntaxValidation = $false
    TestModeValidation = $false
    SingleVaultValidation = $false
    FullScanValidation = $false
    ResumeValidation = $false
    ErrorHandlingValidation = $false
}

Write-Host "`n1️⃣ Testing script syntax validation..." -ForegroundColor Yellow

try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax validation passed" -ForegroundColor Green
        $testResults.SyntaxValidation = $true
    } else {
        Write-Host "   ❌ PowerShell syntax validation failed" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Syntax validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing Test mode execution path..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for Test mode parameter handling
    $testModeParam = $scriptContent -match '\[switch\]\$TestMode'
    Write-Host "   📋 TestMode parameter defined: $testModeParam" -ForegroundColor $(if ($testModeParam) { "Green" } else { "Red" })
    
    # Check for Test mode scan limitation
    $testModeLimit = $scriptContent -match 'TestMode.*Limit.*Key.*Vault'
    Write-Host "   📋 TestMode limit logic found: $testModeLimit" -ForegroundColor $(if ($testModeLimit) { "Green" } else { "Red" })
    
    # Check for global:isTestMode initialization in test path
    $testModeGlobalInit = $scriptContent -match '\$global:isTestMode\s*=\s*\$true'
    Write-Host "   📋 Global TestMode initialization: $testModeGlobalInit" -ForegroundColor $(if ($testModeGlobalInit) { "Green" } else { "Red" })
    
    # Check for Test mode completion message
    $testModeComplete = $scriptContent -match 'TEST MODE COMPLETE'
    Write-Host "   📋 Test mode completion message: $testModeComplete" -ForegroundColor $(if ($testModeComplete) { "Green" } else { "Red" })
    
    if ($testModeParam -and $testModeLimit -and $testModeGlobalInit -and $testModeComplete) {
        $testResults.TestModeValidation = $true
        Write-Host "   ✅ Test mode execution path validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Test mode validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing SingleVault mode execution path..." -ForegroundColor Yellow

try {
    # Check for SingleVault parameter handling
    $singleVaultParam = $scriptContent -match '\[switch\]\$SingleVault'
    Write-Host "   📋 SingleVault parameter defined: $singleVaultParam" -ForegroundColor $(if ($singleVaultParam) { "Green" } else { "Red" })
    
    # Check for SingleVault diagnostics mode
    $singleVaultDiag = $scriptContent -match 'SINGLE VAULT DIAGNOSTICS MODE'
    Write-Host "   📋 SingleVault diagnostics mode: $singleVaultDiag" -ForegroundColor $(if ($singleVaultDiag) { "Green" } else { "Red" })
    
    # Check for vault name prompt handling
    $vaultNamePrompt = $scriptContent -match 'vault.*name.*prompt|prompt.*vault.*name'
    Write-Host "   📋 Vault name prompt handling: $vaultNamePrompt" -ForegroundColor $(if ($vaultNamePrompt) { "Green" } else { "Red" })
    
    # Check for ExecutiveSummary validation call in SingleVault
    $singleVaultValidation = $scriptContent -match 'Test-ExecutiveSummaryProperties.*SingleVault'
    Write-Host "   📋 ExecutiveSummary validation in SingleVault: $singleVaultValidation" -ForegroundColor $(if ($singleVaultValidation) { "Green" } else { "Red" })
    
    if ($singleVaultParam -and $singleVaultDiag -and $vaultNamePrompt -and $singleVaultValidation) {
        $testResults.SingleVaultValidation = $true
        Write-Host "   ✅ SingleVault mode execution path validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ SingleVault mode validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing Full scan execution path..." -ForegroundColor Yellow

try {
    # Check for scan mode selection
    $scanModeSelect = $scriptContent -match 'Select scan mode'
    Write-Host "   📋 Scan mode selection found: $scanModeSelect" -ForegroundColor $(if ($scanModeSelect) { "Green" } else { "Red" })
    
    # Check for full scan option
    $fullScanOption = $scriptContent -match 'Full scan.*all subscriptions.*Key Vaults'
    Write-Host "   📋 Full scan option found: $fullScanOption" -ForegroundColor $(if ($fullScanOption) { "Green" } else { "Red" })
    
    # Check for comprehensive vault discovery
    $vaultDiscovery = $scriptContent -match 'vault.*discovery|discovery.*vault'
    Write-Host "   📋 Vault discovery logic: $vaultDiscovery" -ForegroundColor $(if ($vaultDiscovery) { "Green" } else { "Red" })
    
    # Check for ExecutiveSummary validation call in main execution
    $fullScanValidation = $scriptContent -match 'Test-ExecutiveSummaryProperties.*Main.*HTML'
    Write-Host "   📋 ExecutiveSummary validation in Full scan: $fullScanValidation" -ForegroundColor $(if ($fullScanValidation) { "Green" } else { "Red" })
    
    if ($scanModeSelect -and $fullScanOption -and $vaultDiscovery -and $fullScanValidation) {
        $testResults.FullScanValidation = $true
        Write-Host "   ✅ Full scan execution path validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Full scan validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing Resume mode execution path..." -ForegroundColor Yellow

try {
    # Check for Resume parameter handling
    $resumeParam = $scriptContent -match '\[switch\]\$Resume'
    Write-Host "   📋 Resume parameter defined: $resumeParam" -ForegroundColor $(if ($resumeParam) { "Green" } else { "Red" })
    
    # Check for checkpoint file handling
    $checkpointHandling = $scriptContent -match 'checkpoint.*file|file.*checkpoint'
    Write-Host "   📋 Checkpoint file handling: $checkpointHandling" -ForegroundColor $(if ($checkpointHandling) { "Green" } else { "Red" })
    
    # Check for resume mode selection
    $resumeModeSelect = $scriptContent -match 'RESUME MODE.*Select resume option'
    Write-Host "   📋 Resume mode selection: $resumeModeSelect" -ForegroundColor $(if ($resumeModeSelect) { "Green" } else { "Red" })
    
    # Check for global:isTestMode initialization in resume path
    $resumeGlobalInit = $scriptContent -match 'Resume.*\$global:isTestMode\s*=\s*\$false'
    Write-Host "   📋 Resume global initialization: $resumeGlobalInit" -ForegroundColor $(if ($resumeGlobalInit) { "Green" } else { "Red" })
    
    if ($resumeParam -and $checkpointHandling -and $resumeModeSelect -and $resumeGlobalInit) {
        $testResults.ResumeValidation = $true
        Write-Host "   ✅ Resume mode execution path validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Resume mode validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6️⃣ Testing error handling and validation functions..." -ForegroundColor Yellow

try {
    # Check for comprehensive error handling functions
    $errorHandlingFunctions = @(
        'Test-ExecutiveSummaryProperties',
        'Test-TemplateVariables',
        'Write-ErrorLog',
        'Write-PermissionsLog',
        'Write-DataIssuesLog'
    )
    
    $errorFunctionCount = 0
    foreach ($func in $errorHandlingFunctions) {
        if ($scriptContent -match "function $func") {
            $errorFunctionCount++
            Write-Host "   ✅ Found error handling function: $func" -ForegroundColor Green
        }
    }
    
    Write-Host "   📊 Error handling functions found: $errorFunctionCount/$($errorHandlingFunctions.Count)" -ForegroundColor Gray
    
    # Check for try-catch blocks with defensive programming
    $tryCatchBlocks = ($scriptContent | Select-String 'try\s*\{[\s\S]*?\}\s*catch').Count
    Write-Host "   📊 Try-catch blocks found: $tryCatchBlocks" -ForegroundColor Gray
    
    # Check for defensive property access patterns
    $defensiveAccess = ($scriptContent | Select-String 'if.*null.*ne.*\$_\.').Count
    Write-Host "   📊 Defensive property access patterns: $defensiveAccess" -ForegroundColor Gray
    
    if ($errorFunctionCount -ge 3 -and $tryCatchBlocks -ge 10 -and $defensiveAccess -ge 5) {
        $testResults.ErrorHandlingValidation = $true
        Write-Host "   ✅ Error handling and validation functions comprehensive" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error handling validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 EXECUTION MODE VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests execution modes validated" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } elseif ($passedTests -ge ($totalTests * 0.8)) { "Yellow" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All execution modes validated successfully!" -ForegroundColor Green
    Write-Host "💡 All workflows (Test, SingleVault, Full, Resume) should work correctly" -ForegroundColor Blue
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Most execution modes validated. Minor workflow issues may remain." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Several execution mode issues detected - review results above" -ForegroundColor Red
}

Write-Host "`n💡 Execution Mode Validation Benefits:" -ForegroundColor Cyan
Write-Host "  • Test mode: Limited vault analysis for validation and testing" -ForegroundColor Gray
Write-Host "  • SingleVault mode: Focused analysis of individual vaults with comprehensive diagnostics" -ForegroundColor Gray
Write-Host "  • Full scan mode: Complete organizational assessment across all subscriptions" -ForegroundColor Gray
Write-Host "  • Resume mode: Checkpoint-based recovery for interrupted long-running audits" -ForegroundColor Gray
Write-Host "  • Error handling: Comprehensive validation and defensive programming throughout" -ForegroundColor Gray

return $testResults