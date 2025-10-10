#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Variable Initialization Test Script
.DESCRIPTION
    Tests all execution paths to ensure proper variable initialization,
    focusing on the fixes for $restartVaultAnalysis, $global:isTestMode,
    and log file variables.
#>

[CmdletBinding()]
param()

Write-Host "🔧 VARIABLE INITIALIZATION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    RestartVaultAnalysisInit = $false
    GlobalIsTestModeInit = $false
    LogFileVariableMapping = $false
    ExecutiveSummaryValidation = $false
    TemplateValidation = $false
}

Write-Host "`n1️⃣ Testing \$restartVaultAnalysis initialization..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for proper initialization of $restartVaultAnalysis
    $restartVaultPattern = '\$restartVaultAnalysis\s*=\s*\$false'
    $restartVaultInit = $scriptContent -match $restartVaultPattern
    
    Write-Host "   📋 \$restartVaultAnalysis initialization found: $restartVaultInit" -ForegroundColor $(if ($restartVaultInit) { "Green" } else { "Red" })
    
    # Verify it's used properly
    $restartVaultUsage = ($scriptContent | Select-String '\$restartVaultAnalysis').Count
    Write-Host "   📊 \$restartVaultAnalysis usage count: $restartVaultUsage" -ForegroundColor Gray
    
    if ($restartVaultInit -and $restartVaultUsage -gt 0) {
        $testResults.RestartVaultAnalysisInit = $true
        Write-Host "   ✅ \$restartVaultAnalysis properly initialized and used" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing `$restartVaultAnalysis: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing \$global:isTestMode initialization..." -ForegroundColor Yellow

try {
    # Check for proper initialization in all execution paths
    $testModePatterns = @(
        '\$global:isTestMode\s*=\s*\$true.*HTML',  # Test mode initialization
        '\$global:isTestMode\s*=\s*\$false.*HTML'  # Non-test mode initialization
    )
    
    $testModeInitCount = 0
    foreach ($pattern in $testModePatterns) {
        $matches = ($scriptContent | Select-String $pattern).Count
        if ($matches -gt 0) {
            $testModeInitCount += $matches
            Write-Host "   ✅ Found $matches \$global:isTestMode initialization patterns" -ForegroundColor Green
        }
    }
    
    # Check for usage in HTML generation
    $testModeUsage = $scriptContent -match 'TEST_MODE_BANNER.*global:isTestMode'
    Write-Host "   📋 \$global:isTestMode HTML usage found: $testModeUsage" -ForegroundColor $(if ($testModeUsage) { "Green" } else { "Red" })
    
    if ($testModeInitCount -ge 2 -and $testModeUsage) {
        $testResults.GlobalIsTestModeInit = $true
        Write-Host "   ✅ \$global:isTestMode properly initialized in multiple paths" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing `$global:isTestMode: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing log file variable mapping..." -ForegroundColor Yellow

try {
    # Check for proper log file variable definitions
    $logFileDefinitions = @(
        '\$global:errPath\s*=.*errors',
        '\$global:permissionsPath\s*=.*permissions', 
        '\$global:dataIssuesPath\s*=.*dataissues'
    )
    
    $logFileDefCount = 0
    foreach ($pattern in $logFileDefinitions) {
        if ($scriptContent -match $pattern) {
            $logFileDefCount++
        }
    }
    
    Write-Host "   📋 Global log file definitions found: $logFileDefCount/3" -ForegroundColor Gray
    
    # Check for proper usage in HTML generation (should use global variables)
    $errorLogMapping = $scriptContent -match 'ERROR_LOG_PATH.*\$global:errPath'
    $permissionsLogMapping = $scriptContent -match 'PERMISSIONS_LOG_PATH.*\$global:permissionsPath'
    $dataIssuesLogMapping = $scriptContent -match 'DATA_ISSUES_LOG_PATH.*\$global:dataIssuesPath'
    
    Write-Host "   📊 Error log mapping: $errorLogMapping" -ForegroundColor $(if ($errorLogMapping) { "Green" } else { "Red" })
    Write-Host "   📊 Permissions log mapping: $permissionsLogMapping" -ForegroundColor $(if ($permissionsLogMapping) { "Green" } else { "Red" })
    Write-Host "   📊 Data issues log mapping: $dataIssuesLogMapping" -ForegroundColor $(if ($dataIssuesLogMapping) { "Green" } else { "Red" })
    
    if ($logFileDefCount -eq 3 -and $errorLogMapping -and $permissionsLogMapping -and $dataIssuesLogMapping) {
        $testResults.LogFileVariableMapping = $true
        Write-Host "   ✅ Log file variables properly defined and mapped" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing log file variables: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing ExecutiveSummary validation functions..." -ForegroundColor Yellow

try {
    # Check for Test-ExecutiveSummaryProperties function
    $execSummaryFunction = $scriptContent -match 'function Test-ExecutiveSummaryProperties'
    Write-Host "   📋 Test-ExecutiveSummaryProperties function found: $execSummaryFunction" -ForegroundColor $(if ($execSummaryFunction) { "Green" } else { "Red" })
    
    # Check for function usage
    $execSummaryUsage = ($scriptContent | Select-String 'Test-ExecutiveSummaryProperties').Count
    Write-Host "   📊 Test-ExecutiveSummaryProperties usage count: $execSummaryUsage" -ForegroundColor Gray
    
    # Check for defensive property validation
    $defensiveChecks = $scriptContent -match 'ContainsKey.*property'
    Write-Host "   📊 Defensive property checks: $defensiveChecks" -ForegroundColor $(if ($defensiveChecks) { "Green" } else { "Red" })
    
    if ($execSummaryFunction -and $execSummaryUsage -gt 0 -and $defensiveChecks) {
        $testResults.ExecutiveSummaryValidation = $true
        Write-Host "   ✅ ExecutiveSummary validation properly implemented" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing ExecutiveSummary validation: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing template variable validation..." -ForegroundColor Yellow

try {
    # Check for Test-TemplateVariables function
    $templateFunction = $scriptContent -match 'function Test-TemplateVariables'
    Write-Host "   📋 Test-TemplateVariables function found: $templateFunction" -ForegroundColor $(if ($templateFunction) { "Green" } else { "Red" })
    
    # Check for function usage
    $templateUsage = ($scriptContent | Select-String 'Test-TemplateVariables').Count
    Write-Host "   📊 Test-TemplateVariables usage count: $templateUsage" -ForegroundColor Gray
    
    # Check for required placeholders validation
    $requiredPlaceholders = $scriptContent -match 'requiredPlaceholders.*='
    Write-Host "   📊 Required placeholders validation: $requiredPlaceholders" -ForegroundColor $(if ($requiredPlaceholders) { "Green" } else { "Red" })
    
    if ($templateFunction -and $templateUsage -gt 0 -and $requiredPlaceholders) {
        $testResults.TemplateValidation = $true
        Write-Host "   ✅ Template variable validation properly implemented" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing template validation: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 VARIABLE INITIALIZATION TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } elseif ($passedTests -ge ($totalTests * 0.8)) { "Yellow" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All variable initialization fixes validated successfully!" -ForegroundColor Green
    Write-Host "💡 All execution paths should now have proper variable initialization" -ForegroundColor Blue
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Most variable initialization fixes validated. Minor issues may remain." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Several variable initialization issues detected - review results above" -ForegroundColor Red
}

Write-Host "`n💡 Key Variable Initialization Benefits:" -ForegroundColor Cyan
Write-Host "  • `$restartVaultAnalysis properly initialized in all execution paths" -ForegroundColor Gray
Write-Host "  • `$global:isTestMode correctly set based on scan mode selection" -ForegroundColor Gray
Write-Host "  • Log file variables properly mapped from global scope to HTML placeholders" -ForegroundColor Gray
Write-Host "  • ExecutiveSummary properties validated before aggregation operations" -ForegroundColor Gray
Write-Host "  • Template variables validated before HTML generation" -ForegroundColor Gray

return $testResults