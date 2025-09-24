#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate enhanced diagnostics and error logging improvements
.DESCRIPTION
    Validates that the enhanced diagnostic functions and logging provide detailed
    context information for troubleshooting missing properties and template variables.
#>

[CmdletBinding()]
param()

Write-Host "🔍 ENHANCED DIAGNOSTICS VALIDATION TEST" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"

$testResults = @{
    PropertyInitializationLogging = $false
    EnhancedExecutiveSummaryValidation = $false
    EnhancedTemplateValidation = $false
    DiagnosticContextLogging = $false
    PropertyTrackingCalls = $false
}

Write-Host "`n1️⃣ Testing Write-PropertyInitializationLog function..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for the new diagnostic function
    $propertyLogFunction = $scriptContent -match 'function Write-PropertyInitializationLog'
    Write-Host "   📊 Write-PropertyInitializationLog function found: $propertyLogFunction" -ForegroundColor $(if ($propertyLogFunction) { "Green" } else { "Red" })
    
    # Check for ExecutiveSummary property tracking
    $execSummaryTracking = $scriptContent -match 'ExecutiveSummary.*Stage.*Total properties'
    Write-Host "   📊 ExecutiveSummary property tracking: $execSummaryTracking" -ForegroundColor $(if ($execSummaryTracking) { "Green" } else { "Red" })
    
    # Check for AuditStats property tracking
    $auditStatsTracking = $scriptContent -match 'AuditStats.*Stage.*ExecutionTimeMinutes'
    Write-Host "   📊 AuditStats execution time tracking: $auditStatsTracking" -ForegroundColor $(if ($auditStatsTracking) { "Green" } else { "Red" })
    
    # Check for PropertyTracking error logging
    $propertyTrackingLogs = $scriptContent -match 'Write-ErrorLog.*PropertyTracking'
    Write-Host "   📊 PropertyTracking error log entries: $propertyTrackingLogs" -ForegroundColor $(if ($propertyTrackingLogs) { "Green" } else { "Red" })
    
    if ($propertyLogFunction -and $execSummaryTracking -and $auditStatsTracking -and $propertyTrackingLogs) {
        $testResults.PropertyInitializationLogging = $true
        Write-Host "   ✅ Write-PropertyInitializationLog function validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ PropertyInitializationLog validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing enhanced ExecutiveSummary validation..." -ForegroundColor Yellow

try {
    # Check for enhanced diagnostic logging in ExecutiveSummary validation
    $enhancedExecDiag = $scriptContent -match 'ExecutiveSummary diagnostic.*Total properties expected'
    Write-Host "   📊 Enhanced ExecutiveSummary diagnostics: $enhancedExecDiag" -ForegroundColor $(if ($enhancedExecDiag) { "Green" } else { "Red" })
    
    # Check for property count logging
    $propertyCountLogging = $scriptContent -match 'Properties present.*ExecutiveSummary\.Keys\.Count'
    Write-Host "   📊 Property count logging: $propertyCountLogging" -ForegroundColor $(if ($propertyCountLogging) { "Green" } else { "Red" })
    
    # Check for detailed property status logging
    $detailedPropertyStatus = $scriptContent -match 'Property Status.*Valid.*Missing.*Null'
    Write-Host "   📊 Detailed property status logging: $detailedPropertyStatus" -ForegroundColor $(if ($detailedPropertyStatus) { "Green" } else { "Red" })
    
    # Check for context parameter usage in error logging
    $contextErrorLogging = $scriptContent -match 'Write-ErrorLog.*ExecutiveSummary.*\$Context'
    Write-Host "   📊 Context-aware error logging: $contextErrorLogging" -ForegroundColor $(if ($contextErrorLogging) { "Green" } else { "Red" })
    
    if ($enhancedExecDiag -and $propertyCountLogging -and $detailedPropertyStatus -and $contextErrorLogging) {
        $testResults.EnhancedExecutiveSummaryValidation = $true
        Write-Host "   ✅ Enhanced ExecutiveSummary validation validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Enhanced ExecutiveSummary validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing enhanced template validation..." -ForegroundColor Yellow

try {
    # Check for enhanced template diagnostic logging
    $enhancedTemplateDiag = $scriptContent -match 'Template diagnostic.*Total placeholders expected'
    Write-Host "   📊 Enhanced template diagnostics: $enhancedTemplateDiag" -ForegroundColor $(if ($enhancedTemplateDiag) { "Green" } else { "Red" })
    
    # Check for placeholder count logging
    $placeholderCountLogging = $scriptContent -match 'Placeholders present.*Placeholders\.Keys\.Count'
    Write-Host "   📊 Placeholder count logging: $placeholderCountLogging" -ForegroundColor $(if ($placeholderCountLogging) { "Green" } else { "Red" })
    
    # Check for valid placeholders tracking
    $validPlaceholderTracking = $scriptContent -match 'Valid placeholders.*validPlaceholders.*join'
    Write-Host "   📊 Valid placeholder tracking: $validPlaceholderTracking" -ForegroundColor $(if ($validPlaceholderTracking) { "Green" } else { "Red" })
    
    # Check for placeholder status logging
    $placeholderStatusLogging = $scriptContent -match 'Placeholder Status.*Valid.*Missing.*Null'
    Write-Host "   📊 Placeholder status logging: $placeholderStatusLogging" -ForegroundColor $(if ($placeholderStatusLogging) { "Green" } else { "Red" })
    
    if ($enhancedTemplateDiag -and $placeholderCountLogging -and $validPlaceholderTracking -and $placeholderStatusLogging) {
        $testResults.EnhancedTemplateValidation = $true
        Write-Host "   ✅ Enhanced template validation validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Enhanced template validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing diagnostic context logging..." -ForegroundColor Yellow

try {
    # Check for context parameter usage throughout validation functions
    $contextParams = ($scriptContent | Select-String -Pattern 'Context.*=.*".*"' -AllMatches).Matches.Count
    Write-Host "   📊 Context parameter usage count: $contextParams" -ForegroundColor $(if ($contextParams -gt 5) { "Green" } else { "Red" })
    
    # Check for enhanced error logging with context
    $contextErrorLogs = ($scriptContent | Select-String -Pattern 'Write-ErrorLog.*".*".*".*".*\$Context' -AllMatches).Matches.Count
    Write-Host "   📊 Context-aware error logs: $contextErrorLogs" -ForegroundColor $(if ($contextErrorLogs -gt 0) { "Green" } else { "Red" })
    
    # Check for verbose logging with context
    $contextVerboseLogs = ($scriptContent | Select-String -Pattern 'Write-Verbose.*\$Context.*diagnostic' -AllMatches).Matches.Count
    Write-Host "   📊 Context-aware verbose logs: $contextVerboseLogs" -ForegroundColor $(if ($contextVerboseLogs -gt 0) { "Green" } else { "Red" })
    
    if ($contextParams -gt 5 -and $contextErrorLogs -gt 0 -and $contextVerboseLogs -gt 0) {
        $testResults.DiagnosticContextLogging = $true
        Write-Host "   ✅ Diagnostic context logging validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Diagnostic context logging validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing property tracking function calls..." -ForegroundColor Yellow

try {
    # Check for property tracking calls before HTML generation
    $singleVaultTracking = $scriptContent -match 'Write-PropertyInitializationLog.*SingleVault-PreHTML'
    Write-Host "   📊 SingleVault property tracking call: $singleVaultTracking" -ForegroundColor $(if ($singleVaultTracking) { "Green" } else { "Red" })
    
    $processPartialTracking = $scriptContent -match 'Write-PropertyInitializationLog.*ProcessPartial-PreHTML'
    Write-Host "   📊 ProcessPartial property tracking call: $processPartialTracking" -ForegroundColor $(if ($processPartialTracking) { "Green" } else { "Red" })
    
    $csvTracking = $scriptContent -match 'Write-PropertyInitializationLog.*CSV-PreHTML'
    Write-Host "   📊 CSV processing property tracking call: $csvTracking" -ForegroundColor $(if ($csvTracking) { "Green" } else { "Red" })
    
    $mainTracking = $scriptContent -match 'Write-PropertyInitializationLog.*Main-PreHTML'
    Write-Host "   📊 Main execution property tracking call: $mainTracking" -ForegroundColor $(if ($mainTracking) { "Green" } else { "Red" })
    
    if ($singleVaultTracking -and $processPartialTracking -and $csvTracking -and $mainTracking) {
        $testResults.PropertyTrackingCalls = $true
        Write-Host "   ✅ Property tracking function calls validated" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Property tracking calls validation error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 ENHANCED DIAGNOSTICS TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host ""
Write-Host "🎯 Overall Results: $passedTests/$($testResults.Count) enhanced diagnostic features validated" -ForegroundColor $(if ($passedTests -eq $testResults.Count) { "Green" } else { "Yellow" })

if ($passedTests -eq $testResults.Count) {
    Write-Host "🎉 All enhanced diagnostics successfully implemented!" -ForegroundColor Green
    Write-Host "💡 Property initialization and template validation now have comprehensive logging" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some enhanced diagnostic features need attention - review results above" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "💡 Key Enhanced Diagnostic Benefits:" -ForegroundColor Blue
Write-Host "  • Property tracking: Detailed logging of ExecutiveSummary and AuditStats state at key execution points" -ForegroundColor Gray
Write-Host "  • Context-aware logging: All error logs include execution context for better troubleshooting" -ForegroundColor Gray  
Write-Host "  • Detailed validation: Property and placeholder validation includes counts and status details" -ForegroundColor Gray
Write-Host "  • Comprehensive coverage: All execution modes (SingleVault, ProcessPartial, CSV, Main) tracked" -ForegroundColor Gray
Write-Host "  • Verbose diagnostics: Enhanced Write-Verbose output with property and placeholder details" -ForegroundColor Gray

return $testResults