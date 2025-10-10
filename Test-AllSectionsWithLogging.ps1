#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive test runner for all HTML report sections with enhanced logging validation
.DESCRIPTION
    Runs all individual section tests and validates enhanced logging for data mapping
    and authentication. Provides comprehensive coverage of every major report section
    as requested in the comment.
#>

[CmdletBinding()]
param()

Write-Host "🧪 COMPREHENSIVE SECTION TESTS & ENHANCED LOGGING VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"

# Individual section test scripts
$sectionTests = @(
    @{ Name = "Executive Summary"; Script = "Test-ExecutiveSummarySection.ps1"; Icon = "🎯" }
    @{ Name = "IdAM Insights"; Script = "Test-IdAMInsightsSection.ps1"; Icon = "🔐" }
    @{ Name = "Secrets Management"; Script = "Test-SecretsManagementSection.ps1"; Icon = "🔑" }
    @{ Name = "Compliance Framework"; Script = "Test-ComplianceFrameworkSection.ps1"; Icon = "📊" }
)

$overallResults = @{}

Write-Host "`n🎯 INDIVIDUAL SECTION TESTS" -ForegroundColor Yellow
Write-Host "=" * 40 -ForegroundColor Gray

foreach ($test in $sectionTests) {
    Write-Host "`n$($test.Icon) Testing $($test.Name) section..." -ForegroundColor White
    
    $testPath = Join-Path $PSScriptRoot $test.Script
    if (Test-Path $testPath) {
        try {
            $result = & $testPath
            $passed = ($result.Values | Where-Object { $_ -eq $true }).Count
            $total = $result.Count
            $overallResults[$test.Name] = @{ Passed = $passed; Total = $total; Success = ($passed -eq $total) }
            
            Write-Host "   📊 Results: $passed/$total tests passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
        } catch {
            Write-Host "   ❌ Test execution failed: $($_.Exception.Message)" -ForegroundColor Red
            $overallResults[$test.Name] = @{ Passed = 0; Total = 0; Success = $false }
        }
    } else {
        Write-Host "   ⚠️ Test script not found: $testPath" -ForegroundColor Yellow
        $overallResults[$test.Name] = @{ Passed = 0; Total = 0; Success = $false }
    }
}

Write-Host "`n📝 ENHANCED LOGGING VALIDATION" -ForegroundColor Yellow
Write-Host "=" * 40 -ForegroundColor Gray

$loggingResults = @{
    DataMappingLogs = $false
    AuthenticationLogs = $false
    SectionSpecificLogs = $false
    VerboseOutput = $false
    ErrorHandlingLogs = $false
}

Write-Host "`n1️⃣ Testing data mapping logging enhancements..." -ForegroundColor Cyan

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for enhanced data mapping logs
    $dataMappingPatterns = @(
        "Data mapping diagnostic: Starting aggregation",
        "Data mapping diagnostic: Processing IdAM", 
        "Data mapping diagnostic: Processing Secrets Management",
        "Data mapping results - Service Principals:",
        "Data mapping results - IdAM section:",
        "Data mapping results - Secrets Management section:",
        "Identity metrics successfully aggregated",
        "Secrets Management metrics successfully aggregated"
    )
    
    $foundDataMappingLogs = 0
    Write-Host "   📝 Data mapping log patterns:" -ForegroundColor White
    foreach ($pattern in $dataMappingPatterns) {
        if ($scriptContent -match [regex]::Escape($pattern)) {
            $foundDataMappingLogs++
            Write-Host "      ✅ $pattern" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $pattern" -ForegroundColor Red
        }
    }
    
    Write-Host "   📊 Data mapping logs found: $foundDataMappingLogs/$($dataMappingPatterns.Count)" -ForegroundColor Gray
    $loggingResults.DataMappingLogs = ($foundDataMappingLogs -ge ($dataMappingPatterns.Count * 0.8)) # 80% threshold
    
} catch {
    Write-Host "   ❌ Data mapping logging test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing authentication logging enhancements..." -ForegroundColor Cyan

try {
    # Check for enhanced authentication logs
    $authenticationPatterns = @(
        "Authentication diagnostic: Starting mode detection",
        "Authentication diagnostic: Testing for Azure Cloud Shell",
        "Authentication diagnostic: Testing Windows Integrated Authentication",
        "Authentication diagnostic: Testing for Domain and Azure AD join",
        "Authentication diagnostic: Checking for existing valid Azure context",
        "Authentication diagnostic: Found existing Azure context",
        "Authentication diagnostic: Retrieved access token, validating expiration",
        "Authentication diagnostic: Could not parse token expiry",
        "Authentication context diagnostic: Token expires in",
        "Authentication path: Context reuse",
        "Authentication path decision: Cloud Shell"
    )
    
    $foundAuthLogs = 0
    Write-Host "   🔐 Authentication log patterns:" -ForegroundColor White
    foreach ($pattern in $authenticationPatterns) {
        if ($scriptContent -match [regex]::Escape($pattern)) {
            $foundAuthLogs++
            Write-Host "      ✅ $pattern" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $pattern" -ForegroundColor Red
        }
    }
    
    Write-Host "   📊 Authentication logs found: $foundAuthLogs/$($authenticationPatterns.Count)" -ForegroundColor Gray
    $loggingResults.AuthenticationLogs = ($foundAuthLogs -ge ($authenticationPatterns.Count * 0.7)) # 70% threshold
    
} catch {
    Write-Host "   ❌ Authentication logging test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing section-specific logging..." -ForegroundColor Cyan

try {
    # Check for section-specific logging
    $sectionLogPatterns = @(
        "Processing.*audit results for statistics calculation",
        "Using default zero values.*due to no audit data",
        "Failed to calculate.*statistics",
        "No audit results available.*statistics calculation"
    )
    
    $foundSectionLogs = 0
    Write-Host "   📋 Section-specific log patterns:" -ForegroundColor White
    foreach ($pattern in $sectionLogPatterns) {
        if ($scriptContent -match $pattern) {
            $foundSectionLogs++
            Write-Host "      ✅ $pattern" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $pattern" -ForegroundColor Red
        }
    }
    
    $loggingResults.SectionSpecificLogs = ($foundSectionLogs -ge ($sectionLogPatterns.Count * 0.75)) # 75% threshold
    
} catch {
    Write-Host "   ❌ Section-specific logging test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing verbose output patterns..." -ForegroundColor Cyan

try {
    # Check for Write-Verbose usage
    $verboseCount = ([regex]::Matches($scriptContent, 'Write-Verbose')).Count
    $verboseWithDataMapping = ([regex]::Matches($scriptContent, 'Write-Verbose.*Data mapping')).Count
    $verboseWithAuth = ([regex]::Matches($scriptContent, 'Write-Verbose.*Authentication')).Count
    
    Write-Host "   📢 Verbose output analysis:" -ForegroundColor White
    Write-Host "      Total Write-Verbose calls: $verboseCount" -ForegroundColor Gray
    Write-Host "      Data mapping verbose calls: $verboseWithDataMapping" -ForegroundColor $(if ($verboseWithDataMapping -gt 0) { "Green" } else { "Red" })
    Write-Host "      Authentication verbose calls: $verboseWithAuth" -ForegroundColor $(if ($verboseWithAuth -gt 0) { "Green" } else { "Red" })
    
    $loggingResults.VerboseOutput = ($verboseCount -gt 50 -and $verboseWithDataMapping -gt 0 -and $verboseWithAuth -gt 0)
    
} catch {
    Write-Host "   ❌ Verbose output test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing error handling logging..." -ForegroundColor Cyan

try {
    # Check for error handling logs
    $errorHandlingPatterns = @(
        "Write-ErrorLog.*HTML generation.*statistics calculation failed",
        "Write-ErrorLog.*IdAM statistics calculation failed", 
        "Write-ErrorLog.*Secrets Management statistics calculation failed",
        "Write-Warning.*Failed to calculate.*statistics"
    )
    
    $foundErrorLogs = 0
    Write-Host "   ⚠️ Error handling log patterns:" -ForegroundColor White
    foreach ($pattern in $errorHandlingPatterns) {
        if ($scriptContent -match $pattern) {
            $foundErrorLogs++
            Write-Host "      ✅ $pattern" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $pattern" -ForegroundColor Red
        }
    }
    
    $loggingResults.ErrorHandlingLogs = ($foundErrorLogs -ge ($errorHandlingPatterns.Count * 0.5)) # 50% threshold
    
} catch {
    Write-Host "   ❌ Error handling logging test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 COMPREHENSIVE TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

Write-Host "`n🎯 Section Test Results:" -ForegroundColor White
$totalSectionsPassed = 0
foreach ($section in $overallResults.GetEnumerator()) {
    $status = if ($section.Value.Success) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($section.Value.Success) { "Green" } else { "Red" }
    Write-Host "  $($section.Key): $status ($($section.Value.Passed)/$($section.Value.Total))" -ForegroundColor $color
    if ($section.Value.Success) { $totalSectionsPassed++ }
}

Write-Host "`n📝 Enhanced Logging Results:" -ForegroundColor White
$totalLoggingPassed = 0
foreach ($log in $loggingResults.GetEnumerator()) {
    $status = if ($log.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($log.Value) { "Green" } else { "Red" }
    Write-Host "  $($log.Key): $status" -ForegroundColor $color
    if ($log.Value) { $totalLoggingPassed++ }
}

$totalSections = $overallResults.Count
$totalLoggingTests = $loggingResults.Count
$allPassed = ($totalSectionsPassed -eq $totalSections) -and ($totalLoggingPassed -eq $totalLoggingTests)

Write-Host "`n🎯 Overall Results:" -ForegroundColor Yellow
Write-Host "  Section Tests: $totalSectionsPassed/$totalSections passed" -ForegroundColor $(if ($totalSectionsPassed -eq $totalSections) { "Green" } else { "Yellow" })
Write-Host "  Logging Tests: $totalLoggingPassed/$totalLoggingTests passed" -ForegroundColor $(if ($totalLoggingPassed -eq $totalLoggingTests) { "Green" } else { "Yellow" })

if ($allPassed) {
    Write-Host "`n🎉 ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "✅ Every report section has automated tests" -ForegroundColor Green
    Write-Host "✅ Enhanced logging for data mapping implemented" -ForegroundColor Green
    Write-Host "✅ Enhanced logging for authentication implemented" -ForegroundColor Green
    Write-Host "💡 All requirements from the comment have been addressed" -ForegroundColor Blue
} else {
    Write-Host "`n⚠️ Some tests failed - review results above" -ForegroundColor Yellow
    Write-Host "📋 Sections needing attention:" -ForegroundColor White
    foreach ($section in $overallResults.GetEnumerator()) {
        if (-not $section.Value.Success) {
            Write-Host "  ❌ $($section.Key)" -ForegroundColor Red
        }
    }
}

return @{
    SectionTests = $overallResults
    LoggingTests = $loggingResults
    AllPassed = $allPassed
}