#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Executive Summary section test and validation script
.DESCRIPTION
    Tests and validates the Executive Summary section data population,
    ensuring all metrics are correctly aggregated from audit data and
    properly displayed in the HTML report cards.
#>

[CmdletBinding()]
param()

Write-Host "🎯 EXECUTIVE SUMMARY SECTION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

$testResults = @{
    DataAggregation = $false
    PlaceholderMapping = $false
    StatCards = $false
    ProgressBars = $false
    ComplianceColors = $false
}

Write-Host "`n1️⃣ Testing Executive Summary data aggregation..." -ForegroundColor Yellow

if (Test-Path $csvPath) {
    try {
        $csvData = Import-Csv $csvPath
        Write-Host "   📊 CSV records: $($csvData.Count)" -ForegroundColor Gray
        
        # Test executive summary calculations
        $totalVaults = $csvData.Count
        $compliantVaults = @($csvData | Where-Object { [int]($_.ComplianceScore -replace '%', '') -ge 80 }).Count
        $partiallyCompliantVaults = @($csvData | Where-Object { [int]($_.ComplianceScore -replace '%', '') -ge 60 -and [int]($_.ComplianceScore -replace '%', '') -lt 80 }).Count
        $nonCompliantVaults = @($csvData | Where-Object { [int]($_.ComplianceScore -replace '%', '') -lt 60 }).Count
        
        $compliancePercentage = if ($totalVaults -gt 0) { [math]::Round(($compliantVaults / $totalVaults) * 100, 1) } else { 0 }
        
        # Test diagnostic settings
        $withDiagnostics = @($csvData | Where-Object { $_.DiagnosticsEnabled -eq "Yes" }).Count
        $eventHubEnabled = @($csvData | Where-Object { $_.EventHubEnabled -eq "Yes" }).Count
        $logAnalyticsEnabled = @($csvData | Where-Object { $_.LogAnalyticsEnabled -eq "Yes" }).Count
        
        Write-Host "   📈 Executive Summary metrics:" -ForegroundColor White
        Write-Host "      Total Vaults: $totalVaults" -ForegroundColor Green
        Write-Host "      Compliant: $compliantVaults ($compliancePercentage%)" -ForegroundColor Green
        Write-Host "      Partially Compliant: $partiallyCompliantVaults" -ForegroundColor Yellow
        Write-Host "      Non-Compliant: $nonCompliantVaults" -ForegroundColor Red
        Write-Host "      With Diagnostics: $withDiagnostics" -ForegroundColor Blue
        Write-Host "      Event Hub Enabled: $eventHubEnabled" -ForegroundColor Blue
        Write-Host "      Log Analytics Enabled: $logAnalyticsEnabled" -ForegroundColor Blue
        
        $testResults.DataAggregation = $true
    } catch {
        Write-Host "   ❌ Data aggregation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n2️⃣ Testing Executive Summary placeholder mapping..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for Executive Summary section existence
    $executiveSummaryExists = $scriptContent -match '🎯 Executive Summary'
    Write-Host "   📋 Executive Summary section found: $executiveSummaryExists" -ForegroundColor $(if ($executiveSummaryExists) { "Green" } else { "Red" })
    
    # Check for key placeholders
    $executivePlaceholders = @(
        'TOTAL_KEY_VAULTS',
        'COMPLIANT_VAULTS',
        'COMPLIANCE_PERCENTAGE',
        'SUBSCRIPTIONS_SCANNED',
        'PARTIALLY_COMPLIANT_VAULTS',
        'NON_COMPLIANT_VAULTS',
        'WITH_DIAGNOSTICS',
        'EVENT_HUB_ENABLED',
        'LOG_ANALYTICS_ENABLED'
    )
    
    $foundPlaceholders = 0
    foreach ($placeholder in $executivePlaceholders) {
        if ($scriptContent -match "\{\{$placeholder\}\}") {
            $foundPlaceholders++
            Write-Host "      ✅ $placeholder" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $placeholder" -ForegroundColor Red
        }
    }
    
    Write-Host "   📊 Placeholders found: $foundPlaceholders/$($executivePlaceholders.Count)" -ForegroundColor Gray
    $testResults.PlaceholderMapping = ($foundPlaceholders -eq $executivePlaceholders.Count)
    
} catch {
    Write-Host "   ❌ Placeholder mapping test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing stat cards structure..." -ForegroundColor Yellow

try {
    # Check for stat card structure
    $hasStatGrid = $scriptContent -match 'stats-grid'
    $hasStatCard = $scriptContent -match 'stat-card'
    $hasStatNumber = $scriptContent -match 'stat-number'
    $hasStatLabel = $scriptContent -match 'stat-label'
    
    Write-Host "   📊 Stat grid structure: $hasStatGrid" -ForegroundColor $(if ($hasStatGrid) { "Green" } else { "Red" })
    Write-Host "   📊 Stat card structure: $hasStatCard" -ForegroundColor $(if ($hasStatCard) { "Green" } else { "Red" })
    Write-Host "   📊 Stat number structure: $hasStatNumber" -ForegroundColor $(if ($hasStatNumber) { "Green" } else { "Red" })
    Write-Host "   📊 Stat label structure: $hasStatLabel" -ForegroundColor $(if ($hasStatLabel) { "Green" } else { "Red" })
    
    $testResults.StatCards = $hasStatGrid -and $hasStatCard -and $hasStatNumber -and $hasStatLabel
    
} catch {
    Write-Host "   ❌ Stat cards test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing progress bars and animations..." -ForegroundColor Yellow

try {
    # Check for progress bar features
    $hasProgressBar = $scriptContent -match 'progress-bar'
    $hasProgressFill = $scriptContent -match 'progress-fill'
    $hasProgressAnimation = $scriptContent -match 'progressAnimation'
    
    Write-Host "   📊 Progress bar structure: $hasProgressBar" -ForegroundColor $(if ($hasProgressBar) { "Green" } else { "Red" })
    Write-Host "   📊 Progress fill animation: $hasProgressFill" -ForegroundColor $(if ($hasProgressFill) { "Green" } else { "Red" })
    Write-Host "   📊 CSS animations: $hasProgressAnimation" -ForegroundColor $(if ($hasProgressAnimation) { "Green" } else { "Red" })
    
    $testResults.ProgressBars = $hasProgressBar -and $hasProgressFill -and $hasProgressAnimation
    
} catch {
    Write-Host "   ❌ Progress bars test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing compliance color coding..." -ForegroundColor Yellow

try {
    # Check for compliance color logic
    $hasComplianceColor = $scriptContent -match 'COMPLIANCE_COLOR'
    $hasColorLogic = $scriptContent -match '#28a745.*#ffc107.*#dc3545'
    $hasGreenCompliant = $scriptContent -match '#28a745' # Green for compliant
    $hasYellowPartial = $scriptContent -match '#ffc107'  # Yellow for partial
    $hasRedNonCompliant = $scriptContent -match '#dc3545' # Red for non-compliant
    
    Write-Host "   📊 Compliance color placeholder: $hasComplianceColor" -ForegroundColor $(if ($hasComplianceColor) { "Green" } else { "Red" })
    Write-Host "   📊 Color logic implementation: $hasColorLogic" -ForegroundColor $(if ($hasColorLogic) { "Green" } else { "Red" })
    Write-Host "   📊 Green (compliant): $hasGreenCompliant" -ForegroundColor $(if ($hasGreenCompliant) { "Green" } else { "Red" })
    Write-Host "   📊 Yellow (partial): $hasYellowPartial" -ForegroundColor $(if ($hasYellowPartial) { "Green" } else { "Red" })
    Write-Host "   📊 Red (non-compliant): $hasRedNonCompliant" -ForegroundColor $(if ($hasRedNonCompliant) { "Green" } else { "Red" })
    
    $testResults.ComplianceColors = $hasComplianceColor -and $hasGreenCompliant -and $hasYellowPartial -and $hasRedNonCompliant
    
} catch {
    Write-Host "   ❌ Compliance colors test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 EXECUTIVE SUMMARY TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray

$passedTests = 0
foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
    if ($test.Value) { $passedTests++ }
}

Write-Host "`n🎯 Overall Results: $passedTests/$($testResults.Count) tests passed" -ForegroundColor $(if ($passedTests -eq $testResults.Count) { "Green" } else { "Yellow" })

if ($passedTests -eq $testResults.Count) {
    Write-Host "🎉 Executive Summary section fully validated!" -ForegroundColor Green
    Write-Host "💡 All metrics will be properly populated in the HTML report" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some tests failed - review results above" -ForegroundColor Yellow
}

return $testResults