#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Compliance Framework section test script
.DESCRIPTION
    Tests and validates the Compliance Framework section data population,
    ensuring compliance scoring, color coding, and framework legends
    are correctly implemented in the HTML report.
#>

[CmdletBinding()]
param()

Write-Host "📊 COMPLIANCE FRAMEWORK SECTION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

$testResults = @{
    DataAggregation = $false
    ComplianceScoring = $false
    ColorCoding = $false
    FrameworkLegends = $false
    SectionStructure = $false
}

Write-Host "`n1️⃣ Testing Compliance Framework data aggregation..." -ForegroundColor Yellow

if (Test-Path $csvPath) {
    try {
        $csvData = Import-Csv $csvPath
        Write-Host "   📊 CSV records: $($csvData.Count)" -ForegroundColor Gray
        
        # Test compliance scoring
        $scores = @()
        $companyScores = @()
        foreach ($record in $csvData) {
            try {
                $score = [int]($record.ComplianceScore -replace '%', '')
                $companyScore = [int]($record.CompanyComplianceScore -replace '%', '')
                $scores += $score
                $companyScores += $companyScore
            } catch {
                Write-Verbose "Could not parse scores for record: $($record.KeyVaultName)"
            }
        }
        
        $averageScore = if ($scores.Count -gt 0) { [math]::Round(($scores | Measure-Object -Average).Average, 1) } else { 0 }
        $averageCompanyScore = if ($companyScores.Count -gt 0) { [math]::Round(($companyScores | Measure-Object -Average).Average, 1) } else { 0 }
        
        # Test compliance categorization
        $fullyCompliant = @($csvData | Where-Object { [int]($_.ComplianceScore -replace '%', '') -ge 90 }).Count
        $partiallyCompliant = @($csvData | Where-Object { [int]($_.ComplianceScore -replace '%', '') -ge 60 -and [int]($_.ComplianceScore -replace '%', '') -lt 90 }).Count
        $nonCompliant = @($csvData | Where-Object { [int]($_.ComplianceScore -replace '%', '') -lt 60 }).Count
        
        # Test company framework
        $companyFullyCompliant = @($csvData | Where-Object { [int]($_.CompanyComplianceScore -replace '%', '') -ge 95 }).Count
        $companyPartiallyCompliant = @($csvData | Where-Object { [int]($_.CompanyComplianceScore -replace '%', '') -ge 75 -and [int]($_.CompanyComplianceScore -replace '%', '') -lt 95 }).Count
        $companyNonCompliant = @($csvData | Where-Object { [int]($_.CompanyComplianceScore -replace '%', '') -lt 75 }).Count
        
        Write-Host "   📊 Microsoft Framework scores:" -ForegroundColor White
        Write-Host "      Average Score: $averageScore%" -ForegroundColor Green
        Write-Host "      Fully Compliant (≥90%): $fullyCompliant" -ForegroundColor Green
        Write-Host "      Partially Compliant (60-89%): $partiallyCompliant" -ForegroundColor Yellow
        Write-Host "      Non-Compliant (<60%): $nonCompliant" -ForegroundColor Red
        
        Write-Host "   🏭 Company Framework scores:" -ForegroundColor White
        Write-Host "      Average Score: $averageCompanyScore%" -ForegroundColor Blue
        Write-Host "      Fully Compliant (≥95%): $companyFullyCompliant" -ForegroundColor Green
        Write-Host "      Partially Compliant (75-94%): $companyPartiallyCompliant" -ForegroundColor Yellow
        Write-Host "      Non-Compliant (<75%): $companyNonCompliant" -ForegroundColor Red
        
        $testResults.DataAggregation = $true
    } catch {
        Write-Host "   ❌ Data aggregation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n2️⃣ Testing compliance scoring logic..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for compliance scoring patterns
    $hasComplianceScorePattern = $scriptContent -match 'ComplianceScore.*replace.*%'
    $hasCompanyScorePattern = $scriptContent -match 'CompanyComplianceScore.*replace.*%'
    $hasAverageCalculation = $scriptContent -match 'Measure-Object -Average'
    $hasScoreRounding = $scriptContent -match 'math\]::Round'
    
    Write-Host "   🧮 Scoring logic:" -ForegroundColor White
    Write-Host "      Compliance score parsing: $hasComplianceScorePattern" -ForegroundColor $(if ($hasComplianceScorePattern) { "Green" } else { "Red" })
    Write-Host "      Company score parsing: $hasCompanyScorePattern" -ForegroundColor $(if ($hasCompanyScorePattern) { "Green" } else { "Red" })
    Write-Host "      Average calculation: $hasAverageCalculation" -ForegroundColor $(if ($hasAverageCalculation) { "Green" } else { "Red" })
    Write-Host "      Score rounding: $hasScoreRounding" -ForegroundColor $(if ($hasScoreRounding) { "Green" } else { "Red" })
    
    $testResults.ComplianceScoring = $hasComplianceScorePattern -and $hasCompanyScorePattern -and $hasAverageCalculation
    
} catch {
    Write-Host "   ❌ Compliance scoring test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing compliance color coding..." -ForegroundColor Yellow

try {
    # Check for color coding logic
    $hasGreenCompliant = $scriptContent -match '#28a745'  # Green
    $hasYellowPartial = $scriptContent -match '#ffc107'   # Yellow 
    $hasRedNonCompliant = $scriptContent -match '#dc3545' # Red
    $hasColorLogic = $scriptContent -match 'ge 80.*#28a745.*ge 60.*#ffc107.*#dc3545'
    $hasComplianceColorPlaceholder = $scriptContent -match 'COMPLIANCE_COLOR'
    
    Write-Host "   🎨 Color coding:" -ForegroundColor White
    Write-Host "      Green for compliant: $hasGreenCompliant" -ForegroundColor $(if ($hasGreenCompliant) { "Green" } else { "Red" })
    Write-Host "      Yellow for partial: $hasYellowPartial" -ForegroundColor $(if ($hasYellowPartial) { "Green" } else { "Red" })
    Write-Host "      Red for non-compliant: $hasRedNonCompliant" -ForegroundColor $(if ($hasRedNonCompliant) { "Green" } else { "Red" })
    Write-Host "      Color logic implementation: $hasColorLogic" -ForegroundColor $(if ($hasColorLogic) { "Green" } else { "Red" })
    Write-Host "      Compliance color placeholder: $hasComplianceColorPlaceholder" -ForegroundColor $(if ($hasComplianceColorPlaceholder) { "Green" } else { "Red" })
    
    $testResults.ColorCoding = $hasGreenCompliant -and $hasYellowPartial -and $hasRedNonCompliant -and $hasComplianceColorPlaceholder
    
} catch {
    Write-Host "   ❌ Color coding test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing framework legends..." -ForegroundColor Yellow

try {
    # Check for framework legend sections
    $hasComplianceFrameworkSection = $scriptContent -match '📊 Compliance Framework & Scoring Legend'
    $hasMicrosoftFramework = $scriptContent -match '🏢 Microsoft Security Framework'
    $hasCompanyFramework = $scriptContent -match '🏭 Company Security Framework'
    $hasMicrosoftThresholds = $scriptContent -match '90-100%.*Fully Compliant'
    $hasCompanyThresholds = $scriptContent -match '95-100%.*Fully Compliant'
    $hasDocumentationLinks = $scriptContent -match 'docs\.microsoft\.com'
    
    Write-Host "   📚 Framework legends:" -ForegroundColor White
    Write-Host "      Compliance Framework section: $hasComplianceFrameworkSection" -ForegroundColor $(if ($hasComplianceFrameworkSection) { "Green" } else { "Red" })
    Write-Host "      Microsoft Framework legend: $hasMicrosoftFramework" -ForegroundColor $(if ($hasMicrosoftFramework) { "Green" } else { "Red" })
    Write-Host "      Company Framework legend: $hasCompanyFramework" -ForegroundColor $(if ($hasCompanyFramework) { "Green" } else { "Red" })
    Write-Host "      Microsoft thresholds (90%): $hasMicrosoftThresholds" -ForegroundColor $(if ($hasMicrosoftThresholds) { "Green" } else { "Red" })
    Write-Host "      Company thresholds (95%): $hasCompanyThresholds" -ForegroundColor $(if ($hasCompanyThresholds) { "Green" } else { "Red" })
    Write-Host "      Documentation links: $hasDocumentationLinks" -ForegroundColor $(if ($hasDocumentationLinks) { "Green" } else { "Red" })
    
    $testResults.FrameworkLegends = $hasComplianceFrameworkSection -and $hasMicrosoftFramework -and $hasCompanyFramework -and $hasMicrosoftThresholds -and $hasCompanyThresholds
    
} catch {
    Write-Host "   ❌ Framework legends test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing section structure..." -ForegroundColor Yellow

try {
    # Check for section structure
    $hasFrameworkSection = $scriptContent -match 'framework-section'
    $hasLegendItems = $scriptContent -match 'legend-item'
    $hasDocLinks = $scriptContent -match 'doc-link'
    $hasGridLayout = $scriptContent -match 'grid-template-columns.*1fr 1fr'
    
    Write-Host "   🏗️ Section structure:" -ForegroundColor White
    Write-Host "      Framework section class: $hasFrameworkSection" -ForegroundColor $(if ($hasFrameworkSection) { "Green" } else { "Red" })
    Write-Host "      Legend items: $hasLegendItems" -ForegroundColor $(if ($hasLegendItems) { "Green" } else { "Red" })
    Write-Host "      Documentation links: $hasDocLinks" -ForegroundColor $(if ($hasDocLinks) { "Green" } else { "Red" })
    Write-Host "      Grid layout: $hasGridLayout" -ForegroundColor $(if ($hasGridLayout) { "Green" } else { "Red" })
    
    $testResults.SectionStructure = $hasFrameworkSection -and $hasLegendItems -and $hasDocLinks
    
} catch {
    Write-Host "   ❌ Section structure test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 COMPLIANCE FRAMEWORK TEST SUMMARY" -ForegroundColor Cyan
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
    Write-Host "🎉 Compliance Framework section fully validated!" -ForegroundColor Green
    Write-Host "💡 All compliance scoring and framework legends properly configured" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some tests failed - review results above" -ForegroundColor Yellow
}

return $testResults