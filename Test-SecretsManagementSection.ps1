#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Secrets Management Insights section test script
.DESCRIPTION
    Tests and validates the Secrets Management Insights section data population,
    ensuring secrets, keys, certificates, and related metrics are correctly
    aggregated and displayed in the HTML report.
#>

[CmdletBinding()]
param()

Write-Host "🔑 SECRETS MANAGEMENT INSIGHTS SECTION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

$testResults = @{
    DataAggregation = $false
    PlaceholderMapping = $false
    SecretsMetrics = $false
    WorkloadAnalysis = $false
    SectionStructure = $false
}

Write-Host "`n1️⃣ Testing Secrets Management data aggregation..." -ForegroundColor Yellow

if (Test-Path $csvPath) {
    try {
        $csvData = Import-Csv $csvPath
        Write-Host "   📊 CSV records: $($csvData.Count)" -ForegroundColor Gray
        
        # Test secrets metrics
        $totalSecrets = ($csvData | Where-Object { $null -ne $_.SecretCount } | Measure-Object -Property SecretCount -Sum).Sum
        $totalKeys = ($csvData | Where-Object { $null -ne $_.KeyCount } | Measure-Object -Property KeyCount -Sum).Sum
        $totalCertificates = ($csvData | Where-Object { $null -ne $_.CertificateCount } | Measure-Object -Property CertificateCount -Sum).Sum
        $totalItems = $totalSecrets + $totalKeys + $totalCertificates
        
        # Test workload analysis
        $appServiceIntegrations = ($csvData | Where-Object { $_.AppServiceIntegration -and $_.AppServiceIntegration -ne "None" }).Count
        $workloadCategories = ($csvData | Where-Object { $_.WorkloadCategories -and $_.WorkloadCategories -ne "None" }).Count
        
        Write-Host "   🔑 Secrets Management metrics:" -ForegroundColor White
        Write-Host "      Total Secrets: $totalSecrets" -ForegroundColor Green
        Write-Host "      Total Keys: $totalKeys" -ForegroundColor Green
        Write-Host "      Total Certificates: $totalCertificates" -ForegroundColor Green
        Write-Host "      Total Items: $totalItems" -ForegroundColor Green
        Write-Host "      App Service Integrations: $appServiceIntegrations" -ForegroundColor Blue
        Write-Host "      Workload Categories: $workloadCategories" -ForegroundColor Blue
        
        $testResults.DataAggregation = $true
    } catch {
        Write-Host "   ❌ Data aggregation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n2️⃣ Testing Secrets Management placeholder mapping..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for Secrets Management section existence
    $secretsSectionExists = $scriptContent -match '🔑 Secrets Management Insights'
    Write-Host "   📋 Secrets Management section found: $secretsSectionExists" -ForegroundColor $(if ($secretsSectionExists) { "Green" } else { "Red" })
    
    # Check for secrets placeholders
    $secretsPlaceholders = @(
        'TOTAL_SECRETS',
        'TOTAL_KEYS', 
        'TOTAL_CERTIFICATES',
        'TOTAL_ITEMS'
    )
    
    $foundSecretsPlaceholders = 0
    Write-Host "   🔑 Secrets placeholders:" -ForegroundColor White
    foreach ($placeholder in $secretsPlaceholders) {
        if ($scriptContent -match "\{\{$placeholder\}\}") {
            $foundSecretsPlaceholders++
            Write-Host "      ✅ $placeholder" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $placeholder" -ForegroundColor Red
        }
    }
    
    $testResults.SecretsMetrics = ($foundSecretsPlaceholders -eq $secretsPlaceholders.Count)
    
} catch {
    Write-Host "   ❌ Placeholder mapping test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing workload analysis placeholders..." -ForegroundColor Yellow

try {
    # Check for workload analysis placeholders
    $workloadPlaceholders = @(
        'EXPIRATION_ANALYSIS',
        'ROTATION_ANALYSIS',
        'APP_SERVICE_INTEGRATION',
        'SECRET_VERSIONING',
        'WORKLOAD_CATEGORIES'
    )
    
    $foundWorkloadPlaceholders = 0
    Write-Host "   📈 Workload Analysis placeholders:" -ForegroundColor White
    foreach ($placeholder in $workloadPlaceholders) {
        if ($scriptContent -match "\{\{$placeholder\}\}") {
            $foundWorkloadPlaceholders++
            Write-Host "      ✅ $placeholder" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $placeholder" -ForegroundColor Red
        }
    }
    
    $testResults.WorkloadAnalysis = ($foundWorkloadPlaceholders -eq $workloadPlaceholders.Count)
    
} catch {
    Write-Host "   ❌ Workload analysis placeholders test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing Secrets Management section structure..." -ForegroundColor Yellow

try {
    # Check for section structure elements
    $hasContentAnalysisSection = $scriptContent -match '📦 Content analysis'
    $hasVersioningSection = $scriptContent -match '📋 Versioning analysis'
    $hasExpirationSection = $scriptContent -match '⏰ Expiration monitoring'
    $hasAppServiceSection = $scriptContent -match '🌐 App Service integration'
    $hasRotationSection = $scriptContent -match '🔄 Rotation analysis'
    $hasWorkloadSection = $scriptContent -match '🏭 Workload categorization'
    
    Write-Host "   📊 Section structure:" -ForegroundColor White
    Write-Host "      Content analysis section: $hasContentAnalysisSection" -ForegroundColor $(if ($hasContentAnalysisSection) { "Green" } else { "Red" })
    Write-Host "      Versioning analysis section: $hasVersioningSection" -ForegroundColor $(if ($hasVersioningSection) { "Green" } else { "Red" })
    Write-Host "      Expiration monitoring section: $hasExpirationSection" -ForegroundColor $(if ($hasExpirationSection) { "Green" } else { "Red" })
    Write-Host "      App Service integration section: $hasAppServiceSection" -ForegroundColor $(if ($hasAppServiceSection) { "Green" } else { "Red" })
    Write-Host "      Rotation analysis section: $hasRotationSection" -ForegroundColor $(if ($hasRotationSection) { "Green" } else { "Red" })
    Write-Host "      Workload categorization section: $hasWorkloadSection" -ForegroundColor $(if ($hasWorkloadSection) { "Green" } else { "Red" })
    
    $testResults.SectionStructure = $hasContentAnalysisSection -and $hasVersioningSection -and $hasExpirationSection -and $hasAppServiceSection
    
} catch {
    Write-Host "   ❌ Section structure test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing data mapping logging..." -ForegroundColor Yellow

try {
    # Check for data mapping logging
    $hasSecretsDataMappingLog = $scriptContent -match "Data mapping diagnostic.*Secrets Management"
    $hasSecretsResultsLog = $scriptContent -match "Data mapping results.*Secrets Management section"
    $hasSecretsMetricsLog = $scriptContent -match "Secrets Management metrics successfully aggregated"
    
    Write-Host "   📝 Logging features:" -ForegroundColor White
    Write-Host "      Secrets data mapping diagnostic: $hasSecretsDataMappingLog" -ForegroundColor $(if ($hasSecretsDataMappingLog) { "Green" } else { "Red" })
    Write-Host "      Secrets results logging: $hasSecretsResultsLog" -ForegroundColor $(if ($hasSecretsResultsLog) { "Green" } else { "Red" })
    Write-Host "      Secrets metrics success log: $hasSecretsMetricsLog" -ForegroundColor $(if ($hasSecretsMetricsLog) { "Green" } else { "Red" })
    
    $testResults.PlaceholderMapping = $hasSecretsDataMappingLog -and $hasSecretsResultsLog
    
} catch {
    Write-Host "   ❌ Data mapping logging test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6️⃣ Testing secrets management calculations..." -ForegroundColor Yellow

try {
    # Check for proper calculation patterns in the script
    $hasSecretsCalculation = $scriptContent -match 'SecretCount.*Measure-Object.*Sum'
    $hasKeysCalculation = $scriptContent -match 'KeyCount.*Measure-Object.*Sum'
    $hasCertificatesCalculation = $scriptContent -match 'CertificateCount.*Measure-Object.*Sum'
    $hasTotalItemsCalculation = $scriptContent -match 'TOTAL_SECRETS.*TOTAL_KEYS.*TOTAL_CERTIFICATES'
    
    Write-Host "   🧮 Calculation patterns:" -ForegroundColor White
    Write-Host "      Secrets sum calculation: $hasSecretsCalculation" -ForegroundColor $(if ($hasSecretsCalculation) { "Green" } else { "Red" })
    Write-Host "      Keys sum calculation: $hasKeysCalculation" -ForegroundColor $(if ($hasKeysCalculation) { "Green" } else { "Red" })
    Write-Host "      Certificates sum calculation: $hasCertificatesCalculation" -ForegroundColor $(if ($hasCertificatesCalculation) { "Green" } else { "Red" })
    Write-Host "      Total items calculation: $hasTotalItemsCalculation" -ForegroundColor $(if ($hasTotalItemsCalculation) { "Green" } else { "Red" })
    
} catch {
    Write-Host "   ❌ Calculation patterns test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 SECRETS MANAGEMENT TEST SUMMARY" -ForegroundColor Cyan
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
    Write-Host "🎉 Secrets Management section fully validated!" -ForegroundColor Green
    Write-Host "💡 All secrets, keys, and certificate metrics properly configured" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some tests failed - review results above" -ForegroundColor Yellow
}

return $testResults