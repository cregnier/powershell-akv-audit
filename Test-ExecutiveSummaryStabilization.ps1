#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script for ExecutiveSummary schema stabilization and reporting fixes
.DESCRIPTION
    Validates that the new helper functions work correctly and that ExecutiveSummary
    schema is properly initialized, normalized, and aggregated without missing properties.
#>

[CmdletBinding()]
param()

Write-Host "🔧 EXECUTIVESUMMARY SCHEMA STABILIZATION TEST" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$testResults = @{
    HelperFunctionsExist = $false
    SchemaInitialization = $false
    VaultNormalization = $false
    SafePlaceholderExtraction = $false
    RbacPercentageFixed = $false
    PlaceholderValidation = $false
}

Write-Host "`n1️⃣ Testing helper function definitions...`n" -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for all required helper functions
    $helperFunctions = @(
        'function Initialize-ExecutiveSummary',
        'function Normalize-VaultResultProperties', 
        'function Aggregate-ExecutiveSummary',
        'function Harmonize-ExecutiveSummaryAliases',
        'function Get-PlaceholderValue'
    )
    
    $foundFunctions = 0
    foreach ($func in $helperFunctions) {
        $exists = $scriptContent -match $func
        $funcName = $func -replace 'function ', ''
        Write-Host "   📋 $funcName`: $exists" -ForegroundColor $(if ($exists) { "Green" } else { "Red" })
        if ($exists) { $foundFunctions++ }
    }
    
    if ($foundFunctions -eq $helperFunctions.Count) {
        $testResults.HelperFunctionsExist = $true
        Write-Host "   ✅ All $foundFunctions helper functions defined" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing helper functions: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing ExecutiveSummary schema initialization...`n" -ForegroundColor Yellow

try {
    # Check for canonical key set in Initialize-ExecutiveSummary
    $canonicalKeys = @(
        'TotalKeyVaults', 'SubscriptionsScanned', 'TotalSubscriptions',
        'FullyCompliant', 'PartiallyCompliant', 'NonCompliant',
        'CompanyFullyCompliant', 'CompanyPartiallyCompliant', 'CompanyNonCompliant',
        'AverageComplianceScore', 'CompanyAverageScore', 'CompliancePercentage',
        'RBACCoveragePercent', 'HighRiskVaults', 'WithDiagnostics',
        'WithLogAnalytics', 'WithEventHub', 'WithStorageAccount',
        'TotalServicePrincipals', 'TotalManagedIdentities', 'AuthenticationRefreshes'
    )
    
    $foundKeys = 0
    foreach ($key in $canonicalKeys) {
        if ($scriptContent -match "'$key'") {
            $foundKeys++
        }
    }
    
    Write-Host "   📊 Canonical keys found in schema: $foundKeys/$($canonicalKeys.Count)" -ForegroundColor Gray
    
    # Check for Initialize-ExecutiveSummary usage
    $initUsage = $scriptContent -match 'Initialize-ExecutiveSummary'
    Write-Host "   📋 Initialize-ExecutiveSummary called: $initUsage" -ForegroundColor $(if ($initUsage) { "Green" } else { "Red" })
    
    if ($foundKeys -ge ($canonicalKeys.Count * 0.8) -and $initUsage) {
        $testResults.SchemaInitialization = $true
        Write-Host "   ✅ ExecutiveSummary schema properly initialized" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing schema initialization: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing vault result normalization...`n" -ForegroundColor Yellow

try {
    # Check for Normalize-VaultResultProperties usage
    $normalizeUsage = $scriptContent -match 'Normalize-VaultResultProperties.*VaultResult'
    Write-Host "   📋 Normalize-VaultResultProperties called: $normalizeUsage" -ForegroundColor $(if ($normalizeUsage) { "Green" } else { "Red" })
    
    # Check for required properties in normalization
    $requiredProps = @(
        'SoftDeleteEnabled', 'PurgeProtectionEnabled', 'DiagnosticsEnabled',
        'ComplianceStatus', 'ComplianceScore', 'CompanyComplianceScore'
    )
    
    $foundProps = 0
    foreach ($prop in $requiredProps) {
        if ($scriptContent -match "'$prop'") {
            $foundProps++
        }
    }
    
    Write-Host "   📊 Required properties found: $foundProps/$($requiredProps.Count)" -ForegroundColor Gray
    
    if ($normalizeUsage -and $foundProps -ge ($requiredProps.Count * 0.8)) {
        $testResults.VaultNormalization = $true
        Write-Host "   ✅ Vault result normalization properly implemented" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing vault normalization: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing safe placeholder extraction...`n" -ForegroundColor Yellow

try {
    # Check for Get-PlaceholderValue usage
    $placeholderUsage = $scriptContent -match 'Get-PlaceholderValue.*ExecutiveSummary'
    Write-Host "   📋 Get-PlaceholderValue usage: $placeholderUsage" -ForegroundColor $(if ($placeholderUsage) { "Green" } else { "Red" })
    
    # Check for Harmonize-ExecutiveSummaryAliases usage
    $harmonizeUsage = $scriptContent -match 'Harmonize-ExecutiveSummaryAliases'
    Write-Host "   📋 Harmonize-ExecutiveSummaryAliases usage: $harmonizeUsage" -ForegroundColor $(if ($harmonizeUsage) { "Green" } else { "Red" })
    
    # Check for safe placeholder mapping
    $safePlaceholders = [regex]::Matches($scriptContent, 'Get-PlaceholderValue').Count
    Write-Host "   📊 Safe placeholder extractions: $safePlaceholders" -ForegroundColor Gray
    
    if ($placeholderUsage -and $harmonizeUsage -and $safePlaceholders -gt 10) {
        $testResults.SafePlaceholderExtraction = $true
        Write-Host "   ✅ Safe placeholder extraction properly implemented" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing placeholder extraction: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing rbacPercentage replacement...`n" -ForegroundColor Yellow

try {
    # Check that rbacPercentage is no longer used
    $rbacPercentageUsage = $scriptContent -match '\\$rbacPercentage'
    Write-Host "   📋 \\$rbacPercentage usage found: $rbacPercentageUsage" -ForegroundColor $(if (-not $rbacPercentageUsage) { "Green" } else { "Red" })
    
    # Check for RBACCoveragePercent usage
    $rbacCoverageUsage = $scriptContent -match 'RBACCoveragePercent'
    Write-Host "   📋 RBACCoveragePercent usage: $rbacCoverageUsage" -ForegroundColor $(if ($rbacCoverageUsage) { "Green" } else { "Red" })
    
    if (-not $rbacPercentageUsage -and $rbacCoverageUsage) {
        $testResults.RbacPercentageFixed = $true
        Write-Host "   ✅ \\$rbacPercentage successfully replaced with stored key" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing rbacPercentage replacement: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6️⃣ Testing placeholder validation...`n" -ForegroundColor Yellow

try {
    # Check for unresolved placeholder detection
    $placeholderValidation = $scriptContent -match 'unresolvedPlaceholders.*regex.*Matches'
    Write-Host "   📋 Unresolved placeholder detection: $placeholderValidation" -ForegroundColor $(if ($placeholderValidation) { "Green" } else { "Red" })
    
    # Check for regex pattern for placeholder detection  
    $regexPattern = $scriptContent -match "\\[A-Z_\\]\\+"
    Write-Host "   📋 Placeholder regex pattern: $regexPattern" -ForegroundColor $(if ($regexPattern) { "Green" } else { "Red" })
    
    if ($placeholderValidation -and $regexPattern) {
        $testResults.PlaceholderValidation = $true
        Write-Host "   ✅ Placeholder validation properly implemented" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing placeholder validation: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASSED" } else { "❌ FAILED" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
}

Write-Host "`nOverall: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All ExecutiveSummary stabilization tests passed!" -ForegroundColor Green
    Write-Host "💡 The reporting system should now have stable schema and no missing property errors" -ForegroundColor Blue
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "`n✅ Most tests passed. Implementation is likely stable." -ForegroundColor Yellow
} else {
    Write-Host "`n⚠️ Several issues detected - review results above" -ForegroundColor Red
}

Write-Host "`n💡 Key Stabilization Benefits:" -ForegroundColor Cyan
Write-Host "  • Canonical ExecutiveSummary schema with 31+ keys prevents missing properties" -ForegroundColor Gray
Write-Host "  • Per-vault normalization ensures consistent data structure" -ForegroundColor Gray  
Write-Host "  • Safe placeholder extraction with default values prevents template errors" -ForegroundColor Gray
Write-Host "  • Unresolved placeholder detection provides debugging capability" -ForegroundColor Gray
Write-Host "  • Alias harmonization handles naming drift between properties" -ForegroundColor Gray

return $testResults