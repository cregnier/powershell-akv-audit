#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate the fixed data aggregation pipeline
.DESCRIPTION
    Tests that CSV data properly flows through ExecutiveSummary object to HTML placeholders
    and that all cards show real audit data instead of placeholder values.
#>

[CmdletBinding()]
param()

Write-Host "🔍 TESTING FIXED DATA AGGREGATION PIPELINE" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

if (-not (Test-Path $csvPath)) {
    Write-Host "❌ Test CSV file not found: $csvPath" -ForegroundColor Red
    return $false
}

Write-Host "`n1️⃣ Loading test data..." -ForegroundColor Yellow
$csvData = Import-Csv $csvPath
Write-Host "   📊 CSV records loaded: $($csvData.Count)" -ForegroundColor Gray

# Import the helper function from the main script  
$scriptContent = Get-Content $scriptPath -Raw
$updateFunctionMatch = [regex]::Match($scriptContent, 'function Update-ExecutiveSummaryFromAuditData.*?^}', [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)

if ($updateFunctionMatch.Success) {
    # Execute the function definition
    Invoke-Expression $updateFunctionMatch.Value
    Write-Host "   ✅ Helper function loaded" -ForegroundColor Green
} else {
    Write-Host "   ❌ Could not extract helper function" -ForegroundColor Red
    return $false
}

Write-Host "`n2️⃣ Testing ExecutiveSummary aggregation..." -ForegroundColor Yellow

# Create initial ExecutiveSummary with default values
$executiveSummary = @{
    TotalKeyVaults = 0
    FullyCompliant = 0
    PartiallyCompliant = 0
    NonCompliant = 0
    TotalServicePrincipals = 0
    TotalManagedIdentities = 0
    UsingRBAC = 0
    UsingAccessPolicies = 0
    WithDiagnostics = 0
    WithEventHub = 0
    WithLogAnalytics = 0
}

Write-Host "   📊 Before aggregation:"
Write-Host "      TotalServicePrincipals: $($executiveSummary.TotalServicePrincipals)" -ForegroundColor Gray
Write-Host "      TotalManagedIdentities: $($executiveSummary.TotalManagedIdentities)" -ForegroundColor Gray  
Write-Host "      UsingRBAC: $($executiveSummary.UsingRBAC)" -ForegroundColor Gray

# Run the helper function
$executiveSummary = Update-ExecutiveSummaryFromAuditData -ExecutiveSummary $executiveSummary -AuditResults $csvData

Write-Host "   📊 After aggregation:"
Write-Host "      TotalServicePrincipals: $($executiveSummary.TotalServicePrincipals)" -ForegroundColor Green
Write-Host "      TotalManagedIdentities: $($executiveSummary.TotalManagedIdentities)" -ForegroundColor Green
Write-Host "      UsingRBAC: $($executiveSummary.UsingRBAC)" -ForegroundColor Green

# Validate that real data was aggregated
$testsPassed = 0
$totalTests = 3

if ($executiveSummary.TotalServicePrincipals -gt 0) {
    Write-Host "   ✅ Service Principals aggregated correctly ($($executiveSummary.TotalServicePrincipals))" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "   ❌ Service Principals not aggregated" -ForegroundColor Red
}

if ($executiveSummary.UsingRBAC -gt 0) {
    Write-Host "   ✅ RBAC usage aggregated correctly ($($executiveSummary.UsingRBAC))" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "   ❌ RBAC usage not aggregated" -ForegroundColor Red
}

if ($executiveSummary.TotalKeyVaults -eq $csvData.Count) {
    Write-Host "   ✅ Total key vaults matches CSV count ($($executiveSummary.TotalKeyVaults))" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "   ❌ Total key vaults doesn't match CSV count" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing placeholder mapping..." -ForegroundColor Yellow

# Test that all expected placeholders are defined in the script
$expectedPlaceholders = @(
    'TOTAL_KEY_VAULTS',
    'TOTAL_SERVICE_PRINCIPALS', 
    'TOTAL_MANAGED_IDENTITIES',
    'COMPLIANT_VAULTS',
    'USING_RBAC',
    'WITH_DIAGNOSTICS',
    'EVENT_HUB_ENABLED',
    'LOG_ANALYTICS_ENABLED'
)

$placeholderTests = 0
foreach ($placeholder in $expectedPlaceholders) {
    if ($scriptContent -match "\`$placeholders\[`"\{\{$placeholder\}\}`"\]") {
        Write-Host "   ✅ Placeholder $placeholder is mapped" -ForegroundColor Green
        $placeholderTests++
    } else {
        Write-Host "   ❌ Placeholder $placeholder is not mapped" -ForegroundColor Red
    }
}

Write-Host "`n📊 PIPELINE TEST RESULTS" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray
Write-Host "✅ Data aggregation tests: $testsPassed/$totalTests passed" -ForegroundColor $(if ($testsPassed -eq $totalTests) { "Green" } else { "Yellow" })
Write-Host "✅ Placeholder mapping tests: $placeholderTests/$($expectedPlaceholders.Count) passed" -ForegroundColor $(if ($placeholderTests -eq $expectedPlaceholders.Count) { "Green" } else { "Yellow" })

$overallSuccess = ($testsPassed -eq $totalTests) -and ($placeholderTests -eq $expectedPlaceholders.Count)

if ($overallSuccess) {
    Write-Host "`n🎯 SUCCESS: Data pipeline is working correctly!" -ForegroundColor Green
    Write-Host "   • CSV data properly aggregated into ExecutiveSummary" -ForegroundColor Green
    Write-Host "   • All placeholders mapped to real audit data" -ForegroundColor Green
    Write-Host "   • Executive summary cards will show actual metrics" -ForegroundColor Green
} else {
    Write-Host "`n⚠️ PARTIAL SUCCESS: Some tests failed" -ForegroundColor Yellow
}

return $overallSuccess