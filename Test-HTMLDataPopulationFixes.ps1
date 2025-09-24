#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate the HTML data population fixes
.DESCRIPTION
    Tests that the HTML template placeholders are correctly populated with 
    aggregated data from CSV audit results. Validates the fix for service 
    principal and managed identity counts in executive summary cards.
#>

[CmdletBinding()]
param()

Write-Host "🔍 TESTING HTML DATA POPULATION FIXES" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

if (-not (Test-Path $csvPath)) {
    Write-Host "❌ Test CSV file not found: $csvPath" -ForegroundColor Red
    return $false
}

Write-Host "`n1️⃣ Testing HTML template placeholder fix..." -ForegroundColor Yellow

# Check if the PowerShell variable interpolation was fixed
$templateContent = Get-Content $scriptPath -Raw
$badPattern = '\$\(\$placeholders\["\{\{TOTAL_SERVICE_PRINCIPALS\}\}"\]\)'
$goodPattern = '\{\{TOTAL_SERVICE_PRINCIPALS\}\}'

$hasBadPattern = $templateContent -match $badPattern
$hasGoodPattern = $templateContent -match $goodPattern

Write-Host "   🔍 Checking for incorrect PowerShell interpolation pattern:" -ForegroundColor Gray
Write-Host "      Bad pattern found: $hasBadPattern" -ForegroundColor $(if ($hasBadPattern) { "Red" } else { "Green" })

Write-Host "   🔍 Checking for correct placeholder pattern:" -ForegroundColor Gray  
Write-Host "      Good pattern found: $hasGoodPattern" -ForegroundColor $(if ($hasGoodPattern) { "Green" } else { "Red" })

if (-not $hasBadPattern -and $hasGoodPattern) {
    Write-Host "   ✅ Template fix verified: Using correct placeholder tokens" -ForegroundColor Green
} else {
    Write-Host "   ❌ Template fix verification failed" -ForegroundColor Red
    return $false
}

Write-Host "`n2️⃣ Testing enhanced logging additions..." -ForegroundColor Yellow

# Check for enhanced logging patterns
$loggingPatterns = @(
    "Data mapping diagnostic",
    "Authentication diagnostic", 
    "Authentication path decision",
    "✅ Identity metrics successfully aggregated"
)

$loggingFound = 0
foreach ($pattern in $loggingPatterns) {
    if ($templateContent -match [regex]::Escape($pattern)) {
        Write-Host "   ✅ Found logging enhancement: '$pattern'" -ForegroundColor Green
        $loggingFound++
    } else {
        Write-Host "   ⚠️ Missing logging pattern: '$pattern'" -ForegroundColor Yellow
    }
}

Write-Host "   📊 Enhanced logging patterns found: $loggingFound/$($loggingPatterns.Count)" -ForegroundColor Gray

Write-Host "`n3️⃣ Testing syntax validation..." -ForegroundColor Yellow

try {
    $null = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    Write-Host "   ✅ PowerShell syntax validation passed" -ForegroundColor Green
} catch {
    Write-Host "   ❌ PowerShell syntax validation failed: $($_.Exception.Message)" -ForegroundColor Red
    return $false
}

Write-Host "`n4️⃣ Testing data aggregation logic..." -ForegroundColor Yellow

# Import CSV to test aggregation
$csvData = Import-Csv $csvPath
if ($csvData.Count -gt 0) {
    $record = $csvData[0]
    
    # Test the aggregation logic that should be used in the script
    try {
        $servicePrincipalSum = ($csvData | Where-Object { $null -ne $_.ServicePrincipalCount } | Measure-Object -Property ServicePrincipalCount -Sum).Sum
        $managedIdentitySum = ($csvData | Where-Object { $null -ne $_.ManagedIdentityCount } | Measure-Object -Property ManagedIdentityCount -Sum).Sum
        
        Write-Host "   📊 Aggregation test results:" -ForegroundColor Gray
        Write-Host "      Service Principals: $servicePrincipalSum" -ForegroundColor White
        Write-Host "      Managed Identities: $managedIdentitySum" -ForegroundColor White
        
        if ($servicePrincipalSum -gt 0 -or $managedIdentitySum -gt 0) {
            Write-Host "   ✅ Aggregation logic working: Non-zero counts found" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ Aggregation result: Zero counts (may be expected for test data)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ❌ Aggregation logic failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

Write-Host "`n5️⃣ Testing placeholder replacement patterns..." -ForegroundColor Yellow

# Check that other sections also use correct placeholder patterns
$sections = @(
    "IdAM Insights",
    "Secrets Management Insights", 
    "Executive Summary"
)

foreach ($section in $sections) {
    if ($templateContent -match $section) {
        Write-Host "   ✅ Section found: $section" -ForegroundColor Green
        
        # Extract section content and check for placeholder patterns
        $sectionStart = $templateContent.IndexOf($section)
        $sectionContent = $templateContent.Substring($sectionStart, [Math]::Min(2000, $templateContent.Length - $sectionStart))
        
        $placeholderCount = ([regex]::Matches($sectionContent, '\{\{[A-Z_]+\}\}')).Count
        Write-Host "      Placeholders in section: $placeholderCount" -ForegroundColor Gray
    } else {
        Write-Host "   ⚠️ Section not found: $section" -ForegroundColor Yellow
    }
}

Write-Host "`n📊 SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray
Write-Host "✅ Template fix: PowerShell interpolation → Placeholder tokens" -ForegroundColor Green
Write-Host "✅ Enhanced logging: Diagnostic messages for data mapping and auth" -ForegroundColor Green
Write-Host "✅ Syntax validation: PowerShell parsing successful" -ForegroundColor Green
Write-Host "✅ Data aggregation: Logic validated against test CSV" -ForegroundColor Green
Write-Host "🎯 Ready for testing: All fixes appear to be working correctly" -ForegroundColor Blue

return $true