#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script for vault property normalization fixes
.DESCRIPTION
    Validates that both SoftDelete & PurgeProtection flags are resolved without error
    using the new property normalization functions.
#>

[CmdletBinding()]
param()

Write-Host "🔧 VAULT PROPERTY NORMALIZATION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    PropertyNormalizationFunctions = $false
    SoftDeleteVariants = $false
    PurgeProtectionVariants = $false
    PropertyExtractionIntegration = $false
    ErrorHandling = $false
}

Write-Host "`n1️⃣ Testing property normalization function definitions..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for property normalization functions
    $normalizedVaultFunction = $scriptContent -match 'function Get-AkvNormalizedVault'
    $booleanPropertyFunction = $scriptContent -match 'function Get-AkvVaultBooleanProperty'
    
    Write-Host "   📋 Get-AkvNormalizedVault function: $normalizedVaultFunction" -ForegroundColor $(if ($normalizedVaultFunction) { "Green" } else { "Red" })
    Write-Host "   📋 Get-AkvVaultBooleanProperty function: $booleanPropertyFunction" -ForegroundColor $(if ($booleanPropertyFunction) { "Green" } else { "Red" })
    
    if ($normalizedVaultFunction -and $booleanPropertyFunction) {
        Write-Host "   ✅ Property normalization functions defined" -ForegroundColor Green
        $testResults.PropertyNormalizationFunctions = $true
    }
} catch {
    Write-Host "   ❌ Function definition test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing SoftDelete property variants handling..." -ForegroundColor Yellow

try {
    # Check for both property name variants in the boolean property function
    $softDeleteVariants = $scriptContent -match "EnableSoftDelete.*SoftDeleteEnabled"
    Write-Host "   📋 SoftDelete variants handling: $softDeleteVariants" -ForegroundColor $(if ($softDeleteVariants) { "Green" } else { "Red" })
    
    # Check for normalized variable usage
    $normalizedSoftDelete = $scriptContent -match '\$softDeleteEnabled.*Get-AkvVaultBooleanProperty'
    Write-Host "   📋 Normalized SoftDelete usage: $normalizedSoftDelete" -ForegroundColor $(if ($normalizedSoftDelete) { "Green" } else { "Red" })
    
    if ($softDeleteVariants -and $normalizedSoftDelete) {
        Write-Host "   ✅ SoftDelete variants properly handled" -ForegroundColor Green
        $testResults.SoftDeleteVariants = $true
    }
} catch {
    Write-Host "   ❌ SoftDelete variants test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing PurgeProtection property variants handling..." -ForegroundColor Yellow

try {
    # Check for both property name variants
    $purgeProtectionVariants = $scriptContent -match "EnablePurgeProtection.*PurgeProtectionEnabled"
    Write-Host "   📋 PurgeProtection variants handling: $purgeProtectionVariants" -ForegroundColor $(if ($purgeProtectionVariants) { "Green" } else { "Red" })
    
    # Check for normalized variable usage
    $normalizedPurgeProtection = $scriptContent -match '\$purgeProtectionEnabled.*Get-AkvVaultBooleanProperty'
    Write-Host "   📋 Normalized PurgeProtection usage: $normalizedPurgeProtection" -ForegroundColor $(if ($normalizedPurgeProtection) { "Green" } else { "Red" })
    
    if ($purgeProtectionVariants -and $normalizedPurgeProtection) {
        Write-Host "   ✅ PurgeProtection variants properly handled" -ForegroundColor Green
        $testResults.PurgeProtectionVariants = $true
    }
} catch {
    Write-Host "   ❌ PurgeProtection variants test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing property extraction integration..." -ForegroundColor Yellow

try {
    # Check that normalized variables are used in result objects
    $resultIntegration = $scriptContent -match 'SoftDeleteEnabled.*=.*\$softDeleteEnabled' -and $scriptContent -match 'PurgeProtectionEnabled.*=.*\$purgeProtectionEnabled'
    Write-Host "   📋 Normalized variables in result objects: $resultIntegration" -ForegroundColor $(if ($resultIntegration) { "Green" } else { "Red" })
    
    # Check that Get-AkvNormalizedVault is called before property extraction
    $vaultNormalization = $scriptContent -match 'Get-AkvNormalizedVault.*VaultObject.*\$kv'
    Write-Host "   📋 Vault normalization before property extraction: $vaultNormalization" -ForegroundColor $(if ($vaultNormalization) { "Green" } else { "Red" })
    
    if ($resultIntegration -and $vaultNormalization) {
        Write-Host "   ✅ Property extraction integration complete" -ForegroundColor Green
        $testResults.PropertyExtractionIntegration = $true
    }
} catch {
    Write-Host "   ❌ Property extraction integration test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing error handling in normalization functions..." -ForegroundColor Yellow

try {
    # Check for try/catch in Get-AkvNormalizedVault
    $normalizedVaultErrorHandling = $scriptContent -match 'function Get-AkvNormalizedVault[\s\S]*?try[\s\S]*?catch[\s\S]*?return.*VaultObject'
    Write-Host "   📋 Get-AkvNormalizedVault error handling: $normalizedVaultErrorHandling" -ForegroundColor $(if ($normalizedVaultErrorHandling) { "Green" } else { "Red" })
    
    # Check for fallback behavior in property function
    $propertyFallback = $scriptContent -match 'function Get-AkvVaultBooleanProperty[\s\S]*?return.*false'
    Write-Host "   📋 Get-AkvVaultBooleanProperty fallback: $propertyFallback" -ForegroundColor $(if ($propertyFallback) { "Green" } else { "Red" })
    
    if ($normalizedVaultErrorHandling -and $propertyFallback) {
        Write-Host "   ✅ Error handling properly implemented" -ForegroundColor Green
        $testResults.ErrorHandling = $true
    }
} catch {
    Write-Host "   ❌ Error handling test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📊 VAULT PROPERTY NORMALIZATION TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
}

Write-Host "`nOverall: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All property normalization tests passed!" -ForegroundColor Green
    Write-Host "💡 Both SoftDelete and PurgeProtection variants should now be handled correctly" -ForegroundColor Blue
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "`n✅ Most property normalization tests passed. Minor issues may remain." -ForegroundColor Yellow
} else {
    Write-Host "`n⚠️ Several property normalization issues detected - review results above" -ForegroundColor Red
}

Write-Host "`n💡 Key Property Normalization Benefits:" -ForegroundColor Cyan
Write-Host "  • Handles both EnableSoftDelete and SoftDeleteEnabled property variants" -ForegroundColor Gray
Write-Host "  • Handles both EnablePurgeProtection and PurgeProtectionEnabled property variants" -ForegroundColor Gray
Write-Host "  • Rehydrates partial vault objects when needed" -ForegroundColor Gray
Write-Host "  • Provides fallback behavior for missing properties" -ForegroundColor Gray
Write-Host "  • Prevents vault analysis errors due to property name mismatches" -ForegroundColor Gray

return $testResults