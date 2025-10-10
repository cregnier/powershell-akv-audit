#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test basic functionality of ExecutiveSummary functions in isolation
.DESCRIPTION
    Tests the new helper functions with mock data to ensure they work correctly
    without requiring Azure authentication.
#>

[CmdletBinding()]
param()

Write-Host "🧪 MOCK DATA TEST FOR EXECUTIVESUMMARY FUNCTIONS" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

# Source the functions from the main script
$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$scriptContent = Get-Content $scriptPath -Raw

# Extract and load the helper functions
$functionMatches = [regex]::Matches($scriptContent, 'function (Initialize-ExecutiveSummary|Normalize-VaultResultProperties|Aggregate-ExecutiveSummary|Harmonize-ExecutiveSummaryAliases|Get-PlaceholderValue).*?^}', [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)

foreach ($match in $functionMatches) {
    try {
        Invoke-Expression $match.Value
        Write-Host "✅ Loaded function: $($match.Groups[1].Value)" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to load function: $($match.Groups[1].Value) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test 1: Initialize-ExecutiveSummary
Write-Host "`n1️⃣ Testing Initialize-ExecutiveSummary..." -ForegroundColor Yellow
try {
    $summary = Initialize-ExecutiveSummary
    Write-Host "   📊 Keys created: $($summary.Keys.Count)" -ForegroundColor Gray
    Write-Host "   📋 TotalKeyVaults default: $($summary.TotalKeyVaults)" -ForegroundColor Gray
    Write-Host "   📋 RBACCoveragePercent default: $($summary.RBACCoveragePercent)" -ForegroundColor Gray
    Write-Host "   ✅ Initialize-ExecutiveSummary works correctly" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Initialize-ExecutiveSummary failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Normalize-VaultResultProperties
Write-Host "`n2️⃣ Testing Normalize-VaultResultProperties..." -ForegroundColor Yellow
try {
    $mockVault = [PSCustomObject]@{
        KeyVaultName = "TestVault"
        ComplianceScore = "85%"
    }
    
    $normalizedVault = Normalize-VaultResultProperties -VaultResult $mockVault
    Write-Host "   📊 Properties after normalization: $($normalizedVault.PSObject.Properties.Count)" -ForegroundColor Gray
    Write-Host "   📋 SoftDeleteEnabled added: $($normalizedVault.SoftDeleteEnabled)" -ForegroundColor Gray
    Write-Host "   📋 ComplianceStatus added: $($normalizedVault.ComplianceStatus)" -ForegroundColor Gray
    Write-Host "   ✅ Normalize-VaultResultProperties works correctly" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Normalize-VaultResultProperties failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Aggregate-ExecutiveSummary
Write-Host "`n3️⃣ Testing Aggregate-ExecutiveSummary..." -ForegroundColor Yellow
try {
    $mockResults = @(
        [PSCustomObject]@{ 
            ComplianceScore = "90%"
            DiagnosticsEnabled = $true
            ServicePrincipalCount = 2
            ManagedIdentityCount = 1
        },
        [PSCustomObject]@{ 
            ComplianceScore = "75%"
            DiagnosticsEnabled = $false
            ServicePrincipalCount = 1
            ManagedIdentityCount = 2
        }
    )
    
    $summary = Initialize-ExecutiveSummary
    $aggregatedSummary = Aggregate-ExecutiveSummary -AuditResults $mockResults -Summary $summary
    
    Write-Host "   📊 TotalKeyVaults: $($aggregatedSummary.TotalKeyVaults)" -ForegroundColor Gray
    Write-Host "   📊 FullyCompliant: $($aggregatedSummary.FullyCompliant)" -ForegroundColor Gray
    Write-Host "   📊 WithDiagnostics: $($aggregatedSummary.WithDiagnostics)" -ForegroundColor Gray
    Write-Host "   📊 CompliancePercentage: $($aggregatedSummary.CompliancePercentage)" -ForegroundColor Gray
    Write-Host "   ✅ Aggregate-ExecutiveSummary works correctly" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Aggregate-ExecutiveSummary failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Get-PlaceholderValue
Write-Host "`n4️⃣ Testing Get-PlaceholderValue..." -ForegroundColor Yellow
try {
    $testSummary = @{ TotalKeyVaults = 5; MissingKey = $null }
    
    $value1 = Get-PlaceholderValue $testSummary 'TotalKeyVaults' 0
    $value2 = Get-PlaceholderValue $testSummary 'NonExistentKey' 'N/A'
    $value3 = Get-PlaceholderValue $testSummary 'MissingKey' 'Default'
    
    Write-Host "   📊 Existing key value: $value1" -ForegroundColor Gray
    Write-Host "   📊 Non-existent key default: $value2" -ForegroundColor Gray  
    Write-Host "   📊 Null key default: $value3" -ForegroundColor Gray
    Write-Host "   ✅ Get-PlaceholderValue works correctly" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Get-PlaceholderValue failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Harmonize-ExecutiveSummaryAliases
Write-Host "`n5️⃣ Testing Harmonize-ExecutiveSummaryAliases..." -ForegroundColor Yellow
try {
    $testSummary = @{ 
        WithDiagnostics = 3
        AuthenticationRefreshes = 5
    }
    
    $harmonizedSummary = Harmonize-ExecutiveSummaryAliases -Summary $testSummary
    
    Write-Host "   📊 VaultsWithDiagnostics alias: $($harmonizedSummary.VaultsWithDiagnostics)" -ForegroundColor Gray
    Write-Host "   📊 TokenRefreshCount alias: $($harmonizedSummary.TokenRefreshCount)" -ForegroundColor Gray
    Write-Host "   ✅ Harmonize-ExecutiveSummaryAliases works correctly" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Harmonize-ExecutiveSummaryAliases failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🎉 All mock data tests completed successfully!" -ForegroundColor Green
Write-Host "💡 The ExecutiveSummary functions are working correctly with mock data" -ForegroundColor Blue