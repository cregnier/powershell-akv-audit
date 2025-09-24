#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test HTML report generation to identify actual .Count property errors
.DESCRIPTION
    This script simulates HTML report generation to identify runtime errors
    related to 'The property Count cannot be found on this object'
#>

[CmdletBinding()]
param()

Write-Host "🧪 TESTING HTML REPORT GENERATION FOR .Count ERRORS" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

if (-not (Test-Path $csvPath)) {
    Write-Host "❌ Test CSV file not found: $csvPath" -ForegroundColor Red
    return $false
}

Write-Host "`n1️⃣ Loading test CSV data..." -ForegroundColor Yellow
try {
    $csvData = Import-Csv $csvPath
    Write-Host "   ✅ CSV loaded: $($csvData.Count) records" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to load CSV: $_" -ForegroundColor Red
    return $false
}

Write-Host "`n2️⃣ Loading and testing HTML generation functions..." -ForegroundColor Yellow
try {
    # Source the main script to load functions
    . $scriptPath -ErrorAction Stop
    Write-Host "   ✅ Main script loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to load main script: $_" -ForegroundColor Red
    return $false
}

Write-Host "`n3️⃣ Testing ExecutiveSummary creation..." -ForegroundColor Yellow
try {
    # Create a test ExecutiveSummary 
    $executiveSummary = @{
        TotalKeyVaults = 1
        TotalServicePrincipals = 65
        TotalManagedIdentities = 8
        UserManagedIdentities = 2
        SystemManagedIdentities = 6
        FullyCompliant = 1
        PartiallyCompliant = 0
        NonCompliant = 0
        MicrosoftFullyCompliant = 1
        MicrosoftPartiallyCompliant = 0
        MicrosoftNonCompliant = 0
        CompanyFullyCompliant = 1
        CompanyPartiallyCompliant = 0
        CompanyNonCompliant = 0
        WithDiagnostics = 1
        WithEventHub = 0
        WithLogAnalytics = 1
        WithStorageAccount = 0
        WithPrivateEndpoints = 0
        WithSystemIdentity = 1
        UsingRBAC = 1
        UsingAccessPolicies = 0
        AverageComplianceScore = 95.0
        CompanyAverageScore = 95.0
        HighRiskVaults = 0
        CompliancePercentage = 100.0
    }
    
    Write-Host "   ✅ ExecutiveSummary created with $($executiveSummary.Keys.Count) properties" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Failed to create ExecutiveSummary: $_" -ForegroundColor Red
    return $false
}

Write-Host "`n4️⃣ Testing Update-ExecutiveSummaryFromAuditData function..." -ForegroundColor Yellow
try {
    if (Get-Command Update-ExecutiveSummaryFromAuditData -ErrorAction SilentlyContinue) {
        $updatedSummary = Update-ExecutiveSummaryFromAuditData -ExecutiveSummary $executiveSummary -AuditResults $csvData
        Write-Host "   ✅ Update-ExecutiveSummaryFromAuditData executed successfully" -ForegroundColor Green
        Write-Host "   📊 Updated summary keys: $($updatedSummary.Keys.Count)" -ForegroundColor Gray
    } else {
        Write-Host "   ⚠️ Update-ExecutiveSummaryFromAuditData function not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error in Update-ExecutiveSummaryFromAuditData: $_" -ForegroundColor Red
    Write-Host "   📝 Error details: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing placeholder generation..." -ForegroundColor Yellow
try {
    # Create placeholders hashtable
    $placeholders = @{}
    
    # Test typical placeholder creation patterns that might cause .Count issues
    $placeholders["{{TOTAL_KEY_VAULTS}}"] = $executiveSummary.TotalKeyVaults
    $placeholders["{{TOTAL_SERVICE_PRINCIPALS}}"] = $executiveSummary.TotalServicePrincipals
    $placeholders["{{TOTAL_MANAGED_IDENTITIES}}"] = $executiveSummary.TotalManagedIdentities
    
    # Test array/collection aggregations that might cause issues
    $servicePrincipalSum = ($csvData | Where-Object { $null -ne $_.ServicePrincipalCount } | Measure-Object -Property ServicePrincipalCount -Sum).Sum
    $managedIdentitySum = ($csvData | Where-Object { $null -ne $_.ManagedIdentityCount } | Measure-Object -Property ManagedIdentityCount -Sum).Sum
    
    $placeholders["{{AGGREGATED_SP_COUNT}}"] = $servicePrincipalSum
    $placeholders["{{AGGREGATED_MI_COUNT}}"] = $managedIdentitySum
    
    Write-Host "   ✅ Placeholders created: $($placeholders.Keys.Count) items" -ForegroundColor Green
    Write-Host "   📊 Service Principals (aggregated): $servicePrincipalSum" -ForegroundColor Gray
    Write-Host "   📊 Managed Identities (aggregated): $managedIdentitySum" -ForegroundColor Gray
    
} catch {
    Write-Host "   ❌ Error in placeholder generation: $_" -ForegroundColor Red
    Write-Host "   📝 Error details: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6️⃣ Testing actual HTML generation function..." -ForegroundColor Yellow
try {
    if (Get-Command New-ComprehensiveHtmlReport -ErrorAction SilentlyContinue) {
        $htmlPath = Join-Path $PSScriptRoot "test_output.html"
        $result = New-ComprehensiveHtmlReport -ExecutiveSummary $executiveSummary -AuditResults $csvData -OutputPath $htmlPath
        
        if ($result -and (Test-Path $htmlPath)) {
            Write-Host "   ✅ HTML report generated successfully" -ForegroundColor Green
            $htmlSize = (Get-Item $htmlPath).Length
            Write-Host "   📄 HTML file size: $([math]::Round($htmlSize / 1KB, 2)) KB" -ForegroundColor Gray
        } else {
            Write-Host "   ❌ HTML report generation failed" -ForegroundColor Red
        }
    } else {
        Write-Host "   ⚠️ New-ComprehensiveHtmlReport function not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error in HTML generation: $_" -ForegroundColor Red
    Write-Host "   📝 Error details: $($_.Exception.Message)" -ForegroundColor Red
    
    # Check if this is the specific Count property error
    if ($_.Exception.Message -match "property.*Count.*cannot be found") {
        Write-Host "   🎯 FOUND THE .Count PROPERTY ERROR!" -ForegroundColor Red
        Write-Host "   📝 This is the exact error we need to fix" -ForegroundColor Red
    }
}

Write-Host "`n📊 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray

return $true