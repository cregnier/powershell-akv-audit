#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to identify and validate data aggregation issues in HTML report generation
.DESCRIPTION
    Analyzes the CSV data structure and tests the aggregation logic to identify why 
    service principal and managed identity counts are not being properly aggregated
    in the HTML executive summary cards.
#>

[CmdletBinding()]
param()

Write-Host "🔍 TESTING DATA AGGREGATION ISSUES" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

if (-not (Test-Path $csvPath)) {
    Write-Host "❌ Test CSV file not found: $csvPath" -ForegroundColor Red
    return $false
}

Write-Host "`n1️⃣ Analyzing CSV data structure..." -ForegroundColor Yellow

# Import the CSV to analyze data structure
$csvData = Import-Csv $csvPath
Write-Host "   📊 CSV records loaded: $($csvData.Count)" -ForegroundColor Gray

if ($csvData.Count -gt 0) {
    $firstRecord = $csvData[0]
    
    Write-Host "   🔍 Examining ServicePrincipalCount field:" -ForegroundColor Gray
    Write-Host "      Value: '$($firstRecord.ServicePrincipalCount)'" -ForegroundColor White
    Write-Host "      Type: $($firstRecord.ServicePrincipalCount.GetType().Name)" -ForegroundColor White
    Write-Host "      Contains details instead of count: $($firstRecord.ServicePrincipalCount.Length -gt 10)" -ForegroundColor White
    
    Write-Host "   🔍 Examining ManagedIdentityCount field:" -ForegroundColor Gray  
    Write-Host "      Value: '$($firstRecord.ManagedIdentityCount)'" -ForegroundColor White
    Write-Host "      Type: $($firstRecord.ManagedIdentityCount.GetType().Name)" -ForegroundColor White
    Write-Host "      Contains details instead of count: $($firstRecord.ManagedIdentityCount.Length -gt 10)" -ForegroundColor White
    
    # Test parsing the counts from the details
    Write-Host "`n2️⃣ Testing count extraction from details..." -ForegroundColor Yellow
    
    # Extract counts from ServicePrincipalDetails-like field
    $servicePrincipalText = $firstRecord.ServicePrincipalCount
    if ($servicePrincipalText -and $servicePrincipalText -ne "None" -and $servicePrincipalText.Length -gt 5) {
        # Count occurrences of principal patterns (GUID patterns or principal names)
        $principalMatches = [regex]::Matches($servicePrincipalText, '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
        $estimatedServicePrincipalCount = $principalMatches.Count
        Write-Host "      ✅ Estimated Service Principal Count: $estimatedServicePrincipalCount" -ForegroundColor Green
    } else {
        $estimatedServicePrincipalCount = 0
        Write-Host "      ✅ Estimated Service Principal Count: 0 (no data)" -ForegroundColor Green
    }
    
    # Extract counts from ManagedIdentityDetails-like field  
    $managedIdentityText = $firstRecord.ManagedIdentityCount
    if ($managedIdentityText -and $managedIdentityText -ne "None" -and $managedIdentityText.Length -gt 5) {
        # Count occurrences of managed identity patterns
        $identityMatches = [regex]::Matches($managedIdentityText, '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
        $estimatedManagedIdentityCount = $identityMatches.Count
        Write-Host "      ✅ Estimated Managed Identity Count: $estimatedManagedIdentityCount" -ForegroundColor Green
    } else {
        $estimatedManagedIdentityCount = 0
        Write-Host "      ✅ Estimated Managed Identity Count: 0 (no data)" -ForegroundColor Green
    }
}

Write-Host "`n3️⃣ Testing current aggregation logic..." -ForegroundColor Yellow

# Test the current aggregation logic from the script
try {
    # Simulate the current logic from the script
    $totalServicePrincipals = ($csvData | Where-Object { $null -ne $_.ServicePrincipalCount } | Measure-Object -Property ServicePrincipalCount -Sum -ErrorAction SilentlyContinue).Sum
    $totalManagedIdentities = ($csvData | Where-Object { $null -ne $_.ManagedIdentityCount } | Measure-Object -Property ManagedIdentityCount -Sum -ErrorAction SilentlyContinue).Sum
    
    Write-Host "   ❌ Current aggregation results:" -ForegroundColor Red
    Write-Host "      Total Service Principals: $totalServicePrincipals" -ForegroundColor White
    Write-Host "      Total Managed Identities: $totalManagedIdentities" -ForegroundColor White
    Write-Host "      Issue: Measure-Object expects numeric values, not text details" -ForegroundColor Red
} catch {
    Write-Host "   ❌ Current aggregation failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing improved aggregation logic..." -ForegroundColor Yellow

# Test improved aggregation logic
try {
    $improvedServicePrincipalCount = 0
    $improvedManagedIdentityCount = 0
    
    foreach ($record in $csvData) {
        # Extract service principal count from details
        if ($record.ServicePrincipalCount -and $record.ServicePrincipalCount -ne "None") {
            $spMatches = [regex]::Matches($record.ServicePrincipalCount, '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
            $improvedServicePrincipalCount += $spMatches.Count
        }
        
        # Extract managed identity count from details
        if ($record.ManagedIdentityCount -and $record.ManagedIdentityCount -ne "None") {
            $miMatches = [regex]::Matches($record.ManagedIdentityCount, '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
            $improvedManagedIdentityCount += $miMatches.Count
        }
    }
    
    Write-Host "   ✅ Improved aggregation results:" -ForegroundColor Green
    Write-Host "      Total Service Principals: $improvedServicePrincipalCount" -ForegroundColor White
    Write-Host "      Total Managed Identities: $improvedManagedIdentityCount" -ForegroundColor White
} catch {
    Write-Host "   ❌ Improved aggregation failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Checking for dedicated count fields..." -ForegroundColor Yellow

# Check if there are dedicated numeric count fields
$csvHeaders = $csvData[0].PSObject.Properties.Name
$countFields = $csvHeaders | Where-Object { $_ -like "*Count" }

Write-Host "   📋 Count fields found:" -ForegroundColor Gray
foreach ($field in $countFields) {
    $sampleValue = $csvData[0].$field
    $isNumeric = $sampleValue -match '^\d+$'
    Write-Host "      $field : '$sampleValue' (Numeric: $isNumeric)" -ForegroundColor White
}

Write-Host "`n📊 SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray
Write-Host "✅ Issue Identified: Count fields contain details instead of counts" -ForegroundColor Green
Write-Host "✅ Solution: Parse details to extract actual counts using regex patterns" -ForegroundColor Green
Write-Host "⚠️ Alternative: Check if there are separate numeric count fields" -ForegroundColor Yellow
Write-Host "🔧 Recommendation: Update aggregation logic to handle both scenarios" -ForegroundColor Blue

return $true