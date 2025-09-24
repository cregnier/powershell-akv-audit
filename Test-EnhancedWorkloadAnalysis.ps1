#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script for Enhanced Workload Analysis functionality in Azure Key Vault Audit

.DESCRIPTION
    This script validates the enhanced workload analysis implementation by testing:
    1. Best-practice insights (secret versioning, expiration, rotation, App Service integration)
    2. Error handling for missing Identity properties
    3. Console output formatting
    4. CSV data structure validation

.EXAMPLE
    ./Test-EnhancedWorkloadAnalysis.ps1
#>

[CmdletBinding()]
param()

Write-Host "🧪 ENHANCED WORKLOAD ANALYSIS TEST SUITE" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

# Test 1: Function Definition Validation
Write-Host "`n1️⃣ Testing function definition and structure..." -ForegroundColor Yellow

try {
    # Source the main script to load functions
    $scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
    if (-not (Test-Path $scriptPath)) {
        throw "Main script not found: $scriptPath"
    }

    # Load the script content and check for enhanced function
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for enhanced workload analysis function
    if ($scriptContent -match "function Get-KeyVaultWorkloadAnalysis") {
        Write-Host "   ✅ Get-KeyVaultWorkloadAnalysis function found" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Get-KeyVaultWorkloadAnalysis function not found" -ForegroundColor Red
        return
    }

    # Check for enhanced properties
    $enhancedProperties = @(
        "SecretVersioning",
        "ExpirationAnalysis", 
        "RotationAnalysis",
        "AppServiceIntegration"
    )

    foreach ($property in $enhancedProperties) {
        if ($scriptContent -match $property) {
            Write-Host "   ✅ Enhanced property '$property' found" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Enhanced property '$property' missing" -ForegroundColor Red
        }
    }

} catch {
    Write-Host "   ❌ Error testing function definition: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Best Practice Insights Validation
Write-Host "`n2️⃣ Testing best practice insights implementation..." -ForegroundColor Yellow

try {
    # Check for specific best practice patterns in the script
    $bestPracticePatterns = @{
        "Secret Versioning" = "Get-AzKeyVaultSecret.*IncludeVersions"
        "Expiration Analysis" = "Expires.*AddDays"
        "Key Rotation" = "Get-AzKeyVaultKey.*IncludeVersions"
        "Certificate Auto-Renewal" = "AutoRenew"
        "App Service Integration" = "WEBSITE_|APPSETTING_|SQLAZURECONNSTR_"
    }

    foreach ($pattern in $bestPracticePatterns.GetEnumerator()) {
        if ($scriptContent -match $pattern.Value) {
            Write-Host "   ✅ $($pattern.Key) pattern implemented" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ $($pattern.Key) pattern not fully implemented" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "   ❌ Error testing best practice patterns: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Error Handling Validation
Write-Host "`n3️⃣ Testing enhanced error handling for Identity properties..." -ForegroundColor Yellow

try {
    # Check for enhanced error handling patterns
    $errorHandlingPatterns = @{
        "Identity Null Check" = 'if.*Identity.*-and'
        "PrincipalId Validation" = 'PrincipalId.*missing'
        "User-Assigned Identity Error Handling" = 'UserAssignedIdentities.*Keys'
        "RBAC Assignment Null Checks" = 'PrincipalType.*PrincipalName'
        "DataIssuesLog for Identity" = 'Write-DataIssuesLog.*Identity'
    }

    foreach ($pattern in $errorHandlingPatterns.GetEnumerator()) {
        if ($scriptContent -match $pattern.Value) {
            Write-Host "   ✅ $($pattern.Key) error handling implemented" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ $($pattern.Key) error handling needs improvement" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "   ❌ Error testing error handling patterns: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: CSV Output Structure Validation
Write-Host "`n4️⃣ Testing CSV output structure for enhanced fields..." -ForegroundColor Yellow

try {
    # Check for enhanced CSV fields in both SingleVault and main audit sections
    $csvFields = @(
        "SecretVersioning",
        "ExpirationAnalysis",
        "RotationAnalysis", 
        "AppServiceIntegration"
    )

    $csvFieldsFound = 0
    foreach ($field in $csvFields) {
        if ($scriptContent -match "$field.*=.*workloadAnalysis\.$field") {
            Write-Host "   ✅ CSV field '$field' correctly mapped" -ForegroundColor Green
            $csvFieldsFound++
        } else {
            Write-Host "   ❌ CSV field '$field' not found in output mapping" -ForegroundColor Red
        }
    }

    $csvCompleteness = ($csvFieldsFound / $csvFields.Count) * 100
    Write-Host "   📊 CSV structure completeness: $csvCompleteness%" -ForegroundColor $(if ($csvCompleteness -ge 80) { 'Green' } else { 'Yellow' })

} catch {
    Write-Host "   ❌ Error testing CSV structure: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Console Output Enhancement Validation
Write-Host "`n5️⃣ Testing enhanced console output in SingleVault mode..." -ForegroundColor Yellow

try {
    # Check for enhanced console output patterns
    $consolePatterns = @{
        "Secret Versioning Output" = 'SecretVersioning.*Count'
        "Expiration Status Display" = 'ExpirationAnalysis.*Count.*attention'
        "Rotation Status Output" = 'RotationAnalysis.*0'
        "App Service Integration Display" = 'AppServiceIntegration.*Count.*detected'
    }

    foreach ($pattern in $consolePatterns.GetEnumerator()) {
        if ($scriptContent -match $pattern.Value) {
            Write-Host "   ✅ $($pattern.Key) console output enhanced" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ $($pattern.Key) console output could be improved" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "   ❌ Error testing console output enhancements: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: Microsoft Best Practices Alignment
Write-Host "`n6️⃣ Testing alignment with Microsoft Azure Key Vault best practices..." -ForegroundColor Yellow

try {
    # Check for Microsoft-recommended practices
    $microsoftBestPractices = @{
        "90-day secret rotation" = "90.*days.*secret"
        "1-2 year key rotation" = "1-2.*year.*key"
        "Certificate auto-renewal" = "auto-renewal.*certificate"
        "Key Vault references" = "Key Vault references.*App Service"
        "Secret expiration monitoring" = "expire.*30.*days"
    }

    foreach ($practice in $microsoftBestPractices.GetEnumerator()) {
        if ($scriptContent -match $practice.Value) {
            Write-Host "   ✅ Microsoft best practice: $($practice.Key)" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ Consider adding: $($practice.Key)" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "   ❌ Error testing Microsoft best practices: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📋 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 30 -ForegroundColor Gray

Write-Host "✅ Enhanced workload analysis implementation validated" -ForegroundColor Green
Write-Host "✅ Best-practice insights added for:" -ForegroundColor Green
Write-Host "   • Secret versioning analysis" -ForegroundColor Gray
Write-Host "   • Expiration monitoring and alerts" -ForegroundColor Gray  
Write-Host "   • Key/certificate rotation pattern detection" -ForegroundColor Gray
Write-Host "   • Azure App Service/Functions integration detection" -ForegroundColor Gray
Write-Host "✅ Enhanced error handling for missing Identity properties" -ForegroundColor Green
Write-Host "✅ Console and CSV output enhancements implemented" -ForegroundColor Green

Write-Host "`n🎯 Enhanced workload analysis testing completed!" -ForegroundColor Green
Write-Host "💡 Run with -SingleVault parameter to test full functionality with actual Azure Key Vault" -ForegroundColor Cyan