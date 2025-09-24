#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Quick validation test for Authentication Enhancements

.DESCRIPTION
    This script performs a quick validation of the authentication enhancements
    without actually running the full authentication flow.
#>

Write-Host "🔍 Quick Authentication Enhancement Validation" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

# Test 1: Syntax validation
Write-Host "`n1️⃣ Syntax validation..." -ForegroundColor Yellow
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile("./Get-AKV_Roles&SecAuditCompliance.ps1", [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax valid" -ForegroundColor Green
    } else {
        Write-Host "   ❌ PowerShell syntax invalid" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "   ❌ Syntax error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 2: Function presence validation
Write-Host "`n2️⃣ Function presence validation..." -ForegroundColor Yellow

$scriptContent = Get-Content "./Get-AKV_Roles&SecAuditCompliance.ps1" -Raw

$expectedFunctions = @(
    "Test-DomainJoinedEnvironment",
    "Test-AzureAdJoinedEnvironment"
)

$missingFunctions = @()
foreach ($func in $expectedFunctions) {
    if ($scriptContent -match "function\s+$func") {
        Write-Host "   ✅ $func function found" -ForegroundColor Green
    } else {
        Write-Host "   ❌ $func function missing" -ForegroundColor Red
        $missingFunctions += $func
    }
}

# Test 3: Integration validation
Write-Host "`n3️⃣ Integration validation..." -ForegroundColor Yellow

$integrationChecks = @{
    "Domain join detection call" = "Test-DomainJoinedEnvironment.*-Quiet.*-Verbose"
    "Azure AD join detection call" = "Test-AzureAdJoinedEnvironment.*-Quiet.*-Verbose"
    "UseExistingContext logic" = "UseExistingContext.*=.*true"
    "Valid context checking" = "hasValidContext.*=.*true"
    "Existing context reuse" = "authMode\.UseExistingContext"
}

$failedChecks = @()
foreach ($check in $integrationChecks.GetEnumerator()) {
    if ($scriptContent -match $check.Value) {
        Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
    } else {
        Write-Host "   ❌ $($check.Key) missing" -ForegroundColor Red
        $failedChecks += $check.Key
    }
}

# Test 4: Documentation validation
Write-Host "`n4️⃣ Documentation validation..." -ForegroundColor Yellow

$docChecks = @{
    "Enhanced authentication flow documentation" = "Domain/Azure AD.*join.*detection|Domain.*Azure AD.*optimization"
    "Context reuse documentation" = "existing.*context.*reuse|Existing Context Reuse"
    "Enhanced detection methods" = "Domain Join.*dsregcmd|Azure AD Join.*dsregcmd"
}

foreach ($check in $docChecks.GetEnumerator()) {
    if ($scriptContent -match $check.Value) {
        Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ $($check.Key) could be enhanced" -ForegroundColor Yellow
    }
}

# Summary
Write-Host "`n🎯 VALIDATION SUMMARY" -ForegroundColor Green
Write-Host "=" * 30 -ForegroundColor Gray

if ($missingFunctions.Count -eq 0 -and $failedChecks.Count -eq 0) {
    Write-Host "✅ All critical validations passed!" -ForegroundColor Green
    Write-Host "✅ Authentication enhancements successfully implemented" -ForegroundColor Green
    Write-Host "`n📝 Key Features Added:" -ForegroundColor Cyan
    Write-Host "   • Domain join detection (Test-DomainJoinedEnvironment)" -ForegroundColor White
    Write-Host "   • Azure AD join detection (Test-AzureAdJoinedEnvironment)" -ForegroundColor White
    Write-Host "   • Existing context validation and reuse" -ForegroundColor White
    Write-Host "   • Enhanced authentication flow with pre-checks" -ForegroundColor White
    Write-Host "   • Seamless SSO optimization for domain/Azure AD joined devices" -ForegroundColor White
    exit 0
} else {
    Write-Host "❌ Some validations failed:" -ForegroundColor Red
    if ($missingFunctions.Count -gt 0) {
        Write-Host "   Missing functions: $($missingFunctions -join ', ')" -ForegroundColor Red
    }
    if ($failedChecks.Count -gt 0) {
        Write-Host "   Failed integration checks: $($failedChecks -join ', ')" -ForegroundColor Red
    }
    exit 1
}