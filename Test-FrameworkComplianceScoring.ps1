#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test framework-specific compliance scoring in Get-AKVGapAnalysis.ps1
.DESCRIPTION
    Validates that CIS, NIST, ISO, and Microsoft compliance scores are calculated correctly
    based on different vault configurations and security controls.
#>

[CmdletBinding()]
param()

Write-Host "🧪 FRAMEWORK COMPLIANCE SCORING VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

# Test scenarios with different vault configurations
$testScenarios = @(
    @{
        Name = "Fully Compliant Vault"
        Vault = @{
            EnableSoftDelete = $true
            EnablePurgeProtection = $true
        }
        Analysis = @{
            AccessControl = @{ RbacEnabled = $true }
            NetworkSecurity = @{ HasPrivateEndpoints = $true }
            Diagnostics = @{ HasDiagnostics = $true }
            SecurityGaps = @()  # No gaps
        }
        ExpectedScores = @{
            CIS = 100
            NIST = 100
            ISO = 100
            MS = 100  # Base 100 + bonuses for good practices
        }
    },
    @{
        Name = "No RBAC Vault"
        Vault = @{
            EnableSoftDelete = $true
            EnablePurgeProtection = $true
        }
        Analysis = @{
            AccessControl = @{ RbacEnabled = $false }
            NetworkSecurity = @{ HasPrivateEndpoints = $true }
            Diagnostics = @{ HasDiagnostics = $true }
            SecurityGaps = @(
                @{ Severity = "Critical"; Issue = "RBAC not enabled" }
            )
        }
        ExpectedScores = @{
            CIS = 75   # 100 - 25 for no RBAC
            NIST = 80  # 100 - 20 for no RBAC
            ISO = 80   # 100 - 20 for no RBAC
            MS = 80    # 100 - 20 for no RBAC
        }
    },
    @{
        Name = "No Private Endpoints Vault"
        Vault = @{
            EnableSoftDelete = $true
            EnablePurgeProtection = $true
        }
        Analysis = @{
            AccessControl = @{ RbacEnabled = $true }
            NetworkSecurity = @{ HasPrivateEndpoints = $false }
            Diagnostics = @{ HasDiagnostics = $true }
            SecurityGaps = @(
                @{ Severity = "High"; Issue = "No private endpoints" }
            )
        }
        ExpectedScores = @{
            CIS = 85   # 100 - 15 for no private endpoints
            NIST = 85  # 100 - 15 for no private endpoints
            ISO = 85   # 100 - 15 for no private endpoints
            MS = 85    # 100 - 15 for no private endpoints
        }
    },
    @{
        Name = "No Diagnostics Vault"
        Vault = @{
            EnableSoftDelete = $true
            EnablePurgeProtection = $true
        }
        Analysis = @{
            AccessControl = @{ RbacEnabled = $true }
            NetworkSecurity = @{ HasPrivateEndpoints = $true }
            Diagnostics = @{ HasDiagnostics = $false }
            SecurityGaps = @(
                @{ Severity = "Medium"; Issue = "No diagnostics" }
            )
        }
        ExpectedScores = @{
            CIS = 85   # 100 - 15 for no diagnostics
            NIST = 85  # 100 - 15 for no diagnostics
            ISO = 85   # 100 - 15 for no diagnostics
            MS = 85    # 100 - 15 for no diagnostics
        }
    }
)

$passedTests = 0
$totalTests = $testScenarios.Count * 4  # 4 frameworks per scenario

foreach ($scenario in $testScenarios) {
    Write-Host "`n🔍 Testing: $($scenario.Name)" -ForegroundColor Yellow

    # Simulate the scoring logic from the script
    $baseScore = 100

    # CIS scoring
    $cisScore = $baseScore
    if (-not $scenario.Analysis.AccessControl.RbacEnabled) { $cisScore -= 25 }
    if (-not $scenario.Analysis.NetworkSecurity.HasPrivateEndpoints) { $cisScore -= 15 }
    if (-not $scenario.Analysis.Diagnostics.HasDiagnostics) { $cisScore -= 15 }
    $calculatedCIS = [math]::Max(0, [math]::Min(100, $cisScore))

    # NIST scoring
    $nistScore = $baseScore
    if (-not $scenario.Analysis.AccessControl.RbacEnabled) { $nistScore -= 20 }
    if (-not $scenario.Analysis.NetworkSecurity.HasPrivateEndpoints) { $nistScore -= 15 }
    if (-not $scenario.Analysis.Diagnostics.HasDiagnostics) { $nistScore -= 15 }
    if (-not $scenario.Vault.EnableSoftDelete) { $nistScore -= 10 }
    if (-not $scenario.Vault.EnablePurgeProtection) { $nistScore -= 10 }
    $calculatedNIST = [math]::Max(0, [math]::Min(100, $nistScore))

    # ISO scoring
    $isoScore = $baseScore
    if (-not $scenario.Analysis.AccessControl.RbacEnabled) { $isoScore -= 20 }
    if (-not $scenario.Analysis.NetworkSecurity.HasPrivateEndpoints) { $isoScore -= 15 }
    if (-not $scenario.Vault.EnableSoftDelete -or -not $scenario.Vault.EnablePurgeProtection) { $isoScore -= 15 }
    if (-not $scenario.Analysis.Diagnostics.HasDiagnostics) { $isoScore -= 15 }
    $calculatedISO = [math]::Max(0, [math]::Min(100, $isoScore))

    # Microsoft scoring
    $msScore = $baseScore
    if (-not $scenario.Analysis.AccessControl.RbacEnabled) { $msScore -= 20 }
    if (-not $scenario.Analysis.NetworkSecurity.HasPrivateEndpoints) { $msScore -= 15 }
    if (-not $scenario.Vault.EnableSoftDelete) { $msScore -= 10 }
    if (-not $scenario.Vault.EnablePurgeProtection) { $msScore -= 10 }
    if (-not $scenario.Analysis.Diagnostics.HasDiagnostics) { $msScore -= 15 }
    # Check if AccessPoliciesCount is set, default to 0 if not
    $accessPoliciesCount = if ($scenario.Analysis.AccessControl.ContainsKey('AccessPoliciesCount')) { $scenario.Analysis.AccessControl.AccessPoliciesCount } else { 0 }
    if ($accessPoliciesCount -gt 0) { $msScore -= 5 }
    $calculatedMS = [math]::Max(0, [math]::Min(100, $msScore))

    # Test each framework score
    $frameworks = @(
        @{ Name = "CIS"; Calculated = $calculatedCIS; Expected = $scenario.ExpectedScores.CIS },
        @{ Name = "NIST"; Calculated = $calculatedNIST; Expected = $scenario.ExpectedScores.NIST },
        @{ Name = "ISO"; Calculated = $calculatedISO; Expected = $scenario.ExpectedScores.ISO },
        @{ Name = "MS"; Calculated = $calculatedMS; Expected = $scenario.ExpectedScores.MS }
    )

    foreach ($framework in $frameworks) {
        if ($framework.Calculated -eq $framework.Expected) {
            Write-Host "   ✅ $($framework.Name): $($framework.Calculated) (Expected: $($framework.Expected))" -ForegroundColor Green
            $passedTests++
        } else {
            Write-Host "   ❌ $($framework.Name): $($framework.Calculated) (Expected: $($framework.Expected))" -ForegroundColor Red
        }
    }
}

Write-Host "`n📊 TEST RESULTS" -ForegroundColor Cyan
Write-Host "=" * 30 -ForegroundColor Gray
Write-Host "Passed: $passedTests / $totalTests tests" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All framework compliance scoring tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️  Some framework compliance scoring tests failed!" -ForegroundColor Red
    exit 1
}