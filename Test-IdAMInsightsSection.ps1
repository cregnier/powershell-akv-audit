#!/usr/bin/env pwsh
<#
.SYNOPSIS
    IdAM (Identity & Access Management) Insights section test script
.DESCRIPTION
    Tests and validates the IdAM Insights section data population,
    ensuring identity metrics like Service Principals, Managed Identities,
    RBAC assignments, and access policies are correctly aggregated.
#>

[CmdletBinding()]
param()

Write-Host "🔐 IdAM INSIGHTS SECTION TEST" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$csvPath = Join-Path $PSScriptRoot "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"

$testResults = @{
    DataAggregation = $false
    PlaceholderMapping = $false
    IdentityMetrics = $false
    AccessControlMetrics = $false
    SectionStructure = $false
}

Write-Host "`n1️⃣ Testing IdAM data aggregation..." -ForegroundColor Yellow

if (Test-Path $csvPath) {
    try {
        $csvData = Import-Csv $csvPath
        Write-Host "   📊 CSV records: $($csvData.Count)" -ForegroundColor Gray
        
        # Test identity metrics
        $totalServicePrincipals = ($csvData | Where-Object { $null -ne $_.ServicePrincipalCount } | Measure-Object -Property ServicePrincipalCount -Sum).Sum
        $totalManagedIdentities = ($csvData | Where-Object { $null -ne $_.ManagedIdentityCount } | Measure-Object -Property ManagedIdentityCount -Sum).Sum
        $totalUsers = ($csvData | Where-Object { $null -ne $_.UserCount } | Measure-Object -Property UserCount -Sum).Sum
        $totalGroups = ($csvData | Where-Object { $null -ne $_.GroupCount } | Measure-Object -Property GroupCount -Sum).Sum
        $systemAssignedCount = ($csvData | Where-Object { $_.SystemAssignedIdentity -eq "Yes" }).Count
        
        # Test access control metrics
        $totalRBACAssignments = ($csvData | Where-Object { $null -ne $_.RBACAssignmentCount } | Measure-Object -Property RBACAssignmentCount -Sum).Sum
        $totalAccessPolicies = ($csvData | Where-Object { $null -ne $_.AccessPolicyCount } | Measure-Object -Property AccessPolicyCount -Sum).Sum
        $connectedManagedIdentities = ($csvData | Where-Object { $null -ne $_.ConnectedManagedIdentityCount } | Measure-Object -Property ConnectedManagedIdentityCount -Sum).Sum
        $overPrivilegedCount = ($csvData | Where-Object { $_.OverPrivilegedAssignments -and $_.OverPrivilegedAssignments -ne "None" }).Count
        
        Write-Host "   🔐 Identity metrics:" -ForegroundColor White
        Write-Host "      Service Principals: $totalServicePrincipals" -ForegroundColor Green
        Write-Host "      Managed Identities: $totalManagedIdentities" -ForegroundColor Green
        Write-Host "      Users: $totalUsers" -ForegroundColor Green
        Write-Host "      Groups: $totalGroups" -ForegroundColor Green
        Write-Host "      System Assigned: $systemAssignedCount" -ForegroundColor Green
        
        Write-Host "   🔑 Access Control metrics:" -ForegroundColor White
        Write-Host "      RBAC Assignments: $totalRBACAssignments" -ForegroundColor Blue
        Write-Host "      Access Policies: $totalAccessPolicies" -ForegroundColor Blue
        Write-Host "      Connected Managed Identities: $connectedManagedIdentities" -ForegroundColor Blue
        Write-Host "      Over-privileged: $overPrivilegedCount" -ForegroundColor Yellow
        
        $testResults.DataAggregation = $true
    } catch {
        Write-Host "   ❌ Data aggregation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n2️⃣ Testing IdAM placeholder mapping..." -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for IdAM section existence
    $idamSectionExists = $scriptContent -match '🔐 IdAM Insights'
    Write-Host "   📋 IdAM Insights section found: $idamSectionExists" -ForegroundColor $(if ($idamSectionExists) { "Green" } else { "Red" })
    
    # Check for identity placeholders
    $identityPlaceholders = @(
        'TOTAL_SERVICE_PRINCIPALS',
        'TOTAL_MANAGED_IDENTITIES',
        'USER_COUNT',
        'GROUP_COUNT',
        'SYSTEM_ASSIGNED_COUNT',
        'USER_ASSIGNED_COUNT'
    )
    
    $foundIdentityPlaceholders = 0
    Write-Host "   🔐 Identity placeholders:" -ForegroundColor White
    foreach ($placeholder in $identityPlaceholders) {
        if ($scriptContent -match "\{\{$placeholder\}\}") {
            $foundIdentityPlaceholders++
            Write-Host "      ✅ $placeholder" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $placeholder" -ForegroundColor Red
        }
    }
    
    $testResults.IdentityMetrics = ($foundIdentityPlaceholders -eq $identityPlaceholders.Count)
    
} catch {
    Write-Host "   ❌ Placeholder mapping test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing access control placeholders..." -ForegroundColor Yellow

try {
    # Check for access control placeholders
    $accessControlPlaceholders = @(
        'TOTAL_RBAC_ASSIGNMENTS',
        'ACCESS_POLICY_COUNT',
        'RBAC_ASSIGNMENT_COUNT',
        'CONNECTED_MANAGED_IDENTITIES',
        'OVER_PRIVILEGED_COUNT',
        'TOTAL_IDENTITIES'
    )
    
    $foundAccessPlaceholders = 0
    Write-Host "   🔑 Access Control placeholders:" -ForegroundColor White
    foreach ($placeholder in $accessControlPlaceholders) {
        if ($scriptContent -match "\{\{$placeholder\}\}") {
            $foundAccessPlaceholders++
            Write-Host "      ✅ $placeholder" -ForegroundColor Green
        } else {
            Write-Host "      ❌ $placeholder" -ForegroundColor Red
        }
    }
    
    $testResults.AccessControlMetrics = ($foundAccessPlaceholders -eq $accessControlPlaceholders.Count)
    
} catch {
    Write-Host "   ❌ Access control placeholders test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing IdAM section structure..." -ForegroundColor Yellow

try {
    # Check for section structure elements
    $hasLegendClass = $scriptContent -match 'class="legend"'
    $hasServicePrincipalSection = $scriptContent -match '🏢 Service Principal'
    $hasManagedIdentitySection = $scriptContent -match '🤖 Managed Identity'
    $hasUserGroupSection = $scriptContent -match '👤 User and Group'
    $hasOverPrivilegedSection = $scriptContent -match '⚠️ Over-privileged'
    $hasAccessPolicyVsRBACSection = $scriptContent -match '🆚 Access Policy vs RBAC'
    
    Write-Host "   📊 Section structure:" -ForegroundColor White
    Write-Host "      Legend classes: $hasLegendClass" -ForegroundColor $(if ($hasLegendClass) { "Green" } else { "Red" })
    Write-Host "      Service Principal section: $hasServicePrincipalSection" -ForegroundColor $(if ($hasServicePrincipalSection) { "Green" } else { "Red" })
    Write-Host "      Managed Identity section: $hasManagedIdentitySection" -ForegroundColor $(if ($hasManagedIdentitySection) { "Green" } else { "Red" })
    Write-Host "      User and Group section: $hasUserGroupSection" -ForegroundColor $(if ($hasUserGroupSection) { "Green" } else { "Red" })
    Write-Host "      Over-privileged section: $hasOverPrivilegedSection" -ForegroundColor $(if ($hasOverPrivilegedSection) { "Green" } else { "Red" })
    Write-Host "      Access Policy vs RBAC section: $hasAccessPolicyVsRBACSection" -ForegroundColor $(if ($hasAccessPolicyVsRBACSection) { "Green" } else { "Red" })
    
    $testResults.SectionStructure = $hasLegendClass -and $hasServicePrincipalSection -and $hasManagedIdentitySection -and $hasUserGroupSection -and $hasOverPrivilegedSection
    
} catch {
    Write-Host "   ❌ Section structure test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing data mapping logging..." -ForegroundColor Yellow

try {
    # Check for data mapping logging
    $hasDataMappingLog = $scriptContent -match "Data mapping diagnostic.*IdAM"
    $hasIdAMResultsLog = $scriptContent -match "Data mapping results.*IdAM section"
    $hasIdentityMetricsLog = $scriptContent -match "Identity metrics successfully aggregated"
    
    Write-Host "   📝 Logging features:" -ForegroundColor White
    Write-Host "      IdAM data mapping diagnostic: $hasDataMappingLog" -ForegroundColor $(if ($hasDataMappingLog) { "Green" } else { "Red" })
    Write-Host "      IdAM results logging: $hasIdAMResultsLog" -ForegroundColor $(if ($hasIdAMResultsLog) { "Green" } else { "Red" })
    Write-Host "      Identity metrics success log: $hasIdentityMetricsLog" -ForegroundColor $(if ($hasIdentityMetricsLog) { "Green" } else { "Red" })
    
    $testResults.PlaceholderMapping = $hasDataMappingLog -and $hasIdAMResultsLog
    
} catch {
    Write-Host "   ❌ Data mapping logging test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 IdAM INSIGHTS TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray

$passedTests = 0
foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
    if ($test.Value) { $passedTests++ }
}

Write-Host "`n🎯 Overall Results: $passedTests/$($testResults.Count) tests passed" -ForegroundColor $(if ($passedTests -eq $testResults.Count) { "Green" } else { "Yellow" })

if ($passedTests -eq $testResults.Count) {
    Write-Host "🎉 IdAM Insights section fully validated!" -ForegroundColor Green
    Write-Host "💡 All identity and access management metrics properly configured" -ForegroundColor Blue
} else {
    Write-Host "⚠️ Some tests failed - review results above" -ForegroundColor Yellow
}

return $testResults