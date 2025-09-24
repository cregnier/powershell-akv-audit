#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Enhanced validation for comprehensive HTML feature sections and data completeness

.DESCRIPTION
    Validates that all feature sections are present and complete in the HTML template,
    ensuring no data is lost and all sections provide comprehensive insights.

.EXAMPLE
    ./Validate-HTMLFeatureSections.ps1
#>

[CmdletBinding()]
param()

Write-Host "🔍 COMPREHENSIVE HTML FEATURE SECTIONS VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$testResults = @{
    ExecutiveSummary = $false
    IdAMInsights = $false
    SecretsManagementInsights = $false
    ComplianceFramework = $false
    WorkloadAnalysis = $false
    SecurityConfiguration = $false
    RecommendationsSection = $false
    InteractiveFeatures = $false
    DocumentationLinks = $false
    DataCompleteness = $false
}

# Test 1: Executive Summary Section
Write-Host "`n1️⃣ Testing Executive Summary section..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $executiveSummaryChecks = @{
        "Executive Summary header" = '<h2>🎯 Executive Summary</h2>'
        "Stats grid layout" = 'stats-grid.*grid-template-columns'
        "Key Vaults discovered/analyzed card" = 'Key Vaults.*Discovered|Key Vaults.*Analyzed'
        "Fully Compliant stats" = 'stat-label.*Fully Compliant|Fully Compliant.*stat-label'
        "Average Score display" = 'stat-label.*Average Score|Average Score.*stat-label'
        "High Risk Vaults tracking" = 'stat-label.*High Risk Vaults|High Risk Vaults.*stat-label'
        "Compliance percentage visualization" = 'progress-fill.*width.*COMPLIANCE_PERCENTAGE'
        "Dynamic progress bars" = 'progressAnimation.*ease-out'
    }
    
    $executivePassed = 0
    foreach ($check in $executiveSummaryChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $executivePassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($executivePassed -ge 6) {
        $testResults.ExecutiveSummary = $true
        Write-Host "   🎯 Executive Summary: $executivePassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Executive Summary: $executivePassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Executive Summary: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: IdAM (Identity and Access Management) Insights
Write-Host "`n2️⃣ Testing IdAM Insights section..." -ForegroundColor Yellow
try {
    $idamInsightsChecks = @{
        "RBAC assignments analysis" = 'RBAC.*assignments.*analysis|RBACRoleAssignments'
        "Service Principal identification" = 'Service Principal.*ServicePrincipalCount'
        "Managed Identity analysis" = 'Managed.*Identity.*ManagedIdentityCount'
        "User and Group access tracking" = 'UserCount.*GroupCount'
        "Connected Managed Identities" = 'ConnectedManagedIdentityCount'
        "Over-privileged assignments detection" = 'OverPrivilegedAssignments|over.*privileged'
        "Access Policy vs RBAC comparison" = 'AccessPolicyCount.*RBACAssignmentCount'
        "Total identities calculation" = 'TotalIdentitiesWithAccess'
    }
    
    $idamPassed = 0
    foreach ($check in $idamInsightsChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $idamPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($idamPassed -ge 6) {
        $testResults.IdAMInsights = $true
        Write-Host "   🎯 IdAM Insights: $idamPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ IdAM Insights: $idamPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing IdAM Insights: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Secrets Management Insights
Write-Host "`n3️⃣ Testing Secrets Management Insights section..." -ForegroundColor Yellow
try {
    $secretsInsightsChecks = @{
        "Secret count tracking" = 'SecretCount.*secret.*count'
        "Secret versioning analysis" = 'SecretVersioning.*versioning'
        "Expiration analysis" = 'ExpirationAnalysis.*expiration'
        "Rotation analysis" = 'RotationAnalysis.*rotation'
        "App Service integration detection" = 'AppServiceIntegration.*app.*service'
        "Key and Certificate counts" = 'KeyCount.*CertificateCount'
        "Total items calculation" = 'TotalItems.*secrets.*keys.*certificates'
        "Workload categorization" = 'WorkloadCategories.*workload'
    }
    
    $secretsPassed = 0
    foreach ($check in $secretsInsightsChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $secretsPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($secretsPassed -ge 6) {
        $testResults.SecretsManagementInsights = $true
        Write-Host "   🎯 Secrets Management Insights: $secretsPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Secrets Management Insights: $secretsPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Secrets Management Insights: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Compliance Framework Section
Write-Host "`n4️⃣ Testing Compliance Framework section..." -ForegroundColor Yellow
try {
    $complianceFrameworkChecks = @{
        "Microsoft Security Framework" = 'Microsoft Security Framework'
        "Company Security Framework" = 'Company Security Framework'
        "Compliance scoring legend" = 'Compliance Framework.*Scoring Legend'
        "Color-coded compliance levels" = 'legend-item.*Fully Compliant|legend-item.*Partially Compliant|legend-item.*Non-Compliant'
        "Percentage thresholds" = '90-100%.*Fully Compliant|60-89%.*Partially Compliant|0-59%.*Non-Compliant'
        "Azure documentation links" = 'docs\.microsoft\.com.*azure.*key-vault'
        "Best practices references" = 'security-features.*Security Features|Best Practices.*best-practices'
        "Framework comparison" = '95-100%.*Fully Compliant|Framework Comparison.*95-100%'
    }
    
    $compliancePassed = 0
    foreach ($check in $complianceFrameworkChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $compliancePassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($compliancePassed -ge 6) {
        $testResults.ComplianceFramework = $true
        Write-Host "   🎯 Compliance Framework: $compliancePassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Compliance Framework: $compliancePassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Compliance Framework: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Workload Analysis Section
Write-Host "`n5️⃣ Testing Workload Analysis section..." -ForegroundColor Yellow
try {
    $workloadAnalysisChecks = @{
        "Environment type detection" = 'EnvironmentType.*environment'
        "Primary workload identification" = 'PrimaryWorkload.*primary'
        "Security insights generation" = 'SecurityInsights.*security'
        "Optimization recommendations" = 'OptimizationRecommendations.*optimization'
        "Workload categories breakdown" = 'Workload Categories.*workload.*type'
        "Content analysis integration" = 'content.*analysis.*workload'
        "Data Categories legend" = 'Data Categories.*Definitions'
        "Workload category explanation" = 'Workload Analysis.*secrets.*keys.*certificates'
    }
    
    $workloadPassed = 0
    foreach ($check in $workloadAnalysisChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $workloadPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($workloadPassed -ge 6) {
        $testResults.WorkloadAnalysis = $true
        Write-Host "   🎯 Workload Analysis: $workloadPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Workload Analysis: $workloadPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Workload Analysis: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: Security Configuration Section
Write-Host "`n6️⃣ Testing Security Configuration section..." -ForegroundColor Yellow
try {
    $securityConfigChecks = @{
        "Soft Delete configuration" = 'SoftDeleteEnabled.*soft.*delete'
        "Purge Protection analysis" = 'PurgeProtectionEnabled.*purge.*protection'
        "Network ACLs configuration" = 'NetworkAclsConfigured.*network.*acls'
        "Private Endpoints tracking" = 'PrivateEndpointCount.*private.*endpoints'
        "Public Network Access control" = 'PublicNetworkAccess.*public.*access'
        "System-assigned Identity" = 'SystemAssignedIdentity.*system.*identity'
        "User-assigned Identities" = 'UserAssignedIdentityCount.*user.*assigned'
        "Security Configuration legend" = 'Security Configuration.*soft delete.*purge protection'
    }
    
    $securityPassed = 0
    foreach ($check in $securityConfigChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $securityPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($securityPassed -ge 6) {
        $testResults.SecurityConfiguration = $true
        Write-Host "   🎯 Security Configuration: $securityPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Security Configuration: $securityPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Security Configuration: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 7: Recommendations Section
Write-Host "`n7️⃣ Testing Recommendations section..." -ForegroundColor Yellow
try {
    $recommendationsChecks = @{
        "Security enhancements" = 'SecurityEnhancements.*security.*enhancements'
        "RBAC recommendations" = 'RBACRecommendations.*rbac.*recommendations'
        "Over-privileged assignments" = 'OverPrivilegedAssignments.*over.*privileged'
        "Quick wins section" = 'Quick Wins.*Enable RBAC.*diagnostic logging'
        "Compliance recommendations" = 'ComplianceRecommendations.*compliance'
        "Vault-specific recommendations" = 'VaultRecommendations.*vault.*recommendations'
        "Actionable guidance" = 'Enable.*Configure.*Implement.*Review'
        "Priority-based recommendations" = '🔴 HIGH:|🟡 MEDIUM:|✅'
    }
    
    $recommendationsPassed = 0
    foreach ($check in $recommendationsChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $recommendationsPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($recommendationsPassed -ge 6) {
        $testResults.RecommendationsSection = $true
        Write-Host "   🎯 Recommendations Section: $recommendationsPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Recommendations Section: $recommendationsPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Recommendations Section: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 8: Interactive Features
Write-Host "`n8️⃣ Testing Interactive Features..." -ForegroundColor Yellow
try {
    $interactiveChecks = @{
        "Table sorting functionality" = 'function sortTable|onclick="sortTable'
        "Column filtering" = 'function filterTable|filter-input'
        "Responsive design" = 'grid-template-columns.*auto-fit.*minmax'
        "Hover effects and transitions" = 'hover.*transform.*translateY|:hover.*transform.*translateY'
        "Progress bar animations" = 'progressAnimation.*ease-out'
        "Tooltip functionality" = 'tooltip.*tooltip-text.*visibility.*hidden'
        "Action item toggles" = 'action-details.*display.*none|action-link.*cursor.*pointer'
        "CSS styling and themes" = 'linear-gradient|box-shadow|border-radius'
    }
    
    $interactivePassed = 0
    foreach ($check in $interactiveChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $interactivePassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($interactivePassed -ge 6) {
        $testResults.InteractiveFeatures = $true
        Write-Host "   🎯 Interactive Features: $interactivePassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Interactive Features: $interactivePassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Interactive Features: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 9: Documentation and Resource Links
Write-Host "`n9️⃣ Testing Documentation and Resource Links..." -ForegroundColor Yellow
try {
    $documentationChecks = @{
        "Azure Key Vault documentation links" = 'docs\.microsoft\.com.*azure.*key-vault'
        "Security features documentation" = 'security-features.*Security Best Practices|Security Features.*docs\.microsoft'
        "Best practices references" = 'best-practices.*Security Best Practices|Best Practices.*docs\.microsoft'
        "Azure Security Center links" = 'security-center.*Azure Security Center|Azure Security Center.*security-center'
        "External documentation targets" = 'target="_blank".*doc-link'
        "Quick Actions documentation" = 'Quick Actions.*Azure Documentation|Azure Key Vault.*documentation'
        "Compliance tools references" = 'Compliance Tools.*Azure Policy|Azure Policy.*governance'
        "Support and version information" = 'Support.*Script version.*PowerShell.*compatible'
    }
    
    $documentationPassed = 0
    foreach ($check in $documentationChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $documentationPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($documentationPassed -ge 6) {
        $testResults.DocumentationLinks = $true
        Write-Host "   🎯 Documentation Links: $documentationPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Documentation Links: $documentationPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Documentation Links: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 10: Data Completeness and Error Handling
Write-Host "`n🔟 Testing Data Completeness and Error Handling..." -ForegroundColor Yellow
try {
    $dataCompletenessChecks = @{
        "Missing data fallbacks" = 'else.*None.*N/A.*Unknown|else.*\{ .*None.*\}'
        "Safe property access" = 'if.*\$result\.[A-Za-z].*else|if.*\$_\.[A-Za-z].*else'
        "Truncation for long data" = 'Select-Object -First.*\.\.\.'
        "Title attributes for tooltips" = 'title=.*\$\(\$result\.|title=.*\$\(\$_\.'
        "Error state handling" = 'ErrorsEncountered.*errors.*encountered'
        "Null-safe operations" = 'null-safe.*operations|Add null-safe|Enhanced null-safe'
        "Data validation warnings" = 'Write-.*Warning.*missing.*data|Write-Warning.*No audit results'
        "Comprehensive error logging" = 'Write-ErrorLog.*HTML.*generation.*failed'
    }
    
    $dataPassed = 0
    foreach ($check in $dataCompletenessChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $dataPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) missing" -ForegroundColor Yellow
        }
    }
    
    if ($dataPassed -ge 6) {
        $testResults.DataCompleteness = $true
        Write-Host "   🎯 Data Completeness: $dataPassed/8 features present" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Data Completeness: $dataPassed/8 features present" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing Data Completeness: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary Report
Write-Host "`n📊 HTML FEATURE SECTIONS VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$totalTests = $testResults.Count
$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests feature sections validated" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } elseif ($passedTests -ge ($totalTests * 0.8)) { "Yellow" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All HTML feature sections are complete and comprehensive!" -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Most HTML feature sections are complete. Minor enhancements recommended." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Several HTML feature sections need enhancement or restoration." -ForegroundColor Red
}

Write-Host "`n💡 Comprehensive HTML Feature Benefits:" -ForegroundColor Cyan
Write-Host "  • Executive Summary with dynamic statistics and progress visualization" -ForegroundColor Gray
Write-Host "  • Complete IdAM insights for identity and access management analysis" -ForegroundColor Gray
Write-Host "  • Comprehensive secrets management insights with versioning and rotation" -ForegroundColor Gray
Write-Host "  • Dual compliance framework (Microsoft + Company) with visual legends" -ForegroundColor Gray
Write-Host "  • Advanced workload analysis with environment and content categorization" -ForegroundColor Gray
Write-Host "  • Detailed security configuration analysis and recommendations" -ForegroundColor Gray
Write-Host "  • Multi-tier recommendations with priority-based guidance" -ForegroundColor Gray
Write-Host "  • Interactive features with sorting, filtering, and responsive design" -ForegroundColor Gray
Write-Host "  • Comprehensive documentation links and Azure resource references" -ForegroundColor Gray
Write-Host "  • Robust data completeness handling with error fallbacks" -ForegroundColor Gray

return $testResults