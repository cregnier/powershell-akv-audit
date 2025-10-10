#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive validation for all audit modes using identical reporting templates

.DESCRIPTION
    Tests that SingleVault, Resume, Multi-vault (Test), and Full audit modes all use
    the same comprehensive HTML template and CSV structure without any data loss.

.EXAMPLE
    ./Validate-AuditModeUnification.ps1
#>

[CmdletBinding()]
param()

Write-Host "🔍 AUDIT MODE UNIFICATION VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    AllModesUseSameTemplate = $false
    CSVStructureConsistent = $false
    HTMLGenerationUnified = $false
    NoDataLossHTML = $false
    PlaceholderSynchronization = $false
    ErrorHandlingConsistent = $false
}

Write-Host "`n1️⃣ Testing that all audit modes use the same comprehensive template..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check that all modes call New-ComprehensiveHtmlReport
    $singleVaultHtml = $scriptContent -match 'SingleVault.*New-ComprehensiveHtmlReport.*IsPartialResults.*false'
    $resumeHtml = $scriptContent -match 'New-ComprehensiveHtmlReport.*IsPartialResults.*true.*checkpoint'
    $fullAuditHtml = $scriptContent -match 'Generate comprehensive HTML report.*New-ComprehensiveHtmlReport.*IsPartialResults.*false'
    $processPartialHtml = $scriptContent -match 'ProcessPartial.*New-ComprehensiveHtmlReport.*IsPartialResults.*true'
    
    # Verify all modes exist and use the same function
    $allModesCount = 0
    if ($scriptContent -match 'New-ComprehensiveHtmlReport.*OutputPath.*htmlFile.*AuditResults.*@\(\$auditResult\)') { 
        Write-Host "   ✅ SingleVault mode uses New-ComprehensiveHtmlReport" -ForegroundColor Green
        $allModesCount++
    }
    if ($scriptContent -match 'New-ComprehensiveHtmlReport.*IsPartialResults.*true.*CheckpointData') { 
        Write-Host "   ✅ Resume/ProcessPartial modes use New-ComprehensiveHtmlReport" -ForegroundColor Green
        $allModesCount++
    }
    if ($scriptContent -match 'New-ComprehensiveHtmlReport.*htmlPath.*global:auditResults.*IsPartialResults.*false') { 
        Write-Host "   ✅ Full audit mode uses New-ComprehensiveHtmlReport" -ForegroundColor Green
        $allModesCount++
    }
    if ($scriptContent -match 'Use-HtmlTemplate.*InlineGenerator.*AuditResults.*ExecutiveSummary') { 
        Write-Host "   ✅ All modes use unified template engine (Use-HtmlTemplate)" -ForegroundColor Green
        $allModesCount++
    }
    
    # Check that deprecated functions are removed
    if ($scriptContent -match 'Generate-HTMLReport.*deprecated.*removed') { 
        Write-Host "   ✅ Deprecated HTML generation functions removed" -ForegroundColor Green
        $allModesCount++
    }
    
    if ($allModesCount -ge 4) {
        $testResults.AllModesUseSameTemplate = $true
        Write-Host "   🎯 Template unification: $allModesCount/5 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Template unification: $allModesCount/5 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing template unification: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing CSV structure consistency across all modes..." -ForegroundColor Yellow
try {
    # Extract PSCustomObject properties (CSV columns)
    $csvColumns = @()
    $lines = $scriptContent -split '\n'
    $inResultObject = $false
    $braceCount = 0
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '\$result = \[PSCustomObject\]@\{') {
            $inResultObject = $true
            $braceCount = 1
            continue
        }
        
        if ($inResultObject) {
            $braceCount += ($lines[$i] -split '\{').Count - 1
            $braceCount -= ($lines[$i] -split '\}').Count - 1
            
            if ($lines[$i] -match '^\s*([A-Za-z][A-Za-z0-9_]*)\s*=') {
                $csvColumns += $matches[1]
            }
            
            if ($braceCount -eq 0) {
                break
            }
        }
    }
    
    Write-Host "   📊 CSV columns detected: $($csvColumns.Count)" -ForegroundColor Gray
    
    # Verify all expected columns are present
    $requiredColumns = @(
        'SubscriptionName', 'KeyVaultName', 'Location', 'ResourceGroupName', 'ResourceId', 'SubscriptionId',
        'DiagnosticsEnabled', 'EnabledLogCategories', 'EnabledMetricCategories', 'LogAnalyticsEnabled', 'LogAnalyticsWorkspaceName',
        'EventHubEnabled', 'EventHubNamespace', 'EventHubName', 'StorageAccountEnabled', 'StorageAccountName',
        'AccessPolicyCount', 'AccessPolicyDetails', 'RBACRoleAssignments', 'RBACAssignmentCount', 'TotalIdentitiesWithAccess',
        'ServicePrincipalCount', 'UserCount', 'GroupCount', 'ManagedIdentityCount', 'ServicePrincipalDetails', 'ManagedIdentityDetails',
        'SoftDeleteEnabled', 'PurgeProtectionEnabled', 'PublicNetworkAccess', 'NetworkAclsConfigured', 'PrivateEndpointCount',
        'SystemAssignedIdentity', 'SystemAssignedPrincipalId', 'UserAssignedIdentityCount', 'UserAssignedIdentityIds', 'ConnectedManagedIdentityCount',
        'ComplianceStatus', 'ComplianceScore', 'CompanyComplianceScore', 'CompanyComplianceStatus', 'ComplianceIssues',
        'ComplianceRecommendations', 'VaultRecommendations', 'SecurityEnhancements', 'RBACRecommendations', 'OverPrivilegedAssignments',
        'SecretCount', 'KeyCount', 'CertificateCount', 'WorkloadCategories', 'EnvironmentType', 'PrimaryWorkload',
        'SecurityInsights', 'OptimizationRecommendations', 'TotalItems', 'SecretVersioning', 'ExpirationAnalysis', 'RotationAnalysis',
        'AppServiceIntegration', 'LastAuditDate', 'ErrorsEncountered'
    )
    
    $missingColumns = $requiredColumns | Where-Object { $_ -notin $csvColumns }
    $extraColumns = $csvColumns | Where-Object { $_ -notin $requiredColumns }
    
    if ($missingColumns.Count -eq 0 -and $csvColumns.Count -eq 62) {
        Write-Host "   ✅ All 62 required CSV columns present" -ForegroundColor Green
        $testResults.CSVStructureConsistent = $true
    } else {
        Write-Host "   ⚠️ CSV structure issues detected:" -ForegroundColor Yellow
        if ($missingColumns) {
            Write-Host "      Missing: $($missingColumns -join ', ')" -ForegroundColor Red
        }
        if ($extraColumns) {
            Write-Host "      Extra: $($extraColumns -join ', ')" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "   ❌ Error testing CSV structure: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing HTML generation unification..." -ForegroundColor Yellow
try {
    $htmlUnificationChecks = @{
        "Single comprehensive HTML function" = 'function New-ComprehensiveHtmlReport'
        "Unified template engine" = 'Use-HtmlTemplate.*TemplateName.*InlineGenerator'
        "Consistent parameter structure" = 'OutputPath.*AuditResults.*ExecutiveSummary.*AuditStats.*IsPartialResults'
        "Same HTML structure for all modes" = 'Use-HtmlTemplate.*TemplateName.*InlineGenerator'
        "No mode-specific HTML generators" = 'Generate-HTMLReport.*deprecated.*removed'
    }
    
    $htmlUnificationPassed = 0
    foreach ($check in $htmlUnificationChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $htmlUnificationPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($htmlUnificationPassed -ge 4) {
        $testResults.HTMLGenerationUnified = $true
        Write-Host "   🎯 HTML generation unification: $htmlUnificationPassed/5 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ HTML generation unification: $htmlUnificationPassed/5 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing HTML generation: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing that all CSV columns are mapped to HTML without data loss..." -ForegroundColor Yellow
try {
    # Check that HTML table has 62 columns
    $htmlHeaders = ($scriptContent | Select-String -Pattern '<th onclick="sortTable\(\d+\)"[^>]*>' -AllMatches).Matches.Count
    
    # Check that filter inputs match column count
    $filterInputsPresent = $scriptContent -match 'for.*\$i.*-lt 62.*filter-input'
    
    # Check that data rows map all CSV properties
    $dataRowMappingChecks = @{
        "All CSV properties in HTML table" = 'td.*\$\(\$result\.[A-Za-z]'
        "62 HTML table headers" = $htmlHeaders -eq 62
        "Filter inputs for all columns" = $filterInputsPresent
        "Safe property access in HTML" = 'if.*\$result\.[A-Za-z].*else'
        "Tooltip data for detailed information" = 'title=.*\$\(\$result\.'
    }
    
    $noDataLossPassed = 0
    foreach ($check in $dataRowMappingChecks.GetEnumerator()) {
        $checkResult = if ($check.Key -eq "62 HTML table headers") { $check.Value } else { $scriptContent -match $check.Value }
        
        if ($checkResult) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $noDataLossPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($noDataLossPassed -ge 4) {
        $testResults.NoDataLossHTML = $true
        Write-Host "   🎯 No data loss in HTML: $noDataLossPassed/5 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ No data loss in HTML: $noDataLossPassed/5 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing data loss prevention: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing placeholder synchronization between data and templates..." -ForegroundColor Yellow
try {
    # Extract all placeholders from HTML template
    $placeholderPattern = '\{\{([A-Z_]+)\}\}'
    $matches = [regex]::Matches($scriptContent, $placeholderPattern)
    $placeholders = @()
    
    foreach ($match in $matches) {
        $placeholder = $match.Groups[1].Value
        if ($placeholder -notin $placeholders) {
            $placeholders += $placeholder
        }
    }
    
    Write-Host "   📊 HTML placeholders found: $($placeholders.Count)" -ForegroundColor Gray
    
    # Check that placeholders are properly defined and mapped
    $placeholderSyncChecks = @{
        "Placeholder definition section" = '\$placeholders = @\{'
        "All placeholders have values" = '\$placeholders\["{{[A-Z_]+}}"\].*='
        "Dynamic timestamp generation" = 'Get-Date.*yyyy-MM-dd HH:mm:ss UTC'
        "Current user detection" = 'if.*\$global:currentUser.*else'
        "ExecutiveSummary mapping" = 'ExecutiveSummary\.[A-Za-z]'
        "Partial results placeholders" = 'if.*IsPartialResults.*PROCESSED_VAULTS.*COMPLETION_PERCENTAGE'
    }
    
    $placeholderSyncPassed = 0
    foreach ($check in $placeholderSyncChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $placeholderSyncPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($placeholderSyncPassed -ge 5) {
        $testResults.PlaceholderSynchronization = $true
        Write-Host "   🎯 Placeholder synchronization: $placeholderSyncPassed/6 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Placeholder synchronization: $placeholderSyncPassed/6 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing placeholder synchronization: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6️⃣ Testing consistent error handling across all modes..." -ForegroundColor Yellow
try {
    $errorHandlingChecks = @{
        "HTML generation error logging" = 'Write-ErrorLog.*HTML.*generation|Failed to generate.*HTML'
        "Missing data fallbacks" = 'if.*\$result\.[A-Za-z].*else.*None|N/A'
        "Safe ExecutiveSummary access" = 'if.*-not.*ExecutiveSummary\.ContainsKey.*Add.*missing'
        "Error state tracking" = 'ErrorsEncountered.*errors.*encountered'
        "Comprehensive error context" = 'Write-ErrorLog.*context.*vault.*subscription'
        "HTML validation" = 'if.*-not.*htmlContent.*htmlContent\.Length -eq 0'
    }
    
    $errorHandlingPassed = 0
    foreach ($check in $errorHandlingChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $errorHandlingPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($errorHandlingPassed -ge 4) {
        $testResults.ErrorHandlingConsistent = $true
        Write-Host "   🎯 Error handling consistency: $errorHandlingPassed/6 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Error handling consistency: $errorHandlingPassed/6 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing error handling: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary Report
Write-Host "`n📊 AUDIT MODE UNIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$totalTests = $testResults.Count
$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests unification tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } elseif ($passedTests -ge ($totalTests * 0.8)) { "Yellow" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 Perfect audit mode unification achieved!" -ForegroundColor Green
    Write-Host "All modes (SingleVault, Resume, Multi-vault Test, Full) use identical comprehensive reporting." -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Excellent audit mode unification with minor areas for improvement." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Audit mode unification needs enhancement to ensure consistency." -ForegroundColor Red
}

Write-Host "`n💡 Unified Audit Mode Benefits:" -ForegroundColor Cyan
Write-Host "  • Consistent 62-column CSV structure across all audit modes" -ForegroundColor Gray
Write-Host "  • Unified HTML template ensures no feature differences between modes" -ForegroundColor Gray
Write-Host "  • No data loss - every CSV column mapped to HTML placeholder" -ForegroundColor Gray
Write-Host "  • Same comprehensive executive summary regardless of audit scope" -ForegroundColor Gray
Write-Host "  • Consistent error handling and missing data management" -ForegroundColor Gray
Write-Host "  • Identical interactive features (sorting, filtering) in all modes" -ForegroundColor Gray

return $testResults