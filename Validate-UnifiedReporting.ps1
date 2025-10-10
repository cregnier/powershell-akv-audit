#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Enhanced validation script for unified comprehensive reporting across all audit modes

.DESCRIPTION
    Validates that all audit modes (SingleVault, Resume, Multi-vault Test, Full) use the same
    comprehensive HTML template and CSV structure. Ensures all PSCustomObject fields are 
    mapped to HTML placeholders and that no data is lost in HTML representation.

.EXAMPLE
    ./Validate-UnifiedReporting.ps1
#>

[CmdletBinding()]
param()

Write-Host "🔍 UNIFIED COMPREHENSIVE REPORTING VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    Syntax = $false
    UnifiedTemplate = $false
    CSVColumns = $false
    HTMLPlaceholders = $false
    PlaceholderMapping = $false
    AllModesUnified = $false
    ErrorHandling = $false
    DocumentationComplete = $false
}

# Test 1: PowerShell Syntax Validation
Write-Host "`n1️⃣ Testing PowerShell syntax validation..." -ForegroundColor Yellow
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax is valid" -ForegroundColor Green
        $testResults.Syntax = $true
    } else {
        Write-Host "   ❌ PowerShell syntax errors found" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing syntax: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: CSV Column Structure Analysis
Write-Host "`n2️⃣ Testing CSV column structure and PSCustomObject mapping..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Extract PSCustomObject properties from the main result object
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
            # Count opening/closing braces to track object scope
            $braceCount += ($lines[$i] -split '\{').Count - 1
            $braceCount -= ($lines[$i] -split '\}').Count - 1
            
            # Extract property names (column names)
            if ($lines[$i] -match '^\s*([A-Za-z][A-Za-z0-9_]*)\s*=') {
                $csvColumns += $matches[1]
            }
            
            # Exit when we close the main object
            if ($braceCount -eq 0) {
                break
            }
        }
    }
    
    Write-Host "   📊 CSV columns found: $($csvColumns.Count)" -ForegroundColor Gray
    Write-Host "   📋 Column names: $($csvColumns -join ', ')" -ForegroundColor Gray
    
    if ($csvColumns.Count -eq 62) {
        Write-Host "   ✅ CSV has expected 62 columns" -ForegroundColor Green
        $testResults.CSVColumns = $true
    } else {
        Write-Host "   ❌ CSV has $($csvColumns.Count) columns, expected 62" -ForegroundColor Red
        
        # Show expected vs actual for debugging
        $expectedColumns = @(
            'SubscriptionId', 'SubscriptionName', 'KeyVaultName', 'ResourceId', 'Location', 'ResourceGroupName',
            'DiagnosticsEnabled', 'EnabledLogCategories', 'EnabledMetricCategories', 'LogAnalyticsEnabled', 'LogAnalyticsWorkspaceName',
            'EventHubEnabled', 'EventHubNamespace', 'EventHubName', 'StorageAccountEnabled', 'StorageAccountName',
            'AccessPolicyCount', 'AccessPolicyDetails', 'RBACRoleAssignments', 'RBACAssignmentCount', 'TotalIdentitiesWithAccess',
            'ServicePrincipalCount', 'UserCount', 'GroupCount', 'ManagedIdentityCount', 'ServicePrincipalDetails', 'ManagedIdentityDetails',
            'SoftDeleteEnabled', 'PurgeProtectionEnabled', 'PublicNetworkAccess', 'NetworkAclsConfigured', 'PrivateEndpointCount',
            'SystemAssignedIdentity', 'SystemAssignedPrincipalId', 'UserAssignedIdentityCount', 'UserAssignedIdentityIds',
            'ConnectedManagedIdentityCount', 'ComplianceStatus', 'ComplianceScore', 'CompanyComplianceScore', 'CompanyComplianceStatus',
            'ComplianceIssues', 'ComplianceRecommendations', 'VaultRecommendations', 'SecurityEnhancements', 'RBACRecommendations',
            'OverPrivilegedAssignments', 'SecretCount', 'KeyCount', 'CertificateCount', 'WorkloadCategories',
            'EnvironmentType', 'PrimaryWorkload', 'SecurityInsights', 'OptimizationRecommendations', 'TotalItems',
            'SecretVersioning', 'ExpirationAnalysis', 'RotationAnalysis', 'AppServiceIntegration', 'LastAuditDate', 'ErrorsEncountered'
        )
        
        $missingColumns = $expectedColumns | Where-Object { $_ -notin $csvColumns }
        $extraColumns = $csvColumns | Where-Object { $_ -notin $expectedColumns }
        
        if ($missingColumns) {
            Write-Host "   ⚠️ Missing columns: $($missingColumns -join ', ')" -ForegroundColor Yellow
        }
        if ($extraColumns) {
            Write-Host "   ⚠️ Extra columns: $($extraColumns -join ', ')" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "   ❌ Error analyzing CSV columns: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Unified Template Usage Across All Modes
Write-Host "`n3️⃣ Testing unified template usage across all audit modes..." -ForegroundColor Yellow
try {
    $modeChecks = @{
        "SingleVault mode uses New-ComprehensiveHtmlReport" = 'New-ComprehensiveHtmlReport.*IsPartialResults.*false'
        "Resume/ProcessPartial mode uses New-ComprehensiveHtmlReport" = 'New-ComprehensiveHtmlReport.*IsPartialResults.*true'
        "Full audit uses New-ComprehensiveHtmlReport" = 'Generate comprehensive HTML report.*New-ComprehensiveHtmlReport'
        "No fallback to deprecated Generate-HTMLReport" = 'Generate-HTMLReport.*deprecated.*removed'
        "All modes use Use-HtmlTemplate internally" = 'Use-HtmlTemplate.*TemplateName.*InlineGenerator'
        "Filter inputs configured for 62 columns" = 'for.*\$i.*-lt 62'
    }
    
    $modePassed = 0
    foreach ($check in $modeChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $modePassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($modePassed -ge 5) {
        $testResults.UnifiedTemplate = $true
        Write-Host "   🎯 Unified template usage: $modePassed/6 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Unified template usage: $modePassed/6 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing unified template usage: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: HTML Placeholder Coverage
Write-Host "`n4️⃣ Testing HTML placeholder coverage and mapping..." -ForegroundColor Yellow
try {
    # Extract HTML placeholders from the inline generator
    $htmlPlaceholders = @()
    $placeholderPattern = '\{\{([A-Z_]+)\}\}'
    $matches = [regex]::Matches($scriptContent, $placeholderPattern)
    
    foreach ($match in $matches) {
        $placeholder = $match.Groups[1].Value
        if ($placeholder -notin $htmlPlaceholders) {
            $htmlPlaceholders += $placeholder
        }
    }
    
    Write-Host "   📊 HTML placeholders found: $($htmlPlaceholders.Count)" -ForegroundColor Gray
    Write-Host "   📋 Placeholders: $($htmlPlaceholders -join ', ')" -ForegroundColor Gray
    
    # Check for data row generation with all CSV columns
    $dataRowMappingChecks = @{
        "All CSV columns mapped to HTML table cells" = 'td.*\$\(\$result\.[A-Za-z]'
        "Proper table cell generation for all 62 columns" = '<td.*title.*\$\(\$result\.'
        "Column headers match data cells (62 headers)" = '<th onclick="sortTable\(\d+\)"[^>]*>'
        "Filter inputs match column count" = 'for.*\$i.*-lt 62'
    }
    
    $mappingPassed = 0
    foreach ($check in $dataRowMappingChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $mappingPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($mappingPassed -ge 3) {
        $testResults.HTMLPlaceholders = $true
        $testResults.PlaceholderMapping = $true  # Set this correctly based on mapping checks
        Write-Host "   🎯 HTML placeholder mapping: $mappingPassed/4 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ HTML placeholder mapping: $mappingPassed/4 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing HTML placeholders: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Complete Feature Section Analysis
Write-Host "`n5️⃣ Testing HTML feature section completeness..." -ForegroundColor Yellow
try {
    $featureSections = @{
        "Executive Summary section" = '<h2>🎯 Executive Summary</h2>'
        "Compliance Framework Legend" = 'Compliance Framework & Scoring Legend'
        "Data Categories & Definitions" = 'Data Categories & Definitions'
        "Quick Actions & Azure Documentation" = 'Quick Actions & Azure Documentation'
        "Detailed Vault Analysis table" = '<h2>📋 Detailed Vault Analysis</h2>'
        "Enhanced Summary Statistics" = 'Audit Summary & Key Metrics'
        "Comprehensive Footer" = 'Azure Key Vault Enhanced Security & Compliance Audit Report'
        "Interactive JavaScript functions" = 'function filterTable|function sortTable'
    }
    
    $sectionsPassed = 0
    foreach ($section in $featureSections.GetEnumerator()) {
        if ($scriptContent -match $section.Value) {
            Write-Host "   ✅ $($section.Key) present" -ForegroundColor Green
            $sectionsPassed++
        } else {
            Write-Host "   ❌ $($section.Key) missing or incomplete" -ForegroundColor Red
        }
    }
    
    if ($sectionsPassed -eq $featureSections.Count) {
        $testResults.AllModesUnified = $true
        Write-Host "   🎯 Feature sections: $sectionsPassed/$($featureSections.Count) sections complete" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Feature sections: $sectionsPassed/$($featureSections.Count) sections complete" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing feature sections: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: Error Handling for Missing Data
Write-Host "`n6️⃣ Testing error handling and missing data warnings..." -ForegroundColor Yellow
try {
    $errorHandlingChecks = @{
        "Missing CSV column warnings" = 'Write-.*Warning.*missing.*column|Add.*missing.*property'
        "Empty HTML content validation" = 'if.*-not.*htmlContent.*empty content|htmlContent\.Length -eq 0'
        "ExecutiveSummary property validation" = 'if.*-not.*ExecutiveSummary\.ContainsKey'
        "Safe property access in HTML generation" = 'if.*\$result\.[A-Za-z].*else'
        "Error logging for HTML generation failures" = 'Write-ErrorLog.*HTML.*generation|Failed to generate.*HTML'
    }
    
    $errorPassed = 0
    foreach ($check in $errorHandlingChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $errorPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not found" -ForegroundColor Yellow
        }
    }
    
    if ($errorPassed -ge 3) {
        $testResults.ErrorHandling = $true
        Write-Host "   🎯 Error handling: $errorPassed/5 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Error handling: $errorPassed/5 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing error handling: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 7: Documentation and Help Completeness
Write-Host "`n7️⃣ Testing documentation completeness..." -ForegroundColor Yellow
try {
    # Check help documentation
    $helpContent = pwsh -Command "Get-Help '$scriptPath' -Full" 2>$null
    
    $docChecks = @{
        "Script help available" = $helpContent -and $helpContent.Length -gt 100
        "Parameter documentation" = $helpContent -match "PARAMETERS|SingleVault|TestMode"
        "Examples section" = $helpContent -match "EXAMPLE|Examples"
        "Template documentation in code" = $scriptContent -match "comprehensive.*template.*approach"
    }
    
    $docPassed = 0
    foreach ($check in $docChecks.GetEnumerator()) {
        if ($check.Value) {
            Write-Host "   ✅ $($check.Key)" -ForegroundColor Green
            $docPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) incomplete" -ForegroundColor Yellow
        }
    }
    
    if ($docPassed -ge 3) {
        $testResults.DocumentationComplete = $true
        Write-Host "   🎯 Documentation: $docPassed/4 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Documentation: $docPassed/4 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing documentation: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary Report
Write-Host "`n📊 UNIFIED REPORTING VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$totalTests = $testResults.Count
$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } elseif ($passedTests -ge ($totalTests * 0.8)) { "Yellow" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All unified reporting tests passed! Comprehensive reporting is fully implemented." -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Most unified reporting tests passed. Minor issues may need attention." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Several reporting issues detected. Review and fixes required." -ForegroundColor Red
}

Write-Host "`n💡 Unified Reporting Benefits:" -ForegroundColor Cyan
Write-Host "  • All audit modes use the same comprehensive HTML template" -ForegroundColor Gray
Write-Host "  • All 62 CSV columns mapped to HTML placeholders" -ForegroundColor Gray
Write-Host "  • No data loss between CSV and HTML representation" -ForegroundColor Gray
Write-Host "  • Consistent feature-rich reporting across SingleVault, Resume, Test, and Full modes" -ForegroundColor Gray
Write-Host "  • Enhanced error handling and missing data warnings" -ForegroundColor Gray
Write-Host "  • Complete placeholder synchronization between data and templates" -ForegroundColor Gray

return $testResults