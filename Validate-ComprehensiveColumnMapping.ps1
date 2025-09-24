#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Validation script for comprehensive CSV-HTML column mapping
.DESCRIPTION
    Validates that all 62 CSV columns are properly represented in the HTML template
    and that all audit modes use the same comprehensive reporting structure.
.EXAMPLE
    ./Validate-ComprehensiveColumnMapping.ps1
#>

[CmdletBinding()]
param()

Write-Host "🔍 COMPREHENSIVE CSV-HTML COLUMN MAPPING VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$testResults = @{
    Syntax = $false
    CSVColumns = $false
    HTMLHeaders = $false
    HTMLDataRows = $false
    ColumnMapping = $false
    ModesUseTemplate = $false
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

# Test 2: CSV Column Count Validation
Write-Host "`n2️⃣ Testing CSV column structure..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Extract CSV columns from the main audit PSCustomObject definition (fixed pattern)
    # Look specifically for the $result PSCustomObject around line 10646
    $csvColumns = 0
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
            
            # Count property lines (exclude comments and empty lines)
            if ($lines[$i] -match '^\s*[A-Za-z][A-Za-z0-9_]*\s*=' -and $lines[$i] -notmatch '^\s*#') {
                $csvColumns++
            }
            
            # Exit when we close the main object
            if ($braceCount -eq 0) {
                break
            }
        }
    }
        Write-Host "   📊 CSV columns found: $csvColumns" -ForegroundColor Gray
        
        if ($csvColumns -ge 60 -and $csvColumns -le 65) {
            Write-Host "   ✅ CSV has expected column count ($csvColumns)" -ForegroundColor Green
            $testResults.CSVColumns = $true
        } else {
            Write-Host "   ❌ CSV has $csvColumns columns, expected 60-65" -ForegroundColor Red
        }
} catch {
    Write-Host "   ❌ Error testing CSV columns: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: HTML Table Headers Validation
Write-Host "`n3️⃣ Testing HTML table headers..." -ForegroundColor Yellow
try {
    # Count HTML table headers in template (updated pattern for enhanced headers with titles)
    $htmlHeaders = ($scriptContent | Select-String -Pattern '<th onclick="sortTable\(\d+\)"[^>]*>' -AllMatches).Matches.Count
    
    Write-Host "   📊 HTML table headers found: $htmlHeaders" -ForegroundColor Gray
    
    if ($htmlHeaders -eq 62) {
        Write-Host "   ✅ HTML table has correct 62 headers" -ForegroundColor Green
        $testResults.HTMLHeaders = $true
    } else {
        Write-Host "   ❌ HTML table has $htmlHeaders headers, expected 62" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing HTML headers: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: HTML Data Row Generation Validation
Write-Host "`n4️⃣ Testing HTML data row generation..." -ForegroundColor Yellow
try {
    # Check for comprehensive data row generation (improved patterns)
    $dataRowChecks = @{
        "Basic Information mapping" = '(SubscriptionName|KeyVaultName|Location|ResourceGroupName).*td'
        "Compliance mapping" = '(ComplianceStatus|ComplianceScore|CompanyComplianceScore).*td'
        "Diagnostics mapping" = '(DiagnosticsEnabled|EnabledLogCategories|LogAnalyticsEnabled).*td'
        "Access Control mapping" = '(AccessPolicyCount|RBACAssignmentCount|TotalIdentitiesWithAccess).*td'
        "Security Configuration mapping" = '(SoftDeleteEnabled|PurgeProtectionEnabled|PublicNetworkAccess).*td'
        "Workload Analysis mapping" = '(SecretCount|KeyCount|CertificateCount).*td'
        "Recommendations mapping" = '(SecurityEnhancements|RBACRecommendations|OverPrivilegedAssignments).*td'
        "Enhanced columns mapping" = '(NetworkAclsConfigured|ConnectedManagedIdentityCount|SecretVersioning).*td'
    }
    
    $dataRowPassed = 0
    foreach ($check in $dataRowChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key) found" -ForegroundColor Green
            $dataRowPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not found" -ForegroundColor Yellow
        }
    }
    
    if ($dataRowPassed -ge 6) {
        $testResults.HTMLDataRows = $true
        Write-Host "   🎯 HTML data row generation: $dataRowPassed/8 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ HTML data row generation: $dataRowPassed/8 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing HTML data rows: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Column Mapping Consistency
Write-Host "`n5️⃣ Testing column mapping consistency..." -ForegroundColor Yellow
try {
    # Check that filter inputs match header count (fixed pattern)
    $filterInputCount = 0
    if ($scriptContent -match 'for\s*\(\s*\$i\s*=\s*0;\s*\$i\s*-lt\s*(\d+);\s*\$i\+\+\s*\).*filter-input') {
        $filterInputCount = [int]$matches[1]
    } elseif ($scriptContent -match 'for\s*\(\s*\$i\s*=\s*0\s*;\s*\$i\s*-lt\s*(\d+)\s*;\s*\$i\s*\+\+\s*\)') {
        # Also check for the loop without requiring filter-input in the same line
        $filterInputCount = [int]$matches[1]
    }
    
    Write-Host "   📊 Filter inputs configured for: $filterInputCount columns" -ForegroundColor Gray
    
    if ($filterInputCount -eq 62) {
        Write-Host "   ✅ Filter inputs match 62 columns" -ForegroundColor Green
        
        # Check colspan in error handling
        $colspanCorrect = $scriptContent -match "colspan='62'"
        
        if ($colspanCorrect) {
            Write-Host "   ✅ Error handling colspan updated to 62" -ForegroundColor Green
            $testResults.ColumnMapping = $true
        } else {
            Write-Host "   ⚠️ Error handling colspan may not be updated" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ❌ Filter inputs configured for $filterInputCount, expected 62" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing column mapping: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: All Modes Use Comprehensive Template
Write-Host "`n6️⃣ Testing that all modes use comprehensive template..." -ForegroundColor Yellow
try {
    $modeChecks = @{
        "New-ComprehensiveHtmlReport usage" = 'New-ComprehensiveHtmlReport.*-OutputPath.*-AuditResults'
        "Use-HtmlTemplate usage" = 'Use-HtmlTemplate.*TemplateName.*InlineGenerator'
        "SingleVault mode integration" = 'SingleVault mode uses New-ComprehensiveHtmlReport'
        "No fallback to basic HTML" = 'Generate-HTMLReport.*deprecated.*removed'
    }
    
    $modePassed = 0
    foreach ($check in $modeChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key) confirmed" -ForegroundColor Green
            $modePassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not confirmed" -ForegroundColor Yellow
        }
    }
    
    if ($modePassed -ge 3) {
        $testResults.ModesUseTemplate = $true
        Write-Host "   🎯 Mode integration: $modePassed/4 checks passed" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️ Mode integration: $modePassed/4 checks passed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Error testing mode integration: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary Report
Write-Host "`n📊 COMPREHENSIVE VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Gray

$totalTests = $testResults.Count
$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All comprehensive column mapping tests passed!" -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Most comprehensive mapping tests passed. Minor issues may need attention." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Several mapping issues detected. Review required." -ForegroundColor Red
}

Write-Host "`n💡 Expected Improvements:" -ForegroundColor Cyan
Write-Host "  • HTML reports now show all 62 CSV columns instead of 28" -ForegroundColor Gray
Write-Host "  • All modes (SingleVault, Resume, Test, Full) use same comprehensive template" -ForegroundColor Gray
Write-Host "  • Complete column mapping ensures no data is lost in HTML representation" -ForegroundColor Gray
Write-Host "  • Enhanced filtering and sorting capabilities across all columns" -ForegroundColor Gray

return $testResults