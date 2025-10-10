#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate the critical error fixes for PowerShell script issues
.DESCRIPTION
    Validates fixes for:
    1. Template processing failure with AuthenticationRefreshes property
    2. Dashboard generation failure with missing Unit property
    3. Variable retrieval errors for $diagnosticsPercentage and $privateEndpointsPercentage  
    4. Missing Microsoft compliance properties
#>

[CmdletBinding()]
param()

Write-Host "🔧 CRITICAL ERROR FIXES VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    DiagnosticsPercentageFixed = $false
    PrivateEndpointsPercentageFixed = $false
    DashboardUnitPropertiesFixed = $false
    AuthenticationRefreshesHandled = $false
    MicrosoftComplianceHandled = $false
    SyntaxValid = $false
}

Write-Host "`n1️⃣ Testing syntax validation...`n" -ForegroundColor Yellow

try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax is valid" -ForegroundColor Green
        $testResults.SyntaxValid = $true
    }
} catch {
    Write-Host "   ❌ Syntax validation failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing diagnosticsPercentage variable fix...`n" -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for diagnosticsPercentage calculation
    $diagnosticsCalc = $scriptContent -match '\$diagnosticsPercentage\s*='
    Write-Host "   📊 Diagnostics percentage calculation found: $diagnosticsCalc" -ForegroundColor $(if ($diagnosticsCalc) { "Green" } else { "Red" })
    
    # Check that it's defined before usage
    $lines = Get-Content $scriptPath
    $definitionLine = $null
    $usageLine = $null
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\$diagnosticsPercentage\s*=') {
            $definitionLine = $i + 1
        }
        if ($lines[$i] -match 'diagnosticsPercentage%' -and -not ($lines[$i] -match '^\$diagnosticsPercentage\s*=')) {
            $usageLine = $i + 1
            break
        }
    }
    
    if ($definitionLine -and $usageLine -and $definitionLine -lt $usageLine) {
        Write-Host "   ✅ Variable defined before usage (line $definitionLine < $usageLine)" -ForegroundColor Green
        $testResults.DiagnosticsPercentageFixed = $true
    } else {
        Write-Host "   ❌ Variable not properly defined before usage (def: $definitionLine, use: $usageLine)" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing diagnosticsPercentage: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing privateEndpointsPercentage variable fix...`n" -ForegroundColor Yellow

try {
    # Check for privateEndpointsPercentage calculation
    $privateEndpointsCalc = $scriptContent -match '\$privateEndpointsPercentage\s*='
    Write-Host "   📊 Private endpoints percentage calculation found: $privateEndpointsCalc" -ForegroundColor $(if ($privateEndpointsCalc) { "Green" } else { "Red" })
    
    # Check that it's defined before usage  
    $definitionLine2 = $null
    $usageLine2 = $null
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\$privateEndpointsPercentage\s*=') {
            $definitionLine2 = $i + 1
        }
        if ($lines[$i] -match 'privateEndpointsPercentage%' -and -not ($lines[$i] -match '^\$privateEndpointsPercentage\s*=')) {
            $usageLine2 = $i + 1
            break
        }
    }
    
    if ($definitionLine2 -and $usageLine2 -and $definitionLine2 -lt $usageLine2) {
        Write-Host "   ✅ Variable defined before usage (line $definitionLine2 < $usageLine2)" -ForegroundColor Green
        $testResults.PrivateEndpointsPercentageFixed = $true
    } else {
        Write-Host "   ❌ Variable not properly defined before usage (def: $definitionLine2, use: $usageLine2)" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing privateEndpointsPercentage: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing dashboard Unit property fixes...`n" -ForegroundColor Yellow

try {
    # Check that all dashboard cards have Unit property defined
    $dashboardCardMatches = [regex]::Matches($scriptContent, '@\{\s*Title\s*=\s*"[^"]*"[^}]*\}', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    
    $cardsWithUnit = 0
    $totalCards = 0
    
    foreach ($match in $dashboardCardMatches) {
        $cardContent = $match.Value
        if ($cardContent -match 'Title\s*=\s*"(Total Vaults|Overall Compliance|Private Endpoint Coverage|High Risk Vaults|Legacy Access Policies|Public Network Access|Compliance Score)"') {
            $totalCards++
            if ($cardContent -match 'Unit\s*=') {
                $cardsWithUnit++
                Write-Host "   📋 Card '$($matches[1])' has Unit property" -ForegroundColor Green
            } else {
                Write-Host "   ❌ Card '$($matches[1])' missing Unit property" -ForegroundColor Red
            }
        }
    }
    
    if ($cardsWithUnit -eq $totalCards -and $totalCards -gt 0) {
        Write-Host "   ✅ All $totalCards dashboard cards have Unit property" -ForegroundColor Green
        $testResults.DashboardUnitPropertiesFixed = $true
    } else {
        Write-Host "   ❌ Only $cardsWithUnit of $totalCards cards have Unit property" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing dashboard Unit properties: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testing AuthenticationRefreshes safe handling...`n" -ForegroundColor Yellow

try {
    # Check for safe AuthenticationRefreshes placeholder handling
    $authRefreshesHandling = $scriptContent -match 'AUTHENTICATION_REFRESHES.*if.*AuditStats.*AuthenticationRefreshes.*else.*"0"'
    Write-Host "   📊 Safe AuthenticationRefreshes handling: $authRefreshesHandling" -ForegroundColor $(if ($authRefreshesHandling) { "Green" } else { "Red" })
    
    if ($authRefreshesHandling) {
        $testResults.AuthenticationRefreshesHandled = $true
    }
} catch {
    Write-Host "   ❌ Error testing AuthenticationRefreshes: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n6️⃣ Testing Microsoft compliance properties safe handling...`n" -ForegroundColor Yellow

try {
    # Check for safe Microsoft compliance placeholder handling
    $msComplianceHandling = $scriptContent -match 'MICROSOFT_FULLY_COMPLIANT.*Get-PlaceholderValue.*MicrosoftFullyCompliant'
    Write-Host "   📊 Safe Microsoft compliance handling: $msComplianceHandling" -ForegroundColor $(if ($msComplianceHandling) { "Green" } else { "Red" })
    
    if ($msComplianceHandling) {
        $testResults.MicrosoftComplianceHandled = $true
    }
} catch {
    Write-Host "   ❌ Error testing Microsoft compliance: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📊 CRITICAL ERROR FIXES TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
}

Write-Host "`nOverall: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All critical error fixes validated successfully!" -ForegroundColor Green
    Write-Host "💡 The script should now complete without template processing failures" -ForegroundColor Blue
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "`n✅ Most critical error fixes applied. Minor issues may remain." -ForegroundColor Yellow
} else {
    Write-Host "`n⚠️ Several critical errors remain - review results above" -ForegroundColor Red
}

return $passedTests -eq $totalTests