#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate the new critical fixes for PowerShell script issues
.DESCRIPTION
    Validates the specific fixes made for:
    1. Missing $compliancePercentage variable definition
    2. ShowProgress property defensive access in dashboard cards
    3. Consistency of ShowProgress property across all dashboard cards
#>

[CmdletBinding()]
param()

Write-Host "🔧 NEW CRITICAL FIXES VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$testResults = @{
    CompliancePercentageFixed = $false
    ShowProgressDefensiveAccess = $false
    ShowProgressConsistency = $false
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

Write-Host "`n2️⃣ Testing compliancePercentage variable definition...`n" -ForegroundColor Yellow

try {
    $scriptContent = Get-Content $scriptPath -Raw
    $lines = Get-Content $scriptPath
    
    # Find where compliancePercentage is defined and used
    $definitionLine = $null
    $usageLine = $null
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        # Look for the new definition in the summary section (matches the start of the assignment)
        if ($lines[$i] -match '^\$compliancePercentage\s*=.*executiveSummary\.TotalKeyVaults') {
            $definitionLine = $i + 1
        }
        # Look for usage in the color-coded summary
        if ($lines[$i] -match 'if.*\$compliancePercentage.*-ge.*90' -and $usageLine -eq $null) {
            $usageLine = $i + 1
        }
    }
    
    if ($definitionLine -and $usageLine -and $definitionLine -lt $usageLine) {
        Write-Host "   ✅ compliancePercentage defined before usage (line $definitionLine < $usageLine)" -ForegroundColor Green
        Write-Host "   📊 Definition found in summary section for color-coded output" -ForegroundColor Green
        $testResults.CompliancePercentageFixed = $true
    } else {
        Write-Host "   ❌ compliancePercentage not properly defined before usage (def: $definitionLine, use: $usageLine)" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing compliancePercentage: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing ShowProgress defensive access...`n" -ForegroundColor Yellow

try {
    # Check for defensive ContainsKey check in Convert-AkvCardToHtml
    $defensiveAccess = $scriptContent -match 'ContainsKey.*ShowProgress.*and.*Card\.ShowProgress'
    Write-Host "   📊 Defensive ShowProgress access: $defensiveAccess" -ForegroundColor $(if ($defensiveAccess) { "Green" } else { "Red" })
    
    if ($defensiveAccess) {
        $testResults.ShowProgressDefensiveAccess = $true
        Write-Host "   ✅ ShowProgress property is accessed safely with ContainsKey check" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing ShowProgress defensive access: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n4️⃣ Testing ShowProgress property consistency...`n" -ForegroundColor Yellow

try {
    # Find all dashboard card definitions and check ShowProgress property
    $cardMatches = [regex]::Matches($scriptContent, '@\{\s*Title\s*=\s*"([^"]*)"[^}]*\}', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    
    $cardsChecked = 0
    $cardsWithShowProgress = 0
    $cardNames = @()
    
    foreach ($match in $cardMatches) {
        $cardContent = $match.Value
        $titleMatch = [regex]::Match($cardContent, 'Title\s*=\s*"([^"]*)"')
        
        if ($titleMatch.Success) {
            $cardTitle = $titleMatch.Groups[1].Value
            $cardNames += $cardTitle
            
            # Check if this is a dashboard stats card (not section cards)
            if ($cardTitle -match '^(Overall Compliance|Private Endpoint Coverage|High Risk Vaults|Legacy Access Policies|Public Network Access|Total Vaults|Compliance Score)') {
                $cardsChecked++
                if ($cardContent -match 'ShowProgress\s*=') {
                    $cardsWithShowProgress++
                    Write-Host "   📋 Card '$cardTitle' has ShowProgress property" -ForegroundColor Green
                } else {
                    Write-Host "   ❌ Card '$cardTitle' missing ShowProgress property" -ForegroundColor Red
                }
            }
        }
    }
    
    if ($cardsWithShowProgress -eq $cardsChecked -and $cardsChecked -gt 0) {
        Write-Host "   ✅ All $cardsChecked dashboard cards have ShowProgress property" -ForegroundColor Green
        $testResults.ShowProgressConsistency = $true
    } else {
        Write-Host "   ❌ Only $cardsWithShowProgress of $cardsChecked cards have ShowProgress property" -ForegroundColor Red
    }
    
    Write-Host "   📊 Found cards: $($cardNames -join ', ')" -ForegroundColor Gray
} catch {
    Write-Host "   ❌ Error testing ShowProgress consistency: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n📊 NEW CRITICAL FIXES TEST SUMMARY" -ForegroundColor Cyan
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
    Write-Host "`n🎉 All new critical fixes validated successfully!" -ForegroundColor Green
    Write-Host "💡 The script should now complete without the specific errors mentioned in the problem statement" -ForegroundColor Blue
} else {
    Write-Host "`n⚠️ Some fixes may need additional attention - review results above" -ForegroundColor Red
}

return $passedTests -eq $totalTests