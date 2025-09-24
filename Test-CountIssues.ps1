#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to identify and validate .Count property usage patterns
.DESCRIPTION
    This script analyzes the main script for .Count property usage to identify:
    - Hashtables that should use .Keys.Count
    - Scalars that should not use .Count
    - Arrays/lists that correctly use .Count
#>

[CmdletBinding()]
param()

Write-Host "🔍 ANALYZING .Count PROPERTY USAGE PATTERNS" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$scriptContent = Get-Content $scriptPath -Raw

# Find all .Count usage
$countMatches = [regex]::Matches($scriptContent, '\$\w+\.Count')
Write-Host "`n📊 Found $($countMatches.Count) .Count usages" -ForegroundColor Yellow

# Analyze each match
$issueCount = 0
foreach ($match in $countMatches) {
    $variableName = ($match.Value -split '\.')[0]
    
    # Get context around the match
    $lines = $scriptContent.Split("`n")
    $matchLine = $null
    $lineNumber = 0
    
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -contains $match.Value) {
            $matchLine = $lines[$i]
            $lineNumber = $i + 1
            break
        }
    }
    
    # Look for variable definition patterns
    $hashtablePattern = "$variableName\s*=\s*@\{"
    $arrayPattern = "$variableName\s*=\s*@\(\)"
    $scalarPattern = "$variableName\s*=\s*\d+|$variableName\s*=\s*\$\w+\.\w+"
    
    $isHashtable = $scriptContent -match $hashtablePattern
    $isArray = $scriptContent -match $arrayPattern
    $isScalar = $scriptContent -match $scalarPattern
    
    Write-Host "`n   Variable: $variableName" -ForegroundColor White
    Write-Host "   Usage: $($match.Value)" -ForegroundColor Gray
    Write-Host "   Hashtable pattern found: $isHashtable" -ForegroundColor $(if ($isHashtable) { "Yellow" } else { "Gray" })
    Write-Host "   Array pattern found: $isArray" -ForegroundColor $(if ($isArray) { "Green" } else { "Gray" })
    Write-Host "   Scalar pattern found: $isScalar" -ForegroundColor $(if ($isScalar) { "Red" } else { "Gray" })
    
    # Check if it's a problematic case
    if ($isHashtable -and $match.Value -notmatch "\.Keys\.Count") {
        Write-Host "   ❌ ISSUE: Hashtable using .Count instead of .Keys.Count" -ForegroundColor Red
        $issueCount++
    } elseif ($isScalar) {
        Write-Host "   ❌ ISSUE: Scalar variable using .Count" -ForegroundColor Red
        $issueCount++
    } else {
        Write-Host "   ✅ Usage appears correct" -ForegroundColor Green
    }
}

Write-Host "`n📊 ANALYSIS RESULTS" -ForegroundColor Cyan
Write-Host "=" * 30 -ForegroundColor Gray
Write-Host "Total .Count usages: $($countMatches.Count)" -ForegroundColor White
Write-Host "Potential issues found: $issueCount" -ForegroundColor $(if ($issueCount -gt 0) { "Red" } else { "Green" })

return $issueCount