#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Identify potential .Count property issues by testing runtime scenarios
.DESCRIPTION
    This script identifies places where .Count might fail at runtime by looking for
    specific patterns where variables might not have the expected type.
#>

[CmdletBinding()]
param()

Write-Host "🔍 IDENTIFYING POTENTIAL RUNTIME .Count ISSUES" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$scriptContent = Get-Content $scriptPath -Raw

Write-Host "`n1️⃣ Searching for problematic patterns..." -ForegroundColor Yellow

# Pattern 1: Variables that might be scalars but use .Count
$scalarPatterns = @(
    '\$\w*Score\w*\.Count',
    '\$\w*Average\w*\.Count',
    '\$\w*Percentage\w*\.Count',
    '\$\w*Total\w*\.Count(?!\w)',  # Exclude TotalKeyVaults.Count etc. that might be arrays
    '\$\w*Index\w*\.Count',
    '\$\w*Name\w*\.Count',
    '\$\w*Value\w*\.Count'
)

Write-Host "`n   🔍 Checking for scalar variables using .Count:" -ForegroundColor White
$scalarIssues = 0
foreach ($pattern in $scalarPatterns) {
    $matches = [regex]::Matches($scriptContent, $pattern)
    if ($matches.Count -gt 0) {
        Write-Host "      ❌ Found potential scalar .Count usage: $pattern" -ForegroundColor Red
        foreach ($match in $matches) {
            Write-Host "         $($match.Value)" -ForegroundColor Red
        }
        $scalarIssues += $matches.Count
    }
}

if ($scalarIssues -eq 0) {
    Write-Host "      ✅ No obvious scalar .Count issues found" -ForegroundColor Green
}

# Pattern 2: Hashtables potentially using .Count instead of .Keys.Count
Write-Host "`n   🔍 Checking for hashtables that might need .Keys.Count:" -ForegroundColor White

# Look for variables that are assigned hashtables but then use .Count
$hashTablePatterns = @(
    '\$\w*stats\w*\.Count(?!\.)',
    '\$\w*Summary\w*\.Count(?!\.)',
    '\$\w*Config\w*\.Count(?!\.)',
    '\$\w*Data\w*\.Count(?!\.)',
    '\$\w*Settings\w*\.Count(?!\.)'
)

$hashIssues = 0
foreach ($pattern in $hashTablePatterns) {
    $matches = [regex]::Matches($scriptContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            # Check if this variable is assigned a hashtable somewhere
            $varName = ($match.Value -split '\.')[0]
            if ($scriptContent -match "$varName\s*=\s*@\{") {
                Write-Host "      ❌ Found hashtable using .Count instead of .Keys.Count: $($match.Value)" -ForegroundColor Red
                $hashIssues++
            }
        }
    }
}

if ($hashIssues -eq 0) {
    Write-Host "      ✅ No obvious hashtable .Count issues found" -ForegroundColor Green
}

# Pattern 3: Variables that might be $null and accessed with .Count
Write-Host "`n   🔍 Checking for potential null reference .Count usage:" -ForegroundColor White

# Look for .Count usage without null checks
$lines = $scriptContent -split "`n"
$nullIssues = 0
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '\$\w+\.Count' -and $lines[$i] -notmatch 'if.*\$\w+.*\.Count' -and $lines[$i] -notmatch 'Where-Object.*\.Count' -and $lines[$i] -notmatch '@\(' -and $lines[$i] -notmatch '\.Keys\.Count') {
        # Check if this is in a context where the variable might be null
        $varName = ([regex]::Match($lines[$i], '\$\w+(?=\.Count)')).Value
        if ($varName) {
            # Look for potential null assignments or conditional usage
            $contextStart = [Math]::Max(0, $i - 10)
            $contextEnd = [Math]::Min($lines.Length - 1, $i + 5)
            $context = $lines[$contextStart..$contextEnd] -join "`n"
            
            if ($context -match "$varName\s*=\s*\$null\|if.*not.*$varName\|if.*-not.*$varName") {
                Write-Host "      ⚠️ Potential null reference at line $($i + 1): $($lines[$i].Trim())" -ForegroundColor Yellow
                $nullIssues++
            }
        }
    }
}

if ($nullIssues -eq 0) {
    Write-Host "      ✅ No obvious null reference .Count issues found" -ForegroundColor Green
}

Write-Host "`n2️⃣ Checking for specific problematic variables mentioned in reports..." -ForegroundColor Yellow

# Check if variables known to cause issues exist
$knownProblematicPatterns = @(
    'ServicePrincipalCount\.Count',
    'ManagedIdentityCount\.Count',
    'TotalServicePrincipals\.Count',
    'TotalManagedIdentities\.Count'
)

$knownIssues = 0
foreach ($pattern in $knownProblematicPatterns) {
    if ($scriptContent -match $pattern) {
        Write-Host "      ❌ Found known problematic pattern: $pattern" -ForegroundColor Red
        $knownIssues++
    }
}

if ($knownIssues -eq 0) {
    Write-Host "      ✅ No known problematic patterns found" -ForegroundColor Green
}

Write-Host "`n📊 ISSUE SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray
Write-Host "Scalar variable .Count issues: $scalarIssues" -ForegroundColor $(if ($scalarIssues -gt 0) { "Red" } else { "Green" })
Write-Host "Hashtable .Count issues: $hashIssues" -ForegroundColor $(if ($hashIssues -gt 0) { "Red" } else { "Green" })
Write-Host "Potential null reference issues: $nullIssues" -ForegroundColor $(if ($nullIssues -gt 0) { "Yellow" } else { "Green" })
Write-Host "Known problematic patterns: $knownIssues" -ForegroundColor $(if ($knownIssues -gt 0) { "Red" } else { "Green" })

$totalIssues = $scalarIssues + $hashIssues + $knownIssues
Write-Host "`nTotal issues found: $totalIssues" -ForegroundColor $(if ($totalIssues -gt 0) { "Red" } else { "Green" })

return $totalIssues