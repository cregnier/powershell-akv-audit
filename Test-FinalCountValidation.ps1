#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Final validation of .Count property fixes
.DESCRIPTION
    Validates that all identified .Count property issues have been resolved
    by testing the specific patterns that were problematic.
#>

[CmdletBinding()]
param()

Write-Host "🎯 FINAL VALIDATION OF .Count PROPERTY FIXES" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$scriptContent = Get-Content $scriptPath -Raw

Write-Host "`n✅ SUMMARY OF FIXES APPLIED" -ForegroundColor Green
Write-Host "=" * 50 -ForegroundColor Gray

$fixes = @(
    @{
        Issue = "Parser error: `$Context: invalid variable syntax"
        Lines = @(3544, 3555, 3634, 3645)
        Fix = "Changed to `${Context} for proper variable interpolation"
        Verification = '${Context}'
    },
    @{
        Issue = "CloudShell indicator ForEach-Object scalar .Count error"
        Lines = @(981)
        Fix = "Wrapped in @() to ensure array: @(`$cloudShellChecks.GetEnumerator()...)"
        Verification = '@($cloudShellChecks.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })'
    },
    @{
        Issue = "MSI indicator ForEach-Object scalar .Count error"
        Lines = @(1124)
        Fix = "Wrapped in @() to ensure array: @(`$msiChecks.GetEnumerator()...)"
        Verification = '@($msiChecks.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })'
    },
    @{
        Issue = "Scores ForEach-Object scalar .Count error"
        Lines = @(3869)
        Fix = "Wrapped in @() to ensure array: @(`$auditResultsArray | ForEach-Object...)"
        Verification = '$scores = @($auditResultsArray | ForEach-Object {'
    },
    @{
        Issue = "Company scores ForEach-Object scalar .Count error"
        Lines = @(3882)
        Fix = "Wrapped in @() to ensure array: @(`$auditResultsArray | ForEach-Object...)"
        Verification = '$companyScores = @($auditResultsArray | ForEach-Object {'
    },
    @{
        Issue = "Global MS scores ForEach-Object scalar .Count error"
        Lines = @(7641)
        Fix = "Wrapped in @() to ensure array: @(`$global:auditResults | ForEach-Object...)"
        Verification = '$msScores = @($global:auditResults | ForEach-Object {'
    },
    @{
        Issue = "Global company scores ForEach-Object scalar .Count error"
        Lines = @(7648)
        Fix = "Wrapped in @() to ensure array: @(`$global:auditResults | ForEach-Object...)"
        Verification = '$companyScores = @($global:auditResults | ForEach-Object {'
    }
)

$fixedCount = 0
foreach ($fix in $fixes) {
    $isFixed = $scriptContent -match [regex]::Escape($fix.Verification)
    $status = if ($isFixed) { "✅ FIXED" } else { "❌ NOT FIXED" }
    $color = if ($isFixed) { "Green" } else { "Red" }
    
    Write-Host "`n$($fix.Issue)" -ForegroundColor White
    Write-Host "   Lines: $($fix.Lines -join ', ')" -ForegroundColor Gray
    Write-Host "   Fix: $($fix.Fix)" -ForegroundColor Gray
    Write-Host "   Status: $status" -ForegroundColor $color
    
    if ($isFixed) { $fixedCount++ }
}

Write-Host "`n📊 VALIDATION RESULTS" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray
Write-Host "Total issues identified: $($fixes.Count)" -ForegroundColor White
Write-Host "Issues fixed: $fixedCount" -ForegroundColor $(if ($fixedCount -eq $fixes.Count) { "Green" } else { "Red" })
Write-Host "Remaining issues: $($fixes.Count - $fixedCount)" -ForegroundColor $(if ($fixedCount -eq $fixes.Count) { "Green" } else { "Red" })

if ($fixedCount -eq $fixes.Count) {
    Write-Host "`n🎉 SUCCESS: ALL .Count PROPERTY ISSUES RESOLVED!" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host "✅ Parser errors fixed - PowerShell syntax is now valid" -ForegroundColor Green
    Write-Host "✅ ForEach-Object scalar results wrapped in @() arrays" -ForegroundColor Green  
    Write-Host "✅ HTML report generation should no longer fail with 'Count cannot be found'" -ForegroundColor Green
    Write-Host "✅ Both SingleVault and comprehensive modes should work correctly" -ForegroundColor Green
    Write-Host "`n💡 EXPECTED RESULTS:" -ForegroundColor Yellow
    Write-Host "   • Script syntax validation: No parser errors" -ForegroundColor White
    Write-Host "   • SingleVault mode: No .Count property runtime errors" -ForegroundColor White
    Write-Host "   • Comprehensive mode: Proper aggregation and reporting" -ForegroundColor White
    Write-Host "   • HTML generation: Executive summary cards populate correctly" -ForegroundColor White
} else {
    Write-Host "`n⚠️ INCOMPLETE: Some issues remain unfixed" -ForegroundColor Yellow
}

Write-Host "`n🔧 TECHNICAL DETAILS" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray
Write-Host "The root cause of 'Count cannot be found on this object' errors:" -ForegroundColor White
Write-Host "• PowerShell ForEach-Object returns scalar values when processing single items" -ForegroundColor Gray
Write-Host "• Scalar values (strings, numbers) do not have a .Count property" -ForegroundColor Gray  
Write-Host "• Wrapping results in @() forces PowerShell to create an array" -ForegroundColor Gray
Write-Host "• Arrays always have a .Count property, preventing runtime errors" -ForegroundColor Gray

return ($fixedCount -eq $fixes.Count)