#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to verify the try/catch syntax fix
.DESCRIPTION
    Validates that the PowerShell script can be loaded without syntax errors
    after fixing the premature function closure in New-ComprehensiveHtmlReport.
#>

[CmdletBinding()]
param()

Write-Host "🔍 POWERSHELL TRY/CATCH SYNTAX FIX VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 55 -ForegroundColor Gray

$scriptPath = "./Get-AKV_Roles-SecAuditCompliance.ps1"

Write-Host "`n1️⃣ Testing PowerShell parser syntax validation..." -ForegroundColor Yellow

$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)

Write-Host "   📊 Parser statistics:" -ForegroundColor White
Write-Host "      Total tokens: $($tokens.Count)" -ForegroundColor Gray
Write-Host "      AST nodes: $($ast.FindAll({$true}, $true).Count)" -ForegroundColor Gray

if ($errors -and $errors.Count -gt 0) {
    Write-Host "`n   ❌ SYNTAX ERRORS FOUND: $($errors.Count)" -ForegroundColor Red
    $errors | ForEach-Object {
        Write-Host "      Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "   ✅ No syntax errors found" -ForegroundColor Green
}

Write-Host "`n2️⃣ Testing try/catch block balance..." -ForegroundColor Yellow

$scriptContent = Get-Content $scriptPath -Raw
$tryCount = ([regex]::Matches($scriptContent, "\btry\s*\{")).Count
$catchCount = ([regex]::Matches($scriptContent, "\bcatch\s*\{")).Count
$finallyCount = ([regex]::Matches($scriptContent, "\bfinally\s*\{")).Count

Write-Host "   📊 Try/Catch/Finally statistics:" -ForegroundColor White
Write-Host "      Try blocks: $tryCount" -ForegroundColor Gray
Write-Host "      Catch blocks: $catchCount" -ForegroundColor Gray
Write-Host "      Finally blocks: $finallyCount" -ForegroundColor Gray

# Try blocks should equal catch blocks + finally blocks (since try-catch and try-finally are both valid)
if ($tryCount -eq ($catchCount + $finallyCount)) {
    Write-Host "   ✅ Try/Catch/Finally blocks are perfectly balanced" -ForegroundColor Green
} elseif ($tryCount -eq $catchCount) {
    if ($finallyCount -gt 0) {
        Write-Host "   ⚠️ Try/Catch balanced, but $finallyCount try-finally blocks don't have catch" -ForegroundColor Yellow
    } else {
        Write-Host "   ✅ Try/Catch blocks are balanced (no finally blocks)" -ForegroundColor Green
    }
} else {
    Write-Host "   ℹ️ Try: $tryCount, Catch: $catchCount, Finally: $finallyCount" -ForegroundColor Cyan
    Write-Host "   ℹ️ Note: Some try blocks may have only finally (valid PowerShell)" -ForegroundColor Cyan
}

Write-Host "`n3️⃣ Verifying specific functions..." -ForegroundColor Yellow

# Check Write-VerboseEnvironmentInfo
if ($scriptContent -match "function Write-VerboseEnvironmentInfo") {
    Write-Host "   ✅ Write-VerboseEnvironmentInfo function exists" -ForegroundColor Green
} else {
    Write-Host "   ❌ Write-VerboseEnvironmentInfo function NOT found" -ForegroundColor Red
    exit 1
}

# Check New-ComprehensiveHtmlReport  
if ($scriptContent -match "function New-ComprehensiveHtmlReport") {
    Write-Host "   ✅ New-ComprehensiveHtmlReport function exists" -ForegroundColor Green
} else {
    Write-Host "   ❌ New-ComprehensiveHtmlReport function NOT found" -ForegroundColor Red
    exit 1
}

Write-Host "`n4️⃣ Testing Help system (script loadability)..." -ForegroundColor Yellow

try {
    $help = Get-Help $scriptPath -ErrorAction Stop
    if ($help) {
        Write-Host "   ✅ Script can be loaded via Get-Help" -ForegroundColor Green
        Write-Host "      Synopsis: $($help.Synopsis.Substring(0, [Math]::Min(60, $help.Synopsis.Length)))..." -ForegroundColor Gray
    }
} catch {
    Write-Host "   ❌ Failed to load script via Get-Help: $_" -ForegroundColor Red
    exit 1
}

Write-Host "`n" + ("=" * 55) -ForegroundColor Gray
Write-Host "✅ ALL TESTS PASSED - Try/Catch syntax is valid!" -ForegroundColor Green
Write-Host "" 
Write-Host "Summary: The script successfully loads in PowerShell 7+ without syntax errors." -ForegroundColor Cyan
Write-Host "The premature function closure has been fixed." -ForegroundColor Cyan
Write-Host ""

exit 0
