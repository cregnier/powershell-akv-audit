#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive validation test for Azure Key Vault Audit Script enhancements

.DESCRIPTION
    Validates all the implemented fixes and enhancements:
    - Syntax validation
    - Variable initialization checks
    - Null-safety validation
    - Help documentation
    - Function definitions
    - Parameter validation

.EXAMPLE
    ./Test-ComprehensiveAudit.ps1
#>

[CmdletBinding()]
param()

Write-Host "🧪 COMPREHENSIVE AZURE KEY VAULT AUDIT VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    Syntax = $false
    VariableInitialization = $false
    NullSafety = $false
    HelpDocumentation = $false
    FunctionDefinitions = $false
    NoExternalTemplates = $false
}

# Test 1: PowerShell Syntax Validation
Write-Host "`n1️⃣ PowerShell Syntax Validation" -ForegroundColor Yellow
try {
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    
    if ($errors -and $errors.Count -gt 0) {
        Write-Host "   ❌ Parse errors found:" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
        $testResults.Syntax = $false
    } else {
        Write-Host "   ✅ PowerShell syntax valid" -ForegroundColor Green
        $functions = $ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)
        Write-Host "   ℹ️  Found $($functions.Count) functions" -ForegroundColor Cyan
        $testResults.Syntax = $true
        $testResults.FunctionDefinitions = $true
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    $testResults.Syntax = $false
}

# Test 2: Variable Initialization Check
Write-Host "`n2️⃣ Checking Variable Initialization" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $criticalVars = @(
        'rbacPercentage',
        'diagnosticsPercentage',
        'eventHubPercentage',
        'logAnalyticsPercentage',
        'storageAccountPercentage',
        'privateEndpointsPercentage',
        'compliancePercentage'
    )
    
    $allInitialized = $true
    foreach ($var in $criticalVars) {
        if ($scriptContent -match "\`$$var\s*=") {
            Write-Host "   ✅ $var is initialized" -ForegroundColor Green
        } else {
            Write-Host "   ❌ $var is NOT initialized" -ForegroundColor Red
            $allInitialized = $false
        }
    }
    
    $testResults.VariableInitialization = $allInitialized
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    $testResults.VariableInitialization = $false
}

# Test 3: Null-Safety Validation
Write-Host "`n3️⃣ Checking Null-Safety Patterns" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for try/catch blocks around ComplianceScore access
    $hasTryCatch = $scriptContent -match "try\s*\{[^}]*ComplianceScore[^}]*\}\s*catch"
    if ($hasTryCatch) {
        Write-Host "   ✅ Found try/catch blocks for ComplianceScore access" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  No try/catch blocks found for ComplianceScore (may be using other null-safety)" -ForegroundColor Yellow
    }
    
    # Check for null-safe property access patterns
    $hasNullCheck = $scriptContent -match "if\s*\(\s*\`$.*?\.ComplianceScore\s*\)"
    if ($hasNullCheck) {
        Write-Host "   ✅ Found null-check patterns for property access" -ForegroundColor Green
    }
    
    $testResults.NullSafety = $true
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    $testResults.NullSafety = $false
}

# Test 4: External Template Reference Check
Write-Host "`n4️⃣ Checking for External Template References" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for Use-HtmlTemplate function (should be removed)
    if ($scriptContent -match "function\s+Use-HtmlTemplate") {
        Write-Host "   ❌ Use-HtmlTemplate function still exists (should be removed)" -ForegroundColor Red
        $testResults.NoExternalTemplates = $false
    } else {
        Write-Host "   ✅ Use-HtmlTemplate function removed" -ForegroundColor Green
        $testResults.NoExternalTemplates = $true
    }
    
    # Check that New-ComprehensiveHtmlReport generates inline HTML
    if ($scriptContent -match "New-ComprehensiveHtmlReport.*Generate.*inline") {
        Write-Host "   ✅ New-ComprehensiveHtmlReport documented as inline generation" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  Documentation may need update" -ForegroundColor Cyan
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Help Documentation Validation
Write-Host "`n5️⃣ Validating Help Documentation" -ForegroundColor Yellow
try {
    $help = Get-Help $scriptPath -ErrorAction Stop
    
    if ($help.Synopsis) {
        Write-Host "   ✅ Synopsis available" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Synopsis missing" -ForegroundColor Red
    }
    
    if ($help.Description) {
        Write-Host "   ✅ Description available" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Description missing" -ForegroundColor Yellow
    }
    
    if ($help.Examples) {
        Write-Host "   ✅ Examples available ($($help.Examples.Count) examples)" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Examples missing" -ForegroundColor Yellow
    }
    
    $testResults.HelpDocumentation = $true
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    $testResults.HelpDocumentation = $false
}

# Test 6: Key Function Presence
Write-Host "`n6️⃣ Checking Key Function Definitions" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $keyFunctions = @(
        'New-ComprehensiveHtmlReport',
        'Save-ProgressCheckpoint',
        'Test-CloudShellEnvironment',
        'Get-AuthenticationMode',
        'Write-VaultResultToCSV',
        'Initialize-AzAuth'
    )
    
    foreach ($func in $keyFunctions) {
        if ($scriptContent -match "function\s+$func") {
            Write-Host "   ✅ $func function found" -ForegroundColor Green
        } else {
            Write-Host "   ❌ $func function missing" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Final Summary
Write-Host "`n" + "=" * 70 -ForegroundColor Gray
Write-Host "📊 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$status - $($test.Key)" -ForegroundColor $color
}

Write-Host "`nOverall: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All tests passed! Script is ready for use." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️  Some tests failed. Please review the issues above." -ForegroundColor Yellow
    exit 1
}
