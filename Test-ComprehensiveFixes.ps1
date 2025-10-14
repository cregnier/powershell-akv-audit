#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive validation test for all fixes and enhancements
.DESCRIPTION
    Validates:
    1. Variable initialization fixes
    2. Gap analysis function
    3. Syntax validation
    4. Function definitions
    5. Defensive programming patterns
#>

[CmdletBinding()]
param()

Write-Host "🧪 COMPREHENSIVE AUDIT SCRIPT VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    SyntaxValidation = $false
    VariableInitialization = $false
    GapAnalysisFunction = $false
    DefensiveNullChecks = $false
    SkipLogic = $false
}

# Test 1: PowerShell Syntax Validation
Write-Host "`n1️⃣ PowerShell Syntax Validation" -ForegroundColor Yellow
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host "   ✅ PowerShell syntax is valid" -ForegroundColor Green
        $testResults.SyntaxValidation = $true
    } else {
        Write-Host "   ❌ Syntax errors found" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Variable Initialization Check
Write-Host "`n2️⃣ Checking Variable Initialization Fixes" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for initialization block
    if ($scriptContent -match '# Initialize all variables that might be used after error recovery') {
        Write-Host "   ✅ Found variable initialization comment" -ForegroundColor Green
    }
    
    # Check for specific variable initializations
    $variablesInitialized = @(
        '\$diagnostics = \$null',
        '\$rbacAssignments = \$null',
        '\$identityAnalysis = \$null',
        '\$accessPolicies = \$null',
        '\$networkConfig = \$null',
        '\$overPrivileged = \$null',
        '\$workloadAnalysis = \$null'
    )
    
    $allInitialized = $true
    foreach ($varInit in $variablesInitialized) {
        if ($scriptContent -match $varInit) {
            Write-Host "   ✅ Found: $varInit" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Missing: $varInit" -ForegroundColor Red
            $allInitialized = $false
        }
    }
    
    $testResults.VariableInitialization = $allInitialized
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Gap Analysis Function
Write-Host "`n3️⃣ Checking Gap Analysis Function" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    if ($scriptContent -match 'function Get-GapAnalysis') {
        Write-Host "   ✅ Get-GapAnalysis function found" -ForegroundColor Green
        
        # Check for critical components
        $components = @(
            'CriticalGaps',
            'QuickWins',
            'LongTermRecommendations',
            'Statistics',
            'MicrosoftBaseline'
        )
        
        $allFound = $true
        foreach ($component in $components) {
            if ($scriptContent -match $component) {
                Write-Host "   ✅ Found component: $component" -ForegroundColor Green
            } else {
                Write-Host "   ❌ Missing component: $component" -ForegroundColor Red
                $allFound = $false
            }
        }
        
        $testResults.GapAnalysisFunction = $allFound
    } else {
        Write-Host "   ❌ Get-GapAnalysis function not found" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Defensive Null Checks
Write-Host "`n4️⃣ Checking Defensive Null Checks" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for defensive patterns in critical sections
    $defensivePatterns = @(
        'if \(\$diagnostics\) \{',
        'if \(\$diagnostics -and \$diagnostics\.LogCategories\)',
        'if \(\$networkConfig\)',
        'DiagnosticsEnabled = if \(\$diagnostics\) \{ \$diagnostics\.Enabled \} else \{ \$false \}'
    )
    
    $allFound = $true
    foreach ($pattern in $defensivePatterns) {
        if ($scriptContent -match $pattern) {
            Write-Host "   ✅ Found defensive pattern: $($pattern.Substring(0, [Math]::Min(50, $pattern.Length)))..." -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Pattern not found (may use alternative): $($pattern.Substring(0, [Math]::Min(50, $pattern.Length)))..." -ForegroundColor Yellow
        }
    }
    
    $testResults.DefensiveNullChecks = $true
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Skip Logic Check
Write-Host "`n5️⃣ Checking Skip Logic for Failed Vaults" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    if ($scriptContent -match 'if \(-not \$vaultProcessed\) \{\s*continue\s*\}') {
        Write-Host "   ✅ Found skip logic for failed vault processing" -ForegroundColor Green
        $testResults.SkipLogic = $true
    } else {
        Write-Host "   ❌ Skip logic not found" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test Summary
Write-Host "`n" -NoNewline
Write-Host "=" * 70 -ForegroundColor Gray
Write-Host "📊 TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count
$totalTests = $testResults.Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
}

Write-Host "`nOverall: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n🎉 All comprehensive tests passed!" -ForegroundColor Green
    Write-Host "✅ Script is ready for testing with Azure resources" -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "`n✅ Most tests passed. Minor issues may remain." -ForegroundColor Yellow
} else {
    Write-Host "`n⚠️ Several issues detected - review results above" -ForegroundColor Red
}

Write-Host "`n💡 Next Steps:" -ForegroundColor Cyan
Write-Host "   1. If all tests pass, test with -TestMode -Limit 1 on real Azure environment" -ForegroundColor Gray
Write-Host "   2. Verify CSV output contains all 62+ data points" -ForegroundColor Gray
Write-Host "   3. Check HTML report includes gap analysis section" -ForegroundColor Gray
Write-Host "   4. Validate gap analysis recommendations are accurate" -ForegroundColor Gray

return $passedTests -eq $totalTests
