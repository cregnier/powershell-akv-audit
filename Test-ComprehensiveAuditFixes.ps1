#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Validation script for comprehensive audit fixes

.DESCRIPTION
    Validates all the fixes made to Get-AKV_Roles-SecAuditCompliance.ps1:
    - Syntax validation
    - Parameter availability
    - Help documentation
    - Function definitions
    - No external template references
#>

[CmdletBinding()]
param()

Write-Host "`n🧪 COMPREHENSIVE AUDIT FIXES VALIDATION" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = "./Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    Syntax = $false
    Parameters = $false
    Help = $false
    Functions = $false
    NoExternalTemplates = $false
}

# Test 1: PowerShell Syntax Validation
Write-Host "`n1️⃣ PowerShell Syntax Validation" -ForegroundColor Yellow
try {
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    
    if ($errors.Count -eq 0) {
        Write-Host "   ✅ No syntax errors found" -ForegroundColor Green
        $testResults.Syntax = $true
    } else {
        Write-Host "   ❌ Syntax errors found: $($errors.Count)" -ForegroundColor Red
        foreach ($error in $errors) {
            Write-Host "      Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Parameter Block Validation
Write-Host "`n2️⃣ Parameter Block Validation" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for param block
    if ($scriptContent -match '(?s)^.*#>\s*\[CmdletBinding\(\)\]\s*param\s*\(') {
        Write-Host "   ✅ Script-level param() block exists" -ForegroundColor Green
        
        # Check for key parameters
        $keyParams = @('TestMode', 'Resume', 'ProcessPartial', 'SingleVault', 'VaultName', 'UploadToCloud')
        $foundParams = 0
        foreach ($param in $keyParams) {
            if ($scriptContent -match "\`$$param") {
                $foundParams++
            }
        }
        
        Write-Host "   ✅ Found $foundParams/$($keyParams.Count) key parameters" -ForegroundColor Green
        $testResults.Parameters = ($foundParams -eq $keyParams.Count)
    } else {
        Write-Host "   ❌ No script-level param() block found" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Help Documentation
Write-Host "`n3️⃣ Help Documentation Validation" -ForegroundColor Yellow
try {
    $help = Get-Help $scriptPath -ErrorAction Stop
    
    if ($help.Synopsis) {
        Write-Host "   ✅ Synopsis available" -ForegroundColor Green
    }
    
    if ($help.Description) {
        Write-Host "   ✅ Description available" -ForegroundColor Green
    }
    
    if ($help.Parameters) {
        $paramCount = ($help.Parameters.Parameter | Measure-Object).Count
        Write-Host "   ✅ Parameters documented: $paramCount parameters" -ForegroundColor Green
    }
    
    if ($help.Examples) {
        Write-Host "   ✅ Examples available: $($help.Examples.Example.Count) examples" -ForegroundColor Green
    }
    
    # Check that examples use correct filename (dash, not ampersand)
    $examplesText = $help.Examples | Out-String
    if ($examplesText -match 'Get-AKV_Roles&SecAuditCompliance') {
        Write-Host "   ⚠️  Examples still reference ampersand version" -ForegroundColor Yellow
    } elseif ($examplesText -match 'Get-AKV_Roles-SecAuditCompliance') {
        Write-Host "   ✅ Examples use correct filename (dash version)" -ForegroundColor Green
        $testResults.Help = $true
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Key Function Presence
Write-Host "`n4️⃣ Key Function Definitions" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    $keyFunctions = @(
        'Write-UserMessage',
        'New-ComprehensiveHtmlReport',
        'Save-ProgressCheckpoint',
        'Test-CloudShellEnvironment',
        'Test-ManagedIdentityEnvironment',
        'Get-AuthenticationMode',
        'Write-VaultResultToCSV',
        'Initialize-AzAuth'
    )
    
    $foundFunctions = 0
    foreach ($func in $keyFunctions) {
        if ($scriptContent -match "function\s+$func") {
            Write-Host "   ✅ $func function found" -ForegroundColor Green
            $foundFunctions++
        } else {
            Write-Host "   ❌ $func function missing" -ForegroundColor Red
        }
    }
    
    $testResults.Functions = ($foundFunctions -eq $keyFunctions.Count)
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: No External Template References
Write-Host "`n5️⃣ External Template References Check" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check for references to external HTML template files
    if ($scriptContent -match 'KeyVaultComprehensiveAudit_Full\.html' -or 
        $scriptContent -match 'KeyVaultComprehensiveAudit_Resume\.html') {
        Write-Host "   ❌ External HTML template references found" -ForegroundColor Red
    } else {
        Write-Host "   ✅ No external HTML template file references" -ForegroundColor Green
        
        # Verify inline HTML generation
        if ($scriptContent -match '\$htmlContent\s*=\s*@"[\s\S]*<!DOCTYPE html>') {
            Write-Host "   ✅ Inline HTML generation confirmed" -ForegroundColor Green
            $testResults.NoExternalTemplates = $true
        } else {
            Write-Host "   ⚠️  Could not confirm inline HTML generation" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: Write-UserMessage Verbose Support
Write-Host "`n6️⃣ Write-UserMessage Verbose Support" -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    if ($scriptContent -match 'function Write-UserMessage[\s\S]{0,1000}VerbosePreference') {
        Write-Host "   ✅ Write-UserMessage respects VerbosePreference" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Write-UserMessage may not respect VerbosePreference" -ForegroundColor Yellow
    }
    
    # Check for DEBUG to Write-Verbose conversions
    $debugCount = ([regex]::Matches($scriptContent, 'Write-Host.*"DEBUG:' )).Count
    if ($debugCount -eq 0) {
        Write-Host "   ✅ No hardcoded DEBUG messages found (all converted to Write-Verbose)" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Found $debugCount hardcoded DEBUG messages" -ForegroundColor Yellow
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
    Write-Host "`n🎉 All validation tests passed! Script is ready for use." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️  Some tests failed. Please review the issues above." -ForegroundColor Yellow
    exit 1
}
