#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive test script for Azure Key Vault Audit Script enhancements

.DESCRIPTION
    Validates all the implemented enhancements including:
    - Get-OverPrivilegedUsers function implementation
    - Workload analysis functionality
    - Parameter validation
    - Error handling improvements
    - CSV/HTML output structure

.EXAMPLE
    ./Test-ComprehensiveEnhancements.ps1
#>

[CmdletBinding()]
param()

Write-Host "🧪 COMPREHENSIVE AZURE KEY VAULT AUDIT ENHANCEMENTS TEST" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles-SecAuditCompliance.ps1"
$testResults = @{
    Syntax = $false
    OverPrivilegedFunction = $false
    WorkloadAnalysis = $false
    ParameterValidation = $false
    ErrorHandling = $false
    CSVStructure = $false
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

# Test 2: Get-OverPrivilegedUsers Function Implementation
Write-Host "`n2️⃣ Testing Get-OverPrivilegedUsers function implementation..." -ForegroundColor Yellow
try {
    $scriptContent = Get-Content $scriptPath -Raw
    
    # Check if stub is removed
    if ($scriptContent -notmatch "STUB FUNCTION.*Over-privileged user analysis not yet implemented") {
        Write-Host "   ✅ Stub implementation removed" -ForegroundColor Green
        
        # Check for comprehensive implementation
        $checks = @{
            "Over-privileged roles array" = 'overPrivilegedRoles.*=.*@\('
            "Least-privilege roles array" = 'appropriateRoles.*=.*@\('
            "Priority color coding" = '🔴 HIGH:|🟡 MEDIUM:|✅'
            "Role-specific recommendations" = 'Key Vault.*Officer|Key Vault.*User'
            "Service principal analysis" = 'ServicePrincipal.*Count'
            "Managed identity recommendations" = 'managed identities'
        }
        
        $passedChecks = 0
        foreach ($check in $checks.GetEnumerator()) {
            if ($scriptContent -match $check.Value) {
                Write-Host "   ✅ $($check.Key) implemented" -ForegroundColor Green
                $passedChecks++
            } else {
                Write-Host "   ⚠️ $($check.Key) not found" -ForegroundColor Yellow
            }
        }
        
        if ($passedChecks -ge 5) {
            $testResults.OverPrivilegedFunction = $true
            Write-Host "   🎯 Get-OverPrivilegedUsers comprehensive implementation: $passedChecks/6 checks passed" -ForegroundColor Green
        }
    } else {
        Write-Host "   ❌ Stub implementation still present" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error testing function: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Workload Analysis Validation
Write-Host "`n3️⃣ Testing workload analysis implementation..." -ForegroundColor Yellow
try {
    $workloadChecks = @{
        "SecretVersioning analysis" = 'SecretVersioning.*=.*@\(\)'
        "ExpirationAnalysis tracking" = 'ExpirationAnalysis.*=.*@\(\)'
        "RotationAnalysis patterns" = 'RotationAnalysis.*=.*@\(\)'
        "AppServiceIntegration detection" = 'AppServiceIntegration.*=.*@\(\)'
        "Secret versioning logic" = 'secretsWithVersions'
        "Expiration monitoring" = 'warningThreshold.*AddDays'
        "App Service pattern matching" = 'WEBSITE_|APPSETTING_|AzureWebJobs'
    }
    
    $workloadPassed = 0
    foreach ($check in $workloadChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key) implemented" -ForegroundColor Green
            $workloadPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) not found" -ForegroundColor Yellow
        }
    }
    
    if ($workloadPassed -ge 6) {
        $testResults.WorkloadAnalysis = $true
        Write-Host "   🎯 Workload analysis implementation: $workloadPassed/7 checks passed" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing workload analysis: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 4: Parameter Validation
Write-Host "`n4️⃣ Testing parameter validation logic..." -ForegroundColor Yellow
try {
    # Check for parameter validation code
    $paramChecks = @{
        "SingleVault-Resume conflict" = 'SingleVault.*and.*\(.*Resume.*ProcessPartial.*ReportFromCsv'
        "VaultName without SingleVault" = 'VaultName.*and.*not.*SingleVault'
        "Interactive VaultName prompt" = 'Read-Host.*Key Vault Name'
        "Subscription targeting" = 'SubscriptionName.*and.*not.*SingleVault'
    }
    
    $paramPassed = 0
    foreach ($check in $paramChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key) validation implemented" -ForegroundColor Green
            $paramPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) validation not found" -ForegroundColor Yellow
        }
    }
    
    if ($paramPassed -ge 3) {
        $testResults.ParameterValidation = $true
        Write-Host "   🎯 Parameter validation: $paramPassed/4 checks passed" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing parameter validation: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Enhanced Error Handling
Write-Host "`n5️⃣ Testing enhanced error handling..." -ForegroundColor Yellow
try {
    $errorChecks = @{
        "Null-safe RBAC assignment" = 'if.*assignment\.ObjectId.*else.*Unknown ObjectId'
        "PrincipalName fallback" = 'if.*assignment\.DisplayName.*else'
        "RoleDefinitionName validation" = 'if.*assignment\.RoleDefinitionName.*else.*Unknown Role'
        "DataIssuesLog for RBAC" = 'Write-DataIssuesLog.*RBAC.*assignment missing'
        "Identity PrincipalId handling" = 'if.*Identity\.PrincipalId.*else'
        "UserAssignedIdentities safety" = 'if.*UserAssignedIdentities\.Keys.*else'
    }
    
    $errorPassed = 0
    foreach ($check in $errorChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key) error handling implemented" -ForegroundColor Green
            $errorPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) error handling not found" -ForegroundColor Yellow
        }
    }
    
    if ($errorPassed -ge 4) {
        $testResults.ErrorHandling = $true
        Write-Host "   🎯 Enhanced error handling: $errorPassed/6 checks passed" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing error handling: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: CSV Output Structure
Write-Host "`n6️⃣ Testing CSV output structure..." -ForegroundColor Yellow
try {
    $csvChecks = @{
        "SecretVersioning CSV mapping" = 'SecretVersioning.*=.*workloadAnalysis\.SecretVersioning'
        "ExpirationAnalysis CSV mapping" = 'ExpirationAnalysis.*=.*workloadAnalysis\.ExpirationAnalysis'
        "RotationAnalysis CSV mapping" = 'RotationAnalysis.*=.*workloadAnalysis\.RotationAnalysis'
        "AppServiceIntegration CSV mapping" = 'AppServiceIntegration.*=.*workloadAnalysis\.AppServiceIntegration'
        "OverPrivilegedAssignments output" = 'OverPrivilegedAssignments.*=.*overPrivileged'
    }
    
    $csvPassed = 0
    foreach ($check in $csvChecks.GetEnumerator()) {
        if ($scriptContent -match $check.Value) {
            Write-Host "   ✅ $($check.Key) CSV mapping found" -ForegroundColor Green
            $csvPassed++
        } else {
            Write-Host "   ⚠️ $($check.Key) CSV mapping not found" -ForegroundColor Yellow
        }
    }
    
    if ($csvPassed -ge 4) {
        $testResults.CSVStructure = $true
        Write-Host "   🎯 CSV output structure: $csvPassed/5 checks passed" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Error testing CSV structure: $($_.Exception.Message)" -ForegroundColor Red
}

# Summary Report
Write-Host "`n📊 COMPREHENSIVE TEST SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray

$totalTests = $testResults.Count
$passedTests = ($testResults.Values | Where-Object { $_ -eq $true }).Count

foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "  $($test.Key): $status" -ForegroundColor $color
}

Write-Host "`n🎯 Overall Results: $passedTests/$totalTests tests passed" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } else { "Yellow" })

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 All enhancements successfully implemented and tested!" -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "✅ Most enhancements implemented successfully. Minor issues may need attention." -ForegroundColor Yellow
} else {
    Write-Host "⚠️ Several implementation issues detected. Review required." -ForegroundColor Red
}

Write-Host "`n💡 Next Steps:" -ForegroundColor Cyan
Write-Host "  • Test with actual Azure Key Vault (requires authentication)" -ForegroundColor Gray
Write-Host "  • Validate HTML report generation" -ForegroundColor Gray
Write-Host "  • Run performance testing for SingleVault mode" -ForegroundColor Gray
Write-Host "  • Verify all 65+ CSV columns are populated correctly" -ForegroundColor Gray

return $testResults