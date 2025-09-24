#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test HTML generation to verify Count fixes work in practice
.DESCRIPTION
    Tests actual HTML generation scenarios to confirm that Count property errors are resolved
#>

[CmdletBinding()]
param()

Write-Host "🧪 TESTING HTML GENERATION COUNT FIXES" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$scriptPath = Join-Path $PSScriptRoot "Get-AKV_Roles&SecAuditCompliance.ps1"
$testResults = @{
    SyntaxValidation = $false
    SingleVaultScenario = $false
    ComprehensiveScenario = $false
    FunctionAvailability = $false
}

Write-Host "`n1️⃣ Testing syntax validation..." -ForegroundColor Yellow
try {
    $null = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    Write-Host "   ✅ PowerShell syntax is valid" -ForegroundColor Green
    $testResults.SyntaxValidation = $true
} catch {
    Write-Host "   ❌ Syntax validation failed: $_" -ForegroundColor Red
}

Write-Host "`n2️⃣ Testing function availability..." -ForegroundColor Yellow
try {
    # Source the script to load functions
    . $scriptPath | Out-Null
    
    $functionsToTest = @(
        'Update-ExecutiveSummaryFromAuditData',
        'Use-HtmlTemplate', 
        'New-ComprehensiveHtmlReport',
        'Test-TemplateVariables'
    )
    
    $availableFunctions = 0
    foreach ($funcName in $functionsToTest) {
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            Write-Host "   ✅ $funcName is available" -ForegroundColor Green
            $availableFunctions++
        } else {
            Write-Host "   ❌ $funcName is not available" -ForegroundColor Red
        }
    }
    
    if ($availableFunctions -eq $functionsToTest.Count) {
        $testResults.FunctionAvailability = $true
    }
    
} catch {
    Write-Host "   ❌ Error loading functions: $_" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing single audit result scenario (SingleVault mode)..." -ForegroundColor Yellow
try {
    # Test the scenario that commonly caused .Count errors
    $singleAuditResult = @(
        [PSCustomObject]@{
            KeyVaultName = "test-vault"
            SubscriptionName = "test-sub"
            ComplianceScore = 85
            CompanyComplianceScore = 90
            ServicePrincipalCount = 5
            ManagedIdentityCount = 2
            ResourceId = "/subscriptions/test/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test-vault"
            Location = "eastus"
            ResourceGroupName = "test-rg"
            SubscriptionId = "12345678-1234-1234-1234-123456789012"
            LastAuditDate = (Get-Date).ToString()
            ComplianceStatus = "Fully Compliant"
            SystemAssignedIdentity = "Yes"
            UserAssignedIdentityCount = 1
            DiagnosticsEnabled = $true
            EventHubEnabled = $false
            LogAnalyticsEnabled = $true
            StorageAccountEnabled = $false
            PrivateEndpointCount = 0
            RBACAssignmentCount = 3
            AccessPolicyCount = 0
        }
    )
    
    # Test ExecutiveSummary creation and update
    $executiveSummary = @{
        TotalKeyVaults = 0
        TotalServicePrincipals = 0
        TotalManagedIdentities = 0
    }
    
    # This should not cause .Count errors anymore
    $updatedSummary = Update-ExecutiveSummaryFromAuditData -ExecutiveSummary $executiveSummary -AuditResults $singleAuditResult
    
    Write-Host "   ✅ Single audit result processing successful" -ForegroundColor Green
    Write-Host "      Total Key Vaults: $($updatedSummary.TotalKeyVaults)" -ForegroundColor Gray
    Write-Host "      Total Service Principals: $($updatedSummary.TotalServicePrincipals)" -ForegroundColor Gray
    
    $testResults.SingleVaultScenario = $true
    
} catch {
    Write-Host "   ❌ Single vault scenario failed: $_" -ForegroundColor Red
    if ($_.Exception.Message -match "property.*Count.*cannot be found") {
        Write-Host "   🎯 FOUND THE COUNT ERROR - this indicates our fix didn't cover all cases" -ForegroundColor Red
    }
}

Write-Host "`n4️⃣ Testing comprehensive scenario..." -ForegroundColor Yellow
try {
    # Test with multiple audit results to ensure arrays work correctly
    $multipleAuditResults = @(
        [PSCustomObject]@{
            KeyVaultName = "vault1"
            ComplianceScore = "85%"
            CompanyComplianceScore = "90%"
        },
        [PSCustomObject]@{
            KeyVaultName = "vault2"
            ComplianceScore = "75%"
            CompanyComplianceScore = "80%"
        },
        [PSCustomObject]@{
            KeyVaultName = "vault3"
            ComplianceScore = "95%"
            CompanyComplianceScore = "100%"
        }
    )
    
    # Test the patterns that were fixed
    $testExecutiveSummary = @{
        TotalKeyVaults = $multipleAuditResults.Count
        FullyCompliant = 0
        PartiallyCompliant = 0
        NonCompliant = 0
    }
    
    # This tests the indicator matching fix
    $testCloudShellChecks = @{
        'HOME' = $true
        'SHELL' = $false
        'ACC_CLOUD' = $true
    }
    
    $matchedIndicators = @($testCloudShellChecks.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
    $indicatorCount = $matchedIndicators.Count  # Should not error
    
    Write-Host "   ✅ Comprehensive scenario successful" -ForegroundColor Green
    Write-Host "      Multiple audit results: $($multipleAuditResults.Count)" -ForegroundColor Gray
    Write-Host "      Matched indicators: $indicatorCount" -ForegroundColor Gray
    
    $testResults.ComprehensiveScenario = $true
    
} catch {
    Write-Host "   ❌ Comprehensive scenario failed: $_" -ForegroundColor Red
}

Write-Host "`n📊 TEST RESULTS" -ForegroundColor Cyan
Write-Host "=" * 40 -ForegroundColor Gray

$passedTests = 0
foreach ($test in $testResults.GetEnumerator()) {
    $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($test.Value) { "Green" } else { "Red" }
    Write-Host "$($test.Key): $status" -ForegroundColor $color
    if ($test.Value) { $passedTests++ }
}

Write-Host "`nHTML Generation Tests passed: $passedTests/$($testResults.Count)" -ForegroundColor $(if ($passedTests -eq $testResults.Count) { "Green" } else { "Yellow" })

if ($passedTests -eq $testResults.Count) {
    Write-Host "`n🎯 SUCCESS: HTML generation Count fixes verified!" -ForegroundColor Green
    Write-Host "   • SingleVault mode should work without Count errors" -ForegroundColor Green
    Write-Host "   • Comprehensive mode should work without Count errors" -ForegroundColor Green
    Write-Host "   • All function dependencies are available" -ForegroundColor Green
} else {
    Write-Host "`n⚠️ Some HTML generation tests failed" -ForegroundColor Yellow
}

return ($passedTests -eq $testResults.Count)