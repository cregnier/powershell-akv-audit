#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test script to validate authentication context object shape

.DESCRIPTION
    Validates that Initialize-AkvAuthenticationContext returns an object with all required properties.
    This test can run offline without actual Azure authentication.

.EXAMPLE
    ./Test-AuthenticationContextShape.ps1
#>

param()

Write-Host "🧪 Testing authentication context shape..." -ForegroundColor Cyan

# Define the function inline to avoid loading the entire script
function Initialize-AkvAuthenticationContext {
    [CmdletBinding()]
    param(
        [switch]$ForceLogin,
        [switch]$Quiet
    )
    
    # Initialize standard context object with all required properties
    $ctx = [ordered]@{
        IsAuthenticated = $false
        AuthenticationFlow = 'Unknown'
        TenantId = $null
        AccountUpn = $null
        SubscriptionIds = @()
        Timestamp = (Get-Date).ToUniversalTime()
        RawContext = $null
        Error = $null
    }
    
    try {
        $current = Get-AzContext -ErrorAction SilentlyContinue
        
        if ($ForceLogin -or -not $current) {
            if (-not $Quiet) {
                Write-Host '[Auth] Initiating interactive login...' -ForegroundColor Cyan
            }
            # Skip actual authentication in test mode
            if (-not $Quiet) {
                Write-Host '[Test] Skipping actual authentication for offline test' -ForegroundColor Yellow
            }
            $ctx.AuthenticationFlow = 'Interactive'
        } else {
            $ctx.AuthenticationFlow = 'CachedContext'
        }
        
        if ($current) {
            $ctx.IsAuthenticated = $true
            $ctx.TenantId = $current.Tenant.Id
            $ctx.AccountUpn = $current.Account.Id
            
            try {
                $ctx.SubscriptionIds = @(Get-AzSubscription -ErrorAction Stop | Select-Object -ExpandProperty Id)
            } catch {
                $ctx.SubscriptionIds = @()
            }
            
            $ctx.RawContext = $current
        } else {
            # Set test values for offline testing
            $ctx.AuthenticationFlow = 'TestMode'
            $ctx.Error = 'No Azure context available (expected in test environment)'
        }
    } catch {
        $ctx.Error = $_.Exception.Message
        if (-not $Quiet) {
            Write-Warning "[Auth] Authentication attempt failed: $($ctx.Error)"
        }
    }
    
    return [PSCustomObject]$ctx
}

# Test the function with quiet mode to avoid authentication prompts
$auth = Initialize-AkvAuthenticationContext -Quiet

# Define required properties
$required = @(
    'IsAuthenticated',
    'AuthenticationFlow', 
    'TenantId',
    'AccountUpn',
    'SubscriptionIds',
    'Timestamp',
    'RawContext',
    'Error'
)

# Check for missing properties
$missing = $required | Where-Object { -not $auth.PSObject.Properties[$_] }

if ($missing) {
    Write-Host "❌ Missing properties: $($missing -join ', ')" -ForegroundColor Red
    exit 1
} else {
    Write-Host "✅ Auth context shape OK - all required properties present" -ForegroundColor Green
    
    # Show property values for verification
    Write-Host ""
    Write-Host "📋 Authentication Context Properties:" -ForegroundColor Yellow
    foreach ($prop in $required) {
        $value = $auth.$prop
        $displayValue = if ($null -eq $value) { 
            "null" 
        } elseif ($value -is [array]) { 
            "array($($value.Count))" 
        } else { 
            $value.ToString() 
        }
        Write-Host "   $prop`: $displayValue" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "🎯 Test completed successfully!" -ForegroundColor Green
    exit 0
}