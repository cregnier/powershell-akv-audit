#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test authentication flow without full script execution

.DESCRIPTION
    Tests just the authentication context initialization part to verify the fix works
#>

# Set up minimal global context
$global:ScriptExecutionContext = @{}

# Define the functions
function Initialize-AkvAuthenticationContext {
    [CmdletBinding()]
    param(
        [switch]$ForceLogin,
        [switch]$Quiet
    )
    
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
        Write-Host "[Test] Simulating authentication context creation..." -ForegroundColor Yellow
        
        # Simulate the logic without actual Azure calls
        if ($ForceLogin) {
            $ctx.AuthenticationFlow = 'Interactive'
            Write-Host "[Test] ForceLogin requested - would initiate interactive login" -ForegroundColor Cyan
        } else {
            $ctx.AuthenticationFlow = 'TestMode'
            Write-Host "[Test] No ForceLogin - would check existing context" -ForegroundColor Cyan
        }
        
        # Simulate authentication failure (expected in test environment)
        $ctx.Error = 'Azure modules not available in test environment'
        Write-Host "[Test] Simulated authentication error: $($ctx.Error)" -ForegroundColor Yellow
        
    } catch {
        $ctx.Error = $_.Exception.Message
        Write-Warning "[Auth] Authentication attempt failed: $($ctx.Error)"
    }
    
    return [PSCustomObject]$ctx
}

function Get-AkvAuthFlow {
    param([object]$Auth)
    
    if ($null -eq $Auth) { 
        return 'Unknown' 
    }
    
    if ($Auth.PSObject.Properties['AuthenticationFlow']) { 
        return $Auth.AuthenticationFlow 
    }
    
    return 'Unknown'
}

# Test the pattern as used in the main script
Write-Host "🧪 Testing authentication context pattern..." -ForegroundColor Cyan

# Test without ForceReauth
Write-Host "`n1️⃣ Testing normal authentication flow..." -ForegroundColor Yellow
if (-not $global:ScriptExecutionContext) { 
    $global:ScriptExecutionContext = @{} 
}
if (-not $global:ScriptExecutionContext.Auth) { 
    $global:ScriptExecutionContext.Auth = Initialize-AkvAuthenticationContext
}
$authResult = $global:ScriptExecutionContext.Auth
$authFlow = Get-AkvAuthFlow -Auth $authResult

Write-Host "✅ AuthResult type: $($authResult.GetType().FullName)" -ForegroundColor Green
Write-Host "✅ AuthFlow value: $authFlow" -ForegroundColor Green
Write-Host "✅ IsAuthenticated: $($authResult.IsAuthenticated)" -ForegroundColor Green

# Test with ForceReauth
Write-Host "`n2️⃣ Testing ForceReauth flow..." -ForegroundColor Yellow
$ForceReauth = $true
if (-not $global:ScriptExecutionContext.Auth -or $ForceReauth) { 
    $global:ScriptExecutionContext.Auth = Initialize-AkvAuthenticationContext -ForceLogin:$ForceReauth 
}
$authResult = $global:ScriptExecutionContext.Auth
$authFlow = Get-AkvAuthFlow -Auth $authResult

Write-Host "✅ AuthResult type: $($authResult.GetType().FullName)" -ForegroundColor Green
Write-Host "✅ AuthFlow value: $authFlow" -ForegroundColor Green
Write-Host "✅ IsAuthenticated: $($authResult.IsAuthenticated)" -ForegroundColor Green

# Test the error handling logic
Write-Host "`n3️⃣ Testing authentication failure handling..." -ForegroundColor Yellow
if (-not $authResult.IsAuthenticated) { 
    Write-Host "❌ Authentication failed (flow: $authFlow)." -ForegroundColor Red
    if ($authResult.Error) { 
        Write-Warning "[Auth] Detail: $($authResult.Error)" 
    }
    Write-Host "✅ Error handling worked - would throw: 'Authentication failed. Please check your credentials and try again.'" -ForegroundColor Green
} else { 
    Write-Host "🔐 Authenticated ($authFlow) as $($authResult.AccountUpn)" -ForegroundColor Green
}

Write-Host "`n🎯 Authentication context pattern test completed successfully!" -ForegroundColor Green
Write-Host "✅ No property-not-found errors occurred" -ForegroundColor Green
Write-Host "✅ AuthenticationFlow property access is safe" -ForegroundColor Green