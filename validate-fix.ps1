# Simple test to verify the ValidateSet fix
# Import the main script and test specific functions

# Test by calling the Write-UserMessage with Debug and Progress types
# This will fail if ValidateSet is still restrictive

# Source the script (dot-source the function definitions)
. "c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1" -ErrorAction SilentlyContinue 2>$null

Write-Host "Testing ValidateSet fix..." -ForegroundColor Yellow

try {
    Write-UserMessage -Message "Testing Debug message type" -Type "Debug"
    Write-Host "✅ Debug message type works!" -ForegroundColor Green
    
    Write-UserMessage -Message "Testing Progress message type" -Type "Progress"  
    Write-Host "✅ Progress message type works!" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "🎉 SUCCESS: ValidateSet fix is working correctly!" -ForegroundColor Green
    Write-Host "The script should now run without ValidateSet errors." -ForegroundColor Cyan
    
} catch {
    Write-Host "❌ ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The ValidateSet fix may not be complete." -ForegroundColor Yellow
}