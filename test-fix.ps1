# Test script to verify the Write-UserMessage function fix

# Source the function from the main script
$scriptContent = Get-Content "c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1" -Raw

# Extract just the Write-UserMessage function
$functionStart = $scriptContent.IndexOf("function Write-UserMessage {")
$functionEnd = $scriptContent.IndexOf("}", $functionStart) + 1
$functionCode = $scriptContent.Substring($functionStart, $functionEnd - $functionStart)

# Execute the function definition
Invoke-Expression $functionCode

# Test all message types including the previously problematic ones
Write-Host "Testing Write-UserMessage function with all message types:" -ForegroundColor Yellow
Write-Host ""

try {
    Write-UserMessage -Message "This is an Info message" -Type "Info"
    Write-UserMessage -Message "This is a Warning message" -Type "Warning" 
    Write-UserMessage -Message "This is an Error message" -Type "Error"
    Write-UserMessage -Message "This is a Success message" -Type "Success"
    Write-UserMessage -Message "This is a Debug message" -Type "Debug"
    Write-UserMessage -Message "This is a Progress message" -Type "Progress"
    
    Write-Host ""
    Write-Host "✅ SUCCESS: All message types work correctly!" -ForegroundColor Green
    Write-Host "✅ FIXED: ValidateSet now includes 'Debug' and 'Progress'" -ForegroundColor Green
    
} catch {
    Write-Host "❌ ERROR: $($_.Exception.Message)" -ForegroundColor Red
}