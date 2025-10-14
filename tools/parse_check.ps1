$scriptPath = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$errors = [ref]$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$errors, [ref]$null)
if ($errors.Value) {
    Write-Host "Syntax errors found in $scriptPath`n"
    foreach ($err in $errors.Value) {
        Write-Host "Line $($err.Extent.StartLineNumber): $($err.Message)"
    }
    exit 1
} else {
    Write-Host "No syntax errors detected."
    exit 0
}