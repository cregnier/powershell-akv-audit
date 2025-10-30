$scriptPath = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'

$errors = $null
$tokens = $null
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$errors, [ref]$tokens)
} catch {
    Write-Host "Parser threw an exception: $($_.Exception.Message)"
    exit 1
}

if ($errors -ne $null -and $errors.Count -gt 0) {
    Write-Host "Syntax errors found: $($errors.Count) error(s)"
    foreach ($e in $errors) {
        Write-Host "- $($e.Message) (Line: $($e.Extent.StartLine))"
    }
    exit 1
} else {
    Write-Host 'Syntax valid'
    exit 0
}
