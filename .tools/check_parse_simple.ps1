$errors = $null
$tokens = $null
$scriptPath = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$errors, [ref]$tokens)
    if ($ast) {
        Write-Host 'PowerShell syntax valid'
    } else {
        Write-Host 'Syntax errors found'
        if ($errors) { $errors | ForEach-Object { Write-Host $_.Message } }
    }
} catch {
    Write-Host 'Parse threw exception:' $_.Exception.Message
}
