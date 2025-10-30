$errors = $null
$tokens = $null
try {
    [System.Management.Automation.Language.Parser]::ParseFile('c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1', [ref]$errors, [ref]$tokens)
    if ($errors -and $errors.Count -gt 0) {
        Write-Host "Found $($errors.Count) parser error(s):" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host $_.ToString() -ForegroundColor Yellow }
        exit 1
    } else {
        Write-Host "PowerShell syntax valid" -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "Exception during parse: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}