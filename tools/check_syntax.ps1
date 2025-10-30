$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    if ($ast) { Write-Host "Syntax valid" } else { Write-Host "Syntax errors found" }
} catch {
    Write-Host "Parser exception:`n$($_.Exception.ToString())"
    exit 1
}