$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    if ($ast) { Write-Host 'SYNTAX_OK' } else { Write-Host 'SYNTAX_ERROR' }
} catch {
    Write-Host 'PARSER_EXCEPTION'
    Write-Host $_.Exception.Message
    exit 2
}