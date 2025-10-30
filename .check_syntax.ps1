$scriptPath = Join-Path -Path (Get-Location) -ChildPath 'Get-AKVGapAnalysis.ps1'
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    if ($ast) { Write-Host 'Syntax valid' } else { Write-Host 'Syntax errors' }
} catch {
    Write-Host 'Syntax check failed:' $_.Exception.Message
    exit 1
}