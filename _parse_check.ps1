[ref]$nullRef = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Get-AKVGapAnalysis.ps1).ProviderPath, [ref]$nullRef, [ref]$nullRef)
if ($ast) { Write-Host 'AST parse OK' } else { Write-Host 'AST parse failed' }