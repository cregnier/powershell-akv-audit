$ast = [System.Management.Automation.Language.Parser]::ParseFile('..\Get-AKVGapAnalysis.ps1',[ref]$null,[ref]$null)
$tries = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }, $true)
$missing = @()
foreach ($t in $tries) {
    $c = $t.CatchClauses.Count
    $f = ($t.FinallyClause -ne $null)
    if ($c -eq 0 -and -not $f) { $missing += $t }
}
if ($missing.Count -eq 0) { Write-Host 'No Trys missing catch/finally according to AST' } else { Write-Host "$($missing.Count) Try(s) missing catch/finally:"; foreach ($t in $missing) { Write-Host "Try at $($t.Extent.StartLine):$($t.Extent.StartColumn) to $($t.Extent.EndLine):$($t.Extent.EndColumn)" } }