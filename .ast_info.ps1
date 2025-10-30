$path = "c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1"
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
if ($ast) {
    $functions = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)
    Write-Host "Functions found: $($functions.Count)"
    foreach ($f in $functions) { Write-Host "- " $f.Name }
} else {
    Write-Host "Parse returned null AST"
}
