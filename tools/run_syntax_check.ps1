$script = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$null)
if ($ast) { Write-Host "Syntax valid" } else { Write-Host "Syntax errors found" }