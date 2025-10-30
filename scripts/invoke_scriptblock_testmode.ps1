# Helper to execute Get-AKVGapAnalysis.ps1 by loading into a ScriptBlock and invoking with args
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
Write-Host "Loading script from: $path"
$content = Get-Content -Raw -LiteralPath $path
$sb = [ScriptBlock]::Create($content)
Write-Host "Invoking scriptblock with: -TestMode -Limit 3 -SuppressAzureWarnings -SuppressModuleWarnings"
& $sb -TestMode -Limit 3 -SuppressAzureWarnings -SuppressModuleWarnings
Write-Host "Invocation completed."