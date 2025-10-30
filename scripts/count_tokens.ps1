$s = Get-Content -Raw -LiteralPath 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$open = ([regex]::Matches($s,'<#')).Count
$close = ([regex]::Matches($s,'#>')).Count
Write-Host "Open <# count: $open, Close #> count: $close"