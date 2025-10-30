$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$t = Get-Content -Raw -LiteralPath $path
$open = ([regex]::Matches($t, '@"')).Count
$close = ([regex]::Matches($t, '"@')).Count
Write-Host ("@`" count: {0}" -f $open)
Write-Host ('"@ count: {0}' -f $close)
# Also count here-strings with @' and '@
$openS = ([regex]::Matches($t, "@'")).Count
$closeS = ([regex]::Matches($t, "'@")).Count
Write-Host ("@' count: {0}" -f $openS)
Write-Host ("'@ count: {0}" -f $closeS)
