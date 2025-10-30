$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$text = Get-Content -LiteralPath $path -Raw
$open = ([regex]::Matches($text,'@"')).Count
$close = ([regex]::Matches($text,'"@')).Count
Write-Output "OPEN:$open CLOSE:$close"