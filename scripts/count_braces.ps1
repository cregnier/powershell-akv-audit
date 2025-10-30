$s = Get-Content -Raw -LiteralPath 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$openC = ([regex]::Matches($s,'\{')).Count
$closeC = ([regex]::Matches($s,'\}')).Count
$openParen = ([regex]::Matches($s,'\(')).Count
$closeParen = ([regex]::Matches($s,'\)')).Count
Write-Host "{ count: $openC, } count: $closeC, ( count: $openParen, ) count: $closeParen"