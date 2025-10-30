$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$text = Get-Content -Raw -LiteralPath $path
$openDQ = ([regex]::Matches($text,'@"')).Count
$closeDQ = ([regex]::Matches($text,'"@')).Count
$openSQ = ([regex]::Matches($text,"@'")).Count
$closeSQ = ([regex]::Matches($text,"'@")).Count
Write-Host "Double-quoted here-strings: opens=@$openDQ closes=@$closeDQ"
Write-Host "Single-quoted here-strings: opens=@$openSQ closes=@$closeSQ"

# Print any lines that have opening markers
$lines = Get-Content -LiteralPath $path
for ($i=0;$i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match '@"' -or $line -match "@'" ) { Write-Host "OPEN at line $($i+1): $line" }
    if ($line -match '"@' -or $line -match "'@") { Write-Host "CLOSE at line $($i+1): $line" }
}
