$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$openToken = '@' + '"'
$closeToken = '"' + '@'
$pattern = [regex]::Escape($openToken) + '|' + [regex]::Escape($closeToken)
for ($i=0; $i -lt $lines.Length; $i++) {
    $line = $lines[$i]
    $matches = [regex]::Matches($line, $pattern)
    foreach ($m in $matches) {
        $token = $m.Value
        $type = if ($token -eq $openToken) { 'OPEN' } else { 'CLOSE' }
        Write-Output ("{0,5}: {1} {2}" -f ($i+1), $type, $line.Trim())
    }
}
