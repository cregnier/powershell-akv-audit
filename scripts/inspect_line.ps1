param([int]$line=228)
$lines = Get-Content -LiteralPath 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
if ($line -le $lines.Count) {
    $text = $lines[$line-1]
    Write-Host ("Line {0}: [{1}]" -f $line, $text)
    $chars = $text.ToCharArray()
    $i = 0
    foreach ($c in $chars) { $i++; Write-Host (("{0,3}: '{1}' (U+{2:X4})") -f $i, $c, [int][char]$c) }
} else { Write-Host ("Line {0} out of range (max {1})" -f $line, $lines.Count) }