$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$stack = @()
for ($i=0; $i -lt $lines.Length; $i++) {
    $line = $lines[$i]
    $dq = '"'
    $openToken = '@' + $dq
    $closeToken = $dq + '@'
    $pattern = [regex]::Escape($openToken) + '|' + [regex]::Escape($closeToken)
    $matches = [regex]::Matches($line, $pattern)
    foreach ($m in $matches) {
        if ($m.Value -eq $openToken) {
            $stack += @{line = $i+1; col = $m.Index+1}
        } elseif ($m.Value -eq $closeToken) {
            if ($stack.Count -gt 0) {
                $stack = $stack[0..($stack.Count-2)]
            } else {
                Write-Output ("Found unmatched closing {0} at line {1}, col {2}" -f $closeToken, ($i+1), ($m.Index+1))
            }
        }
    }
}
if ($stack.Count -eq 0) {
    Write-Output ("All {0} and {1} markers balanced" -f $openToken, $closeToken)
} else {
    Write-Output ("Unmatched {0} markers: {1}" -f $openToken, $stack.Count)
    foreach ($item in $stack) {
        $ln = $item.line
        Write-Output ("- Open at line {0}, col {1}" -f $ln, $($item.col))
        $start = [math]::Max(1, $ln-3)
        $end = [math]::Min($lines.Length, $ln+3)
        Write-Output ("Context lines {0}..{1}:" -f $start, $end)
        for ($j=$start; $j -le $end; $j++) { $prefix = '{0,5}:' -f $j; Write-Output ("$prefix $($lines[$j-1])") }
    }
}