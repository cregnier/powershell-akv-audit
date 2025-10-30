$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$openToken = '@' + '"'
$closeToken = '"' + '@'
$pattern = [regex]::Escape($openToken) + '|' + [regex]::Escape($closeToken)
$stack = @()
for ($i=0; $i -lt $lines.Length; $i++) {
    $line = $lines[$i]
    $matches = [regex]::Matches($line, $pattern)
    foreach ($m in $matches) {
        $token = $m.Value
        if ($token -eq $openToken) {
            $stack += @{line=$i+1; col=$m.Index+1}
            Write-Output ("{0,5}: PUSH {1} (stack={2})" -f ($i+1), $line.Trim(), $stack.Count)
        } else {
            if ($stack.Count -gt 0) {
                $popped = $stack[-1]
                $stack = $stack[0..($stack.Count-2)]
                Write-Output ("{0,5}: POP  {1} popped-open-line={2} (stack={3})" -f ($i+1), $line.Trim(), $popped.line, $stack.Count)
            } else {
                Write-Output ("{0,5}: CLOSE with empty stack at {1}" -f ($i+1), $line.Trim())
            }
        }
    }
}
if ($stack.Count -gt 0) {
    Write-Output "Remaining open here-strings: $($stack.Count)"
    foreach ($s in $stack) { Write-Output ("- Open at line {0}, col {1}" -f $s.line, $s.col) }
} else { Write-Output 'No remaining open here-strings' }
