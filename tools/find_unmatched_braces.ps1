$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$stack = @()
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    for ($j=0; $j -lt $line.Length; $j++) {
        $ch = $line[$j]
        if ($ch -eq '{') { $stack += @{line=$i+1;col=$j+1} }
        elseif ($ch -eq '}') {
            if ($stack.Count -eq 0) { Write-Host "Unmatched closing brace at $($i+1):$($j+1)" }
            else { $stack = $stack[0..($stack.Count-2)] }
        }
    }
}
if ($stack.Count -gt 0) {
    Write-Host "Unmatched opening braces:"
    foreach ($s in $stack) { Write-Host "Open at $($s.line):$($s.col)" }
} else { Write-Host "All braces matched" }
