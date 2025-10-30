$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$stack = @()
for ($i=0;$i -lt $lines.Count; $i++) {
    $ln = $i+1
    $trim = $lines[$i].Trim()
    if ($trim -eq '@"' -or $trim -eq "@'") {
        $stack += @{ type = $trim; line = $ln }
    } elseif ($trim -eq '"@' -or $trim -eq "'@") {
        if ($stack.Count -eq 0) {
            Write-Host "Found closing here-string marker at $ln but stack empty: $trim"
        } else {
            $top = $stack[-1]
            # check matching type
            if (($top.type -eq '@"' -and $trim -eq '"@') -or ($top.type -eq "@'" -and $trim -eq "'@")) {
                # matched
                $stack = $stack[0..($stack.Count-2)]
            } else {
                Write-Host ('Mismatched here-string close at {0}: close {1} doesn''t match open {2} at line {3}' -f $ln, $trim, $($top.type), $($top.line))
                $stack = $stack[0..($stack.Count-2)]
            }
        }
    }
}
if ($stack.Count -gt 0) {
    Write-Host "Unclosed here-strings found:"
    foreach ($s in $stack) { Write-Host "Open $($s.type) at line $($s.line)" }
} else {
    Write-Host "All here-strings matched"
}
