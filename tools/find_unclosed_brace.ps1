$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$stack = @()
for ($idx = 0; $idx -lt $lines.Count; $idx++) {
    $line = $lines[$idx]
    # Count opens and closes; handle multiple braces on same line
    for ($i = 0; $i -lt $line.Length; $i++) {
        $ch = $line[$i]
        if ($ch -eq '{') { $stack += @{line = $idx+1; char = $i+1; text = $line.Trim() } }
        if ($ch -eq '}') { if ($stack.Count -gt 0) { $stack = $stack[0..($stack.Count-2)] } else { Write-Output "Extra closing brace at $($idx+1):$($i+1)" } }
    }
}
if ($stack.Count -eq 0) { Write-Output "All braces balanced" } else {
    Write-Output "Unclosed brace(s): $($stack.Count) - showing last 5 entries"
    $stack[-5..-1] | ForEach-Object { Write-Output ("Line {0}, Col {1}: {2}" -f $_.line,$_.char,$_.text) }
}
