$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path
$stack = @()
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($stack.Count -eq 0) {
        if ($line -match '^\s*@"\s*$') { $stack += '"'; Write-Host ("Line {0}: start @\"" -f ($i+1)) }
        elseif ($line -match '^\s*@'\''\s*$') { $stack += "'"; Write-Host ("Line {0}: start @'" -f ($i+1)) }
    } else {
        $top = $stack[-1]
        if ($top -eq '"' -and $line -match '^\s*"@\s*$') { Write-Host ("Line {0}: end \"@" -f ($i+1)); $stack = $stack[0..($stack.Count-2)] }
        elseif ($top -eq "'" -and $line -match '^\s*'\@\s*$') { Write-Host ("Line {0}: end '@" -f ($i+1)); $stack = $stack[0..($stack.Count-2)] }
    }
}
if ($stack.Count -eq 0) { Write-Host 'Here-strings balanced' } else { Write-Host 'Unbalanced here-strings: ' $stack }
