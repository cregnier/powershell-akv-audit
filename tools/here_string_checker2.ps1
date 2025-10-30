$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path -Encoding UTF8
$stack = @()
for ($i=0; $i -lt $lines.Count; $i++) {
    $trim = $lines[$i].Trim()
    if ($trim -eq '@"' -or $trim -eq "@'") {
        $stack += @{type=$trim; line=($i+1)}
        continue
    }
    if ($trim -eq '"@' -or $trim -eq "'@") {
        if ($stack.Count -gt 0) { $stack = $stack[0..($stack.Count-2)] } else { Write-Output "Found here-string close at $($i+1) with no open" }
    }
}
if ($stack.Count -eq 0) { Write-Output 'All here-strings appear balanced (by simple check).' } else { Write-Output "Unclosed here-strings: $($stack.Count)"; $stack | ForEach-Object { Write-Output "Open at $($_.line): token $($_.type)" } }
