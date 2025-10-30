$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$start = 996; $end = 1330
$lines = Get-Content $path
$segment = $lines[$start-1..$end-1]
$index = $start
$openHere = @()
$closeHere = @()
foreach ($ln in $segment) {
    if ($ln -match '^[ \t]*@"\s*$' -or $ln -match '^[ \t]*@''\s*$') { $openHere += $index }
    if ($ln -match '^[ \t]*"@\s*$' -or $ln -match '^[ \t]*''@\s*$') { $closeHere += $index }
    $index++
}
Write-Output "Here-string opens: $($openHere.Count) at lines: $($openHere -join ', ')"
Write-Output "Here-string closes: $($closeHere.Count) at lines: $($closeHere -join ', ')"

# Print lines that look like potential terminators but not exact matches
for ($i=0; $i -lt $segment.Count; $i++) {
    $ln = $segment[$i]
    if ($ln -match '"@' -or $ln -match "'@" -or $ln -match '@"' -or $ln -match "@'") {
        $lineno = $start + $i
        Write-Output ($lineno.ToString() + ': ' + $ln)
    }
}

# Simple brace counts ignoring here-strings
$open = 0; $close = 0
foreach ($ln in $segment) {
    $open += ([regex]::Matches($ln,'\{')).Count
    $close += ([regex]::Matches($ln,'\}')).Count
}
Write-Output "Braces in region: open=$open close=$close"
