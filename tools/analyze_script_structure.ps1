param(
    [string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
)

Write-Output "Analyzing file: $Path"
$lines = Get-Content -Path $Path -ErrorAction Stop

$inHere = $false
$hereType = '' # '@' or '@"
$lineNumber = 0
$open = 0
$close = 0
$firstNegativeBalanceLine = $null

for ($i = 0; $i -lt $lines.Count; $i++) {
    $lineNumber = $i + 1
    $line = $lines[$i]
    $trim = $line.Trim()

    if (-not $inHere) {
        # Detect here-string openers (@" or @') that start the line after optional whitespace
        if ($trim -like '@"*' -and $trim -eq '@"') { $inHere = $true; $hereType = 'double'; continue }
        if ($trim -like "@'*" -and $trim -eq "@'") { $inHere = $true; $hereType = 'single'; continue }
        # Also handle lines that start exactly with @" or @'
        if ($trim -eq '@"') { $inHere = $true; $hereType = 'double'; continue }
        if ($trim -eq "@'") { $inHere = $true; $hereType = 'single'; continue }
        # Count braces in this line (simple character count)
        $open += ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
        $close += ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
        if (($open - $close) -lt 0 -and -not $firstNegativeBalanceLine) { $firstNegativeBalanceLine = $lineNumber }
    } else {
        # We are inside a here-string; detect terminator
        if ($hereType -eq 'double' -and $trim -eq '"@') { $inHere = $false; $hereType = ''; continue }
        if ($hereType -eq 'single' -and $trim -eq "'@") { $inHere = $false; $hereType = ''; continue }
        # Otherwise, skip content
        continue
    }
}

Write-Output "Finished scanning. Here-string open state: $inHere (if true, an unclosed here-string remains)"
Write-Output "Total brace counts: open=$open close=$close diff=$([int]($open-$close))"
if ($firstNegativeBalanceLine) { Write-Output "Balance went negative at line: $firstNegativeBalanceLine" }

if ($inHere) {
    Write-Output "Unclosed here-string detected. Showing lines with here-string tokens around file:" 
    for ($i=0; $i -lt $lines.Count; $i++) {
        $trim = $lines[$i].Trim()
        if ($trim -eq '@"' -or $trim -eq '"@' -or $trim -eq "@'" -or $trim -eq "'@") {
            $start = [Math]::Max(0,$i-3)
            $end = [Math]::Min($lines.Count-1,$i+3)
            Write-Output "--- context around line $($i+1) ---"
            for ($j=$start; $j -le $end; $j++) { Write-Output ("{0,6}: {1}" -f ($j+1), $lines[$j]) }
        }
    }
}

if ($firstNegativeBalanceLine) {
    $start = [Math]::Max(0,$firstNegativeBalanceLine-5)
    $end = [Math]::Min($lines.Count-1,$firstNegativeBalanceLine+5)
    Write-Output "--- Context around first negative balance (lines $start-$end) ---"
    for ($j=$start; $j -le $end; $j++) { Write-Output ("{0,6}: {1}" -f ($j+1), $lines[$j]) }
}

Write-Output "Analysis complete."
