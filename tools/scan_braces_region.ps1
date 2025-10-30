param(
    [int]$StartLine = 996,
    [int]$EndLine = 1330
)
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path
$inHere = $false
$hereType = ''
$opens = @()
$closes = @()
for ($i = $StartLine; $i -le $EndLine; $i++) {
    $ln = $lines[$i-1]
    $trim = $ln.TrimEnd()
    if (-not $inHere -and ($trim.EndsWith('@"') -or $trim.EndsWith("@'"))) {
        $inHere = $true; $hereType = if ($trim.EndsWith('@"')) { 'double' } else { 'single' }; continue
    }
    if ($inHere) {
        if ($ln.Trim() -eq '"@' -or $ln.Trim() -eq "'@") { $inHere = $false; $hereType = ''; continue }
        else { continue }
    }
    # not in here-string
    for ($c = 0; $c -lt $ln.Length; $c++) {
        $ch = $ln[$c]
        if ($ch -eq '{') { $opens += @{line=$i;col=($c+1)} }
        if ($ch -eq '}') { $closes += @{line=$i;col=($c+1)} }
    }
}
Write-Output "Opens: $($opens.Count)"
Write-Output "Closes: $($closes.Count)"
# Pair them
$min = [math]::Min($opens.Count, $closes.Count)
for ($j=0;$j -lt $min; $j++) {
    # matched
}
if ($opens.Count -gt $closes.Count) {
    Write-Output "Unmatched opens: $($opens.Count - $closes.Count)"
    $opens[$closes.Count..($opens.Count-1)] | ForEach-Object { Write-Output "Open at $($_.line):$($_.col)" }
} elseif ($closes.Count -gt $opens.Count) {
    Write-Output "Unmatched closes: $($closes.Count - $opens.Count)"
    $closes[$opens.Count..($closes.Count-1)] | ForEach-Object { Write-Output "Close at $($_.line):$($_.col)" }
} else { Write-Output 'Balanced in region' }
