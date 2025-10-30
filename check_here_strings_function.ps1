$content = Get-Content './Get-AKVGapAnalysis.ps1'
$lines = $content[995..1294]
$inHereString = $false
$hereStringStart = ''
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match '@"') {
        if (-not $inHereString) {
            $inHereString = $true
            $hereStringStart = "Line $($i + 996): $line"
            Write-Host "Starting here-string: $hereStringStart"
        } elseif ($line -match '"@') {
            $inHereString = $false
            Write-Host "Ending here-string: Line $($i + 996): $line"
        }
    }
}
if ($inHereString) {
    Write-Host "Unclosed here-string starting at: $hereStringStart"
}