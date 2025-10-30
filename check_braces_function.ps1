$content = Get-Content './Get-AKVGapAnalysis.ps1'
$lines = $content[995..1294]
$openBraces = 0
$closeBraces = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $openCount = ($line -split '{').Count - 1
    $closeCount = ($line -split '}').Count - 1
    $openBraces += $openCount
    $closeBraces += $closeCount
    if ($openCount -gt 0 -or $closeCount -gt 0) {
        Write-Host "Line $($i + 996): opens=$openCount, closes=$closeCount, total opens=$openBraces, total closes=$closeBraces"
    }
}
Write-Host "Final: opens=$openBraces, closes=$closeBraces"