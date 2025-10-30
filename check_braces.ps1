$content = Get-Content 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1' -Raw
$lines = $content -split '\r?\n'
$braceCount = 0
$hereStringOpen = $false
$hereStringStart = $null

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $lineNum = $i + 1

    # Check for here-string starts/ends
    if ($line -match '@"') {
        if (-not $hereStringOpen) {
            $hereStringOpen = $true
            $hereStringStart = $lineNum
        } elseif ($line -match '"@') {
            $hereStringOpen = $false
            $hereStringStart = $null
        }
    }

    # Only count braces outside here-strings
    if (-not $hereStringOpen) {
        $openBraces = ($line | Select-String -Pattern '\{' -AllMatches).Matches.Count
        $closeBraces = ($line | Select-String -Pattern '\}' -AllMatches).Matches.Count
        $braceCount += $openBraces - $closeBraces

        if ($braceCount -lt 0) {
            Write-Host "Brace mismatch at line $lineNum (negative count: $braceCount)"
            break
        }
    }
}

Write-Host "Final brace count: $braceCount"
if ($hereStringOpen) {
    Write-Host "Unclosed here-string starting at line $hereStringStart"
}