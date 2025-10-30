$content = Get-Content 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1' -Raw
$lines = $content -split '\r?\n'

$hereStringStack = @()

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $lineNum = $i + 1

    # Check for here-string start: @"
    if ($line -match '=\s*@"') {
        $hereStringStack += @{ Start = $lineNum; Type = 'start' }
        Write-Host "Here-string START at line $lineNum"
    }

    # Check for here-string end: "@
    if ($line -match '"@') {
        if ($hereStringStack.Length -gt 0) {
            $start = $hereStringStack[-1].Start
            Write-Host "Here-string END at line $lineNum (started at $start)"
            $hereStringStack = $hereStringStack[0..($hereStringStack.Length - 2)]
        } else {
            Write-Host "Here-string END without START at line $lineNum"
        }
    }
}

if ($hereStringStack.Length -gt 0) {
    Write-Host "Unclosed here-strings:"
    foreach ($hs in $hereStringStack) {
        Write-Host "  Started at line $($hs.Start)"
    }
} else {
    Write-Host "All here-strings are balanced"
}