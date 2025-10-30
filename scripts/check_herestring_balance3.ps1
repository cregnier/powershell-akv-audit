$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$inDouble = $false
$inSingle = $false
$lineNum = 0
$openDoubleStarts = @()
foreach ($line in Get-Content -LiteralPath $path) {
    $lineNum++
    if (-not $inDouble -and -not $inSingle) {
        if ($line -match '@"\s*$') {
            $inDouble = $true
            $openDoubleStarts += $lineNum
            Write-Host "Found double here-string start at line $lineNum"
        } elseif ($line -match "@'\s*$") {
            $inSingle = $true
            Write-Host "Found single here-string start at line $lineNum"
        }
    } elseif ($inDouble) {
        if ($line -match '"@\s*$') {
            $inDouble = $false
            Write-Host "Closed double here-string at line $lineNum"
        }
    } elseif ($inSingle) {
        if ($line -match "'@\s*$") {
            $inSingle = $false
            Write-Host "Closed single here-string at line $lineNum"
        }
    }
}
if ($inDouble) { Write-Host "Unclosed double-quote here-string started at line $($openDoubleStarts[-1])" } else { Write-Host "No unclosed double-quote here-strings" }
if ($inSingle) { Write-Host "Unclosed single-quote here-string detected" } else { Write-Host "No unclosed single-quote here-strings" }
Write-Host "All starts: $($openDoubleStarts -join ', ')"
