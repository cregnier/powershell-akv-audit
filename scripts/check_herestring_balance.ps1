$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$inDouble = $false
$inSingle = $false
$lineNum = 0
$openDoubleStarts = @()
$unclosed = @()
foreach ($line in Get-Content -LiteralPath $path) {
    $lineNum++
    if (-not $inDouble -and -not $inSingle) {
        if ($line -match '(^|\s)@"(\s*$|\s+.*)') {
            $inDouble = $true
            $openDoubleStarts += $lineNum
            continue
        }
        if ($line -match "(^|\s)@'(\s*$|\s+.*)") {
            $inSingle = $true
            continue
        }
    } elseif ($inDouble) {
        if ($line -match '"@\s*$') {
            # closed
            $inDouble = $false
            $openDoubleStarts = $openDoubleStarts | Where-Object { $_ -ne $openDoubleStarts[-1] }
            continue
        }
    } elseif ($inSingle) {
        if ($line -match "'@\s*$") {
            $inSingle = $false
            continue
        }
    }
}
if ($inDouble) { Write-Host "Unclosed double-quote here-string started at line $($openDoubleStarts[-1])" } else { Write-Host "No unclosed double-quote here-strings" }
if ($inSingle) { Write-Host "Unclosed single-quote here-string detected" } else { Write-Host "No unclosed single-quote here-strings" }
Write-Host "All double starts: $($openDoubleStarts -join ', ' )" 
