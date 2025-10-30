$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$startLine = 1052
$brace = 0
$inHere = $false
$hereType = ''
for ($i=$startLine-1; $i -lt $lines.Length; $i++) {
    $ln = $lines[$i]
    $trim = $ln.Trim()
    # detect here-string start/end
    if (-not $inHere -and ($trim -eq '@"' -or $trim -eq "@'" -or $ln.TrimEnd().EndsWith('@"') -or $ln.TrimEnd().EndsWith("@'"))) {
        $inHere = $true; $hereType = if ($trim -like '@"*' -or $ln.TrimEnd().EndsWith('@"')) { 'double' } else { 'single' }
        Write-Output ("{0,5}: ENTER_HERE {1} -> {2}" -f ($i+1), $hereType, $ln.Trim())
        continue
    }
    if ($inHere) {
        if ($trim -eq '"@' -or $trim -eq "'@") {
            Write-Output ("{0,5}: EXIT_HERE  {1} -> {2}" -f ($i+1), $hereType, $ln.Trim())
            $inHere = $false; $hereType = ''
        }
        continue
    }
    # count braces outside here-strings
    $openCount = ([regex]::Matches($ln,'\{')).Count
    $closeCount = ([regex]::Matches($ln,'\}')).Count
    if ($openCount -gt 0 -or $closeCount -gt 0) {
        $brace += $openCount - $closeCount
        Write-Output ("{0,5}: BRACE delta {1} (line: {2})" -f ($i+1), ($openCount - $closeCount), $ln.Trim())
        if ($brace -lt 0) { Write-Output "Negative brace count at line $($i+1)"; break }
    }
}
Write-Output "Final brace balance: $brace"