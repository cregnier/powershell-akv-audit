$file = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $file
$balance = 0
$inHere = $false
for ($i = 900; $i -le 1100 -and $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    $trim = $ln.Trim()
    if (-not $inHere -and ($trim -eq '@"' -or $trim -eq "@'" -or $ln.TrimEnd().EndsWith('@"') -or $ln.TrimEnd().EndsWith("@'"))) { $inHere = $true }
    elseif ($inHere -and ($trim -eq '"@' -or $trim -eq "'@")) { $inHere = $false }
    if (-not $inHere) {
        $opens = ($ln.ToCharArray() | Where-Object { $_ -eq '{' }).Count
        $closes = ($ln.ToCharArray() | Where-Object { $_ -eq '}' }).Count
        $balance += $opens - $closes
    } else { $opens = 0; $closes = 0 }
    Write-Output ("{0,5}: bal={1,3} opens={2,2} closes={3,2} | {4}" -f ($i+1), $balance, $opens, $closes, $ln)
}
Write-Output "Final balance: $balance"