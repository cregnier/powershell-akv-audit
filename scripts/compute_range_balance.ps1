$target = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $target
$start = 1622
$end = 3171
$balance=0
$inHere=$false
for ($i=$start-1;$i -lt $end;$i++) {
    $line = $lines[$i]
    if (-not $inHere -and $line -match '@"\s*$') { $inHere = $true }
    elseif ($inHere -and $line -match '^\s*"@\s*$') { $inHere = $false; continue }
    $opens = ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $closes = ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    $balance += $opens - $closes
}
Write-Output "Balance from $start to $end (ignoring here-strings): $balance"