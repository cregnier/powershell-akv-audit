$target = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $target
$balance = 0
$inHere = $false
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if (-not $inHere -and $line -match '@"\s*$') { $inHere = $true }
    elseif ($inHere -and $line -match '^\s*"@\s*$') { $inHere = $false; continue }

    $opens = ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $closes = ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    $balance += $opens - $closes

    if ($i -gt 3100 -and $i -lt 3190) {
        $num = $i+1
        $escaped = $line -replace "`r|`n",""
        Write-Output ("{0,5} {1,3} +{2} -{3} | {4}" -f $num, $balance, $opens, $closes, $escaped)
    }
}
Write-Output "Final balance: $balance"