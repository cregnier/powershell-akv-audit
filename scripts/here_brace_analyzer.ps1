$target = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $target
$inHere = $false
$hereStart = $null
$balance = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if (-not $inHere) {
        if ($line -match '@"\s*$') {
            $inHere = $true
            $hereStart = $i+1
            continue
        }
    } else {
        if ($line -match '^\s*"@\s*$') {
            $inHere = $false
            $hereStart = $null
            continue
        } else {
            continue
        }
    }

    # Count braces outside here-strings
    $opens = ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $closes = ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    $balance += $opens - $closes
    if ($balance -lt 0) {
        Write-Host "Imbalance at line $($i+1): balance=$balance"
        Write-Host $line
        break
    }
}
Write-Host "Final balance: $balance"