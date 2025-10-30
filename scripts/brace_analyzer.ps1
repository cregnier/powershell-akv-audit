$target = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $target
$balance = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
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