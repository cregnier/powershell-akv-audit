param([string]$Path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$lines = Get-Content -LiteralPath $Path
$balance = 0
$report = @()
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $open = ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $close = ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    $balance += $open - $close
    $report += ([pscustomobject]@{Line = $i+1; Open = $open; Close = $close; Balance = $balance; Text = $line})
}
# Print lines where balance changes or is minimal
$report | Where-Object { $_.Open -gt 0 -or $_.Close -gt 0 -or $_.Balance -le 0 } | Select-Object -First 200 | ForEach-Object {
    Write-Output ("{0,5}: O={1} C={2} BAL={3}  {4}" -f $_.Line, $_.Open, $_.Close, $_.Balance, $_.Text)
}
Write-Output "Final balance: $balance"
