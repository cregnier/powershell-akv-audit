$path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines=Get-Content -LiteralPath $path
$balance=0
$balances = @()
for ($i=0;$i -lt $lines.Count;$i++){
    $open = ($lines[$i].ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $close = ($lines[$i].ToCharArray() | Where-Object { $_ -eq '}' }).Count
    $balance += $open - $close
    $balances += [pscustomobject]@{Line=$i+1; Open=$open; Close=$close; Balance=$balance; Text=$lines[$i]}
}
$max = ($balances | Measure-Object -Property Balance -Maximum).Maximum
Write-Output ("Max balance = $max")
# show last lines where balance == max
$lastMax = ($balances | Where-Object { $_.Balance -eq $max } | Select-Object -Last 1)
Write-Output ("Last line with max balance: {0}" -f $lastMax.Line)
$start = [math]::Max(1, $lastMax.Line - 8)
$end = [math]::Min($lines.Count, $lastMax.Line + 8)
for ($i=$start;$i -le $end;$i++) {
    $b = $balances[$i-1]
    Write-Output ("{0,5}: BAL={1,3} O={2} C={3} | {4}" -f $i, $b.Balance, $b.Open, $b.Close, $b.Text)
}
