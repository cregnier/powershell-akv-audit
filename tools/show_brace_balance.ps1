$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$balance = 0
$start = 4289; $end = 4451
for ($idx = 0; $idx -lt $lines.Count; $idx++) {
    $line = $lines[$idx]
    $opens = ($line -split '{').Count - 1
    $closes = ($line -split '}').Count - 1
    $balance += $opens - $closes
    if ($idx + 1 -ge $start -and $idx + 1 -le $end) {
        $num = $idx + 1
        Write-Output ("{0,5}: {1,3} | {2}" -f $num, $balance, $line)
    }
}
Write-Output "Final balance: $balance" 
