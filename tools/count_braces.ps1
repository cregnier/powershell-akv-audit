$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$balance = 0
for ($idx = 0; $idx -lt $lines.Count; $idx++) {
    $line = $lines[$idx]
    $opens = ($line -split '{').Count - 1
    $closes = ($line -split '}').Count - 1
    $balance += $opens - $closes
}
Write-Output "Total brace balance: $balance"
