$path='c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$lines = Get-Content -LiteralPath $path
$start = ($lines | Select-Object -Index 0..($lines.Length-1) | ForEach-Object {$_}) | ForEach-Object -Begin { $i=0 } -Process { $i++; if ($_ -match '^\s*param\s*\(') { [PSCustomObject]@{Line=$i; Text=$_} } } | Where-Object { $_ } | Select-Object -First 1
Write-Host "Param start line: $($start.Line)"
$balance = 0
for ($i=$start.Line-1; $i -lt $lines.Length; $i++) {
    $line = $lines[$i]
    foreach ($ch in $line.ToCharArray()) {
        if ($ch -eq '(') { $balance++ }
        if ($ch -eq ')') { $balance-- }
    }
    if ($balance -eq 0 -and $i -gt ($start.Line-1)) { Write-Host "Param block ends at line $($i+1)"; break }
}
Write-Host "Final balance: $balance"