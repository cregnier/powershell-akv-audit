$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$start = 990
$end = 1160
$lines = Get-Content -LiteralPath $path
for ($i=$start-1; $i -lt $end; $i++) {
    if ($i -lt 0 -or $i -ge $lines.Length) { continue }
    $ln = $lines[$i]
    if ($ln -match '@"' -or $ln -match '"@') {
        Write-Output ("{0,5}: {1}" -f ($i+1), $ln)
    }
}
