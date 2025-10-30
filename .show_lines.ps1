$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$start = 1610
$end = 1640
$lines = Get-Content $path
for ($i=$start; $i -le $end; $i++) { Write-Host ("{0,4}: {1}" -f $i, $lines[$i-1]) }
