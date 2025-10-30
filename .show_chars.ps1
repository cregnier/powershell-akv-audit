$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path
for ($i=1596; $i -le 1606; $i++) {
    $line = $lines[$i-1]
    Write-Host ('{0,4}: {1}' -f $i, $line)
    for ($j=0; $j -lt $line.Length; $j++) { $c = $line[$j]; $code = [int][char]$c; Write-Host ("  {0,3}:{1} ({2})" -f $j, $c, $code) }
    Write-Host '-----'
}
