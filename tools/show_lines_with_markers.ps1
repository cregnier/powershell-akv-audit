param($path='C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1',$start=1032,$end=1040)
$lines = Get-Content -LiteralPath $path
for ($i=$start-1; $i -lt $end; $i++) {
    $ln = $lines[$i]
    $num = $i+1
    $marker = ($ln -replace '\t','[TAB]') -replace ' ','[SP]'
    Write-Output ("{0,5}: {1}" -f $num, $marker)
}
