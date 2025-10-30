$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match '@"' -or $line -match '"@') {
        $ln = $i + 1
        Write-Host ('Line {0}: {1}' -f $ln, $line)
    }
}
