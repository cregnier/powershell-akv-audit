$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
$last = 0
for ($i=0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '{') { $last = $i + 1 }
}
Write-Output $last
