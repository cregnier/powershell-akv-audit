$path = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content -LiteralPath $path
for ($i=0; $i -lt $lines.Length; $i++) {
    $trim = $lines[$i].Trim()
    if ($trim -eq '@"' -or $trim -eq "@'") { Write-Output ("{0,5}: OPEN  -> {1}" -f ($i+1), $trim) }
    if ($trim -eq '"@' -or $trim -eq "'@") { Write-Output ("{0,5}: CLOSE -> {1}" -f ($i+1), $trim) }
}
