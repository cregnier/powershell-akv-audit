$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
Get-Content -LiteralPath $path | Select-Object -Index (0..100) -ErrorAction SilentlyContinue
$i=0
foreach ($line in Get-Content -LiteralPath $path) {
    $i++
    if ($line -match '@"' -or $line -match "@'" -or $line -match '"@' -or $line -match "'@") {
        Write-Host ("Line ${i}: {0}" -f $line)
    }
}
