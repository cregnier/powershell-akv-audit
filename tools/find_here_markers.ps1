$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
Get-Content -Path $path | ForEach-Object -Begin {$ln=1} -Process {
    $line = $_
    if ($line -match "@\"\s*$") { Write-Host ("{0,5}: OPEN_DQ_HERES {1}" -f $ln, $line) }
    if ($line -match "\"@\s*$") { Write-Host ("{0,5}: CLOSE_DQ_HERES {1}" -f $ln, $line) }
    if ($line -match "@'\s*$") { Write-Host ("{0,5}: OPEN_SQ_HERES {1}" -f $ln, $line) }
    if ($line -match "'@\s*$") { Write-Host ("{0,5}: CLOSE_SQ_HERES {1}" -f $ln, $line) }
    $ln++
}
