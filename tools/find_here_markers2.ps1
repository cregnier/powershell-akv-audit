$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }
$i = 1
Get-Content -Path $path | ForEach-Object {
    $trim = $_.TrimEnd()
    $t2 = $trim.Trim()
    switch ($t2) {
        '@"' { Write-Host ("{0,5}: OPEN_DQ_HERES {1}" -f $i, $trim) }
        '"@' { Write-Host ("{0,5}: CLOSE_DQ_HERES {1}" -f $i, $trim) }
        "@'" { Write-Host ("{0,5}: OPEN_SQ_HERES {1}" -f $i, $trim) }
        "'@" { Write-Host ("{0,5}: CLOSE_SQ_HERES {1}" -f $i, $trim) }
        default { }
    }
    $i++
}
