$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }
$lines = Get-Content -Path $path -Encoding UTF8
for ($i=0; $i -lt $lines.Count; $i++) {
    $ln = $i + 1
    $line = $lines[$i]
    if ($line -match '@"' -or $line -match '"@' -or $line -match "@'" -or $line -match "'@") {
        $markers = @()
        if ($line -match '@"') { $markers += '@"' }
        if ($line -match '"@') { $markers += '"@' }
        if ($line -match "@'") { $markers += "@'" }
        if ($line -match "'@") { $markers += "'@" }
        Write-Host ("{0,5}: {1} => {2}" -f $ln, ($markers -join ','), $line)
    }
}
