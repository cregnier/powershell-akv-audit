$path = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path -Encoding UTF8 -Raw
for ($i=0; $i -lt $lines.Length; $i++) { }
$lineArr = $lines -split "\r?\n"
$bad = @()
for ($idx=0; $idx -lt $lineArr.Count; $idx++) {
    $line = $lineArr[$idx]
    for ($j=0; $j -lt $line.Length; $j++) {
        $c = [int][char]$line[$j]
        if (($c -lt 32 -and $c -ne 9) -or $c -gt 126) {
            $bad += [PSCustomObject]@{ Line = $idx+1; Col = $j+1; Char = $line[$j]; Code = $c; Context = $line }
        }
    }
}
if ($bad.Count -eq 0) { Write-Host 'No non-printable chars found' } else { $bad | Format-Table -AutoSize }
