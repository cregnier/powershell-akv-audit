Param(
    [string]$FilePath = "c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1",
    [int]$Context = 6
)

if (-not (Test-Path $FilePath)) { Write-Error "File not found: $FilePath"; exit 2 }

$lines = Get-Content $FilePath
$bal = 0
$firstNeg = 0

for ($i=0; $i -lt $lines.Count; $i++) {
    $opens = ([regex]::Matches($lines[$i],'\{')).Count
    $closes = ([regex]::Matches($lines[$i],'\}')).Count
    $bal += $opens - $closes
    if ($bal -lt 0 -and $firstNeg -eq 0) { $firstNeg = $i+1; break }
}

Write-Host "Final balance: $bal"
if ($firstNeg -gt 0) {
    Write-Host "First negative balance at line $firstNeg"
    $start = [math]::Max(1, $firstNeg - $Context)
    $end = [math]::Min($lines.Count, $firstNeg + $Context)
    for ($j=$start; $j -le $end; $j++) { $prefix = if ($j -eq $firstNeg) { '>>' } else { '  ' }; Write-Host ($prefix + ('{0,5}: ' -f $j) + $lines[$j-1]) }
} else {
    Write-Host "No negative balance found."
}

exit 0
