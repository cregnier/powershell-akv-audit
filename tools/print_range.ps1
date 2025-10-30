param(
    [int]$Start = 1,
    [int]$End = 100
)
$lines = Get-Content -Path ..\Get-AKVGapAnalysis.ps1
for ($i = $Start-1; $i -lt $End -and $i -lt $lines.Length; $i++) {
    $num = $i + 1
    Write-Host ("{0,5}: {1}" -f $num, $lines[$i])
}