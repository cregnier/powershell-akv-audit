Param(
    [string]$FilePath = "c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1"
)
if (-not (Test-Path $FilePath)) { Write-Error "File not found: $FilePath"; exit 2 }
$lines = Get-Content $FilePath
$bal = 0
for ($i=0; $i -lt $lines.Count; $i++) {
    $opens = ([regex]::Matches($lines[$i],'\{')).Count
    $closes = ([regex]::Matches($lines[$i],'\}')).Count
    $bal += $opens - $closes
    if ($bal -lt 0) { Write-Host ('NEGATIVE at {0,5}: opens={1,2} closes={2,2} balance={3,4} {4}' -f ($i+1), $opens, $closes, $bal, $lines[$i].Trim()) }
    if ($opens -gt 0 -or $closes -gt 0) { Write-Host ('{0,5}: opens={1,2} closes={2,2} balance={3,4} {4}' -f ($i+1), $opens, $closes, $bal, $lines[$i].Trim()) }
}
Write-Host 'Final balance:' $bal
exit 0
