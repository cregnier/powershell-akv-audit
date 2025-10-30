Param(
    [string]$FilePath = "c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1",
    [int]$ContextRadius = 8
)

if (-not (Test-Path $FilePath)) { Write-Error "File not found: $FilePath"; exit 2 }

$lines = Get-Content $FilePath
$bal = 0
$maxBal = 0
$maxLine = 0

for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $opens = ([regex]::Matches($line, '\{')).Count
    $closes = ([regex]::Matches($line, '\}')).Count
    $bal += $opens - $closes
    if ($bal -gt $maxBal) { $maxBal = $bal; $maxLine = $i+1 }
}

Write-Host "Final balance (open - close): $bal"
Write-Host "Maximum nesting balance: $maxBal at line: $maxLine"

if ($maxLine -gt 0) {
    $start = [math]::Max(1, $maxLine - $ContextRadius)
    $end = [math]::Min($lines.Count, $maxLine + $ContextRadius)
    Write-Host "--- Context around line $maxLine ---"
    for ($j=$start; $j -le $end; $j++) {
        $prefix = if ($j -eq $maxLine) { '>>' } else { '  ' }
        Write-Host ($prefix + ('{0,5}: ' -f $j) + $lines[$j-1])
    }
} else {
    Write-Host "No imbalance detected."
}

exit 0
