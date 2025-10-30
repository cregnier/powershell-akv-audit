$lines = Get-Content -LiteralPath 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$bal=0; $parenbal=0; $lineNum=0
foreach ($line in $lines) {
    $lineNum++
    $open = ([regex]::Matches($line,'\{')).Count
    $close = ([regex]::Matches($line,'\}')).Count
    $bal += ($open - $close)
    $op = ([regex]::Matches($line,'\(')).Count
    $cl = ([regex]::Matches($line,'\)')).Count
    $parenbal += ($op - $cl)
    if ($lineNum % 500 -eq 0) { Write-Host "Line ${lineNum}: braceBal=${bal} parenBal=${parenbal}" }
}
Write-Host "Final: braceBal=$bal parenBal=$parenbal"
# Try to find first line where braceBal became >0 and remained
$bal=0; $lineNum=0
foreach ($line in $lines) {
    $lineNum++
    $bal += (([regex]::Matches($line,'\{')).Count - ([regex]::Matches($line,'\}')).Count)
    if ($bal -gt 0) { Write-Host "First positive brace balance at line $lineNum"; break }
}
# Find last line where brace balance is non-zero
$bal=0; $lastNonZero=0; $lineNum=0
foreach ($line in $lines) {
    $lineNum++
    $bal += (([regex]::Matches($line,'\{')).Count - ([regex]::Matches($line,'\}')).Count)
    if ($bal -ne 0) { $lastNonZero=$lineNum }
}
Write-Host "Last non-zero brace balance at line $lastNonZero"