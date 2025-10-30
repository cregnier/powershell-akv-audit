$path = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path
$inHere = $false
$lineNum = 0
$parenBalance = 0
$singleQuoteOpen = $false
$doubleQuoteOpen = $false
foreach ($line in $lines) {
    $lineNum++
    if (-not $inHere) {
        if ($line -match '@"\s*$') { $inHere = $true; continue }
    } else {
        if ($line -match '^\s*"@\s*$') { $inHere = $false; continue } else { continue }
    }
    # Remove escaped quotes for parity check
    $clean = $line -replace "''","" -replace '""',''
    # Count single and double quotes
    $singleCount = ($clean.ToCharArray() | Where-Object { $_ -eq "'" }).Count
    $doubleCount = ($clean.ToCharArray() | Where-Object { $_ -eq '"' }).Count
    if ($singleCount % 2 -ne 0) { Write-Host "Odd single quotes at line $lineNum"; Write-Host $line }
    if ($doubleCount % 2 -ne 0) { Write-Host "Odd double quotes at line $lineNum"; Write-Host $line }
    # Count parentheses
    $opens = ($line.ToCharArray() | Where-Object { $_ -eq '(' }).Count
    $closes = ($line.ToCharArray() | Where-Object { $_ -eq ')' }).Count
    $parenBalance += $opens - $closes
}
Write-Host "Final paren balance: $parenBalance" 
