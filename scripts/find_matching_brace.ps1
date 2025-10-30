$target = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $target
$startLine = 1622
$balance = 0
$inHere = $false
for ($i = $startLine-1; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if (-not $inHere -and $line -match '@"\s*$') { $inHere = $true }
    elseif ($inHere -and $line -match '^\s*"@\s*$') { $inHere = $false; continue }
    $opens = ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $closes = ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    # On the first line (function declaration), include its opens
    $balance += $opens - $closes
    if ($balance -eq 0) {
        Write-Output "Matching closing brace for function at line $($i+1)"
        break
    }
}
Write-Output "Final balance after scan: $balance"