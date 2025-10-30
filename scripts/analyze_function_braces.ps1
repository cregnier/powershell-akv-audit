$target = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $target
$funcName = 'New-GapAnalysisHtmlReport'
$start = ($lines | Select-Object -Index (0..($lines.Count-1)) | ForEach-Object { $_ } ) | Select-String -Pattern "function\s+$funcName\s*\{" -SimpleMatch -AllMatches | ForEach-Object { $_.LineNumber } | Select-Object -First 1
if (-not $start) { Write-Host "Function $funcName not found"; exit 1 }
$startLine = $start
$endLine = 3175
$balance = 0
$inHere = $false
for ($i = $startLine-1; $i -lt $endLine; $i++) {
    $line = $lines[$i]
    if (-not $inHere -and $line -match '@"\s*$') { $inHere = $true }
    elseif ($inHere -and $line -match '^\s*"@\s*$') { $inHere = $false; continue }
    $opens = ($line.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $closes = ($line.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    $balance += $opens - $closes
    $num = $i+1
    if ($num -ge 1600 -and $num -le 3180) {
        Write-Output ("{0,5} {1,3} +{2} -{3} | {4}" -f $num, $balance, $opens, $closes, ($line -replace "`r|`n",""))
    }
}
Write-Output "Function $funcName balance: $balance (positive means unclosed opens)"