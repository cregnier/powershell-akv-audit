# Count braces outside of here-strings in a PowerShell file and report imbalance
param(
    [string]$FilePath = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
)

$text = Get-Content -Raw -LiteralPath $FilePath
# Remove double-quoted here-strings @"..."@ and single-quoted here-strings @'...'@
$textNoHere = [regex]::Replace($text, "(?s)@\".*?\"@", '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$textNoHere = [regex]::Replace($textNoHere, "(?s)@'.*?'@", '', [System.Text.RegularExpressions.RegexOptions]::Singleline)

$lines = $textNoHere -split "\r?\n"
$balance = 0
$open = 0
$close = 0
$firstNeg = $null
for ($i=0; $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    foreach ($c in $ln.ToCharArray()) {
        if ($c -eq '{') { $open++; $balance++ }
        if ($c -eq '}') { $close++; $balance-- }
        if ($balance -lt 0 -and -not $firstNeg) { $firstNeg = $i + 1 }
    }
}
Write-Output "open=$open close=$close diff=$($open-$close)"
if ($firstNeg) { Write-Output "First negative balance at line: $firstNeg" } else { Write-Output "No negative balance encountered" }

# Also report surrounding context for New-GapAnalysisHtmlReport
$allLines = $text -split "\r?\n"
$idx = ($allLines | Select-String -Pattern 'function New-GapAnalysisHtmlReport' -SimpleMatch | Select-Object -First 1).LineNumber
if ($idx) {
    Write-Output "New-GapAnalysisHtmlReport declaration at line: $idx"
    $start = [Math]::Max(1,$idx-20)
    $end = [Math]::Min($allLines.Length,$idx+200)
    Write-Output "--- Context around declaration ---"
    for ($j=$start; $j -le $end; $j++) { Write-Output ("{0,5}: {1}" -f $j, $allLines[$j-1]) }
}
