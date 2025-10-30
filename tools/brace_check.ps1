$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$s = Get-Content $path -Raw
# Remove single-quoted here-strings @'... '@ and double-quoted here-strings @"..."@
$patternHere = "(@'(?s).*?'@)|(@\"(?s).*?\"@)"
$sNoHere = [regex]::Replace($s,$patternHere,'', [System.Text.RegularExpressions.RegexOptions]::Singleline)
# Remove single-quoted and double-quoted strings
$sNoStrings = [regex]::Replace($sNoHere,"('(?:''|[^'])*')|\"(?:\\\"|[^\"])*\"",'', [System.Text.RegularExpressions.RegexOptions]::Singleline)
[int]$open = 0; [int]$close = 0
for ($i=0; $i -lt $sNoStrings.Length; $i++) {
    $ch = $sNoStrings[$i]
    if ($ch -eq '{') { $open++ }
    if ($ch -eq '}') { $close++ }
}
Write-Output "After stripping strings/here-strings: open={$open} close={$close} diff={$open-$close}"
# Now find first position where running balance goes negative
$balance = 0
$lines = $sNoStrings -split "\r?\n"
for ($ln=0; $ln -lt $lines.Length; $ln++) {
    $line = $lines[$ln]
    for ($i=0; $i -lt $line.Length; $i++) {
        $c = $line[$i]
        if ($c -eq '{') { $balance++ }
        if ($c -eq '}') { $balance-- }
    }
    if ($balance -lt 0) { Write-Output "Balance negative at line $($ln+1)"; break }
}
Write-Output "Final balance after scanning: $balance"
# Print surrounding lines around New-GapAnalysisHtmlReport declaration
$allLines = $s -split "\r?\n"
$idx = ($allLines | Select-String -Pattern 'function New-GapAnalysisHtmlReport' -SimpleMatch | Select-Object -First 1).LineNumber
if ($idx) {
    Write-Output "New-GapAnalysisHtmlReport at line: $idx"
    $start = [Math]::Max(1,$idx-30)
    $end = [Math]::Min($allLines.Length,$idx+30)
    Write-Output "--- Context ---"
    for ($i=$start; $i -le $end; $i++) { Write-Output "$(('{0,6}' -f $i)) $($allLines[$i-1])" }
}
