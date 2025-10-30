$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$text = Get-Content $path -Raw
$tokens = [System.Management.Automation.Language.Parser]::Tokenize($text, [ref]$null)
Write-Host "Total tokens: $($tokens.Count)"
# Find last token before function New-GapAnalysisHtmlReport
for ($i=0; $i -lt $tokens.Count; $i++) {
    $t = $tokens[$i]
    if ($t.Text -eq 'function' -and $i+2 -lt $tokens.Count -and $tokens[$i+1].Text -match '\s*' -and $tokens[$i+2].Text -eq 'New-GapAnalysisHtmlReport') {
        Write-Host "Found function token at token index $i; token start line: $($t.Extent.StartLineNumber)"
        $startIndex = [Math]::Max(0, $i-50)
        $endIndex = [Math]::Min($tokens.Count-1, $i+50)
        for ($j=$startIndex; $j -le $endIndex; $j++) {
            $tt = $tokens[$j]
            Write-Host ("{0,4} {1,-20} {2}" -f $j, $tt.Kind, $tt.Text)
        }
        break
    }
}
# Find any unterminated here-strings or string tokens
$unterminated = $tokens | Where-Object { $_.Kind -eq 'HereString' -and $_.Text -match '\n$' }
Write-Host "Done"
