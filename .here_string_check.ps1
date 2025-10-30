$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$text = Get-Content $path -Raw
$starts = ([regex]::Matches($text, '^(\s*)@"', [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
$ends = ([regex]::Matches($text, '^(\s*)"@', [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
Write-Host "Here-string starts: $starts, ends: $ends"
# Print last 30 lines before the New-GapAnalysisHtmlReport declaration
$lines = Get-Content $path
$startLine = 1590
$endLine = 1635
for ($i=$startLine; $i -le $endLine; $i++) { Write-Host ("{0,4}: {1}" -f $i, $lines[$i-1]) }
