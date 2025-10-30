# tools/count_herestrings.ps1
# Count here-string open (@") and close ("@) delimiters and show their surrounding context

#!/usr/bin/env pwsh
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }

$text = Get-Content -Raw -Path $path -ErrorAction Stop
$openPattern = '@"'
$closePattern = '"@'
$openMatches = [regex]::Matches($text, [regex]::Escape($openPattern), 'Singleline')
$closeMatches = [regex]::Matches($text, [regex]::Escape($closePattern), 'Singleline')

$openCount = $openMatches.Count
$closeCount = $closeMatches.Count

Write-Host "$openPattern count: $openCount; $closePattern count: $closeCount"
Write-Host ("--- First {0} {1} positions ---" -f [math]::Min(10,$openCount), $openPattern)
for ($i=0; $i -lt [math]::Min(10,$openCount); $i++) {
    $m = $openMatches[$i]
    $start = [math]::Max(0, $m.Index - 60)
    $len = [math]::Min(200, $text.Length - $start)
    $snippet = $text.Substring($start,$len) -replace "`r`n", ' '
    Write-Host ("{0} at index {1}: ...{2}..." -f $openPattern, $m.Index, $snippet)
}

Write-Host ("--- First {0} {1} positions ---" -f [math]::Min(10,$closeCount), $closePattern)
for ($i=0; $i -lt [math]::Min(10,$closeCount); $i++) {
    $m = $closeMatches[$i]
    $start = [math]::Max(0, $m.Index - 60)
    $len = [math]::Min(200, $text.Length - $start)
    $snippet = $text.Substring($start,$len) -replace "`r`n", ' '
    Write-Host ("{0} at index {1}: ...{2}..." -f $closePattern, $m.Index, $snippet)
}

exit 0
#!/usr/bin/env pwsh
# tools/count_herestrings.ps1
# Count here-string open (@") and close ("@) delimiters and show their surrounding context

$path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }

$text = Get-Content -Raw -Path $path
$openMatches = [regex]::Matches($text, '@"', 'Singleline')
$closeMatches = [regex]::Matches($text, '"@', 'Singleline')

$openMarker = '@' + '"'
$closeMarker = '"' + '@'

$openCount = $openMatches.Count
$closeCount = $closeMatches.Count

Write-Host ("$openMarker count: $openCount; $closeMarker count: $closeCount")
Write-Host ("--- First 10 $openMarker positions ---")
for ($i = 0; $i -lt [math]::Min(10,$openMatches.Count); $i++) {
    $m = $openMatches[$i]
    $start = [math]::Max(0, $m.Index - 40)
    $len = [math]::Min(120, $text.Length - $start)
    $snippet = $text.Substring($start, $len) -replace "`r`n", ' '
    Write-Host ("$openMarker at index {0}: ...{1}..." -f $m.Index, $snippet)
}

Write-Host ("--- First 10 $closeMarker positions ---")
for ($i = 0; $i -lt [math]::Min(10,$closeMatches.Count); $i++) {
    $m = $closeMatches[$i]
    $start = [math]::Max(0, $m.Index - 40)
    $len = [math]::Min(120, $text.Length - $start)
    $snippet = $text.Substring($start, $len) -replace "`r`n", ' '
    Write-Host ("$closeMarker at index {0}: ...{1}..." -f $m.Index, $snippet)
}

exit 0
# tools/count_herestrings.ps1
# Count here-string open (@") and close ("@) delimiters and show their surrounding context
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }
$text = Get-Content -Raw -Path $path
$openMatches = [regex]::Matches($text, '@"', 'Singleline')
$closeMatches = [regex]::Matches($text, '"@', 'Singleline')
Write-Host ('@
exit 0
