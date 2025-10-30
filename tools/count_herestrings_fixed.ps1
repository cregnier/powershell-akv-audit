#!/usr/bin/env pwsh
# tools/count_herestrings_fixed.ps1
# Count here-string open (@") and close ("@) delimiters and show their surrounding context

$path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }

$text = Get-Content -Raw -Path $path -ErrorAction Stop

$openPattern = '@"'
$closePattern = '"@'

function PrintMatches($pattern, $label) {
  $matches = [regex]::Matches($text, [regex]::Escape($pattern), 'Singleline')
  Write-Host "$label count: $($matches.Count)"
  for ($i=0; $i -lt [math]::Min(10,$matches.Count); $i++) {
    $m = $matches[$i]
    $start = [math]::Max(0, $m.Index - 80)
    $len = [math]::Min(240, $text.Length - $start)
    $snippet = $text.Substring($start,$len) -replace "`r`n", ' '
    Write-Host ("{0} at index {1}: ...{2}..." -f $pattern, $m.Index, $snippet)
  }
}

PrintMatches $openPattern '@"'
PrintMatches $closePattern '"@'

exit 0
