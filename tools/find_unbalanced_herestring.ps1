#!/usr/bin/env pwsh
# tools/find_unbalanced_herestring.ps1
# Scan file for @" and "@ tokens in order and find first imbalance (extra closing here-string)

$path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }

$text = Get-Content -Raw -Path $path -ErrorAction Stop
$pattern = '^[ \t]*@"[ \t]*$|^[ \t]*"@[ \t]*$'
$matches = [regex]::Matches($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
$balance = 0
for ($i = 0; $i -lt $matches.Count; $i++) {
  $m = $matches[$i]
  $token = $m.Value
  if ($token -eq '@"') { $balance++ } elseif ($token -eq '"@') { $balance-- }
  if ($balance -lt 0) {
    $index = $m.Index
    # compute approximate line number
    $prefix = $text.Substring(0,$index)
    $line = ($prefix -split "`n").Count
    $start = [math]::Max(0, $index - 120)
    $len = [math]::Min(300, $text.Length - $start)
    $snippet = $text.Substring($start, $len) -replace "`r`n", ' '
  Write-Host ("Imbalance: extra {0} found at index {1} (approx line {2})" -f $closePattern, $index, $line)
  Write-Host ("Snippet: ...{0}..." -f $snippet)
    exit 3
  }
}
Write-Host "Scan complete. Final balance: $balance (opens - closes)"
exit 0
