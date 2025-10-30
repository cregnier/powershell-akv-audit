#!/usr/bin/env pwsh
# tools/find_parse_breakpoint.ps1
# Find the largest prefix of the script that parses without errors (binary search)

$script = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
if (-not (Test-Path $script)) { Write-Error "File not found: $script"; exit 2 }
# Read file as array of lines (compatible across PS versions)
$allLines = Get-Content -Path $script -ErrorAction Stop -Encoding UTF8
$total = $allLines.Count
Write-Host "File has $total lines"

$temp = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName() + '.ps1')
function Test-Prefix($n) {
  if ($n -le 0) { return $false }
  $content = $allLines[0..($n-1)] -join "`n"
  Set-Content -Path $temp -Value $content -Encoding UTF8
  $errorsRef = $null; $tokensRef = $null
  try {
    [System.Management.Automation.Language.Parser]::ParseFile($temp,[ref]$errorsRef,[ref]$tokensRef) | Out-Null
  } catch {
    Remove-Item -Path $temp -ErrorAction SilentlyContinue
    return $false
  }
  if ($errorsRef -and $errorsRef.Count -gt 0) { return $false } else { return $true }
}

$low = 0
$high = $total
while ($low -lt $high) {
  $mid = [int](([int]($low + $high + 1))/2)
  Write-Host "Testing prefix $mid/$total..."
  if (Test-Prefix $mid) { $low = $mid } else { $high = $mid - 1 }
}
Remove-Item -Path $temp -ErrorAction SilentlyContinue
Write-Host "Largest parsable prefix: $low lines (of $total)"
if ($low -lt $total) {
  $start = [math]::Max(1, $low - 10)
  $end = [math]::Min($total, $low + 50)
  Write-Host "Printing lines $start..$end for inspection"
  $allLines[$start-1..$end-1] | ForEach-Object { $nr = $start + ($_ -as [int] $null) ; Write-Host $_ }
}
exit 0
