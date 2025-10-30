#!/usr/bin/env pwsh
# tools/collect_parse_errors.ps1
$script = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$errors, [ref]$tokens) | Out-Null
if ($errors -and $errors.Count -gt 0) {
  $errors | Sort-Object { if ($_.Extent) { $_.Extent.StartLine } else { [int]::MaxValue } } | Select-Object -First 40 | ForEach-Object {
    $line = if ($_.Extent) { $_.Extent.StartLine } else { 'N/A' }
    $col = if ($_.Extent) { $_.Extent.StartColumn } else { 'N/A' }
    $msg = if ($_.Message) { ($_.Message -replace "\r|\n", ' ') } else { '<empty message>' }
    Write-Output "Line:$line Col:$col - $msg"
  }
  exit 1
} else {
  Write-Output 'No parse errors'
  exit 0
}
