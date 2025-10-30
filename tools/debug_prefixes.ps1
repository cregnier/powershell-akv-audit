#!/usr/bin/env pwsh
$script = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$all = Get-Content -Path $script -Encoding UTF8
for ($n=1; $n -le 60; $n++) {
  $content = $all[0..($n-1)] -join "`n"
  $tmp = [System.IO.Path]::Combine($env:TEMP, "prefix_test_$n.ps1")
  Set-Content -Path $tmp -Value $content -Encoding UTF8
  $errors = $null; $tokens = $null
  [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$errors, [ref]$tokens) | Out-Null
  if ($errors -and $errors.Count -gt 0) {
    Write-Host ("Prefix {0}: FAIL (errors: {1})" -f $n, $errors.Count)
    $errors | ForEach-Object { $line = if ($_.Extent) { $_.Extent.StartLine } else { 'N/A' }; Write-Host ("  Line:{0} - {1}" -f $line, ($_.Message -replace "`r|`n", ' ')) }
    break
  } else {
    Write-Host ("Prefix {0}: OK" -f $n)
  }
}
exit 0
