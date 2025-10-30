#!/usr/bin/env pwsh
# tools/dump_tokens.ps1 - tokenize the main script and print first N tokens with position
$script = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$errors, [ref]$tokens) | Out-Null
if ($tokens -eq $null) { Write-Error "No tokens returned"; exit 2 }
$max = 500
Write-Host "Tokens total: $($tokens.Count)"
for ($i=0; $i -lt [math]::Min($max,$tokens.Count); $i++) {
  $t = $tokens[$i]
  $text = $t.Text -replace "`r`n", '\n'
  $line = if ($t.Extent) { $t.Extent.StartLine } else { 'N/A' }
  $col = if ($t.Extent) { $t.Extent.StartColumn } else { 'N/A' }
  Write-Host ("#{0} Line:{1} Col:{2} Kind:{3} Text:{4}" -f $i, $line, $col, $t.Kind, ($text.Substring(0,[math]::Min(80,$text.Length)) ))
}
exit 0
