param(
    [int]$Start=572,
    [int]$End=582,
    [string]$Path='c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
)
$lines = Get-Content -LiteralPath $Path -ErrorAction Stop
$snippet = $lines[$Start-1..$End-1] -join "`r`n"
Write-Host "--- SNIPPET ---"
Write-Host $snippet
Write-Host "--- PARSE ---"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($snippet,[ref]$tokens,[ref]$errors)
Write-Host ("Tokens: {0} Errors: {1}" -f ($tokens.Count), ($errors.Count))
if ($tokens) { $tokens | ForEach-Object { Write-Host ("Token: Kind={0} Text='{1}'" -f $_.Kind, $_.Text) } }
if ($errors) { $errors | ForEach-Object { Write-Host ("Error: {0} Start={1}:{2} End={3}:{4} Token='{5}'" -f $_.Message, $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Extent.EndLineNumber, $_.Extent.EndColumnNumber, $_.TokenText) } }
