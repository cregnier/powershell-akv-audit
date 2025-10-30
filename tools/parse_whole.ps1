$path='c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
Write-Host "Errors: $($errors.Count)"
if ($errors) { foreach ($e in $errors) { Write-Host "Msg:$($e.Message) Start:$($e.Extent.StartLineNumber):$($e.Extent.StartColumnNumber)" } }
else { Write-Host 'No parse errors' }
