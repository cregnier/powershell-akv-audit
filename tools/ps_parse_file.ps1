param([string]$file = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$errors = [ref]$null
[void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$errors, [ref]$null)
if ($errors.Value) {
    foreach ($e in $errors.Value) { Write-Output ("Line $($e.Extent.StartLineNumber):$($e.Extent.StartColumn) - $($e.Message)") }
} else { Write-Output 'PARSE-OK' }
