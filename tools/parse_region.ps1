param([int]$Start=1,[int]$End=200)
$path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = (Get-Content -LiteralPath $path)[$Start-1..($End-1)] -join "`r`n"
$errors = [ref] @()
[void][System.Management.Automation.Language.Parser]::ParseInput($lines, [ref]$null, $errors)
if ($errors.Value -and $errors.Value.Count -gt 0) {
    Write-Output ('Parse errors for region {0}-{1}:' -f $Start,$End)
    foreach ($e in $errors.Value) { Write-Output $e }
} else { Write-Output ('No parse errors for region {0}-{1}' -f $Start,$End) }
