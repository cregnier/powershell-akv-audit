$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors -and $errors.Count -gt 0) {
    Write-Host "Total parse errors: $($errors.Count)"
    $errors | Select-Object -First 40 | ForEach-Object {
        Write-Host '----'
        Write-Host "Message: $($_.Message)"
        Write-Host "Start: $($_.Extent.StartLineNumber):$($_.Extent.StartColumnNumber) End: $($_.Extent.EndLineNumber):$($_.Extent.EndColumnNumber)"
        Write-Host "Text: $([string]$_.Extent.Text)"
    }
} else {
    Write-Host 'No parse errors'
}
