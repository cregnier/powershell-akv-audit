$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$errorsRef = $null; $tokensRef = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$errorsRef, [ref]$tokensRef) | Out-Null
if ($errorsRef -and $errorsRef.Count -gt 0) {
    Write-Host "Total parse errors: $($errorsRef.Count)"
    for ($i=0;$i -lt [math]::Min(20,$errorsRef.Count); $i++) {
        $e = $errorsRef[$i]
        Write-Host "--- Error #$i ---"
        Write-Host "Message: [$($e.Message)]"
        Write-Host "Reason: $($e.Reason)"
        Write-Host "Extent Start: $($e.Extent.StartLineNumber):$($e.Extent.StartColumn)"
        Write-Host "Extent End: $($e.Extent.EndLineNumber):$($e.Extent.EndColumn)"
        Write-Host "ErrorText: $($e.ScriptStackTrace)"
        Write-Host "ToString: $([string]$e)"
    }
} else {
    Write-Host "No parse errors"
}
