$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$errors = [ref]$null
$tokens = [ref]$null
try {
    ## ParseFile expects tokens then errors (out params)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Value) {
        $errors.Value | ForEach-Object {
            Write-Host "Parse error at line $($_.Extent.StartLineNumber): $($_.Message)"
        }
        exit 1
    } else {
        Write-Host 'No parse errors'
        exit 0
    }
} catch {
    Write-Host 'Parser exception:' $_.Exception.Message
    exit 2
}