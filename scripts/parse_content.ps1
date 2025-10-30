$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$content = Get-Content -Raw -LiteralPath $path
$errors = [ref]@()
$tokens = [ref]@()
$ast = [System.Management.Automation.Language.Parser]::ParseInput($content, $errors, $tokens)
if ($errors.Value.Count -gt 0) {
    Write-Host "Found $($errors.Value.Count) parse errors:`n"
    foreach ($e in $errors.Value) {
        Write-Host "---- Parse Error ----"
        $e | Format-List * -Force
        Write-Host "Location: Line $($e.Extent.StartLineNumber) Col $($e.Extent.StartColumn) to Line $($e.Extent.EndLineNumber) Col $($e.Extent.EndColumn)`n"
    }
} else {
    Write-Host "No parse errors from ParseInput"
}
Write-Host "AST present: $([bool]$ast)"
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$content = Get-Content -Raw -LiteralPath $path
$errors = [ref]@()
$tokens = [ref]@()
$ast = [System.Management.Automation.Language.Parser]::ParseInput($content, $errors, $tokens)
if ($errors.Value.Count -gt 0) {
    Write-Host "Found $($errors.Value.Count) parse errors:`n"
    foreach ($e in $errors.Value) {
        Write-Host "---- Parse Error ----"
        $e | Format-List * -Force
        Write-Host "Location: Line $($e.Extent.StartLineNumber) Col $($e.Extent.StartColumn) to Line $($e.Extent.EndLineNumber) Col $($e.Extent.EndColumn)`n"
    }
} else {
    Write-Host "No parse errors from ParseInput"
}
Write-Host "AST present: $([bool]$ast)"