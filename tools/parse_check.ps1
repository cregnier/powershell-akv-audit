$scriptPath = 'C:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$code = Get-Content -Raw -LiteralPath $scriptPath
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
    Write-Host "Parse errors found in $scriptPath`n" -ForegroundColor Red
    foreach ($err in $errors) {
        $msg = $err.Message
        $start = $err.Extent.StartLineNumber
        $startCol = $err.Extent.StartColumn
        $end = $err.Extent.EndLineNumber
        $endCol = $err.Extent.EndColumn
        Write-Host "Line $start,$startCol - $end,$endCol : $msg" -ForegroundColor Yellow
    }
    exit 1
} else {
    Write-Host "Syntax valid" -ForegroundColor Green
    exit 0
}