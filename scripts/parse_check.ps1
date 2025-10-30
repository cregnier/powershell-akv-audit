param([string]$FilePath)

$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$null, [ref]$errors)
if ($errors) {
    Write-Host "Parse errors for file: $FilePath" -ForegroundColor Red
    foreach ($e in $errors) {
        $ln = $e.Extent.StartLineNumber
        $msg = $e.Message -replace "\r|\n"," "
        Write-Host ("Line " + $ln + ": " + $msg) -ForegroundColor Yellow
    }
    exit 1
} else {
    Write-Host "PARSE OK" -ForegroundColor Green
    exit 0
}
