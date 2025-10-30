# Show parse errors for a PowerShell file
param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# Initialize token and error holders as arrays to satisfy the ParseFile signature
$tokens = @()
$errors = @()
$ast = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$errors)
if ($errors.Value) {
    foreach ($err in $errors.Value) {
        Write-Host "Message: $($err.Message)" -ForegroundColor Yellow
        Write-Host "StartLine: $($err.Extent.StartLineNumber) EndLine: $($err.Extent.EndLineNumber)" -ForegroundColor Cyan
        Write-Host "Text:" -ForegroundColor Green
        $start = [Math]::Max(1, $err.Extent.StartLineNumber - 3)
        $end = [Math]::Min((Get-Content -Path $FilePath).Count, $err.Extent.EndLineNumber + 3)
        (Get-Content -Path $FilePath -TotalCount $end | Select-Object -Skip ($start - 1)) | ForEach-Object -Begin { $ln = $start } -Process { Write-Host ("{0,5}: {1}" -f $ln, $_); $ln++ }
        Write-Host "----"
    }
} else {
    Write-Host "PARSE_OK" -ForegroundColor Green
}
