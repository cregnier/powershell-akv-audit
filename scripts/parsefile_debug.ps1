$path = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$errors = @()
$tokens = @()
try {
    # ParseFile signature: ParseFile(string path, out Token[] tokens, out ParseError[] errors)
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
} catch {
    Write-Host "ParseFile exception: $($_.Exception.Message)"
    exit 2
}
if ($errors.Count -eq 0) { Write-Host 'No parse errors'; exit 0 }
Write-Host "Parse errors: $($errors.Count)"
$lines = Get-Content $path
for ($i=0;$i -lt [math]::Min(20,$errors.Count); $i++) {
    $e = $errors[$i]
    Write-Host '---'
    Write-Host "Message: $($e.Message)"
    Write-Host "StartLine: $($e.Extent.StartLineNumber) EndLine: $($e.Extent.EndLineNumber)"
    $start = [math]::Max(1, $e.Extent.StartLineNumber - 3)
    $end = [math]::Min($lines.Count, $e.Extent.EndLineNumber + 3)
    for ($ln = $start; $ln -le $end; $ln++) { Write-Host ("{0,5}: {1}" -f $ln, $lines[$ln-1]) }
}
exit 1
