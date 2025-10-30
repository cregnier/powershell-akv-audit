$srcPath = Join-Path -Path (Get-Location) -ChildPath 'Get-AKVGapAnalysis.ps1'
$src = Get-Content -Path $srcPath -Raw -ErrorAction Stop
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
    Write-Host "Parse errors found: $($errors.Count)"
    $errors | ForEach-Object {
        $e = $_
        Write-Host ("Line {0} Char {1}: {2}" -f $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
    }
    # Print token context around each error
    foreach ($err in $errors) {
        $line = $err.Extent.StartLineNumber
        Write-Host "\nToken context around error at line $line (kind, text, line:col):"
        if ($tokens) {
            $ctx = $tokens | Where-Object { $_.Extent.StartLineNumber -ge [math]::Max(1, $line-8) -and $_.Extent.StartLineNumber -le ($line+8) }
            foreach ($t in $ctx) {
                $txt = $t.Text -replace "\r|\n", '␤'
                Write-Host ("{0}    [{1}]    {2}:{3}    {4}" -f $t.Kind, ($t.TypeName -split '\\')[-1], $t.Extent.StartLineNumber, $t.Extent.StartColumnNumber, $txt)
            }
        } else { Write-Host 'No tokens available' }
    }
    exit 2
} else {
    Write-Host 'No parse errors'
}
