param([string]$Path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$src = Get-Content -LiteralPath $Path
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
if ($ast.Errors.Count -eq 0) { Write-Output "No parse errors."; exit 0 }
Write-Output ("Found {0} parse errors:" -f $ast.Errors.Count)
foreach ($e in $ast.Errors) {
    $startLine = $e.Extent.StartLineNumber
    $endLine = $e.Extent.EndLineNumber
    $startCol = $e.Extent.StartColumnNumber
    $endCol = $e.Extent.EndColumnNumber
    Write-Output "----"
    Write-Output ("Message: {0}" -f $e.Message)
    Write-Output ("Start: Line {0}, Col {1}  End: Line {2}, Col {3}" -f $startLine, $startCol, $endLine, $endCol)
    $contextStart = [math]::Max(1, $startLine - 3)
    $contextEnd = [math]::Min($src.Count, $endLine + 3)
    Write-Output "Context:" 
    for ($i=$contextStart; $i -le $contextEnd; $i++) {
        $marker = '   '
        if ($i -ge $startLine -and $i -le $endLine) { $marker = '>>>' }
        Write-Output ("{0}{1,5}: {2}" -f $marker, $i, $src[$i-1])
    }
}
