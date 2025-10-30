$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$errorsRef = $null; $tokensRef = $null
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$errorsRef, [ref]$tokensRef)
    if ($errorsRef -and $errorsRef.Count -gt 0) {
        Write-Host "Errors found: $($errorsRef.Count)"
        $i=0
        foreach ($e in $errorsRef) { Write-Host "[$i] $($e.Message) at $($e.Extent.StartLineNumber):$($e.Extent.StartColumn)"; $i++ }
    } else {
        Write-Host "No errors. AST has $($ast.EndBlock)"
    }
} catch {
    Write-Host "Parse threw exception: $($_.Exception.Message)"
}
