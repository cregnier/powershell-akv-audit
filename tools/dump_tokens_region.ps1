param([int]$Start=1,[int]$End=100)
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
 $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
 $errors = $ast.Errors
 $tokens = $ast.Tokens
 Write-Output ("Tokens total: {0}" -f $tokens.Count)
for ($i=0; $i -lt $tokens.Count; $i++) {
    $t = $tokens[$i]
    $line = $t.Extent.StartLineNumber
    if ($line -ge $Start -and $line -le $End) {
        $text = $t.Text -replace "`r`n","\n"
        Write-Output ("{0,4}:{1,3} {2} -> {3}" -f $line, $t.Extent.StartColumnNumber, $t.Kind, $text)
    }
}
