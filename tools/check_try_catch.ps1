$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$errors = [ref] $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$null,[ref]$errors)
$tokens = $ast.Tokens
$stack = @()
$unmatched = @()
for ($i=0; $i -lt $tokens.Count; $i++) {
    $t = $tokens[$i]
    if ($t.Kind -eq 'Try') { $stack += @{ token=$t; index=$i } }
    if ($t.Kind -eq 'Catch' -or $t.Kind -eq 'Finally') {
        if ($stack.Count -gt 0) { $stack = $stack[0..($stack.Count-2)] } else { $unmatched += @{type=$t.Kind; token=$t; index=$i} }
    }
}
if ($stack.Count -eq 0) { Write-Output 'All Try tokens have corresponding Catch/Finally (token-level)' } else {
    Write-Output "Unmatched Try tokens: $($stack.Count)"
    $stack | ForEach-Object { $t = $_.token; Write-Output ("Try at Line {0}, Col {1}" -f $t.Extent.StartLineNumber, $t.Extent.StartColumnNumber) }
}
if ($unmatched.Count -gt 0) { Write-Output "Unmatched Catch/Finally tokens: $($unmatched.Count)"; $unmatched | ForEach-Object { $t=$_.token; Write-Output ("{0} at Line {1}, Col {2}" -f $_.type, $t.Extent.StartLineNumber, $t.Extent.StartColumnNumber) } }
