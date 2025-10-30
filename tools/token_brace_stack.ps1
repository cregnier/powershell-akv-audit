param([string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$null,[ref]$null)
$tokens = $ast.Tokens
$stack = @()
foreach ($t in $tokens) {
    if ($t.Kind -eq 'LCurly') { $stack += @{ kind=$t.Kind; line=$t.Extent.StartLineNumber; col=$t.Extent.StartColumnNumber; text=$t.Text } }
    if ($t.Kind -eq 'RCurly') { if ($stack.Count -gt 0) { $stack = $stack[0..($stack.Count-2)] } else { Write-Output "Unmatched RCurly at $($t.Extent.StartLineNumber):$($t.Extent.StartColumnNumber)" } }
}
if ($stack.Count -eq 0) { Write-Output 'All token-level curly braces matched' } else { Write-Output "Unmatched LCurly tokens: $($stack.Count)"; $stack | Select-Object -Last 10 | ForEach-Object { Write-Output ("Line {0}, Col {1}: {2}" -f $_.line,$_.col,$_.text) } }
