param(
    [string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1',
    [int]$Lines = 580
)

$lines = Get-Content -LiteralPath $Path -ErrorAction Stop
$prefix = ($lines[0..($Lines-1)] -join "`r`n")
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($prefix, [ref]$tokens, [ref]$errors)
Write-Host ("Parsed prefix lines: {0}. Tokens: {1} Errors: {2}" -f $Lines, ($tokens.Count), ($errors.Count))
if ($tokens) {
    for ($i=0; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i]
        Write-Host ("Token[{0}]: Kind={1} Text='{2}'" -f $i, $t.Kind, $t.Text)
    }
}
if ($errors) {
    for ($i=0; $i -lt $errors.Count; $i++) {
        $e = $errors[$i]
        Write-Host ("Error[{0}]: Msg='{1}' Start={2}:{3} End={4}:{5} TokenText='{6}'" -f $i, $e.Message, $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Extent.EndLineNumber, $e.Extent.EndColumnNumber, $e.TokenText)
    }
}
