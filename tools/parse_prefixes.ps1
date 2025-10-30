param(
    [string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1',
    [int]$MaxLines = 20
)

$lines = Get-Content -LiteralPath $Path -ErrorAction Stop
$tot = $lines.Length
Write-Host "File lines: $tot"
for ($n=1; $n -le [math]::Min($MaxLines,$tot); $n++) {
    $prefix = ($lines[0..($n-1)] -join "`r`n")
    $tokens = $null
    $errors = $null
    try {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($prefix, [ref]$tokens, [ref]$errors)
    } catch {
        Write-Host ("Prefix {0}: PARSE THREW: {1}" -f $n, $_.Exception.Message)
        continue
    }
    $tokCount = if ($tokens) { $tokens.Count } else { 0 }
    $errCount = if ($errors) { $errors.Count } else { 0 }
    Write-Host ("Prefix {0}: tokens={1} errors={2}" -f $n, $tokCount, $errCount)
    if ($errCount -gt 0) {
        for ($i=0; $i -lt [math]::Min(3,$errCount); $i++) {
            $e = $errors[$i]
            $msg = $e.Message
            $start = $e.Extent.StartLineNumber
            $end = $e.Extent.EndLineNumber
            $tokText = $e.TokenText
            Write-Host ("  Error[{0}]: Msg='{1}' StartLine={2} EndLine={3} TokenText='{4}'" -f $i, $msg, $start, $end, $tokText)
        }
    } else {
        # show first few tokens
        if ($tokCount -gt 0) {
            for ($i=0; $i -lt [math]::Min(6,$tokCount); $i++) {
                $t = $tokens[$i]
                Write-Host ("  Token[{0}]: Kind={1} Text='{2}'" -f $i, $t.Kind, $t.Text)
            }
        }
    }
}
