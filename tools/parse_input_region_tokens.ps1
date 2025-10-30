param([int]$Start=1,[int]$End=100,[string]$Path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$all = Get-Content -LiteralPath $Path
$total = $all.Count
if ($Start -lt 1) { $Start = 1 }
if ($End -gt $total) { $End = $total }
$regionLines = [System.Collections.Generic.List[string]]::new()
for ($i = $Start; $i -le $End; $i++) {
    $regionLines.Add($all[$i - 1])
}
$region = $regionLines -join "`r`n"

$errors = @()
$tokens = @()
[void][System.Management.Automation.Language.Parser]::ParseInput($region, [ref]$errors, [ref]$tokens)
Write-Output ("ParseInput returned {0} tokens and {1} errors for region {2}-{3}" -f $tokens.Count, $errors.Count, $Start, $End)
if ($errors.Count -gt 0) {
    Write-Output "---- Parse Errors ----"
    foreach ($e in $errors) {
        if ($e -is [System.Management.Automation.Language.ParseError]) {
            $line = $e.Extent.StartLineNumber + $Start - 1
            $col = $e.Extent.StartColumnNumber
            Write-Output ("Line {0}, Col {1}: {2}" -f $line, $col, $e.Message)
        } else {
            Write-Output ($e.ToString())
        }
    }
}
Write-Output "---- Tokens in region ----"
for ($i=0; $i -lt $tokens.Count; $i++) {
    $t = $tokens[$i]
    # Token extents are relative to the parsed region: adjust by Start
    $ln = $t.Extent.StartLineNumber + $Start - 1
    $col = $t.Extent.StartColumnNumber
    $text = $t.Text -replace "`r`n","\n"
    if ($ln -ge $Start -and $ln -le $End) {
        Write-Output ("{0,4}:{1,3} {2} -> {3}" -f $ln, $col, $t.Kind, $text)
    }
}
