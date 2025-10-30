param(
    [int]$StartLine = 996
)
$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path -Encoding UTF8

$openCount = 0
$inHere = $false
$hereType = ''
$inSingle = $false
$inDouble = $false
for ($i = $StartLine-1; $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    $trim = $ln.Trim()
    # here-string start/stop detection
    if (-not $inHere -and ($trim -eq '@"' -or $trim -eq "@'" -or $ln.TrimEnd().EndsWith('@"') -or $ln.TrimEnd().EndsWith("@'"))) {
        $inHere = $true; $hereType = if ($trim -like '@"*' -or $ln.TrimEnd().EndsWith('@"')) { 'double' } else { 'single' }
        continue
    }
    if ($inHere) {
        if ($trim -eq '"@' -or $trim -eq "'@") { $inHere = $false; $hereType = ''; }
        continue
    }
    # not in here-string
    $chars = $ln.ToCharArray()
    for ($c=0; $c -lt $chars.Length; $c++) {
        $ch = $chars[$c]
        if ($ch -eq "'" -and -not $inDouble) { $inSingle = -not $inSingle; continue }
        if ($ch -eq '"' -and -not $inSingle) { $inDouble = -not $inDouble; continue }
        if ($inSingle -or $inDouble) { continue }
        if ($ch -eq '{') { $openCount++ }
        elseif ($ch -eq '}') { $openCount-- }
    }
    if ($openCount -eq 0) { Write-Output "Matching closing brace for function starting at line $StartLine found at line $($i+1)"; break }
}
if ($openCount -gt 0) { Write-Output "No matching closing brace found; remaining opens = $openCount" }
