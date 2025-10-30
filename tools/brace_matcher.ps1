$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$lines = Get-Content $path -Raw -Encoding UTF8 -ErrorAction Stop -Split "\r?\n"

$inHere = $false
$hereType = '' # 'single' or 'double'
$inSingle = $false
$inDouble = $false
$stack = @()

for ($i = 0; $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    $trim = $ln.Trim()

    # detect here-string start (look for @" or @') at line end after possible code
    if (-not $inHere -and ($trim -eq '@"' -or $trim -eq "@'" -or $ln.TrimEnd().EndsWith('@"') -or $ln.TrimEnd().EndsWith("@'"))) {
        # start here-string
        $inHere = $true
        $hereType = if ($trim -like '@"*' -or $ln.TrimEnd().EndsWith('@"')) { 'double' } else { 'single' }
        continue
    }

    if ($inHere) {
        # detect here-string terminator: "@ or '@ on its own trimmed line
        if ($trim -eq '"@' -or $trim -eq "'@") {
            $inHere = $false
            $hereType = ''
        }
        continue
    }

    # not in here-string: scan characters, ignore quotes
    $chars = $ln.ToCharArray()
    for ($c = 0; $c -lt $chars.Length; $c++) {
        $ch = $chars[$c]
        if ($ch -eq "'" -and -not $inDouble) { $inSingle = -not $inSingle; continue }
        if ($ch -eq '"' -and -not $inSingle) { $inDouble = -not $inDouble; continue }
        if ($inSingle -or $inDouble) { continue }
        if ($ch -eq '{') { $stack += @{line=($i+1);col=($c+1)} }
        elseif ($ch -eq '}') {
            if ($stack.Count -gt 0) { $stack = $stack[0..($stack.Count-2)] } else { Write-Output "Unmatched closing brace at $($i+1):$($c+1)" }
        }
    }
}

if ($stack.Count -eq 0) { Write-Output 'No unmatched opening braces found (outside here-strings).' } else { Write-Output "Unmatched opening braces: $($stack.Count)"; $stack | ForEach-Object { Write-Output "Open at $($_.line):$($_.col)" } }
