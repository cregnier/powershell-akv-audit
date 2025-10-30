param(
    [Parameter(Mandatory=$true)][string]$FilePath
)

$lines = Get-Content -Path $FilePath -ErrorAction Stop -Encoding UTF8
$inHereString = $false
$hereStringDelim = ''
$inBlockComment = $false
$balance = 0
$lineNumber = 0

Write-Host "Scanning file: $FilePath" -ForegroundColor Cyan
Write-Host "Line | opens | closes | balance | text" -ForegroundColor Gray

foreach ($line in $lines) {
    $lineNumber++
    $trim = $line.TrimEnd("`r","`n")

    # Detect start/end of block comment
    if (-not $inHereString) {
        if (-not $inBlockComment -and $trim -match '<#') { $inBlockComment = $true }
        if ($inBlockComment -and $trim -match '#>') { $inBlockComment = $false; continue }
    }

    if ($inBlockComment) { continue }

    # Detect here-string start/end only when not in a here-string
    if (-not $inHereString) {
        if ($trim -match '^@"\s*$' -or $trim -match "^@'\s*$") {
            $inHereString = $true
            $hereStringDelim = $trim.Substring(0,2)
            continue
        }
    } else {
        # inside here-string; end when a line exactly matches the terminator
        if (($hereStringDelim -eq '@"' -and $trim -match '^"@\s*$') -or ($hereStringDelim -eq "@'" -and $trim -match "^'@\s*$")) {
            $inHereString = $false
            $hereStringDelim = ''
            continue
        }
        continue
    }

    # Remove single-line comments
    $codeLine = $trim -replace '\s*#.*$',''

    # Count braces (approximate)
    $opens = ([regex]::Matches($codeLine,'\{')).Count
    $closes = ([regex]::Matches($codeLine,'\}')).Count
    $balance += ($opens - $closes)

    if ($opens -ne 0 -or $closes -ne 0) {
        $display = $codeLine.Trim()
        if ($display.Length -gt 80) { $display = $display.Substring(0,77) + '...' }
        Write-Host ("{0,5} | {1,5} | {2,6} | {3,7} | {4}" -f $lineNumber, $opens, $closes, $balance, $display)
    }
}

Write-Host "\nFinal balance: $balance" -ForegroundColor Yellow
if ($balance -ne 0) { Write-Host "Imbalance detected (positive = more opens; negative = more closes)." -ForegroundColor Red } else { Write-Host "Braces appear balanced in this scan range." -ForegroundColor Green }
