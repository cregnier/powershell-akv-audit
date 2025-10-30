param([string]$FilePath)

$lines = Get-Content -Path $FilePath -ErrorAction Stop -Encoding UTF8
$index = 0
foreach ($line in $lines) {
    $index++
    # Detect here-string start (line contains @" or @') but is not the terminator line
    if (($line -match '@"' -or $line -match "@'") -and -not ($line -match '^"@\s*$' -or $line -match "^'@\s*$")) {
        Write-Host ("HERE-START " + $index + ": " + $line)
    }
    # Detect here-string terminator (line that is exactly '"@' or "'@")
    if ($line -match '^"@\s*$' -or $line -match "^'@\s*$") {
        Write-Host ("HERE-END   " + $index + ": " + $line)
    }
}
