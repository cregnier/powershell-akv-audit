$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$s = Get-Content $path -Raw
$open = ([regex]::Matches($s, '@"', 'IgnoreCase')).Count
$close = ([regex]::Matches($s, '"@', 'IgnoreCase')).Count
Write-Output "@\" occurrences (open tokens): $open"
Write-Output '"@ occurrences (close tokens): ' + $close
# Also count single-quoted here-strings @' and '@
$open2 = ([regex]::Matches($s, "@'", 'IgnoreCase')).Count
$close2 = ([regex]::Matches($s, "'@", 'IgnoreCase')).Count
Write-Output "@' occurrences (open tokens): $open2"
Write-Output "'@ occurrences (close tokens): $close2"
# Print first mismatched occurrences context if counts differ
if ($open -ne $close -or $open2 -ne $close2) {
    Write-Output 'Mismatch detected. Showing lines with here-string tokens:'
    $lines = $s -split "\r?\n"
    for ($i=0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match '@"|"@|@\'|\'@') {
            Write-Output ("{0,6}: {1}" -f ($i+1), $lines[$i])
        }
    }
}
