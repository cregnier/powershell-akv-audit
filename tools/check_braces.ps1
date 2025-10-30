$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$text = Get-Content -Raw -LiteralPath $path
$opens = ($text.ToCharArray() | Where-Object { $_ -eq '{' }).Count
$closes = ($text.ToCharArray() | Where-Object { $_ -eq '}' }).Count
Write-Host "Open braces: $opens  Close braces: $closes"

# Find here-string markers that start at line start
$lines = Get-Content -LiteralPath $path
$index = 0
foreach ($line in $lines) {
    $index++
    if ($line.TrimStart() -match '^@"$' -or $line.TrimStart() -match "^@'$") {
        Write-Host "Here-string OPEN at line $index : $line"
    }
    if ($line.TrimEnd() -match '^"@' -or $line.TrimEnd() -match "^'@") {
        Write-Host "Here-string CLOSE at line $index : $line"
    }
}

# Print first 200 lines to inspect head
Write-Host "\n-- File head (first 200 lines) --"
Get-Content -LiteralPath $path -TotalCount 200 | ForEach-Object -Begin {$ln=0} -Process { $ln++; Write-Host ("{0,4}: {1}" -f $ln, $_) }
