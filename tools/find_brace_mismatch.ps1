$lines = Get-Content -Path .\Get-AKVGapAnalysis.ps1 -Raw -ErrorAction Stop -Encoding UTF8 | Out-String -Stream
$balance = 0
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $open = ([regex]::Matches($line,'\{')).Count
    $close = ([regex]::Matches($line,'\}')).Count
    $balance += $open - $close
    if ($balance -lt 0) {
        Write-Host "Negative balance at line $($i+1): $balance"
        Write-Host "Line: $line"
        break
    }
}
Write-Host "Final balance after full file: $balance" 

# Show first 20 lines where balance changed significantly
$balance = 0
for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $open = ([regex]::Matches($line,'\{')).Count
    $close = ([regex]::Matches($line,'\}')).Count
    $newBalance = $balance + $open - $close
    if ($newBalance -ne $balance) {
        Write-Host "Line $($i+1): balance -> $newBalance    $line"
    }
    $balance = $newBalance
    if ($i -gt 4500) { break }
}