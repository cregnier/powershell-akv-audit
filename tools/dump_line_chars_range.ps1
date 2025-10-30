param([int]$Start=5688,[int]$End=5698,[string]$Path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$lines = Get-Content -LiteralPath $Path
$total = $lines.Count
if ($Start -lt 1) { $Start = 1 }
if ($End -gt $total) { $End = $total }
for ($i = $Start; $i -le $End; $i++) {
    $l = $lines[$i-1]
    Write-Output ("{0,5}: {1}" -f $i, $l)
    $chars = @()
    $pos = 1
    foreach ($c in $l.ToCharArray()) {
        $chars += ("{0}:{1} (0x{2:X2})" -f $pos, $c, [int][char]$c)
        $pos++
    }
    Write-Output ($chars -join ' | ')
    Write-Output '---'
}
