$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
[byte[]]$b = [System.IO.File]::ReadAllBytes($path)
$take = if ($b.Length -gt 8) { 0..7 } else { 0..($b.Length-1) }
Write-Output ($take | ForEach-Object { '0x' + '{0:X2}' -f $b[$_] } ) -join ' '
Write-Output ("Length: {0}" -f $b.Length)
