$b = [System.IO.File]::ReadAllBytes('c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
if ($b.Length -ge 4) { Write-Host ($b[0..3] -join ',') } else { Write-Host 'file too small' }