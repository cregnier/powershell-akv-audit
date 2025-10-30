. "c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1"
if (Get-Command -Name Invoke-GapAnalysis -ErrorAction SilentlyContinue) { Write-Host 'INVOKE_AVAILABLE' } else { Write-Host 'INVOKE_NOT_AVAILABLE' }
