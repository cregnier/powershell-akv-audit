$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
$content = Get-Content -Raw -Path $path
# Re-save as UTF8 (no BOM) to normalize encoding/line endings
Set-Content -Path $path -Value $content -Encoding utf8
Write-Host "Re-saved $path as UTF8 (no BOM)"