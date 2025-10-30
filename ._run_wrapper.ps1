Set-Location 'c:\Source\Github\powershell-akv-audit'
# Call the main script with TestMode
& .\Get-AKVGapAnalysis.ps1 -TestMode -Limit 1 -SuppressAzureWarnings
