$code = Get-Content -Path .\Get-AKVGapAnalysis.ps1 -Raw
try {
    [scriptblock]::Create($code) | Out-Null
    Write-Host 'ScriptBlock creation OK'
} catch {
    Write-Host 'Script parse error: ' $_.Exception.Message
    exit 1
}