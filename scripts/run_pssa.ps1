param(
    [string]$FilePath = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
)

if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing PSScriptAnalyzer (may require network) ...'
    Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
}

Write-Host "Running PSScriptAnalyzer on: $FilePath"
$results = Invoke-ScriptAnalyzer -Path $FilePath -Severity Warning,Error | Select-Object RuleName, Severity, ScriptName, Line, Message
if ($results) {
    $results | Format-Table -AutoSize
} else {
    Write-Host 'No issues found by PSScriptAnalyzer.' -ForegroundColor Green
}
