try {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
    }
} catch {}

$out = @()
try {
    $out = Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error -ErrorAction SilentlyContinue
} catch {
    Write-Output "Invoke-ScriptAnalyzer failed: $($_.Exception.Message)"
}

if ($out -and $out.Count -gt 0) {
    $out | Select-Object RuleName,Severity,ScriptName,Line,Message | Export-Csv -Path .\output\psscriptanalyzer_results.csv -NoTypeInformation -Encoding UTF8
    Write-Output "WROTE_RESULTS"
} else {
    Write-Output "NO_RESULTS"
}
