# tools/header_diff.ps1
# Extract headers from CSV files and HTML report(s), compare, and write a diff report.
param(
    [string[]] $CsvFiles = @("KeyVaultComprehensiveAudit_2025-10-13_17-10-45.csv", "KeyVaultComprehensiveAudit_2025-10-08_16-53-16.csv", "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.csv"),
    [string[]] $HtmlFiles = @("KeyVaultComprehensiveAudit_2025-10-13_17-10-45.html", "KeyVaultComprehensiveAudit_2025-10-08_16-53-16.html", "KeyVaultSingleVault_prod-skr-cloud-key-vault_20250915_123742.html"),
    [string] $ReportPath = "header_diff_report.txt"
)

Set-Location -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) | Out-Null
Set-Location -Path ".." | Out-Null

function Get-CsvHeader($path) {
    if (-not (Test-Path $path)) { return @() }
    $line = Get-Content -Path $path -TotalCount 1 -ErrorAction SilentlyContinue
    if (-not $line) { return @() }
    # Handle possible BOM and quoted headers
    $line = $line -replace "^\uFEFF", ""
    try {
        $parts = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$null, [ref]$null) | Out-Null
    } catch { }
    # Simple split by comma, but handle quoted values by using a CSV parser
    $temp = ConvertFrom-Csv -InputObject $line -ErrorAction SilentlyContinue
    if ($temp) {
        return $temp.PSObject.Properties | ForEach-Object { $_.Name }
    } else {
        return $line -split ',' | ForEach-Object { ($_ -replace '"','').Trim() }
    }
}

function Get-HtmlTableHeaders($path) {
    if (-not (Test-Path $path)) { return @() }
    $html = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
    if (-not $html) { return @() }
    # Find first table's header row <th>
    $matches = [regex]::Matches($html, '<th[^>]*>(.*?)</th>', 'Singleline')
    if ($matches.Count -gt 0) {
        return $matches | ForEach-Object { $_.Groups[1].Value.Trim() }
    }
    # fallback: look for <td> in header-like row
    $matches = [regex]::Matches($html, '<tr[^>]*>\s*(?:<td[^>]*>\s*<b>?(.*?)</b?>\s*</td>)+', 'Singleline')
    if ($matches.Count -gt 0) {
        return $matches | ForEach-Object { $_.Groups[1].Value.Trim() }
    }
    return @()
}

$report = New-Object System.Text.StringBuilder
$report.AppendLine(("Header diff report generated: " + (Get-Date).ToString('u'))) | Out-Null
$csvHeadersByFile = @{}
foreach ($csv in $CsvFiles) {
    $h = Get-CsvHeader $csv
    $csvHeadersByFile[$csv] = $h
    $report.AppendLine("CSV: $csv - Columns: $($h.Count)") | Out-Null
    $report.AppendLine(($h -join ", ")) | Out-Null
    $report.AppendLine("----") | Out-Null
}

$htmlHeadersByFile = @{}
foreach ($html in $HtmlFiles) {
    $h = Get-HtmlTableHeaders $html
    $htmlHeadersByFile[$html] = $h
    $report.AppendLine("HTML: $html - Headers: $($h.Count)") | Out-Null
    $report.AppendLine(($h -join ", ")) | Out-Null
    $report.AppendLine("----") | Out-Null
}

# Compare the first CSV (assumed 'latest' comprehensive) to the others and to first HTML
$latestCsv = $CsvFiles[0]
$latestCsvCols = $csvHeadersByFile[$latestCsv]
for ($i=0; $i -lt $CsvFiles.Count; $i++) {
    $csv = $CsvFiles[$i]
    $cols = $csvHeadersByFile[$csv]
    $missing = $cols | Where-Object { $latestCsvCols -notcontains $_ }
    $extra = $latestCsvCols | Where-Object { $cols -notcontains $_ }
    $report.AppendLine("Comparison: $csv vs $latestCsv") | Out-Null
    $report.AppendLine(" - Missing in latestCsv (present in $csv but not in $latestCsv):") | Out-Null
    $report.AppendLine(($missing -join ", `n") ) | Out-Null
    $report.AppendLine(" - Extra in latestCsv (present in $latestCsv but not in $csv):") | Out-Null
    $report.AppendLine(($extra -join ", `n")) | Out-Null
    $report.AppendLine("----") | Out-Null
}

# Compare csv to html headers
$firstHtml = $HtmlFiles[0]
$htmlCols = $htmlHeadersByFile[$firstHtml]
$missingFromHtml = $latestCsvCols | Where-Object { $htmlCols -notcontains $_ }
$report.AppendLine("Columns present in ${latestCsv} but missing from ${firstHtml}:") | Out-Null
$report.AppendLine(($missingFromHtml -join ", `n")) | Out-Null

# Write report file
$report.ToString() | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Output "Wrote report to $ReportPath"
Write-Output "Latest CSV columns: $($latestCsvCols.Count)"
Write-Output "HTML columns: $($htmlCols.Count)"
Write-Output "Columns in latest CSV not in HTML: $($missingFromHtml.Count)"

exit 0
