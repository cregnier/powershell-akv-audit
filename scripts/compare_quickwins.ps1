$csvPath = "$(Join-Path $PSScriptRoot '..\output\KeyVaultGapAnalysis_2025-10-22_16-51-22.csv')"
if (-not (Test-Path $csvPath)) { Write-Error "CSV not found: $csvPath"; exit 2 }
$rows = Import-Csv -Path $csvPath
$sumQuickWins = 0
$allTitles = @()
foreach ($r in $rows) {
    $count = 0
    if ($null -ne $r.QuickWinsCount -and $r.QuickWinsCount -ne '') {
        if ([int]::TryParse($r.QuickWinsCount, [ref]$count)) { $sumQuickWins += $count } else { $count = 0 }
    }
    if ($r.QuickWinsSummary -and $r.QuickWinsSummary.Trim() -ne '') {
        $parts = $r.QuickWinsSummary -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $allTitles += $parts
    }
}
$unique = $allTitles | Sort-Object -Unique
Write-Output "Rows: $($rows.Count)"
Write-Output "Sum of QuickWinsCount (CSV column): $sumQuickWins"
Write-Output "Parsed QuickWinsSummary entries (total): $($allTitles.Count)"
Write-Output "Unique QuickWins count (parsed titles): $($unique.Count)"
Write-Output "Unique QuickWins titles:"
$unique | ForEach-Object { Write-Output " - $_" }
Write-Output "Per-vault QuickWinsCount:" 
$rows | ForEach-Object { Write-Output " - $($_.VaultName): $($_.QuickWinsCount)" }
# Simple parity check vs HTML reported value (4) - adjust if needed
$reportedHtmlTotal = 4
if ($unique.Count -eq $reportedHtmlTotal) { Write-Output "PARITY CHECK: PASS (unique quick wins == $reportedHtmlTotal)" } else { Write-Output "PARITY CHECK: FAIL (unique quick wins != $reportedHtmlTotal)"; exit 1 }
