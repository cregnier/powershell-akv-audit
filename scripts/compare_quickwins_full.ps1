# Compare QuickWins parity between latest CSV and HTML
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
## find latest report CSV (exclude reconciliation files)
$csv = Get-ChildItem -Path .\output -Filter 'KeyVaultGapAnalysis_*.csv' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch 'quickwins_reconciliation' -and $_.Name -match '^KeyVaultGapAnalysis_\d{4}-' } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $csv) { Write-Error "No report CSV found in ./output"; exit 2 }

# find latest report HTML (exclude policy details or other variants if any)
$html = Get-ChildItem -Path .\output -Filter 'KeyVaultGapAnalysis_*.html' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^KeyVaultGapAnalysis_\d{4}-' } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $html) { Write-Error "No report HTML found in ./output"; exit 2 }
Write-Output "Using CSV: $($csv.FullName)"
Write-Output "Using HTML: $($html.FullName)"
$rows = Import-Csv -Path $csv.FullName
$allTitles = @()
$perVault = @{}
foreach ($r in $rows) {
    $count = 0
    if ($null -ne $r.QuickWinsCount -and $r.QuickWinsCount -ne '') {
        if (-not [int]::TryParse($r.QuickWinsCount, [ref]$count)) { $count = 0 }
    }
    $perVault[$r.VaultName] = $count
    if ($r.QuickWinsSummary -and $r.QuickWinsSummary.Trim() -ne '') {
        $parts = $r.QuickWinsSummary -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($p in $parts) { $allTitles += $p }
    }
}
$unique = $allTitles | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique
# Build map of canonical title -> original casing (pick first occurrence)
$canonicalToOriginal = @{}
foreach ($title in $allTitles) {
    $key = $title.Trim().ToLowerInvariant()
    if (-not $canonicalToOriginal.ContainsKey($key)) { $canonicalToOriginal[$key] = $title.Trim() }
}
# Count occurrences
$counts = @{}
foreach ($k in $unique) { $counts[$k] = 0 }
foreach ($r in $rows) {
    if ($r.QuickWinsSummary -and $r.QuickWinsSummary.Trim() -ne '') {
        $parts = $r.QuickWinsSummary -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($p in $parts) { $counts[$p.ToLowerInvariant()] += 1 }
    }
}
# Extract reported total from HTML robustly
$htmlContent = Get-Content -Path $html.FullName -Raw
$reportedTotal = $null
## Try embedded canonical JSON first (more reliable)
try {
    $jsonMatch = [regex]::Match($htmlContent, '<script[^>]*id="canonical-quickwins"[^>]*>(?<json>[\s\S]*?)</script>', 'IgnoreCase')
    if ($jsonMatch.Success) {
        $jsonRaw = $jsonMatch.Groups['json'].Value.Trim()
        if ($jsonRaw -and $jsonRaw -ne '[]') {
            try {
                $parsed = $jsonRaw | ConvertFrom-Json -ErrorAction Stop
                if ($parsed) { $reportedTotal = ($parsed | Measure-Object).Count }
            } catch {
                # if JSON decode fails, fall back to DOM/regex extraction below
                $reportedTotal = $null
            }
        } else { $reportedTotal = 0 }
    }
} catch {
    # ignore and fallback
    $reportedTotal = $null
}

if ($reportedTotal -eq $null) {
    $labelPattern = 'Total Quick Wins Available'
    $labelIndex = $htmlContent.IndexOf($labelPattern, [System.StringComparison]::OrdinalIgnoreCase)
    if ($labelIndex -ge 0) {
        # Find the nearest preceding '<div' that likely starts the stat-card
        $cardStart = $htmlContent.LastIndexOf('<div', $labelIndex)
        if ($cardStart -ge 0) {
            # Slice from cardStart up to the labelIndex to search for the stat-number div
            $sliceLength = [math]::Max(0, $labelIndex - $cardStart + $labelPattern.Length)
            $cardSlice = $htmlContent.Substring($cardStart, $sliceLength)
            $numMatch = [regex]::Match($cardSlice, '<div[^>]*class="stat-number"[^>]*>(?<inner>[\s\S]*?)</div>', 'IgnoreCase')
            if ($numMatch.Success) {
                $inner = $numMatch.Groups['inner'].Value
                # Extract the first integer found in the inner HTML (handles spans and <br/>)
                $digit = [regex]::Match($inner, '\d+')
                if ($digit.Success) { $reportedTotal = [int]$digit.Value }
            }
        }
    }
}
if ($reportedTotal -eq $null) { Write-Warning "Could not find HTML reported total; defaulting to null" }
# Write reconciliation CSV
$outCsv = Join-Path $PSScriptRoot "..\output\KeyVaultGapAnalysis_quickwins_reconciliation_$timestamp.csv"
$rowsOut = @()
foreach ($k in $counts.Keys) {
    $rowsOut += [PSCustomObject]@{
        CanonicalTitle = $k
        Title = $canonicalToOriginal[$k]
        Count = $counts[$k]
    }
}
$rowsOut | Sort-Object -Property Count -Descending | Export-Csv -Path $outCsv -NoTypeInformation -Force
Write-Output "Reconciliation CSV written: $outCsv"
Write-Output "Parsed unique quick wins: $($counts.Keys.Count)"
if ($reportedTotal -ne $null) { Write-Output "HTML reported total quick wins: $reportedTotal" }
# Print the unique titles and counts
Write-Output "Unique QuickWins and counts:" 
foreach ($r in $rowsOut | Sort-Object -Property Count -Descending) { Write-Output " - $($r.Title) : $($r.Count)" }
# Parity check
if ($reportedTotal -ne $null) {
    if ($reportedTotal -eq $counts.Keys.Count) { Write-Output "PARITY CHECK: PASS (reported $reportedTotal == parsed $($counts.Keys.Count))"; exit 0 }
    else { Write-Warning "PARITY CHECK: FAIL (reported $reportedTotal != parsed $($counts.Keys.Count))"; exit 1 }
} else {
    Write-Warning "PARITY CHECK: HTML total not found; parsed unique count = $($counts.Keys.Count)"; exit 3
}
