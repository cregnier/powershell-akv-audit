# Quick artifact checks for current run
Write-Host "=== Lock file check ==="
$lock = 'C:\Users\cregnier\AppData\Local\Temp\akv_gap_analysis_running.lock'
if (Test-Path $lock) {
    Get-Item $lock | Format-List FullName,Length,LastWriteTime
    if ((Get-Item $lock).Length -gt 0) {
        Write-Host "---- Lock content (first 1000 chars) ----"
        $c = Get-Content $lock -Raw -ErrorAction SilentlyContinue
        if ($c) { Write-Host $c.Substring(0, [math]::Min(1000, $c.Length)) }
    } else { Write-Host "(lock file is empty)" }
} else { Write-Host "No lock file found at: $lock" }

Write-Host "`n=== final_coercion_diag files (workspace & temp) ==="
Get-ChildItem -Path . -Filter 'final_coercion_diag_*.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ForEach-Object { Write-Host $_.FullName }
Get-ChildItem -Path $env:TEMP -Filter 'final_coercion_diag_*.txt' -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ForEach-Object { Write-Host $_.FullName }

Write-Host "`n=== Recent per-vault JSONs (last 60 minutes) ==="
Get-ChildItem -Path . -Include '*.json' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-60) } | Select-Object FullName,Length,LastWriteTime | ForEach-Object { Write-Host $_.FullName }

Write-Host "`n=== Recent CSVs (top 10 by LastWriteTime) ==="
Get-ChildItem -Path . -Include '*.csv' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName,Length,LastWriteTime | ForEach-Object { Write-Host $_.FullName $_.LastWriteTime }

Write-Host "`n=== pwsh processes running with Get-AKVGapAnalysis.ps1 in command line (if any) ==="
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and $_.CommandLine -match 'Get-AKVGapAnalysis.ps1' } | Select-Object ProcessId,CommandLine,CreationDate | ForEach-Object { Write-Host "PID:$($_.ProcessId) Created:$($_.CreationDate)"; Write-Host $_.CommandLine }
} catch { Write-Host "Process inspection failed: $($_.Exception.Message)" }

Write-Host "`n=== End of checks ==="
