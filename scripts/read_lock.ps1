$p = Join-Path $env:TEMP 'akv_gap_analysis_running.lock'
if (Test-Path $p) {
    Write-Output "Lock file found at: $p"
    try { Get-Content -Path $p -Raw } catch { Write-Output "Failed to read lock file: $($_.Exception.Message)" }
} else {
    Write-Output "Lock file not found at: $p"
}

# Also attempt to parse JSON metadata if present and print fields
try {
    $raw = Get-Content -Path $p -Raw -ErrorAction SilentlyContinue
    if ($raw -and $raw.Trim() -ne '') {
        try {
            $meta = $raw | ConvertFrom-Json -ErrorAction Stop
            Write-Output "\nParsed lock metadata:" 
            $meta | Format-List | Out-String | Write-Output
        } catch {
            Write-Output "\nLock file is not JSON or failed to parse as JSON. Raw length: $($raw.Length)"
        }
    }
} catch { }

# Also show a base64 preview of the raw bytes (first 1024 bytes)
try {
    $bytes = [System.IO.File]::ReadAllBytes($p)
    Write-Output "\nLock file byte length: $($bytes.Length)"
    $preview = if ($bytes.Length -gt 1024) { $bytes[0..1023] } else { $bytes }
    $b64 = [System.Convert]::ToBase64String($preview)
    Write-Output "Base64 preview (first up to 1024 bytes):"
    Write-Output $b64
} catch { }
