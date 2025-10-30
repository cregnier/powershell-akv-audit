# Generates a PowerShell 5.1 compatible copy of Get-AKVGapAnalysis.ps1
# - inserts NullCoalesce and ConvertTo-JsonCompact helpers
# - replaces uses of the ?? operator with NullCoalesce(...)
# - replaces ConvertTo-Json ... -Compress with ConvertTo-JsonCompact

param(
    [string]$SourcePath = "./Get-AKVGapAnalysis.ps1",
    [string]$DestPath = "./Get-AKVGapAnalysis.PS5.ps1",
    [switch]$Overwrite
)

if (-not (Test-Path $SourcePath)) { Write-Error "Source file not found: $SourcePath"; exit 2 }

$raw = Get-Content -Raw -Path $SourcePath -ErrorAction Stop

# Helper block to insert (PS5-compatible)
$helpers = @'

# --- Compatibility helpers for PowerShell 5.1 ---
function NullCoalesce {
    param(
        [Parameter(Mandatory=$true)][object]$Left,
        [Parameter(Mandatory=$true)][object]$Right
    )
    if ($null -ne $Left) { return $Left } else { return $Right }
}

function ConvertTo-JsonCompact {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][object]$InputObject,
        [int]$Depth = 2
    )
    # Use built-in ConvertTo-Json then remove newlines/indentation to approximate -Compress
    $json = $InputObject | ConvertTo-Json -Depth $Depth
    if ($null -eq $json) { return $json }
    # Remove indentation/newlines but keep structural characters. This keeps content safe for embedding.
    return ($json -replace "(\r?\n)\s*", '')
}

# --- End compatibility helpers ---
'@

# Find insertion point: after the param(...) block. We'll look for the first occurrence of "# Script configuration" or ")`r?\n\s*# Script configuration"
$insertPos = $null
$pattern = "\)\s*\r?\n\s*# Script configuration"
if ($raw -match $pattern) {
    $matches = [regex]::Matches($raw, $pattern)
    $m = $matches[0]
    $insertIndex = $m.Index
    # Insert helpers just before the '# Script configuration' comment so they are defined early
    $newContent = $raw.Substring(0,$insertIndex) + "`n" + $helpers + "`n" + $raw.Substring($insertIndex)
} else {
    # Fallback: insert after the param(...) closing parenthesis by finding the first occurrence of "\)\r?\n\r?\n"
    $pattern2 = "\)\s*\r?\n\s*\r?\n"
    if ($raw -match $pattern2) {
        $m2 = [regex]::Matches($raw, $pattern2)[0]
        $insertIndex = $m2.Index + $m2.Length
        $newContent = $raw.Substring(0,$insertIndex) + "`n" + $helpers + "`n" + $raw.Substring($insertIndex)
    } else {
        # As last resort, put helpers at top
        $newContent = $helpers + "`n" + $raw
    }
}

# Replace ConvertTo-Json ... -Compress occurrences: we will transform lines that include both 'ConvertTo-Json' and '-Compress'
# Strategy: for any line that contains both, replace 'ConvertTo-Json' with 'ConvertTo-JsonCompact' and remove '-Compress'
$newContent = (( $newContent -split "\r?\n" ) | ForEach-Object {
    $line = $_
    if ($line -match "ConvertTo-Json" -and $line -match "-Compress") {
        $line = $line -replace "ConvertTo-Json", "ConvertTo-JsonCompact"
        $line = $line -replace "-Compress", ""
    }
    $line
}) -join "`n"

# Replace '??' operator usages iteratively with NullCoalesce(...) - best-effort
# We perform multiple passes, replacing simple patterns like: (<expr>) ?? (<expr>) or <token> ?? <token>
$passes = 0
while ($newContent -match '\?\?' -and $passes -lt 50) {
    $passes++
    # pattern matches either parenthesized expr or token, whitespace, ??, whitespace, parenthesized expr or token
    $patternCoalesce = '((?:\([^\)]*\)|[^\s\(\)\[\];,]+))\s*\?\?\s*((?:\([^\)]*\)|[^\s\(\)\[\];,]+))'
    $newContent = [regex]::Replace($newContent, $patternCoalesce, 'NullCoalesce($1,$2)')
}

# Tidy: remove any leftover multiple spaces introduced and trim trailing spaces for lines
$newContent = (( $newContent -split "\r?\n" ) | ForEach-Object { $_ -replace '\s+$','' }) -join "`n"

# Post-processing fixes: common malformed patterns introduced by blind text-replace
# Fix cases where a cast like "-as [type]" was transformed into "-as NullCoalesce([type])"
try {
    $newContent = [regex]::Replace($newContent, '-as\s+NullCoalesce\(\s*(\[[^\]]+\])\s*\)', '-as $1')
    # Also handle cases with an extra wrapping paren: -as NullCoalesce(([type])) -> -as [type]
    $newContent = [regex]::Replace($newContent, '-as\s+NullCoalesce\(\s*\(\s*(\[[^\]]+\])\s*\)\s*\)', '-as $1')
} catch {
    # non-fatal; keep original content if regex fails
}

# Ensure destination directory exists and handle absolute/relative paths robustly
$destPathResolved = $null
try {
    $destParent = Split-Path -Path $DestPath -Parent
    if ($destParent -and -not (Test-Path $destParent)) {
        New-Item -ItemType Directory -Path $destParent -Force | Out-Null
    }
} catch {
    # ignore errors creating directory; Set-Content will fail if path invalid
}

if ((Test-Path -Path $DestPath -PathType Leaf) -and (-not $Overwrite)) {
    Write-Error "Destination exists: $DestPath (use -Overwrite to replace)"; exit 3
}

Set-Content -Path $DestPath -Value $newContent -Encoding UTF8
Write-Host "Generated PS5-compatible file: $DestPath (passes: $passes)"

# Fallback: if any '??' remain (complex expressions not matched by the first pattern),
# perform a more permissive iterative replacement as a last resort. This tries to
# convert remaining 'A ?? B' into 'NullCoalesce(A,B)' when they occur on the same
# logical line (not across semicolons/newlines).
try {
    $fb = 0
    while ($newContent -match '\?\?' -and $fb -lt 20) {
        $fb++
        $patternFallback = '([^\r\n;]+?)\s*\?\?\s*([^\r\n;]+?)'
        $newContent = [regex]::Replace($newContent, $patternFallback, 'NullCoalesce($1,$2)')
    }
    if ($fb -gt 0) { Write-Host "Fallback coalesce passes: $fb" }
    # Re-run cast-fix in case casting patterns were touched by fallback replacement
    $newContent = [regex]::Replace($newContent, '-as\s+NullCoalesce\(\s*(\[[^\]]+\])\s*\)', '-as $1')
    $newContent = [regex]::Replace($newContent, '-as\s+NullCoalesce\(\s*\(\s*(\[[^\]]+\])\s*\)\s*\)', '-as $1')
} catch {
    # ignore fallback errors; final output may still require manual inspection
}

# Final conservative pass: catch remaining patterns where a parenthesized expression is followed by '??'
# Example: '...)) ?? 0' -> 'NullCoalesce(...),0)' -> produce 'NullCoalesce(<left>, <right>)'
try {
    $finalFb = 0
    while ($newContent -match '\?\?' -and $finalFb -lt 10) {
        $finalFb++
        $patternFinal = '([^\r\n;]+?\))\s*\?\?\s*([^\r\n;]+?)'
        $newContent = [regex]::Replace($newContent, $patternFinal, 'NullCoalesce($1,$2)')
    }
    if ($finalFb -gt 0) { Write-Host "Final coalesce passes: $finalFb" }
    # Re-apply cast-fix one more time
    $newContent = [regex]::Replace($newContent, '-as\s+NullCoalesce\(\s*(\[[^\]]+\])\s*\)', '-as $1')
} catch {
    # swallow
}

# Line-level conservative fix: if any remaining '??' appear on a single line (simple assignments or expressions),
# replace that line with a direct NullCoalesce(<left>,<right>) form. This is a last-resort heuristic for lines
# where the operator spans simple expressions and should be safe for the small number of remaining cases.
try {
    $lines = $newContent -split "\r?\n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        if ($ln -match '\?\?') {
            # Skip commented lines
            if ($ln -match '^\s*#') { continue }
            # Prefer preserving assignments: replace 'LHS = RHS ?? ALT' -> 'LHS = NullCoalesce(RHS, ALT)'
            $replAssign = [regex]::Replace($ln, '^(\s*[^=]+?=\s*)(.+?)\s*\?\?\s*(.+)$', '$1NullCoalesce($2,$3)')
            if ($replAssign -ne $ln) { $lines[$i] = $replAssign; continue }
            # Fallback: replace entire expression on the line (less safe)
            $repl = [regex]::Replace($ln, '^\s*(.+?)\s*\?\?\s*(.+)$', 'NullCoalesce($1,$2)')
            if ($repl -ne $ln) { $lines[$i] = $repl }
        }
    }
    $newContent = $lines -join "`n"
} catch {
    # non-fatal
}

# Assignment-aware replacement (multiline): convert lines like
#    "    $var = (<expr>) ?? <alt>"
# to
#    "    $var = NullCoalesce((<expr>),<alt>)"
try {
    $assignPattern = '(?m)^(\s*[^=\r\n]+=\s*)(.+?)\s*\?\?\s*(.+)$'
    $newContent = [regex]::Replace($newContent, $assignPattern, '$1NullCoalesce($2,$3)')
} catch {
    # ignore
}
