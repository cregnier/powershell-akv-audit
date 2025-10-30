# Generator: produce a PS5-compatible copy of Get-AKVGapAnalysis.ps1
# Usage: pwsh -File scripts/generate-ps5-version.ps1

param(
    [string]$Source = "Get-AKVGapAnalysis.ps1",
    [string]$Destination = "Get-AKVGapAnalysis.PS5.ps1"
)

Write-Host "Reading $Source ..."
$content = Get-Content -Path $Source -Raw -ErrorAction Stop

# Define PS5 helper functions text to insert after the param block
$helpers = @"

# --- PS5 compatibility helpers inserted by generator ---
function NullCoalesce {
    param(
        [Parameter(Mandatory=$true)][object]$Left,
        [Parameter(Mandatory=$true)][object]$Right
    )
    if ($null -ne $Left) { return $Left } else { return $Right }
}

function ConvertTo-JsonCompact {
    param(
        [Parameter(Mandatory=$true)][object]$InputObject,
        [int]$Depth = 2
    )
    # Use native ConvertTo-Json then remove newlines/indentation to approximate -Compress
    try {
        $json = $InputObject | ConvertTo-Json -Depth $Depth
        return ($json -replace "(\r?\n)\s*", '')
    } catch {
        # Fallback: attempt default conversion
        $json = $InputObject | ConvertTo-Json -Depth $Depth -ErrorAction SilentlyContinue
        if ($json) { return ($json -replace "(\r?\n)\s*", '') } else { return '' }
    }
}
# --- end helpers ---

"@

# Insert helpers after the first closing parenthesis of the top-level param block.
# We'll look for the first occurrence of a line that's just ')' that closes the parameter list.
$pattern = "(?ms)^(\s*\[CmdletBinding\(\).*?^\)\s*)"
$rv = [regex]::Match($content, $pattern)
if ($rv.Success) {
    $insertPos = $rv.Index + $rv.Length
    $newContent = $content.Substring(0, $insertPos) + "`n" + $helpers + $content.Substring($insertPos)
    $content = $newContent
    Write-Host "Inserted helpers after param block."
} else {
    # Fallback: insert after the first param( occurrence end )
    $paramEnd = $content.IndexOf(')')
    if ($paramEnd -gt 0) {
        $insertPos = $paramEnd + 1
        $newContent = $content.Substring(0, $insertPos) + "`n" + $helpers + $content.Substring($insertPos)
        $content = $newContent
        Write-Host "Inserted helpers after first ')'."
    } else {
        # As last resort, prepend to file
        $content = $helpers + "`n" + $content
        Write-Host "Prepended helpers to the top of the file."
    }
}

# Replace ConvertTo-Json -Compress occurrences by ConvertTo-JsonCompact wrapper
$content = [regex]::Replace($content, "ConvertTo-Json\s+([^\n\r]+?)\s*-Compress", 'ConvertTo-JsonCompact -InputObject $1', 'IgnoreCase')
# Also handle cases like ConvertTo-Json -Depth 4 -Compress or (... | ConvertTo-Json -Depth 4 -Compress)
$content = [regex]::Replace($content, "ConvertTo-Json\s*(-Depth\s+\d+\s*)?-Compress", 'ConvertTo-JsonCompact', 'IgnoreCase')

# Iteratively replace the null-coalescing operator '??' with NullCoalesce(left,right)
$prev = $null
$iteration = 0
while ($true) {
    $iteration++
    # Match either a parenthesized expression or a contiguous non-space token as left and right operands
    $pattern2 = '(\([^)]+\)|\S+)\s*\?\?\s*(\([^)]+\)|\S+)'
    $new = [regex]::Replace($content, $pattern2, 'NullCoalesce($1,$2)')
    if ($new -eq $content) { break }
    $content = $new
    if ($iteration -gt 1000) { Write-Host "Reached replacement iteration limit"; break }
}

# Finally, also replace any '??' that may be adjacent without whitespace
$content = $content -replace '\?\?', 'NullCoalesce'  # defensive last-resort (shouldn't trigger often)

# Determine destination path (honor absolute paths)
if ([System.IO.Path]::IsPathRooted($Destination)) {
    $destPath = $Destination
} else {
    $destPath = Join-Path -Path (Get-Location) -ChildPath $Destination
}

# Ensure destination directory exists
$destDir = Split-Path -Path $destPath -Parent
if (-not (Test-Path -Path $destDir)) {
    try { New-Item -ItemType Directory -Path $destDir -Force | Out-Null } catch { }
}

Write-Host "Writing $destPath ..."
Set-Content -Path $destPath -Value $content -Encoding UTF8
Write-Host "Done. Generated $destPath"
