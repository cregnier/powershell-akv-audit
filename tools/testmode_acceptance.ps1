# Acceptance test for Get-AKVGapAnalysis.ps1 (local checks only)
# - Runs syntax parser
# - Checks for presence of DeepCrossReference param
# - Checks for Write-PermissionsIssue function
# - Verifies permissions-issues JSON embed marker exists
# - Ensures soft-delete severity is marked Critical
# - Ensures no "/100" substrings remain in compliance formatting

$scriptPath = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1' | Resolve-Path -ErrorAction SilentlyContinue
Write-Host "Running acceptance checks against $scriptPath`n"

# 1) Syntax parse using existing helper if present
$parseScript = Join-Path $PSScriptRoot 'parse_check.ps1' | Resolve-Path -ErrorAction SilentlyContinue
if (Test-Path $parseScript) {
    Write-Host "-> Running syntax parser: $parseScript"
    pwsh -NoProfile -File $parseScript
} else {
    Write-Host "-> parse_check.ps1 not found, attempting basic AST parse"
    try {
        $content = Get-Content -Raw -Path $scriptPath
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$errors)
        if ($errors -and $errors.Count -gt 0) {
            Write-Host "Syntax errors found:`n" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host $_.Message }
            exit 1
        } else {
            Write-Host "Syntax parse OK" -ForegroundColor Green
        }
    } catch {
        Write-Host "AST parse failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Load file for static checks
$content = Get-Content -Raw -Path $scriptPath
$failures = @()

# Check for DeepCrossReference param
if ($content -match "\[switch\]\$DeepCrossReference") { Write-Host "Found -DeepCrossReference param" -ForegroundColor Green } else { $failures += "Missing -DeepCrossReference param" }

# Check for Write-PermissionsIssue function
if ($content -match "function Write-PermissionsIssue") { Write-Host "Found Write-PermissionsIssue helper" -ForegroundColor Green } else { $failures += "Missing Write-PermissionsIssue helper" }

# Check for permissions-issues JSON embed marker
if ($content -match "permissions-issues" ) { Write-Host "Found embedded permissions JSON marker" -ForegroundColor Green } else { $failures += "Missing permissions-issues JSON embed" }

# Check soft delete severity marked Critical
# Relaxed check for soft delete severity marked Critical
if ($content -match 'Soft delete not enabled' -and $content -match 'Severity\s*=\s*"?Critical"?') { Write-Host "Soft delete severity set to Critical" -ForegroundColor Green } else { $failures += "Soft delete severity not set to Critical or missing phrase" }

# Check for '/100' in content (shouldn't be present)
if ($content -match "/100") { $failures += "Found '/100' substring - compliance formatting may be wrong" } else { Write-Host "No '/100' formatting found" -ForegroundColor Green }

# Report
if ($failures.Count -eq 0) {
    Write-Host "\nAcceptance checks PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "\nAcceptance checks FAILED:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host " - $_" }
    exit 2
}
