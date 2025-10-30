$scriptPath = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$errors = $null
$tokens = $null
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$errors, [ref]$tokens)
} catch {
    Write-Host "Parser threw an exception: $($_.Exception.Message)"
    exit 1
}

if ($errors -ne $null -and $errors.Count -gt 0) {
    Write-Host "Syntax errors found: $($errors.Count) error(s)"
    $index = 0
    foreach ($e in $errors) {
        $index++
        $msg = $e.Message
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = '<empty message>' }
        $start = if ($e.Extent) { $e.Extent.StartLine } else { '<no start>' }
        $end = if ($e.Extent) { $e.Extent.EndLine } else { '<no end>' }
        Write-Host "--- Error #$index ---"
        Write-Host "Line(s): $start - $end"
        Write-Host "Message: $msg"
        Write-Host "TokenText: $($e.Extent.Text -replace "`n", ' ')"
    }
    exit 1
} else {
    Write-Host 'Syntax valid'
    exit 0
}