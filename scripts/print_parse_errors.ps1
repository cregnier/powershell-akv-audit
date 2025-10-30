$path = Join-Path $PSScriptRoot '..\Get-AKVGapAnalysis.ps1'
$errors = [ref]$null
$tokens = [ref]$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Value) {
    $i = 0
    foreach ($e in $errors.Value) {
        $i++
        Write-Host "----------------------------------------"
        Write-Host "Error #$i"
        Write-Host "Message:"
        Write-Host $e.Message
        Write-Host "Full error object:"; $e | Format-List -Force
        Write-Host "StartLine: $($e.Extent.StartLineNumber) StartColumn: $($e.Extent.StartColumn)"
        Write-Host "EndLine: $($e.Extent.EndLineNumber) EndColumn: $($e.Extent.EndColumn)"
        Write-Host "Surrounding Text:" 
        $start = [math]::Max(1, $e.Extent.StartLineNumber - 5)
        $end = [math]::Min((Get-Content $path).Count, $e.Extent.EndLineNumber + 5)
        $lines = Get-Content $path
        for ($ln = $start; $ln -le $end; $ln++) {
            $lineText = $lines[$ln-1]
            if ($ln -ge $e.Extent.StartLineNumber -and $ln -le $e.Extent.EndLineNumber) {
                Write-Host ("{0,5}: {1}" -f $ln, $lineText)
            } else {
                Write-Host ("{0,5}: {1}" -f $ln, $lineText)
            }
        }
        # Print nearby tokens
        Write-Host "Tokens near error (first 50):"
        if ($tokens.Value) {
            $near = $tokens.Value | Where-Object { $_.Extent.StartLineNumber -ge $start -and $_.Extent.EndLineNumber -le $end }
            $near | Select-Object -First 50 | ForEach-Object { Write-Host ($_ | Format-List -Property Kind, Text, @{Name='StartLine';Expression={$_.Extent.StartLineNumber}}, @{Name='EndLine';Expression={$_.Extent.EndLineNumber}} -Force) }
        }
        if ($i -ge 10) { break }
    }
} else {
    Write-Host 'No parse errors'
}
