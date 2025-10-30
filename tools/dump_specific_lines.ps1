param(
    [string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1',
    [int[]]$Lines = @(17,996)
)
$lines = Get-Content -LiteralPath $Path
foreach ($ln in $Lines) {
    if ($ln -le $lines.Count) {
        $text = $lines[$ln-1]
        Write-Output ('--- Line {0} ---' -f $ln)
        for ($i=0; $i -lt $text.Length; $i++) {
            $ch = $text[$i]
            $code = [int][char]$ch
            Write-Output ('{0,4}:{1} 0x{2:X2}' -f ($i+1), ($ch -replace ' ', '·'), $code)
        }
        Write-Output ('Full: {0}' -f $text)
    } else {
        Write-Output ('Line {0} out of range' -f $ln)
    }
}
