param(
    [string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1',
    [int[]]$Lines = @(1..40)
)
$lines = Get-Content -LiteralPath $Path
foreach ($ln in $Lines) {
    if ($ln -le $lines.Count) {
        $text = $lines[$ln-1]
    Write-Host ('Line {0}: {1}' -f $ln, $text)
        for ($i=0; $i -lt $text.Length; $i++) {
            $ch = $text[$i]
            $code = [int][char]$ch
            Write-Host (" {0,3}:{1} '0x{2:X2}'" -f ($i+1), ($ch -replace ' ', '·'), $code) -NoNewline
            if (($i+1) % 8 -eq 0) { Write-Host }
        }
        Write-Host "\n"
    }
}
