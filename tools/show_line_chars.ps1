param(
    [string]$Path = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1',
    [int]$StartLine = 574,
    [int]$EndLine = 590
)
$lines = Get-Content -LiteralPath $Path -ErrorAction Stop
for ($i=$StartLine; $i -le $EndLine; $i++) {
    $line = $lines[$i-1]
    Write-Host ("Line {0}: '{1}'" -f $i, $line)
    $chars = $line.ToCharArray()
    $out = $chars | ForEach-Object { '{0} U+{1:X4}' -f $_, [int]$_ }
    Write-Host ($out -join ' | ')
    Write-Host ""
}
