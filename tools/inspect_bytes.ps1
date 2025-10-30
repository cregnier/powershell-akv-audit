#!/usr/bin/env pwsh
$p = 'c:\Source\Github\powershell-akv-audit\Get-AKV_Roles-SecAuditCompliance.ps1'
$b = [System.IO.File]::ReadAllBytes($p)
Write-Host "Length: $($b.Length)"
$first = $b[0..([math]::Min(31,$b.Length-1))]
$hex = ($first | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host "First bytes (hex): $hex"
$s = [System.Text.Encoding]::UTF8.GetString($b,0,[math]::Min(800,$b.Length))
Write-Host "\nFirst 800 chars (interpreted as UTF8):\n"
Write-Host $s
