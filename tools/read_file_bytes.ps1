$path = 'c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1'
if (-not (Test-Path $path)) { Write-Error "File not found: $path"; exit 2 }
$bytes = [System.IO.File]::ReadAllBytes($path)
Write-Host "File length: $($bytes.Length) bytes"
$first = $bytes[0..([math]::Min(31,$bytes.Length-1))]
Write-Host "First bytes (hex):"
$first | ForEach-Object { Write-Host -NoNewline ("{0:X2} " -f $_) }
Write-Host "`nBOM detection:"
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { Write-Host "UTF-8 BOM (EF BB BF)" }
elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { Write-Host "UTF-16 LE BOM (FF FE)" }
elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { Write-Host "UTF-16 BE BOM (FE FF)" }
elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) { Write-Host "UTF-32 LE BOM (FF FE 00 00)" }
elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) { Write-Host "UTF-32 BE BOM (00 00 FE FF)" }
else { Write-Host "No BOM detected or unknown" }
# print first 8 characters interpreting as UTF8 and UTF16LE
try { $sUtf8 = [System.Text.Encoding]::UTF8.GetString($first); Write-Host "As UTF8 sample: $sUtf8" } catch {}
try { $sUtf16 = [System.Text.Encoding]::Unicode.GetString($first); Write-Host "As UTF16LE sample: $sUtf16" } catch {}
