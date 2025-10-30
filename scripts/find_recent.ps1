param(
    [int]$Minutes = 60
)
$cutoff = (Get-Date).AddMinutes(-$Minutes)
Write-Host "Files modified since: $cutoff`n"
Get-ChildItem -Path . -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cutoff } | Sort-Object LastWriteTime -Descending | Select-Object FullName,Length,LastWriteTime | ForEach-Object { Write-Host "$(($_.LastWriteTime).ToString('s'))  $($_.FullName)" }
