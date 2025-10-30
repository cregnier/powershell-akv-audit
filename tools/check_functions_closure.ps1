$src = Get-Content -Path .\Get-AKVGapAnalysis.ps1 -Raw -ErrorAction Stop
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) { Write-Host "Parse errors present: $($errors.Count)" }

$stack = @()
$awaitingFunctionLCurly = $false
$currentFunctionName = $null

for ($i=0; $i -lt $tokens.Count; $i++) {
    $t = $tokens[$i]
    switch ($t.Kind) {
        'Function' {
            # look ahead for name token
            $name = ''
            if ($i+1 -lt $tokens.Count) {
                $next = $tokens[$i+1]
                $name = $next.Text
            }
            $awaitingFunctionLCurly = $true
            $currentFunctionName = $name
        }
        'LCurly' {
            if ($awaitingFunctionLCurly) {
                $stack += [pscustomobject]@{ Type='Function'; Name=$currentFunctionName; StartLine=$t.Extent.StartLineNumber }
                $awaitingFunctionLCurly = $false
                $currentFunctionName = $null
            } else {
                $stack += [pscustomobject]@{ Type='Block'; Name=''; StartLine=$t.Extent.StartLineNumber }
            }
        }
        'RCurly' {
            if ($stack.Count -gt 0) { $popped = $stack[-1]; $stack = $stack[0..($stack.Count-2)] } else { Write-Host "Unbalanced RCurly at line $($t.Extent.StartLineNumber)" }
        }
    }
}

if ($stack.Count -eq 0) { Write-Host "All blocks closed by end of file" } else {
    Write-Host "Open blocks at EOF: $($stack.Count)"
    foreach ($s in $stack) { Write-Host "$($s.Type) $($s.Name) started at line $($s.StartLine)" }
}

# Now find open blocks at line 4401
$lineThreshold = 4401
$stack = @(); $awaitingFunctionLCurly = $false; $currentFunctionName = $null
for ($i=0; $i -lt $tokens.Count; $i++) {
    $t = $tokens[$i]
    if ($t.Extent.StartLineNumber -gt $lineThreshold) { break }
    switch ($t.Kind) {
        'Function' {
            $name = ''
            if ($i+1 -lt $tokens.Count) { $name = $tokens[$i+1].Text }
            $awaitingFunctionLCurly = $true; $currentFunctionName = $name
        }
        'LCurly' {
            if ($awaitingFunctionLCurly) {
                $stack += [pscustomobject]@{ Type='Function'; Name=$currentFunctionName; StartLine=$t.Extent.StartLineNumber }
                $awaitingFunctionLCurly = $false; $currentFunctionName = $null
            } else {
                $stack += [pscustomobject]@{ Type='Block'; Name=''; StartLine=$t.Extent.StartLineNumber }
            }
        }
        'RCurly' {
            if ($stack.Count -gt 0) { $stack = $stack[0..($stack.Count-2)] } else { Write-Host "Unbalanced } before line $lineThreshold at token line $($t.Extent.StartLineNumber)" }
        }
    }

Write-Host ([string]::Format("\nOpen blocks at line {0}: {1}", $lineThreshold, $stack.Count))
foreach ($s in $stack) { Write-Host ([string]::Format("{0} {1} started at line {2}", $s.Type, $s.Name, $s.StartLine)) }
