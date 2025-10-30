param([string]$Path='c:\Source\Github\powershell-akv-audit\Get-AKVGapAnalysis.ps1')
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
$allTries = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }, $true)
Write-Output ("Found {0} Try statements" -f $allTries.Count)
foreach ($t in $allTries) {
    $start = $t.Extent.StartLineNumber
    $end = $t.Extent.EndLineNumber
    $catchCount = $t.CatchClauses.Count
    $hasFinally = ($t.FinallyClause -ne $null)
    Write-Output ("Try at {0}-{1}: Catches={2}, Finally={3}" -f $start, $end, $catchCount, $hasFinally)
}
