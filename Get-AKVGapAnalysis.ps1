<#
.SYNOPSIS
    Azure Key Vault Gap Analysis Script - Enterprise Security & Compliance Assessment

.DESCRIPTION
    Performs comprehensive enterprise-grade gap analysis of Azure Key Vault security posture across subscriptions.
    This script provides detailed security assessments, compliance scoring, and actionable recommendations
    for improving Key Vault security, operational excellence, and regulatory compliance.

    KEY FEATURES:
    - Multi-subscription Key Vault inventory with comprehensive diagnostics tracking
    - Advanced security gap identification with risk prioritization and red flag detection
    - Quick wins identification with prescriptive security recommendations
    - Deep Azure platform integration assessment (RBAC, Azure Policy, Event Hubs, Log Analytics, Managed Identities)
    - Complete Key Vault configuration analysis (networking, access control, encryption, monitoring)
    - Interactive HTML report generation with detailed insights and compliance frameworks
    - Real-time CSV data export with incremental processing capabilities
    - Parallel processing support for large-scale enterprise environments
    - Resume capability for interrupted long-running assessments
    - Comprehensive logging with multiple output formats (HTML, CSV, LOG, JSON)

    RUN LOCK MECHANISMS:
    The script implements sophisticated run lock mechanisms to prevent concurrent executions:
    - Global flag ($global:AkvGapAnalysis_InProcessRun) prevents nested invocations
    - Process ID tracking for cross-session detection
    - Force parameter (-Force) allows override of safety locks when needed
    - Environment variable bypass (AKV_FORCE_BYPASS_LOCK=1) for advanced scenarios
    - Automatic lock cleanup on successful completion or graceful shutdown

    OUTPUT FILES:
    - KeyVaultGapAnalysis_[timestamp].html - Interactive executive summary report
    - KeyVaultGapAnalysis_[timestamp].csv - Detailed vault data with 50+ columns
    - KeyVaultGapAnalysis_RunLog_[timestamp].log - Comprehensive operation tracking
    - KeyVaultGapAnalysis_[timestamp].log - Standard execution log
    - KeyVaultGapAnalysis_errors_[timestamp].log - Error tracking and diagnostics
    - KeyVaultGapAnalysis_permissions_[timestamp].log - Access permission issues
    - KeyVaultGapAnalysis_dataissues_[timestamp].log - Data collection problems
    - Per-vault JSON files for detailed analysis and API integration

    COMPLIANCE FRAMEWORKS:
    - CIS Azure Foundations Benchmark v2.0
    - NIST Cybersecurity Framework (CSF)
    - ISO 27001 Information Security Standard
    - Microsoft Azure Security Baseline
    - Custom composite scoring methodology

.PARAMETER TestMode
    Enables test mode for validation and limited execution. Limits processing to a small number of vaults
    and provides detailed logging for troubleshooting. Use with -Limit parameter for controlled testing.

.PARAMETER Limit
    Maximum number of vaults to analyze when TestMode is enabled. Default is 10.
    Higher limits provide more comprehensive test coverage but increase execution time.

.PARAMETER SubscriptionId
    Specific Azure subscription ID to analyze. If not provided, analyzes all accessible subscriptions.
    Useful for targeted assessments or when working with specific subscription scopes.

.PARAMETER OutputDirectory
    Custom output directory for reports and logs. Defaults to ~/Documents/KeyVaultGapAnalysis/.
    Must be writable and have sufficient space for large enterprise assessments.

.PARAMETER SuppressAzureWarnings
    Suppresses Azure PowerShell module warnings during execution. Recommended for cleaner output
    in automated environments.

.PARAMETER SingleVault
    Analyze only a single specified vault instead of all vaults in the subscription.
    Must be used with -VaultName parameter.

.PARAMETER VaultName
    Name of the specific vault to analyze when SingleVault is enabled.
    Required when using -SingleVault parameter.

.PARAMETER SubscriptionName
    Display name of the subscription to analyze (alternative to SubscriptionId).
    Useful when subscription ID is not known but display name is available.

.PARAMETER UseParallelProcessing
    Enables parallel processing of vaults for improved performance on large environments.
    Automatically respects run lock mechanisms to prevent conflicts.

.PARAMETER MaxParallelJobs
    Maximum number of parallel jobs when UseParallelProcessing is enabled. Default is 4.
    Higher values improve performance but increase Azure API load and memory usage.

.PARAMETER Resume
    Resumes a previously interrupted analysis from the last checkpoint.
    Automatically detects and restores state from checkpoint.json file.

.PARAMETER SuppressModuleWarnings
    Suppresses PowerShell module loading warnings during execution.
    Recommended for production environments with stable module configurations.

.PARAMETER AutoInstallModules
    Automatically installs required Azure PowerShell modules if not present.
    Requires internet access and may take 5-15 minutes for initial setup.

.PARAMETER NoRunLock
    Disables run lock checking, allowing multiple instances to run simultaneously.
    WARNING: May cause duplicate work, race conditions, and resource conflicts.
    Only use for testing or when you fully understand the implications.

.PARAMETER Force
    Forces execution even when run locks or other safety checks would prevent it.
    Overrides safety mechanisms for emergency situations or controlled testing.

.PARAMETER DeepCrossReference
    Enables deep cross-referencing of Azure resources for comprehensive analysis.
    Inspects runbook content and function app settings for Key Vault references.
    Significantly increases execution time and API calls.

.PARAMETER SimulateInterruptAfter
    For testing purposes only. Simulates a CTRL-C interrupt after processing N vaults.
    Used for testing resume functionality and graceful shutdown handling.

.PARAMETER FinalCoercionTimeoutSeconds
    Timeout in seconds for final data coercion operations. Default is 0 (no timeout).
    Used for long-running data processing in large enterprise environments.

.PARAMETER FinalCoercionHeartbeatSeconds
    Heartbeat interval in seconds for long-running coercion operations.
    Provides progress feedback during extended processing operations.

.PARAMETER IncludeFunctionApps
    Includes Azure Function Apps in the platform assessment.
    Adds function app discovery and Key Vault reference analysis.

.PARAMETER AKV_HTML_ONLY
    Internal parameter for HTML-only report generation in child processes.
    Used by the script's internal HTML generation mechanisms.

.PARAMETER AKV_HTML_DATA_PATH
    Internal parameter specifying data file path for HTML generation.
    Part of the child process HTML generation workflow.

.PARAMETER AKV_HTML_PLATFORM_PATH
    Internal parameter specifying platform assessment file path for HTML generation.
    Used for integrating platform data into HTML reports.

.PARAMETER AKV_HTML_OUTPUT_PATH
    Internal parameter specifying output path for HTML report generation.
    Defines where child process HTML reports are written.

.EXAMPLE
    # Basic test mode execution
    .\Get-AKVGapAnalysis.ps1 -TestMode -Limit 3

.EXAMPLE
    # Full production scan of all subscriptions
    .\Get-AKVGapAnalysis.ps1

.EXAMPLE
    # Analyze specific subscription with custom output directory
    .\Get-AKVGapAnalysis.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputDirectory "C:\Reports"

.EXAMPLE
    # Single vault analysis with parallel processing
    .\Get-AKVGapAnalysis.ps1 -SingleVault -VaultName "my-keyvault" -SubscriptionId "12345678-1234-1234-1234-123456789012" -UseParallelProcessing

.EXAMPLE
    # Resume interrupted analysis
    .\Get-AKVGapAnalysis.ps1 -Resume

.EXAMPLE
    # Enterprise-scale analysis with all features enabled
    .\Get-AKVGapAnalysis.ps1 -UseParallelProcessing -MaxParallelJobs 8 -DeepCrossReference -IncludeFunctionApps -AutoInstallModules

.EXAMPLE
    # Force execution bypassing safety locks (use with caution)
    .\Get-AKVGapAnalysis.ps1 -Force -NoRunLock

.EXAMPLE
    # Quiet mode with suppressed warnings
    .\Get-AKVGapAnalysis.ps1 -TestMode -SuppressAzureWarnings -SuppressModuleWarnings

.NOTES
    REQUIREMENTS:
    - PowerShell 7.x or higher (recommended for parallel processing)
    - Azure PowerShell modules: Az.Accounts, Az.KeyVault, Az.Resources, Az.Monitor, Az.Security
    - Azure authentication with appropriate permissions (Reader role minimum)
    - Sufficient disk space for output files (HTML reports can be 100MB+ for large environments)

    PERMISSIONS REQUIRED:
    - Reader role at subscription or management group level (recommended)
    - Key Vault Reader role for Key Vault access
    - Monitoring Reader role for diagnostics access
    - Directory Readers role in Azure AD for identity analysis
    - Additional roles may be needed for deep cross-referencing

    EXECUTION TIME GUIDELINES:
    - Test mode (3-5 vaults): 5-15 minutes
    - Small organization (10-50 vaults): 30-60 minutes
    - Medium organization (50-200 vaults): 2-4 hours
    - Large organization (200-1000 vaults): 4-8 hours
    - Enterprise (1000+ vaults): 8+ hours (consider parallel processing)

    RUN LOCK SAFETY:
    The script prevents accidental concurrent executions that could cause:
    - Duplicate API calls and Azure throttling
    - Race conditions in output file writing
    - Inconsistent checkpoint state
    - Resource conflicts in parallel processing

    Use -Force or -NoRunLock only when you understand the risks and have implemented
    external coordination mechanisms.

    TROUBLESHOOTING:
    - Check KeyVaultGapAnalysis_RunLog_[timestamp].log for detailed execution tracing
    - Review KeyVaultGapAnalysis_errors_[timestamp].log for API failures
    - Use -TestMode -Limit 1 for initial validation
    - Enable -AutoInstallModules if module errors occur

    DOCUMENTATION:
    - README.md - Main repository documentation and setup guide
    - requirements.md - Detailed requirements and prerequisites
    - AUDIT_SUMMARY.md - Audit methodology and approach documentation
    - COMPREHENSIVE_AUDIT_FIXES.md - Technical implementation details
    - ENHANCED_WORKLOAD_ANALYSIS_GUIDE.md - Advanced analysis techniques
    - DiagnosticSettingsGuide.md - Monitoring and diagnostics setup

    SUPPORT:
    For issues, feature requests, or contributions, please refer to the repository documentation
    or create an issue in the project repository.

    VERSION: This script follows semantic versioning. Current version: enterprise-edition
    LAST UPDATED: October 2025
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][switch]$TestMode,
    [Parameter(Mandatory = $false)][int]$Limit = 10,
    [Parameter(Mandatory = $false)][string]$SubscriptionId,
    [Parameter(Mandatory = $false)][string]$OutputDirectory,
    [Parameter(Mandatory = $false)][switch]$SuppressAzureWarnings,
    [Parameter(Mandatory = $false)][switch]$SingleVault,
    [Parameter(Mandatory = $false)][string]$VaultName,
    [Parameter(Mandatory = $false)][string]$SubscriptionName,
    [Parameter(Mandatory = $false)][switch]$UseParallelProcessing,
    [Parameter(Mandatory = $false)][int]$MaxParallelJobs = 4,
    [Parameter(Mandatory = $false)][switch]$Resume,
    [Parameter(Mandatory = $false)][switch]$SuppressModuleWarnings,
    [Parameter(Mandatory = $false)][switch]$AutoInstallModules,
    [Parameter(Mandatory = $false)][switch]$NoRunLock,
    [Parameter(Mandatory = $false)][switch]$Force,
    [Parameter(Mandatory = $false)][switch]$DeepCrossReference,
    [Parameter(Mandatory = $false)][int]$SimulateInterruptAfter = 0,
    [Parameter(Mandatory = $false)][int]$FinalCoercionTimeoutSeconds = 0,
    [Parameter(Mandatory = $false)][int]$FinalCoercionHeartbeatSeconds = 0
    ,
    # HTML-only child invocation compatibility parameters. These allow the
    # wrapper to invoke the script with -AKV_HTML_ONLY and related args when
    # running the HTML generator in a child process via -File. They are
    # forwarded into Invoke-GapAnalysis via @PSBoundParameters later in the
    # script so the internal HTML-only branch executes correctly.
    [Parameter(Mandatory = $false)][switch]$AKV_HTML_ONLY,
    [Parameter(Mandatory = $false)][string]$AKV_HTML_DATA_PATH,
    [Parameter(Mandatory = $false)][string]$AKV_HTML_PLATFORM_PATH,
    [Parameter(Mandatory = $false)][string]$AKV_HTML_OUTPUT_PATH
)

# Script configuration
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)][ValidateSet('DEBUG','INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    switch ($Level) {
        'DEBUG'   { Write-Host "[$time] [DEBUG]   $Message" -ForegroundColor DarkGray }
        'INFO'    { Write-Host "[$time] [INFO]    $Message" -ForegroundColor Cyan }
        'WARN'    { Write-Host "[$time] [WARN]    $Message" -ForegroundColor Yellow }
        'ERROR'   { Write-Host "[$time] [ERROR]   $Message" -ForegroundColor Red }
        'SUCCESS' { Write-Host "[$time] [SUCCESS] $Message" -ForegroundColor Green }
        default   { Write-Host "[$time] [LOG]     $Message" }
    }
}
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

function Initialize-AzureAuthentication {
    try {
        # Ensure Az context is present
        $context = Get-AzContext -ErrorAction Stop
        Write-Log "Successfully authenticated as: $($context.Account.Id)" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Not authenticated or failed to get Az context: $($_.Exception.Message)" -Level "WARN"
        try {
            Connect-AzAccount -ErrorAction Stop
            $context = Get-AzContext -ErrorAction Stop
            Write-Log "Successfully authenticated as: $($context.Account.Id)" -Level "SUCCESS"
            return $true
        } catch {
            Write-Log "Azure authentication failed: $($_.Exception.Message)" -Level "ERROR"
            return $false
        }
    }
}
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$defaultOutputDir = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "KeyVaultGapAnalysis"
# Script semantic version (set a default if not injected by CI/release)
if (-not (Get-Variable -Name ScriptVersion -Scope Script -ErrorAction SilentlyContinue)) {
    $ScriptVersion = 'unreleased'
}
if ($OutputDirectory) {
    $outputDir = $OutputDirectory
} else {
    $outputDir = $defaultOutputDir
}

if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Output file paths used later in the run
$csvPath = Join-Path $outputDir "KeyVaultGapAnalysis_$timestamp.csv"
$htmlPath = Join-Path $outputDir "KeyVaultGapAnalysis_$timestamp.html"
$logPath = Join-Path $outputDir "KeyVaultGapAnalysis_$timestamp.log"
$incrementalCsvPath = Join-Path $outputDir "KeyVaultGapAnalysis_incremental_$timestamp.csv"

# Global stop flag used for graceful shutdown on CTRL-C
$global:ScriptStopRequested = $false


# Permission issues logging helper (collects permission/read failures during deep scans)
function Write-PermissionsIssue {
    param(
        [string]$Component,
        [string]$SubscriptionId,
        [string]$Message,
        [string]$Cmdlet,
        [string]$ResourceId,
        [string]$SuggestedRole
    )

    # Build a permission issue object and return it. Callers should append to $PermissionsIssues.
    $issue = [PSCustomObject]@{
        Timestamp     = (Get-Date)
        Component     = $Component
        Subscription  = $SubscriptionId
        Message       = $Message
        Cmdlet        = $Cmdlet
        ResourceId    = $ResourceId
        SuggestedRole = $SuggestedRole
    }

    Write-Log ("Permission issue detected for {0} in subscription {1}: {2}" -f $Component, $SubscriptionId, $Message) -Level "WARN"
    return $issue
}

# Checkpoint helpers for resume/persistence
function Get-CheckpointPath {
    param()
    $cp = Join-Path $PSScriptRoot "checkpoint.json"
    return $cp
}

function Load-Checkpoint {
    param()
    $cp = Get-CheckpointPath
    if (Test-Path $cp) {
        try { return (Get-Content $cp -Raw | ConvertFrom-Json -ErrorAction Stop) } catch { return @{} }
    }
    return @{}
}

function Save-Checkpoint-Atomic {
    param(
        [Parameter(Mandatory=$false)][hashtable]$State = @{}
    )
    $cp = Get-CheckpointPath
    $tmp = "$cp.tmp"
    try {
        if ($null -eq $State) { $State = @{} }
        $json = $State | ConvertTo-Json -Depth 5 -Compress
        $json | Out-File -FilePath $tmp -Encoding UTF8 -Force
        Move-Item -Path $tmp -Destination $cp -Force
        # Also write a workspace-visible copy into the output directory so the repo can see the checkpoint
        try {
            if ($null -ne $outputDir -and (Test-Path $outputDir -PathType Container)) {
                $repoCp = Join-Path $outputDir 'checkpoint.json'
                Copy-Item -Path $cp -Destination $repoCp -Force -ErrorAction Stop
            }
        } catch {
            # best-effort: if copying to workspace fails, ignore
        }
    } catch {
        # best-effort: ignore checkpoint write failures
    }
}

# Invoke a scriptblock in a background job and fail if it doesn't complete within timeout
function Invoke-WithTimeout {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$false)][object[]]$Args = @(),
        [Parameter(Mandatory=$false)][int]$TimeoutSeconds = 30,
        [Parameter(Mandatory=$false)][string]$CmdletName = ''
    )
    try {
    Write-Log ("[DEBUG] Starting background job for {0} with timeout {1}s" -f ($CmdletName -as [string]), $TimeoutSeconds) -Level 'INFO'
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Args
    try { Write-Log ("[DEBUG] Started job Id=$($job.Id) for {0}" -f ($CmdletName -as [string])) -Level 'INFO' } catch { Write-Log ("Invoke-WithTimeout inner logging failed: {0}" -f ($_.Exception.Message -as [string])) -Level 'DEBUG' }
    } catch {
        Write-Log ("Failed to start job for {0}: {1}" -f ($CmdletName -as [string]), ($_.Exception.Message -as [string])) -Level 'WARN'
        throw
    }
    if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
        try {
            $result = Receive-Job -Job $job -ErrorAction Stop
        } catch {
            $result = $null
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        return $result
    } else {
                try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { Write-Log ("Cleanup of background job failed: {0}" -f ($_.Exception.Message -as [string])) -Level 'DEBUG' }
        # Log job state for diagnostics
        try {
            $jstate = (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)
            Write-Log ("[DEBUG] Job state for Id=$($job.Id): State=$($jstate.State) HasMoreData=$($jstate.HasMoreData) ChildJobs=$($jstate.ChildJobs.Count)" ) -Level 'INFO'
        } catch { }
        Write-Log "Timeout after ${TimeoutSeconds}s waiting for $($CmdletName -or 'operation')" -Level 'WARN'
        throw "Timed out waiting for $($CmdletName -or 'operation') after ${TimeoutSeconds}s"
    }
}

# Run a ScriptBlock in a background job with periodic heartbeat logs and a hard timeout.
function Invoke-WithHeartbeat {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
        [Parameter(Mandatory=$false)][object[]]$Args = @(),
        [Parameter(Mandatory=$false)][int]$TimeoutSeconds = 300,
        [Parameter(Mandatory=$false)][int]$HeartbeatSeconds = 15,
        [Parameter(Mandatory=$false)][string]$Description = ''
    )

    if ($HeartbeatSeconds -le 0) { $HeartbeatSeconds = 15 }
    if ($TimeoutSeconds -le 0) { $TimeoutSeconds = 300 }

    try {
        Write-Log ("[DEBUG] Starting background job for '{0}' with timeout {1}s and heartbeat {2}s" -f ($Description -as [string]), $TimeoutSeconds, $HeartbeatSeconds) -Level 'INFO'
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Args
    } catch {
        Write-Log ("Failed to start job for '{0}': {1}" -f ($Description -as [string]), ($_.Exception.Message -as [string])) -Level 'WARN'
        throw
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        while ($true) {
            # Wait in heartbeat-sized slices so we can emit progress logs
            if (Wait-Job -Job $job -Timeout $HeartbeatSeconds) {
                # finished
                try { $result = Receive-Job -Job $job -ErrorAction Stop } catch { $result = $null }
                try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch {}
                $sw.Stop()
                Write-Log ("'{0}' completed in {1}s" -f ($Description -as [string], [math]::Round($sw.Elapsed.TotalSeconds,2))) -Level 'INFO'
                return $result
            } else {
                # still running
                Write-Log ("'{0}' still running after {1}s..." -f ($Description -as [string], [math]::Round($sw.Elapsed.TotalSeconds,1))) -Level 'INFO'
                if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                    try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue } catch {}
                    try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch {}
                    Write-Log ("Timeout after {0}s waiting for '{1}'" -f ($TimeoutSeconds, $Description -as [string])) -Level 'WARN'
                    throw "Timed out waiting for '{0}' after {1}s" -f $Description, $TimeoutSeconds
                }
            }
        }
    } finally {
        if ($sw -and -not $sw.IsRunning) { } # noop to avoid leftover variables
    }
}

# Append a single vault row to an incremental CSV (writes header first if not present)
function Get-WorkerTempIncrementalPath {
    param(
        [Parameter(Mandatory=$false)][string]$WorkerId
    )
    if (-not $WorkerId) { $WorkerId = $global:WorkerId }
    $dir = Join-Path $outputDir 'incremental_temp'
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    return Join-Path $dir ("incremental_worker_{0}.csv" -f $WorkerId)
}

function Merge-IncrementalTempFiles {
    param(
        [Parameter(Mandatory=$false)][switch]$Force
    )
    try {
        if (-not $incrementalCsvPath) { return }
        $dir = Join-Path $outputDir 'incremental_temp'
        if (-not (Test-Path $dir)) { return }
        $files = Get-ChildItem -Path $dir -File -Filter 'incremental_worker_*.csv' | Sort-Object Name
        if (-not $files -or $files.Count -eq 0) { return }
        $tmpMaster = "$incrementalCsvPath.tmp"
        # Use header from first file
        $first = $files[0]
        $header = Get-Content -Path $first.FullName -TotalCount 1
        $header | Out-File -FilePath $tmpMaster -Encoding UTF8 -Force
        foreach ($f in $files) {
            $lines = Get-Content -Path $f.FullName
            if ($lines.Count -gt 1) {
                $lines | Select-Object -Skip 1 | Out-File -FilePath $tmpMaster -Encoding UTF8 -Append
            }
        }
        Move-Item -Path $tmpMaster -Destination $incrementalCsvPath -Force
    } catch {
        Write-Log "Failed to merge incremental temp files: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Append-IncrementalCsvRow {
    param(
        [Parameter(Mandatory=$true)][PSObject]$Row,
        [string]$WorkerId
    )
    try {
        if ($UseParallelProcessing) {
            $wp = Get-WorkerTempIncrementalPath -WorkerId ($WorkerId -or $global:WorkerId)
            if (-not (Test-Path $wp)) {
                $Row | Export-Csv -Path $wp -NoTypeInformation -Encoding UTF8
            } else {
                $csv = $Row | ConvertTo-Csv -NoTypeInformation
                $csv | Select-Object -Skip 1 | Out-File -FilePath $wp -Encoding UTF8 -Append
            }
        } else {
            if (-not (Test-Path $incrementalCsvPath)) {
                # Write header + first row
                $Row | Export-Csv -Path $incrementalCsvPath -NoTypeInformation -Encoding UTF8
            } else {
                # Append without header
                $csv = $Row | ConvertTo-Csv -NoTypeInformation
                $csv | Select-Object -Skip 1 | Out-File -FilePath $incrementalCsvPath -Encoding UTF8 -Append
            }
        }
    } catch {
        Write-Log "Failed to append incremental CSV row: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Mark-Vault-Processed {
    param(
        [Parameter(Mandatory=$true)][string]$VaultResourceId,
        [Parameter(Mandatory=$true)][string]$JsonFilePath
    )
    $state = Load-Checkpoint
    if (-not $state.Processed) { $state.Processed = @{} }
    $state.Processed[$VaultResourceId] = @{ Timestamp = (Get-Date).ToString('o'); Json = $JsonFilePath }
    Save-Checkpoint-Atomic -State $state
}

# Atomic JSON writer: write to temp file then move into place to avoid partial writes
function Write-AtomicJson {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][object]$Object,
        [int]$Depth = 4
    )
    $tmp = "$Path.tmp"
    try {
        $json = (Normalize-ForJson $Object | ConvertTo-Json -Depth $Depth -Compress)
        $json | Out-File -FilePath $tmp -Encoding UTF8 -Force
        Move-Item -Path $tmp -Destination $Path -Force
        return $true
    } catch {
    try { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch { Write-Log ("Failed to remove temp file ${tmp}: {0}" -f ($_.Exception.Message -as [string])) -Level 'DEBUG' }
        return $false
    }
}

# Helper: get tag value case-insensitively from a hashtable of tags
function Get-TagValueInsensitive {
    param(
        [hashtable]$Tags,
        [string[]]$Candidates
    )

    if (-not $Tags) { return $null }

    foreach ($candidate in $Candidates) {
        foreach ($key in $Tags.Keys) {
            if ($key -and $key.ToString().ToLower() -eq $candidate.ToLower()) {
                return $Tags[$key]
            }
        }
    }

    return $null
}

# Helper: normalize objects for safe JSON serialization (strip methods, PSObject type names)
function Normalize-ForJson {
    param(
        [Parameter(ValueFromPipeline=$true)] $InputObject
    )

    process {
        if ($null -eq $InputObject) { return $null }

        switch -Regex ($InputObject.GetType().Name) {
            'Hashtable' {
                $out = @{}
                foreach ($k in $InputObject.Keys) { $out[$k] = Normalize-ForJson $InputObject[$k] }
                return $out
            }
            'PSObject' {
                $out = @{}
                foreach ($p in $InputObject.PSObject.Properties) { $out[$p.Name] = Normalize-ForJson $p.Value }
                return $out
            }
            default {
                if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
                    $arr = @()
                    foreach ($i in $InputObject) { $arr += (Normalize-ForJson $i) }
                    return $arr
                }
                # Primitive or unknown type - return as-is (stringify if necessary)
                return $InputObject
            }
        }
    }
}

# Build a comprehensive, flattened CSV record from the analysis object
function Build-MasterCsvRecord {
    param(
        $Analysis
    )

    if (-not $Analysis) { return $null }

    # Safe access helper
    $safe = {
        param($expr, $default = '')
        try { if ($null -ne $expr) { return $expr } else { return $default } } catch { return $default }
    }
    
    # CSV escape helper: remove newlines and compress double-quotes to single-quotes to keep CSV compact
    $escapeForCsv = {
        param($s)
        try {
            if ($null -eq $s) { return '' }
            $str = [string]$s
            $str = $str -replace "[\r\n]+", ' '
            $str = $str -replace '"', "'"
            return $str.Trim()
        } catch { return '' }
    }

    # Extract scalar values directly from the original Analysis object (prefer primitives)
    $subscriptionIdVar = ($safe.Invoke($Analysis.SubscriptionId, '') -as [string]) ?? ''
    $subscriptionNameVar = ($safe.Invoke($Analysis.SubscriptionName, '') -as [string]) ?? ''
    $tenantId = ($Analysis.Vault.TenantId -as [string]) ?? ''
    $resourceId = ($Analysis.Vault.ResourceId -as [string]) ?? ''
    $location = ($Analysis.Location -as [string]) ?? ''

    $vaultSku = ''
    if ($Analysis.Vault -and $Analysis.Vault.Sku -and $Analysis.Vault.Sku.Name) { $vaultSku = $Analysis.Vault.Sku.Name -as [string] }

    $enableSoftDelete = $false
    if ($Analysis.Vault -and $Analysis.Vault.EnableSoftDelete -ne $null) { $enableSoftDelete = [bool]$Analysis.Vault.EnableSoftDelete }

    $enablePurgeProtection = $false
    if ($Analysis.Vault -and $Analysis.Vault.EnablePurgeProtection -ne $null) { $enablePurgeProtection = [bool]$Analysis.Vault.EnablePurgeProtection }

    $softDeleteRetention = ''
    if ($Analysis.Vault -and $Analysis.Vault.SoftDeleteRetentionInDays -ne $null) { $softDeleteRetention = ($Analysis.Vault.SoftDeleteRetentionInDays -as [string]) }

    $accessModel = 'Unknown'
    if ($Analysis.AccessControl -and $Analysis.AccessControl.RbacEnabled) { $accessModel = 'RBAC' } elseif ($Analysis.AccessControl -and $Analysis.AccessControl.AccessPoliciesCount -gt 0) { $accessModel = 'AccessPolicies' }

    $rbacEnabledVar = $false
    if ($Analysis.AccessControl -and $Analysis.AccessControl.RbacEnabled -ne $null) { $rbacEnabledVar = [bool]$Analysis.AccessControl.RbacEnabled }

    $accessPoliciesCountVar = 0
    if ($Analysis.AccessControl -and $Analysis.AccessControl.AccessPoliciesCount -ne $null) { $accessPoliciesCountVar = [int]$Analysis.AccessControl.AccessPoliciesCount }

    $roleAssignmentsCountVar = 0
    if ($Analysis.AccessControl -and $Analysis.AccessControl.RoleAssignmentsCount -ne $null) { $roleAssignmentsCountVar = [int]$Analysis.AccessControl.RoleAssignmentsCount }

    $hasPrivateEndpointsVar = $false
    if ($Analysis.NetworkSecurity -and $Analysis.NetworkSecurity.HasPrivateEndpoints -ne $null) { $hasPrivateEndpointsVar = [bool]$Analysis.NetworkSecurity.HasPrivateEndpoints }

    $privateEndpointIdsStr = ''
    if ($Analysis.NetworkSecurity -and $Analysis.NetworkSecurity.PrivateEndpointIds) { $privateEndpointIdsStr = ($Analysis.NetworkSecurity.PrivateEndpointIds | ForEach-Object { $_ } ) -join ';' }
    $publicNetworkAccessVar = ''
    if ($Analysis.NetworkSecurity -and $Analysis.NetworkSecurity.PublicNetworkAccess -ne $null) { $publicNetworkAccessVar = ($Analysis.NetworkSecurity.PublicNetworkAccess -as [string]) }
    $privateEndpointIdsNormalized = ''
    if ($privateEndpointIdsStr) { $privateEndpointIdsNormalized = ($privateEndpointIdsStr -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) -join ';' }

    $firewallEnabledVar = $false
    if ($Analysis.NetworkSecurity -and $Analysis.NetworkSecurity.FirewallEnabled -ne $null) { $firewallEnabledVar = [bool]$Analysis.NetworkSecurity.FirewallEnabled }

    $allowedIpsStr = ''
    if ($Analysis.NetworkSecurity -and $Analysis.NetworkSecurity.AllowedIpAddresses) { $allowedIpsStr = ($Analysis.NetworkSecurity.AllowedIpAddresses | ForEach-Object { $_ } ) -join ';' }

    $hasDiagnosticsVar = $false
    $diagNames = @()
    if ($Analysis.Diagnostics) {
        if ($Analysis.Diagnostics.HasDiagnostics -ne $null) { $hasDiagnosticsVar = [bool]$Analysis.Diagnostics.HasDiagnostics }
        if ($Analysis.Diagnostics.Settings) { $diagNames = $Analysis.Diagnostics.Settings | ForEach-Object { $_.Name } }
    }

    $secretsCountVar = 0
    $certificatesCountVar = 0
    $keysCountVar = 0
    $totalAssetsVar = 0
    if ($Analysis.SecretInventory) {
    $secretsCountVar = ($Analysis.SecretInventory.SecretsCount -as [int]) ?? 0
    $certificatesCountVar = ($Analysis.SecretInventory.CertificatesCount -as [int]) ?? 0
    $keysCountVar = ($Analysis.SecretInventory.KeysCount -as [int]) ?? 0
    $totalAssetsVar = ($Analysis.SecretInventory.TotalAssets -as [int]) ?? ($secretsCountVar + $certificatesCountVar + $keysCountVar)
    }

    $recentlyRotatedVar = 0
    $manualRotationNeededVar = 0
    $neverRotatedVar = 0
    if ($Analysis.RotationAnalysis) {
    $recentlyRotatedVar = ($Analysis.RotationAnalysis.RecentlyRotated -as [int]) ?? 0
    $manualRotationNeededVar = ($Analysis.RotationAnalysis.ManualRotationNeeded -as [int]) ?? 0
    $neverRotatedVar = ($Analysis.RotationAnalysis.NeverRotated -as [int]) ?? 0
    }

    $securityGapsCountVar = 0
    $securityGapsSummary = ''
    if ($Analysis.SecurityGaps) {
        $securityGapsCountVar = $Analysis.SecurityGaps.Count
        $securityGapsSummary = ($Analysis.SecurityGaps | Select-Object -First 5 | ForEach-Object { "$($_.Severity): $($_.Issue)" }) -join '; '
    }

    $quickWinsCount = 0
    $quickWinsSummary = ''
    if ($Analysis.QuickWins) {
        $quickWinsCount = $Analysis.QuickWins.Count
        $quickWinsSummary = ($Analysis.QuickWins | Select-Object -First 10 | ForEach-Object { $_.Title }) -join '; '
    }

    $complianceScore = ($Analysis.ComplianceScore -as [int]) ?? 0
    $cisScore = ($Analysis.CISComplianceScore -as [int]) ?? 0
    $nistScore = ($Analysis.NISTComplianceScore -as [int]) ?? 0
    $isoScore = ($Analysis.ISOComplianceScore -as [int]) ?? 0
    $msScore = ($Analysis.MSComplianceScore -as [int]) ?? 0
    $riskLevel = ($Analysis.RiskLevel -as [string]) ?? 'Unknown'

    $policyCount = 0
    if ($Analysis.Platform -and $Analysis.Platform.Policies -and $Analysis.Platform.Policies.KeyVaultPolicies) { $policyCount = $Analysis.Platform.Policies.KeyVaultPolicies.Count }

    # Permission issues scoped to this vault/subscription
    $permIssuesCount = 0
    if (Get-Variable -Name PermissionsIssues -Scope Script -ErrorAction SilentlyContinue) {
        $allPerms = Get-Variable -Name PermissionsIssues -Scope Script -ValueOnly
        if ($allPerms) {
            $permIssuesCount = ($allPerms | Where-Object {
                ($_.Subscription -and ($_.Subscription -eq $subscriptionIdVar -or $_.Subscription -eq $subscriptionNameVar)) -or ($_.ResourceId -and $_.ResourceId -eq $resourceId)
            }).Count
        }
    }
    # Prepare additional simple scalars for return
    $vaultNameVar = ($Analysis.VaultName -as [string]) ?? (($Analysis.Vault -and $Analysis.Vault.Name) -as [string]) ?? ''
    $resourceGroupVar = ($Analysis.ResourceGroupName -as [string]) ?? ''

    # Use previously computed scalars for private endpoints/diag names/policy count
    $privateEndpoints = @()
    if ($privateEndpointIdsStr) { $privateEndpoints = $privateEndpointIdsStr.Split(';') }
    $privateEndpointCount = ($privateEndpoints | Where-Object { $_ -and $_ -ne '' }).Count

    # diagNames already computed earlier
    # policyCount already computed earlier

    # Prepare Diagnostics summary
    $diagDestinations = ''
    if ($diagNames -and $diagNames.Count -gt 0) { $diagDestinations = ($diagNames | Select-Object -Unique | ForEach-Object { $_ } ) -join ';' }

    # Prepare compact policy names summary
    $policyNames = ''
    if ($Analysis.Platform -and $Analysis.Platform.Policies -and $Analysis.Platform.Policies.KeyVaultPolicies) {
        $policyNames = ($Analysis.Platform.Policies.KeyVaultPolicies | Select-Object -First 10 | ForEach-Object { $_.DisplayName -as [string] }) -join '; '
    }

    # Prepare Tags as compact JSON string
    $tagsJsonCompact = ''
    if ($Analysis.Vault -and $Analysis.Vault.Tags) {
        $tagsJsonCompact = (Normalize-ForJson $Analysis.Vault.Tags | ConvertTo-Json -Depth 2 -Compress)
    } else {
        $tagsJsonCompact = '{}'
    }

    # Ensure output directory for per-vault JSON exists (use global $outputDir if available)
    $vaultJsonPath = ''
    try {
        if (Get-Variable -Name outputDir -Scope Script -ErrorAction SilentlyContinue) {
            $root = (Get-Variable -Name outputDir -Scope Script -ValueOnly)
        } else {
            $root = $env:TEMP
        }
        $vaultJsonDir = Join-Path $root 'VaultJson'
        if (!(Test-Path $vaultJsonDir)) { New-Item -ItemType Directory -Path $vaultJsonDir -Force | Out-Null }
        $safeVaultName = ($vaultNameVar -replace '[\\/:*?"<>|]', '_')
        $safeSub = ($subscriptionIdVar -replace '[\\/:*?"<>|]', '')
        $vaultJsonPath = Join-Path $vaultJsonDir ("${safeSub}_${safeVaultName}.json")
    } catch {
        # best-effort per-vault JSON export; failures should not stop CSV generation
        $vaultJsonPath = ''
    }

    # Flatten extra Az/az enrichment if present
    $managedIdentityType = ''
    $managedIdentityIds = ''
    $managedIdentityResolved = ''
    $resourceLockTypes = ''
    $networkIpRules = ''
    $networkVNetRuleIds = ''
    $networkDefaultAction = ''
    $networkBypass = ''
    $secretRotationMostRecent = ''
    $keyRotationMostRecent = ''
    $roleAssignmentsResolved = ''
    if ($Analysis.Extra) {
        try { $managedIdentityType = $Analysis.Extra.ManagedIdentityType -as [string] } catch { $managedIdentityType = '' }
        try { $managedIdentityIds = $Analysis.Extra.ManagedIdentityIds -as [string] } catch { $managedIdentityIds = '' }
        try { $managedIdentityResolved = $Analysis.Extra.ManagedIdentityResolved -as [string] } catch { $managedIdentityResolved = '' }
        if (-not $managedIdentityResolved -or $managedIdentityResolved -eq '') {
            # fall back to principal ids if present or mark as NotReadable
            if ($Analysis.Extra -and $Analysis.Extra.ManagedIdentityIds -and $Analysis.Extra.ManagedIdentityIds -ne '') {
                $managedIdentityResolved = $Analysis.Extra.ManagedIdentityIds -as [string]
            } else {
                $managedIdentityResolved = 'NotReadable'
            }
        }
        try { $resourceLockTypes = ($Analysis.Extra.ResourceLocks | ForEach-Object { $_ } ) -join ';' } catch { $resourceLockTypes = ($Analysis.Extra.ResourceLockTypes -as [string]) ?? '' }
    try { $networkIpRules = $Analysis.Extra.NetworkAcls.IpRules -join ';' } catch { $networkIpRules = ($Analysis.Extra.NetworkIpRules -as [string]) ?? '' }
    try { $networkVNetRuleIds = $Analysis.Extra.NetworkAcls.VirtualNetworkRules -join ';' } catch { $networkVNetRuleIds = ($Analysis.Extra.NetworkVNetRuleIds -as [string]) ?? '' }
    try { $networkDefaultAction = $Analysis.Extra.NetworkAcls.DefaultAction -as [string] } catch { $networkDefaultAction = ($Analysis.Extra.NetworkDefaultAction -as [string]) ?? '' }
    try { $networkBypass = $Analysis.Extra.NetworkAcls.Bypass -as [string] } catch { $networkBypass = ($Analysis.Extra.NetworkBypass -as [string]) ?? '' }
        try { $secretRotationMostRecent = $Analysis.Extra.SecretRotationMostRecent -as [string] } catch { $secretRotationMostRecent = '' }
        try { $keyRotationMostRecent = $Analysis.Extra.KeyRotationMostRecent -as [string] } catch { $keyRotationMostRecent = '' }
        if (-not $secretRotationMostRecent -or $secretRotationMostRecent -eq '') { $secretRotationMostRecent = 'NotReadable' }
        if (-not $keyRotationMostRecent -or $keyRotationMostRecent -eq '') { $keyRotationMostRecent = 'NotReadable' }
        # RoleAssignmentsResolved may be an array/collection; coerce to semicolon-joined string for CSV
        try { $roleAssignmentsResolved = $Analysis.Extra.RoleAssignmentsResolved } catch { $roleAssignmentsResolved = '' }
        try {
            $norm = Normalize-ForJson $roleAssignmentsResolved
            if ($norm -is [System.Collections.IEnumerable] -and -not ($norm -is [string])) {
                $parts = @()
                foreach ($item in $norm) {
                    if ($null -eq $item) { continue }
                    # If item looks like a role assignment PSObject, format key fields
                    if ($item.PSObject -and ($item.PSObject.Properties.Name -contains 'RoleDefinitionName' -or $item.PSObject.Properties.Name -contains 'PrincipalId')) {
                        $rname = ($item.RoleDefinitionName -as [string]) ?? ($item.RoleName -as [string]) ?? ''
                        $principalId = ($item.PrincipalId -as [string]) ?? ($item.Principal -as [string]) ?? ''
                        $ptype = ($item.PrincipalType -as [string]) ?? ''
                        if ($rname -or $principalId) { $parts += ("$($rname):$($ptype):$($principalId)") } else { $parts += (ConvertTo-Json $item -Depth 2 -Compress) }
                    } elseif ($item -is [hashtable]) {
                        $parts += (($item.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ',')
                    } elseif ($item -is [string] -or $item -is [int] -or $item -is [bool]) {
                        $parts += $item.ToString()
                    } else {
                        try { $parts += (ConvertTo-Json $item -Depth 2 -Compress) } catch { $parts += $item.ToString() }
                    }
                }
                $roleAssignmentsResolved = ($parts | Where-Object { $_ -and $_ -ne '' }) -join '; '
            } else {
                $roleAssignmentsResolved = $norm -as [string]
            }
        } catch { $roleAssignmentsResolved = ($roleAssignmentsResolved -as [string]) ?? '' }
    }

    # Prepare resolved diagnostic destination names and raw destination ids and SKU for CSV
    $diagnosticDestinationNames = ''
    $diagnosticDestinationsRaw = ''
    if ($Analysis.Extra -and $Analysis.Extra.DiagnosticDestinationsResolved) { $diagnosticDestinationNames = ($Analysis.Extra.DiagnosticDestinationsResolved -join ';') }
    if ($Analysis.Extra -and $Analysis.Extra.DiagnosticDestinations) { $diagnosticDestinationsRaw = ($Analysis.Extra.DiagnosticDestinations -join ';') }
    $skuNameCsv = ''
    if ($Analysis.Extra -and $Analysis.Extra.SkuName) { $skuNameCsv = $Analysis.Extra.SkuName -as [string] }
    if (-not $skuNameCsv -or $skuNameCsv -eq '') { $skuNameCsv = 'NotReadable' }

    # Ensure VaultScore is a scalar numeric value (fallback to ComplianceScore when available)
    $vaultScoreVal = ($complianceScore -as [int])
    if ($null -eq $vaultScoreVal) { $vaultScoreVal = 0 }

    # Prepare a CSV-safe RoleAssignmentsResolved string (handle collections/PSObjects)
    $roleAssignmentsResolvedCsv = ''
    try {
        if ($roleAssignmentsResolved -is [System.Collections.IEnumerable] -and -not ($roleAssignmentsResolved -is [string])) {
            $parts = @()
            foreach ($it in $roleAssignmentsResolved) {
                if ($null -eq $it) { continue }
                if ($it -is [PSObject] -or $it -is [hashtable]) {
                    try { $parts += (ConvertTo-Json $it -Depth 2 -Compress) } catch { $parts += $it.ToString() }
                } else { $parts += $it.ToString() }
            }
            $roleAssignmentsResolvedCsv = ($parts | Where-Object { $_ -and $_ -ne '' }) -join '; '
        } else {
            $roleAssignmentsResolvedCsv = $roleAssignmentsResolved -as [string]
        }
    } catch { $roleAssignmentsResolvedCsv = ($roleAssignmentsResolved -as [string]) ?? '' }

    $roleAssignmentsResolvedCsv = $escapeForCsv.Invoke($roleAssignmentsResolvedCsv)

    # Write a compact per-vault JSON file with flattened scalars for UI use (best-effort)
    try {
        if ($vaultJsonPath -and $vaultJsonPath -ne '') {
            $vaultExport = @{
                Timestamp = (Get-Date).ToString('o')
                SubscriptionId = $subscriptionIdVar
                SubscriptionName = $subscriptionNameVar
                VaultName = $vaultNameVar
                VaultResourceId = $resourceId
                Location = $location
                ComplianceScore = $complianceScore
                VaultScore = $vaultScoreVal
                RoleAssignmentsResolved = $roleAssignmentsResolvedCsv
                ManagedIdentityResolved = $managedIdentityResolved
                DiagnosticDestinationNames = $diagnosticDestinationNames
                DiagnosticDestinationsRaw = $diagnosticDestinationsRaw
                SkuName = $skuNameCsv
                SecretRotationMostRecent = $secretRotationMostRecent
                KeyRotationMostRecent = $keyRotationMostRecent
                NetworkDefaultAction = $networkDefaultAction
                NetworkBypass = $networkBypass
                PublicNetworkAccess = $publicNetworkAccessVar
                PrivateEndpointIdsNormalized = $privateEndpointIdsNormalized
                        JsonFilePath = $vaultJsonPath
                        AccessPoliciesDetails = ($Analysis.Extra.AccessPoliciesDetails -as [string]) ?? ''
                        AccessPolicies_Permissions_Keys = ($Analysis.Extra.AccessPolicies_Permissions_Keys -as [string]) ?? ''
                        AccessPolicies_Permissions_Secrets = ($Analysis.Extra.AccessPolicies_Permissions_Secrets -as [string]) ?? ''
                        AccessPolicies_Permissions_Certificates = ($Analysis.Extra.AccessPolicies_Permissions_Certificates -as [string]) ?? ''
                        ProvisioningState = ($Analysis.Extra.ProvisioningState -as [string]) ?? ''
                        LogAnalyticsWorkspaceIds = ($Analysis.Extra.LogAnalyticsWorkspaceIds -as [string]) ?? ''
            }
            try { Write-AtomicJson -Path $vaultJsonPath -Object $vaultExport -Depth 4 } catch { Write-Log ("Write-AtomicJson failed for ${vaultJsonPath}: {0}" -f ($_.Exception.Message -as [string])) -Level 'DEBUG' }
        }
    } catch { }

    # If parallel processing is requested, require the run-lock to avoid concurrent runs
    try {
        if ($UseParallelProcessing -and $NoRunLock) {
            Write-Log "Parallel processing requested but -NoRunLock was specified. Parallel runs require the run-lock to avoid concurrent conflicting runs; honoring safety and ignoring -NoRunLock." -Level 'WARN'
            $NoRunLock = $false
        }
    } catch { }

    # Prevent accidental child re-entry: when running a focused SingleVault test run
    # mark a script-scoped flag so any child-spawn checks reliably see the intention.
    # This is more robust than checking local vars in multiple places.
    try {
        $script:PreventChildHtmlSpawn = $false
        if ($SingleVault -and $TestMode) { $script:PreventChildHtmlSpawn = $true }
    } catch { $script:PreventChildHtmlSpawn = $false }

    return [PSCustomObject]@{
        SubscriptionId = $subscriptionIdVar
        SubscriptionName = $subscriptionNameVar
        TenantId = $tenantId
        KeyVaultName = $vaultNameVar
        ResourceId = $resourceId
        Location = $location
        ResourceGroupName = $resourceGroupVar
        ComplianceStatus = if ($complianceScore -ge 80) { "Compliant" } elseif ($complianceScore -ge 60) { "Partial" } else { "Non-Compliant" }
        ComplianceScore = $complianceScore
        ErrorsEncountered = ""
        LastAuditDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        SoftDeleteEnabled = $enableSoftDelete
        PurgeProtectionEnabled = $enablePurgeProtection
        DiagnosticsEnabled = $hasDiagnosticsVar
        EnabledLogCategories = $diagDestinations
        EnabledMetricCategories = ""
        LogAnalyticsEnabled = if ($diagnosticDestinationNames -match "workspace") { $true } else { $false }
        LogAnalyticsWorkspaceName = ""
        EventHubEnabled = if ($diagnosticDestinationNames -match "eventhub") { $true } else { $false }
        EventHubNamespace = ""
        EventHubName = ""
        StorageAccountEnabled = if ($diagnosticDestinationNames -match "storage") { $true } else { $false }
        StorageAccountName = ""
        AccessPolicyCount = $accessPoliciesCountVar
        AccessPolicyDetails = ($Analysis.Extra.AccessPoliciesDetails -as [string]) ?? ''
        RBACRoleAssignments = $roleAssignmentsResolvedCsv
        RBACAssignmentCount = $roleAssignmentsCountVar
        TotalIdentitiesWithAccess = $roleAssignmentsCountVar + $accessPoliciesCountVar
        ServicePrincipalCount = 0
        UserCount = 0
        GroupCount = 0
        ManagedIdentityCount = if ($managedIdentityResolved -and $managedIdentityResolved -ne 'NotReadable') { 1 } else { 0 }
        ServicePrincipalDetails = ""
        ManagedIdentityDetails = $managedIdentityResolved
        PublicNetworkAccess = $publicNetworkAccessVar
        NetworkAclsConfigured = $firewallEnabledVar
        PrivateEndpointCount = $privateEndpointCount
        SystemAssignedIdentity = if ($managedIdentityType -eq 'SystemAssigned') { $true } else { $false }
        SystemAssignedPrincipalId = ""
        UserAssignedIdentityCount = if ($managedIdentityType -eq 'UserAssigned') { 1 } else { 0 }
        UserAssignedIdentityIds = $managedIdentityIds
        ConnectedManagedIdentityCount = if ($managedIdentityResolved -and $managedIdentityResolved -ne 'NotReadable') { 1 } else { 0 }
        CompanyComplianceScore = $complianceScore
        CompanyComplianceStatus = if ($complianceScore -ge 80) { "Compliant" } elseif ($complianceScore -ge 60) { "Partial" } else { "Non-Compliant" }
        ComplianceIssues = $securityGapsSummary
        ComplianceRecommendations = $quickWinsSummary
        VaultRecommendations = $quickWinsSummary
        SecurityEnhancements = ""
        RBACRecommendations = ""
        OverPrivilegedAssignments = ""
        SecretCount = $secretsCountVar
        KeyCount = $keysCountVar
        CertificateCount = $certificatesCountVar
        WorkloadCategories = ""
        EnvironmentType = ""
        PrimaryWorkload = ""
        SecurityInsights = ""
        OptimizationRecommendations = ""
        TotalItems = $totalAssetsVar
        MicrosoftComplianceScore = $msScore
        ComplianceFrameworkReasons = if ($Analysis.ComplianceFrameworkReasons) { $Analysis.ComplianceFrameworkReasons -join '; ' } else { '' }
        RiskLevel = $riskLevel
        RiskFactors = $securityGapsSummary
        CriticalFindings = if ($Analysis.CriticalFindings) { $Analysis.CriticalFindings -join '; ' } else { '' }
        OverPrivilegedDetails = if ($Analysis.OverPrivilegedAssignments) { ($Analysis.OverPrivilegedAssignments | ForEach-Object { "$($_.Role): $($_.Principal)" }) -join ' | ' } else { '' }
        CertificatePolicyIssuer = if ($Analysis.SecretInventory -and $Analysis.SecretInventory.Certificates) { ($Analysis.SecretInventory.Certificates | Where-Object { $_.CertificatePolicy } | Select-Object -First 1 | ForEach-Object { $_.CertificatePolicy.IssuerName }) -join '; ' } else { '' }
        CertificatePolicyKeySize = if ($Analysis.SecretInventory -and $Analysis.SecretInventory.Certificates) { ($Analysis.SecretInventory.Certificates | Where-Object { $_.CertificatePolicy } | Select-Object -First 1 | ForEach-Object { $_.CertificatePolicy.KeySize }) -join '; ' } else { '' }
        CertificatePolicyValidityMonths = if ($Analysis.SecretInventory -and $Analysis.SecretInventory.Certificates) { ($Analysis.SecretInventory.Certificates | Where-Object { $_.CertificatePolicy } | Select-Object -First 1 | ForEach-Object { $_.CertificatePolicy.ValidityInMonths }) -join '; ' } else { '' }
        KeyRotationPolicyEnabled = if ($Analysis.RotationAnalysis -and $Analysis.RotationAnalysis.AutomaticRotationEnabled -gt 0) { $true } else { $false }
        AzurePolicyCompliantCount = if ($Analysis.Extra -and $Analysis.Extra.PolicyCompliance) { $Analysis.Extra.PolicyCompliance.CompliantPolicies.Count } else { 0 }
        AzurePolicyNonCompliantCount = if ($Analysis.Extra -and $Analysis.Extra.PolicyCompliance) { $Analysis.Extra.PolicyCompliance.NonCompliantPolicies.Count } else { 0 }
        SecurityCenterCriticalAssessments = if ($Analysis.Extra -and $Analysis.Extra.SecurityInsights) { $Analysis.Extra.SecurityInsights.CriticalAssessments.Count } else { 0 }
        SecurityCenterHighAssessments = if ($Analysis.Extra -and $Analysis.Extra.SecurityInsights) { $Analysis.Extra.SecurityInsights.HighAssessments.Count } else { 0 }
        SecurityCenterRecommendations = if ($Analysis.Extra -and $Analysis.Extra.SecurityInsights) { ($Analysis.Extra.SecurityInsights.Recommendations -join '; ') } else { '' }
        ResourceGraphEnabledForDeployment = if ($Analysis.Extra -and $Analysis.Extra.ResourceGraphInsights -and $Analysis.Extra.ResourceGraphInsights.enabledForDeployment) { $Analysis.Extra.ResourceGraphInsights.enabledForDeployment } else { $false }
        ResourceGraphEnabledForDiskEncryption = if ($Analysis.Extra -and $Analysis.Extra.ResourceGraphInsights -and $Analysis.Extra.ResourceGraphInsights.enabledForDiskEncryption) { $Analysis.Extra.ResourceGraphInsights.enabledForDiskEncryption } else { $false }
        ResourceGraphSoftDeleteEnabled = if ($Analysis.Extra -and $Analysis.Extra.ResourceGraphInsights -and $Analysis.Extra.ResourceGraphInsights.enableSoftDelete) { $Analysis.Extra.ResourceGraphInsights.enableSoftDelete } else { $false }
        ResourceGraphPurgeProtectionEnabled = if ($Analysis.Extra -and $Analysis.Extra.ResourceGraphInsights -and $Analysis.Extra.ResourceGraphInsights.enablePurgeProtection) { $Analysis.Extra.ResourceGraphInsights.enablePurgeProtection } else { $false }
    }
}

# Collect extra Azure data using Az PowerShell and az CLI where needed to enrich analysis objects
function Collect-ExtraAzData {
    param(
        [Parameter(Mandatory=$true)][psobject]$Analysis
    )

    try {
        $__collect_start = Get-Date
        try { $resIdDbg = $Analysis.Vault.ResourceId } catch { $resIdDbg = '' }
        Write-Log "[DEBUG] Collect-ExtraAzData start for $resIdDbg" -Level 'INFO'
        # Initialize script-scoped permission issues collector if not present
        if (-not (Get-Variable -Name PermissionsIssues -Scope Script -ErrorAction SilentlyContinue)) {
            # Use Set-Variable to avoid 'variable has been optimized' warnings in some run contexts
            Set-Variable -Name PermissionsIssues -Scope Script -Value @() -Force
        }
        # Ensure we have the resource id
        $resId = $Analysis.Vault.ResourceId
        if (-not $resId) { return $Analysis }

        # Attempt to get resource details via Get-AzResource for properties not included in Get-AzKeyVault
        try {
            Write-Log "Collect-ExtraAzData: calling Get-AzResource for $resId" -Level 'DEBUG'
            $resource = Get-AzResource -ResourceId $resId -ErrorAction Stop
        } catch {
            # best-effort: skip if not accessible
            $resource = $null
        }

        # Managed Identity details (system-assigned / user-assigned identities attached to resources)
        $mi = $null
        if ($resource -and $resource.Properties -and $resource.Properties.identity) {
            $mi = $resource.Properties.identity
        }
        $Analysis.Extra = @{}
        $Analysis.Extra.ManagedIdentity = $mi

        # Resource locks - list locks on the resource
        try {
            Write-Log "Collect-ExtraAzData: calling Get-AzResourceLock for $resId" -Level 'DEBUG'
            $locks = Get-AzResourceLock -ResourceId $resId -ErrorAction Stop
            $Analysis.Extra.ResourceLocks = $locks | ForEach-Object { $_.LockType }
        } catch {
            $Analysis.Extra.ResourceLocks = @()
            $err = $error[0]
            $entry = [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Subscription = $Analysis.SubscriptionId
                ResourceId = $resId
                Cmdlet = 'Get-AzResourceLock'
                ErrorMessage = $err.Exception.Message
                ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
            }
            $PermissionsIssues += $entry
        }

        # Diagnostics destinations: re-query diagnostic settings for full destination ids
        try {
            # Use Invoke-WithTimeout to avoid permanent hang on slow/blocked diagnostic queries
            $diagSettings = Invoke-WithTimeout -ScriptBlock { param($rid) Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction Stop } -Args @($resId) -TimeoutSeconds 30 -CmdletName 'Get-AzDiagnosticSetting'
            $destinations = @()
            foreach ($d in $diagSettings) {
                if ($d.WorkspaceId) { $destinations += $d.WorkspaceId }
                if ($d.EventHubAuthorizationRuleId) { $destinations += $d.EventHubAuthorizationRuleId }
                if ($d.StorageAccountId) { $destinations += $d.StorageAccountId }
            }
            $Analysis.Extra.DiagnosticDestinations = $destinations | Select-Object -Unique
        } catch {
            $Analysis.Extra.DiagnosticDestinations = @()
            $err = $error[0]
            $PermissionsIssues += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Subscription = $Analysis.SubscriptionId
                ResourceId = $resId
                Cmdlet = 'Get-AzDiagnosticSetting'
                ErrorMessage = $err.Exception.Message
                ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
            }
        }

        # Resolve diagnostic destination IDs to friendly names (best-effort)
        $resolved = @()
        foreach ($id in $Analysis.Extra.DiagnosticDestinations) {
            try {
                $res = Get-AzResource -ResourceId $id -ErrorAction Stop
                $type = if ($res.ResourceType) { $res.ResourceType } else { $res.Type }
                $friendly = "{0}:{1}" -f $type, $res.Name
                $resolved += $friendly
            } catch {
                # fallback to raw id
                $resolved += $id
            }
        }
        $Analysis.Extra.DiagnosticDestinationsResolved = $resolved | Select-Object -Unique

        # Network rule details (firewall IPs, virtual network rules) - prefer Az cmdlets
        try {
            # Try to get vault details using Get-AzKeyVault (parse resourceId to get RG and name)
            $parts = $resId.Trim('/').Split('/')
            $rgIndex = [Array]::IndexOf($parts, 'resourceGroups') + 1
            $rg = $null; $vaultName = $null
            if ($rgIndex -gt 0 -and $rgIndex -lt $parts.Count) { $rg = $parts[$rgIndex] }
            $vaultIndex = [Array]::IndexOf($parts, 'vaults') + 1
            if ($vaultIndex -gt 0 -and $vaultIndex -lt $parts.Count) { $vaultName = $parts[$vaultIndex] }

            if ($vaultName) {
                try {
                    # Protect Get-AzKeyVault with a timeout to avoid long hangs when the control plane is slow
                    Write-Log "Attempting Get-AzKeyVault (timeout 30s) for $vaultName in RG $rg" -Level 'DEBUG'
                    $kv = Invoke-WithTimeout -ScriptBlock { param($v,$g) Get-AzKeyVault -VaultName $v -ResourceGroupName $g -ErrorAction Stop } -Args @($vaultName,$rg) -TimeoutSeconds 30 -CmdletName 'Get-AzKeyVault'
                    # networkAcls may be in kv.Properties.NetworkAcls
                    $n = $null
                    if ($kv -and $kv.Properties -and $kv.Properties.networkAcls) { $n = $kv.Properties.networkAcls }
                    elseif ($kv -and $kv.NetworkAcls) { $n = $kv.NetworkAcls }

                    if ($n) {
                        $ipRules = @(); $vnetRules = @();
                        if ($n.ipRules) { foreach ($r in $n.ipRules) { $ipRules += ($r.value -or $r.IpAddressOrRange -or $r.IpMask -or $r) } }
                        if ($n.virtualNetworkRules) { foreach ($r in $n.virtualNetworkRules) { $vnetRules += ($r.id -or $r.VirtualNetworkResourceId -or $r) } }
                        $Analysis.Extra.NetworkAcls = @{
                            DefaultAction = ($n.defaultAction -or $n.DefaultAction -or $null)
                            Bypass = ($n.bypass -or $n.Bypass -or $null)
                            IpRules = $ipRules
                            VirtualNetworkRules = $vnetRules
                        }
                    }

                    # capture SKU if present
                    if ($kv.Sku -and $kv.Sku.Name) { $Analysis.Extra.SkuName = $kv.Sku.Name }
                    # Collect role assignments on the vault resource and attempt to resolve principal names (best-effort)
                    try {
                        $roleAssignments = Get-AzRoleAssignment -Scope $kv.ResourceId -ErrorAction Stop
                        $Analysis.Extra.RoleAssignments = $roleAssignments | Select-Object @{Name='RoleDefinitionName';Expression={$_.RoleDefinitionName}}, @{Name='PrincipalId';Expression={$_.PrincipalId}}, @{Name='PrincipalType';Expression={$_.PrincipalType}}
                        $resolvedRoles = @()
                        foreach ($ra in $roleAssignments) {
                            $principalId = $ra.PrincipalId
                            $pname = $null
                            try {
                                $u = Get-AzADUser -ObjectId $principalId -ErrorAction Stop
                                if ($u.DisplayName) { $pname = "$($u.DisplayName):User:$principalId" }
                            } catch {
                                try {
                                    $sp = Get-AzADServicePrincipal -ObjectId $principalId -ErrorAction Stop
                                    if ($sp.DisplayName) { $pname = "$($sp.DisplayName):ServicePrincipal:$principalId" }
                                } catch {
                                    $pname = $principalId
                                }
                            }
                            $roleName = ($ra.RoleDefinitionName -as [string]) ?? ''
                            $resolvedRoles += ("$($roleName):$($pname)")
                        }
                        $Analysis.Extra.RoleAssignmentsResolved = $resolvedRoles -join ';'
                    } catch {
                        # fallback when role assignments cannot be listed
                        $Analysis.Extra.RoleAssignments = @()
                        $Analysis.Extra.RoleAssignmentsResolved = ''
                        $err = $error[0]
                        $PermissionsIssues += [PSCustomObject]@{
                            Timestamp = (Get-Date).ToString('o')
                            Subscription = $Analysis.SubscriptionId
                            ResourceId = $resId
                            Cmdlet = 'Get-AzRoleAssignment'
                            ErrorMessage = $err.Exception.Message
                            ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
                        }
                    }
                    
                    # Capture AccessPolicies details (principal + permissions) for CSV/UI
                    try {
                        $apDetails = @()
                        $apKeys = @()
                        $apSecrets = @()
                        $apCerts = @()
                        if ($kv -and $kv.AccessPolicies) {
                            foreach ($ap in $kv.AccessPolicies) {
                                try {
                                    $pname = ($ap.DisplayName -as [string]) ?? ($ap.ObjectId -as [string])
                                    $pobj = ($ap.ObjectId -as [string]) ?? ''
                                    $keys = @(); $secrets = @(); $certs = @()
                                    try { if ($ap.PermissionsToKeys) { $keys = $ap.PermissionsToKeys } } catch {}
                                    try { if ($ap.PermissionsToSecrets) { $secrets = $ap.PermissionsToSecrets } } catch {}
                                    try { if ($ap.PermissionsToCertificates) { $certs = $ap.PermissionsToCertificates } } catch {}
                                    $apDetails += ("$pname(objectId=$pobj):Keys[$(($keys -join ',') -replace '\s+','')];Secrets[$(($secrets -join ',') -replace '\s+','')];Certificates[$(($certs -join ',') -replace '\s+','')]" )
                                    if ($keys) { $apKeys += ('{0}:"{1}"' -f $pname, ($keys -join ',')) }
                                    if ($secrets) { $apSecrets += ('{0}:"{1}"' -f $pname, ($secrets -join ',')) }
                                    if ($certs) { $apCerts += ('{0}:"{1}"' -f $pname, ($certs -join ',')) }
                                } catch { }
                            }
                        }
                        $Analysis.Extra.AccessPoliciesDetails = if ($apDetails) { $apDetails -join ' | ' } else { '' }
                        $Analysis.Extra.AccessPolicies_Permissions_Keys = if ($apKeys) { $apKeys -join '; ' } else { '' }
                        $Analysis.Extra.AccessPolicies_Permissions_Secrets = if ($apSecrets) { $apSecrets -join '; ' } else { '' }
                        $Analysis.Extra.AccessPolicies_Permissions_Certificates = if ($apCerts) { $apCerts -join '; ' } else { '' }
                    } catch { $Analysis.Extra.AccessPoliciesDetails = $Analysis.Extra.AccessPoliciesDetails ?? '' }

                    # Capture provisioning state from Get-AzResource result if present
                    try {
                        $prov = ''
                        if ($resource) {
                            $prov = ($resource.Properties.provisioningState -as [string]) ?? ($resource.ProvisioningState -as [string]) ?? ''
                        }
                        $Analysis.Extra.ProvisioningState = $prov
                    } catch { $Analysis.Extra.ProvisioningState = $Analysis.Extra.ProvisioningState ?? '' }

                    # Capture Log Analytics workspace ids (diagnostic workspace ids) explicitly
                    try {
                        $laWs = @()
                        if ($destinations) {
                            foreach ($d in $destinations) {
                                if ($d -and ($d -match '/workspaces/' -or $d -match 'workspace' -or ($d -match '^[0-9a-fA-F\\-]{36}$'))) { $laWs += $d }
                            }
                        }
                        $Analysis.Extra.LogAnalyticsWorkspaceIds = if ($laWs) { ($laWs | Select-Object -Unique) -join ';' } else { '' }
                    } catch { $Analysis.Extra.LogAnalyticsWorkspaceIds = $Analysis.Extra.LogAnalyticsWorkspaceIds ?? '' }
                    } catch {
                    # fallback: no kv details
                    $err = $error[0]
                    # annotate SKU as permission/network restricted when we cannot read vault details
                    $msg = $err.Exception.Message -as [string]
                    if ($msg -and ($msg -match 'Public network access is disabled' -or $msg -match 'ForbiddenByConnection')) {
                        $Analysis.Extra.SkuName = 'NetworkRestricted'
                    } elseif ($msg -and $msg -match 'Forbidden') {
                        $Analysis.Extra.SkuName = 'PermissionDenied'
                    } else {
                        $Analysis.Extra.SkuName = $Analysis.Extra.SkuName ?? ''
                    }
                    # record a permission issue for the inability to get vault details
                    $PermissionsIssues += [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString('o')
                        Subscription = $Analysis.SubscriptionId
                        ResourceId = $resId
                        Cmdlet = 'Get-AzKeyVault'
                        ErrorMessage = $msg
                        ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
                    }
                }
            }
        } catch {
            # ignore errors
        }

        # Resolve managed identity principal names and user-assigned identity details (best-effort)
        try {
            if ($Analysis.Extra.ManagedIdentity) {
                $mi = $Analysis.Extra.ManagedIdentity
                $miType = $null
                $miIds = @()
                if ($mi.type) { $miType = $mi.type }
                if ($mi.userAssignedIdentities) { $miIds = $mi.userAssignedIdentities.Keys }
                $Analysis.Extra.ManagedIdentityType = $miType
                $Analysis.Extra.ManagedIdentityIds = if ($miIds) { $miIds -join ';' } else { '' }

                $resolvedNames = @()
                foreach ($id in $miIds) {
                    try {
                        $ua = Get-AzUserAssignedIdentity -ResourceId $id -ErrorAction Stop
                        if ($ua -and $ua.Name) { $resolvedNames += ("$($ua.Name):$($ua.PrincipalId)") } else { $resolvedNames += $id }
                    } catch {
                        # fallback to principalId extraction when name lookup fails
                        try {
                            # resource id format: /subscriptions/{sub}/resourcegroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}
                            $principalId = ($id -split '/')[ -1 ]
                            if ($principalId) { $resolvedNames += $principalId } else { $resolvedNames += $id }
                        } catch { $resolvedNames += $id }
                        # record permission issue
                        $err = $error[0]
                        $PermissionsIssues += [PSCustomObject]@{
                            Timestamp = (Get-Date).ToString('o')
                            Subscription = $Analysis.SubscriptionId
                            ResourceId = $resId
                            Cmdlet = 'Get-AzUserAssignedIdentity'
                            ErrorMessage = $err.Exception.Message
                            ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
                        }
                    }
                }
                $Analysis.Extra.ManagedIdentityResolved = if ($resolvedNames) { $resolvedNames -join ';' } else { '' }
            } else {
                $Analysis.Extra.ManagedIdentityType = ''
                $Analysis.Extra.ManagedIdentityIds = ''
                $Analysis.Extra.ManagedIdentityResolved = ''
            }
        } catch {
            # record permission error for managed identity resolution
            $err = $error[0]
            $PermissionsIssues += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Subscription = $Analysis.SubscriptionId
                ResourceId = $resId
                Cmdlet = 'Get-AzUserAssignedIdentity'
                ErrorMessage = $err.Exception.Message
                ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
            }
            $Analysis.Extra.ManagedIdentityType = $Analysis.Extra.ManagedIdentityType ?? ''
            $Analysis.Extra.ManagedIdentityIds = $Analysis.Extra.ManagedIdentityIds ?? ''
            $Analysis.Extra.ManagedIdentityResolved = $Analysis.Extra.ManagedIdentityResolved ?? ''
        }

        # Best-effort: collect most recent secret/key updated timestamps for rotation summary
        try {
            $secretDates = @()
            $keyDates = @()
            if ($vaultName) {
                try {
                    Write-Log "Listing secrets for vault $vaultName via Get-AzKeyVaultSecret (timeout 30s)" -Level 'DEBUG'
                    $secrets = Invoke-WithTimeout -ScriptBlock { param($v) Get-AzKeyVaultSecret -VaultName $v -ErrorAction Stop } -Args @($vaultName) -TimeoutSeconds 30 -CmdletName 'Get-AzKeyVaultSecret'
                    foreach ($s in $secrets) {
                        if ($s.Attributes -and $s.Attributes.Updated) { $secretDates += $s.Attributes.Updated }
                    }
                } catch {
                    $err = $error[0]
                    $msg = $err.Exception.Message -as [string]
                    # mark SecretRotationMostRecent as permission/network restricted so CSV is explicit
                    if ($msg -and ($msg -match 'Public network access is disabled' -or $msg -match 'ForbiddenByConnection')) {
                        $Analysis.Extra.SecretRotationMostRecent = 'NetworkRestricted'
                    } else {
                        $Analysis.Extra.SecretRotationMostRecent = 'PermissionDenied'
                    }
                    $PermissionsIssues += [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString('o')
                        Subscription = $Analysis.SubscriptionId
                        ResourceId = $resId
                        Cmdlet = 'Get-AzKeyVaultSecret'
                        ErrorMessage = $msg
                        ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
                    }
                    Write-Log "Failed to list secrets for vault $($vaultName): $msg" -Level 'WARN'
                }
                try {
                    Write-Log "Listing keys for vault $vaultName via Get-AzKeyVaultKey (timeout 30s)" -Level 'DEBUG'
                    $keys = Invoke-WithTimeout -ScriptBlock { param($v) Get-AzKeyVaultKey -VaultName $v -ErrorAction Stop } -Args @($vaultName) -TimeoutSeconds 30 -CmdletName 'Get-AzKeyVaultKey'
                    foreach ($k in $keys) {
                        if ($k.Attributes -and $k.Attributes.Updated) { $keyDates += $k.Attributes.Updated }
                    }
                } catch {
                    $err = $error[0]
                    $msg = $err.Exception.Message -as [string]
                    if ($msg -and ($msg -match 'Public network access is disabled' -or $msg -match 'ForbiddenByConnection')) {
                        $Analysis.Extra.KeyRotationMostRecent = 'NetworkRestricted'
                    } else {
                        $Analysis.Extra.KeyRotationMostRecent = 'PermissionDenied'
                    }
                    $PermissionsIssues += [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString('o')
                        Subscription = $Analysis.SubscriptionId
                        ResourceId = $resId
                        Cmdlet = 'Get-AzKeyVaultKey'
                        ErrorMessage = $msg
                        ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
                    }
                    Write-Log "Failed to list keys for vault $($vaultName): $msg" -Level 'WARN'
                }
            }
            $Analysis.Extra.SecretRotationMostRecent = if ($secretDates) { ($secretDates | Sort-Object -Descending | Select-Object -First 1).ToString('o') } else { '' }
            $Analysis.Extra.KeyRotationMostRecent = if ($keyDates) { ($keyDates | Sort-Object -Descending | Select-Object -First 1).ToString('o') } else { '' }
        } catch {
            $Analysis.Extra.SecretRotationMostRecent = $Analysis.Extra.SecretRotationMostRecent ?? ''
            $Analysis.Extra.KeyRotationMostRecent = $Analysis.Extra.KeyRotationMostRecent ?? ''
        }

        # Azure Policy compliance checks for Key Vault
        try {
            Write-Log "Collect-ExtraAzData: checking Azure Policy compliance for $resId" -Level 'DEBUG'
            $policyStates = Get-AzPolicyState -ResourceId $resId -ErrorAction Stop
            $policyCompliance = @{
                CompliantPolicies = @()
                NonCompliantPolicies = @()
                TotalPolicies = 0
            }
            foreach ($state in $policyStates) {
                $policyCompliance.TotalPolicies++
                if ($state.ComplianceState -eq 'Compliant') {
                    $policyCompliance.CompliantPolicies += $state.PolicyDefinitionName
                } else {
                    $policyCompliance.NonCompliantPolicies += $state.PolicyDefinitionName
                }
            }
            $Analysis.Extra.PolicyCompliance = $policyCompliance
        } catch {
            $Analysis.Extra.PolicyCompliance = @{
                CompliantPolicies = @()
                NonCompliantPolicies = @()
                TotalPolicies = 0
                Error = $_.Exception.Message
            }
            $err = $error[0]
            $PermissionsIssues += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Subscription = $Analysis.SubscriptionId
                ResourceId = $resId
                Cmdlet = 'Get-AzPolicyState'
                ErrorMessage = $err.Exception.Message
                ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
            }
        # Security Center insights and recommendations
        try {
            Write-Log "Collect-ExtraAzData: checking Security Center assessments for $resId" -Level 'DEBUG'
            $securityAssessments = Get-AzSecurityAssessment -ResourceId $resId -ErrorAction Stop
            $securityInsights = @{
                CriticalAssessments = @()
                HighAssessments = @()
                MediumAssessments = @()
                LowAssessments = @()
                TotalAssessments = 0
                Recommendations = @()
            }
            foreach ($assessment in $securityAssessments) {
                $securityInsights.TotalAssessments++
                $severity = $assessment.Status.Severity ?? 'Unknown'
                switch ($severity) {
                    'Critical' { $securityInsights.CriticalAssessments += $assessment.DisplayName }
                    'High' { $securityInsights.HighAssessments += $assessment.DisplayName }
                    'Medium' { $securityInsights.MediumAssessments += $assessment.DisplayName }
                    'Low' { $securityInsights.LowAssessments += $assessment.DisplayName }
                }
                if ($assessment.Status.Code -ne 'Healthy') {
                    $securityInsights.Recommendations += $assessment.DisplayName
                }
            }
            $Analysis.Extra.SecurityInsights = $securityInsights
        } catch {
            $Analysis.Extra.SecurityInsights = @{
                CriticalAssessments = @()
                HighAssessments = @()
                MediumAssessments = @()
                LowAssessments = @()
                TotalAssessments = 0
                Recommendations = @()
                Error = $_.Exception.Message
            }
            $err = $error[0]
            $PermissionsIssues += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Subscription = $Analysis.SubscriptionId
                ResourceId = $resId
                Cmdlet = 'Get-AzSecurityAssessment'
                ErrorMessage = $err.Exception.Message
                ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
            }
        # Azure Resource Graph insights for cross-subscription Key Vault analysis
        try {
            Write-Log "Collect-ExtraAzData: querying Azure Resource Graph for Key Vault insights" -Level 'DEBUG'
            $argQuery = @"
Resources
| where type =~ 'Microsoft.KeyVault/vaults'
| where id =~ '$resId'
| extend vaultName = name
| extend resourceGroup = resourceGroup
| extend location = location
| extend sku = sku.name
| extend enabledForDeployment = properties.enabledForDeployment
| extend enabledForDiskEncryption = properties.enabledForDiskEncryption
| extend enabledForTemplateDeployment = properties.enabledForTemplateDeployment
| extend enableSoftDelete = properties.enableSoftDelete
| extend enablePurgeProtection = properties.enablePurgeProtection
| extend networkAcls = properties.networkAcls
| extend accessPolicies = array_length(properties.accessPolicies)
| project vaultName, resourceGroup, location, sku, enabledForDeployment, enabledForDiskEncryption, enabledForTemplateDeployment, enableSoftDelete, enablePurgeProtection, networkAcls, accessPolicies
"@
            $argResult = Search-AzGraph -Query $argQuery -ErrorAction Stop
            $Analysis.Extra.ResourceGraphInsights = $argResult
        } catch {
            $Analysis.Extra.ResourceGraphInsights = $null
            $err = $error[0]
            $PermissionsIssues += [PSCustomObject]@{
                Timestamp = (Get-Date).ToString('o')
                Subscription = $Analysis.SubscriptionId
                ResourceId = $resId
                Cmdlet = 'Search-AzGraph'
                ErrorMessage = $err.Exception.Message
                ErrorCode = ($err.Exception.Response | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue) -replace '"','' -replace "[\r\n]+"," "
            }
        }

        # Log completion
        try {
            if ($__collect_start) {
                $dur = (Get-Date) - $__collect_start
                Write-Log "[DEBUG] Collect-ExtraAzData completed for $resIdDbg in $([math]::Round($dur.TotalSeconds,2))s" -Level 'INFO'
            }
        } catch { }

        return $Analysis
    } catch {
        # on any failure, return original analysis object
        return $Analysis
    }
}

# Subscription discovery
function Get-SubscriptionsToAnalyze {
    Write-Log "Discovering accessible subscriptions..." -Level "INFO"

    try {
        Write-Log "About to call Get-AzSubscription to discover accessible subscriptions" -Level 'DEBUG'
        $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }

        if ($SubscriptionId) {
            $subscriptions = $subscriptions | Where-Object { $_.Id -eq $SubscriptionId }
            if ($subscriptions.Count -eq 0) {
                Write-Log "Specified subscription $SubscriptionId not found or not accessible" -Level "ERROR"
                return @()
            }
        }

        Write-Log "Found $($subscriptions.Count) accessible subscription(s)" -Level "INFO"
        return $subscriptions

    } catch {
        Write-Log "Failed to discover subscriptions: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Key Vault discovery
function Get-KeyVaultsInSubscription {
    param([string]$SubscriptionId)

    Write-Log "Discovering Key Vaults in subscription $SubscriptionId..." -Level "INFO"

    try {
        Write-Log "Setting Az context to subscription: $SubscriptionId (Set-AzContext)" -Level 'DEBUG'
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    # Use timeout wrapper for listing key vaults in case the Az call stalls
    try { Write-Log "Listing Key Vaults in subscription $SubscriptionId via Get-AzKeyVault (with timeout)" -Level 'DEBUG'; $keyVaults = Invoke-WithTimeout -ScriptBlock { Get-AzKeyVault } -TimeoutSeconds 60 -CmdletName 'Get-AzKeyVault' } catch { throw }

        Write-Log "Found $($keyVaults.Count) Key Vaults in subscription $SubscriptionId" -Level "INFO"
        return $keyVaults

    } catch {
        Write-Log "Failed to discover Key Vaults in subscription ${SubscriptionId}: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Diagnostics configuration analysis
function Get-DiagnosticsConfiguration {
    param([string]$VaultName, [string]$ResourceGroupName)

    try {
        if ($SuppressAzureWarnings) {
            $diagnostics = Invoke-WithTimeout -ScriptBlock { param($rid) Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } -Args @("/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName") -TimeoutSeconds 30 -CmdletName 'Get-AzDiagnosticSetting'
        } else {
            $diagnostics = Invoke-WithTimeout -ScriptBlock { param($rid) Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction SilentlyContinue } -Args @("/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName") -TimeoutSeconds 30 -CmdletName 'Get-AzDiagnosticSetting'
        }

        return @{
            HasDiagnostics = ($diagnostics.Count -gt 0)
            DiagnosticSettings = $diagnostics
            LogsEnabled = ($diagnostics | Where-Object { $_.Logs.Count -gt 0 }).Count -gt 0
            MetricsEnabled = ($diagnostics | Where-Object { $_.Metrics.Count -gt 0 }).Count -gt 0
        }
    } catch {
        return @{
            HasDiagnostics = $false
            DiagnosticSettings = $null
            LogsEnabled = $false
            MetricsEnabled = $false
        }
    }
}

# RBAC vs Access Policies analysis
function Get-AccessControlAnalysis {
    param([string]$VaultName, [string]$ResourceGroupName)

    try {
        $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName

        # Check if using RBAC
        $rbacEnabled = $vault.EnableRbacAuthorization

        # Get access policies
        $accessPolicies = $vault.AccessPolicies

        # Get RBAC role assignments
        $roleAssignments = Get-AzRoleAssignment -Scope $vault.ResourceId -ErrorAction SilentlyContinue

        return @{
            RbacEnabled = $rbacEnabled
            AccessPoliciesCount = $accessPolicies.Count
            RoleAssignmentsCount = $roleAssignments.Count
            HasAccessPolicies = ($accessPolicies.Count -gt 0)
            HasRoleAssignments = ($roleAssignments.Count -gt 0)
        }
    } catch {
        return @{
            RbacEnabled = $null
            AccessPoliciesCount = 0
            RoleAssignmentsCount = 0
            HasAccessPolicies = $false
            HasRoleAssignments = $false
        }
    }
}

# Network security analysis
function Get-NetworkSecurityAnalysis {
    param([string]$VaultName, [string]$ResourceGroupName)

    try {
        $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName

        # Check network ACLs
        $networkAcls = $vault.NetworkAcls

        # Check private endpoints
        $privateEndpoints = Get-AzPrivateEndpoint | Where-Object {
            $_.PrivateLinkServiceConnections.PrivateLinkServiceId -like "*$VaultName*"
        }

        return @{
            PublicNetworkAccess = $vault.PublicNetworkAccess
            NetworkAclsConfigured = ($null -ne $networkAcls)
            PrivateEndpointsCount = $privateEndpoints.Count
            HasPrivateEndpoints = ($privateEndpoints.Count -gt 0)
            TrustedServicesEnabled = $networkAcls.Bypass -contains "AzureServices"
        }
    } catch {
        return @{
            PublicNetworkAccess = $null
            NetworkAclsConfigured = $false
            PrivateEndpointsCount = 0
            HasPrivateEndpoints = $false
            TrustedServicesEnabled = $false
        }
    }
}

# Secret, Certificate, and Key inventory analysis
function Get-SecretInventoryAnalysis {
    param([string]$VaultName, [string]$ResourceGroupName)

    try {
        # Get vault details for tags
        $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        $vaultTags = if ($vault -and $vault.Tags) { $vault.Tags } else { @{} }

        # Get secrets with detailed information
        $secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction SilentlyContinue
        $secretDetails = @()
        $secretCount = 0

        if ($secrets) {
            $secretCount = $secrets.Count
            foreach ($secret in $secrets) {
                $secretDetails += @{
                    Name = $secret.Name
                    Enabled = $secret.Enabled
                    Created = $secret.Created
                    Updated = $secret.Updated
                    Expires = $secret.Expires
                    NotBefore = $secret.NotBefore
                    ContentType = $secret.ContentType
                    Tags = $secret.Tags
                    RecoveryLevel = $secret.RecoveryLevel
                    VaultName = $VaultName
                    BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                    IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                    Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                    DaysSinceLastUpdate = [math]::Round(((Get-Date) - $secret.Updated).TotalDays, 0)
                    # Note: Last accessed information would require diagnostic logs analysis
                    LastAccessed = $null  # Would need Log Analytics integration
                    AccessCount = 0       # Would need Log Analytics integration
                }
            }
        }

        # Get certificates with detailed information
        $certificates = Get-AzKeyVaultCertificate -VaultName $VaultName -ErrorAction SilentlyContinue
        $certificateDetails = @()
        $certificateCount = 0

        if ($certificates) {
            $certificateCount = $certificates.Count
            foreach ($cert in $certificates) {
                $certificateDetails += @{
                    Name = $cert.Name
                    Enabled = $cert.Enabled
                    Created = $cert.Created
                    Updated = $cert.Updated
                    Expires = $cert.Expires
                    NotBefore = $cert.NotBefore
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    Tags = $cert.Tags
                    RecoveryLevel = $cert.RecoveryLevel
                    VaultName = $VaultName
                    BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                    IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                    Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                    DaysSinceLastUpdate = [math]::Round(((Get-Date) - $cert.Updated).TotalDays, 0)
                    LastAccessed = $null
                    AccessCount = 0
                }
            }
        }

        # Get keys with detailed information
        $keys = Get-AzKeyVaultKey -VaultName $VaultName -ErrorAction SilentlyContinue
        $keyDetails = @()
        $keyCount = 0

        if ($keys) {
            $keyCount = $keys.Count
            foreach ($key in $keys) {
                $keyDetails += @{
                    Name = $key.Name
                    Enabled = $key.Enabled
                    Created = $key.Created
                    Updated = $key.Updated
                    Expires = $key.Expires
                    NotBefore = $key.NotBefore
                    KeyType = $key.KeyType
                    KeySize = $key.KeySize
                    CurveName = $key.CurveName
                    KeyOps = $key.KeyOps
                    Tags = $key.Tags
                    RecoveryLevel = $key.RecoveryLevel
                    VaultName = $VaultName
                    BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                    IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                    Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                    DaysSinceLastUpdate = [math]::Round(((Get-Date) - $key.Updated).TotalDays, 0)
                    LastAccessed = $null
                    AccessCount = 0
                }
            }
        }

        $totalAssets = $secretCount + $certificateCount + $keyCount

        return @{
            SecretsCount = $secretCount
            CertificatesCount = $certificateCount
            KeysCount = $keyCount
            TotalAssets = $totalAssets
            Secrets = $secretDetails
            Certificates = $certificateDetails
            Keys = $keyDetails
            VaultTags = $vaultTags
            BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
            IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
            Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
        }
    } catch {
        return @{
            SecretsCount = 0
            CertificatesCount = 0
            KeysCount = 0
            TotalAssets = 0
            Secrets = @()
            Certificates = @()
            Keys = @()
            VaultTags = @{}
            BusinessUnit = "Unknown"
            Environment = "Unknown"
        }
    }
}

# Rotation and lifecycle analysis
function Get-RotationAnalysis {
    param([string]$VaultName, [string]$ResourceGroupName, $SecretInventory)

    $rotationAnalysis = @{
        AutoRotatedSecrets = 0
        AutoRotatedCertificates = 0
        AutoRotatedKeys = 0
        ManualRotationNeeded = 0
        NeverRotated = 0
        RecentlyRotated = 0
        RotationDetails = @()
    }

    # $thirtyDaysAgo was previously calculated but not used; keep only the 90-day threshold used below
    $ninetyDaysAgo = (Get-Date).AddDays(-90)
    # Mark ResourceGroupName as referenced to satisfy static analysis when it's unused in some modes
    [void]$ResourceGroupName

    # Analyze secrets
    foreach ($secret in $SecretInventory.Secrets) {
        try {
            $secretDetails = Get-AzKeyVaultSecret -VaultName $VaultName -Name $secret.Name -ErrorAction SilentlyContinue
            if ($secretDetails) {
                $lastUpdated = $secretDetails.Updated

                # Check for auto-rotation indicators (this is a simplified check)
                # In practice, you'd need to check for automation accounts, runbooks, or Event Grid subscriptions
                $rotationType = "Manual"

                if ($lastUpdated -gt $ninetyDaysAgo) {
                    $rotationAnalysis.RecentlyRotated++
                } elseif ($lastUpdated -lt $ninetyDaysAgo) {
                    $rotationAnalysis.ManualRotationNeeded++
                }

                $rotationAnalysis.RotationDetails += @{
                    Type = "Secret"
                    Name = $secret.Name
                    LastUpdated = $lastUpdated
                    RotationType = $rotationType
                    DaysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 0)
                    NeedsRotation = ($lastUpdated -lt $ninetyDaysAgo)
                }
            }
        } catch {
            $rotationAnalysis.NeverRotated++
            $rotationAnalysis.RotationDetails += @{
                Type = "Secret"
                Name = $secret.Name
                LastUpdated = $null
                RotationType = "Unknown"
                DaysSinceUpdate = $null
                NeedsRotation = $true
            }
        }
    }

    # Analyze certificates
    foreach ($cert in $SecretInventory.Certificates) {
        try {
            $certDetails = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $cert.Name -ErrorAction SilentlyContinue
            if ($certDetails) {
                $lastUpdated = $certDetails.Updated

                # Get certificate policy for additional analysis
                try {
                    $certPolicy = Get-AzKeyVaultCertificatePolicy -VaultName $VaultName -Name $cert.Name -ErrorAction SilentlyContinue
                    if ($certPolicy) {
                        # Store certificate policy details for analysis
                        $cert.CertificatePolicy = @{
                            IssuerName = $certPolicy.IssuerName
                            SubjectName = $certPolicy.SubjectName
                            ValidityInMonths = $certPolicy.ValidityInMonths
                            KeySize = $certPolicy.KeySize
                            KeyType = $certPolicy.KeyType
                            ReuseKeyOnRenewal = $certPolicy.ReuseKeyOnRenewal
                            Exportable = $certPolicy.Exportable
                        }
                    }
                } catch {
                    # Certificate policy not accessible
                }

                # Check for auto-renewal (simplified check)
                $rotationType = "Manual"

                # Certificates often have expiry dates to check
                if ($certDetails.Expires) {
                    $daysToExpiry = [math]::Round(($certDetails.Expires - (Get-Date)).TotalDays, 0)
                    if ($daysToExpiry -lt 30) {
                        $rotationAnalysis.ManualRotationNeeded++
                    }
                }

                if ($lastUpdated -gt $ninetyDaysAgo) {
                    $rotationAnalysis.RecentlyRotated++
                }

                $rotationAnalysis.RotationDetails += @{
                    Type = "Certificate"
                    Name = $cert.Name
                    LastUpdated = $lastUpdated
                    RotationType = $rotationType
                    DaysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 0)
                    ExpiryDate = $certDetails.Expires
                    DaysToExpiry = if ($certDetails.Expires) { [math]::Round(($certDetails.Expires - (Get-Date)).TotalDays, 0) } else { $null }
                    NeedsRotation = ($certDetails.Expires -and ($certDetails.Expires - (Get-Date)).TotalDays -lt 30)
                }
            }
        } catch {
            $rotationAnalysis.NeverRotated++
            $rotationAnalysis.RotationDetails += @{
                Type = "Certificate"
                Name = $cert.Name
                LastUpdated = $null
                RotationType = "Unknown"
                DaysSinceUpdate = $null
                ExpiryDate = $null
                DaysToExpiry = $null
                NeedsRotation = $true
            }
        }
    }

    # Analyze keys
    foreach ($key in $SecretInventory.Keys) {
        try {
            $keyDetails = Get-AzKeyVaultKey -VaultName $VaultName -Name $key.Name -ErrorAction SilentlyContinue
            if ($keyDetails) {
                $lastUpdated = $keyDetails.Updated
                $rotationType = "Manual"

                # Check for key rotation policy
                try {
                    $rotationPolicy = Get-AzKeyVaultKeyRotationPolicy -VaultName $VaultName -Name $key.Name -ErrorAction SilentlyContinue
                    if ($rotationPolicy) {
                        $rotationType = "Automatic"
                        $rotationAnalysis.AutomaticRotationEnabled++
                    }
                } catch {
                    # Rotation policy not accessible or not set
                }

                if ($lastUpdated -gt $ninetyDaysAgo) {
                    $rotationAnalysis.RecentlyRotated++
                } elseif ($lastUpdated -lt $ninetyDaysAgo) {
                    $rotationAnalysis.ManualRotationNeeded++
                }

                $rotationAnalysis.RotationDetails += @{
                    Type = "Key"
                    Name = $key.Name
                    LastUpdated = $lastUpdated
                    RotationType = $rotationType
                    DaysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 0)
                    NeedsRotation = ($lastUpdated -lt $ninetyDaysAgo)
                }
            }
        } catch {
            $rotationAnalysis.NeverRotated++
            $rotationAnalysis.RotationDetails += @{
                Type = "Key"
                Name = $key.Name
                LastUpdated = $null
                RotationType = "Unknown"
                DaysSinceUpdate = $null
                NeedsRotation = $true
            }
        }
    }

    return $rotationAnalysis
}

# Security gap identification
function Identify-SecurityGaps {
    param($VaultAnalysis)

    $gaps = @()

    # RBAC vs Access Policies gap
    if (!$VaultAnalysis.AccessControl.RbacEnabled -and $VaultAnalysis.AccessControl.AccessPoliciesCount -eq 0) {
        $gaps += @{
            Category = "Access Control"
            Severity = "Critical"
            Issue = "No access control configured"
            Impact = "Vault is inaccessible - complete security failure"
            Recommendation = "Enable Azure RBAC or configure access policies immediately"
            BestPractice = "Azure Key Vault should use Azure RBAC for access control. Access policies are legacy and should be migrated to RBAC for better security, auditability, and management. RBAC provides centralized access control, better audit trails, and integration with Azure AD PIM for just-in-time access."
            RemediationSteps = @(
                "🔐 ENABLE AZURE RBAC: Run 'Update-AzKeyVault -VaultName <vault-name> -EnableRbacAuthorization `$true' to enable RBAC on the Key Vault",
                "👥 ASSIGN MINIMUM PRIVILEGE ROLES: Use built-in roles like 'Key Vault Secrets User' for read access, 'Key Vault Secrets Officer' for read/write, or 'Key Vault Administrator' for full control",
                "📋 EXAMPLE POWERSHELL: New-AzRoleAssignment -ObjectId <user-object-id> -RoleDefinitionName 'Key Vault Secrets Officer' -Scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>",
                "🧪 TEST ACCESS: Verify users can access secrets with their assigned roles before removing legacy policies",
                "🗑️ CLEANUP LEGACY POLICIES: After RBAC testing, remove access policies using 'Remove-AzKeyVaultAccessPolicy -VaultName <vault> -ObjectId <object-id>'",
                "📊 AUDIT & MONITOR: Enable diagnostic logs to monitor RBAC changes and access patterns",
                "🔄 CONSIDER PIM: For production environments, implement Azure AD Privileged Identity Management for just-in-time vault access"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide"
        }
    }

    # Diagnostics gap
    if (!$VaultAnalysis.Diagnostics.HasDiagnostics) {
        $gaps += @{
            Category = "Monitoring & Auditing"
            Severity = "High"
            Issue = "No diagnostic settings configured"
            Impact = "No audit logging, monitoring, or security alerting - blind to threats and compliance violations"
            Recommendation = "Enable diagnostic settings to capture audit logs and metrics"
            BestPractice = "Azure Key Vault must have diagnostic settings enabled to send audit logs to Log Analytics, Event Hub, or Storage for security monitoring, compliance reporting, and threat detection. This enables SIEM integration, compliance auditing, and real-time security alerting."
            RemediationSteps = @(
                "📊 PORTAL METHOD: Key Vault → Monitoring → Diagnostic settings → Add diagnostic setting",
                "📋 SELECT LOGS: Enable 'AuditEvent' (secret operations), 'AzurePolicyEvaluationDetails' (policy compliance)",
                "📈 SELECT METRICS: Enable 'AllMetrics' for performance and usage monitoring",
                "🎯 DESTINATION: Choose 'Send to Log Analytics workspace' for centralized monitoring and alerting",
                "🔧 POWERSHELL ALTERNATIVE: Set-AzDiagnosticSetting -ResourceId <vault-resource-id> -WorkspaceId <log-analytics-id> -Enabled `$true -Category AuditEvent,AzurePolicyEvaluationDetails -MetricCategory AllMetrics",
                "⚠️ RETENTION: Configure log retention (30-90 days minimum) based on compliance requirements",
                "🚨 ALERTS: Create alerts for suspicious activities like multiple failed access attempts or unusual access patterns",
                "📊 DASHBOARDS: Build Azure Monitor workbooks to visualize Key Vault usage and security events",
                "🔄 REGULAR REVIEW: Audit diagnostic settings quarterly to ensure logs are being collected and monitored"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault"
        }
    }

    # Network security gap
    if ($VaultAnalysis.NetworkSecurity.PublicNetworkAccess -eq "Enabled" -and !$VaultAnalysis.NetworkSecurity.HasPrivateEndpoints) {
        $gaps += @{
            Category = "Network Security"
            Severity = "Medium"
            Issue = "Public network access enabled without private endpoints"
            Impact = "Potential exposure to public internet attacks, data exfiltration risks"
            Recommendation = "Configure private endpoints or restrict network access with firewall rules"
            BestPractice = "Azure Key Vault should be configured with private endpoints to ensure traffic remains on the Azure backbone network and is not exposed to the public internet."
            RemediationSteps = @(
                "Create a private endpoint for the Key Vault in your virtual network",
                "Configure private DNS zone for privatelink.vaultcore.azure.net",
                "Update Key Vault firewall to deny public access: Set-AzKeyVaultAccessFirewall -VaultName <vault> -DefaultAction Deny",
                "Allow access from specific virtual networks or IP ranges if needed",
                "Test connectivity from authorized networks only"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/private-link-service"
        }
    }

    # Soft delete gap (treat as Critical - prevents irreversible data loss)
    if (!$VaultAnalysis.Vault.EnableSoftDelete) {
        $gaps += @{
            Category = "Data Protection & Recovery"
            Severity = "Critical"           # Align with policy/prioritization elsewhere in the report
            Issue = "Soft delete not enabled"
            Impact = "Permanent data loss if secrets/certificates/keys are accidentally deleted - no recovery possible"
            Recommendation = "Enable soft delete protection (mandatory for production vaults)"
            BestPractice = "Soft delete must be enabled on all Azure Key Vaults to protect against accidental deletion. This provides a 7-90 day recovery window for deleted secrets."
            RemediationSteps = @(
                "Enable soft delete: Update-AzKeyVault -VaultName <vault> -EnableSoftDelete",
                "Configure retention period (7-90 days, default is 90)",
                "Enable purge protection for additional security: -EnablePurgeProtection",
                "Test recovery by deleting and restoring a test secret"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
        }
    }

    # Purge protection gap
    if (!$VaultAnalysis.Vault.EnablePurgeProtection) {
        $gaps += @{
            Category = "Data Protection & Recovery"
            Severity = "Medium"
            Issue = "Purge protection not enabled"
            Impact = "Deleted secrets can be permanently purged, preventing recovery from ransomware or malicious deletion"
            Recommendation = "Enable purge protection to prevent permanent data loss"
            BestPractice = "Purge protection prevents immediate permanent deletion of secrets, providing additional protection against ransomware and malicious actors."
            RemediationSteps = @(
                "Enable purge protection: Update-AzKeyVault -VaultName <vault> -EnablePurgeProtection",
                "Note: This setting is irreversible once enabled",
                "Test that purge operations are blocked"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection"
        }
    }

    # Rotation analysis gaps
    if ($VaultAnalysis.RotationAnalysis.ManualRotationNeeded -gt 0) {
        $gaps += @{
            Category = "Secret Management"
            Severity = "Medium"
            Issue = "$($VaultAnalysis.RotationAnalysis.ManualRotationNeeded) secrets/certificates/keys need rotation"
            Impact = "Outdated credentials increase security risk and may cause service disruptions"
            Recommendation = "Implement automated rotation for secrets, certificates, and keys"
            BestPractice = "Secrets and certificates should be rotated regularly (typically 30-90 days) to minimize the impact of credential compromise. Use Azure Automation or Event Grid for automated rotation."
            RemediationSteps = @(
                "Identify secrets requiring rotation based on age (>90 days)",
                "Set up Azure Automation runbooks for automated rotation",
                "Configure Event Grid subscriptions for certificate expiry notifications",
                "Implement rotation policies and schedules",
                "Monitor rotation success and failures"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/secrets/tutorial-rotation"
        }
    }

    return $gaps
}

# Quick wins identification
function Identify-QuickWins {
    param($VaultAnalysis)

    $wins = @()

    # RBAC migration opportunity
    if ($VaultAnalysis.AccessControl.AccessPoliciesCount -gt 0 -and !$VaultAnalysis.AccessControl.RbacEnabled) {
        $wins += @{
            Category = "Access Control"
            Title = "Migrate to Azure RBAC"
            Description = "Replace access policies with Azure RBAC for better security and management"
            Effort = "Medium"
            Impact = "High"
            RemediationSteps = @(
                "Enable RBAC: Set-AzKeyVaultAccessPolicy -VaultName $($VaultAnalysis.VaultName) -EnabledForRoleBasedAccess `$true",
                "Assign Key Vault roles to users/groups instead of access policies",
                "Test access with new RBAC permissions",
                "Gradually remove legacy access policies"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-migration"
        }
    }

    # Diagnostics setup
    if (!$VaultAnalysis.Diagnostics.HasDiagnostics) {
        $wins += @{
            Category = "Monitoring"
            Title = "Enable Diagnostic Logging"
            Description = "Configure diagnostic settings to capture audit logs and metrics"
            Effort = "Low"
            Impact = "High"
            RemediationSteps = @(
                "Portal: Key Vault → Monitoring → Diagnostic settings → Add diagnostic setting",
                "Select logs: AuditEvent",
                "Select metrics: AllMetrics",
                "Destination: Log Analytics workspace",
                "Save and verify logs are flowing"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault"
        }
    }

    # Private endpoint setup
    if (!$VaultAnalysis.NetworkSecurity.HasPrivateEndpoints -and $VaultAnalysis.NetworkSecurity.PublicNetworkAccess -eq "Enabled") {
        $wins += @{
            Category = "Network Security"
            Title = "Implement Private Endpoints"
            Description = "Create private endpoints to secure network access to Key Vault"
            Effort = "Medium"
            Impact = "High"
            RemediationSteps = @(
                "Create private endpoint in virtual network",
                "Connect to Key Vault private link service",
                "Configure private DNS zone",
                "Update applications to use private endpoint URL",
                "Test connectivity and disable public access"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/private-link-service"
        }
    }

    # Soft delete enablement
    if (!$VaultAnalysis.Vault.EnableSoftDelete) {
        $wins += @{
            Category = "Data Protection"
            Title = "Enable Soft Delete"
            Description = "Protect against accidental deletion with recovery capability"
            Effort = "Low"
            Impact = "High"
            RemediationSteps = @(
                "PowerShell: Update-AzKeyVault -VaultName $($VaultAnalysis.VaultName) -EnableSoftDelete",
                "Portal: Key Vault → Properties → Soft delete → Enable",
                "Configure retention period (7-90 days)",
                "Test by deleting and recovering a test secret"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
        }
    }

    # Rotation automation
    if ($VaultAnalysis.RotationAnalysis.ManualRotationNeeded -gt 0) {
        $wins += @{
            Category = "Automation"
            Title = "Implement Secret Rotation"
            Description = "Set up automated rotation for secrets and certificates"
            Effort = "High"
            Impact = "Medium"
            RemediationSteps = @(
                "Create Azure Automation account",
                "Develop rotation runbooks for each secret type",
                "Configure schedules for regular rotation",
                "Set up monitoring and alerting for rotation failures",
                "Test rotation process with non-production secrets first"
            )
            Documentation = "https://docs.microsoft.com/en-us/azure/key-vault/secrets/tutorial-rotation-dual"
        }
    }

    return $wins
}

# Azure platform assessment
function Get-AzurePlatformAssessment {
    param([string]$SubscriptionId)

    Write-Log "Assessing Azure platform integration for subscription $SubscriptionId..." -Level "INFO"

    $assessment = @{
        SubscriptionId = $SubscriptionId
        SubscriptionName = ""
        Policies = @{}
        EventHubs = @{}
        LogAnalytics = @{}
        RbacRoles = @{}
        ManagedIdentities = @{}
        ServicePrincipals = @{}
        ServiceIdentities = @{}
        Runbooks = @{}
    }

    try {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

        # Get subscription name
        $subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
        $assessment.SubscriptionName = $subscription.Name

        # Check Azure Policies related to Key Vault (with error handling)
        try {
            # First try to get built-in policies only (more reliable)
            $kvPolicies = Get-AzPolicyDefinition -Builtin | Where-Object {
                $_.Properties.DisplayName -like "*Key Vault*" -or
                $_.Properties.Description -like "*Key Vault*"
            }

            # If no built-in policies found, try custom policies (more prone to errors)
            if ($kvPolicies.Count -eq 0) {
                try {
                    $customPolicies = Get-AzPolicyDefinition -Custom | Where-Object {
                        $_.Properties.DisplayName -like "*Key Vault*" -or
                        $_.Properties.Description -like "*Key Vault*"
                    }
                    $kvPolicies = $customPolicies
                } catch {
                    Write-Log "Failed to retrieve custom policy definitions, using built-in only: $($_.Exception.Message)" -Level "WARNING"
                }
            }

            $assessment.Policies = @{
                KeyVaultPoliciesCount = $kvPolicies.Count
                KeyVaultPolicies = $kvPolicies
            }

            Write-Log "Found $($kvPolicies.Count) Key Vault related policies in subscription $($subscription.Name)" -Level "INFO"
        } catch {
            Write-Log "Failed to retrieve Azure Policy definitions: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Policy assessment will be skipped for this subscription" -Level "WARNING"

            $assessment.Policies = @{
                KeyVaultPoliciesCount = 0
                KeyVaultPolicies = @()
                Error = $_.Exception.Message
            }
        }

        # Check Event Hubs (handle missing module gracefully)
        try {
            if (Get-Command Get-AzEventHubNamespace -ErrorAction SilentlyContinue) {
                $eventHubs = Get-AzEventHubNamespace -ErrorAction Stop
                $assessment.EventHubs = @{
                    NamespacesCount = $eventHubs.Count
                    Namespaces = $eventHubs
                }
            } else {
                if ($AutoInstallModules) {
                    Write-Log "Installing Az.EventHub module for Event Hub assessment..." -Level "INFO"
                    try {
                        Install-Module -Name Az.EventHub -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                        Write-Log "Az.EventHub module installed successfully" -Level "SUCCESS"
                        $eventHubs = Get-AzEventHubNamespace -ErrorAction Stop
                        $assessment.EventHubs = @{
                            NamespacesCount = $eventHubs.Count
                            Namespaces = $eventHubs
                        }
                    } catch {
                        if (-not $SuppressModuleWarnings) {
                            Write-Log "Failed to install Az.EventHub module: $($_.Exception.Message)" -Level "WARNING"
                        }
                        $assessment.EventHubs = @{
                            NamespacesCount = 0
                            Namespaces = @()
                            ModuleMissing = $true
                        }
                    }
                } else {
                    if (-not $SuppressModuleWarnings) {
                        Write-Log "Event Hub module (Az.EventHub) not available - Event Hub integration assessment skipped. Install with: Install-Module -Name Az.EventHub -Scope CurrentUser" -Level "WARNING"
                    }
                    $assessment.EventHubs = @{
                        NamespacesCount = 0
                        Namespaces = @()
                        ModuleMissing = $true
                    }
                }
            }
        } catch {
            if (-not $SuppressModuleWarnings) {
                Write-Log "Event Hub assessment failed: $($_.Exception.Message)" -Level "WARNING"
            }
            $assessment.EventHubs = @{
                NamespacesCount = 0
                Namespaces = @()
            }
        }

        # Check Log Analytics workspaces
        try {
            $logWorkspaces = Get-AzOperationalInsightsWorkspace -ErrorAction Stop
            $assessment.LogAnalytics = @{
                WorkspacesCount = $logWorkspaces.Count
                Workspaces = $logWorkspaces
            }
        } catch {
            if (-not $SuppressModuleWarnings) {
                Write-Log "Log Analytics assessment failed: $($_.Exception.Message)" -Level "WARNING"
            }
            $assessment.LogAnalytics = @{
                WorkspacesCount = 0
                Workspaces = @()
            }
        }

        # Check Key Vault related RBAC roles
        $kvRoles = Get-AzRoleDefinition | Where-Object {
            $_.Name -like "*Key Vault*" -or
            $_.Description -like "*Key Vault*"
        }

        $assessment.RbacRoles = @{
            KeyVaultRolesCount = $kvRoles.Count
            KeyVaultRoles = $kvRoles
        }

        # Check Managed Identities
        try {
            $managedIdentities = Get-AzUserAssignedIdentity -ErrorAction Stop
            $assessment.ManagedIdentities = @{
                Count = $managedIdentities.Count
                Identities = $managedIdentities
            }
        } catch {
            if (-not $SuppressModuleWarnings) {
                Write-Log "Managed Identity assessment failed: $($_.Exception.Message)" -Level "WARNING"
            }
            $assessment.ManagedIdentities = @{
                Count = 0
                Identities = @()
            }
        }

        # Check Service Principals (Azure AD applications)
        try {
            $servicePrincipals = Get-AzADServicePrincipal | Where-Object {
                $_.DisplayName -like "*key*" -or
                $_.DisplayName -like "*vault*" -or
                $null -ne $_.ApplicationId
            } | Select-Object -First 50  # Limit for performance

            $assessment.ServicePrincipals = @{
                Count = $servicePrincipals.Count
                ServicePrincipals = $servicePrincipals
            }
        } catch {
            if (-not $SuppressModuleWarnings) {
                Write-Log "Service Principal assessment failed: $($_.Exception.Message)" -Level "WARNING"
            }
            $assessment.ServicePrincipals = @{
                Count = 0
                ServicePrincipals = @()
            }
        }

        # Check Service Identities (system-assigned managed identities)
        try {
            # Get resources with system-assigned managed identities
            $resourcesWithMSI = Get-AzResource | Where-Object {
                $null -ne $_.Identity -and $_.Identity.Type -like "*SystemAssigned*"
            }

            $assessment.ServiceIdentities = @{
                Count = $resourcesWithMSI.Count
                Resources = $resourcesWithMSI
            }
        } catch {
            if (-not $SuppressModuleWarnings) {
                Write-Log "Service Identity assessment failed: $($_.Exception.Message)" -Level "WARNING"
            }
            $assessment.ServiceIdentities = @{
                Count = 0
                Resources = @()
            }
        }

        # Check Azure Runbooks
        try {
            # Check if Az.Automation module is available
            if (Get-Command Get-AzAutomationAccount -ErrorAction SilentlyContinue) {
                $automationAccounts = Get-AzAutomationAccount -ErrorAction Stop
                $runbooks = @()

                foreach ($account in $automationAccounts) {
                    $accountRunbooks = Get-AzAutomationRunbook -ResourceGroupName $account.ResourceGroupName -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
                    $runbooks += $accountRunbooks | Where-Object {
                        $_.Description -like "*key*" -or
                        $_.Description -like "*vault*" -or
                        $_.Name -like "*key*" -or
                        $_.Name -like "*vault*"
                    }
                }

                $assessment.Runbooks = @{
                    AutomationAccountsCount = $automationAccounts.Count
                    KeyVaultRunbooksCount = $runbooks.Count
                    Runbooks = $runbooks
                }
            } else {
                if ($AutoInstallModules) {
                    Write-Log "Installing Az.Automation module for Runbooks assessment..." -Level "INFO"
                    try {
                        Install-Module -Name Az.Automation -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                        Write-Log "Az.Automation module installed successfully" -Level "SUCCESS"
                        $automationAccounts = Get-AzAutomationAccount -ErrorAction Stop
                        $runbooks = @()

                        foreach ($account in $automationAccounts) {
                            $accountRunbooks = Get-AzAutomationRunbook -ResourceGroupName $account.ResourceGroupName -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
                            $runbooks += $accountRunbooks | Where-Object {
                                $_.Description -like "*key*" -or
                                $_.Description -like "*vault*" -or
                                $_.Name -like "*key*" -or
                                $_.Name -like "*vault*"
                            }
                        }

                        $assessment.Runbooks = @{
                            AutomationAccountsCount = $automationAccounts.Count
                            KeyVaultRunbooksCount = $runbooks.Count
                            Runbooks = $runbooks
                        }
                    } catch {
                        if (-not $SuppressModuleWarnings) {
                            Write-Log "Failed to install Az.Automation module: $($_.Exception.Message)" -Level "WARNING"
                        }
                        $assessment.Runbooks = @{
                            AutomationAccountsCount = 0
                            KeyVaultRunbooksCount = 0
                            Runbooks = @()
                            ModuleMissing = $true
                        }
                    }
                } else {
                    if (-not $SuppressModuleWarnings) {
                        Write-Log "Automation module (Az.Automation) not available - Runbooks integration assessment skipped. Install with: Install-Module -Name Az.Automation -Scope CurrentUser" -Level "WARNING"
                    }
                    $assessment.Runbooks = @{
                        AutomationAccountsCount = 0
                        KeyVaultRunbooksCount = 0
                        Runbooks = @()
                        ModuleMissing = $true
                    }
                }
            }
        } catch {
            if (-not $SuppressModuleWarnings) {
                Write-Log "Runbooks assessment failed: $($_.Exception.Message)" -Level "WARNING"
            }
            # Log permission/module issue (include likely cmdlet for triage)
            $PermissionsIssues += Write-PermissionsIssue -Component 'Runbooks' -SubscriptionId $SubscriptionId -Message $_.Exception.Message -Cmdlet 'Get-AzAutomationAccount' -ResourceId ''
            $assessment.Runbooks = @{
                AutomationAccountsCount = 0
                KeyVaultRunbooksCount = 0
                Runbooks = @()
                Error = $_.Exception.Message
            }
        }

            # Discover Function Apps that may interact with Key Vault (try command, fallback to resource scan)
            if ($IncludeFunctionApps) {
                try {
                    if (Get-Command Get-AzFunctionApp -ErrorAction SilentlyContinue) {
                        $functions = Get-AzFunctionApp -ErrorAction Stop
                        $assessment.FunctionApps = @{ Count = $functions.Count; Functions = $functions }
                    } else {
                        # Fallback: list web sites and filter by kind
                        $sites = Get-AzResource -ErrorAction Stop | Where-Object { $_.ResourceType -eq 'Microsoft.Web/sites' -and $_.Kind -like '*functionapp*' }
                        $assessment.FunctionApps = @{ Count = $sites.Count; Functions = $sites }
                    }
                } catch {
                    if (-not $SuppressModuleWarnings) { Write-Log "Function App discovery failed: $($_.Exception.Message)" -Level "WARNING" }
                    $PermissionsIssues += Write-PermissionsIssue -Component 'FunctionApps' -SubscriptionId $SubscriptionId -Message $_.Exception.Message -Cmdlet 'Get-AzFunctionApp' -ResourceId ''
                    $assessment.FunctionApps = @{ Count = 0; Functions = @(); Error = $_.Exception.Message }
                }
            } else {
                # User did not opt in to Function App inspection - record as skipped
                $assessment.FunctionApps = @{ Count = 0; Functions = @(); Skipped = $true }
                Write-Log "Function App discovery skipped for subscription $SubscriptionId (use -IncludeFunctionApps to enable)" -Level 'DEBUG'
            }

    } catch {
        Write-Log "Failed to assess Azure platform for subscription ${SubscriptionId}: $($_.Exception.Message)" -Level "ERROR"
    }

    return $assessment
}

# If DeepCrossReference is enabled at script level, attempt to inspect runbook content and function app settings for Key Vault URIs/names
if ($DeepCrossReference) {
    Write-Log "Deep cross-referencing enabled: scanning runbook contents and Function App settings for Key Vault references" -Level "INFO"
    foreach ($platform in $PlatformAssessments) {
        $subId = $platform.SubscriptionId
        try {
            # Inspect runbooks
            if ($platform.Runbooks -and $platform.Runbooks.Runbooks) {
                foreach ($rb in $platform.Runbooks.Runbooks) {
                    try {
                        # Best-effort: some runbook objects include a 'Definition' or 'Script' property; otherwise try Get-AzAutomationRunbook -Name
                        $content = $null
                        if ($rb.PSObject.Properties.Match('Definition')) { $content = $rb.Definition } elseif ($rb.PSObject.Properties.Match('Text')) { $content = $rb.Text }
                        if (-not $content) {
                            if (Get-Command Get-AzAutomationRunbook -ErrorAction SilentlyContinue) {
                                $d = Get-AzAutomationRunbook -ResourceGroupName $rb.ResourceGroupName -AutomationAccountName $rb.AutomationAccountName -Name $rb.Name -ErrorAction SilentlyContinue
                                if ($d -and $d.PSObject.Properties.Match('Definition')) { $content = $d.Definition }
                            }
                        }

                        if ($content -and $content.ToString() -match 'vaults?\/|vaultcore\.azure\.net|vault.azure.net|KeyVault') {
                            if (-not $platform.CrossReferences) { $platform.CrossReferences = @() }
                            $platform.CrossReferences += @{ Type = 'Runbook'; Name = $rb.Name; AutomationAccount = $rb.AutomationAccountName; Match = $Matches[0]; Subscription = $subId }
                        }
                    } catch {
                        $PermissionsIssues += Write-PermissionsIssue -Component 'RunbookContent' -SubscriptionId $subId -Message $_.Exception.Message -Cmdlet 'Get-AzAutomationRunbook' -ResourceId ($rb.Id -or '')
                    }
                }
            }

            # Inspect Function App settings (only if user opted-in)
            if ($IncludeFunctionApps -and $platform.FunctionApps -and $platform.FunctionApps.Functions) {
                foreach ($fa in $platform.FunctionApps.Functions) {
                    try {
                        # Try to read app settings (best-effort)
                        $appSettings = $null
                        if (Get-Command Get-AzWebApp -ErrorAction SilentlyContinue) {
                            $webapp = Get-AzWebApp -Name $fa.Name -ResourceGroupName $fa.ResourceGroupName -ErrorAction SilentlyContinue
                            if ($webapp) { $appSettings = $webapp.SiteConfig.AppSettings }
                        } elseif (Get-Command Get-AzFunctionApp -ErrorAction SilentlyContinue) {
                            $f = Get-AzFunctionApp -Name $fa.Name -ResourceGroupName $fa.ResourceGroupName -ErrorAction SilentlyContinue
                            if ($f) { $appSettings = $f.SiteConfig.AppSettings }
                        }

                        if ($appSettings) {
                            $joined = ($appSettings | ForEach-Object { $_.Value } ) -join " `n"
                            if ($joined -match 'vaults?\/|vaultcore\.azure\.net|vault.azure.net|KeyVault') {
                                if (-not $platform.CrossReferences) { $platform.CrossReferences = @() }
                                $platform.CrossReferences += @{ Type = 'FunctionApp'; Name = $fa.Name; Match = $Matches[0]; Subscription = $subId }
                            }
                        }
                    } catch {
                        $PermissionsIssues += Write-PermissionsIssue -Component 'FunctionAppSettings' -SubscriptionId $subId -Message $_.Exception.Message -Cmdlet 'Get-AzWebApp' -ResourceId ($fa.Id -or '')
                    }
                }
            }
        } catch {
            $PermissionsIssues += Write-PermissionsIssue -Component 'DeepCrossReference' -SubscriptionId $subId -Message $_.Exception.Message -Cmdlet 'DeepCrossReference' -ResourceId ''
        }
    }
}

# Main vault analysis function
function Analyze-KeyVault {
    param($Vault, [string]$SubscriptionId, [string]$SubscriptionName)

    Write-Log "Analyzing Key Vault: $($Vault.VaultName)" -Level "INFO"
    $__analyze_start = Get-Date

    $analysis = @{
        SubscriptionId = $SubscriptionId
        SubscriptionName = $SubscriptionName
        VaultName = $Vault.VaultName
        ResourceGroupName = $Vault.ResourceGroupName
        Location = $Vault.Location
        Vault = $Vault
        Diagnostics = $null
        AccessControl = $null
        NetworkSecurity = $null
        SecurityGaps = @()
        QuickWins = @()
        ComplianceScore = 0
        CISComplianceScore = 0
        NISTComplianceScore = 0
        ISOComplianceScore = 0
        MSComplianceScore = 0
        RiskLevel = "Unknown"
    }

    # Get diagnostics configuration
    $analysis.Diagnostics = Get-DiagnosticsConfiguration -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

    # Get access control analysis
    $analysis.AccessControl = Get-AccessControlAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

    # Get network security analysis
    $analysis.NetworkSecurity = Get-NetworkSecurityAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

    # Get secret inventory analysis
    $analysis.SecretInventory = Get-SecretInventoryAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

    # Get rotation analysis
    $analysis.RotationAnalysis = Get-RotationAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName -SecretInventory $analysis.SecretInventory

    # Identify security gaps
    $analysis.SecurityGaps = Identify-SecurityGaps -VaultAnalysis $analysis

    # Identify quick wins
    $analysis.QuickWins = Identify-QuickWins -VaultAnalysis $analysis

    # Calculate compliance scores by framework
    $baseScore = 100

    # CIS Azure Foundations Benchmark scoring
    $cisScore = $baseScore
    if (-not $analysis.AccessControl.RbacEnabled) { $cisScore -= 25 }  # CIS 3.1 - Access Control
    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $cisScore -= 15 }  # CIS 3.2 - Network Security
    if (-not $analysis.Diagnostics.HasDiagnostics) { $cisScore -= 15 }  # CIS 3.4 - Monitoring
    $analysis.CISComplianceScore = [math]::Max(0, [math]::Min(100, $cisScore))

    # NIST Cybersecurity Framework scoring
    $nistScore = $baseScore
    if (-not $analysis.AccessControl.RbacEnabled) { $nistScore -= 20 }  # NIST AC-2 - Access Control
    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $nistScore -= 15 }  # NIST SC-7 - Network Security
    if (-not $analysis.Diagnostics.HasDiagnostics) { $nistScore -= 15 }  # NIST SI-4 - Monitoring
    if (-not $Vault.EnableSoftDelete) { $nistScore -= 10 }  # NIST SI-12 - Recovery
    if (-not $Vault.EnablePurgeProtection) { $nistScore -= 10 }  # NIST SI-12 - Recovery
    $analysis.NISTComplianceScore = [math]::Max(0, [math]::Min(100, $nistScore))

    # ISO 27001 scoring
    $isoScore = $baseScore
    if (-not $analysis.AccessControl.RbacEnabled) { $isoScore -= 20 }  # ISO 27001 A.9 - Access Control
    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $isoScore -= 15 }  # ISO 27001 A.13 - Network Security
    if (-not $Vault.EnableSoftDelete -or -not $Vault.EnablePurgeProtection) { $isoScore -= 15 }  # ISO 27001 A.12 - Data Protection
    if (-not $analysis.Diagnostics.HasDiagnostics) { $isoScore -= 15 }  # ISO 27001 A.12.4 - Monitoring
    # ISO 27001 A.9.2.1 - Secret Rotation (would need additional logic for secret age analysis)
    $analysis.ISOComplianceScore = [math]::Max(0, [math]::Min(100, $isoScore))

    # Microsoft Security Baseline scoring (composite of all controls)
    $msScore = $baseScore
    # Deduct points for missing critical controls (similar to other frameworks)
    if (-not $analysis.AccessControl.RbacEnabled) { $msScore -= 20 }  # Microsoft recommends RBAC
    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $msScore -= 15 }  # Microsoft recommends private endpoints
    if (-not $Vault.EnableSoftDelete) { $msScore -= 10 }  # Microsoft security baseline requires soft delete
    if (-not $Vault.EnablePurgeProtection) { $msScore -= 10 }  # Microsoft recommends purge protection for production
    if (-not $analysis.Diagnostics.HasDiagnostics) { $msScore -= 15 }  # Microsoft requires monitoring
    # Additional Microsoft-specific controls
    if ($analysis.AccessControl.AccessPoliciesCount -gt 0) { $msScore -= 5 }  # Penalty for using legacy access policies
    $analysis.MSComplianceScore = [math]::Max(0, [math]::Min(100, $msScore))

    # Keep the original composite score for backward compatibility
    $analysis.ComplianceScore = [math]::Round(($analysis.CISComplianceScore + $analysis.NISTComplianceScore + $analysis.ISOComplianceScore + $analysis.MSComplianceScore) / 4)

    # Determine risk level
    if ($analysis.ComplianceScore -ge 90) {
        $analysis.RiskLevel = "Low"
    } elseif ($analysis.ComplianceScore -ge 70) {
        $analysis.RiskLevel = "Medium"
    } elseif ($analysis.ComplianceScore -ge 50) {
        $analysis.RiskLevel = "High"
    } else {
        $analysis.RiskLevel = "Critical"
    }

    # Log analyze duration
    try {
        if ($__analyze_start) {
            $dur = (Get-Date) - $__analyze_start
            Write-Log "[DEBUG] Finished Analyze-KeyVault for $($Vault.VaultName) in $([math]::Round($dur.TotalSeconds,2))s" -Level 'INFO'
        }
    } catch { }

    return $analysis
}

# Generate Policy Details HTML Page
function New-PolicyDetailsHtmlPage {
    param(
        [array]$PlatformAssessments,
        [string]$OutputPath
    )

    $policyDetailsPath = $OutputPath -replace '\.html$', '_PolicyDetails.html'

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Key Vault Policies - Detailed View</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .policy-section { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .policy-item { border-left: 4px solid #28a745; padding: 10px; margin: 10px 0; background: #f8fff8; }
        .subscription-header { background: #e9ecef; padding: 10px; margin: 20px 0 10px 0; border-radius: 5px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }
        th { background: #343a40; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e9ecef; }
        .back-link { margin-top: 20px; padding: 10px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; display: inline-block; }
        .back-link:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📋 Azure Key Vault Policies - Detailed Analysis</h1>
        <p>Comprehensive listing of all Key Vault-related Azure Policies across subscriptions</p>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <a href="$([System.IO.Path]::GetFileName($OutputPath))" class="back-link">← Back to Main Report</a>

    <div class="policy-section">
        <h2>📊 Policy Summary by Subscription</h2>
        <table>
            <tr><th>Subscription</th><th>Total Key Vault Policies</th><th>Built-in Policies</th><th>Custom Policies</th></tr>
"@

    foreach ($platform in $PlatformAssessments) {
        $policies = $platform.Policies.KeyVaultPolicies
        $builtinCount = ($policies | Where-Object { $_.Properties.PolicyType -eq 'BuiltIn' }).Count
        $customCount = ($policies | Where-Object { $_.Properties.PolicyType -eq 'Custom' }).Count

    # Show subscription name only for readability; subscription id is available in details/modal JSON
    $subscriptionDisplay = if ($platform.SubscriptionName) { $platform.SubscriptionName } else { $platform.SubscriptionId }

        $html += @"
            <tr>
                <td>$subscriptionDisplay</td>
                <td>$($policies.Count)</td>
                <td>$builtinCount</td>
                <td>$customCount</td>
            </tr>
"@
    }

    $html += @"
        </table>
    </div>
"@

    # Group all policies by name for summary
    $allPolicies = @()
    foreach ($platform in $PlatformAssessments) {
        foreach ($policy in $platform.Policies.KeyVaultPolicies) {
            $policyInfo = @{
                Name = $policy.Properties.DisplayName
                Id = $policy.ResourceId
                Type = $policy.Properties.PolicyType
                Description = $policy.Properties.Description
                Category = $policy.Properties.Metadata.category
                SubscriptionName = $platform.SubscriptionName
                SubscriptionId = $platform.SubscriptionId
            }
            $allPolicies += $policyInfo
        }
    }

    $uniquePolicies = $allPolicies | Group-Object -Property Name | Sort-Object -Property Count -Descending

    $html += @"
    <div class="policy-section">
        <h2>🎯 Most Common Key Vault Policies</h2>
        <table>
            <tr><th>Policy Name</th><th>Occurrences</th><th>Type</th><th>Subscriptions</th><th>Description</th></tr>
"@

    foreach ($policyGroup in $uniquePolicies | Select-Object -First 20) {
        $policy = $policyGroup.Group[0]
        $subscriptions = ($policyGroup.Group | Select-Object -ExpandProperty SubscriptionName -Unique) -join ", "

        $html += @"
            <tr>
                <td>$($policy.Name)</td>
                <td>$($policyGroup.Count)</td>
                <td>$($policy.Type)</td>
                <td>$subscriptions</td>
                <td>$($policy.Description)</td>
            </tr>
"@
    }

    $html += @"
        </table>
    </div>
"@

    # Detailed policy listings by subscription
    foreach ($platform in $PlatformAssessments) {
        if ($platform.Policies.KeyVaultPolicies.Count -gt 0) {
            $html += @"
    <div class="policy-section">
        <div class="subscription-header">
            📂 $($platform.SubscriptionName) ($($platform.SubscriptionId))
        </div>
"@

            foreach ($policy in $platform.Policies.KeyVaultPolicies) {
                $html += @"
        <div class="policy-item">
            <strong>$($policy.Properties.DisplayName)</strong><br>
            <em>ID:</em> $($policy.Name)<br>
            <em>Type:</em> $($policy.Properties.PolicyType)<br>
            <em>Description:</em> $($policy.Properties.Description)<br>
            <em>Category:</em> $($policy.Properties.Metadata.category)
        </div>
"@
            }

            $html += @"
    </div>

    <div class="summary">
        <h2>🔒 Security Best Practices & Compliance Frameworks</h2>
        <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <h3>🏛️ Compliance Standards Alignment</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin: 15px 0;">
                <div style="border-left: 4px solid #007bff; padding-left: 10px;">
                    <strong>Microsoft Security Baseline</strong><br>
                    <em>Azure Key Vault CIS Benchmarks 2.0</em><br>
                    • RBAC over access policies<br>
                    • Private endpoints for network isolation<br>
                    • Soft delete and purge protection enabled<br>
                    • Diagnostic logging configured
                </div>
                <div style="border-left: 4px solid #28a745; padding-left: 10px;">
                    <strong>NIST Cybersecurity Framework</strong><br>
                    <em>Identify, Protect, Detect, Respond, Recover</em><br>
                    • Regular secret rotation (PR.DS-2)<br>
                    • Access control and monitoring (PR.AC-1, DE.AE-1)<br>
                    • Data protection at rest/transit (PR.DS-1, PR.DS-8)
                </div>
                <div style="border-left: 4px solid #ffc107; padding-left: 10px;">
                    <strong>CERT Secure Coding</strong><br>
                    <em>Key Management Best Practices</em><br>
                    • Least privilege access (RBAC)<br>
                    • Automated key rotation<br>
                    • Secure key storage and handling
                </div>
                <div style="border-left: 4px solid #dc3545; padding-left: 10px;">
                    <strong>Industry Standards</strong><br>
                    <em>ISO 27001, SOC 2, PCI DSS</em><br>
                    • Encryption key management<br>
                    • Access logging and monitoring<br>
                    • Incident response capabilities
                </div>
            </div>

            <h3>⚠️ Required Permissions for Complete Analysis</h3>
            <p><strong>If you see zeros or missing data in the report, ensure these permissions are granted:</strong></p>
            <ul>
                <li><strong>Reader</strong> role at subscription or management group level</li>
                <li><strong>Key Vault Reader</strong> role on each Key Vault</li>
                <li><strong>Monitoring Reader</strong> role for diagnostic settings analysis</li>
                <li><strong>Network Contributor</strong> role for private endpoint analysis</li>
                <li><strong>Directory Readers</strong> role in Azure AD for identity analysis</li>
            </ul>
            <p><em>Note: Missing permissions will result in incomplete data rather than errors.</em></p>
        </div>
    </div>

    <div class="summary">
        <h2>📊 Top 10 Security Gaps Report</h2>
        <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
"@

    # Calculate top 10 security gaps (track both occurrences and distinct affected vaults)
    $gapCounts = @{}
    $totalVaults = $AnalysisResults.Count
    $severityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4 }

    # Compute footer sums for the inventory table
    $totalSecretsSum = ($AnalysisResults | ForEach-Object { $_.SecretInventory.SecretsCount } | Measure-Object -Sum).Sum
    $totalCertsSum = ($AnalysisResults | ForEach-Object { $_.SecretInventory.CertificatesCount } | Measure-Object -Sum).Sum
    $totalKeysSum = ($AnalysisResults | ForEach-Object { $_.SecretInventory.KeysCount } | Measure-Object -Sum).Sum
    $totalAssetsSum = ($AnalysisResults | ForEach-Object { $_.SecretInventory.TotalAssets } | Measure-Object -Sum).Sum
    $totalRecentRotationsSum = ($AnalysisResults | ForEach-Object { $_.RotationAnalysis.RecentlyRotated } | Measure-Object -Sum).Sum
    $totalNeedsRotationSum = ($AnalysisResults | ForEach-Object { $_.RotationAnalysis.ManualRotationNeeded } | Measure-Object -Sum).Sum

    foreach ($vault in $AnalysisResults) {
        # Create a safe anchor id for this vault so table links can jump to details
        # Use Make-SafeId helper to ensure ids are lowercase, do not start with digits, and avoid illegal characters
        $vaultAnchorId = Make-SafeId -Value ("$($vault.SubscriptionId)-$($vault.VaultName)") -Prefix 'vault'

        # Adjusted colspan to account for the added 'Overall' column
        $html += "`n            <tr id='$vaultAnchorId'><td colspan='13' style='background:#f7f7f9;padding:8px;font-weight:bold;'>Details for $($vault.VaultName) (<small>$($vault.SubscriptionName) - $($vault.SubscriptionId)</small>)</td></tr>`n"
        foreach ($gap in $vault.SecurityGaps) {
            $key = "$($gap.Category): $($gap.Issue)"
            if (-not $gapCounts.ContainsKey($key)) {
                $gapCounts[$key] = @{
                    Count = 0
                    Vaults = @()
                    Severity = $gap.Severity
                    Category = $gap.Category
                    Issue = $gap.Issue
                    Impact = $gap.Impact
                }
            }
            $gapCounts[$key].Count++
            $vaultIdentifier = "$($vault.SubscriptionId)|$($vault.VaultName)"
            if (-not ($gapCounts[$key].Vaults -contains $vaultIdentifier)) { $gapCounts[$key].Vaults += $vaultIdentifier }
        }
    }

    # Add table footer with sums
    $html += @"
            <tfoot>
                <tr style="font-weight:bold; background:#e9ecef;">
                    <td colspan="3">Totals</td>
                    <td>$totalSecretsSum</td>
                    <td>$totalCertsSum</td>
                    <td>$totalKeysSum</td>
                    <td>$totalAssetsSum</td>
                    <td></td>
                    <td></td>
                    <td></td>
                    <td style="color:#28a745;">$totalRecentRotationsSum</td>
                    <td style="color:#dc3545;">$totalNeedsRotationSum</td>
                </tr>
            </tfoot>
"@

    # Annotate counts with distinct affected vault counts and sort
    $gapAggregates = $gapCounts.GetEnumerator() | ForEach-Object {
        $entry = $_.Value
        $entry | Add-Member -MemberType NoteProperty -Name 'AffectedVaults' -Value (($entry.Vaults | Select-Object -Unique).Count) -Force
        $entry | Add-Member -MemberType NoteProperty -Name 'InstanceCount' -Value $entry.Count -Force
        $entry
    }

    $topGaps = $gapAggregates | Sort-Object @{Expression={ $severityOrder[$_.Severity] }; Ascending=$true}, @{Expression={ $_.AffectedVaults }; Ascending=$false} | Select-Object -First 10

    $html += @"
            <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                <tr style="background: #f8f9fa;">
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Rank</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Security Gap</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Severity</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Affected Vaults</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Percentage</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Business Impact</th>
                </tr>
"@

    $rank = 1
    foreach ($gap in $topGaps) {
        $affectedVaults = if ($gap.PSObject.Members.Name -contains 'AffectedVaults') { $gap.AffectedVaults } elseif ($gap.Vaults) { ($gap.Vaults | Select-Object -Unique).Count } else { $gap.Count }
    # instanceCount value computed for display but not used elsewhere; keep calculation local
    $instanceCount = if ($gap.PSObject.Members.Name -contains 'InstanceCount') { $gap.InstanceCount } else { $gap.Count }
    # Mark as used to satisfy static analysis (value is displayed in the HTML row generation)
    [void]$instanceCount
    $percentage = if ($totalVaults -gt 0) { [math]::Round(($affectedVaults / $totalVaults) * 100, 1) } else { 0 }
        $severityColor = switch ($gap.Severity) {
            "Critical" { "#dc3545" }
            "High" { "#fd7e14" }
            "Medium" { "#ffc107" }
            default { "#6c757d" }
        }

        $html += @"
                <tr>
                    <td style="border: 1px solid #dee2e6; padding: 8px; font-weight: bold;">$rank</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;"><strong>$($gap.Category)</strong><br>$($gap.Issue)</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: $severityColor; font-weight: bold;">$($gap.Severity)</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$affectedVaults</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$percentage%</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">$($gap.Impact)</td>
                </tr>
"@
        $rank++
    }

    $html += @"
            </table>
            <p style="margin-top: 15px; color: #6c757d;"><em>Total Key Vaults Analyzed: $totalVaults</em></p>
        </div>
    </div>
"@
        }
    }

    $html += @"
</body>
</html>
"@

    $html | Out-File -FilePath $policyDetailsPath -Encoding UTF8
    Write-Log "Policy details page generated: $policyDetailsPath" -Level "SUCCESS"

    return $policyDetailsPath
}

# Generate HTML report
function New-GapAnalysisHtmlReport {
    param(
        [array]$AnalysisResults,
        [array]$PlatformAssessments,
        [string]$OutputPath
    )

    # Helper function to format stat values with explanations for zeros
    function Format-StatValue {
        param([int]$Value, [string]$Explanation)
        if ($Value -eq 0) {
            return "<span style='color: #dc3545; font-size: 0.8em;'>0<br/>($Explanation)</span>"
        } else {
            return $Value.ToString()
        }
    }

    # Helper: make deterministic safe element IDs for HTML anchors
    function Make-SafeId {
        param(
            [Parameter(Mandatory=$true)][string]$Value,
            [string]$Prefix = 'id'
        )
        if ($null -eq $Value) { $Value = '' }
        $s = $Value -as [string]
        $s = $s.ToLowerInvariant()
        $s = $s -replace '\s+','-'
        $s = $s -replace '[^a-z0-9\-_]','-'
        $s = $s -replace '-+','-'
        $s = $s.Trim('-')
        if ($s -match '^[0-9]') { $s = "$Prefix-$s" }
        if (-not $s) { $s = "$Prefix-0" }
        return $s
    }

    # Generate policy details page
    $policyDetailsPath = New-PolicyDetailsHtmlPage -PlatformAssessments $PlatformAssessments -OutputPath $OutputPath
    $policyDetailsFileName = [System.IO.Path]::GetFileName($policyDetailsPath)
    # Instrumentation: log entry and policy details creation
    $htmlFunctionStart = Get-Date
    Write-Log "[HTML] New-GapAnalysisHtmlReport started -> OutputPath: $OutputPath | Vaults: $($AnalysisResults.Count)" -Level "INFO"
    Write-Log "[HTML] Policy details page path: $policyDetailsPath" -Level "INFO"

    $totalVaults = $AnalysisResults.Count
    $vaultsWithDiagnostics = ($AnalysisResults | Where-Object { $_.Diagnostics.HasDiagnostics }).Count
    $diagnosticsPercentage = if ($totalVaults -gt 0) { [math]::Round(($vaultsWithDiagnostics / $totalVaults) * 100, 1) } else { 0 }

    # Previous code counted gap instances; this produced inflated counts when a vault had multiple gap entries.
    # We want to count unique affected vaults per severity so the executive summary shows how many vaults
    # have at least one Critical/High/Medium gap respectively.

    # Collect per-vault severities (ensure SecurityGaps is present)
    $vaultsWithGaps = @()
    foreach ($vault in $AnalysisResults) {
        if ($vault.SecurityGaps -and $vault.SecurityGaps.Count -gt 0) {
            $severities = ($vault.SecurityGaps | Where-Object { $_.Severity } | ForEach-Object { $_.Severity.ToString().ToLower() } | Select-Object -Unique)
            $vaultsWithGaps += @{ VaultName = $vault.VaultName; SubscriptionId = $vault.SubscriptionId; Severities = $severities }
        }
    }

    $criticalGaps = ($vaultsWithGaps | Where-Object { $_.Severities -contains 'critical' }).Count
    $highGaps = ($vaultsWithGaps | Where-Object { $_.Severities -contains 'high' }).Count
    $mediumGaps = ($vaultsWithGaps | Where-Object { $_.Severities -contains 'medium' }).Count

    $averageComplianceScore = if ($totalVaults -gt 0) {
        [math]::Round(($AnalysisResults | Measure-Object -Property ComplianceScore -Average).Average, 1)
    } else { 0 }

    # Additional statistics
    $vaultsWithRBAC = ($AnalysisResults | Where-Object { $_.AccessControl.RbacEnabled }).Count
    $rbacPercentage = if ($totalVaults -gt 0) { [math]::Round(($vaultsWithRBAC / $totalVaults) * 100, 1) } else { 0 }

    $vaultsWithPrivateEndpoints = ($AnalysisResults | Where-Object { $_.NetworkSecurity.HasPrivateEndpoints }).Count
    $privateEndpointPercentage = if ($totalVaults -gt 0) { [math]::Round(($vaultsWithPrivateEndpoints / $totalVaults) * 100, 1) } else { 0 }

    # Compute total quick wins as a deduplicated set of unique quick-win titles (avoid double-counting the same recommendation)
    $allWinTitles = @()
    foreach ($v in $AnalysisResults) { foreach ($w in ($v.QuickWins)) { if ($w.Title) { $allWinTitles += $w.Title } } }
    $uniqueWinsCount = if ($allWinTitles.Count -gt 0) { ($allWinTitles | Select-Object -Unique).Count } else { 0 }
    $totalQuickWins = $uniqueWinsCount
    # Compute canonical unique quick-win titles and expose as global so HTML generation can use it
    try {
        $uniqueWinTitles = @()
        if ($allWinTitles.Count -gt 0) {
            $uniqueWinTitles = ($allWinTitles | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '' } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
        }
        # Expose canonical titles globally so the HTML embed and external tools can read them
        $global:uniqueWinTitles = $uniqueWinTitles
        $global:TotalQuickWinsUnique = ($uniqueWinTitles).Count
        Write-Log "[HTML] Canonical quick wins computed: $($global:TotalQuickWinsUnique) unique titles" -Level "INFO"
    } catch {
        $uniqueWinTitles = @()
        $global:TotalQuickWinsUnique = 0
    }
    $uniqueSubscriptions = ($AnalysisResults | Select-Object -Property SubscriptionId -Unique).Count

    # Secret inventory statistics
    $totalSecrets = ($AnalysisResults | ForEach-Object { $_.SecretInventory.SecretsCount } | Measure-Object -Sum).Sum
    $totalCertificates = ($AnalysisResults | ForEach-Object { $_.SecretInventory.CertificatesCount } | Measure-Object -Sum).Sum
    $totalKeys = ($AnalysisResults | ForEach-Object { $_.SecretInventory.KeysCount } | Measure-Object -Sum).Sum
    $totalAssets = $totalSecrets + $totalCertificates + $totalKeys

    # Rotation statistics
    $assetsNeedingRotation = ($AnalysisResults | ForEach-Object { $_.RotationAnalysis.ManualRotationNeeded } | Measure-Object -Sum).Sum
    $recentlyRotated = ($AnalysisResults | ForEach-Object { $_.RotationAnalysis.RecentlyRotated } | Measure-Object -Sum).Sum
    $neverRotated = ($AnalysisResults | ForEach-Object { $_.RotationAnalysis.NeverRotated } | Measure-Object -Sum).Sum
    # Mark as used to avoid false-positive unused variable in static analysis
    [void]$neverRotated

    # Collect gap instances with context so we can summarize and list them below
    Write-Log "[HTML] Building gap details (collecting and formatting) ..." -Level "INFO"
    $gapDetailsStart = Get-Date
    $allGaps = @()
    foreach ($vault in $AnalysisResults) {
        foreach ($gap in $vault.SecurityGaps) {
            $gapWithContext = $gap.PSObject.Copy()
            $gapWithContext | Add-Member -MemberType NoteProperty -Name "VaultName" -Value $vault.VaultName -Force
            $gapWithContext | Add-Member -MemberType NoteProperty -Name "SubscriptionName" -Value $vault.SubscriptionName -Force
            $gapWithContext | Add-Member -MemberType NoteProperty -Name "SubscriptionId" -Value $vault.SubscriptionId -Force
            $allGaps += $gapWithContext
        }
    }

    # After collecting gaps
    $gapDetailsCollected = $allGaps.Count
    $gapDetailsEndCollect = Get-Date
    Write-Log "[HTML] Collected $gapDetailsCollected gap items (collection took $(([math]::Round(($gapDetailsEndCollect - $gapDetailsStart).TotalSeconds, 2)))s)" -Level "INFO"

    # Sort by severity priority (Critical first, then High, then Medium)
    $severityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4 }
    $allGaps = $allGaps | Sort-Object { $severityOrder[$_.Severity] }, Category, VaultName

    # Build gap details HTML
    $gapDetailsHtml = ""
    Write-Log "[HTML] Rendering gap detail items into HTML..." -Level "INFO"
    foreach ($gap in $allGaps) {
        $cssClass = switch ($gap.Severity) {
            "Critical" { "gap-critical" }
            "High" { "gap-high" }
            "Medium" { "gap-medium" }
            default { "gap-medium" }
        }

        $remediationStepsHtml = ""
        if ($gap.RemediationSteps) {
            foreach ($step in $gap.RemediationSteps) {
                $remediationStepsHtml += "<li>$step</li>"
            }
        }

        $gapDetailsHtml += @"
        <div class="gap-item $cssClass">
            <strong>$($gap.VaultName)</strong> ($($gap.SubscriptionName))<br>
            <strong>$($gap.Category) - $($gap.Severity)</strong>: $($gap.Issue)<br>
            <em>Impact:</em> $($gap.Impact)<br>
            <em>Best Practice:</em> $($gap.BestPractice)<br>
            <em>Recommendation:</em> $($gap.Recommendation)<br>
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Remediation Steps</summary>
                <ol style="margin-top: 5px;">
                    $remediationStepsHtml
                </ol>
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="$($gap.Documentation)" target="_blank">$($gap.Documentation)</a></p>
            </details>
        </div>
"@
    }
    $gapDetailsRenderEnd = Get-Date
    Write-Log "[HTML] Rendered gap details HTML (took $(([math]::Round(($gapDetailsRenderEnd - $gapDetailsEndCollect).TotalSeconds, 2)))s)" -Level "INFO"

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Key Vault Gap Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2b9af3; }
    .score-value { color: #2b9af3; font-weight: 700; }
    /* Framework links (CIS/NIST/ISO/MS) - lighter blue for readability */
    .framework-link { color: #2b9af3; text-decoration: none; font-weight:700; }
    .framework-link:hover { text-decoration: underline; }
        .stat-label { color: #666; margin-top: 5px; }
        .gaps-section { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .gap-item { border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; background: #fff5f5; }
        .gap-critical { border-left-color: #dc3545; background: #fff5f5; }
        .gap-high { border-left-color: #fd7e14; background: #fffbf0; }
        .gap-medium { border-left-color: #ffc107; background: #fffef0; }
        .wins-section { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .win-item { border-left: 4px solid #28a745; padding: 10px; margin: 10px 0; background: #f8fff8; }
        .platform-section { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vault-details { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }
        th { background: #343a40; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e9ecef; }
        .risk-low { color: #28a745; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-high { color: #fd7e14; font-weight: bold; }
        .risk-critical { color: #dc3545; font-weight: bold; }
        .recommendations { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Azure Key Vault Gap Analysis Report</h1>
        <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Script Version $ScriptVersion</p>
    <p>Analysis Period: $(((Get-Date) - $StartTime).Days) days | Total Execution Time: $(([math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1))) minutes</p>
    </div>

    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $totalVaults -Explanation "No Key Vaults found or access denied")</div>
                <div class="stat-label">Total Key Vaults</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $uniqueSubscriptions -Explanation "No subscriptions accessible or authentication failed")</div>
                <div class="stat-label">Subscriptions Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vaultsWithDiagnostics</div>
                <div class="stat-label">Vaults with Diagnostics ($diagnosticsPercentage%)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vaultsWithRBAC</div>
                <div class="stat-label">Vaults with RBAC ($rbacPercentage%)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vaultsWithPrivateEndpoints</div>
                <div class="stat-label">Vaults with Private Endpoints ($privateEndpointPercentage%)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$averageComplianceScore%</div>
                <div class="stat-label">Average Compliance Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $totalSecrets -Explanation "No secrets found or access denied")</div>
                <div class="stat-label">Total Secrets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $totalCertificates -Explanation "No certificates found or access denied")</div>
                <div class="stat-label">Total Certificates</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $totalKeys -Explanation "No keys found or access denied")</div>
                <div class="stat-label">Total Keys</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $assetsNeedingRotation -Explanation "No assets need rotation or data unavailable")</div>
                <div class="stat-label">Assets Needing Rotation</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $recentlyRotated -Explanation "No recent rotations or data unavailable")</div>
                <div class="stat-label">Recently Rotated (< 90 days)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($global:TotalQuickWinsUnique -ne $null) { Format-StatValue -Value $global:TotalQuickWinsUnique -Explanation "No quick wins identified or analysis incomplete" } else { Format-StatValue -Value $totalQuickWins -Explanation "No quick wins identified or analysis incomplete" })</div>
                <div class="stat-label">Total Quick Wins Available</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $criticalGaps -Explanation "No critical gaps found or analysis incomplete")</div>
                <div class="stat-label">Critical Security Gaps</div>
            </div>
        </div>
    </div>

    <!-- Embedded canonical quickwins JSON for machine parsing -->
    <script type="application/json" id="canonical-quickwins">
        $(if ($global:uniqueWinTitles -and $global:uniqueWinTitles.Count -gt 0) { ($global:uniqueWinTitles | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode($_) } | ConvertTo-Json -Depth 3) } else { '[]' })
    </script>


    <div class="summary">
        <h2>📋 Risk Assessment Methodology</h2>
        <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3>Compliance Scoring Framework</h3>
            <p>The compliance score is calculated based on security best practices mapped to multiple compliance frameworks:</p>
            <ul>
                <li><strong>Base Score:</strong> 100 points (perfect compliance)</li>
                <li><strong>Deductions:</strong> Points are subtracted for security gaps based on severity and compliance impact</li>
                <li><strong>Bonuses:</strong> Points are added for implemented security controls and best practices</li>
            </ul>

            <h4>Scoring Matrix by Compliance Framework</h4>
            <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                <tr style="background: #f8f9fa;">
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Security Control</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Critical Gap<br>(-25 pts)</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">High Gap<br>(-15 pts)</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Medium Gap<br>(-10 pts)</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Bonus<br>(+pts)</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Compliance Frameworks</th>
                </tr>
                <tr>
                    <td style="border: 1px solid #dee2e6; padding: 8px;"><strong>Access Control</strong></td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #dc3545;">No RBAC/ACL</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Legacy ACL only</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">RBAC misconfigured</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #28a745;">+10 RBAC</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">CIS 3.1, NIST AC-2, ISO 27001 A.9</td>
                </tr>
                <tr style="background: #f8f9fa;">
                    <td style="border: 1px solid #dee2e6; padding: 8px;"><strong>Network Security</strong></td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Public access</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">No firewall rules</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Weak network rules</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #28a745;">+10 Private Link</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">CIS 3.2, NIST SC-7, ISO 27001 A.13</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #dee2e6; padding: 8px;"><strong>Data Protection</strong></td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">No soft delete</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">No purge protection</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Weak retention</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #28a745;">+5 each</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">CIS 3.3, NIST SI-12, ISO 27001 A.12</td>
                </tr>
                <tr style="background: #f8f9fa;">
                    <td style="border: 1px solid #dee2e6; padding: 8px;"><strong>Monitoring & Auditing</strong></td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">No diagnostics</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">No logging</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Incomplete logging</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #28a745;">+10 Diagnostics</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">CIS 3.4, NIST SI-4, ISO 27001 A.12.4</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #dee2e6; padding: 8px;"><strong>Secret Rotation</strong></td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Never rotated</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">>180 days old</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">>90 days old</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">-</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">CIS 3.5, NIST IA-5, ISO 27001 A.9.2.1</td>
                </tr>
            </table>

            <h4>Framework-Specific Scoring Examples</h4>
            <div style="background: #e9ecef; padding: 10px; border-radius: 5px; margin: 10px 0;">
                <p><strong>CIS Azure Foundations Benchmark:</strong> Focuses on access control (RBAC), network security (private endpoints), and monitoring (diagnostics)</p>
                <p><strong>NIST Cybersecurity Framework:</strong> Emphasizes identification (access control), protection (encryption/network), detection (monitoring), and recovery (soft delete)</p>
                <p><strong>ISO 27001:</strong> Covers information security management with focus on access control, cryptography, and audit logging</p>
                <p><strong>Microsoft Best Practices:</strong> Azure-specific hardening guidelines including RBAC, private networking, and comprehensive monitoring</p>
            </div>

            <h3>Risk Level Definitions</h3>
            <ul>
                <li><strong class="risk-low">Low Risk (90-100%):</strong> Excellent security posture with minimal gaps</li>
                <li><strong class="risk-medium">Medium Risk (70-89%):</strong> Good security with some areas for improvement</li>
                <li><strong class="risk-high">High Risk (50-69%):</strong> Significant security gaps requiring immediate attention</li>
                <li><strong class="risk-critical">Critical Risk (0-49%):</strong> Severe security vulnerabilities requiring urgent remediation</li>
            </ul>

            <h3>Compliance Standards Measured</h3>
            <p>This assessment evaluates Key Vault configurations against common frameworks (CIS, NIST, ISO, and Microsoft security baseline) and checks for widely-adopted best practices.</p>
        </div>
    </div>

    <div class="summary">
        <h2>🔐 Identity & Access Management Analysis</h2>
        <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3>📊 Identity Distribution</h3>
            <p>Analysis of identity types and access patterns across all analyzed Key Vaults:</p>
            <ul>
                <li><strong>Managed Identities:</strong> $((($AnalysisResults | Where-Object { $_.AccessControl.RbacEnabled -or $_.AccessControl.AccessPoliciesCount -gt 0 }) | Measure-Object).Count) vaults with configured access</li>
                <li><strong>Service Principals:</strong> Analysis shows mixed usage of service principals and managed identities</li>
                <li><strong>User Accounts:</strong> Direct user access should be minimized for production workloads</li>
            </ul>

            <h3>🎯 Access Patterns & Risk Analysis</h3>
            <h4>High-Privilege Assignments</h4>
            <p>Vaults with Owner or Contributor access that may need review:</p>
            <ul>
                <li><strong>Owner Role Assignments:</strong> $((($AnalysisResults | Where-Object { $_.RBACAssignmentCount -gt 0 }) | Measure-Object).Count) vaults with RBAC assignments</li>
                <li><strong>Cross-Vault Access:</strong> Service principals with access to multiple vaults</li>
                <li><strong>Orphaned Permissions:</strong> Access policies for deleted or inactive principals</li>
            </ul>

            <h3>🔄 RBAC vs Access Policy Comparison</h3>
            <h4>RBAC Model (Recommended)</h4>
            <h5>Benefits:</h5>
            <ul>
                <li>Centralized access management through Azure RBAC</li>
                <li>Integration with Azure AD PIM for just-in-time access</li>
                <li>Simplified permission management at scale</li>
                <li>Better audit trails and compliance reporting</li>
            </ul>

            <h4>Access Policy Model (Legacy)</h4>
            <h5>Limitations:</h5>
            <ul>
                <li>Key Vault-specific permissions management</li>
                <li>Limited integration with broader Azure governance</li>
                <li>More complex to manage at enterprise scale</li>
            </ul>

            <h4>✅ Excellent: High RBAC Adoption</h4>
            <p>$rbacPercentage% of analyzed vaults use Azure RBAC, indicating good modernization progress.</p>

            <h3>🛡️ Identity Security Recommendations</h3>
            <h4>Regular Access Reviews</h4>
            <p>Implement quarterly access reviews for all Key Vault permissions.</p>

            <h4>Time-Limited Access</h4>
            <p>Use Azure AD Privileged Identity Management (PIM) for time-bound access elevation.</p>

            <h4>Prefer Managed Identities</h4>
            <p>Migrate service principals to managed identities where possible for improved security.</p>

            <h4>Monitor Access Patterns</h4>
            <p>Enable diagnostic logging and set up alerts for unusual access patterns.</p>
        </div>
    </div>

    <div class="summary">
        <h2>🔑 Secrets Management Insights</h2>
        <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3>📈 Secrets Distribution & Health</h3>
            <p>Analysis of secret types, rotation status, and lifecycle management:</p>
            <ul>
                <li><strong>Total Secrets:</strong> $(($AnalysisResults | ForEach-Object { $_.SecretInventory.SecretsCount } | Measure-Object -Sum).Sum)</li>
                <li><strong>Total Certificates:</strong> $(($AnalysisResults | ForEach-Object { $_.SecretInventory.CertificatesCount } | Measure-Object -Sum).Sum)</li>
                <li><strong>Total Keys:</strong> $(($AnalysisResults | ForEach-Object { $_.SecretInventory.KeysCount } | Measure-Object -Sum).Sum)</li>
            </ul>

            <h3>✅ Security Best Practices Assessment</h3>
            <h4>Secret Rotation</h4>
            <h5>Recommendations:</h5>
            <ul>
                <li>Implement automated rotation for all secrets with expiration dates</li>
                <li>Set up monitoring alerts for secrets approaching expiration</li>
                <li>Use Azure Key Vault integration with Azure services for automatic rotation</li>
            </ul>

            <h4>Expiration Management</h4>
            <h5>Recommendations:</h5>
            <ul>
                <li>All secrets should have defined expiration dates</li>
                <li>Implement automated cleanup of expired secrets</li>
                <li>Set up notifications for secrets without expiration dates</li>
            </ul>

            <h4>Naming & Tagging</h4>
            <h5>Recommendations:</h5>
            <ul>
                <li>Use consistent naming conventions for secrets</li>
                <li>Implement tagging strategy for secret classification and ownership</li>
                <li>Document secret purposes and ownership in tags</li>
            </ul>

            <h4>Access Patterns</h4>
            <h5>Recommendations:</h5>
            <ul>
                <li>Monitor secret access patterns for anomalies</li>
                <li>Implement least-privilege access principles</li>
                <li>Regular review of secret access permissions</li>
            </ul>

            <h3>🔗 Common Integration Patterns</h3>
            <h4>Application Integration</h4>
            <h5>Common Scenarios:</h5>
            <ul>
                <li>Web applications retrieving connection strings and API keys</li>
                <li>Microservices accessing shared secrets and certificates</li>
                <li>DevOps pipelines retrieving deployment secrets</li>
            </ul>

            <h4>DevOps Integration</h4>
            <h5>Implementation Strategies:</h5>
            <ul>
                <li>Azure DevOps service connections with Key Vault integration</li>
                <li>GitHub Actions using OIDC for Key Vault access</li>
                <li>GitLab CI/CD with Azure Key Vault secrets</li>
            </ul>
        </div>
    </div>

    <div class="summary">
        <h2>🛡️ Comprehensive Security Enhancement Recommendations</h2>
        <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3>🚨 High Priority Actions (Immediate Implementation)</h3>
            <h4>🔐 Enable Purge Protection</h4>
            <h5>Implementation Steps:</h5>
            <ol>
                <li>Identify vaults without purge protection enabled</li>
                <li>Enable purge protection via Azure Portal, PowerShell, or CLI</li>
                <li>Test purge protection functionality</li>
                <li>Update documentation and procedures</li>
            </ol>

            <h4>🔍 Implement Comprehensive Monitoring</h4>
            <h5>Complete Monitoring Stack:</h5>
            <ul>
                <li>Enable diagnostic logging for all Key Vault operations</li>
                <li>Configure Log Analytics workspace integration</li>
                <li>Set up Azure Monitor alerts for security events</li>
                <li>Implement Azure Sentinel integration for advanced threat detection</li>
            </ul>
            <h5>Benefits:</h5>
            <ul>
                <li>Complete audit trail of all Key Vault operations</li>
                <li>Real-time security monitoring and alerting</li>
                <li>Compliance reporting and forensic analysis capabilities</li>
            </ul>

            <h4>🌐 Network Security Hardening</h4>
            <h5>Network Security Implementation:</h5>
            <ul>
                <li>Configure private endpoints for all production vaults</li>
                <li>Implement network security groups and firewall rules</li>
                <li>Enable Azure DDoS Protection Standard</li>
                <li>Configure virtual network integration</li>
            </ul>

            <h3>⚡ Medium Priority Actions (30-60 Days)</h3>
            <h4>🔄 Migrate to RBAC Authorization</h4>
            <h5>RBAC vs Access Policy Benefits:</h5>
            <ul>
                <li>Unified access management across Azure services</li>
                <li>Better integration with Azure AD and PIM</li>
                <li>Simplified governance and compliance reporting</li>
                <li>Reduced administrative overhead</li>
            </ul>
            <h5>Migration Strategy:</h5>
            <ol>
                <li>Assess current access policy configurations</li>
                <li>Plan RBAC role assignments and custom roles if needed</li>
                <li>Implement migration in development environments first</li>
                <li>Gradually migrate production vaults with rollback plans</li>
                <li>Update documentation and training materials</li>
            </ol>

            <h4>🔐 Implement Secret Rotation Automation</h4>
            <h5>Automated Rotation Benefits:</h5>
            <ul>
                <li>Reduced manual intervention and human error</li>
                <li>Consistent rotation schedules and policies</li>
                <li>Improved security posture and compliance</li>
                <li>Better audit trails and monitoring</li>
            </ul>
            <h5>Implementation Approaches:</h5>
            <h6>🔄 Native Auto-Rotation</h6>
            <ul>
                <li>Use Azure Key Vault's built-in rotation for supported secret types</li>
                <li>Configure rotation policies for certificates and keys</li>
                <li>Set up automated rotation notifications</li>
            </ul>
            <h6>🤖 Custom Automation</h6>
            <ul>
                <li>Develop Azure Automation runbooks for custom rotation logic</li>
                <li>Use Azure Functions for event-driven rotation</li>
                <li>Implement Logic Apps for complex rotation workflows</li>
            </ul>
            <h6>🔗 Third-party Integration</h6>
            <ul>
                <li>Integrate with HashiCorp Vault for advanced rotation features</li>
                <li>Use CyberArk Conjur for enterprise secret management</li>
                <li>Implement custom rotation solutions for legacy systems</li>
            </ul>

            <h4>👥 Implement Identity Governance</h4>
            <h5>Identity Governance Framework:</h5>
            <h6>🔍 Access Reviews</h6>
            <ul>
                <li>Regular review of all Key Vault access permissions</li>
                <li>Automated access certification campaigns</li>
                <li>Integration with Azure AD access reviews</li>
            </ul>
            <h6>⏰ Privileged Identity Management</h6>
            <ul>
                <li>Implement just-in-time access for privileged operations</li>
                <li>Configure approval workflows for access elevation</li>
                <li>Set up automatic access revocation after time limits</li>
            </ul>
            <h6>🤖 Managed Identity Adoption</h6>
            <ul>
                <li>Migrate service principals to managed identities</li>
                <li>Configure system-assigned and user-assigned identities</li>
                <li>Update application code to use managed identity authentication</li>
            </ul>
            <h6>📊 Continuous Monitoring</h6>
            <ul>
                <li>Monitor identity lifecycle events</li>
                <li>Alert on anomalous access patterns</li>
                <li>Regular reporting on identity governance metrics</li>
            </ul>

            <h3>🎯 Strategic Enhancements (90+ Days)</h3>
            <h4>🏛️ Enterprise Key Management Architecture</h4>
            <h5>Future-State Architecture:</h5>
            <h6>🌐 Global Key Management</h6>
            <ul>
                <li>Implement Azure Key Vault in multiple regions</li>
                <li>Configure geo-redundant key storage</li>
                <li>Plan for cross-region disaster recovery</li>
            </ul>
            <h6>🔐 Advanced Cryptographic Services</h6>
            <ul>
                <li>Implement Hardware Security Modules (HSMs)</li>
                <li>Use Azure Dedicated HSM for high-security requirements</li>
                <li>Configure managed HSM pools for enterprise scenarios</li>
            </ul>
            <h6>🤖 Intelligent Automation</h6>
            <ul>
                <li>Implement AI-powered threat detection</li>
                <li>Use machine learning for access pattern analysis</li>
                <li>Automate compliance remediation workflows</li>
            </ul>
            <h5>Implementation Roadmap:</h5>
            <ol>
                <li>Assess current cryptographic requirements and compliance needs</li>
                <li>Design target architecture with security and compliance teams</li>
                <li>Plan phased migration with minimal business disruption</li>
                <li>Implement monitoring and alerting for new architecture</li>
                <li>Establish ongoing governance and maintenance procedures</li>
            </ol>

            <h3>📊 Security Metrics & Key Performance Indicators</h3>
            <h4>🔒 Security Baseline Compliance</h4>
            <ul>
                <li>Percentage of vaults with purge protection enabled</li>
                <li>Percentage of vaults with private endpoints configured</li>
                <li>Percentage of vaults with comprehensive diagnostic logging</li>
                <li>Average time to rotate secrets and certificates</li>
            </ul>
            <h4>🎯 Operational Excellence</h4>
            <ul>
                <li>Mean time to detect security incidents</li>
                <li>Mean time to respond to security alerts</li>
                <li>Percentage of automated vs manual secret rotations</li>
                <li>Key Vault availability and performance metrics</li>
            </ul>
        </div>
    </div>

    <div class="gaps-section">
        <h2>🚨 Security Gaps Identified</h2>
        <p>Critical: $criticalGaps | High: $highGaps | Medium: $mediumGaps</p>
        $gapDetailsHtml
    </div>

    <div class="summary">
        <h2>🔐 Detailed Key Vault Inventory by Subscription</h2>
        <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">

            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <h3>📊 Consolidated Key Vault Inventory</h3>
                <p>This table provides a comprehensive view of all Key Vaults across subscriptions, including asset counts, business context, and rotation status.</p>
            </div>

            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background: #e9ecef;">
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Subscription</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Vault Name</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">IAPM#</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Environment</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Secrets</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Certificates</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Keys</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Total Assets</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Overall Score</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Recent Rotations</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Needs Rotation</th>
                </tr>
"@

    # Group vaults by subscription for summary cards but use single table
    foreach ($subscriptionGroup in $vaultsBySubscription) {
        $subscriptionName = $subscriptionGroup.Name
        $subscriptionVaults = $subscriptionGroup.Group

        foreach ($vault in $subscriptionVaults) {
            # Determine status codes for missing data
            # Prefer tag-derived IAPM/project identifiers (case-insensitive), fallback to inventory heuristics
            $tagIapm = Get-TagValueInsensitive -Tags $vault.Vault.Tags -Candidates @('IAPM#','IAPM','ProjectID','IntelApplicationNumber','IntelApp','ApplicationNumber')
            $iapmCode = if ($tagIapm) { $tagIapm } elseif ($vault.SecretInventory.IAPMNumber) { $vault.SecretInventory.IAPMNumber } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                elseif ($vault.SecretInventory.SecretsCount -eq 0 -and $vault.SecretInventory.CertificatesCount -eq 0 -and $vault.SecretInventory.KeysCount -eq 0) { "2" }  # Empty vault
                else { "3" }  # Data not available
            }

            $envCode = if ($vault.SecretInventory.Environment) { $vault.SecretInventory.Environment } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                elseif ($vault.SecretInventory.SecretsCount -eq 0 -and $vault.SecretInventory.CertificatesCount -eq 0 -and $vault.SecretInventory.KeysCount -eq 0) { "2" }  # Empty vault
                else { "3" }  # Data not available
            }

            $secrets = if ($vault.SecretInventory.SecretsCount -gt 0) { $vault.SecretInventory.SecretsCount } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                elseif ($vault.SecretInventory.SecretsCount -eq 0 -and $vault.SecretInventory.CertificatesCount -eq 0 -and $vault.SecretInventory.KeysCount -eq 0) { "2" }  # Empty vault
                else { "3" }  # Data not available
            }

            $certs = if ($vault.SecretInventory.CertificatesCount -gt 0) { $vault.SecretInventory.CertificatesCount } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                elseif ($vault.SecretInventory.SecretsCount -eq 0 -and $vault.SecretInventory.CertificatesCount -eq 0 -and $vault.SecretInventory.KeysCount -eq 0) { "2" }  # Empty vault
                else { "3" }  # Data not available
            }

            $keys = if ($vault.SecretInventory.KeysCount -gt 0) { $vault.SecretInventory.KeysCount } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                elseif ($vault.SecretInventory.SecretsCount -eq 0 -and $vault.SecretInventory.CertificatesCount -eq 0 -and $vault.SecretInventory.KeysCount -eq 0) { "2" }  # Empty vault
                else { "3" }  # Data not available
            }

            $total = if ($vault.SecretInventory.TotalAssets -gt 0) { $vault.SecretInventory.TotalAssets } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                elseif ($vault.SecretInventory.SecretsCount -eq 0 -and $vault.SecretInventory.CertificatesCount -eq 0 -and $vault.SecretInventory.KeysCount -eq 0) { "2" }  # Empty vault
                else { "3" }  # Data not available
            }

            $recentRotations = if ($vault.RotationAnalysis.RecentlyRotated -gt 0) { $vault.RotationAnalysis.RecentlyRotated } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                else { "3" }  # Data not available
            }

            $needsRotation = if ($vault.RotationAnalysis.ManualRotationNeeded -gt 0) { $vault.RotationAnalysis.ManualRotationNeeded } else {
                if ($vault.AccessControl.AccessPoliciesCount -eq 0 -and -not $vault.AccessControl.RbacEnabled) { "1" }  # Access issue
                else { "3" }  # Data not available
            }

            # Helper function to format status codes with colors
            function Format-StatusCode {
                param([string]$value)
                switch ($value) {
                    "1" { return "<span style='color: #dc3545; font-weight: bold;'>$value</span>" }  # Red for access issues
                    "2" { return "<span style='color: #ffc107; font-weight: bold;'>$value</span>" }  # Yellow for empty vaults
                    "3" { return "<span style='color: #6c757d; font-weight: bold;'>$value</span>" }  # Gray for data not available
                    default { return $value }  # Return actual values as-is
                }
            }

            $vaultAnchor = Make-SafeId -Value ("$($vault.SubscriptionId)-$($vault.VaultName)") -Prefix 'vault'

            # Only make subscription and vault name clickable; render numeric/status columns as plain text (or colored status)
            $html += @"
                <tr>
                        <td style="border: 1px solid #dee2e6; padding: 8px; font-weight: bold;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$subscriptionName</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; font-weight: bold;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($vault.VaultName)</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$(Format-StatusCode $iapmCode)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$(Format-StatusCode $envCode)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$(Format-StatusCode $secrets)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$(Format-StatusCode $certs)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$(Format-StatusCode $keys)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; font-weight: bold;">$(Format-StatusCode $total)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$($vault.ComplianceScore)%</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #28a745;">$(Format-StatusCode $recentRotations)</td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #dc3545;">$(Format-StatusCode $needsRotation)</td>
                    </tr>
"@
        }
    }

    $html += @"
            </table>

            <div style="margin-top: 15px; padding: 10px; background: #e9ecef; border-radius: 5px; border-left: 4px solid #6c757d;">
                <h5>🔢 Status Code Legend</h5>
                <p>Status codes are color-coded to indicate data issues; hover/click cells to view details.</p>
                <ul style="margin: 5px 0; padding-left: 20px;">
                    <li><strong><span style='color: #dc3545;'>1</span> = Access Issue:</strong> Unable to retrieve data due to insufficient permissions or authentication problems</li>
                    <li><strong><span style='color: #ffc107;'>2</span> = Empty Vault:</strong> Vault contains no secrets, certificates, or keys</li>
                    <li><strong><span style='color: #6c757d;'>3</span> = Data Not Available:</strong> Information could not be retrieved or is not applicable</li>
                </ul>
                <p style="margin: 0; font-size: 0.9em; color: #6c757d;">Example row: <em>1ci-preprod-metrics &nbsp; kv-adx-access &nbsp; <span style='color: #ffc107;'>2</span> &nbsp; Unknown &nbsp; <span style='color: #ffc107;'>2</span> &nbsp; <span style='color: #ffc107;'>2</span> &nbsp; <span style='color: #ffc107;'>2</span> &nbsp; <span style='color: #ffc107;'>2</span> &nbsp; <span style='color: #6c757d;'>3</span> &nbsp; <span style='color: #6c757d;'>3</span></em></p>
            </div>

            <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                <h4>📈 Subscription Summary</h4>
                <table style="width: 100%; border-collapse: collapse; margin-top: 15px; background: white;">
                    <tr style="background: #e9ecef;">
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: left;">Subscription</th>
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: center;">Vaults</th>
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: center;">Total Assets</th>
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: center;">Secrets</th>
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: center;">Certificates</th>
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: center;">Keys</th>
                        <th style="border: 1px solid #dee2e6; padding: 10px; text-align: center;">Recent Rotations</th>
                    </tr>
"@

    foreach ($subscriptionGroup in $vaultsBySubscription) {
        $subscriptionName = $subscriptionGroup.Name
        $subscriptionVaults = $subscriptionGroup.Group

        # Calculate subscription totals
        $subTotalSecrets = ($subscriptionVaults | ForEach-Object { $_.SecretInventory.SecretsCount } | Measure-Object -Sum).Sum
        $subTotalCertificates = ($subscriptionVaults | ForEach-Object { $_.SecretInventory.CertificatesCount } | Measure-Object -Sum).Sum
        $subTotalKeys = ($subscriptionVaults | ForEach-Object { $_.SecretInventory.KeysCount } | Measure-Object -Sum).Sum
        $subTotalAssets = $subTotalSecrets + $subTotalCertificates + $subTotalKeys
        $subTotalRotations = ($subscriptionVaults | ForEach-Object { $_.RotationAnalysis.RecentlyRotated } | Measure-Object -Sum).Sum

        # Determine explanations for zero values
        $assetsExplanation = if ($subTotalAssets -eq 0) {
            $emptyVaults = ($subscriptionVaults | Where-Object { $_.SecretInventory.TotalAssets -eq 0 }).Count
            $accessIssueVaults = ($subscriptionVaults | Where-Object { $_.AccessControl.AccessPoliciesCount -eq 0 -and -not $_.AccessControl.RbacEnabled }).Count
            if ($accessIssueVaults -gt 0) { " (Access issues in $accessIssueVaults vault(s))" } elseif ($emptyVaults -gt 0) { " (All vaults empty)" } else { " (No data available)" }
        } else { "" }

        $secretsExplanation = if ($subTotalSecrets -eq 0 -and $subTotalAssets -gt 0) { " (No secrets found)" } else { "" }
        $certsExplanation = if ($subTotalCertificates -eq 0 -and $subTotalAssets -gt 0) { " (No certificates found)" } else { "" }
        $keysExplanation = if ($subTotalKeys -eq 0 -and $subTotalAssets -gt 0) { " (No keys found)" } else { "" }
        $rotationsExplanation = if ($subTotalRotations -eq 0) { " (No recent rotations)" } else { "" }

        $html += @"
                    <tr>
                        <td style="border: 1px solid #dee2e6; padding: 10px; font-weight: bold;">$subscriptionName</td>
                        <td style="border: 1px solid #dee2e6; padding: 10px; text-align: center; font-weight: bold;">$($subscriptionVaults.Count)</td>
                        <td style="border: 1px solid #dee2e6; padding: 10px; text-align: center; font-weight: bold;">$subTotalAssets$assetsExplanation</td>
                        <td style="border: 1px solid #dee2e6; padding: 10px; text-align: center; color: #28a745; font-weight: bold;">$subTotalSecrets$secretsExplanation</td>
                        <td style="border: 1px solid #dee2e6; padding: 10px; text-align: center; color: #ffc107; font-weight: bold;">$subTotalCertificates$certsExplanation</td>
                        <td style="border: 1px solid #dee2e6; padding: 10px; text-align: center; color: #dc3545; font-weight: bold;">$subTotalKeys$keysExplanation</td>
                        <td style="border: 1px solid #dee2e6; padding: 10px; text-align: center; color: #17a2b8; font-weight: bold;">$subTotalRotations$rotationsExplanation</td>
                    </tr>
"@
    }

    $html += @"
                </table>
            </div>
        </div>
    </div>

    <div class="platform-section">
        <h2>☁️ Azure Platform Integration Assessment</h2>

        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
            <h3>📊 Column Definitions</h3>
            <ul style="margin-bottom: 15px;">
                <li><strong>Key Vault Policies:</strong> Number of Azure Policies assigned to enforce Key Vault security standards</li>
                <li><strong>Event Hub Namespaces:</strong> Event Hubs configured for Key Vault diagnostic log streaming</li>
                <li><strong>Log Analytics Workspaces:</strong> Workspaces receiving Key Vault audit logs for monitoring and alerting</li>
                <li><strong>Key Vault RBAC Roles:</strong> Number of Azure RBAC roles defined for Key Vault access management</li>
                <li><strong>Managed Identities:</strong> Azure resources using managed identities for Key Vault authentication</li>
                <li><strong>Service Principals:</strong> Applications using service principal authentication (should be minimized)</li>
                <li><strong>Service Identities:</strong> Total managed identities and service principals with Key Vault access</li>
                <li><strong>Automation Runbooks:</strong> Azure Automation runbooks for Key Vault operations and rotation</li>
            </ul>
            <p><em>These integrations enable comprehensive monitoring, automated rotation, and centralized governance of Key Vault resources.</em></p>
        </div>

        <table>
            <tr><th>Subscription</th><th>Key Vault Policies</th><th>Event Hub Namespaces</th><th>Log Analytics Workspaces</th><th>Key Vault RBAC Roles</th><th>Managed Identities</th><th>Service Principals</th><th>Service Identities</th><th>Automation Runbooks</th></tr>
"@

    foreach ($platform in $PlatformAssessments) {
        $subscriptionDisplay = if ($platform.SubscriptionName) { $platform.SubscriptionName } else { $platform.SubscriptionId }
        $platformAnchor = "platform-$($platform.SubscriptionId)" -replace '[^a-zA-Z0-9_-]', '-'
        $html += @"
            <tr>
                <td>$subscriptionDisplay</td>
                <td>$($platform.Policies.KeyVaultPoliciesCount)</td>
                <td>$($platform.EventHubs.NamespacesCount)</td>
                <td>$($platform.LogAnalytics.WorkspacesCount)</td>
                <td>$($platform.RbacRoles.KeyVaultRolesCount)</td>
                <td>$($platform.ManagedIdentities.Count)</td>
                <td>$($platform.ServicePrincipals.Count)</td>
                <td>$($platform.ServiceIdentities.Count)</td>
                <td>$($platform.Runbooks.KeyVaultRunbooksCount)</td>
            </tr>
"@
    }

    $html += @"
        </table>

        <h3>🔧 Azure Policy Details</h3>
        <div style="margin-top: 15px; margin-bottom: 20px;">
            <p><a href="$policyDetailsFileName" target="_blank" style="background: #007bff; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; display: inline-block;">📋 View Detailed Policy Analysis</a></p>
            <p style="margin-top: 10px; color: #666;">Click the link above to see a comprehensive breakdown of all Key Vault policies across subscriptions, including policy summaries and detailed listings.</p>
        </div>

        <h3>📊 Key Vault Policy Summary</h3>
        <div style="margin-top: 15px;">
"@

    # Create condensed policy summary
    $allPolicies = @()
    foreach ($platform in $PlatformAssessments) {
        foreach ($policy in $platform.Policies.KeyVaultPolicies) {
            $policyInfo = @{
                Name = $policy.Properties.DisplayName
                Type = $policy.Properties.PolicyType
                SubscriptionName = $platform.SubscriptionName
            }
            $allPolicies += $policyInfo
        }
    }

    if ($allPolicies.Count -gt 0) {
        $policySummary = $allPolicies | Group-Object -Property Name | Sort-Object -Property Count -Descending | Select-Object -First 10

        $html += @"
            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
                <strong>Top 10 Most Common Key Vault Policies:</strong>
                <ul style="margin-top: 10px;">
"@

        foreach ($policy in $policySummary) {
            $subscriptions = ($policy.Group | Select-Object -ExpandProperty SubscriptionName -Unique) -join ", "
            $html += "<li><strong>$($policy.Name)</strong> - Used in $($policy.Count) subscription(s): $subscriptions</li>"
        }

        $html += @"
                </ul>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">Total unique Key Vault policies found: $(($allPolicies | Select-Object -Property Name -Unique).Count)</p>
            </div>
"@
    } else {
        $html += @"
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #ffeaa7;">
                <strong>No Key Vault policies found</strong><br>
                Consider implementing Azure Policies for Key Vault governance and security compliance.
            </div>
"@
    }

    $html += @"
        </div>

        <h3>🔍 Azure Policy Analysis & Recommendations</h3>
        <div style="margin-top: 15px;">
"@

    # Analyze current policies and suggest missing ones
    $essentialPolicies = @(
        @{ Name = "Key vaults should have soft delete enabled"; Priority = "Critical"; Reason = "Prevents accidental data loss and enables recovery from ransomware attacks" },
        @{ Name = "Key vaults should have purge protection enabled"; Priority = "Critical"; Reason = "Provides additional protection against data loss by preventing immediate deletion" },
        @{ Name = "Key vaults should use RBAC permission model"; Priority = "High"; Reason = "RBAC provides better security, auditability, and centralized access management" },
        @{ Name = "Key vaults should have maximum certificate validity period"; Priority = "High"; Reason = "Prevents certificates from being valid for excessively long periods" },
        @{ Name = "Key vaults should have maximum key validity period"; Priority = "High"; Reason = "Ensures cryptographic keys are rotated regularly for security" },
        @{ Name = "Key vaults should have maximum secret validity period"; Priority = "High"; Reason = "Prevents secrets from being valid indefinitely, enforcing rotation" },
        @{ Name = "Key vaults should have firewall enabled"; Priority = "Medium"; Reason = "Restricts network access to approved networks only" },
        @{ Name = "Key vaults should use private link"; Priority = "Medium"; Reason = "Prevents data exfiltration over public networks" },
        @{ Name = "Key vaults should have diagnostic settings enabled"; Priority = "Medium"; Reason = "Enables monitoring, auditing, and security alerting" },
        @{ Name = "Resource logs in Key Vault should be enabled"; Priority = "Medium"; Reason = "Provides audit trails for compliance and security monitoring" }
    )

    $currentPolicyNames = $allPolicies | Select-Object -ExpandProperty Name -Unique
    $missingPolicies = $essentialPolicies | Where-Object { $_.Name -notin $currentPolicyNames }

    if ($missingPolicies.Count -gt 0) {
        $html += @"
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #ffeaa7;">
                <h4>⚠️ Missing Critical Azure Policies</h4>
                <p>The following essential Key Vault security policies are not implemented:</p>
                <ul style="margin-top: 10px;">
"@

        # Sort policies by priority: Critical first, then High, Medium, Low
        $priorityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4 }
        foreach ($policy in $missingPolicies | Sort-Object { $priorityOrder[$_.Priority] }) {
            $priorityColor = switch ($policy.Priority) {
                "Critical" { "#dc3545" }
                "High" { "#fd7e14" }
                "Medium" { "#ffc107" }
                default { "#6c757d" }
            }
            $html += "<li><strong style='color: $priorityColor;'>[$($policy.Priority)]</strong> $($policy.Name)<br><em>$($policy.Reason)</em></li>"
        }

        $html += @"
                </ul>
                <p style="margin-top: 15px;"><strong>💡 Implementation Steps:</strong></p>
                <ol>
                    <li>Go to <strong>Azure Policy → Definitions</strong> in the Azure Portal</li>
                    <li>Search for 'Key Vault' to find built-in policies</li>
                    <li>Assign policies at management group or subscription level</li>
                    <li>Set <strong>Policy enforcement</strong> to 'Enabled' for immediate effect</li>
                    <li>Monitor compliance through the <strong>Policy → Compliance</strong> dashboard</li>
                    <li>Create custom policies for organization-specific requirements</li>
                </ol>
            </div>
"@

        # Suggest policy initiatives
        $html += @"
            <div style="background: #d1ecf1; padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #bee5eb;">
                <h4>📋 Recommended Policy Initiatives</h4>
                <p>Consider implementing these comprehensive policy initiatives:</p>
                <ul>
                    <li><strong>ISO 27001:2013</strong> - Information security management standards</li>
                    <li><strong>CIS Microsoft Azure Foundations Benchmark</strong> - Industry security best practices</li>
                    <li><strong>NIST SP 800-53 Rev. 5</strong> - U.S. government security controls</li>
                    <li><strong>Azure Security Benchmark</strong> - Microsoft's comprehensive security guidance</li>
                </ul>
                <p><em>Policy initiatives bundle multiple related policies for easier management and compliance reporting.</em></p>
            </div>
"@
    } else {
        $html += @"
            <div style="background: #d4edda; padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #c3e6cb;">
                <h4>✅ Comprehensive Policy Coverage</h4>
                <p>All essential Key Vault security policies are implemented. Consider regular policy reviews and updates as new threats emerge.</p>
            </div>
"@
    }

    $html += @"
        </div>

        <h3>🛡️ Key Vault Access Control Summary</h3>
        <div style="margin-top: 15px;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background: #e9ecef;">
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Vault Name</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">Subscription</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Access Control Type</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">RBAC Status</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Access Policies</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Actions</th>
                </tr>
"@

    foreach ($vault in $AnalysisResults) {
        $vaultName = $vault.VaultName
        $subscriptionName = $vault.SubscriptionName
        $rbacEnabled = $vault.AccessControl.RbacEnabled
        $accessPoliciesCount = $vault.AccessControl.AccessPoliciesCount

        $accessControlType = if ($rbacEnabled) { "Azure RBAC" } else { "Access Policies" }
        $rbacStatus = if ($rbacEnabled) { "✅ Enabled" } else { "⚠️ Disabled" }
        $statusColor = if ($rbacEnabled) { "#28a745" } else { "#ffc107" }

        $html += @"
                <tr>
                    <td style="border: 1px solid #dee2e6; padding: 8px; font-weight: bold;">$vaultName</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px;">$subscriptionName</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$accessControlType</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: $statusColor; font-weight: bold;">$rbacStatus</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">$accessPoliciesCount</td>
                    <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">
                        <button onclick="showRbacDetails('$vaultName')" style="padding: 3px 8px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 0.8em;">
                            View Details
                        </button>
                    </td>
                </tr>
"@
    }

    $html += @"
            </table>

            <div id="rbacDetails" style="display: none; margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                <h4>Access Control Details for <span id="selectedVault"></span></h4>
                <div id="rbacContent"></div>
                <button onclick="hideRbacDetails()" style="margin-top: 10px; padding: 5px 10px; background: #6c757d; color: white; border: none; border-radius: 3px; cursor: pointer;">
                    Close
                </button>
            </div>

            <script>
                function showRbacDetails(vaultName) {
                    document.getElementById('selectedVault').textContent = vaultName;
                    document.getElementById('rbacDetails').style.display = 'block';

                    // This would need to be populated with actual RBAC role assignments for the vault
                    // For now, showing available Key Vault roles in the subscription
                    var content = '<p><strong>Available Key Vault RBAC Roles in this subscription:</strong></p><ul>';

                    // Add common Key Vault roles
                    var roles = [
                        'Key Vault Administrator - Full access to all operations',
                        'Key Vault Secrets Officer - Manage secrets',
                        'Key Vault Crypto Officer - Manage keys',
                        'Key Vault Certificates Officer - Manage certificates',
                        'Key Vault Reader - Read all objects',
                        'Key Vault Secrets User - Read secret contents',
                        'Key Vault Crypto User - Perform crypto operations'
                    ];

                    roles.forEach(function(role) {
                        content += '<li>' + role + '</li>';
                    });

                    content += '</ul>';
                    content += '<p style="color: #6c757d; font-size: 0.9em;"><em>Note: This shows available roles. Actual assignments depend on current RBAC configuration.</em></p>';

                    document.getElementById('rbacContent').innerHTML = content;
                }

                function hideRbacDetails() {
                    document.getElementById('rbacDetails').style.display = 'none';
                }
            </script>
        </div>
    </div>

    <div class="vault-details">
        <h2>🔐 Key Vault Details</h2>
        <table>
            <tr><th>Vault Name</th><th>Subscription</th><th>Location</th><th><a class="framework-link" href="https://www.cisecurity.org/benchmark/azure/" target="_blank" title="CIS Azure Foundations Benchmark">CIS Score</a></th><th><a class="framework-link" href="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/r5/" target="_blank" title="NIST Cybersecurity Framework">NIST Score</a></th><th><a class="framework-link" href="https://www.iso.org/standard/54534.html" target="_blank" title="ISO 27001 Information Security">ISO Score</a></th><th><a class="framework-link" href="https://learn.microsoft.com/en-us/azure/key-vault/general/security-baseline" target="_blank" title="Microsoft Security Baseline">MS Baseline</a></th><th>Overall</th><th>Risk Level</th><th>Diagnostics</th><th>RBAC</th><th>Private Endpoints</th><th>Security Gaps</th></tr>
"@

    function Make-SafeId {
        param(
            [Parameter(Mandatory=$true)][string]$Value,
            [string]$Prefix = 'id'
        )
        if ($null -eq $Value) { $Value = '' }
        $s = $Value -as [string]
        $s = $s.ToLowerInvariant()
        # collapse whitespace and replace non-alphanumerics with '-'
        $s = $s -replace '\s+','-'
        $s = $s -replace '[^a-z0-9\-_]','-'
        $s = $s -replace '-+','-'
        $s = $s.Trim('-')
        # ensure ID doesn't start with a digit
        if ($s -match '^[0-9]') { $s = "$Prefix-$s" }
        if (-not $s) { $s = "$Prefix-0" }
        return $s
    }

    foreach ($vault in $AnalysisResults) {
        # Precompute a stable anchor id for this vault so the table row and embedded JSON use the same id
        $vaultAnchorId = Make-SafeId -Value "$($vault.SubscriptionId)-$($vault.VaultName)" -Prefix 'vault'
        $riskClass = switch ($vault.RiskLevel) {
            "Low" { "risk-low" }
            "Medium" { "risk-medium" }
            "High" { "risk-high" }
            "Critical" { "risk-critical" }
        }

        $html += @"
            <tr>
                <td><a id="$vaultAnchorId"></a>$($vault.VaultName)</td>
                <td>$($vault.SubscriptionName)</td>
                <td>$($vault.Location)</td>
                <td><span class="score-value">$($vault.CISComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.NISTComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.ISOComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.MSComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.ComplianceScore)%</span></td>
                <td class="$riskClass">$($vault.RiskLevel)</td>
                <td>$($vault.Diagnostics.HasDiagnostics ? "✅" : "❌")</td>
                <td>$($vault.AccessControl.RbacEnabled ? "✅" : "❌")</td>
                <td>$($vault.NetworkSecurity.HasPrivateEndpoints ? "✅" : "❌")</td>
                <td>
"@

        if ($vault.SecurityGaps.Count -gt 0) {
            $gapList = $vault.SecurityGaps | ForEach-Object { "$($_.Severity): $($_.Issue)" }
            $html += $gapList -join "<br>"
        } else {
            $html += "None"
        }

        $html += @"
                </td>
            </tr>
"@
    }

    $html += @"
        </table>
    </div>

    <!-- Embedded JSON blobs for modal popups -->
"@

    # Add platform JSON blobs
    foreach ($platform in $PlatformAssessments) {
        $platformAnchor = Make-SafeId -Value ($platform.SubscriptionId -as [string]) -Prefix 'platform'
        $safeJson = (Normalize-ForJson $platform | ConvertTo-Json -Depth 4 -Compress) -replace '</', '<\/'
        $html += "<script type='application/json' id='$platformAnchor'>`n$safeJson`n</script>`n"
    }

    # Add vault JSON blobs
    foreach ($vault in $AnalysisResults) {
        # Ensure we compute a stable anchor id for this vault so the table row and embedded JSON use the same id
        $vaultAnchorId = Make-SafeId -Value ("$($vault.SubscriptionId)-$($vault.VaultName)") -Prefix 'vault'
        $vaultPayload = @{
            VaultName = $vault.VaultName
            SubscriptionName = $vault.SubscriptionName
            SubscriptionId = $vault.SubscriptionId
            ResourceId = $vault.Vault.ResourceId
            Location = $vault.Location
            SecretsCount = $vault.SecretInventory.SecretsCount
            CertificatesCount = $vault.SecretInventory.CertificatesCount
            KeysCount = $vault.SecretInventory.KeysCount
            TotalAssets = $vault.SecretInventory.TotalAssets
            Diagnostics = $vault.Diagnostics
            AccessControl = $vault.AccessControl
            NetworkSecurity = $vault.NetworkSecurity
            Rotation = $vault.RotationAnalysis
            Compliance = @{
                CIS = $vault.CISComplianceScore; NIST = $vault.NISTComplianceScore; ISO = $vault.ISOComplianceScore; MS = $vault.MSComplianceScore
            }
            # Flattened scalar fields for reliable client-side display
            VaultScore = ($vault.ComplianceScore -as [int]) ?? 0
            RoleAssignmentsResolved = ($vault.Extra.RoleAssignmentsResolved -as [string])
            ManagedIdentityResolved = ($vault.Extra.ManagedIdentityResolved -as [string])
            DiagnosticDestinationNames = ($vault.Extra.DiagnosticDestinationsResolved -as [string])
            SkuName = ($vault.Extra.SkuName -as [string])
            SecretRotationMostRecent = ($vault.Extra.SecretRotationMostRecent -as [string])
            KeyRotationMostRecent = ($vault.Extra.KeyRotationMostRecent -as [string])
            JsonFilePath = ($vault.JsonFilePath -as [string])
            Tags = if ($vault.Vault.Tags) {
                # Normalize tags into a simple ordered hashtable to make JSON/HTML embedding predictable
                $t = @{}
                foreach ($k in $vault.Vault.Tags.Keys) { $t[$k] = $vault.Vault.Tags[$k] }
                $t
            } else { @{} }
            SecurityGaps = $vault.SecurityGaps
            QuickWins = $vault.QuickWins
        }
        # Ensure SecurityGaps and QuickWins are normalized for JSON embedding
        try {
            $vaultPayload.SecurityGaps = if ($vaultPayload.SecurityGaps) { Normalize-ForJson $vaultPayload.SecurityGaps } else { @() }
        } catch { $vaultPayload.SecurityGaps = @() }
        try {
            $vaultPayload.QuickWins = if ($vaultPayload.QuickWins) { Normalize-ForJson $vaultPayload.QuickWins } else { @() }
        } catch { $vaultPayload.QuickWins = @() }

        # Compress vault payload JSON to limit size in the HTML output, escape '</' for safe embedding
        try {
            $safeVaultJson = (Normalize-ForJson $vaultPayload | ConvertTo-Json -Depth 4 -Compress) -replace '</', '<\\/'
        } catch {
            # fallback minimal payload when serialization fails
            $fallback = @{ VaultName = ($vault.VaultName -as [string]); SubscriptionId = ($vault.SubscriptionId -as [string]); VaultScore = ($vault.ComplianceScore -as [int]) }
            $safeVaultJson = (Normalize-ForJson $fallback | ConvertTo-Json -Depth 2 -Compress) -replace '</', '<\\/'
        }
        $html += "<script type='application/json' id='$vaultAnchorId'>`n$safeVaultJson`n</script>`n"
    }

    # Embed permissions issues so the UI can surface them (if any)
    # Ensure we always embed a JSON array (empty array when no issues)
    $permsForEmbed = if ($PermissionsIssues -and $PermissionsIssues.Count -gt 0) { $PermissionsIssues } else { @() }
    $safePermsJson = (Normalize-ForJson $permsForEmbed | ConvertTo-Json -Depth 4 -Compress) -replace '</', '<\/'
    $html += "<script type='application/json' id='permissions-issues'>`n$safePermsJson`n</script>`n"

    # Also write a CSV of permissions/issues to the output directory for easier inspection
    try {
        if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
        $permsCsvPath = Join-Path $outputDir "KeyVaultGapAnalysis_permissions_$timestamp.csv"
    if ($PermissionsIssues -and $PermissionsIssues.Count -gt 0) {
            # Normalize PSObjects to objects with expected columns
            $csvRecords = $PermissionsIssues | ForEach-Object {
                    [PSCustomObject]@{
                    Timestamp     = $_.Timestamp
                    Component     = $_.Component
                    Subscription  = $_.Subscription
                    Message       = $_.Message
                    Cmdlet        = ($_.Cmdlet -as [string])
                    ResourceId    = ($_.ResourceId -as [string])
                    SuggestedRole = ($_.SuggestedRole -as [string])
                }
            }
            $csvRecords | Export-Csv -Path $permsCsvPath -NoTypeInformation -Encoding UTF8
            Write-Log "Permissions issues CSV written: $permsCsvPath" -Level "INFO"

            # Also write a copy into the repository workspace for easier inspection during development
                try {
                    $repoCopyPath = Join-Path 'c:\Source\Github\powershell-akv-audit' "KeyVaultGapAnalysis_permissions_$timestamp.csv"
                    $csvRecords | Export-Csv -Path $repoCopyPath -NoTypeInformation -Encoding UTF8
                    Write-Log "Permissions issues CSV copied to workspace: $repoCopyPath" -Level "INFO"
                } catch {
                    Write-Log "Failed to write workspace copy of permissions CSV: $($_.Exception.Message)" -Level "WARN"
                    # Record the failure so it surfaces in the embedded permissions issues
                    $PermissionsIssues += [PSCustomObject]@{ Timestamp = (Get-Date); Component = 'CSVWrite'; Subscription = ''; Message = "Failed to write workspace copy: $($_.Exception.Message)" }
                }
        } else {
            # No permission issues found: write a CSV copy with header and a human-readable note row so reviewers see the artifact
            try {
                $repoCopyPath = Join-Path 'c:\Source\Github\powershell-akv-audit' "KeyVaultGapAnalysis_permissions_$timestamp.csv"
                $header = [PSCustomObject]@{ Timestamp = ''; Component = ''; Subscription = ''; Message = '' }
                $note = [PSCustomObject]@{ Timestamp = (Get-Date).ToString('o'); Component = 'Info'; Subscription = ''; Message = 'No permission issues recorded during this run' }
                $header | Export-Csv -Path $repoCopyPath -NoTypeInformation -Encoding UTF8
                $note | Export-Csv -Path $repoCopyPath -NoTypeInformation -Encoding UTF8 -Append
                Write-Log "Permissions CSV (note) written to workspace: $repoCopyPath" -Level "INFO"
            } catch {
                Write-Log "Failed to write empty permissions CSV to workspace: $($_.Exception.Message)" -Level "WARN"
            }
        }
    } catch {
        Write-Log "Failed to write permissions CSV: $($_.Exception.Message)" -Level "WARN"
        # Ensure we record the failure so the UI can show it
        $PermissionsIssues += [PSCustomObject]@{ Timestamp = (Get-Date); Component = 'CSVWrite'; Subscription = ''; Message = "Failed to write permissions CSV: $($_.Exception.Message)" }
    }

    $html += @"

    <!-- Modal markup (hidden by default) -->
    <div id="detailsModal" style="display:none; position: fixed; top: 0; left: 0; width:100%; height:100%; background: rgba(0,0,0,0.5); z-index: 9999;">
        <div style="background: white; max-width: 900px; margin: 40px auto; padding: 20px; border-radius: 6px; position: relative;">
            <button onclick="closeDetailsModal()" style="position:absolute; right:12px; top:12px; background:#dc3545; color:white; border:none; padding:6px 10px; border-radius:4px; cursor:pointer;">Close</button>
            <div id="detailsModalContent"></div>
        </div>
    </div>

    <script>
        // Safer, structured modal renderer to avoid accidental string-artifact injection
        function showDetailsModal(id, type) {
            try {
                var blob = document.getElementById(id);
                if (!blob) { alert('Details not available for ' + id); return; }
                var data = {};
                try { data = JSON.parse(blob.textContent || blob.innerText); } catch(e) { data = {}; }

                // clear previous content
                var container = document.getElementById('detailsModalContent');
                container.innerHTML = '';

                var title = document.createElement('h3');
                title.style.margin = '0 0 8px 0';
                if (type === 'platform') {
                    title.textContent = 'Platform assessment for ' + (data.SubscriptionName || data.SubscriptionId || 'Platform');
                    container.appendChild(title);
                    var p = document.createElement('p');
                    p.innerHTML = '<strong>Key Vault Policies:</strong> ' + (data.Policies ? data.Policies.KeyVaultPoliciesCount : 'N/A');
                    container.appendChild(p);
                    // show raw JSON collapsible
                    var details = document.createElement('details');
                    details.style.marginTop = '10px';
                    var summary = document.createElement('summary'); summary.style.cursor = 'pointer'; summary.textContent = 'Raw platform JSON';
                    var pre = document.createElement('pre'); pre.style.whiteSpace = 'pre-wrap'; pre.style.background = '#f8f9fa'; pre.style.padding = '10px'; pre.style.borderRadius = '4px';
                    pre.textContent = JSON.stringify(data, null, 2);
                    details.appendChild(summary); details.appendChild(pre); container.appendChild(details);
                } else {
                    title.textContent = 'Vault: ' + (data.VaultName || id);
                    container.appendChild(title);
                    var copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy JSON';
                    copyBtn.style.cssText = 'background:#2b9af3;color:white;border:none;padding:6px 10px;border-radius:4px;cursor:pointer;margin-left:8px;';
                    copyBtn.onclick = function(){ navigator.clipboard.writeText(JSON.stringify(data, null, 2)); alert('Vault JSON copied to clipboard'); };
                    container.appendChild(copyBtn);

                    var table = document.createElement('table'); table.style.width = '100%'; table.style.borderCollapse = 'collapse'; table.style.marginTop = '8px';
                    function addRow(k,v) {
                        var tr = document.createElement('tr');
                        var td1 = document.createElement('td'); td1.style.padding = '6px'; td1.style.border = '1px solid #eee'; td1.innerHTML = '<strong>'+k+'</strong>';
                        var td2 = document.createElement('td'); td2.style.padding='6px'; td2.style.border='1px solid #eee'; td2.textContent = (v===undefined||v===null)?'':v;
                        tr.appendChild(td1); tr.appendChild(td2); table.appendChild(tr);
                    }
                    addRow('Subscription', data.SubscriptionName || data.SubscriptionId || '');
                    addRow('Location', data.Location || 'N/A');
                    addRow('Secrets / Certs / Keys', (data.SecretsCount||0) + ' / ' + (data.CertificatesCount||0) + ' / ' + (data.KeysCount||0) + ' (Total: ' + (data.TotalAssets||0) + ')');
                    addRow('Diagnostics', (data.Diagnostics && data.Diagnostics.HasDiagnostics) ? '✅' : '❌');
                    addRow('RBAC', (data.AccessControl && data.AccessControl.RbacEnabled) ? '✅' : '❌');
                    addRow('Private endpoints', (data.NetworkSecurity && data.NetworkSecurity.HasPrivateEndpoints) ? '✅' : '❌');
                    addRow('Rotation needs', (data.Rotation && data.Rotation.ManualRotationNeeded) ? data.Rotation.ManualRotationNeeded : 0);
                    addRow('Compliance (CIS/NIST)', 'CIS ' + ((data.Compliance && data.Compliance.CIS)?data.Compliance.CIS:'N/A') + '%, NIST ' + ((data.Compliance && data.Compliance.NIST)?data.Compliance.NIST:'N/A') + '%');
                    if (typeof data.VaultScore !== 'undefined') { addRow('Overall Score', (data.VaultScore) + '%'); }
                    if (data.RoleAssignmentsResolved) { addRow('Role Assignments', data.RoleAssignmentsResolved); }
                    if (data.ManagedIdentityResolved) { addRow('Managed Identities', data.ManagedIdentityResolved); }
                    if (data.DiagnosticDestinationNames) { addRow('Diagnostics Destinations', data.DiagnosticDestinationNames); }
                    if (data.SkuName) { addRow('SKU', data.SkuName); }
                    if (data.SecretRotationMostRecent) { addRow('Most Recent Secret Rotation', data.SecretRotationMostRecent); }
                    if (data.KeyRotationMostRecent) { addRow('Most Recent Key Rotation', data.KeyRotationMostRecent); }
                    if (data.JsonFilePath) { addRow('JSON Path', data.JsonFilePath); }
                    container.appendChild(table);

                    if (data.Tags) {
                        var th = document.createElement('h4'); th.textContent = '🏷️ Tags'; container.appendChild(th);
                        var ul = document.createElement('ul'); Object.keys(data.Tags).forEach(function(k){ var li = document.createElement('li'); li.innerHTML = '<strong>'+k+':</strong> '+data.Tags[k]; ul.appendChild(li); }); container.appendChild(ul);
                    }

                    if (data.QuickWins && data.QuickWins.length>0) {
                        var qh = document.createElement('h4'); qh.textContent='🎯 Quick Wins'; container.appendChild(qh);
                        var ql = document.createElement('ul'); data.QuickWins.slice(0,20).forEach(function(w){ var li=document.createElement('li'); li.innerHTML = '<strong>'+ (w.Title||'') +'</strong> - '+(w.Description||''); ql.appendChild(li); }); container.appendChild(ql);
                    }

                    if (data.SecurityGaps && data.SecurityGaps.length>0) {
                        var gh = document.createElement('h4'); gh.textContent='🚨 Security Gaps'; container.appendChild(gh);
                        var gl = document.createElement('ul'); data.SecurityGaps.slice(0,50).forEach(function(g){ var li=document.createElement('li'); li.innerHTML = '<strong>['+ (g.Severity||'') +']</strong> '+ (g.Issue||'') + ' - ' + (g.Impact||''); gl.appendChild(li); }); container.appendChild(gl);
                    }
                }

                document.getElementById('detailsModal').style.display = 'block';
            } catch(e) {
                console.error('Error rendering details modal', e);
                alert('Failed to render details: ' + e.message);
            }
        }
        function closeDetailsModal(){ var m=document.getElementById('detailsModal'); if (m) { m.style.display='none'; } }
    </script>

    <div class="recommendations">
        <h2>💡 Security Recommendations & Best Practices</h2>
        <ul>
            <li><strong>Enable Azure RBAC:</strong> Migrate from access policies to Azure RBAC for better security and management</li>
            <li><strong>Configure Diagnostics:</strong> Enable diagnostic settings for all Key Vaults to capture audit logs and metrics</li>
            <li><strong>Implement Private Endpoints:</strong> Use private endpoints to secure network access and prevent data exfiltration</li>
            <li><strong>Enable Soft Delete:</strong> Protect against accidental deletion of keys, secrets, and certificates</li>
            <li><strong>Purge Protection:</strong> Enable purge protection to prevent forced deletion during retention period</li>
            <li><strong>Network Restrictions:</strong> Configure network ACLs and firewall rules to limit access</li>
            <li><strong>Regular Audits:</strong> Perform regular security assessments and compliance reviews</li>
            <li><strong>Azure Policy:</strong> Implement Azure Policies for Key Vault governance and compliance</li>
        </ul>
    </div>

    <div class="real-world-examples">
        <h2>🔎 Real-World AKV Examples (from inventory)</h2>
        <p>Selected examples pulled from your analyzed Key Vaults — quick wins and actionable recommendations tailored to each vault.</p>
"@

    # Choose up to 3 example vaults prioritizing those with QuickWins or SecurityGaps
    $exampleVaults = @()
    $exampleVaults += $AnalysisResults | Where-Object { $_.QuickWins.Count -gt 0 } | Select-Object -First 3
    if ($exampleVaults.Count -lt 3) { $exampleVaults += $AnalysisResults | Where-Object { $_.SecurityGaps.Count -gt 0 } | Select-Object -First (3 - $exampleVaults.Count) }
    if ($exampleVaults.Count -lt 3) { $exampleVaults += $AnalysisResults | Select-Object -First (3 - $exampleVaults.Count) }

    foreach ($ev in $exampleVaults) {
        $html += @"
        <div style="background:#f8f9fa;padding:10px;margin:8px 0;border-radius:6px;">
            <strong>$($ev.VaultName)</strong> — $($ev.SubscriptionName)<br>
            <em>Top Quick Wins:</em>
            <ul>
"@

        if ($ev.QuickWins -and $ev.QuickWins.Count -gt 0) {
            foreach ($w in $ev.QuickWins | Select-Object -First 5) {
                $html += "<li><strong>$($w.Title)</strong>: $($w.Description)</li>`n"
            }
        } else {
            $html += "<li>No quick wins identified; review security gaps for remediation.</li>`n"
        }

        # Add a one-line actionable command where applicable (best-effort)
        if ($ev.QuickWins -and $ev.QuickWins.Count -gt 0) {
            $first = $ev.QuickWins[0]
            if ($first.Title -like '*Enable Soft Delete*') {
                $html += "</ul><p><code>Update-AzKeyVault -VaultName $($ev.VaultName) -EnableSoftDelete</code></p>`n"
            } elseif ($first.Title -like '*Enable Diagnostic*' -or $first.Title -like '*Diagnostic*') {
                $html += "</ul><p><code>Set-AzDiagnosticSetting -ResourceId $($ev.Vault.ResourceId) -WorkspaceId &lt;log-analytics-id&gt; -Enabled $true</code></p>`n"
            } elseif ($first.Title -like '*Migrate to Azure RBAC*' -or $first.Title -like '*RBAC*') {
                $html += "</ul><p><code>Update-AzKeyVault -VaultName $($ev.VaultName) -EnableRbacAuthorization $true</code></p>`n"
            } else {
                $html += "</ul>"
            }
        } else { $html += "</ul>" }

        $html += "</div>`n"
    }

    $html += @"

    <div class="service-interactions">
        <h2>🔗 Azure Key Vault Service Interactions & Authentication Guidance</h2>

        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
            <h3>🤖 Non-Human Identity Interactions</h3>
            <p>Non-human identities (applications, services, and automated processes) require secure authentication to access Key Vault resources. The following guidance covers common scenarios and recommended authentication patterns:</p>

            <div style="margin: 15px 0;">
                <h4>🔐 Service Principals (Application Identities)</h4>
                <ul>
                    <li><strong>Use Case:</strong> Web applications, APIs, background services, and CI/CD pipelines</li>
                    <li><strong>Recommended Approach:</strong> Use certificate-based authentication instead of client secrets</li>
                    <li><strong>Security Benefits:</strong> Certificate rotation is automated, no secrets in configuration, stronger authentication</li>
                    <li><strong>Implementation:</strong>
                        <ul>
                            <li>Store certificates in Key Vault and use them for service principal authentication</li>
                            <li>Implement certificate auto-rotation using Azure Automation or Azure Functions</li>
                            <li>Use Azure AD managed identities where possible instead of service principals</li>
                        </ul>
                    </li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>⚙️ Automation & DevOps</h4>
                <ul>
                    <li><strong>Use Case:</strong> Azure DevOps pipelines, GitHub Actions, Jenkins, and other CI/CD systems</li>
                    <li><strong>Recommended Approach:</strong> Use workload identity federation or managed identities</li>
                    <li><strong>Security Benefits:</strong> No long-lived secrets, automatic token management, reduced attack surface</li>
                    <li><strong>Implementation:</strong>
                        <ul>
                            <li>Azure DevOps: Use service connections with workload identity federation</li>
                            <li>GitHub Actions: Configure OpenID Connect (OIDC) for Azure</li>
                            <li>Grant minimal required permissions using Azure RBAC roles</li>
                        </ul>
                    </li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>🔄 Batch Processing & Scheduled Jobs</h4>
                <ul>
                    <li><strong>Use Case:</strong> Azure Functions (timer-triggered), Azure Automation runbooks, Azure Logic Apps</li>
                    <li><strong>Recommended Approach:</strong> System-assigned managed identities with minimal privilege</li>
                    <li><strong>Security Benefits:</strong> No credential management, automatic scaling, built-in rotation</li>
                    <li><strong>Implementation:</strong>
                        <ul>
                            <li>Enable managed identity on the Azure resource</li>
                            <li>Grant Key Vault RBAC roles (Key Vault Secrets User, Key Vault Crypto User, etc.)</li>
                            <li>Use Azure Key Vault references in App Settings for Azure Functions</li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>

        <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
            <h3>☁️ Azure Native Service Interactions</h3>
            <p>Azure platform services have built-in integration patterns with Key Vault for securing authentication flows and data access. These integrations provide secure, managed authentication without manual credential handling:</p>

            <div style="margin: 15px 0;">
                <h4>🖥️ Compute Services (VMs, VMSS, App Services)</h4>
                <ul>
                    <li><strong>Authentication Pattern:</strong> System-assigned or user-assigned managed identities</li>
                    <li><strong>Key Vault Integration:</strong> Direct access using Azure.Identity libraries or Key Vault references</li>
                    <li><strong>Security Flow:</strong> Azure IMDS → Managed Identity token → Key Vault access</li>
                    <li><strong>Recommendations:</strong>
                        <ul>
                            <li>Use system-assigned managed identities for single-resource scenarios</li>
                            <li>Use user-assigned managed identities for cross-resource access patterns</li>
                            <li>Implement Key Vault references in App Service configuration</li>
                            <li>Enable Azure Disk Encryption with Key Vault for VM data protection</li>
                        </ul>
                    </li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>⚡ Serverless & Event-Driven (Functions, Logic Apps, Event Grid)</h4>
                <ul>
                    <li><strong>Authentication Pattern:</strong> System-assigned managed identities with Key Vault references</li>
                    <li><strong>Key Vault Integration:</strong> Native Key Vault binding and reference syntax</li>
                    <li><strong>Security Flow:</strong> Function execution context → Managed Identity → Key Vault</li>
                    <li><strong>Recommendations:</strong>
                        <ul>
                            <li>Use Key Vault references in function app settings (@Microsoft.KeyVault(...))</li>
                            <li>Implement managed identities for custom code accessing Key Vault</li>
                            <li>Use Azure Event Grid integration for Key Vault event-driven scenarios</li>
                            <li>Enable diagnostic logging for audit trails</li>
                        </ul>
                    </li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>🗄️ Data Services (SQL Database, Storage, Cosmos DB)</h4>
                <ul>
                    <li><strong>Authentication Pattern:</strong> Service-managed identities or Key Vault integration</li>
                    <li><strong>Key Vault Integration:</strong> Transparent key management and credential storage</li>
                    <li><strong>Security Flow:</strong> Service authentication → Key Vault → Data access</li>
                    <li><strong>Recommendations:</strong>
                        <ul>
                            <li>Use Azure SQL Database managed identities with Key Vault</li>
                            <li>Implement Storage account key rotation via Key Vault</li>
                            <li>Use customer-managed keys (CMK) for data encryption at rest</li>
                            <li>Enable Azure Monitor integration for access pattern analysis</li>
                        </ul>
                    </li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>🚀 Containers & Orchestration (AKS, Container Instances)</h4>
                <ul>
                    <li><strong>Authentication Pattern:</strong> Workload identity or pod-managed identities</li>
                    <li><strong>Key Vault Integration:</strong> Azure Key Vault Provider for Secrets Store CSI Driver</li>
                    <li><strong>Security Flow:</strong> Pod identity → Azure AD → Key Vault access</li>
                    <li><strong>Recommendations:</strong>
                        <ul>
                            <li>Implement Azure AD workload identity for AKS pods</li>
                            <li>Use Secrets Store CSI Driver for native Kubernetes integration</li>
                            <li>Enable pod security policies and network policies</li>
                            <li>Implement secret rotation and audit logging</li>
                        </ul>
                    </li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>🔒 Security & Identity Services (Azure AD, PIM, Sentinel)</h4>
                <ul>
                    <li><strong>Authentication Pattern:</strong> Service principals with minimal privilege</li>
                    <li><strong>Key Vault Integration:</strong> Certificate-based authentication and key management</li>
                    <li><strong>Security Flow:</strong> Azure AD authentication → Certificate validation → Key Vault</li>
                    <li><strong>Recommendations:</strong>
                        <ul>
                            <li>Use Azure AD Privileged Identity Management (PIM) for just-in-time access</li>
                            <li>Implement certificate-based service principal authentication</li>
                            <li>Enable Azure Sentinel integration for threat detection</li>
                            <li>Use Azure AD conditional access policies</li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>

        <div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #4a90e2;">
            <h3>🔐 Secrets Management for Workloads</h3>
            <p>Effective secrets management requires understanding how different workload types interact with Key Vault and implementing appropriate security patterns:</p>

            <div style="margin: 15px 0;">
                <h4>🏗️ Application Architecture Patterns</h4>
                <ul>
                    <li><strong>Configuration as Code:</strong> Use Key Vault references in infrastructure templates (ARM, Bicep, Terraform)</li>
                    <li><strong>Application Bootstrap:</strong> Load secrets at application startup using managed identities</li>
                    <li><strong>Runtime Secret Access:</strong> Implement caching and connection pooling to avoid throttling</li>
                    <li><strong>Secret Rotation Handling:</strong> Design applications to handle secret changes without downtime</li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>🔄 Secret Lifecycle Management</h4>
                <ul>
                    <li><strong>Secret Creation:</strong> Use Azure CLI/PowerShell or Azure Portal for initial secret setup</li>
                    <li><strong>Access Control:</strong> Implement time-bound access using Azure AD PIM for emergency access</li>
                    <li><strong>Monitoring & Alerting:</strong> Set up alerts for unusual access patterns or failed authentications</li>
                    <li><strong>Backup & Recovery:</strong> Include Key Vault secrets in disaster recovery plans</li>
                    <li><strong>Deprecation:</strong> Safely remove unused secrets and update access policies</li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>⚡ Performance & Reliability Considerations</h4>
                <ul>
                    <li><strong>Throttling Limits:</strong> Key Vault has rate limits (2000/sec for secrets, 100/sec for crypto operations)</li>
                    <li><strong>Caching Strategy:</strong> Implement local caching with short TTL for frequently accessed secrets</li>
                    <li><strong>Retry Logic:</strong> Implement exponential backoff for transient failures</li>
                    <li><strong>Regional Distribution:</strong> Use Key Vault in same region as workloads to reduce latency</li>
                    <li><strong>High Availability:</strong> Design for Key Vault service availability (99.99% SLA)</li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>🔒 Advanced Security Patterns</h4>
                <ul>
                    <li><strong>Envelope Encryption:</strong> Use Key Vault keys to encrypt application data keys</li>
                    <li><strong>Certificate Pinning:</strong> Pin certificates in Key Vault for service-to-service authentication</li>
                    <li><strong>Dynamic Credentials:</strong> Generate temporary credentials using Azure AD app registrations</li>
                    <li><strong>Zero Trust Architecture:</strong> Implement continuous verification and least privilege access</li>
                    <li><strong>Compliance Automation:</strong> Use Azure Policy to enforce Key Vault security standards</li>
                </ul>
            </div>

            <div style="margin: 15px 0;">
                <h4>📊 Operational Excellence</h4>
                <ul>
                    <li><strong>Cost Optimization:</strong> Use standard tier for most workloads, premium only for HSM operations</li>
                    <li><strong>Resource Tagging:</strong> Implement consistent tagging for cost tracking and management</li>
                    <li><strong>Documentation:</strong> Maintain inventory of secrets and their purposes</li>
                    <li><strong>Change Management:</strong> Implement approval processes for secret modifications</li>
                    <li><strong>Audit & Compliance:</strong> Regular review of access logs and compliance status</li>
                </ul>
            </div>
        </div>

        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
            <h4>⚠️ Critical Security Considerations</h4>
            <ul>
                <li><strong>Never store secrets in code or configuration files</strong> - Always use Key Vault references or managed identities</li>
                <li><strong>Implement least privilege</strong> - Grant only the minimum required permissions for each identity</li>
                <li><strong>Enable audit logging</strong> - Monitor all Key Vault access for security incidents and compliance</li>
                <li><strong>Regular credential rotation</strong> - Implement automated rotation for certificates and keys</li>
                <li><strong>Network security</strong> - Use private endpoints and network restrictions to limit access</li>
                <li><strong>Backup and recovery</strong> - Ensure Key Vault secrets are backed up and recoverable</li>
            </ul>
        </div>
    </div>
</body>
</html>
"@

    # Sanitization: remove accidental here-string concatenation tokens and stray @" left in the template
    Write-Log "[HTML] Sanitization: starting HTML cleanup" -Level "INFO"
    $htmlSanitizationStart = Get-Date
    try {
        # Remove patterns like newline + = @" that sometimes leak into output
        $html = $html -replace '\r?\n\s*\+\=\s*@"', [Environment]::NewLine
        # Remove any leftover literal '@"' sequences that could break HTML
        $html = $html -replace '@"', '"'
        # Remove accidental concatenation markers like '" + ' (drop the plus)
        $html = $html -replace '"\s*\+\s*', '"'

        # Remove duplicate DOCTYPE declarations (keep the first only)
        $doctypeCounter = 0
        $html = [regex]::Replace($html, '(?i)<!DOCTYPE html>', { param($m) ; $doctypeCounter++; if ($doctypeCounter -eq 1) { $m.Value } else { '' } })

        # Remove any stray PowerShell evaluation residues that begin a line with an '=' (e.g. "= if () { .Count } else { 0 }")
        # These occasionally appear from malformed template concatenation; drop the whole line
        $html = [regex]::Replace($html, '(?m)^\s*=\s*.*\r?\n', '')

        # If the HTML accidentally contains a second full document (duplicate <!DOCTYPE html>), truncate at the second occurrence
        try {
            $first = $html.IndexOf('<!DOCTYPE html>')
            if ($first -ge 0) {
                $second = $html.IndexOf('<!DOCTYPE html>', $first + 1)
                if ($second -gt 0) { $html = $html.Substring(0, $second) }
            }
        } catch { }

        # Remove accidental PowerShell textualizations that leaked into HTML (e.g. System.Collections.Hashtable outputs)
        $html = [regex]::Replace($html, '(?m)^.*System\.Collections\.Hashtable.*\r?\n', '')

        # Remove stray pipeline / Group-Object leftovers that sometimes appear as '=  | Group-Object -Property ...'
        $html = [regex]::Replace($html, '(?m)^\s*=\s*.*\|\s*Group-Object[^\r\n]*\r?\n', '')
    } catch {
        Write-Log "Warning: HTML sanitization step failed: $($_.Exception.Message)" -Level "WARN"
    }
    $htmlSanitizationEnd = Get-Date
    Write-Log "[HTML] Sanitization completed (took $(([math]::Round(($htmlSanitizationEnd - $htmlSanitizationStart).TotalSeconds, 2)))s)" -Level "INFO"

    Write-Log "[HTML] Writing HTML output to: $OutputPath" -Level "INFO"
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "HTML report generated: $OutputPath" -Level "SUCCESS"
}

# --- Parameter Validation ---
# SingleVault parameter validation
if ($PSBoundParameters.ContainsKey('SingleVault') -and -not $PSBoundParameters.ContainsKey('VaultName')) {
    Write-Log "VaultName parameter is required when using -SingleVault" -Level "ERROR"
    exit 1
}

if ($PSBoundParameters.ContainsKey('VaultName') -and -not $PSBoundParameters.ContainsKey('SingleVault')) {
    Write-Log "VaultName parameter can only be used with -SingleVault" -Level "ERROR"
    exit 1
}

if ($PSBoundParameters.ContainsKey('SubscriptionName') -and -not $PSBoundParameters.ContainsKey('SingleVault')) {
    Write-Log "SubscriptionName parameter can only be used with -SingleVault" -Level "ERROR"
    exit 1
}

# Main execution
function Invoke-GapAnalysis {
    param(
        [Parameter(Mandatory=$false)][switch]$TestMode,
        [Parameter(Mandatory=$false)][int]$Limit = 10,
        [Parameter(Mandatory=$false)][string]$SubscriptionId,
        [Parameter(Mandatory=$false)][string]$OutputDirectory,
        [Parameter(Mandatory=$false)][switch]$SuppressAzureWarnings,
        [Parameter(Mandatory=$false)][switch]$SingleVault,
        [Parameter(Mandatory=$false)][string]$VaultName,
        [Parameter(Mandatory=$false)][string]$SubscriptionName,
        [Parameter(Mandatory=$false)][switch]$UseParallelProcessing,
        [Parameter(Mandatory=$false)][int]$MaxParallelJobs = 4,
        [Parameter(Mandatory=$false)][switch]$Resume,
        [Parameter(Mandatory=$false)][switch]$SuppressModuleWarnings,
        [Parameter(Mandatory=$false)][switch]$AutoInstallModules,
        [Parameter(Mandatory=$false)][switch]$DeepCrossReference,
        [Parameter(Mandatory=$false)][switch]$Force,
    [Parameter(Mandatory=$false)][int]$SimulateInterruptAfter = 0
    ,
    [Parameter(Mandatory=$false)][switch]$IncludeFunctionApps
        ,
        [Parameter(Mandatory=$false)][switch]$AKV_HTML_ONLY
        ,[Parameter(Mandatory=$false)][string]$AKV_HTML_DATA_PATH
        ,[Parameter(Mandatory=$false)][string]$AKV_HTML_PLATFORM_PATH
        ,[Parameter(Mandatory=$false)][string]$AKV_HTML_OUTPUT_PATH
    )

    # If the caller passed function parameters, override script-level defaults so
    # calling Invoke-GapAnalysis -TestMode -Limit 1 works when the script was dot-sourced.
    try {
        if ($PSBoundParameters.ContainsKey('TestMode')) { $script:TestMode = $TestMode }
        if ($PSBoundParameters.ContainsKey('Limit')) { $script:Limit = $Limit }
        if ($PSBoundParameters.ContainsKey('SubscriptionId')) { $script:SubscriptionId = $SubscriptionId }
        if ($PSBoundParameters.ContainsKey('OutputDirectory')) { $script:OutputDirectory = $OutputDirectory; if ($OutputDirectory) { $script:outputDir = $OutputDirectory } }
        if ($PSBoundParameters.ContainsKey('SuppressAzureWarnings')) { $script:SuppressAzureWarnings = $SuppressAzureWarnings }
        if ($PSBoundParameters.ContainsKey('SingleVault')) { $script:SingleVault = $SingleVault }
        if ($PSBoundParameters.ContainsKey('VaultName')) { $script:VaultName = $VaultName }
        if ($PSBoundParameters.ContainsKey('SubscriptionName')) { $script:SubscriptionName = $SubscriptionName }
        if ($PSBoundParameters.ContainsKey('UseParallelProcessing')) { $script:UseParallelProcessing = $UseParallelProcessing }
        if ($PSBoundParameters.ContainsKey('MaxParallelJobs')) { $script:MaxParallelJobs = $MaxParallelJobs }
        if ($PSBoundParameters.ContainsKey('Resume')) { $script:Resume = $Resume }
        if ($PSBoundParameters.ContainsKey('SuppressModuleWarnings')) { $script:SuppressModuleWarnings = $SuppressModuleWarnings }
        if ($PSBoundParameters.ContainsKey('AutoInstallModules')) { $script:AutoInstallModules = $AutoInstallModules }
        if ($PSBoundParameters.ContainsKey('DeepCrossReference')) { $script:DeepCrossReference = $DeepCrossReference }
    if ($PSBoundParameters.ContainsKey('SimulateInterruptAfter')) { $script:SimulateInterruptAfter = $SimulateInterruptAfter }
    if ($PSBoundParameters.ContainsKey('IncludeFunctionApps')) { $script:IncludeFunctionApps = $IncludeFunctionApps }
        if ($PSBoundParameters.ContainsKey('AKV_HTML_ONLY')) { $script:AKV_HTML_ONLY = $AKV_HTML_ONLY }
        if ($PSBoundParameters.ContainsKey('FinalCoercionTimeoutSeconds')) { $script:FinalCoercionTimeoutSeconds = $FinalCoercionTimeoutSeconds }
        if ($PSBoundParameters.ContainsKey('FinalCoercionHeartbeatSeconds')) { $script:FinalCoercionHeartbeatSeconds = $FinalCoercionHeartbeatSeconds }
        if ($PSBoundParameters.ContainsKey('AKV_HTML_DATA_PATH')) { $script:AKV_HTML_DATA_PATH = $AKV_HTML_DATA_PATH }
        if ($PSBoundParameters.ContainsKey('AKV_HTML_PLATFORM_PATH')) { $script:AKV_HTML_PLATFORM_PATH = $AKV_HTML_PLATFORM_PATH }
        if ($PSBoundParameters.ContainsKey('AKV_HTML_OUTPUT_PATH')) { $script:AKV_HTML_OUTPUT_PATH = $AKV_HTML_OUTPUT_PATH }
    }
catch { $null }

    # Normalize and reconcile parameter values so logging and conditional logic
    # use a single authoritative local value (handles auto-splatting and script-level calls).
    try {
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('TestMode')) { $TestMode = [bool]$PSBoundParameters['TestMode'] }
        elseif ($script:TestMode) { $TestMode = [bool]$script:TestMode }

        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('Limit')) { $Limit = [int]$PSBoundParameters['Limit'] }
        elseif ($script:Limit) { $Limit = [int]$script:Limit }

        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('NoRunLock')) { $NoRunLock = [bool]$PSBoundParameters['NoRunLock'] }
        elseif ($script:NoRunLock) { $NoRunLock = [bool]$script:NoRunLock }

        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('UseParallelProcessing')) { $UseParallelProcessing = [bool]$PSBoundParameters['UseParallelProcessing'] }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('MaxParallelJobs')) { $MaxParallelJobs = [int]$PSBoundParameters['MaxParallelJobs'] }
    } catch { }

    # Ensure local variables reflect script-level bound parameters (robustness when auto-splatting)
    try {
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('TestMode')) { $TestMode = $PSBoundParameters['TestMode'] }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('Limit')) { $Limit = $PSBoundParameters['Limit'] }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('UseParallelProcessing')) { $UseParallelProcessing = $PSBoundParameters['UseParallelProcessing'] }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('MaxParallelJobs')) { $MaxParallelJobs = $PSBoundParameters['MaxParallelJobs'] }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('Resume')) { $Resume = $PSBoundParameters['Resume'] }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = $PSBoundParameters['OutputDirectory']; if ($OutputDirectory) { $script:outputDir = $OutputDirectory } }
        if ($PSBoundParameters -and $PSBoundParameters.ContainsKey('NoRunLock')) { $NoRunLock = $PSBoundParameters['NoRunLock'] }
    } catch { }

    # Prevent re-entrant calls in the same process: if the function is already running,
    # bail out early to avoid nested or recursive invocations that interfere with locks.
    if ($Force) {
        $global:AkvGapAnalysis_InProcessRun = $false
        Write-Log "Forced reset of in-process run flag due to -Force parameter" -Level 'WARN'
    }

    try {
        # Test-only bypass: if AKV_FORCE_BYPASS_LOCK=1 in the environment, skip the
        # early in-process sentinel check so a controlled test run can proceed even
        # while another run previously set the sentinel. This is intentionally
        # guarded by an explicit env var to avoid accidental bypass in production.
        if ($env:AKV_FORCE_BYPASS_LOCK -eq '1') {
            Write-Log "AKV_FORCE_BYPASS_LOCK=1 detected — bypassing in-process sentinel check for test run" -Level 'WARN'
        } else {
            if ($global:AkvGapAnalysis_InProcessRun) {
                # Capture call stack for diagnostics
                try { $cs = Get-PSCallStack | Out-String -ErrorAction SilentlyContinue } catch { $cs = 'Unable to capture call stack' }
                Write-Log "Invoke-GapAnalysis called while another run is active in this process (PID: $PID) - skipping nested invocation. CallStack: $cs" -Level 'WARN'
                return
            }
        }
        $global:AkvGapAnalysis_InProcessRun = $true
    } catch { }

    # If the user requested to suppress the noisy Azure module warnings, also
    # silence non-critical module discovery warnings to avoid log spam. This
    # keeps the UX tidy when -SuppressAzureWarnings is passed at the script
    # invocation level (propagated via splatting below).
    try {
        if ($SuppressAzureWarnings -and -not $SuppressModuleWarnings) { $SuppressModuleWarnings = $true }
    } catch { }

    Write-Log "Starting Azure Key Vault Gap Analysis v$ScriptVersion" -Level "INFO"
    Write-Log "Test Mode: $TestMode" -Level "INFO"
    if ($TestMode) { Write-Log "Test Limit: $Limit vaults" -Level "INFO" }

    # Record start time for reporting and duration calculations
    $script:StartTime = Get-Date

    # Lightweight run lock to avoid accidental re-entry: create a lock file when a full
    # run starts. Child/HTML-only runner sets AKV_RUN_HTML_ONLY=1 and should not be
    # blocked from generating HTML. If a lock already exists and we're not an
    # HTML-only runner, exit early to avoid starting a second full analysis.
    # Respect explicit opt-out for developers/testing: -NoRunLock skips run-lock creation/inspection.
    if ($NoRunLock) {
        Write-Log "NoRunLock specified: skipping run-lock creation and inspection. This allows concurrent runs and may cause duplicate work or race conditions. Use only for testing/development. To force a bypass in scripts without changing parameters, set AKV_FORCE_BYPASS_LOCK=1 in the environment." -Level 'WARN'
        # still set a canonical RunLockPath variable so other code that references it won't error
        $script:RunLockPath = Join-Path -Path $env:TEMP -ChildPath 'akv_gap_analysis_running.lock'
    } else {
        try {
            $script:RunLockPath = Join-Path -Path $env:TEMP -ChildPath 'akv_gap_analysis_running.lock'
            # TTL for run lock (seconds). Default 1 hour.
            if (-not $global:RunLockTtlSeconds) { $global:RunLockTtlSeconds = 3600 }
            $runLockTtl = [int]$global:RunLockTtlSeconds

            # Respect a test-only bypass env var that allows forcing a run even when a
            # lock file or sentinel exists. This should only be used for short-lived
            # test runs and requires an explicit env var to enable.
            if ($env:AKV_FORCE_BYPASS_LOCK -eq '1') {
                Write-Log "AKV_FORCE_BYPASS_LOCK=1 detected — bypassing run-lock file checks for test run" -Level 'WARN'
            }

            if (-not ($env:AKV_FORCE_BYPASS_LOCK -eq '1')) {
                if (-not ($env:AKV_RUN_HTML_ONLY -eq '1' -or ($script:AKV_HTML_ONLY -eq $true))) {
                    if (Test-Path $script:RunLockPath) {
                        # Try to read lock metadata to determine age
                        try {
                            $raw = Get-Content -Path $script:RunLockPath -ErrorAction SilentlyContinue -Raw
                            $meta = $null
                            if ($raw -and $raw.Trim() -ne '') {
                                try { $meta = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { $meta = $null }
                            }
                            if ($meta -and $meta.StartedUtc) {
                                # Try ISO-8601 ('o') first, then fall back to a general parse to be tolerant of other formats
                                $started = $null
                                try {
                                    $ok = [datetime]::TryParseExact($meta.StartedUtc, 'o', $null, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$started)
                                    if (-not $ok) {
                                        try { $started = [datetime]::Parse($meta.StartedUtc) } catch { $started = $null }
                                    }
                                } catch {
                                    try { $started = [datetime]::Parse($meta.StartedUtc) } catch { $started = $null }
                                }
                                if ($started) { $age = (Get-Date) - $started } else { $age = $null }
                                if ($age.TotalSeconds -gt $runLockTtl) {
                                    Write-Log "Found stale run lock (age: $([math]::Round($age.TotalMinutes,1))m) at $script:RunLockPath - removing stale lock" -Level 'WARN'
                                    try { Remove-Item -Path $script:RunLockPath -Force -ErrorAction SilentlyContinue } catch { }
                                } else {
                                    if ($age) {
                                        # If the lock metadata contains a PID, check whether that process is still running.
                                        $lockPid = $meta.PID
                                        $proc = $null
                                        if ($lockPid) {
                                            try { $proc = Get-Process -Id $lockPid -ErrorAction SilentlyContinue } catch { $proc = $null }
                                        }
                                        if ($lockPid -and -not $proc) {
                                            # The recorded PID is not running. Allow an automatic bypass for test/resume flows
                                            # or prompt the interactive user to confirm removal. Non-interactive runs will be conservative
                                            # and will not remove the lock unless -Resume is provided or the test env var is set.
                                            if ($Resume -or ($env:AKV_FORCE_BYPASS_LOCK -eq '1')) {
                                                Write-Log "Run lock at $script:RunLockPath refers to PID $lockPid which is not running; removing lock due to -Resume/AKV_FORCE_BYPASS_LOCK" -Level 'WARN'
                                                try { Remove-Item -Path $script:RunLockPath -Force -ErrorAction SilentlyContinue } catch { }
                                            } else {
                                                $confirmed = $false
                                                try {
                                                    # Attempt an interactive prompt; if Read-Host fails (non-interactive), fall through to exit.
                                                    $prompt = "Detected run lock for PID $lockPid (started $($meta.StartedUtc)) but that process is not running. Remove lock and continue? [y/N]"
                                                    $answer = Read-Host -Prompt $prompt
                                                    if ($answer -and $answer.Trim().ToUpper().StartsWith('Y')) { $confirmed = $true }
                                                } catch {
                                                    # Non-interactive host; cannot prompt. Do not remove lock.
                                                    $confirmed = $false
                                                }
                                                if ($confirmed) {
                                                    Write-Log "User confirmed removal of run lock for PID $lockPid; removing and continuing" -Level 'WARN'
                                                    try { Remove-Item -Path $script:RunLockPath -Force -ErrorAction SilentlyContinue } catch { }
                                                } else {
                                                    Write-Log "Run-lock present and user did not confirm removal; exiting to avoid duplicate work." -Level 'WARN'
                                                    return
                                                }
                                            }
                                        } else {
                                            if ($age) {
                                                Write-Log "Detected existing run lock ($script:RunLockPath) created by PID $($meta.PID) at $($meta.StartedUtc). Another run appears active — exiting to avoid duplicate work." -Level 'WARN'
                                            } else {
                                                Write-Log "Detected existing run lock ($script:RunLockPath) with unparsable StartedUtc ('$($meta.StartedUtc)'). Treating as active and exiting to avoid duplicate work." -Level 'WARN'
                                            }
                                            return
                                        }
                                    } else {
                                        # Unknown lock contents; be conservative and exit
                                        Write-Log "Detected existing run lock ($script:RunLockPath) with unknown metadata. Another run may be active — exiting to avoid duplicate work." -Level 'WARN'
                                        return
                                    }
                                }
                            } else {
                                # Unknown lock contents; be conservative and exit
                                Write-Log "Detected existing run lock ($script:RunLockPath) with unknown metadata. Another run may be active — exiting to avoid duplicate work." -Level 'WARN'
                                return
                            }
                        } catch {
                            Write-Log "Error while inspecting run lock ($script:RunLockPath): $($_.Exception.Message) - exiting to avoid duplicate work" -Level 'WARN'
                            return
                        }
                    }

                    # Create a lock file with metadata
                    try {
                        $lockMeta = [ordered]@{
                            PID = $PID
                            Owner = $env:USERNAME
                            StartedUtc = (Get-Date).ToString('o')
                            Command = ($MyInvocation.MyCommand.Definition -as [string])
                        }
                        $lockMeta | ConvertTo-Json -Depth 4 | Out-File -FilePath $script:RunLockPath -Encoding UTF8 -Force
                        # Use INFO level here because Write-Log ValidateSet may not accept DEBUG in some contexts
                        Write-Log "Created run lock at: $script:RunLockPath (PID: $PID)" -Level 'INFO'
                    } catch {
                        Write-Log "Failed to create run lock ($script:RunLockPath): $($_.Exception.Message) - continuing without lock" -Level 'WARN'
                    }
                }
            }
        } catch {
            # best-effort: if lock cannot be created or inspected, continue
        }
    }

        # Debug: print canonical effective runtime parameters for visibility (useful when dot-sourced)
    try {
        $debugParams = [PSCustomObject]@{
            TestMode = $TestMode
            Limit = $Limit
            UseParallelProcessing = $UseParallelProcessing
            MaxParallelJobs = $MaxParallelJobs
            Resume = $Resume
        }
        Write-Log ("Effective parameters: TestMode={0} Limit={1} UseParallelProcessing={2} MaxParallelJobs={3} Resume={4}" -f $debugParams.TestMode, $debugParams.Limit, $debugParams.UseParallelProcessing, $debugParams.MaxParallelJobs, $debugParams.Resume) -Level 'INFO'
    } catch { }

        # If the caller requested suppression of Azure warnings, reduce global
        # warning noise for the duration of this run by setting WarningPreference
        # to SilentlyContinue. We restore it at the end of the run.
        try {
            if ($SuppressAzureWarnings) {
                $script:__prevWarningPreference = $WarningPreference
                $WarningPreference = 'SilentlyContinue'
            }
        } catch { }

        # If invoked as HTML-only child via parameter, populate legacy env vars so the
        # existing HTML-only branch (which checks $env:AKV_RUN_HTML_ONLY) continues to work.
        try {
            if ($AKV_HTML_ONLY) {
                Write-Log "HTML-only invocation detected via -AKV_HTML_ONLY; setting legacy env vars for compatibility" -Level 'INFO'
                $env:AKV_RUN_HTML_ONLY = '1'
                if ($AKV_HTML_DATA_PATH) { $env:AKV_HTML_DATA_PATH = $AKV_HTML_DATA_PATH }
                if ($AKV_HTML_PLATFORM_PATH) { $env:AKV_HTML_PLATFORM_PATH = $AKV_HTML_PLATFORM_PATH }
                if ($AKV_HTML_OUTPUT_PATH) { $env:AKV_HTML_OUTPUT_PATH = $AKV_HTML_OUTPUT_PATH }
            }
        } catch { }

    # Prepare a path for a test-mode reservation counter so parallel runspaces can atomically reserve slots
    try {
        $testCounterPath = Join-Path -Path $outputDir -ChildPath 'testmode_counter.txt'
        # Reset counter at run start when starting fresh (not resuming)
        if ($TestMode -and -not $Resume) {
            try { if (Test-Path $testCounterPath) { Remove-Item -Path $testCounterPath -Force -ErrorAction SilentlyContinue } } catch { }
        }
    } catch { $testCounterPath = Join-Path -Path $env:TEMP -ChildPath ('testmode_counter_{0}.txt' -f ([guid]::NewGuid().ToString())) }

    # Load or initialize checkpoint in memory so Save-Checkpoint-Atomic can use it
    try {
        $global:checkpoint = Load-Checkpoint
        if ($null -eq $global:checkpoint) { $global:checkpoint = @{} }
    } catch { $global:checkpoint = @{} }
    # Create a worker id for this process (used for parallel-safe incremental CSV temp files)
    try { $global:WorkerId = "${env:COMPUTERNAME}_${PID}" } catch { $global:WorkerId = ([guid]::NewGuid().ToString()) }

    # Install CTRL-C / CancelKeyPress handler if available to allow graceful shutdown
    try {
        if ([console] -and [console].PSIsContainer -ne $null -and ([console] | Get-Member -Name 'CancelKeyPress' -MemberType Event -ErrorAction SilentlyContinue)) {
            Register-EngineEvent -SourceIdentifier Console_CancelKeyPress -SupportEvent -Action {
                Write-Log "CTRL-C detected: requesting graceful shutdown..." -Level 'WARN'
                $global:ScriptStopRequested = $true
                try {
                    # If a vault is currently in-progress (sequential mode), mark it as processed with a partial marker
                    if ($null -ne $global:currentVaultInProgress -and $global:currentVaultInProgress -ne '') {
                        try {
                            Write-Log "Marking in-progress vault ($global:currentVaultInProgress) as partially processed in checkpoint." -Level 'INFO'
                            if (Get-Command -Name Mark-Vault-Processed -ErrorAction SilentlyContinue) {
                                Mark-Vault-Processed -VaultResourceId $global:currentVaultInProgress -JsonFilePath ''
                            }
                        } catch { }
                    }
                    # persist the current checkpoint state if any
                    if (Get-Command -Name Save-Checkpoint-Atomic -ErrorAction SilentlyContinue) {
                        $state = Load-Checkpoint
                        Save-Checkpoint-Atomic -State $state
                        Write-Log "Checkpoint saved during shutdown." -Level 'INFO'
                    }
                } catch { }
            } | Out-Null
        }
    } catch { }

    # Initialize authentication
    if (!(Initialize-AzureAuthentication)) {
        Write-Log "Authentication failed. Exiting." -Level "ERROR"
        exit 1
    }

    # Capture Azure context for parallel processing
    $azContext = Get-AzContext
    if ($SingleVault) {
        Write-Log "Single Vault Mode: Analyzing $VaultName" -Level "INFO"

        # Find the subscription containing the vault
        $targetSubscription = $null
        $foundVault = $null

        if ($SubscriptionName) {
            # User specified subscription name
            Write-Log "Looking up subscription by name: $SubscriptionName (Get-AzSubscription)" -Level 'DEBUG'
            $targetSubscription = Get-AzSubscription | Where-Object { $_.Name -eq $SubscriptionName }
            if (-not $targetSubscription) {
                Write-Log "Specified subscription '$SubscriptionName' not found" -Level "ERROR"
                exit 1
            }
        } else {
            # Auto-discover subscription containing the vault
            Write-Log "Auto-discovering subscription containing vault '$VaultName'..." -Level "INFO"
            Write-Log "About to call Get-AzSubscription for auto-discovery" -Level 'DEBUG'
            $subscriptionsToCheck = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }

            foreach ($sub in $subscriptionsToCheck) {
                Write-Log "Setting Az context to subscription $($sub.Name) ($($sub.Id)) before checking for vault" -Level 'DEBUG'
                Set-AzContext -SubscriptionId $sub.Id | Out-Null
                try {
                    Write-Log "Probing Get-AzKeyVault -VaultName $VaultName in subscription $($sub.Name)" -Level 'DEBUG'
                    $vault = Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
                    $targetSubscription = $sub
                    $foundVault = $vault
                    Write-Log "Found vault '$VaultName' in subscription '$($sub.Name)'" -Level "SUCCESS"
                    break
                } catch {
                    # Vault not in this subscription, continue
                    Write-Log "Vault not in subscription $($sub.Name) or not accessible: $($_.Exception.Message)" -Level "DEBUG"
                }
            }
        }

        if (-not $targetSubscription) {
            Write-Log "Vault '$VaultName' not found in any accessible subscription" -Level "ERROR"
            exit 1
        }

        # Get the vault if not already found
        if (-not $foundVault) {
            Set-AzContext -SubscriptionId $targetSubscription.Id | Out-Null
            try {
                $foundVault = Get-AzKeyVault -VaultName $VaultName
            } catch {
                Write-Log "Failed to retrieve vault '$VaultName': $($_.Exception.Message)" -Level "ERROR"
                exit 1
            }
        }

        # Create single-item arrays for processing
        $subscriptions = @($targetSubscription)
        $keyVaults = @($foundVault)

        Write-Log "Single Vault Analysis: $VaultName in subscription $($targetSubscription.Name)" -Level "INFO"
    } else {
        # Get subscriptions to analyze
        $subscriptions = Get-SubscriptionsToAnalyze
        if ($subscriptions.Count -eq 0) {
            Write-Log "No subscriptions found or accessible. Exiting." -Level "ERROR"
            exit 1
        }
    }

    $totalVaultsAnalyzed = 0
    $platformAssessments = @()
    $vaultsProcessedInTestMode = 0
    $subscriptionsProcessedInTestMode = 0
    $expectedVaultsInTestMode = 0

    # Initialize global variables for this run
    $global:gapAnalysisResults = @()
    $global:securityGaps = @()
    $global:quickWins = @()
    $global:recommendations = @()

    # Load checkpoint if resume requested
    $checkpoint = @{}
    if ($Resume) {
        Write-Log "Resume requested - loading checkpoint if present" -Level "INFO"
        $checkpoint = Load-Checkpoint
        if (-not $checkpoint) { $checkpoint = @{} }
    }

    # Analyze each subscription
    foreach ($subscription in $subscriptions) {
        # If TestMode, check if we've already reached the expected limit
        if ($TestMode -and $expectedVaultsInTestMode -ge $Limit) {
            Write-Log "Test mode: expected vault limit ($Limit) reached, stopping subscription processing" -Level 'INFO'
            break
        }
        # If TestMode limit already reached, stop processing further subscriptions immediately
        if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
            Write-Log "Test mode limit ($Limit) already reached; stopping subscription processing" -Level 'INFO'
            break
        }

        # Short-circuit scanning for TestMode: first probe for Key Vaults and only
        # perform heavier platform assessment work if this subscription contains
        # vaults we intend to analyze. This keeps TestMode quick by using the
        # minimum number of subscriptions necessary to satisfy -Limit.
        Write-Log "Analyzing subscription: $($subscription.Name) ($($subscription.Id))" -Level "INFO"

        # If SingleVault and this isn't the target subscription, skip
        if ($SingleVault -and $subscription.Id -ne $targetSubscription.Id) { continue }

        # Discover vaults first when in TestMode to avoid scanning many subscriptions
        if (-not $SingleVault) {
            $keyVaults = Get-KeyVaultsInSubscription -SubscriptionId $subscription.Id

            if ($keyVaults.Count -eq 0) {
                Write-Log "No Key Vaults found in subscription $($subscription.Name)" -Level "INFO"
                continue
            }

            # If resuming, filter out vaults already processed per checkpoint
            if ($Resume -and $checkpoint.Processed) {
                $keyVaults = $keyVaults | Where-Object { -not $checkpoint.Processed.ContainsKey($_.ResourceId) }
                Write-Log "Resume mode: skipping $([math]::Max(0, ($keyVaults.Count))) already-processed vaults in subscription $($subscription.Name)" -Level "INFO"
            }

            # Apply test-mode global limit if TestMode is enabled
            if ($TestMode) {
                $remainingLimit = $Limit - $expectedVaultsInTestMode
                if ($remainingLimit -le 0) {
                    Write-Log "Test mode limit ($Limit) reached, skipping remaining subscriptions" -Level "INFO"
                    break
                }

                if ($keyVaults.Count -gt $remainingLimit) {
                    $keyVaults = $keyVaults | Select-Object -First $remainingLimit
                    Write-Log "Test mode: Limited to $remainingLimit vaults in this subscription" -Level "INFO"
                }
            }
        }

        # For SingleVault mode, $keyVaults is already set above
        if ($TestMode -and -not $SingleVault -and $keyVaults.Count -gt ($Limit - $expectedVaultsInTestMode)) {
            $remainingLimit = $Limit - $expectedVaultsInTestMode
            $keyVaults = $keyVaults | Select-Object -First $remainingLimit
            Write-Log "Test mode: Limited to $remainingLimit vaults in this subscription" -Level "INFO"
        }

        # Update expected vault count for test mode
        if ($TestMode) {
            $expectedVaultsInTestMode += $keyVaults.Count
        }

        # Now that we know this subscription contains vault(s) we care about,
        # perform the (heavier) Azure platform assessment and continue.
        $platformAssessment = Get-AzurePlatformAssessment -SubscriptionId $subscription.Id
        $platformAssessments += $platformAssessment

        # Analyze each vault
        if ($UseParallelProcessing -and $env:OS -notlike "*Windows*") {
            Write-Log "Parallel processing is only supported on Windows. Falling back to sequential processing." -Level "WARNING"
            $UseParallelProcessing = $false
        }

        if ($UseParallelProcessing) {
            Write-Log "Using parallel processing with max $MaxParallelJobs concurrent jobs" -Level "INFO"

            # Create vault analysis jobs
            $vaultJobs = $keyVaults | ForEach-Object -ThrottleLimit $MaxParallelJobs -Parallel {
                $vault = $_
                $subscriptionId = $using:subscription.Id
                $subscriptionName = $using:subscription.Name

                # Define Write-Log function for parallel job
                function Write-Log {
                    param([string]$Message, [string]$Level = 'INFO')
                    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    Write-Host "[$time] [$Level] $Message"
                }

                # Define Invoke-WithTimeout function for parallel job
                function Invoke-WithTimeout {
                    param(
                        [Parameter(Mandatory=$true)][ScriptBlock]$ScriptBlock,
                        [Parameter(Mandatory=$false)][object[]]$Args = @(),
                        [Parameter(Mandatory=$false)][int]$TimeoutSeconds = 30,
                        [Parameter(Mandatory=$false)][string]$CmdletName = ''
                    )
                    try {
                        Write-Log ("[DEBUG] Starting background job for {0} with timeout {1}s" -f ($CmdletName -as [string]), $TimeoutSeconds) -Level 'INFO'
                        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Args
                        try { Write-Log ("[DEBUG] Started job Id=$($job.Id) for {0}" -f ($CmdletName -as [string])) -Level 'INFO' } catch { Write-Log ("Invoke-WithTimeout inner logging failed: {0}" -f ($_.Exception.Message -as [string])) -Level 'DEBUG' }
                    } catch {
                        Write-Log ("Failed to start job for {0}: {1}" -f ($CmdletName -as [string]), ($_.Exception.Message -as [string])) -Level 'WARN'
                        throw
                    }
                    if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
                        try {
                            $result = Receive-Job -Job $job -ErrorAction Stop
                        } catch {
                            $result = $null
                        }
                        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        return $result
                    } else {
                        try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { Write-Log ("Cleanup of background job failed: {0}" -f ($_.Exception.Message -as [string])) -Level 'DEBUG' }
                        # Log job state for diagnostics
                        try {
                            $jstate = (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)
                            Write-Log ("[DEBUG] Job state for Id=$($job.Id): State=$($jstate.State) HasMoreData=$($jstate.HasMoreData) ChildJobs=$($jstate.ChildJobs.Count)" ) -Level 'INFO'
                        } catch { }
                        Write-Log "Timeout after ${TimeoutSeconds}s waiting for $($CmdletName -or 'operation')" -Level 'WARN'
                        throw "Timed out waiting for $($CmdletName -or 'operation') after ${TimeoutSeconds}s"
                    }
                }

                # Define Get-DiagnosticsConfiguration function for parallel job
                function Get-DiagnosticsConfiguration {
                    param([string]$VaultName, [string]$ResourceGroupName)

                    try {
                        $diagnostics = Invoke-WithTimeout -ScriptBlock { param($rid) Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction SilentlyContinue } -Args @("/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName") -TimeoutSeconds 30 -CmdletName 'Get-AzDiagnosticSetting'

                        return @{
                            HasDiagnostics = ($diagnostics.Count -gt 0)
                            DiagnosticSettings = $diagnostics
                            LogsEnabled = ($diagnostics | Where-Object { $_.Logs.Count -gt 0 }).Count -gt 0
                            MetricsEnabled = ($diagnostics | Where-Object { $_.Metrics.Count -gt 0 }).Count -gt 0
                        }
                    } catch {
                        return @{
                            HasDiagnostics = $false
                            DiagnosticSettings = $null
                            LogsEnabled = $false
                            MetricsEnabled = $false
                        }
                    }
                }

                # Define Get-AccessControlAnalysis function for parallel job
                function Get-AccessControlAnalysis {
                    param([string]$VaultName, [string]$ResourceGroupName)

                    try {
                        $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName

                        # Check if using RBAC
                        $rbacEnabled = $vault.EnableRbacAuthorization

                        # Get access policies
                        $accessPolicies = $vault.AccessPolicies

                        # Get RBAC role assignments
                        $roleAssignments = Get-AzRoleAssignment -Scope $vault.ResourceId -ErrorAction SilentlyContinue

                        return @{
                            RbacEnabled = $rbacEnabled
                            AccessPoliciesCount = $accessPolicies.Count
                            RoleAssignmentsCount = $roleAssignments.Count
                            HasAccessPolicies = ($accessPolicies.Count -gt 0)
                            HasRoleAssignments = ($roleAssignments.Count -gt 0)
                        }
                    } catch {
                        return @{
                            RbacEnabled = $null
                            AccessPoliciesCount = 0
                            RoleAssignmentsCount = 0
                            HasAccessPolicies = $false
                            HasRoleAssignments = $false
                        }
                    }
                }

                # Define Get-NetworkSecurityAnalysis function for parallel job
                function Get-NetworkSecurityAnalysis {
                    param([string]$VaultName, [string]$ResourceGroupName)

                    try {
                        $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName

                        # Check network ACLs
                        $networkAcls = $vault.NetworkAcls

                        # Check private endpoints
                        $privateEndpoints = Get-AzPrivateEndpoint | Where-Object {
                            $_.PrivateLinkServiceConnections.PrivateLinkServiceId -like "*$VaultName*"
                        }

                        return @{
                            PublicNetworkAccess = $vault.PublicNetworkAccess
                            NetworkAclsConfigured = ($null -ne $networkAcls)
                            PrivateEndpointsCount = $privateEndpoints.Count
                            HasPrivateEndpoints = ($privateEndpoints.Count -gt 0)
                            TrustedServicesEnabled = $networkAcls.Bypass -contains "AzureServices"
                        }
                    } catch {
                        return @{
                            PublicNetworkAccess = $null
                            NetworkAclsConfigured = $false
                            PrivateEndpointsCount = 0
                            HasPrivateEndpoints = $false
                            TrustedServicesEnabled = $false
                        }
                    }
                }

                # Define Get-SecretInventoryAnalysis function for parallel job
                function Get-SecretInventoryAnalysis {
                    param([string]$VaultName, [string]$ResourceGroupName)

                    try {
                        # Get vault details for tags
                        $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                        $vaultTags = if ($vault -and $vault.Tags) { $vault.Tags } else { @{} }

                        # Get secrets with detailed information
                        $secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction SilentlyContinue
                        $secretDetails = @()
                        $secretCount = 0

                        if ($secrets) {
                            $secretCount = $secrets.Count
                            foreach ($secret in $secrets) {
                                $secretDetails += @{
                                    Name = $secret.Name
                                    Enabled = $secret.Enabled
                                    Created = $secret.Created
                                    Updated = $secret.Updated
                                    Expires = $secret.Expires
                                    NotBefore = $secret.NotBefore
                                    ContentType = $secret.ContentType
                                    Tags = $secret.Tags
                                    RecoveryLevel = $secret.RecoveryLevel
                                    VaultName = $VaultName
                                    BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                                    IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                                    Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                                    DaysSinceLastUpdate = [math]::Round(((Get-Date) - $secret.Updated).TotalDays, 0)
                                    LastAccessed = $null
                                    AccessCount = 0
                                }
                            }
                        }

                        # Get certificates with detailed information
                        $certificates = Get-AzKeyVaultCertificate -VaultName $VaultName -ErrorAction SilentlyContinue
                        $certificateDetails = @()
                        $certificateCount = 0

                        if ($certificates) {
                            $certificateCount = $certificates.Count
                            foreach ($cert in $certificates) {
                                $certificateDetails += @{
                                    Name = $cert.Name
                                    Enabled = $cert.Enabled
                                    Created = $cert.Created
                                    Updated = $cert.Updated
                                    Expires = $cert.Expires
                                    NotBefore = $cert.NotBefore
                                    Subject = $cert.Subject
                                    Issuer = $cert.Issuer
                                    Thumbprint = $cert.Thumbprint
                                    Tags = $cert.Tags
                                    RecoveryLevel = $cert.RecoveryLevel
                                    VaultName = $VaultName
                                    BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                                    IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                                    Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                                    DaysSinceLastUpdate = [math]::Round(((Get-Date) - $cert.Updated).TotalDays, 0)
                                    LastAccessed = $null
                                    AccessCount = 0
                                }
                            }
                        }

                        # Get keys with detailed information
                        $keys = Get-AzKeyVaultKey -VaultName $VaultName -ErrorAction SilentlyContinue
                        $keyDetails = @()
                        $keyCount = 0

                        if ($keys) {
                            $keyCount = $keys.Count
                            foreach ($key in $keys) {
                                $keyDetails += @{
                                    Name = $key.Name
                                    Enabled = $key.Enabled
                                    Created = $key.Created
                                    Updated = $key.Updated
                                    Expires = $key.Expires
                                    NotBefore = $key.NotBefore
                                    KeyType = $key.KeyType
                                    KeySize = $key.KeySize
                                    CurveName = $key.CurveName
                                    KeyOps = $key.KeyOps
                                    Tags = $key.Tags
                                    RecoveryLevel = $key.RecoveryLevel
                                    VaultName = $VaultName
                                    BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                                    IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                                    Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                                    DaysSinceLastUpdate = [math]::Round(((Get-Date) - $key.Updated).TotalDays, 0)
                                    LastAccessed = $null
                                    AccessCount = 0
                                }
                            }
                        }

                        $totalAssets = $secretCount + $certificateCount + $keyCount

                        return @{
                            SecretsCount = $secretCount
                            CertificatesCount = $certificateCount
                            KeysCount = $keyCount
                            TotalAssets = $totalAssets
                            Secrets = $secretDetails
                            Certificates = $certificateDetails
                            Keys = $keyDetails
                            VaultTags = $vaultTags
                            BusinessUnit = $vaultTags.Get_Item("BusinessUnit") ?? $vaultTags.Get_Item("BU") ?? "Unknown"
                            IAPMNumber = $vaultTags.Get_Item("IAPM#") ?? $vaultTags.Get_Item("IAPM") ?? $vaultTags.Get_Item("ProjectID") ?? "Unknown"
                            Environment = $vaultTags.Get_Item("Environment") ?? "Unknown"
                        }
                    } catch {
                        return @{
                            SecretsCount = 0
                            CertificatesCount = 0
                            KeysCount = 0
                            TotalAssets = 0
                            Secrets = @()
                            Certificates = @()
                            Keys = @()
                            VaultTags = @{}
                            BusinessUnit = "Unknown"
                            Environment = "Unknown"
                        }
                    }
                }

                # Define Get-RotationAnalysis function for parallel job
                function Get-RotationAnalysis {
                    param([string]$VaultName, [string]$ResourceGroupName, $SecretInventory)

                    $rotationAnalysis = @{
                        AutoRotatedSecrets = 0
                        AutoRotatedCertificates = 0
                        AutoRotatedKeys = 0
                        ManualRotationNeeded = 0
                        NeverRotated = 0
                        RecentlyRotated = 0
                        RotationDetails = @()
                    }

                    $ninetyDaysAgo = (Get-Date).AddDays(-90)

                    # Analyze secrets
                    foreach ($secret in $SecretInventory.Secrets) {
                        try {
                            $secretDetails = Get-AzKeyVaultSecret -VaultName $VaultName -Name $secret.Name -ErrorAction SilentlyContinue
                            if ($secretDetails) {
                                $lastUpdated = $secretDetails.Updated
                                $rotationType = "Manual"

                                if ($lastUpdated -gt $ninetyDaysAgo) {
                                    $rotationAnalysis.RecentlyRotated++
                                } elseif ($lastUpdated -lt $ninetyDaysAgo) {
                                    $rotationAnalysis.ManualRotationNeeded++
                                }

                                $rotationAnalysis.RotationDetails += @{
                                    Type = "Secret"
                                    Name = $secret.Name
                                    LastUpdated = $lastUpdated
                                    RotationType = $rotationType
                                    DaysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 0)
                                    NeedsRotation = ($lastUpdated -lt $ninetyDaysAgo)
                                }
                            }
                        } catch {
                            $rotationAnalysis.NeverRotated++
                            $rotationAnalysis.RotationDetails += @{
                                Type = "Secret"
                                Name = $secret.Name
                                LastUpdated = $null
                                RotationType = "Unknown"
                                DaysSinceUpdate = $null
                                NeedsRotation = $true
                            }
                        }
                    }

                    # Analyze certificates
                    foreach ($cert in $SecretInventory.Certificates) {
                        try {
                            $certDetails = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $cert.Name -ErrorAction SilentlyContinue
                            if ($certDetails) {
                                $lastUpdated = $certDetails.Updated
                                $rotationType = "Manual"

                                if ($certDetails.Expires) {
                                    $daysToExpiry = [math]::Round(($certDetails.Expires - (Get-Date)).TotalDays, 0)
                                    if ($daysToExpiry -lt 30) {
                                        $rotationAnalysis.ManualRotationNeeded++
                                    }
                                }

                                if ($lastUpdated -gt $ninetyDaysAgo) {
                                    $rotationAnalysis.RecentlyRotated++
                                }

                                $rotationAnalysis.RotationDetails += @{
                                    Type = "Certificate"
                                    Name = $cert.Name
                                    LastUpdated = $lastUpdated
                                    RotationType = $rotationType
                                    DaysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 0)
                                    ExpiryDate = $certDetails.Expires
                                    DaysToExpiry = if ($certDetails.Expires) { [math]::Round(($certDetails.Expires - (Get-Date)).TotalDays, 0) } else { $null }
                                    NeedsRotation = ($certDetails.Expires -and ($certDetails.Expires - (Get-Date)).TotalDays -lt 30)
                                }
                            }
                        } catch {
                            $rotationAnalysis.NeverRotated++
                            $rotationAnalysis.RotationDetails += @{
                                Type = "Certificate"
                                Name = $cert.Name
                                LastUpdated = $null
                                RotationType = "Unknown"
                                DaysSinceUpdate = $null
                                ExpiryDate = $null
                                DaysToExpiry = $null
                                NeedsRotation = $true
                            }
                        }
                    }

                    # Analyze keys
                    foreach ($key in $SecretInventory.Keys) {
                        try {
                            $keyDetails = Get-AzKeyVaultKey -VaultName $VaultName -Name $key.Name -ErrorAction SilentlyContinue
                            if ($keyDetails) {
                                $lastUpdated = $keyDetails.Updated
                                $rotationType = "Manual"

                                if ($lastUpdated -gt $ninetyDaysAgo) {
                                    $rotationAnalysis.RecentlyRotated++
                                } elseif ($lastUpdated -lt $ninetyDaysAgo) {
                                    $rotationAnalysis.ManualRotationNeeded++
                                }

                                $rotationAnalysis.RotationDetails += @{
                                    Type = "Key"
                                    Name = $key.Name
                                    LastUpdated = $lastUpdated
                                    RotationType = $rotationType
                                    DaysSinceUpdate = [math]::Round(((Get-Date) - $lastUpdated).TotalDays, 0)
                                    NeedsRotation = ($lastUpdated -lt $ninetyDaysAgo)
                                }
                            }
                        } catch {
                            $rotationAnalysis.NeverRotated++
                            $rotationAnalysis.RotationDetails += @{
                                Type = "Key"
                                Name = $key.Name
                                LastUpdated = $null
                                RotationType = "Unknown"
                                DaysSinceUpdate = $null
                                NeedsRotation = $true
                            }
                        }
                    }

                    return $rotationAnalysis
                }

                # Define Identify-SecurityGaps function for parallel job
                function Identify-SecurityGaps {
                    param($VaultAnalysis)

                    $gaps = @()

                    # RBAC vs Access Policies gap
                    if (!$VaultAnalysis.AccessControl.RbacEnabled -and $VaultAnalysis.AccessControl.AccessPoliciesCount -eq 0) {
                        $gaps += @{
                            Category = "Access Control"
                            Severity = "Critical"
                            Issue = "No access control configured"
                            Impact = "Vault is inaccessible - complete security failure"
                            Recommendation = "Enable Azure RBAC or configure access policies immediately"
                        }
                    }

                    # Diagnostics gap
                    if (!$VaultAnalysis.Diagnostics.HasDiagnostics) {
                        $gaps += @{
                            Category = "Monitoring & Auditing"
                            Severity = "High"
                            Issue = "No diagnostic settings configured"
                            Impact = "No audit logging, monitoring, or security alerting - blind to threats and compliance violations"
                            Recommendation = "Enable diagnostic settings to capture audit logs and metrics"
                        }
                    }

                    # Network security gap
                    if ($VaultAnalysis.NetworkSecurity.PublicNetworkAccess -eq "Enabled" -and !$VaultAnalysis.NetworkSecurity.HasPrivateEndpoints) {
                        $gaps += @{
                            Category = "Network Security"
                            Severity = "Medium"
                            Issue = "Public network access enabled without private endpoints"
                            Impact = "Potential exposure to public internet attacks, data exfiltration risks"
                            Recommendation = "Configure private endpoints or restrict network access with firewall rules"
                        }
                    }

                    # Soft delete gap
                    if (!$VaultAnalysis.Vault.EnableSoftDelete) {
                        $gaps += @{
                            Category = "Data Protection & Recovery"
                            Severity = "Critical"
                            Issue = "Soft delete not enabled"
                            Impact = "Permanent data loss if secrets/certificates/keys are accidentally deleted - no recovery possible"
                            Recommendation = "Enable soft delete protection (mandatory for production vaults)"
                        }
                    }

                    # Purge protection gap
                    if (!$VaultAnalysis.Vault.EnablePurgeProtection) {
                        $gaps += @{
                            Category = "Data Protection & Recovery"
                            Severity = "Medium"
                            Issue = "Purge protection not enabled"
                            Impact = "Deleted secrets can be permanently purged, preventing recovery from ransomware or malicious deletion"
                            Recommendation = "Enable purge protection to prevent permanent data loss"
                        }
                    }

                    # Rotation analysis gaps
                    if ($VaultAnalysis.RotationAnalysis.ManualRotationNeeded -gt 0) {
                        $gaps += @{
                            Category = "Secret Management"
                            Severity = "Medium"
                            Issue = "$($VaultAnalysis.RotationAnalysis.ManualRotationNeeded) secrets/certificates/keys need rotation"
                            Impact = "Outdated credentials increase security risk and may cause service disruptions"
                            Recommendation = "Implement automated rotation for secrets, certificates, and keys"
                        }
                    }

                    return $gaps
                }

                # Define Identify-QuickWins function for parallel job
                function Identify-QuickWins {
                    param($VaultAnalysis)

                    $wins = @()

                    # RBAC migration opportunity
                    if ($VaultAnalysis.AccessControl.AccessPoliciesCount -gt 0 -and !$VaultAnalysis.AccessControl.RbacEnabled) {
                        $wins += @{
                            Category = "Access Control"
                            Title = "Migrate to Azure RBAC"
                            Description = "Replace access policies with Azure RBAC for better security and management"
                            Effort = "Medium"
                            Impact = "High"
                        }
                    }

                    # Diagnostics setup
                    if (!$VaultAnalysis.Diagnostics.HasDiagnostics) {
                        $wins += @{
                            Category = "Monitoring"
                            Title = "Enable Diagnostic Logging"
                            Description = "Configure diagnostic settings to capture audit logs and metrics"
                            Effort = "Low"
                            Impact = "High"
                        }
                    }

                    # Private endpoint setup
                    if (!$VaultAnalysis.NetworkSecurity.HasPrivateEndpoints -and $VaultAnalysis.NetworkSecurity.PublicNetworkAccess -eq "Enabled") {
                        $wins += @{
                            Category = "Network Security"
                            Title = "Implement Private Endpoints"
                            Description = "Create private endpoints to secure network access to Key Vault"
                            Effort = "Medium"
                            Impact = "High"
                        }
                    }

                    # Soft delete enablement
                    if (!$VaultAnalysis.Vault.EnableSoftDelete) {
                        $wins += @{
                            Category = "Data Protection"
                            Title = "Enable Soft Delete"
                            Description = "Protect against accidental deletion with recovery capability"
                            Effort = "Low"
                            Impact = "High"
                        }
                    }

                    # Rotation automation
                    if ($VaultAnalysis.RotationAnalysis.ManualRotationNeeded -gt 0) {
                        $wins += @{
                            Category = "Automation"
                            Title = "Implement Secret Rotation"
                            Description = "Set up automated rotation for secrets and certificates"
                            Effort = "High"
                            Impact = "Medium"
                        }
                    }

                    return $wins
                }

                # Define Analyze-KeyVault function for parallel job
                function Analyze-KeyVault {
                    param($Vault, [string]$SubscriptionId, [string]$SubscriptionName)

                    Write-Log "Analyzing Key Vault: $($Vault.VaultName)" -Level "INFO"
                    $__analyze_start = Get-Date

                    $analysis = @{
                        SubscriptionId = $SubscriptionId
                        SubscriptionName = $SubscriptionName
                        VaultName = $Vault.VaultName
                        ResourceGroupName = $Vault.ResourceGroupName
                        Location = $Vault.Location
                        Vault = $Vault
                        Diagnostics = $null
                        AccessControl = $null
                        NetworkSecurity = $null
                        SecurityGaps = @()
                        QuickWins = @()
                        ComplianceScore = 0
                        CISComplianceScore = 0
                        NISTComplianceScore = 0
                        ISOComplianceScore = 0
                        MSComplianceScore = 0
                        RiskLevel = "Unknown"
                    }

                    # Get diagnostics configuration
                    $analysis.Diagnostics = Get-DiagnosticsConfiguration -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

                    # Get access control analysis
                    $analysis.AccessControl = Get-AccessControlAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

                    # Get network security analysis
                    $analysis.NetworkSecurity = Get-NetworkSecurityAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

                    # Get secret inventory analysis
                    $analysis.SecretInventory = Get-SecretInventoryAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName

                    # Get rotation analysis
                    $analysis.RotationAnalysis = Get-RotationAnalysis -VaultName $Vault.VaultName -ResourceGroupName $Vault.ResourceGroupName -SecretInventory $analysis.SecretInventory

                    # Identify security gaps
                    $analysis.SecurityGaps = Identify-SecurityGaps -VaultAnalysis $analysis

                    # Identify quick wins
                    $analysis.QuickWins = Identify-QuickWins -VaultAnalysis $analysis

                    # Calculate compliance scores by framework
                    $baseScore = 100

                    # CIS Azure Foundations Benchmark scoring
                    $cisScore = $baseScore
                    if (-not $analysis.AccessControl.RbacEnabled) { $cisScore -= 25 }
                    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $cisScore -= 15 }
                    if (-not $analysis.Diagnostics.HasDiagnostics) { $cisScore -= 15 }
                    $analysis.CISComplianceScore = [math]::Max(0, [math]::Min(100, $cisScore))

                    # NIST Cybersecurity Framework scoring
                    $nistScore = $baseScore
                    if (-not $analysis.AccessControl.RbacEnabled) { $nistScore -= 20 }
                    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $nistScore -= 15 }
                    if (-not $analysis.Diagnostics.HasDiagnostics) { $nistScore -= 15 }
                    if (-not $Vault.EnableSoftDelete) { $nistScore -= 10 }
                    if (-not $Vault.EnablePurgeProtection) { $nistScore -= 10 }
                    $analysis.NISTComplianceScore = [math]::Max(0, [math]::Min(100, $nistScore))

                    # ISO 27001 scoring
                    $isoScore = $baseScore
                    if (-not $analysis.AccessControl.RbacEnabled) { $isoScore -= 20 }
                    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $isoScore -= 15 }
                    if (-not $Vault.EnableSoftDelete -or -not $Vault.EnablePurgeProtection) { $isoScore -= 15 }
                    if (-not $analysis.Diagnostics.HasDiagnostics) { $isoScore -= 15 }
                    $analysis.ISOComplianceScore = [math]::Max(0, [math]::Min(100, $isoScore))

                    # Microsoft scoring
                    $msScore = $baseScore
                    if (-not $analysis.AccessControl.RbacEnabled) { $msScore -= 20 }
                    if (-not $analysis.NetworkSecurity.HasPrivateEndpoints) { $msScore -= 15 }
                    if (-not $Vault.EnableSoftDelete) { $msScore -= 15 }
                    if (-not $Vault.EnablePurgeProtection) { $msScore -= 10 }
                    if (-not $analysis.Diagnostics.HasDiagnostics) { $msScore -= 15 }
                    $analysis.MSComplianceScore = [math]::Max(0, [math]::Min(100, $msScore))

                    # Calculate overall compliance score (average of all frameworks)
                    $analysis.ComplianceScore = [math]::Round(($analysis.CISComplianceScore + $analysis.NISTComplianceScore + $analysis.ISOComplianceScore + $analysis.MSComplianceScore) / 4, 0)

                    # Determine risk level based on compliance score and critical gaps
                    $criticalGaps = ($analysis.SecurityGaps | Where-Object { $_.Severity -eq "Critical" }).Count
                    if ($analysis.ComplianceScore -ge 90 -and $criticalGaps -eq 0) {
                        $analysis.RiskLevel = "Low"
                    } elseif ($analysis.ComplianceScore -ge 70 -and $criticalGaps -le 1) {
                        $analysis.RiskLevel = "Medium"
                    } elseif ($analysis.ComplianceScore -ge 50 -or $criticalGaps -le 2) {
                        $analysis.RiskLevel = "High"
                    } else {
                        $analysis.RiskLevel = "Critical"
                    }

                    $__analyze_end = Get-Date
                    Write-Log "Completed analysis of $($Vault.VaultName) - Score: $($analysis.ComplianceScore)%, Risk: $($analysis.RiskLevel) (took $(([math]::Round(($__analyze_end - $__analyze_start).TotalSeconds, 2)))s)" -Level "SUCCESS"

                    return $analysis
                }

                # Re-establish Azure context in parallel job
                $azContext = $using:azContext
                if ($azContext) {
                    try {
                        Set-AzContext -Context $azContext | Out-Null
                    } catch {
                        # Context sharing failed, try alternative authentication
                        Write-Log "Parallel job: failed to set Az context in job for subscription ${subscriptionId}: $($_.Exception.Message)" -Level "DEBUG"
                        try {
                            $null = Connect-AzAccount -Identity -ErrorAction Stop
                        } catch {
                            Write-Log "Parallel job: Connect-AzAccount -Identity also failed: $($_.Exception.Message)" -Level "DEBUG"
                            # If both methods fail, we'll proceed without context and handle errors gracefully
                        }
                    }
                }

                # Test-mode: vaults are pre-limited at subscription level, so no per-job reservation needed

                try {
                    # Use the full Analyze-KeyVault function for complete analysis
                    $analysis = Analyze-KeyVault -Vault $vault -SubscriptionId $subscriptionId -SubscriptionName $subscriptionName
                    $analysis | Add-Member -MemberType NoteProperty -Name "WorkerId" -Value "$($env:COMPUTERNAME)_$PID" -Force
                    return $analysis

                } catch {
                    return @{
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        VaultName = $vault.VaultName
                        ResourceGroupName = $vault.ResourceGroupName
                        Location = $vault.Location
                        Diagnostics = @{ HasDiagnostics = $false }
                        AccessControl = @{ RbacEnabled = $false; AccessPoliciesCount = 0; RoleAssignmentsCount = 0 }
                        NetworkSecurity = @{ HasPrivateEndpoints = $false }
                        SecretInventory = @{ SecretsCount = 0; CertificatesCount = 0; KeysCount = 0; TotalAssets = 0; IAPMNumber = $null; Environment = $null }
                        RotationAnalysis = @{ ManualRotationNeeded = 0; RecentlyRotated = 0; NeverRotated = 0 }
                        SecurityGaps = @(@{ Category = "Error"; Severity = "High"; Issue = "Analysis failed: $($_.Exception.Message)" })
                        QuickWins = @()
                        ComplianceScore = 0
                        CISComplianceScore = 0
                        NISTComplianceScore = 0
                        ISOComplianceScore = 0
                        MSComplianceScore = 0
                        RiskLevel = "Critical"
                        Vault = $vault
                        WorkerId = "$($env:COMPUTERNAME)_$PID"
                    }
                }
            }

            # Collect results from parallel jobs
            foreach ($result in $vaultJobs) {
                if ($global:ScriptStopRequested) {
                    Write-Log "Script stop requested - halting collection of parallel results" -Level 'WARN'
                    break
                }
                $global:gapAnalysisResults += $result
                $totalVaultsAnalyzed++
                $vaultsProcessedInTestMode++

                # persist per-vault JSON/marker if available
                try {
                    if ($result.Vault -and $result.Vault.ResourceId) {
                        Write-Log "Finished analysis of $($result.VaultName) - persisting marker and checkpoint" -Level 'INFO'
                        $jsonPath = $null
                        if ($result.JsonFilePath) { $jsonPath = $result.JsonFilePath }
                        Mark-Vault-Processed -VaultResourceId $result.Vault.ResourceId -JsonFilePath $jsonPath
                        # Immediately persist checkpoint for recoverability
                        try { Save-Checkpoint-Atomic -State $global:checkpoint } catch { Write-Log "Checkpoint save failed: $($_.Exception.Message)" -Level 'WARN' }
                        # Append to incremental CSV. When running in parallel, write to a per-worker temp
                        try {
                            $row = Build-MasterCsvRecord -Analysis $result
                            if ($UseParallelProcessing) {
                                $wId = $null
                                if ($result.PSObject.Properties.Name -contains 'WorkerId') { $wId = $result.WorkerId }
                                Append-IncrementalCsvRow -Row $row -WorkerId $wId
                            } else {
                                Append-IncrementalCsvRow -Row $row
                            }
                        } catch {
                            # Non-fatal: continue on append errors
                        }
                    }
                } catch { }

                Write-Log "Completed parallel analysis of $($result.VaultName) - Score: $($result.ComplianceScore)%, Risk: $($result.RiskLevel)" -Level "INFO"

                # Check if we've reached the overall limit
                if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
                    Write-Log "Test mode limit ($Limit) reached, stopping analysis" -Level "INFO"
                    break
                }

                # Simulate an interrupt for testing if requested
                if ($SimulateInterruptAfter -and $SimulateInterruptAfter -gt 0 -and $vaultsProcessedInTestMode -ge $SimulateInterruptAfter) {
                    Write-Log "SimulateInterruptAfter threshold reached ($SimulateInterruptAfter) - saving checkpoint and setting stop flag" -Level "WARN"
                    $global:ScriptStopRequested = $true
                    try {
                        try {
                            Save-Checkpoint-Atomic -State $global:checkpoint
                            Write-Log "Checkpoint saved to: $(Get-CheckpointPath)" -Level "INFO"
                        } catch {
                            Write-Log "Save-Checkpoint-Atomic failed: $($_.Exception.Message)" -Level 'ERROR'
                        }
                    } catch {
                        Write-Log "Failed to save checkpoint during simulated interrupt: $($_.Exception.Message)" -Level "ERROR"
                    }
                    break
                }

                # Simulation: optionally trigger an interrupt after N processed vaults
                if ($SimulateInterruptAfter -gt 0 -and $vaultsProcessedInTestMode -ge $SimulateInterruptAfter) {
                    Write-Log "SimulateInterruptAfter reached ($SimulateInterruptAfter) - simulating CTRL-C and saving checkpoint" -Level 'WARN'
                    $global:ScriptStopRequested = $true
                    try { Save-Checkpoint-Atomic -State $global:checkpoint } catch { }
                    break
                }
            }
        } else {
            # Sequential processing (original logic)
            foreach ($vault in $keyVaults) {
                if ($global:ScriptStopRequested) {
                    Write-Log "Script stop requested - aborting sequential vault processing" -Level 'WARN'
                    break
                }
                # mark current in-progress vault so CTRL-C handler can persist a partial checkpoint if needed
                $global:currentVaultInProgress = $vault.ResourceId

                # Test-mode: attempt an atomic reservation before processing this vault (only for parallel processing)
                if ($TestMode -and $UseParallelProcessing) {
                    try {
                        $reserved = Try-Reserve-TestSlot -Limit $Limit -CounterPath $testCounterPath
                    } catch {
                        $reserved = $false
                    }
                    if (-not $reserved) {
                        Write-Log "Test mode: global limit reached; skipping remaining vaults" -Level 'INFO'
                        break
                    } else {
                        Write-Log ("Test mode: reserved slot for vault: $($vault.VaultName)") -Level 'DEBUG'
                    }
                }
                $analysis = Analyze-KeyVault -Vault $vault -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name
                $global:gapAnalysisResults += $analysis
                $totalVaultsAnalyzed++
                $vaultsProcessedInTestMode++

                # persist per-vault JSON/marker
                try {
                    if ($analysis.Vault -and $analysis.Vault.ResourceId) {
                        Write-Log "Finished analysis of $($analysis.Vault.VaultName) - persisting marker and checkpoint" -Level 'INFO'
                        $jsonPath = $null
                        if ($analysis.JsonFilePath) { $jsonPath = $analysis.JsonFilePath }
                        Mark-Vault-Processed -VaultResourceId $analysis.Vault.ResourceId -JsonFilePath $jsonPath
                        # clear in-progress marker now that vault completed successfully
                        $global:currentVaultInProgress = $null
                        # Immediately persist checkpoint for recoverability
                        try { Save-Checkpoint-Atomic -State $global:checkpoint } catch { Write-Log "Checkpoint save failed: $($_.Exception.Message)" -Level 'WARN' }
                        # Append to incremental CSV when sequential
                        if (-not $UseParallelProcessing) {
                            try { $row = Build-MasterCsvRecord -Analysis $analysis; Append-IncrementalCsvRow -Row $row } catch { }
                        }
                    }
                } catch { }

                Write-Log "Completed analysis of $($vault.VaultName) - Score: $($analysis.ComplianceScore)%, Risk: $($analysis.RiskLevel)" -Level "INFO"

                # Check if we've reached the overall limit
                if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
                    Write-Log "Test mode limit ($Limit) reached, stopping analysis" -Level "INFO"
                    break
                }

                    # Simulate an interrupt for testing if requested
                    if ($SimulateInterruptAfter -and $SimulateInterruptAfter -gt 0 -and $vaultsProcessedInTestMode -ge $SimulateInterruptAfter) {
                        Write-Log "SimulateInterruptAfter threshold reached ($SimulateInterruptAfter) - saving checkpoint and setting stop flag" -Level "WARN"
                        $global:ScriptStopRequested = $true
                        try {
                            try {
                                Save-Checkpoint-Atomic -State $global:checkpoint
                                Write-Log "Checkpoint saved to: $(Get-CheckpointPath)" -Level "INFO"
                            } catch {
                                Write-Log "Save-Checkpoint-Atomic failed: $($_.Exception.Message)" -Level 'ERROR'
                            }
                        } catch {
                            Write-Log "Failed to save checkpoint during simulated interrupt: $($_.Exception.Message)" -Level "ERROR"
                        }
                        break
                    }

                # Simulation: optionally trigger an interrupt after N processed vaults
                if ($SimulateInterruptAfter -gt 0 -and $vaultsProcessedInTestMode -ge $SimulateInterruptAfter) {
                    Write-Log "SimulateInterruptAfter reached ($SimulateInterruptAfter) - simulating CTRL-C and saving checkpoint" -Level 'WARN'
                    $global:ScriptStopRequested = $true
                    try { Save-Checkpoint-Atomic -State $global:checkpoint } catch { }
                    break
                }
            }
        }

        # Break out of subscription loop if overall limit reached
        if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
            break
        }

        # Increment subscription counter for test mode
        if ($TestMode) {
            $subscriptionsProcessedInTestMode++
        }
    }

    # Export CSV results
    Write-Log "Exporting CSV results..." -Level "INFO"
    # Merge any per-worker incremental temp files into the master incremental CSV (parallel-safe)
    try { Merge-IncrementalTempFiles } catch { }
    Write-Log "Analysis results count: $($global:gapAnalysisResults.Count)" -Level "INFO"

    if ($global:gapAnalysisResults -and $global:gapAnalysisResults.Count -gt 0) {
        # --- Normalization: QuickWins dedupe and deterministic counts ---
        # Ensure QuickWins titles are deduplicated (case-insensitive) per-vault
        # so both CSV and HTML compute totals from the same canonical set.
        try {
            foreach ($a in $global:gapAnalysisResults) {
                if ($null -ne $a.QuickWins -and ($a.QuickWins -is [System.Collections.IEnumerable])) {
                    # Group by lowercased Title to dedupe recommendations that differ only by case
                    $deduped = ($a.QuickWins | Where-Object { $_.Title } | Group-Object -Property { ($_.Title -as [string]).ToLowerInvariant() } | ForEach-Object { $_.Group[0] })
                    $a.QuickWins = @()
                    if ($deduped) { $a.QuickWins = $deduped }
                    # Ensure a numeric QuickWinsCount is present and deterministic
                    try { $a.QuickWinsCount = ($a.QuickWins | Where-Object { $_.Title } | Measure-Object).Count } catch { $a.QuickWinsCount = 0 }
                } else {
                    $a.QuickWins = @()
                    $a.QuickWinsCount = 0
                }
            }

            # Compute global unique quick-win titles across all vaults (canonicalized)
            $allTitles = @()
            foreach ($v in $global:gapAnalysisResults) {
                foreach ($w in $v.QuickWins) { if ($w.Title) { $allTitles += ($w.Title -as [string]) } }
            }
            $uniqueWinTitles = ($allTitles | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '' } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
            $global:TotalQuickWinsUnique = ($uniqueWinTitles).Count
            Write-Log "Canonical QuickWins unique titles: $($global:TotalQuickWinsUnique)" -Level "INFO"
        } catch {
            Write-Log "QuickWins normalization failed: $($_.Exception.Message)" -Level "WARN"
        }

        # Enrich results with additional Az CLI/Pwsh data (best-effort)
        Write-Log "Starting enrichment of $($global:gapAnalysisResults.Count) results with Collect-ExtraAzData" -Level 'INFO'
        $enrichStart = Get-Date
        $enrichedResults = @()
        foreach ($gr in $global:gapAnalysisResults) {
            try {
                Write-Log "Enriching vault: $($gr.VaultName) ($($gr.Vault.ResourceId))" -Level 'INFO'
                $er = Collect-ExtraAzData -Analysis $gr
                $enrichedResults += $er
                Write-Log "Enriched vault: $($gr.VaultName) - done" -Level 'INFO'
            } catch {
                Write-Log "Collect-ExtraAzData threw for $($gr.VaultName): $($_.Exception.Message)" -Level 'ERROR'
                $enrichedResults += $gr
            }
        }
        $enrichDur = (Get-Date) - $enrichStart
        Write-Log "Enrichment completed for $($enrichedResults.Count) vault(s) in $([math]::Round($enrichDur.TotalSeconds,2))s" -Level 'INFO'

        # Progress marker file to help diagnose hangs/stalls (appends latest step)
        $progressFile = Join-Path -Path $env:TEMP -ChildPath 'akv_gap_progress.txt'
        function Write-ProgressMarker([string]$m) {
            try {
                $t = (Get-Date).ToString('o')
                "$t`t$m" | Out-File -FilePath $progressFile -Encoding UTF8 -Append -Force
            } catch { }
        }

        # Flatten the enriched results for CSV export using the master record builder
        Write-Log "Starting Build-MasterCsvRecord for $($enrichedResults.Count) enriched results" -Level 'INFO'
        Write-ProgressMarker ("Starting Build-MasterCsvRecord for {0} enriched results" -f $enrichedResults.Count)
        $buildStart = Get-Date
        $flattenedResults = @()
        foreach ($er in $enrichedResults) {
            try {
                $id = ''
                try { $id = $er.VaultName -as [string] } catch { $id = ($er.Vault.ResourceId -as [string]) }
                Write-Log "Building CSV record for: $id" -Level 'INFO'
                $row = Build-MasterCsvRecord -Analysis $er
                if ($row -ne $null) { $flattenedResults += $row; Write-Log "Built CSV record for: $id" -Level 'INFO'; Write-ProgressMarker ("Built CSV record for: {0}" -f $id) } else { Write-Log "Build-MasterCsvRecord returned null for: $id" -Level 'WARN'; Write-ProgressMarker ("Build-MasterCsvRecord returned null for: {0}" -f $id) }
            } catch {
                Write-Log ("Error building CSV record for {0}: {1}" -f $id, ($_.Exception.Message -as [string])) -Level 'ERROR'
            }
        }
        $buildDur = (Get-Date) - $buildStart
        Write-Log "Build-MasterCsvRecord completed for $($flattenedResults.Count) records in $([math]::Round($buildDur.TotalSeconds,2))s" -Level 'INFO'

        # Final coercion pass: build a safe, new PSCustomObject per row so we don't try to set properties
        # on values that may be immutable or missing properties. This also makes exported CSVs stable.
        try {
            # Allow test-time override of the final coercion timeout and heartbeat via env vars or global vars.
            $finalCoercionTimeout = 60
            if ($env:FINAL_COERCION_TIMEOUT) {
                try { $finalCoercionTimeout = [int]$env:FINAL_COERCION_TIMEOUT } catch { }
            } elseif ($global:FinalCoercionTimeoutSeconds) {
                try { $finalCoercionTimeout = [int]$global:FinalCoercionTimeoutSeconds } catch { }
            }
            $finalCoercionHeartbeat = 5
            if ($env:FINAL_COERCION_HEARTBEAT) {
                try { $finalCoercionHeartbeat = [int]$env:FINAL_COERCION_HEARTBEAT } catch { }
            } elseif ($global:FinalCoercionHeartbeatSeconds) {
                try { $finalCoercionHeartbeat = [int]$global:FinalCoercionHeartbeatSeconds } catch { }
            }

            Write-Log "Final coercion timeout set to ${finalCoercionTimeout}s (heartbeat ${finalCoercionHeartbeat}s)" -Level 'DEBUG'

            # To avoid Start-Job serialization issues with complex Az/PSObject types,
            # write the flattened results to a temporary JSON file and pass the file
            # path to the background job. The job will read and parse the JSON which
            # avoids attempting to serialize CLR types across runspaces.
            $finalCoercionTemp = Join-Path -Path $env:TEMP -ChildPath ("akv_final_coercion_{0}.json" -f ([guid]::NewGuid().ToString()))
            # Normalize flattenedResults: drop obvious primitives or empty/zero-property items to avoid coercion confusion
            try {
                $preCount = 0; if ($flattenedResults) { $preCount = $flattenedResults.Count }
            } catch { $preCount = 0 }
            try {
                $flattenedResults = @($flattenedResults | Where-Object { $_ -and ( ($_ -is [PSObject]) -or ($_ -is [hashtable]) ) -and ($_.PSObject.Properties.Count -gt 0) })
            } catch { }
            try { $filteredCount = $flattenedResults.Count } catch { $filteredCount = 0 }
            Write-Log "Final coercion: filtered flattenedResults $preCount -> $filteredCount (dropped non-object/empty rows)" -Level 'DEBUG'
            try {
                $flattenedResults | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $finalCoercionTemp -Encoding UTF8 -Force
                Write-ProgressMarker ("WROTE_FINAL_COERCION_TEMP {0} count={1}" -f $finalCoercionTemp, $filteredCount)
            } catch {
                # Fallback: try a lower depth if conversion fails
                try { $flattenedResults | ConvertTo-Json -Depth 6 | Out-File -FilePath $finalCoercionTemp -Encoding UTF8 -Force; Write-ProgressMarker ("WROTE_FINAL_COERCION_TEMP (fallback depth6) {0} count={1}" -f $finalCoercionTemp, $filteredCount) } catch { Write-ProgressMarker ("FAILED_WRITE_FINAL_COERCION_TEMP {0}" -f $finalCoercionTemp) }
            }

            $finalCoercionScript = {
                param($rowsOrPath)
                # If the caller passed a file path, read JSON from disk to obtain rows
                $rows = $null
                try {
                    if ($rowsOrPath -is [string] -and (Test-Path $rowsOrPath)) {
                        $txt = Get-Content -Path $rowsOrPath -Raw -ErrorAction Stop
                        try { $rows = $txt | ConvertFrom-Json -ErrorAction Stop } catch { $rows = @() }
                    } else {
                        $rows = $rowsOrPath
                    }
                } catch {
                    $rows = @()
                }
                # Testing hook: if FORCE_FINAL_COERCION env var is set, sleep inside
                # the timed scriptblock long enough to guarantee the heartbeat
                # wrapper will time out and trigger the diagnostic writer.
                try {
                    if ($env:FORCE_FINAL_COERCION -and $env:FORCE_FINAL_COERCION -ne '') {
                        $baseTimeout = 60
                        if ($env:FINAL_COERCION_TIMEOUT) {
                            try { $baseTimeout = [int]$env:FINAL_COERCION_TIMEOUT } catch { }
                        }
                        $sleepSec = $baseTimeout + 10
                        if ($env:FORCE_FINAL_COERCION_SLEEP) {
                            try { $sleepSec = [int]$env:FORCE_FINAL_COERCION_SLEEP } catch { }
                        }
                        Write-Output "FORCE_FINAL_COERCION detected: sleeping ${sleepSec}s to trigger final-coercion timeout"
                        Start-Sleep -Seconds $sleepSec
                    }
                } catch {
                    # swallow test-hook failures so they don't affect main logic
                }
                $localFinal = @()
                $diagMsgs = @()
                # Normalize incoming rows: ensure we have a flat array of objects to iterate
                $rowsToProcess = @()
                try {
                    if ($null -eq $rows) {
                        $rowsToProcess = @()
                    } elseif ($rows -is [System.Collections.IEnumerable] -and -not ($rows -is [string])) {
                        foreach ($r in $rows) { $rowsToProcess += $r }
                    } else {
                        $rowsToProcess += $rows
                    }
                } catch {
                    # fallback: wrap as single element
                    $rowsToProcess = @($rows)
                }
                # Add optional bounds and progress logging for in-process runs
                $rowIndex = 0
                $coercionStart = Get-Date
                $maxRows = $null
                $maxSeconds = $null
                if ($env:FINAL_COERCION_MAX_ROWS) { try { $maxRows = [int]$env:FINAL_COERCION_MAX_ROWS } catch { $maxRows = $null } }
                if ($env:FINAL_COERCION_MAX_SECONDS) { try { $maxSeconds = [int]$env:FINAL_COERCION_MAX_SECONDS } catch { $maxSeconds = $null } }
                # In-process guard: maximum seconds to allow synchronous coercion (0 = unlimited)
                $inprocessMaxSec = 0
                if ($env:FINAL_COERCION_INPROCESS_MAX_SECONDS) { try { $inprocessMaxSec = [int]$env:FINAL_COERCION_INPROCESS_MAX_SECONDS } catch { $inprocessMaxSec = 0 } }
                # Allow skipping per-vault JSON writes when running in-process for faster runs
                $disablePerVaultJson = $false
                if ($env:DISABLE_PER_VAULT_JSON -and $env:DISABLE_PER_VAULT_JSON -ne '') { $disablePerVaultJson = $true }
                if ($rowsToProcess.Count -eq 0) { Write-Log "[COERCION] No rows to process in final coercion" -Level 'DEBUG' }
                foreach ($orig in $rowsToProcess) {
                    $rowIndex++
                    if ($rowIndex % 10 -eq 0) {
                        $elapsed = (Get-Date) - $coercionStart
                        Write-Log "[COERCION] Processing row $rowIndex of $($rowsToProcess.Count) (elapsed: $([math]::Round($elapsed.TotalSeconds,1))s)" -Level 'DEBUG'
                    }
                    # Respect optional bounds to avoid unbounded synchronous runs
                    if ($maxRows -and $rowIndex -gt $maxRows) {
                        $diagMsgs += ("Stopped coercion after {0} rows due to FINAL_COERCION_MAX_ROWS" -f $maxRows)
                        break
                    }
                    if ($maxSeconds) {
                        $elapsed = (Get-Date) - $coercionStart
                        if ($elapsed.TotalSeconds -gt $maxSeconds) {
                            $diagMsgs += ("Stopped coercion after {0}s due to FINAL_COERCION_MAX_SECONDS" -f $maxSeconds)
                            break
                        }
                    }

                    # Per-row diagnostics: type and prop count
                    $rowStart = Get-Date
                    try { $rowType = if ($null -eq $orig) { 'Null' } else { $orig.GetType().FullName } } catch { $rowType = 'Unknown' }
                    try { $propCount = if ($orig -and $orig.PSObject -and $orig.PSObject.Properties) { $orig.PSObject.Properties.Count } else { 0 } } catch { $propCount = 0 }
                    Write-Log "[COERCION] Row #$rowIndex type=$rowType propCount=$propCount VaultName='$($orig.VaultName -as [string])'" -Level 'DEBUG'

                    # If the incoming element looks like a primitive (no properties and is value type/string), coerce into hashtable
                    if ($propCount -eq 0 -and ($orig -is [string] -or $orig -is [System.ValueType] -or $rowType -eq 'System.Boolean')) {
                        try {
                            $co = [ordered]@{}
                            $co['Value'] = ($orig -as [string]) ?? ''
                            $orig = [PSCustomObject]$co
                            Write-Log "[COERCION] Coerced non-object row #$rowIndex to PSCustomObject" -Level 'DEBUG'
                        } catch {
                            $errMsg = $_.Exception.Message
                            Write-Log ("[COERCION] Failed to coerce non-object row #{0}: {1}" -f $rowIndex, $errMsg) -Level 'WARN'
                        }
                    }

                    # Start with an ordered hashtable copy of existing properties when possible
                    $props = [ordered]@{}
                    try {
                        foreach ($p in $orig.PSObject.Properties) {
                            $val = $p.Value
                            # Flatten arrays to string for CSV
                            if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                                try { $val = ($val | ForEach-Object { $_.ToString() }) -join '; ' } catch { $val = $val.ToString() }
                            }
                            $props[$p.Name] = $val
                        }
                        Write-Log "[COERCION] Processed props for $($orig.VaultName -as [string]): $($props | Out-String)" -Level 'DEBUG'
                    } catch {
                        $props['Value'] = ($orig -as [string]) ?? ''
                        Write-Log "[COERCION] Failed to process props for $($orig): $($_.Exception.Message)" -Level 'ERROR'
                    }

                    # Helper to safely read from $props (local)
                    function Get-PropValueLocal([hashtable]$h, [string]$name) {
                        if ($h.ContainsKey($name)) { return $h[$name] } else { return $null }
                    }

                    try {
                        # Coerce RoleAssignmentsResolved to a predictable string
                        $rawRole = Get-PropValueLocal $props 'RoleAssignmentsResolved'
                        if ($null -eq $rawRole) {
                            $props['RoleAssignmentsResolved'] = ''
                        } elseif ($rawRole -is [string]) {
                            $props['RoleAssignmentsResolved'] = $rawRole
                        } elseif ($rawRole -is [System.Collections.IEnumerable]) {
                            $parts = @()
                            foreach ($elem in $rawRole) {
                                if ($null -eq $elem) { continue }
                                if ($elem -is [PSObject] -or $elem -is [hashtable]) {
                                    try { $parts += (ConvertTo-Json $elem -Depth 2 -Compress) } catch { $parts += $elem.ToString() }
                                } else { $parts += $elem.ToString() }
                            }
                            $props['RoleAssignmentsResolved'] = ($parts | Where-Object { $_ -and $_ -ne '' }) -join '; '
                        } else {
                            $props['RoleAssignmentsResolved'] = ($rawRole -as [string]) ?? ''
                        }
                    } catch {
                        $props['RoleAssignmentsResolved'] = ''
                    }

                    # Coerce VaultScore to int scalar
                    try {
                        $vs = Get-PropValueLocal $props 'VaultScore'
                        $cs = Get-PropValueLocal $props 'ComplianceScore'
                        $props['VaultScore'] = ($vs -as [int]) ?? ($cs -as [int]) ?? 0
                    } catch {
                        $props['VaultScore'] = (Get-PropValueLocal $props 'ComplianceScore' -as [int]) ?? 0
                    }

                    # Ensure JsonFilePath is string
                    $props['JsonFilePath'] = (Get-PropValueLocal $props 'JsonFilePath' -as [string]) ?? ''

                    # If a per-vault JSON path exists, write a compact vault JSON using the coerced scalars
                    try {
                        $jsonPath = $props['JsonFilePath']
                        if (-not $disablePerVaultJson -and $jsonPath -and $jsonPath -ne '') {
                            $vaultExport = [ordered]@{
                                Timestamp = (Get-Date).ToString('o')
                                SubscriptionId = (Get-PropValueLocal $props 'SubscriptionId' -as [string]) ?? ''
                                SubscriptionName = (Get-PropValueLocal $props 'SubscriptionName' -as [string]) ?? ''
                                VaultName = (Get-PropValueLocal $props 'VaultName' -as [string]) ?? ''
                                VaultResourceId = (Get-PropValueLocal $props 'VaultResourceId' -as [string]) ?? ''
                                Location = (Get-PropValueLocal $props 'Location' -as [string]) ?? ''
                                ComplianceScore = (Get-PropValueLocal $props 'ComplianceScore' -as [int]) ?? 0
                                VaultScore = ($props['VaultScore'] -as [int]) ?? 0
                                RoleAssignmentsResolved = ($props['RoleAssignmentsResolved'] -as [string]) ?? ''
                                ManagedIdentityResolved = (Get-PropValueLocal $props 'ManagedIdentityResolved' -as [string]) ?? ''
                                DiagnosticDestinationNames = (Get-PropValueLocal $props 'DiagnosticDestinationNames' -as [string]) ?? ''
                                SkuName = (Get-PropValueLocal $props 'SkuName' -as [string]) ?? ''
                                SecretRotationMostRecent = (Get-PropValueLocal $props 'SecretRotationMostRecent' -as [string]) ?? ''
                                KeyRotationMostRecent = (Get-PropValueLocal $props 'KeyRotationMostRecent' -as [string]) ?? ''
                                JsonFilePath = $jsonPath
                            }
                            try {
                                Write-ProgressMarker ("ATTEMPT_PER_VAULT_JSON {0}" -f $jsonPath)
                                # Use a simple Out-File for per-vault JSON to avoid atomic helpers that may block on special filesystems
                                $vaultExport | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
                                Write-ProgressMarker ("WROTE_PER_VAULT_JSON {0}" -f $jsonPath)
                            } catch {
                                Write-Log "[COERCION] Failed to write per-vault JSON for $($props['VaultName'] -as [string]): $($_.Exception.Message)" -Level 'DEBUG'
                                Write-ProgressMarker ("FAILED_PER_VAULT_JSON {0} err={1}" -f $jsonPath, ($_.Exception.Message -replace '\r|\n',' '))
                            }
                        }
                    } catch {
                        # ignore failures to write per-vault JSON - CSV should still be the authoritative output
                    }

                    # Record a small diagnostic message for the caller
                    try {
                        $vn = (Get-PropValueLocal $props 'VaultName' -as [string]) ?? ''
                        $diagMsgs += ("Processed vault: {0}" -f $vn)
                    } catch { }

                    try {
                        if ($props -is [hashtable] -or $props -is [System.Collections.Specialized.OrderedDictionary]) {
                            $localFinal += [PSCustomObject]$props
                        } else {
                            # Ensure we always have some representation
                            try { $localFinal += [PSCustomObject]@{ Value = ($orig -as [string]) ?? '' } } catch { }
                            Write-Log "[COERCION] Skipped non-hashtable props for $($orig.VaultName -as [string])" -Level 'ERROR'
                        }
                    } catch {
                        Write-Log "[COERCION] Failed to cast props to PSCustomObject for $($orig.VaultName -as [string]): $($_.Exception.Message)" -Level 'ERROR'
                    }

                    # Check total elapsed time for in-process guard
                    if ($inprocessMaxSec -gt 0) {
                        $elapsed = (Get-Date) - $coercionStart
                        if ($elapsed.TotalSeconds -ge $inprocessMaxSec) {
                            Write-Log "[COERCION] Aborting in-process final coercion after $([math]::Round($elapsed.TotalSeconds,1))s (max=${inprocessMaxSec}s)" -Level 'WARN'
                            $diagMsgs += ("Aborted in-process after processing $rowIndex rows due to FINAL_COERCION_INPROCESS_MAX_SECONDS")
                            break
                        }
                    }
                    # Per-row duration debug (only if slow)
                    $rowDur = (Get-Date) - $rowStart
                    if ($rowDur.TotalSeconds -gt 1) {
                        Write-Log "[COERCION] Slow row #$rowIndex processed in $([math]::Round($rowDur.TotalSeconds,2))s" -Level 'DEBUG'
                    }
                }

                return @{ Results = $localFinal; Messages = $diagMsgs }
            }

            # Decide whether to run final coercion in a timed background job or inline.
            # Default: use background job (Invoke-WithHeartbeat). But for small/test runs
            # prefer in-process to avoid Start-Job serialization issues and command-line limits.
            $inprocessLimit = 3
            if ($env:FINAL_COERCION_INPROCESS_LIMIT) { try { $inprocessLimit = [int]$env:FINAL_COERCION_INPROCESS_LIMIT } catch { $inprocessLimit = 3 } }

            $shouldForceInProcess = $false
            if ($env:FORCE_FINAL_COERCION_MODE -and ($env:FORCE_FINAL_COERCION_MODE -ieq 'inprocess' -or $env:FORCE_FINAL_COERCION_MODE -ieq 'local')) { $shouldForceInProcess = $true }
            if ($global:ForceInProcessFinalCoercion) { $shouldForceInProcess = $true }
            # If running TestMode or processing only a small number of vaults (Limit), prefer in-process
            try {
                if ($TestMode) { $shouldForceInProcess = $true }
                if (($Limit -as [int]) -ne $null) { if ($Limit -le $inprocessLimit) { $shouldForceInProcess = $true } }
            } catch { }

            if ($shouldForceInProcess) {
                Write-Log "Running final coercion synchronously in-process (shouldForceInProcess=$shouldForceInProcess)" -Level 'WARN'
                # When running coercion in-process, avoid per-vault JSON writes which may
                # hang on slow filesystems (OneDrive, network mounts) or cause long IO.
                Write-Log "Disabling per-vault JSON writes for in-process final coercion" -Level 'DEBUG'
                $env:DISABLE_PER_VAULT_JSON = '1'
                try {
                    $invokeResult = & $finalCoercionScript $finalCoercionTemp
                } catch {
                    throw
                } finally {
                    # restore env var if previously unset
                    try { Remove-Item Env:DISABLE_PER_VAULT_JSON -ErrorAction SilentlyContinue } catch { }
                }
            } else {
                $invokeResult = Invoke-WithHeartbeat -ScriptBlock $finalCoercionScript -Args @($finalCoercionTemp) -TimeoutSeconds $finalCoercionTimeout -HeartbeatSeconds $finalCoercionHeartbeat -Description 'Final coercion & per-vault JSON writes'
            }
            # Cleanup temp file (best-effort)
            try { if (Test-Path $finalCoercionTemp) { Remove-Item -Path $finalCoercionTemp -Force -ErrorAction SilentlyContinue } } catch {}

            # Unpack invoke result and log diagnostic messages
            $finalResults = @()
            if ($invokeResult -and $invokeResult.Results) { $finalResults = $invokeResult.Results }
            try {
                if ($invokeResult -and $invokeResult.Messages) {
                    foreach ($m in $invokeResult.Messages) { Write-Log $m -Level 'DEBUG' }
                }
            } catch { }
        } catch {
            Write-Log "Final coercion step timed out or errored: $($_.Exception.Message)" -Level 'ERROR'
            # If job-based invocation failed due to Start-Job serialization of complex objects,
            # attempt an in-process fallback to perform the same coercion logic synchronously.
            if ($_.Exception.Message -and ($_.Exception.Message -match 'Cannot convert the "System.Object\[\]" value')) {
                Write-Log "Detected Start-Job serialization error; attempting in-process final coercion fallback" -Level 'WARN'
                try {
                    $localFinalFb = @()
                    $diagMsgsFb = @()
                    foreach ($orig in $flattenedResults) {
                        try {
                            $propsFb = [ordered]@{}
                            foreach ($p in $orig.PSObject.Properties) {
                                $val = $p.Value
                                if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                                    try { $val = ($val | ForEach-Object { $_.ToString() }) -join '; ' } catch { $val = $val.ToString() }
                                }
                                $propsFb[$p.Name] = $val
                            }
                        } catch {
                            $propsFb['Value'] = ($orig -as [string]) ?? ''
                        }

                        # Coerce RoleAssignmentsResolved
                        try {
                            $rawRole = $propsFb['RoleAssignmentsResolved']
                            if ($null -eq $rawRole) { $propsFb['RoleAssignmentsResolved'] = '' }
                            elseif ($rawRole -is [string]) { $propsFb['RoleAssignmentsResolved'] = $rawRole }
                            elseif ($rawRole -is [System.Collections.IEnumerable]) {
                                $parts = @()
                                foreach ($elem in $rawRole) {
                                    if ($null -eq $elem) { continue }
                                    if ($elem -is [PSObject] -or $elem -is [hashtable]) {
                                        try { $parts += (ConvertTo-Json $elem -Depth 2 -Compress) } catch { $parts += $elem.ToString() }
                                    } else { $parts += $elem.ToString() }
                                }
                                $propsFb['RoleAssignmentsResolved'] = ($parts | Where-Object { $_ -and $_ -ne '' }) -join '; '
                            } else { $propsFb['RoleAssignmentsResolved'] = ($rawRole -as [string]) ?? '' }
                        } catch { $propsFb['RoleAssignmentsResolved'] = '' }

                        # VaultScore
                        try {
                            $vs = $propsFb['VaultScore']; $cs = $propsFb['ComplianceScore']
                            $propsFb['VaultScore'] = ($vs -as [int]) ?? ($cs -as [int]) ?? 0
                        } catch { $propsFb['VaultScore'] = ($propsFb['ComplianceScore'] -as [int]) ?? 0 }

                        # JsonFilePath
                        $propsFb['JsonFilePath'] = ($propsFb['JsonFilePath'] -as [string]) ?? ''

                        # Write per-vault JSON if requested
                        try {
                            $jsonPathFb = $propsFb['JsonFilePath']
                            if ($jsonPathFb -and $jsonPathFb -ne '') {
                                $vaultExportFb = [ordered]@{
                                    Timestamp = (Get-Date).ToString('o')
                                    SubscriptionId = ($propsFb['SubscriptionId'] -as [string]) ?? ''
                                    SubscriptionName = ($propsFb['SubscriptionName'] -as [string]) ?? ''
                                    VaultName = ($propsFb['VaultName'] -as [string]) ?? ''
                                    VaultResourceId = ($propsFb['VaultResourceId'] -as [string]) ?? ''
                                    Location = ($propsFb['Location'] -as [string]) ?? ''
                                    ComplianceScore = ($propsFb['ComplianceScore'] -as [int]) ?? 0
                                    VaultScore = ($propsFb['VaultScore'] -as [int]) ?? 0
                                    RoleAssignmentsResolved = ($propsFb['RoleAssignmentsResolved'] -as [string]) ?? ''
                                    JsonFilePath = $jsonPathFb
                                }
                                try { Write-AtomicJson -Path $jsonPathFb -Object $vaultExportFb -Depth 4 } catch { }
                            }
                        } catch { }

                        $diagMsgsFb += ("Processed vault: {0}" -f (($propsFb['VaultName'] -as [string]) ?? ''))
                        try { $localFinalFb += [PSCustomObject]$propsFb } catch { }
                    }
                    $invokeResult = @{ Results = $localFinalFb; Messages = $diagMsgsFb }
                    $finalResults = $invokeResult.Results
                    Write-Log "In-process final coercion fallback succeeded" -Level 'INFO'
                } catch {
                    Write-Log "In-process final coercion fallback also failed: $($_.Exception.Message)" -Level 'ERROR'
                }
            }
            try {
                $diagPath = Join-Path -Path $outputDir -ChildPath ("final_coercion_diag_{0}.txt" -f (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))
                $diag = [ordered]@{
                    Timestamp = (Get-Date).ToString('o')
                    Error = ($_.Exception.Message)
                    FlattenedCount = ($flattenedResults.Count)
                    FirstVaults = ($flattenedResults | Select-Object -First 20 | ForEach-Object { ($_).VaultName } | Where-Object { $_ } ) -join '; '
                }
                $diag | Out-File -FilePath $diagPath -Encoding UTF8
                Write-Log "Wrote final coercion diagnostic to: $diagPath" -Level 'INFO'
                    Write-ProgressMarker ("WROTE_FINAL_COERCION_DIAG {0}" -f $diagPath)

                # Also write a fuller diagnostic into the repository workspace for easier inspection by developers
                try {
                    # Determine repository base safely. $PSScriptRoot is preferred when available.
                    # Some invocation contexts populate MyInvocation.MyCommand.Definition with the
                    # entire script body (not a path), which makes Split-Path blow up with a "path
                    # too long" error. Guard by testing the path first.
                    if ($PSScriptRoot -and $PSScriptRoot -ne '') {
                        $repoBase = $PSScriptRoot
                    } elseif ($MyInvocation -and $MyInvocation.MyCommand -and
                              $MyInvocation.MyCommand.Definition -and
                              (Test-Path $MyInvocation.MyCommand.Definition)) {
                        $repoBase = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent -ErrorAction SilentlyContinue
                    } else {
                        $repoBase = Get-Location
                    }
                    $repoOutputDir = Join-Path -Path $repoBase 'output'
                    if (-not (Test-Path $repoOutputDir)) { New-Item -ItemType Directory -Path $repoOutputDir -Force | Out-Null }
                    $repoDiagPath = Join-Path -Path $repoOutputDir -ChildPath ("final_coercion_diag_full_{0}.json" -f (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))
                    try {
                        $sample = $flattenedResults | Select-Object -First 50
                        $sample | ConvertTo-Json -Depth 8 | Out-File -FilePath $repoDiagPath -Encoding UTF8 -Force
                        Write-Log "Wrote extended final coercion diagnostic to workspace: $repoDiagPath" -Level 'INFO'
                            Write-ProgressMarker ("WROTE_FINAL_COERCION_FULL {0}" -f $repoDiagPath)
                    } catch {
                        Write-Log "Failed to write extended final coercion diagnostic to workspace: $($_.Exception.Message)" -Level 'WARN'
                    }
                } catch {
                    # non-fatal
                }
            } catch {
                Write-Log "Failed to write final coercion diagnostic: $($_.Exception.Message)" -Level 'WARN'
            }
            # Continue to HTML generation despite final coercion failure
        }

        # Recompute canonical unique QuickWins now (ensure it's up-to-date before HTML generation)
        try {
            $allWinTitles = @()
            foreach ($v in $global:gapAnalysisResults) { foreach ($w in ($v.QuickWins)) { if ($w.Title) { $allWinTitles += $w.Title } } }
            $uniqueWinTitles = @()
            if ($allWinTitles.Count -gt 0) {
                $uniqueWinTitles = ($allWinTitles | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '' } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
            }
            $global:uniqueWinTitles = $uniqueWinTitles
            $global:TotalQuickWinsUnique = ($uniqueWinTitles).Count
        } catch {
            $global:uniqueWinTitles = @()
            $global:TotalQuickWinsUnique = 0
        }

        # Pre-export parity check: ensure canonical unique QuickWins (computed earlier) matches parsed QuickWinsSummary
        try {
            $parsedTitles = @()
            foreach ($row in $finalResults) {
                if ($row.QuickWinsSummary -and $row.QuickWinsSummary.Trim() -ne '') {
                    $parts = $row.QuickWinsSummary -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
                    $parsedTitles += $parts
                }
            }
            $parsedUnique = ($parsedTitles | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
            $parsedCount = ($parsedUnique).Count
            if ($global:TotalQuickWinsUnique -ne $parsedCount) {
                Write-Log "Pre-export parity check failed: canonical unique quick wins ($($global:TotalQuickWinsUnique)) != parsed quick wins from CSV data ($parsedCount)" -Level "WARN"
                # Write a small reconciliation file to workspace for debugging
                try {
                    $reconPath = Join-Path -Path (Split-Path -Path $csvPath -Parent) -ChildPath "quickwins_reconciliation_$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')).csv"
                    $reconObj = [PSCustomObject]@{
                        CanonicalCount = $global:TotalQuickWinsUnique
                        ParsedCount = $parsedCount
                        CanonicalTitles = ($uniqueWinTitles -join '; ')
                        ParsedTitles = ($parsedUnique -join '; ')
                    }
                    $reconObj | Export-Csv -Path $reconPath -NoTypeInformation -Encoding UTF8
                    Write-Log "Wrote quick-wins reconciliation to: $reconPath" -Level "INFO"
                } catch {
                    Write-Log "Failed to write quick-wins reconciliation file: $($_.Exception.Message)" -Level "WARN"
                }
            } else {
                Write-Log "Pre-export parity check: canonical quick wins ($($global:TotalQuickWinsUnique)) == parsed quick wins ($parsedCount)" -Level "INFO"
            }
        } catch {
            Write-Log "Pre-export parity check encountered an error: $($_.Exception.Message)" -Level "WARN"
        }

        Write-Log "Starting final CSV export to: $csvPath" -Level "INFO"
        # Use background job with heartbeat and timeout to detect IO stalls/hangs
        $csvTimeout = $global:CsvExportTimeoutSeconds
        if (-not $csvTimeout -or $csvTimeout -le 0) { $csvTimeout = 600 } # default 10 minutes
        try {
            # Ensure a stable, canonical column order for CSV exports.
            # Prefer an existing template CSV header (most recent KeyVaultComprehensiveAudit_*.csv in script dir) if available,
            # otherwise use the union of property names from the final results.
            # Compute script directory robustly: prefer $PSScriptRoot; fall back to MyInvocation when it's a real path.
            if ($PSScriptRoot -and $PSScriptRoot -ne '') {
                $scriptDir = $PSScriptRoot
            } elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Definition -and (Test-Path $MyInvocation.MyCommand.Definition)) {
                $scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
            } else {
                $scriptDir = Get-Location
            }
            $templateCsv = Get-ChildItem -Path $scriptDir -Filter 'KeyVaultComprehensiveAudit_*.csv' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($templateCsv) {
                try {
                    $headerLine = (Get-Content -Path $templateCsv.FullName -TotalCount 1 -ErrorAction Stop)
                    $headerLine = $headerLine.Trim()
                    if ($headerLine.StartsWith('"') -and $headerLine.EndsWith('"')) { $headerLine = $headerLine.TrimStart('"').TrimEnd('"') }
                    $templateHeaders = $headerLine -split '","'
                } catch {
                    $templateHeaders = @()
                }
            } else {
                $templateHeaders = @()
            }

            # Get all properties from the results
            $resultProperties = $finalResults | ForEach-Object { $_.PSObject.Properties.Name } | Sort-Object -Unique
            
            # Merge template headers with result properties, preferring template order but ensuring all result properties are included
            if ($templateHeaders -and $templateHeaders.Count -gt 0) {
                $preferredHeaders = $templateHeaders
                # Add any result properties that are not in the template
                $missingProperties = $resultProperties | Where-Object { $_ -notin $templateHeaders }
                $preferredHeaders += $missingProperties
            } else {
                # Fall back to union of properties found in the results (stable alphabetical order)
                $preferredHeaders = $resultProperties
            }

            # Select objects with the preferred header order; missing properties will be emitted as empty fields.
            $exportSelection = $preferredHeaders
            $toExport = $finalResults | Select-Object -Property $exportSelection
            $toExport | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
            Write-Log "CSV export finished (file: $csvPath)" -Level 'SUCCESS'
            Write-Log "HTML Report: $htmlPath" -Level "INFO"
            Write-Log "CSV Data: $csvPath" -Level "INFO"
        } catch {
            Write-Log "CSV export FAILED: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    } else {
        Write-Log "No analysis results to export" -Level "WARNING"
        # Create empty CSV with headers
        $emptyResult = [PSCustomObject]@{
            SubscriptionId = ""
            VaultName = ""
            Location = ""
            ComplianceScore = 0
            RiskLevel = ""
            SecurityGapsCount = 0
            QuickWinsCount = 0
        }
        $emptyResult | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }

    # Generate HTML report
    Write-Log "Generating HTML report..." -Level "INFO"
    New-GapAnalysisHtmlReport -AnalysisResults $global:gapAnalysisResults -PlatformAssessments $platformAssessments -OutputPath $htmlPath

    # Post-run: copy CSV and HTML into repository workspace for easier inspection (best-effort)
    try {
        # Prefer PSScriptRoot when running as a script; fallback to MyInvocation path when necessary
        $repoBase = $PSScriptRoot
        if (-not $repoBase -or $repoBase -eq '') {
            $repoBase = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent -ErrorAction SilentlyContinue
        }
        if (-not $repoBase -or $repoBase -eq '') { throw 'Unable to determine repository base path for workspace copy' }

        $repoOutputDir = Join-Path $repoBase 'output'
        if (!(Test-Path $repoOutputDir)) { New-Item -ItemType Directory -Path $repoOutputDir -Force | Out-Null }
        $repoCsv = Join-Path $repoOutputDir (Split-Path -Path $csvPath -Leaf)
        $repoHtml = Join-Path $repoOutputDir (Split-Path -Path $htmlPath -Leaf)
        # Copy CSV
        try {
            Write-Log "Copying CSV to workspace: $repoCsv" -Level "INFO"
            Copy-Item -Path $csvPath -Destination $repoCsv -Force -ErrorAction Stop
            Write-Log "Copied CSV to workspace: $repoCsv" -Level "INFO"
        } catch {
            Write-Log "Failed to copy CSV to workspace: $($_.Exception.Message)" -Level "WARN"
        }

        # Copy HTML if present
        try {
            if (Test-Path $htmlPath) {
                Write-Log "Copying HTML to workspace: $repoHtml" -Level "INFO"
                Copy-Item -Path $htmlPath -Destination $repoHtml -Force -ErrorAction Stop
                Write-Log "Copied HTML to workspace: $repoHtml" -Level "INFO"
            } else {
                Write-Log "HTML path not found, skipping workspace copy: $htmlPath" -Level "INFO"
            }
        } catch {
            Write-Log "Failed to copy HTML to workspace: $($_.Exception.Message)" -Level "WARN"
        }
        Write-Log "Workspace copy attempts completed (best-effort) to: $repoOutputDir" -Level "INFO"
    } catch {
        # Non-fatal if copy fails (e.g., permissions or path issues) - continue silently
    }

    # Restore any altered global preferences (best-effort)
    try {
        if (Get-Variable -Name __prevWarningPreference -Scope Script -ErrorAction SilentlyContinue) {
            $WarningPreference = $script:__prevWarningPreference
            Remove-Variable -Name __prevWarningPreference -Scope Script -ErrorAction SilentlyContinue
        }
    } catch { }

    # Summary
    $endTime = Get-Date
    $duration = $endTime - $StartTime

    Write-Log "Gap analysis completed successfully!" -Level "SUCCESS"
    Write-Log "Total vaults analyzed: $totalVaultsAnalyzed" -Level "INFO"
    Write-Log "Execution time: $([math]::Round($duration.TotalMinutes, 1)) minutes" -Level "INFO"
    Write-Log "Results saved to: $outputDir" -Level "INFO"
    Write-Log "HTML Report: $htmlPath" -Level "INFO"
    Write-Log "CSV Data: $csvPath" -Level "INFO"
    Write-Log "Log File: $logPath" -Level "INFO"

    # Cleanup run lock (best-effort) so future runs can start
    if (-not $NoRunLock) {
        if ($script:RunLockPath -and (Test-Path $script:RunLockPath)) {
            try {
                $rawLock = Get-Content -Path $script:RunLockPath -ErrorAction SilentlyContinue -Raw
                $meta = $null
                if ($rawLock -and $rawLock.Trim() -ne '') {
                try {
                    $meta = $rawLock | ConvertFrom-Json -ErrorAction SilentlyContinue
                } catch {
                    $meta = $null
                }
            }
                $shouldRemove = $false
                if ($meta -and $meta.PID) {
                    if ($meta.PID -eq $PID) { $shouldRemove = $true }
                } else {
                    # Unknown metadata - attempt removal
                    $shouldRemove = $true
                }
                if ($shouldRemove) {
                        Remove-Item -Path $script:RunLockPath -Force -ErrorAction SilentlyContinue
                        Write-Log "Removed run lock: $script:RunLockPath" -Level 'INFO'
                } else {
                    Write-Log "Did not remove run lock ($script:RunLockPath) owned by PID $($meta.PID)" -Level 'DEBUG'
                }
            } catch {
                # fallback: attempt remove
                Remove-Item -Path $script:RunLockPath -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-Log "NoRunLock was set for this run; skipping run-lock cleanup." -Level 'DEBUG'
    }
    # Clear in-process sentinel
    try {
        $global:AkvGapAnalysis_InProcessRun = $false
    } catch {
    }
}

# Run the gap analysis (or run HTML-only mode for child process)
## Compatibility alias: some older callers referenced Get-AKVGapAnalysis as the entrypoint
try {
    if (-not (Get-Command -Name Get-AKVGapAnalysis -ErrorAction SilentlyContinue)) {
        Set-Alias -Name Get-AKVGapAnalysis -Value Invoke-GapAnalysis -Force
    }
} catch {
    $null
}

# Decide whether to auto-run: only invoke when the script is executed directly (not dot-sourced).
# When dot-sourcing we want to make the function(s) available and not start a potentially long run.
try {
    $invocationName = $MyInvocation.InvocationName
} catch {
    $invocationName = $null
}

if ($env:AKV_RUN_HTML_ONLY -eq '1') {
        try {
            $dataPath = $env:AKV_HTML_DATA_PATH
            $platformPath = $env:AKV_HTML_PLATFORM_PATH
            $outPath = $env:AKV_HTML_OUTPUT_PATH

            if ($dataPath -and (Test-Path $dataPath)) {
                $analysis = Get-Content -Path $dataPath -Raw | ConvertFrom-Json
            } else {
                $analysis = @()
            }

            if ($platformPath -and (Test-Path $platformPath)) {
                $platform = Get-Content -Path $platformPath -Raw | ConvertFrom-Json
            } else {
                $platform = @()
            }

            Write-Log "[HTML-ONLY] Invoking New-GapAnalysisHtmlReport (child runner) -> OutputPath: $outPath" -Level "INFO"
            New-GapAnalysisHtmlReport -AnalysisResults $analysis -PlatformAssessments $platform -OutputPath $outPath
        } catch {
            Write-Log "HTML-only runner failed: $($_.Exception.Message)" -Level "ERROR"
            exit 2
        }
        exit 0
    }
    else {
        # Normal full run when executed as a script
        # If the script was invoked with parameters (script-level $PSBoundParameters),
        if ($Force) {
            $global:AkvGapAnalysis_InProcessRun = $false
            Write-Log "Forced reset of in-process run flag due to -Force parameter" -Level 'WARN'
        }

        # splat them into the function so invoking the script file with args works
        # the same as dot-sourcing and calling the function interactively.
        try {
            # Debug: show script-level bound parameters before splatting into the function
            try {
                $pairs = @()
                foreach ($kv in $PSBoundParameters.GetEnumerator()) { $pairs += ("$($kv.Key)=$($kv.Value)") }
                Write-Log ("[DEBUG] Script-level PSBoundParameters: {0}" -f ($pairs -join ', ')) -Level 'INFO'
            } catch { $null }

            if ($PSBoundParameters -and $PSBoundParameters.Count -gt 0) {
                Write-Log "Auto-running Invoke-GapAnalysis with script-level parameters (count: $($PSBoundParameters.Count))" -Level 'INFO'
                if ($global:AkvGapAnalysis_InProcessRun) {
                    Write-Log "Skipping auto-run because Invoke-GapAnalysis is already running in this process" -Level 'WARN'
                } else {
                    Invoke-GapAnalysis @PSBoundParameters
                }
            } else {
                Write-Log "Auto-running Invoke-GapAnalysis with no script-level parameters" -Level 'INFO'
                if ($global:AkvGapAnalysis_InProcessRun) {
                    Write-Log "Skipping auto-run because Invoke-GapAnalysis is already running in this process" -Level 'WARN'
                } else {
                    Invoke-GapAnalysis
                }
            }
        } catch {
            # fallback to a plain call if splatting fails for any reason
            Invoke-GapAnalysis
        }
    }