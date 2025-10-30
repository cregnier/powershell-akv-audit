<#
.SYNOPSIS
    Azure Key Vault Gap Analysis Script - Lightweight Security & Compliance Assessment
.DESCRIPTION
    Performs comprehensive gap analysis of Azure Key Vault security posture across subscriptions.
    Focuses on identifying security gaps, compliance issues, and providing actionable recommendations
    for improving Key Vault security and operational excellence.

    KEY FEATURES:
    - Subscription and Key Vault inventory with diagnostics tracking
    - Security gap identification and red flag detection
    - Quick wins and prescriptive security recommendations
    - Azure platform integration assessment (RBAC, Policy, Event Hubs, Log Analytics)
    - Key Vault configuration and metadata analysis
    - HTML report generation with actionable insights

.PARAMETER TestMode
    Run in test mode with limited vault processing for validation

.PARAMETER Limit
    Maximum number of vaults to analyze in test mode

.PARAMETER SubscriptionId
    Specific subscription ID to analyze (optional)

.PARAMETER SuppressAzureWarnings
    Suppress Azure PowerShell breaking change warnings for cleaner output

.PARAMETER SingleVault
    Analyze only a single Key Vault for focused testing

.PARAMETER VaultName
    Name of the specific Key Vault to analyze (required when using -SingleVault)

.PARAMETER UseParallelProcessing
    Enable parallel processing of Key Vault analysis for faster execution (Windows only)

.PARAMETER AutoInstallModules
    Automatically install missing optional Azure PowerShell modules

.EXAMPLE
    .\Get-AKVGapAnalysis.ps1
    Run full gap analysis across all accessible subscriptions

.EXAMPLE
    .\Get-AKVGapAnalysis.ps1 -TestMode -Limit 5
    Run gap analysis on first 5 vaults for testing

.EXAMPLE
    .\Get-AKVGapAnalysis.ps1 -SingleVault -VaultName "my-key-vault"
    Analyze a single Key Vault while still assessing Azure platform integration

.EXAMPLE
    .\Get-AKVGapAnalysis.ps1 -SingleVault -VaultName "my-key-vault" -SubscriptionName "MySubscription" -SuppressAzureWarnings
    Analyze a single Key Vault in a specific subscription with warnings suppressed

.EXAMPLE
    .\Get-AKVGapAnalysis.ps1 -TestMode -Limit 10 -UseParallelProcessing -MaxParallelJobs 3 -SuppressModuleWarnings
    Run gap analysis on first 10 vaults using parallel processing with 3 concurrent jobs, suppressing module warnings

.EXAMPLE
    .\Get-AKVGapAnalysis.ps1 -AutoInstallModules -SuppressAzureWarnings
    Run full gap analysis with automatic installation of missing optional modules
    Requires Azure PowerShell modules: Az.Accounts, Az.KeyVault, Az.Resources, Az.Monitor, Az.Policy
    Minimum permissions: Reader at subscription level, Key Vault Reader, Monitoring Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$TestMode,

    [Parameter(Mandatory = $false)]
    [int]$Limit = 10,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [switch]$SuppressAzureWarnings,

    [Parameter(Mandatory = $false)]
    [switch]$SingleVault,

    [Parameter(Mandatory = $false)]
    [string]$VaultName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionName,

    [Parameter(Mandatory = $false)]
    [switch]$UseParallelProcessing,

    [Parameter(Mandatory = $false)]
    [int]$MaxParallelJobs = 4,

    [Parameter(Mandatory = $false)]
    [switch]$SuppressModuleWarnings,

    [Parameter(Mandatory = $false)]
    [switch]$AutoInstallModules

    ,
    [Parameter(Mandatory = $false)]
    [switch]$DeepCrossReference  # Optional extra: scan runbook contents and function app settings for Key Vault URIs
)

# Script configuration
$ScriptVersion = "1.0"
$StartTime = Get-Date

# Suppress Azure warnings if requested
if ($SuppressAzureWarnings) {
    $WarningPreference = 'SilentlyContinue'
    # Try to suppress Azure warnings using environment variable
    $env:AZURE_CORE_SUPPRESS_WARNINGS = "true"
    Write-Host "Azure PowerShell warnings suppressed" -ForegroundColor Gray
}

# Initialize output paths
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$defaultOutputDir = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "KeyVaultGapAnalysis"
if ($OutputDirectory) {
    $outputDir = $OutputDirectory
} else {
    $outputDir = $defaultOutputDir
}

# Create output directory
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Output file paths
$csvPath = Join-Path $outputDir "KeyVaultGapAnalysis_$timestamp.csv"
$htmlPath = Join-Path $outputDir "KeyVaultGapAnalysis_$timestamp.html"
$logPath = Join-Path $outputDir "KeyVaultGapAnalysis_$timestamp.log"

# Enhanced logging function with colors
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    switch ($Level.ToUpper()) {
        "ERROR" {
            Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red
        }
        "WARNING" {
            Write-Host "[$timestamp] [WARNING] $Message" -ForegroundColor Yellow
        }
        "SUCCESS" {
            Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green
        }
        "INFO" {
            Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan
        }
        default {
            Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor White
        }
    }

    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logPath -Value $logMessage
}

# Permission issues logging helper
function Write-PermissionsIssue {
    param(
        [string]$Component,
        [string]$SubscriptionId,
        [string]$Message
    )

    if (-not $global:PermissionsIssues) { $global:PermissionsIssues = @() }
    $issue = @{ Timestamp = (Get-Date); Component = $Component; Subscription = $SubscriptionId; Message = $Message }
    $global:PermissionsIssues += $issue
    # Also write to main log for visibility
    Write-Log ("Permission issue detected for {0} in subscription {1}: {2}" -f $Component, $SubscriptionId, $Message) -Level "WARNING"
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

# Authentication function
function Initialize-AzureAuthentication {
    Write-Log "Initializing Azure authentication..." -Level "INFO"

    try {
        # Check if already authenticated
        $context = Get-AzContext
        if ($context) {
            Write-Log "Already authenticated as: $($context.Account.Id)" -Level "INFO"
            return $true
        }

        # Attempt interactive authentication
        Write-Log "Attempting interactive authentication..." -Level "INFO"
        Connect-AzAccount -ErrorAction Stop

        $context = Get-AzContext
        Write-Log "Successfully authenticated as: $($context.Account.Id)" -Level "SUCCESS"
        return $true

    } catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Subscription discovery
function Get-SubscriptionsToAnalyze {
    Write-Log "Discovering accessible subscriptions..." -Level "INFO"

    try {
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
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

        $keyVaults = Get-AzKeyVault

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
            $diagnostics = Get-AzDiagnosticSetting -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } else {
            $diagnostics = Get-AzDiagnosticSetting -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName" -ErrorAction SilentlyContinue
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
            NetworkAclsConfigured = ($networkAcls -ne $null)
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

    $thirtyDaysAgo = (Get-Date).AddDays(-30)
    $ninetyDaysAgo = (Get-Date).AddDays(-90)

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
            # Log permission/module issue
            Write-PermissionsIssue -Component 'Runbooks' -SubscriptionId $SubscriptionId -Message $_.Exception.Message
            $assessment.Runbooks = @{
                AutomationAccountsCount = 0
                KeyVaultRunbooksCount = 0
                Runbooks = @()
                Error = $_.Exception.Message
            }
        }

            # Discover Function Apps that may interact with Key Vault (try command, fallback to resource scan)
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
                Write-PermissionsIssue -Component 'FunctionApps' -SubscriptionId $SubscriptionId -Message $_.Exception.Message
                $assessment.FunctionApps = @{ Count = 0; Functions = @(); Error = $_.Exception.Message }
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
                        Write-PermissionsIssue -Component 'RunbookContent' -SubscriptionId $subId -Message $_.Exception.Message
                    }
                }
            }

            # Inspect Function App settings
            if ($platform.FunctionApps -and $platform.FunctionApps.Functions) {
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
                        Write-PermissionsIssue -Component 'FunctionAppSettings' -SubscriptionId $subId -Message $_.Exception.Message
                    }
                }
            }
        } catch {
            Write-PermissionsIssue -Component 'DeepCrossReference' -SubscriptionId $subId -Message $_.Exception.Message
        }
    }
}

# Main vault analysis function
function Analyze-KeyVault {
    param($Vault, [string]$SubscriptionId, [string]$SubscriptionName)

    Write-Log "Analyzing Key Vault: $($Vault.VaultName)" -Level "INFO"

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

        $subscriptionDisplay = if ($platform.SubscriptionName) { "$($platform.SubscriptionName)<br><small>$($platform.SubscriptionId)</small>" } else { $platform.SubscriptionId }

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
        $vaultAnchorId = "vault-$($vault.SubscriptionId)-$($vault.VaultName)" -replace '[^a-zA-Z0-9_-]', '-'

        $html += "`n            <tr id='$vaultAnchorId'><td colspan='12' style='background:#f7f7f9;padding:8px;font-weight:bold;'>Details for $($vault.VaultName) (<small>$($vault.SubscriptionName) - $($vault.SubscriptionId)</small>)</td></tr>`n"
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
        $instanceCount = if ($gap.PSObject.Members.Name -contains 'InstanceCount') { $gap.InstanceCount } else { $gap.Count }
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

    # Generate policy details page
    $policyDetailsPath = New-PolicyDetailsHtmlPage -PlatformAssessments $PlatformAssessments -OutputPath $OutputPath
    $policyDetailsFileName = [System.IO.Path]::GetFileName($policyDetailsPath)

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

    $totalQuickWins = ($AnalysisResults | ForEach-Object { $_.QuickWins.Count } | Measure-Object -Sum).Sum
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
        <p>Analysis Period: $(($StartTime - (Get-Date)).Days) days | Total Execution Time: $(([math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1))) minutes</p>
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
                <div class="stat-number">$(Format-StatValue -Value $totalQuickWins -Explanation "No quick wins identified or analysis incomplete")</div>
                <div class="stat-label">Total Quick Wins Available</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value $criticalGaps -Explanation "No critical gaps found or analysis incomplete")</div>
                <div class="stat-label">Critical Security Gaps</div>
            </div>
        </div>
    </div>

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

    <div class="gaps-section">
        <h2>🚨 Security Gaps Identified</h2>
        <p>
            Critical: $criticalGaps vault(s) (<span id="criticalInstances">$((($allGaps | Where-Object { $_.Severity -eq 'Critical' }).Count))</span> instances) |
            High: $highGaps vault(s) (<span id="highInstances">$((($allGaps | Where-Object { $_.Severity -eq 'High' }).Count))</span> instances) |
            Medium: $mediumGaps vault(s) (<span id="mediumInstances">$((($allGaps | Where-Object { $_.Severity -eq 'Medium' }).Count))</span> instances)
        </p>
"@

    # Add gap details - prioritize by severity (Critical > High > Medium)
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

    # Sort by severity priority (Critical first, then High, then Medium)
    $severityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4 }
    $allGaps = $allGaps | Sort-Object { $severityOrder[$_.Severity] }, Category, VaultName

    foreach ($gap in $allGaps) {
        $cssClass = switch ($gap.Severity) {
            "Critical" { "gap-critical" }
            "High" { "gap-high" }
            "Medium" { "gap-medium" }
            default { "gap-medium" }
        }

        $html += @"
        <div class="gap-item $cssClass">
            <strong>$($gap.VaultName)</strong> ($($gap.SubscriptionName))<br>
            <strong>$($gap.Category) - $($gap.Severity)</strong>: $($gap.Issue)<br>
            <em>Impact:</em> $($gap.Impact)<br>
            <em>Best Practice:</em> $($gap.BestPractice)<br>
            <em>Recommendation:</em> $($gap.Recommendation)<br>
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Remediation Steps</summary>
                <ol style="margin-top: 5px;">
"@

        if ($gap.RemediationSteps) {
            foreach ($step in $gap.RemediationSteps) {
                $html += "<li>$step</li>"
            }
        }

        $html += @"
                </ol>
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="$($gap.Documentation)" target="_blank">$($gap.Documentation)</a></p>
            </details>
        </div>
"@
    }

    $html += @"
    </div>

    <div class="wins-section">
        <h2>🎯 Quick Wins & Opportunities</h2>
"@

    # Add quick wins - remove duplicates and prioritize by impact
    $allWins = @()
    foreach ($vault in $AnalysisResults) {
        foreach ($win in $vault.QuickWins) {
            $winWithContext = $win.PSObject.Copy()
            $winWithContext | Add-Member -MemberType NoteProperty -Name "VaultName" -Value $vault.VaultName -Force
            $winWithContext | Add-Member -MemberType NoteProperty -Name "SubscriptionName" -Value $vault.SubscriptionName -Force
            $allWins += $winWithContext
        }
    }

    # Remove duplicates and prioritize by impact (High > Medium > Low)
    $impactOrder = @{ "High" = 1; "Medium" = 2; "Low" = 3 }
    $uniqueWins = @()
    $seenWinTitles = @{}
    $allWins = $allWins | Sort-Object { $impactOrder[$_.Impact] }, Title

    foreach ($win in $allWins) {
        if (-not $seenWinTitles.ContainsKey($win.Title)) {
            $uniqueWins += $win
            $seenWinTitles[$win.Title] = $true
        }
    }

    foreach ($win in $uniqueWins) {
        $html += @"
        <div class="win-item">
            <strong>$($win.Category) - $($win.Title)</strong><br>
            <em>Description:</em> $($win.Description)<br>
            <em>Effort:</em> $($win.Effort) | <em>Impact:</em> $($win.Impact)
"@

        if ($win.RemediationSteps) {
            $html += @"
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Implementation Steps</summary>
                <ol style="margin-top: 5px;">
"@

            foreach ($step in $win.RemediationSteps) {
                $html += "<li>$step</li>"
            }

            $html += @"
                </ol>
"@

            if ($win.Documentation) {
                $html += "<p style=`"margin-top: 10px;`"><strong>📚 Documentation:</strong> <a href=`"$($win.Documentation)`" target=`"_blank`">$($win.Documentation)</a></p>"
            }

            $html += @"
            </details>
"@
        }

        $html += @"
        </div>
"@
    }

    # Add general recommendations
    $html += @"
        <h3>💡 Additional Recommendations</h3>
        <div class="win-item">
            <strong>Security - Implement Azure Policy for Key Vault Governance</strong><br>
            <em>Description:</em> Deploy Azure Policies to enforce Key Vault security standards across all subscriptions<br>
            <em>Effort:</em> Medium | <em>Impact:</em> High
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Implementation Steps</summary>
                <ol style="margin-top: 5px;">
                    <li>Go to Azure Policy → Definitions → Search for 'Key Vault'</li>
                    <li>Assign built-in policies like 'Key vaults should have soft delete enabled'</li>
                    <li>Create custom policies for organization-specific requirements</li>
                    <li>Set policy scope to management group or subscription level</li>
                    <li>Monitor compliance through Azure Policy compliance dashboard</li>
                </ol>
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="https://docs.microsoft.com/en-us/azure/key-vault/general/azure-policy" target="_blank">Azure Policy for Key Vault</a></p>
            </details>
        </div>
        <div class="win-item">
            <strong>Monitoring - Centralize Logs with Log Analytics</strong><br>
            <em>Description:</em> Configure all Key Vaults to send diagnostic logs to a central Log Analytics workspace<br>
            <em>Effort:</em> Medium | <em>Impact:</em> High
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Implementation Steps</summary>
                <ol style="margin-top: 5px;">
                    <li>Create or identify central Log Analytics workspace</li>
                    <li>For each Key Vault: Diagnostic settings → Add diagnostic setting</li>
                    <li>Select logs: AuditEvent, AzurePolicyEvaluationDetails</li>
                    <li>Select destination: Log Analytics workspace</li>
                    <li>Create workbooks and alerts for Key Vault monitoring</li>
                </ol>
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="https://docs.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault" target="_blank">Monitor Key Vault</a></p>
            </details>
        </div>
        <div class="win-item">
            <strong>Automation - Create Runbooks for Key Management</strong><br>
            <em>Description:</em> Develop Azure Automation runbooks for automated certificate renewal and key rotation<br>
            <em>Effort:</em> High | <em>Impact:</em> High
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Implementation Steps</summary>
                <ol style="margin-top: 5px;">
                    <li>Create Azure Automation account</li>
                    <li>Import required PowerShell modules (Az.KeyVault, Az.Automation)</li>
                    <li>Develop runbooks for certificate renewal and key rotation</li>
                    <li>Set up schedules for automated execution</li>
                    <li>Configure notifications for rotation failures</li>
                    <li>Test runbooks with non-production certificates first</li>
                </ol>
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="https://docs.microsoft.com/en-us/azure/automation/automation-runbook-types" target="_blank">Azure Automation Runbooks</a></p>
            </details>
        </div>
        <div class="win-item">
            <strong>Identity - Use Managed Identities</strong><br>
            <em>Description:</em> Replace service principals with managed identities for Azure VMs, App Services, Functions, AKS, and other Azure resources that support managed identities<br>
            <em>Effort:</em> Medium | <em>Impact:</em> Medium
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Implementation Steps</summary>
                <ol style="margin-top: 5px;">
                    <li>Identify Azure resources (VMs, App Services, Functions, AKS) using service principals for Key Vault access</li>
                    <li>Enable system-assigned managed identity on supported Azure resources</li>
                    <li>Grant appropriate Key Vault RBAC roles to managed identities</li>
                    <li>Update application code to use Azure.Identity or DefaultAzureCredential</li>
                    <li>Remove service principal client secrets from configuration and Key Vault</li>
                    <li>Test authentication with managed identities in non-production first</li>
                </ol>

                <h4 style="margin-top: 15px; color: #007bff;">💡 Real-World AKV Examples</h4>

                <details style="margin-top: 10px;">
                    <summary style="cursor: pointer; font-weight: bold; color: #007bff;">🔍 Click to expand real-world examples from your Key Vault inventory</summary>

                <div style="margin: 15px 0; padding: 10px; background: #e8f5e8; border-left: 4px solid #28a745; border-radius: 4px;">
                    <strong>📊 Analysis Results:</strong> Found $($AnalysisResults.Count) Key Vaults across $($vaultsBySubscription.Count) subscriptions
                </div>
"@

    # Generate real examples from actual vault data
    $exampleCount = 0

    # Helper: list of tag keys to check for IAPM/Intel/Project identifiers
    $iapmCandidates = @('IAPM#','IAPM','ProjectID','IntelApplicationNumber','IntelApp','ApplicationNumber')

    # Pre-compute grouping by subscription so later sections (examples, summary) can use it
    $vaultsBySubscription = $AnalysisResults | Group-Object -Property SubscriptionName

    # Find vaults using access policies (potential candidates for managed identity conversion)
    $accessPolicyVaults = $AnalysisResults | Where-Object { $_.AccessControl.AccessPoliciesCount -gt 0 -and -not $_.AccessControl.RbacEnabled }

    if ($accessPolicyVaults.Count -gt 0) {
        $html += @"
                <div style="background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #ffc107;">
                    <strong>⚠️ Priority Candidates for Managed Identity Migration:</strong> Found $($accessPolicyVaults.Count) vaults using legacy access policies
                </div>
"@

        foreach ($vault in $accessPolicyVaults | Select-Object -First 3) {
            $exampleCount++
            $subscriptionId = $vault.SubscriptionId
            $resourceGroup = $vault.ResourceGroupName
            $vaultName = $vault.VaultName

            $html += @"
                <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <strong>Example $($exampleCount): $($vaultName)</strong><br>
                    <code style="background: #e9ecef; padding: 2px 4px; border-radius: 3px;">$vaultName</code> → Currently using $($vault.AccessControl.AccessPoliciesCount) access policies<br>
                    <strong>Subscription:</strong> $($vault.SubscriptionName)<br>
                    <strong>Assets:</strong> $($vault.SecretInventory.TotalAssets) total (Secrets: $($vault.SecretInventory.SecretsCount), Certificates: $($vault.SecretInventory.CertificatesCount), Keys: $($vault.SecretInventory.KeysCount))<br>
                    <strong>Tags:</strong> IAPM/Project: $((Get-TagValueInsensitive -Tags $vault.Vault.Tags -Candidates $iapmCandidates) -or 'Unknown')<br>
                    <strong>Associated Automation/Functions:</strong> See platform assessment section for related runbooks and functions
                    <strong>Migration Commands:</strong>
                    <ul style="margin: 5px 0;">
                        <li><code>az keyvault update --name $vaultName --resource-group $resourceGroup --enable-rbac-authorization true</code></li>
                        <li><code># For Azure resources, assign managed identities instead of access policies</code></li>
                        <li><code># Example: az webapp identity assign --name myApp --resource-group $resourceGroup</code></li>
                        <li><code>az role assignment create --assignee-object-id &lt;managed-identity-id&gt; --role "Key Vault Secrets User" --scope /subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.KeyVault/vaults/$vaultName</code></li>
                    </ul>
                </div>
"@
        }
    }

    # Show RBAC-enabled vaults as good examples
    $rbacVaults = $AnalysisResults | Where-Object { $_.AccessControl.RbacEnabled }

    if ($rbacVaults.Count -gt 0) {
        $html += @"
                <div style="background: #d1ecf1; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #17a2b8;">
                    <strong>✅ Well-Configured Vaults:</strong> Found $($rbacVaults.Count) vaults already using RBAC (good practice)
                </div>
"@

        foreach ($vault in $rbacVaults | Select-Object -First 2) {
            $exampleCount++
            $html += @"
                <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <strong>Good Example $($exampleCount - $accessPolicyVaults.Count): $($vault.VaultName)</strong><br>
                    <code style="background: #e9ecef; padding: 2px 4px; border-radius: 3px;">$($vault.VaultName)</code> → Already using RBAC with $($vault.AccessControl.RoleAssignmentsCount) role assignments<br>
                    <strong>Compliance Scores:</strong> CIS: <span class="score-value">$($vault.CISComplianceScore)%</span>, NIST: <span class="score-value">$($vault.NISTComplianceScore)%</span>, ISO: <span class="score-value">$($vault.ISOComplianceScore)%</span>, MS: <span class="score-value">$($vault.MSComplianceScore)%</span><br>
                    <strong>Additional Notes:</strong> Tags: IAPM/Project: $((Get-TagValueInsensitive -Tags $vault.Vault.Tags -Candidates $iapmCandidates) -or 'Unknown')
                </div>
"@
        }
    }

    # Additional example categories: missing diagnostics, missing soft-delete, private endpoint status, rotation-needed
    $noDiagnostics = $AnalysisResults | Where-Object { -not $_.Diagnostics.HasDiagnostics }
    if ($noDiagnostics.Count -gt 0) {
        $html += @"
                <div style="background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #ffc107;">
                    <strong>⚠️ Vaults missing diagnostic settings:</strong> Found $($noDiagnostics.Count) vault(s) without diagnostics
                </div>
"@
    }

    $noSoftDelete = $AnalysisResults | Where-Object { -not $_.Vault.EnableSoftDelete }
    if ($noSoftDelete.Count -gt 0) {
        $html += @"
                <div style="background: #f8d7da; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #dc3545;">
                    <strong>🚨 Vaults missing soft delete (Critical):</strong> Found $($noSoftDelete.Count) vault(s) without soft delete enabled
                </div>
"@
    }

    $needsRotation = $AnalysisResults | Where-Object { $_.RotationAnalysis.ManualRotationNeeded -gt 0 }
    if ($needsRotation.Count -gt 0) {
        $html += @"
                <div style="background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #ffc107;">
                    <strong>🔄 Vaults needing rotation:</strong> Found $($needsRotation.Count) vault(s) with rotation-needed assets
                </div>
"@
    }

    if ($exampleCount -eq 0) {
        $html += @"
                <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <strong>No specific examples available</strong><br>
                    All vaults in the analysis are properly configured or no access control data was available.
                </div>
"@
    }

    $html += @"
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview" target="_blank">Managed Identities</a></p>
                <p style="margin-top: 5px; color: #6c757d;"><em>Applicable to: Azure VMs, App Services, Functions, AKS, Container Instances, and other Azure services with managed identity support</em></p>
                </details>
            </details>
        </div>
"@

    $html += @"
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
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Recent Rotations</th>
                    <th style="border: 1px solid #dee2e6; padding: 8px; text-align: center;">Needs Rotation</th>
                </tr>
"@

    # Group vaults by subscription for summary cards but use single table
    $vaultsBySubscription = $AnalysisResults | Group-Object -Property SubscriptionName

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

            $vaultAnchor = "vault-$($vault.SubscriptionId)-$($vault.VaultName)" -replace '[^a-zA-Z0-9_-]', '-'

            $html += @"
                <tr>
                        <td style="border: 1px solid #dee2e6; padding: 8px; font-weight: bold;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$subscriptionName</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; font-weight: bold;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($vault.VaultName)</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($iapmCode -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($envCode -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($secrets -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($certs -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($keys -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; font-weight: bold;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($total -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #28a745;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($recentRotations -replace '^([0-9]+)$', '$1*')</a></td>
                        <td style="border: 1px solid #dee2e6; padding: 8px; text-align: center; color: #dc3545;"><a href="#" onclick="showDetailsModal('$vaultAnchor','vault')">$($needsRotation -replace '^([0-9]+)$', '$1*')</a></td>
                    </tr>
"@
        }
    }

    $html += @"
            </table>

            <div style="margin-top: 15px; padding: 10px; background: #e9ecef; border-radius: 5px; border-left: 4px solid #6c757d;">
                <h5>🔢 Status Code Legend</h5>
                <p>Some table cells use compact footnote-style markers (e.g., <strong>2*</strong>) to indicate data issues; hover/click cells to view details.</p>
                <ul style="margin: 5px 0; padding-left: 20px;">
                    <li><strong>1* = Access Issue:</strong> Unable to retrieve data due to insufficient permissions or authentication problems</li>
                    <li><strong>2* = Empty Vault:</strong> Vault contains no secrets, certificates, or keys</li>
                    <li><strong>3* = Data Not Available:</strong> Information could not be retrieved or is not applicable</li>
                </ul>
                <p style="margin: 0; font-size: 0.9em; color: #6c757d;">Example row: <em>1ci-preprod-metrics &nbsp; kv-adx-access &nbsp; 2* &nbsp; Unknown &nbsp; 2* &nbsp; 2* &nbsp; 2* &nbsp; 2* &nbsp; 3* &nbsp; 3*</em></p>
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
        $subscriptionDisplay = if ($platform.SubscriptionName) { "$($platform.SubscriptionName)<br><small>$($platform.SubscriptionId)</small>" } else { $platform.SubscriptionId }
        $platformAnchor = "platform-$($platform.SubscriptionId)" -replace '[^a-zA-Z0-9_-]', '-'
        $html += "`n            <tr id='$platformAnchor'><td colspan='9' style='background:#f7f7f9;padding:6px;font-weight:bold;'>Platform assessment for $subscriptionDisplay</td></tr>`n"
        $html += @"
            <tr>
                <td>$subscriptionDisplay</td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.Policies.KeyVaultPoliciesCount)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.EventHubs.NamespacesCount)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.LogAnalytics.WorkspacesCount)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.RbacRoles.KeyVaultRolesCount)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.ManagedIdentities.Count)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.ServicePrincipals.Count)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.ServiceIdentities.Count)</a></td>
                <td><a href="#" onclick="showDetailsModal('$platformAnchor','platform')" style="text-decoration:none;">$($platform.Runbooks.KeyVaultRunbooksCount)</a></td>
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
            <tr><th>Vault Name</th><th>Subscription</th><th>Location</th><th><a class="framework-link" href="https://www.cisecurity.org/benchmark/azure/" target="_blank" title="CIS Azure Foundations Benchmark">CIS Score</a></th><th><a class="framework-link" href="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/r5/" target="_blank" title="NIST Cybersecurity Framework">NIST Score</a></th><th><a class="framework-link" href="https://www.iso.org/standard/54534.html" target="_blank" title="ISO 27001 Information Security">ISO Score</a></th><th><a class="framework-link" href="https://learn.microsoft.com/en-us/azure/key-vault/general/security-baseline" target="_blank" title="Microsoft Security Baseline">MS Baseline</a></th><th>Risk Level</th><th>Diagnostics</th><th>RBAC</th><th>Private Endpoints</th><th>Security Gaps</th></tr>
"@

    foreach ($vault in $AnalysisResults) {
        $riskClass = switch ($vault.RiskLevel) {
            "Low" { "risk-low" }
            "Medium" { "risk-medium" }
            "High" { "risk-high" }
            "Critical" { "risk-critical" }
        }

        $html += @"
            <tr>
                <td><a id="$vaultAnchorId"></a>$($vault.VaultName)</td>
                <td>$($vault.SubscriptionName)<br><small>$($vault.SubscriptionId)</small></td>
                <td>$($vault.Location)</td>
                <td><span class="score-value">$($vault.CISComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.NISTComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.ISOComplianceScore)%</span></td>
                <td><span class="score-value">$($vault.MSComplianceScore)%</span></td>
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
        $platformAnchor = "platform-$($platform.SubscriptionId)" -replace '[^a-zA-Z0-9_-]', '-'
        $safeJson = ($platform | ConvertTo-Json -Depth 6) -replace '</', '<\/'
        $html += "<script type='application/json' id='$platformAnchor'>`n$safeJson`n</script>`n"
    }

    # Add vault JSON blobs
    foreach ($vault in $AnalysisResults) {
        $vaultAnchorId = "vault-$($vault.SubscriptionId)-$($vault.VaultName)" -replace '[^a-zA-Z0-9_-]', '-'
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
            Tags = $vault.Vault.Tags
            SecurityGaps = $vault.SecurityGaps
            QuickWins = $vault.QuickWins
        }
        $safeVaultJson = ($vaultPayload | ConvertTo-Json -Depth 6) -replace '</', '<\/'
        $html += "<script type='application/json' id='$vaultAnchorId'>`n$safeVaultJson`n</script>`n"
    }

    # Embed permissions issues so the UI can surface them (if any)
    if (-not $global:PermissionsIssues) { $global:PermissionsIssues = @() }
    $safePermsJson = ($global:PermissionsIssues | ConvertTo-Json -Depth 6) -replace '</', '<\/'
    $html += "<script type='application/json' id='permissions-issues'>`n$safePermsJson`n</script>`n"

    $html += @"

    <!-- Modal markup (hidden by default) -->
    <div id="detailsModal" style="display:none; position: fixed; top: 0; left: 0; width:100%; height:100%; background: rgba(0,0,0,0.5); z-index: 9999;">
        <div style="background: white; max-width: 900px; margin: 40px auto; padding: 20px; border-radius: 6px; position: relative;">
            <button onclick="closeDetailsModal()" style="position:absolute; right:12px; top:12px; background:#dc3545; color:white; border:none; padding:6px 10px; border-radius:4px; cursor:pointer;">Close</button>
            <div id="detailsModalContent"></div>
        </div>
    </div>

    <script>
        function showDetailsModal(id, type) {
            var blob = document.getElementById(id);
            if (!blob) {
                alert('Details not available for ' + id);
                return;
            }
            var data = JSON.parse(blob.textContent || blob.innerText);

            // Load permission issues blob (if present) and filter by subscription
            var perms = [];
            var permsBlob = document.getElementById('permissions-issues');
            if (permsBlob) {
                try { perms = JSON.parse(permsBlob.textContent || permsBlob.innerText) || []; } catch(e) { perms = []; }
            }

            var html = '';
            if (type === 'platform') {
                html += '<h3>Platform assessment for ' + (data.SubscriptionName || data.SubscriptionId) + '</h3>';
                html += '<p><strong>Key Vault Policies:</strong> ' + (data.Policies ? data.Policies.KeyVaultPoliciesCount : 'N/A') + '</p>';
                html += '<p><strong>Event Hubs:</strong> ' + (data.EventHubs ? data.EventHubs.NamespacesCount : 'N/A') + '</p>';
                html += '<p><strong>Log Analytics:</strong> ' + (data.LogAnalytics ? data.LogAnalytics.WorkspacesCount : 'N/A') + '</p>';
                html += '<p><strong>Runbooks (KeyVault):</strong> ' + (data.Runbooks ? data.Runbooks.KeyVaultRunbooksCount : 'N/A') + '</p>';

                // List runbook names (if available)
                if (data.Runbooks && data.Runbooks.Runbooks && data.Runbooks.Runbooks.length > 0) {
                    html += '<h4>🔁 Runbooks referencing Key Vault</h4><ul>';
                    data.Runbooks.Runbooks.slice(0,50).forEach(function(rb){ html += '<li>' + (rb.Name || rb.RunbookName || '(unnamed)') + (rb.AutomationAccountName ? ' (Account: '+rb.AutomationAccountName+')' : '') + '</li>'; });
                    html += '</ul>';
                }

                // Show discovered cross-references (platform.CrossReferences)
                if (data.CrossReferences && data.CrossReferences.length > 0) {
                    html += '<h4>🔗 Cross-References Found</h4><ul>';
                    data.CrossReferences.forEach(function(x){ html += '<li>['+x.Type+'] ' + (x.Name || '') + ' - Match: ' + (x.Match || '') + '</li>'; });
                    html += '</ul>';
                }

                // Permission issues for this subscription
                var subId = data.SubscriptionId || (data.SubscriptionName ? data.SubscriptionName : '');
                var relatedPerms = perms.filter(function(p){ return (p.Subscription == subId) || (p.Subscription == (data.SubscriptionId || '')); });
                if (relatedPerms && relatedPerms.length > 0) {
                    html += '<h4 style="color:#dc3545;">⚠️ Permission Issues Detected</h4>';
                    html += '<table style="width:100%;border-collapse:collapse;background:#fff;">';
                    html += '<tr style="background:#f8f9fa;"><th style="padding:6px;border:1px solid #eee;">Time</th><th style="padding:6px;border:1px solid #eee;">Component</th><th style="padding:6px;border:1px solid #eee;">Message</th></tr>';
                    relatedPerms.forEach(function(p){ html += '<tr><td style="padding:6px;border:1px solid #eee;">'+(new Date(p.Timestamp)).toLocaleString()+'</td><td style="padding:6px;border:1px solid #eee;">'+p.Component+'</td><td style="padding:6px;border:1px solid #eee;">'+p.Message+'</td></tr>'; });
                    html += '</table>';
                }

                // Raw JSON collapsed for advanced users
                html += '<details style="margin-top:10px;"><summary style="cursor:pointer;">Raw platform JSON</summary><pre style="white-space:pre-wrap;background:#f8f9fa;padding:10px;border-radius:4px;">' + JSON.stringify(data,null,2) + '</pre></details>';

            } else {
                html += '<div style="display:flex;justify-content:space-between;align-items:center;">';
                html += '<h3 style="margin:0">Vault: ' + (data.VaultName || id) + '</h3>';
                html += '<div><button onclick="copyVaultJson()" style="background:#2b9af3;color:white;border:none;padding:6px 10px;border-radius:4px;cursor:pointer;margin-left:8px;">Copy JSON</button></div>';
                html += '</div>';

                    html += '<table style="width:100%;border-collapse:collapse;margin-top:8px;">';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Subscription</strong></td><td style="padding:6px;border:1px solid #eee;">' + (data.SubscriptionName || data.SubscriptionId) + '</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Location</strong></td><td style="padding:6px;border:1px solid #eee;">' + (data.Location || 'N/A') + '</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Secrets / Certs / Keys</strong></td><td style="padding:6px;border:1px solid #eee;">' + (data.SecretsCount||0) + ' / ' + (data.CertificatesCount||0) + ' / ' + (data.KeysCount||0) + ' (Total: ' + (data.TotalAssets||0) + ')</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Diagnostics</strong></td><td style="padding:6px;border:1px solid #eee;">' + ((data.Diagnostics && data.Diagnostics.HasDiagnostics) ? '✅' : '❌') + '</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>RBAC</strong></td><td style="padding:6px;border:1px solid #eee;">' + ((data.AccessControl && data.AccessControl.RbacEnabled) ? '✅' : '❌') + '</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Private endpoints</strong></td><td style="padding:6px;border:1px solid #eee;">' + ((data.NetworkSecurity && data.NetworkSecurity.HasPrivateEndpoints) ? '✅' : '❌') + '</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Rotation needs</strong></td><td style="padding:6px;border:1px solid #eee;">' + ((data.Rotation && data.Rotation.ManualRotationNeeded) ? data.Rotation.ManualRotationNeeded : 0) + '</td></tr>';
                    html += '<tr><td style="padding:6px;border:1px solid #eee;"><strong>Compliance (CIS/NIST)</strong></td><td style="padding:6px;border:1px solid #eee;">CIS ' + (data.Compliance ? data.Compliance.CIS : 'N/A') + '%, NIST ' + (data.Compliance ? data.Compliance.NIST : 'N/A') + '%</td></tr>';
                    html += '</table>';

                // Tags (if present)
                if (data.Tags) {
                    var tagsHtml = '<h4>🏷️ Tags</h4><ul>';
                    Object.keys(data.Tags).forEach(function(k){ tagsHtml += '<li><strong>'+k+':</strong> '+data.Tags[k]+'</li>'; });
                    tagsHtml += '</ul>';
                    html += tagsHtml;
                }

                // Show quick wins and security gaps if available
                if (data.QuickWins && data.QuickWins.length > 0) {
                    html += '<h4>🎯 Quick Wins</h4><ul>';
                    data.QuickWins.slice(0,20).forEach(function(w){ html += '<li><strong>'+w.Title+'</strong> - '+(w.Description||'')+'</li>'; });
                    html += '</ul>';
                }

                if (data.SecurityGaps && data.SecurityGaps.length > 0) {
                    html += '<h4>🚨 Security Gaps</h4><ul>';
                    data.SecurityGaps.slice(0,50).forEach(function(g){ html += '<li><strong>['+g.Severity+']</strong> '+g.Issue+' - '+(g.Impact||'')+'</li>'; });
                    html += '</ul>';
                }

                // Platform cross-references: look up permission issues for vault subscription
                var subId = data.SubscriptionId || '';
                var relatedPerms = perms.filter(function(p){ return (p.Subscription == subId); });
                if (relatedPerms && relatedPerms.length > 0) {
                    html += '<h4 style="color:#dc3545;">⚠️ Permission Issues</h4><ul>';
                    relatedPerms.forEach(function(p){ html += '<li>'+p.Component+': '+p.Message+'</li>'; });
                    html += '</ul>';
                }

                html += '<details style="margin-top:10px;"><summary style="cursor:pointer;">Raw vault JSON</summary><pre id="rawJson" style="white-space:pre-wrap;background:#f8f9fa;padding:10px;border-radius:4px;">' + JSON.stringify(data,null,2) + '</pre></details>';
                html += '<script>function copyVaultJson(){ var t = document.getElementById("rawJson").innerText; navigator.clipboard.writeText(t); alert("Vault JSON copied to clipboard"); }</script>';
            }

            document.getElementById('detailsModalContent').innerHTML = html;
            document.getElementById('detailsModal').style.display = 'block';
        }
        function closeDetailsModal(){ document.getElementById('detailsModal').style.display = 'none'; }
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
    Write-Log "Starting Azure Key Vault Gap Analysis v$ScriptVersion" -Level "INFO"
    Write-Log "Test Mode: $TestMode" -Level "INFO"
    if ($TestMode) {
        Write-Log "Test Limit: $Limit vaults" -Level "INFO"
    }

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
            $targetSubscription = Get-AzSubscription | Where-Object { $_.Name -eq $SubscriptionName }
            if (-not $targetSubscription) {
                Write-Log "Specified subscription '$SubscriptionName' not found" -Level "ERROR"
                exit 1
            }
        } else {
            # Auto-discover subscription containing the vault
            Write-Log "Auto-discovering subscription containing vault '$VaultName'..." -Level "INFO"
            $subscriptionsToCheck = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }

            foreach ($sub in $subscriptionsToCheck) {
                Set-AzContext -SubscriptionId $sub.Id | Out-Null
                try {
                    $vault = Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
                    $targetSubscription = $sub
                    $foundVault = $vault
                    Write-Log "Found vault '$VaultName' in subscription '$($sub.Name)'" -Level "SUCCESS"
                    break
                } catch {
                    # Vault not in this subscription, continue
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

    # Initialize global variables for this run
    $global:gapAnalysisResults = @()
    $global:securityGaps = @()
    $global:quickWins = @()
    $global:recommendations = @()

    # Analyze each subscription
    foreach ($subscription in $subscriptions) {
        Write-Log "Analyzing subscription: $($subscription.Name) ($($subscription.Id))" -Level "INFO"

        # Get Azure platform assessment (always done for comprehensive analysis)
        $platformAssessment = Get-AzurePlatformAssessment -SubscriptionId $subscription.Id
        $platformAssessments += $platformAssessment

        # Get Key Vaults in subscription (skip if SingleVault and this isn't the target subscription)
        if ($SingleVault -and $subscription.Id -ne $targetSubscription.Id) {
            continue
        }

        if (-not $SingleVault) {
            $keyVaults = Get-KeyVaultsInSubscription -SubscriptionId $subscription.Id

            if ($keyVaults.Count -eq 0) {
                Write-Log "No Key Vaults found in subscription $($subscription.Name)" -Level "INFO"
                continue
            }

            # Apply global limit in test mode
            if ($TestMode) {
                $remainingLimit = $Limit - $vaultsProcessedInTestMode
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
        if ($TestMode -and -not $SingleVault -and $keyVaults.Count -gt ($Limit - $vaultsProcessedInTestMode)) {
            $remainingLimit = $Limit - $vaultsProcessedInTestMode
            $keyVaults = $keyVaults | Select-Object -First $remainingLimit
            Write-Log "Test mode: Limited to $remainingLimit vaults in this subscription" -Level "INFO"
        }

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

                # Re-establish Azure context in parallel job
                $azContext = $using:azContext
                if ($azContext) {
                    try {
                        Set-AzContext -Context $azContext | Out-Null
                    } catch {
                        # Context sharing failed, try alternative authentication
                        try {
                            $null = Connect-AzAccount -Identity -ErrorAction Stop
                        } catch {
                            # If both methods fail, we'll proceed without context and handle errors gracefully
                        }
                    }
                }

                try {
                    # Get diagnostics configuration
                    $diagnostics = & {
                        param($vaultName, $rgName)
                        try {
                            $diag = Get-AzDiagnosticSetting -ResourceId "/subscriptions/$subscriptionId/resourceGroups/$rgName/providers/Microsoft.KeyVault/vaults/$vaultName" -ErrorAction SilentlyContinue
                            return @{
                                HasDiagnostics = ($diag.Count -gt 0)
                                DiagnosticSettings = $diag
                                LogsEnabled = ($diag | Where-Object { $_.Logs.Count -gt 0 }).Count -gt 0
                                MetricsEnabled = ($diag | Where-Object { $_.Metrics.Count -gt 0 }).Count -gt 0
                            }
                        } catch {
                            return @{
                                HasDiagnostics = $false
                                DiagnosticSettings = $null
                                LogsEnabled = $false
                                MetricsEnabled = $false
                            }
                        }
                    } $vault.VaultName $vault.ResourceGroupName

                    # Get access control analysis
                    $accessControl = & {
                        param($vaultName, $rgName, $subId)
                        try {
                            $vaultObj = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $rgName
                            $rbacEnabled = $vaultObj.EnableRbacAuthorization
                            $accessPolicies = $vaultObj.AccessPolicies
                            $roleAssignments = Get-AzRoleAssignment -Scope $vaultObj.ResourceId -ErrorAction SilentlyContinue

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
                    } $vault.VaultName $vault.ResourceGroupName $subscriptionId

                    # Get network security analysis
                    $networkSecurity = & {
                        param($vaultName, $rgName)
                        try {
                            $vaultObj = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $rgName
                            $networkAcls = $vaultObj.NetworkAcls
                            $privateEndpoints = Get-AzPrivateEndpoint | Where-Object {
                                $_.PrivateLinkServiceConnections.PrivateLinkServiceId -like "*$vaultName*"
                            }

                            return @{
                                PublicNetworkAccess = $vaultObj.PublicNetworkAccess
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
                    } $vault.VaultName $vault.ResourceGroupName

                    # Calculate compliance score and identify gaps
                    $gaps = @()
                    $wins = @()

                    # Security gap identification logic
                    if (!$accessControl.RbacEnabled -and $accessControl.AccessPoliciesCount -eq 0) {
                        $gaps += @{
                            Category = "Access Control"
                            Severity = "Critical"
                            Issue = "No access control configured"
                            Impact = "Vault is inaccessible"
                            Recommendation = "Enable RBAC or configure access policies"
                        }
                    }

                    if (!$diagnostics.HasDiagnostics) {
                        $gaps += @{
                            Category = "Monitoring"
                            Severity = "High"
                            Issue = "No diagnostic settings configured"
                            Impact = "No audit logging or monitoring"
                            Recommendation = "Enable diagnostic settings to Log Analytics or Event Hub"
                        }
                    }

                    if ($networkSecurity.PublicNetworkAccess -eq "Enabled" -and !$networkSecurity.HasPrivateEndpoints) {
                        $gaps += @{
                            Category = "Network Security"
                            Severity = "Medium"
                            Issue = "Public network access enabled without private endpoints"
                            Impact = "Potential exposure to public internet"
                            Recommendation = "Configure private endpoints or restrict network access"
                        }
                    }

                    # Quick wins logic
                    if ($accessControl.AccessPoliciesCount -gt 0 -and !$accessControl.RbacEnabled) {
                        $wins += @{
                            Category = "Access Control"
                            Title = "Migrate to RBAC"
                            Description = "Replace access policies with Azure RBAC for better security and management"
                            Effort = "Medium"
                            Impact = "High"
                        }
                    }

                    if (!$diagnostics.HasDiagnostics) {
                        $wins += @{
                            Category = "Monitoring"
                            Title = "Enable Diagnostic Logging"
                            Description = "Configure diagnostic settings to capture audit logs and metrics"
                            Effort = "Low"
                            Impact = "High"
                        }
                    }

                    # Calculate compliance score
                    $score = 100
                    foreach ($gap in $gaps) {
                        switch ($gap.Severity) {
                            "Critical" { $score -= 25 }
                            "High" { $score -= 15 }
                            "Medium" { $score -= 10 }
                            "Low" { $score -= 5 }
                        }
                    }

                    # Bonus points
                    if ($diagnostics.HasDiagnostics) { $score += 10 }
                    if ($accessControl.RbacEnabled) { $score += 10 }
                    if ($networkSecurity.HasPrivateEndpoints) { $score += 10 }

                    $complianceScore = [math]::Max(0, [math]::Min(100, $score))
                    $riskLevel = switch ($complianceScore) {
                        { $_ -ge 90 } { "Low" }
                        { $_ -ge 70 } { "Medium" }
                        { $_ -ge 50 } { "High" }
                        default { "Critical" }
                    }

                    return @{
                        SubscriptionId = $subscriptionId
                        SubscriptionName = $subscriptionName
                        VaultName = $vault.VaultName
                        ResourceGroupName = $vault.ResourceGroupName
                        Location = $vault.Location
                        Diagnostics = $diagnostics
                        AccessControl = $accessControl
                        NetworkSecurity = $networkSecurity
                        SecurityGaps = $gaps
                        QuickWins = $wins
                        ComplianceScore = $complianceScore
                        RiskLevel = $riskLevel
                        Vault = $vault
                    }
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
                        SecurityGaps = @(@{ Category = "Error"; Severity = "High"; Issue = "Analysis failed: $($_.Exception.Message)" })
                        QuickWins = @()
                        ComplianceScore = 0
                        RiskLevel = "Critical"
                        Vault = $vault
                    }
                }
            }

            # Collect results from parallel jobs
            foreach ($result in $vaultJobs) {
                $global:gapAnalysisResults += $result
                $totalVaultsAnalyzed++
                $vaultsProcessedInTestMode++

                Write-Log "Completed parallel analysis of $($result.VaultName) - Score: $($result.ComplianceScore)%, Risk: $($result.RiskLevel)" -Level "INFO"

                # Check if we've reached the test mode limit
                if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
                    Write-Log "Test mode limit ($Limit) reached, stopping analysis" -Level "INFO"
                    break
                }
            }
        } else {
            # Sequential processing (original logic)
            foreach ($vault in $keyVaults) {
                $analysis = Analyze-KeyVault -Vault $vault -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name
                $global:gapAnalysisResults += $analysis
                $totalVaultsAnalyzed++
                $vaultsProcessedInTestMode++

                Write-Log "Completed analysis of $($vault.VaultName) - Score: $($analysis.ComplianceScore)%, Risk: $($analysis.RiskLevel)" -Level "INFO"

                # Check if we've reached the test mode limit
                if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
                    Write-Log "Test mode limit ($Limit) reached, stopping analysis" -Level "INFO"
                    break
                }
            }
        }

        # Break out of subscription loop if test mode limit reached
        if ($TestMode -and $vaultsProcessedInTestMode -ge $Limit) {
            break
        }
    }

    # Export CSV results
    Write-Log "Exporting CSV results..." -Level "INFO"
    Write-Log "Analysis results count: $($global:gapAnalysisResults.Count)" -Level "INFO"

    if ($global:gapAnalysisResults -and $global:gapAnalysisResults.Count -gt 0) {
        # Flatten the results for CSV export
        $flattenedResults = $global:gapAnalysisResults | ForEach-Object {
            [PSCustomObject]@{
                SubscriptionId = $_.SubscriptionId
                SubscriptionName = $_.SubscriptionName
                VaultName = $_.VaultName
                ResourceGroupName = $_.ResourceGroupName
                Location = $_.Location
                ComplianceScore = $_.ComplianceScore
                RiskLevel = $_.RiskLevel
                HasDiagnostics = $_.Diagnostics.HasDiagnostics
                RbacEnabled = $_.AccessControl.RbacEnabled
                AccessPoliciesCount = $_.AccessControl.AccessPoliciesCount
                HasPrivateEndpoints = $_.NetworkSecurity.HasPrivateEndpoints
                SecurityGapsCount = $_.SecurityGaps.Count
                QuickWinsCount = $_.QuickWins.Count
                EnableSoftDelete = $_.Vault.EnableSoftDelete
                EnablePurgeProtection = $_.Vault.EnablePurgeProtection
            }
        }
        $flattenedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV export completed: $csvPath" -Level "SUCCESS"
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
}

# Run the gap analysis
Invoke-GapAnalysis