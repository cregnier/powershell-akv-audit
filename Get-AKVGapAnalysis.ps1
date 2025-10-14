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
        # Get secrets
        $secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction SilentlyContinue
        $secretCount = if ($secrets) { $secrets.Count } else { 0 }

        # Get certificates
        $certificates = Get-AzKeyVaultCertificate -VaultName $VaultName -ErrorAction SilentlyContinue
        $certificateCount = if ($certificates) { $certificates.Count } else { 0 }

        # Get keys
        $keys = Get-AzKeyVaultKey -VaultName $VaultName -ErrorAction SilentlyContinue
        $keyCount = if ($keys) { $keys.Count } else { 0 }

        $totalAssets = $secretCount + $certificateCount + $keyCount

        return @{
            SecretsCount = $secretCount
            CertificatesCount = $certificateCount
            KeysCount = $keyCount
            TotalAssets = $totalAssets
            Secrets = $secrets
            Certificates = $certificates
            Keys = $keys
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

                if ($lastUpdated -gt $thirtyDaysAgo) {
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

                if ($lastUpdated -gt $thirtyDaysAgo) {
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

                if ($lastUpdated -gt $thirtyDaysAgo) {
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
            BestPractice = "Azure Key Vault should use Azure RBAC for access control. Access policies are legacy and should be migrated to RBAC for better security, auditability, and management."
            RemediationSteps = @(
                "Enable Azure RBAC on the Key Vault: Set-AzKeyVaultAccessPolicy -VaultName <vault> -EnabledForRoleBasedAccess $true",
                "Assign appropriate RBAC roles (Key Vault Administrator, Key Vault Secrets Officer, etc.) to users/groups",
                "Remove legacy access policies after RBAC migration",
                "Test access with the new RBAC permissions"
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
            BestPractice = "Azure Key Vault must have diagnostic settings enabled to send audit logs to Log Analytics, Event Hub, or Storage for security monitoring, compliance reporting, and threat detection."
            RemediationSteps = @(
                "Go to Key Vault in Azure Portal → Monitoring → Diagnostic settings",
                "Click 'Add diagnostic setting'",
                "Select logs: AuditEvent, AzurePolicyEvaluationDetails",
                "Select metrics: AllMetrics",
                "Choose destination: Log Analytics workspace (recommended) or Event Hub",
                "Save the diagnostic setting"
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

    # Soft delete gap
    if (!$VaultAnalysis.Vault.EnableSoftDelete) {
        $gaps += @{
            Category = "Data Protection & Recovery"
            Severity = "High"
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

        # Check Azure Policies related to Key Vault
        $kvPolicies = Get-AzPolicyDefinition | Where-Object {
            $_.Properties.DisplayName -like "*Key Vault*" -or
            $_.Properties.Description -like "*Key Vault*"
        }

        $assessment.Policies = @{
            KeyVaultPoliciesCount = $kvPolicies.Count
            KeyVaultPolicies = $kvPolicies
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
            $assessment.Runbooks = @{
                AutomationAccountsCount = 0
                KeyVaultRunbooksCount = 0
                Runbooks = @()
            }
        }

    } catch {
        Write-Log "Failed to assess Azure platform for subscription ${SubscriptionId}: $($_.Exception.Message)" -Level "ERROR"
    }

    return $assessment
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

    # Calculate compliance score
    $score = 100

    # Deduct points for gaps
    foreach ($gap in $analysis.SecurityGaps) {
        switch ($gap.Severity) {
            "Critical" { $score -= 25 }
            "High" { $score -= 15 }
            "Medium" { $score -= 10 }
            "Low" { $score -= 5 }
        }
    }

    # Bonus points for good practices
    if ($analysis.Diagnostics.HasDiagnostics) { $score += 10 }
    if ($analysis.AccessControl.RbacEnabled) { $score += 10 }
    if ($analysis.NetworkSecurity.HasPrivateEndpoints) { $score += 10 }
    if ($Vault.EnableSoftDelete) { $score += 5 }
    if ($Vault.EnablePurgeProtection) { $score += 5 }

    $analysis.ComplianceScore = [math]::Max(0, [math]::Min(100, $score))

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

    # Generate policy details page
    $policyDetailsPath = New-PolicyDetailsHtmlPage -PlatformAssessments $PlatformAssessments -OutputPath $OutputPath
    $policyDetailsFileName = [System.IO.Path]::GetFileName($policyDetailsPath)

    $totalVaults = $AnalysisResults.Count
    $vaultsWithDiagnostics = ($AnalysisResults | Where-Object { $_.Diagnostics.HasDiagnostics }).Count
    $diagnosticsPercentage = if ($totalVaults -gt 0) { [math]::Round(($vaultsWithDiagnostics / $totalVaults) * 100, 1) } else { 0 }

    $criticalGaps = ($AnalysisResults | ForEach-Object { $_.SecurityGaps | Where-Object { $_.Severity -eq "Critical" } }).Count
    $highGaps = ($AnalysisResults | ForEach-Object { $_.SecurityGaps | Where-Object { $_.Severity -eq "High" } }).Count
    $mediumGaps = ($AnalysisResults | ForEach-Object { $_.SecurityGaps | Where-Object { $_.Severity -eq "Medium" } }).Count

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
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
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
                <div class="stat-number">$totalVaults</div>
                <div class="stat-label">Total Key Vaults</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$uniqueSubscriptions</div>
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
                <div class="stat-number">$totalSecrets</div>
                <div class="stat-label">Total Secrets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalCertificates</div>
                <div class="stat-label">Total Certificates</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalKeys</div>
                <div class="stat-label">Total Keys</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$assetsNeedingRotation</div>
                <div class="stat-label">Assets Needing Rotation</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$recentlyRotated</div>
                <div class="stat-label">Recently Rotated (< 30 days)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalQuickWins</div>
                <div class="stat-label">Total Quick Wins Available</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$criticalGaps</div>
                <div class="stat-label">Critical Security Gaps</div>
            </div>
        </div>
    </div>

    <div class="summary">
        <h2>📋 Risk Assessment Methodology</h2>
        <div style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3>Compliance Scoring Framework</h3>
            <p>The compliance score is calculated based on security best practices and Azure Key Vault hardening guidelines:</p>
            <ul>
                <li><strong>Base Score:</strong> 100 points</li>
                <li><strong>Deductions:</strong> Points are subtracted for security gaps (Critical: -25, High: -15, Medium: -10, Low: -5)</li>
                <li><strong>Bonuses:</strong> Points are added for good practices (+10 for diagnostics, RBAC, private endpoints each; +5 for soft delete and purge protection)</li>
            </ul>

            <h3>Risk Level Definitions</h3>
            <ul>
                <li><strong class="risk-low">Low Risk (90-100%):</strong> Excellent security posture with minimal gaps</li>
                <li><strong class="risk-medium">Medium Risk (70-89%):</strong> Good security with some areas for improvement</li>
                <li><strong class="risk-high">High Risk (50-69%):</strong> Significant security gaps requiring immediate attention</li>
                <li><strong class="risk-critical">Critical Risk (0-49%):</strong> Severe security vulnerabilities requiring urgent remediation</li>
            </ul>
        </div>
    </div>

    <div class="gaps-section">
        <h2>🚨 Security Gaps Identified</h2>
        <p>Critical: $criticalGaps | High: $highGaps | Medium: $mediumGaps</p>
"@

    # Add gap details
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
    $allGaps = $allGaps | Sort-Object -Property Severity -Descending

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

    # Add quick wins
    $allWins = $AnalysisResults | ForEach-Object { $_.QuickWins } | Sort-Object -Property Impact -Descending
    foreach ($win in $allWins) {
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
            <em>Description:</em> Replace service principals with managed identities where possible for improved security<br>
            <em>Effort:</em> Medium | <em>Impact:</em> Medium
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; font-weight: bold;">🔧 Implementation Steps</summary>
                <ol style="margin-top: 5px;">
                    <li>Identify applications using service principals for Key Vault access</li>
                    <li>Enable system-assigned managed identity on Azure resources</li>
                    <li>Grant Key Vault access to managed identities</li>
                    <li>Update application code to use managed identity authentication</li>
                    <li>Remove service principal credentials from configuration</li>
                    <li>Test authentication with managed identities</li>
                </ol>
                <p style="margin-top: 10px;"><strong>📚 Documentation:</strong> <a href="https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview" target="_blank">Managed Identities</a></p>
            </details>
        </div>
"@

    $html += @"
    </div>

    <div class="summary">
        <h2>🔐 Secret Inventory & Rotation Analysis</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$totalAssets</div>
                <div class="stat-label">Total Assets (Secrets + Certs + Keys)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$assetsNeedingRotation</div>
                <div class="stat-label">Assets Needing Rotation</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$neverRotated</div>
                <div class="stat-label">Never Rotated Assets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$recentlyRotated</div>
                <div class="stat-label">Recently Rotated (< 30 days)</div>
            </div>
        </div>

        <h3>🔄 Rotation Status by Vault</h3>
        <table>
            <tr><th>Vault Name</th><th>Subscription</th><th>Secrets</th><th>Certificates</th><th>Keys</th><th>Total Assets</th><th>Need Rotation</th><th>Recently Rotated</th><th>Never Rotated</th></tr>
"@

    foreach ($vault in $AnalysisResults) {
        $html += @"
            <tr>
                <td>$($vault.VaultName)</td>
                <td>$($vault.SubscriptionName)<br><small>$($vault.SubscriptionId)</small></td>
                <td>$($vault.SecretInventory.SecretsCount)</td>
                <td>$($vault.SecretInventory.CertificatesCount)</td>
                <td>$($vault.SecretInventory.KeysCount)</td>
                <td>$($vault.SecretInventory.TotalAssets)</td>
                <td>$($vault.RotationAnalysis.ManualRotationNeeded)</td>
                <td>$($vault.RotationAnalysis.RecentlyRotated)</td>
                <td>$($vault.RotationAnalysis.NeverRotated)</td>
            </tr>
"@
    }

    $html += @"
        </table>

        <h3>⚠️ Assets Requiring Immediate Rotation</h3>
        <table>
            <tr><th>Vault Name</th><th>Asset Type</th><th>Asset Name</th><th>Last Updated</th><th>Days Since Update</th><th>Status</th></tr>
"@

    foreach ($vault in $AnalysisResults) {
        foreach ($asset in $vault.RotationAnalysis.RotationDetails | Where-Object { $_.NeedsRotation }) {
            $status = if ($null -eq $asset.LastUpdated) { "Never Rotated" } else { "Outdated (>90 days)" }
            $lastUpdatedDisplay = if ($asset.LastUpdated) { $asset.LastUpdated.ToString("yyyy-MM-dd") } else { "Never" }

            $html += @"
            <tr>
                <td>$($vault.VaultName)</td>
                <td>$($asset.Type)</td>
                <td>$($asset.Name)</td>
                <td>$lastUpdatedDisplay</td>
                <td>$($asset.DaysSinceUpdate)</td>
                <td style="color: #dc3545; font-weight: bold;">$status</td>
            </tr>
"@
        }
    }

    $html += @"
        </table>
    </div>

    <div class="platform-section">
        <h2>☁️ Azure Platform Integration Assessment</h2>
        <table>
            <tr><th>Subscription</th><th>Key Vault Policies</th><th>Event Hub Namespaces</th><th>Log Analytics Workspaces</th><th>Key Vault RBAC Roles</th><th>Managed Identities</th><th>Service Principals</th><th>Service Identities</th><th>Automation Runbooks</th></tr>
"@

    foreach ($platform in $PlatformAssessments) {
        $subscriptionDisplay = if ($platform.SubscriptionName) { "$($platform.SubscriptionName)<br><small>$($platform.SubscriptionId)</small>" } else { $platform.SubscriptionId }
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
        }
    }

    $html += @"
        </div>

        <h3>🛡️ Key Vault RBAC Roles</h3>
        <div style="margin-top: 15px;">
"@

    foreach ($platform in $PlatformAssessments) {
        if ($platform.RbacRoles.KeyVaultRoles.Count -gt 0) {
            $html += @"
            <div style="margin-bottom: 20px; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                <strong>$($platform.SubscriptionName)</strong> ($($platform.SubscriptionId)):
                <ul>
"@

            foreach ($role in $platform.RbacRoles.KeyVaultRoles) {
                $html += "<li>$($role.Name) - $($role.Description)</li>"
            }

            $html += @"
                </ul>
            </div>
"@
        }
    }

    $html += @"
        </div>
    </div>

    <div class="vault-details">
        <h2>🔐 Key Vault Details</h2>
        <table>
            <tr><th>Vault Name</th><th>Subscription</th><th>Location</th><th>Compliance Score</th><th>Risk Level</th><th>Diagnostics</th><th>RBAC</th><th>Private Endpoints</th><th>Security Gaps</th></tr>
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
                <td>$($vault.VaultName)</td>
                <td>$($vault.SubscriptionName)<br><small>$($vault.SubscriptionId)</small></td>
                <td>$($vault.Location)</td>
                <td>$($vault.ComplianceScore)%</td>
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