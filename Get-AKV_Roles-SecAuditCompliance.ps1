<#
.SYNOPSIS
    Enhanced Azure Key Vault Comprehensive Security & Compliance Audit Script v2.1
.DESCRIPTION
 

    Production-ready PowerShell script to perform comprehensive Azure Key Vault security audits across all subscriptions.
    Includes advanced RBAC analysis, managed identity detection, service principal analysis, compliance scoring,
    detailed recommendations, enhanced token management for 10-12 hour execution periods, and executive reporting
    with enhanced HTML and CSV outputs.
    
    VERSION 2.1 ENHANCEMENTS:
    - Production-ready token management with proactive refresh (15-min threshold)
    - Enhanced 5-tier color-coded percentage system for visual compliance assessment
    - Custom company compliance framework with 5 minimum requirements
    - Updated Microsoft compliance framework with 2024-2025 recommendations
    - Comprehensive permissions validation and reporting
    - Enhanced logging infrastructure with UTC timestamps and detailed context
    - Advanced retry mechanisms with exponential backoff for production stability
    - Minimum permissions recommendations section in HTML report
    - Enhanced progress tracking with confidence-based ETA calculations
    - Detailed secrets management insights with implementation guidance
    - Automated cancellation recovery with checkpoint marker system
    - Enhanced checkpoint selection with system crash vs manual cancellation distinction
    - OneDrive/SharePoint upload integration for walk-away reliability with Microsoft Graph API
    - Automatic checkpoint uploads during long-running analysis for continuity
    - Final report uploads with artifact URLs and resume instructions logging
    
    VERSION 2.2 PSScriptAnalyzer COMPLIANCE & ENHANCED ERROR HANDLING:
    - PSScriptAnalyzer compliance improvements with CmdletBinding and proper parameter attributes
    - Comprehensive environment detection with verbose logging for Cloud Shell, MSI, and local environments
    - Enhanced authentication flow documentation and decision logic with user guidance
    - Robust interruption handling with CTRL-C support and graceful cleanup mechanisms
    - Enhanced checkpoint management with interruption-aware saving and recovery metadata
    - Improved HTML report generation with comprehensive partial results support
    - Clear "PARTIAL RESULTS" banners with completion status and resume instructions
    - Standardized output system reducing Write-Host usage for better pipeline compatibility
    - Enhanced error handling and logging throughout all functions
    - Comprehensive execution context tracking for troubleshooting and recovery

.NOTES
    Author: Curtus Regnier & Claude Sonnet 4.0
    Version: 2.2 - Enhanced PSScriptAnalyzer Compliance & Enterprise Error Handling Edition
    Date: $(Get-Date -Format 'yyyy-MM-dd')
    Requirements: PowerShell 7.x, Azure PowerShell modules, MSAL.PS (for OneDrive upload), appropriate Azure RBAC permissions
    
    AUTHENTICATION METHODS & ENVIRONMENT DETECTION:
    The script now includes comprehensive environment detection and authentication flow mapping:
    
    1. Azure Cloud Shell Detection:
       - Automatically detects Cloud Shell environment using multiple indicators
       - Uses interactive browser authentication (optimal for Cloud Shell)
       - Provides verbose logging of detection criteria and reasoning
    
    2. Managed Identity Detection:
       - Detects MSI/automation environments through environment variables and Azure context
       - Uses managed identity authentication when available
       - Falls back to device code authentication in automation scenarios
    
    3. Service Principal Detection:
       - Automatically detects complete service principal credentials in environment
       - Uses app-only authentication for automation and CI/CD scenarios
       - Supports both environment variables and interactive credential input
    
    4. Interactive Authentication:
       - Browser-based authentication for local development environments
       - Device code fallback for environments without browser access
       - Clear user guidance and authentication method explanations
    
    INTERRUPTION HANDLING & RECOVERY:
    Enhanced interruption handling provides enterprise-grade reliability:
    
    - CTRL-C handler registration for graceful shutdown
    - Automatic checkpoint saving on interruption with detailed metadata
    - Comprehensive recovery instructions in HTML reports
    - Resume capability with progress tracking and completion estimates
    - Error context preservation for troubleshooting interrupted runs
    
.PARAMETER TestMode
    Optional. Run in test mode with limited Key Vaults for validation and testing.
    Recommended for initial setup validation before production runs.
    
.PARAMETER Limit
    Optional. Number of Key Vaults to test when in test mode. Default is 3.
    Only applies when TestMode is enabled.

.PARAMETER Resume
    Optional. Resume audit from a selected checkpoint file.
    If checkpoint files are found, lists all available checkpoints and allows user selection for resume point.
    If no checkpoint files are found but a master discovery file exists, automatically uses the master file 
    for optimized performance, skipping subscription discovery and access validation.
    Useful for continuing interrupted audits in large environments.

.PARAMETER ProcessPartial
    Optional. Process partial results from either a checkpoint file, master discovery file, or an existing CSV file.
    When used without -CsvFilePath, will first check for checkpoint files, then fallback to master discovery file.
    When used with -CsvFilePath, will load results directly from the specified CSV file.
    If a master discovery file is found (even without checkpoints), automatically uses it for optimized performance,
    skipping subscription discovery and access validation.
    Generates HTML/CSV reports from the loaded partial data.
    Useful for extracting results from incomplete audits without restarting the analysis.

.PARAMETER CsvFilePath
    Optional. Specify a CSV file path when using -ProcessPartial or -ReportFromCsv.
    For -ProcessPartial: If provided, the script will load partial results directly from this CSV file
    instead of prompting for checkpoint selection.
    For -ReportFromCsv: Specify the CSV file path to generate reports from.
    If not provided with -ReportFromCsv, the script will auto-detect the latest KeyVaultComprehensiveAudit*.csv file
    in the output directory.
    The CSV file should contain valid audit results from a previous run.
    When using this parameter, subscription discovery and access validation are completely bypassed.

.PARAMETER ReportFromCsv
    Optional. Generate HTML report directly from an existing CSV file without performing any Azure analysis.
    This mode is designed for generating production HTML reports from interrupted audits.
    Cannot be used with -Resume or -ProcessPartial parameters.
    Requires no Azure authentication and works completely offline.

.PARAMETER MarkPartial
    Optional. Controls whether reports generated with -ReportFromCsv are marked as "PARTIAL RESULTS".
    Can only be used with -ReportFromCsv parameter. If not specified when using -ReportFromCsv, 
    defaults to $true. Set to $false to generate reports without partial result banners.

.PARAMETER ResumeCsvStrict
    Optional. Enable strict CSV deduplication validation when resuming from checkpoints.
    If enabled, the script will warn and skip any rows that already exist in the CSV file
    based on multi-key identity matching. Helps prevent duplicate entries during resume.

.PARAMETER OutputDirectory
    Optional. Override the default output directory.
    If not specified, automatically detects:
    - Azure Cloud Shell: /home/<upn_prefix> (where upn_prefix is username before @)
    - Local environment: $env:USERPROFILE/Documents/KeyVaultAudit (Windows) or equivalent

.PARAMETER ProgressMode
    Optional. Controls how progress is displayed during vault processing.
    Valid values: 'Session', 'Overall', 'Both'. Default is 'Session'.
    - Session: Shows progress within current session (e.g., "Session: 1/972" when 1000 of 1972 already processed)
    - Overall: Shows overall progress including baseline (e.g., "Overall: 1001/1972")
    - Both: Shows both session and overall progress

.PARAMETER UnmatchedLogCount
    Optional. Number of unmatched checkpoint entries to log for diagnostics when resuming.
    Default is 10. Set to 0 to disable unmatched entry logging.
    Helps identify renamed/removed vaults or permission changes between runs.

.PARAMETER UploadToCloud
    Optional. Enable automatic upload of all output files to OneDrive/SharePoint after audit completion.
    Uses Microsoft Graph API with device code authentication for seamless integration in Azure Cloud Shell.
    Requires Files.ReadWrite.All permissions. Default is $false.

.PARAMETER CloudUploadPath
    Optional. Target folder path in OneDrive/SharePoint for file uploads when using -UploadToCloud.
    If not specified, user will be prompted to enter the target folder path.
    Examples: "/Documents/KeyVaultAudits", "/Shared Documents/Security/Audits"

.PARAMETER ResumeSourcePriority
    Optional. Controls which sources contribute to the processed identity set when resuming.
    Valid values: 'Checkpoint', 'CSV', 'Union'. Default is 'Union'.
    - Checkpoint: Use checkpoint data only
    - CSV: Use existing CSV file data only  
    - Union: Combine both checkpoint and CSV data (recommended for robustness)

.PARAMETER ResumeStrictMatch
    Optional. Enable strict matching validation when resuming.
    If enabled and the baseline match percentage falls below the threshold, the script will abort 
    with a clear error message before processing begins.
    Helps detect significant mismatches between checkpoint/CSV data and current discovery.

.PARAMETER StrictMatchThresholdPercent
    Optional. Minimum percentage of processed identities that must match discovered vaults when 
    -ResumeStrictMatch is enabled. Valid range: 1-100. Default is 60.
    If the match percentage falls below this threshold, processing is aborted with recommendations.

.PARAMETER GraphClientId
    Optional. Client ID (Application ID) for Microsoft Graph app-only authentication.
    If provided along with GraphTenantId and GraphClientSecret, enables app-only authentication mode.
    Can also be specified via AZURE_CLIENT_ID environment variable.

.PARAMETER GraphTenantId
    Optional. Tenant ID for Microsoft Graph app-only authentication.
    Required when using app-only authentication with GraphClientId and GraphClientSecret.
    Can also be specified via AZURE_TENANT_ID environment variable.

.PARAMETER GraphClientSecret
    Optional. Client Secret for Microsoft Graph app-only authentication.
    Required when using app-only authentication with GraphClientId and GraphTenantId.
    Can also be specified via AZURE_CLIENT_SECRET environment variable.

.PARAMETER GraphAuthMode
    Optional. Override the automatic Microsoft Graph authentication mode selection.
    Valid values: 'Interactive', 'App', 'DeviceCode', 'Auto'. Default is 'Auto'.
    
    Authentication Method Descriptions:
    - Interactive: Browser-based authentication (optimal for local desktop environments)
    - App: App-only authentication using client credentials (optimal for automation scenarios)  
    - DeviceCode: Device code flow authentication (fallback when other methods fail)
    - Auto: Automatically select based on environment detection and available credentials
    
    Enhanced Auto-Detection Logic (Priority Order):
    1. Service Principal credentials detected (env vars/parameters) → App authentication
    2. Azure Cloud Shell environment detected → Interactive authentication  
    3. Managed Identity environment without credentials → DeviceCode authentication
    4. Local desktop environment → Interactive authentication (with DeviceCode fallback)
    
    Az.Accounts Context Integration:
    - Automatically detects tenant/client IDs from current Az.Accounts context
    - Leverages existing managed identity authentication when available
    - Provides verbose logging of auto-detection decisions and fallback reasons  
    3. Managed Identity environment without credentials → DeviceCode authentication
    4. Local desktop environment → Interactive authentication (with DeviceCode fallback)
    
    Environment Detection Uses:
    - $env:CLOUD_SHELL, $env:ACC_CLOUD (Cloud Shell indicators)
    - $env:MSI_SECRET, $env:AZURE_HTTP_USER_AGENT (MSI/automation indicators)  
    - $env:AZURE_CLIENT_ID, $env:AZURE_TENANT_ID, $env:AZURE_CLIENT_SECRET (credentials)
    - Az.Accounts context analysis for managed identity authentication
    1. Complete Service Principal credentials available → App-only authentication
       - Checks parameters: GraphClientId, GraphTenantId, GraphClientSecret
       - Checks environment: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET
       - Preferred in ALL environments when credentials are available
    
    2. Local environment (non-Cloud Shell) → Interactive browser authentication
       - Uses Microsoft Graph PowerShell modules with browser sign-in
       - Automatic fallback to device code if modules unavailable
    
    3. Azure Cloud Shell environment (without app credentials) → Device code authentication  
       - Device code authentication used as FALLBACK ONLY, not default
       - Interactive user prompts when MSI/app-only authentication fails
       - Clear explanations of each authentication method provided to users
    
    Enhanced Error Handling & User Guidance:
    - Comprehensive error logging with environment context and authentication details
    - Interactive prompts when primary authentication fails (when Interactive=true)
    - Clear explanations of device code vs browser login options  
    - Detailed troubleshooting information logged for failed authentication attempts
    
    Environment Detection Indicators:
    - Cloud Shell: $env:CLOUD_SHELL, $env:ACC_CLOUD, $env:AZUREPS_HOST_ENVIRONMENT
    - MSI/Automation: $env:MSI_ENDPOINT, $env:IDENTITY_ENDPOINT, $env:IMDS_ENDPOINT
    - Az.Accounts context analysis for current authentication state
    - Comprehensive logging shows which detection logic matched and why

.PARAMETER GraphScopeScenario
    Optional. Determines the Microsoft Graph permission scopes requested during authentication.
    Valid values: 'Files', 'Sites', 'Full'. Default is 'Files'.
    - Files: Basic file operations (Files.ReadWrite.All, Sites.ReadWrite.All)
    - Sites: Enhanced SharePoint operations (adds Sites.Manage.All, Sites.FullControl.All)
    - Full: Comprehensive enterprise permissions (adds User.Read, Directory.Read.All)

.PARAMETER SingleVault
    Optional. Run targeted diagnostics scan for a single Key Vault instead of full organizational scan.
    This mode is designed for quick testing and validation of diagnostic settings configuration.
    
    When enabled:
    - Prompts for Key Vault name (or use -VaultName parameter)
    - Searches across all accessible subscriptions to locate the specified vault
    - Performs comprehensive diagnostics analysis including RBAC, access policies, and network config
    - Generates focused CSV and HTML reports for just that vault
    - Completes in seconds/minutes vs hours for full organizational scans
    - Cannot be used with -Resume, -ProcessPartial, or -ReportFromCsv parameters
    
    Perfect for:
    - Testing diagnostic settings after configuration changes
    - Validating specific vault compliance before production deployment
    - Troubleshooting diagnostic logging issues on individual vaults
    - Quick verification of Azure Portal configuration vs script output

.PARAMETER VaultName
    Optional. Specify the Key Vault name when using -SingleVault mode.
    If not provided, the script will prompt interactively for the vault name.
    The vault name is case-sensitive and must match exactly.
    
    Example: -SingleVault -VaultName "MyCompanyProdVault"
    
    When used with -SubscriptionName, the script will search only within the specified subscription.
    If -SubscriptionName is not provided, the script will search across all accessible subscriptions.
    If the vault is not found, the script will display helpful troubleshooting guidance.
    
.PARAMETER SubscriptionName
    Optional. Specify the subscription name or ID when using -SingleVault mode.
    If not provided, the script will prompt interactively for the subscription (allowing blank for full enumeration).
    Accepts both subscription display names and subscription IDs (GUIDs).
    
    Example: -SingleVault -SubscriptionName "Production" -VaultName "MyCompanyProdVault"
    Example: -SingleVault -SubscriptionName "12345678-1234-1234-1234-123456789abc" -VaultName "MyVault"
    
    When provided, significantly speeds up vault discovery by targeting only the specified subscription
    instead of enumerating all accessible subscriptions. Leave blank when prompted to fall back
    to normal enumeration across all subscriptions.
    
.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    Run full production audit of all Key Vaults across all accessible subscriptions.
    
.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode
    Run in test mode with default limit of 3 Key Vaults for validation.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Limit 5
    Run in test mode with custom limit of 5 Key Vaults for extended testing.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -SingleVault
    Run targeted diagnostics scan for a single Key Vault. Script will prompt for vault name
    and subscription name (optional), then search to locate and analyze the specified vault.
    
.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -SingleVault -VaultName "MyCompanyProdVault"
    Run targeted diagnostics scan for the specific Key Vault "MyCompanyProdVault".
    Script will prompt for subscription name to speed up discovery, or search all subscriptions if left blank.
    Generates focused CSV and HTML reports with comprehensive diagnostic settings analysis.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -SingleVault -VaultName "MyVault" -SubscriptionName "Production"
    Run targeted diagnostics scan for "MyVault" in the "Production" subscription.
    Bypasses subscription enumeration for faster vault discovery.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -SingleVault -VaultName "TestVault" -SubscriptionName "12345678-1234-1234-1234-123456789abc"
    Run targeted diagnostics scan using a specific subscription ID for maximum precision and speed.
    Useful when you know the exact subscription GUID containing the target vault.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume
    Resume a previously interrupted audit. Will first check for checkpoint files,
    then automatically use master discovery file if no checkpoints are found.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial
    Generate reports from partial results. Will first check for checkpoint files,
    then automatically use master discovery file if no checkpoints are found.
    
.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial -CsvFilePath "C:\Reports\KeyVaultAudit_partial.csv"
    Generate reports from partial results by loading directly from a CSV file.
    Completely bypasses subscription discovery and access validation for maximum performance.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "./KeyVaultComprehensiveAudit_20250910-131119.csv"
    Generate HTML report directly from a specific CSV file. No Azure authentication required.
    Output will be marked as "PARTIAL RESULTS" and named with FROMCSV prefix.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv
    Generate HTML report from the latest KeyVaultComprehensiveAudit*.csv file in the output directory.
    Auto-detects the most recent CSV file if -CsvFilePath is not specified.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "results.csv" -MarkPartial:$false
    Generate HTML report from CSV without "PARTIAL RESULTS" marking.
    Useful for final reports from complete but interrupted audits.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume -Verbose
    Resume audit from a selected checkpoint with enhanced verbose logging.
    Shows comprehensive authentication flow detection, environment analysis, and checkpoint recovery details.
    Demonstrates new PSScriptAnalyzer-compliant verbose output system.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Verbose
    Run in test mode with comprehensive verbose logging to understand environment detection.
    Shows authentication method selection logic, environment variable analysis, and detailed decision reasoning.
    Useful for troubleshooting authentication issues and understanding environment detection.

.EXAMPLE
    # Environment-specific authentication examples:
    
    # Cloud Shell environment (auto-detected)
    .\Get-AKV_Roles-SecAuditCompliance.ps1  # Uses interactive browser authentication
    
    # Automation environment with service principal
    $env:AZURE_CLIENT_ID = "app-id"; $env:AZURE_TENANT_ID = "tenant-id"; $env:AZURE_CLIENT_SECRET = "secret"
    .\Get-AKV_Roles-SecAuditCompliance.ps1  # Uses service principal authentication automatically
    
    # Local development with verbose authentication flow
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Verbose  # Shows environment detection and authentication method selection

.EXAMPLE
    # Interruption handling and recovery examples:
    
    # Start audit (can be interrupted with CTRL-C)
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # Script handles interruption gracefully, saves checkpoint with interruption metadata
    
    # Resume from interruption checkpoint
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume
    # Detects interruption checkpoint, shows completion status and resume instructions

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -OutputDirectory "/custom/path"
    Run audit with custom output directory override.
    Enhanced error handling ensures directory creation and proper checkpoint management.

.EXAMPLE
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "./out/KeyVaultComprehensiveAudit_20250910-131119.csv"
    Generate HTML report from a specific CSV file with default MarkPartial behavior (marked as "PARTIAL RESULTS").
    This mode requires no Azure authentication and works completely offline.
    Enhanced report includes comprehensive partial results context and resume instructions.

.EXAMPLE
    # OPTIMIZED WORKFLOW EXAMPLES:
    
    # First run - creates master discovery file
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    
    # Subsequent runs using master file for optimized performance (no checkpoints needed)
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume          # ⚡ OPTIMIZED MODE: Uses master file, skips discovery
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial  # ⚡ OPTIMIZED MODE: Uses master file, skips discovery
    
    # Direct CSV processing (fastest option - no discovery at all)
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial -CsvFilePath "results.csv"

.EXAMPLE
    # Auto-Resume Scenarios:
    # Scenario 1: Manual interruption (CTRL+C)
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # Press CTRL+C during execution...
    # Script saves checkpoint and cancellation marker
    
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # On next run, script detects cancellation marker and prompts:
    # "Do you want to resume from your last checkpoint? (Y/N):"
    # Selecting Y automatically resumes from the last saved checkpoint

.EXAMPLE
    # Scenario 2: System crash or hang recovery
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # System crashes or script hangs...
    
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume
    # Script detects system recovery scenario and lists available checkpoints:
    # "SYSTEM RECOVERY MODE - Detected restart without manual cancellation marker"
    # Lists all available checkpoints with progress information for selection

.EXAMPLE
    # Scenario 3: Tenant authentication error handling with ManagedIdentityCredential fix
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # Script encounters ManagedIdentityCredential or tenant authentication errors
    # Enhanced detection of ExpiresOn token format issues with managed identity
    # Logs clear warnings: "Tenant authentication issue: tenant-id"
    # Provides specific guidance for managed identity ExpiresOn token format problems
    # Recommends alternative authentication methods (interactive or service principal)
    # Continues with accessible subscriptions and includes error details in final report

.EXAMPLE
    # Scenario 4: Generate partial reports without resuming analysis
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial
    # Lists available checkpoints and CSV files
    # Generates HTML/CSV reports from selected partial data
    # Reports clearly marked as "PARTIAL RESULTS" with original execution metadata

.EXAMPLE
    # Scenario 5: Resume with specific source priority and strict matching
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume -ResumeSourcePriority CSV -ResumeStrictMatch -StrictMatchThresholdPercent 70
    # Resume using only CSV data (ignore checkpoint) with strict 70% match requirement
    # Aborts if fewer than 70% of CSV identities match current discovery

.EXAMPLE  
    # Scenario 6: Resume with union of sources and relaxed diagnostics
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume -ResumeSourcePriority Union -UnmatchedLogCount 5 -Verbose
    # Use both checkpoint and CSV data (union) for maximum matching
    # Show only 5 unmatched entries per source in verbose diagnostics

.EXAMPLE
    # Scenario 7: Walk-away reliability with OneDrive upload integration
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # Audit automatically uploads checkpoint files every 25 vaults for continuity
    # Final reports (CSV, HTML, logs) uploaded to OneDrive upon completion
    # Device code authentication for Microsoft Graph API integration
    # All upload events logged with UTC timestamps and artifact URLs for resumability
    # Scenario 7: Azure Cloud Shell with automatic OneDrive/SharePoint upload
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -CloudUploadPath "/Documents/KeyVaultAudits"
    # Run full audit with automatic upload to OneDrive/SharePoint after completion
    # Uses device code authentication for seamless Azure Cloud Shell integration
    # All output files (CSV, HTML, logs) uploaded to the specified folder

.EXAMPLE
    # Scenario 8: Manual cloud upload prompt in Azure Cloud Shell
    .\Get-AKV_Roles-SecAuditCompliance.ps1
    # Run audit normally - script automatically detects Azure Cloud Shell
    # After completion, prompts user to upload files to OneDrive/SharePoint
    # Prevents data loss when Cloud Shell session expires

.EXAMPLE
    # Scenario 9: Test mode with cloud upload
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Limit 5 -UploadToCloud
    # Run test mode with 5 vaults and automatic cloud upload
    # Perfect for validating both audit functionality and upload integration

.EXAMPLE
    # Scenario 10: Partial results processing with cloud upload
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial -UploadToCloud -CloudUploadPath "/Shared Documents/Security/Audits"
    # Process partial results from checkpoints and upload to SharePoint team site
    # Useful for sharing incomplete audit results with team

.EXAMPLE
    # Scenario 11: App-only authentication for automated scenarios
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -GraphClientId "your-app-id" -GraphTenantId "your-tenant-id" -GraphClientSecret "your-secret"
    # Use app-only authentication for unattended execution
    # Perfect for scheduled audits in CI/CD pipelines

.EXAMPLE
    # Scenario 12: Environment variables for app authentication
    $env:AZURE_CLIENT_ID = "your-app-id"
    $env:AZURE_TENANT_ID = "your-tenant-id"  
    $env:AZURE_CLIENT_SECRET = "your-secret"
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud
    # Credentials automatically detected from environment variables
    # Secure way to provide app credentials

.EXAMPLE
    # Scenario 13: Enhanced automatic authentication with verbose logging
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -Verbose
    # Enables verbose logging to show detailed environment detection logic
    # Shows which environment variables were checked and which authentication method was selected
    # Automatically detects Cloud Shell, MSI, or service principal environments

.EXAMPLE
    # Scenario 14: Force specific Graph authentication mode
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -GraphAuthMode Interactive
    # Override automatic mode selection to force interactive browser authentication
    # Useful when you want browser auth even with app credentials available

.EXAMPLE
    # Scenario 15: Cloud Shell with device code authentication
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -GraphAuthMode DeviceCode
    # Explicitly use device code flow in Azure Cloud Shell
    # Alternative when interactive authentication has Conditional Access restrictions

.EXAMPLE
    # Scenario 16: Enhanced SharePoint permissions for site management
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -GraphScopeScenario Sites
    # Request enhanced SharePoint permissions including Sites.Manage.All
    # Useful when uploading to SharePoint sites requiring elevated permissions

.EXAMPLE
    # Scenario 17: Full enterprise permissions for comprehensive automation
    .\Get-AKV_Roles-SecAuditCompliance.ps1 -UploadToCloud -GraphScopeScenario Full -GraphAuthMode App -GraphClientId "app-id" -GraphTenantId "tenant-id"
    # Request comprehensive permissions including Directory.Read.All
    # Perfect for enterprise scenarios requiring user and directory information
    # Uses app-only authentication with provided credentials
    
.NOTES
    Auto-Resume & Error Handling Features:
    - Real-time CSV saving: Vault analyses saved immediately, no data loss on interruption
    - Checkpoint management: Automatic progress checkpoints every 10 vaults + final checkpoint
    - Graceful interruption: CTRL+C saves current progress and creates recovery marker
    - Auto-resume detection: Next run automatically detects and offers to resume
    - System recovery: Distinguishes between manual cancellation and system issues
    - Multi-checkpoint support: Interactive selection when multiple checkpoints exist
    - Tenant error handling: Gracefully handles ManagedIdentityCredential and tenant auth failures
    - ManagedIdentity fix: Enhanced token ExpiresOn format handling for managed identity authentication
    - Skip tracking: Detailed logging and reporting of skipped subscriptions with actionable guidance
    - Partial processing: Generate reports from incomplete audits at any time
    
    Optimized Performance Features:
    - Master file discovery: First run creates a master discovery file with all subscriptions and Key Vaults
    - Optimized resume: Resume operations automatically load from master file, skipping subscription discovery
    - Optimized partial processing: ProcessPartial operations use master file or CSV, bypassing discovery entirely
    - Smart bypass: When master files exist, subscription discovery and access validation are automatically skipped
    - Performance gains: Master file operations can reduce startup time from minutes to seconds
    - Clear messaging: Script clearly indicates when optimized mode is used vs full discovery

.LINK
    https://learn.microsoft.com/azure/key-vault/general/best-practices
    
.LINK
    https://learn.microsoft.com/security/benchmark/azure/
    
.LINK
    https://learn.microsoft.com/azure/key-vault/general/security-features
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Run in test mode with limited Key Vaults for validation")]
    [switch]$TestMode,
    
    [Parameter(HelpMessage = "Number of Key Vaults to test when in test mode. Default is 3")]
    [int]$Limit = 3,
    
    [Parameter(HelpMessage = "Resume audit from a selected checkpoint file")]
    [switch]$Resume,
    
    [Parameter(HelpMessage = "Process partial results from checkpoint/CSV file")]
    [switch]$ProcessPartial,
    
    [Parameter(HelpMessage = "CSV file path for ProcessPartial or ReportFromCsv modes")]
    [string]$CsvFilePath,
    
    [Parameter(HelpMessage = "Generate HTML report directly from CSV file")]
    [switch]$ReportFromCsv,
    
    [Parameter(HelpMessage = "Mark ReportFromCsv output as PARTIAL RESULTS")]
    [bool]$MarkPartial = $true,
    
    [Parameter(HelpMessage = "Enable strict CSV deduplication when resuming")]
    [switch]$ResumeCsvStrict,
    
    [Parameter(HelpMessage = "Override the default output directory")]
    [string]$OutputDirectory,
    
    [Parameter(HelpMessage = "Progress display mode: Session, Overall, or Both")]
    [ValidateSet('Session', 'Overall', 'Both')]
    [string]$ProgressMode = 'Session',
    
    [Parameter(HelpMessage = "Number of unmatched entries to log when resuming")]
    [int]$UnmatchedLogCount = 10,
    
    [Parameter(HelpMessage = "Enable automatic upload to OneDrive/SharePoint")]
    [switch]$UploadToCloud,
    
    [Parameter(HelpMessage = "Target folder path in OneDrive/SharePoint")]
    [string]$CloudUploadPath,
    
    [Parameter(HelpMessage = "Resume source priority: Checkpoint, CSV, or Union")]
    [ValidateSet('Checkpoint', 'CSV', 'Union')]
    [string]$ResumeSourcePriority = 'Union',
    
    [Parameter(HelpMessage = "Enable strict matching validation when resuming")]
    [switch]$ResumeStrictMatch,
    
    [Parameter(HelpMessage = "Minimum match percentage for strict matching (1-100)")]
    [ValidateRange(1, 100)]
    [int]$StrictMatchThresholdPercent = 60,
    
    [Parameter(HelpMessage = "Client ID for Microsoft Graph app-only authentication")]
    [string]$GraphClientId,
    
    [Parameter(HelpMessage = "Tenant ID for Microsoft Graph app-only authentication")]
    [string]$GraphTenantId,
    
    [Parameter(HelpMessage = "Client Secret for Microsoft Graph app-only authentication")]
    [string]$GraphClientSecret,
    
    [Parameter(HelpMessage = "Microsoft Graph authentication mode")]
    [ValidateSet('Interactive', 'App', 'DeviceCode', 'Auto')]
    [string]$GraphAuthMode = 'Auto',
    
    [Parameter(HelpMessage = "Microsoft Graph permission scope scenario")]
    [ValidateSet('Files', 'Sites', 'Full')]
    [string]$GraphScopeScenario = 'Files',
    
    [Parameter(HelpMessage = "Run targeted diagnostics scan for a single Key Vault")]
    [switch]$SingleVault,
    
    [Parameter(HelpMessage = "Key Vault name for single vault mode")]
    [string]$VaultName,
    
    [Parameter(HelpMessage = "Subscription name or ID for single vault mode")]
    [string]$SubscriptionName
)

# Enable strict mode for better error handling
Set-StrictMode -Version Latest

# Global variables for tracking execution context
$global:startTime = Get-Date
$global:RunspaceId = [System.Guid]::NewGuid().ToString()
$global:ScriptExecutionContext = @{
    StartTime = $global:startTime
    RunspaceId = $global:RunspaceId
    IsInterrupted = $false
    EnvironmentDetection = @{}
    AuthenticationFlow = @{}
    InterruptionHandlers = @()
}

# Initialize critical global variables early for defensive programming
$global:dataIssuesPath = $null
$global:errPath = $null  
$global:permissionsPath = $null
$SCRIPT_VERSION = "2.2"
$userAgent = if ($env:AZURE_HTTP_USER_AGENT) { $env:AZURE_HTTP_USER_AGENT } else { "PowerShell/$($PSVersionTable.PSVersion.ToString())" }

# Defensive: Always declare $diagnostics at the top to guarantee it exists in all code paths
$diagnostics = $null

# Enable strict mode for better error handling
Set-StrictMode -Version Latest

# Global variables for tracking execution context
$global:startTime = Get-Date
$global:RunspaceId = [System.Guid]::NewGuid().ToString()
$global:ScriptExecutionContext = @{
    StartTime = $global:startTime
    RunspaceId = $global:RunspaceId
    IsInterrupted = $false
    EnvironmentDetection = @{}
    AuthenticationFlow = @{}
    InterruptionHandlers = @()
}

# Initialize critical global variables early for defensive programming
$global:dataIssuesPath = $null
$global:errPath = $null  
$global:permissionsPath = $null
$SCRIPT_VERSION = "2.2"
$userAgent = if ($env:AZURE_HTTP_USER_AGENT) { $env:AZURE_HTTP_USER_AGENT } else { "PowerShell/$($PSVersionTable.PSVersion.ToString())" }

# Standardized user message function for consistent output
function Write-UserMessage {
    <#
    .SYNOPSIS
    Standardized message output function that respects Verbose and Debug preferences
    .DESCRIPTION
    Provides consistent message output across the script with appropriate handling for different message types.
    Info and Progress messages are suppressed unless -Verbose is active to reduce console clutter.
    Error, Warning, and Success messages are always shown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug', 'Progress', 'Verbose')]
        [string]$Type = 'Info'
    )

    # Handle different message types with appropriate output methods
    switch ($Type) {
        'Error' {
            # Errors always shown
            Write-Error -Message $Message
        }
        'Warning' {
            # Warnings always shown
            Write-Warning $Message
        }
        'Success' {
            # Success messages always shown
            Write-Host $Message -ForegroundColor Green
        }
        'Debug' {
            # Debug messages only shown when -Debug is active
            Write-Debug -Message $Message
        }
        'Verbose' {
            # Verbose messages only shown when -Verbose is active
            Write-Verbose $Message
        }
        'Progress' {
            # Progress messages shown when verbose or as Write-Progress
            if ($VerbosePreference -eq 'Continue') {
                Write-Host "Progress: $Message" -ForegroundColor Cyan
            }
            Write-Progress -Activity "Auditing Key Vaults" -Status $Message
        }
        'Info' {
            # Info messages only shown when verbose is active, otherwise suppressed to reduce output
            if ($VerbosePreference -eq 'Continue') {
                Write-Host $Message -ForegroundColor Gray
            }
        }
        default {
            # Default to info behavior
            if ($VerbosePreference -eq 'Continue') {
                Write-Host $Message -ForegroundColor White
            }
        }
    }
}

# Helper function for safe property access in PowerShell 7
function Get-SafeProperty {
    param($Object, $PropertyName, $DefaultValue = 'N/A')
    if ($null -eq $Object) { return $DefaultValue }
    try {
        # Use safer property access for PowerShell 7
        if ($Object -is [array] -and $PropertyName -eq 'Count') {
            return $Object.Count
        }
        if ($Object.PSObject -and $Object.PSObject.Properties -and $Object.PSObject.Properties[$PropertyName]) {
            $value = $Object.$PropertyName
            if ([string]::IsNullOrWhiteSpace($value)) { 
                return $DefaultValue 
            } else { 
                return $value 
            }
        } else {
            return $DefaultValue
        }
    } catch {
        return $DefaultValue
    }
}

# Helper function for safe count access - prevents "Count property not found" errors
function Get-SafeCount {
    <#
    .SYNOPSIS
    Safely get the count of items in a collection, handling nulls and single objects
    .DESCRIPTION
    PowerShell Where-Object returns single objects (not arrays) when only one item matches.
    This causes ".Count" to fail since single objects don't have a Count property.
    This function handles:
    - Null objects (returns 0)
    - Arrays (returns Count)
    - Single objects (returns 1)
    - Objects with Count property (returns Count)
    .PARAMETER Object
    The object to count
    .EXAMPLE
    Get-SafeCount $results
    Returns the count safely, whether $results is null, a single object, or an array
    #>
    param($Object)
    
    if ($null -eq $Object) { 
        return 0 
    }
    
    try {
        # If it's an array or collection with Count property
        if ($Object -is [array]) {
            return $Object.Count
        }
        # Check if the object has a Count property
        if ($Object.PSObject.Properties['Count']) {
            return $Object.Count
        }
        # If it's a single object (not null), count is 1
        return 1
    } catch {
        return 0
    }
}

function Write-VerboseEnvironmentInfo {
    <#
    .SYNOPSIS
    Write detailed environment detection information with verbose logging
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$DetectionResults,
        
        [Parameter()]
        [string]$DetectionType = "Environment"
    )
    
    Write-UserMessage -Message "$DetectionType Detection Results:" -Type Debug
    
    foreach ($key in $DetectionResults.Keys) {
        $value = $DetectionResults[$key]
        if ($value -is [hashtable]) {
            Write-UserMessage -Message "  ${key}:" -Type Debug
            foreach ($subKey in $value.Keys) {
                $subValue = $value[$subKey]
                if ($subValue -is [bool]) {
                    $displayValue = if ($subValue) { "YES" } else { "NO" }
                } else {
                    $displayValue = if ($subValue) { $subValue } else { "not set" }
                }
                Write-UserMessage -Message "    $subKey = $displayValue" -Type Debug
            }
        } else {
            $displayValue = if ($value -is [bool]) { 
                if ($value) { "YES" } else { "NO" } 
            } else { 
                if ($value) { $value } else { "not set" } 
            }
            Write-UserMessage -Message "  $key = $displayValue" -Type Debug
        }

    } catch {
        Write-UserMessage -Message "Error generating comprehensive HTML report: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Register-InterruptionHandler {
    <#
    .SYNOPSIS
    Register a cleanup function to be called on script interruption
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Handler,
        
        [Parameter()]
        [string]$Name
    )
    
    $handlerName = $Name
    if (-not $handlerName) {
        $handlerName = "Handler_$(Get-Date -Format 'HHmmss')"
    }
    $handlerInfo = @{
        Handler = $Handler
        Name = $handlerName
        RegisteredAt = (Get-Date)
    }
    if (-not $global:ScriptExecutionContext.InterruptionHandlers) {
        $global:ScriptExecutionContext.InterruptionHandlers = @()
    }
    $global:ScriptExecutionContext.InterruptionHandlers += $handlerInfo
    Write-Verbose "Registered interruption handler: $($handlerInfo.Name)"
}

# Set up global interruption handling
    $global:OriginalCtrlCHandler = $null
    $global:ScriptExecutionContext.IsInterrupted = $false
try {
    # Check if CancelKeyPress property exists before trying to access it
    if ([console] | Get-Member -Name "CancelKeyPress" -MemberType Property -Static) {
        # Register CTRL+C handler for graceful interruption
        $global:OriginalCtrlCHandler = [console]::CancelKeyPress
        [console]::CancelKeyPress = {
            param($e)
            
            Write-UserMessage -Message "Interruption detected (CTRL+C). Initiating graceful shutdown..." -Type Warning
            $global:ScriptExecutionContext.IsInterrupted = $true
            $e.Cancel = $true  # Prevent immediate termination
            
            # Execute registered interruption handlers
            foreach ($handlerInfo in $global:ScriptExecutionContext.InterruptionHandlers) {
                try {
                    Write-UserMessage -Message "Executing cleanup handler: $($handlerInfo.Name)" -Type Debug
                    & $handlerInfo.Handler
                } catch {
                    Write-UserMessage -Message "Error in cleanup handler $($handlerInfo.Name): $($_.Exception.Message)" -Type Error
                }
            }
            
            Write-UserMessage -Message "Graceful shutdown completed. Script execution halted." -Type Warning
            exit 0
        }
    } else {
        Write-UserMessage -Message "CancelKeyPress property not available in this PowerShell host. CTRL+C handling will use default behavior." -Type Warning
    }
} catch {
    Write-Warning "Could not register CTRL+C handler: $($_.Exception.Message)"
}

# --- Microsoft Graph Upload Functions ---

function Install-MSALModule {
    <#
    .SYNOPSIS
    Install MSAL.PS module if not available
    .DESCRIPTION
    Checks for and installs the MSAL.PS module required for Microsoft Graph authentication.
    Uses the new standardized output system for consistent messaging.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-UserMessage -Message "Checking for MSAL.PS module..." -Type Info
        $msalModule = Get-Module -ListAvailable -Name MSAL.PS
        
        if (-not $msalModule) {
            Write-UserMessage -Message "Installing MSAL.PS module for Microsoft Graph authentication..." -Type Progress
            Install-Module -Name MSAL.PS -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-UserMessage -Message "MSAL.PS module installed successfully" -Type Success
        } else {
            Write-UserMessage -Message "MSAL.PS module is already available" -Type Success
        }
        
        Import-Module MSAL.PS -Force -ErrorAction Stop
        return $true
    } catch {
        Write-UserMessage -Message "Failed to install/import MSAL.PS module: $($_.Exception.Message)" -Type Error
        Write-ErrorLog "GraphUpload" "Failed to install MSAL.PS module: $($_.Exception.Message)"
        return $false
    }
}


function Install-GraphModule {
    <#
    .SYNOPSIS
    Install Microsoft.Graph PowerShell modules if not available
    .DESCRIPTION
    Checks for and installs required Microsoft Graph PowerShell modules.
    Uses the new standardized output system for consistent messaging.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-UserMessage -Message "Checking for Microsoft Graph PowerShell modules..." -Type Info
        
        $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Files')
        $missingModules = @()
        
        foreach ($module in $requiredModules) {
            $graphModule = Get-Module -ListAvailable -Name $module
            if (-not $graphModule) {
                $missingModules += $module
            } else {
                Write-UserMessage -Message "$module is already available" -Type Success
            }
        }
        
        if ($missingModules.Count -gt 0) {
            Write-UserMessage -Message "Installing Microsoft Graph modules: $($missingModules -join ', ')..." -Type Progress
            Install-Module -Name $missingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-UserMessage -Message "Microsoft Graph modules installed successfully" -Type Success
        } else {
            Write-UserMessage -Message "All required Microsoft Graph modules are available" -Type Success
        }
        
        # Import the modules
        foreach ($module in $requiredModules) {
            Import-Module $module -Force -ErrorAction Stop
        }
        
        return $true
    } catch {
        Write-UserMessage -Message "Failed to install/import Microsoft Graph modules: $($_.Exception.Message)" -Type Error
        Write-ErrorLog "GraphAuth" "Failed to install Microsoft Graph modules: $($_.Exception.Message)"
        return $false
    }
}

function Test-CloudShellEnvironment {
    <#
    .SYNOPSIS
    Detect if running in Azure Cloud Shell environment with enhanced detection logic and verbose logging
    .DESCRIPTION
    Checks multiple environment variables and system indicators to reliably detect Azure Cloud Shell.
    Provides comprehensive logging for authentication flow mapping and troubleshooting.
    
    Detection Methods (in priority order):
    1. $env:CLOUD_SHELL (dedicated Cloud Shell indicator)
    2. $env:ACC_CLOUD (Azure Cloud Shell context flag)  
    3. $env:AZUREPS_HOST_ENVIRONMENT (PowerShell host environment)
    4. $env:ACC_OID and $env:ACC_TID (Cloud Shell user identifiers)
    5. File system and binary presence indicators (Linux paths, az CLI)
    
    Authentication Flow Implications:
    - Cloud Shell detected → Interactive authentication preferred
    - Local environment → Interactive with device code fallback
    - Comprehensive logging supports authentication troubleshooting
    #>
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = "Suppress user-facing output messages")]
        [switch]$Quiet
    )
    
    try {
        $detectionResults = @{}
        
        Write-UserMessage "Starting Azure Cloud Shell environment detection..." -Type Verbose
        
        # Enhanced Cloud Shell indicators with comprehensive tracking
        $cloudShellChecks = @{
            'CLOUD_SHELL_ENV' = ($env:CLOUD_SHELL -eq '1' -or $env:CLOUD_SHELL -eq 'true')
            'ACC_CLOUD_ENV' = ($env:ACC_CLOUD -eq '1')
            'SHELL_CLOUDSHELL' = ($env:SHELL -match "cloudshell")
            'AZUREPS_HOST_ENV' = ($env:AZUREPS_HOST_ENVIRONMENT -eq "cloud-shell")
            'ACC_IDENTIFIERS' = ($env:ACC_OID -and $env:ACC_TID)
            'FILESYSTEM_INDICATORS' = ($PWD.Path.StartsWith('/home/') -and (Test-Path '/usr/bin/az' -ErrorAction SilentlyContinue))
        }
        
        # Collect all environment variables for verbose logging and troubleshooting
        $envVarsChecked = @{
            'CLOUD_SHELL' = $env:CLOUD_SHELL
            'ACC_CLOUD' = $env:ACC_CLOUD
            'SHELL' = $env:SHELL
            'AZUREPS_HOST_ENVIRONMENT' = $env:AZUREPS_HOST_ENVIRONMENT
            'ACC_OID' = if ($env:ACC_OID) { "***present***" } else { $null }
            'ACC_TID' = if ($env:ACC_TID) { "***present***" } else { $null }
            'PWD' = $PWD.Path
            'AZ_CLI_PATH' = if (Test-Path '/usr/bin/az' -ErrorAction SilentlyContinue) { "/usr/bin/az exists" } else { "not found" }
        }
        
        $detectionResults['EnvironmentVariables'] = $envVarsChecked
        $detectionResults['CheckResults'] = $cloudShellChecks
        
        # Determine if we're in Cloud Shell based on indicators
        $isCloudShell = $cloudShellChecks.Values -contains $true
        $detectionResults['IsCloudShell'] = $isCloudShell
        
        # Identify which specific indicators matched for debugging
        $matchedIndicators = $cloudShellChecks.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key }
        $detectionResults['MatchedIndicators'] = $matchedIndicators
        
        # Store detection results in global context for authentication flow reference
        $global:ScriptExecutionContext.EnvironmentDetection.CloudShell = $detectionResults
        
        # User-facing output and verbose logging
        if (-not $Quiet) {
            if ($isCloudShell) {
                Write-UserMessage -Message "Azure Cloud Shell environment detected" -Type Success
                Write-UserMessage "Cloud Shell detection successful. Matched indicators: $($matchedIndicators -join ', ')" -Type Verbose
                
                # Show authentication flow implications
                Write-UserMessage -Message "Authentication Flow: Interactive authentication will be used" -Type Info
                
                if ($VerbosePreference -eq 'Continue' -and $matchedIndicators.Count -gt 0) {
                    Write-UserMessage -Message "Matched indicators: $($matchedIndicators -join ', ')" -Type Debug
                }
            } else {
                Write-UserMessage -Message "Local environment detected" -Type Info
                Write-UserMessage "Local environment detection. No Cloud Shell indicators found." -Type Verbose
                
                # Show authentication flow implications
                Write-UserMessage -Message "Authentication Flow: Interactive with device code fallback" -Type Info
                
                if ($VerbosePreference -eq 'Continue') {
                    Write-UserMessage -Message "No Cloud Shell indicators found" -Type Debug
                }
            }
        }
        
        # Verbose environment information logging
        if ($VerbosePreference -eq 'Continue') {
            Write-VerboseEnvironmentInfo -DetectionResults $detectionResults -DetectionType "Cloud Shell"
        }
        
        Write-UserMessage "Cloud Shell environment detection completed. Result: $isCloudShell" -Type Verbose
        return $isCloudShell
        
    } catch {
        $errorMessage = "Environment detection failed: $($_.Exception.Message)"
        Write-UserMessage $errorMessage -Type Verbose
        
        if (-not $Quiet) {
            Write-UserMessage -Message "Environment detection failed, assuming local environment" -Type Warning
            if ($VerbosePreference -eq 'Continue') {
                Write-UserMessage -Message "Error: $($_.Exception.Message)" -Type Debug
            }
        }
        
        # Store error information for troubleshooting
        $global:ScriptExecutionContext.EnvironmentDetection.CloudShell = @{
            IsCloudShell = $false
            Error = $_.Exception.Message
            Timestamp = Get-Date
        }
        
        return $false
    }
}

function Test-ManagedIdentityEnvironment {
    <#
    .SYNOPSIS
    Detect if running in a Managed Service Identity (MSI) or automation environment with enhanced logging
    .DESCRIPTION
    Checks multiple environment variables and Azure context to detect MSI/automation environments.
    Provides comprehensive logging for authentication flow mapping and troubleshooting.
    
    Detection Methods (in priority order):
    1. $env:MSI_ENDPOINT, $env:MSI_SECRET (legacy MSI indicators)
    2. $env:IDENTITY_ENDPOINT, $env:IDENTITY_HEADER (IMDS v2 indicators)
    3. $env:AZURE_CLIENT_ID (service principal/MSI client ID)
    4. $env:AZURE_HTTP_USER_AGENT (automation context indicators)
    5. Az.Accounts context analysis for managed identity authentication
    
    Authentication Flow Implications:
    - MSI detected with credentials → App-only authentication preferred
    - MSI detected without credentials → Device code authentication
    - No MSI detected → Interactive authentication with fallbacks
    - Comprehensive logging supports authentication troubleshooting
    #>
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = "Suppress user-facing output messages")]
        [switch]$Quiet
    )
    
    try {
        $detectionResults = @{}
        
        Write-UserMessage "Starting Managed Identity environment detection..." -Type Verbose
        
        # Enhanced MSI/automation environment checks with comprehensive tracking
        $msiChecks = @{
            'MSI_ENDPOINT' = (-not [string]::IsNullOrWhiteSpace($env:MSI_ENDPOINT))
            'MSI_SECRET' = (-not [string]::IsNullOrWhiteSpace($env:MSI_SECRET))
            'IDENTITY_ENDPOINT' = (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT))
            'IDENTITY_HEADER' = (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER))
            'AZURE_CLIENT_ID' = (-not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_ID))
            'AZURE_TENANT_ID' = (-not [string]::IsNullOrWhiteSpace($env:AZURE_TENANT_ID))
            'AZURE_CLIENT_SECRET' = (-not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_SECRET))
            'AZURE_HTTP_USER_AGENT' = ($env:AZURE_HTTP_USER_AGENT -like "*automation*" -or $env:AZURE_HTTP_USER_AGENT -like "*runbook*")
        }
        
        # Check Azure context for managed identity indicators
        try {
            $context = Get-AzContext -ErrorAction SilentlyContinue
            $msiChecks['AZ_CONTEXT_MSI'] = ($context -and $context.Account -and $context.Account.Type -eq "ManagedService")
            
            # Store context information for verbose logging
            if ($context) {
                $detectionResults['AzContext'] = @{
                    AccountType = $context.Account.Type
                    AccountId = $context.Account.Id
                    TenantId = $context.Tenant.Id
                }
            }
        } catch {
            $msiChecks['AZ_CONTEXT_MSI'] = $false
            Write-UserMessage "Failed to check Az.Accounts context: $($_.Exception.Message)" -Type Verbose
        }
        
        # Collect all environment variables for verbose logging and troubleshooting
        $envVarsChecked = @{
            'MSI_ENDPOINT' = if ($env:MSI_ENDPOINT) { "***present***" } else { $null }
            'MSI_SECRET' = if ($env:MSI_SECRET) { "***present***" } else { $null }
            'IDENTITY_ENDPOINT' = if ($env:IDENTITY_ENDPOINT) { "***present***" } else { $null }
            'IDENTITY_HEADER' = if ($env:IDENTITY_HEADER) { "***present***" } else { $null }
            'AZURE_CLIENT_ID' = if ($env:AZURE_CLIENT_ID) { $env:AZURE_CLIENT_ID } else { $null }
            'AZURE_TENANT_ID' = if ($env:AZURE_TENANT_ID) { $env:AZURE_TENANT_ID } else { $null }
            'AZURE_CLIENT_SECRET' = if ($env:AZURE_CLIENT_SECRET) { "***present***" } else { $null }
            'AZURE_HTTP_USER_AGENT' = $env:AZURE_HTTP_USER_AGENT
        }
        
        $detectionResults['EnvironmentVariables'] = $envVarsChecked
        $detectionResults['CheckResults'] = $msiChecks
        
        # Determine if we have managed identity based on indicators
        $hasManagedIdentity = $msiChecks.Values -contains $true
        $detectionResults['HasManagedIdentity'] = $hasManagedIdentity
        
        # Identify which specific indicators matched for debugging
        $matchedIndicators = $msiChecks.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key }
        $detectionResults['MatchedIndicators'] = $matchedIndicators
        
        # Determine authentication capability
        $hasCompleteCredentials = ($env:AZURE_CLIENT_ID -and $env:AZURE_TENANT_ID -and $env:AZURE_CLIENT_SECRET)
        $detectionResults['HasCompleteCredentials'] = $hasCompleteCredentials
        
        # Store detection results in global context for authentication flow reference
        $global:ScriptExecutionContext.EnvironmentDetection.ManagedIdentity = $detectionResults
        
        # User-facing output and verbose logging
        if (-not $Quiet) {
            if ($hasManagedIdentity) {
                Write-UserMessage -Message "Managed Identity/Automation environment detected" -Type Success
                Write-UserMessage "MSI detection successful. Matched indicators: $($matchedIndicators -join ', ')" -Type Verbose
                
                # Show authentication flow implications
                if ($hasCompleteCredentials) {
                    Write-UserMessage -Message "Authentication Flow: App-only authentication available" -Type Info
                } else {
                    Write-UserMessage -Message "Authentication Flow: Device code authentication recommended" -Type Info
                }
                
                if ($VerbosePreference -eq 'Continue' -and $matchedIndicators.Count -gt 0) {
                    Write-UserMessage -Message "Matched indicators: $($matchedIndicators -join ', ')" -Type Debug
                }
            } else {
                if ($VerbosePreference -eq 'Continue') {
                    Write-UserMessage -Message "No Managed Identity indicators found" -Type Debug
                }
            }
        }
        
        # Verbose environment information logging
        if ($VerbosePreference -eq 'Continue') {
            Write-VerboseEnvironmentInfo -DetectionResults $detectionResults -DetectionType "Managed Identity"
        }
        
        Write-UserMessage "Managed Identity environment detection completed. Result: $hasManagedIdentity" -Type Verbose
        return $hasManagedIdentity
        
    } catch {
        $errorMessage = "MSI environment detection failed: $($_.Exception.Message)"
        Write-UserMessage $errorMessage -Type Verbose
        
        if (-not $Quiet) {
            Write-UserMessage -Message "MSI environment detection failed" -Type Warning
            if ($VerbosePreference -eq 'Continue') {
                Write-UserMessage -Message "Error: $($_.Exception.Message)" -Type Debug
            }
        }
        
        # Store error information for troubleshooting
        $global:ScriptExecutionContext.EnvironmentDetection.ManagedIdentity = @{
            HasManagedIdentity = $false
            Error = $_.Exception.Message
            Timestamp = Get-Date
        }
        
        return $false
    }
}

function Get-GraphCredentialsFromEnvironment {
    <#
    .SYNOPSIS
    Get Graph authentication credentials from environment variables or parameters
    #>
    param(
        [string]$ClientId,
        [string]$TenantId, 
        [string]$ClientSecret
    )
    
    $credentials = @{
        ClientId = $ClientId
        TenantId = $TenantId
        ClientSecret = $ClientSecret
    }
    
    # Check environment variables if parameters not provided
    if ([string]::IsNullOrWhiteSpace($credentials.ClientId)) {
        $credentials.ClientId = $env:AZURE_CLIENT_ID
    }
    
    if ([string]::IsNullOrWhiteSpace($credentials.TenantId)) {
        $credentials.TenantId = $env:AZURE_TENANT_ID
    }
    
    if ([string]::IsNullOrWhiteSpace($credentials.ClientSecret)) {
        $credentials.ClientSecret = $env:AZURE_CLIENT_SECRET
    }
    
    # Check if we have complete app credentials
    $hasAppCredentials = -not [string]::IsNullOrWhiteSpace($credentials.ClientId) -and
                        -not [string]::IsNullOrWhiteSpace($credentials.TenantId) -and  
                        -not [string]::IsNullOrWhiteSpace($credentials.ClientSecret)
    
    return @{
        Credentials = $credentials
        HasAppCredentials = $hasAppCredentials
    }
}

function Get-GraphAuthenticationContext {
    <#
    .SYNOPSIS
    Collect comprehensive context information for Microsoft Graph authentication troubleshooting
    #>
    param(
        [string]$ClientId,
        [string]$TenantId,
        [string]$ClientSecret
    )
    
    $context = @{}
    
    # Environment Variables Context
    $context['EnvironmentVariables'] = @{
        'AZURE_CLIENT_ID' = if ($env:AZURE_CLIENT_ID) { "***present***" } else { "not set" }
        'AZURE_TENANT_ID' = if ($env:AZURE_TENANT_ID) { "***present***" } else { "not set" }
        'AZURE_CLIENT_SECRET' = if ($env:AZURE_CLIENT_SECRET) { "***present***" } else { "not set" }
        'AZURE_AUTHORITY_HOST' = $env:AZURE_AUTHORITY_HOST
        'AZURE_ENVIRONMENT' = $env:AZURE_ENVIRONMENT
        'MSI_ENDPOINT' = if ($env:MSI_ENDPOINT) { "***present***" } else { "not set" }
        'IDENTITY_ENDPOINT' = if ($env:IDENTITY_ENDPOINT) { "***present***" } else { "not set" }
        'IMDS_ENDPOINT' = if ($env:IMDS_ENDPOINT) { "***present***" } else { "not set" }
    }
    
    # Azure PowerShell Context
    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $context['AzContext'] = @{
                'Account' = $azContext.Account.Id
                'TenantId' = $azContext.Tenant.Id
                'SubscriptionId' = $azContext.Subscription.Id
                'Environment' = $azContext.Environment.Name
                'AuthenticationType' = $azContext.Account.Type
            }
        } else {
            $context['AzContext'] = @{
                'Status' = 'No active Azure PowerShell context'
            }
        }
    } catch {
        $context['AzContext'] = @{
            'Error' = "Failed to get Az context: $($_.Exception.Message)"
        }
    }
    
    # Provided Credentials Context (without exposing secrets)
    $context['ProvidedCredentials'] = @{
        'ClientId' = if ($ClientId) { "provided" } else { "not provided" }
        'TenantId' = if ($TenantId) { "provided" } else { "not provided" }
        'ClientSecret' = if ($ClientSecret) { "provided" } else { "not provided" }
    }
    
    # Cloud Shell and Environment Detection
    try {
        $envDetection = Test-CloudShellEnvironment -Quiet -Verbose
        if ($global:LastEnvironmentDetection) {
            $context['EnvironmentDetection'] = $global:LastEnvironmentDetection
        } else {
            $context['EnvironmentDetection'] = @{
                'IsCloudShell' = $envDetection
                'DetectionMethod' = 'Basic detection only'
            }
        }
    } catch {
        $context['EnvironmentDetection'] = @{
            'Error' = "Environment detection failed: $($_.Exception.Message)"
        }
    }
    
    # Module Availability
    $context['ModuleAvailability'] = @{
        'MSAL.PS' = if (Get-Module -ListAvailable -Name 'MSAL.PS' -ErrorAction SilentlyContinue) { "available" } else { "not available" }
        'Microsoft.Graph.Authentication' = if (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' -ErrorAction SilentlyContinue) { "available" } else { "not available" }
        'Microsoft.Graph.Files' = if (Get-Module -ListAvailable -Name 'Microsoft.Graph.Files' -ErrorAction SilentlyContinue) { "available" } else { "not available" }
    }
    
    return $context
}

function Get-GraphScopesForScenario {
    <#
    .SYNOPSIS
    Get appropriate Microsoft Graph scopes for different SharePoint/OneDrive scenarios
    #>
    param(
        [ValidateSet('Files', 'Sites', 'Full')]
        [string]$Scenario = 'Files'
    )
    switch ($Scenario) {
        'Files' {
            # Basic file operations in OneDrive/SharePoint
            return @(
                "Files.ReadWrite.All",
                "Sites.ReadWrite.All"
            )
        }
        'Sites' {
            # Enhanced SharePoint site operations
            return @(
                "Files.ReadWrite.All",
                "Sites.ReadWrite.All",
                "Sites.Manage.All",
                "Sites.FullControl.All"
            )
        }
        'Full' {
            # Full control scenario
            return @(
                "Files.ReadWrite.All",
                "Sites.ReadWrite.All",
                "Sites.Manage.All",
                "Sites.FullControl.All",
                "User.Read",
                "Directory.Read.All"
            )
        }
        default {
            return @("Files.ReadWrite.All")
        }
    }
}

function Invoke-InteractiveAuthenticationPrompt {
    <#
    .SYNOPSIS
    Interactive prompt to guide users through Microsoft Graph authentication options when automatic methods fail
    #>
    param(
        [string]$FailedMethod,
        [string]$FailureReason,
        [bool]$HasAppCredentials = $false,
        [bool]$IsCloudShell = $false
    )
    
    Write-Host ""
    Write-Host "🔐 Microsoft Graph Authentication Assistance" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "❌ The automatic authentication method ($FailedMethod) failed:" -ForegroundColor Red
    Write-Host "   $FailureReason" -ForegroundColor Red
    Write-Host ""
    
    # Provide context-aware guidance
    Write-Host "📋 Available authentication options:" -ForegroundColor White
    Write-Host ""
    
    $options = @()
    $descriptions = @()
    
    # Device Code option (always available if MSAL.PS can be installed)
    $options += "1"
    $descriptions += @{
        Number = "1"
        Title = "Device Code Authentication"
        Description = "Uses a device code that you enter on another device/browser"
        Recommendation = if ($IsCloudShell) { "✅ RECOMMENDED for Azure Cloud Shell" } else { "✅ RECOMMENDED for automation scenarios" }
        Instructions = "You'll get a code to enter at https://microsoft.com/devicelogin"
    }
    
    # Interactive Browser option (if not in Cloud Shell)
    if (-not $IsCloudShell) {
        $options += "2"
        $descriptions += @{
            Number = "2"
            Title = "Interactive Browser Authentication"
            Description = "Opens a browser window for sign-in"
            Recommendation = "✅ RECOMMENDED for local development"
            Instructions = "A browser window will open for you to sign in"
        }
    }
    
    # App-only option (if credentials available)
    if ($HasAppCredentials) {
        $optionNum = if ($IsCloudShell) { "2" } else { "3" }
        $options += $optionNum
        $descriptions += @{
            Number = $optionNum
            Title = "Retry App-Only Authentication"
            Description = "Retry using the provided application credentials"
            Recommendation = "⚠️ Only if you believe the previous failure was temporary"
            Instructions = "Will retry with the same credentials that just failed"
        }
    }
    
    # Display options
    foreach ($desc in $descriptions) {
        Write-Host "[$($desc.Number)] $($desc.Title)" -ForegroundColor Yellow
        Write-Host "    $($desc.Description)" -ForegroundColor Gray
        Write-Host "    $($desc.Recommendation)" -ForegroundColor $(if ($desc.Recommendation.StartsWith("✅")) { "Green" } else { "Yellow" })
        Write-Host "    💡 $($desc.Instructions)" -ForegroundColor Cyan
        Write-Host ""
    }
    
    # Skip option
    $skipOption = ($descriptions.Count + 1).ToString()
    Write-Host "[$skipOption] Skip Microsoft Graph authentication" -ForegroundColor Yellow
    Write-Host "    Continue without OneDrive/SharePoint upload functionality" -ForegroundColor Gray
    Write-Host "    ⚠️ Files will only be saved locally" -ForegroundColor Yellow
    Write-Host ""
    
    # Get user choice
    do {
        $choice = Read-Host "Please select an option [1-$skipOption]"
        $validChoice = $choice -in ($options + $skipOption)
        if (-not $validChoice) {
            Write-Host "⚠️ Invalid choice. Please enter a number between 1 and $skipOption." -ForegroundColor Red
        }
    } while (-not $validChoice)
    
    # Map choice to authentication method
    if ($choice -eq $skipOption) {
        return @{
            Method = "Skip"
            Description = "User chose to skip Graph authentication"
        }
    }
    
    $selectedDescription = $descriptions | Where-Object { $_.Number -eq $choice }
    
    switch ($selectedDescription.Title) {
        "Device Code Authentication" {
            return @{
                Method = "DeviceCode"
                Description = "User selected device code authentication"
            }
        }
        "Interactive Browser Authentication" {
            return @{
                Method = "Interactive"
                Description = "User selected interactive browser authentication"
            }
        }
        "Retry App-Only Authentication" {
            return @{
                Method = "App"
                Description = "User chose to retry app-only authentication"
            }
        }
        default {
            return @{
                Method = "Skip"
                Description = "Unable to determine authentication method"
            }
        }
    }
}

function Test-GraphAuthenticationPrerequisites {
    <#
    .SYNOPSIS
    Test that required modules and environment are ready for Graph authentication with enhanced logging
    #>
    [CmdletBinding()]
    param(
        [string]$AuthMode
    )
    
    $prerequisites = @{
        Success = $true
        Messages = @()
        Warnings = @()
        DetectedCapabilities = @()
    }
    
    try {
        $verboseEnabled = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
        if ($verboseEnabled) {
            Write-Host "🔍 Checking Microsoft Graph authentication prerequisites..." -ForegroundColor Cyan
        }
        
        # Test Microsoft Graph modules for Interactive and App modes
        if ($AuthMode -in @('Interactive', 'App', 'Auto')) {
            $graphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Files')
            foreach ($module in $graphModules) {
                $moduleAvailable = Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue
                if ($moduleAvailable) {
                    $prerequisites.Messages += "Microsoft Graph module '$module' is available (v$($moduleAvailable[0].Version))"
                    $prerequisites.DetectedCapabilities += "GraphModule-$($module.Replace('Microsoft.Graph.',''))"
                    if ($verboseEnabled) {
                        Write-Host "   ✅ $module available (v$($moduleAvailable[0].Version))" -ForegroundColor Green
                    }
                } else {
                    $prerequisites.Warnings += "Microsoft Graph module '$module' not installed - will attempt auto-installation"
                    if ($verboseEnabled) {
                        Write-Host "   ⚠️ $module not available - will attempt auto-installation" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Test MSAL.PS for DeviceCode mode
        if ($AuthMode -in @('DeviceCode', 'Auto')) {
            $msalModule = Get-Module -ListAvailable -Name MSAL.PS -ErrorAction SilentlyContinue
            if ($msalModule) {
                $prerequisites.Messages += "MSAL.PS module is available (v$($msalModule[0].Version))"
                $prerequisites.DetectedCapabilities += "MSAL.PS"
                if ($verboseEnabled) {
                    Write-Host "   ✅ MSAL.PS available (v$($msalModule[0].Version))" -ForegroundColor Green
                }
            } else {
                $prerequisites.Warnings += "MSAL.PS module not installed - will attempt auto-installation"
                if ($verboseEnabled) {
                    Write-Host "   ⚠️ MSAL.PS not available - will attempt auto-installation" -ForegroundColor Yellow
                }
            }
        }
        
        # Test environment variables and provide detailed analysis
        $envVars = @('AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET')
        $envVarsPresent = 0
        $envDetails = @()
        
        foreach ($var in $envVars) {
            $envItem = Get-Item "env:$var" -ErrorAction SilentlyContinue
            $value = if ($envItem) { $envItem.Value } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $envVarsPresent++
                $envDetails += "$var (present)"
                if ($verboseEnabled) {
                    Write-Host "   ✅ $var is set" -ForegroundColor Green
                }
            } else {
                $envDetails += "$var (not set)"
                if ($verboseEnabled) {
                    Write-Host "   ⚠️ $var is not set" -ForegroundColor Yellow
                }
            }
        }
        
        if ($envVarsPresent -eq 3) {
            $prerequisites.Messages += "Complete app credentials found in environment variables"
            $prerequisites.DetectedCapabilities += "AppCredentials-Environment"
            if ($verboseEnabled) {
                Write-Host "   ✅ Complete app credentials available from environment" -ForegroundColor Green
            }
        } elseif ($envVarsPresent -gt 0) {
            $prerequisites.Warnings += "Partial app credentials in environment variables (have $envVarsPresent of 3: $($envDetails -join ', '))"
            if ($verboseEnabled) {
                Write-Host "   ⚠️ Partial app credentials ($envVarsPresent/3): $($envDetails -join ', ')" -ForegroundColor Yellow
            }
        } else {
            if ($verboseEnabled) {
                Write-Host "   ℹ️ No app credentials in environment variables" -ForegroundColor Cyan
            }
        }
        
        # Test MSI/Managed Identity capabilities
        try {
            $msiEndpoint = $env:MSI_ENDPOINT
            $identityEndpoint = $env:IDENTITY_ENDPOINT
            $imdsEndpoint = $env:IMDS_ENDPOINT
            
            if ($msiEndpoint -or $identityEndpoint -or $imdsEndpoint) {
                $prerequisites.Messages += "Managed Identity endpoints detected - MSI authentication may be available"
                $prerequisites.DetectedCapabilities += "ManagedIdentity"
                if ($verboseEnabled) {
                    Write-Host "   ✅ Managed Identity environment detected" -ForegroundColor Green
                    if ($msiEndpoint) { Write-Host "      - MSI_ENDPOINT: present" -ForegroundColor Gray }
                    if ($identityEndpoint) { Write-Host "      - IDENTITY_ENDPOINT: present" -ForegroundColor Gray }
                    if ($imdsEndpoint) { Write-Host "      - IMDS_ENDPOINT: present" -ForegroundColor Gray }
                }
            } else {
                if ($verboseEnabled) {
                    Write-Host "   ℹ️ No Managed Identity endpoints detected" -ForegroundColor Cyan
                }
            }
        } catch {
            if ($verboseEnabled) {
                Write-Host "   ⚠️ Could not check Managed Identity endpoints: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        return $prerequisites
        
    } catch {
        $prerequisites.Success = $false
        $prerequisites.Messages += "Prerequisites check failed: $($_.Exception.Message)"
        if ($verboseEnabled) {
            Write-Host "   ❌ Prerequisites check failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $prerequisites
    }
}

function Connect-GraphWithStrategy {
    <#
    .SYNOPSIS
    Connect to Microsoft Graph using improved multi-mode authentication strategy with environment-aware defaults
    .DESCRIPTION
    Implements robust authentication flow with intelligent environment detection:
    1. Interactive browser authentication for local/desktop environments (default)
    2. App-only/MSI authentication for Cloud Shell/automation environments with auto-detection
    3. Device code authentication as fallback with user-friendly prompts
    
    Includes comprehensive verbose logging and Az.Accounts context integration.
    Connect to Microsoft Graph using multi-mode authentication strategy with enhanced error handling and user guidance
    .DESCRIPTION
    This function implements a comprehensive Microsoft Graph authentication strategy that:
    1. Automatically detects the environment (Azure Cloud Shell, local, MSI-enabled)
    2. Prioritizes MSI/app-only authentication in cloud environments  
    3. Uses device code authentication only as a fallback, not as default
    4. Provides detailed error logging with context information
    5. Offers interactive user guidance when automatic methods fail
    6. Logs all authentication attempts and environment detection logic
    #>
    [CmdletBinding()]
    param(
        [string]$AuthMode = 'Auto',
        [string]$ClientId,
        [string]$TenantId,
        [string]$ClientSecret,
        [string[]]$Scopes,
        [switch]$Interactive = $false
    )
    
    try {
        $verboseEnabled = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
        
        # If no scopes provided, use the configured scenario
        if (-not $Scopes) {
            $Scopes = Get-GraphScopesForScenario -Scenario $GraphScopeScenario
        }
        
        Write-Host ""
        Write-Host "🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Write-Host "📋 Requested scopes: $($Scopes -join ', ')" -ForegroundColor Gray
        
        # Collect comprehensive authentication context for troubleshooting
        $authContext = Get-GraphAuthenticationContext -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret
        
        # Get credentials from environment if not provided
        $credInfo = Get-GraphCredentialsFromEnvironment -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret
        $creds = $credInfo.Credentials
        $hasAppCreds = $credInfo.HasAppCredentials
        
        # Enhanced Az.Accounts context detection for auto-configuration
        $azContext = $null
        $autoDetectedTenantId = $null
        $autoDetectedClientId = $null
        try {
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if ($azContext) {
                $autoDetectedTenantId = $azContext.Tenant.Id
                if ($azContext.Account -and $azContext.Account.Type -eq "ServicePrincipal") {
                    $autoDetectedClientId = $azContext.Account.Id
                }
                if ($verboseEnabled) {
                    Write-Host "🔍 Az.Accounts context detected:" -ForegroundColor Cyan
                    Write-Host "   Account: $($azContext.Account.Id) ($($azContext.Account.Type))" -ForegroundColor Gray
                    Write-Host "   Tenant: $autoDetectedTenantId" -ForegroundColor Gray
                    Write-Host "   Environment: $($azContext.Environment.Name)" -ForegroundColor Gray
                }
            }
        } catch {
            if ($verboseEnabled) {
                Write-Host "🔍 No Az.Accounts context available: $($_.Exception.Message)" -ForegroundColor Gray
            }
        }
        
        # Use auto-detected values if not explicitly provided
        if (-not $creds.TenantId -and $autoDetectedTenantId) {
            $creds.TenantId = $autoDetectedTenantId
            if ($verboseEnabled) {
                Write-Host "✅ Auto-detected tenant ID from Az.Accounts: $autoDetectedTenantId" -ForegroundColor Green
            }
        }
        if (-not $creds.ClientId -and $autoDetectedClientId) {
            $creds.ClientId = $autoDetectedClientId
            if ($verboseEnabled) {
                Write-Host "✅ Auto-detected client ID from Az.Accounts: $autoDetectedClientId" -ForegroundColor Green
            }
        }
        
        # Improved authentication mode determination with verbose logging
        
        # Determine authentication mode with detailed reasoning
        $selectedMode = $AuthMode
        $selectionReasoning = @()
        
        if ($selectedMode -eq 'Auto') {
            Write-Host "🔍 Auto-detecting optimal Graph authentication method..." -ForegroundColor Cyan
            
            # Enhanced environment detection with verbose logging
            $isCloudShell = Test-CloudShellEnvironment -Quiet:(-not $verboseEnabled) -Verbose:$verboseEnabled
            $hasManagedIdentity = Test-ManagedIdentityEnvironment -Quiet:(-not $verboseEnabled) -Verbose:$verboseEnabled
            
            # Priority 1: Check for complete app credentials (highest priority for automation)
            if ($hasAppCreds) {
                $selectedMode = 'App'
                $selectionReasoning += "Complete app credentials available (ClientId, TenantId, ClientSecret)"
                if ($isCloudShell) {
                    $selectionReasoning += "Azure Cloud Shell environment detected - app-only authentication preferred over device code"
                } else {
                    $selectionReasoning += "Local environment with app credentials - app-only authentication selected"
                }
                Write-Host "🤖 Selected: App-only authentication" -ForegroundColor Green
                Write-Host "   🔍 Reason: Complete service principal credentials detected" -ForegroundColor Gray
                if ($verboseEnabled) {
                    Write-Host "   📝 Client ID: $($creds.ClientId)" -ForegroundColor Gray
                    Write-Host "   🏢 Tenant ID: $($creds.TenantId)" -ForegroundColor Gray
                    Write-Host "   🔑 Has Secret: $(-not [string]::IsNullOrWhiteSpace($creds.ClientSecret))" -ForegroundColor Gray
                }
            }
            # Priority 2: Cloud Shell or automation environment detection
            elseif ($isCloudShell -or $hasManagedIdentity) {
                if ($isCloudShell) {
                    $selectedMode = 'Interactive'
                    $selectionReasoning += "Azure Cloud Shell environment detected"
                    $selectionReasoning += "No app credentials available - interactive browser authentication selected"
                    Write-Host "☁️ Selected: Interactive browser authentication" -ForegroundColor Green
                    Write-Host "   🔍 Reason: Azure Cloud Shell environment detected" -ForegroundColor Gray
                    if ($verboseEnabled) {
                        Write-Host "   💡 Cloud Shell provides secure browser context for interactive auth" -ForegroundColor Gray
                    }
                } else {
                    # MSI environment without Cloud Shell - try app-only first, then device code
                    if ($azContext -and $azContext.Account.Type -eq "ManagedService") {
                        $selectedMode = 'App'
                        $selectionReasoning += "Active managed identity context detected"
                        Write-Host "🔧 Selected: Managed Identity authentication" -ForegroundColor Green
                        Write-Host "   🔍 Reason: Active managed identity context detected" -ForegroundColor Gray
                    } else {
                        $selectedMode = 'DeviceCode'
                        $selectionReasoning += "Automation environment without interactive capabilities"
                        Write-Host "🔧 Selected: Device code authentication" -ForegroundColor Green
                        Write-Host "   🔍 Reason: Automation environment without interactive capabilities" -ForegroundColor Gray
                    }
                }
            }
            # Priority 3: Local environment - default to interactive
            else {
                $selectedMode = 'Interactive'
                $selectionReasoning += "Local environment detected (not Azure Cloud Shell)"
                $selectionReasoning += "No app credentials available - defaulting to interactive browser authentication"
                Write-Host "🖥️ Selected: Interactive browser authentication" -ForegroundColor Green
                Write-Host "   🔍 Reason: Local desktop environment detected" -ForegroundColor Gray
                if ($verboseEnabled) {
                    Write-Host "   💡 Interactive auth is optimal for local development scenarios" -ForegroundColor Gray
                }
            }
        } else {
            $selectionReasoning += "Explicit authentication mode specified: $selectedMode"
            Write-Host "⚙️ Using explicit authentication mode: $selectedMode" -ForegroundColor Cyan
            if ($verboseEnabled) {
                Write-Host "   🔍 Reason: Explicitly specified by user/parameter" -ForegroundColor Gray
            }
        }
        
        # Log authentication decision rationale
        if ($selectionReasoning.Count -gt 0) {
            Write-Host "💭 Authentication selection reasoning:" -ForegroundColor Cyan
            foreach ($reason in $selectionReasoning) {
                Write-Host "   • $reason" -ForegroundColor Gray
            }
        }
        
        # Check prerequisites with verbose output
        $prereqCheck = Test-GraphAuthenticationPrerequisites -AuthMode $selectedMode -Verbose:$verboseEnabled
        foreach ($message in $prereqCheck.Messages) {
            Write-Host "ℹ️ $message" -ForegroundColor Cyan
        }
        foreach ($warning in $prereqCheck.Warnings) {
            Write-Host "⚠️ $warning" -ForegroundColor Yellow
        }
        
        # Ensure Graph modules are available for Interactive/App modes
        if ($selectedMode -in @('Interactive', 'App')) {
            if (-not (Install-GraphModule)) {
                Write-Host "⚠️ Microsoft Graph modules not available, falling back to MSAL.PS" -ForegroundColor Yellow
                if ($selectedMode -eq 'Interactive') {
                    $selectedMode = 'DeviceCode'
                    Write-Host "🔄 Fallback: Device code authentication (MSAL.PS)" -ForegroundColor Yellow
                    Write-Host "   🔍 Reason: Microsoft.Graph modules unavailable" -ForegroundColor Gray
                }
            }
        }
        
        Write-Host ""
        Write-Host "🚀 Executing authentication strategy: $selectedMode" -ForegroundColor Cyan
        
        # Execute authentication strategy with enhanced error handling and fallback
        # Ensure Graph modules are available for non-DeviceCode modes
        if ($selectedMode -in @('Interactive', 'App')) {
            if (-not (Install-GraphModule)) {
                Write-Host "⚠️ Microsoft Graph modules not available, falling back to MSAL.PS device code" -ForegroundColor Yellow
                $selectedMode = 'DeviceCode'
                $selectionReasoning += "Fallback to DeviceCode due to missing Microsoft Graph modules"
            }
        }
        
        # Execute authentication strategy with comprehensive error handling
        $authSuccess = $false
        $authError = $null
        
        switch ($selectedMode) {
            'Interactive' {
                Write-Host "🌐 Attempting interactive browser authentication..." -ForegroundColor Yellow
                if ($Verbose) {
                    Write-Host "   📝 This will open your default browser for Azure AD authentication" -ForegroundColor Gray
                    Write-Host "   🔒 Secure OAuth2 flow with browser-based consent" -ForegroundColor Gray
                }
                
                try {
                    $tenantParam = if ($creds.TenantId) { $creds.TenantId } else { "common" }
                    if ($Verbose) {
                        Write-Host "   🏢 Using tenant: $tenantParam" -ForegroundColor Gray
                    }
                    Write-Host "   Target tenant: $tenantParam" -ForegroundColor Gray
                    
                    Connect-MgGraph -Scopes $Scopes -TenantId $tenantParam -NoWelcome -ErrorAction Stop
                    
                    $context = Get-MgContext
                    Write-Host "✅ Interactive authentication successful" -ForegroundColor Green
                    Write-Host "👤 Authenticated as: $($context.Account)" -ForegroundColor Cyan
                    Write-Host "🏢 Tenant: $($context.TenantId)" -ForegroundColor Cyan
                    $authSuccess = $true
                } catch {
                    Write-Host "❌ Interactive authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                    if ($Verbose) {
                        Write-Host "   🔍 This may be due to browser restrictions, network issues, or missing permissions" -ForegroundColor Gray
                    }
                    
                    # Intelligent fallback logic
                    Write-Host ""
                    Write-Host "🔄 Attempting fallback authentication methods..." -ForegroundColor Yellow
                    
                    if ($hasAppCreds) {
                        Write-Host "   ⬇️ Trying app-only authentication (service principal credentials available)" -ForegroundColor Cyan
                        return Connect-GraphWithStrategy -AuthMode 'App' -ClientId $creds.ClientId -TenantId $creds.TenantId -ClientSecret $creds.ClientSecret -Scopes $Scopes -Verbose:$verboseEnabled
                    } else {
                        Write-Host "   ⬇️ Trying device code authentication (no credentials required)" -ForegroundColor Cyan
                        Write-Host "   💡 Device code auth works in restrictive network environments" -ForegroundColor Gray
                        return Connect-GraphWithStrategy -AuthMode 'DeviceCode' -Scopes $Scopes -Verbose:$verboseEnabled
                    }
                    $authError = $_.Exception
                    $errorMessage = "Interactive authentication failed: $($_.Exception.Message)"
                    Write-Host "❌ $errorMessage" -ForegroundColor Red
                    
                    # Log comprehensive error context
                    Write-GraphAuthErrorLog -AuthMethod "Interactive" -Message $errorMessage -Exception $_.Exception -EnvironmentContext $authContext.EnvironmentVariables -AuthenticationContext $authContext.ProvidedCredentials
                }
            }
            
            'App' {
                # Handle both explicit app credentials and managed identity scenarios
                if (-not $hasAppCreds -and $azContext -and $azContext.Account.Type -eq "ManagedService") {
                    Write-Host "🔧 Attempting managed identity authentication..." -ForegroundColor Yellow
                    if ($Verbose) {
                        Write-Host "   🔍 Using existing managed identity context from Az.Accounts" -ForegroundColor Gray
                        Write-Host "   🤖 Account: $($azContext.Account.Id)" -ForegroundColor Gray
                    }
                    
                    try {
                        # For managed identity, we'll try to use the existing context
                        # This is a simplified approach - in practice, you might need to get a Graph token using the MSI endpoint
                        Write-Host "⚠️ Managed identity Graph authentication requires manual implementation" -ForegroundColor Yellow
                        Write-Host "   💡 Falling back to device code authentication for Graph access" -ForegroundColor Gray
                        return Connect-GraphWithStrategy -AuthMode 'DeviceCode' -Scopes $Scopes -Verbose:$verboseEnabled
                    } catch {
                        Write-Host "❌ Managed identity authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "🔄 Falling back to device code authentication..." -ForegroundColor Yellow
                        return Connect-GraphWithStrategy -AuthMode 'DeviceCode' -Scopes $Scopes -Verbose:$verboseEnabled
                    }
                }
                
                if (-not $hasAppCreds) {
                    $errorMsg = "App-only authentication requires ClientId, TenantId, and ClientSecret"
                    Write-Host "❌ $errorMsg" -ForegroundColor Red
                    if ($Verbose) {
                        Write-Host "   💡 Service principal credentials can be provided via:" -ForegroundColor Gray
                        Write-Host "      - Parameters: `$GraphClientId, `$GraphTenantId, `$GraphClientSecret" -ForegroundColor Gray
                        Write-Host "      - Environment variables: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET" -ForegroundColor Gray
                    }
                    Write-Host "🔄 Falling back to device code authentication..." -ForegroundColor Yellow
                    return Connect-GraphWithStrategy -AuthMode 'DeviceCode' -Scopes $Scopes -Verbose:$verboseEnabled
                }
                
                Write-Host "🤖 Attempting app-only authentication..." -ForegroundColor Yellow
                if ($Verbose) {
                    Write-Host "   📝 Client ID: $($creds.ClientId)" -ForegroundColor Gray
                    Write-Host "   🏢 Tenant ID: $($creds.TenantId)" -ForegroundColor Gray
                    Write-Host "   🔐 Using client secret authentication" -ForegroundColor Gray
                }
                
                try {
                    # PSScriptAnalyzer suppression: This is necessary for Graph API authentication
                    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
                    $secureSecret = ConvertTo-SecureString $creds.ClientSecret -AsPlainText -Force
                    $clientSecretCredential = New-Object System.Management.Automation.PSCredential($creds.ClientId, $secureSecret)
                    
                    Connect-MgGraph -ClientSecretCredential $clientSecretCredential -TenantId $creds.TenantId -NoWelcome -ErrorAction Stop
                    
                    $context = Get-MgContext
                    Write-Host "✅ App-only authentication successful" -ForegroundColor Green
                    Write-Host "🤖 Application: $($context.ClientId)" -ForegroundColor Cyan
                    Write-Host "🏢 Tenant: $($context.TenantId)" -ForegroundColor Cyan
                    return $true
                } catch {
                    Write-Host "❌ App-only authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                    if ($Verbose) {
                        Write-Host "   🔍 This may be due to invalid credentials, insufficient permissions, or network issues" -ForegroundColor Gray
                        Write-Host "   💡 Verify the service principal has necessary Graph API permissions" -ForegroundColor Gray
                    }
                    Write-Host "🔄 Falling back to device code authentication..." -ForegroundColor Yellow
                    return Connect-GraphWithStrategy -AuthMode 'DeviceCode' -Scopes $Scopes -Verbose:$verboseEnabled
                    $errorMessage = "App-only authentication requires ClientId, TenantId, and ClientSecret"
                    Write-Host "❌ $errorMessage" -ForegroundColor Red
                    Write-GraphAuthErrorLog -AuthMethod "App" -Message $errorMessage -EnvironmentContext $authContext.EnvironmentVariables -AuthenticationContext $authContext.ProvidedCredentials
                    $authError = [System.Exception]::new($errorMessage)
                } else {
                    Write-Host "🤖 Attempting app-only authentication..." -ForegroundColor Yellow
                    Write-Host "   📝 Client ID: $($creds.ClientId)" -ForegroundColor Gray
                    Write-Host "   🏢 Tenant ID: $($creds.TenantId)" -ForegroundColor Gray
                    
                    try {
                        # PSScriptAnalyzer suppression: This is necessary for Graph API authentication
                        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
                        $secureSecret = ConvertTo-SecureString $creds.ClientSecret -AsPlainText -Force
                        $clientSecretCredential = New-Object System.Management.Automation.PSCredential($creds.ClientId, $secureSecret)
                        
                        Connect-MgGraph -ClientSecretCredential $clientSecretCredential -TenantId $creds.TenantId -NoWelcome -ErrorAction Stop
                        
                        $context = Get-MgContext
                        Write-Host "✅ App-only authentication successful" -ForegroundColor Green
                        Write-Host "🤖 Application: $($context.ClientId)" -ForegroundColor Cyan
                        Write-Host "🏢 Tenant: $($context.TenantId)" -ForegroundColor Cyan
                    } catch {
                        $errorMessage = "App-only authentication failed: $($_.Exception.Message)"
                        Write-Host "❌ $errorMessage" -ForegroundColor Red
                        
                        # Log comprehensive error context including credential availability
                        $credentialContext = @{
                            'ClientIdProvided' = if ($creds.ClientId) { "Yes" } else { "No" }
                            'TenantIdProvided' = if ($creds.TenantId) { "Yes" } else { "No" }
                            'ClientSecretProvided' = if ($creds.ClientSecret) { "Yes" } else { "No" }
                        }
                        Write-GraphAuthErrorLog -AuthMethod "App" -Message $errorMessage -Exception $_.Exception -EnvironmentContext $authContext.EnvironmentVariables -AuthenticationContext $credentialContext
                    }
                }
            }
            
            'DeviceCode' {
                Write-Host "📱 Attempting device code authentication..." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "💡 Device Code Authentication - User-Friendly Guide:" -ForegroundColor Cyan
                Write-Host "   📱 You'll receive a code to enter at https://microsoft.com/devicelogin" -ForegroundColor Gray
                Write-Host "   🌐 This method works in restrictive environments (firewalls, proxy servers)" -ForegroundColor Gray
                Write-Host "   🔒 Secure: No passwords stored locally, uses OAuth2 device flow" -ForegroundColor Gray
                Write-Host "   ⏱️  Timeout: You have 15 minutes to complete the authentication" -ForegroundColor Gray
                Write-Host ""
                
                if ($Verbose) {
                    Write-Host "🔍 Device code authentication details:" -ForegroundColor Cyan
                    Write-Host "   🏷️  Using MSAL.PS for maximum compatibility" -ForegroundColor Gray
                    Write-Host "   🆔 Client ID: Microsoft PowerShell (trusted first-party app)" -ForegroundColor Gray
                    Write-Host "   🏢 Tenant: $($creds.TenantId -or 'common')" -ForegroundColor Gray
                }
                
                # Ensure MSAL module is available
                if (-not (Install-MSALModule)) {
                    $errorMsg = "MSAL.PS module not available for device code authentication"
                    Write-Host "❌ $errorMsg" -ForegroundColor Red
                    Write-Host ""
                    Write-Host "🔧 Troubleshooting Device Code Authentication:" -ForegroundColor Yellow
                    Write-Host "   1. Install MSAL.PS module: Install-Module -Name MSAL.PS -Force" -ForegroundColor Gray
                    Write-Host "   2. Check PowerShell execution policy: Get-ExecutionPolicy" -ForegroundColor Gray
                    Write-Host "   3. Verify internet connectivity to PowerShell Gallery" -ForegroundColor Gray
                    Write-Host "   4. Try manual module installation from PowerShell Gallery website" -ForegroundColor Gray
                    throw $errorMsg
                }
                
                try {
                    $tenantId = if ($creds.TenantId) { $creds.TenantId } else { "common" }
                    $clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft PowerShell client ID
                    
                    if ($Verbose) {
                        Write-Host "🔄 Initiating device code flow..." -ForegroundColor Cyan
                    }
                    
                    Write-Host "⏳ Starting device code authentication flow..." -ForegroundColor Yellow
                    $authResult = Get-MsalToken -ClientId $clientId -TenantId $tenantId -Scopes $Scopes -DeviceCode -ErrorAction Stop
                    
                    if ($authResult -and $authResult.AccessToken) {
                        Write-Host "✅ Device code authentication successful" -ForegroundColor Green
                        Write-Host "👤 Authenticated as: $($authResult.Account.Username)" -ForegroundColor Cyan
                        if ($authResult.Account.HomeAccountId.TenantId) {
                            Write-Host "🏢 Tenant: $($authResult.Account.HomeAccountId.TenantId)" -ForegroundColor Cyan
                        }
                        
                        # Store token for use by upload functions
                        $global:GraphAccessToken = $authResult.AccessToken
                        $authSuccess = $true
                    } else {
                        $errorMessage = "Device code authentication failed - no access token received"
                        Write-Host "❌ $errorMessage" -ForegroundColor Red
                        Write-GraphAuthErrorLog -AuthMethod "DeviceCode" -Message $errorMessage -EnvironmentContext $authContext.EnvironmentVariables
                        $authError = [System.Exception]::new($errorMessage)
                    }
                } catch {
                    Write-Host "❌ Device code authentication failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host ""
                    Write-Host "🔧 Device Code Authentication Troubleshooting:" -ForegroundColor Yellow
                    Write-Host "   🌐 Check internet connectivity to login.microsoftonline.com" -ForegroundColor Gray
                    Write-Host "   🔐 Ensure your account has permissions for the requested scopes" -ForegroundColor Gray
                    Write-Host "   ⏱️  Verify you completed authentication within the time limit" -ForegroundColor Gray
                    Write-Host "   🚫 Check if your organization blocks device code authentication" -ForegroundColor Gray
                    Write-Host "   📞 Contact your IT administrator if organizational policies prevent access" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "❌ All Microsoft Graph authentication methods have failed" -ForegroundColor Red
                    Write-Host "💡 Available authentication options were:" -ForegroundColor Yellow
                    Write-Host "   1. Interactive browser authentication (requires GUI/browser)" -ForegroundColor Gray
                    Write-Host "   2. App-only authentication (requires service principal credentials)" -ForegroundColor Gray
                    Write-Host "   3. Device code authentication (current method that failed)" -ForegroundColor Gray
                    
                    Write-ErrorLog "GraphAuth" "All Graph authentication methods failed: $($_.Exception.Message)"
                    return $false
                }
            }
            
            default {
                $errorMsg = "Invalid authentication mode: $selectedMode"
                Write-Host "❌ $errorMsg" -ForegroundColor Red
                Write-Host "💡 Valid modes: Interactive, App, DeviceCode, Auto" -ForegroundColor Gray
                Write-GraphAuthErrorLog -AuthMethod $selectedMode -Message $errorMsg
                $authError = [System.Exception]::new($errorMsg)
                throw $errorMsg
            }
        }
        
        # Handle authentication failures with interactive guidance
        if (-not $authSuccess -and $Interactive) {
            Write-Host ""
            Write-Host "🔄 Primary authentication method failed. Offering alternative options..." -ForegroundColor Yellow
            
            $promptResult = Invoke-InteractiveAuthenticationPrompt -FailedMethod $selectedMode -FailureReason $authError.Message -HasAppCredentials $hasAppCreds -IsCloudShell $isCloudShell
            
            if ($promptResult.Method -ne "Skip") {
                Write-Host "🔄 Retrying with user-selected method: $($promptResult.Method)" -ForegroundColor Cyan
                # Recursive call with user-selected method
                return Connect-GraphWithStrategy -AuthMode $promptResult.Method -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -Scopes $Scopes -Interactive:$false
            } else {
                Write-Host "⏭️ User chose to skip Microsoft Graph authentication" -ForegroundColor Yellow
                return $false
            }
        }
        
        return $authSuccess
        
    } catch {
        $errorMessage = "Microsoft Graph authentication failed: $($_.Exception.Message)"
        Write-Host "❌ $errorMessage" -ForegroundColor Red
        Write-GraphAuthErrorLog -AuthMethod "General" -Message $errorMessage -Exception $_.Exception
        return $false
    }
}

function Get-GraphAccessToken {
    <#
    .SYNOPSIS
    Enhanced Microsoft Graph authentication with interactive fallback support
    .DESCRIPTION
    This function provides backwards compatibility while leveraging the new enhanced authentication strategy.
    When authentication fails, it can optionally prompt users for alternative methods.
    #>
    param(
        [string]$TenantId = "common",
        [string]$ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        [string[]]$Scopes,
        [switch]$Interactive
    )
    
    # If no scopes provided, use the configured scenario
    if (-not $Scopes) {
        $Scopes = Get-GraphScopesForScenario -Scenario $GraphScopeScenario
    }
    
    Write-Host "🔄 Initializing Microsoft Graph authentication..." -ForegroundColor Cyan
    
    # Use the new multi-mode authentication strategy with interactive fallback
    # Use provided parameters or fall back to global variables
    $actualClientId = if ($ClientId) { $ClientId } else { $GraphClientId }
    $actualTenantId = if ($TenantId) { $TenantId } else { $GraphTenantId }
    
    $success = Connect-GraphWithStrategy -AuthMode $GraphAuthMode -ClientId $actualClientId -TenantId $actualTenantId -ClientSecret $GraphClientSecret -Scopes $Scopes -Interactive:$Interactive
    
    if ($success) {
        Write-Host "✅ Microsoft Graph authentication completed successfully" -ForegroundColor Green
        
        # For backwards compatibility, return the token if available
        if ($global:GraphAccessToken) {
            return $global:GraphAccessToken
        } else {
            # For Connect-MgGraph based authentication, we don't have a direct token
            # Return a placeholder to indicate success
            return "MgGraph-Connected"
        }
    } else {
        Write-Host "❌ Microsoft Graph authentication failed after all available methods" -ForegroundColor Red
        return $null
    }
}

function Get-CloudUploadPath {
    <#
    .SYNOPSIS
    Get target upload path from user or parameter
    #>
    param(
        [string]$ProvidedPath
    )
    
    if (-not [string]::IsNullOrWhiteSpace($ProvidedPath)) {
        Write-Host "📁 Using provided cloud upload path: $ProvidedPath" -ForegroundColor Cyan
        return $ProvidedPath.Trim()
    }
    
    Write-Host ""
    Write-Host "📁 Cloud Upload Configuration" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "Please specify the target folder in OneDrive/SharePoint for uploading audit files." -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Gray
    Write-Host "  • /Documents/KeyVaultAudits" -ForegroundColor Gray
    Write-Host "  • /Shared Documents/Security/Audits" -ForegroundColor Gray
    Write-Host "  • /KeyVaultReports" -ForegroundColor Gray
    Write-Host ""
    
    do {
        $uploadPath = Read-Host "Enter target folder path"
        if ([string]::IsNullOrWhiteSpace($uploadPath)) {
            Write-Host "⚠️  Path cannot be empty. Please enter a valid folder path." -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($uploadPath))
    
    return $uploadPath.Trim()
}

function Get-FilesToUpload {
    <#
    .SYNOPSIS
    Get list of files to upload from the output directory
    #>
    param(
        [string]$OutputDirectory,
        [string]$CsvFilePath,
        [string]$HtmlPath,
        [string]$ErrorLogPath,
        [string]$PermissionsLogPath,
        [string]$DataIssuesLogPath
    )
    
    $filesToUpload = @()
    
    # Add main report files
    if ($CsvFilePath -and (Test-Path $CsvFilePath)) {
        $filesToUpload += @{
            LocalPath = $CsvFilePath
            FileName = Split-Path $CsvFilePath -Leaf
            Type = "CSV Report"
        }
    }
    
    if ($HtmlPath -and (Test-Path $HtmlPath)) {
        $filesToUpload += @{
            LocalPath = $HtmlPath
            FileName = Split-Path $HtmlPath -Leaf
            Type = "HTML Report"
        }
    }
    
    # Add log files
    if ($ErrorLogPath -and (Test-Path $ErrorLogPath)) {
        $filesToUpload += @{
            LocalPath = $ErrorLogPath
            FileName = Split-Path $ErrorLogPath -Leaf
            Type = "Error Log"
        }
    }
    
    if ($PermissionsLogPath -and (Test-Path $PermissionsLogPath)) {
        $filesToUpload += @{
            LocalPath = $PermissionsLogPath
            FileName = Split-Path $PermissionsLogPath -Leaf
            Type = "Permissions Log"
        }
    }
    
    if ($DataIssuesLogPath -and (Test-Path $DataIssuesLogPath)) {
        $filesToUpload += @{
            LocalPath = $DataIssuesLogPath
            FileName = Split-Path $DataIssuesLogPath -Leaf
            Type = "Data Issues Log"
        }
    }
    
    # Look for any other relevant files in the output directory
    if ($OutputDirectory -and (Test-Path $OutputDirectory)) {
        $additionalFiles = Get-ChildItem -Path $OutputDirectory -File | Where-Object {
            $_.Name -match '(?i)\.(csv|html|log|txt)$' -and
            $_.FullName -notin @($CsvFilePath, $HtmlPath, $ErrorLogPath, $PermissionsLogPath, $DataIssuesLogPath)
        }
        
        foreach ($file in $additionalFiles) {
            $filesToUpload += @{
                LocalPath = $file.FullName
                FileName = $file.Name
                Type = "Additional File"
            }
        }
    }
    
    return $filesToUpload
}

function Invoke-GraphFileUpload {
    <#
    .SYNOPSIS
    Upload a file to Microsoft Graph (OneDrive/SharePoint)
    #>
    param(
        [string]$AccessToken,
        [string]$LocalFilePath,
        [string]$TargetPath,
        [string]$FileName
    )
    
    try {
        $fileSize = (Get-Item $LocalFilePath).Length
        
        # For files larger than 4MB, use upload session
        if ($fileSize -gt 4MB) {
            return Invoke-GraphLargeFileUpload -AccessToken $AccessToken -LocalFilePath $LocalFilePath -TargetPath $TargetPath -FileName $FileName
        }
        
        # For smaller files, use simple upload
        $uploadUrl = "https://graph.microsoft.com/v1.0/me/drive/root:$TargetPath/$FileName`:/content"
        
        $fileBytes = [System.IO.File]::ReadAllBytes($LocalFilePath)
        
        $response = Invoke-RestMethod -Uri $uploadUrl -Method PUT -Body $fileBytes -Headers @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/octet-stream'
        } -ErrorAction Stop
        
        return @{
            Success = $true
            WebUrl = $response.webUrl
            DownloadUrl = $response.'@microsoft.graph.downloadUrl'
            FileId = $response.id
        }
    } catch {
        Write-ErrorLog "GraphUpload" "Failed to upload file $FileName : $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Invoke-GraphLargeFileUpload {
    <#
    .SYNOPSIS
    Upload large files using upload session
    #>
    param(
        [string]$AccessToken,
        [string]$LocalFilePath,
        [string]$TargetPath,
        [string]$FileName
    )
    
    try {
        $fileSize = (Get-Item $LocalFilePath).Length
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }
        
        # Create upload session
        $sessionUrl = "https://graph.microsoft.com/v1.0/me/drive/root:$TargetPath/$FileName`:/createUploadSession"
        $sessionBody = @{
            item = @{
                "@microsoft.graph.conflictBehavior" = "replace"
                name = $FileName
            }
        } | ConvertTo-Json -Depth 3
        
        $sessionResponse = Invoke-RestMethod -Uri $sessionUrl -Method POST -Body $sessionBody -Headers $headers -ErrorAction Stop
        $uploadUrl = $sessionResponse.uploadUrl
        
        # Upload in chunks
        $chunkSize = 320KB * 10  # 3.2MB chunks for better performance
        $fileStream = [System.IO.File]::OpenRead($LocalFilePath)
        $buffer = New-Object byte[] $chunkSize
        $bytesUploaded = 0
        
        try {
            while ($bytesUploaded -lt $fileSize) {
                $bytesRead = $fileStream.Read($buffer, 0, $chunkSize)
                if ($bytesRead -eq 0) { break }
                
                $chunkEnd = $bytesUploaded + $bytesRead - 1
                $contentRange = "bytes $bytesUploaded-$chunkEnd/$fileSize"
                
                $chunkData = $buffer[0..($bytesRead-1)]
                
                $chunkHeaders = @{
                    'Content-Range' = $contentRange
                    'Content-Length' = $bytesRead.ToString()
                }
                
                $chunkResponse = Invoke-RestMethod -Uri $uploadUrl -Method PUT -Body $chunkData -Headers $chunkHeaders -ErrorAction Stop
                
                $bytesUploaded += $bytesRead
                
                # Show progress
                $percentComplete = [math]::Round(($bytesUploaded / $fileSize) * 100, 1)
                Write-Progress -Activity "Uploading $FileName" -Status "$percentComplete% complete" -PercentComplete $percentComplete
            }
            
            Write-Progress -Activity "Uploading $FileName" -Completed
            
            return @{
                Success = $true
                WebUrl = $chunkResponse.webUrl
                DownloadUrl = $chunkResponse.'@microsoft.graph.downloadUrl'
                FileId = $chunkResponse.id
            }
        } finally {
            $fileStream.Close()
        }
    } catch {
        Write-ErrorLog "GraphUpload" "Failed to upload large file $FileName : $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Invoke-CloudUpload {
    <#
    .SYNOPSIS
    Main function to handle cloud upload workflow
    #>
    param(
        [string]$OutputDirectory,
        [string]$CsvFilePath,
        [string]$HtmlPath,
        [string]$ErrorLogPath,
        [string]$PermissionsLogPath,
        [string]$DataIssuesLogPath,
        [string]$TargetPath
    )
    
    try {
        Write-Host ""
        Write-Host "☁️  CLOUD UPLOAD INTEGRATION" -ForegroundColor Cyan
        Write-Host "============================" -ForegroundColor Cyan
        
        # Install MSAL module if needed
        if (-not (Install-MSALModule)) {
            Write-Host "❌ Cannot proceed with cloud upload - MSAL module installation failed" -ForegroundColor Red
            return $false
        }
        
        # Get access token
        $accessToken = Get-GraphAccessToken
        if (-not $accessToken) {
            Write-Host "❌ Cannot proceed with cloud upload - authentication failed" -ForegroundColor Red
            return $false
        }
        
        # Get files to upload
        $filesToUpload = Get-FilesToUpload -OutputDirectory $OutputDirectory -CsvFilePath $CsvFilePath -HtmlPath $HtmlPath -ErrorLogPath $ErrorLogPath -PermissionsLogPath $PermissionsLogPath -DataIssuesLogPath $DataIssuesLogPath
        
        if ($filesToUpload.Count -eq 0) {
            Write-Host "⚠️  No files found to upload" -ForegroundColor Yellow
            return $false
        }
        
        Write-Host ""
        Write-Host "📁 Files to upload to $TargetPath :" -ForegroundColor Cyan
        foreach ($file in $filesToUpload) {
            $fileSize = if (Test-Path $file.LocalPath) { 
                $size = (Get-Item $file.LocalPath).Length
                if ($size -gt 1MB) { "$([math]::Round($size/1MB, 1)) MB" }
                elseif ($size -gt 1KB) { "$([math]::Round($size/1KB, 1)) KB" }
                else { "$size bytes" }
            } else { "Unknown" }
            Write-Host "   • $($file.FileName) ($($file.Type)) - $fileSize" -ForegroundColor Gray
        }
        
        Write-Host ""
        $confirmUpload = Read-Host "Do you want to proceed with uploading these files to OneDrive/SharePoint? (Y/N)"
        if ($confirmUpload -notmatch '^[Yy]') {
            Write-Host "❌ Upload cancelled by user" -ForegroundColor Yellow
            return $false
        }
        
        # Upload files
        Write-Host ""
        Write-Host "📤 Starting file uploads..." -ForegroundColor Cyan
        $successCount = 0
        $failureCount = 0
        $uploadResults = @()
        
        foreach ($file in $filesToUpload) {
            Write-Host "   📤 Uploading $($file.FileName)..." -ForegroundColor Yellow
            
            $result = Invoke-GraphFileUpload -AccessToken $accessToken -LocalFilePath $file.LocalPath -TargetPath $TargetPath -FileName $file.FileName
            
            if ($result.Success) {
                $successCount++
                Write-Host "   ✅ $($file.FileName) uploaded successfully" -ForegroundColor Green
                $uploadResults += @{
                    FileName = $file.FileName
                    Type = $file.Type
                    Success = $true
                    WebUrl = $result.WebUrl
                    DownloadUrl = $result.DownloadUrl
                }
            } else {
                $failureCount++
                Write-Host "   ❌ Failed to upload $($file.FileName): $($result.Error)" -ForegroundColor Red
                $uploadResults += @{
                    FileName = $file.FileName
                    Type = $file.Type
                    Success = $false
                    Error = $result.Error
                }
            }
        }
        
        # Summary
        Write-Host ""
        Write-Host "📊 Upload Summary:" -ForegroundColor Cyan
        Write-Host "   ✅ Successful uploads: $successCount" -ForegroundColor Green
        Write-Host "   ❌ Failed uploads: $failureCount" -ForegroundColor Red
        
        if ($successCount -gt 0) {
            Write-Host ""
            Write-Host "🔗 Successfully uploaded files:" -ForegroundColor Cyan
            foreach ($result in ($uploadResults | Where-Object { $_.Success })) {
                Write-Host "   • $($result.FileName) ($($result.Type))" -ForegroundColor Green
                if ($result.WebUrl) {
                    Write-Host "     🌐 View online: $($result.WebUrl)" -ForegroundColor Blue
                }
            }
        }
        
        if ($failureCount -gt 0) {
            Write-Host ""
            Write-Host "❌ Failed uploads:" -ForegroundColor Red
            foreach ($result in ($uploadResults | Where-Object { -not $_.Success })) {
                Write-Host "   • $($result.FileName): $($result.Error)" -ForegroundColor Red
            }
        }
        
        return $successCount -gt 0
    } catch {
        Write-Host "❌ Cloud upload failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog "GraphUpload" "Cloud upload process failed: $($_.Exception.Message)"
        return $false
    }
}

# --- End of Microsoft Graph Upload Functions ---

# --- Environment Detection for OneDrive Upload ---
function Get-ScriptExecutionEnvironment {
    <#
    .SYNOPSIS
    Determine the script execution environment for conditional OneDrive upload behavior
    .DESCRIPTION
    Returns whether the script is running in Azure Cloud Shell or a local environment.
    This is used to control OneDrive upload behavior based on environment.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Use the existing comprehensive Cloud Shell detection
        $isCloudShell = Test-CloudShellEnvironment -Quiet
        
        if ($isCloudShell) {
            return @{
                Environment = "CloudShell"
                AllowOneDriveUpload = $true
                RequireUserConsent = $false
                Description = "Azure Cloud Shell detected - OneDrive upload enabled by default"
            }
        } else {
            return @{
                Environment = "Local"
                AllowOneDriveUpload = $false  # Will be set to true only with user consent
                RequireUserConsent = $true
                Description = "Local environment detected - OneDrive upload requires user consent"
            }
        }
    } catch {
        Write-UserMessage "Environment detection failed: $($_.Exception.Message)" -Type Verbose
        # Default to local environment with user consent required
        return @{
            Environment = "Unknown"
            AllowOneDriveUpload = $false
            RequireUserConsent = $true
            Description = "Environment detection failed - defaulting to local behavior"
        }
    }
}

function Get-OneDriveUploadConsent {
    <#
    .SYNOPSIS
    Prompt user for OneDrive upload consent in local environments
    .DESCRIPTION
    Prompts the user to consent to OneDrive upload when running in a local environment.
    Default is No to respect user privacy.
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "📁 OneDrive for Business Upload Option" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script can automatically upload the generated reports to your OneDrive for Business." -ForegroundColor White
    Write-Host ""
    Write-Host "Benefits:" -ForegroundColor Green
    Write-Host "  ✅ Automatic backup of audit results" -ForegroundColor Gray
    Write-Host "  ✅ Easy sharing with team members" -ForegroundColor Gray
    Write-Host "  ✅ Centralized storage for compliance" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Note: This requires Microsoft Graph authentication and Files.ReadWrite permissions." -ForegroundColor Yellow
    Write-Host ""
    
    # Simplified prompt without timeout (timeout mechanism was causing hangs in some environments)
    $response = Read-Host "Do you want to upload reports to OneDrive for Business? [y/N] (default: N)"
    
    # Handle empty response
    if ([string]::IsNullOrWhiteSpace($response)) {
        $response = "N"  # Default to No
    }
    
    $response = $response.Trim().ToUpper()
    
    if ($response -eq "Y" -or $response -eq "YES") {
        Write-Host "✅ OneDrive upload enabled - will attempt to upload after report generation" -ForegroundColor Green
        return $true
    } else {
        Write-Host "ℹ️  OneDrive upload skipped - reports will be saved locally only" -ForegroundColor Cyan
        return $false
    }
}

# --- End of Environment Detection Functions ---

# --- Global Variables and Cancel Handling ---
$global:auditResults = @()
$global:executionId = (Get-Date -Format 'yyyyMMdd-HHmmss')

# Debug logging function specifically for cancellation operations
function Write-CancellationDebugLog {
    param([string]$Operation, [string]$Message, [string]$Trigger = "", [string]$Context = "")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $triggerInfo = if ($Trigger) { " | Trigger: $Trigger" } else { "" }
    $contextInfo = if ($Context) { " | Context: $Context" } else { "" }
    $logMessage = "[$timestamp] [Cancellation-$Operation] $Message$triggerInfo$contextInfo"
    
    # Only write to file if paths are available (they get set later in the script)
    if ($global:dataIssuesPath -and (Test-Path (Split-Path $global:dataIssuesPath -Parent) -ErrorAction SilentlyContinue)) {
        $logMessage | Out-File -FilePath $global:dataIssuesPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    
    Write-UserMessage "Debug: $Operation - $Message$triggerInfo$contextInfo" -Type Verbose
}

# --- Cancellation Recovery Functions ---
function Get-CancellationMarkerPath {
    <#
    .SYNOPSIS
        Get the path to the cancellation marker file in user's home directory.
    #>
    $homeDir = if ($IsWindows -or $env:OS -eq "Windows_NT" -or -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $env:USERPROFILE
    } elseif (-not [string]::IsNullOrWhiteSpace($env:HOME)) {
        $env:HOME
    } else {
        $PWD.Path
    }
    
    return Join-Path $homeDir ".akv_audit_cancelled"
}

function Test-CancellationMarker {
    <#
    .SYNOPSIS
        Check if cancellation marker file exists.
    #>
    $markerPath = Get-CancellationMarkerPath
    return Test-Path $markerPath -ErrorAction SilentlyContinue
}

function Set-CancellationMarker {
    <#
    .SYNOPSIS
        Create cancellation marker file with timestamp and execution ID.
    #>
    try {
        $markerPath = Get-CancellationMarkerPath
        $userName = if ($env:USERNAME) { $env:USERNAME } elseif ($env:USER) { $env:USER } else { "Unknown" }
        $markerData = @{
            CancelledAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss UTC')
            ExecutionId = $global:executionId
            User = $userName
        }
        $markerData | ConvertTo-Json | Out-File -FilePath $markerPath -Encoding UTF8 -Force
        Write-Host "📝 Cancellation marker created: $markerPath" -ForegroundColor Gray
        Write-CancellationDebugLog "MarkerCreate" "Cancellation marker file created successfully" -Context "Path=$markerPath|ExecutionId=$($global:executionId)|User=$($markerData.User)"
    } catch {
        Write-Warning "Failed to create cancellation marker: $_"
        Write-CancellationDebugLog "Error" "Failed to create cancellation marker file" -Context "Error=$($_)|Path=$markerPath"
    }
}

function Remove-CancellationMarker {
    <#
    .SYNOPSIS
        Remove cancellation marker file.
    #>
    try {
        $markerPath = Get-CancellationMarkerPath
        if (Test-Path $markerPath) {
            Remove-Item $markerPath -Force -ErrorAction SilentlyContinue
            Write-Host "🗑️ Cancellation marker removed" -ForegroundColor Gray
            Write-CancellationDebugLog "MarkerRemove" "Cancellation marker file removed successfully" -Context "Path=$markerPath"
        } else {
            Write-CancellationDebugLog "MarkerRemove" "No cancellation marker file found to remove" -Context "Path=$markerPath"
        }
    } catch {
        Write-Warning "Failed to remove cancellation marker: $_"
        Write-CancellationDebugLog "Error" "Failed to remove cancellation marker file" -Context "Error=$($_)|Path=$markerPath"
    }
}

function Test-CancellationRecovery {
    <#
    .SYNOPSIS
        Check for cancellation marker and prompt user for recovery action.
        Returns $true if user wants to resume, $false if starting fresh.
    #>
    Write-CancellationDebugLog "Recovery" "Checking for cancellation marker file" -Context "Testing cancellation recovery"
    
    if (Test-CancellationMarker) {
        Write-CancellationDebugLog "MarkerFound" "Cancellation marker file detected" -Context "Previous manual cancellation detected"
        
        try {
            $markerPath = Get-CancellationMarkerPath
            $markerContent = Get-Content $markerPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            Write-Host ""
            Write-Host "🔄 CANCELLATION RECOVERY DETECTED" -ForegroundColor Yellow
            Write-Host "=".PadRight(50, "=") -ForegroundColor Gray
            Write-Host "Previous audit run was manually cancelled (CTRL+C)." -ForegroundColor Yellow
            
            if ($markerContent) {
                Write-Host "📅 Cancelled at: $($markerContent.CancelledAt)" -ForegroundColor Gray
                Write-Host "🆔 Execution ID: $($markerContent.ExecutionId)" -ForegroundColor Gray
                Write-Host "👤 User: $($markerContent.User)" -ForegroundColor Gray
                Write-CancellationDebugLog "MarkerData" "Cancellation marker data parsed successfully" -Context "CancelledAt=$($markerContent.CancelledAt)|ExecutionId=$($markerContent.ExecutionId)|User=$($markerContent.User)"
            } else {
                Write-CancellationDebugLog "Warning" "Cancellation marker file found but data could not be parsed" -Context "Invalid JSON or empty file"
            }
            
            Write-Host ""
            Write-Host "Do you want to resume from your last checkpoint? (Y/N): " -NoNewline -ForegroundColor Cyan
            $response = Read-Host
            
            Write-CancellationDebugLog "UserChoice" "User response to cancellation recovery prompt" -Context "Response=$response"
            
            Remove-CancellationMarker
            
            if ($response -eq 'Y' -or $response -eq 'y') {
                Write-Host "✅ Resuming from checkpoint after manual cancellation..." -ForegroundColor Green
                Write-CancellationDebugLog "Resume" "User chose to resume from cancellation checkpoint" -Context "Will enable Resume mode"
                return $true
            } else {
                Write-Host "🔄 Starting fresh audit (cancellation marker cleared)..." -ForegroundColor Yellow
                Write-CancellationDebugLog "Fresh" "User chose to start fresh audit" -Context "Cancellation marker cleared"
                return $false
            }
            
        } catch {
            Write-Warning "Failed to read cancellation marker, proceeding normally: $_"
            Write-CancellationDebugLog "Error" "Failed to process cancellation marker" -Context "Error=$($_)|Proceeding normally"
            Remove-CancellationMarker
            return $false
        }
    } else {
        Write-CancellationDebugLog "NoMarker" "No cancellation marker found" -Context "Normal script start"
    }
    
    return $false
}

# --- Critical Functions (Called by Event Handlers) ---
function Invoke-PartialResults {
    param(
        [object]$CheckpointData
    )
    
    try {
        Write-Host "📊 Generating partial results report..." -ForegroundColor Cyan
        
        # Mark this as a partial results run
        $global:IsPartialResults = $true
        $global:partialResultsTimestamp = $CheckpointData.Timestamp
        $global:partialResultsVaultCount = $CheckpointData.VaultIndex
        $global:partialResultsTotalVaults = $CheckpointData.TotalVaults
        
        # Set the execution ID to match the checkpoint for consistent naming
        $global:executionId = $CheckpointData.ExecutionId
        
        # Generate timestamp for partial results
        $partialTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        
        # Update file paths to indicate partial results
        $csvPath = Join-Path $outDir "KeyVaultComprehensiveAudit_PARTIAL_${partialTimestamp}.csv"
        $htmlPath = Join-Path $outDir "KeyVaultComprehensiveAudit_PARTIAL_${partialTimestamp}.html"
        
        Write-Host "📁 Output files:" -ForegroundColor Gray
        Write-Host "   CSV: $(Split-Path $csvPath -Leaf)" -ForegroundColor Gray
        Write-Host "   HTML: $(Split-Path $htmlPath -Leaf)" -ForegroundColor Gray
        
        # Generate CSV report using existing logic
        try {
            $global:auditResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "✅ Partial CSV report generated: $(Split-Path $csvPath -Leaf)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to generate partial CSV report: $_" -ForegroundColor Red
            return $false
        }
        
        # Generate comprehensive HTML report for partial results using the new function
        try {
            # Calculate executive summary for partial results
            $partialExecutiveSummary = @{
                TotalKeyVaults = if ($global:auditResults -and (Get-SafeProperty -Object $global:auditResults -PropertyName 'Count') -ne 'N/A') { $global:auditResults.Count } else { 0 }
                CompliantVaults = if ($global:auditResults) { (@($global:auditResults | Where-Object { $_.ComplianceScore -ge 90 })).Count } else { 0 }
                CompliancePercentage = if ($global:auditResults -and (Get-SafeProperty -Object $global:auditResults -PropertyName 'Count') -ne 'N/A' -and $global:auditResults.Count -gt 0) { 
                    [math]::Round(((@($global:auditResults | Where-Object { $_.ComplianceScore -ge 90 })).Count / $global:auditResults.Count) * 100, 1) 
                } else { 0 }
                AverageComplianceScore = if ($global:auditResults -and (Get-SafeProperty -Object $global:auditResults -PropertyName 'Count') -ne 'N/A' -and $global:auditResults.Count -gt 0) { 
                    $complianceMeasure = $global:auditResults | Measure-Object -Property ComplianceScore -Average
                    [math]::Round((Get-SafeProperty -Object $complianceMeasure -PropertyName 'Average' -DefaultValue 0), 1) 
                } else { 0 }
                CompanyAverageScore = if ($global:auditResults -and (Get-SafeProperty -Object $global:auditResults -PropertyName 'Count') -ne 'N/A' -and $global:auditResults.Count -gt 0) { 
                    $companyScores = @($global:auditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'CompanyComplianceScore') -ne 'N/A' } | ForEach-Object { try { [int]($_.CompanyComplianceScore -replace '%', '') } catch { 0 } })
                    if ($companyScores.Count -gt 0) { 
                        $companyMeasure = $companyScores | Measure-Object -Average
                        [math]::Round((Get-SafeProperty -Object $companyMeasure -PropertyName 'Average' -DefaultValue 0), 1) 
                    } else { 0 }
                } else { 0 }
                HighRiskVaults = if ($global:auditResults) { (@($global:auditResults | Where-Object { $_.ComplianceScore -lt 60 })).Count } else { 0 }
            }
            
            # Use the comprehensive HTML generation function
            $htmlGenerated = New-ComprehensiveHtmlReport -OutputPath $htmlPath -AuditResults $global:auditResults -ExecutiveSummary $partialExecutiveSummary -AuditStats $global:auditStats -IsPartialResults $true -CheckpointData $CheckpointData -PartialDataSource "checkpoint"
            
            if (-not $htmlGenerated) {
                Write-Host "❌ Failed to generate comprehensive partial HTML report" -ForegroundColor Red
                return $false
            }
        } catch {
            Write-Host "❌ Failed to generate comprehensive partial HTML report: $_" -ForegroundColor Red
            return $false
        }
        
        # Display summary
        Write-Host ""
        Write-Host "📋 Partial Results Summary:" -ForegroundColor Cyan
        Write-Host "   Original execution: $($CheckpointData.ExecutionId)" -ForegroundColor Gray
        Write-Host "   Original timestamp: $($CheckpointData.Timestamp)" -ForegroundColor Gray
        Write-Host "   Vaults processed: $($CheckpointData.VaultIndex)/$($CheckpointData.TotalVaults)" -ForegroundColor Gray
        Write-Host "   Progress: $([math]::Round(($CheckpointData.VaultIndex / $CheckpointData.TotalVaults) * 100, 1))%" -ForegroundColor Gray
        Write-Host "   Results extracted: $($global:auditResults.Count) vaults" -ForegroundColor Green
        
        # Cloud upload integration for partial results
        if ($UploadToCloud) {
            Write-Host ""
            Write-Host "📤 Automatic cloud upload enabled for partial results..." -ForegroundColor Cyan
            
            # Get target upload path
            $uploadPath = Get-CloudUploadPath -ProvidedPath $CloudUploadPath
            
            # Attempt cloud upload
            $uploadSuccess = Invoke-CloudUpload -OutputDirectory $outDir -CsvFilePath $csvPath -HtmlPath $htmlPath -ErrorLogPath $global:errPath -PermissionsLogPath $global:permissionsPath -DataIssuesLogPath $global:dataIssuesPath -TargetPath $uploadPath
            
            if ($uploadSuccess) {
                Write-Host "✅ Partial results cloud upload completed successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Partial results cloud upload failed or was cancelled" -ForegroundColor Yellow
            }
        } else {
            # Detect Azure Cloud Shell and offer upload option for partial results
            $isCloudShell = $false
            $cloudShellIndicators = @($env:ACC_TERM, $env:ACC_CLOUD, $env:AZUREPS_HOST_ENVIRONMENT)
            foreach ($indicator in $cloudShellIndicators) {
                if (-not [string]::IsNullOrWhiteSpace($indicator)) {
                    $isCloudShell = $true
                    break
                }
            }
            
            if (-not $isCloudShell -and $PWD.Path.StartsWith('/home/') -and (Test-Path '/usr/bin/az' -ErrorAction SilentlyContinue)) {
                $isCloudShell = $true
            }
            
            if ($isCloudShell) {
                Write-Host ""
                Write-Host "☁️  Azure Cloud Shell detected" -ForegroundColor Cyan
                Write-Host "To prevent data loss when Cloud Shell session expires, you can upload partial results to OneDrive/SharePoint." -ForegroundColor Yellow
                Write-Host ""
                $offerUpload = Read-Host "Would you like to upload partial audit files to OneDrive/SharePoint? (Y/N)"
                
                if ($offerUpload -match '^[Yy]') {
                    # Get target upload path
                    $uploadPath = Get-CloudUploadPath -ProvidedPath $CloudUploadPath
                    
                    # Attempt cloud upload
                    $uploadSuccess = Invoke-CloudUpload -OutputDirectory $outDir -CsvFilePath $csvPath -HtmlPath $htmlPath -ErrorLogPath $global:errPath -PermissionsLogPath $global:permissionsPath -DataIssuesLogPath $global:dataIssuesPath -TargetPath $uploadPath
                    
                    if ($uploadSuccess) {
                        Write-Host "✅ Partial results cloud upload completed successfully" -ForegroundColor Green
                    } else {
                        Write-Host "⚠️  Partial results cloud upload failed or was cancelled" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "📋 Partial results remain in Cloud Shell temporary storage: $outDir" -ForegroundColor Gray
                    Write-Host "⚠️  Remember to download files before Cloud Shell session expires" -ForegroundColor Yellow
                }
            }
        }
        
        return $true
        
    } catch {
        Write-Host "❌ Error processing partial results: $_" -ForegroundColor Red
        Write-ErrorLog "PartialResults" "Failed to process partial results: $($_.Exception.Message)"
        return $false
    }
}

function New-ComprehensiveHtmlReport {
    <#
    .SYNOPSIS
    Generate comprehensive HTML report with inline template generation
    .DESCRIPTION
    Creates detailed HTML audit reports by generating HTML content inline (not from external templates).
    All HTML is dynamically generated within the function based on audit data.
    
    Supports:
    - Full audit results with complete compliance analysis
    - Partial/resume results with progress tracking
    - Dynamic data visualization and executive insights
    - Consistent feature-rich reporting regardless of audit mode
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [Parameter(Mandatory)]
        [array]$AuditResults,
        [Parameter()]
        [hashtable]$ExecutiveSummary,
        [Parameter()]
        [object]$AuditStats,
        [Parameter()]
        [bool]$IsPartialResults = $false,
        [Parameter()]
        [object]$CheckpointData = $null,
        [Parameter()]
        [ValidateSet("checkpoint", "csv", "interruption", "resume")]
        [string]$PartialDataSource = "checkpoint",
        [Parameter()]
        [string]$InterruptionReason = ""
    )
        # Ensure global currentUser is defined to avoid 'cannot be retrieved because it has not been set' errors
        try {
            # Check for an existing global variable named 'currentUser'
            $gv = Get-Variable -Name 'currentUser' -Scope Global -ErrorAction SilentlyContinue
            if (-not $gv) {
                # Define the global variable with a safe default
                Set-Variable -Name 'currentUser' -Scope Global -Value 'System' -Force
            } else {
                # If it exists but has no value, set a default safely
                try {
                    $val = (Get-Variable -Name 'currentUser' -Scope Global -ValueOnly -ErrorAction Stop)
                    if ([string]::IsNullOrWhiteSpace([string]$val)) { Set-Variable -Name 'currentUser' -Scope Global -Value 'System' -Force }
                } catch {
                    Set-Variable -Name 'currentUser' -Scope Global -Value 'System' -Force
                }
            }
        } catch {
            # As a last resort, ensure the variable is present
            Set-Variable -Name 'currentUser' -Scope Global -Value 'System' -Force
        }

        # Normalize globals used in template rendering to avoid runtime errors when script is run in CSV-only or offline modes
        # Use a local safe variable to prevent unbound variable exceptions inside here-strings
        $safeCurrentUser = if ($null -ne $global:currentUser -and $global:currentUser) { $global:currentUser } else { 'System' }

    # Function body starts here
    try {
        if ($null -eq $ExecutiveSummary) { $ExecutiveSummary = @{} }
        if ($null -eq $AuditStats) { $AuditStats = @{} }
        Write-UserMessage -Message "Generating comprehensive HTML audit report..." -Type Progress
        Write-UserMessage "HTML report generation started. IsPartial: $IsPartialResults, Source: $PartialDataSource" -Type Verbose
        
        # Defensive check for AuditResults - ensure it's a proper array
        if (-not $AuditResults) {
            Write-Warning "AuditResults is null or empty. Creating empty array."
            $AuditResults = @()
        } elseif ($AuditResults -isnot [array]) {
            # Convert single object to array
            $AuditResults = @($AuditResults)
        }
        
        # Ensure each audit result is properly formatted with error handling
        $AuditResults = @($AuditResults | ForEach-Object {
            if ($_ -and $_.PSObject) {
                $_
            } else {
                # Skip null or malformed objects
                Write-Warning "Skipping malformed audit result object"
                $null
            }
        } | Where-Object { $null -ne $_ })
        
    # Use Get-SafeCount to avoid .Count property errors when a single object is passed
    $auditResultsCount = Get-SafeCount $AuditResults
        Write-UserMessage "Processed AuditResults: Count = $auditResultsCount" -Type Verbose

        # Additional defensive normalization and debug information to avoid unexpected .Count access
        try {
            # Ensure AuditResults is an array of PSCustomObject
            $AuditResults = @($AuditResults | Where-Object { $_ -ne $null })
            for ($i = 0; $i -lt $AuditResults.Count; $i++) {
                if (-not $AuditResults[$i].PSObject) { Write-Verbose "AuditResults item $i is not a PSObject" }
            }
        } catch {
            Write-Host "Debug: Failed to normalize AuditResults: $_" -ForegroundColor Yellow
        }

        # Dump types/counts of key inputs for troubleshooting (visible in console to help identify which object lacks Count)
        try {
            $dbgAuditResultsType = if ($AuditResults) { $AuditResults.GetType().FullName } else { 'null' }
            $dbgExecutiveType = if ($ExecutiveSummary) { $ExecutiveSummary.GetType().FullName } else { 'null' }
            $dbgCheckpointType = if ($CheckpointData) { $CheckpointData.GetType().FullName } else { 'null' }
            Write-Host "Debug Input Types: AuditResults=$dbgAuditResultsType (Count=$([int] (Get-SafeCount $AuditResults))) | ExecutiveSummary=$dbgExecutiveType | CheckpointData=$dbgCheckpointType" -ForegroundColor Cyan
        } catch {
            Write-Host "Debug: Error while dumping input types: $_" -ForegroundColor Yellow
        }
        
        # Helper function to format stat values with explanations for zero values
        function Format-StatValue {
            param([int]$Value, [string]$Explanation)
            if ($Value -eq 0) {
                return "<span style='color: #dc3545; font-size: 0.8em;'>0<br/>($Explanation)</span>"
            } else {
                return $Value.ToString()
            }
        }
        
        # Convert AuditStats to hashtable if needed
        if ($AuditStats -and $AuditStats -isnot [hashtable]) {
            try {
                if ($AuditStats -is [PSCustomObject]) {
                    $convertedStats = @{}
                    foreach ($prop in $AuditStats.PSObject.Properties) {
                        $convertedStats[$prop.Name] = $prop.Value
                    }
                    $AuditStats = $convertedStats
                    Write-UserMessage "Converted AuditStats from PSCustomObject to Hashtable" -Type Verbose
                } else {
                    Write-UserMessage -Message "AuditStats parameter is not Hashtable or PSCustomObject, using empty hashtable" -Type Warning
                    $AuditStats = @{}
                }
            } catch {
                Write-UserMessage -Message "Failed to convert AuditStats: $_" -Type Warning
                $AuditStats = @{}
            }
        } elseif (-not $AuditStats) {
            $AuditStats = @{}
        }
        

        
        # Determine report context and characteristics
        $reportContext = @{
            IsPartial = $IsPartialResults
            Source = $PartialDataSource
            InterruptionReason = $InterruptionReason
            HasCheckpointData = $null -ne $CheckpointData
            ReportType = if ($IsPartialResults) { "Partial Results" } else { "Complete Audit" }
        }
        
        Write-UserMessage "Report context: $($reportContext | ConvertTo-Json -Compress)" -Type Verbose
        
        # Use main HTML generation logic but adapt for partial results
        $testModeAnimation = ""
        if ($TestMode) {
            $testModeAnimation = "animation: bloom 2s infinite;"
        }
        
        # Calculate statistics with enhanced handling for partial results
        try {
            Write-UserMessage "Calculating report statistics..." -Type Verbose
            $totalVaults = if ($IsPartialResults -and $CheckpointData -and $CheckpointData.TotalVaults) { 
                $CheckpointData.TotalVaults 
            } elseif ($IsPartialResults -and $ExecutiveSummary -and $ExecutiveSummary.TotalDiscoveredVaults) {
                $ExecutiveSummary.TotalDiscoveredVaults
            } else { 
                if ($AuditResults -and ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -or (Get-SafeProperty -Object $AuditResults -PropertyName 'Length'))) { (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) } else { 0 }
            }
            # Use Get-SafeCount for processedVaults as well
            $processedVaults = Get-SafeCount $AuditResults
            $completionPercentage = if ($totalVaults -gt 0) { 
                [math]::Round(($processedVaults / $totalVaults) * 100, 1) 
            } else { 100 }
            $remainingVaults = $totalVaults - $processedVaults
            Write-UserMessage "Statistics calculated - Processed: $processedVaults, Total: $totalVaults, Completion: $completionPercentage%" -Type Verbose
            Write-UserMessage "Report statistics: Processed=$processedVaults, Total=$totalVaults, Completion=$completionPercentage%" -Type Verbose
        } catch {
            Write-Host "❌ Error calculating report statistics: $_" -ForegroundColor Red
        }
        
        # Generate enhanced executive summary for partial results
        if ($IsPartialResults) {
            $ExecutiveSummary.TotalKeyVaults = $auditResultsCount
            $ExecutiveSummary.ProcessedVaults = $processedVaults
            $ExecutiveSummary.TotalDiscoveredVaults = $totalVaults
            $ExecutiveSummary.CompletionPercentage = $completionPercentage
            $ExecutiveSummary.RemainingVaults = $remainingVaults
            $ExecutiveSummary.IsPartialResults = $true
            $ExecutiveSummary.PartialDataSource = $PartialDataSource
            $ExecutiveSummary.InterruptionReason = $InterruptionReason
            
            # Add checkpoint context if available
            if ($CheckpointData) {
                $checkpointTimestamp = Get-SafeProperty -Object $CheckpointData -PropertyName 'Timestamp'
                if ($checkpointTimestamp -ne 'N/A') {
                    $ExecutiveSummary.CheckpointTimestamp = $checkpointTimestamp
                }
                $checkpointVersion = Get-SafeProperty -Object $CheckpointData -PropertyName 'ScriptVersion'
                if ($checkpointVersion -ne 'N/A') {
                    $ExecutiveSummary.CheckpointVersion = $checkpointVersion
                }
                $executionId = Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId'
                if ($executionId -ne 'N/A') {
                    $ExecutiveSummary.ExecutionId = $executionId
                }
            }
        }
        
        # Build recommendations with partial results considerations
        $quickWinsRecommendations = if ($IsPartialResults) {
            @(
                "⚠️ NOTICE: These recommendations are based on PARTIAL AUDIT DATA ($completionPercentage% complete)<br><em>Complete the full audit for comprehensive recommendations</em>",
                "[HIGH] Enable RBAC authorization model for analyzed Key Vaults to leverage Azure AD for fine-grained access control<br><em>Example:</em> az keyvault update --name mykeyvault --enable-rbac-authorization true",
                "[HIGH] Implement proper network access restrictions using virtual network service endpoints or private endpoints<br><em>Example:</em> Restrict DefaultAction to Deny, configure IP rules for authorized networks only",
                "[MEDIUM] Enable diagnostic logging for all Key Vaults to capture access patterns and security events<br><em>Example:</em> Configure Log Analytics workspace integration, monitor AuditEvent and AllMetrics categories",
                "[MEDIUM] Review and minimize access permissions - remove unused service principals and overprivileged assignments<br><em>Example:</em> Audit access policies quarterly, implement principle of least privilege with specific secret/key/certificate permissions",
                "[MEDIUM] Replace hardcoded secrets with Key Vault references in application configurations<br><em>Example:</em> App Settings: @Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/connection-string/), ARM templates with KeyVault references",
                "🟡 MEDIUM: Set up secret expiration monitoring and automated alerts for approaching expirations<br><em>Example:</em> Logic App triggered by Key Vault events, query for secrets expiring in 30 days, send Teams/email notifications with renewal instructions",
                "🟢 LOW: Enable Key Vault notifications for secret access patterns and unauthorized changes<br><em>Example:</em> Configure Event Grid subscriptions for 'Microsoft.KeyVault.SecretNewVersion' and 'Microsoft.KeyVault.VaultAccessPolicyChanged' events, integrate with monitoring dashboards"
            )
        } else {
            @(
                "[HIGH] Enable RBAC authorization model for all Key Vaults to leverage Azure AD for fine-grained access control<br><em>Example:</em> az keyvault update --name mykeyvault --enable-rbac-authorization true",
                "[HIGH] Implement proper network access restrictions using virtual network service endpoints or private endpoints<br><em>Example:</em> Restrict DefaultAction to Deny, configure IP rules for authorized networks only",
                "[MEDIUM] Enable diagnostic logging for all Key Vaults to capture access patterns and security events<br><em>Example:</em> Configure Log Analytics workspace integration, monitor AuditEvent and AllMetrics categories",
                "[MEDIUM] Review and minimize access permissions - remove unused service principals and overprivileged assignments<br><em>Example:</em> Audit access policies quarterly, implement principle of least privilege with specific secret/key/certificate permissions",
                "[MEDIUM] Replace hardcoded secrets with Key Vault references in application configurations<br><em>Example:</em> App Settings: @Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/connection-string/), ARM templates with KeyVault references",
                "🟡 MEDIUM: Set up secret expiration monitoring and automated alerts for approaching expirations<br><em>Example:</em> Logic App triggered by Key Vault events, query for secrets expiring in 30 days, send Teams/email notifications with renewal instructions",
                "🟢 LOW: Enable Key Vault notifications for secret access patterns and unauthorized changes<br><em>Example:</em> Configure Event Grid subscriptions for 'Microsoft.KeyVault.SecretNewVersion' and 'Microsoft.KeyVault.VaultAccessPolicyChanged' events, integrate with monitoring dashboards"
            )
        }
        
        # Start building HTML content
        # Generate HTML content with defensive programming for Count properties
        Write-UserMessage "About to generate HTML content" -Type Verbose
        
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Key Vault Enhanced Security & Compliance Audit$(if ($IsPartialResults) { " - Partial Results" })</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
.test-mode-banner { background: #dc3545; color: white; padding: 15px; text-align: center; font-weight: bold; font-size: 1.4em; border-radius: 8px; margin: 20px 0; $testModeAnimation }
.partial-results-banner { background: #e67e22; color: white; padding: 12px; text-align: center; font-weight: 600; font-size: 1.1em; border-radius: 6px; margin: 15px 0; border-left: 4px solid #d35400; opacity: 0.95; }
.summary { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.compliant { color: #28a745; font-weight: bold; }
.non-compliant { color: #dc3545; font-weight: bold; }
.partially-compliant { color: #ffc107; font-weight: bold; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
.stat-card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; position: relative; }
.stat-card:hover { transform: translateY(-2px); transition: transform 0.3s ease; }
.stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
.stat-label { color: #666; margin-top: 5px; }
.stat-percentage { font-size: 0.9em; margin-top: 3px; font-weight: bold; }
.progress-bar { width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; margin-top: 8px; }
.progress-fill { height: 100%; transition: width 0.8s ease; border-radius: 4px; }
.dual-framework { display: flex; gap: 10px; margin-top: 10px; }
.framework-score { flex: 1; padding: 8px; border-radius: 6px; text-align: center; font-size: 0.85em; }
.microsoft-framework { background: #e7f3ff; border: 1px solid #b8daff; }
.company-framework { background: #fff3cd; border: 1px solid #ffeaa7; }
table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; font-size: 0.8em; }
th { background: #343a40; color: white; padding: 6px; text-align: left; font-weight: 600; cursor: pointer; position: sticky; top: 0; z-index: 10; font-size: 0.8em; }
td { padding: 4px; border-bottom: 1px solid #dee2e6; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.8em; }
tr:nth-child(even) { background-color: #f8f9fa; }
tr:hover { background-color: #e9ecef; }
.recommendations { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-top: 20px; }
.filter-input { width: 90%; padding: 3px; margin-bottom: 3px; border: 1px solid #ccc; border-radius: 4px; font-size: 0.75em; }
.identity-section { background: #e7f3ff; border: 1px solid #b8daff; padding: 15px; border-radius: 8px; margin: 20px 0; }
.security-section { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 8px; margin: 20px 0; }
.secrets-section { background: #fff3cd; border: 1px solid #ffeeba; padding: 15px; border-radius: 8px; margin: 20px 0; }
.quick-wins-section { background: #f8f9ff; border: 1px solid #e6e6ff; padding: 15px; border-radius: 8px; margin: 20px 0; }
.configuration-coverage-section { background: #f0f8ff; border: 1px solid #b8daff; padding: 15px; border-radius: 8px; margin: 20px 0; }
.compliance-legend-section { background: #f8f0ff; border: 1px solid #e6d7ff; padding: 15px; border-radius: 8px; margin: 20px 0; }
.action-link { color: #007bff; cursor: pointer; text-decoration: underline; font-size: 0.8em; }
.action-details { display: none; background: #f8f9fa; border: 1px solid #dee2e6; padding: 8px; margin-top: 3px; border-radius: 4px; font-size: 0.75em; }
.legend-section { background: #e9ecef; border: 1px solid #dee2e6; padding: 15px; border-radius: 8px; margin: 20px 0; }
.tooltip { position: relative; display: inline-block; cursor: help; color: #007bff; font-weight: bold; }
.tooltip .tooltiptext { visibility: hidden; width: 300px; background-color: #333; color: #fff; text-align: left; padding: 8px; border-radius: 6px; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -150px; font-size: 0.8em; box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
.tooltip:hover .tooltiptext { visibility: visible; }
.enhancement-badge { display: inline-block; padding: 2px 8px; background: #667eea; color: white; border-radius: 12px; font-size: 0.7em; margin-left: 8px; }
.collapsible-toggle { cursor: pointer; padding: 5px 10px; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; font-size: 0.8em; margin-left: 10px; transition: all 0.3s ease; }
.collapsible-toggle:hover { background: #e9ecef; }
.collapsible-content { margin-top: 10px; }
@keyframes bloom { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }
@keyframes progressAnimation { from { width: 0%; } }
    </style>
    <script>
function filterTable(input, col) {
    var filter = input.value.toUpperCase();
    var table = document.getElementById("vaultTable");
    var trs = table.getElementsByTagName("tr");
    for (var i = 2; i < trs.length; i++) {
        var tds = trs[i].getElementsByTagName("td");
        if (tds.length > col) {
            var txt = tds[col].textContent || tds[col].innerText;
            trs[i].style.display = txt.toUpperCase().indexOf(filter) > -1 ? "" : "none";
        }
    }
}
    // Removed stray catch block from JavaScript

function sortTable(n) {
    var table = document.getElementById("vaultTable");
    var switching = true;
    var dir = "asc";
    var switchcount = 0;
    while (switching) {
        switching = false;
        var rows = table.rows;
        for (var i = 2; i < (rows.length - 1); i++) {
            var shouldSwitch = false;
            var x = rows[i].getElementsByTagName("TD")[n];
            var y = rows[i + 1].getElementsByTagName("TD")[n];
            if (dir == "asc") {
                if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            } else if (dir == "desc") {
                if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount++;
        } else {
            if (switchcount == 0 && dir == "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
}

function toggleActionItems(id) {
    var element = document.getElementById(id);
    if (element.style.display === "none" || element.style.display === "") {
        element.style.display = "block";
    } else {
        element.style.display = "none";
    }
}

function toggleCollapsible(elementId) {
    var content = document.getElementById(elementId);
    var toggle = content.previousElementSibling.querySelector('.collapsible-toggle');
    
    if (content.style.display === "none" || content.style.display === "") {
        content.style.display = "block";
        toggle.textContent = "Hide Details";
        toggle.style.backgroundColor = "#007bff";
        toggle.style.color = "white";
    } else {
        content.style.display = "none";
        toggle.textContent = "Show Details";
        toggle.style.backgroundColor = "#f8f9fa";
        toggle.style.color = "#333";
    }
}
    </script>
</head>
<body>
    <div class="header">
        <h1>🔐 Azure Key Vault Enhanced Security & Compliance Audit$(if ($IsPartialResults) { " - Partial Results" })</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') by $safeCurrentUser</p>
        $(if ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'ExecutionId') -ne 'N/A' -and $ExecutiveSummary.ExecutionId) { "<p><strong>Execution ID:</strong> $($ExecutiveSummary.ExecutionId)</p>" } else { "" })
        <p><strong>Script Version:</strong> 2.1 - Production Enterprise Edition</p>
"@
        
        # Add enhanced partial results banner if applicable
        if ($IsPartialResults) {
            $bannerText = switch ($PartialDataSource) {
                "interruption" { "⚠️ PARTIAL RESULTS REPORT - Generated from interrupted audit (Manual interruption)" }
                "resume" { "⚠️ PARTIAL RESULTS REPORT - Generated from resumed audit checkpoint" }
                "csv" { "⚠️ PARTIAL RESULTS REPORT - Generated from existing CSV data file" }
                default { "⚠️ PARTIAL RESULTS REPORT - Generated from checkpoint data" }
            }
            
            if ($InterruptionReason) {
                $bannerText += " - Reason: $InterruptionReason"
            }
            
            $htmlContent += @"
    </div>
    
    <div class="partial-results-banner">
        $bannerText
    </div>
"@
            
            if ($CheckpointData -or $InterruptionReason) {
                $remainingVaults = $totalVaults - $processedVaults
                $estimatedTimeRemaining = if ($AuditStats -and $AuditStats.AverageProcessingTime -and $remainingVaults -gt 0) {
                    [math]::Round($AuditStats.AverageProcessingTime * $remainingVaults / 60, 1)
                } else { "Unknown" }
                
                $htmlContent += @"
    <div class="summary">
        <h2>📊 Partial Results Information & Recovery Context</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$processedVaults</div>
                <div class="stat-label">Processed Vaults</div>
                <div class="stat-percentage">of $totalVaults total discovered</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $completionPercentage%; background: #667eea; animation: progressAnimation 1.5s ease-out;"></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$completionPercentage%</div>
                <div class="stat-label">Completion</div>
                <div class="stat-percentage">Audit Progress</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $completionPercentage%; background: $(if ($completionPercentage -ge 75) { '#28a745' } elseif ($completionPercentage -ge 50) { '#ffc107' } else { '#dc3545' }); animation: progressAnimation 2s ease-out;"></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$remainingVaults</div>
                <div class="stat-label">Remaining</div>
                <div class="stat-percentage">Vaults to Process</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($estimatedTimeRemaining -ne "Unknown") { "$estimatedTimeRemaining min" } else { "N/A" })</div>
                <div class="stat-label">Est. Time</div>
                <div class="stat-percentage">To Complete</div>
            </div>
        </div>
        
        <div style="background: #e7f3ff; border: 1px solid #b8daff; padding: 15px; border-radius: 8px; margin-top: 20px;">
            <h4>📋 Data Source & Audit Context:</h4>
            <ul>
                <li><strong>Original Execution ID:</strong> $(if ($CheckpointData) { Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId' -DefaultValue "N/A" } else { "N/A" })</li>
                <li><strong>Original Audit Started:</strong> $(if ($CheckpointData.Timestamp) { $CheckpointData.Timestamp } else { "Unknown" })</li>
                <li><strong>Data Source:</strong> $(
                    switch ($PartialDataSource) {
                        "interruption" { "Emergency checkpoint from interrupted execution" }
                        "resume" { "Checkpoint recovery from resumed audit" }
                        "csv" { "CSV file import (offline report generation)" }
                        default { "Checkpoint data recovery" }
                    }
                )</li>
                <li><strong>Interruption Reason:</strong> $(if ($InterruptionReason) { $InterruptionReason } else { "Not specified" })</li>
                <li><strong>Processing Status:</strong> $processedVaults of $totalVaults Key Vaults analyzed ($completionPercentage% complete, $remainingVaults remaining)</li>
                <li><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') by $safeCurrentUser</li>
"@
                
                # Add recovery instructions if checkpoint data is available
                if ($CheckpointData -and $remainingVaults -gt 0) {
                    $htmlContent += @"
                <li><strong>Script Version:</strong> $(if ($CheckpointData.ScriptVersion) { $CheckpointData.ScriptVersion } else { "Unknown" })</li>
            </ul>
            
            <h4>🔄 Resume Instructions:</h4>
            <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 12px; border-radius: 6px; margin-top: 10px;">
                <strong>To complete this audit:</strong><br>
                1. Use the <code>-Resume</code> parameter to continue from the last checkpoint<br>
                2. The script will automatically detect and load checkpoint data<br>
                3. Processing will continue from vault $(if ($CheckpointData.NextVaultIndex) { $CheckpointData.NextVaultIndex } else { $processedVaults + 1 }) of $totalVaults<br>
                4. Estimated time to complete: $(if ($estimatedTimeRemaining -ne "Unknown") { "$estimatedTimeRemaining minutes" } else { "depends on remaining vault complexity" })
                <br><br>
                <strong>Command example:</strong><br>
                <code>.\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume</code>
            </div>
            
            <h4>⚠️ Important Notes:</h4>
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 12px; border-radius: 6px; margin-top: 10px;">
                • This report contains <strong>incomplete audit data</strong> ($completionPercentage% of total Key Vaults)<br>
                • Compliance scores and recommendations are based on partial data only<br>
                • Complete the full audit for comprehensive security assessment<br>
                • Some statistics may be underrepresented due to incomplete data collection
            </div>
"@
                } else {
                    $htmlContent += @"
            </ul>
            
            <h4>ℹ️ Report Limitations:</h4>
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 12px; border-radius: 6px; margin-top: 10px;">
                • This report is based on partial audit data ($completionPercentage% complete)<br>
                • Compliance scores and recommendations may not represent the full environment<br>
                • Consider running a complete audit for comprehensive assessment<br>
                • Some security insights may be missing due to incomplete data collection
            </div>
"@
                }
                
                $htmlContent += @"
        </div>
    </div>
"@
            }
        }
        
        $htmlContent += @"
                $(if ($global:executionId -and $CheckpointData -and (Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId') -and $global:executionId -ne (Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId')) { "<li><strong>Report Generation ID:</strong> $($global:executionId)</li>" } else { "" })
            </ul>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-top: 15px;">
            <h4>🔄 Audit Resume Instructions:</h4>
            <p><strong>To complete the full organizational audit:</strong></p>
            <ol>
                <li><strong>Check for checkpoint files:</strong> Look for files matching <code>akv_audit_checkpoint_$(if ($CheckpointData) { Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId' -DefaultValue "unknown" } else { "unknown" })_*.json</code> in your output directory</li>
                <li><strong>Resume from checkpoint:</strong> Run <code>Get-AKV_Roles-SecAuditCompliance.ps1 -Resume</code> and select the appropriate checkpoint</li>
                <li><strong>Alternative approach:</strong> Start a new complete audit with <code>Get-AKV_Roles-SecAuditCompliance.ps1</code> (full scan)</li>
                <li><strong>Test mode first:</strong> Use <code>Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode</code> to validate setup before full scan</li>
            </ol>
            <p><strong>📝 Note:</strong> Resume functionality requires the original checkpoint files from the incomplete audit. If checkpoints are not available, a new full audit will be required.</p>
        </div>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 8px; margin-top: 15px;">
            <h4>⚠️ Data Completeness Disclaimer:</h4>
            <p>This partial results report contains analysis for <strong>$processedVaults Key Vaults ($completionPercentage% of discovered infrastructure)</strong>. Statistics, percentages, and compliance metrics reflect only the processed subset and should not be extrapolated to represent complete organizational security posture.</p>
            <ul>
                <li><strong>Risk Assessment:</strong> Additional security risks may exist in unprocessed Key Vaults</li>
                <li><strong>Compliance Scoring:</strong> Organization-wide compliance rates may differ significantly</li>
                <li><strong>Resource Planning:</strong> Complete audit required for accurate capacity and resource planning</li>
                <li><strong>Executive Reporting:</strong> Full audit recommended for comprehensive executive dashboards</li>
            </ul>
        </div>
        
        <p><strong>📊 Analysis Summary:</strong> This report contains analysis results for $processedVaults out of $totalVaults discovered Key Vaults. The audit was generated from $(if ($PartialDataSource -eq "csv") { "an existing CSV file" } else { "checkpoint data" }) and represents a subset of the complete organizational analysis.</p>
    </div>
"@
                # Handle case where there's no checkpoint data (CSV-only partial results)
                $htmlContent += @"
    <div class="summary">
        <h2>📊 Partial Results Information</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$processedVaults</div>
                <div class="stat-label">Processed Vaults</div>
                <div class="stat-percentage">From $(if ($PartialDataSource -eq "csv") { "CSV Import" } else { "Data Source" })</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">N/A</div>
                <div class="stat-label">Total Discovery</div>
                <div class="stat-percentage">Unknown</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($global:executionId) { $global:executionId.Substring(0,8) + "..." } else { "N/A" })</div>
                <div class="stat-label">Report ID</div>
                <div class="stat-percentage">Current Generation</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Get-Date -Format 'MM-dd')</div>
                <div class="stat-label">Generated</div>
                <div class="stat-percentage">$(Get-Date -Format 'HH:mm UTC')</div>
            </div>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-top: 20px;">
            <h4>📋 Data Source Information:</h4>
            <ul>
                <li><strong>Data Source:</strong> External data source</li>
                <li><strong>Records Processed:</strong> $processedVaults Key Vaults</li>
                <li><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') by System</li>
                <li><strong>Completeness:</strong> Unknown - CSV data source does not provide total discovery scope</li>
            </ul>
        </div>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 8px; margin-top: 15px;">
            <h4>⚠️ Important Limitations:</h4>
            <p>This report was generated from imported CSV data. The scope and completeness of the original data collection is unknown.</p>
            <ul>
                <li><strong>Statistical Accuracy:</strong> Percentages reflect only the provided dataset, not organizational totals</li>
                <li><strong>Discovery Scope:</strong> Unknown if all organizational Key Vaults are represented</li>
                <li><strong>Data Currency:</strong> CSV data age and accuracy cannot be verified</li>
                <li><strong>Compliance Assessment:</strong> Organizational compliance status requires complete audit</li>
            </ul>
        </div>
        
        <p><strong>📊 Analysis Summary:</strong> This report contains analysis results for $processedVaults Key Vaults imported from external source. For complete organizational assessment, conduct a full live audit using the main script parameters.</p>
    </div>
"@
            
            # Additional content based on data source
            if ($PartialDataSource -eq "csv") {
                # CSV-specific content already included above
            } else {
                $htmlContent += "</div>"
            }
        
        # Add test mode banner if applicable
        if ($TestMode) {
            $htmlContent += @"
    
    <div class="test-mode-banner">
        🧪 TEST MODE ACTIVE - Limited subset for validation
    </div>
"@
        }
        
        # Continue with executive summary and main content
        # Ensure ExecutiveSummary exists and has all required properties before generating HTML
        if (-not $ExecutiveSummary) {
            $ExecutiveSummary = @{}
        }
        
        # Ensure all required properties exist with default values
        if (-not (Get-Member -InputObject $ExecutiveSummary -Name 'TotalKeyVaults' -MemberType Properties)) {
            $ExecutiveSummary.TotalKeyVaults = 0
        }
        if (-not (Get-Member -InputObject $ExecutiveSummary -Name 'CompliantVaults' -MemberType Properties)) {
            $ExecutiveSummary.CompliantVaults = 0
        }
        if (-not (Get-Member -InputObject $ExecutiveSummary -Name 'CompliancePercentage' -MemberType Properties)) {
            $ExecutiveSummary.CompliancePercentage = 0
        }
        if (-not (Get-Member -InputObject $ExecutiveSummary -Name 'AverageComplianceScore' -MemberType Properties)) {
            $ExecutiveSummary.AverageComplianceScore = 0
        }
        if (-not (Get-Member -InputObject $ExecutiveSummary -Name 'CompanyAverageScore' -MemberType Properties)) {
            $ExecutiveSummary.CompanyAverageScore = 0
        }
        if (-not (Get-Member -InputObject $ExecutiveSummary -Name 'HighRiskVaults' -MemberType Properties)) {
            $ExecutiveSummary.HighRiskVaults = 0
        }
        
        $htmlContent += @"
    
    <div class="summary">
        <h2>🎯 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 0)</div>
                <div class="stat-label">Key Vaults $(if ($IsPartialResults) { "Analyzed" } else { "Discovered" })</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 100%; background: #667eea; animation: progressAnimation 1.5s ease-out;"></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliantVaults' -DefaultValue 0)</div>
                <div class="stat-label">Fully Compliant</div>
                <div class="stat-percentage $(if ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliancePercentage' -DefaultValue 0) -ge 90) { 'compliant' } elseif ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliancePercentage' -DefaultValue 0) -ge 60) { 'partially-compliant' } else { 'non-compliant' })">$(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliancePercentage' -DefaultValue 0)%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliancePercentage' -DefaultValue 0)%; background: $(if ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliancePercentage' -DefaultValue 0) -ge 90) { '#28a745' } elseif ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompliancePercentage' -DefaultValue 0) -ge 60) { '#ffc107' } else { '#dc3545' }); animation: progressAnimation 2s ease-out;"></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'AverageComplianceScore' -DefaultValue 0)</div>
                <div class="stat-label">Average Score</div>
                <div class="stat-percentage">Microsoft Framework</div>
                <div class="dual-framework">
                    <div class="framework-score microsoft-framework">
                        <strong>MS:</strong> $(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'AverageComplianceScore' -DefaultValue 0)%
                    </div>
                    <div class="framework-score company-framework">
                        <strong>Company:</strong> $(Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'CompanyAverageScore' -DefaultValue 0)%
                    </div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(Format-StatValue -Value (Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'HighRiskVaults' -DefaultValue 0) -Explanation "No high-risk vaults found")</div>
                <div class="stat-label">High Risk Vaults</div>
                <div class="stat-percentage $(if ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'HighRiskVaults' -DefaultValue 0) -eq 0) { 'compliant' } else { 'non-compliant' })">Require Attention</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $(if ((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 0) -gt 0) { [math]::Round(((Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'HighRiskVaults' -DefaultValue 0) / (Get-SafeProperty -Object $ExecutiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1)) * 100, 1) } else { 0 })%; background: #dc3545; animation: progressAnimation 2.5s ease-out;"></div>
                </div>
            </div>
        </div>
"@
        
        # Continue with the rest of the comprehensive HTML report content
        # Add the detailed vault table section
        $htmlContent += @"
        </div>
    </div>
    
    <div class="summary">
        <h2>📋 Detailed Vault Analysis</h2>
        <p>Comprehensive analysis of all $(if ($IsPartialResults) { "processed" }) Key Vaults with compliance scoring, security configurations, and actionable recommendations.</p>
        
        <table id="vaultTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Subscription</th>
                    <th onclick="sortTable(1)">Key Vault Name</th>
                    <th onclick="sortTable(2)">Location</th>
                    <th onclick="sortTable(3)">Resource Group</th>
                    <th onclick="sortTable(4)">Compliance Status</th>
                    <th onclick="sortTable(5)">MS Score</th>
                    <th onclick="sortTable(6)">Company Score</th>
                    <th onclick="sortTable(7)">Diagnostics</th>
                    <th onclick="sortTable(8)">Log Categories</th>
                    <th onclick="sortTable(9)">Log Analytics</th>
                    <th onclick="sortTable(10)">Event Hub</th>
                    <th onclick="sortTable(11)">Storage Account</th>
                    <th onclick="sortTable(12)">Access Policies</th>
                    <th onclick="sortTable(13)">RBAC Assignments</th>
                    <th onclick="sortTable(14)">Service Principals</th>
                    <th onclick="sortTable(15)">Managed Identities</th>
                    <th onclick="sortTable(16)">System Identity</th>
                    <th onclick="sortTable(17)">User Identities</th>
                    <th onclick="sortTable(18)">Soft Delete</th>
                    <th onclick="sortTable(19)">Purge Protection</th>
                    <th onclick="sortTable(20)">Public Access</th>
                    <th onclick="sortTable(21)">Private Endpoints</th>
                    <th onclick="sortTable(22)">Secrets</th>
                    <th onclick="sortTable(23)">Keys</th>
                    <th onclick="sortTable(24)">Certificates</th>
                    <th onclick="sortTable(25)">Environment</th>
                    <th onclick="sortTable(26)">Workload</th>
                    <th onclick="sortTable(27)">Last Audit</th>
                    <th onclick="sortTable(28)">Errors</th>
                    <th onclick="sortTable(29)">Details</th>
                    <th onclick="sortTable(30)">Action Items</th>
                </tr>
                <tr>
"@

        # Add filter inputs for major columns (updated count to include new columns)
        for ($i = 0; $i -lt 31; $i++) {
            $htmlContent += "<th><input type='text' class='filter-input' onkeyup='filterTable(this, $i)' placeholder='Filter...'></th>"
        }
        
        $htmlContent += @"
                </tr>
            </thead>
            <tbody>
"@

        # Add vault data rows
        $rowIndex = 0
    # Use Get-SafeCount to reliably determine number of records
    $totalRecords = Get-SafeCount $AuditResults
        foreach ($result in $AuditResults) {
            $rowIndex++
            
            # Update progress bar
            $percentComplete = if ($totalRecords -gt 0) { [math]::Round(($rowIndex / $totalRecords) * 100, 1) } else { 100 }
            Write-Progress -Activity "Generating HTML Report" -Status "Processing vault $rowIndex of $totalRecords" -PercentComplete $percentComplete
            
            # Determine compliance status class
            $complianceScore = Get-SafeProperty -Object $result -PropertyName 'ComplianceScore' -DefaultValue 0
            $complianceClass = if ($complianceScore -ge 90) { "compliant" } 
                              elseif ($complianceScore -ge 60) { "partially-compliant" } 
                              else { "non-compliant" }
            
            $scoreColor = if ($complianceScore -ge 90) { "#28a745" } 
                          elseif ($complianceScore -ge 60) { "#ffc107" } 
                          else { "#dc3545" }
            
            $htmlContent += "<tr>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'SubscriptionId' -DefaultValue 'N/A')'>$(Get-SafeProperty -Object $result -PropertyName 'SubscriptionName' -DefaultValue 'N/A')</td>"
            $htmlContent += "<td><strong>$(Get-SafeProperty -Object $result -PropertyName 'KeyVaultName' -DefaultValue 'N/A')</strong></td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'Location' -DefaultValue 'N/A')</td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'ResourceGroupName' -DefaultValue 'N/A')</td>"
            $htmlContent += "<td><span class='$complianceClass'>$(Get-SafeProperty -Object $result -PropertyName 'ComplianceStatus' -DefaultValue 'Unknown')</span></td>"
            $htmlContent += "<td><span style='color: $scoreColor; font-weight: bold;'>$($complianceScore)%</span></td>"
            
            # Add Company compliance score with appropriate color coding
            $companyScore = Get-SafeProperty -Object $result -PropertyName 'CompanyComplianceScore' -DefaultValue 0
            $companyScoreColor = if ($companyScore -ge 95) { "#28a745" } 
                                elseif ($companyScore -ge 75) { "#ffc107" } 
                                else { "#dc3545" }
            $htmlContent += "<td><span style='color: $companyScoreColor; font-weight: bold;' title='Company Framework Score'>$companyScore%</span></td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'DiagnosticsEnabled')</td>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'EnabledLogCategories')'>$(Get-SafeProperty -Object $result -PropertyName 'EnabledLogCategories' | ForEach-Object { $_ -replace ',', ', ' })</td>"
            $htmlContent += "<td title='Workspace: $(Get-SafeProperty -Object $result -PropertyName 'LogAnalyticsWorkspaceName')'>$(Get-SafeProperty -Object $result -PropertyName 'LogAnalyticsEnabled')</td>"
            $htmlContent += "<td title='Namespace: $(Get-SafeProperty -Object $result -PropertyName 'EventHubNamespace'), Hub: $(Get-SafeProperty -Object $result -PropertyName 'EventHubName')'>$(Get-SafeProperty -Object $result -PropertyName 'EventHubEnabled')</td>"
            $htmlContent += "<td title='Storage: $(Get-SafeProperty -Object $result -PropertyName 'StorageAccountName')'>$(Get-SafeProperty -Object $result -PropertyName 'StorageAccountEnabled')</td>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'AccessPolicyDetails')'>$(Get-SafeProperty -Object $result -PropertyName 'AccessPolicyCount')</td>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'RBACRoleAssignments')'>$(Get-SafeProperty -Object $result -PropertyName 'RBACAssignmentCount')</td>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'ServicePrincipalDetails')'>$(Get-SafeProperty -Object $result -PropertyName 'ServicePrincipalCount')</td>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'ManagedIdentityDetails')'>$(Get-SafeProperty -Object $result -PropertyName 'ManagedIdentityCount')</td>"
            $htmlContent += "<td title='Principal ID: $(Get-SafeProperty -Object $result -PropertyName 'SystemAssignedPrincipalId')'>$(Get-SafeProperty -Object $result -PropertyName 'SystemAssignedIdentity')</td>"
            $htmlContent += "<td title='User Assigned IDs: $(Get-SafeProperty -Object $result -PropertyName 'UserAssignedIdentityIds')'>$(Get-SafeProperty -Object $result -PropertyName 'UserAssignedIdentityCount')</td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'SoftDeleteEnabled')</td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'PurgeProtectionEnabled')</td>"
            $htmlContent += "<td title='Network ACLs: $(Get-SafeProperty -Object $result -PropertyName 'NetworkAclsConfigured')'>$(Get-SafeProperty -Object $result -PropertyName 'PublicNetworkAccess')</td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'PrivateEndpointCount')</td>"
            
            # Workload Analysis columns
            $htmlContent += "<td style='text-align: center;'>$(Get-SafeProperty -Object $result -PropertyName 'SecretCount')</td>"
            $htmlContent += "<td style='text-align: center;'>$(Get-SafeProperty -Object $result -PropertyName 'KeyCount')</td>" 
            $htmlContent += "<td style='text-align: center;'>$(Get-SafeProperty -Object $result -PropertyName 'CertificateCount')</td>"
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'EnvironmentType')</td>"
            $htmlContent += "<td title='$(Get-SafeProperty -Object $result -PropertyName 'WorkloadCategories')'>$(Get-SafeProperty -Object $result -PropertyName 'PrimaryWorkload')</td>"
            
            # Last audit and errors columns (visible)
            $htmlContent += "<td>$(Get-SafeProperty -Object $result -PropertyName 'LastAuditDate' -DefaultValue '')</td>"
            $htmlContent += "<td title='Errors'>$(Get-SafeProperty -Object $result -PropertyName 'ErrorsEncountered' -DefaultValue '')</td>"

            # Details panel column (compact) - shows additional restored fields when expanded
            $detailsId = "details_$rowIndex"
            $htmlContent += "<td>"
            $htmlContent += "<span class='action-link' onclick=`"toggleActionItems('$detailsId')`">View Details</span>"
            $htmlContent += "<div id='$detailsId' class='action-details'>"
            $htmlContent += "<h5>Details for $(Get-SafeProperty -Object $result -PropertyName 'KeyVaultName' -DefaultValue 'Unknown'):</h5>"
            $htmlContent += "<ul>"
            $htmlContent += "<li><strong>Over-Privileged:</strong> $(Get-SafeProperty -Object $result -PropertyName 'OverPrivilegedDetails' -DefaultValue '')</li>"
            $htmlContent += "<li><strong>OverPrivilegedAssignments:</strong> $(Get-SafeProperty -Object $result -PropertyName 'OverPrivilegedAssignments' -DefaultValue '')</li>"
            $htmlContent += "<li><strong>Compliance Reasons:</strong> $(Get-SafeProperty -Object $result -PropertyName 'ComplianceFrameworkReasons' -DefaultValue '')</li>"
            $htmlContent += "<li><strong>Audit Duration (s):</strong> $(Get-SafeProperty -Object $result -PropertyName 'AuditDurationSeconds' -DefaultValue 0)</li>"
            $htmlContent += "<li><strong>Secret Versioning:</strong> $(Get-SafeProperty -Object $result -PropertyName 'SecretVersioning' -DefaultValue 'Unknown')</li>"
            $htmlContent += "<li><strong>Expiration Analysis:</strong> $(Get-SafeProperty -Object $result -PropertyName 'ExpirationAnalysis' -DefaultValue '')</li>"
            $htmlContent += "<li><strong>Rotation Analysis:</strong> $(Get-SafeProperty -Object $result -PropertyName 'RotationAnalysis' -DefaultValue '')</li>"
            $htmlContent += "<li><strong>App Service Integration:</strong> $(Get-SafeProperty -Object $result -PropertyName 'AppServiceIntegration' -DefaultValue 'No')</li>"
            $htmlContent += "</ul>"
            $htmlContent += "</div>"
            $htmlContent += "</td>"

            # Action items as clickable link
            $actionItemsId = "actions_$rowIndex"

            $htmlContent += "<td>"
            $htmlContent += "<span class='action-link' onclick=`"toggleActionItems('$actionItemsId')`">View Actions</span>"
            $htmlContent += "<div id='$actionItemsId' class='action-details'>"
            $htmlContent += "<h5>Priority Actions for $(Get-SafeProperty -Object $result -PropertyName 'KeyVaultName' -DefaultValue 'Unknown Vault'):</h5>"
            $htmlContent += "<ul>"
            
            $complianceRecommendations = Get-SafeProperty -Object $result -PropertyName 'ComplianceRecommendations'
            if ($complianceRecommendations) {
                foreach ($recommendation in ($complianceRecommendations -split '; ')) {
                    if ($recommendation.Trim()) {
                        $htmlContent += "<li>$($recommendation.Trim())</li>"
                    }
                }
            } else {
                $htmlContent += "<li>Vault analysis completed successfully - no major issues found</li>"
            }
            
            $htmlContent += "</ul>"
            if ($complianceScore -lt 90) {
                $htmlContent += "<p><strong>Impact:</strong> Implementing these recommendations will improve security posture and compliance score.</p>"
            }
            $htmlContent += "</div>"
            $htmlContent += "</td>"
            $htmlContent += "</tr>`n"
        }
        
        # Clear progress bar
        Write-Progress -Activity "Generating HTML Report" -Completed

        # Close the table and add footer
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="quick-wins-section">
        <h3>🚀 Quick Wins Recommendations<span class="enhancement-badge">Enhanced</span></h3>
        <p>Prioritized action items for immediate security improvements:</p>
        <ul>
"@

        foreach ($recommendation in $quickWinsRecommendations) {
            $htmlContent += "<li>$recommendation</li>"
        }

        $htmlContent += @"
        </ul>
    </div>
    
    <div class="identity-section">
        <h3>🔐 Identity & Access Management Insights$(if ($IsPartialResults) { ' <span class="tooltip">[ℹ️]<span class="tooltiptext">Data from partial results - may not reflect complete organization scope</span></span>' })</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $servicePrincipalSum = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'ServicePrincipalCount') -ne 'N/A' } | Measure-Object -Property ServicePrincipalCount -Sum -ErrorAction SilentlyContinue
                    if ($servicePrincipalSum -and (Get-SafeProperty -Object $servicePrincipalSum -PropertyName 'Sum') -ne 'N/A') { Get-SafeProperty -Object $servicePrincipalSum -PropertyName 'Sum' -DefaultValue 'N/A' } else { "N/A" }
                } else { "N/A" })</div>
                <div class="stat-label">Total Service Principals</div>
                $(if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $managedIdentitySum = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'ManagedIdentityCount') -ne 'N/A' } | Measure-Object -Property ManagedIdentityCount -Sum -ErrorAction SilentlyContinue
                    if ($managedIdentitySum -and (Get-SafeProperty -Object $managedIdentitySum -PropertyName 'Sum') -ne 'N/A') { Get-SafeProperty -Object $managedIdentitySum -PropertyName 'Sum' -DefaultValue 'N/A' } else { "N/A" }
                } else { "N/A" })</div>
                <div class="stat-label">Total Managed Identities</div>
                $(if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $systemAssignedResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SystemAssignedIdentity') -eq "Yes" }
                    Get-SafeCount $systemAssignedResults
                } else { "N/A" })</div>
                <div class="stat-label">System-Assigned Identities</div>
                $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A' -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                    $systemAssignedResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SystemAssignedIdentity') -eq "Yes" }
                    $sysAssignedCount = Get-SafeCount $systemAssignedResults
                    $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A') { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                    $percentage = [math]::Round(($sysAssignedCount / $auditCount) * 100, 1)
                    if ($percentage -eq 0) { 
                        '<div class="stat-percentage" style="color: #dc3545">' + $percentage + '%</div>' 
                    } elseif ($percentage -lt 50) { 
                        '<div class="stat-percentage" style="color: #ffc107">' + $percentage + '%</div>' 
                    } else { 
                        '<div class="stat-percentage" style="color: #28a745">' + $percentage + '%</div>' 
                    }
                } else { if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' } else { '<div class="stat-percentage" style="color: #dc3545">0%</div>' } })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $userAssignedSum = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'UserAssignedIdentityCount') -ne 'N/A' } | Measure-Object -Property UserAssignedIdentityCount -Sum -ErrorAction SilentlyContinue
                    if ($userAssignedSum -and (Get-SafeProperty -Object $userAssignedSum -PropertyName 'Sum') -ne 'N/A') { Get-SafeProperty -Object $userAssignedSum -PropertyName 'Sum' -DefaultValue 'N/A' } else { "N/A" }
                } else { "N/A" })</div>
                <div class="stat-label">User-Assigned Identities</div>
                $(if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $rbacResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount') -ne 'N/A' -and ([int](Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0') -gt 0) }
                    Get-SafeCount $rbacResults
                } else { "N/A" })</div>
                <div class="stat-label">Using RBAC</div>
                $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A' -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                    $rbacResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount') -ne 'N/A' -and ([int](Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0') -gt 0) }
                    $rbacCount = Get-SafeCount $rbacResults
                    $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A') { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                    $percentage = [math]::Round(($rbacCount / $auditCount) * 100, 1)
                    if ($percentage -ge 90) { 
                        '<div class="stat-percentage" style="color: #28a745">' + $percentage + '%</div>' 
                    } elseif ($percentage -ge 60) { 
                        '<div class="stat-percentage" style="color: #ffc107">' + $percentage + '%</div>' 
                    } else { 
                        '<div class="stat-percentage" style="color: #dc3545">' + $percentage + '%</div>' 
                    }
                } else { if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' } else { '<div class="stat-percentage" style="color: #dc3545">0%</div>' } })
            </div>
        </div>
        
        <h4>Key Identity Recommendations:</h4>
        <ul>
            <li><strong>Migrate to Managed Identities:</strong> Replace service principals with managed identities where possible for enhanced security</li>
            <li><strong>Implement RBAC:</strong> Move from legacy access policies to Azure RBAC for fine-grained access control$(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A' -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $rbacResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount') -ne 'N/A' -and ([int](Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0') -gt 0) }
                $rbacCount = Get-SafeCount $rbacResults
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A') { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($rbacCount / $auditCount) * 100, 1)
                " ($percentage% currently using RBAC)"
            })</li>
            <li><strong>Apply Least Privilege:</strong> Review and reduce over-privileged role assignments</li>
            <li><strong>Enable System-Assigned Identities:</strong> Configure system-assigned managed identities on Key Vault resources$(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A' -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $systemAssignedResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SystemAssignedIdentity') -eq "Yes" }
                $sysAssignedCount = Get-SafeCount $systemAssignedResults
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -ne 'N/A') { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0 } else { 0 }
                " ($sysAssignedCount of $auditCount vaults have system-assigned identities)"
            })</li>
        </ul>
        
        <div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px;">
            <h5>📝 Note on Service Principals vs System Identity:</h5>
            <p><strong>Total Service Principals</strong> refers to external service principals assigned RBAC roles to access Key Vaults.</p>
            <p><strong>System Identity</strong> refers to system-assigned managed identities directly on the Key Vault resource itself. These are separate concepts - a Key Vault can have external service principals accessing it while not having its own system-assigned identity enabled.</p>
            $(if ($IsPartialResults) { '<p><strong>⚠️ Partial Data:</strong> These statistics reflect only the processed Key Vaults in this report and may not represent the complete organizational picture.</p>' })
        </div>
    </div>

    <div class="secrets-section">
        <h3>🔑 Secrets Management Insights$(if ($IsPartialResults) { ' <span class="tooltip">[ℹ️]<span class="tooltiptext">Data from partial results - statistics may be incomplete</span></span>' })</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $secretResults = $AuditResults | Where-Object { 
                        $secretCount = Get-SafeProperty -Object $_ -PropertyName 'SecretCount' -DefaultValue '0'
                        try { [int]$secretCount -gt 0 } catch { $false }
                    }
                    $secretVaultCount = Get-SafeCount $secretResults
                    Format-StatValue -Value $secretVaultCount -Explanation "No vaults contain secrets"
                } else { "N/A" })</div>
                <div class="stat-label">Vaults Storing Secrets</div>
                $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                    $secretResults = $AuditResults | Where-Object { 
                        $secretCount = Get-SafeProperty -Object $_ -PropertyName 'SecretCount' -DefaultValue '0'
                        try { [int]$secretCount -gt 0 } catch { $false }
                    }
                    $secretVaultCount = Get-SafeCount $secretResults
                    $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                    $percentage = [math]::Round(($secretVaultCount / $auditCount) * 100, 1)
                    '<div class="stat-percentage" style="color: #667eea;">' + $percentage + '%</div>'
                } else { if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' } else { '<div class="stat-percentage" style="color: #667eea;">N/A</div>' } })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $monitoringCount = @($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -and ((Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -eq "Yes" -or (Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -eq $true) }).Count
                    Format-StatValue -Value $monitoringCount -Explanation "No diagnostic monitoring configured"
                } else { "N/A" })</div>
                <div class="stat-label">Secret Access Monitoring</div>
                $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                    $monitoringCount = @($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -and ((Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -eq "Yes" -or (Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -eq $true) }).Count
                    $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                    $percentage = [math]::Round(($monitoringCount / $auditCount) * 100, 1)
                    if ($percentage -eq 0) { 
                        '<div class="stat-percentage" style="color: #dc3545">' + $percentage + '%</div>' 
                    } elseif ($percentage -lt 50) { 
                        '<div class="stat-percentage" style="color: #ffc107">' + $percentage + '%</div>' 
                    } else { 
                        '<div class="stat-percentage" style="color: #28a745">' + $percentage + '%</div>' 
                    }
                } else { if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' } else { '<div class="stat-percentage" style="color: #dc3545">0%</div>' } })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $rbacResults = $AuditResults | Where-Object { 
                        $rbacCount = Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0'
                        try { [int]$rbacCount -gt 0 } catch { $false }
                    }
                    $rbacCount = Get-SafeCount $rbacResults
                    Format-StatValue -Value $rbacCount -Explanation "No RBAC assignments configured"
                } else { "N/A" })</div>
                <div class="stat-label">Granular Secret Access</div>
                $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                    $rbacResults = $AuditResults | Where-Object { 
                        $rbacCount = Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0'
                        try { [int]$rbacCount -gt 0 } catch { $false }
                    }
                    $rbacCount = Get-SafeCount $rbacResults
                    $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                    $percentage = [math]::Round(($rbacCount / $auditCount) * 100, 1)
                    if ($percentage -ge 90) { 
                        '<div class="stat-percentage" style="color: #28a745">' + $percentage + '%</div>' 
                    } elseif ($percentage -ge 60) { 
                        '<div class="stat-percentage" style="color: #ffc107">' + $percentage + '%</div>' 
                    } else { 
                        '<div class="stat-percentage" style="color: #dc3545">' + $percentage + '%</div>' 
                    }
                } else { if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' } else { '<div class="stat-percentage" style="color: #dc3545">0%</div>' } })
            </div>
            <div class="stat-card">
                <div class="stat-number">$(if ($AuditResults) { 
                    $softDeleteCount = @($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SoftDeleteEnabled') -eq "Yes" }).Count
                    Format-StatValue -Value $softDeleteCount -Explanation "No soft delete protection enabled"
                } else { "N/A" })</div>
                <div class="stat-label">Secret Recovery Protection</div>
                $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                    $softDeleteCount = @($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SoftDeleteEnabled') -eq "Yes" }).Count
                    $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                    $percentage = [math]::Round(($softDeleteCount / $auditCount) * 100, 1)
                    if ($percentage -eq 0) { 
                        '<div class="stat-percentage" style="color: #dc3545">' + $percentage + '%</div>' 
                    } elseif ($percentage -lt 50) { 
                        '<div class="stat-percentage" style="color: #ffc107">' + $percentage + '%</div>' 
                    } else { 
                        '<div class="stat-percentage" style="color: #28a745">' + $percentage + '%</div>' 
                    }
                } else { if ($IsPartialResults) { '<div class="stat-percentage" style="color: #ffc107;">Partial Data</div>' } else { '<div class="stat-percentage" style="color: #dc3545">0%</div>' } })
            </div>
        </div>
        
        <h4>🔐 Secrets Management Terms & Best Practices:</h4>
        <ul>
            <li><strong>Secret Access Monitoring:</strong> Comprehensive logging and auditing of all secret access attempts, including who accessed what secrets, when, and from where. This enables detection of unauthorized access patterns and compliance reporting.</li>
            <li><strong>Granular Secret Access:</strong> Fine-grained permissions using Azure RBAC instead of broad access policies. This allows specific roles like 'Key Vault Secrets User' for read access only, rather than full vault permissions.</li>
            <li><strong>Secret Recovery Protection:</strong> Soft delete functionality that allows recovery of accidentally deleted secrets within the retention period (7-90 days), preventing permanent data loss.</li>
            <li><strong>Secret Rotation:</strong> Microsoft recommends automated rotation every 90 days for high-value secrets. Consider implementing Azure Functions or Logic Apps for automated rotation workflows.</li>
            <li><strong>Secret Versioning:</strong> Key Vault automatically versions secrets. Leverage this for rollback capabilities and audit trails.</li>
            <li><strong>Application Integration:</strong> Use Key Vault references in Azure App Service and Azure Functions instead of hardcoding secrets in application configurations.</li>
        </ul>
        
        <h4>📊 Compliance & Security Insights:</h4>
        <ul>
            <li><strong>Audit Trail:</strong> $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $diagnosticsCount = @($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -and ((Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -eq "Yes" -or (Get-SafeProperty -Object $_ -PropertyName 'DiagnosticsEnabled') -eq $true) }).Count
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($diagnosticsCount / $auditCount) * 100, 1)
                "$percentage% of vaults have diagnostic logging enabled"
            } else { "Diagnostic logging status unknown for partial data" }), providing visibility into secret access patterns and potential security incidents.</li>
            <li><strong>Network Isolation:</strong> $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $privateEndpointCount = @($AuditResults | Where-Object { 
                    $peCount = Get-SafeProperty -Object $_ -PropertyName 'PrivateEndpointCount' -DefaultValue '0'
                    try { [int]$peCount -gt 0 } catch { $false }
                }).Count
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($privateEndpointCount / $auditCount) * 100, 1)
                "$percentage% of vaults use private endpoints"
            } else { "Private endpoint usage unknown for partial data" }), protecting secrets from unauthorized network access.</li>
            <li><strong>Identity-Based Access:</strong> $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $rbacResults = $AuditResults | Where-Object { 
                    $rbacCount = Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0'
                    try { [int]$rbacCount -gt 0 } catch { $false }
                }
                $rbacCount = if ($rbacResults) { @($rbacResults).Count } else { 0 }
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($rbacCount / $auditCount) * 100, 1)
                "$percentage% of vaults use RBAC"
            } else { "RBAC usage unknown for partial data" }) for granular secret permissions instead of legacy access policies.</li>
            <li><strong>Secret Recovery:</strong> Soft delete is enabled on $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $softDeleteCount = @($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SoftDeleteEnabled') -eq "Yes" }).Count
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($softDeleteCount / $auditCount) * 100, 1)
                "$percentage% of vaults"
            } else { "unknown percentage for partial data" }), enabling secret recovery in case of accidental deletion.</li>
        </ul>
        
        <h4>⚠️ Common Secrets Management Risks:</h4>
        <ul>
            <li><strong>Hardcoded Secrets:</strong> Avoid storing secrets directly in application code, configuration files, or environment variables.</li>
            <li><strong>Over-Privileged Access:</strong> Applications with broad Key Vault permissions increase attack surface.</li>
            <li><strong>Stale Secrets:</strong> Unused or forgotten secrets should be regularly audited and removed.</li>
            <li><strong>Weak Secret Generation:</strong> Use cryptographically secure random generators for password and key generation.</li>
            <li><strong>Cross-Environment Leakage:</strong> Ensure proper isolation between development, staging, and production secrets.</li>
        </ul>
        
        $(if ($IsPartialResults) { 
            $auditResultsCount = if ($AuditResults) { (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') } else { 0 }
            '<div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px;"><p><strong>⚠️ Partial Data Notice:</strong> These insights are based on ' + $auditResultsCount + ' processed vaults and may not reflect the complete organizational secrets management posture.</p></div>' 
        })
    </div>

    <div class="security-section">
        <h3>🛡️ Security Enhancement Recommendations$(if ($IsPartialResults) { ' <span class="tooltip">[ℹ️]<span class="tooltiptext">Recommendations based on partial data set</span></span>' })</h3>
        
        <h4>Network Security:</h4>
        <ul>
            <li><strong>Private Endpoints:</strong> $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $privateEndpointCount = (@($AuditResults | Where-Object { 
                    $peCount = Get-SafeProperty -Object $_ -PropertyName 'PrivateEndpointCount' -DefaultValue '0'
                    try { [int]$peCount -gt 0 } catch { $false }
                })).Count
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                "$privateEndpointCount of $auditCount vaults"
                $percentage = [math]::Round(($privateEndpointCount / $auditCount) * 100, 1)
                " ($percentage%)"
            } else { "Status unknown for partial data" }) have private endpoints configured</li>
            <li><strong>Network ACLs:</strong> Implement network access control lists to restrict access</li>
            <li><strong>Firewall Rules:</strong> Configure IP-based firewall rules for additional protection</li>
        </ul>
        
        <h4>Monitoring & Compliance:</h4>
        <ul>
            <li><strong>Event Hub Integration:</strong> $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $eventHubCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'EventHubEnabled') -eq "Yes" })).Count
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($eventHubCount / $auditCount) * 100, 1)
                "$eventHubCount of $auditCount vaults ($percentage%)"
            } else { "Status unknown for partial data" }) have Event Hub enabled for real-time monitoring</li>
            <li><strong>Log Analytics Integration:</strong> $(if ($AuditResults -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count') -and (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $logAnalyticsCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'LogAnalyticsEnabled') -eq "Yes" })).Count
                $auditCount = if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count')) { Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1 } else { 1 }
                $percentage = [math]::Round(($logAnalyticsCount / $auditCount) * 100, 1)
                "$logAnalyticsCount of $auditCount vaults ($percentage%)"
            } else { "Status unknown for partial data" }) have Log Analytics enabled for centralized query and alerting</li>
            <li><strong>Storage Account Logging:</strong> $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $storageCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'StorageAccountEnabled') -eq "Yes" })).Count
                $percentage = [math]::Round(($storageCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$storageCount of $((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0)) vaults ($percentage%)"
            } else { "Status unknown for partial data" }) have storage account logging configured</li>
            <li><strong>Azure Sentinel Integration:</strong> Connect Key Vault logs to Azure Sentinel for advanced threat detection</li>
            <li><strong>Azure Policy:</strong> Implement automated compliance enforcement</li>
        </ul>
        
        $(if ($IsPartialResults) { '<div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px;"><p><strong>⚠️ Partial Data Notice:</strong> Security metrics reflect only the processed subset of Key Vaults and may not represent complete organizational security posture.</p></div>' })
    </div>

    <div class="legend-section">
        <h3>📊 Compliance Score Calculation Legend</h3>
        <p>The compliance score is calculated based on Microsoft Security Baseline requirements:</p>
        
        <h4>🔒 Core Security Features (50 points total):</h4>
        <ul>
            <li><strong>Soft Delete Enabled:</strong> 10 points - Protects against accidental deletion</li>
            <li><strong>Purge Protection Enabled:</strong> 15 points - Critical security baseline requirement</li>
            <li><strong>Diagnostics Enabled:</strong> 15 points - Essential for monitoring and compliance</li>
            <li><strong>Event Hub Integration:</strong> 10 points - Real-time security monitoring capability</li>
        </ul>
        
        <h4>🔐 Access Control (30 points total):</h4>
        <ul>
            <li><strong>RBAC Enabled:</strong> 15 points - Modern role-based access control vs legacy policies</li>
            <li><strong>Private Endpoints:</strong> 15 points - Network security and zero-trust architecture</li>
        </ul>
        
        <h4>📊 Monitoring & Compliance (20 points total):</h4>
        <ul>
            <li><strong>Log Analytics Integration:</strong> 10 points - Advanced querying and alerting</li>
            <li><strong>Audit Event Logging:</strong> 5 points - Security event tracking</li>
            <li><strong>Policy Evaluation Logging:</strong> 5 points - Azure Policy compliance tracking</li>
        </ul>
        
        <h4>🎯 Compliance Thresholds:</h4>
        <ul>
            <li><strong class="compliant">Fully Compliant:</strong> 90-100 points - Meets Microsoft security baselines</li>
            <li><strong class="partially-compliant">Partially Compliant:</strong> 60-89 points - Some improvements needed</li>
            <li><strong class="non-compliant">Non-Compliant:</strong> 0-59 points - Immediate action required</li>
        </ul>
    </div>
    
    <div style="margin-top: 30px; padding: 15px; background: #e9ecef; border-radius: 8px; font-size: 0.9em;">
        <h3>📋 Enhanced Compliance Framework</h3>
        <p>This comprehensive audit evaluates Key Vault configurations against current Microsoft security standards:</p>
        <ul>
            <li><strong>Azure Security Benchmark v3.0</strong> - Latest Microsoft cloud security recommendations <a href="https://learn.microsoft.com/security/benchmark/azure/" target="_blank">[Learn More]</a></li>
            <li><strong>Key Vault Security Baseline 2024</strong> - Specific security controls and requirements <a href="https://learn.microsoft.com/azure/key-vault/general/security-baseline" target="_blank">[Learn More]</a></li>
            <li><strong>Microsoft Cloud Security Best Practices</strong> - Identity and access management standards <a href="https://learn.microsoft.com/azure/security/fundamentals/best-practices-and-patterns" target="_blank">[Learn More]</a></li>
            <li><strong>Zero Trust Architecture</strong> - Never trust, always verify principles <a href="https://learn.microsoft.com/security/zero-trust/" target="_blank">[Learn More]</a></li>
            <li><strong>NIST Cybersecurity Framework</strong> - Industry-standard security practices <a href="https://www.nist.gov/cyberframework" target="_blank">[Learn More]</a></li>
            <li><strong>Azure Well-Architected Framework</strong> - Security pillar recommendations <a href="https://learn.microsoft.com/azure/well-architected/security/" target="_blank">[Learn More]</a></li>
        </ul>
        
        <h4>📊 Audit Statistics:</h4>
        <ul>
            $(if ((Get-SafeProperty -Object $AuditStats -PropertyName 'SubscriptionCount' -DefaultValue $null)) { "<li>Subscriptions analyzed: $((Get-SafeProperty -Object $AuditStats -PropertyName 'SubscriptionCount' -DefaultValue 'N/A'))</li>" } else { "<li>Subscriptions analyzed: $(if ($IsPartialResults) { 'N/A (partial data)' } else { 'N/A' })</li>" })
            <li>Key Vaults $(if ($IsPartialResults) { "processed" } else { "discovered" }): $((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0))$(if ($IsPartialResults -and $CheckpointData -and $CheckpointData.TotalVaults) { " of $($CheckpointData.TotalVaults) total discovered" })</li>
            <li>Compliance rate: $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $compliantCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'ComplianceScore' -DefaultValue 0) -ge 90 })).Count
                $percentage = [math]::Round(($compliantCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$percentage% ($compliantCount fully compliant)"
            } else { "N/A" })</li>
            <li>RBAC adoption: $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $rbacResults = $AuditResults | Where-Object { 
                    $rbacCount = Get-SafeProperty -Object $_ -PropertyName 'RBACAssignmentCount' -DefaultValue '0'
                    try { [int]$rbacCount -gt 0 } catch { $false }
                }
                $rbacCount = Get-SafeCount $rbacResults
                $percentage = [math]::Round(($rbacCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$percentage% ($rbacCount vaults using RBAC)"
            } else { "N/A" })</li>
            <li>Event Hub integration: $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $eventHubCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'EventHubEnabled') -eq "Yes" })).Count
                $percentage = [math]::Round(($eventHubCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$percentage% ($eventHubCount vaults configured)"
            } else { "N/A" })</li>
            <li>Log Analytics integration: $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $logAnalyticsCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'LogAnalyticsEnabled') -eq "Yes" })).Count
                $percentage = [math]::Round(($logAnalyticsCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$percentage% ($logAnalyticsCount vaults configured)"
            } else { "N/A" })</li>
            <li>Storage Account logging: $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $storageCount = (@($AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'StorageAccountEnabled') -eq "Yes" })).Count
                $percentage = [math]::Round(($storageCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$percentage% ($storageCount vaults configured)"
            } else { "N/A" })</li>
            <li>Private endpoint adoption: $(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $privateEndpointCount = (@($AuditResults | Where-Object { 
                    try { [int](Get-SafeProperty -Object $_ -PropertyName 'PrivateEndpointCount' -DefaultValue '0') -gt 0 } catch { $false }
                })).Count
                $percentage = [math]::Round(($privateEndpointCount / (Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 1)) * 100, 1)
                "$percentage% ($privateEndpointCount vaults secured)"
            } else { "N/A" })</li>
            $(if ((Get-SafeProperty -Object $AuditStats -PropertyName 'ExecutionTimeMinutes' -DefaultValue $null)) { "<li>Total execution time: $((Get-SafeProperty -Object $AuditStats -PropertyName 'ExecutionTimeMinutes' -DefaultValue 'N/A')) minutes</li>" } else { "<li>Total execution time: $(if ($IsPartialResults) { 'N/A (partial data)' } else { 'N/A' })</li>" })
            $(if ((Get-SafeProperty -Object $AuditStats -PropertyName 'AuthenticationRefreshes' -DefaultValue $null)) { "<li>Authentication refreshes: $((Get-SafeProperty -Object $AuditStats -PropertyName 'AuthenticationRefreshes' -DefaultValue '0'))</li>" } else { "<li>Authentication refreshes: $(if ($IsPartialResults) { 'N/A (partial data)' } else { '0' })</li>" })
            $(if ($IsPartialResults) { 
                "<li><strong>Report Type:</strong> PARTIAL RESULTS - Generated from $(if ($PartialDataSource -eq "csv") { "CSV file data" } else { "checkpoint data" })</li>"
                if ($CheckpointData -and $CheckpointData.ExecutionId) { "<li><strong>Original Execution ID:</strong> $($CheckpointData.ExecutionId)</li>" }
                if ($CheckpointData -and $CheckpointData.Timestamp) { "<li><strong>Original Audit Started:</strong> $($CheckpointData.Timestamp)</li>" }
                if ($CheckpointData -and $CheckpointData.VaultIndex -and $CheckpointData.TotalVaults) { 
                    $completionPercentage = [math]::Round(($CheckpointData.VaultIndex / $CheckpointData.TotalVaults) * 100, 1)
                    "<li><strong>Processing Progress:</strong> $($CheckpointData.VaultIndex)/$($CheckpointData.TotalVaults) vaults ($completionPercentage%)</li>"
                }
            })
        </ul>
        
        <h4>📁 Generated Files:</h4>
        <ul>
            <li><strong>HTML Report:</strong> $OutputPath</li>
            $(if ($IsPartialResults) { 
                if ($PartialDataSource -eq "csv") { "<li><strong>Source CSV:</strong> Referenced from CSV import</li>" }
                else { "<li><strong>Source Data:</strong> Extracted from checkpoint data</li>" }
            } else {
                "<li><strong>CSV Data:</strong> $(($OutputPath -replace '\.html$', '.csv'))</li>"
                "<li><strong>Error Log:</strong> $(($OutputPath -replace 'KeyVaultComprehensiveAudit_.*\.html$', "KeyVaultAudit_errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"))</li>"
                "<li><strong>Permissions Log:</strong> $(($OutputPath -replace 'KeyVaultComprehensiveAudit_.*\.html$', "KeyVaultAudit_permissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"))</li>"
                "<li><strong>Data Issues Log:</strong> $(($OutputPath -replace 'KeyVaultComprehensiveAudit_.*\.html$', "KeyVaultAudit_dataissues_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"))</li>"
            })
        </ul>
        
        <h4>🔍 Enhanced Features Implemented:</h4>
        <ul>
            <li>✅ Comprehensive managed identity detection and analysis$(if ((Get-SafeProperty -Object $AuditResults -PropertyName 'Count' -DefaultValue 0) -gt 0) { 
                $systemAssignedResults = $AuditResults | Where-Object { (Get-SafeProperty -Object $_ -PropertyName 'SystemAssignedIdentity') -and (Get-SafeProperty -Object $_ -PropertyName 'SystemAssignedIdentity') -eq "Yes" }
                $sysAssignedCount = Get-SafeCount $systemAssignedResults
                $userAssignedSum = $AuditResults | Where-Object { Get-SafeProperty -Object $_ -PropertyName 'UserAssignedIdentityCount' } | Measure-Object -Property UserAssignedIdentityCount -Sum -ErrorAction SilentlyContinue
                $userAssignedCount = if ($userAssignedSum) { Get-SafeProperty -Object $userAssignedSum -PropertyName 'Sum' -DefaultValue 0 } else { 0 }
                " (System: $sysAssignedCount, User: $userAssignedCount)"
            } else { " (Partial data: metrics unavailable)" })</li>
            <li>✅ Advanced service principal analysis with over-privilege detection</li>
            <li>✅ RBAC least-privilege recommendations based on current assignments</li>
            <li>✅ Real-time compliance scoring with Microsoft baseline alignment</li>
            <li>✅ Enhanced progress tracking with intelligent ETA calculations</li>
            <li>✅ Automatic token refresh and seamless re-authentication$(if ((Get-SafeProperty -Object $AuditStats -PropertyName 'AuthenticationRefreshes' -DefaultValue $null)) { " (Refreshes: $((Get-SafeProperty -Object $AuditStats -PropertyName 'AuthenticationRefreshes' -DefaultValue 'N/A')))" } else { " (Refreshes: N/A)" })</li>
            <li>✅ Comprehensive error handling and permissions logging</li>
            <li>✅ Network security assessment including private endpoint analysis</li>
            <li>✅ Complete diagnostic configuration analysis (Event Hub, Log Analytics, Storage)</li>
            <li>✅ Executive-level reporting with actionable insights and percentages</li>
            <li>✅ Secrets management insights with Microsoft best practices alignment</li>
            <li>✅ Color-coded sliding scale percentages for visual impact assessment</li>
            <li>✅ Reverse color logic for Non-Compliant metrics (0% = good, 100% = bad)</li>
            <li>✅ Dynamic user authentication tracking from Azure login context</li>
            $(if ($IsPartialResults) { "<li>✅ <strong>Partial results processing with data provenance tracking</strong></li>" })
        </ul>
    </div>
    
    <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; border: 1px solid #ffeaa7;">
        <h3>⚠️ Important Notes</h3>
        <ul>
            $(if ($IsPartialResults) { 
                "<li><strong>Partial Data Report:</strong> This report contains analysis for only $(Get-SafeProperty -Object $AuditResults -PropertyName 'Count') Key Vaults and may not reflect the complete organizational security posture.</li>"
                if ($CheckpointData -and $CheckpointData.TotalVaults) { 
                    $completionPercentage = [math]::Round(((Get-SafeProperty -Object $AuditResults -PropertyName 'Count') / $CheckpointData.TotalVaults) * 100, 1)
                    "<li><strong>Data Completeness:</strong> Represents $completionPercentage% of originally discovered Key Vaults ($(Get-SafeProperty -Object $AuditResults -PropertyName 'Count') of $($CheckpointData.TotalVaults)).</li>"
                }
                "<li><strong>Resume Instructions:</strong> To complete the full audit, use the <code>-Resume</code> parameter with the original execution ID if checkpoint files are available.</li>"
                "<li><strong>Data Source:</strong> Generated from $(if ($PartialDataSource -eq "csv") { "CSV file import" } else { "checkpoint recovery data" }).</li>"
            })
            <li><strong>Permissions:</strong> Some data may be incomplete due to insufficient permissions. Check the permissions log for details.</li>
            <li><strong>Best Practices:</strong> This audit reflects current Microsoft recommendations as of $(Get-Date -Format 'MMMM yyyy').</li>
            <li><strong>Continuous Improvement:</strong> Regular audits are recommended to maintain security posture.</li>
            <li><strong>Authentication:</strong> Script performed $(if ((Get-SafeProperty -Object $AuditStats -PropertyName 'AuthenticationRefreshes' -DefaultValue $null)) { (Get-SafeProperty -Object $AuditStats -PropertyName 'AuthenticationRefreshes' -DefaultValue '0') } else { "0" }) token refresh(es) to maintain connectivity.</li>
            $(if ($IsPartialResults) { 
                "<li><strong>Statistical Accuracy:</strong> Percentages and averages in this partial report reflect only the processed subset and should not be extrapolated to represent complete organizational metrics.</li>"
            })
        </ul>
    </div>
    
    <footer style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center; color: #6c757d; border-top: 3px solid #667eea;">
        <p><strong>Azure Key Vault Enhanced Security & Compliance Audit Report</strong></p>
    <p>Generated by Script v2.1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') by $safeCurrentUser</p>
        $(if ($IsPartialResults) { 
            "<p><strong>⚠️ This is a PARTIAL RESULTS report generated from $(if ($PartialDataSource -eq "csv") { "CSV file data" } else { "checkpoint data" })</strong></p>"
            if ($CheckpointData) { "<p><strong>Original Execution ID:</strong> $(Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId')</p>" }
            if ($global:executionId -and $CheckpointData -and (Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId') -and $global:executionId -ne (Get-SafeProperty -Object $CheckpointData -PropertyName 'ExecutionId')) { "<p><strong>Report Generation ID:</strong> $($global:executionId)</p>" }
        } else {
            if ($global:executionId) { "<p><strong>Execution ID:</strong> $($global:executionId)</p>" }
        })
        <p>For questions or support, contact your Azure security team.</p>
        $(if ($IsPartialResults) { 
            "<p style='font-size: 0.9em; margin-top: 15px;'><strong>Data Provenance:</strong> Report generated from partial dataset | Processed: $(Get-SafeProperty -Object $AuditResults -PropertyName 'Count') vaults$(if ($CheckpointData -and $CheckpointData.TotalVaults) { " of $($CheckpointData.TotalVaults) total" }) | Source: $(if ($PartialDataSource -eq "csv") { "CSV import" } else { "checkpoint recovery" })</p>"
        })
    </footer>
</body>
</html>
"@
    Write-UserMessage "HTML content string generation completed" -Type Verbose
    Write-UserMessage "HTML content generation completed successfully" -Type Verbose
    
    } catch {
        $errorMessage = "An error occurred during HTML report generation. Exception type: $($_.GetType().Name)"
        Write-Host "❌ Error generating comprehensive HTML report: $errorMessage" -ForegroundColor Red
        Write-Host "Exception message: $($_.Exception.Message)" -ForegroundColor Yellow
        if ($_.Exception.StackTrace) { Write-Host "Stack trace: $($_.Exception.StackTrace)" -ForegroundColor Yellow }
        if ($_.InvocationInfo) {
            Write-Host "Script Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
            Write-Host "Invocation Line: $($_.InvocationInfo.Line)" -ForegroundColor Yellow
        }
        Write-Warning $errorMessage
        return $false
    }
    
    # Save HTML content to file
    try {
        $htmlContent | Set-Content -Path $OutputPath -Encoding UTF8 -ErrorAction Stop
        Write-UserMessage -Message "Comprehensive HTML report saved: $OutputPath" -Type Success
        return $true
    } catch {
        Write-Host "❌ Error saving comprehensive HTML report: $_" -ForegroundColor Red
        Write-UserMessage -Message "Error saving comprehensive HTML report: $_" -Type Error
        return $false
    }

}
function Save-ProgressCheckpoint {
    <#
    .SYNOPSIS
    Save progress checkpoint with enhanced interruption handling and recovery metadata
    .DESCRIPTION
    Creates comprehensive checkpoint files for recovery after interruptions. Includes
    enhanced error handling, retry mechanisms, and detailed metadata for resumption.
    Automatically registers cleanup handlers for graceful interruption handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$VaultIndex,
        
        [Parameter(Mandatory)]
        [int]$TotalVaults,
        
        [Parameter()]
        [array]$ProcessedResults = @(),
        
        [Parameter()]
        [array]$ProcessedVaults = @(),
        
        [Parameter()]
        [bool]$IsFinalCheckpoint = $false,
        
        [Parameter()]
        [int]$MaxCheckpoints = 3,
        
        [Parameter()]
        [string]$InterruptionReason = ""
    )
    # ...existing code...
    
    # Save checkpoint every 25 vaults for recovery purposes, or if it's a final checkpoint, or on interruption
    $shouldSaveCheckpoint = ($VaultIndex % 25 -eq 0 -and $VaultIndex -gt 0) -or $IsFinalCheckpoint -or $InterruptionReason
    
    if ($shouldSaveCheckpoint) {
        $checkpointSaved = $false
        $retryCount = 0
        $maxRetries = 3
        
        Write-Verbose "Attempting to save checkpoint at vault $VaultIndex of $TotalVaults"
        
        while (-not $checkpointSaved -and $retryCount -lt $maxRetries) {
            try {
                $checkpointType = if ($IsFinalCheckpoint) { "final" } elseif ($InterruptionReason) { "interrupted" } else { "progress" }
                $checkpointFileName = "akv_audit_checkpoint_${global:executionId}_${checkpointType}_vault${VaultIndex}.json"
                $checkpointPath = Join-Path $outDir $checkpointFileName
                
                # Ensure output directory exists with enhanced error handling
                if (-not (Test-Path $outDir)) {
                    Write-Verbose "Creating output directory: $outDir"
                    New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null
                }
                
                # Build processed vaults list from results if not provided
                if ($ProcessedVaults.Count -eq 0 -and $ProcessedResults) {
                    Write-Verbose "Building processed vaults list from results ($($ProcessedResults.Count) items)"
                    $ProcessedVaults = $ProcessedResults | ForEach-Object {
                        @{
                            VaultName = $_.KeyVaultName
                            SubscriptionId = $_.SubscriptionId
                            ResourceId = $_.ResourceId
                            Status = "completed"
                            ProcessedTime = Get-SafeProperty -Object $_ -PropertyName 'LastAuditDate' -DefaultValue (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
                
                # Build comprehensive checkpoint data with enhanced metadata
                $checkpointData = @{
                    # Core progress information
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
                    VaultIndex = $VaultIndex
                    TotalVaults = $TotalVaults
                    ProcessedCount = if ($ProcessedResults) { $ProcessedResults.Count } else { 0 }
                    PercentComplete = if ($TotalVaults -gt 0) { [math]::Round(($VaultIndex / $TotalVaults) * 100, 2) } else { 0 }
                    
                    # Version and execution metadata
                    ScriptVersion = "2.1"
                    ExecutionId = if ($global:executionId) { $global:executionId } else { "unknown" }
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    
                    # Checkpoint type and interruption handling
                    CheckpointType = $checkpointType
                    IsFinalCheckpoint = $IsFinalCheckpoint
                    InterruptionReason = $InterruptionReason
                    IsInterrupted = [bool]$InterruptionReason
                    
                    # Recovery and resumption metadata
                    CanResume = $true
                    ResumeInstructions = "Use -Resume parameter to continue from this checkpoint"
                    NextVaultIndex = $VaultIndex + 1
                    RemainingVaults = $TotalVaults - $VaultIndex
                    
                    # Execution context
                    ExecutionContext = @{
                        StartTime = $global:ScriptExecutionContext.StartTime
                        Environment = $global:ScriptExecutionContext.EnvironmentDetection
                        Authentication = $global:ScriptExecutionContext.AuthenticationFlow
                        IsInterrupted = $global:ScriptExecutionContext.IsInterrupted
                    }
                }
                
                # Add optional components with enhanced error handling
                try {
                    if ($ProcessedVaults -and $ProcessedVaults.Count -gt 0) { 
                        $checkpointData.ProcessedVaults = $ProcessedVaults 
                        Write-Verbose "Added $($ProcessedVaults.Count) processed vaults to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include ProcessedVaults in checkpoint: $($_.Exception.Message)" -Type Warning
                    Write-DataCollectionLog "Checkpoint" "ProcessedVaults inclusion failed" -DataType "CheckpointData" -Impact "RecoveryDataLoss"
                }
                
                try {
                    if ($ProcessedResults -and $ProcessedResults.Count -gt 0) { 
                        $checkpointData.ProcessedResults = $ProcessedResults 
                        Write-Verbose "Added $($ProcessedResults.Count) processed results to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include ProcessedResults in checkpoint: $($_.Exception.Message)" -Type Warning
                    Write-DataCollectionLog "Checkpoint" "ProcessedResults inclusion failed" -DataType "CheckpointData" -Impact "RecoveryDataLoss"
                }
                
                try {
                    if ($global:auditStats) { 
                        $checkpointData.Statistics = $global:auditStats 
                        Write-Verbose "Added audit statistics to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include Statistics in checkpoint: $($_.Exception.Message)" -Type Warning
                }
                
                try {
                    if ($global:currentUser) { 
                        $checkpointData.User = $global:currentUser 
                        Write-Verbose "Added user context to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include User in checkpoint: $($_.Exception.Message)" -Type Warning
                }
                
                # Convert to JSON with enhanced error handling
                Write-Verbose "Converting checkpoint data to JSON..."
                $jsonContent = $checkpointData | ConvertTo-Json -Depth 5 -ErrorAction Stop
                $jsonContent | Out-File -FilePath $checkpointPath -Encoding UTF8 -ErrorAction Stop
                
                $checkpointTypeLabel = switch ($checkpointType) {
                    "final" { "Final" }
                    "interrupted" { "Emergency (Interrupted)" }
                    default { "Progress" }
                }
                
                Write-DataCollectionLog "Checkpoint" "$checkpointTypeLabel checkpoint saved: $VaultIndex/$TotalVaults vaults processed" -DataType "RecoveryData" -Impact "ContinuityPlanning"
                Write-UserMessage -Message "$checkpointTypeLabel checkpoint saved successfully ($VaultIndex/$TotalVaults vaults)" -Type Success
                
                $checkpointSaved = $true
                
                # Clean up old checkpoint files (keep last N as configured) - non-critical operation
                if (-not $IsFinalCheckpoint -and -not $InterruptionReason) {
                    try {
                        $oldCheckpoints = Get-ChildItem -Path $outDir -Filter "akv_audit_checkpoint_${global:executionId}_*_vault*.json" -ErrorAction SilentlyContinue | 
                                        Where-Object { $_.Name -notmatch "(final|interrupted)" } |
                                        Sort-Object LastWriteTime -Descending | 
                                        Select-Object -Skip $MaxCheckpoints
                        if ($oldCheckpoints) {
                            Write-UserMessage -Message "Cleaning up $($oldCheckpoints.Count) old checkpoint files (keeping last $MaxCheckpoints)" -Type Info
                            foreach ($oldFile in $oldCheckpoints) {
                                Remove-Item $oldFile.FullName -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {
                        # Cleanup failure is not critical - don't break checkpoint process
                        Write-UserMessage -Message "Old checkpoint cleanup failed but checkpoint saved successfully" -Type Warning
                    }
                }
                
            } catch {
                $retryCount++
                $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                
                if ($retryCount -lt $maxRetries) {
                    Write-UserMessage -Message "Checkpoint save attempt $retryCount failed, retrying... Error: $errorMessage" -Type Warning
                    Start-Sleep -Seconds 2
                } else {
                    Write-UserMessage -Message "Failed to save checkpoint after $maxRetries attempts. Script will continue but resume may not be possible." -Type Error
                    Write-ErrorLog "Checkpoint" "Failed to save checkpoint after $maxRetries attempts: $errorMessage" -Context "VaultIndex:$VaultIndex|TotalVaults:$TotalVaults|IsFinal:$IsFinalCheckpoint"
                }
            }
        }
        
        # Final success/failure notification
        if ($checkpointSaved) {
            Write-UserMessage -Message "Checkpoint saved successfully (Vault $VaultIndex/$TotalVaults)" -Type Success
            
            # Upload checkpoint files to OneDrive/SharePoint for walk-away reliability
            if (Get-Command Initialize-GraphAuth -ErrorAction SilentlyContinue) {
                try {
                    if (Initialize-GraphAuth -Verbose:($VerbosePreference -eq 'Continue')) {
                        # Determine current CSV path for upload
                        $currentCsvPath = if ($global:csvPath -and (Test-Path $global:csvPath)) { 
                            $global:csvPath 
                        } else { 
                            $null 
                        }
                        # Upload checkpoint and current files
                        $uploadResults = Send-CheckpointFiles -CheckpointPath $checkpointPath -CsvFilePath $currentCsvPath
                        if ($uploadResults -and $uploadResults.Count -gt 0) {
                            Write-UserMessage -Message "Checkpoint uploaded to cloud storage ($($uploadResults.Count) files)" -Type Success
                        }
                    }
                } catch {
                    # Upload failure should not break the audit process
                    Write-UploadLog "Error" "Checkpoint upload failed but audit continues: $_" -FileName "checkpoint" -Context "NonCritical"
                }
            }
        } else {
            Write-UserMessage -Message "Checkpoint save failed but audit will continue" -Type Warning
        }
    }
}

# --- Critical Resume/Recovery Functions (Must be defined before main execution) ---

function Get-DefaultOutputDirectory {
    if ($IsWindows -or $env:OS -eq "Windows_NT" -or -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        # Windows environment
        $documentsPath = Join-Path $env:USERPROFILE "Documents"
        return Join-Path $documentsPath "KeyVaultAudit"
    } elseif (-not [string]::IsNullOrWhiteSpace($env:HOME)) {
        # Linux/macOS environment
        if ($env:SHELL -match "cloudshell" -or $env:ACC_CLOUD -eq "1" -or $env:AZUREPS_HOST_ENVIRONMENT -eq "cloud-shell") {
            # Azure Cloud Shell detected
            # Extract username before @ from UPN if available
            $cloudShellUser = if ($env:ACC_OID -and $env:ACC_TID) {
                # Try to get UPN from environment or context
                try {
                    $context = Get-AzContext -ErrorAction SilentlyContinue
                    if ($context -and $context.Account -and $context.Account.Id -and $context.Account.Id.Contains("@")) {
                        $upnPrefix = $context.Account.Id.Split("@")[0]
                        Write-Host "🔍 Cloud Shell UPN prefix detected: $upnPrefix" -ForegroundColor Gray
                        $upnPrefix
                    } else {
                        "cloudshell"
                    }
                } catch {
                    Write-Host "Cloud Shell UPN detection failed: $_" -ForegroundColor Red
                    "cloudshell"
                }
            } else {
                "cloudshell"
            }
            
            $cloudShellPath = "/home/$cloudShellUser"
            Write-Host "☁️ Azure Cloud Shell detected - using path: $cloudShellPath" -ForegroundColor Cyan
            return $cloudShellPath
        } else {
            # Standard Unix environment
            return Join-Path $env:HOME "KeyVaultAudit"
        }
    } else {
        # Fallback to current directory
        Write-Warning "Unable to determine user profile directory, using current directory"
        return Join-Path $PWD "KeyVaultAudit"
    }
}
    
    function Export-ComprehensiveHTMLReport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [object]$AllVaultsData,
    
            [Parameter(Mandatory=$true)]
            [string]$FilePath,
    
            [Parameter(Mandatory=$false)]
            [string]$Title = "Azure Key Vault Comprehensive Security Audit",
    
            [Parameter(Mandatory=$false)]
            [string]$ReportDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"),
    
            [Parameter(Mandatory=$false)]
            [string]$User = "N/A",
    
            [Parameter(Mandatory=$false)]
            [string]$Version = "N/A",
    
            [Parameter(Mandatory=$false)]
            [string]$TenantId = "N/A",
    
            [Parameter(Mandatory=$false)]
            [string[]]$SubscriptionFilter,
    
            [Parameter(Mandatory=$false)]
            [string]$ComplianceFramework = "None"
        )
    
        try {
            Write-UserMessage -Message "📊 Generating comprehensive HTML report..." -Level Info
    
            # Determine if we have a collection of vaults or a single one
            $vaults = @()
            if ($AllVaultsData -is [System.Collections.IDictionary]) {
                $vaults = $AllVaultsData.Values
            } else {
                $vaults = $AllVaultsData
            }
    
            if (-not $vaults) {
                Write-UserMessage -Message "WARNING: No vault data was successfully processed. Generating a failure report." -Level Warning
                $errorMessageBody = @"
    <h2>❌ Audit Data Incomplete</h2>
    <p>The audit script did not collect data for any Key Vaults. This can happen due to several reasons:</p>
    <ul>
        <li><strong>Permissions:</strong> The account running the script may lack 'Reader' permissions on subscriptions or 'Key Vault Reader' on the vaults.</li>
        <li><strong>Scope:</strong> The specified subscription filter might not contain any Key Vaults.</li>
        <li><strong>Connectivity:</strong> There might have been issues connecting to Azure APIs.</li>
    </ul>
    <p>Please check the log files for detailed error messages and run the script again with appropriate permissions.</p>
"@
                $template = Get-FailureReportTemplate -Title "Key Vault Audit Failure" -Body $errorMessageBody -User $User -Date $ReportDate -Version $Version
                $template | Out-File -FilePath $FilePath -Encoding utf8
                Write-UserMessage -Message "❌ Failure report generated at $FilePath" -Level Error
                return
            }
        }
        catch {
            Write-UserMessage -Message "An unexpected error occurred during HTML report generation setup: $($_.Exception.Message)" -Level Error
            throw
        }
    
    # Save checkpoint every 25 vaults for recovery purposes, or if it's a final checkpoint, or on interruption
    $shouldSaveCheckpoint = ($VaultIndex % 25 -eq 0 -and $VaultIndex -gt 0) -or $IsFinalCheckpoint -or $InterruptionReason
    
    if ($shouldSaveCheckpoint) {
        $checkpointSaved = $false
        $retryCount = 0
        $maxRetries = 3
        
        Write-Verbose "Attempting to save checkpoint at vault $VaultIndex of $TotalVaults"
        
        while (-not $checkpointSaved -and $retryCount -lt $maxRetries) {
            try {
                $checkpointType = if ($IsFinalCheckpoint) { "final" } elseif ($InterruptionReason) { "interrupted" } else { "progress" }
                $checkpointFileName = "akv_audit_checkpoint_${global:executionId}_${checkpointType}_vault${VaultIndex}.json"
                $checkpointPath = Join-Path $outDir $checkpointFileName
                
                # Ensure output directory exists with enhanced error handling
                if (-not (Test-Path $outDir)) {
                    Write-Verbose "Creating output directory: $outDir"
                    New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null
                }
                
                # Build processed vaults list from results if not provided
                if ($ProcessedVaults.Count -eq 0 -and $ProcessedResults) {
                    Write-Verbose "Building processed vaults list from results ($($ProcessedResults.Count) items)"
                    $ProcessedVaults = $ProcessedResults | ForEach-Object {
                        @{
                            VaultName = $_.KeyVaultName
                            SubscriptionId = $_.SubscriptionId
                            ResourceId = $_.ResourceId
                            Status = "completed"
                            ProcessedTime = Get-SafeProperty -Object $_ -PropertyName 'LastAuditDate' -DefaultValue (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
                
                # Build comprehensive checkpoint data with enhanced metadata
                $checkpointData = @{
                    # Core progress information
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
                    VaultIndex = $VaultIndex
                    TotalVaults = $TotalVaults
                    ProcessedCount = if ($ProcessedResults) { $ProcessedResults.Count } else { 0 }
                    PercentComplete = if ($TotalVaults -gt 0) { [math]::Round(($VaultIndex / $TotalVaults) * 100, 2) } else { 0 }
                    
                    # Version and execution metadata
                    ScriptVersion = "2.1"
                    ExecutionId = if ($global:executionId) { $global:executionId } else { "unknown" }
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    
                    # Checkpoint type and interruption handling
                    CheckpointType = $checkpointType
                    IsFinalCheckpoint = $IsFinalCheckpoint
                    InterruptionReason = $InterruptionReason
                    IsInterrupted = [bool]$InterruptionReason
                    
                    # Recovery and resumption metadata
                    CanResume = $true
                    ResumeInstructions = "Use -Resume parameter to continue from this checkpoint"
                    NextVaultIndex = $VaultIndex + 1
                    RemainingVaults = $TotalVaults - $VaultIndex
                    
                    # Execution context
                    ExecutionContext = @{
                        StartTime = $global:ScriptExecutionContext.StartTime
                        Environment = $global:ScriptExecutionContext.EnvironmentDetection
                        Authentication = $global:ScriptExecutionContext.AuthenticationFlow
                        IsInterrupted = $global:ScriptExecutionContext.IsInterrupted
                    }
                }
                
                # Add optional components with enhanced error handling
                try {
                    if ($ProcessedVaults -and $ProcessedVaults.Count -gt 0) { 
                        $checkpointData.ProcessedVaults = $ProcessedVaults 
                        Write-Verbose "Added $($ProcessedVaults.Count) processed vaults to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include ProcessedVaults in checkpoint: $($_.Exception.Message)" -Type Warning
                    Write-DataCollectionLog "Checkpoint" "ProcessedVaults inclusion failed" -DataType "CheckpointData" -Impact "RecoveryDataLoss"
                }
                
                try {
                    if ($ProcessedResults -and $ProcessedResults.Count -gt 0) { 
                        $checkpointData.ProcessedResults = $ProcessedResults 
                        Write-Verbose "Added $($ProcessedResults.Count) processed results to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include ProcessedResults in checkpoint: $($_.Exception.Message)" -Type Warning
                    Write-DataCollectionLog "Checkpoint" "ProcessedResults inclusion failed" -DataType "CheckpointData" -Impact "RecoveryDataLoss"
                }
                
                try {
                    if ($global:auditStats) { 
                        $checkpointData.Statistics = $global:auditStats 
                        Write-Verbose "Added audit statistics to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include Statistics in checkpoint: $($_.Exception.Message)" -Type Warning
                }
                
                try {
                    if ($global:currentUser) { 
                        $checkpointData.User = $global:currentUser 
                        Write-Verbose "Added user context to checkpoint"
                    }
                } catch {
                    Write-UserMessage -Message "Failed to include User in checkpoint: $($_.Exception.Message)" -Type Warning
                }
                
                # Convert to JSON with enhanced error handling
                Write-Verbose "Converting checkpoint data to JSON..."
                $jsonContent = $checkpointData | ConvertTo-Json -Depth 5 -ErrorAction Stop
                $jsonContent | Out-File -FilePath $checkpointPath -Encoding UTF8 -ErrorAction Stop
                
                $checkpointTypeLabel = switch ($checkpointType) {
                    "final" { "Final" }
                    "interrupted" { "Emergency (Interrupted)" }
                    default { "Progress" }
                }
                
                Write-DataCollectionLog "Checkpoint" "$checkpointTypeLabel checkpoint saved: $VaultIndex/$TotalVaults vaults processed" -DataType "RecoveryData" -Impact "ContinuityPlanning"
                Write-UserMessage -Message "$checkpointTypeLabel checkpoint saved successfully ($VaultIndex/$TotalVaults vaults)" -Type Success
                
                $checkpointSaved = $true
                
                # Clean up old checkpoint files (keep last N as configured) - non-critical operation
                if (-not $IsFinalCheckpoint -and -not $InterruptionReason) {
                    try {
                        $oldCheckpoints = Get-ChildItem -Path $outDir -Filter "akv_audit_checkpoint_${global:executionId}_*_vault*.json" -ErrorAction SilentlyContinue | 
                                        Where-Object { $_.Name -notmatch "(final|interrupted)" } |
                                        Sort-Object LastWriteTime -Descending | 
                                        Select-Object -Skip $MaxCheckpoints
                        if ($oldCheckpoints) {
                            Write-UserMessage -Message "Cleaning up $($oldCheckpoints.Count) old checkpoint files (keeping last $MaxCheckpoints)" -Type Info
                            foreach ($oldFile in $oldCheckpoints) {
                                Remove-Item $oldFile.FullName -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {
                        # Cleanup failure is not critical - don't break checkpoint process
                        Write-UserMessage -Message "Old checkpoint cleanup failed but checkpoint saved successfully" -Type Warning
                    }
                }
                
            } catch {
                $retryCount++
                $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                
                if ($retryCount -lt $maxRetries) {
                    Write-UserMessage -Message "Checkpoint save attempt $retryCount failed, retrying... Error: $errorMessage" -Type Warning
                    Start-Sleep -Seconds 2
                } else {
                    Write-UserMessage -Message "Failed to save checkpoint after $maxRetries attempts. Script will continue but resume may not be possible." -Type Error
                    Write-ErrorLog "Checkpoint" "Failed to save checkpoint after $maxRetries attempts: $errorMessage" -Context "VaultIndex:$VaultIndex|TotalVaults:$TotalVaults|IsFinal:$IsFinalCheckpoint"
                }
            }
        }
        
        # Final success/failure notification
        if ($checkpointSaved) {
            Write-UserMessage -Message "Checkpoint saved successfully (Vault $VaultIndex/$TotalVaults)" -Type Success
            
            # Upload checkpoint files to OneDrive/SharePoint for walk-away reliability
            if (Get-Command Initialize-GraphAuth -ErrorAction SilentlyContinue) {
                try {
                    if (Initialize-GraphAuth -Verbose:($VerbosePreference -eq 'Continue')) {
                        # Determine current CSV path for upload
                        $currentCsvPath = if ($global:csvPath -and (Test-Path $global:csvPath)) { 
                            $global:csvPath 
                        } else { 
                            $null 
                        }
                        # Upload checkpoint and current files
                        $uploadResults = Send-CheckpointFiles -CheckpointPath $checkpointPath -CsvFilePath $currentCsvPath
                        if ($uploadResults -and $uploadResults.Count -gt 0) {
                            Write-UserMessage -Message "Checkpoint uploaded to cloud storage ($($uploadResults.Count) files)" -Type Success
                        }
                    }
                } catch {
                    # Upload failure should not break the audit process
                    Write-UploadLog "Error" "Checkpoint upload failed but audit continues: $_" -FileName "checkpoint" -Context "NonCritical"
                }
            }
        } else {
            Write-UserMessage -Message "Checkpoint save failed but audit will continue" -Type Warning
        }
    }
}

# --- Critical Resume/Recovery Functions (Must be defined before main execution) ---

function Get-DefaultOutputDirectory {
    if ($IsWindows -or $env:OS -eq "Windows_NT" -or -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        # Windows environment
        $documentsPath = Join-Path $env:USERPROFILE "Documents"
        return Join-Path $documentsPath "KeyVaultAudit"
    } elseif (-not [string]::IsNullOrWhiteSpace($env:HOME)) {
        # Linux/macOS environment
        if ($env:SHELL -match "cloudshell" -or $env:ACC_CLOUD -eq "1" -or $env:AZUREPS_HOST_ENVIRONMENT -eq "cloud-shell") {
            # Azure Cloud Shell detected
            # Extract username before @ from UPN if available
            $cloudShellUser = if ($env:ACC_OID -and $env:ACC_TID) {
                # Try to get UPN from environment or context
                try {
                    $context = Get-AzContext -ErrorAction SilentlyContinue
                    if ($context -and $context.Account -and $context.Account.Id -and $context.Account.Id.Contains("@")) {
                        $upnPrefix = $context.Account.Id.Split("@")[0]
                        Write-Host "🔍 Cloud Shell UPN prefix detected: $upnPrefix" -ForegroundColor Gray
                        $upnPrefix
                    } else {
                        "cloudshell"
                    }
                } catch {
                    Write-Host "Cloud Shell UPN detection failed: $_" -ForegroundColor Red
                    "cloudshell"
                }
            } else {
                "cloudshell"
            }
            
            $cloudShellPath = "/home/$cloudShellUser"
            Write-Host "☁️ Azure Cloud Shell detected - using path: $cloudShellPath" -ForegroundColor Cyan
            return $cloudShellPath
        } else {
            # Standard Unix environment
            return Join-Path $env:HOME "KeyVaultAudit"
        }
    } else {
        # Fallback to current directory
        Write-Warning "Unable to determine user profile directory, using current directory"
        return Join-Path $PWD "KeyVaultAudit"
    }
}

function Test-DiscoveryMasterValidity {
    param(
        [object]$MasterData,
        [int]$MaxAgeHours = 48
    )
    
    # Check if MasterData exists and has required properties
    if (-not $MasterData) {
        return $false
    }
    
    # Check for required properties
    $requiredProperties = @('Timestamp', 'User', 'Subscriptions')
    foreach ($prop in $requiredProperties) {
        if (-not ($MasterData | Get-Member -Name $prop -ErrorAction SilentlyContinue)) {
            Write-Verbose "Master data missing required property: $prop"
            return $false
        }
    }
    
    # Check timestamp validity and age
    try {
        $timestamp = [DateTime]::ParseExact($MasterData.Timestamp, 'yyyy-MM-dd HH:mm:ss UTC', $null)
        $ageHours = ((Get-Date) - $timestamp).TotalHours
        
        if ($ageHours -gt $MaxAgeHours) {
            Write-Verbose "Master data is too old: $ageHours hours (max: $MaxAgeHours)"
            return $false
        }
    } catch {
        Write-Verbose "Invalid timestamp format in master data: $($MasterData.Timestamp)"
        return $false
    }
    
    return $true
}

function Import-DiscoveryMaster {
    [CmdletBinding()]
    param([string]$OutputDirectory)
    
    try {
        # Define search directories in precedence order
        $candidateDirectories = @()
        
        # 1. Explicit -OutputDirectory if provided and exists
        if ($OutputDirectory -and (Test-Path $OutputDirectory)) {
            $candidateDirectories += $OutputDirectory
        }
        
        # 2. $script:outDir (if set)
        if ($script:outDir -and (Test-Path $script:outDir)) {
            $candidateDirectories += $script:outDir
        }
        
        # 3. $outDir (if set)
        if ($outDir -and (Test-Path $outDir)) {
            $candidateDirectories += $outDir
        }
        
        # 4. Script directory (prefer $PSScriptRoot; fallback to Split-Path -Parent $PSCommandPath)
        $scriptDir = $null
        if ($PSScriptRoot) {
            $scriptDir = $PSScriptRoot
        } elseif ($PSCommandPath) {
            $scriptDir = Split-Path -Parent $PSCommandPath
        }
        if ($scriptDir -and (Test-Path $scriptDir)) {
            $candidateDirectories += $scriptDir
        }
        
        # 5. Current working directory
        $currentDir = (Get-Location).Path
        if ($currentDir -and (Test-Path $currentDir)) {
            $candidateDirectories += $currentDir
        }
        
        # 6. $HOME/Documents/KeyVaultAudit (if exists)
        if ($HOME) {
            $docsDir = Join-Path $HOME 'Documents/KeyVaultAudit'
            if (Test-Path $docsDir) {
                $candidateDirectories += $docsDir
            }
        }
        
        # 7. $HOME (if exists)
        if ($HOME -and (Test-Path $HOME)) {
            $candidateDirectories += $HOME
        }

        # Remove duplicates while preserving order
        $candidateDirectories = $candidateDirectories | Select-Object -Unique

        # Define filename patterns to search
        $patterns = @(
            'akv_discovery_master_*.json',
            'akv_master_discovery_*.json',
            'akv_audit_master_*.json'
        )

        # Search all directories for all patterns and collect candidates
        $allCandidates = @()
        foreach ($dir in $candidateDirectories) {
            foreach ($pattern in $patterns) {
                $files = Get-ChildItem -Path $dir -Filter $pattern -File -ErrorAction SilentlyContinue
                if ($files) {
                    $allCandidates += $files
                }
            }
        }

        # Select the newest file across all matches by LastWriteTimeUtc
        $candidate = $allCandidates | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1

        if (-not $candidate) {
            # Enhanced verbose logging when nothing is found
            $dirList = $candidateDirectories -join ', '
            $patternList = $patterns -join ', '
            Write-Verbose "Resume: No master discovery file found. Searched directories: [$dirList] using patterns: [$patternList]" -Verbose
            return $null
        }

        $data = Get-Content -Path $candidate.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
        
        # Normalize TotalSubscriptions/TotalKeyVaults if needed (maintain backward compatibility)
        if (-not $data.TotalSubscriptions -and $data.Subscriptions) {
            $data | Add-Member -NotePropertyName 'TotalSubscriptions' -NotePropertyValue $data.Subscriptions.Count -Force
        }
        if (-not $data.TotalKeyVaults -and $data.Subscriptions) {
            $vaultCounts = $data.Subscriptions | ForEach-Object { $_.KeyVaults.Count } | Measure-Object -Sum -ErrorAction SilentlyContinue
            $totalVaults = if ($vaultCounts) { Get-SafeProperty -Object $vaultCounts -PropertyName 'Sum' -DefaultValue 0 } else { 0 }
            $data | Add-Member -NotePropertyName 'TotalKeyVaults' -NotePropertyValue $totalVaults -Force
        }
        
        # Validate the master data if validation function is available
        if ((Get-Command Test-DiscoveryMasterValidity -ErrorAction SilentlyContinue) -and 
            -not (Test-DiscoveryMasterValidity -MasterData $data)) {
            Write-Warning "Resume: Discovery master file is invalid or outdated"
            return $null
        }

        # Enhanced success message with full path
        Write-Host "⚡ Resume: Loaded master discovery file: $($candidate.FullName)" -ForegroundColor Green
        
        # Optional additional info display (maintain existing functionality)
        if ($data.Timestamp) {
            Write-Host "   📅 Created: $($data.Timestamp)" -ForegroundColor Gray
        }
        if ($data.User) {
            Write-Host "   👤 User: $($data.User)" -ForegroundColor Gray
        }
        if ($data.TotalSubscriptions -or $data.TotalKeyVaults) {
            Write-Host "   📊 Subscriptions: $($data.TotalSubscriptions) | Key Vaults: $($data.TotalKeyVaults)" -ForegroundColor Gray
        }
        
        # Note: Write-ErrorLog function will be available when this is called during main execution
        if (Get-Command Write-ErrorLog -ErrorAction SilentlyContinue) {
            Write-ErrorLog "DiscoveryMaster" "Master discovery file loaded successfully" -Details "File: $($candidate.FullName) | Subscriptions: $($data.TotalSubscriptions) | KeyVaults: $($data.TotalKeyVaults)"
        }
        
        return $data
    } catch {
        Write-Warning "Resume: Failed to import master discovery file: $_"
        # Note: Write-ErrorLog function will be available when this is called during main execution
        if (Get-Command Write-ErrorLog -ErrorAction SilentlyContinue) {
            Write-ErrorLog "DiscoveryMaster" "Failed to load master discovery file: $_"
        }
        return $null
    }
}

function Import-PartialResultsFromCsv {
    param(
        [string]$CsvFilePath
    )
    
    try {
        Write-Host "📊 Loading CSV data for report generation..." -ForegroundColor Cyan
        
        # Import CSV data
        $csvData = Import-Csv -Path $CsvFilePath -ErrorAction Stop
        if (-not $csvData -or $csvData.Count -eq 0) {
            Write-Host "❌ Error: CSV file is empty or invalid: $CsvFilePath" -ForegroundColor Red
            return $false
        }
        
        Write-Host "✅ Loaded $($csvData.Count) vault records from CSV" -ForegroundColor Green
        
        # Convert CSV data to audit results format
        $global:auditResults = @()
        foreach ($row in $csvData) {
            $global:auditResults += $row
        }
        
        # Mark this as a partial results run from CSV
        $global:isPartialResults = $true
        $global:partialResultsTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
        $global:partialResultsVaultCount = $csvData.Count
        $global:partialResultsTotalVaults = $csvData.Count  # For CSV, we don't know total intended
        
        # Generate timestamp for partial results
        $partialTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        
        # Determine output directory from CSV file location or use default
        $csvDir = Split-Path $CsvFilePath -Parent
        if (-not $csvDir) { $csvDir = $PWD }
        
        # Check if we can write to the CSV directory, otherwise use default output directory
        $testFile = Join-Path $csvDir "test_write_permissions.tmp"
        try {
            "test" | Out-File -FilePath $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            $outDir = $csvDir
            Write-Host "📁 Using CSV file directory for output: $outDir" -ForegroundColor Gray
        } catch {
            # Fall back to default output directory detection
            $outDir = Get-DefaultOutputDirectory
            Write-Host "📁 Using default output directory: $outDir" -ForegroundColor Gray
        }
        
        # Ensure output directory exists
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        
        # Update file paths to indicate partial results from CSV
        $csvOutputPath = Join-Path $outDir "KeyVaultComprehensiveAudit_PARTIAL_CSV_${partialTimestamp}.csv"
        $htmlPath = Join-Path $outDir "KeyVaultComprehensiveAudit_PARTIAL_CSV_${partialTimestamp}.html"
        
        Write-Host "📁 Output files:" -ForegroundColor Gray
        Write-Host "   CSV: $(Split-Path $csvOutputPath -Leaf)" -ForegroundColor Gray
        Write-Host "   HTML: $(Split-Path $htmlPath -Leaf)" -ForegroundColor Gray
        
        # Generate CSV report (copy of source with additional metadata)
        try {
            $global:auditResults | Export-Csv -Path $csvOutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "✅ Partial CSV report generated: $(Split-Path $csvOutputPath -Leaf)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to generate partial CSV report: $_" -ForegroundColor Red
            return $false
        }
        
        # Generate comprehensive HTML report for CSV partial results using the new function
        try {
            # Create a fake checkpoint data structure for CSV source
            $csvCheckpointData = @{
                ExecutionId = "CSV-Import-$(Get-Date -Format 'yyyyMMdd')"
                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
                VaultIndex = $csvData.Count
                TotalVaults = $csvData.Count
                ProcessedResults = $global:auditResults
            }
            
            # Calculate executive summary for CSV partial results
            $csvExecutiveSummary = @{
                TotalKeyVaults = Get-SafeCount $global:auditResults
                CompliantVaults = if ($global:auditResults) { 
                    @($global:auditResults | Where-Object { 
                        try { [int]($_.ComplianceScore -replace '%', '') -ge 90 } catch { $false }
                    }).Count
                } else { 0 }
                CompliancePercentage = if ($global:auditResults -and (Get-SafeCount $global:auditResults) -gt 0) { 
                    $compliantCount = @($global:auditResults | Where-Object { 
                        try { [int]($_.ComplianceScore -replace '%', '') -ge 90 } catch { $false }
                    }).Count
                    [math]::Round(($compliantCount / (Get-SafeCount $global:auditResults)) * 100, 1) 
                } else { 0 }
                AverageComplianceScore = if ($global:auditResults -and (Get-SafeCount $global:auditResults) -gt 0) { 
                    $scores = @($global:auditResults | ForEach-Object { 
                        try { [int]($_.ComplianceScore -replace '%', '') } catch { $null }
                    } | Where-Object { $null -ne $_ })
                    if ((Get-SafeCount $scores) -gt 0) {
                        $scoreMeasure = $scores | Measure-Object -Average
                        [math]::Round((Get-SafeProperty -Object $scoreMeasure -PropertyName 'Average' -DefaultValue 0), 1) 
                    } else { 0 }
                } else { 0 }
                CompanyAverageScore = if ($global:auditResults -and (Get-SafeCount $global:auditResults) -gt 0) { 
                    $scores = @($global:auditResults | Where-Object { Get-SafeProperty -Object $_ -PropertyName 'CompanyComplianceScore' } | ForEach-Object { 
                        try { [int]((Get-SafeProperty -Object $_ -PropertyName 'CompanyComplianceScore') -replace '%', '') } catch { 0 }
                    } | Where-Object { $null -ne $_ })
                    if ((Get-SafeCount $scores) -gt 0) {
                        $companyScoreMeasure = $scores | Measure-Object -Average
                        [math]::Round((Get-SafeProperty -Object $companyScoreMeasure -PropertyName 'Average' -DefaultValue 0), 1) 
                    } else { 0 }
                } else { 0 }
                HighRiskVaults = if ($global:auditResults) { 
                    @($global:auditResults | Where-Object { 
                        try { [int]($_.ComplianceScore -replace '%', '') -lt 60 } catch { $false }
                    }).Count
                } else { 0 }
            }
            
            # Defensive normalization before generating HTML
            try {
                $global:auditResults = @($global:auditResults | Where-Object { $_ -ne $null })
                $dbgType = if ($global:auditResults) { $global:auditResults.GetType().FullName } else { 'null' }
                Write-Host "Debug: Calling New-ComprehensiveHtmlReport with AuditResults type: $dbgType, Count: $(Get-SafeCount $global:auditResults)" -ForegroundColor Cyan

                # Use the comprehensive HTML generation function
                $htmlGenerated = New-ComprehensiveHtmlReport -OutputPath $htmlPath -AuditResults $global:auditResults -ExecutiveSummary $csvExecutiveSummary -AuditStats @{} -IsPartialResults $true -CheckpointData $csvCheckpointData -PartialDataSource "csv"

                if (-not $htmlGenerated) {
                    Write-Host "❌ Failed to generate comprehensive CSV partial HTML report" -ForegroundColor Red
                    return $false
                }
            } catch {
                Write-Host "❌ Failed to generate comprehensive CSV partial HTML report: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Exception details:" -ForegroundColor Yellow
                $_.Exception | Format-List * -Force | ForEach-Object { Write-Host $_ }
                Write-Host "Dumping debug info for inputs:" -ForegroundColor Yellow
                Write-Host "AuditResults type: $(if ($global:auditResults) { $global:auditResults.GetType().FullName } else { 'null' })" -ForegroundColor Yellow
                Write-Host "AuditResults safe count: $(Get-SafeCount $global:auditResults)" -ForegroundColor Yellow
                Write-Host "CheckpointData type: $(if ($csvCheckpointData) { $csvCheckpointData.GetType().FullName } else { 'null' })" -ForegroundColor Yellow
                Write-Host "ExecutiveSummary type: $(if ($csvExecutiveSummary) { $csvExecutiveSummary.GetType().FullName } else { 'null' })" -ForegroundColor Yellow
                return $false
            }
        } catch {
            Write-Host "❌ Failed to generate comprehensive CSV partial HTML report: $_" -ForegroundColor Red
            return $false
        }
        
        # Display summary
        Write-Host ""
        Write-Host "📋 CSV Partial Results Summary:" -ForegroundColor Cyan
        Write-Host "   Source CSV file: $(Split-Path $CsvFilePath -Leaf)" -ForegroundColor Gray
        Write-Host "   File size: $([math]::Round((Get-Item $CsvFilePath).Length / 1KB, 2)) KB" -ForegroundColor Gray
        Write-Host "   Records loaded: $($csvData.Count) vaults" -ForegroundColor Gray
        Write-Host "   Processing completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        Write-Host ""
        Write-Host "📁 Generated Reports:" -ForegroundColor Green
        Write-Host "   📄 CSV: $(Split-Path $csvOutputPath -Leaf)" -ForegroundColor Green
        Write-Host "   🌐 HTML: $(Split-Path $htmlPath -Leaf)" -ForegroundColor Green
        
        # Cloud upload integration for CSV partial results
        if ($UploadToCloud) {
            Write-Host ""
            Write-Host "📤 Automatic cloud upload enabled for CSV partial results..." -ForegroundColor Cyan
            
            # Get target upload path
            $uploadPath = Get-CloudUploadPath -ProvidedPath $CloudUploadPath
            
            # Attempt cloud upload
            $uploadSuccess = Invoke-CloudUpload -OutputDirectory $outDir -CsvFilePath $csvOutputPath -HtmlPath $htmlPath -ErrorLogPath $global:errPath -PermissionsLogPath $global:permissionsPath -DataIssuesLogPath $global:dataIssuesPath -TargetPath $uploadPath
            
            if ($uploadSuccess) {
                Write-Host "✅ CSV partial results cloud upload completed successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  CSV partial results cloud upload failed or was cancelled" -ForegroundColor Yellow
            }
        } else {
            # Detect Azure Cloud Shell and offer upload option for CSV partial results
            $isCloudShell = $false
            $cloudShellIndicators = @($env:ACC_TERM, $env:ACC_CLOUD, $env:AZUREPS_HOST_ENVIRONMENT)
            foreach ($indicator in $cloudShellIndicators) {
                if (-not [string]::IsNullOrWhiteSpace($indicator)) {
                    $isCloudShell = $true
                    break
                }
            }
            
            if (-not $isCloudShell -and $PWD.Path.StartsWith('/home/') -and (Test-Path '/usr/bin/az' -ErrorAction SilentlyContinue)) {
                $isCloudShell = $true
            }
            
            if ($isCloudShell) {
                Write-Host ""
                Write-Host "☁️  Azure Cloud Shell detected" -ForegroundColor Cyan
                Write-Host "To prevent data loss when Cloud Shell session expires, you can upload CSV partial results to OneDrive/SharePoint." -ForegroundColor Yellow
                Write-Host ""
                $offerUpload = Read-Host "Would you like to upload CSV partial results to OneDrive/SharePoint? (Y/N)"
                
                if ($offerUpload -match '^[Yy]') {
                    # Get target upload path
                    $uploadPath = Get-CloudUploadPath -ProvidedPath $CloudUploadPath
                    
                    # Attempt cloud upload
                    $uploadSuccess = Invoke-CloudUpload -OutputDirectory $outDir -CsvFilePath $csvOutputPath -HtmlPath $htmlPath -ErrorLogPath $global:errPath -PermissionsLogPath $global:permissionsPath -DataIssuesLogPath $global:dataIssuesPath -TargetPath $uploadPath
                    
                    if ($uploadSuccess) {
                        Write-Host "✅ CSV partial results cloud upload completed successfully" -ForegroundColor Green
                    } else {
                        Write-Host "⚠️  CSV partial results cloud upload failed or was cancelled" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "📋 CSV partial results remain in Cloud Shell temporary storage: $outDir" -ForegroundColor Gray
                    Write-Host "⚠️  Remember to download files before Cloud Shell session expires" -ForegroundColor Yellow
                }
            }
        }
        
        return $true
        
    } catch {
        Write-Host "❌ Error processing CSV file: $_" -ForegroundColor Red
        Write-Host "   File: $CsvFilePath" -ForegroundColor Red
        return $false
    }
}

# --- Supporting Functions for HTML-from-CSV and Resume CSV Alignment ---

function Resolve-LatestAuditCsv {
    param(
        [string]$CsvFilePath,
        [string]$OutputDirectory
    )
    
    try {
        # If explicit path provided, validate and return it
        if ($CsvFilePath) {
            if (Test-Path $CsvFilePath) {
                return (Resolve-Path $CsvFilePath).Path
            } else {
                Write-Host "❌ Error: Specified CSV file not found: $CsvFilePath" -ForegroundColor Red
                return $null
            }
        }
        
        # Auto-detect latest CSV file in output directory
        if (-not $OutputDirectory) {
            $OutputDirectory = Get-DefaultOutputDirectory
        }
        
        if (-not (Test-Path $OutputDirectory)) {
            Write-Host "❌ Error: Output directory not found: $OutputDirectory" -ForegroundColor Red
            return $null
        }
        
        # Search for KeyVaultComprehensiveAudit*.csv files
        $csvFiles = Get-ChildItem -Path $OutputDirectory -Filter "KeyVaultComprehensiveAudit*.csv" -ErrorAction SilentlyContinue | 
                   Sort-Object LastWriteTime -Descending
        
        if (-not $csvFiles -or $csvFiles.Count -eq 0) {
            Write-Host "❌ Error: No KeyVaultComprehensiveAudit*.csv files found in: $OutputDirectory" -ForegroundColor Red
            Write-Host "   Hint: Run a full audit first or specify a CSV file with -CsvFilePath" -ForegroundColor Yellow
            return $null
        }
        
        $latestCsv = $csvFiles[0]
        Write-Host "📄 Auto-detected latest CSV file: $($latestCsv.Name)" -ForegroundColor Green
        Write-Host "   Modified: $($latestCsv.LastWriteTime)" -ForegroundColor Gray
        return $latestCsv.FullName
        
    } catch {
        Write-Host "❌ Error resolving CSV file: $_" -ForegroundColor Red
        return $null
    }
}

function Get-IdentityKeys {
    param(
        [object]$VaultObject
    )
    
    # Extract identity keys for vault matching (case-insensitive, trimmed)
    $keys = @()
    
    if ($VaultObject.ResourceId) { $keys += $VaultObject.ResourceId.ToString().Trim().ToLowerInvariant() }
    if ($VaultObject.Id) { $keys += $VaultObject.Id.ToString().Trim().ToLowerInvariant() }
    if ($VaultObject.VaultId) { $keys += $VaultObject.VaultId.ToString().Trim().ToLowerInvariant() }
    if ($VaultObject.Name) { $keys += $VaultObject.Name.ToString().Trim().ToLowerInvariant() }
    if ($VaultObject.KeyVaultName) { $keys += $VaultObject.KeyVaultName.ToString().Trim().ToLowerInvariant() }
    if ($VaultObject.VaultName) { $keys += $VaultObject.VaultName.ToString().Trim().ToLowerInvariant() }
    
    return $keys | Where-Object { $_ -and $_.Length -gt 0 } | Select-Object -Unique
}

function BuildIdentitySetFromCsv {
    param(
        [array]$CsvRows
    )
    
    $identitySet = New-Object System.Collections.Generic.HashSet[string]
    
    foreach ($row in $CsvRows) {
        $identityKeys = Get-IdentityKeys -VaultObject $row
        foreach ($key in $identityKeys) {
            [void]$identitySet.Add($key)
        }
    }
    
    return $identitySet
}

function Get-AppendOffset {
    param(
        [array]$DiscoveryItems,
        [System.Collections.Generic.HashSet[string]]$CsvIdentitySet,
        [System.Collections.Generic.HashSet[string]]$CheckpointProcessedSet = $null,
        [int]$UnmatchedLogCount = 10
    )
    
    $result = @{
        AppendStartIndex = 0
        OverlapCount = 0
        CsvMatches = 0
        CheckpointMatches = 0
        UnmatchedFromCsv = @()
        UnmatchedFromCheckpoint = @()
        FirstUnmatchedIndex = -1
    }
    
    if (-not $DiscoveryItems -or $DiscoveryItems.Count -eq 0) {
        return $result
    }
    
    # Build identity set from discovery items
    $discoveryIdentitySet = New-Object System.Collections.Generic.HashSet[string]
    for ($i = 0; $i -lt $DiscoveryItems.Count; $i++) {
        $item = $DiscoveryItems[$i]
        $identityKeys = Get-IdentityKeys -VaultObject $item
        
        $hasMatch = $false
        foreach ($key in $identityKeys) {
            [void]$discoveryIdentitySet.Add($key)
            
            # Check if this discovery item matches CSV
            if ($CsvIdentitySet.Contains($key)) {
                $result.CsvMatches++
                $hasMatch = $true
                break
            }
            
            # Check if this discovery item matches checkpoint (if provided)
            if ($CheckpointProcessedSet -and $CheckpointProcessedSet.Contains($key)) {
                $result.CheckpointMatches++
                $hasMatch = $true
                break
            }
        }
        
        # Track first unmatched item for append offset
        if (-not $hasMatch -and $result.FirstUnmatchedIndex -eq -1) {
            $result.FirstUnmatchedIndex = $i
        }
    }
    
    # Set append start index
    $result.AppendStartIndex = if ($result.FirstUnmatchedIndex -eq -1) { $DiscoveryItems.Count } else { $result.FirstUnmatchedIndex }
    
    # Calculate overlap
    $result.OverlapCount = $result.CsvMatches + $result.CheckpointMatches
    
    # Find unmatched entries for diagnostics (limited by UnmatchedLogCount)
    if ($UnmatchedLogCount -gt 0) {
        $csvOnlyKeys = $CsvIdentitySet | Where-Object { -not $discoveryIdentitySet.Contains($_) } | Select-Object -First $UnmatchedLogCount
        $result.UnmatchedFromCsv = @($csvOnlyKeys)
        
        if ($CheckpointProcessedSet) {
            $checkpointOnlyKeys = $CheckpointProcessedSet | Where-Object { -not $discoveryIdentitySet.Contains($_) } | Select-Object -First $UnmatchedLogCount
            $result.UnmatchedFromCheckpoint = @($checkpointOnlyKeys)
        }
    }
    
    return $result
}

# --- Critical Logging Functions (Must be defined early for error handling) ---

function Write-ErrorLog {
    param([string]$Category, [string]$Message, [string]$KeyVaultName = "", [string]$Context = "")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $contextInfo = if ($Context) { " | Context: $Context" } else { "" }
    $keyVaultInfo = if ($KeyVaultName) { " [$KeyVaultName]" } else { "" }
    $logMessage = "[$timestamp] [$Category]$keyVaultInfo $Message$contextInfo"
    if ($global:errPath -and (Test-Path (Split-Path $global:errPath -Parent) -ErrorAction SilentlyContinue)) {
        $logMessage | Out-File -FilePath $global:errPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    Write-Warning $logMessage
}

function Write-PermissionsLog {
    param([string]$Category, [string]$Message, [string]$KeyVaultName = "", [string]$RequiredRole = "")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $roleInfo = if ($RequiredRole) { " | Required: $RequiredRole" } else { "" }
    $keyVaultInfo = if ($KeyVaultName) { " [$KeyVaultName]" } else { "" }
    $logMessage = "[$timestamp] [$Category]$keyVaultInfo $Message$roleInfo"
    if ($global:permissionsPath -and (Test-Path (Split-Path $global:permissionsPath -Parent) -ErrorAction SilentlyContinue)) {
        $logMessage | Out-File -FilePath $global:permissionsPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Write-DataCollectionLog {
    param([string]$Category, [string]$Message, [string]$KeyVaultName = "", [string]$DataType = "", [string]$Impact = "")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $dataInfo = if ($DataType) { " | DataType: $DataType" } else { "" }
    $impactInfo = if ($Impact) { " | Impact: $Impact" } else { "" }
    $keyVaultInfo = if ($KeyVaultName) { " [$KeyVaultName]" } else { "" }
    $logMessage = "[$timestamp] [$Category]$keyVaultInfo $Message$dataInfo$impactInfo"
    if ($global:dataIssuesPath -and (Test-Path (Split-Path $global:dataIssuesPath -Parent) -ErrorAction SilentlyContinue)) {
        $logMessage | Out-File -FilePath $global:dataIssuesPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

# Legacy function for backward compatibility
function Write-DataIssuesLog {
    param([string]$Category, [string]$Message, [string]$KeyVaultName = "", [string]$Reason = "")
    Write-DataCollectionLog -Category $Category -Message $Message -KeyVaultName $KeyVaultName -Impact $Reason
}

# Upload logging function for OneDrive/SharePoint integration
function Write-UploadLog {
    param([string]$Category, [string]$Message, [string]$FileName = "", [string]$Context = "", [string]$ArtifactUrl = "")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $fileInfo = if ($FileName) { " [$FileName]" } else { "" }
    $contextInfo = if ($Context) { " | Context: $Context" } else { "" }
    $urlInfo = if ($ArtifactUrl) { " | URL: $ArtifactUrl" } else { "" }
    $logMessage = "[$timestamp] [Upload-$Category]$fileInfo $Message$contextInfo$urlInfo"
    if ($global:dataIssuesPath -and (Test-Path (Split-Path $global:dataIssuesPath -Parent) -ErrorAction SilentlyContinue)) {
        $logMessage | Out-File -FilePath $global:dataIssuesPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    Write-Host "☁️ Upload: $Message" -ForegroundColor Cyan
}

# Enhanced Microsoft Graph authentication error logging function
function Write-GraphAuthErrorLog {
    <#
    .SYNOPSIS
    Enhanced error logging specifically for Microsoft Graph authentication failures with comprehensive context
    #>
    param(
        [string]$AuthMethod,
        [string]$Message,
        [System.Exception]$Exception,
        [hashtable]$EnvironmentContext = @{},
        [hashtable]$AuthenticationContext = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    
    # Build comprehensive error context
    $contextInfo = @()
    
    # Add authentication method and basic message
    $contextInfo += "Authentication Method: $AuthMethod"
    $contextInfo += "Error: $Message"
    
    # Add exception details if provided
    if ($Exception) {
        $contextInfo += "Exception Type: $($Exception.GetType().Name)"
        $contextInfo += "Exception Message: $($Exception.Message)"
        if ($Exception.InnerException) {
            $contextInfo += "Inner Exception: $($Exception.InnerException.Message)"
        }
    }
    
    # Add environment context
    if ($EnvironmentContext.Count -gt 0) {
        $contextInfo += "=== Environment Context ==="
        foreach ($key in $EnvironmentContext.Keys) {
            $value = $EnvironmentContext[$key]
            if ($key -match "(SECRET|PASSWORD|TOKEN)" -and $value) {
                $value = "***REDACTED***"
            }
            $contextInfo += "$key`: $value"
        }
    }
    
    # Add authentication context
    if ($AuthenticationContext.Count -gt 0) {
        $contextInfo += "=== Authentication Context ==="
        foreach ($key in $AuthenticationContext.Keys) {
            $value = $AuthenticationContext[$key]
            if ($key -match "(SECRET|PASSWORD|TOKEN)" -and $value) {
                $value = "***REDACTED***"
            }
            $contextInfo += "$key : $value"
        }
    }
    
    # Log to error file with full context
    $fullContext = $contextInfo -join " | "
    $logMessage = "$timestamp GraphAuth-$AuthMethod $fullContext"
    
    if ($global:errPath -and (Test-Path (Split-Path $global:errPath -Parent) -ErrorAction SilentlyContinue)) {
        $logMessage | Out-File -FilePath $global:errPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    
    # Also log to console with readable format
    Write-Host "❌ Graph Authentication Error [$AuthMethod]" -ForegroundColor Red
    Write-Host "   Message: $Message" -ForegroundColor Red
    if ($Exception) {
        Write-Host "   Exception: $($Exception.Message)" -ForegroundColor Red
    }
}

# --- Initialize Script Cancellation State ---
# Check for cancellation recovery first, then set global variable appropriately
$shouldResumeFromCancellation = Test-CancellationRecovery

# Always clear scriptCancelled variable except when resuming directly after manual cancel
$global:scriptCancelled = $false
Write-CancellationDebugLog "Initialize" "Script cancellation state initialized" -Context "scriptCancelled=false"

# --- Parameter Validation ---
if ($PSBoundParameters.ContainsKey('Resume') -and $PSBoundParameters.ContainsKey('ProcessPartial')) {
    Write-Host "❌ Error: Cannot use both -Resume and -ProcessPartial parameters simultaneously." -ForegroundColor Red
    Write-Host "   Use -Resume to continue an audit or -ProcessPartial to generate reports from existing data." -ForegroundColor Yellow
    exit 1
}

if ($PSBoundParameters.ContainsKey('CsvFilePath') -and !$PSBoundParameters.ContainsKey('ProcessPartial')) {
    Write-Host "❌ Error: -CsvFilePath can only be used with -ProcessPartial parameter." -ForegroundColor Red
    Write-Host "   Use: .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial -CsvFilePath 'path\to\file.csv'" -ForegroundColor Yellow
    exit 1
}

# New parameter validation for ReportFromCsv mode
if ($PSBoundParameters.ContainsKey('ReportFromCsv') -and $PSBoundParameters.ContainsKey('Resume')) {
    Write-Host "❌ Error: Cannot use both -ReportFromCsv and -Resume parameters simultaneously." -ForegroundColor Red
    Write-Host "   Use -ReportFromCsv to generate HTML from CSV or -Resume to continue an audit." -ForegroundColor Yellow
    exit 1
}

if ($PSBoundParameters.ContainsKey('ReportFromCsv') -and $PSBoundParameters.ContainsKey('ProcessPartial')) {
    Write-Host "❌ Error: Cannot use both -ReportFromCsv and -ProcessPartial parameters simultaneously." -ForegroundColor Red
    Write-Host "   Use -ReportFromCsv to generate HTML from CSV or -ProcessPartial to process checkpoint data." -ForegroundColor Yellow
    exit 1
}

if ($PSBoundParameters.ContainsKey('CsvFilePath') -and !$PSBoundParameters.ContainsKey('ReportFromCsv') -and !$PSBoundParameters.ContainsKey('ProcessPartial')) {
    Write-Host "❌ Error: -CsvFilePath can only be used with -ReportFromCsv or -ProcessPartial parameters." -ForegroundColor Red
    Write-Host "   Use: .\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath 'path\to\file.csv'" -ForegroundColor Yellow
    Write-Host "   Or:  .\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial -CsvFilePath 'path\to\file.csv'" -ForegroundColor Yellow
    exit 1
}

if (!$PSBoundParameters.ContainsKey('ReportFromCsv') -and $PSBoundParameters.ContainsKey('MarkPartial')) {
    Write-Host "❌ Error: -MarkPartial can only be used with -ReportFromCsv parameter." -ForegroundColor Red
    Write-Host "   Use: .\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -MarkPartial:`$false" -ForegroundColor Yellow
    exit 1
}

# SingleVault parameter validation
if ($PSBoundParameters.ContainsKey('SingleVault') -and ($PSBoundParameters.ContainsKey('Resume') -or $PSBoundParameters.ContainsKey('ProcessPartial') -or $PSBoundParameters.ContainsKey('ReportFromCsv'))) {
    Write-Host "❌ Error: -SingleVault cannot be used with -Resume, -ProcessPartial, or -ReportFromCsv parameters." -ForegroundColor Red
    Write-Host "   Use -SingleVault for quick targeted diagnostics scan only." -ForegroundColor Yellow
    exit 1
}

if ($PSBoundParameters.ContainsKey('VaultName') -and !$PSBoundParameters.ContainsKey('SingleVault')) {
    Write-Host "❌ Error: -VaultName can only be used with -SingleVault parameter." -ForegroundColor Red
    Write-Host "   Use: .\Get-AKV_Roles-SecAuditCompliance.ps1 -SingleVault -VaultName 'your-vault-name'" -ForegroundColor Yellow
    exit 1
}

if ($PSBoundParameters.ContainsKey('SubscriptionName') -and !$PSBoundParameters.ContainsKey('SingleVault')) {
    Write-Host "❌ Error: -SubscriptionName can only be used with -SingleVault parameter." -ForegroundColor Red
    Write-Host "   Use: .\Get-AKV_Roles-SecAuditCompliance.ps1 -SingleVault -SubscriptionName 'your-subscription'" -ForegroundColor Yellow
    exit 1
}

# Set MarkPartial default when ReportFromCsv is used without explicit MarkPartial
if ($PSBoundParameters.ContainsKey('ReportFromCsv') -and -not $PSBoundParameters.ContainsKey('MarkPartial')) { 
    $MarkPartial = $true 
}

if ($PSBoundParameters.ContainsKey('ResumeCsvStrict') -and -not $PSBoundParameters.ContainsKey('Resume')) {
    Write-Host "❌ Error: -ResumeCsvStrict can only be used with -Resume parameter." -ForegroundColor Red
    Write-Host "   Use: .\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume -ResumeCsvStrict" -ForegroundColor Yellow
    exit 1
}

# Graceful cancel handling for CTRL+C
$cancelHandler = {
    Write-Host ""
    Write-Host "🛑 MANUAL CANCELLATION DETECTED (CTRL+C)" -ForegroundColor Yellow
    Write-Host "Saving progress and creating recovery marker..." -ForegroundColor Yellow
    
    Write-CancellationDebugLog "Triggered" "Manual cancellation handler invoked" -Trigger "User Interrupt (CTRL+C)" -Context "Event=PowerShell.Exiting"
    
    $global:scriptCancelled = $true
    Write-CancellationDebugLog "StateChange" "Script cancellation flag set to true" -Trigger "User Interrupt (CTRL+C)" -Context "Manual cancellation handler"
    
    # Create cancellation marker for recovery on next run
    Set-CancellationMarker
    
    # Save final checkpoint with current results
    try {
        if ($global:auditResults -and $global:auditResults.Count -gt 0) {
            Save-ProgressCheckpoint -VaultIndex $global:auditResults.Count -TotalVaults $global:totalVaultsToProcess -ProcessedResults $global:auditResults -IsFinalCheckpoint $true
            Write-Host "✅ Progress saved successfully." -ForegroundColor Green
            Write-CancellationDebugLog "Checkpoint" "Final checkpoint saved successfully" -Context "VaultCount=$($global:auditResults.Count)"
        } else {
            Write-CancellationDebugLog "Checkpoint" "No audit results to save in checkpoint" -Context "auditResults.Count=0"
        }
    } catch {
        Write-Warning "❌ Failed to save final checkpoint: $_"
        Write-CancellationDebugLog "Error" "Failed to save final checkpoint during cancellation" -Context "Error=$($_)"
    }
    
    Write-Host ""
    Write-Host "🔄 On next script run, you will be prompted to resume from this checkpoint." -ForegroundColor Cyan
    Write-Host "🏁 Audit cancelled by user. Exiting gracefully..." -ForegroundColor Yellow
    Write-CancellationDebugLog "Complete" "Manual cancellation process completed, exiting script" -Trigger "User Interrupt (CTRL+C)"
    exit 0
}

# Register CTRL+C handler specifically for user interrupts
Write-CancellationDebugLog "Setup" "Registering cancellation handlers for user interrupts only" -Context "PowerShell.Exiting event"
$null = Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action $cancelHandler

# Handle CTRL+C specifically with refined trap that only catches interrupts
trap [System.Management.Automation.PipelineStoppedException] {
    Write-CancellationDebugLog "TrapTriggered" "Pipeline stopped exception caught - likely user interrupt" -Trigger "PipelineStoppedException" -Context "Trap handler"
    & $cancelHandler
}

trap [System.OperationCanceledException] {
    Write-CancellationDebugLog "TrapTriggered" "Operation cancelled exception caught - likely user interrupt" -Trigger "OperationCanceledException" -Context "Trap handler"
    & $cancelHandler
}

# --- Minimum Required Permissions Documentation ---
$MinimumPermissions = @"
MINIMUM REQUIRED PERMISSIONS FOR RUNNING THIS SCRIPT:

Azure RBAC Permissions (at Subscription or Management Group level):
- Reader: Required to discover and read Key Vault configurations
- Key Vault Reader: Required to access Key Vault properties and settings
- Monitoring Reader: Required to access diagnostic settings and logs

Optional permissions for enhanced analysis:
- Security Reader: For security-related configurations and recommendations
- Key Vault Crypto Service Encryption User: For key usage analysis (if analyzing key operations)

Azure AD Permissions (for service principal and managed identity analysis):
- Directory Readers: To read Azure AD objects and service principals

ENHANCED AUTHENTICATION METHODS AND ENVIRONMENT DETECTION:

The script now includes robust environment detection and automatic authentication mode selection:

Azure Authentication (for Key Vault operations):
1. Interactive authentication: Connect-AzAccount (optimal for local desktop environments)
2. Service principal authentication: Connect-AzAccount -ServicePrincipal (optimal for automation)
3. Managed identity authentication: Connect-AzAccount -Identity (for Azure resources with MSI)

Microsoft Graph Authentication (for OneDrive upload):
1. Interactive browser: Optimal for Cloud Shell and local environments with browser access
2. App-only (client credentials): Optimal for automation and environments with service principal
3. Device code: Fallback when browser and app-only authentication are not available

Enhanced Environment Detection Logic:
- Azure Cloud Shell: $env:CLOUD_SHELL, $env:ACC_CLOUD, shell patterns, filesystem indicators
- Managed Identity: $env:MSI_SECRET, $env:IDENTITY_ENDPOINT, $env:AZURE_HTTP_USER_AGENT patterns
- Service Principal: $env:AZURE_CLIENT_ID, $env:AZURE_TENANT_ID, $env:AZURE_CLIENT_SECRET
- Az.Accounts context analysis for authentication type detection

Automatic Authentication Selection:
1. Complete service principal credentials detected → App-only authentication
2. Azure Cloud Shell environment detected → Interactive browser authentication
3. Managed Identity environment without credentials → Device code authentication (Graph)
4. Local desktop environment → Interactive authentication with device code fallback
5. Cannot determine environment → Interactive prompt with clear explanations

Device code authentication is now used only as a true fallback when other methods fail or
are explicitly requested by the user. The system provides comprehensive verbose logging
to explain each authentication decision and auto-detects tenant/client IDs from Az.Accounts context.

Known Issue with Managed Identity Authentication:
- Some managed identity configurations may experience "ExpiresOn token format" errors
- Error message: "ManagedIdentityCredential authentication failed: The following token provider result value is invalid: ExpiresOn"
- This script includes enhanced error handling for this issue and will continue operation
- If persistent, switch to interactive or service principal authentication
- Troubleshooting: https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-troubleshoot

MINIMUM PERMISSIONS FOR KEY VAULT ADMINISTRATION:

Key Vault Owner/Administrator should have:
- Key Vault Administrator: Full administrative access to Key Vault
- Key Vault Certificates Officer: Manage certificates
- Key Vault Secrets Officer: Manage secrets
- Key Vault Keys Officer: Manage keys

Best Practice - Use RBAC instead of Access Policies:
- Assign specific Key Vault roles rather than broad access policies
- Use managed identities for applications instead of service principals
- Enable audit logging and monitoring
- Implement private endpoints for network security
- Use Azure Policy for governance and compliance

SECURITY RECOMMENDATIONS:
- Enable soft delete and purge protection
- Use Event Hub or Log Analytics for centralized logging
- Implement network restrictions (private endpoints or network ACLs)
- Regular access reviews and principle of least privilege
- Use Azure Sentinel for advanced threat detection
"@

Write-Host $MinimumPermissions -ForegroundColor Yellow
Write-Host ""

# Skip interactive prompts for ReportFromCsv mode (offline mode)
if (-not $PSBoundParameters.ContainsKey('ReportFromCsv')) {
    # Simple prompt without timeout (timeout mechanism was causing hangs in some environments)
    Write-Host "Press Enter to continue with the audit (Ctrl+C to exit): " -NoNewline -ForegroundColor Yellow
    Read-Host  # Simple read without timeout
    Write-Host ""
}

# --- User Prompt for Mode ---
Write-Host "🔐 Azure Key Vault Comprehensive Security & Compliance Audit" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# Initialize scan mode control variables
$mode = "Full"  # Default mode
$skipDiscovery = $false

# Determine available scan options based on parameters
if (-not $PSBoundParameters.ContainsKey('TestMode') -and -not $PSBoundParameters.ContainsKey('Resume') -and -not $PSBoundParameters.ContainsKey('ProcessPartial') -and -not $PSBoundParameters.ContainsKey('ReportFromCsv') -and -not $PSBoundParameters.ContainsKey('SingleVault')) {
    Write-Host "Select scan mode:" -ForegroundColor Yellow
    Write-Host "1. Test mode: scan a limited number of Key Vaults for validation" -ForegroundColor White
    Write-Host "2. Full scan: scan all subscriptions and all Key Vaults" -ForegroundColor White
    Write-Host "   ⚠️ WARNING: Option 2 performs comprehensive organizational audit - use SingleVault mode for individual vault analysis" -ForegroundColor Red
    Write-Host "3. Resume mode: resume from checkpoint, master file, or restart" -ForegroundColor White
    Write-Host ""

    do {
        $choice = Read-Host "Enter 1 for Test mode, 2 for Full scan, or 3 for Resume mode"
        if ($choice -eq "1") {
            $TestMode = $true
            $mode = "Test"
            $userLimit = Read-Host "Enter how many Key Vaults to test (integer, e.g. 3)"
            if ([int]::TryParse($userLimit, [ref]$null)) { 
                $Limit = [int]$userLimit 
            }
            Write-Host "🧪 TEST MODE: Will scan up to $Limit Key Vault(s)" -ForegroundColor Red
            break
        } elseif ($choice -eq "2") {
            $TestMode = $false
            $mode = "Full"
            $Limit = [int]::MaxValue
            Write-Host "✅ Full scan enabled. Will scan all Key Vaults in all subscriptions." -ForegroundColor Green
            break
        } elseif ($choice -eq "3") {
            $Resume = $true
            $mode = "Resume"
            Write-Host "🔄 Resume mode selected. You will choose resume options next..." -ForegroundColor Cyan
            break
        } else {
            Write-Host "❌ Invalid input '$choice'. Please enter 1 for Test mode, 2 for Full scan, or 3 for Resume mode." -ForegroundColor Red
        }
    } while ($true)
} else {
    # Mode was set by parameters, set the mode variable accordingly
    if ($TestMode) {
        $mode = "Test"
    } elseif ($Resume) {
        $mode = "Resume"
    } elseif ($ProcessPartial) {
        $mode = "ProcessPartial"
    } elseif ($SingleVault) {
        $mode = "SingleVault"
        # If subscription name/ID is provided with SingleVault, skip scan mode selection and start analysis immediately
        if ($SubscriptionName) {
            Write-Host "🎯 SINGLE VAULT MODE: Subscription specified, starting analysis immediately..." -ForegroundColor Cyan
            Write-Host "   Target Subscription: $SubscriptionName" -ForegroundColor Green
            if ($VaultName) {
                Write-Host "   Target Vault: $VaultName" -ForegroundColor Green
            }
        }
    } else {
        $mode = "Full"
    }
}

# Handle Resume mode choice when Resume is enabled (either by parameter or user selection)
if ($PSBoundParameters.ContainsKey('Resume') -and $mode -eq "Resume") {
    Write-Host ""
    Write-Host "🔄 RESUME MODE - Select resume option:" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Gray
    Write-Host ""
    Write-Host "1. Resume from latest checkpoint (partial audit progress)" -ForegroundColor Green
    Write-Host "2. Resume from master file (skip subscription and access discovery)" -ForegroundColor Cyan  
    Write-Host "3. Full scan (start over, ignoring resume data)" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $resumeChoice = Read-Host "Choose resume option (1-3)"
        if ($resumeChoice -eq "1") {
            Write-Host "✅ Will resume from latest checkpoint if available" -ForegroundColor Green
            $mode = "ResumeCheckpoint"
            break
        } elseif ($resumeChoice -eq "2") {
            Write-Host "✅ Will resume from master file, skipping subscription discovery" -ForegroundColor Cyan
            $mode = "ResumeMaster"
            $skipDiscovery = $true
            break
        } elseif ($resumeChoice -eq "3") {
            Write-Host "✅ Will perform full scan, ignoring any resume data" -ForegroundColor Yellow
            $mode = "ResumeFullScan"
            $Resume = $false  # Disable resume to force full scan
            $TestMode = $false
            $Limit = [int]::MaxValue
            break
        } else {
            Write-Host "❌ Invalid input '$resumeChoice'. Please enter 1, 2, or 3." -ForegroundColor Red
        }
    } while ($true)
}

# --- Prerequisites Check (Fixed Az.Profile issue) ---
Write-Host "📋 Checking prerequisites..." -ForegroundColor Yellow
$modules = @('Az.Accounts', 'Az.KeyVault', 'Az.Resources', 'Az.Monitor', 'Az.Security', 'MSAL.PS')
$missingModules = @()

# Check each module with verbose output
foreach ($module in $modules) {
    $installedModule = Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1
    if ($installedModule) {
        Write-Host "✅ Checking $module module... Found v$($installedModule.Version)" -ForegroundColor Green
    } else {
        Write-Host "❌ Checking $module module... Not found" -ForegroundColor Red
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "⚠️  Installing missing modules: $($missingModules -join ', ')" -ForegroundColor Yellow
    foreach ($module in $missingModules) {
        try {
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
            Write-Host "✅ Installed $module" -ForegroundColor Green
        } catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            Write-Host "❌ Failed to install $module : $errorMessage" -ForegroundColor Red
        }
    }
}

# Import modules
foreach ($module in $modules) {
    try {
        Import-Module $module -Force -ErrorAction SilentlyContinue
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-Warning "Could not import $module : $errorMessage"
    }
}

# --- Resume Logging Function ---
# Enhanced resume logging function
function Write-ResumeLog {
    param([string]$Action, [string]$Message, [string]$Detail = "")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $detailInfo = if ($Detail) { " | Detail: $Detail" } else { "" }
    $logMessage = "[$timestamp] [Resume-$Action] $Message$detailInfo"
    $logMessage | Out-File -FilePath $global:dataIssuesPath -Append -Encoding UTF8
    Write-Host "🔄 Resume: $Message" -ForegroundColor Cyan
}

# --- Enhanced Identity-Based Skip Filtering Functions ---
# Helper: normalize a vault object to a stable identity string
function Resolve-VaultKey {
    param([Parameter(Mandatory)][object]$Vault)
    
    $id = Get-SafeProperty -Object $Vault -PropertyName 'Id'
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = Get-SafeProperty -Object $Vault -PropertyName 'ResourceId'
    }
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = Get-SafeProperty -Object $Vault -PropertyName 'VaultId'
    }
    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = Get-SafeProperty -Object $Vault -PropertyName 'Name'
    }
    
    if ([string]::IsNullOrWhiteSpace($id)) { 
        return $null 
    }
    return $id.Trim()
}

function Get-ProcessedVaultSet {
    param([Parameter(Mandatory=$true)][object]$Checkpoint)
    
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    
    # Support common property names for processed vaults
    $processedList = Get-SafeProperty -Object $Checkpoint -PropertyName 'ProcessedVaults'
    if (-not $processedList) {
        $processedList = Get-SafeProperty -Object $Checkpoint -PropertyName 'Processed'
    }
    
    if ($processedList) {
        foreach ($v in $processedList) { 
            # Use multi-key identity generation for better matching
            $keys = Get-IdentityKeys -Vault $v
            foreach ($key in $keys) {
                if (-not [string]::IsNullOrWhiteSpace($key)) {
                    $null = $set.Add($key.Trim())
                }
            }
        }
    }
    
    # Ensure we return the HashSet explicitly
    Write-Output $set -NoEnumerate
}

function Get-VaultsToProcess {
    param(
        [Parameter(Mandatory=$true)][object[]]$AllVaults, 
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$ProcessedSet
    )
    
    # Normalize all vaults with their multi-keys
    $normalized = @()
    foreach ($v in $AllVaults) { 
        $keys = Get-IdentityKeys -Vault $v.KeyVault
        if ($keys -and $keys.Count -gt 0) { 
            $normalized += [PSCustomObject]@{ 
                __Keys = $keys
                Vault = $v 
            } 
        } 
    }
    
    # Count how many vaults have at least one key that matches the processed set
    $matchedProcessed = 0
    foreach ($n in $normalized) { 
        $hasMatch = $false
        foreach ($key in $n.__Keys) {
            if ($ProcessedSet.Contains($key)) { 
                $hasMatch = $true
                break
            }
        }
        if ($hasMatch) {
            $matchedProcessed++
        }
    }
    
    # Filter to only unprocessed vaults (vaults with no keys in processed set)
    $toProcess = @()
    foreach ($n in $normalized) { 
        $hasMatch = $false
        foreach ($key in $n.__Keys) {
            if ($ProcessedSet.Contains($key)) { 
                $hasMatch = $true
                break
            }
        }
        if (-not $hasMatch) {
            $toProcess += $n.Vault
        }
    }
    
    [PSCustomObject]@{ 
        ToProcess = $toProcess
        TotalDiscovered = $normalized.Count
        BaselineMatched = $matchedProcessed 
    }
}

# --- Enhanced Resume Helper Functions ---

function Get-IdentityKeys {
    <#
    .SYNOPSIS
        Generate multiple identity keys for a vault object to improve cross-source matching.
    .DESCRIPTION
        Returns an array of normalized identity strings from various vault properties.
        Supports canonical keys (ResourceId, Id, VaultId) and alternate keys (Name, VaultName).
    #>
    param([Parameter(Mandatory)][object]$Vault)
    
    $keys = @()
    
    # Canonical identity fields (preferred)
    $canonicalFields = @('ResourceId', 'Id', 'VaultId', 'VaultResourceId')
    foreach ($field in $canonicalFields) {
        if ($Vault.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace($Vault.$field)) {
            $keys += $Vault.$field.ToString().Trim()
        }
    }
    
    # Alternate identity fields (name-based)
    $nameFields = @('Name', 'VaultName', 'KeyVaultName')
    foreach ($field in $nameFields) {
        if ($Vault.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace($Vault.$field)) {
            $keys += $Vault.$field.ToString().Trim()
        }
    }
    
    return $keys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
}

function Find-LatestCsvFile {
    <#
    .SYNOPSIS
        Find the latest CSV file matching the script's naming pattern.
    .DESCRIPTION
        Searches standard output directories for CSV files that match the audit script's naming pattern.
    #>
    param([string]$OutputDirectory)
    
    try {
        # Search for CSV files matching the audit pattern
        $csvPattern = "KeyVaultComprehensiveAudit_*.csv"
        $csvFiles = Get-ChildItem -Path $OutputDirectory -Filter $csvPattern -ErrorAction SilentlyContinue
        
        if ($csvFiles) {
            $latestCsv = $csvFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            return $latestCsv.FullName
        }
    } catch {
        Write-Verbose "Error finding CSV files: $_" -Verbose
    }
    
    return $null
}

function Find-CsvByExecutionId {
    <#
    .SYNOPSIS
        Find CSV file that matches the checkpoint's executionId, with fallback to latest CSV.
    .DESCRIPTION
        Searches for CSV files that match the checkpoint's executionId in the filename.
        If no match is found, falls back to the latest CSV file.
        Used for resume in-place CSV append functionality.
    #>
    param(
        [string]$OutputDirectory,
        [string]$ExecutionId
    )
    
    try {
        # Search for CSV files matching the audit pattern
        $csvPattern = "KeyVaultComprehensiveAudit_*.csv"
        $csvFiles = Get-ChildItem -Path $OutputDirectory -Filter $csvPattern -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Name -notmatch "PARTIAL" }  # Exclude partial result files
        
        if ($csvFiles) {
            # First try to find CSV with matching executionId
            if ($ExecutionId) {
                $matchingCsv = $csvFiles | Where-Object { $_.Name -match [regex]::Escape($ExecutionId) } | 
                              Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                if ($matchingCsv) {
                    Write-Host "✅ Found CSV matching executionId: $($matchingCsv.Name)" -ForegroundColor Green
                    return $matchingCsv.FullName
                }
                
                Write-Host "⚠️  No CSV found matching executionId '$ExecutionId', using latest CSV" -ForegroundColor Yellow
            }
            
            # Fallback to latest CSV
            $latestCsv = $csvFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-Host "📄 Using latest CSV file: $($latestCsv.Name)" -ForegroundColor Gray
            return $latestCsv.FullName
        }
    } catch {
        Write-Warning "Error finding CSV files: $_"
    }
    
    return $null
}

function Get-ProcessedSetFromCsv {
    <#
    .SYNOPSIS
        Build a processed identity set from an existing CSV file.
    .DESCRIPTION
        Reads CSV file and extracts identity keys from multiple columns.
        Supports case-insensitive matching for common identity field names.
    #>
    param([Parameter(Mandatory)][string]$CsvFilePath)
    
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $processedCount = 0
    
    try {
        if (-not (Test-Path $CsvFilePath)) {
            Write-Verbose "CSV file not found: $CsvFilePath" -Verbose
            return [PSCustomObject]@{
                ProcessedSet = $set
                ProcessedCount = 0
            }
        }
        
        # Import CSV and process each row
        $csvData = Import-Csv -Path $CsvFilePath -ErrorAction Stop
        
        # Define identity field names (case-insensitive)
        $identityFields = @('ResourceId', 'Id', 'VaultId', 'VaultResourceId', 'VaultName', 'Name', 'KeyVaultName')
        
        foreach ($row in $csvData) {
            $rowKeys = @()
            
            # Extract all available identity keys from this row
            foreach ($field in $identityFields) {
                if ($row.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace($row.$field)) {
                    $rowKeys += $row.$field.ToString().Trim()
                }
            }
            
            # Add unique keys to the set
            foreach ($key in ($rowKeys | Sort-Object -Unique)) {
                if (-not [string]::IsNullOrWhiteSpace($key)) {
                    $null = $set.Add($key)
                }
            }
            
            if ($rowKeys.Count -gt 0) {
                $processedCount++
            }
        }
        
        Write-Verbose "CSV processed: $processedCount rows, $($set.Count) unique identity keys" -Verbose
        
    } catch {
        Write-Warning "Error processing CSV file '$CsvFilePath': $_"
    }
    
    return [PSCustomObject]@{
        ProcessedSet = $set
        ProcessedCount = $processedCount
    }
}

function Get-CombinedProcessedSet {
    <#
    .SYNOPSIS
        Combine processed sets from multiple sources based on priority setting.
    .DESCRIPTION
        Merges checkpoint and CSV processed sets according to ResumeSourcePriority parameter.
    #>
    param(
        [System.Collections.Generic.HashSet[string]]$CheckpointSet,
        [System.Collections.Generic.HashSet[string]]$CsvSet,
        [int]$CheckpointCount = 0,
        [int]$CsvCount = 0,
        [string]$Priority = 'Union'
    )
    
    $combinedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sourceInfo = @{
        CheckpointUsed = $false
        CsvUsed = $false
        CombinedCount = 0
        UniqueCount = 0
    }
    
    switch ($Priority) {
        'Checkpoint' {
            if ($CheckpointSet) {
                foreach ($key in $CheckpointSet) {
                    $null = $combinedSet.Add($key)
                }
                $sourceInfo.CheckpointUsed = $true
            }
        }
        'CSV' {
            if ($CsvSet) {
                foreach ($key in $CsvSet) {
                    $null = $combinedSet.Add($key)
                }
                $sourceInfo.CsvUsed = $true
            }
        }
        'Union' {
            if ($CheckpointSet) {
                foreach ($key in $CheckpointSet) {
                    $null = $combinedSet.Add($key)
                }
                $sourceInfo.CheckpointUsed = $true
            }
            if ($CsvSet) {
                foreach ($key in $CsvSet) {
                    $null = $combinedSet.Add($key)
                }
                $sourceInfo.CsvUsed = $true
            }
        }
    }
    
    $sourceInfo.CombinedCount = $CheckpointCount + $CsvCount
    $sourceInfo.UniqueCount = $combinedSet.Count
    
    return [PSCustomObject]@{
        ProcessedSet = $combinedSet
        SourceInfo = $sourceInfo
    }
}

# --- Checkpoint Management Functions ---
function Get-CheckpointData {
    param([string]$CheckpointPath)
    
    $retryCount = 0
    $maxRetries = 3
    
    while ($retryCount -lt $maxRetries) {
        try {
            if (Test-Path $CheckpointPath) {
                # Verify file is not empty and readable
                $fileInfo = Get-Item $CheckpointPath
                if ($fileInfo.Length -eq 0) {
                    throw "Checkpoint file is empty"
                }
                
                $checkpointContent = Get-Content -Path $CheckpointPath -Raw -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($checkpointContent)) {
                    throw "Checkpoint file content is empty"
                }
                
                $checkpointObject = $checkpointContent | ConvertFrom-Json -ErrorAction Stop
                if (-not $checkpointObject) {
                    throw "Failed to parse checkpoint JSON"
                }
                
                Write-Host "✅ Successfully loaded checkpoint from: $([System.IO.Path]::GetFileName($CheckpointPath))" -ForegroundColor Green
                return $checkpointObject
            } else {
                Write-Warning "Checkpoint file not found: $CheckpointPath"
                return $null
            }
        } catch {
            $retryCount++
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            
            if ($retryCount -lt $maxRetries) {
                Write-Warning "Checkpoint read attempt $retryCount failed, retrying... Error: $errorMessage"
                Start-Sleep -Seconds 1
            } else {
                Write-Host "❌ Failed to read checkpoint after $maxRetries attempts: $errorMessage" -ForegroundColor Red
                Write-ErrorLog "Checkpoint" "Failed to read checkpoint file: $errorMessage" -Context "Path:$CheckpointPath|Attempts:$maxRetries"
                return $null
            }
        }
    }
    
    return $null
}

function Test-CheckpointValidity {
    param(
        [object]$CheckpointData,
        [switch]$AllowOld
    )
    
    if (-not $CheckpointData) { return $false }
    
    $requiredProperties = @('Timestamp', 'VaultIndex', 'TotalVaults', 'ProcessedVaults', 'ExecutionId')
    foreach ($prop in $requiredProperties) {
        if (-not $CheckpointData.PSObject.Properties.Name -contains $prop) {
            Write-Warning "Checkpoint missing required property: $prop"
            return $false
        }
    }
    
    # Check if checkpoint is not too old (more than 7 days) unless AllowOld is specified
    if (-not $AllowOld) {
        try {
            $checkpointDate = [DateTime]::ParseExact($CheckpointData.Timestamp, 'yyyy-MM-dd HH:mm:ss UTC', $null)
            $daysSinceCheckpoint = (Get-Date) - $checkpointDate
            if ($daysSinceCheckpoint.TotalDays -gt 7) {
                Write-Warning "Checkpoint is older than 7 days. Consider starting fresh."
                return $false
            }
        } catch {
            Write-Warning "Invalid checkpoint timestamp format"
            return $false
        }
    }
    
    return $true
}

function Get-AllCheckpoints {
    param(
        [string]$OutputDirectory,
        [switch]$IncludeCorrupt,
        [int]$MaxResults = 0  # 0 means no limit, positive number limits results to most recent N checkpoints
    )
    
    Write-CancellationDebugLog "CheckpointEnumeration" "Starting checkpoint enumeration" -Context "OutputDirectory=$OutputDirectory|IncludeCorrupt=$IncludeCorrupt|MaxResults=$MaxResults"
    
    try {
        $checkpointFiles = Get-ChildItem -Path $OutputDirectory -Filter "akv_audit_checkpoint_*.json" -ErrorAction SilentlyContinue
        Write-CancellationDebugLog "CheckpointEnumeration" "Found checkpoint files in directory" -Context "Count=$($checkpointFiles.Count)|Directory=$OutputDirectory"
        
        if (-not $checkpointFiles) {
            Write-CancellationDebugLog "CheckpointEnumeration" "No checkpoint files found" -Context "Directory=$OutputDirectory"
            return @()
        }
        
        $validCheckpoints = @()
        foreach ($file in $checkpointFiles) {
            Write-CancellationDebugLog "CheckpointEnumeration" "Processing checkpoint file" -Context "FileName=$($file.Name)|Size=$($file.Length)|LastModified=$($file.LastWriteTime)"
            
            $checkpointData = Get-CheckpointData -CheckpointPath $file.FullName
            if ($checkpointData) {
                if (Test-CheckpointValidity -CheckpointData $checkpointData -AllowOld) {
                    $validCheckpoints += @{
                        FilePath = $file.FullName
                        FileName = $file.Name
                        Data = $checkpointData
                        LastModified = $file.LastWriteTime
                        Size = $file.Length
                    }
                    Write-CancellationDebugLog "CheckpointEnumeration" "Added valid checkpoint" -Context "FileName=$($file.Name)|ExecutionId=$($checkpointData.ExecutionId)|VaultIndex=$($checkpointData.VaultIndex)"
                } elseif ($IncludeCorrupt) {
                    $validCheckpoints += @{
                        FilePath = $file.FullName
                        FileName = $file.Name
                        Data = $checkpointData
                        LastModified = $file.LastWriteTime
                        Size = $file.Length
                        IsCorrupt = $true
                    }
                    Write-CancellationDebugLog "CheckpointEnumeration" "Added invalid checkpoint (corrupt)" -Context "FileName=$($file.Name)|Reason=FailedValidation"
                } else {
                    Write-CancellationDebugLog "CheckpointEnumeration" "Skipped invalid checkpoint" -Context "FileName=$($file.Name)|Reason=FailedValidation|IncludeCorrupt=false"
                }
            } elseif ($IncludeCorrupt) {
                $validCheckpoints += @{
                    FilePath = $file.FullName
                    FileName = $file.Name
                    Data = $null
                    LastModified = $file.LastWriteTime
                    Size = $file.Length
                    IsCorrupt = $true
                }
                Write-CancellationDebugLog "CheckpointEnumeration" "Added unreadable checkpoint (corrupt)" -Context "FileName=$($file.Name)|Reason=FailedToLoad"
            } else {
                Write-CancellationDebugLog "CheckpointEnumeration" "Skipped unreadable checkpoint" -Context "FileName=$($file.Name)|Reason=FailedToLoad|IncludeCorrupt=false"
            }
        }
        
        # Sort by last modified time (newest first)
        $sortedCheckpoints = $validCheckpoints | Sort-Object LastModified -Descending
        Write-CancellationDebugLog "CheckpointEnumeration" "Sorted checkpoints by last modified time" -Context "TotalValid=$($sortedCheckpoints.Count)|SortOrder=Descending"
        
        # Apply limit if specified
        if ($MaxResults -gt 0 -and $sortedCheckpoints.Count -gt $MaxResults) {
            $limitedCheckpoints = $sortedCheckpoints | Select-Object -First $MaxResults
            Write-CancellationDebugLog "CheckpointEnumeration" "Applied MaxResults limit" -Context "OriginalCount=$($sortedCheckpoints.Count)|LimitedCount=$($limitedCheckpoints.Count)|MaxResults=$MaxResults"
            return $limitedCheckpoints
        }
        
        Write-CancellationDebugLog "CheckpointEnumeration" "Checkpoint enumeration completed" -Context "FinalCount=$($sortedCheckpoints.Count)|NoLimitApplied=true"
        return $sortedCheckpoints
    } catch {
        Write-Warning "Error finding checkpoint files: $_"
        Write-CancellationDebugLog "CheckpointEnumeration" "Error during checkpoint enumeration" -Context "Error=$($_)|Directory=$OutputDirectory"
        return @()
    }
}

function Show-CheckpointSelection {
    <#
    .SYNOPSIS
        Displays available checkpoints and prompts user for selection.
    
    .DESCRIPTION
        Robust helper function for checkpoint selection that lists available checkpoint files 
        with metadata (name, last modified date, progress) and prompts for user selection by number.
        Handles cancellation (Enter for none or 'q' to quit) and invalid input gracefully.
        
    .PARAMETER Checkpoints
        Array of checkpoint objects with FilePath, FileName, Data, LastModified properties.
        
    .PARAMETER Mode
        Selection mode: "Resume" or "ProcessPartial" - affects display text and behavior.
        
    .PARAMETER IsManualCancellationRecovery
        If true, limits display to last 3 checkpoints for manual cancellation recovery scenarios.
        
    .OUTPUTS
        Returns selected checkpoint object or $null if cancelled/invalid.
    #>
    param(
        [array]$Checkpoints,
        [string]$Mode = "Resume",  # "Resume" or "ProcessPartial"
        [bool]$IsManualCancellationRecovery = $false  # New parameter to limit to last 3 for manual cancellation recovery
    )
    
    if (-not $Checkpoints -or $Checkpoints.Count -eq 0) {
        Write-Host "❌ No valid checkpoints found." -ForegroundColor Red
        Write-CancellationDebugLog "CheckpointPicker" "No valid checkpoints found for selection" -Context "Mode=$Mode|IsManualRecovery=$IsManualCancellationRecovery"
        return $null
    }
    
    Write-CancellationDebugLog "CheckpointPicker" "Starting checkpoint selection process" -Context "Mode=$Mode|TotalCheckpoints=$($Checkpoints.Count)|IsManualRecovery=$IsManualCancellationRecovery"
    
    # Limit to last 3 checkpoints if this is manual cancellation recovery
    $checkpointsToShow = $Checkpoints
    if ($IsManualCancellationRecovery -and $Checkpoints.Count -gt 3) {
        $checkpointsToShow = $Checkpoints | Select-Object -First 3
        Write-Host "🔍 Showing last 3 checkpoints for manual cancellation recovery..." -ForegroundColor Yellow
        Write-CancellationDebugLog "CheckpointPicker" "Limited to last 3 checkpoints for manual cancellation recovery" -Context "OriginalCount=$($Checkpoints.Count)|ShowingCount=$($checkpointsToShow.Count)"
    } else {
        Write-CancellationDebugLog "CheckpointPicker" "Showing all available checkpoints" -Context "Count=$($Checkpoints.Count)"
    }
    
    $modeText = if ($Mode -eq "Resume") { "resume from" } else { "process partial results from" }
    Write-Host ""
    Write-Host "📋 Available checkpoints to $modeText" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Gray
    
    for ($i = 0; $i -lt $checkpointsToShow.Count; $i++) {
        $checkpoint = $checkpointsToShow[$i]
        $data = $checkpoint.Data
        $number = $i + 1
        
        Write-CancellationDebugLog "CheckpointPicker" "Displaying checkpoint option" -Context "Index=$i|Number=$number|FileName=$($checkpoint.FileName)"
        
        # Format timestamp
        $timestamp = if ($data.Timestamp) { $data.Timestamp } else { "Unknown" }
        
        # Calculate progress percentage
        $progressPercent = if ($data.TotalVaults -gt 0) { 
            [math]::Round(($data.VaultIndex / $data.TotalVaults) * 100, 1) 
        } else { 0 }
        
        # Get execution ID for grouping
        $execId = if ($data.ExecutionId) { $data.ExecutionId } else { "Unknown" }
        
        # Determine checkpoint type
        $checkpointType = if ($data.IsFinalCheckpoint) { "Final" } else { "Progress" }
        
        Write-CancellationDebugLog "CheckpointPicker" "Checkpoint details prepared" -Context "Timestamp=$timestamp|Progress=$progressPercent%|ExecutionId=$execId|Type=$checkpointType|IsCorrupt=$($checkpoint.IsCorrupt)"
        
        # Show checkpoint info
        Write-Host "  [$number] " -NoNewline -ForegroundColor White
        Write-Host "$timestamp" -NoNewline -ForegroundColor Green
        Write-Host " | " -NoNewline -ForegroundColor Gray
        Write-Host "Progress: $($data.VaultIndex)/$($data.TotalVaults) ($progressPercent%)" -NoNewline -ForegroundColor Yellow
        Write-Host " | " -NoNewline -ForegroundColor Gray
        Write-Host "Type: $checkpointType" -NoNewline -ForegroundColor Cyan
        
        if ($checkpoint.IsCorrupt) {
            Write-Host " | " -NoNewline -ForegroundColor Gray
            Write-Host "⚠️ CORRUPT" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host "      ExecutionID: $execId" -ForegroundColor Gray
        Write-Host "      File: $($checkpoint.FileName)" -ForegroundColor Gray
        
        if ($data.ProcessedVaults -and $data.ProcessedVaults.Count -gt 0) {
            $sampleVaults = $data.ProcessedVaults | Select-Object -First 3 | ForEach-Object { $_.VaultName }
            $vaultList = $sampleVaults -join ", "
            if ($data.ProcessedVaults.Count -gt 3) {
                $vaultList += " (and $($data.ProcessedVaults.Count - 3) more)"
            }
            Write-Host "      Vaults: $vaultList" -ForegroundColor Gray
            Write-CancellationDebugLog "CheckpointPicker" "Sample vaults listed" -Context "SampleCount=$($sampleVaults.Count)|TotalVaults=$($data.ProcessedVaults.Count)"
        } else {
            Write-CancellationDebugLog "CheckpointPicker" "No processed vaults found in checkpoint" -Context "FileName=$($checkpoint.FileName)"
        }
        
        Write-Host ""
        
        Write-CancellationDebugLog "CheckpointPicker" "Displayed checkpoint option" -Context "Number=$number|File=$($checkpoint.FileName)|Type=$checkpointType|Progress=$progressPercent%|ExecutionId=$execId"
    }
    
    # Get user selection with enhanced cancellation handling
    Write-Host "Select a checkpoint (1-$($checkpointsToShow.Count)), 'q' to quit, or press Enter to cancel: " -NoNewline -ForegroundColor White
    $selection = Read-Host
    
    Write-CancellationDebugLog "CheckpointPicker" "User selection received" -Context "Selection=$selection|AvailableOptions=1-$($checkpointsToShow.Count)"
    
    # Handle cancellation - both 'q' and empty input (Enter)
    if ($selection -eq 'q' -or $selection -eq 'Q' -or [string]::IsNullOrWhiteSpace($selection)) {
        $cancelReason = if ([string]::IsNullOrWhiteSpace($selection)) { "empty input (Enter)" } else { "quit command" }
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        Write-CancellationDebugLog "CheckpointPicker" "User cancelled checkpoint selection" -Context "Selection=$cancelReason"
        return $null
    }
    
    $selectedIndex = $null
    if ([int]::TryParse($selection, [ref]$selectedIndex)) {
        if ($selectedIndex -ge 1 -and $selectedIndex -le $checkpointsToShow.Count) {
            $selectedCheckpoint = $checkpointsToShow[$selectedIndex - 1]
            
            # Warn about corrupt checkpoints
            if ($selectedCheckpoint.IsCorrupt) {
                Write-Host "⚠️ Warning: Selected checkpoint may be corrupt or invalid." -ForegroundColor Yellow
                Write-Host "Do you want to continue? (y/N): " -NoNewline -ForegroundColor Yellow
                $confirm = Read-Host
                Write-CancellationDebugLog "CheckpointPicker" "Corrupt checkpoint confirmation" -Context "File=$($selectedCheckpoint.FileName)|UserResponse=$confirm"
                if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                    Write-Host "Operation cancelled." -ForegroundColor Yellow
                    Write-CancellationDebugLog "CheckpointPicker" "User declined to use corrupt checkpoint" -Context "File=$($selectedCheckpoint.FileName)"
                    return $null
                }
            }
            
            Write-Host "✅ Selected checkpoint: $($selectedCheckpoint.FileName)" -ForegroundColor Green
            Write-CancellationDebugLog "CheckpointPicker" "Checkpoint successfully selected" -Context "File=$($selectedCheckpoint.FileName)|Index=$selectedIndex|IsCorrupt=$($selectedCheckpoint.IsCorrupt)"
            return $selectedCheckpoint
        }
    }
    
    Write-Host "❌ Invalid selection. Please enter a number between 1 and $($checkpointsToShow.Count)." -ForegroundColor Red
    Write-CancellationDebugLog "CheckpointPicker" "Invalid selection made by user" -Context "Selection=$selection|ValidRange=1-$($checkpointsToShow.Count)"
    return $null
}

# --- Working Directory Detection Function ---
function Get-WorkingDirectory {
    param(
        [string]$OverrideDirectory,
        [string]$AuthenticatedUser
    )
    
    # If override directory is provided, use it
    if (-not [string]::IsNullOrWhiteSpace($OverrideDirectory)) {
        Write-Host "📁 Using override output directory: $OverrideDirectory" -ForegroundColor Cyan
        return $OverrideDirectory
    }
    
    # Detect if running in Azure Cloud Shell
    $isCloudShell = $false
    $cloudShellIndicators = @(
        $env:ACC_TERM,
        $env:AZUREPS_HOST_ENVIRONMENT,
        $env:ACC_CLOUD
    )
    
    foreach ($indicator in $cloudShellIndicators) {
        if (-not [string]::IsNullOrWhiteSpace($indicator)) {
            $isCloudShell = $true
            Write-Host "☁️  Azure Cloud Shell detected via environment variable" -ForegroundColor Cyan
            break
        }
    }
    
    # Additional Cloud Shell detection - check if we're in /home/<user> and have cloudshell-specific paths
    if (-not $isCloudShell -and $PWD.Path.StartsWith('/home/') -and (Test-Path '/usr/bin/az' -ErrorAction SilentlyContinue)) {
        $isCloudShell = $true
        Write-Host "☁️  Azure Cloud Shell detected via filesystem analysis" -ForegroundColor Cyan
    }
    
    if ($isCloudShell) {
        # Extract UPN prefix for Cloud Shell directory
        if (-not [string]::IsNullOrWhiteSpace($AuthenticatedUser) -and $AuthenticatedUser.Contains('@')) {
            $upnPrefix = $AuthenticatedUser.Split('@')[0]
            $cloudShellDir = "/home/$upnPrefix"
            
            # Validate the directory exists and is writable
            try {
                if (-not (Test-Path $cloudShellDir)) {
                    Write-Host "⚠️  Cloud Shell home directory not found: $cloudShellDir" -ForegroundColor Yellow
                    Write-Host "   Using current user home: $HOME" -ForegroundColor Yellow
                    $cloudShellDir = $HOME
                }
                
                # Test write permissions
                $testFile = Join-Path $cloudShellDir "kvaudit_write_test_$(Get-Date -Format 'yyyyMMddHHmmss')"
                "test" | Out-File -FilePath $testFile -ErrorAction Stop
                Remove-Item -Path $testFile -ErrorAction SilentlyContinue
                
                Write-Host "📁 Azure Cloud Shell output directory: $cloudShellDir" -ForegroundColor Green
                return $cloudShellDir
                
            } catch {
                Write-Host "⚠️  Cannot write to Cloud Shell directory $cloudShellDir : $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "   Falling back to $HOME" -ForegroundColor Yellow
                return $HOME
            }
        } else {
            Write-Host "⚠️  Cannot determine UPN prefix from user: '$AuthenticatedUser'" -ForegroundColor Yellow
            Write-Host "   Using $HOME for Cloud Shell output" -ForegroundColor Yellow
            return $HOME
        }
    } else {
        # Local environment - use traditional path
        if ($IsWindows -or $env:OS -eq "Windows_NT" -or -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
            $localDir = "$env:USERPROFILE\Documents\KeyVaultAudit"
            Write-Host "💻 Local Windows environment detected" -ForegroundColor Cyan
        } elseif ($IsLinux -or $IsMacOS -or -not [string]::IsNullOrWhiteSpace($env:HOME)) {
            $localDir = "$env:HOME/Documents/KeyVaultAudit"
            Write-Host "💻 Local Unix/Linux environment detected" -ForegroundColor Cyan
        } else {
            # Fallback
            $localDir = "$PWD/KeyVaultAudit"
            Write-Host "💻 Unknown environment - using current directory" -ForegroundColor Yellow
        }
        
        Write-Host "📁 Local output directory: $localDir" -ForegroundColor Green
        return $localDir
    }
}

# --- Resume/Process Partial Parameter Processing ---
# Initialize temporary paths for early logging, will be updated after authentication
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$tempLogDir = if ($IsWindows -or $env:OS -eq "Windows_NT") { $env:TEMP } else { "/tmp" }
$outDir = $null
$csvPath = $null  
$htmlPath = $null
$global:errPath = Join-Path $tempLogDir "kv_audit_errors_temp_${timestamp}.txt"
$global:permissionsPath = Join-Path $tempLogDir "kv_audit_permissions_temp_${timestamp}.txt"
$global:dataIssuesPath = Join-Path $tempLogDir "kv_audit_dataissues_temp_${timestamp}.txt"

# Will be set to true after proper paths are established
$global:pathsInitialized = $false

# --- Resume Functionality ---
$resumeData = $null
$processedVaultIds = @()
$global:totalVaultsToProcess = 0

# Enhanced vault filtering variables
$global:checkpointProcessedSet = $null
$global:checkpointProcessedCount = 0
$global:csvProcessedSet = $null
$global:csvProcessedCount = 0
$global:resumeCsvPath = $null

# Handle cancellation recovery - auto-enable Resume if user chose to resume from cancellation
if ($shouldResumeFromCancellation -and -not $Resume -and -not $ProcessPartial) {
    Write-Host "🔄 Auto-enabling Resume mode for cancellation recovery..." -ForegroundColor Green
    $Resume = $true
}

# Handle ReportFromCsv mode - HTML-only generation from existing CSV
if ($PSBoundParameters.ContainsKey('ReportFromCsv')) {
    Write-Host "🔄 HTML-FROM-CSV RENDERING MODE" -ForegroundColor Cyan
    Write-Host "=".PadRight(50, "=") -ForegroundColor Gray
    Write-Host "Generating HTML report from existing CSV file (no Azure analysis)..." -ForegroundColor Cyan
    
    # Determine output directory
    $outDir = if ($OutputDirectory) { $OutputDirectory } else { Get-DefaultOutputDirectory }
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    
    # Resolve CSV file path
    # Note: Use PSBoundParameters because $CsvFilePath variable may be overwritten by local $csvPath usage
    $userCsvPath = if ($PSBoundParameters.ContainsKey('CsvFilePath')) { $PSBoundParameters.CsvFilePath } else { $null }
    
    if ($userCsvPath) {
        $csvFile = $userCsvPath
    } else {
        $csvFile = Get-ChildItem "$outDir" -Filter "KeyVaultComprehensiveAudit*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $csvFile) {
            Write-Host "❌ Error: No KeyVaultComprehensiveAudit*.csv files found in: $outDir" -ForegroundColor Red
            Write-Host "   Hint: Run a full audit first or specify a CSV file with -CsvFilePath" -ForegroundColor Yellow
            exit 1
        }
        $csvFile = $csvFile.FullName
    }
    
    if (-not (Test-Path $csvFile)) {
        Write-Host "❌ Error: CSV file not found: $csvFile" -ForegroundColor Red
        exit 1
    }
    
    $resolvedCsvPath = $csvFile
    
    Write-Host "📄 Loading CSV data from: $(Split-Path $resolvedCsvPath -Leaf)" -ForegroundColor Green
    
    try {
        # Import CSV data
        $csvData = Import-Csv -Path $resolvedCsvPath -ErrorAction Stop
        if (-not $csvData -or $csvData.Count -eq 0) {
            Write-Host "❌ Error: CSV file is empty or invalid: $resolvedCsvPath" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "✅ Loaded $($csvData.Count) vault records from CSV" -ForegroundColor Green
        
        # Convert CSV data to audit results format
        $global:auditResults = @()
        foreach ($row in $csvData) {
            $global:auditResults += $row
        }
        
        # Generate timestamp for HTML-from-CSV file
        $fromCsvTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $htmlPath = Join-Path $outDir "KeyVaultComprehensiveAudit_FROMCSV_${fromCsvTimestamp}.html"
        
        # Create metadata for HTML generation
        $csvMetadata = @{
            GeneratedAtUtc = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
            GeneratedBy = $global:currentUser
            Host = $env:COMPUTERNAME
            SourceCsvPath = $resolvedCsvPath
            RowCount = $csvData.Count
            Mode = "HTML-from-CSV"
            MarkPartial = $MarkPartial
        }
        
        # Build executive summary for HTML generation
        $compliantVaults = @($global:auditResults | Where-Object { 
            try { [int]($_.ComplianceScore -replace '%', '') -ge 90 } catch { $false }
        }).Count
        $partiallyCompliantVaults = @($global:auditResults | Where-Object { 
            try { 
                $score = [int]($_.ComplianceScore -replace '%', '')
                $score -ge 60 -and $score -lt 90 
            } catch { $false }
        }).Count
        $nonCompliantVaults = @($global:auditResults | Where-Object { 
            try { [int]($_.ComplianceScore -replace '%', '') -lt 60 } catch { $false }
        }).Count
        $highRiskVaults = @($global:auditResults | Where-Object { 
            try { [int]($_.ComplianceScore -replace '%', '') -lt 60 } catch { $false }
        }).Count
        
        # Calculate compliance percentage
        $compliancePercentage = if ($global:auditResults.Count -gt 0) { 
            [math]::Round(($compliantVaults / $global:auditResults.Count) * 100, 1) 
        } else { 0 }
        
        # Calculate average compliance scores
        $msScores = $global:auditResults | ForEach-Object { 
            try { [int]($_.ComplianceScore -replace '%', '') } catch { 0 }
        }
        $averageComplianceScore = if ($msScores.Count -gt 0) { 
            $msMeasure = $msScores | Measure-Object -Average
            [math]::Round((Get-SafeProperty -Object $msMeasure -PropertyName 'Average' -DefaultValue 0), 1) 
        } else { 0 }
        
        $companyScores = $global:auditResults | ForEach-Object { 
            try { [int]($_.CompanyComplianceScore -replace '%', '') } catch { 0 }
        }
        $companyAverageScore = if ($companyScores.Count -gt 0) { 
            $companyMeasure = $companyScores | Measure-Object -Average
            [math]::Round((Get-SafeProperty -Object $companyMeasure -PropertyName 'Average' -DefaultValue 0), 1) 
        } else { 0 }
        
        $executiveSummary = @{
            TotalKeyVaults = $global:auditResults.Count
            CompliantVaults = $compliantVaults
            PartiallyCompliantVaults = $partiallyCompliantVaults
            NonCompliantVaults = $nonCompliantVaults
            HighRiskVaults = $highRiskVaults
            CompliancePercentage = $compliancePercentage
            AverageComplianceScore = $averageComplianceScore
            CompanyAverageScore = $companyAverageScore
            WithDiagnostics = @($global:auditResults | Where-Object { 
                $_.DiagnosticsEnabled -eq "Yes" -or $_.DiagnosticsEnabled -eq $true 
            }).Count
            WithEventHub = @($global:auditResults | Where-Object { 
                $_.EventHubEnabled -eq "Yes" -or $_.EventHubEnabled -eq $true 
            }).Count
            WithLogAnalytics = @($global:auditResults | Where-Object { 
                $_.LogAnalyticsEnabled -eq "Yes" -or $_.LogAnalyticsEnabled -eq $true 
            }).Count
            UsingRBAC = @($global:auditResults | Where-Object { 
                try { [int]$_.RBACAssignmentCount -gt 0 } catch { $false }
            }).Count
            WithPrivateEndpoints = @($global:auditResults | Where-Object { 
                try { [int]$_.PrivateEndpointCount -gt 0 } catch { $false }
            }).Count
        }
        
        # Mark as partial results if requested
        $global:isPartialResults = $MarkPartial
        $global:partialResultsTimestamp = $csvMetadata.GeneratedAtUtc
        $global:partialResultsVaultCount = $csvData.Count
        $global:partialResultsTotalVaults = $csvData.Count
        
        # Create fake checkpoint data for HTML template
        $csvCheckpointData = @{
            ExecutionId = "CSV-Import-$(Get-Date -Format 'yyyyMMdd')"
            Timestamp = $csvMetadata.GeneratedAtUtc
            VaultIndex = $csvData.Count
            TotalVaults = $csvData.Count
            ProcessedResults = $global:auditResults
            CsvMetadata = $csvMetadata
        }
        
        # Generate HTML report using existing infrastructure
        Write-Host "📊 Generating HTML report..." -ForegroundColor Cyan
        $htmlGenerated = New-ComprehensiveHtmlReport -OutputPath $htmlPath -AuditResults $global:auditResults -ExecutiveSummary $executiveSummary -AuditStats @{} -IsPartialResults $MarkPartial -CheckpointData $csvCheckpointData -PartialDataSource "csv-fromcsv"
        
        if ($htmlGenerated) {
            Write-Host ""
            Write-Host "✅ HTML-FROM-CSV RENDERING COMPLETE" -ForegroundColor Green -BackgroundColor Black
            Write-Host "======================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "📄 Source CSV: $(Split-Path $resolvedCsvPath -Leaf)" -ForegroundColor White
            Write-Host "🌐 HTML Report: $(Split-Path $htmlPath -Leaf)" -ForegroundColor White
            Write-Host "📊 Records processed: $($csvData.Count) vaults" -ForegroundColor White
            if ($MarkPartial) {
                Write-Host "⚠️  Report marked as: PARTIAL RESULTS" -ForegroundColor Yellow
            } else {
                Write-Host "✅ Report generated without partial marking" -ForegroundColor Green
            }
            Write-Host "🕐 Generated at: $($csvMetadata.GeneratedAtUtc)" -ForegroundColor Gray
            Write-Host ""
            exit 0
        } else {
            Write-Host "❌ Failed to generate HTML report from CSV" -ForegroundColor Red
            exit 1
        }
        
    } catch {
        Write-Host "❌ Error processing CSV file for HTML generation: $_" -ForegroundColor Red
        Write-Host "   File: $resolvedCsvPath" -ForegroundColor Red
        exit 1
    }
}

# Enhanced resume logic with system crash vs manual cancellation distinction
if ($PSBoundParameters.ContainsKey('Resume') -or $PSBoundParameters.ContainsKey('ProcessPartial')) {
    # Handle CSV file processing for ProcessPartial mode first (functions are defined by this point)
    if ($PSBoundParameters.ContainsKey('ProcessPartial') -and $PSBoundParameters.ContainsKey('CsvFilePath')) {
        Write-Host "🔄 PARTIAL PROCESSING MODE - CSV File Processing" -ForegroundColor Cyan
        Write-Host "=".PadRight(50, "=") -ForegroundColor Gray
        
        # Validate CSV file exists
        if (-not (Test-Path $CsvFilePath)) {
            Write-Host "❌ Error: CSV file not found: $CsvFilePath" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "📄 Loading partial results from CSV file: $(Split-Path $CsvFilePath -Leaf)" -ForegroundColor Green
        
        # Process CSV file and generate reports
        if (Import-PartialResultsFromCsv -CsvFilePath $CsvFilePath) {
            Write-Host "✅ Partial results processing from CSV completed successfully!" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "❌ Failed to process partial results from CSV" -ForegroundColor Red
            exit 1
        }
    }
    
    # Determine if this is system recovery vs manual cancellation recovery
    $isSystemRecovery = -not $shouldResumeFromCancellation
    
    if ($isSystemRecovery) {
        Write-Host ""
        Write-Host "🔄 SYSTEM RECOVERY MODE" -ForegroundColor Cyan
        Write-Host "=".PadRight(40, "=") -ForegroundColor Gray
        Write-Host "Detected restart without manual cancellation marker." -ForegroundColor Cyan
        Write-Host "This indicates a system hang, crash, or normal restart." -ForegroundColor Gray
        Write-Host ""
    }
    
    $modeText = if ($Resume) { "RESUME MODE" } else { "PARTIAL PROCESSING MODE" }
    $actionText = if ($Resume) { "resume from" } else { "process partial results from" }
    
    Write-Host "🔄 $modeText Checking for available checkpoints..." -ForegroundColor Cyan
    
    # For resume/partial processing, we need to search in potential output directories
    # Try to determine the most likely output directory before authentication
    $searchDirs = @()
    
    # If override directory provided, use that
    if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $searchDirs += $OutputDirectory
    }
    
    # Add standard directories to search
    if ($IsWindows -or $env:OS -eq "Windows_NT" -or -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $searchDirs += "$env:USERPROFILE\Documents\KeyVaultAudit"
    }
    if ($IsLinux -or $IsMacOS -or -not [string]::IsNullOrWhiteSpace($env:HOME)) {
        $searchDirs += "$env:HOME/Documents/KeyVaultAudit"
        $searchDirs += "$env:HOME"  # For potential Cloud Shell
    }
    $searchDirs += "$PWD/KeyVaultAudit"  # Fallback
    
    # Search for checkpoints in all potential directories
    $allCheckpoints = @()
    $foundInDir = $null
    Write-CancellationDebugLog "CheckpointSearch" "Starting directory search for checkpoints" -Context "TotalDirectories=$($searchDirs.Count)|IsManualRecovery=$shouldResumeFromCancellation"
    
    foreach ($dir in $searchDirs) {
        Write-CancellationDebugLog "CheckpointSearch" "Checking directory for checkpoints" -Context "Directory=$dir"
        if (Test-Path $dir -ErrorAction SilentlyContinue) {
            # For manual cancellation recovery, limit to last 3 checkpoints at the source
            $maxCheckpoints = if ($shouldResumeFromCancellation) { 3 } else { 0 }
            Write-CancellationDebugLog "CheckpointSearch" "Calling Get-AllCheckpoints" -Context "Directory=$dir|MaxResults=$maxCheckpoints|IncludeCorrupt=$ProcessPartial"
            
            $dirCheckpoints = Get-AllCheckpoints -OutputDirectory $dir -IncludeCorrupt:$ProcessPartial -MaxResults $maxCheckpoints
            if ($dirCheckpoints -and $dirCheckpoints.Count -gt 0) {
                $allCheckpoints += $dirCheckpoints
                $foundInDir = $dir
                Write-Host "🔍 Found checkpoints in: $dir" -ForegroundColor Green
                Write-CancellationDebugLog "CheckpointSearch" "Found checkpoints in directory" -Context "Directory=$dir|CheckpointCount=$($dirCheckpoints.Count)"
                
                if ($shouldResumeFromCancellation -and $maxCheckpoints -gt 0) {
                    Write-Host "🔍 Limited to last $maxCheckpoints checkpoints for manual cancellation recovery" -ForegroundColor Yellow
                    Write-CancellationDebugLog "CheckpointSearch" "Applied limit for manual cancellation recovery" -Context "MaxCheckpoints=$maxCheckpoints"
                }
                break  # Use the first directory where we find checkpoints
            } else {
                Write-CancellationDebugLog "CheckpointSearch" "No checkpoints found in directory" -Context "Directory=$dir"
            }
        } else {
            Write-CancellationDebugLog "CheckpointSearch" "Directory does not exist or not accessible" -Context "Directory=$dir"
        }
    }
    
    if (-not $foundInDir) {
        Write-ResumeLog "Error" "No checkpoint files found in any standard directories" "Searched: $($searchDirs -join ', ')"
    } else {
        # Set outDir to the directory where we found checkpoints
        $outDir = $foundInDir
        Write-ResumeLog "Start" "$modeText activated, found checkpoint files" "OutputDir: $outDir"
        
        # Initialize CSV path for resume mode - will be set later after checkpoint selection
    }
    
    if ($allCheckpoints -and $allCheckpoints.Count -gt 0) {
        $selectedCheckpoint = $null
        
        # If only one checkpoint, auto-select for Resume mode
        if ($Resume -and $allCheckpoints.Count -eq 1 -and -not $allCheckpoints[0].IsCorrupt) {
            $selectedCheckpoint = $allCheckpoints[0]
            Write-Host "✅ Auto-selected single valid checkpoint: $($selectedCheckpoint.FileName)" -ForegroundColor Green
        } else {
            # Show selection interface
            $selectedCheckpoint = Show-CheckpointSelection -Checkpoints $allCheckpoints -Mode $(if ($Resume) { "Resume" } else { "ProcessPartial" }) -IsManualCancellationRecovery $shouldResumeFromCancellation
        }
        
        if ($selectedCheckpoint) {
            $resumeData = $selectedCheckpoint.Data
            $checkpointFileName = $selectedCheckpoint.FileName
            
            Write-Host "📅 Checkpoint from: $($resumeData.Timestamp)" -ForegroundColor Gray
            Write-Host "📊 Progress: $($resumeData.VaultIndex)/$($resumeData.TotalVaults) vaults processed" -ForegroundColor Gray
            Write-Host "👤 Original user: $($resumeData.User)" -ForegroundColor Gray
            
            Write-ResumeLog "Checkpoint" "Checkpoint selected for $actionText" "File: $checkpointFileName | Progress: $($resumeData.VaultIndex)/$($resumeData.TotalVaults)"
            
            # Build processed vault set using stable identities
            $processedVaultSet = $null
            $checkpointProcessedCount = 0
            if ($resumeData.ProcessedVaults) {
                $processedVaultSet = Get-ProcessedVaultSet -Checkpoint $resumeData
                $checkpointProcessedCount = $resumeData.ProcessedVaults.Count
                Write-Host "✅ Will reference $checkpointProcessedCount processed vaults from checkpoint" -ForegroundColor Green
                Write-ResumeLog "ProcessedVaults" "Built processed vault set" "Count: $checkpointProcessedCount"
            } else {
                $processedVaultSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Write-Host "ℹ️ No processed vaults found in checkpoint - will process all discovered vaults" -ForegroundColor Gray
                Write-ResumeLog "ProcessedVaults" "No processed vaults in checkpoint" "Starting fresh processing"
            }
            
            # Store for later use in vault filtering
            $global:checkpointProcessedSet = $processedVaultSet
            $global:checkpointProcessedCount = $checkpointProcessedCount
            
            # CSV fallback and union processing for enhanced resume robustness
            $csvProcessedResult = $null
            $global:csvProcessedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $global:csvProcessedCount = 0
            
            # Try to find existing CSV file for additional processed identities
            if ($PSBoundParameters.ContainsKey('Resume')) {
                $csvPath = $null
                
                # Use explicit CSV path if provided, otherwise search by executionId with fallback to latest
                if ($global:resumeCsvPath -and (Test-Path $global:resumeCsvPath)) {
                    $csvPath = $global:resumeCsvPath
                } else {
                    # Use new function to find CSV by executionId match (prefer matching, fallback to latest)
                    $csvPath = Find-CsvByExecutionId -OutputDirectory $outDir -ExecutionId $resumeData.ExecutionId
                }
                
                if ($csvPath) {
                    # RESUME CSV ALIGNMENT - Verbose banner with diagnostics
                    Write-Verbose "======================================" -Verbose
                    Write-Verbose "🔄 RESUME CSV ALIGNMENT" -Verbose
                    Write-Verbose "======================================" -Verbose
                    Write-Verbose "Target CSV: $(Split-Path $csvPath -Leaf)" -Verbose
                    Write-Verbose "Checkpoint ExecutionId: $($resumeData.ExecutionId)" -Verbose
                    Write-Verbose "Checkpoint processed: $checkpointProcessedCount vaults" -Verbose
                    
                    Write-Host "📄 Found existing CSV file: $(Split-Path $csvPath -Leaf)" -ForegroundColor Gray
                    $csvProcessedResult = Get-ProcessedSetFromCsv -CsvFilePath $csvPath
                    $global:csvProcessedSet = $csvProcessedResult.ProcessedSet
                    $global:csvProcessedCount = $csvProcessedResult.ProcessedCount
                    $global:resumeCsvPath = $csvPath
                    
                    if ($global:csvProcessedCount -gt 0) {
                        # Calculate overlap for diagnostics
                        $overlapCount = 0
                        if ($global:checkpointProcessedSet -and $global:csvProcessedSet) {
                            foreach ($csvId in $global:csvProcessedSet) {
                                if ($global:checkpointProcessedSet.Contains($csvId)) {
                                    $overlapCount++
                                }
                            }
                        }
                        
                        Write-Verbose "CSV row identities: $($global:csvProcessedCount) rows → $($global:csvProcessedSet.Count) unique identities" -Verbose
                        Write-Verbose "Overlap count: $overlapCount identities" -Verbose
                        Write-Verbose "Append will start at index: $($global:csvProcessedCount + 1)" -Verbose
                        Write-Verbose "======================================" -Verbose
                        
                        Write-Host "✅ Extracted $($global:csvProcessedSet.Count) unique identities from $($global:csvProcessedCount) CSV entries" -ForegroundColor Green
                        Write-ResumeLog "CsvProcessing" "Built CSV processed set" "Path: $(Split-Path $csvPath -Leaf) | Count: $($global:csvProcessedCount) | Unique: $($global:csvProcessedSet.Count) | Overlap: $overlapCount"
                    } else {
                        Write-Verbose "CSV file exists but contains no processable entries" -Verbose
                        Write-Verbose "======================================" -Verbose
                        Write-Host "ℹ️ CSV file found but no processable entries detected" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "ℹ️ No existing CSV file found for additional identity extraction" -ForegroundColor Gray
                }
                
                # Combine processed sets according to priority
                if ($global:checkpointProcessedSet -or $global:csvProcessedSet) {
                    $combinedResult = Get-CombinedProcessedSet -CheckpointSet $global:checkpointProcessedSet -CsvSet $global:csvProcessedSet -CheckpointCount $global:checkpointProcessedCount -CsvCount $global:csvProcessedCount -Priority $ResumeSourcePriority
                    
                    # Update the main processed set for vault filtering
                    $global:checkpointProcessedSet = $combinedResult.ProcessedSet
                    
                    # Report source combination results
                    $sourceDesc = @()
                    if ($combinedResult.SourceInfo.CheckpointUsed) { $sourceDesc += "Checkpoint" }
                    if ($combinedResult.SourceInfo.CsvUsed) { $sourceDesc += "CSV" }
                    
                    Write-Host "🔄 Resume Source Priority: $ResumeSourcePriority (using: $($sourceDesc -join ' + '))" -ForegroundColor Cyan
                    Write-Host "   📊 Combined unique identities: $($combinedResult.ProcessedSet.Count)" -ForegroundColor Gray
                    Write-ResumeLog "SourceCombination" "Combined processed sets" "Priority: $ResumeSourcePriority | Sources: $($sourceDesc -join ', ') | UniqueIdentities: $($combinedResult.ProcessedSet.Count)"
                    
                    # Enhanced CSV alignment diagnostics for Resume mode
                    if ($Verbose -and $global:csvProcessedSet -and $global:csvProcessedSet.Count -gt 0) {
                        Write-Host ""
                        Write-Host "📋 RESUME CSV ALIGNMENT" -ForegroundColor Cyan -BackgroundColor DarkBlue
                        Write-Host "========================" -ForegroundColor Cyan
                        Write-Host "Checkpoint Processed Count: $($global:checkpointProcessedCount)" -ForegroundColor Gray
                        Write-Host "CSV Row Identities: $($global:csvProcessedCount)" -ForegroundColor Gray
                        Write-Host "CSV Unique Identities: $($global:csvProcessedSet.Count)" -ForegroundColor Gray
                        Write-Host "Combined Unique Identities: $($combinedResult.ProcessedSet.Count)" -ForegroundColor Gray
                        Write-Host "Resume Source Priority: $ResumeSourcePriority" -ForegroundColor Gray
                        
                        if ($csvProcessedResult -and $csvProcessedResult.CsvPath) {
                            Write-Host "CSV File Used: $(Split-Path $csvProcessedResult.CsvPath -Leaf)" -ForegroundColor Gray
                        }
                        
                        # Log unmatched entries if configured
                        if ($UnmatchedLogCount -gt 0 -and $csvProcessedResult) {
                            if ($csvProcessedResult.UnmatchedFromCsv -and $csvProcessedResult.UnmatchedFromCsv.Count -gt 0) {
                                Write-Host "Sample Unmatched from CSV ($($csvProcessedResult.UnmatchedFromCsv.Count) total):" -ForegroundColor Yellow
                                $csvProcessedResult.UnmatchedFromCsv | Select-Object -First $UnmatchedLogCount | ForEach-Object {
                                    Write-Host "  • $_" -ForegroundColor Yellow
                                }
                            }
                            if ($csvProcessedResult.UnmatchedFromCheckpoint -and $csvProcessedResult.UnmatchedFromCheckpoint.Count -gt 0) {
                                Write-Host "Sample Unmatched from Checkpoint ($($csvProcessedResult.UnmatchedFromCheckpoint.Count) total):" -ForegroundColor Yellow
                                $csvProcessedResult.UnmatchedFromCheckpoint | Select-Object -First $UnmatchedLogCount | ForEach-Object {
                                    Write-Host "  • $_" -ForegroundColor Yellow
                                }
                            }
                        }
                        Write-Host "========================" -ForegroundColor Cyan
                        Write-Host ""
                    }
                }
            }
            
            # Restore global statistics
            if ($resumeData.Statistics) {
                $global:auditStats = $resumeData.Statistics
                Write-Host "📈 Restored audit statistics" -ForegroundColor Gray
                Write-ResumeLog "Statistics" "Restored previous audit statistics" "Successful: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'SuccessfulVaults' -DefaultValue 0) | Errors: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'ProcessingErrors' -DefaultValue 0)"
            }
            
            # Handle ProcessPartial mode - generate reports and exit
            if ($ProcessPartial) {
                Write-Host ""
                Write-Host "🔄 Processing partial results from checkpoint..." -ForegroundColor Cyan
                
                # Load existing results from checkpoint - use full ProcessedResults if available
                if ($resumeData.ProcessedResults -and $resumeData.ProcessedResults.Count -gt 0) {
                    # Use the complete audit results from checkpoint
                    $global:auditResults = $resumeData.ProcessedResults
                    Write-Host "✅ Loaded $($global:auditResults.Count) complete vault results from checkpoint" -ForegroundColor Green
                } elseif ($resumeData.ProcessedVaults -and $resumeData.ProcessedVaults.Count -gt 0) {
                    # Fallback to ProcessedVaults data if ProcessedResults not available (older checkpoint format)
                    $global:auditResults = @()
                    foreach ($processedVault in $resumeData.ProcessedVaults) {
                        # Create a minimal result structure for report generation (backward compatibility)
                        $partialResult = [PSCustomObject]@{
                            KeyVaultName = $processedVault.VaultName
                            SubscriptionId = $processedVault.SubscriptionId
                            ResourceId = $processedVault.ResourceId
                            Status = if ($processedVault.Status) { $processedVault.Status } else { "Processed" }
                            LastAuditDate = if ($processedVault.ProcessedTime) { $processedVault.ProcessedTime } else { "Unknown" }
                            ComplianceScore = 0  # Default for minimal data
                            CompanyComplianceScore = 0  # Default for minimal data
                            IsPartialResult = $true
                        }
                        $global:auditResults += $partialResult
                    }
                    Write-Host "✅ Loaded $($global:auditResults.Count) vault results from checkpoint (legacy format)" -ForegroundColor Green
                } else {
                    Write-Host "❌ No processed vault data found in checkpoint" -ForegroundColor Red
                    exit 1
                }
                
                # Generate comprehensive partial reports
                if (Invoke-PartialResults -CheckpointData $resumeData) {
                    Write-Host "✅ Partial results processing completed successfully!" -ForegroundColor Green
                    exit 0
                } else {
                    Write-Host "❌ Failed to process partial results" -ForegroundColor Red
                    exit 1
                }
            }
            
            # Import existing results if final checkpoint (Resume mode only)
            if ($Resume -and $resumeData.IsFinalCheckpoint) {
                Write-Host "ℹ️ This is a final checkpoint. All vaults were processed." -ForegroundColor Blue
                $csvFile = Get-ChildItem -Path $outDir -Filter "*KeyVaultComprehensiveAudit*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($csvFile) {
                    Write-Host "📄 Existing results found: $($csvFile.Name)" -ForegroundColor Gray
                    Write-Host "❓ Resume will process any newly discovered vaults only." -ForegroundColor Yellow
                    Write-ResumeLog "FinalCheckpoint" "Final checkpoint detected, will process new vaults only" "ExistingResults: $($csvFile.Name)"
                }
            }
            
            # For Resume mode with valid checkpoint, ensure we skip discovery if master file is available
            if ($Resume -and $processedVaultIds -and $processedVaultIds.Count -gt 0) {
                Write-Host "🔄 Resume mode: Checking for master discovery file to optimize performance..." -ForegroundColor Cyan
                if (-not $masterData) {
                    $masterData = Import-DiscoveryMaster -OutputDirectory $outDir
                }
                
                if ($masterData -and (Test-DiscoveryMasterValidity -MasterData $masterData -MaxAgeHours 48)) {
                    Write-Host "⚡ RESUME OPTIMIZATION: Using master file to skip redundant discovery" -ForegroundColor Green
                    $global:usesMasterFileWithoutCheckpoint = $true
                    $global:masterDataForOptimizedMode = $masterData
                    $skipDiscovery = $true
                    Write-ResumeLog "Optimization" "Master file found for resume mode - discovery will be skipped" "MasterAge: $((Get-Date) - [DateTime]::ParseExact($masterData.Timestamp, 'yyyy-MM-dd HH:mm:ss UTC', $null)) hours"
                } else {
                    Write-Host "⚠️ Master file not available or too old - will perform fresh discovery" -ForegroundColor Yellow
                    Write-ResumeLog "Discovery" "Fresh discovery required - master file unavailable or expired" "SkipDiscovery: $skipDiscovery"
                }
            }
            
        } else {
            Write-Host "❌ No checkpoint selected." -ForegroundColor Yellow
            
            # Check for master file before exiting ProcessPartial or falling back for Resume
            if ($Resume -or $ProcessPartial) {
                Write-Host "🔍 Checking for master discovery file as fallback..." -ForegroundColor Cyan
                $masterData = Import-DiscoveryMaster -OutputDirectory $outDir
                
                if ($masterData) {
                    Write-Host "⚡ OPTIMIZED MODE: Using subscriptions/vaults from master file. Skipping subscription discovery." -ForegroundColor Green
                    Write-Host "📂 Master file contains: $($masterData.TotalSubscriptions) subscriptions, $($masterData.TotalKeyVaults) Key Vaults" -ForegroundColor Gray
                    
                    # Set global flags to use master file and skip discovery
                    $global:usesMasterFileWithoutCheckpoint = $true
                    $global:masterDataForOptimizedMode = $masterData
                    
                    if ($ProcessPartial) {
                        Write-Host "✅ ProcessPartial will generate reports from master file data" -ForegroundColor Green
                    } else {
                        Write-Host "✅ Resume will start fresh analysis using master file discovery" -ForegroundColor Green
                    }
                } else {
                    if ($ProcessPartial) {
                        Write-Host "❌ ProcessPartial requires existing checkpoint or master file data. Exiting." -ForegroundColor Red
                        exit 1
                    } else {
                        Write-Host "🔄 Resume will start fresh audit with full discovery" -ForegroundColor Yellow
                    }
                }
            }
            
            $Resume = $false
            $resumeData = $null
        }
    } else {
        Write-Host "❌ No checkpoint files found." -ForegroundColor Yellow
        Write-ResumeLog "Error" "No checkpoint files found in output directory" "SearchPath: $outDir"
        
        # Check for master file before exiting ProcessPartial or falling back for Resume
        if ($Resume -or $ProcessPartial) {
            Write-Host "🔍 Checking for master discovery file as fallback..." -ForegroundColor Cyan
            $masterData = Import-DiscoveryMaster -OutputDirectory $outDir
            
            if ($masterData) {
                Write-Host "⚡ OPTIMIZED MODE: Using subscriptions/vaults from master file. Skipping subscription discovery." -ForegroundColor Green
                Write-Host "📂 Master file contains: $($masterData.TotalSubscriptions) subscriptions, $($masterData.TotalKeyVaults) Key Vaults" -ForegroundColor Gray
                
                # Set global flags to use master file and skip discovery
                $global:usesMasterFileWithoutCheckpoint = $true
                $global:masterDataForOptimizedMode = $masterData
                
                if ($ProcessPartial) {
                    Write-Host "✅ ProcessPartial will generate reports from master file data" -ForegroundColor Green
                } else {
                    Write-Host "✅ Resume will start fresh analysis using master file discovery" -ForegroundColor Green
                }
            } else {
                if ($ProcessPartial) {
                    Write-Host "❌ ProcessPartial requires existing checkpoint or master file data. Exiting." -ForegroundColor Red
                    exit 1
                } else {
                    Write-Host "🔄 Resume will start fresh audit with full discovery" -ForegroundColor Yellow
                }
            }
        }
        
        $Resume = $false
        $resumeData = $null
    }
    
    Write-Host ""
}

$global:ScriptExecutionContext.StartTime = Get-Date
$global:ScriptExecutionContext.SubscriptionCount = 0
$global:ScriptExecutionContext.ServiceProviderCount = 0
$global:ScriptExecutionContext.ManagedIdentityCount = 0
$global:ScriptExecutionContext.UserManagedIdentityCount = 0
$global:ScriptExecutionContext.SystemManagedIdentityCount = 0
$global:ScriptExecutionContext.AccessPolicyCount = 0
$global:IsPartialResults = $false
$global:auditStats = @{
    TokenRefreshCount = 0
    PermissionErrors = 0
    ProcessingErrors = 0
    SuccessfulVaults = 0
    SkippedVaults = 0
    TotalRetries = 0
    SkippedSubscriptions = 0
    AuthenticationErrors = 0
}
$global:skippedSubscriptions = @()
$global:currentUser = ""

# Initialize global count variables for RBAC analysis
$global:serviceProviderCount = 0
$global:managedIdentityCount = 0
$global:systemManagedIdentityCount = 0
$global:userManagedIdentityCount = 0
$global:accessPolicyCount = 0

# --- Production Memory Management and Checkpoint System ---
function Invoke-MemoryCleanup {
    param(
        [int]$VaultIndex,
        [int]$MemoryThresholdMB = 1024,
        [bool]$ForceCleanup = $false
    )
    
    # Get current memory usage
    try {
        $process = Get-Process -Id $PID
        $memoryMB = [math]::Round($process.WorkingSet64 / 1MB, 1)
    } catch {
        Write-Warning "Failed to get memory usage: $_"
        return
    }
    
    # Determine if cleanup is needed
    $needsCleanup = $ForceCleanup -or 
                   ($VaultIndex % 50 -eq 0 -and $VaultIndex -gt 0) -or
                   ($memoryMB -gt $MemoryThresholdMB)
    
    if ($needsCleanup) {
        $cleanupReason = if ($ForceCleanup) { "Forced" } 
                        elseif ($memoryMB -gt $MemoryThresholdMB) { "Threshold exceeded ($memoryMB MB > $MemoryThresholdMB MB)" }
                        else { "Periodic (every 50 vaults)" }
                        
        Write-Host "🧹 Performing memory cleanup (Vault $VaultIndex) - Reason: $cleanupReason" -ForegroundColor Cyan
        
        # Define comprehensive list of variables to clean up
        $variablesToClean = @(
            'tempResults',
            'vaultDetails', 
            'rbacAssignments',
            'accessPolicies',
            'identityAnalysis',
            'networkConfig',
            'overPrivileged',
            'workloadAnalysis',
            'diagnostics',
            'vaultData',
            'complianceResult',
            'recommendations',
            'result',
            'roleAssignments',
            'connectedManagedIdentities',
            'processedVaultIds',
            'checkpointData',
            'resumeData'
        )
        
        $cleanedVariables = @()
        $cleanupErrors = @()
        
        try {
            # Safely remove variables with existence check and logging
            foreach ($varName in $variablesToClean) {
                try {
                    $variable = Get-Variable -Name $varName -ErrorAction SilentlyContinue
                    if ($variable) {
                        # Try to get variable size estimate before removal
                        $varSize = "unknown"
                        try {
                            if ($variable.Value) {
                                if ($variable.Value -is [Array]) {
                                    $varSize = "$($variable.Value.Count) items"
                                } elseif ($variable.Value -is [String]) {
                                    $varSize = "$($variable.Value.Length) chars"
                                } elseif ($variable.Value -is [PSCustomObject]) {
                                    $propertiesMeasure = $variable.Value.PSObject.Properties | Measure-Object
                                    $propCount = Get-SafeProperty -Object $propertiesMeasure -PropertyName 'Count' -DefaultValue 0
                                    $varSize = "$propCount properties"
                                }
                            }
                        } catch {
                            # Size estimation failed, but continue with cleanup
                            Write-Verbose "Failed to estimate size for variable $varName`: $($_.Exception.Message)"
                        }
                        
                        Remove-Variable -Name $varName -Force -ErrorAction Stop
                        $cleanedVariables += "$varName ($varSize)"
                    }
                } catch {
                    $cleanupErrors += "$varName : $($_.Exception.Message)"
                }
            }
            
            # Force garbage collection with multiple passes
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
            
            # Get memory usage after cleanup
            $process = Get-Process -Id $PID
            $memoryAfterMB = [math]::Round($process.WorkingSet64 / 1MB, 1)
            $memoryReduced = $memoryMB - $memoryAfterMB
            
            # Log cleanup results
            $cleanupSummary = if ($cleanedVariables.Count -gt 0) {
                "Cleaned: [$($cleanedVariables -join ', ')]"
            } else {
                "No variables needed cleanup"
            }
            
            if ($cleanupErrors.Count -gt 0) {
                $errorSummary = "Errors: [$($cleanupErrors -join ', ')]"
                Write-Host "⚠️ Memory cleanup completed with errors" -ForegroundColor Yellow
                Write-DataCollectionLog "MemoryManagement" "Memory cleanup with errors | $cleanupSummary | $errorSummary | Before: $memoryMB MB | After: $memoryAfterMB MB" -DataType "ResourceManagement" -Impact "Performance"
            } else {
                Write-Host "💾 Memory usage: $memoryAfterMB MB (reduced by $memoryReduced MB)" -ForegroundColor Gray
                Write-DataCollectionLog "MemoryManagement" "Memory cleanup completed | $cleanupSummary | Before: $memoryMB MB | After: $memoryAfterMB MB | Reduced: $memoryReduced MB" -DataType "ResourceManagement" -Impact "Performance"
            }
            
            # Enhanced warnings based on memory thresholds
            if ($memoryAfterMB -gt 2048) {
                Write-Host "[CRITICAL] Very high memory usage ($memoryAfterMB MB). Consider reducing vault batch size or restarting." -ForegroundColor Red
                Write-DataCollectionLog "MemoryManagement" "Critical memory warning: $memoryAfterMB MB" -DataType "ResourceManagement" -Impact "CriticalPerformanceWarning"
                
                # Suggest pausing in large environments
                if (-not $TestMode) {
                    Write-Host "[PAUSE] Consider pausing execution or using TestMode for large environments" -ForegroundColor Yellow
                }
            } elseif ($memoryAfterMB -gt $MemoryThresholdMB) {
                Write-Host "⚠️ High memory usage detected ($memoryAfterMB MB). Monitoring closely." -ForegroundColor Yellow
                Write-DataCollectionLog "MemoryManagement" "High memory usage warning: $memoryAfterMB MB" -DataType "ResourceManagement" -Impact "PerformanceWarning"
            } else {
                Write-Host "✅ Memory usage within normal range ($memoryAfterMB MB)" -ForegroundColor Green
            }
            
        } catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            Write-Host "❌ Memory cleanup failed but script will continue" -ForegroundColor Red
            Write-ErrorLog "MemoryManagement" "Memory cleanup error: $errorMessage" -Context "VaultIndex:$VaultIndex|MemoryMB:$memoryMB|CleanedVars:$($cleanedVariables.Count)|Errors:$($cleanupErrors.Count)"
        }
    } else {
        # Periodic memory monitoring without cleanup
        if ($VaultIndex % 10 -eq 0 -and $VaultIndex -gt 0) {
            Write-Host "📊 Memory monitoring: $memoryMB MB (Vault $VaultIndex)" -ForegroundColor DarkGray
        }
    }
}

# --- Resume and Checkpoint Enhancement Functions ---
function Find-LatestCheckpoint {
    param([string]$OutputDirectory)
    
    try {
        $checkpointFiles = Get-ChildItem -Path $OutputDirectory -Filter "akv_audit_checkpoint_*.json" -ErrorAction SilentlyContinue
        if ($checkpointFiles) {
            $latestCheckpoint = $checkpointFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            return $latestCheckpoint.FullName
        }
    } catch {
        Write-Warning "Error finding checkpoint files: $_"
    }
    return $null
}

# --- Master Discovery File Functions ---
function Save-DiscoveryMaster {
    param(
        [array]$AllKeyVaults,
        [array]$Subscriptions,
        [string]$OutputDirectory
    )
    
    try {
        $masterData = @{
            Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss UTC')
            User = $global:currentUser
            ExecutionId = $global:executionId
            TotalSubscriptions = $Subscriptions.Count
            TotalKeyVaults = $AllKeyVaults.Count
            Subscriptions = @()
        }
        
        # Group Key Vaults by subscription
        $subscriptionGroups = $AllKeyVaults | Group-Object SubscriptionId
        
        foreach ($subscription in $Subscriptions) {
            $subscriptionGroup = $subscriptionGroups | Where-Object { $_.Name -eq $subscription.Id }
            $subKeyVaults = if ($subscriptionGroup) { $subscriptionGroup.Group } else { @() }
            
            $subscriptionData = @{
                Id = $subscription.Id
                Name = $subscription.Name
                KeyVaults = @()
            }
            
            foreach ($kvItem in $subKeyVaults) {
                $kv = $kvItem.KeyVault
                $subscriptionData.KeyVaults += @{
                    VaultName = $kv.VaultName
                    ResourceId = $kv.ResourceId
                    Location = $kv.Location
                    ResourceGroupName = $kv.ResourceGroupName
                }
            }
            
            $masterData.Subscriptions += $subscriptionData
        }
        
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $masterFilePath = Join-Path $OutputDirectory "akv_audit_master_$timestamp.json"
        $masterData | ConvertTo-Json -Depth 10 | Set-Content -Path $masterFilePath -Encoding UTF8
        
        Write-Host "✅ Discovery master file saved: $(Split-Path $masterFilePath -Leaf)" -ForegroundColor Green
        Write-ErrorLog "DiscoveryMaster" "Master discovery file saved successfully" -Details "Path: $masterFilePath | Subscriptions: $($Subscriptions.Count) | KeyVaults: $($AllKeyVaults.Count)"
        
        return $masterFilePath
    } catch {
        Write-Warning "❌ Failed to save discovery master file: $_"
        Write-ErrorLog "DiscoveryMaster" "Failed to save master discovery file: $_"
        return $null
    }
}


function Convert-MasterToKeyVaultArray {
    param(
        [object]$MasterData
    )
    
    $allKeyVaults = @()
    
    foreach ($subscription in $MasterData.Subscriptions) {
        foreach ($kvData in $subscription.KeyVaults) {
            # Reconstruct the Key Vault object to match expected structure
            $kvObject = [PSCustomObject]@{
                VaultName = $kvData.VaultName
                ResourceId = $kvData.ResourceId
                Location = $kvData.Location
                ResourceGroupName = $kvData.ResourceGroupName
            }
            
            $allKeyVaults += [PSCustomObject]@{
                KeyVault = $kvObject
                SubscriptionName = $subscription.Name
                SubscriptionId = $subscription.Id
            }
        }
    }
    
    return $allKeyVaults
}



# --- Enhanced Logging Functions for Production ---

# --- Enhanced Progress Tracking for Production Environments ---
function Show-Progress {
    param(
        [string]$Phase,
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem = "",
        [string]$Operation = ""
    )
    
    $elapsed = (Get-Date) - $global:startTime
    $percentComplete = if ($Total -gt 0) { ($Current / $Total) * 100 } else { 0 }
    
    # Enhanced ETA calculation with confidence intervals
    $eta = if ($Current -gt 0) { 
        $rate = $elapsed.TotalSeconds / $Current
        $remaining = $Total - $Current
        $estimatedRemaining = [timespan]::FromSeconds($remaining * $rate)
        
        # Add confidence factor based on progress
        $confidenceFactor = if ($percentComplete -lt 10) { 1.5 } elseif ($percentComplete -lt 25) { 1.3 } elseif ($percentComplete -lt 50) { 1.15 } else { 1.05 }
        [timespan]::FromSeconds($estimatedRemaining.TotalSeconds * $confidenceFactor)
    } else { 
        [timespan]::Zero 
    }
    
    # Enhanced status display with operation details
    $operationInfo = if ($Operation) { " | Op: $Operation" } else { "" }
    $itemInfo = if ($CurrentItem) { " - $CurrentItem" } else { "" }
    
    Write-Progress -Activity "Azure Key Vault Comprehensive Audit" -Status "$Phase$itemInfo$operationInfo" -PercentComplete $percentComplete
    
    $statusColor = if ($percentComplete -lt 25) { "Red" } elseif ($percentComplete -lt 50) { "Yellow" } elseif ($percentComplete -lt 75) { "Cyan" } else { "Green" }
    
    # Production-grade progress display
    $rate = if ($elapsed.TotalMinutes -gt 0) { $Current / $elapsed.TotalMinutes } else { 0 }
    $progressLine = "📊 [{0}] Progress: {1}/{2} ({3:F1}%) | Elapsed: {4:mm\:ss} | ETA: {5:mm\:ss} | Rate: {6:F1}/min" -f $Phase, $Current, $Total, $percentComplete, $elapsed, $eta, $rate
    
    Write-Host $progressLine -ForegroundColor $statusColor
    
    # Log progress for production monitoring
    if ($Current % 10 -eq 0 -or $Current -eq $Total) {
        Write-DataCollectionLog "Progress" $progressLine -DataType "ProgressTracking" -Impact "Monitoring"
    }
}

# --- Enhanced Authentication Mode Selection ---
function Get-AuthenticationMode {
    <#
    .SYNOPSIS
    Determines the optimal authentication mode based on comprehensive environment detection and user guidance
    .DESCRIPTION
    Performs intelligent environment detection to select the most appropriate authentication method.
    Uses enhanced detection logic for Azure Cloud Shell, MSI/automation environments, and service principal
    credentials. Provides clear user guidance and explanations when manual selection is required.
    
    Authentication Decision Flow:
    1. Azure Cloud Shell Detection → Interactive browser authentication (optimal for Cloud Shell)
    2. Managed Identity Detection → MSI authentication (optimal for Azure compute)
    3. Service Principal Credentials → App-only authentication (optimal for automation)
    4. Unknown Environment → Interactive user prompt with detailed guidance
    
    Enhanced Detection Methods:
    - Cloud Shell: Multiple environment variables, filesystem indicators, process detection
    - MSI/Automation: MSI endpoints, identity headers, Azure context analysis
    - Service Principal: Environment variable validation for complete credential sets
    - Fallback: Interactive prompts with authentication method explanations
    #>
    [CmdletBinding()]
    param()
    
    $verboseEnabled = $VerbosePreference -eq 'Continue'
    
    # Store authentication decision process in global context
    $authDecision = @{
        StartTime = Get-Date
        DetectionResults = @{}
        SelectedMethod = $null
        Reasoning = $null
    }
    $global:ScriptExecutionContext.AuthenticationFlow.Decision = $authDecision
    
    # Enhanced verbose logging for environment detection
    Write-UserMessage -Message "Performing comprehensive environment detection for authentication..." -Type Info
    Write-Verbose "Starting authentication mode detection with enhanced environment analysis"
    
    # First, detect Azure Cloud Shell with comprehensive logging
    Write-Verbose "Testing for Azure Cloud Shell environment..."
    $isCloudShell = Test-CloudShellEnvironment -Quiet:(-not $verboseEnabled) -Verbose:$verboseEnabled
    $authDecision.DetectionResults.CloudShell = $isCloudShell
    
    if ($isCloudShell) {
        $authDecision.SelectedMethod = "Interactive Browser"
        $authDecision.Reasoning = "Azure Cloud Shell detected - interactive authentication optimal for browser-enabled environment"
        
        Write-UserMessage -Message "Azure Cloud Shell environment detected - using optimal authentication" -Type Success
        Write-UserMessage -Message "Selected: Interactive browser authentication (optimal for Cloud Shell)" -Type Success
        
        if ($verboseEnabled) {
            Write-UserMessage -Message "Reasoning: Cloud Shell provides secure browser context for interactive auth" -Type Debug
        }
        
        Write-Verbose "Authentication mode selected: Interactive (Cloud Shell detected)"
        return @{}  # Default interactive authentication
    }
    
    # Check for managed identity/automation environment with comprehensive logging
    Write-Verbose "Testing for Managed Identity/automation environment..."
    $hasManagedIdentity = Test-ManagedIdentityEnvironment -Quiet:(-not $verboseEnabled) -Verbose:$verboseEnabled
    $authDecision.DetectionResults.ManagedIdentity = $hasManagedIdentity
    
    if ($hasManagedIdentity) {
        $authDecision.SelectedMethod = "Managed Identity"
        $authDecision.Reasoning = "Managed Identity environment detected - MSI authentication optimal for Azure compute resources"
        
        Write-UserMessage -Message "Managed Identity/Automation environment detected - using app-only authentication" -Type Success
        Write-UserMessage -Message "Selected: Managed Identity authentication (optimal for automation)" -Type Success
        
        if ($verboseEnabled) {
            Write-UserMessage -Message "Reasoning: MSI environment provides secure automated authentication without explicit credentials" -Type Debug
        }
        
        Write-Verbose "Authentication mode selected: Managed Identity (MSI detected)"
        return @{ Identity = $true }
    }
    
    # Check for service principal credentials in environment variables
    Write-Verbose "Testing for Service Principal credentials in environment..."
    $hasServicePrincipalCreds = (-not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_ID)) -and 
                               (-not [string]::IsNullOrWhiteSpace($env:AZURE_TENANT_ID)) -and 
                               (-not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_SECRET))
    
    $authDecision.DetectionResults.ServicePrincipalCredentials = $hasServicePrincipalCreds
    
    if ($hasServicePrincipalCreds) {
        $authDecision.SelectedMethod = "Service Principal"
        $authDecision.Reasoning = "Complete service principal credentials found in environment variables"
        
        Write-UserMessage -Message "Service Principal credentials detected in environment variables" -Type Success
        Write-UserMessage -Message "Selected: Service Principal authentication (using environment credentials)" -Type Success
        
        if ($verboseEnabled) {
            Write-UserMessage -Message "Reasoning: Complete service principal credentials found in environment" -Type Debug
            Write-UserMessage -Message "Client ID: $env:AZURE_CLIENT_ID" -Type Debug
            Write-UserMessage -Message "Tenant ID: $env:AZURE_TENANT_ID" -Type Debug
        }
        
        try {
            # PSScriptAnalyzer suppression: This is necessary for Azure authentication with service principal
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
            $clientSecret = ConvertTo-SecureString $env:AZURE_CLIENT_SECRET -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($env:AZURE_CLIENT_ID, $clientSecret)
            
            Write-Verbose "Service Principal credentials prepared successfully"
            return @{ 
                ServicePrincipal = $true
                Credential = $credential
                TenantId = $env:AZURE_TENANT_ID
            }
        } catch {
            Write-UserMessage -Message "Failed to prepare Service Principal credentials: $($_.Exception.Message)" -Type Error
            Write-Verbose "Service Principal credential preparation failed, falling back to interactive prompt"
        }
    }
    
    # Check for local Windows environment - default to interactive authentication
    Write-Verbose "Testing for local Windows environment..."
    $isLocalWindows = $PSVersionTable.PSVersion.Major -ge 5 -and $env:OS -eq "Windows_NT" -and 
                     (-not $hasManagedIdentity) -and (-not $isCloudShell) -and (-not $hasServicePrincipalCreds)
    
    $authDecision.DetectionResults.LocalWindows = $isLocalWindows
    
    if ($isLocalWindows) {
        $authDecision.SelectedMethod = "Interactive Browser"
        $authDecision.Reasoning = "Local Windows environment detected - interactive authentication optimal for desktop use"
        
        Write-UserMessage -Message "Local Windows environment detected - using interactive authentication" -Type Success
        Write-UserMessage -Message "Selected: Interactive browser authentication (optimal for local desktop)" -Type Success
        
        if ($verboseEnabled) {
            Write-UserMessage -Message "Reasoning: Local Windows desktop environment with no Azure automation indicators" -Type Debug
        }
        
        Write-Verbose "Authentication mode selected: Interactive (local Windows detected)"
        return @{}  # Default interactive authentication
    }
    
    # Environment cannot be confidently determined - provide interactive prompt with comprehensive guidance
    $authDecision.SelectedMethod = "User Prompt"
    $authDecision.Reasoning = "Environment could not be automatically determined - requiring user selection"
    
    Write-UserMessage -Message "Environment cannot be automatically determined. Manual authentication method selection required." -Type Warning
    Write-Information ""
    Write-UserMessage -Message "Please select the most appropriate authentication mode for your environment:" -Type Info
    Write-Information ""
    Write-Information "1️⃣ Interactive browser login"
    Write-Information "   └── ✅ Best for: Local desktop use with access to web browser"
    Write-Information "   └── ℹ️  Opens browser window for secure Azure login"
    Write-Information ""
    Write-Information "2️⃣ App-only (client credential) authentication"
    Write-Information "   └── ✅ Best for: Azure Cloud Shell, automation, CI/CD pipelines"
    Write-Information "   └── ℹ️  Requires application registration with client ID, tenant ID, and secret"
    Write-Information ""
    Write-Information "3️⃣ Device code authentication"
    Write-Information "   └── ⚠️  Fallback only: When browser and app-only authentication are not available"
    Write-Information "   └── ℹ️  Provides device code for authentication at https://microsoft.com/devicelogin"
    Write-Information ""
    
    do {
        $choice = Read-Host "Enter your choice (1-3)"
        switch ($choice) {
            "1" {
                $authDecision.SelectedMethod = "Interactive Browser (User Selected)"
                Write-UserMessage -Message "Selected: Interactive browser authentication" -Type Success
                Write-Information "   → This will open a browser window for Azure login"
                
                if ($verboseEnabled) {
                    Write-UserMessage -Message "Reasoning: User manually selected interactive browser authentication" -Type Debug
                }
                
                Write-Verbose "Authentication mode selected: Interactive (user choice)"
                return @{}  # Default interactive authentication
            }
            "2" {
                $authDecision.SelectedMethod = "Service Principal (User Selected)"
                Write-UserMessage -Message "Selected: App-only (client credential) authentication" -Type Success
                Write-Information "   → You will need to provide client ID, tenant ID, and client secret"
                
                # Prompt for client credentials with validation
                do {
                    $clientId = Read-Host "Enter Client ID (Application ID)"
                    if ([string]::IsNullOrWhiteSpace($clientId)) {
                        Write-UserMessage -Message "Client ID cannot be empty" -Type Error
                        continue
                    }
                    break
                } while ($true)
                
                do {
                    $tenantId = Read-Host "Enter Tenant ID"
                    if ([string]::IsNullOrWhiteSpace($tenantId)) {
                        Write-UserMessage -Message "Tenant ID cannot be empty" -Type Error
                        continue
                    }
                    break
                } while ($true)
                
                $clientSecret = Read-Host "Enter Client Secret" -AsSecureString
                
                if ($verboseEnabled) {
                    Write-UserMessage -Message "Reasoning: User provided service principal credentials interactively" -Type Debug
                    Write-UserMessage -Message "Client ID: $clientId" -Type Debug
                    Write-UserMessage -Message "Tenant ID: $tenantId" -Type Debug
                }
                
                try {
                    $credential = New-Object System.Management.Automation.PSCredential($clientId, $clientSecret)
                    Write-Verbose "Service Principal credentials prepared successfully from user input"
                    
                    return @{ 
                        ServicePrincipal = $true
                        Credential = $credential
                        TenantId = $tenantId
                    }
                } catch {
                    Write-UserMessage -Message "Failed to create Service Principal credential: $($_.Exception.Message)" -Type Error
                    Write-UserMessage -Message "Please try again or select a different authentication method." -Type Warning
                    continue
                }
            }
            "3" {
                $authDecision.SelectedMethod = "Device Code (User Selected)"
                Write-UserMessage -Message "Selected: Device code authentication (fallback mode)" -Type Warning
                Write-Information "   → You will receive a device code to enter at https://microsoft.com/devicelogin"
                Write-UserMessage -Message "Note: Consider using interactive or app-only authentication for better user experience" -Type Warning
                
                if ($verboseEnabled) {
                    Write-UserMessage -Message "Reasoning: User manually selected device code authentication as fallback" -Type Debug
                }
                
                Write-Verbose "Authentication mode selected: Device Code (user choice)"
                return @{ UseDeviceAuthentication = $true }
            }
            default {
                Write-UserMessage -Message "Invalid choice. Please enter 1, 2, or 3." -Type Error
            }
        }
    } while ($true)
}

# --- Enhanced Auth Handling with User Detection ---
function Initialize-AzAuth {
    <#
    .SYNOPSIS
    Initialize Azure authentication with enhanced environment detection and comprehensive logging
    .DESCRIPTION
    Performs Azure authentication using enhanced environment detection and authentication flow mapping.
    Includes comprehensive logging of the authentication method selected and the reasoning behind it.
    Supports Cloud Shell, MSI, Service Principal, Interactive, and Device Code authentication flows.
    
    Authentication Flow Decision Logic:
    1. Check for existing valid Azure context (unless -Force specified)
    2. Use Get-AuthenticationMode for intelligent environment-based authentication selection
    3. Log authentication method selection with detailed reasoning
    4. Perform authentication with appropriate method and comprehensive error handling
    5. Validate token expiration and refresh if needed
    
    Supported Authentication Methods:
    - Managed Identity: For Azure compute resources with MSI enabled
    - Service Principal: For automation scenarios with client credentials
    - Interactive Browser: For local development and user authentication
    - Device Code: For environments without browser access or as fallback
    #>
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = "Force re-authentication even if valid context exists")]
        [switch]$Force
    )
    
    $verboseEnabled = $VerbosePreference -eq 'Continue'
    
    try {
        Write-UserMessage "Starting Azure authentication initialization..." -Type Verbose
        
        # Store authentication attempt in global context
        $authAttempt = @{
            StartTime = Get-Date
            Method = $null
            Success = $false
            UserIdentity = $null
        }
        $global:ScriptExecutionContext.AuthenticationFlow.Azure = $authAttempt
        
        $context = Get-AzContext -ErrorAction SilentlyContinue
        
        if (-not $context -or $Force) {
            if ($Force) {
                Write-UserMessage -Message "Forcing re-authentication..." -Type Progress
                Write-ErrorLog "Auth" "Forcing Azure re-authentication (user requested)"
            } else {
                Write-UserMessage -Message "No Azure context found. Initiating authentication..." -Type Progress
                Write-ErrorLog "Auth" "No Azure context found, starting authentication process"
            }
            
            # Clear existing context if forced
            if ($Force) {
                try {
                    Clear-AzContext -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Cleared existing Azure context for re-authentication"
                } catch {
                    Write-Verbose "Failed to clear Azure context: $($_.Exception.Message)"
                }
            }
            
            # Enhanced authentication with environment detection and user choice
            Write-ErrorLog "Auth" "Starting enhanced authentication mode detection"
            Write-UserMessage -Message "Analyzing environment for optimal authentication method..." -Type Info
            
            $authMode = Get-AuthenticationMode -Verbose:$verboseEnabled
            
            # Map authentication mode to user-friendly description
            $authMethodDescription = if ($authMode.ContainsKey('Identity') -and $authMode.Identity) {
                "Managed Identity (MSI)"
            } elseif ($authMode.ContainsKey('ServicePrincipal') -and $authMode.ServicePrincipal) {
                "Service Principal (Client ID: $($authMode.Credential.UserName))"
            } elseif ($authMode.ContainsKey('UseDeviceAuthentication') -and $authMode.UseDeviceAuthentication) {
                "Device Code Authentication"
            } else {
                "Interactive Browser Authentication"
            }
            
            $authAttempt.Method = $authMethodDescription
            
            # Log the selected authentication method with reasoning
            Write-ErrorLog "Auth" "Selected authentication method: $authMethodDescription"
            Write-UserMessage -Message "Authentication method selected: $authMethodDescription" -Type Success
            
            # Show authentication flow explanation to user
            if ($authMode.ContainsKey('Identity') -and $authMode.Identity) {
                Write-UserMessage -Message "Using Managed Identity based on MSI environment detection" -Type Info
            } elseif ($authMode.ContainsKey('ServicePrincipal') -and $authMode.ServicePrincipal) {
                Write-UserMessage -Message "Using Service Principal based on available client credentials" -Type Info
            } elseif ($authMode.ContainsKey('UseDeviceAuthentication') -and $authMode.UseDeviceAuthentication) {
                Write-UserMessage -Message "Using Device Code authentication as environment fallback" -Type Info
            } else {
                Write-UserMessage -Message "Using Interactive Browser authentication for local environment" -Type Info
            }
            
            # Perform authentication with error handling
            Write-UserMessage -Message "Initiating Azure authentication..." -Type Progress
            $account = Connect-AzAccount @authMode -ErrorAction Stop
            $global:auditStats.TokenRefreshCount++
            
            # Capture the authenticated user and validate success
            if ($account -and $account.Context -and $account.Context.Account) {
                $global:currentUser = $account.Context.Account.Id
                $authAttempt.UserIdentity = $global:currentUser
                $authAttempt.Success = $true
                
                Write-ErrorLog "Auth" "Successfully authenticated as $($global:currentUser) using $authMethodDescription"
                Write-UserMessage -Message "Authentication successful for user: $($global:currentUser)" -Type Success
            } else {
                Write-ErrorLog "Auth" "Authentication appeared successful but unable to determine user identity"
                Write-UserMessage -Message "Authentication completed but user identity could not be determined" -Type Warning
                $global:currentUser = "Unknown"
                $authAttempt.Success = $true  # Still consider successful since Connect-AzAccount didn't throw
            }
            
            Write-UserMessage -Message "Azure authentication completed successfully" -Type Success
            return $true
        }
        
        # Handle existing context - capture current user and validate token
        if ($context -and $context.Account) {
            $global:currentUser = $context.Account.Id
            $authAttempt.Method = "Existing Context"
            $authAttempt.UserIdentity = $global:currentUser
            $authAttempt.Success = $true
            
            Write-ErrorLog "Auth" "Using existing Azure context for user: $($global:currentUser)"
            Write-UserMessage -Message "Using existing Azure authentication for: $($global:currentUser)" -Type Success
        }
        
        # Enhanced token validation with managed identity support
        try {
            Write-UserMessage "Validating Azure access token..." -Type Verbose
            $token = Get-AzAccessToken -ErrorAction Stop
            
            # Parse expiry time more robustly with managed identity format handling
            $expiryTime = $null
            try {
                if ($token.ExpiresOn -is [DateTime]) {
                    $expiryTime = $token.ExpiresOn
                } elseif ($token.ExpiresOn -is [DateTimeOffset]) {
                    $expiryTime = $token.ExpiresOn.DateTime
                } elseif ($token.ExpiresOn -and $token.ExpiresOn.ToString() -match '^\d+$') {
                    # Handle Unix timestamp format (common with managed identity)
                    $expiryTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$token.ExpiresOn).DateTime
                } elseif ($token.ExpiresOn) {
                    # Try to parse as string
                    $expiryTime = [DateTimeOffset]::Parse($token.ExpiresOn.ToString()).DateTime
                } else {
                    # ExpiresOn is null or empty - common issue with managed identity
                    throw "Token ExpiresOn property is null or invalid - managed identity format issue"
                }
                
                Write-UserMessage "Token expiry time parsed successfully: $expiryTime" -Type Verbose
            } catch {
                # Handle managed identity ExpiresOn format issues
                Write-UserMessage -Message "Token expiration parsing failed: $($_.Exception.Message)" -Type Warning
                Write-ErrorLog "TokenParsing" "ExpiresOn parsing failed for managed identity: $($_.Exception.Message)"
                
                # For managed identity, assume token is valid for default period and continue
                $expiryTime = (Get-Date).AddHours(1)  # Assume 1 hour validity for managed identity
                Write-UserMessage -Message "Using default 1-hour token validity assumption for managed identity" -Type Warning
            }
            
            $timeUntilExpiry = $expiryTime - (Get-Date)
            Write-UserMessage "Time until token expiry: $($timeUntilExpiry.TotalMinutes) minutes" -Type Verbose
            
            # Enhanced token refresh for production (refresh when < 15 minutes remaining)
            if ($timeUntilExpiry.TotalMinutes -lt 15) {
                Write-UserMessage -Message "Token expires in $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) minutes. Performing proactive refresh..." -Type Progress
                
                # Implement retry logic for token refresh
                $maxRetries = 3
                $retryCount = 0
                $refreshSuccess = $false
                
                while (-not $refreshSuccess -and $retryCount -lt $maxRetries) {
                    try {
                        Write-Verbose "Attempting token refresh (attempt $($retryCount + 1) of $maxRetries)"
                        $account = Connect-AzAccount -ErrorAction Stop
                        $refreshSuccess = $true
                        $global:auditStats.TokenRefreshCount++
                        
                        # Update user info on refresh
                        if ($account -and $account.Context -and $account.Context.Account) {
                            $global:currentUser = $account.Context.Account.Id
                        }
                        
                        Write-ErrorLog "Auth" "Token refreshed successfully for $($global:currentUser) (Attempt $($retryCount + 1))"
                        Write-UserMessage -Message "Token refresh completed successfully" -Type Success
                        
                    } catch {
                        $retryCount++
                        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                        Write-ErrorLog "Auth" "Token refresh attempt $retryCount failed: $errorMessage | Retrying in $($retryCount * 2) seconds"
                        
                        if ($retryCount -lt $maxRetries) {
                            Write-UserMessage -Message "Token refresh attempt $retryCount failed. Retrying in $($retryCount * 2) seconds..." -Type Warning
                            Start-Sleep -Seconds ($retryCount * 2)
                        }
                    }
                }
                
                if (-not $refreshSuccess) {
                    Write-ErrorLog "Auth" "Failed to refresh token after $maxRetries attempts"
                    throw "Token refresh failed after multiple attempts. Please check your credentials."
                }
            } else {
                Write-UserMessage "Token is valid for $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) more minutes" -Type Verbose
            }
            
            return $true
        } catch {
            Write-UserMessage -Message "Token validation failed. Attempting re-authentication..." -Type Warning
            
            try {
                $account = Connect-AzAccount -ErrorAction Stop
                $global:auditStats.TokenRefreshCount++
                
                # Update user info on re-auth
                if ($account -and $account.Context -and $account.Context.Account) {
                    $global:currentUser = $account.Context.Account.Id
                }
                
                Write-ErrorLog "Auth" "Re-authentication successful after token validation failure for $($global:currentUser)"
                Write-UserMessage -Message "Re-authentication completed successfully" -Type Success
                return $true
            } catch {
                $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                Write-ErrorLog "Auth" "Re-authentication failed: $errorMessage"
                throw "Re-authentication failed: $errorMessage"
            }
        }
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        $authAttempt.Success = $false
        $authAttempt.Error = $errorMessage
        
        Write-ErrorLog "Auth" "Authentication failed: $errorMessage"
        Write-UserMessage -Message "Authentication failed: $errorMessage" -Type Error
        throw "Authentication failed. Please check your credentials and try again."
    }
}

# Enhanced token validity test with retry mechanisms for production stability
function Test-TokenValidity {
    $maxRetries = 3
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries) {
        try {
            # Test token with basic subscription call
            Get-AzSubscription -ErrorAction Stop | Out-Null
            
            # Additional validation - try to get access token details with managed identity support
            $token = Get-AzAccessToken -ErrorAction Stop
            $expiryTime = $null
            try {
                if ($token.ExpiresOn -is [DateTime]) {
                    $expiryTime = $token.ExpiresOn
                } elseif ($token.ExpiresOn -is [DateTimeOffset]) {
                    $expiryTime = $token.ExpiresOn.DateTime
                } elseif ($token.ExpiresOn -and $token.ExpiresOn.ToString() -match '^\d+$') {
                    # Handle Unix timestamp format (common with managed identity)
                    $expiryTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$token.ExpiresOn).DateTime
                } elseif ($token.ExpiresOn) {
                    # Try to parse as string
                    $expiryTime = [DateTimeOffset]::Parse($token.ExpiresOn.ToString()).DateTime
                } else {
                    # ExpiresOn is null or empty - common issue with managed identity
                    throw "Token ExpiresOn property is null or invalid - managed identity format issue"
                }
            } catch {
                # Handle managed identity ExpiresOn format issues
                Write-Warning "⚠️ Token expiration parsing failed: $($_.Exception.Message)"
                Write-ErrorLog "TokenParsing" "ExpiresOn parsing failed during validation: $($_.Exception.Message)"
                
                # For managed identity, assume token is valid for default period and continue
                $expiryTime = (Get-Date).AddHours(1)  # Assume 1 hour validity for managed identity
                Write-Host "🔄 Using default 1-hour token validity assumption during validation" -ForegroundColor Yellow
            }
            
            $timeUntilExpiry = $expiryTime - (Get-Date)
            
            if ($timeUntilExpiry.TotalMinutes -lt 5) {
                Write-Host "⚠️ Token expires in $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) minutes. Forcing refresh..." -ForegroundColor Yellow
                throw "Token expiring soon - forcing refresh"
            }
            
            Write-ErrorLog "TokenValidation" "Token valid for $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) minutes"
            return $true
            
        } catch {
            $retryCount++
            Write-Host "🔄 Token validation failed (attempt $retryCount/$maxRetries). Re-authenticating..." -ForegroundColor Yellow
            
            try {
                $account = Connect-AzAccount -ErrorAction Stop
                $global:auditStats.TokenRefreshCount++
                
                # Update user info
                if ($account -and $account.Context -and $account.Context.Account) {
                    $global:currentUser = $account.Context.Account.Id
                }
                
                Write-ErrorLog "Auth" "Re-authentication successful after validation failure for $($global:currentUser) (attempt $retryCount)"
                
                # If successful, exit retry loop
                return $true
                
            } catch {
                $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                Write-ErrorLog "Auth" "Re-authentication attempt $retryCount failed: $errorMessage"
                
                if ($retryCount -lt $maxRetries) {
                    Write-Host "⏳ Waiting $($retryCount * 2) seconds before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds ($retryCount * 2)
                } else {
                    Write-ErrorLog "Auth" "Authentication failed after $maxRetries attempts: $errorMessage"
                    throw "Authentication failed after multiple attempts. Please check your credentials and try again."
                }
            }
        }
    }
    
    return $false
}

# --- RBAC Analysis Functions ---
function Get-RBACAssignments {
    param([string]$ResourceId, [string]$KeyVaultName)
    
    $assignments = @()
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope $ResourceId -ErrorAction Stop
        foreach ($assignment in $roleAssignments) {
            # Enhanced null-safe property access for RBAC assignments
            $principalId = if ($assignment.ObjectId) { $assignment.ObjectId } else { "Unknown ObjectId" }
            $principalName = if ($assignment.DisplayName) { $assignment.DisplayName } else { 
                if ($assignment.SignInName) { $assignment.SignInName } else { "Unknown Principal" }
            }
            $roleDefinitionName = if ($assignment.RoleDefinitionName) { $assignment.RoleDefinitionName } else { "Unknown Role" }
            $principalType = if ($assignment.ObjectType) { $assignment.ObjectType } else { "Unknown Type" }
            $scope = if ($assignment.Scope) { $assignment.Scope } else { "Unknown Scope" }
            
            # Log data issues if any critical properties are missing
            if (-not $assignment.ObjectId) {
                Write-DataIssuesLog "RBAC" "RBAC assignment missing ObjectId property" $KeyVaultName
            }
            if (-not $assignment.DisplayName -and -not $assignment.SignInName) {
                Write-DataIssuesLog "RBAC" "RBAC assignment missing DisplayName/SignInName for ObjectId: $principalId" $KeyVaultName
            }
            if (-not $assignment.RoleDefinitionName) {
                Write-DataIssuesLog "RBAC" "RBAC assignment missing RoleDefinitionName for principal: $principalName" $KeyVaultName
            }
            
            $assignments += [PSCustomObject]@{
                PrincipalId = $principalId
                PrincipalName = $principalName
                RoleDefinitionName = $roleDefinitionName
                PrincipalType = $principalType
                Scope = $scope
            }
        }
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        $errorMsg = "Failed to get RBAC assignments for $ResourceId : $errorMessage"
        Write-ErrorLog "RBAC" $errorMsg $KeyVaultName
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
            Write-PermissionsLog "RBAC" "Insufficient permissions to read RBAC assignments" $KeyVaultName
            Write-DataIssuesLog "RBAC" "RBAC assignments not gathered" $KeyVaultName "Insufficient permissions"
        } else {
            Write-DataIssuesLog "RBAC" "RBAC assignments not gathered" $KeyVaultName $_.Exception.Message
        }
    }
    
    return $assignments
}

function Test-RBACPrivileges {
    param($Assignments)
    
    $overPrivileged = @()
    $privilegedRoles = @('Owner', 'Contributor', 'User Access Administrator', 'Key Vault Contributor')
    
    foreach ($assignment in $Assignments) {
        if ($assignment.RoleDefinitionName -in $privilegedRoles) {
            $overPrivileged += "$($assignment.PrincipalName) has '$($assignment.RoleDefinitionName)' role"
        }
    }
    
    return $overPrivileged
}

# --- Enhanced Permissions Validation for Production Environments ---
function Test-SecretsManagementPermissions {
    param([string]$KeyVaultName = "")
    
    $permissionResults = @{
        HasSubscriptionReader = $false
        HasKeyVaultReader = $false
        HasSecretsUser = $false
        HasLogAnalyticsReader = $false
        HasMonitoringReader = $false
        HasDirectoryReaders = $false
        # Workload Analysis specific permissions
        HasKeyVaultSecretsUser = $false
        HasKeyVaultKeysUser = $false  
        HasKeyVaultCertificatesUser = $false
        RequiredPermissions = @()
        MissingPermissions = @()
        RecommendedActions = @()
        WorkloadAnalysisPermissions = @()
    }
    
    try {
        # Get current user context
        $context = Get-AzContext
        if (-not $context) {
            $permissionResults.MissingPermissions += "No Azure context found - authentication required"
            return $permissionResults
        }
        
        # Test Subscription Reader permissions
        try {
            $subscriptions = Get-AzSubscription -ErrorAction Stop
            if ($subscriptions -and $subscriptions.Count -gt 0) {
                $permissionResults.HasSubscriptionReader = $true
                Write-PermissionsLog "SecretsManagement" "Subscription Reader access confirmed" $KeyVaultName
            }
        } catch {
            $permissionResults.MissingPermissions += "Reader role required at subscription level for resource discovery"
            $permissionResults.RecommendedActions += "Assign 'Reader' role at subscription level"
        }
        
        # Test Key Vault Reader permissions by attempting to list Key Vaults
        try {
            $testVaults = Get-AzKeyVault -ErrorAction Stop | Select-Object -First 1
            if ($testVaults) {
                $permissionResults.HasKeyVaultReader = $true
                Write-PermissionsLog "SecretsManagement" "Key Vault Reader access confirmed" $KeyVaultName
            }
        } catch {
            $permissionResults.MissingPermissions += "Key Vault Reader role required for configuration analysis"
            $permissionResults.RecommendedActions += "Assign 'Key Vault Reader' role at subscription or Key Vault level"
        }
        
        # Test Log Analytics Reader access for audit analysis
        try {
            Get-AzOperationalInsightsWorkspace -ErrorAction Stop | Select-Object -First 1 | Out-Null
            $permissionResults.HasLogAnalyticsReader = $true
            Write-PermissionsLog "SecretsManagement" "Log Analytics Reader access confirmed" $KeyVaultName
        } catch {
            $permissionResults.MissingPermissions += "Log Analytics Reader role required for audit log analysis"
            $permissionResults.RecommendedActions += "Assign 'Log Analytics Reader' role for monitoring capabilities"
        }
        
        # Test Monitoring Reader permissions for diagnostic settings
        try {
            # Try to read diagnostic settings for a subscription-level resource
            $subscription = (Get-AzSubscription | Select-Object -First 1)
            if ($subscription) {
                Get-AzDiagnosticSetting -ResourceId "/subscriptions/$($subscription.Id)" -ErrorAction SilentlyContinue | Out-Null
                $permissionResults.HasMonitoringReader = $true
                Write-PermissionsLog "SecretsManagement" "Monitoring Reader access confirmed" $KeyVaultName
            }
        } catch {
            if ($_.Exception.Message -notlike "*does not exist*" -and $_.Exception.Message -notlike "*not found*") {
                $permissionResults.MissingPermissions += "Monitoring Reader role required for diagnostic settings evaluation"
                $permissionResults.RecommendedActions += "Assign 'Monitoring Reader' role for diagnostic analysis"
            } else {
                # If resource not found, we likely have the permission but resource doesn't support diagnostics
                $permissionResults.HasMonitoringReader = $true
            }
        }
        
        # Test workload analysis specific permissions
        if ($KeyVaultName) {
            # Test Key Vault Secrets User permissions for workload analysis
            try {
                Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop | Select-Object -First 1 | Out-Null
                $permissionResults.HasKeyVaultSecretsUser = $true
                $permissionResults.WorkloadAnalysisPermissions += "✅ Key Vault Secrets User - Can analyze secret patterns for workload categorization"
                Write-PermissionsLog "WorkloadAnalysis" "Key Vault Secrets User access confirmed for $KeyVaultName" $KeyVaultName
            } catch {
                if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                    $permissionResults.MissingPermissions += "Key Vault Secrets User role required for secret pattern analysis in workload categorization"
                    $permissionResults.RecommendedActions += "Assign 'Key Vault Secrets User' role for comprehensive workload analysis"
                    $permissionResults.WorkloadAnalysisPermissions += "❌ Key Vault Secrets User - Cannot analyze secret patterns (workload categorization limited)"
                } else {
                    $permissionResults.HasKeyVaultSecretsUser = $true  # Vault might be empty but permission exists
                    $permissionResults.WorkloadAnalysisPermissions += "✅ Key Vault Secrets User - Permission verified (vault may be empty)"
                }
            }
            
            # Test Key Vault Keys User permissions for cryptographic workload analysis  
            try {
                Get-AzKeyVaultKey -VaultName $KeyVaultName -ErrorAction Stop | Select-Object -First 1 | Out-Null
                $permissionResults.HasKeyVaultKeysUser = $true
                $permissionResults.WorkloadAnalysisPermissions += "✅ Key Vault Keys User - Can analyze cryptographic operations"
                Write-PermissionsLog "WorkloadAnalysis" "Key Vault Keys User access confirmed for $KeyVaultName" $KeyVaultName
            } catch {
                if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                    $permissionResults.MissingPermissions += "Key Vault Keys User role recommended for cryptographic workload analysis" 
                    $permissionResults.RecommendedActions += "Consider 'Key Vault Crypto User' role for advanced key operations analysis"
                    $permissionResults.WorkloadAnalysisPermissions += "⚠️ Key Vault Keys User - Cannot analyze key operations (crypto workload analysis limited)"
                } else {
                    $permissionResults.HasKeyVaultKeysUser = $true
                    $permissionResults.WorkloadAnalysisPermissions += "✅ Key Vault Keys User - Permission verified (vault may have no keys)"
                }
            }
            
            # Test Key Vault Certificates User permissions for certificate workload analysis
            try {
                Get-AzKeyVaultCertificate -VaultName $KeyVaultName -ErrorAction Stop | Select-Object -First 1 | Out-Null
                $permissionResults.HasKeyVaultCertificatesUser = $true
                $permissionResults.WorkloadAnalysisPermissions += "✅ Key Vault Certificates User - Can analyze certificate management workloads"
                Write-PermissionsLog "WorkloadAnalysis" "Key Vault Certificates User access confirmed for $KeyVaultName" $KeyVaultName
            } catch {
                if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                    $permissionResults.MissingPermissions += "Key Vault Certificates User role recommended for certificate workload analysis"
                    $permissionResults.RecommendedActions += "Consider 'Key Vault Certificates User' role for SSL/TLS certificate analysis"
                    $permissionResults.WorkloadAnalysisPermissions += "⚠️ Key Vault Certificates User - Cannot analyze certificates (cert workload analysis limited)"
                } else {
                    $permissionResults.HasKeyVaultCertificatesUser = $true
                    $permissionResults.WorkloadAnalysisPermissions += "✅ Key Vault Certificates User - Permission verified (vault may have no certificates)"
                }
            }
        } else {
            $permissionResults.WorkloadAnalysisPermissions += "ℹ️ Workload analysis permissions require specific Key Vault context - will be validated per vault"
        }
        
        # Test Azure AD Directory Readers for identity analysis
        try {
            # Try to read Azure AD service principals (requires Directory Readers)
            Get-AzADServicePrincipal -First 1 -ErrorAction Stop | Out-Null
            $permissionResults.HasDirectoryReaders = $true
            Write-PermissionsLog "SecretsManagement" "Directory Readers access confirmed" $KeyVaultName
        } catch {
            $permissionResults.MissingPermissions += "Directory Readers role required for service principal and managed identity analysis"
            $permissionResults.RecommendedActions += "Assign 'Directory Readers' role in Azure AD for identity analysis"
        }
        
        # Generate permission requirements summary
        $permissionResults.RequiredPermissions = @(
            "Reader role on subscription (for resource discovery)",
            "Key Vault Reader on all Key Vaults (for configuration analysis)", 
            "Monitoring Reader (for diagnostic settings)",
            "Log Analytics Reader (for audit log analysis)",
            "Directory Readers in Azure AD (for identity analysis)"
        )
        
        # Add workload analysis specific requirements 
        if ($KeyVaultName) {
            $permissionResults.RequiredPermissions += @(
                "Key Vault Secrets User on Key Vaults (for secret pattern analysis in workload categorization)",
                "Key Vault Keys User on Key Vaults (for cryptographic workload analysis - optional)",
                "Key Vault Certificates User on Key Vaults (for certificate workload analysis - optional)"
            )
        }
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-ErrorLog "PermissionsValidation" "Error during permissions validation: $errorMessage" $KeyVaultName
    }
    
    return $permissionResults
}

function Test-AdministrativeRoles {
    param([string]$KeyVaultName = "")
    
    $roleResults = @{
        HasOwnerRole = $false
        HasSecurityAdminRole = $false  
        HasPolicyContributorRole = $false
        # Key Vault Administration roles
        HasKeyVaultAdministrator = $false
        HasKeyVaultContributor = $false
        HasUserAccessAdministrator = $false
        RoleValidationErrors = @()
    }
    
    try {
        # Get current user context
        $context = Get-AzContext
        if (-not $context) {
            $roleResults.RoleValidationErrors += "No Azure context found - authentication required"
            return $roleResults
        }
        
        $currentUserId = $context.Account.Id
        
        # Get all role assignments for the current user across accessible scopes
        try {
            $userRoleAssignments = Get-AzRoleAssignment -SignInName $currentUserId -ErrorAction SilentlyContinue
            if (-not $userRoleAssignments) {
                # Try alternative method using ObjectId if available
                $userInfo = Get-AzADUser -UserPrincipalName $currentUserId -ErrorAction SilentlyContinue
                if ($userInfo) {
                    $userRoleAssignments = Get-AzRoleAssignment -ObjectId $userInfo.Id -ErrorAction SilentlyContinue
                }
            }
            
            if ($userRoleAssignments) {
                foreach ($assignment in $userRoleAssignments) {
                    switch ($assignment.RoleDefinitionName) {
                        "Owner" { $roleResults.HasOwnerRole = $true }
                        "Security Admin" { $roleResults.HasSecurityAdminRole = $true }
                        "Policy Contributor" { $roleResults.HasPolicyContributorRole = $true }
                        "Key Vault Administrator" { $roleResults.HasKeyVaultAdministrator = $true }
                        "Key Vault Contributor" { $roleResults.HasKeyVaultContributor = $true }
                        "User Access Administrator" { $roleResults.HasUserAccessAdministrator = $true }
                    }
                }
                Write-PermissionsLog "AdministrativeRoles" "Role validation completed for user: $currentUserId" $KeyVaultName
            } else {
                $roleResults.RoleValidationErrors += "Unable to retrieve role assignments for current user"
            }
        } catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            $roleResults.RoleValidationErrors += "Error checking administrative roles: $errorMessage"
            Write-ErrorLog "AdministrativeRoles" "Error during role validation: $errorMessage" $KeyVaultName
        }
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        $roleResults.RoleValidationErrors += "Error during administrative role validation: $errorMessage"
        Write-ErrorLog "AdministrativeRoles" "Error during administrative role validation: $errorMessage" $KeyVaultName
    }
    
    return $roleResults
}

function Get-MinimumPermissionsReport {
    param(
        $PermissionResults,
        $AdministrativeRoles
    )
    
    # Define color coding function
    function Get-PermissionColor {
        param([bool]$HasPermission)
        if ($HasPermission) { return "#28a745" } # Green for permissions user has
        else { return "#dc3545" } # Red for permissions user does NOT have
    }
    
    $permissionsHtml = @"
    <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
        <h3 style="color: #f57c00; margin-top: 0;">🔐 Minimum Permissions Requirements</h3>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 15px 0;">
            <div>
                <h4 style="color: #1976d2;">📖 For Script Execution (Least Privilege):</h4>
                <ul style="font-size: 0.9em; line-height: 1.4;">
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasSubscriptionReader); margin-bottom: 4px;"><strong>Reader</strong> role on subscription (for discovery) $(if ($PermissionResults.HasSubscriptionReader) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasKeyVaultReader); margin-bottom: 4px;"><strong>Key Vault Reader</strong> on all Key Vaults (for configuration analysis) $(if ($PermissionResults.HasKeyVaultReader) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasMonitoringReader); margin-bottom: 4px;"><strong>Monitoring Reader</strong> (for diagnostic settings) $(if ($PermissionResults.HasMonitoringReader) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasLogAnalyticsReader); margin-bottom: 4px;"><strong>Log Analytics Reader</strong> (for audit log analysis) $(if ($PermissionResults.HasLogAnalyticsReader) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasDirectoryReaders); margin-bottom: 4px;"><strong>Directory Readers</strong> in Azure AD (for identity analysis) $(if ($PermissionResults.HasDirectoryReaders) { '✅' } else { '❌' })</li>
                </ul>
                
                <h4 style="color: #1976d2;">📊 For Workload Analysis (Enhanced Features):</h4>
                <ul style="font-size: 0.9em; line-height: 1.4;">
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasKeyVaultSecretsUser); margin-bottom: 4px;"><strong>Key Vault Secrets User</strong> (for secret pattern analysis) $(if ($PermissionResults.HasKeyVaultSecretsUser) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasKeyVaultKeysUser); margin-bottom: 4px;"><strong>Key Vault Keys User</strong> (for crypto workload analysis) $(if ($PermissionResults.HasKeyVaultKeysUser) { '✅' } elseif ($PermissionResults.HasKeyVaultKeysUser -eq $false) { '❌' } else { '⚠️' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $PermissionResults.HasKeyVaultCertificatesUser); margin-bottom: 4px;"><strong>Key Vault Certificates User</strong> (for cert workload analysis) $(if ($PermissionResults.HasKeyVaultCertificatesUser) { '✅' } elseif ($PermissionResults.HasKeyVaultCertificatesUser -eq $false) { '❌' } else { '⚠️' })</li>
                </ul>
                
                $(if ($PermissionResults.WorkloadAnalysisPermissions.Count -gt 0) {
                    "<div style='background: #e7f3ff; padding: 8px; border-radius: 4px; margin: 10px 0; border-left: 3px solid #0066cc;'>"
                    "<h5 style='color: #0066cc; margin: 0 0 5px 0;'>🔍 Workload Analysis Status:</h5>"
                    "<ul style='font-size: 0.8em; margin: 0; line-height: 1.3;'>"
                    foreach ($status in $PermissionResults.WorkloadAnalysisPermissions) {
                        "<li style='margin-bottom: 2px;'>$status</li>"
                    }
                    "</ul>"
                    "</div>"
                })
                
                <h4 style="color: #1976d2;">🛠️ For Key Vault Administration (Additional Roles):</h4>
                <ul style="font-size: 0.9em; line-height: 1.4;">
                    <li style="color: $(Get-PermissionColor -HasPermission $AdministrativeRoles.HasKeyVaultAdministrator); margin-bottom: 4px;"><strong>Key Vault Administrator</strong> (for full management) $(if ($AdministrativeRoles.HasKeyVaultAdministrator) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $AdministrativeRoles.HasKeyVaultContributor); margin-bottom: 4px;"><strong>Key Vault Contributor</strong> (for configuration changes) $(if ($AdministrativeRoles.HasKeyVaultContributor) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $AdministrativeRoles.HasUserAccessAdministrator); margin-bottom: 4px;"><strong>User Access Administrator</strong> (for RBAC management) $(if ($AdministrativeRoles.HasUserAccessAdministrator) { '✅' } else { '❌' })</li>
                </ul>
            </div>
            
            <div>
                <h4 style="color: #1976d2;">📈 Permission Status Summary:</h4>
                <div style="background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 0.85em;">
                    $(
                        $totalRequired = 5  # Total required permissions for audit
                        $granted = @($PermissionResults.HasSubscriptionReader, $PermissionResults.HasKeyVaultReader, $PermissionResults.HasMonitoringReader, $PermissionResults.HasLogAnalyticsReader, $PermissionResults.HasDirectoryReaders) | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
                        $percentage = [math]::Round(($granted / $totalRequired) * 100, 1)
                        $color = if ($percentage -ge 80) { "#28a745" } elseif ($percentage -ge 60) { "#ffc107" } else { "#dc3545" }
                        
                        "<p><strong>Permissions Status:</strong> <span style='color: $color; font-weight: bold;'>$granted/$totalRequired ($percentage%)</span></p>"
                    )
                    
                    $(if ($PermissionResults.MissingPermissions.Count -gt 0) {
                        "<p><strong>Missing Permissions:</strong></p><ul style='margin: 5px 0; color: #dc3545;'>"
                        foreach ($missing in $PermissionResults.MissingPermissions) {
                            "<li style='font-size: 0.8em;'>$missing</li>"
                        }
                        "</ul>"
                    })
                    
                    $(if ($PermissionResults.RecommendedActions.Count -gt 0) {
                        "<p><strong>Recommended Actions:</strong></p><ul style='margin: 5px 0; color: #0056b3;'>"
                        foreach ($action in $PermissionResults.RecommendedActions) {
                            "<li style='font-size: 0.8em;'>$action</li>"
                        }
                        "</ul>"
                    })
                </div>
                
                <h4 style="color: #1976d2;">👑 Optional Administrative Roles:</h4>
                <ul style="font-size: 0.85em; line-height: 1.3;">
                    <li style="color: $(Get-PermissionColor -HasPermission $AdministrativeRoles.HasOwnerRole); margin-bottom: 3px;"><strong>Owner</strong> on Key Vault resource group $(if ($AdministrativeRoles.HasOwnerRole) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $AdministrativeRoles.HasSecurityAdminRole); margin-bottom: 3px;"><strong>Security Admin</strong> for compliance enforcement $(if ($AdministrativeRoles.HasSecurityAdminRole) { '✅' } else { '❌' })</li>
                    <li style="color: $(Get-PermissionColor -HasPermission $AdministrativeRoles.HasPolicyContributorRole); margin-bottom: 3px;"><strong>Policy Contributor</strong> for Azure Policy $(if ($AdministrativeRoles.HasPolicyContributorRole) { '✅' } else { '❌' })</li>
                </ul>
            </div>
        </div>
        
        <div style="margin-top: 15px; padding: 10px; background: #e9ecef; border-radius: 4px; font-size: 0.85em;">
            <p><strong>Color Legend:</strong> 
                <span style="color: #28a745; font-weight: bold;">✅ Green = Permission Verified</span> | 
                <span style="color: #dc3545; font-weight: bold;">❌ Red = Permission Missing/Not Verified</span> |
                <span style="color: #6c757d;">ℹ️ Gray = Administrative Role (Not Validated)</span>
            </p>
        </div>
    </div>
"@
    
    return $permissionsHtml
}

# --- Service Principal and Managed Identity Analysis ---
function Get-ServicePrincipalsAndManagedIdentities {
    param($Assignments)
    
    $servicePrincipals = @()
    $managedIdentities = @()
    $users = @()
    $groups = @()
    
    foreach ($assignment in $Assignments) {
        switch ($assignment.PrincipalType) {
            'ServicePrincipal' { 
                # Improved logic to determine if this is a managed identity or service principal
                # Managed identities typically have specific naming patterns or can be identified by additional properties
                $isManagedIdentity = $false
                
                # Check for common managed identity naming patterns
                if ($assignment.PrincipalName -match '^(mi-|managed-identity-|identity-)' -or 
                    $assignment.PrincipalName -match '-(mi|managed-identity)(-|$)' -or
                    $assignment.PrincipalName -match 'managed.*identity' -or
                    $assignment.PrincipalName -match 'identity.*managed') {
                    $isManagedIdentity = $true
                }
                
                # Check if the name looks like a system-assigned managed identity (often just a GUID)
                # But be more careful - only treat as managed identity if it's JUST a GUID
                elseif ($assignment.PrincipalName -match '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
                    $isManagedIdentity = $true
                }
                
                if ($isManagedIdentity) {
                    $managedIdentities += "$($assignment.PrincipalName) ($($assignment.PrincipalId)) - $($assignment.RoleDefinitionName) [RBAC]"
                    $global:managedIdentityCount++
                } else {
                    $servicePrincipals += "$($assignment.PrincipalName) ($($assignment.PrincipalId)) - $($assignment.RoleDefinitionName) [RBAC]"
                    $global:serviceProviderCount++
                }
            }
            'User' { 
                $users += "$($assignment.PrincipalName) ($($assignment.PrincipalId)) - $($assignment.RoleDefinitionName) [RBAC]"
            }
            'Group' { 
                $groups += "$($assignment.PrincipalName) ($($assignment.PrincipalId)) - $($assignment.RoleDefinitionName) [RBAC]"
            }
        }
    }
    
    return @{
        ServicePrincipals = $servicePrincipals
        ManagedIdentities = $managedIdentities
        Users = $users
        Groups = $groups
    }
}

# --- Access Policy Analysis ---
function Get-AccessPolicyDetails {
    param($KeyVault)
    
    $accessPolicies = @()
    try {
        $vault = Get-AzKeyVault -VaultName $KeyVault.VaultName -ErrorAction Stop
        if ($vault.AccessPolicies) {
            foreach ($policy in $vault.AccessPolicies) {
                $permissions = @()
                if ($policy.PermissionsToKeys) { $permissions += "Keys[$($policy.PermissionsToKeys -join ',')]" }
                if ($policy.PermissionsToSecrets) { $permissions += "Secrets[$($policy.PermissionsToSecrets -join ',')]" }
                if ($policy.PermissionsToCertificates) { $permissions += "Certs[$($policy.PermissionsToCertificates -join ',')]" }
                
                $accessPolicies += "$($policy.DisplayName) ($($policy.ObjectId)): $($permissions -join ', ')"
            }
        }
    } catch {
        $errorMsg = "Failed to get access policies for $($KeyVault.VaultName): $_"
        Write-ErrorLog "AccessPolicy" $errorMsg $KeyVault.VaultName
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
            Write-PermissionsLog "AccessPolicy" "Insufficient permissions to read access policies" $KeyVault.VaultName
            Write-DataIssuesLog "AccessPolicy" "Access policies not gathered" $KeyVault.VaultName "Insufficient permissions"
        } else {
            Write-DataIssuesLog "AccessPolicy" "Access policies not gathered" $KeyVault.VaultName $_.Exception.Message
        }
    }
    
    return $accessPolicies
}

# --- Network Security Analysis ---
function Get-NetworkSecurityConfig {
    param($KeyVault)
    
    $networkConfig = @{
        PublicNetworkAccess = "Unknown"
        NetworkAclsConfigured = $false
        PrivateEndpointCount = 0
    }
    
    try {
        $vault = Get-AzKeyVault -VaultName $KeyVault.VaultName -ErrorAction Stop
        
        if ($vault.PublicNetworkAccess) {
            $networkConfig.PublicNetworkAccess = $vault.PublicNetworkAccess
        } elseif ($vault.NetworkAcls) {
            $networkConfig.PublicNetworkAccess = if ($vault.NetworkAcls.DefaultAction -eq "Deny") { "Disabled" } else { "Enabled" }
            $networkConfig.NetworkAclsConfigured = $true
        }
        
        # Check for private endpoints
        try {
            $privateEndpoints = Get-AzPrivateEndpoint -ResourceGroupName $KeyVault.ResourceGroupName -ErrorAction SilentlyContinue | 
                Where-Object { $_.PrivateLinkServiceConnections.PrivateLinkServiceId -eq $KeyVault.ResourceId }
            $networkConfig.PrivateEndpointCount = if ($privateEndpoints) { $privateEndpoints.Count } else { 0 }
        } catch {
            Write-DataIssuesLog "NetworkSecurity" "Private endpoint check failed" $KeyVault.VaultName $_.Exception.Message
        }
    } catch {
        $errorMsg = "Failed to get network config for $($KeyVault.VaultName): $_"
        Write-ErrorLog "NetworkSecurity" $errorMsg $KeyVault.VaultName
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
            Write-PermissionsLog "NetworkSecurity" "Insufficient permissions to read network configuration" $KeyVault.VaultName
            Write-DataIssuesLog "NetworkSecurity" "Network configuration not gathered" $KeyVault.VaultName "Insufficient permissions"
        } else {
            Write-DataIssuesLog "NetworkSecurity" "Network configuration not gathered" $KeyVault.VaultName $_.Exception.Message
        }
    }
    
    return $networkConfig
}

# --- Enhanced Diagnostics Analysis ---
function Get-DiagnosticsConfiguration {
    param($ResourceId, $KeyVaultName)
    
    $config = @{
        Enabled = $false
        LogCategories = @()
        MetricCategories = @()
        LogAnalyticsEnabled = $false
        LogAnalyticsWorkspaceName = ""
        EventHubEnabled = $false
        EventHubNamespace = ""
        EventHubName = ""
        StorageAccountEnabled = $false
        StorageAccountName = ""
        # Enhanced validation properties
        HasAuditLogs = $false
        HasPolicyLogs = $false
        CompanyCompliantEventHub = $false
        ComplianceIssues = @()
    }
    try {
        # Enhanced diagnostic settings retrieval with debugging
        Write-UserMessage -Message "Retrieving diagnostic settings for $KeyVaultName..." -Type Debug
        try {
            $rawDiag = Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction Stop
        } catch {
            # If diagnostics retrieval fails, log and return the default config with a data issue
            $err = $_.Exception.Message
            Write-ErrorLog "Diagnostics" "Failed to retrieve diagnostic settings for $ResourceId : $err" $KeyVaultName
            Write-DataIssuesLog "Diagnostics" "Diagnostic settings not gathered" $KeyVaultName $err
            $config.ComplianceIssues += "Cannot validate diagnostic settings - API error or insufficient permissions"
            Write-UserMessage -Message "Diagnostic retrieval failed for $($KeyVaultName): $err" -Type Debug
            return $config
        }

        Write-UserMessage -Message "Raw diagnostic response type: $(if ($rawDiag) { $rawDiag.GetType().Name } else { 'null' }), Count: $(if ($rawDiag) { if ($rawDiag.GetType().IsArray) { if ($rawDiag.PSObject.Properties['Count']) { $rawDiag.PSObject.Properties['Count'].Value } else { 'NoCount' } } elseif ($rawDiag -is [System.Collections.IEnumerable] -and $rawDiag -isnot [string]) { ($rawDiag | Measure-Object).Count } else { 1 } } else { 0 })" -Type Debug

        if ($rawDiag) {
            try {
                $normalized = Normalize-DiagnosticSetting -RawDiag $rawDiag
            } catch {
                Write-UserMessage -Message "Diagnostic normalization failed: $($_.Exception.Message)" -Type Warning
                $normalized = $null
            }

            if ($normalized) {
                # Map normalized keys into the standard $config hashtable
                $config.Enabled = $normalized.Enabled
                $config.LogCategories = @($normalized.LogCategories)
                $config.MetricCategories = @($normalized.MetricCategories)
                $config.LogAnalyticsEnabled = $normalized.LogAnalyticsEnabled
                $config.LogAnalyticsWorkspaceName = $normalized.LogAnalyticsWorkspaceName
                $config.EventHubEnabled = $normalized.EventHubEnabled
                $config.EventHubNamespace = $normalized.EventHubNamespace
                $config.EventHubName = $normalized.EventHubName
                $config.StorageAccountEnabled = $normalized.StorageAccountEnabled
                $config.StorageAccountName = $normalized.StorageAccountName
                $config.HasAuditLogs = $normalized.HasAuditLogs
                $config.HasPolicyLogs = $normalized.HasPolicyLogs
                $config.CompanyCompliantEventHub = $normalized.CompanyCompliantEventHub
                if ($normalized.ComplianceIssues) { $config.ComplianceIssues += $normalized.ComplianceIssues }
                Write-UserMessage -Message "Diagnostic settings normalized and mapped for $KeyVaultName" -Type Debug
            } else {
                Write-UserMessage -Message "No diagnostic settings found for $KeyVaultName" -Type Debug
                $config.ComplianceIssues += "No diagnostic settings configured"
            }
        } else {
            Write-UserMessage -Message "No diagnostic settings found for $KeyVaultName" -Type Debug
            $config.ComplianceIssues += "No diagnostic settings configured"
        }

        # Validate compliance requirements
        if ($config.Enabled) {
            if (-not $config.HasAuditLogs) {
                $config.ComplianceIssues += "Missing audit log categories (AuditEvent, AuditLogs, or Audit)"
            }
            if (-not $config.HasPolicyLogs) {
                $config.ComplianceIssues += "Missing policy evaluation log categories (Policy or AuditPolicyEvaluationDetails)"
            }
            if (-not $config.EventHubEnabled) {
                $config.ComplianceIssues += "Event Hub destination not configured - required for centralized logging"
            }
        } else {
            $config.ComplianceIssues += "Diagnostic settings not enabled"
        }

        # Log final configuration summary
        Write-UserMessage -Message "Diagnostic summary for $KeyVaultName - Enabled: $($config.Enabled), LogAnalytics: $($config.LogAnalyticsEnabled), EventHub: $($config.EventHubEnabled), Storage: $($config.StorageAccountEnabled)" -Type Debug
    } catch {
        $errorMsg = "Failed to get diagnostics for $ResourceId : $_"
        Write-ErrorLog "Diagnostics" $errorMsg $KeyVaultName
        Write-UserMessage -Message "Diagnostic retrieval failed for $KeyVaultName`: $_" -Type Debug
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
            Write-PermissionsLog "Diagnostics" "Insufficient permissions to read diagnostic settings" $KeyVaultName
            Write-DataIssuesLog "Diagnostics" "Diagnostic settings not gathered" $KeyVaultName "Insufficient permissions"
            $config.ComplianceIssues += "Cannot validate diagnostic settings - insufficient permissions"
        } else {
            Write-DataIssuesLog "Diagnostics" "Diagnostic settings not gathered" $KeyVaultName $_.Exception.Message
            $config.ComplianceIssues += "Cannot validate diagnostic settings - API error"
        }
    }
    
    return $config
}

# Helper: Normalize diagnostic settings into a stable hashtable shape (compatible across Az.Monitor versions)
function Normalize-DiagnosticSetting {
    param(
        [Parameter(Mandatory)]
        [object]$RawDiag
    )

    $norm = @{ 
        Enabled = $false
        LogCategories = @()
        MetricCategories = @()
        LogAnalyticsEnabled = $false
        LogAnalyticsWorkspaceName = ""
        EventHubEnabled = $false
        EventHubNamespace = ""
        EventHubName = ""
        StorageAccountEnabled = $false
        StorageAccountName = ""
        HasAuditLogs = $false
        HasPolicyLogs = $false
        CompanyCompliantEventHub = $false
        ComplianceIssues = @()
    }

    if (-not $RawDiag) { return $norm }

    $diagArray = @($RawDiag) | Where-Object { $_ -ne $null }

    foreach ($d in $diagArray) {
        # Workspace / Log Analytics
        if ($d.PSObject.Properties.Name -contains 'WorkspaceId') { $ws = $d.WorkspaceId } 
        elseif ($d.PSObject.Properties.Name -contains 'WorkspaceResourceId') { $ws = $d.WorkspaceResourceId } 
        elseif ($d.PSObject.Properties.Name -contains 'Properties' -and $d.Properties.WorkspaceId) { $ws = $d.Properties.WorkspaceId }
        if ($ws) { $norm.LogAnalyticsEnabled = $true; $norm.LogAnalyticsWorkspaceName = $ws }

        # EventHub / ServiceBus
        if ($d.PSObject.Properties.Name -contains 'EventHubAuthorizationRuleId') { $norm.EventHubEnabled = $true; $norm.EventHubNamespace = ($d.EventHubAuthorizationRuleId -split '/')[([array]::IndexOf(($d.EventHubAuthorizationRuleId -split '/'),'namespaces') + 1)] -as [string] }
        elseif ($d.PSObject.Properties.Name -contains 'ServiceBusRuleId') { $norm.EventHubEnabled = $true; $norm.EventHubNamespace = $d.ServiceBusRuleId }
        elseif ($d.PSObject.Properties.Name -contains 'Properties' -and $d.Properties.EventHubAuthorizationRuleId) { $norm.EventHubEnabled = $true; $norm.EventHubNamespace = ($d.Properties.EventHubAuthorizationRuleId -split '/')[([array]::IndexOf(($d.Properties.EventHubAuthorizationRuleId -split '/'),'namespaces') + 1)] -as [string] }

        if ($d.PSObject.Properties.Name -contains 'EventHubName') { $norm.EventHubName = $d.EventHubName }
        elseif ($d.PSObject.Properties.Name -contains 'Properties' -and $d.Properties.EventHubName) { $norm.EventHubName = $d.Properties.EventHubName }

        # Storage
        if ($d.PSObject.Properties.Name -contains 'StorageAccountId') { $norm.StorageAccountEnabled = -not [string]::IsNullOrEmpty($d.StorageAccountId); $norm.StorageAccountName = ($d.StorageAccountId -split '/')[-1] }
        elseif ($d.PSObject.Properties.Name -contains 'Properties' -and $d.Properties.StorageAccountId) { $norm.StorageAccountEnabled = -not [string]::IsNullOrEmpty($d.Properties.StorageAccountId); $norm.StorageAccountName = ($d.Properties.StorageAccountId -split '/')[-1] }

        # Logs: various property names may exist (Logs, Log, Properties.Logs)
        $logs = $null
        if ($d.PSObject.Properties.Name -contains 'Logs') { $logs = $d.Logs }
        elseif ($d.PSObject.Properties.Name -contains 'Log') { $logs = $d.Log }
        elseif ($d.PSObject.Properties.Name -contains 'Properties' -and $d.Properties.Logs) { $logs = $d.Properties.Logs }
        if ($logs) {
            foreach ($l in @($logs)) {
                if ($l -and $l.PSObject.Properties.Name -contains 'Category') { $norm.LogCategories += $l.Category; if ($l.Category -match 'AuditEvent|AuditLogs|Audit') { $norm.HasAuditLogs = $true } if ($l.Category -match 'Policy|AuditPolicyEvaluationDetails') { $norm.HasPolicyLogs = $true } }
                elseif ($l -and $l.PSObject.Properties.Name -contains 'CategoryName') { $norm.LogCategories += $l.CategoryName; if ($l.CategoryName -match 'AuditEvent|AuditLogs|Audit') { $norm.HasAuditLogs = $true } }
            }
        }

        # Metrics
        $metrics = $null
        if ($d.PSObject.Properties.Name -contains 'Metrics') { $metrics = $d.Metrics }
        elseif ($d.PSObject.Properties.Name -contains 'Metric') { $metrics = $d.Metric }
        elseif ($d.PSObject.Properties.Name -contains 'Properties' -and $d.Properties.Metrics) { $metrics = $d.Properties.Metrics }
        if ($metrics) {
            foreach ($m in @($metrics)) { if ($m -and $m.PSObject.Properties.Name -contains 'Category') { $norm.MetricCategories += $m.Category } }
        }

        # Enabled heuristics
        if ($d.PSObject.Properties.Name -contains 'Enabled') { if ($d.Enabled -eq $true) { $norm.Enabled = $true } }
        else {
            if ($norm.LogCategories.Count -gt 0 -or $norm.MetricCategories.Count -gt 0 -or $norm.LogAnalyticsEnabled -or $norm.EventHubEnabled -or $norm.StorageAccountEnabled) { $norm.Enabled = $true }
        }
    }

    # Unique lists
    $norm.LogCategories = ($norm.LogCategories | Where-Object { $_ } | Select-Object -Unique)
    $norm.MetricCategories = ($norm.MetricCategories | Where-Object { $_ } | Select-Object -Unique)

    # Company policy check for event hub namespace
    if ($norm.EventHubNamespace -and $norm.EventHubNamespace -eq 'InfoSecEventHubwestus') { $norm.CompanyCompliantEventHub = $true } else { if ($norm.EventHubEnabled -and $norm.EventHubNamespace) { $norm.ComplianceIssues += "Event Hub namespace should be 'InfoSecEventHubwestus' but is '$($norm.EventHubNamespace)'" } }

    return $norm
}

# --- Zero Value Explanation Helper ---
function Get-ZeroValueTooltip {
    param(
        [string]$MetricType,
        [int]$Value
    )
    
    if ($Value -eq 0) {
        switch -Regex ($MetricType) {
            "ServicePrincipals" {
                return @"
<div style='display: inline-block; margin-left: 8px; cursor: help;'>
    <span style='font-size: 0.8em; color: #007acc; border-bottom: 1px dashed #007acc;' title='Why Zero Service Principals?
✅ Good Practice: Using managed identities instead of service principals
ℹ️ No external applications accessing Key Vaults
⚡ All access through users with RBAC roles

This is often a positive security indicator showing modern authentication practices.'>❓ Why Zero?</span>
</div>
"@
            }
            "TotalManagedIdentities" {
                return @"
<div style='display: inline-block; margin-left: 8px; cursor: help;'>
    <span style='font-size: 0.8em; color: #007acc; border-bottom: 1px dashed #007acc;' title='Why Zero Managed Identities?
⚠️ Key Vaults may not have managed identities enabled
ℹ️ Using legacy access policies instead of RBAC
🔍 May be permissions issue preventing identity enumeration

Recommended: Enable managed identities for better security and easier management.'>❓ Why Zero?</span>
</div>
"@
            }
            "SystemManagedIdentities" {
                return @"
<div style='display: inline-block; margin-left: 8px; cursor: help;'>
    <span style='font-size: 0.8em; color: #007acc; border-bottom: 1px dashed #007acc;' title='Why Zero System-Assigned Identities?
ℹ️ No Key Vaults have system-assigned managed identities enabled
🔄 May be using user-assigned identities instead
🔑 External service principals used for authentication

System-assigned identities provide automatic lifecycle management.'>❓ Why Zero?</span>
</div>
"@
            }
            "UserManagedIdentities" {
                return @"
<div style='display: inline-block; margin-left: 8px; cursor: help;'>
    <span style='font-size: 0.8em; color: #007acc; border-bottom: 1px dashed #007acc;' title='Why Zero User-Assigned Identities?
ℹ️ No user-assigned managed identities attached to Key Vaults
🔄 May be using system-assigned identities instead
🔑 Using service principals for cross-resource authentication

User-assigned identities allow sharing across multiple resources.'>❓ Why Zero?</span>
</div>
"@
            }
            default {
                return @"
<div style='display: inline-block; margin-left: 8px; cursor: help;'>
    <span style='font-size: 0.8em; color: #007acc; border-bottom: 1px dashed #007acc;' title='Zero Value Detected
This could indicate:
• Configuration not enabled
• Permissions limiting data collection
• Intentional security setting
• Environment still being configured

Check error logs for specific details.'>❓ Why Zero?</span>
</div>
"@
            }
        }
    }
    return ""
}

# --- Real-time CSV Output Functions ---
function Write-VaultResultToCSV {
    <#
    .SYNOPSIS
        Atomically writes a single vault result to the CSV file for real-time output.
    
    .DESCRIPTION
        Appends individual vault analysis results to the CSV file immediately after processing.
        Handles header creation for new files and ensures atomic writing to prevent data loss.
        Supports deduplication checking when ResumeCsvStrict mode is enabled.
    
    .PARAMETER VaultResult
        The vault analysis result object to write to CSV
    
    .PARAMETER CsvPath
        Path to the CSV file
    
    .PARAMETER IsFirstResult
        Whether this is the first result being written (determines if header is needed)
    #>
    param(
        [Parameter(Mandatory=$true)]
        $VaultResult,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvFilePath,
        
        [Parameter(Mandatory=$false)]
        [bool]$IsFirstResult = $false
    )
    
    try {
        # ResumeCsvStrict deduplication check
        if ($ResumeCsvStrict -and $global:csvProcessedSet -and $global:csvProcessedSet.Count -gt 0) {
            $vaultIdentityKeys = Get-IdentityKeys -VaultObject $VaultResult
            $isDuplicate = $false
            
            foreach ($key in $vaultIdentityKeys) {
                if ($global:csvProcessedSet.Contains($key)) {
                    $isDuplicate = $true
                    break
                }
            }
            
            if ($isDuplicate) {
                Write-Host "🔄 Skipping duplicate vault in CSV (ResumeCsvStrict): $($VaultResult.KeyVaultName)" -ForegroundColor Yellow
                Write-ResumeLog "Deduplication" "Skipped duplicate vault in CSV" "Vault: $($VaultResult.KeyVaultName) | ResumeCsvStrict: True"
                return
            }
        }
        
        # Ensure output directory exists
        $csvDir = Split-Path $CsvFilePath -Parent
        if (-not (Test-Path $csvDir)) {
            New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
        }
        
        # Check if CSV file exists and has content
        $csvExists = Test-Path $CsvFilePath
        $needsHeader = $false
        
        if (-not $csvExists) {
            $needsHeader = $true
        } elseif ($IsFirstResult) {
            # In resume mode, check if existing CSV is empty or only has header
            $existingContent = Get-Content $CsvFilePath -ErrorAction SilentlyContinue
            if (-not $existingContent -or $existingContent.Count -le 1) {
                $needsHeader = $true
            }
        }
        
        # Create a temporary file for atomic writing
        $tempCsvPath = "${CsvFilePath}.tmp"
        
        # If we need header and file doesn't exist, write it first
        if ($needsHeader) {
            $VaultResult | Export-Csv -Path $tempCsvPath -NoTypeInformation -Encoding UTF8
            # Move temp file to final location atomically
            Move-Item -Path $tempCsvPath -Destination $CsvFilePath -Force
        } else {
            # Append mode: export to temp file without header, then append to main file
            $VaultResult | Export-Csv -Path $tempCsvPath -NoTypeInformation -Encoding UTF8
            
            # Get content without header (skip first line)
            $contentWithoutHeader = Get-Content $tempCsvPath | Select-Object -Skip 1
            
            # Append to main CSV file
            $contentWithoutHeader | Add-Content -Path $CsvFilePath -Encoding UTF8
            
            # Clean up temp file
            Remove-Item -Path $tempCsvPath -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "✅ Real-time CSV updated: $($VaultResult.KeyVaultName)" -ForegroundColor Gray
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-Host "⚠️ Failed to write real-time CSV for $($VaultResult.KeyVaultName): $errorMessage" -ForegroundColor Yellow
        Write-ErrorLog "CSVRealTime" "Failed to write real-time CSV: $errorMessage" $VaultResult.KeyVaultName
        
        # Clean up temp file if it exists
        if (Test-Path "${CsvPath}.tmp" -ErrorAction SilentlyContinue) {
            Remove-Item -Path "${CsvPath}.tmp" -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Key Vault Workload Analysis ---
function Get-KeyVaultWorkloadAnalysis {
    param($KeyVaultName)
    
    $workloadData = @{
        SecretCount = 0
        KeyCount = 0
        CertificateCount = 0
        ManagedStorageAccountCount = 0
        SecretTypes = @()
        WorkloadCategories = @()
        EnvironmentType = "Unknown"
        PrimaryWorkload = "Not Determined"
        SecurityInsights = @()
        OptimizationRecommendations = @()
        SecretVersioning = @()
        ExpirationAnalysis = @()
        RotationAnalysis = @()
        AppServiceIntegration = @()
        RiskLevel = "Low"
        RiskFactors = @()
        CriticalFindings = @()
    }
    
    try {
        # Count secrets and analyze naming patterns, versioning, and expiration
        $secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop
        $workloadData.SecretCount = $secrets.Count
        
        # Enhanced secret analysis with versioning and expiration
        $secretsWithVersions = 0
        $secretsNearExpiration = 0
        $appServiceSecrets = 0
        $secretsWithoutExpiration = 0
        $currentDate = Get-Date
        $warningThreshold = $currentDate.AddDays(30) # 30 days warning
        
        foreach ($secret in $secrets) {
            try {
                # Get secret versions for versioning analysis
                $secretVersions = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secret.Name -IncludeVersions -ErrorAction SilentlyContinue
                if ($secretVersions -and $secretVersions.Count -gt 1) {
                    $secretsWithVersions++
                }
                
                # Check expiration dates
                if ($secret.Expires) {
                    if ($secret.Expires -le $warningThreshold) {
                        $secretsNearExpiration++
                        $daysUntilExpiration = ($secret.Expires - $currentDate).Days
                        $workloadData.ExpirationAnalysis += "Secret '$($secret.Name)' expires in $daysUntilExpiration days"
                    }
                } else {
                    $secretsWithoutExpiration++
                }
                
                # Check for App Service integration patterns
                if ($secret.Name -match "WEBSITE_|APPSETTING_|SQLAZURECONNSTR_|MYSQLCONNSTR_|CUSTOMCONNSTR_|AzureWebJobsStorage|AzureWebJobsDashboard") {
                    $appServiceSecrets++
                    $workloadData.AppServiceIntegration += "App Service setting: $($secret.Name)"
                }
                
                # Check for Azure Functions integration
                if ($secret.Name -match "AzureWebJobs|FUNCTIONS_|AzureFunctionsJobHost") {
                    $workloadData.AppServiceIntegration += "Azure Functions setting: $($secret.Name)"
                }
                
            } catch {
                Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing secret versions for $($secret.Name)" $KeyVaultName $_.Exception.Message
            }
        }
        
        # Secret versioning insights
        if ($secretsWithVersions -gt 0) {
            $versioningPercentage = [math]::Round(($secretsWithVersions / $secrets.Count) * 100, 1)
            $workloadData.SecretVersioning += "Secret versioning: $secretsWithVersions of $($secrets.Count) secrets have multiple versions ($versioningPercentage%)"
            $workloadData.SecurityInsights += "Good practice: Secret versioning is being used for $versioningPercentage% of secrets"
        } else {
            $workloadData.SecretVersioning += "No secret versioning detected - consider implementing version management for rollback capabilities"
            $workloadData.OptimizationRecommendations += "Implement secret versioning for improved change management and rollback capabilities"
        }
        
        # Expiration analysis insights
        if ($secretsNearExpiration -gt 0) {
            $workloadData.SecurityInsights += "⚠️ $secretsNearExpiration secrets expire within 30 days - rotation needed"
            $workloadData.OptimizationRecommendations += "Implement automated secret rotation for secrets nearing expiration"
        }
        
        if ($secretsWithoutExpiration -gt 0) {
            $workloadData.SecurityInsights += "⚠️ $secretsWithoutExpiration secrets have no expiration date set"
            $workloadData.OptimizationRecommendations += "Set expiration dates on all secrets following principle of least privilege"
        }
        
        # App Service integration insights
        if ($appServiceSecrets -gt 0) {
            $workloadData.SecurityInsights += "✅ Azure App Service/Functions integration detected: $appServiceSecrets Key Vault references"
            $workloadData.OptimizationRecommendations += "Continue using Key Vault references instead of hardcoded secrets in app settings"
        } else {
            $workloadData.OptimizationRecommendations += "Consider using Key Vault references in Azure App Service/Functions for better secret management"
        }
        
        # Analyze secret naming patterns for workload identification
        $databaseSecrets = (@($secrets.Name | Where-Object { $_ -match "db|database|sql|conn|connection" })).Count
        $apiSecrets = (@($secrets.Name | Where-Object { $_ -match "api|key|token|auth" })).Count
        $certSecrets = (@($secrets.Name | Where-Object { $_ -match "cert|certificate|ssl|tls" })).Count
        $storageSecrets = (@($secrets.Name | Where-Object { $_ -match "storage|blob|queue|table" })).Count
        
        # Categorize workload based on secret patterns
        if ($databaseSecrets -gt 0) { $workloadData.WorkloadCategories += "Database Services" }
        if ($apiSecrets -gt 0) { $workloadData.WorkloadCategories += "API Services" }
        if ($certSecrets -gt 0) { $workloadData.WorkloadCategories += "Certificate Management" }
        if ($storageSecrets -gt 0) { $workloadData.WorkloadCategories += "Storage Services" }
        
        # Determine primary workload
        $workloadTypes = @{
            "Database" = $databaseSecrets
            "API" = $apiSecrets
            "Certificate" = $certSecrets
            "Storage" = $storageSecrets
        }
        
        $primaryWorkload = $workloadTypes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
        
        if ($primaryWorkload.Value -gt 0) {
            $workloadData.PrimaryWorkload = "$($primaryWorkload.Key) Services ($($primaryWorkload.Value) secrets)"
        }
        
        # Environment type detection from vault name and tags
        if ($KeyVaultName -match "prod|production") {
            $workloadData.EnvironmentType = "Production"
        } elseif ($KeyVaultName -match "dev|development") {
            $workloadData.EnvironmentType = "Development"
        } elseif ($KeyVaultName -match "test|testing|qa") {
            $workloadData.EnvironmentType = "Testing"
        } elseif ($KeyVaultName -match "stage|staging") {
            $workloadData.EnvironmentType = "Staging"
        }
        
    } catch {
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
            Write-PermissionsLog "WorkloadAnalysis" "Insufficient permissions to list secrets" $KeyVaultName
            $workloadData.SecurityInsights += "Secrets analysis limited due to permissions"
        } else {
            Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing secrets" $KeyVaultName $_.Exception.Message
        }
    }
    
    try {
        # Enhanced key analysis with rotation pattern detection
        $keys = Get-AzKeyVaultKey -VaultName $KeyVaultName -ErrorAction Stop
        $workloadData.KeyCount = $keys.Count
        
        if ($keys.Count -gt 0) {
            $workloadData.WorkloadCategories += "Cryptographic Operations"
            
            # Analyze key rotation patterns
            $keysWithMultipleVersions = 0
            $keysNearExpiration = 0
            $keysWithoutExpiration = 0
            
            foreach ($key in $keys) {
                try {
                    # Get key versions for rotation analysis
                    $keyVersions = Get-AzKeyVaultKey -VaultName $KeyVaultName -Name $key.Name -IncludeVersions -ErrorAction SilentlyContinue
                    if ($keyVersions -and $keyVersions.Count -gt 1) {
                        $keysWithMultipleVersions++
                        
                        # Analyze rotation frequency if multiple versions exist
                        $sortedVersions = $keyVersions | Sort-Object Created -Descending
                        if ($sortedVersions.Count -ge 2) {
                            $timeBetweenRotations = ($sortedVersions[0].Created - $sortedVersions[1].Created).Days
                            if ($timeBetweenRotations -gt 365) {
                                $workloadData.RotationAnalysis += "Key '$($key.Name)' last rotated $timeBetweenRotations days ago - consider more frequent rotation"
                            }
                        }
                    }
                    
                    # Check expiration dates
                    if ($key.Expires) {
                        if ($key.Expires -le $warningThreshold) {
                            $keysNearExpiration++
                            $daysUntilExpiration = ($key.Expires - $currentDate).Days
                            $workloadData.ExpirationAnalysis += "Key '$($key.Name)' expires in $daysUntilExpiration days"
                        }
                    } else {
                        $keysWithoutExpiration++
                    }
                    
                } catch {
                    Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing key versions for $($key.Name)" $KeyVaultName $_.Exception.Message
                }
            }
            
            # Key rotation insights
            if ($keysWithMultipleVersions -gt 0) {
                $rotationPercentage = [math]::Round(($keysWithMultipleVersions / $keys.Count) * 100, 1)
                $workloadData.RotationAnalysis += "Key rotation: $keysWithMultipleVersions of $($keys.Count) keys have been rotated ($rotationPercentage%)"
                $workloadData.SecurityInsights += "Good practice: Key rotation is being performed for $rotationPercentage% of keys"
            } else {
                $workloadData.RotationAnalysis += "No key rotation detected - consider implementing regular key rotation"
                $workloadData.OptimizationRecommendations += "Implement regular key rotation following security best practices (recommended: every 1-2 years)"
            }
            
            # Key expiration insights
            if ($keysNearExpiration -gt 0) {
                $workloadData.SecurityInsights += "⚠️ $keysNearExpiration keys expire within 30 days - rotation needed"
                $workloadData.OptimizationRecommendations += "Plan key rotation for keys nearing expiration"
            }
            
            if ($keysWithoutExpiration -gt 0) {
                $workloadData.SecurityInsights += "ℹ️ $keysWithoutExpiration keys have no expiration date set"
                $workloadData.OptimizationRecommendations += "Consider setting expiration dates on keys to enforce regular rotation"
            }
        }
        
    } catch {
        if ($_.Exception.Message -notlike "*Forbidden*" -and $_.Exception.Message -notlike "*Authorization*") {
            Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing keys" $KeyVaultName $_.Exception.Message
        }
    }
    
    try {
        # Enhanced certificate analysis with expiration and rotation tracking
        $certificates = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -ErrorAction Stop
        $workloadData.CertificateCount = $certificates.Count
        
        if ($certificates.Count -gt 0) {
            $workloadData.WorkloadCategories += "SSL/TLS Certificate Management"
            
            # Analyze certificate expiration and renewal patterns
            $certsNearExpiration = 0
            $certsWithAutoRenewal = 0
            $expiredCerts = 0
            
            foreach ($cert in $certificates) {
                try {
                    # Check certificate expiration
                    if ($cert.Expires) {
                        if ($cert.Expires -le $currentDate) {
                            $expiredCerts++
                            $workloadData.ExpirationAnalysis += "Certificate '$($cert.Name)' has EXPIRED"
                        } elseif ($cert.Expires -le $warningThreshold) {
                            $certsNearExpiration++
                            $daysUntilExpiration = ($cert.Expires - $currentDate).Days
                            $workloadData.ExpirationAnalysis += "Certificate '$($cert.Name)' expires in $daysUntilExpiration days"
                        }
                    }
                    
                    # Get certificate policy to check auto-renewal
                    $certPolicy = Get-AzKeyVaultCertificatePolicy -VaultName $KeyVaultName -Name $cert.Name -ErrorAction SilentlyContinue
                    if ($certPolicy -and $certPolicy.AutoRenew) {
                        $certsWithAutoRenewal++
                    }
                    
                } catch {
                    Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing certificate details for $($cert.Name)" $KeyVaultName $_.Exception.Message
                }
            }
            
            # Certificate insights
            if ($expiredCerts -gt 0) {
                $workloadData.SecurityInsights += "❌ $expiredCerts certificates have EXPIRED - immediate action required"
                $workloadData.OptimizationRecommendations += "Replace expired certificates immediately to maintain security"
            }
            
            if ($certsNearExpiration -gt 0) {
                $workloadData.SecurityInsights += "⚠️ $certsNearExpiration certificates expire within 30 days - renewal needed"
                $workloadData.OptimizationRecommendations += "Renew certificates approaching expiration"
            }
            
            if ($certsWithAutoRenewal -gt 0) {
                $autoRenewalPercentage = [math]::Round(($certsWithAutoRenewal / $certificates.Count) * 100, 1)
                $workloadData.SecurityInsights += "✅ Auto-renewal enabled for $autoRenewalPercentage% of certificates"
            } else {
                $workloadData.OptimizationRecommendations += "Enable auto-renewal for certificates to prevent expiration issues"
            }
        }
        
    } catch {
        if ($_.Exception.Message -notlike "*Forbidden*" -and $_.Exception.Message -notlike "*Authorization*") {
            Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing certificates" $KeyVaultName $_.Exception.Message
        }
    }
    
    try {
        # Analyze managed storage accounts
        $managedStorageAccounts = Get-AzKeyVaultManagedStorageAccount -VaultName $KeyVaultName -ErrorAction Stop
        $workloadData.ManagedStorageAccountCount = $managedStorageAccounts.Count
        
        if ($managedStorageAccounts.Count -gt 0) {
            $workloadData.WorkloadCategories += "Storage Account Key Management"
            $workloadData.SecurityInsights += "✅ Key Vault managed storage accounts: $($managedStorageAccounts.Count) accounts with automatic key rotation"
            $workloadData.OptimizationRecommendations += "Continue using Key Vault for storage account key management to ensure automatic rotation"
        }
        
    } catch {
        if ($_.Exception.Message -notlike "*Forbidden*" -and $_.Exception.Message -notlike "*Authorization*") {
            Write-DataIssuesLog "WorkloadAnalysis" "Error analyzing managed storage accounts" $KeyVaultName $_.Exception.Message
        }
    }
    
    # Generate enhanced security insights based on comprehensive analysis
    $totalItems = $workloadData.SecretCount + $workloadData.KeyCount + $workloadData.CertificateCount
    
    if ($totalItems -eq 0) {
        $workloadData.SecurityInsights += "Empty Key Vault - consider removing if unused"
        $workloadData.OptimizationRecommendations += "Review if this Key Vault is necessary"
    } elseif ($totalItems -lt 5) {
        $workloadData.OptimizationRecommendations += "Low utilization - consider consolidating with other vaults"
    } elseif ($totalItems -gt 100) {
        $workloadData.SecurityInsights += "High item count - monitor for secret sprawl"
        $workloadData.OptimizationRecommendations += "Consider organizing secrets into separate vaults by workload"
    }
    
    if ($workloadData.SecretCount -gt ($workloadData.KeyCount + $workloadData.CertificateCount) * 10) {
        $workloadData.SecurityInsights += "Secret-heavy usage pattern detected"
    }
    
    if ($workloadData.WorkloadCategories.Count -gt 3) {
        $workloadData.OptimizationRecommendations += "Multi-purpose vault detected - consider splitting by workload for better security isolation"
    }
    
    # Best practice recommendations based on Microsoft Azure Key Vault security guidelines
    if ($workloadData.SecretCount -gt 0) {
        $workloadData.OptimizationRecommendations += "Follow Microsoft recommendation: Rotate secrets every 90 days for high-value secrets"
        if ($workloadData.AppServiceIntegration.Count -eq 0) {
            $workloadData.OptimizationRecommendations += "Consider using Key Vault references in Azure App Service instead of hardcoded secrets"
        }
    }
    
    if ($workloadData.KeyCount -gt 0) {
        $workloadData.OptimizationRecommendations += "Best practice: Implement key rotation every 1-2 years for customer-managed keys"
    }
    
    if ($workloadData.CertificateCount -gt 0) {
        $workloadData.OptimizationRecommendations += "Enable certificate auto-renewal to prevent service disruptions from expired certificates"
    }
    
    # Risk Assessment
    $riskScore = 0
    $criticalCount = 0
    
    # High risk factors
    if ($workloadData.SecretCount -eq 0 -and $workloadData.KeyCount -eq 0 -and $workloadData.CertificateCount -eq 0) {
        $workloadData.RiskFactors += "Empty vault - potential unused resource"
        $riskScore += 2
    }
    
    if ($workloadData.SecretCount -gt 100) {
        $workloadData.RiskFactors += "High secret count ($($workloadData.SecretCount)) - monitor for secret sprawl"
        $riskScore += 3
    }
    
    if ($workloadData.CertificateCount -gt 0) {
        $expiredCerts = ($workloadData.ExpirationAnalysis | Where-Object { $_ -like "*EXPIRED*" }).Count
        if ($expiredCerts -gt 0) {
            $workloadData.CriticalFindings += "$expiredCerts certificates have EXPIRED"
            $criticalCount += $expiredCerts
            $riskScore += 5
        }
        
        $nearExpirationCerts = ($workloadData.ExpirationAnalysis | Where-Object { $_ -like "*expires in*" }).Count
        if ($nearExpirationCerts -gt 0) {
            $workloadData.RiskFactors += "$nearExpirationCerts certificates expiring within 30 days"
            $riskScore += 2
        }
    }
    
    if ($workloadData.SecretCount -gt 0) {
        $secretsWithoutExpiration = ($workloadData.ExpirationAnalysis | Where-Object { $_ -like "*no expiration*" }).Count
        if ($secretsWithoutExpiration -gt 0) {
            $workloadData.RiskFactors += "$secretsWithoutExpiration secrets without expiration dates"
            $riskScore += 1
        }
    }
    
    if ($workloadData.KeyCount -gt 0) {
        $keysWithoutExpiration = ($workloadData.ExpirationAnalysis | Where-Object { $_ -like "*no expiration*" }).Count
        if ($keysWithoutExpiration -gt 0) {
            $workloadData.RiskFactors += "$keysWithoutExpiration keys without expiration dates"
            $riskScore += 1
        }
    }
    
    # Determine risk level
    if ($criticalCount -gt 0) {
        $workloadData.RiskLevel = "Critical"
    } elseif ($riskScore -ge 5) {
        $workloadData.RiskLevel = "High"
    } elseif ($riskScore -ge 3) {
        $workloadData.RiskLevel = "Medium"
    } else {
        $workloadData.RiskLevel = "Low"
    }
    
    return $workloadData
}

# --- Over-Privileged Users Analysis ---
function Get-OverPrivilegedUsers {
    param($Assignments)
    
    $overPrivilegedUsers = @()
    
    # Define over-privileged roles (roles with excessive permissions for typical Key Vault operations)
    $overPrivilegedRoles = @(
        'Owner',                           # Full resource management access
        'Contributor',                     # Full resource management except access assignment  
        'User Access Administrator',       # Can manage access to Azure resources
        'Key Vault Administrator',         # Full access to all Key Vault operations (data plane)
        'Key Vault Contributor'            # Can manage Key Vault resources (control plane)
    )
    
    # Define least-privilege roles (appropriate for specific operations)
    $appropriateRoles = @(
        'Reader',                          # Read-only access to resource properties
        'Key Vault Reader',               # Read Key Vault properties without data access
        'Key Vault Secrets User',        # Read secret contents
        'Key Vault Secrets Officer',     # Manage secrets (create, update, delete)
        'Key Vault Certificates User',   # Read certificate contents
        'Key Vault Certificates Officer', # Manage certificates
        'Key Vault Keys User',           # Use keys for crypto operations
        'Key Vault Keys Officer',        # Manage keys (create, update, delete)
        'Key Vault Crypto User',         # Use keys for encryption/decryption
        'Key Vault Crypto Officer',      # Perform crypto operations and manage keys
        'Key Vault Crypto Service Encryption User' # Use customer-managed keys for service encryption
    )
    
    if (-not $Assignments -or $Assignments.Count -eq 0) {
        return @("No RBAC assignments found")
    }
    
    foreach ($assignment in $Assignments) {
        $principalName = if ($assignment.PrincipalName) { $assignment.PrincipalName } else { "Unknown Principal" }
        $principalType = if ($assignment.PrincipalType) { $assignment.PrincipalType } else { "Unknown" }
        $roleName = if ($assignment.RoleDefinitionName) { $assignment.RoleDefinitionName } else { "Unknown Role" }
        
        # Check if this is an over-privileged assignment
        if ($roleName -in $overPrivilegedRoles) {
            $recommendedRole = switch ($roleName) {
                'Owner' { "Key Vault Secrets Officer or Key Vault Keys Officer (based on needs)" }
                'Contributor' { "Key Vault Secrets Officer or Key Vault Keys Officer (based on needs)" }
                'User Access Administrator' { "Key Vault Reader for read-only operations" }
                'Key Vault Administrator' { "Key Vault Secrets Officer, Keys Officer, or Certificates Officer (based on specific needs)" }
                'Key Vault Contributor' { "Key Vault Reader for monitoring, or specific Officer roles for management" }
                default { "More specific Key Vault role" }
            }
            
            $overPrivilegedUsers += "[HIGH] $principalName ($principalType) has '$roleName' - consider '$recommendedRole'"
        }
        # Also identify assignments that could be more specific
        elseif ($roleName -like "*Officer*" -and $principalType -eq "User") {
            $overPrivilegedUsers += "[MEDIUM] $principalName ($principalType) has '$roleName' - verify if 'User' role is sufficient for daily operations"
        }
    }
    
    # Add recommendations if no over-privileged users found
    if ($overPrivilegedUsers.Count -eq 0) {
        # Still provide guidance
        $hasAppropriateRoles = $false
        foreach ($assignment in $Assignments) {
            if ($assignment.RoleDefinitionName -in $appropriateRoles) {
                $hasAppropriateRoles = $true
                break
            }
        }
        
        if ($hasAppropriateRoles) {
            $overPrivilegedUsers += "✅ All RBAC assignments follow least-privilege principles"
        } else {
            $overPrivilegedUsers += "ℹ️ Consider implementing Key Vault-specific RBAC roles for better security"
        }
    }
    
    # Add general best practice recommendations
    $servicePrincipals = $Assignments | Where-Object { $_.PrincipalType -eq "ServicePrincipal" }
    $users = $Assignments | Where-Object { $_.PrincipalType -eq "User" }
    
    if ($users.Count -gt 3) {
        $overPrivilegedUsers += "⚠️ AUDIT: $($users.Count) user accounts have direct access - consider using groups or managed identities"
    }
    
    if ($servicePrincipals.Count -gt 0) {
        $overPrivilegedUsers += "ℹ️ RECOMMENDATION: Consider migrating service principals to managed identities where possible"
    }
    
    return $overPrivilegedUsers
}

# --- Compliance Scoring ---
function Get-ComplianceScore {
    param($VaultData, [string]$Framework = "Microsoft")
    
    $score = 0
    $maxScore = 100
    
    if ($Framework -eq "Microsoft") {
        # Microsoft Security Baseline scoring
        # Core security features (50 points)
        if ($VaultData.SoftDeleteEnabled) { $score += 10 }
        if ($VaultData.PurgeProtectionEnabled) { $score += 15 }
        if ($VaultData.DiagnosticsEnabled) { $score += 15 }
        if ($VaultData.EventHubEnabled) { $score += 10 }
        
        # Access control (30 points)
        if ($VaultData.RBACEnabled) { $score += 15 }
        if ($VaultData.PrivateEndpointCount -gt 0) { $score += 15 }
        
        # Monitoring and compliance (20 points)
        if ($VaultData.LogAnalyticsEnabled) { $score += 10 }
        if ($VaultData.AuditEventEnabled) { $score += 5 }
        if ($VaultData.PolicyEvaluationEnabled) { $score += 5 }
    }
    elseif ($Framework -eq "Company") {
        # Company-specific compliance framework (more stringent)
        # Core security requirements (40 points)
        if ($VaultData.SoftDeleteEnabled) { $score += 8 }
        if ($VaultData.PurgeProtectionEnabled) { $score += 12 }
        if ($VaultData.DiagnosticsEnabled) { $score += 10 }
        if ($VaultData.EventHubEnabled) { $score += 10 }
        
        # Enhanced access control (35 points)
        if ($VaultData.RBACEnabled) { $score += 20 }
        if ($VaultData.PrivateEndpointCount -gt 0) { $score += 15 }
        
        # Advanced monitoring (25 points)
        if ($VaultData.LogAnalyticsEnabled) { $score += 15 }
        if ($VaultData.AuditEventEnabled) { $score += 5 }
        if ($VaultData.PolicyEvaluationEnabled) { $score += 5 }
    }
    
    return [math]::Min($score, $maxScore)
}

function Get-ComplianceStatus {
    param([int]$Score, [string]$Framework = "Microsoft")
    
    if ($Framework -eq "Microsoft") {
        # Microsoft baseline thresholds
        if ($Score -ge 90) { return "Fully Compliant" }
        elseif ($Score -ge 60) { return "Partially Compliant" }
        else { return "Non-Compliant" }
    }
    elseif ($Framework -eq "Company") {
        # Company framework (more stringent thresholds)
        if ($Score -ge 95) { return "Fully Compliant" }
        elseif ($Score -ge 75) { return "Partially Compliant" }
        else { return "Non-Compliant" }
    }
}

# --- Recommendation Engine ---
function New-SecurityRecommendations {
    param($VaultData)
    
    $recommendations = @()
    
    # Core security recommendations with external resources
    if (-not $VaultData.EventHubEnabled) {
        $recommendations += "Enable Event Hub integration for SIEM and external security tools (<a href='https://learn.microsoft.com/azure/key-vault/general/logging' target='_blank'>Microsoft Docs: Key Vault Logging</a>)"
    }
    
    if (-not $VaultData.PurgeProtectionEnabled) {
        $recommendations += "Enable Purge Protection (Microsoft security baseline requirement) (<a href='https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview' target='_blank'>Microsoft Docs: Soft Delete & Purge Protection</a>)"
    }
    
    if (-not $VaultData.LogAnalyticsEnabled) {
        $recommendations += "Integrate with Log Analytics for advanced query capabilities and alerting (<a href='https://learn.microsoft.com/azure/azure-monitor/logs/design-logs-deployment' target='_blank'>Microsoft Docs: Log Analytics Design</a>)"
    }
    
    if ($VaultData.PrivateEndpointCount -eq 0) {
        $recommendations += "Consider Private Endpoints for enhanced network security (<a href='https://learn.microsoft.com/azure/key-vault/general/private-link-service' target='_blank'>Microsoft Docs: Private Link Service</a> | <a href='https://www.cisecurity.org/benchmark/azure' target='_blank'>CIS Azure Benchmark</a>)"
    }
    
    if (-not ($VaultData.PSObject.Properties['SystemAssignedIdentity'] -and $VaultData.SystemAssignedIdentity)) {
        $recommendations += "Enable System Assigned Managed Identity on the Key Vault itself (<a href='https://learn.microsoft.com/azure/key-vault/general/managed-identity' target='_blank'>Microsoft Docs: Managed Identity</a>)"
    }
    
    if (-not $VaultData.RBACEnabled) {
        $recommendations += "Enable RBAC authorization and migrate from access policies (<a href='https://learn.microsoft.com/azure/key-vault/general/rbac-guide' target='_blank'>Microsoft Docs: RBAC Guide</a> | <a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf' target='_blank'>NIST SP 800-53: Access Control</a>)"
    }
    
    # RBAC recommendations with compliance links
    foreach ($overPriv in $VaultData.OverPrivilegedAssignments) {
        $recommendations += "Reduce $overPriv to specific Key Vault role (Key Vault Secrets User, etc.) (<a href='https://learn.microsoft.com/azure/key-vault/general/rbac-guide#azure-built-in-roles-for-key-vault-data-plane-operations' target='_blank'>Built-in Roles Reference</a>)"
    }
    
    # General security enhancements with best practice links
    $recommendations += "Implement secret rotation policies and expiration monitoring (<a href='https://learn.microsoft.com/azure/key-vault/secrets/tutorial-rotation-dual' target='_blank'>Microsoft Docs: Secret Rotation</a> | <a href='https://owasp.org/www-project-application-security-verification-standard/' target='_blank'>OWASP ASVS</a>)"
    $recommendations += "Use Key Vault references in applications instead of storing secrets in configuration (<a href='https://learn.microsoft.com/azure/app-service/app-service-key-vault-references' target='_blank'>App Service Key Vault References</a>)"
    $recommendations += "Enable Key Vault notifications for secret access and changes (<a href='https://learn.microsoft.com/azure/key-vault/general/event-grid-overview' target='_blank'>Key Vault Event Grid Integration</a>)"
    
    return $recommendations
}

# --- OneDrive/SharePoint Upload Integration Functions ---

# Global variables for Graph authentication
$global:graphAccessToken = $null
$global:graphTokenExpiry = $null

function Initialize-GraphAuth {
    <#
    .SYNOPSIS
    Initialize Microsoft Graph authentication with enhanced environment detection
    .DESCRIPTION
    Legacy compatibility wrapper that redirects to the improved Connect-GraphWithStrategy function.
    Maintains backward compatibility while leveraging the enhanced authentication logic with:
    - Intelligent environment detection and authentication method selection
    - Comprehensive verbose logging at each decision point
    - Az.Accounts context auto-detection for tenant/client IDs
    - Robust fallback mechanisms with user-friendly error messages
    - Support for Interactive, App-only, and Device Code authentication flows
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,
        [string]$ClientId,
        [string]$TenantId, 
        [string]$ClientSecret,
        [ValidateSet('Interactive','App','DeviceCode','Auto')]
        [string]$AuthMode = 'Auto'
    )
    
    try {
        $verboseEnabled = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
        
        # Check if MSAL.PS module is available for device code fallback
        if (-not (Get-Module -ListAvailable -Name "MSAL.PS" -ErrorAction SilentlyContinue)) {
            Write-UploadLog "Auth" "MSAL.PS module not available, OneDrive upload disabled" -Context "ModuleCheck"
            return $false
        }
        
        # Check if we have a valid token (unless forced)
        if (-not $Force -and $global:graphAccessToken -and $global:graphTokenExpiry) {
            $timeUntilExpiry = $global:graphTokenExpiry - (Get-Date)
            if ($timeUntilExpiry.TotalMinutes -gt 5) {
                Write-UploadLog "Auth" "Existing Graph token valid for $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) more minutes" -Context "TokenCheck"
                return $true
            }
        }
        
        Write-UploadLog "Auth" "Delegating to improved Connect-GraphWithStrategy function" -Context "AuthMode=$AuthMode|Force=$Force"
        
        # Get scopes for OneDrive/SharePoint file upload
        $scopes = @("Files.ReadWrite", "Files.ReadWrite.All")
        
        # Delegate to the improved Connect-GraphWithStrategy function
        $success = Connect-GraphWithStrategy -AuthMode $AuthMode -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -Scopes $scopes -Verbose:$verboseEnabled
        
        if ($success) {
            Write-UploadLog "Auth" "Graph authentication successful via Connect-GraphWithStrategy" -Context "AuthMode=$AuthMode"
            return $true
        } else {
            Write-UploadLog "Auth" "Graph authentication failed via Connect-GraphWithStrategy" -Context "AuthMode=$AuthMode"
            return $false
        }
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-UploadLog "Auth" "Graph authentication initialization failed: $errorMessage" -Context "AuthMode=$AuthMode"
        Write-Host "❌ Graph authentication failed: $errorMessage" -ForegroundColor Red
        return $false
    }
}

function Test-GraphTokenValidity {
    <#
    .SYNOPSIS
    Test if current Graph token is valid and refresh if needed
    #>
    try {
        if (-not $global:graphAccessToken -or -not $global:graphTokenExpiry) {
            return $false
        }
        
        $timeUntilExpiry = $global:graphTokenExpiry - (Get-Date)
        
        # Refresh token if less than 15 minutes remaining (similar to Az token management)
        if ($timeUntilExpiry.TotalMinutes -lt 15) {
            Write-UploadLog "Auth" "Graph token expires in $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) minutes, refreshing..." -Context "TokenRefresh"
            return Initialize-GraphAuth -Force -Verbose:($VerbosePreference -eq 'Continue')
        }
        
        return $true
        
    } catch {
        Write-UploadLog "Auth" "Graph token validation failed: $_" -Context "TokenValidation"
        return $false
    }
}

function Send-FileToOneDrive {
    <#
    .SYNOPSIS
    Upload a file to OneDrive using Microsoft Graph API
    .DESCRIPTION
    Uploads files to OneDrive with retry logic and comprehensive logging
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$OneDriveFolder,
        
        [string]$FileName = "",
        
        [int]$MaxRetries = 3
    )
    
    try {
        # Validate file exists
        if (-not (Test-Path $FilePath)) {
            Write-UploadLog "Error" "File not found for upload: $FilePath" -FileName $FileName -Context "FileValidation"
            return $null
        }
        
        # Use filename from path if not provided
        if (-not $FileName) {
            $FileName = Split-Path $FilePath -Leaf
        }
        
        # Ensure we have a valid Graph token
        if (-not (Test-GraphTokenValidity)) {
            Write-UploadLog "Error" "No valid Graph token for upload" -FileName $FileName -Context "Authentication"
            return $null
        }
        
        # Prepare file upload
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileSize = $fileBytes.Length
        
        # Build OneDrive path
        $oneDrivePath = if ($OneDriveFolder.EndsWith("/")) { 
            "$OneDriveFolder$FileName" 
        } else { 
            "$OneDriveFolder/$FileName" 
        }
        
        # Microsoft Graph API endpoint for file upload
        $uploadUrl = "https://graph.microsoft.com/v1.0/me/drive/root:$oneDrivePath`:/content"
        
        Write-UploadLog "Start" "Uploading file ($([math]::Round($fileSize/1KB, 1)) KB)" -FileName $FileName -Context "Path=$oneDrivePath"
        
        $retryCount = 0
        $uploadSuccess = $false
        $artifactUrl = $null
        
        while (-not $uploadSuccess -and $retryCount -lt $MaxRetries) {
            try {
                # Upload file using Microsoft Graph API
                $headers = @{
                    'Authorization' = "Bearer $global:graphAccessToken"
                    'Content-Type' = 'application/octet-stream'
                }
                
                $response = Invoke-RestMethod -Uri $uploadUrl -Method Put -Body $fileBytes -Headers $headers -ErrorAction Stop
                
                if ($response -and $response.id) {
                    $uploadSuccess = $true
                    $artifactUrl = if ($response.webUrl) { $response.webUrl } else { "https://onedrive.live.com/?id=$($response.id)" }
                    
                    Write-UploadLog "Success" "File uploaded successfully" -FileName $FileName -Context "Size=$([math]::Round($fileSize/1KB, 1))KB|Attempt=$($retryCount + 1)" -ArtifactUrl $artifactUrl
                    Write-Host "✅ Uploaded: $FileName ($([math]::Round($fileSize/1KB, 1)) KB)" -ForegroundColor Green
                    
                    return @{
                        Success = $true
                        FileName = $FileName
                        Size = $fileSize
                        Url = $artifactUrl
                        OneDrivePath = $oneDrivePath
                    }
                } else {
                    throw "Upload response missing required fields"
                }
                
            } catch {
                $retryCount++
                $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                
                if ($retryCount -lt $MaxRetries) {
                    Write-UploadLog "Retry" "Upload attempt $retryCount failed, retrying: $errorMessage" -FileName $FileName -Context "Attempt=$retryCount"
                    Start-Sleep -Seconds ($retryCount * 2)
                } else {
                    Write-UploadLog "Error" "Upload failed after $MaxRetries attempts: $errorMessage" -FileName $FileName -Context "FinalAttempt"
                    Write-Host "❌ Failed to upload: $FileName after $MaxRetries attempts" -ForegroundColor Red
                }
            }
        }
        
        return $null
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-UploadLog "Error" "Upload function error: $errorMessage" -FileName $FileName -Context "Exception"
        return $null
    }
}

function Send-CheckpointFiles {
    <#
    .SYNOPSIS
    Upload checkpoint and related audit files to OneDrive
    .DESCRIPTION
    Uploads checkpoint files and current logs for walk-away reliability
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckpointPath,
        
        [string]$CsvFilePath = "",
        
        [string]$OneDriveFolder = "/AzureKeyVaultAudit"
    )
    
    try {
        $uploadResults = @()
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $folderWithTimestamp = "$OneDriveFolder/$timestamp"
        
        Write-UploadLog "Start" "Uploading checkpoint files batch" -Context "Folder=$folderWithTimestamp"
        
        # Upload checkpoint file
        if (Test-Path $CheckpointPath) {
            $result = Send-FileToOneDrive -FilePath $CheckpointPath -OneDriveFolder $folderWithTimestamp
            if ($result) { $uploadResults += $result }
        }
        
        # Upload current CSV if it exists and was provided
        if ($CsvFilePath -and (Test-Path $CsvFilePath)) {
            $result = Send-FileToOneDrive -FilePath $CsvFilePath -OneDriveFolder $folderWithTimestamp
            if ($result) { $uploadResults += $result }
        }
        
        # Upload current log files
        $logFiles = @($global:errPath, $global:permissionsPath, $global:dataIssuesPath) | Where-Object { $_ -and (Test-Path $_) }
        foreach ($logFile in $logFiles) {
            $result = Send-FileToOneDrive -FilePath $logFile -OneDriveFolder $folderWithTimestamp
            if ($result) { $uploadResults += $result }
        }
        
        if ($uploadResults.Count -gt 0) {
            Write-UploadLog "Summary" "Checkpoint batch upload completed: $($uploadResults.Count) files" -Context "ResumeInstructions"
            
            # Log resume instructions
            $resumeInstructions = "Files uploaded for resume capability. Download checkpoint file and use -Resume parameter to continue audit from this point."
            Write-UploadLog "Resume" $resumeInstructions -Context "ArtifactCount=$($uploadResults.Count)|Folder=$folderWithTimestamp"
        }
        
        return $uploadResults
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-UploadLog "Error" "Checkpoint batch upload failed: $errorMessage" -Context "Exception"
        return @()
    }
}

function Send-FinalReports {
    <#
    .SYNOPSIS
    Upload final audit reports and logs to OneDrive
    .DESCRIPTION
    Uploads all final audit artifacts for complete documentation
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvFilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$HtmlPath,
        
        [string]$OneDriveFolder = "/AzureKeyVaultAudit"
    )
    
    try {
        $uploadResults = @()
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $folderWithTimestamp = "$OneDriveFolder/Final_$timestamp"
        
        Write-UploadLog "Start" "Uploading final reports batch" -Context "Folder=$folderWithTimestamp"
        
        # Upload CSV report
        if (Test-Path $CsvFilePath) {
            $result = Send-FileToOneDrive -FilePath $CsvFilePath -OneDriveFolder $folderWithTimestamp
            if ($result) { $uploadResults += $result }
        }
        
        # Upload HTML report
        if (Test-Path $HtmlPath) {
            $result = Send-FileToOneDrive -FilePath $HtmlPath -OneDriveFolder $folderWithTimestamp
            if ($result) { $uploadResults += $result }
        }
        
        # Upload all log files
        $logFiles = @($global:errPath, $global:permissionsPath, $global:dataIssuesPath) | Where-Object { $_ -and (Test-Path $_) }
        foreach ($logFile in $logFiles) {
            $result = Send-FileToOneDrive -FilePath $logFile -OneDriveFolder $folderWithTimestamp
            if ($result) { $uploadResults += $result }
        }
        
        # Upload any remaining checkpoint files
        if ($global:executionId) {
            $checkpointPattern = Join-Path $outDir "akv_audit_checkpoint_${global:executionId}_*.json"
            $checkpointFiles = Get-ChildItem -Path $checkpointPattern -ErrorAction SilentlyContinue
            foreach ($checkpointFile in $checkpointFiles) {
                $result = Send-FileToOneDrive -FilePath $checkpointFile.FullName -OneDriveFolder $folderWithTimestamp
                if ($result) { $uploadResults += $result }
            }
        }
        
        if ($uploadResults.Count -gt 0) {
            Write-UploadLog "Summary" "Final reports upload completed: $($uploadResults.Count) files" -Context "CompleteAudit"
            
            # Log completion summary with artifact URLs
            $completionSummary = "Audit completed. All artifacts uploaded for documentation and compliance purposes."
            Write-UploadLog "Complete" $completionSummary -Context "ArtifactCount=$($uploadResults.Count)|Folder=$folderWithTimestamp"
            
            Write-Host "☁️ Final reports uploaded to OneDrive: $($uploadResults.Count) files" -ForegroundColor Green
        }
        
        return $uploadResults
        
    } catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-UploadLog "Error" "Final reports upload failed: $errorMessage" -Context "Exception"
        return @()
    }
}

# --- Single Vault Mode Handler ---
if ($PSBoundParameters.ContainsKey('SingleVault')) {
    Write-Host "🎯 SINGLE VAULT DIAGNOSTICS MODE" -ForegroundColor Cyan
    Write-Host "=".PadRight(50, "=") -ForegroundColor Gray
    Write-Host "Running targeted diagnostics scan for a single Key Vault..." -ForegroundColor Cyan
    
    # Helper function to get vault name for logging (fallback logic)
    function Get-VaultNameForLogging {
        param([string]$FallbackName = "")
        
        if ($kv -and $kv.VaultName) {
            return $kv.VaultName
        } elseif ($VaultName) {
            return $VaultName
        } elseif ($FallbackName) {
            return $FallbackName
        } else {
            return "<unknown>"
        }
    }
    
    # Initialize authentication
    Initialize-AzAuth -Verbose:($VerbosePreference -eq 'Continue')
    Test-TokenValidity
    Write-Host "🔐 Authenticated as: $global:currentUser" -ForegroundColor Green
    
    # Determine output directory
    $outDir = if ($OutputDirectory) { $OutputDirectory } else { Get-DefaultOutputDirectory }
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    
    # Initialize logging
    $global:timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $global:errPath = Join-Path $outDir "KeyVaultAudit_errors_$global:timestamp.log"
    $global:permissionsPath = Join-Path $outDir "KeyVaultAudit_permissions_$global:timestamp.log"
    $global:dataIssuesPath = Join-Path $outDir "KeyVaultAudit_dataissues_$global:timestamp.log"
    
    Write-ErrorLog "Audit" "Starting Azure Key Vault Single Vault Diagnostics - Version 2.2"
    Write-PermissionsLog "Audit" "Single vault audit started for targeted diagnostics"
    Write-DataIssuesLog "Audit" "Single vault data collection started"
    
    # Prompt for vault name if not provided
    if (-not $VaultName) {
        Write-Host ""
        Write-Host "Please provide the Key Vault name for diagnostics scan:" -ForegroundColor Yellow
        do {
            $VaultName = Read-Host "Key Vault Name"
            if (-not $VaultName) {
                Write-Host "❌ Vault name cannot be empty. Please try again." -ForegroundColor Red
            }
        } while (-not $VaultName)
    }
    
    # Prompt for subscription name/ID if not provided
    if (-not $SubscriptionName) {
        Write-Host ""
        Write-Host "Optionally provide the subscription name or ID to speed up vault discovery:" -ForegroundColor Yellow
        Write-Host "  (Leave blank to search across all accessible subscriptions)" -ForegroundColor Gray
        $SubscriptionName = Read-Host "Subscription Name or ID (optional)"
        if ([string]::IsNullOrWhiteSpace($SubscriptionName)) {
            $SubscriptionName = $null
            Write-Host "  ℹ️ Will search across all accessible subscriptions" -ForegroundColor Cyan
        } else {
            Write-Host "  ✅ Will target subscription: $SubscriptionName" -ForegroundColor Green
        }
    }
    
    Write-Host "🔍 Searching for Key Vault: $VaultName" -ForegroundColor Yellow
    
    # Find the specified vault - use targeted subscription if provided, otherwise search all
    $targetVault = $null
    $searchedSubscriptions = 0
    
    try {
        if ($SubscriptionName) {
            # Targeted subscription search
            Write-Host "🎯 Targeting specific subscription: $SubscriptionName" -ForegroundColor Cyan
            
            # Try to find subscription by name or ID
            $targetSubscription = $null
            $allSubscriptions = Get-AzSubscription -ErrorAction Stop
            
            # First try to match by ID (GUID)
            $targetSubscription = $allSubscriptions | Where-Object { $_.Id -eq $SubscriptionName }
            
            # If not found by ID, try to match by name
            if (-not $targetSubscription) {
                $targetSubscription = $allSubscriptions | Where-Object { $_.Name -eq $SubscriptionName }
            }
            
            if (-not $targetSubscription) {
                Write-Host "❌ Subscription '$SubscriptionName' not found or not accessible" -ForegroundColor Red
                Write-Host "   💡 Available subscriptions:" -ForegroundColor Yellow
                $allSubscriptions | ForEach-Object { Write-Host "      - $($_.Name) ($($_.Id))" -ForegroundColor Gray }
                Write-ErrorLog "SingleVault" "Subscription '$SubscriptionName' not found" $VaultName
                exit 1
            }
            
            # Search in the specific subscription
            try {
                Set-AzContext -SubscriptionId $targetSubscription.Id -ErrorAction Stop | Out-Null
                $searchedSubscriptions = 1
                
                Write-Host "  🔍 Searching in subscription: $($targetSubscription.Name)" -ForegroundColor Gray
                
                $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue
                $foundVault = $vaults | Where-Object { $_.VaultName -eq $VaultName }
                
                if ($foundVault) {
                    $targetVault = $foundVault
                    Write-Host "  ✅ Found vault in subscription: $($targetSubscription.Name)" -ForegroundColor Green
                }
            } catch {
                Write-Host "  ⚠️ Cannot access subscription: $($targetSubscription.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
                Write-PermissionsLog "SingleVault" "Cannot access subscription $($targetSubscription.Name)" $VaultName
            }
        } else {
            # Original logic - search across all accessible subscriptions
            $subscriptions = Get-AzSubscription -ErrorAction Stop
            Write-Host "🔄 Searching across $($subscriptions.Count) subscription(s)..." -ForegroundColor Cyan
            
            foreach ($subscription in $subscriptions) {
                try {
                    Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
                    $searchedSubscriptions++
                    
                    Write-Host "  🔍 Searching in subscription: $($subscription.Name)" -ForegroundColor Gray
                    
                    $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue
                    $foundVault = $vaults | Where-Object { $_.VaultName -eq $VaultName }
                    
                    if ($foundVault) {
                        $targetVault = $foundVault
                        Write-Host "  ✅ Found vault in subscription: $($subscription.Name)" -ForegroundColor Green
                        break
                    }
                } catch {
                    Write-Host "  ⚠️ Cannot access subscription: $($subscription.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-PermissionsLog "SingleVault" "Cannot access subscription $($subscription.Name)" $VaultName
                }
            }
        }
    } catch {
        Write-Host "❌ Failed to enumerate subscriptions: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog "SingleVault" "Failed to enumerate subscriptions: $($_.Exception.Message)" $VaultName
        exit 1
    }
    
    if (-not $targetVault) {
        $searchContext = if ($SubscriptionName) { "subscription '$SubscriptionName'" } else { "$searchedSubscriptions subscription(s)" }
        Write-Host "❌ Key Vault '$VaultName' not found in $searchContext" -ForegroundColor Red
        Write-Host "   💡 Please verify:" -ForegroundColor Yellow
        Write-Host "      - Vault name is correct (case-sensitive)" -ForegroundColor Yellow
        if ($SubscriptionName) {
            Write-Host "      - Subscription name/ID is correct" -ForegroundColor Yellow
        }
        Write-Host "      - You have Reader permissions on the vault's resource group or subscription" -ForegroundColor Yellow
        Write-Host "      - Vault exists and is not deleted" -ForegroundColor Yellow
        Write-ErrorLog "SingleVault" "Vault '$VaultName' not found in $searchContext" $VaultName
        exit 1
    }
    
    Write-Host "✅ Successfully located Key Vault: $($targetVault.VaultName)" -ForegroundColor Green
    Write-Host "   📍 Location: $($targetVault.Location)" -ForegroundColor Gray
    Write-Host "   📁 Resource Group: $($targetVault.ResourceGroupName)" -ForegroundColor Gray
    Write-Host "   🆔 Resource ID: $($targetVault.ResourceId)" -ForegroundColor Gray
    Write-Host ""
    
    # Perform comprehensive single vault analysis
    Write-Host "🔬 Performing comprehensive diagnostics analysis..." -ForegroundColor Cyan
    
    # Defensive check: Ensure vault name is available for error logging
    if (-not $VaultName) {
        Write-Host "❌ Error: VaultName not available for analysis" -ForegroundColor Red
        Write-ErrorLog "SingleVault" "VaultName parameter is null or empty" ""
        exit 1
    }
    
    # Get detailed vault information
    try {
        $kvDetail = Get-AzKeyVault -VaultName $targetVault.VaultName -ResourceGroupName $targetVault.ResourceGroupName -ErrorAction Stop
        
        # Create vault object in expected format with defensive checks
        if (-not $kvDetail.VaultName) {
            Write-Host "❌ Error: Retrieved vault has no name property" -ForegroundColor Red
            Write-ErrorLog "SingleVault" "Retrieved vault missing VaultName property" $VaultName
            exit 1
        }
        
        $kv = @{
            VaultName = $kvDetail.VaultName
            ResourceId = $kvDetail.ResourceId
            Location = $kvDetail.Location
            ResourceGroupName = $kvDetail.ResourceGroupName
            EnableSoftDelete = if ($kvDetail.PSObject.Properties['EnableSoftDelete']) { $kvDetail.EnableSoftDelete } else { $null }
            EnablePurgeProtection = if ($kvDetail.PSObject.Properties['EnablePurgeProtection']) { $kvDetail.EnablePurgeProtection } else { $null }
        }
        
        # Validate that vault name is consistently available for logging
        if (-not $kv.VaultName) {
            Write-Host "❌ Error: Vault object has no VaultName property" -ForegroundColor Red
            Write-ErrorLog "SingleVault" "Vault object missing VaultName property" $VaultName
            exit 1
        }
        
        # Get subscription context
        $currentContext = Get-AzContext
        $kvItem = @{
            SubscriptionId = $currentContext.Subscription.Id
            SubscriptionName = $currentContext.Subscription.Name
        }
        
        Write-Host "📊 Analyzing diagnostic settings..." -ForegroundColor Yellow
        $diagnostics = Get-DiagnosticsConfiguration -ResourceId (Get-SafeProperty -Object $kv -PropertyName 'ResourceId') -KeyVaultName (Get-SafeProperty -Object $kv -PropertyName 'VaultName')
        # Defensive: ensure $diagnostics exists even if Get-DiagnosticsConfiguration failed to assign
        if (-not (Get-Variable -Name 'diagnostics' -Scope Local -ErrorAction SilentlyContinue) -or $null -eq $diagnostics) {
            $diagnostics = @{
                Enabled = $false
                LogCategories = @()
                MetricCategories = @()
                LogAnalyticsEnabled = $false
                LogAnalyticsWorkspaceName = ""
                EventHubEnabled = $false
                EventHubNamespace = ""
                EventHubName = ""
                StorageAccountEnabled = $false
                StorageAccountName = ""
                HasAuditLogs = $false
                HasPolicyLogs = $false
                CompanyCompliantEventHub = $false
                ComplianceIssues = @()
            }
        }
        
        Write-Host "🔐 Analyzing RBAC assignments..." -ForegroundColor Yellow
        $rbacAssignments = Get-RBACAssignments -ResourceId (Get-SafeProperty -Object $kv -PropertyName 'ResourceId') -KeyVaultName (Get-SafeProperty -Object $kv -PropertyName 'VaultName')
        
        Write-Host "👥 Analyzing identities..." -ForegroundColor Yellow
        $identityAnalysis = Get-ServicePrincipalsAndManagedIdentities -Assignments $rbacAssignments
        
        Write-Host "🔑 Analyzing access policies..." -ForegroundColor Yellow
        $accessPolicies = Get-AccessPolicyDetails -KeyVault $kv
        
        Write-Host "🌐 Analyzing network configuration..." -ForegroundColor Yellow
        # Fixed function call - was incorrectly calling Get-NetworkConfiguration (which doesn't exist)
        # Now correctly calls Get-NetworkSecurityConfig with the proper parameter
        $networkConfig = Get-NetworkSecurityConfig -KeyVault $kv
        
        Write-Host "📊 Analyzing workload patterns..." -ForegroundColor Yellow
        $workloadAnalysis = Get-KeyVaultWorkloadAnalysis -KeyVaultName $kv.VaultName
        
        Write-Host "🔍 Analyzing over-privileged assignments..." -ForegroundColor Yellow
        $overPrivileged = Get-OverPrivilegedUsers -Assignments $rbacAssignments
        
        Write-Host "🆔 Processing managed identities..." -ForegroundColor Yellow
        # Get connected managed identities (those with RBAC assignments to this vault)
        $connectedManagedIdentities = $identityAnalysis.ManagedIdentities
        
        # Enhanced system assigned identity information with error handling
        $systemAssignedIdentity = "No"
        $systemAssignedPrincipalId = ""
        
        try {
            if ($kv.Identity -and $kv.Identity.Type -eq "SystemAssigned") {
                $systemAssignedIdentity = "Yes"
                if ($kv.Identity.PrincipalId) {
                    $systemAssignedPrincipalId = $kv.Identity.PrincipalId
                } else {
                    Write-DataIssuesLog "Identity" "System-assigned identity has no PrincipalId" $kv.VaultName
                    $systemAssignedPrincipalId = "Identity missing PrincipalId"
                }
            }
        } catch {
            Write-DataIssuesLog "Identity" "Error processing system-assigned identity" $kv.VaultName $_.Exception.Message
            $systemAssignedIdentity = "Error processing identity"
        }
        
        # Enhanced user assigned identities with error handling
        $userAssignedIdentityCount = 0
        $userAssignedIdentityIds = @()
        
        try {
            if ($kv.Identity -and $kv.Identity.UserAssignedIdentities) {
                $userAssignedIdentityCount = $kv.Identity.UserAssignedIdentities.Count
                $userAssignedIdentityIds = $kv.Identity.UserAssignedIdentities.Keys
            }
        } catch {
            Write-DataIssuesLog "Identity" "Error processing user-assigned identities" $kv.VaultName $_.Exception.Message
            $userAssignedIdentityCount = 0
            $userAssignedIdentityIds = @("Error processing user-assigned identities")
        }
        
        Write-Host "📋 Building comprehensive vault data..." -ForegroundColor Yellow
        # Build vault data for compliance assessment (matching main audit structure)
        $vaultData = @{
            KeyVaultName = $kv.VaultName
            DiagnosticsEnabled = if ($diagnostics) { $diagnostics.Enabled } else { $false }
            LogAnalyticsEnabled = if ($diagnostics) { $diagnostics.LogAnalyticsEnabled } else { $false }
            EventHubEnabled = if ($diagnostics) { $diagnostics.EventHubEnabled } else { $false }
            StorageAccountEnabled = if ($diagnostics) { $diagnostics.StorageAccountEnabled } else { $false }
            EnabledLogCategories = if ($diagnostics) { $diagnostics.LogCategories } else { @() }
            SoftDeleteEnabled = if ($kv.PSObject.Properties['EnableSoftDelete']) { $kv.EnableSoftDelete } else { "Unknown" }
            PurgeProtectionEnabled = if ($kv.PSObject.Properties['EnablePurgeProtection']) { $kv.EnablePurgeProtection } else { "Unknown" }
            PublicNetworkAccess = $networkConfig.PublicNetworkAccess
            PrivateEndpointCount = $networkConfig.PrivateEndpointCount
            NetworkAclsConfigured = $networkConfig.NetworkAclsConfigured
            AccessPolicyCount = if ($accessPolicies.PSObject.Properties['Count']) { $accessPolicies.PSObject.Properties['Count'].Value } else { if ($accessPolicies) { ($accessPolicies | Measure-Object).Count } else { 0 } }
            RBACAssignmentCount = if ($rbacAssignments.PSObject.Properties['Count']) { $rbacAssignments.PSObject.Properties['Count'].Value } else { if ($rbacAssignments) { ($rbacAssignments | Measure-Object).Count } else { 0 } }
            ServicePrincipalCount = if ($identityAnalysis.ServicePrincipals.PSObject.Properties['Count']) { $identityAnalysis.ServicePrincipals.PSObject.Properties['Count'].Value } else { if ($identityAnalysis.ServicePrincipals) { ($identityAnalysis.ServicePrincipals | Measure-Object).Count } else { 0 } }
            UserCount = if ($identityAnalysis.Users.PSObject.Properties['Count']) { $identityAnalysis.Users.PSObject.Properties['Count'].Value } else { if ($identityAnalysis.Users) { ($identityAnalysis.Users | Measure-Object).Count } else { 0 } }
            GroupCount = if ($identityAnalysis.Groups.PSObject.Properties['Count']) { $identityAnalysis.Groups.PSObject.Properties['Count'].Value } else { if ($identityAnalysis.Groups) { ($identityAnalysis.Groups | Measure-Object).Count } else { 0 } }
            ConnectedManagedIdentityCount = if ($connectedManagedIdentities.PSObject.Properties['Count']) { $connectedManagedIdentities.PSObject.Properties['Count'].Value } else { if ($connectedManagedIdentities) { ($connectedManagedIdentities | Measure-Object).Count } else { 0 } }
            SecretCount = $workloadAnalysis.SecretCount
            KeyCount = $workloadAnalysis.KeyCount
            CertificateCount = $workloadAnalysis.CertificateCount
            ManagedStorageAccountCount = $workloadAnalysis.ManagedStorageAccountCount
            AuditEventEnabled = if ($diagnostics -and $diagnostics.LogCategories) { "AuditEvent" -in $diagnostics.LogCategories } else { $false }
            PolicyEvaluationEnabled = if ($diagnostics -and $diagnostics.LogCategories) { "AzurePolicyEvaluationDetails" -in $diagnostics.LogCategories } else { $false }
            RBACEnabled = $(if ($rbacAssignments.PSObject.Properties['Count']) { $rbacAssignments.PSObject.Properties['Count'].Value -gt 0 } else { if ($rbacAssignments) { ($rbacAssignments | Measure-Object).Count -gt 0 } else { $false } })
            SystemAssignedIdentity = $systemAssignedIdentity
            OverPrivilegedAssignments = $overPrivileged
            RiskLevel = $workloadAnalysis.RiskLevel
            RiskFactors = $workloadAnalysis.RiskFactors -join " | "
            CriticalFindings = $workloadAnalysis.CriticalFindings -join " | "
        }
        
        Write-Host "🏆 Calculating compliance scores..." -ForegroundColor Yellow
        # Calculate dual compliance frameworks (matching main audit)
        $complianceScore = Get-ComplianceScore -VaultData $vaultData -Framework "Microsoft"
        $companyComplianceScore = Get-ComplianceScore -VaultData $vaultData -Framework "Company"
        $complianceStatus = Get-ComplianceStatus -Score $complianceScore -Framework "Microsoft"
        $companyComplianceStatus = Get-ComplianceStatus -Score $companyComplianceScore -Framework "Company"
        
        Write-Host "💡 Generating security recommendations..." -ForegroundColor Yellow
        
        # Generate recommendations (matching main audit)
        $recommendations = New-SecurityRecommendations -VaultData $vaultData
    }
    catch {
        # Use fallback vault name if kv.VaultName is available, otherwise use parameter VaultName
        $errorVaultName = if ($kv -and $kv.VaultName) { $kv.VaultName } else { $VaultName }
        $displayVaultName = if ($errorVaultName) { "'$errorVaultName'" } else { "<unknown>" }
        
        Write-Host "❌ Failed to analyze vault $displayVaultName`: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog "SingleVault" "Failed to analyze vault: $($_.Exception.Message)" $errorVaultName
        
        # Provide helpful troubleshooting guidance
        Write-Host ""
        Write-Host "💡 Troubleshooting guidance:" -ForegroundColor Yellow
        Write-Host "   - Verify you have the required permissions (Reader role on subscription/vault)" -ForegroundColor Gray
        Write-Host "   - Check that the vault is accessible from your current network location" -ForegroundColor Gray
        Write-Host "   - Ensure Azure PowerShell modules are up to date" -ForegroundColor Gray
        Write-Host "   - Review error logs: $global:errPath" -ForegroundColor Gray
        
        exit 1
    }
    try {
        # Calculate defensive counts before hashtable creation to avoid syntax issues
        $accessPolicyCountSafe = if (($accessPolicies | Get-Member -Name 'Count' -MemberType Properties)) { $accessPolicies.Count } else { ($accessPolicies | Measure-Object).Count }        
        $rbacAssignmentCountSafe = if (($rbacAssignments | Get-Member -Name 'Count' -MemberType Properties)) { $rbacAssignments.Count } else { ($rbacAssignments | Measure-Object).Count }
        $servicePrincipalCountSafe = if (($identityAnalysis.ServicePrincipals | Get-Member -Name 'Count' -MemberType Properties)) { $identityAnalysis.ServicePrincipals.Count } else { ($identityAnalysis.ServicePrincipals | Measure-Object).Count }
        $userCountSafe = if (($identityAnalysis.Users | Get-Member -Name 'Count' -MemberType Properties)) { $identityAnalysis.Users.Count } else { ($identityAnalysis.Users | Measure-Object).Count }
        $groupCountSafe = if (($identityAnalysis.Groups | Get-Member -Name 'Count' -MemberType Properties)) { $identityAnalysis.Groups.Count } else { ($identityAnalysis.Groups | Measure-Object).Count }
        $managedIdentityCountSafe = if (($connectedManagedIdentities | Get-Member -Name 'Count' -MemberType Properties)) { $connectedManagedIdentities.Count } else { ($connectedManagedIdentities | Measure-Object).Count }
        
        # Build comprehensive results (matching main audit structure exactly)
        $auditResult = [PSCustomObject]@{
            SubscriptionId = $kvItem.SubscriptionId
            SubscriptionName = $kvItem.SubscriptionName
            KeyVaultName = $kv.VaultName
            ResourceId = $kv.ResourceId
            Location = $kv.Location
            ResourceGroupName = $kv.ResourceGroupName
            DiagnosticsEnabled = if ($diagnostics) { $diagnostics.Enabled } else { $false }
            EnabledLogCategories = if ($diagnostics -and $diagnostics.LogCategories) { $diagnostics.LogCategories -join "," } else { "" }
            EnabledMetricCategories = if ($diagnostics -and $diagnostics.MetricCategories) { $diagnostics.MetricCategories -join "," } else { "" }
            LogAnalyticsEnabled = if ($diagnostics) { $diagnostics.LogAnalyticsEnabled } else { $false }
            LogAnalyticsWorkspaceName = if ($diagnostics) { $diagnostics.LogAnalyticsWorkspaceName } else { "" }
            EventHubEnabled = if ($diagnostics) { $diagnostics.EventHubEnabled } else { $false }
            EventHubNamespace = if ($diagnostics) { $diagnostics.EventHubNamespace } else { "" }
            EventHubName = if ($diagnostics) { $diagnostics.EventHubName } else { "" }
            StorageAccountEnabled = if ($diagnostics) { $diagnostics.StorageAccountEnabled } else { $false }
            StorageAccountName = if ($diagnostics) { $diagnostics.StorageAccountName } else { "" }
            AccessPolicyCount = $accessPolicyCountSafe
            AccessPolicyDetails = $accessPolicies -join " | "
            RBACRoleAssignments = ($rbacAssignments | ForEach-Object { "$($_.PrincipalName): $($_.RoleDefinitionName)" }) -join " | "
            RBACAssignmentCount = $rbacAssignmentCountSafe
            TotalIdentitiesWithAccess = $rbacAssignmentCountSafe + $accessPolicyCountSafe
            ServicePrincipalCount = $servicePrincipalCountSafe
            UserCount = $userCountSafe
            GroupCount = $groupCountSafe
            ManagedIdentityCount = $managedIdentityCountSafe
            ServicePrincipalDetails = $identityAnalysis.ServicePrincipals -join " | "
            ManagedIdentityDetails = $connectedManagedIdentities -join " | "
            SoftDeleteEnabled = $(if ($kv.PSObject.Properties.Name -contains 'EnableSoftDelete') { $kv.EnableSoftDelete } else { "Unknown" })
            PurgeProtectionEnabled = $(if ($kv.PSObject.Properties.Name -contains 'EnablePurgeProtection') { $kv.EnablePurgeProtection } else { "Unknown" })
            PublicNetworkAccess = $networkConfig.PublicNetworkAccess
            NetworkAclsConfigured = $networkConfig.NetworkAclsConfigured
            PrivateEndpointCount = $networkConfig.PrivateEndpointCount
            SystemAssignedIdentity = $systemAssignedIdentity
            SystemAssignedPrincipalId = $systemAssignedPrincipalId
            UserAssignedIdentityCount = $userAssignedIdentityCount
            UserAssignedIdentityIds = $userAssignedIdentityIds -join ","
            ConnectedManagedIdentityCount = if (($connectedManagedIdentities | Get-Member -Name 'Count' -MemberType Properties)) { $connectedManagedIdentities.Count } else { ($connectedManagedIdentities | Measure-Object).Count }
            ComplianceStatus = $complianceStatus
            ComplianceScore = $complianceScore
            CompanyComplianceScore = $companyComplianceScore
            CompanyComplianceStatus = $companyComplianceStatus
            ComplianceIssues = ""
            ComplianceRecommendations = ($recommendations -join "; ")
            VaultRecommendations = ($recommendations | Select-Object -First 10) -join "; "
            SecurityEnhancements = ($recommendations | Where-Object { $_ -like "*Private*" -or $_ -like "*System*" -or $_ -like "*Log*" -or $_ -like "*secret*" -or $_ -like "*Key Vault*" }) -join "; "
            RBACRecommendations = ($recommendations | Where-Object { $_ -like "*Reduce*" -or $_ -like "*Consider reducing*" -or $_ -like "*Replace*" }) -join "; "
            OverPrivilegedAssignments = $overPrivileged -join "; "
            # Workload Analysis Data
            SecretCount = $workloadAnalysis.SecretCount
            KeyCount = $workloadAnalysis.KeyCount
            CertificateCount = $workloadAnalysis.CertificateCount
            ManagedStorageAccountCount = $workloadAnalysis.ManagedStorageAccountCount
            WorkloadCategories = $workloadAnalysis.WorkloadCategories -join " | "
            EnvironmentType = $workloadAnalysis.EnvironmentType
            PrimaryWorkload = $workloadAnalysis.PrimaryWorkload
            SecurityInsights = $workloadAnalysis.SecurityInsights -join " | "
            OptimizationRecommendations = $workloadAnalysis.OptimizationRecommendations -join " | "
            TotalItems = ($workloadAnalysis.SecretCount + $workloadAnalysis.KeyCount + $workloadAnalysis.CertificateCount)
            # Enhanced Workload Analysis Data
            SecretVersioning = $workloadAnalysis.SecretVersioning -join " | "
            ExpirationAnalysis = $workloadAnalysis.ExpirationAnalysis -join " | "
            RotationAnalysis = $workloadAnalysis.RotationAnalysis -join " | "
            AppServiceIntegration = $workloadAnalysis.AppServiceIntegration -join " | "
            RiskLevel = $workloadAnalysis.RiskLevel
            RiskFactors = $workloadAnalysis.RiskFactors -join " | "
            CriticalFindings = $workloadAnalysis.CriticalFindings -join " | "
            LastAuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ErrorsEncountered = ""
        }
        
        # Create CSV output
        $csvFile = Join-Path $outDir "KeyVaultSingleVault_$($VaultName)_$global:timestamp.csv"
        $auditResult | Export-Csv -Path $csvFile -NoTypeInformation
        
        # Create comprehensive HTML report (matching main audit)
        $htmlFile = Join-Path $outDir "KeyVaultSingleVault_$($VaultName)_$global:timestamp.html"
        $global:auditResults = @($auditResult)
        
        # Build executive summary for single vault with all required fields
        $executiveSummary = @{
            TotalVaults = 1
            TotalKeyVaults = 1
            TOTAL_KEY_VAULTS = 1
            FullyCompliant = if ($complianceStatus -eq "Fully Compliant") { 1 } else { 0 }
            PartiallyCompliant = if ($complianceStatus -eq "Partially Compliant") { 1 } else { 0 }
            NonCompliant = if ($complianceStatus -eq "Non-Compliant") { 1 } else { 0 }
            MicrosoftFullyCompliant = if ($complianceStatus -eq "Fully Compliant") { 1 } else { 0 }
            MicrosoftPartiallyCompliant = if ($complianceStatus -eq "Partially Compliant") { 1 } else { 0 }
            MicrosoftNonCompliant = if ($complianceStatus -eq "Non-Compliant") { 1 } else { 0 }
            CompanyFullyCompliant = if ($companyComplianceStatus -eq "Fully Compliant") { 1 } else { 0 }
            CompanyPartiallyCompliant = if ($companyComplianceStatus -eq "Partially Compliant") { 1 } else { 0 }
            CompanyNonCompliant = if ($companyComplianceStatus -eq "Non-Compliant") { 1 } else { 0 }
            CompliantVaults = if ($complianceStatus -eq "Fully Compliant") { 1 } else { 0 }
            PartiallyCompliantVaults = if ($complianceStatus -eq "Partially Compliant") { 1 } else { 0 }
            NonCompliantVaults = if ($complianceStatus -eq "Non-Compliant") { 1 } else { 0 }
            WithDiagnostics = if ($diagnostics.Enabled) { 1 } else { 0 }
            WithEventHub = if ($diagnostics.EventHubEnabled) { 1 } else { 0 }
            WithLogAnalytics = if ($diagnostics.LogAnalyticsEnabled) { 1 } else { 0 }
            WithStorageAccount = if ($diagnostics.StorageAccountEnabled) { 1 } else { 0 }
            WithPrivateEndpoints = if ($networkConfig.PrivateEndpointCount -gt 0) { 1 } else { 0 }
            UsingRBAC = if ($rbacAssignments.Count -gt 0) { 1 } else { 0 }
            UsingAccessPolicies = if ($accessPolicies.Count -gt 0) { 1 } else { 0 }
            TotalServicePrincipals = $identityAnalysis.ServicePrincipals.Count
            TotalManagedIdentities = if ($connectedManagedIdentities.PSObject.Properties['Count']) { $connectedManagedIdentities.Count } else { ($connectedManagedIdentities | Measure-Object).Count }
            UserManagedIdentities = $userAssignedIdentityCount
            SystemManagedIdentities = if ($systemAssignedIdentity -eq "Yes") { 1 } else { 0 }
            CompliancePercentage = $complianceScore
            AverageComplianceScore = $complianceScore
            HighRiskVaults = if ($complianceScore -lt 60) { 1 } else { 0 }
        }
        
        # Build audit stats for single vault with comprehensive data
        $auditStats = @{
            TotalVaultsDiscovered = 1
            TotalVaultsAnalyzed = 1
            SuccessfulAnalyses = 1
            FailedAnalyses = 0
            TotalSubscriptions = 1
            AuthenticationRefreshes = 0
            ProcessingErrors = 0
            PermissionErrors = 0
        }
        
        # Generate comprehensive HTML report using the unified function
        Write-Host "📄 Generating comprehensive reports..." -ForegroundColor Yellow
        $htmlGenerated = New-ComprehensiveHtmlReport -OutputPath $htmlFile -AuditResults @($auditResult) -ExecutiveSummary $executiveSummary -AuditStats $auditStats -IsPartialResults $false
        
        if (-not $htmlGenerated) {
            Write-Host "❌ Failed to generate comprehensive HTML report" -ForegroundColor Red
            Write-ErrorLog "SingleVault" "Failed to generate HTML report for vault: $($kv.VaultName)" $kv.VaultName
            exit 1
        }
        
        # Display comprehensive results summary
        Write-Host ""
        Write-Host "✅ SINGLE VAULT COMPREHENSIVE AUDIT COMPLETE" -ForegroundColor Green
        Write-Host "=".PadRight(55, "=") -ForegroundColor Gray
        Write-Host "📊 Comprehensive Analysis Summary for: $($kv.VaultName)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "🔬 DIAGNOSTICS ANALYSIS:" -ForegroundColor Yellow
        Write-Host "   Diagnostics Enabled: $(if ($diagnostics.Enabled) { '✅ YES' } else { '❌ NO' })" -ForegroundColor $(if ($diagnostics.Enabled) { 'Green' } else { 'Red' })
        Write-Host "   Log Categories: $(if ($diagnostics.LogCategories -and $diagnostics.LogCategories.PSObject.Properties['Count']) { $diagnostics.LogCategories.PSObject.Properties['Count'].Value } else { if ($diagnostics.LogCategories) { ($diagnostics.LogCategories | Measure-Object).Count } else { 0 } }) enabled" -ForegroundColor Gray
        Write-Host "   Metric Categories: $(if ($diagnostics.MetricCategories -and $diagnostics.MetricCategories.PSObject.Properties['Count']) { $diagnostics.MetricCategories.PSObject.Properties['Count'].Value } else { if ($diagnostics.MetricCategories) { ($diagnostics.MetricCategories | Measure-Object).Count } else { 0 } }) enabled" -ForegroundColor Gray
        Write-Host "   Log Analytics: $(if ($diagnostics.LogAnalyticsEnabled) { '✅ ENABLED' } else { '❌ DISABLED' }) $(if ($diagnostics.LogAnalyticsWorkspaceName) { "($($diagnostics.LogAnalyticsWorkspaceName))" } else { '' })" -ForegroundColor $(if ($diagnostics.LogAnalyticsEnabled) { 'Green' } else { 'Red' })
        Write-Host "   Event Hub: $(if ($diagnostics.EventHubEnabled) { '✅ ENABLED' } else { '❌ DISABLED' }) $(if ($diagnostics.EventHubNamespace) { "($($diagnostics.EventHubNamespace))" } else { '' })" -ForegroundColor $(if ($diagnostics.EventHubEnabled) { 'Green' } else { 'Red' })
        Write-Host "   Storage Account: $(if ($diagnostics.StorageAccountEnabled) { '✅ ENABLED' } else { '❌ DISABLED' }) $(if ($diagnostics.StorageAccountName) { "($($diagnostics.StorageAccountName))" } else { '' })" -ForegroundColor $(if ($diagnostics.StorageAccountEnabled) { 'Green' } else { 'Red' })
        
        Write-Host ""
        Write-Host "🏆 COMPLIANCE ANALYSIS:" -ForegroundColor Yellow
        Write-Host "   Microsoft Framework Score: $complianceScore% ($complianceStatus)" -ForegroundColor $(if ($complianceScore -ge 80) { 'Green' } elseif ($complianceScore -ge 60) { 'Yellow' } else { 'Red' })
        Write-Host "   Company Framework Score: $companyComplianceScore% ($companyComplianceStatus)" -ForegroundColor $(if ($companyComplianceScore -ge 80) { 'Green' } elseif ($companyComplianceScore -ge 60) { 'Yellow' } else { 'Red' })
        
        Write-Host ""
        Write-Host "🔐 ACCESS ANALYSIS:" -ForegroundColor Yellow
        Write-Host "   RBAC Assignments: $($rbacAssignments.Count)" -ForegroundColor Gray
        Write-Host "   Access Policies: $($accessPolicies.Count)" -ForegroundColor Gray
        Write-Host "   Service Principals: $($identityAnalysis.ServicePrincipals.Count)" -ForegroundColor Gray
        Write-Host "   Users: $($identityAnalysis.Users.Count)" -ForegroundColor Gray
        Write-Host "   Groups: $($identityAnalysis.Groups.Count)" -ForegroundColor Gray
        Write-Host "   Managed Identities: $($connectedManagedIdentities.Count)" -ForegroundColor Gray
        Write-Host "   Over-privileged: $($overPrivileged.Count)" -ForegroundColor $(if ($overPrivileged.Count -gt 0) { 'Red' } else { 'Green' })
        
        Write-Host ""
        Write-Host "📦 WORKLOAD ANALYSIS:" -ForegroundColor Yellow
        Write-Host "   Secrets: $($workloadAnalysis.SecretCount)" -ForegroundColor Gray
        Write-Host "   Keys: $($workloadAnalysis.KeyCount)" -ForegroundColor Gray
        Write-Host "   Certificates: $($workloadAnalysis.CertificateCount)" -ForegroundColor Gray
        Write-Host "   Environment Type: $($workloadAnalysis.EnvironmentType)" -ForegroundColor Gray
        Write-Host "   Primary Workload: $($workloadAnalysis.PrimaryWorkload)" -ForegroundColor Gray
        
        # Enhanced workload analysis insights
        if ($workloadAnalysis.SecretVersioning.Count -gt 0) {
            Write-Host "   Secret Versioning: $($workloadAnalysis.SecretVersioning[0])" -ForegroundColor Gray
        }
        
        if ($workloadAnalysis.ExpirationAnalysis.Count -gt 0) {
            $expirationColor = if ($workloadAnalysis.ExpirationAnalysis -join " " -match "expire") { 'Yellow' } else { 'Gray' }
            Write-Host "   Expiration Status: $($workloadAnalysis.ExpirationAnalysis.Count) items need attention" -ForegroundColor $expirationColor
        }
        
        if ($workloadAnalysis.RotationAnalysis.Count -gt 0) {
            Write-Host "   Rotation Status: $($workloadAnalysis.RotationAnalysis[0])" -ForegroundColor Gray
        }
        
        if ($workloadAnalysis.AppServiceIntegration.Count -gt 0) {
            Write-Host "   App Service Integration: $($workloadAnalysis.AppServiceIntegration.Count) Key Vault references detected" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "🌐 NETWORK SECURITY:" -ForegroundColor Yellow
        Write-Host "   Private Endpoints: $($networkConfig.PrivateEndpointCount)" -ForegroundColor Gray
        Write-Host "   Public Network Access: $($networkConfig.PublicNetworkAccess)" -ForegroundColor $(if ($networkConfig.PublicNetworkAccess -eq "Disabled") { 'Green' } else { 'Yellow' })
        Write-Host "   Network ACLs: $(if ($networkConfig.NetworkAclsConfigured) { 'Configured' } else { 'Not Configured' })" -ForegroundColor $(if ($networkConfig.NetworkAclsConfigured) { 'Green' } else { 'Yellow' })
        
        Write-Host ""
        Write-Host "💡 RECOMMENDATIONS:" -ForegroundColor Yellow
        if ($recommendations.Count -gt 0) {
            $recommendations | Select-Object -First 5 | ForEach-Object { Write-Host "   • $_" -ForegroundColor Gray }
            if ($recommendations.Count -gt 5) {
                Write-Host "   ... and $($recommendations.Count - 5) more (see reports for full details)" -ForegroundColor Gray
            }
        } else {
            Write-Host "   ✅ No security recommendations at this time" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "📁 Output Files Generated:" -ForegroundColor Cyan
        Write-Host "   📄 CSV Report: $(Split-Path $csvFile -Leaf)" -ForegroundColor Green
        Write-Host "   🌐 HTML Report: $(Split-Path $htmlFile -Leaf)" -ForegroundColor Green
        Write-Host "   📋 Error Log: $(Split-Path $global:errPath -Leaf)" -ForegroundColor Green
        Write-Host "   🔒 Permissions Log: $(Split-Path $global:permissionsPath -Leaf)" -ForegroundColor Green
        Write-Host "   📊 Data Issues Log: $(Split-Path $global:dataIssuesPath -Leaf)" -ForegroundColor Green
        Write-Host ""
        Write-Host "💾 Output Directory: $outDir" -ForegroundColor Cyan
        
        # Show compliance issues if any
        if ($diagnostics.ComplianceIssues -and $diagnostics.ComplianceIssues.Count -gt 0) {
            Write-Host ""
            Write-Host "⚠️ Compliance Issues Found:" -ForegroundColor Yellow
            foreach ($issue in $diagnostics.ComplianceIssues) {
                Write-Host "   • $issue" -ForegroundColor Yellow
            }
        }
        
        Write-Host ""
        Write-Host "🎯 Single vault diagnostics scan completed successfully!" -ForegroundColor Green
        
        # Upload to cloud if requested
        if ($UploadToCloud) {
            Write-Host ""
            Write-Host "☁️ Uploading single vault results to cloud..." -ForegroundColor Cyan
            $uploadResults = Send-FinalReportsBatch -CsvFilePath $csvFile -HtmlPath $htmlFile
            if ($uploadResults -and $uploadResults.Count -gt 0) {
                Write-Host "✅ Cloud upload completed: $($uploadResults.Count) files uploaded" -ForegroundColor Green
            }
        }
        
        exit 0
        
    } catch {
        # Use fallback vault name if kv.VaultName is available, otherwise use parameter VaultName
        $errorVaultName = if ($kv -and $kv.VaultName) { $kv.VaultName } else { $VaultName }
        $displayVaultName = if ($errorVaultName) { "'$errorVaultName'" } else { "<unknown>" }
        
        Write-Host "❌ Failed to analyze vault $displayVaultName`: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog "SingleVault" "Failed to analyze vault: $($_.Exception.Message)" $errorVaultName
        
        # Provide helpful troubleshooting guidance
        Write-Host ""
        Write-Host "💡 Troubleshooting guidance:" -ForegroundColor Yellow
        Write-Host "   - Verify you have the required permissions (Reader role on subscription/vault)" -ForegroundColor Gray
        Write-Host "   - Check that the vault is accessible from your current network location" -ForegroundColor Gray
        Write-Host "   - Ensure Azure PowerShell modules are up to date" -ForegroundColor Gray
        Write-Host "   - Review error logs: $global:errPath" -ForegroundColor Gray
        
        exit 1
    }
}

# --- Main Discovery and Analysis ---
if ($skipDiscovery) {
    Write-Host "⚡ OPTIMIZED MODE: Using existing master file data" -ForegroundColor Green
    Write-Host "🔄 Skipping subscription discovery and access validation for improved performance" -ForegroundColor Cyan
    
    # Initialize logging
    Write-ErrorLog "Audit" "Starting Azure Key Vault Comprehensive Audit - Version 2.1 (Optimized Mode)"
    Write-PermissionsLog "Audit" "Audit started in optimized mode using master file"
    Write-DataIssuesLog "Audit" "Data collection started from master file"
} else {
    Write-Host "🔍 Starting Key Vault discovery..." -ForegroundColor Yellow

    # Initialize logging
    Write-ErrorLog "Audit" "Starting Azure Key Vault Comprehensive Audit - Version 2.1"
    Write-PermissionsLog "Audit" "Audit started"
    Write-DataIssuesLog "Audit" "Data collection started"

    # Initialize Authentication (Fixed catch blocks)
    Initialize-AzAuth -Verbose:($VerbosePreference -eq 'Continue')
    Test-TokenValidity

    Write-Host "🔐 Authenticated as: $global:currentUser" -ForegroundColor Green
    
    # Determine OneDrive upload behavior based on environment
    Write-Host "🔍 Checking environment for OneDrive upload behavior..." -ForegroundColor Cyan
    $global:environmentInfo = Get-ScriptExecutionEnvironment
    $global:enableOneDriveUpload = $false
    
    Write-Host "   📍 Environment: $($global:environmentInfo.Environment)" -ForegroundColor Gray
    Write-Host "   📝 $($global:environmentInfo.Description)" -ForegroundColor Gray
    
    # Handle OneDrive upload based on environment
    if ($global:environmentInfo.Environment -eq "CloudShell") {
        # Cloud Shell: Enable OneDrive upload by default
        Write-Host "☁️ Initializing OneDrive upload capability for Cloud Shell..." -ForegroundColor Cyan
        if (Get-Command Initialize-GraphAuth -ErrorAction SilentlyContinue) {
            if (Initialize-GraphAuth -Verbose:($VerbosePreference -eq 'Continue')) {
                $global:enableOneDriveUpload = $true
                Write-Host "✅ OneDrive upload ready - files will be uploaded automatically" -ForegroundColor Green
            } else {
                Write-Host "⚠️ OneDrive upload not available - audit will continue with local files only" -ForegroundColor Yellow
            }
        } else {
            Write-Host "⚠️ OneDrive upload functionality not available (Graph modules not found)" -ForegroundColor Gray
        }
    } elseif ($global:environmentInfo.RequireUserConsent) {
        # Local environment: Ask for user consent
        if (Get-Command Initialize-GraphAuth -ErrorAction SilentlyContinue) {
            $userConsent = Get-OneDriveUploadConsent
            if ($userConsent) {
                Write-Host "☁️ Initializing OneDrive upload capability..." -ForegroundColor Cyan
                if (Initialize-GraphAuth -Verbose:($VerbosePreference -eq 'Continue')) {
                    $global:enableOneDriveUpload = $true
                    Write-Host "✅ OneDrive upload ready - files will be uploaded after generation" -ForegroundColor Green
                } else {
                    Write-Host "⚠️ OneDrive authentication failed - audit will continue with local files only" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "ℹ️  OneDrive upload functionality not available (Graph modules not found)" -ForegroundColor Gray
        }
    } else {
        Write-Host "ℹ️  OneDrive upload disabled for this environment" -ForegroundColor Gray
    }
}

# --- Initialize Analysis Variables ---
$restartVaultAnalysis = $false

# --- Output Directory Setup with Cloud Shell Support ---
if (-not $global:pathsInitialized) {
    Write-Host ""
    Write-Host "📁 Configuring output directory..." -ForegroundColor Yellow
    
    # Determine working directory based on environment and user context
    $outDir = Get-WorkingDirectory -OverrideDirectory $PSBoundParameters['OutputDirectory'] -AuthenticatedUser $global:currentUser
    
    # Create the directory
    try {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        Write-Host "✅ Output directory created/verified: $outDir" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to create output directory $outDir : $($_.Exception.Message)" -ForegroundColor Red
        throw "Cannot proceed without valid output directory"
    }
    
    # Update all file paths
    if ($PSBoundParameters.ContainsKey('Resume') -and $global:resumeCsvPath -and (Test-Path $global:resumeCsvPath)) {
        # In resume mode, use the existing CSV file that was resolved by executionId matching
        $csvPath = $global:resumeCsvPath
        Write-Host "🔄 Resume mode: Using existing CSV file for in-place append: $(Split-Path $csvPath -Leaf)" -ForegroundColor Cyan
        Write-ResumeLog "CSVPath" "Using existing CSV for in-place append" "Path: $csvPath"
    } else {
        # Create new CSV file for fresh audit
        $csvPath = Join-Path $outDir "KeyVaultComprehensiveAudit_${timestamp}.csv"
        if ($PSBoundParameters.ContainsKey('Resume')) {
            Write-Host "ℹ️ No existing CSV found for resume, creating new file: $(Split-Path $csvPath -Leaf)" -ForegroundColor Yellow
        }
    }
    $htmlPath = Join-Path $outDir "KeyVaultComprehensiveAudit_${timestamp}.html"
    
    # Handle restart vault analysis scenario - create fresh CSV instead of resuming
    if ($restartVaultAnalysis) {
        Write-Host "🔄 Creating fresh CSV file for restarted vault analysis..." -ForegroundColor Cyan
        # Generate new timestamp for fresh analysis
        $restartTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $csvPath = Join-Path $outDir "KeyVaultComprehensiveAudit_RESTART_${restartTimestamp}.csv"
        $htmlPath = Join-Path $outDir "KeyVaultComprehensiveAudit_RESTART_${restartTimestamp}.html"
        Write-Host "📄 Fresh CSV file: $(Split-Path $csvPath -Leaf)" -ForegroundColor Green
        
        # Clear any existing audit results and reset statistics for fresh analysis
        $global:auditResults = @()
        $global:auditStats = @{
            SuccessfulVaults = 0
            SkippedVaults = 0
            ProcessingErrors = 0
            PermissionErrors = 0
            TotalRetries = 0
            TokenRefreshCount = 0
        }
        Write-Host "🧹 Cleared previous audit results for fresh analysis" -ForegroundColor Yellow
    }
    
    # Update log paths and move any existing temp logs
    $newErrPath = Join-Path $outDir "KeyVaultAudit_errors_${timestamp}.log"
    $newPermissionsPath = Join-Path $outDir "KeyVaultAudit_permissions_${timestamp}.log"
    $newDataIssuesPath = Join-Path $outDir "KeyVaultAudit_dataissues_${timestamp}.log"
    
    # Move temporary logs to final location
    try {
        if (Test-Path $global:errPath -ErrorAction SilentlyContinue) {
            Move-Item -Path $global:errPath -Destination $newErrPath -ErrorAction SilentlyContinue
        }
        if (Test-Path $global:permissionsPath -ErrorAction SilentlyContinue) {
            Move-Item -Path $global:permissionsPath -Destination $newPermissionsPath -ErrorAction SilentlyContinue
        }
        if (Test-Path $global:dataIssuesPath -ErrorAction SilentlyContinue) {
            Move-Item -Path $global:dataIssuesPath -Destination $newDataIssuesPath -ErrorAction SilentlyContinue
        }
    } catch {
        # If move fails, just start fresh logs
        Write-Host "⚠️  Could not move temporary logs, starting fresh log files" -ForegroundColor Yellow
    }
    
    # Update global path variables
    $global:errPath = $newErrPath
    $global:permissionsPath = $newPermissionsPath
    $global:dataIssuesPath = $newDataIssuesPath
    $global:pathsInitialized = $true
    
    Write-Host "📄 Report files will be saved as:" -ForegroundColor Cyan
    Write-Host "   CSV: $csvPath" -ForegroundColor Gray
    Write-Host "   HTML: $htmlPath" -ForegroundColor Gray
    Write-Host "   Logs: $outDir" -ForegroundColor Gray
    Write-Host ""
}

# --- Enhanced Prerequisites Validation with Comprehensive RBAC Checks ---
Write-Host "📋 Checking comprehensive prerequisites..." -ForegroundColor Yellow
Write-Host "   🔍 Validating PowerShell modules..." -ForegroundColor Cyan

# Verify all modules are properly loaded
$modules = @('Az.Accounts', 'Az.KeyVault', 'Az.Resources', 'Az.Monitor', 'Az.Security')
$moduleStatus = @{}
foreach ($module in $modules) {
    try {
        $importedModule = Get-Module -Name $module -ErrorAction SilentlyContinue
        if ($importedModule) {
            Write-Host "   ✅ $module v$($importedModule.Version) loaded" -ForegroundColor Green
            $moduleStatus[$module] = $true
        } else {
            Write-Host "   ⚠️  $module not loaded, attempting import..." -ForegroundColor Yellow
            Import-Module $module -Force -ErrorAction Stop
            Write-Host "   ✅ $module imported successfully" -ForegroundColor Green
            $moduleStatus[$module] = $true
        }
    } catch {
        Write-Host "   ❌ Failed to load $module : $($_.Exception.Message)" -ForegroundColor Red
        $moduleStatus[$module] = $false
    }
}

if (-not $skipDiscovery) {
    Write-Host "   🔐 Testing Azure authentication..." -ForegroundColor Cyan  
    # Validate current user context
    try {
        $context = Get-AzContext -ErrorAction Stop
        if ($context -and $context.Account) {
            Write-Host "   ✅ Authenticated as: $($context.Account.Id)" -ForegroundColor Green
            $global:currentUser = $context.Account.Id
        } else {
            Write-Host "   ❌ No valid authentication context found" -ForegroundColor Red
            throw "Authentication validation failed"
        }
    } catch {
        Write-Host "   ❌ Authentication validation failed: $($_.Exception.Message)" -ForegroundColor Red
        throw "Cannot proceed without valid Azure authentication"
    }

    Write-Host "   🏢 Verifying subscription access..." -ForegroundColor Cyan
# Test subscription-level permissions
try {
    $subscriptions = Get-AzSubscription -ErrorAction Stop
    if ($subscriptions) {
        Write-Host "   ✅ Found $($subscriptions.Count) accessible subscription(s)" -ForegroundColor Green
        Write-Host "   📊 Testing Reader permissions on subscriptions..." -ForegroundColor Cyan
        
        $subscriptionErrors = 0
        foreach ($sub in $subscriptions | Select-Object -First 3) {
            try {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
                Get-AzResourceGroup -ErrorAction Stop | Select-Object -First 1 | Out-Null
                Write-Host "   ✅ Reader access confirmed for: $($sub.Name)" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Limited access to subscription: $($sub.Name)" -ForegroundColor Yellow
                $subscriptionErrors++
            }
        }
        
        if ($subscriptionErrors -eq 0) {
            Write-Host "   ✅ Subscription permissions validated" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Some subscription permissions limited - audit may be incomplete" -ForegroundColor Yellow
        }
    } else {
        throw "No accessible subscriptions found"
    }
} catch {
    Write-Host "   ❌ Subscription access validation failed: $($_.Exception.Message)" -ForegroundColor Red
    throw "Cannot proceed without subscription access"
}

Write-Host "   🔑 Checking Key Vault permissions..." -ForegroundColor Cyan
# Test Key Vault Reader access
try {
    $testKeyVaults = Get-AzKeyVault -ErrorAction Stop | Select-Object -First 2
    if ($testKeyVaults) {
        Write-Host "   ✅ Found $($testKeyVaults.Count) Key Vault(s) for testing permissions" -ForegroundColor Green
        
        $vaultErrors = 0
        foreach ($vault in $testKeyVaults) {
            try {
                $vaultDetails = Get-AzKeyVault -VaultName $vault.VaultName -ErrorAction Stop
                Write-Host "   ✅ Key Vault Reader access confirmed: $($vault.VaultName)" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Limited access to Key Vault: $($vault.VaultName)" -ForegroundColor Yellow
                $vaultErrors++
            }
        }
        
        if ($vaultErrors -eq 0) {
            Write-Host "   ✅ Key Vault permissions validated" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Some Key Vault permissions limited - detailed analysis may be incomplete" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ⚠️  No Key Vaults found for permission testing" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ⚠️  Key Vault permission validation inconclusive: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "   📋 Audit will attempt Key Vault discovery during execution" -ForegroundColor Cyan
}

Write-Host "   📊 Testing monitoring access..." -ForegroundColor Cyan
# Verify diagnostic settings permissions
try {
    if ($testKeyVaults) {
        $monitoringErrors = 0
        foreach ($vault in $testKeyVaults | Select-Object -First 1) {
            try {
                Get-AzDiagnosticSetting -ResourceId $vault.ResourceId -ErrorAction Stop | Out-Null
                Write-Host "   ✅ Monitoring Reader access confirmed: $($vault.VaultName)" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Limited monitoring access: $($vault.VaultName)" -ForegroundColor Yellow
                $monitoringErrors++
            }
        }
        
        if ($monitoringErrors -eq 0) {
            Write-Host "   ✅ Monitoring permissions validated" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Limited monitoring permissions - diagnostic analysis may be incomplete" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "   ⚠️  Monitoring permission validation inconclusive" -ForegroundColor Yellow
}

Write-Host "   🛡️ Validating security permissions..." -ForegroundColor Cyan
# Check Security Reader capabilities  
try {
    Get-AzSecurityContact -ErrorAction SilentlyContinue | Out-Null
    Write-Host "   ✅ Security Reader permissions available" -ForegroundColor Green
} catch {
    Write-Host "   ⚠️  Security Reader permissions limited - compliance scoring may be affected" -ForegroundColor Yellow
}

Write-Host "   👥 Checking RBAC analysis permissions..." -ForegroundColor Cyan
# Test role assignment enumeration
try {
    if ($testKeyVaults) {
        $rbacErrors = 0
        foreach ($vault in $testKeyVaults | Select-Object -First 1) {
            try {
                $roleAssignments = Get-AzRoleAssignment -Scope $vault.ResourceId -ErrorAction Stop
                Write-Host "   ✅ RBAC Reader access confirmed: $($vault.VaultName)" -ForegroundColor Green
            } catch {
                Write-Host "   ⚠️  Limited RBAC access: $($vault.VaultName)" -ForegroundColor Yellow
                $rbacErrors++
            }
        }
        
        if ($rbacErrors -eq 0) {
            Write-Host "   ✅ RBAC analysis permissions validated" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Limited RBAC permissions - identity analysis may be incomplete" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "   ⚠️  RBAC permission validation inconclusive" -ForegroundColor Yellow
}

Write-Host "   🏷️ Validating identity permissions..." -ForegroundColor Cyan
# Check managed identity and service principal access
try {
    $managedIdentities = Get-AzUserAssignedIdentity -ErrorAction SilentlyContinue | Select-Object -First 1
    $serviceprincipals = Get-AzADServicePrincipal -First 1 -ErrorAction SilentlyContinue
    if ($managedIdentities -or $serviceprincipals) {
        Write-Host "   ✅ Identity Reader permissions available" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Identity permissions may be limited" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ⚠️  Identity permission validation inconclusive" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "📋 Prerequisites validation completed" -ForegroundColor Green
Write-Host "✅ Minimum required permissions validated - proceeding with audit" -ForegroundColor Green
Write-Host "🔐 Authenticated as: $global:currentUser" -ForegroundColor Green
} else {
    # In optimized mode, set up minimal authentication for report generation
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($context -and $context.Account) {
        $global:currentUser = $context.Account.Id
    } else {
        $global:currentUser = "Unknown (optimized mode)"
    }
    Write-Host "🔐 Using existing authentication context: $global:currentUser" -ForegroundColor Green
}

# Initialize audit results (global for checkpoint access)
if (-not $global:auditResults) {
    $global:auditResults = @()
}
$executiveSummary = @{
    TotalSubscriptions = 0
    TotalKeyVaults = 0
    FullyCompliant = 0
    PartiallyCompliant = 0
    NonCompliant = 0
    CompliantVaults = 0
    PartiallyCompliantVaults = 0
    NonCompliantVaults = 0
    CompliancePercentage = 0
    AverageComplianceScore = 0
    CompanyAverageScore = 0
    CompanyComplianceScore = 0
    # Microsoft Framework Compliance
    MicrosoftFullyCompliant = 0
    MicrosoftPartiallyCompliant = 0
    MicrosoftNonCompliant = 0
    # Company Framework Compliance  
    CompanyFullyCompliant = 0
    CompanyPartiallyCompliant = 0
    CompanyNonCompliant = 0
    # Identity Analysis
    TotalServicePrincipals = 0
    TotalManagedIdentities = 0
    UserManagedIdentities = 0
    SystemManagedIdentities = 0
    # Configuration Analysis
    WithDiagnostics = 0
    WithEventHub = 0
    WithLogAnalytics = 0
    WithStorageAccount = 0
    WithPrivateEndpoints = 0
    WithSystemIdentity = 0
    UsingRBAC = 0
    UsingAccessPolicies = 0
    HighRiskVaults = 0
}

# Check for existing master discovery file in Resume or ProcessPartial mode
$allKeyVaults = @()
$subscriptions = @()
$usingMasterFile = $false
$restartVaultAnalysis = $false
$testModeEarlyTermination = $false
$subscriptionIndex = 0
# Note: $skipDiscovery is now set by the scan mode selection logic above

if ($PSBoundParameters.ContainsKey('Resume') -or $PSBoundParameters.ContainsKey('ProcessPartial') -or $mode -eq "ResumeMaster" -or $mode -eq "ResumeCheckpoint") {
    # Check if master file was already loaded in checkpoint handling
    if ($global:usesMasterFileWithoutCheckpoint -and $global:masterDataForOptimizedMode) {
        Write-Host "✅ Using master file data from optimized mode (already loaded)" -ForegroundColor Green
        $masterData = $global:masterDataForOptimizedMode
    } else {
        Write-Host "🔍 Checking for existing discovery master file..." -ForegroundColor Cyan
        $masterData = Import-DiscoveryMaster -OutputDirectory $outDir
    }
    
    if ($masterData) {
        Write-Host "📂 Master discovery file found - subscriptions and vaults will be loaded from file" -ForegroundColor Green
        
        # Only skip discovery if user chose ResumeMaster mode or if this is ProcessPartial mode
        if ($mode -eq "ResumeMaster" -or $ProcessPartial) {
            Write-Host "⚡ Skipping subscription discovery and access validation for optimized performance" -ForegroundColor Cyan
            $skipDiscovery = $true
        } elseif ($mode -eq "ResumeCheckpoint") {
            Write-Host "🔄 Master file available but proceeding with checkpoint resume as requested" -ForegroundColor Cyan
            # $skipDiscovery remains as set by user choice (should be false for checkpoint resume)
        }
        
        # Apply user's scan mode choice to resume logic
        $hasCheckpoints = (Get-ChildItem -Path $outDir -Filter "akv_audit_checkpoint_*.json" -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
        
        if ($mode -eq "ResumeCheckpoint") {
            # User chose to resume from checkpoint
            if ($hasCheckpoints) {
                Write-Host "✅ Proceeding with checkpoint resume as requested..." -ForegroundColor Green
                $usingMasterFile = $true
                $restartVaultAnalysis = $false
            } else {
                Write-Host "⚠️ No checkpoints found, but master file is available" -ForegroundColor Yellow
                Write-Host "🔄 Falling back to master file mode (fresh analysis with existing discovery)" -ForegroundColor Cyan
                $usingMasterFile = $true
                $restartVaultAnalysis = $true
                $skipDiscovery = $true
                # Clear resume data since no checkpoints exist
                $Resume = $false
                $resumeData = $null
                $processedVaultIds = @()
                $global:checkpointProcessedSet = $null
                $global:checkpointProcessedCount = 0
                $global:csvProcessedSet = $null
                $global:csvProcessedCount = 0
                $global:resumeCsvPath = $null
            }
        } elseif ($mode -eq "ResumeMaster") {
            # User chose to resume from master file
            Write-Host "🔄 Using master file for fresh vault analysis with existing discovery..." -ForegroundColor Cyan
            $usingMasterFile = $true
            $restartVaultAnalysis = $true
            # Clear resume data to force fresh vault analysis
            $Resume = $false
            $resumeData = $null
            $processedVaultIds = @()
            $global:checkpointProcessedSet = $null
            $global:checkpointProcessedCount = 0
            $global:csvProcessedSet = $null
            $global:csvProcessedCount = 0
            $global:resumeCsvPath = $null
        } elseif ($mode -eq "ResumeFullScan") {
            # User chose full scan - ignore master file and checkpoints
            Write-Host "🔄 Performing full rediscovery and fresh analysis as requested..." -ForegroundColor Yellow
            $usingMasterFile = $false
            $restartVaultAnalysis = $false
            $skipDiscovery = $false
            $Resume = $false
            $resumeData = $null
            $processedVaultIds = @()
            $global:checkpointProcessedSet = $null
            $global:checkpointProcessedCount = 0
            $global:csvProcessedSet = $null
            $global:csvProcessedCount = 0
            $global:resumeCsvPath = $null
        } elseif ($global:usesMasterFileWithoutCheckpoint) {
            # Optimized mode: using master file without checkpoints
            Write-Host "🚀 OPTIMIZED MODE: Using master discovery file without checkpoints - skipping subscription enumeration" -ForegroundColor Green
            $usingMasterFile = $true
        } elseif ($ProcessPartial) {
            # For ProcessPartial, always use master file when available
            Write-Host "🚀 Using master discovery file for ProcessPartial mode - skipping subscription enumeration" -ForegroundColor Green
            $usingMasterFile = $true
        } else {
            # Resume mode without checkpoints, just use master file normally
            Write-Host "🚀 Using master discovery file - skipping subscription enumeration" -ForegroundColor Green
            $usingMasterFile = $true
        }
        
        # Load master data if using it
        if ($usingMasterFile) {
            # Convert master data back to expected format
            $allKeyVaults = Convert-MasterToKeyVaultArray -MasterData $masterData
            $executiveSummary.TotalSubscriptions = $masterData.TotalSubscriptions
            
            # Create minimal subscription objects for compatibility
            foreach ($subData in $masterData.Subscriptions) {
                $subscriptions += [PSCustomObject]@{
                    Id = $subData.Id
                    Name = $subData.Name
                }
            }
            
            Write-Host "✅ Loaded from master: $($masterData.TotalSubscriptions) subscriptions, $($masterData.TotalKeyVaults) Key Vaults" -ForegroundColor Green
            Write-Host "🎯 No re-discovery or access validation will be performed - proceeding with existing data" -ForegroundColor Cyan
        }
    } else {
        if ($ProcessPartial -and -not $CsvFilePath) {
            Write-Host "📂 No master file found - ProcessPartial mode requires existing data" -ForegroundColor Yellow
            Write-Host "💡 Hint: Use -CsvFilePath to specify a CSV file, or run a full audit first to create master data" -ForegroundColor Yellow
        } else {
            Write-Host "📂 No valid master file found - proceeding with full discovery" -ForegroundColor Yellow
        }
    }
}

# Perform full discovery if not using master file
if (-not $usingMasterFile -and -not $skipDiscovery) {
    # Enhanced subscription discovery with tenant-specific error handling
    function Get-SubscriptionsWithTenantHandling {
        <#
        .SYNOPSIS
            Robustly discover subscriptions with graceful handling of tenant-specific authentication failures.
        
        .DESCRIPTION
            Attempts to get all subscriptions, but handles ManagedIdentityCredential and tenant-specific 
            authentication errors gracefully by logging warnings and continuing discovery.
            
            In TestMode, will stop validation once enough subscriptions are validated to potentially meet the vault limit.
        #>
        
        param(
            [bool]$TestMode = $false,
            [int]$TargetVaultCount = 3
        )
        
        $discoveredSubscriptions = @()
        $totalSkipped = 0
        $loggedTenantErrors = @{} # Track tenants we've already logged errors for
        
        try {
            Write-Host "🔍 Discovering accessible subscriptions..." -ForegroundColor Cyan
            
            # Attempt to get all subscriptions with enhanced error handling
            $allSubscriptions = Get-AzSubscription -ErrorAction Stop
            
            if (-not $allSubscriptions -or $allSubscriptions.Count -eq 0) {
                Write-Warning "⚠️ No subscriptions found - this may indicate authentication or permission issues"
                Write-ErrorLog "Subscription" "No subscriptions discovered - authentication or permission issue"
                return @(), 0
            }
            
            Write-Host "📋 Found $($allSubscriptions.Count) subscription(s) - validating access..." -ForegroundColor Gray
            
            # Test mode optimization: in test mode, we'll validate subscriptions incrementally as needed
            # Instead of pre-determining a fixed limit, we'll stop validation as soon as we have enough
            # accessible subscriptions to potentially meet the vault limit
            $maxSubscriptionsToValidate = if ($TestMode) {
                # In test mode with a small limit, start conservatively
                # Assume at least 1 vault per subscription to minimize over-validation
                [Math]::Min($allSubscriptions.Count, [Math]::Max(3, $TargetVaultCount))
            } else {
                $allSubscriptions.Count
            }
            
            if ($TestMode -and $maxSubscriptionsToValidate -lt $allSubscriptions.Count) {
                Write-Host "🧪 Test mode optimization: Will validate subscriptions incrementally (initial target: $maxSubscriptionsToValidate)" -ForegroundColor Yellow
            }
            
            # Validate access to subscriptions (with test mode optimization)
            $subscriptionIndex = 0
            foreach ($subscription in $allSubscriptions) {
                $subscriptionIndex++
                
                # Test mode early termination
                if ($TestMode -and $subscriptionIndex -gt $maxSubscriptionsToValidate) {
                    Write-Host "🎯 Test mode: Stopping subscription validation after $maxSubscriptionsToValidate subscription(s)" -ForegroundColor Cyan
                    Write-Host "   ⚡ Skipped $($allSubscriptions.Count - $maxSubscriptionsToValidate) subscription(s) for test efficiency" -ForegroundColor Yellow
                    break
                }
                try {
                    # Test access to the subscription context
                    $null = Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop
                    
                    # Test basic read permissions
                    $null = Get-AzResourceGroup -ErrorAction Stop | Select-Object -First 1
                    
                    $discoveredSubscriptions += $subscription
                    Write-Host "  ✅ $($subscription.Name) - Access confirmed" -ForegroundColor Green
                    
                } catch {
                    $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                    $totalSkipped++
                    $global:auditStats.SkippedSubscriptions++
                    $global:auditStats.AuthenticationErrors++
                    
                    # Create detailed skip record
                    $skipRecord = @{
                        SubscriptionName = $subscription.Name
                        SubscriptionId = $subscription.Id
                        TenantId = $subscription.TenantId
                        ErrorMessage = $errorMessage
                        ErrorType = "Authentication/Permission"
                        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss UTC')
                    }
                    $global:skippedSubscriptions += $skipRecord
                    
                    # Determine error type and provide actionable guidance (with tenant-based deduplication)
                    if ($errorMessage -like "*ManagedIdentityCredential*" -or $errorMessage -like "*invalid tenant*" -or $errorMessage -like "*tenant*") {
                        Write-Warning "  ⚠️ $($subscription.Name) - Tenant authentication issue: $($subscription.TenantId)"
                        Write-ErrorLog "TenantAuth" "Skipped subscription due to tenant authentication failure: $($subscription.Name) (Tenant: $($subscription.TenantId)) - $errorMessage"
                        
                        # Check for specific managed identity ExpiresOn issue
                        if ($errorMessage -like "*ExpiresOn*" -or $errorMessage -like "*token provider result value is invalid*") {
                            Write-Host "    💡 Detected ManagedIdentityCredential ExpiresOn token format issue" -ForegroundColor Yellow
                            Write-Host "    💡 Recommendation: Use interactive authentication or service principal instead of managed identity" -ForegroundColor Yellow
                            Write-Host "    💡 Troubleshooting: https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-troubleshoot" -ForegroundColor Yellow
                        }
                        
                        # Only show recommendation once per tenant to avoid flooding
                        if (-not $loggedTenantErrors.ContainsKey($subscription.TenantId)) {
                            Write-Host "    💡 Recommendation: Verify tenant access or exclude subscriptions in tenant $($subscription.TenantId) from the audit scope" -ForegroundColor Yellow
                            $loggedTenantErrors[$subscription.TenantId] = $true
                        }
                    }
                    elseif ($errorMessage -like "*Forbidden*" -or $errorMessage -like "*Authorization*" -or $errorMessage -like "*access denied*") {
                        Write-Warning "  ⚠️ $($subscription.Name) - Permission denied"
                        Write-PermissionsLog "Subscription" "Insufficient permissions for subscription $($subscription.Name): $errorMessage"
                        Write-Host "    💡 Recommendation: Request Reader role on subscription $($subscription.Name)" -ForegroundColor Yellow
                    }
                    else {
                        Write-Warning "  ⚠️ $($subscription.Name) - Access error: $($errorMessage.Split('.')[0])"
                        Write-ErrorLog "Subscription" "Subscription access error for $($subscription.Name): $errorMessage"
                        Write-Host "    💡 Recommendation: Check subscription status and connectivity" -ForegroundColor Yellow
                    }
                }
            }
            
            return $discoveredSubscriptions, $totalSkipped
            
        } catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            
            # Handle complete subscription discovery failure
            if ($errorMessage -like "*ManagedIdentityCredential*" -or $errorMessage -like "*authentication*") {
                Write-Host "❌ Complete subscription discovery failed due to authentication issues" -ForegroundColor Red
                Write-ErrorLog "Auth" "Complete subscription discovery failed: $errorMessage"
                
                # Check for specific managed identity ExpiresOn issue
                if ($errorMessage -like "*ExpiresOn*" -or $errorMessage -like "*token provider result value is invalid*") {
                    Write-Host "💡 Detected ManagedIdentityCredential ExpiresOn token format issue" -ForegroundColor Yellow
                    Write-Host "💡 This is a known issue with managed identity authentication where the ExpiresOn token format is invalid" -ForegroundColor Yellow
                    Write-Host "💡 Recommendations:" -ForegroundColor Yellow
                    Write-Host "   - Use interactive authentication: Connect-AzAccount (without -Identity)" -ForegroundColor Yellow
                    Write-Host "   - Use service principal authentication: Connect-AzAccount -ServicePrincipal" -ForegroundColor Yellow
                    Write-Host "   - Troubleshooting guide: https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-troubleshoot" -ForegroundColor Yellow
                } else {
                    Write-Host "💡 This may indicate a fundamental authentication problem with your Azure context" -ForegroundColor Yellow
                    Write-Host "💡 Recommendations:" -ForegroundColor Yellow
                    Write-Host "   - Verify your Azure login with 'Get-AzContext'" -ForegroundColor Yellow
                    Write-Host "   - Try re-authenticating with 'Connect-AzAccount'" -ForegroundColor Yellow
                    Write-Host "   - Check if you have proper tenant access permissions" -ForegroundColor Yellow
                }
            }
            else {
                Write-ErrorLog "Subscription" "Failed to discover subscriptions: $errorMessage"
                if ($errorMessage -like "*Forbidden*" -or $errorMessage -like "*Authorization*") {
                    Write-PermissionsLog "Subscription" "Insufficient permissions to list subscriptions: $errorMessage"
                }
            }
            
            throw "Failed to discover subscriptions: $errorMessage"
        }
    }

    # Get all subscriptions with enhanced error handling (with test mode optimization)
    $subscriptions, $skippedCount = Get-SubscriptionsWithTenantHandling -TestMode $TestMode -TargetVaultCount $Limit
    $executiveSummary.TotalSubscriptions = $subscriptions.Count
    
    if ($subscriptions.Count -eq 0) {
        Write-Host "❌ No accessible subscriptions found - cannot proceed with audit" -ForegroundColor Red
        if ($skippedCount -gt 0) {
            Write-Host "📊 $skippedCount subscription(s) were skipped due to access issues" -ForegroundColor Yellow
        }
        throw "No accessible subscriptions found"
    }
    
    Write-Host "✅ Successfully validated access to $($subscriptions.Count) subscription(s)" -ForegroundColor Green
    if ($skippedCount -gt 0) {
        Write-Host "⚠️ $skippedCount subscription(s) skipped due to authentication/permission issues" -ForegroundColor Yellow
    }
    if ($TestMode) {
        Write-Host "🧪 Test mode: Will search subscriptions until $Limit Key Vault(s) found" -ForegroundColor Cyan
    }

    # Discover Key Vaults with test mode optimization
    foreach ($subscription in $subscriptions) {
        $subscriptionIndex++
        try {
            Show-Progress -Phase "Discovery" -Current $subscriptionIndex -Total $subscriptions.Count -CurrentItem $subscription.Name
            
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
            $keyVaults = Get-AzKeyVault -ErrorAction Stop
            
            foreach ($kv in $keyVaults) {
                $allKeyVaults += [PSCustomObject]@{
                    KeyVault = $kv
                    SubscriptionName = $subscription.Name
                    SubscriptionId = $subscription.Id
                }
                
                # Test mode optimization: Stop when we have enough vaults
                if ($TestMode -and $allKeyVaults.Count -ge $Limit) {
                    Write-Host "🎯 Test mode limit reached: Found $($allKeyVaults.Count) Key Vault(s)" -ForegroundColor Green
                    $testModeEarlyTermination = $true
                    break
                }
            }
            
            # Early termination for test mode - stop processing subscriptions
            if ($TestMode -and $allKeyVaults.Count -ge $Limit) {
                Write-Host "🏁 Test mode optimization: Stopping subscription discovery early" -ForegroundColor Cyan
                Write-Host "   📊 Found $($allKeyVaults.Count) Key Vault(s) across $subscriptionIndex of $($subscriptions.Count) subscription(s)" -ForegroundColor Gray
                Write-Host "   ⚡ Skipped $($subscriptions.Count - $subscriptionIndex) subscription(s) for efficiency" -ForegroundColor Yellow
                break
            }
        } catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            Write-ErrorLog "Subscription" "Error processing subscription $($subscription.Name): $errorMessage"
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
                Write-PermissionsLog "Subscription" "Insufficient permissions for subscription $($subscription.Name)"
            }
        }
    }
    
    # Save master discovery file for future use (unless in test mode)
    if (-not $TestMode -and $allKeyVaults.Count -gt 0) {
        Write-Host "💾 Saving discovery master file for future resume operations..." -ForegroundColor Cyan
        Save-DiscoveryMaster -AllKeyVaults $allKeyVaults -Subscriptions $subscriptions -OutputDirectory $outDir
    }
}

$executiveSummary.TotalKeyVaults = $allKeyVaults.Count
$global:totalVaultsToProcess = $allKeyVaults.Count

if ($TestMode) {
    Write-Host "🔐 Found $($allKeyVaults.Count) Key Vault(s) to analyze (test mode limited to $Limit)" -ForegroundColor Green
    if ($testModeEarlyTermination) {
        Write-Host "⚡ Test mode efficiency: Examined only $subscriptionIndex of $($subscriptions.Count) subscription(s)" -ForegroundColor Cyan
    }
} else {
    Write-Host "🔐 Found $($allKeyVaults.Count) Key Vault(s) to analyze" -ForegroundColor Green
}

# Enhanced vault filtering and progress planning
$vaultsToProcess = $allKeyVaults
$baselineProcessed = 0
$totalDiscovered = $allKeyVaults.Count
$planning = $null

if ($PSBoundParameters.ContainsKey('Resume') -and $global:checkpointProcessedSet) {
    Write-Host "🔄 RESUME MODE: Computing vault filtering with enhanced identity matching..." -ForegroundColor Cyan
    
    # Use new helper functions for vault filtering
    $planning = Get-VaultsToProcess -AllVaults $allKeyVaults -ProcessedSet $global:checkpointProcessedSet
    $vaultsToProcess = @($planning.ToProcess)
    $baselineProcessed = $planning.BaselineMatched
    $totalDiscovered = $planning.TotalDiscovered
    
    Write-Host "📊 RESUME ANALYSIS:" -ForegroundColor Cyan
    Write-Host "   📊 Total vaults discovered: $totalDiscovered" -ForegroundColor Gray
    Write-Host "   ✅ Vaults already processed (baseline): $baselineProcessed" -ForegroundColor Gray
    Write-Host "   🔍 Vaults to process this session: $($vaultsToProcess.Count)" -ForegroundColor Green
    
    # Enhanced diagnostics for multiple sources (always computed, shown when -Verbose)
    $checkpointMatched = 0
    $csvMatched = 0
    $unmatchedFromCheckpoint = @()
    $unmatchedFromCsv = @()
    
    # Compute diagnostics if verbose or strict matching is enabled
    if ($VerbosePreference -eq 'Continue' -or $ResumeStrictMatch) {
        # Generate discovery keys for matching analysis
        $discoveryKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($vault in $allKeyVaults) {
            $keys = Get-IdentityKeys -Vault $vault.KeyVault
            foreach ($key in $keys) {
                if (-not [string]::IsNullOrWhiteSpace($key)) {
                    $null = $discoveryKeys.Add($key.Trim())
                }
            }
        }
        
        # Calculate matches per source
        if ($global:checkpointProcessedSet -and $global:checkpointProcessedSet.Count -gt 0) {
            foreach ($key in $global:checkpointProcessedSet) {
                if ($discoveryKeys.Contains($key)) {
                    $checkpointMatched++
                } else {
                    $unmatchedFromCheckpoint += $key
                }
            }
        }
        
        if ($global:csvProcessedSet -and $global:csvProcessedSet.Count -gt 0) {
            foreach ($key in $global:csvProcessedSet) {
                if ($discoveryKeys.Contains($key)) {
                    $csvMatched++
                } else {
                    $unmatchedFromCsv += $key
                }
            }
        }
        
        # Enhanced logging when verbose
        if ($VerbosePreference -eq 'Continue') {
            $checkpointInfo = if ($global:checkpointProcessedCount -gt 0) {
                "Checkpoint: $($global:checkpointProcessedCount) (matched $checkpointMatched, unmatched $($unmatchedFromCheckpoint.Count))"
            } else { "Checkpoint: 0" }
            
            $csvInfo = if ($global:csvProcessedCount -gt 0) {
                "CSV: $($global:csvProcessedCount) (matched $csvMatched, unmatched $($unmatchedFromCsv.Count))"
            } else { "CSV: 0" }
            
            Write-Verbose "Resume: Processed IDs — $checkpointInfo, $csvInfo" -Verbose
            
            # Show unmatched entries (respecting UnmatchedLogCount)
            if ($unmatchedFromCheckpoint.Count -gt 0 -and $UnmatchedLogCount -gt 0) {
                $sample = $unmatchedFromCheckpoint | Select-Object -First $UnmatchedLogCount
                Write-Verbose "Resume: Unmatched from checkpoint (showing up to $UnmatchedLogCount): $($sample -join ', ')" -Verbose
            }
            
            if ($unmatchedFromCsv.Count -gt 0 -and $UnmatchedLogCount -gt 0) {
                $sample = $unmatchedFromCsv | Select-Object -First $UnmatchedLogCount
                Write-Verbose "Resume: Unmatched from CSV (showing up to $UnmatchedLogCount): $($sample -join ', ')" -Verbose
            }
        }
    }
    
    # Strict-match guard
    if ($ResumeStrictMatch) {
        $totalSourceIdentities = ($global:checkpointProcessedCount + $global:csvProcessedCount)
        if ($totalSourceIdentities -gt 0) {
            # Calculate unique identities to avoid double-counting overlaps
            $uniqueSourceIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if ($global:checkpointProcessedSet) {
                foreach ($key in $global:checkpointProcessedSet) {
                    $null = $uniqueSourceIdentities.Add($key)
                }
            }
            if ($global:csvProcessedSet) {
                foreach ($key in $global:csvProcessedSet) {
                    $null = $uniqueSourceIdentities.Add($key)
                }
            }
            
            $matchRatio = if ($uniqueSourceIdentities.Count -gt 0) {
                [math]::Round(($baselineProcessed / $uniqueSourceIdentities.Count) * 100, 1)
            } else { 0 }
            
            Write-Host "🔍 Strict Match Analysis: $matchRatio% ($baselineProcessed/$($uniqueSourceIdentities.Count) unique source identities)" -ForegroundColor Yellow
            
            if ($matchRatio -lt $StrictMatchThresholdPercent) {
                Write-Error @"
❌ STRICT MATCH GUARD: Resume aborted due to low match percentage ($matchRatio% < $StrictMatchThresholdPercent%)

This indicates significant drift between your resume sources and current vault discovery:
• Sources found: $($uniqueSourceIdentities.Count) unique identities
• Current discovery matched: $baselineProcessed identities  
• Match ratio: $matchRatio% (threshold: $StrictMatchThresholdPercent%)

RECOMMENDATIONS:
1. Run with -Verbose to see detailed unmatched identity lists
2. Try different -ResumeSourcePriority: 'Checkpoint', 'CSV', or 'Union'
3. Consider running without -ResumeStrictMatch if drift is expected
4. Verify your resume data is from the same environment/tenant

To proceed anyway, remove -ResumeStrictMatch or lower -StrictMatchThresholdPercent.
"@
                exit 1
            } else {
                Write-Host "✅ Strict match validation passed ($matchRatio% >= $StrictMatchThresholdPercent%)" -ForegroundColor Green
            }
        }
    }
    
    if ($vaultsToProcess.Count -eq 0) {
        Write-Host "   ✅ All vaults already processed! No new work required." -ForegroundColor Green
    } else {
        Write-Host "   🚀 Ready to continue processing from where we left off..." -ForegroundColor Green
        if ($vaultsToProcess.Count -gt 0) {
            Write-Verbose "Resume: First vault to process: $($vaultsToProcess[0].KeyVault.VaultName)" -Verbose
        }
    }
    Write-Host ""
} else {
    Write-Host "🔄 FULL PROCESSING MODE: Will process all discovered vaults" -ForegroundColor Green
    $baselineProcessed = 0
    $totalDiscovered = $allKeyVaults.Count
    $vaultsToProcess = @($allKeyVaults)
}

# Initial permissions validation for production readiness
Write-Host "🔐 Validating permissions for enhanced secrets management insights..." -ForegroundColor Cyan
$globalPermissions = Test-SecretsManagementPermissions
if ($globalPermissions.MissingPermissions.Count -gt 0) {
    Write-Host "⚠️ Some permissions are missing. Enhanced features may have limited data." -ForegroundColor Yellow
    foreach ($missing in $globalPermissions.MissingPermissions) {
        Write-PermissionsLog "GlobalValidation" $missing -RequiredRole "Multiple"
    }
}

# Validate administrative roles for Optional Administrative Roles section
Write-Host "👑 Validating administrative roles..." -ForegroundColor Cyan
$globalAdministrativeRoles = Test-AdministrativeRoles
if ($globalAdministrativeRoles.RoleValidationErrors.Count -gt 0) {
    Write-Host "⚠️ Some administrative role validations encountered issues." -ForegroundColor Yellow
    foreach ($roleError in $globalAdministrativeRoles.RoleValidationErrors) {
        Write-PermissionsLog "AdministrativeRoleValidation" $roleError -RequiredRole "Administrative"
    }
}

if ($TestMode) {
    Write-Host "🧪 TEST MODE: Limited to $Limit Key Vault(s)" -ForegroundColor Red
}

# Enhanced vault processing with identity-based filtering
$totalToProcess = $vaultsToProcess.Count
$sessionIndex = 0

# Enhanced planning banner with resume source information
if ($PSBoundParameters.ContainsKey('Resume') -and ($global:checkpointProcessedCount -gt 0 -or $global:csvProcessedCount -gt 0)) {
    Write-Host "📋 RESUME SOURCES:" -ForegroundColor Cyan
    
    if ($global:checkpointProcessedCount -gt 0) {
        Write-Host "   • Checkpoint IDs: $($global:checkpointProcessedCount) (matched $checkpointMatched)" -ForegroundColor Gray
    }
    
    if ($global:csvProcessedCount -gt 0) {
        Write-Host "   • CSV IDs: $($global:csvProcessedCount) (matched $csvMatched)" -ForegroundColor Gray
    }
    
    $uniqueProcessedCount = if ($global:checkpointProcessedSet) { $global:checkpointProcessedSet.Count } else { 0 }
    Write-Host "   • Combined processed set (unique): $uniqueProcessedCount" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "📊 PROCESSING PLAN:" -ForegroundColor Cyan
Write-Host "   🔍 Vaults to process this session: $totalToProcess" -ForegroundColor Green
Write-Host "   📊 Total discovered vaults: $totalDiscovered" -ForegroundColor Gray
if ($baselineProcessed -gt 0) {
    Write-Host "   ✅ Baseline already processed: $baselineProcessed" -ForegroundColor Gray
}
Write-Host ""

# Main vault processing loop - iterate only unprocessed vaults
foreach ($kvItem in $vaultsToProcess) {
    $sessionIndex++
    $kv = $kvItem.KeyVault
    $overallProcessed = $baselineProcessed + $sessionIndex
    
    # Check for script cancellation
    if ($global:scriptCancelled) {
        Write-Host "🛑 Script cancellation detected. Exiting loop..." -ForegroundColor Yellow
        Write-CancellationDebugLog "LoopExit" "Script cancellation flag detected in main processing loop" -Context "SessionIndex=$sessionIndex|VaultName=$($kv.VaultName)|Breaking from loop"
        break
    }
    
    # Enhanced progress display based on ProgressMode
    $effectiveProgressMode = if ($PSBoundParameters.ContainsKey('ProgressMode')) { $ProgressMode } else { 'Session' }
    $progressMessage = switch ($effectiveProgressMode) {
        'Session' { "Vault $sessionIndex/$totalToProcess" }
        'Overall' { "Vault $overallProcessed/$totalDiscovered" }
        default   { "Vault $sessionIndex/$totalToProcess" }
    }
    
    # Use the traditional Show-Progress for the progress bar (keeping existing functionality)
    Show-Progress -Phase "Analyzing" -Status $progressMessage -Current $sessionIndex -Total $totalToProcess -CurrentItem $kv.VaultName
    
    # Production memory management and checkpointing
    Invoke-MemoryCleanup -VaultIndex $sessionIndex
    
    # Build current processed vault entry for checkpoint
    $currentProcessedVaults = $global:auditResults | ForEach-Object {
        @{
            VaultName = $_.KeyVaultName
            SubscriptionId = $_.SubscriptionId
            ResourceId = $_.ResourceId
            Status = "completed"
            ProcessedTime = Get-SafeProperty -Object $_ -PropertyName 'LastAuditDate' -DefaultValue (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }
    
    # Update checkpoint saving to use session-based counting
    Save-ProgressCheckpoint -VaultIndex $sessionIndex -TotalVaults $totalToProcess -ProcessedResults $global:auditResults -ProcessedVaults $currentProcessedVaults
    
    # Enhanced token management for production stability (10-12 hour runs)
    if ($sessionIndex % 10 -eq 0) {
        Write-Host "🔄 Performing routine token validation (Session vault $sessionIndex/$totalToProcess, Overall: $overallProcessed/$totalDiscovered)..." -ForegroundColor Cyan
        Initialize-AzAuth
        Test-TokenValidity
        
        # Log token status for production monitoring
        try {
            $currentToken = Get-AzAccessToken -ErrorAction SilentlyContinue
            if ($currentToken) {
                # Enhanced token health monitoring with managed identity support
                $tokenExpiry = $null
                try {
                    if ($currentToken.ExpiresOn -is [DateTime]) {
                        $tokenExpiry = $currentToken.ExpiresOn
                    } elseif ($currentToken.ExpiresOn -is [DateTimeOffset]) {
                        $tokenExpiry = $currentToken.ExpiresOn.DateTime
                    } elseif ($currentToken.ExpiresOn -and $currentToken.ExpiresOn.ToString() -match '^\d+$') {
                        # Handle Unix timestamp format (common with managed identity)
                        $tokenExpiry = [DateTimeOffset]::FromUnixTimeSeconds([long]$currentToken.ExpiresOn).DateTime
                    } elseif ($currentToken.ExpiresOn) {
                        # Try to parse as string
                        $tokenExpiry = [DateTimeOffset]::Parse($currentToken.ExpiresOn.ToString()).DateTime
                    } else {
                        # ExpiresOn is null or empty - common issue with managed identity
                        $tokenExpiry = (Get-Date).AddHours(1)  # Assume 1 hour validity for managed identity
                        Write-ErrorLog "TokenHealth" "Token ExpiresOn property is null/invalid - using default 1-hour assumption for managed identity"
                    }
                } catch {
                    # Handle managed identity ExpiresOn format issues during health check
                    $tokenExpiry = (Get-Date).AddHours(1)  # Assume 1 hour validity for managed identity
                    Write-ErrorLog "TokenHealth" "ExpiresOn parsing failed during health check: $($_.Exception.Message) - using default assumption"
                }
                $timeUntilExpiry = $tokenExpiry - (Get-Date)
                Write-ErrorLog "TokenHealth" "Token valid for $([math]::Round($timeUntilExpiry.TotalMinutes, 1)) minutes | Session progress: $sessionIndex/$totalToProcess | Overall: $overallProcessed/$totalDiscovered | User: $($global:currentUser)"
            }
        } catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            Write-ErrorLog "TokenHealth" "Token status check failed: $errorMessage | Continuing with next vault"
        }
    }
    
    # Production-grade processing with retry mechanisms
    $retryCount = 0
    $maxRetries = 3
    $vaultProcessed = $false
    
    # Initialize variables defensively to prevent null reference errors
    $accessPolicies = @()
    $rbacAssignments = @()
    $diagnostics = @{
        Enabled = $false
        LogCategories = @()
        MetricCategories = @()
        LogAnalyticsEnabled = $false
        LogAnalyticsWorkspaceName = ""
        EventHubEnabled = $false
        EventHubNamespace = ""
        EventHubName = ""
        StorageAccountEnabled = $false
        StorageAccountName = ""
    }
    # ...existing code...
    $identityAnalysis = @{
        ServicePrincipals = @()
        Users = @()
        Groups = @()
    }
    $networkConfig = @{
        PublicNetworkAccess = "Unknown"
        NetworkAclsConfigured = $false
        PrivateEndpointCount = 0
    }
    $overPrivileged = @()
    $workloadAnalysis = @{
        SecretCount = 0
        KeyCount = 0
        CertificateCount = 0
        WorkloadCategories = @()
        EnvironmentType = "Unknown"
        PrimaryWorkload = "Unknown"
        SecurityInsights = @()
        OptimizationRecommendations = @()
    }
    $diagnostics = @{
        Enabled = $false
        LogCategories = @()
        MetricCategories = @()
        LogAnalyticsEnabled = $false
        LogAnalyticsWorkspaceName = ""
        EventHubEnabled = $false
        EventHubNamespace = ""
        EventHubName = ""
        StorageAccountEnabled = $false
        StorageAccountName = ""
    }
    $connectedManagedIdentities = @()
    $systemAssignedIdentity = $false
    $systemAssignedPrincipalId = ""
    $userAssignedIdentityCount = 0
    $userAssignedIdentityIds = @()
    $complianceStatus = "Unknown"
    $complianceScore = 0
    $companyComplianceScore = 0
    $companyComplianceStatus = "Unknown"
    $recommendations = @()
    
    while (-not $vaultProcessed -and $retryCount -lt $maxRetries) {
        try {
            # Defensive: Always initialize $diagnostics as empty hashtable at the start of each try
            $diagnostics = @{
                Enabled = $false
                LogCategories = @()
                MetricCategories = @()
                LogAnalyticsEnabled = $false
                LogAnalyticsWorkspaceName = ""
                EventHubEnabled = $false
                EventHubNamespace = ""
                EventHubName = ""
                StorageAccountEnabled = $false
                StorageAccountName = ""
            }
            # Set context for this vault's subscription with retry
            try {
                Set-AzContext -SubscriptionId $kvItem.SubscriptionId -ErrorAction Stop | Out-Null
            } catch {
                if ($retryCount -eq 0) {
                    # First retry - try to refresh context
                    Write-Host "⚠️ Context switch failed, refreshing auth..." -ForegroundColor Yellow
                    Initialize-AzAuth -Force
                    Set-AzContext -SubscriptionId $kvItem.SubscriptionId -ErrorAction Stop | Out-Null
                } else {
                    throw
                }
            }
            
            Show-Progress -Phase "Processing" -Current $sessionIndex -Total $totalToProcess -CurrentItem $kv.VaultName -Operation "Data Collection"
            
            # Get diagnostics configuration
            $actualDiagnostics = Get-DiagnosticsConfiguration -ResourceId $kv.ResourceId -KeyVaultName $kv.VaultName
            if ($actualDiagnostics -and $actualDiagnostics -is [hashtable]) {
                # Merge actual diagnostics into defaults
                foreach ($key in $actualDiagnostics.Keys) {
                    $diagnostics[$key] = $actualDiagnostics[$key]
                }
            }
            
            # Get RBAC assignments
            $rbacAssignments = Get-RBACAssignments -ResourceId $kv.ResourceId -KeyVaultName $kv.VaultName
            if ($null -eq $rbacAssignments) { $rbacAssignments = @() }
            
            # Analyze identities
            $identityAnalysis = Get-ServicePrincipalsAndManagedIdentities -Assignments $rbacAssignments
            if ($null -eq $identityAnalysis) { 
                $identityAnalysis = @{
                    ServicePrincipals = @()
                    Users = @()
                    Groups = @()
                }
            }
            
            # Get access policies
            $accessPolicies = Get-AccessPolicyDetails -KeyVault $kv
            if ($null -eq $accessPolicies) { $accessPolicies = @() }
            
            # Get network security config
            $networkConfig = Get-NetworkSecurityConfig -KeyVault $kv
            if ($null -eq $networkConfig) { 
                $networkConfig = @{
                    PublicNetworkAccess = "Unknown"
                    NetworkAclsConfigured = $false
                    PrivateEndpointCount = 0
                }
            }
            
            # Analyze over-privileged assignments
            $overPrivileged = Get-OverPrivilegedUsers -Assignments $rbacAssignments
            if ($null -eq $overPrivileged) { $overPrivileged = @() }
            
            # Get Key Vault workload analysis
            $workloadAnalysis = Get-KeyVaultWorkloadAnalysis -KeyVaultName $kv.VaultName
            if ($null -eq $workloadAnalysis) { 
                $workloadAnalysis = @{
                    SecretCount = 0
                    KeyCount = 0
                    CertificateCount = 0
                    WorkloadCategories = @()
                    EnvironmentType = "Unknown"
                    PrimaryWorkload = "Unknown"
                    SecurityInsights = @()
                    OptimizationRecommendations = @()
                }
            }
            
            # Get connected managed identities (placeholder - may need to implement this function)
            # $connectedManagedIdentities = Get-ConnectedManagedIdentities -KeyVault $kv
            # For now, ensure it's not null
            if ($null -eq $connectedManagedIdentities) { $connectedManagedIdentities = @() }
            
            $vaultProcessed = $true
            $global:auditStats.SuccessfulVaults++
            
            # Calculate defensive counts before hashtable creation to avoid syntax issues
            $accessPolicyCountSafe2 = if ($null -ne $accessPolicies -and $accessPolicies -is [System.Collections.ICollection]) { $accessPolicies.Count } else { 0 }
            $rbacAssignmentCountSafe2 = if ($null -ne $rbacAssignments -and $rbacAssignments -is [System.Collections.ICollection]) { $rbacAssignments.Count } else { 0 }
            $servicePrincipalCountSafe2 = if ($null -ne $identityAnalysis -and $null -ne $identityAnalysis.ServicePrincipals -and $identityAnalysis.ServicePrincipals -is [System.Collections.ICollection]) { $identityAnalysis.ServicePrincipals.Count } else { 0 }
            $userCountSafe2 = if ($null -ne $identityAnalysis -and $null -ne $identityAnalysis.Users -and $identityAnalysis.Users -is [System.Collections.ICollection]) { $identityAnalysis.Users.Count } else { 0 }
            $groupCountSafe2 = if ($null -ne $identityAnalysis -and $null -ne $identityAnalysis.Groups -and $identityAnalysis.Groups -is [System.Collections.ICollection]) { $identityAnalysis.Groups.Count } else { 0 }
            $managedIdentityCountSafe2 = if ($null -ne $connectedManagedIdentities -and $connectedManagedIdentities -is [System.Collections.ICollection]) { $connectedManagedIdentities.Count } else { 0 }
            
            # Build result record
            $result = [PSCustomObject]@{
                SubscriptionId = $kvItem.SubscriptionId
                SubscriptionName = $kvItem.SubscriptionName
                KeyVaultName = $kv.VaultName
                ResourceId = $kv.ResourceId
                Location = $kv.Location
                ResourceGroupName = $kv.ResourceGroupName
                DiagnosticsEnabled = $diagnostics.Enabled
                EnabledLogCategories = $diagnostics.LogCategories -join ","
                EnabledMetricCategories = $diagnostics.MetricCategories -join ","
                LogAnalyticsEnabled = $diagnostics.LogAnalyticsEnabled
                LogAnalyticsWorkspaceName = $diagnostics.LogAnalyticsWorkspaceName
                EventHubEnabled = $diagnostics.EventHubEnabled
                EventHubNamespace = $diagnostics.EventHubNamespace
                EventHubName = $diagnostics.EventHubName
                StorageAccountEnabled = $diagnostics.StorageAccountEnabled
                StorageAccountName = $diagnostics.StorageAccountName
                AccessPolicyCount = $accessPolicyCountSafe2
                AccessPolicyDetails = $accessPolicies -join " | "
                RBACRoleAssignments = ($rbacAssignments | ForEach-Object { "$($_.PrincipalName): $($_.RoleDefinitionName)" }) -join " | "
                RBACAssignmentCount = $rbacAssignmentCountSafe2
                TotalIdentitiesWithAccess = $rbacAssignmentCountSafe2 + $accessPolicyCountSafe2
                ServicePrincipalCount = $servicePrincipalCountSafe2
                UserCount = $userCountSafe2
                GroupCount = $groupCountSafe2
                ManagedIdentityCount = $managedIdentityCountSafe2
                ServicePrincipalDetails = $identityAnalysis.ServicePrincipals -join " | "
                ManagedIdentityDetails = $connectedManagedIdentities -join " | "
                SoftDeleteEnabled = $(if ($kv.PSObject.Properties.Name -contains 'EnableSoftDelete') { $kv.EnableSoftDelete } else { "Unknown" })
                PurgeProtectionEnabled = $(if ($kv.PSObject.Properties.Name -contains 'EnablePurgeProtection') { $kv.EnablePurgeProtection } else { "Unknown" })
                PublicNetworkAccess = $networkConfig.PublicNetworkAccess
                NetworkAclsConfigured = $networkConfig.NetworkAclsConfigured
                PrivateEndpointCount = $networkConfig.PrivateEndpointCount
                SystemAssignedIdentity = $systemAssignedIdentity
                SystemAssignedPrincipalId = $systemAssignedPrincipalId
                UserAssignedIdentityCount = $userAssignedIdentityCount
                UserAssignedIdentityIds = $userAssignedIdentityIds -join ","
                ConnectedManagedIdentityCount = if ($null -ne $connectedManagedIdentities -and $connectedManagedIdentities -is [System.Collections.ICollection]) { $connectedManagedIdentities.Count } else { 0 }
                ComplianceStatus = $complianceStatus
                ComplianceScore = $complianceScore
                CompanyComplianceScore = $companyComplianceScore
                CompanyComplianceStatus = $companyComplianceStatus
                ComplianceIssues = ""
                ComplianceRecommendations = ($recommendations -join "; ")
                VaultRecommendations = ($recommendations | Select-Object -First 10) -join "; "
                SecurityEnhancements = ($recommendations | Where-Object { $_ -like "*Private*" -or $_ -like "*System*" -or $_ -like "*Log*" -or $_ -like "*secret*" -or $_ -like "*Key Vault*" }) -join "; "
                RBACRecommendations = ($recommendations | Where-Object { $_ -like "*Reduce*" -or $_ -like "*Consider reducing*" -or $_ -like "*Replace*" }) -join "; "
                OverPrivilegedAssignments = $overPrivileged -join "; "
                # Workload Analysis Data
                SecretCount = $workloadAnalysis.SecretCount
                KeyCount = $workloadAnalysis.KeyCount
                CertificateCount = $workloadAnalysis.CertificateCount
                ManagedStorageAccountCount = $workloadAnalysis.ManagedStorageAccountCount
                WorkloadCategories = $workloadAnalysis.WorkloadCategories -join " | "
                EnvironmentType = $workloadAnalysis.EnvironmentType
                PrimaryWorkload = $workloadAnalysis.PrimaryWorkload
                SecurityInsights = $workloadAnalysis.SecurityInsights -join " | "
                OptimizationRecommendations = $workloadAnalysis.OptimizationRecommendations -join " | "
                RiskLevel = $workloadAnalysis.RiskLevel
                RiskFactors = $workloadAnalysis.RiskFactors -join " | "
                CriticalFindings = $workloadAnalysis.CriticalFindings -join " | "
                TotalItems = ($workloadAnalysis.SecretCount + $workloadAnalysis.KeyCount + $workloadAnalysis.CertificateCount)
                # Restored legacy/diagnostic fields (safely populated)
                LastAuditDate = if ($kv.PSObject.Properties.Name -contains 'LastAuditDate') { $kv.LastAuditDate } elseif ($global:lastAuditDate) { $global:lastAuditDate } else { (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
                ErrorsEncountered = if ($ErrorsEncountered) { ($ErrorsEncountered -join "; ") } else { "" }
                OverPrivilegedDetails = if ($overPrivileged -and ($overPrivileged -is [System.Collections.ICollection])) { $overPrivileged -join "; " } else { "" }
                MicrosoftComplianceScore = $complianceScore
                ComplianceFrameworkReasons = if ($complianceFrameworkReasons) { $complianceFrameworkReasons -join "; " } else { "" }
                AuditDurationSeconds = if ($global:CurrentVaultStartTime) { ([math]::Round((New-TimeSpan -Start $global:CurrentVaultStartTime -End (Get-Date)).TotalSeconds, 0)) } else { 0 }

                # Single-vault detailed workload fields (safe defaults)
                SecretVersioning = if ($workloadAnalysis.PSObject.Properties.Name -contains 'SecretVersioning') { $workloadAnalysis.SecretVersioning } else { "Unknown" }
                ExpirationAnalysis = if ($workloadAnalysis.PSObject.Properties.Name -contains 'ExpirationAnalysis') { $workloadAnalysis.ExpirationAnalysis -join "; " } else { "" }
                RotationAnalysis = if ($workloadAnalysis.PSObject.Properties.Name -contains 'RotationAnalysis') { $workloadAnalysis.RotationAnalysis -join "; " } else { "" }
                AppServiceIntegration = if ($workloadAnalysis.PSObject.Properties.Name -contains 'AppServiceIntegration') { $workloadAnalysis.AppServiceIntegration } else { "No" }
            }
            
            $global:auditResults += $result
        
        # Write result to CSV immediately for real-time output (if CSV path is available)
        if ($csvPath) {
            Write-VaultResultToCSV -VaultResult $result -CsvFilePath $csvPath -IsFirstResult ($global:auditResults.Count -eq 1)
        } else {
            Write-Host "⚠️ CSV path not yet initialized, skipping real-time CSV write for $($result.KeyVaultName)" -ForegroundColor Yellow
        }
        
        # Perform targeted cleanup of vault-specific variables after adding result
        try {
            $cleanupVars = @('rbacAssignments', 'accessPolicies', 'identityAnalysis', 'networkConfig', 
                           'overPrivileged', 'workloadAnalysis', 'diagnostics', 'vaultData', 
                           'complianceResult', 'recommendations', 'result', 'connectedManagedIdentities')
            
            foreach ($varName in $cleanupVars) {
                if (Get-Variable -Name $varName -Scope "Script" -ErrorAction SilentlyContinue) {
                    Remove-Variable -Name $varName -Scope "Script" -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Variable cleanup failure should not break script execution
            Write-Verbose "Error cleanup variable removal failed: $($_.Exception.Message)"
        }
            
        } catch {
            $retryCount++
            $global:auditStats.TotalRetries++
            
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
            $errorContext = "Vault: $($kv.VaultName) | Subscription: $($kvItem.SubscriptionId) | Attempt: $retryCount/$maxRetries"
            Write-ErrorLog "VaultProcessing" "Processing error: $errorMessage" $kv.VaultName $errorContext
            
            if ($retryCount -lt $maxRetries) {
                $waitTime = [math]::Pow(2, $retryCount)
                Write-Host "⏳ Retrying in $waitTime seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $waitTime
                
                # Force token refresh on second retry
                if ($retryCount -eq 2) {
                    Write-Host "🔄 Forcing authentication refresh for retry..." -ForegroundColor Yellow
                    Initialize-AzAuth -Force
                }
            } else {
                Write-Host "❌ Failed to process $($kv.VaultName) after $maxRetries attempts. Skipping..." -ForegroundColor Red
                $global:auditStats.ProcessingErrors++
                $global:auditStats.SkippedVaults++
                
                # Add a comprehensive failure record to ensure reports can be generated even if all vaults fail
                $global:auditResults += [PSCustomObject]@{
                    SubscriptionId = Get-SafeProperty -Object $kvItem -PropertyName 'SubscriptionId'
                    SubscriptionName = Get-SafeProperty -Object $kvItem -PropertyName 'SubscriptionName'
                    KeyVaultName = Get-SafeProperty -Object $kv -PropertyName 'VaultName'
                    ResourceId = Get-SafeProperty -Object $kv -PropertyName 'ResourceId'
                    Location = Get-SafeProperty -Object $kv -PropertyName 'Location'
                    ResourceGroupName = Get-SafeProperty -Object $kv -PropertyName 'ResourceGroupName'
                    ComplianceStatus = "Collection Failed"
                    ComplianceScore = 0
                    ErrorsEncountered = "Failed to collect data after $maxRetries retries. Last error: $errorMessage"
                    LastAuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    SoftDeleteEnabled = "Error"
                    PurgeProtectionEnabled = "Error"
                    DiagnosticsEnabled = "Error"
                    EnabledLogCategories = "Error"
                    EnabledMetricCategories = "Error"
                    LogAnalyticsEnabled = "Error"
                    LogAnalyticsWorkspaceName = "Error"
                    EventHubEnabled = "Error"
                    EventHubNamespace = "Error"
                    EventHubName = "Error"
                    StorageAccountEnabled = "Error"
                    StorageAccountName = "Error"
                    AccessPolicyCount = 0
                    AccessPolicyDetails = "Error"
                    RBACRoleAssignments = "Error"
                    RBACAssignmentCount = 0
                    TotalIdentitiesWithAccess = 0
                    ServicePrincipalCount = 0
                    UserCount = 0
                    GroupCount = 0
                    ManagedIdentityCount = 0
                    ServicePrincipalDetails = "Error"
                    ManagedIdentityDetails = "Error"
                    PublicNetworkAccess = "Error"
                    NetworkAclsConfigured = "Error"
                    PrivateEndpointCount = 0
                    SystemAssignedIdentity = "Error"
                    SystemAssignedPrincipalId = "Error"
                    UserAssignedIdentityCount = 0
                    UserAssignedIdentityIds = "Error"
                    ConnectedManagedIdentityCount = 0
                    CompanyComplianceScore = 0
                    CompanyComplianceStatus = "Collection Failed"
                    ComplianceIssues = "Collection Failed"
                    ComplianceRecommendations = "Data collection failed, no recommendations available."
                    VaultRecommendations = "Data collection failed"
                    SecurityEnhancements = "Data collection failed"
                    RBACRecommendations = "Data collection failed"
                    OverPrivilegedAssignments = "Error"
                    SecretCount = 0
                    KeyCount = 0
                    CertificateCount = 0
                    WorkloadCategories = "Error"
                    EnvironmentType = "Error"
                    PrimaryWorkload = "Error"
                    SecurityInsights = "Error"
                    OptimizationRecommendations = "Error"
                    TotalItems = 0
                }
                continue
            }
        }
    }
        
    try {
        # Enhanced managed identity analysis
        $systemAssignedIdentity = $false
        $systemAssignedPrincipalId = ""
        $userAssignedIdentityCount = 0
        $userAssignedIdentityIds = @()
        
        try {
            $vaultDetails = Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction Stop
            
            # Enhanced Identity property handling with robust error checking
            if ($vaultDetails.Identity) {
                try {
                    # System-assigned identity processing with error handling
                    if ($vaultDetails.Identity.Type -match "SystemAssigned") {
                        $systemAssignedIdentity = $true
                        
                        # Check if PrincipalId exists and is valid
                        if ($vaultDetails.Identity.PrincipalId) {
                            $systemAssignedPrincipalId = $vaultDetails.Identity.PrincipalId
                        } else {
                            Write-DataIssuesLog "Identity" "System-assigned identity exists but PrincipalId is missing or null" $kv.VaultName
                            $systemAssignedPrincipalId = "PrincipalId missing"
                        }
                        
                        $global:systemManagedIdentityCount++
                        $executiveSummary.WithSystemIdentity++
                    }
                    
                    # User-assigned identities processing with error handling
                    if ($vaultDetails.Identity.UserAssignedIdentities) {
                        try {
                            $userAssignedIdentityCount = $vaultDetails.Identity.UserAssignedIdentities.Count
                            
                            # Safely extract Keys collection
                            if ($vaultDetails.Identity.UserAssignedIdentities.Keys) {
                                $userAssignedIdentityIds = $vaultDetails.Identity.UserAssignedIdentities.Keys
                            } else {
                                Write-DataIssuesLog "Identity" "User-assigned identities exist but Keys collection is missing" $kv.VaultName
                                $userAssignedIdentityIds = @("Keys collection missing")
                            }
                            
                            $global:userManagedIdentityCount += $userAssignedIdentityCount
                        } catch {
                            Write-DataIssuesLog "Identity" "Error processing user-assigned identities collection" $kv.VaultName $_.Exception.Message
                            $userAssignedIdentityCount = 0
                            $userAssignedIdentityIds = @("Error processing user-assigned identities")
                        }
                    }
                } catch {
                    Write-DataIssuesLog "Identity" "Error processing Identity properties structure" $kv.VaultName $_.Exception.Message
                    $systemAssignedIdentity = $false
                    $systemAssignedPrincipalId = "Error processing identity"
                    $userAssignedIdentityCount = 0
                    $userAssignedIdentityIds = @("Error processing identity")
                }
            } else {
                # Identity object is null or missing - this is normal for vaults without managed identities
                Write-DataIssuesLog "Identity" "Vault has no managed identity configured" $kv.VaultName "No Identity object found"
            }
        } catch {
            Write-DataIssuesLog "Identity" "Managed identity details not gathered - vault access error" $kv.VaultName $_.Exception.Message
        }
        
        # Enhanced connected managed identities processing with error handling
        # Ensure rbacAssignments is initialized
        if (-not (Get-Variable -Name 'rbacAssignments' -ErrorAction SilentlyContinue)) { $rbacAssignments = @() }
        $connectedManagedIdentities = @()
        foreach ($assignment in $rbacAssignments) {
            try {
                # Safely check for required properties with null checks
                $principalType = if ($assignment.PrincipalType) { $assignment.PrincipalType } else { "Unknown" }
                $principalName = if ($assignment.PrincipalName) { $assignment.PrincipalName } else { "Name not available" }
                $principalId = if ($assignment.PrincipalId) { $assignment.PrincipalId } else { "ID not available" }
                $roleDefinitionName = if ($assignment.RoleDefinitionName) { $assignment.RoleDefinitionName } else { "Role not available" }
                
                # Check if this is a managed identity assignment with enhanced error handling
                if ($principalType -eq 'ServicePrincipal' -and 
                    ($principalName -match 'mi-|identity|managed' -or 
                     $principalId -match '^[a-f0-9-]{36}$')) {
                    $connectedManagedIdentities += "Connected: $principalName ($roleDefinitionName)"
                }
            } catch {
                Write-DataIssuesLog "RBAC" "Error processing RBAC assignment properties" $kv.VaultName $_.Exception.Message
                $connectedManagedIdentities += "Error processing assignment: $($_.Exception.Message)"
            }
        }
        
        # Defensive: ensure $diagnostics exists before building vault data (some code paths may not initialize it)
        if (-not (Get-Variable -Name 'diagnostics' -ErrorAction SilentlyContinue)) {
            $diagnostics = @{
                Enabled = $false
                LogCategories = @()
                MetricCategories = @()
                LogAnalyticsEnabled = $false
                LogAnalyticsWorkspaceName = ""
                EventHubEnabled = $false
                EventHubNamespace = ""
                EventHubName = ""
                StorageAccountEnabled = $false
                StorageAccountName = ""
            }
        }

        # Defensive: ensure $networkConfig exists before building vault data
        if (-not (Get-Variable -Name 'networkConfig' -ErrorAction SilentlyContinue)) {
            $networkConfig = @{
                PublicNetworkAccess = "Unknown"
                NetworkAclsConfigured = $false
                PrivateEndpointCount = 0
            }
        }

        # Defensive: ensure commonly-used collections are initialized
        if (-not (Get-Variable -Name 'rbacAssignments' -ErrorAction SilentlyContinue)) { $rbacAssignments = @() }
        if (-not (Get-Variable -Name 'overPrivileged' -ErrorAction SilentlyContinue)) { $overPrivileged = @() }
        if (-not (Get-Variable -Name 'accessPolicies' -ErrorAction SilentlyContinue)) { $accessPolicies = @() }
        if (-not (Get-Variable -Name 'systemAssignedIdentity' -ErrorAction SilentlyContinue)) { $systemAssignedIdentity = $false }

        # Build comprehensive vault data
        $vaultData = @{
            SoftDeleteEnabled = if ($kv.PSObject.Properties['EnableSoftDelete']) { $kv.EnableSoftDelete -eq $true } else { $false }
            PurgeProtectionEnabled = if ($kv.PSObject.Properties['EnablePurgeProtection']) { $kv.EnablePurgeProtection -eq $true } else { $false }
            DiagnosticsEnabled = $diagnostics.Enabled
            EventHubEnabled = $diagnostics.EventHubEnabled
            LogAnalyticsEnabled = $diagnostics.LogAnalyticsEnabled
            AuditEventEnabled = "AuditEvent" -in $diagnostics.LogCategories
            PolicyEvaluationEnabled = "AzurePolicyEvaluationDetails" -in $diagnostics.LogCategories
            RBACEnabled = $rbacAssignments.Count -gt 0
            PrivateEndpointCount = $networkConfig.PrivateEndpointCount
            SystemAssignedIdentity = $systemAssignedIdentity
            OverPrivilegedAssignments = $overPrivileged
        }
        
        # Calculate dual compliance frameworks
        $complianceScore = Get-ComplianceScore -VaultData $vaultData -Framework "Microsoft"
        $companyComplianceScore = Get-ComplianceScore -VaultData $vaultData -Framework "Company"
        $complianceStatus = Get-ComplianceStatus -Score $complianceScore -Framework "Microsoft"
        $companyComplianceStatus = Get-ComplianceStatus -Score $companyComplianceScore -Framework "Company"
        
        # Ensure diagnostics is initialized for executive summary
        if (-not (Get-Variable -Name 'diagnostics' -ErrorAction SilentlyContinue)) { 
            $diagnostics = @{
                Enabled = $false
                LogCategories = @()
                MetricCategories = @()
                LogAnalyticsEnabled = $false
                LogAnalyticsWorkspaceName = ""
                EventHubEnabled = $false
                EventHubNamespace = ""
                EventHubName = ""
                StorageAccountEnabled = $false
                StorageAccountName = ""
            }
        }
        
        # Update Microsoft framework executive summary
        switch ($complianceStatus) {
            "Fully Compliant" { $executiveSummary.FullyCompliant++; $executiveSummary.MicrosoftFullyCompliant++ }
            "Partially Compliant" { $executiveSummary.PartiallyCompliant++; $executiveSummary.MicrosoftPartiallyCompliant++ }
            "Non-Compliant" { $executiveSummary.NonCompliant++; $executiveSummary.MicrosoftNonCompliant++ }
        }
        
        # Update Company framework executive summary
        switch ($companyComplianceStatus) {
            "Fully Compliant" { $executiveSummary.CompanyFullyCompliant++ }
            "Partially Compliant" { $executiveSummary.CompanyPartiallyCompliant++ }
            "Non-Compliant" { $executiveSummary.CompanyNonCompliant++ }
        }
        
        # Defensive: ensure $diagnostics exists (some code paths may remove or not initialize it)
        if (-not (Get-Variable -Name 'diagnostics' -ErrorAction SilentlyContinue)) {
            $diagnostics = @{
                Enabled = $false
                LogCategories = @()
                MetricCategories = @()
                LogAnalyticsEnabled = $false
                LogAnalyticsWorkspaceName = ""
                EventHubEnabled = $false
                EventHubNamespace = ""
                EventHubName = ""
                StorageAccountEnabled = $false
                StorageAccountName = ""
            }
        }

        if ($diagnostics -and $diagnostics.Enabled) { $executiveSummary.WithDiagnostics++ }
        if ($diagnostics -and $diagnostics.EventHubEnabled) { $executiveSummary.WithEventHub++ }
        if ($diagnostics -and $diagnostics.LogAnalyticsEnabled) { $executiveSummary.WithLogAnalytics++ }
        if ($diagnostics -and $diagnostics.StorageAccountEnabled) { $executiveSummary.WithStorageAccount++ }
        if ($networkConfig.PrivateEndpointCount -gt 0) { $executiveSummary.WithPrivateEndpoints++ }
        $rbacCount = if ($null -ne $rbacAssignments -and $rbacAssignments -is [array]) { $rbacAssignments.Count } else { 0 }
        if ($rbacCount -gt 0) { $executiveSummary.UsingRBAC++ }
        $accessPolicyCount = if ($null -ne $accessPolicies -and $accessPolicies -is [array]) { $accessPolicies.Count } else { 0 }
        if ($accessPolicyCount -gt 0) { $executiveSummary.UsingAccessPolicies++ }
        
        # Update global access policy counter (using defensive count)
        if ($accessPolicies) { $global:accessPolicyCount += $accessPolicyCount }
        
        # Generate recommendations
        $recommendations = New-SecurityRecommendations -VaultData $vaultData
        
    } catch {
        # Always initialize $diagnostics as the first line in the catch block
        $diagnostics = @{
            Enabled = $false
            LogCategories = @()
            MetricCategories = @()
            LogAnalyticsEnabled = $false
            LogAnalyticsWorkspaceName = ""
            EventHubEnabled = $false
            EventHubNamespace = ""
            EventHubName = ""
            StorageAccountEnabled = $false
            StorageAccountName = ""
        }
        $errorMsg = "Failed to analyze vault $($kv.VaultName): $($_.ToString())"
        Write-UserMessage -Message "[VaultAnalysis] [$($kv.VaultName)] $errorMsg" -Type Error
        Write-ErrorLog "VaultAnalysis" $errorMsg $kv.VaultName
        if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization*") {
            Write-PermissionsLog "VaultAnalysis" "Insufficient permissions to analyze vault" $kv.VaultName
        }
        # Add minimal record for failed analysis
        $global:auditResults += [PSCustomObject]@{
            SubscriptionId = $kvItem.SubscriptionId
            SubscriptionName = $kvItem.SubscriptionName
            KeyVaultName = $kv.VaultName
            ResourceId = $kv.ResourceId
            Location = $kv.Location
            ResourceGroupName = $kv.ResourceGroupName
            ComplianceStatus = "Analysis Failed"
            ComplianceScore = 0
            CompanyComplianceScore = 0
            CompanyComplianceStatus = "Collection Failed"
            DiagnosticsEnabled = $diagnostics.Enabled
            EventHubEnabled = $diagnostics.EventHubEnabled
            LogAnalyticsEnabled = $diagnostics.LogAnalyticsEnabled
            StorageAccountEnabled = $diagnostics.StorageAccountEnabled
            RBACAssignmentCount = 0
            PrivateEndpointCount = 0
            ErrorsEncountered = $_.Exception.Message
            LastAuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }

        # Perform cleanup of any partially created variables after error
        try {
            $cleanupVars = @('rbacAssignments', 'accessPolicies', 'identityAnalysis', 'networkConfig', 
                             'overPrivileged', 'workloadAnalysis', 'diagnostics', 'vaultData', 
                             'complianceResult', 'recommendations', 'connectedManagedIdentities')
            
            foreach ($varName in $cleanupVars) {
                if (Get-Variable -Name $varName -Scope "Script" -ErrorAction SilentlyContinue) {
                    Remove-Variable -Name $varName -Scope "Script" -ErrorAction SilentlyContinue
                }
            }
        } catch {
            # Variable cleanup failure should not break script execution
            Write-Verbose "Error cleanup variable removal failed: $($_.Exception.Message)"
        }
    }
}



# Calculate comprehensive executive summary from audit results
# Ensure $global:auditResults is an array
if (-not $global:auditResults -or $global:auditResults -isnot [array]) {
    Write-UserMessage "WARNING: `$global:auditResults is not an array, initializing as empty array" -Type Verbose
    $global:auditResults = @()
}

Write-UserMessage "Executive Summary: Processing $($global:auditResults.Count) audit results" -Type Verbose

$compliantVaults = @($global:auditResults | Where-Object { $_.ComplianceStatus -eq "Fully Compliant" }).Count
$partiallyCompliantVaults = @($global:auditResults | Where-Object { $_.ComplianceStatus -eq "Partially Compliant" }).Count
$nonCompliantVaults = @($global:auditResults | Where-Object { $_.ComplianceStatus -eq "Non-Compliant" }).Count
$highRiskVaults = @($global:auditResults | Where-Object {
    try { [int]$_.ComplianceScore -le 50 } catch { $false }
}).Count

$compliancePercentage = if ($global:auditResults.Count -gt 0) {
    [math]::Round(($compliantVaults / $global:auditResults.Count) * 100, 1)
} else { 0 }

$averageComplianceScore = if ($global:auditResults.Count -gt 0) {
    $scoreMeasure = $global:auditResults | Where-Object { $_.ComplianceScore -and $_.ComplianceScore -ne "N/A" } |
        Measure-Object -Property ComplianceScore -Average
    [math]::Round((Get-SafeProperty -Object $scoreMeasure -PropertyName 'Average' -DefaultValue 0), 1)
} else { 0 }

$companyScores = $global:auditResults | Where-Object { $_.CompanyComplianceScore -and $_.CompanyComplianceScore -ne "N/A" } |
    Select-Object -ExpandProperty CompanyComplianceScore
$companyAverageScore = if ($companyScores -and ($companyScores -is [array] -or $companyScores -is [System.Collections.IEnumerable]) -and $companyScores.Count -gt 0) {
    $companyMeasure = $companyScores | Measure-Object -Average
    [math]::Round((Get-SafeProperty -Object $companyMeasure -PropertyName 'Average' -DefaultValue 0), 1)
} else { 0 }$executiveSummary = @{
    TotalKeyVaults = $global:auditResults.Count
    CompliantVaults = $compliantVaults
    PartiallyCompliantVaults = $partiallyCompliantVaults
    NonCompliantVaults = $nonCompliantVaults
    HighRiskVaults = $highRiskVaults
    CompliancePercentage = $compliancePercentage
    AverageComplianceScore = $averageComplianceScore
    CompanyAverageScore = $companyAverageScore
    WithDiagnostics = @($global:auditResults | Where-Object {
        $_.DiagnosticsEnabled -eq "Yes" -or $_.DiagnosticsEnabled -eq $true
    }).Count
    WithEventHub = @($global:auditResults | Where-Object {
        $_.EventHubEnabled -eq "Yes" -or $_.EventHubEnabled -eq $true
    }).Count
    WithLogAnalytics = @($global:auditResults | Where-Object {
        $_.LogAnalyticsEnabled -eq "Yes" -or $_.LogAnalyticsEnabled -eq $true
    }).Count
    UsingRBAC = @($global:auditResults | Where-Object { 
        try { [int]$_.RBACAssignmentCount -gt 0 } catch { $false }
    }).Count
    WithPrivateEndpoints = @($global:auditResults | Where-Object { 
        try { [int]$_.PrivateEndpointCount -gt 0 } catch { $false }
    }).Count
    TotalSubscriptions = ($global:auditResults | Select-Object -ExpandProperty SubscriptionId -Unique | Measure-Object).Count
    FullyCompliant = $compliantVaults
    PartiallyCompliant = $partiallyCompliantVaults
    NonCompliant = $nonCompliantVaults
    UsingAccessPolicies = @($global:auditResults | Where-Object { 
        try { [int]$_.AccessPolicyCount -gt 0 } catch { $false }
    }).Count
    WithStorageAccount = @($global:auditResults | Where-Object { 
        $_.StorageAccountEnabled -eq "Yes" -or $_.StorageAccountEnabled -eq $true 
    }).Count
    # Microsoft Framework Compliance
    MicrosoftFullyCompliant = $compliantVaults
    MicrosoftPartiallyCompliant = $partiallyCompliantVaults
    MicrosoftNonCompliant = $nonCompliantVaults
    # Company Framework Compliance
    CompanyFullyCompliant = @($global:auditResults | Where-Object { $_.CompanyComplianceStatus -eq "Fully Compliant" }).Count
    CompanyPartiallyCompliant = @($global:auditResults | Where-Object { $_.CompanyComplianceStatus -eq "Partially Compliant" }).Count
    CompanyNonCompliant = @($global:auditResults | Where-Object { $_.CompanyComplianceStatus -eq "Non-Compliant" }).Count
    CompanyComplianceScore = $companyAverageScore
    # Additional metrics
    TotalServicePrincipals = 0  # Will be updated below
    TotalManagedIdentities = 0  # Will be updated below
    UserManagedIdentities = 0   # Will be updated below
    SystemManagedIdentities = 0 # Will be updated below
}

# Update final executive summary with calculations
$executiveSummary.TotalServicePrincipals = $global:serviceProviderCount
# Fix: TotalManagedIdentities should be the sum of system and user assigned managed identities
# not the RBAC-based count which represents external managed identities accessing vaults
$executiveSummary.TotalManagedIdentities = $global:systemManagedIdentityCount + $global:userManagedIdentityCount
$executiveSummary.UserManagedIdentities = $global:userManagedIdentityCount
$executiveSummary.SystemManagedIdentities = $global:systemManagedIdentityCount

$global:ScriptExecutionContext.EndTime = Get-Date
$executionTime = $global:ScriptExecutionContext.EndTime - $global:ScriptExecutionContext.StartTime
$executionTimeMinutes = [math]::Round($executionTime.TotalMinutes, 2)
$executionTimeFormatted = "{0:mm}m {0:ss}s" -f $executionTime
Write-Host ""
Write-Host "✅ Analysis completed in $executionTimeMinutes minutes ($executionTimeFormatted)" -ForegroundColor Green

# --- Export Results ---
Write-Host "📊 Generating reports..." -ForegroundColor Yellow

# Export to CSV
try {
    $global:auditResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
} catch {
    $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
    Write-ErrorLog "Export" "Failed to export CSV: $errorMessage"
    Write-Host "❌ Failed to export CSV: $errorMessage" -ForegroundColor Red
}

# --- Generate Enhanced HTML Report with All Requested Features ---
# Use the comprehensive HTML generation function for consistent output

# Initialize variables needed for HTML report generation
$IsPartialResults = $false
Write-UserMessage "IsPartialResults initialized to: $IsPartialResults" -Type Verbose

# Generate comprehensive HTML report using the unified function
Write-Host "📊 Generating comprehensive HTML report..." -ForegroundColor Cyan

# Use the comprehensive HTML generation function for consistent formatting
Write-UserMessage "About to call New-ComprehensiveHtmlReport..." -Type Verbose

# Defensive check to prevent crash when no vaults are processed
if (-not $global:auditResults -or $global:auditResults.Count -eq 0) {
    Write-Warning "No vault data was successfully processed. Generating a failure report."
    
    $failureReport = [PSCustomObject]@{
        KeyVaultName                  = "No Vaults Processed"
        KeyVaultUri                   = "N/A"
        ResourceGroup                 = "N/A"
        Location                      = "N/A"
        SubscriptionId                = "N/A"
        SubscriptionName              = "N/A"
        TenantId                      = "N/A"
        Sku                           = "N/A"
        DiagSettings                  = "N/A"
        ActivityLogs                  = "N/A"
        Certificates                  = "N/A"
        Keys                          = "N/A"
        Secrets                       = "N/A"
        SecretProperties              = "N/A"
        AccessPolicies                = "N/A"
        NetworkAcls                   = "N/A"
        RoleAssignments               = "N/A"
        PrivateEndpoints              = "N/A"
        Tags                          = "N/A"
        Content                       = "N/A"
        ErrorsEncountered             = "Critical: No vaults were successfully analyzed. This can happen due to lack of permissions, invalid vault names, or network connectivity issues. Please check the terminal for specific error messages that occurred during the analysis phase."
        PSComputerName                = $env:COMPUTERNAME
        RunspaceId                    = $global:RunspaceId
        ScriptVersion                 = $SCRIPT_VERSION
        PSVersion                     = $PSVersionTable.PSVersion.ToString()
        ExecutionTime                 = $executionTime
        StartTime                     = $global:startTime
        EndTime                       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Username                      = $env:USERNAME
        TotalVaults                   = $vaultsToProcess.Count
        SuccessfulVaults              = 0
        FailedVaults                  = $vaultsToProcess.Count
        Cmdlet                        = $MyInvocation.MyCommand.Name
        Parameters                    = $PSBoundParameters
        ComputerName                  = $env:COMPUTERNAME
        OSVersion                     = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        UserAgent                     = $userAgent
        ReportTitle                   = "Key Vault Comprehensive Security Audit Failure Report"
        ReportDate                    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ReportGeneratedBy             = "$env:USERNAME on $env:COMPUTERNAME"
        ReportColor                   = "#FF0000"
        ReportStatus                  = "Failure"
        ReportSummary                 = "No Key Vaults were successfully analyzed."
        # Add properties expected by HTML template with default values
        ComplianceScore               = 0
        CompanyComplianceScore        = 0
        ComplianceStatus              = "Non-Compliant"
        ResourceGroupName             = "N/A"
        DiagnosticsEnabled            = "No"
        EnabledLogCategories          = "N/A"
        LogAnalyticsEnabled           = "No"
        EventHubEnabled               = "No"
        StorageAccountEnabled         = "No"
        AccessPolicyCount             = 0
        RBACAssignmentCount           = 0
        ServicePrincipalCount         = 0
        ManagedIdentityCount          = 0
        SystemAssignedIdentity        = "No"
        UserAssignedIdentityCount     = 0
        UserAssignedIdentityIds       = "N/A"
        SystemAssignedPrincipalId     = "N/A"
        SoftDeleteEnabled             = "No"
        PurgeProtectionEnabled        = "No"
        PublicNetworkAccess           = "N/A"
        PrivateEndpointCount          = 0
        SecretCount                   = 0
        KeyCount                      = 0
        CertificateCount              = 0
        EnvironmentType               = "N/A"
        PrimaryWorkload               = "N/A"
        WorkloadCategories            = "N/A"
        ComplianceRecommendations     = "No recommendations available - no vaults were processed"
        ServicePrincipalDetails       = "N/A"
        ManagedIdentityDetails        = "N/A"
        RBACRoleAssignments           = "N/A"
        AccessPolicyDetails           = "N/A"
        NetworkAclsConfigured         = "N/A"
        StorageAccountName            = "N/A"
        EventHubNamespace             = "N/A"
        EventHubName                  = "N/A"
        LogAnalyticsWorkspaceName     = "N/A"
        ResourceId                    = "N/A"
        LastAuditDate                 = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    $global:auditResults = @($failureReport)
}

$htmlGenerated = New-ComprehensiveHtmlReport -OutputPath $htmlPath -AuditResults $global:auditResults -ExecutiveSummary $executiveSummary -AuditStats $global:auditStats -IsPartialResults $IsPartialResults
Write-UserMessage "New-ComprehensiveHtmlReport call completed" -Type Verbose

if ($htmlGenerated) {
    # Success - report will be shown in final summary
} else {
    Write-Host "❌ Failed to generate HTML report" -ForegroundColor Red
    Write-ErrorLog "Export" "Failed to generate comprehensive HTML report"
}

# --- Upload Final Reports to OneDrive/SharePoint ---
if ($global:enableOneDriveUpload -and (Get-Command Initialize-GraphAuth -ErrorAction SilentlyContinue)) {
    try {
        Write-Host "☁️ Uploading final reports to OneDrive..." -ForegroundColor Cyan
        Write-Host "   📍 Environment: $($global:environmentInfo.Environment)" -ForegroundColor Gray
        
        if (Initialize-GraphAuth -Verbose:($VerbosePreference -eq 'Continue')) {
            $uploadResults = Send-FinalReports -CsvFilePath $csvPath -HtmlPath $htmlPath
            
            if ($uploadResults -and $uploadResults.Count -gt 0) {
                Write-Host "✅ Final reports uploaded to OneDrive: $($uploadResults.Count) files" -ForegroundColor Green
                
                # Log final artifact URLs for reference
                foreach ($result in $uploadResults) {
                    if ($result.Url) {
                        Write-UploadLog "Artifact" "Final report available" -FileName $result.FileName -ArtifactUrl $result.Url
                    }
                }
            } else {
                Write-Host "⚠️ Final report upload completed with warnings - check upload logs" -ForegroundColor Yellow
            }
        } else {
            Write-Host "⚠️ OneDrive authentication not available - reports saved locally only" -ForegroundColor Yellow
        }
    } catch {
        Write-UploadLog "Error" "Final upload failed but audit completed successfully: $_" -Context "NonCritical"
        Write-Host "⚠️ Upload failed but audit completed - reports available locally" -ForegroundColor Yellow
    }
} else {
    if (-not $global:enableOneDriveUpload) {
        $reason = switch ($global:environmentInfo.Environment) {
            "Local" { "User chose not to upload to OneDrive" }
            "CloudShell" { "OneDrive upload initialization failed" }
            default { "OneDrive upload not enabled for this environment" }
        }
        Write-Host "ℹ️  OneDrive upload skipped - $reason" -ForegroundColor Cyan
    } else {
        Write-Host "ℹ️  OneDrive upload functionality not available (Graph modules not found)" -ForegroundColor Gray
    }
    Write-Host "📁 All reports saved locally in: $(Split-Path $htmlPath -Parent)" -ForegroundColor Green
}

# --- Final Summary ---

Write-Host ""
Write-Host "🎯 AUDIT COMPLETE" -ForegroundColor Green -BackgroundColor Black
Write-Host "==================" -ForegroundColor Green
Write-Host ""

# Summary table
$rbacPercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'UsingRBAC' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)
$diagnosticsPercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'WithDiagnostics' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)
$eventHubPercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'WithEventHub' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)
$logAnalyticsPercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'WithLogAnalytics' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)
$storageAccountPercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'WithStorageAccount' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)
$privateEndpointsPercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'WithPrivateEndpoints' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)
$compliancePercentage = [math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'FullyCompliant' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1)

$summaryData = @(
    @{Metric="Total Subscriptions"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalSubscriptions' -DefaultValue 0); Percentage="N/A"}
    @{Metric="Skipped Subscriptions"; Value=(Get-SafeProperty -Object $global:auditStats -PropertyName 'SkippedSubscriptions' -DefaultValue 0); Percentage="N/A"}
    @{Metric="Total Key Vaults"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 0); Percentage="N/A"}
    @{Metric="Fully Compliant"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'FullyCompliant' -DefaultValue 0); Percentage="$([math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'FullyCompliant' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1))%"}
    @{Metric="Partially Compliant"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'PartiallyCompliant' -DefaultValue 0); Percentage="$([math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'PartiallyCompliant' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1))%"}
    @{Metric="Non-Compliant"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'NonCompliant' -DefaultValue 0); Percentage="$([math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'NonCompliant' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1))%"}
    @{Metric="Using RBAC"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'UsingRBAC' -DefaultValue 0); Percentage="$rbacPercentage%"}
    @{Metric="Using Access Policies"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'UsingAccessPolicies' -DefaultValue 0); Percentage="$([math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'UsingAccessPolicies' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1))%"}
    @{Metric="Total Service Principals"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalServicePrincipals' -DefaultValue 0); Percentage="N/A"}
    @{Metric="Total Managed Identities"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalManagedIdentities' -DefaultValue 0); Percentage="N/A"}
    @{Metric="With Diagnostics"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'WithDiagnostics' -DefaultValue 0); Percentage="$diagnosticsPercentage%"}
    @{Metric="Event Hub Enabled"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'WithEventHub' -DefaultValue 0); Percentage="$eventHubPercentage%"}
    @{Metric="Log Analytics"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'WithLogAnalytics' -DefaultValue 0); Percentage="$logAnalyticsPercentage%"}
    @{Metric="Storage Logging"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'WithStorageAccount' -DefaultValue 0); Percentage="$storageAccountPercentage%"}
    @{Metric="Private Endpoints"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'WithPrivateEndpoints' -DefaultValue 0); Percentage="$privateEndpointsPercentage%"}
    @{Metric="System Identities"; Value=(Get-SafeProperty -Object $executiveSummary -PropertyName 'SystemManagedIdentities' -DefaultValue 0); Percentage="$([math]::Round(((Get-SafeProperty -Object $executiveSummary -PropertyName 'SystemManagedIdentities' -DefaultValue 0) / [math]::Max((Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 1), 1)) * 100, 1))%"}
)

$summaryData | Format-Table -Property @{Label="Metric"; Expression={$_.Metric}; Width=25}, 
                                     @{Label="Count"; Expression={$_.Value}; Width=10}, 
                                     @{Label="Percentage"; Expression={$_.Percentage}; Width=15} -AutoSize

Write-Host ""

# Color-coded compliance summary
if ($compliancePercentage -ge 90) {
    Write-Host "🎉 EXCELLENT: $compliancePercentage% compliance rate!" -ForegroundColor Green
} elseif ($compliancePercentage -ge 70) {
    Write-Host "✅ GOOD: $compliancePercentage% compliance rate - room for improvement" -ForegroundColor Yellow
} elseif ($compliancePercentage -ge 50) {
    Write-Host "⚠️  MODERATE: $compliancePercentage% compliance rate - action needed" -ForegroundColor Yellow
} else {
    Write-Host "🚨 ATTENTION REQUIRED: $compliancePercentage% compliance rate - immediate action required" -ForegroundColor Red
}

# Log completion
Write-ErrorLog "Audit" "Azure Key Vault Comprehensive Audit completed successfully"
Write-ErrorLog "Audit" "Summary: $(Get-SafeProperty -Object $executiveSummary -PropertyName 'TotalKeyVaults' -DefaultValue 0) vaults analyzed, $compliancePercentage% compliance rate, $(Get-SafeProperty -Object $global:auditStats -PropertyName 'TokenRefreshCount' -DefaultValue 0) token refresh(es)"
Write-PermissionsLog "Audit" "Audit completed with permissions validation logged"
Write-DataIssuesLog "Audit" "Data collection completed - check logs for any collection issues"

if ($TestMode) {
    Write-Host ""
    Write-Host "🧪 TEST MODE COMPLETE" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "Ready for full production scan!" -ForegroundColor Yellow
    Write-Host "Run without -TestMode parameter for complete organizational assessment" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🔗 Next Steps & Resources:" -ForegroundColor Cyan
Write-Host "   📖 Azure Key Vault Best Practices: https://learn.microsoft.com/azure/key-vault/general/best-practices" -ForegroundColor Blue
Write-Host "   🛡️  Microsoft Security Benchmark: https://learn.microsoft.com/security/benchmark/azure/" -ForegroundColor Blue
Write-Host "   🏛️  Azure Architecture Center: https://learn.microsoft.com/azure/architecture/" -ForegroundColor Blue
Write-Host "   📚 Key Vault Security Guide: https://learn.microsoft.com/azure/key-vault/general/security-features" -ForegroundColor Blue

Write-Host ""
Write-Host "Thank you for using the Enhanced Azure Key Vault Comprehensive Audit Tool!" -ForegroundColor Green
Write-Host "For support or questions, please refer to the generated logs and documentation." -ForegroundColor Gray

Write-Host ""
Write-Host "📊 PRODUCTION AUDIT STATISTICS" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host "Execution Duration: $executionTimeMinutes minutes ($executionTimeFormatted)" -ForegroundColor White
Write-Host "Successful Vaults: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'SuccessfulVaults' -DefaultValue 0)" -ForegroundColor Green
Write-Host "Skipped Vaults: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'SkippedVaults' -DefaultValue 0)" -ForegroundColor $(if ((Get-SafeProperty -Object $global:auditStats -PropertyName 'SkippedVaults' -DefaultValue 0) -gt 0) { "Yellow" } else { "Green" })
Write-Host "Total Retries: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'TotalRetries' -DefaultValue 0)" -ForegroundColor $(if ((Get-SafeProperty -Object $global:auditStats -PropertyName 'TotalRetries' -DefaultValue 0) -gt 0) { "Yellow" } else { "Green" })
Write-Host "Token Refreshes: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'TokenRefreshCount' -DefaultValue 0)" -ForegroundColor Cyan
Write-Host "Processing Errors: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'ProcessingErrors' -DefaultValue 0)" -ForegroundColor $(if ((Get-SafeProperty -Object $global:auditStats -PropertyName 'ProcessingErrors' -DefaultValue 0) -gt 0) { "Red" } else { "Green" })
Write-Host "Permission Errors: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'PermissionErrors' -DefaultValue 0)" -ForegroundColor $(if ((Get-SafeProperty -Object $global:auditStats -PropertyName 'PermissionErrors' -DefaultValue 0) -gt 0) { "Red" } else { "Green" })
Write-Host "Authentication Errors: $(Get-SafeProperty -Object $global:auditStats -PropertyName 'AuthenticationErrors' -DefaultValue 0)" -ForegroundColor $(if ((Get-SafeProperty -Object $global:auditStats -PropertyName 'AuthenticationErrors' -DefaultValue 0) -gt 0) { "Red" } else { "Green" })
Write-Host "Skipped Subscriptions: $($global:auditStats.SkippedSubscriptions)" -ForegroundColor $(if ($global:auditStats.SkippedSubscriptions -gt 0) { "Yellow" } else { "Green" })

Write-Host ""
Write-Host "📁 OUTPUT FILES GENERATED" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host "HTML Report: $htmlPath" -ForegroundColor Green
Write-Host "CSV Data: $csvPath" -ForegroundColor Green
Write-Host "Error Log: $errPath" -ForegroundColor Yellow
Write-Host "Permissions Log: $permissionsPath" -ForegroundColor Yellow
Write-Host "Data Collection Log: $dataIssuesPath" -ForegroundColor Yellow

# --- Cloud Upload Integration ---
if ($PSBoundParameters.ContainsKey('UploadToCloud') -and $UploadToCloud -and $global:enableOneDriveUpload) {
    Write-Host ""
    Write-Host "📤 Automatic cloud upload enabled..." -ForegroundColor Cyan
    Write-Host "   📍 Environment: $($global:environmentInfo.Environment)" -ForegroundColor Gray
    
    # Get target upload path
    $uploadPath = Get-CloudUploadPath -ProvidedPath $CloudUploadPath
    
    # Attempt cloud upload
    $uploadSuccess = Invoke-CloudUpload -OutputDirectory $outDir -CsvFilePath $csvPath -HtmlPath $htmlPath -ErrorLogPath $errPath -PermissionsLogPath $permissionsPath -DataIssuesLogPath $dataIssuesPath -TargetPath $uploadPath
    
    if ($uploadSuccess) {
        Write-Host "✅ Cloud upload completed successfully" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Cloud upload failed or was cancelled" -ForegroundColor Yellow
    }
} elseif ($PSBoundParameters.ContainsKey('UploadToCloud') -and $UploadToCloud -and -not $global:enableOneDriveUpload) {
    Write-Host ""
    Write-Host "ℹ️  Cloud upload parameter provided but OneDrive upload not enabled" -ForegroundColor Cyan
    $reason = switch ($global:environmentInfo.Environment) {
        "Local" { "User chose not to upload to OneDrive in local environment" }
        "CloudShell" { "OneDrive upload initialization failed in Cloud Shell" }
        default { "OneDrive upload not available for this environment" }
    }
    Write-Host "   📝 Reason: $reason" -ForegroundColor Gray
    Write-Host "   📁 All files saved locally: $(Split-Path $htmlPath -Parent)" -ForegroundColor Green
} else {
    # Original Azure Cloud Shell detection logic (legacy support)
    $isCloudShell = $false
    $cloudShellIndicators = @($env:ACC_TERM, $env:ACC_CLOUD, $env:AZUREPS_HOST_ENVIRONMENT)
    foreach ($indicator in $cloudShellIndicators) {
        if (-not [string]::IsNullOrWhiteSpace($indicator)) {
            $isCloudShell = $true
            break
        }
    }
    
    if (-not $isCloudShell -and $PWD.Path.StartsWith('/home/') -and (Test-Path '/usr/bin/az' -ErrorAction SilentlyContinue)) {
        $isCloudShell = $true
    }
    
    if ($isCloudShell) {
        Write-Host ""
        Write-Host "☁️  Azure Cloud Shell detected" -ForegroundColor Cyan
        Write-Host "To prevent data loss when Cloud Shell session expires, you can upload files to OneDrive/SharePoint." -ForegroundColor Yellow
        Write-Host ""
        $offerUpload = Read-Host "Would you like to upload audit files to OneDrive/SharePoint? (Y/N)"
        
        if ($offerUpload -match '^[Yy]') {
            # Get target upload path
            $uploadPath = Get-CloudUploadPath -ProvidedPath $CloudUploadPath
            
            # Attempt cloud upload
            $uploadSuccess = Invoke-CloudUpload -OutputDirectory $outDir -CsvFilePath $csvPath -HtmlPath $htmlPath -ErrorLogPath $errPath -PermissionsLogPath $permissionsPath -DataIssuesLogPath $dataIssuesPath -TargetPath $uploadPath
            
            if ($uploadSuccess) {
                Write-Host "✅ Cloud upload completed successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Cloud upload failed or was cancelled" -ForegroundColor Yellow
            }
        } else {
            Write-Host "📋 Files remain in Cloud Shell temporary storage: $outDir" -ForegroundColor Gray
            Write-Host "⚠️  Remember to download files before Cloud Shell session expires" -ForegroundColor Yellow
        }
    }
}

# Final token check and cleanup
try {
    $finalToken = Get-AzAccessToken -ErrorAction SilentlyContinue
    if ($finalToken) {
        # Final token status with enhanced managed identity support
        $timeUntilFinalExpiry = $finalToken.ExpiresOn - (Get-Date)
        Write-Host ""
        Write-Host "🔐 Final Token Status: Valid for $([math]::Round($timeUntilFinalExpiry.TotalMinutes, 1)) more minutes" -ForegroundColor Gray
        Write-Host "👤 Authenticated User: $($global:currentUser)" -ForegroundColor Gray
    }
} catch {
    # Token check failed - not critical for final reporting
    Write-Host "🔐 Token Status: Unknown (check failed)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "🏆 AUDIT COMPLETED SUCCESSFULLY" -ForegroundColor Green

# Perform final memory cleanup
Write-Host "🧹 Performing final cleanup..." -ForegroundColor Cyan
try {
    # Force final cleanup of all large variables and intermediate data
    Invoke-MemoryCleanup -VaultIndex $allKeyVaults.Count -ForceCleanup $true
    
    # Additional cleanup of script-level variables
    $finalCleanupVars = @('allKeyVaults', 'kvItem', 'kv', 'testKeyVaults', 'oldCheckpoints', 
                         'processedVaultIds', 'currentProcessedVaults', 'latestCheckpoint')
    
    $finalCleaned = @()
    foreach ($varName in $finalCleanupVars) {
        if (Get-Variable -Name $varName -ErrorAction SilentlyContinue) {
            try {
                Remove-Variable -Name $varName -Force -ErrorAction Stop
                $finalCleaned += $varName
            } catch {
                Write-Verbose "Failed to remove variable $varName`: $($_.Exception.Message)"
            }
        }
    }
} catch {
    Write-Host "Final cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host "Script execution completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" -ForegroundColor Gray
Write-Host "Thank you for using the Enhanced Azure Key Vault Comprehensive Audit Tool!" -ForegroundColor Green

#End of Script