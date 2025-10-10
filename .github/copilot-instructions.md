# Azure Key Vault Audit Script Repository

**ALWAYS follow these instructions first and fallback to additional search and context gathering only if the information here is incomplete or found to be in error.**

This repository contains a comprehensive PowerShell script for Azure Key Vault security and compliance auditing. The main script performs detailed RBAC analysis, managed identity detection, service principal analysis, compliance scoring, and generates executive-level HTML and CSV reports.

## Working Effectively

### Prerequisites and Environment Setup
- Install PowerShell 7.x: `pwsh --version` should return 7.x or higher
- Check execution policy: `pwsh -Command "Get-ExecutionPolicy"` (should be `Unrestricted` or `RemoteSigned`)
- Set execution policy if needed: `pwsh -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"`

### Required Azure PowerShell Modules
Install required Azure modules (takes 5-15 minutes, NEVER CANCEL):
```powershell
pwsh -Command "Install-Module -Name Az.Accounts, Az.KeyVault, Az.Resources, Az.Monitor, Az.Security -Scope CurrentUser -Force -AllowClobber"
```

Set timeout to 20+ minutes for module installation. If installation fails due to repository issues, this is expected in sandboxed environments - the script will attempt auto-installation when run.

### Validation and Linting
- **Syntax validation** (< 1 second): `pwsh -Command "$ast = [System.Management.Automation.Language.Parser]::ParseFile('./Get-AKV_Roles-SecAuditCompliance.ps1', [ref]$null, [ref]$null); Write-Host 'Syntax valid'"`
- **PSScriptAnalyzer linting** (6-10 seconds): `pwsh -Command "Invoke-ScriptAnalyzer -Path './Get-AKV_Roles-SecAuditCompliance.ps1' -ExcludeRule PSAvoidUsingWriteHost,PSAvoidUsingPositionalParameters"`
  - Note: PSScriptAnalyzer installation may fail in sandboxed environments - this is expected
  - The script has known style warnings (Write-Host usage, positional parameters) that are acceptable for this interactive audit tool
- **Help system test** (< 1 second): `pwsh -Command "Get-Help './Get-AKV_Roles-SecAuditCompliance.ps1'"`

### Running the Script

#### Authentication Requirements
The script requires Azure authentication with these minimum permissions:
- **Reader** role at subscription or management group level
- **Key Vault Reader** role for Key Vault access  
- **Monitoring Reader** role for diagnostics access
- **Directory Readers** in Azure AD for identity analysis

#### Test Mode Execution (5-30 minutes depending on Key Vault count)
**NEVER CANCEL** - Azure API calls can be slow, especially with authentication:
```powershell
pwsh -Command "./Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Limit 3"
```
- Use timeout of 45+ minutes for test mode
- Script will prompt for Azure login if not authenticated
- Creates output files in `~/Documents/KeyVaultAudit/` with timestamp

#### Full Production Scan (30 minutes to several hours)
**NEVER CANCEL** - Full organizational scans take significant time:
```powershell  
pwsh -Command "./Get-AKV_Roles-SecAuditCompliance.ps1"
```
- Set timeout to 4+ hours for large organizations
- Use `-TestMode` first to validate setup before full scan

### Output Files and Validation
The script generates timestamped files in `~/Documents/KeyVaultAudit/`:
- `KeyVaultComprehensiveAudit_[timestamp].html` - Executive report
- `KeyVaultComprehensiveAudit_[timestamp].csv` - Detailed data  
- `KeyVaultAudit_errors_[timestamp].log` - Error log
- `KeyVaultAudit_permissions_[timestamp].log` - Permissions log
- `KeyVaultAudit_dataissues_[timestamp].log` - Data collection issues

## Manual Validation Scenarios

**CRITICAL**: After making changes to the script, ALWAYS test these scenarios:

### Scenario 1: Help and Parameter Validation
```powershell
pwsh -Command "Get-Help './Get-AKV_Roles-SecAuditCompliance.ps1' -Examples"
pwsh -Command "Get-Help './Get-AKV_Roles-SecAuditCompliance.ps1' -Parameter TestMode"
```
- Verify help documentation displays correctly
- Confirm parameter descriptions are accurate

### Scenario 2: Syntax and Code Quality Check  
```powershell
pwsh -Command "$ast = [System.Management.Automation.Language.Parser]::ParseFile('./Get-AKV_Roles-SecAuditCompliance.ps1', [ref]$null, [ref]$null); if ($ast) { Write-Host 'PowerShell syntax valid' } else { Write-Host 'Syntax errors found' }"
```
- Must return "PowerShell syntax valid"
- Any syntax errors will prevent script execution

### Scenario 3: Module Installation Test (when Azure modules are available)
Run the prerequisite check portion of the script:
```powershell
pwsh -Command "& { $modules = @('Az.Accounts', 'Az.KeyVault', 'Az.Resources', 'Az.Monitor', 'Az.Security'); foreach ($module in $modules) { if (Get-Module -ListAvailable -Name $module) { Write-Host \"✅ $module available\" } else { Write-Host \"❌ $module missing\" } } }"
```
- Should show module availability status
- Missing modules will be auto-installed during script execution

### Scenario 4: Authentication Flow Test (without actual Azure login)
Test the authentication functions without connecting:
```powershell
pwsh -Command "& './Get-AKV_Roles-SecAuditCompliance.ps1' -TestMode -Limit 1" 
```
- Should fail at authentication step (expected when not logged into Azure)
- Verify error messages are helpful and not cryptic
- Should not crash with unhandled exceptions

## Common Tasks and Timing Expectations

### Build and Test Workflow (Total: 10-20 seconds)
1. **Syntax validation**: `< 1 second`
2. **Linting** (if PSScriptAnalyzer available): `6-10 seconds` 
3. **Help system check**: `< 1 second`

### Development Workflow
1. Make changes to the script
2. **ALWAYS** run syntax validation first
3. Test with `-TestMode -Limit 1` for basic functionality 
4. Run full linting if available
5. Test actual Azure scenarios only if you have valid Azure access

### File Structure Reference
```
powershell-akv-audit/
├── Get-AKV_Roles-SecAuditCompliance.ps1    # Main audit script (1649 lines)
├── README.md                                # Basic repository info
├── requirements.md                          # Enhancement requirements
└── .github/
    └── copilot-instructions.md              # This file
```

### Key Script Functions and Areas
When working with the script, these are important areas:
- **Lines 107-135**: Module installation and import logic
- **Lines 137-147**: Output file path setup  
- **Lines 160-179**: Logging functions
- **Lines 216-289**: Authentication and token management
- **Lines 637-700**: Main Key Vault discovery loop
- **Lines 910-920**: CSV export logic
- **Lines 920-1550**: HTML report generation

### Authentication Context and User Information
The script tracks the current user via `$global:currentUser` and authentication via:
- `Get-AzContext` for current context
- `Connect-AzAccount` for authentication
- Token refresh logic to handle long-running scans

### Error Handling and Logging
The script uses three log types:
- **Error log**: Authentication and API failures  
- **Permissions log**: Access denied scenarios
- **Data issues log**: Missing or incomplete data collection

## Important Notes

### Known Limitations
- **Cannot run without Azure authentication** - will fail at Connect-AzAccount step
- **Requires appropriate Azure permissions** - Reader roles at minimum
- **PowerShell module repositories may not be available** in sandboxed environments
- **Long execution times** are normal for comprehensive organizational scans

### Timing Guidelines  
- **Syntax validation**: < 1 second (always run first)
- **Module checks**: < 5 seconds
- **Single Key Vault analysis**: 30-60 seconds per vault
- **Test mode (3 vaults)**: 5-15 minutes with authentication
- **Full organizational scan**: 1-8 hours depending on size
- **Report generation**: 10-30 seconds

### Development Best Practices
- **Test changes in TestMode first** before full scans
- **Always validate syntax** before committing changes  
- **Check authentication context handling** when modifying user/date logic
- **Verify output file generation** and HTML report formatting
- **Test error handling** for common failure scenarios

Remember: This is an enterprise audit tool designed for comprehensive organizational assessment. Authentication and API call timing varies significantly based on Azure tenant size and network conditions.