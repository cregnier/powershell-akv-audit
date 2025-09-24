# Single Vault Audit Mode - Test Instructions

## Overview

The `-SingleVault` parameter has been enhanced to provide comprehensive Azure Key Vault auditing for a single specified vault, matching the full audit capabilities while targeting only one vault for faster validation and testing.

## Prerequisites

Before testing, ensure you have:

1. **PowerShell 7.x or higher**
   ```powershell
   pwsh --version
   ```

2. **Azure PowerShell Modules** (will auto-install if missing)
   ```powershell
   Get-Module -ListAvailable Az.Accounts, Az.KeyVault, Az.Resources, Az.Monitor, Az.Security
   ```

3. **Azure Authentication with appropriate permissions:**
   - **Reader** role at subscription or management group level
   - **Key Vault Reader** role for Key Vault access
   - **Monitoring Reader** role for diagnostics access
   - **Directory Readers** in Azure AD for identity analysis

## Test Scenarios

### Test 1: Basic Single Vault Analysis

**Command:**
```powershell
.\Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -VaultName "YourVaultName"
```

**Expected Behavior:**
- Script searches all accessible subscriptions for the specified vault
- Performs comprehensive analysis including diagnostics, RBAC, compliance, and workload analysis
- Generates timestamped CSV and HTML reports

**Validation Points:**
1. **Console Output Verification:**
   ```
   🎯 SINGLE VAULT DIAGNOSTICS MODE
   ===========================
   🔐 Authenticating to Azure...
   📊 Analyzing diagnostic settings...
   🔐 Analyzing RBAC assignments...
   👥 Analyzing identities...
   🔑 Analyzing access policies...
   🌐 Analyzing network configuration...
   📊 Analyzing workload patterns...
   🔍 Analyzing over-privileged assignments...
   🆔 Processing managed identities...
   📋 Building comprehensive vault data...
   🏆 Calculating compliance scores...
   💡 Generating security recommendations...
   📄 Generating comprehensive reports...
   ```

2. **Results Summary Format:**
   ```
   ✅ SINGLE VAULT COMPREHENSIVE AUDIT COMPLETE
   =======================================================
   📊 Comprehensive Analysis Summary for: [VaultName]

   🔬 DIAGNOSTICS ANALYSIS:
   🏆 COMPLIANCE ANALYSIS:
   🔐 ACCESS ANALYSIS:
   📦 WORKLOAD ANALYSIS:
   🌐 NETWORK SECURITY:
   💡 RECOMMENDATIONS:
   ```

### Test 2: Interactive Vault Name Entry

**Command:**
```powershell
.\Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault
```

**Expected Behavior:**
- Script prompts: "Enter the Key Vault name to analyze:"
- User enters vault name interactively
- Continues with full analysis

### Test 3: Vault Not Found Scenario

**Command:**
```powershell
.\Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -VaultName "NonExistentVault"
```

**Expected Behavior:**
- Script searches all accessible subscriptions
- Displays helpful error message with troubleshooting guidance:
  ```
  ❌ Key Vault 'NonExistentVault' not found in any accessible subscription
     💡 Please verify:
        - Vault name is correct (case-sensitive)
        - You have Reader permissions on the vault's resource group or subscription
        - Vault exists and is not deleted
  ```

### Test 4: Parameter Validation

**Test Invalid Combinations:**
```powershell
# Should fail - SingleVault with Resume
.\Get-AKV_Roles&SecAuditCompliance.ps1 -SingleVault -Resume

# Should fail - VaultName without SingleVault  
.\Get-AKV_Roles&SecAuditCompliance.ps1 -VaultName "TestVault"
```

**Expected Error Messages:**
```
❌ Error: -SingleVault cannot be used with -Resume, -ProcessPartial, or -ReportFromCsv parameters.
❌ Error: -VaultName can only be used with -SingleVault parameter.
```

## Output Validation

### CSV Output Verification

**File Location:** `~/Documents/KeyVaultAudit/KeyVaultSingleVault_[VaultName]_[timestamp].csv`

**Required Columns (verify all are present and populated):**

#### Basic Information
- SubscriptionId, SubscriptionName, KeyVaultName, ResourceId, Location, ResourceGroupName

#### Diagnostic Settings (should NOT be blank if diagnostics exist)
- DiagnosticsEnabled, EnabledLogCategories, EnabledMetricCategories
- LogAnalyticsEnabled, LogAnalyticsWorkspaceName
- EventHubEnabled, EventHubNamespace, EventHubName
- StorageAccountEnabled, StorageAccountName

#### Compliance Analysis
- ComplianceStatus, ComplianceScore, CompanyComplianceScore, CompanyComplianceStatus
- ComplianceRecommendations, VaultRecommendations, SecurityEnhancements

#### Access Control
- AccessPolicyCount, AccessPolicyDetails
- RBACAssignmentCount, RBACRoleAssignments
- ServicePrincipalCount, UserCount, GroupCount, ManagedIdentityCount
- ServicePrincipalDetails, ManagedIdentityDetails
- OverPrivilegedAssignments

#### Workload Analysis  
- SecretCount, KeyCount, CertificateCount, TotalItems
- WorkloadCategories, EnvironmentType, PrimaryWorkload
- SecurityInsights, OptimizationRecommendations

#### Security Configuration
- SoftDeleteEnabled, PurgeProtectionEnabled
- PublicNetworkAccess, NetworkAclsConfigured, PrivateEndpointCount
- SystemAssignedIdentity, SystemAssignedPrincipalId
- UserAssignedIdentityCount, UserAssignedIdentityIds

### HTML Output Verification

**File Location:** `~/Documents/KeyVaultAudit/KeyVaultSingleVault_[VaultName]_[timestamp].html`

**Validation Points:**
1. **Executive Summary Section** - Should show:
   - Total Vaults: 1
   - Compliance scores for both Microsoft and Company frameworks
   - Diagnostic settings summary
   - Access control summary

2. **Detailed Analysis Section** - Should include:
   - Full vault details table with all 65+ columns
   - Color-coded compliance status
   - Detailed diagnostic settings if configured
   - RBAC and access policy details
   - Workload analysis results

3. **Visual Elements:**
   - Compliance score color coding (Green ≥80%, Yellow 60-79%, Red <60%)
   - Diagnostic settings status indicators
   - Responsive design for different screen sizes

## Specific Diagnostic Settings Test Cases

### Test Case 1: Vault with Complete Diagnostic Configuration

**Expected CSV Output (no blank fields):**
```csv
DiagnosticsEnabled,EnabledLogCategories,EnabledMetricCategories,LogAnalyticsEnabled,LogAnalyticsWorkspaceName,EventHubEnabled,EventHubNamespace,EventHubName,StorageAccountEnabled,StorageAccountName
True,"AuditEvent,AzurePolicyEvaluationDetails","AllMetrics",True,"my-workspace",True,"my-eventhub-ns","my-eventhub",True,"mystorageaccount"
```

### Test Case 2: Vault with Partial Diagnostic Configuration

**Expected Behavior:**
- Only enabled destinations should show TRUE
- Disabled destinations should show FALSE
- Names/namespaces should only appear for enabled destinations

### Test Case 3: Vault with No Diagnostic Configuration

**Expected CSV Output:**
```csv
DiagnosticsEnabled,EnabledLogCategories,EnabledMetricCategories,LogAnalyticsEnabled,EventHubEnabled,StorageAccountEnabled
False,"","",False,False,False
```

## Performance Validation

**Expected Timing:**
- Authentication: 10-30 seconds
- Single vault analysis: 30-90 seconds
- Report generation: 5-15 seconds
- **Total time: 1-3 minutes** (vs hours for full organizational scan)

## Troubleshooting Common Issues

### Issue: "Insufficient permissions" errors

**Resolution:**
1. Verify Azure authentication: `Get-AzContext`
2. Check required role assignments
3. Review permissions logs: `KeyVaultAudit_permissions_[timestamp].log`

### Issue: "Vault not found" despite existing vault

**Resolution:**
1. Verify vault name is case-sensitive exact match
2. Check if vault is in a different subscription
3. Verify subscription access with: `Get-AzSubscription`

### Issue: Blank diagnostic settings columns despite visible Azure Portal configuration

**Resolution:**
1. Check if user has "Monitoring Reader" role
2. Verify diagnostics are actually enabled (not just showing in portal UI)
3. Review data issues log: `KeyVaultAudit_dataissues_[timestamp].log`

## Success Criteria

✅ **SingleVault mode should produce:**
1. **Complete CSV with 65+ populated columns** (no unexpected blanks where data exists)
2. **Comprehensive HTML report** with executive summary and detailed analysis
3. **Accurate diagnostic settings data** matching Azure Portal configuration
4. **Compliance scores** for both Microsoft and Company frameworks
5. **Detailed workload analysis** showing secrets/keys/certificates breakdown
6. **Security recommendations** based on vault configuration
7. **Execution time under 3 minutes** for single vault analysis

---

**Note:** All test scenarios should work without Azure authentication errors in the sandboxed environment. The script includes comprehensive error handling and should provide clear guidance for any issues encountered.