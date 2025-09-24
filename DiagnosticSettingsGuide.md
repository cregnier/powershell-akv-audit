# Diagnostic Settings Validation Guide

This document explains the specific diagnostic settings requirements and validation checks performed by the Azure Key Vault audit script.

## Required Diagnostic Settings

### Minimum Requirements
For compliance, each Key Vault should have diagnostic settings enabled with:

1. **Diagnostic Settings Enabled:** Basic requirement
2. **Audit Log Categories:** Must include specific audit categories
3. **Destination Configuration:** Logs should go to appropriate destinations
4. **Company-Specific Requirements:** Special namespace requirements

### Audit Log Categories

#### Required Categories
The audit script validates that these log categories are enabled:

- **AuditEvent** - Key Vault access events and operations
- **AuditLogs** - Alternative name for audit events in some API versions  
- **Policy** - Policy evaluation and access control decisions
- **AuditPolicyEvaluationDetails** - Detailed policy evaluation results

#### Category Validation Logic
```
IF diagnostic settings enabled:
  CHECK LogCategories contains:
    - "AuditEvent" OR "AuditLogs" OR "Audit" (any audit-related category)
    AND
    - "Policy" OR "AuditPolicyEvaluationDetails" (policy evaluation)
```

### Destination Requirements

#### Event Hub (Primary Requirement)
- **Event Hub Enabled:** Must be true
- **Event Hub Namespace:** Should be specified
- **Company Requirement:** Namespace must be "InfoSecEventHubwestus"

#### Alternative Destinations (Secondary)
- **Log Analytics Workspace:** For query and analysis capabilities
- **Storage Account:** For long-term retention and compliance archiving

### Company-Specific Compliance

#### InfoSecEventHubwestus Requirement
The organization requires all Key Vault audit logs to be sent to the specific Event Hub namespace:
- **Namespace:** `InfoSecEventHubwestus`
- **Region:** West US (implied by name)
- **Purpose:** Centralized security monitoring and SIEM integration

#### Validation Process
1. Check if Event Hub is configured
2. Extract namespace from Event Hub authorization rule ID
3. Compare against required namespace: "InfoSecEventHubwestus"
4. Flag non-compliant configurations

## Troubleshooting Diagnostic Settings

### Common Issues

#### Diagnostic Settings Not Found
**Possible causes:**
- Diagnostic settings not configured
- Insufficient permissions to read diagnostic settings
- API version compatibility issues

**Resolution:**
1. Verify account has "Monitoring Reader" role
2. Check if diagnostic settings exist in Azure portal
3. Ensure Key Vault resource ID is correct

#### Event Hub Namespace Mismatch
**Issue:** Event Hub configured but wrong namespace
**Expected:** InfoSecEventHubwestus
**Common alternatives:**
- Default Event Hub namespaces
- Regional Event Hub namespaces
- Development/test Event Hub namespaces

**Resolution:**
1. Update diagnostic settings to use correct Event Hub
2. Ensure InfoSecEventHubwestus namespace exists and is accessible
3. Verify connection string and permissions

#### Missing Audit Categories
**Issue:** Diagnostic settings enabled but missing required log categories

**Check these categories:**
- AuditEvent ✓
- Policy ✓  
- AllMetrics (optional but recommended)

**Resolution:**
1. Update diagnostic settings in Azure portal
2. Enable missing log categories
3. Test log flow to destination

### Permissions Required

#### For Audit Script
- **Monitoring Reader** - Read diagnostic settings
- **Reader** - Access to Key Vault metadata
- **Key Vault Reader** - Key Vault specific permissions

#### For Diagnostic Settings Configuration
- **Monitoring Contributor** - Configure diagnostic settings
- **Owner** or **Contributor** - Full resource management

### PowerShell Commands for Manual Validation

#### Check Current Diagnostic Settings
```powershell
# Get diagnostic settings for a specific Key Vault
$keyVaultResourceId = "/subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault-name}"
Get-AzDiagnosticSetting -ResourceId $keyVaultResourceId
```

#### Configure Proper Diagnostic Settings
```powershell
# Set diagnostic settings with required categories
$eventHubAuthRuleId = "/subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.EventHub/namespaces/InfoSecEventHubwestus/authorizationrules/RootManageSharedAccessKey"

Set-AzDiagnosticSetting `
  -ResourceId $keyVaultResourceId `
  -EventHubAuthorizationRuleId $eventHubAuthRuleId `
  -EventHubName "keyvault-audit-logs" `
  -Enabled $true `
  -Category @("AuditEvent", "Policy")
```

### Compliance Validation Results

#### Fully Compliant Diagnostic Settings
- ✅ Diagnostic settings enabled
- ✅ AuditEvent or AuditLogs category enabled
- ✅ Policy or AuditPolicyEvaluationDetails category enabled  
- ✅ Event Hub destination configured
- ✅ Event Hub namespace is "InfoSecEventHubwestus"

#### Partially Compliant
- ✅ Diagnostic settings enabled
- ⚠️ Missing some required log categories OR
- ⚠️ Wrong Event Hub namespace OR
- ⚠️ No Event Hub destination (using only Log Analytics/Storage)

#### Non-Compliant
- ❌ No diagnostic settings configured
- ❌ Diagnostic settings disabled
- ❌ No audit log categories enabled
- ❌ No logging destinations configured

### Automated Remediation

The audit script provides recommendations for fixing non-compliant diagnostic settings:

1. **Enable diagnostic settings** if not configured
2. **Add missing log categories** (AuditEvent, Policy)
3. **Configure Event Hub destination** if missing
4. **Update Event Hub namespace** to InfoSecEventHubwestus
5. **Add Log Analytics workspace** for enhanced querying
6. **Configure retention policies** as needed

### Monitoring and Alerting

After proper diagnostic settings configuration:

1. **Verify log flow** - Check Event Hub for incoming messages
2. **Set up alerting** - Monitor for suspicious Key Vault access
3. **Create dashboards** - Visualize Key Vault usage patterns
4. **Regular reviews** - Ensure continued compliance

For additional assistance with diagnostic settings configuration, consult the Azure Key Vault monitoring documentation or contact your security team.