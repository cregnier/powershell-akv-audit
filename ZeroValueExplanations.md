# Zero Value Explanations for Azure Key Vault Audit

This document explains why certain metrics in the Azure Key Vault audit report might show zero values and what this indicates about your environment.

## Identity & Access Management

### Total Managed Identities: 0
**Why this might be zero:**
- Your Key Vaults don't have managed identities enabled
- All identities are using legacy access policies instead of RBAC
- Permissions issue preventing identity enumeration

**What this means:**
- ✅ **If intentional:** You're using service principals or access policies for authentication
- ⚠️ **If unexpected:** Missing modern identity management - consider enabling managed identities

**Recommended actions:**
1. Enable system-assigned managed identities on Key Vaults that need them
2. Consider migrating from service principals to managed identities
3. Verify audit script has proper permissions to read identity configurations

### System-Assigned Identities: 0
**Why this might be zero:**
- No Key Vaults have system-assigned managed identities enabled
- Using user-assigned identities instead
- External service principals are used for authentication

**What this means:**
- Key Vaults don't have their own built-in identities
- May rely on external identities for operations

**Recommended actions:**
1. Enable system-assigned identities for Key Vaults that need to authenticate to other Azure services
2. Consider system-assigned identities for automated lifecycle management

### User-Assigned Identities: 0
**Why this might be zero:**
- No user-assigned managed identities are attached to Key Vaults
- Using system-assigned identities instead
- Using service principals for cross-resource authentication

**What this means:**
- No shared identities across multiple resources
- Each Key Vault uses its own authentication method

## Diagnostic Settings

### With Diagnostics: 0
**Why this might be zero:**
- Diagnostic settings are not configured on any Key Vault
- Permissions issue preventing diagnostic settings enumeration
- Organization doesn't use centralized logging

**What this means:**
- ❌ **Security Gap:** No audit logging or monitoring configured
- Missing compliance requirements for access tracking

**Recommended actions:**
1. **URGENT:** Enable diagnostic settings on all Key Vaults
2. Configure audit logs to go to Event Hub, Log Analytics, or Storage Account
3. Enable at minimum: AuditEvent and Policy logs

### Event Hub Enabled: 0
**Why this might be zero:**
- Diagnostic settings are not configured
- Using Log Analytics or Storage Account instead of Event Hub
- Event Hub is not the preferred logging destination

**What this means:**
- Not using Event Hub for centralized log aggregation
- May be using alternative logging solutions

**Company-Specific Note:**
- If your organization requires "InfoSecEventHubwestus" namespace, this indicates non-compliance

### Log Analytics: 0
**Why this might be zero:**
- No Log Analytics workspace configured for Key Vault logs
- Using Event Hub or Storage Account instead
- Diagnostic settings not enabled

**What this means:**
- No Azure Monitor integration for Key Vault logs
- Missing query capabilities for security analysis

## Network Security

### Private Endpoints: 0
**Why this might be zero:**
- Key Vaults are using public endpoints
- Network restrictions implemented through firewall rules instead
- Development/test environment with public access needs

**What this means:**
- ⚠️ **Security consideration:** Key Vaults accessible from public internet
- May be acceptable for non-production environments

**Recommended actions:**
1. Implement private endpoints for production Key Vaults
2. Use network ACLs as minimum network restriction
3. Review public access requirements

## Compliance Scores

### Fully Compliant: 0
**Why this might be zero:**
- All Key Vaults have configuration issues that prevent full compliance
- Compliance framework is very strict
- New environment still being configured

**What this means:**
- No Key Vaults meet all security and compliance requirements
- Immediate attention needed for security posture

### Service Principals: 0
**Why this might be zero:**
- ✅ **Good practice:** All authentication uses managed identities
- No external applications access Key Vaults
- All access is through users with RBAC roles

**What this means:**
- Modern authentication approach with managed identities
- Reduced credential management overhead

## Next Steps for Zero Values

1. **Review permissions:** Ensure the audit script has sufficient permissions
2. **Check configuration:** Verify Key Vault settings match organizational requirements
3. **Implement missing controls:** Follow recommendations for zero values that indicate security gaps
4. **Validate intentional zeros:** Confirm zero values that represent good security practices

## Getting Help

If zero values are unexpected:
1. Run the audit script with `-TestMode -Limit 1` to test a single vault
2. Check the error logs generated during the audit
3. Verify Azure RBAC permissions for the account running the audit
4. Review the detailed CSV output for per-vault configuration details