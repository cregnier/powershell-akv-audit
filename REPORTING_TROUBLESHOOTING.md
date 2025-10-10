# Azure Key Vault Audit - Reporting Troubleshooting Guide

## 🔧 Quick Diagnostic Commands

### Validate Script Health
```powershell
# Test PowerShell syntax
pwsh -Command "`$ast = [System.Management.Automation.Language.Parser]::ParseFile('./Get-AKV_Roles-SecAuditCompliance.ps1', [ref]`$null, [ref]`$null); Write-Host 'Syntax valid'"

# Run comprehensive validation
.\Validate-UnifiedReporting.ps1

# Test audit mode unification
.\Validate-AuditModeUnification.ps1
```

## 🐛 Common Issues and Solutions

### Issue: HTML Report Generation Fails

**Symptoms:**
- "❌ Failed to generate comprehensive HTML report" error
- HTML file is not created or is empty
- Script exits with HTML generation error

**Diagnosis:**
```powershell
# Check if New-ComprehensiveHtmlReport function exists
pwsh -Command "Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String 'function New-ComprehensiveHtmlReport'"

# Verify Use-HtmlTemplate function
pwsh -Command "Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String 'function Use-HtmlTemplate'"
```

**Solutions:**
1. **Check ExecutiveSummary Properties:**
   ```powershell
   # Verify required properties exist
   $requiredProperties = @('TotalKeyVaults', 'FullyCompliant', 'PartiallyCompliant', 'NonCompliant')
   # ExecutiveSummary should contain all these properties
   ```

2. **Verify AuditResults Structure:**
   ```powershell
   # Ensure AuditResults is not empty and contains PSCustomObject with 62 properties
   # Check: $AuditResults.Count -gt 0
   # Check: $AuditResults[0].PSObject.Properties.Count -eq 62
   ```

3. **Check Output Path Permissions:**
   ```powershell
   # Ensure output directory is writable
   Test-Path -Path (Split-Path $htmlPath -Parent) -IsValid
   ```

### Issue: CSV Columns Don't Match HTML Headers

**Symptoms:**
- HTML table has wrong number of columns
- Data appears in wrong columns
- Filter inputs don't work correctly

**Diagnosis:**
```powershell
# Check CSV column count
.\Validate-UnifiedReporting.ps1 | Select-String "CSV columns found"

# Verify HTML header count
pwsh -Command "(Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' -Raw | Select-String -Pattern '<th onclick=\"sortTable\(\d+\)\"[^>]*>' -AllMatches).Matches.Count"
```

**Solutions:**
1. **Verify PSCustomObject Structure:**
   ```powershell
   # Check around line 10825 for $result = [PSCustomObject]@{
   # Count all property definitions
   # Should be exactly 62 properties
   ```

2. **Check HTML Header Generation:**
   ```powershell
   # Verify table header generation includes all 62 columns
   # Look for: <!-- Basic Information (7 columns) --> etc.
   ```

3. **Fix Filter Input Loop:**
   ```powershell
   # Ensure filter input generation: for ($i = 0; $i -lt 62; $i++)
   # Should generate exactly 62 filter input fields
   ```

### Issue: Missing Data in HTML Report

**Symptoms:**
- Empty cells in HTML table
- "N/A" or "None" showing instead of data
- Incomplete executive summary statistics

**Diagnosis:**
```powershell
# Check for safe property access patterns
Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String "if.*\$result\.[A-Za-z].*else"

# Verify placeholder mapping
Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String "\$placeholders\["
```

**Solutions:**
1. **Check Data Collection Functions:**
   ```powershell
   # Verify these functions return proper data:
   # - Get-DiagnosticSettings
   # - Get-RBACAssignments  
   # - Get-ServicePrincipalsAndManagedIdentities
   # - Get-KeyVaultWorkloadAnalysis
   ```

2. **Verify Error Handling:**
   ```powershell
   # Check error logs for data collection issues
   # Look for: Write-ErrorLog calls during data collection
   ```

3. **Check Property Mapping:**
   ```powershell
   # Ensure all PSCustomObject properties are mapped to HTML
   # Verify: $result.PropertyName maps to <td>$($result.PropertyName)</td>
   ```

### Issue: Inconsistent Reporting Between Audit Modes

**Symptoms:**
- SingleVault report looks different from Full audit report
- Different column counts between modes
- Features missing in some modes

**Diagnosis:**
```powershell
# Test mode unification
.\Validate-AuditModeUnification.ps1

# Check for deprecated function usage
Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String "Generate-HTMLReport"
```

**Solutions:**
1. **Verify All Modes Use New-ComprehensiveHtmlReport:**
   ```powershell
   # Check that all audit modes call:
   # New-ComprehensiveHtmlReport -OutputPath ... -AuditResults ... -ExecutiveSummary ...
   ```

2. **Check IsPartialResults Parameter:**
   ```powershell
   # SingleVault and Full: -IsPartialResults $false
   # Resume and ProcessPartial: -IsPartialResults $true
   ```

3. **Validate ExecutiveSummary Calculation:**
   ```powershell
   # Ensure ExecutiveSummary is calculated consistently across all modes
   # Check: $executiveSummary hashtable has same properties
   ```

### Issue: Placeholder Errors in HTML

**Symptoms:**
- "{{PLACEHOLDER_NAME}}" appears in final HTML
- Missing dynamic content
- Static timestamps or user names

**Diagnosis:**
```powershell
# Check for unreplaced placeholders
Get-Content './KeyVaultComprehensiveAudit_*.html' | Select-String "\{\{[A-Z_]+\}\}"

# Verify placeholder definition
Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String "\$placeholders.*="
```

**Solutions:**
1. **Check Placeholder Definition:**
   ```powershell
   # Verify all placeholders in $placeholders hashtable have values
   # Example: $placeholders["{{GENERATION_TIMESTAMP}}"] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
   ```

2. **Verify Dynamic Value Generation:**
   ```powershell
   # Check: $global:currentUser is populated from Get-AzContext
   # Check: Get-Date calls use proper UTC formatting
   # Check: ExecutiveSummary properties are properly referenced
   ```

3. **Check String Replacement:**
   ```powershell
   # Ensure placeholder replacement logic works correctly
   # Look for: $htmlContent -replace pattern in Use-HtmlTemplate
   ```

### Issue: Authentication and User Detection Problems

**Symptoms:**
- "Unknown" user in reports
- Authentication errors during reporting
- Missing user context in HTML

**Diagnosis:**
```powershell
# Check current Azure context
Get-AzContext

# Verify global user variable
pwsh -Command "Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String '\$global:currentUser'"
```

**Solutions:**
1. **Verify Azure Authentication:**
   ```powershell
   # Ensure proper Azure login
   Connect-AzAccount
   
   # Check context
   $context = Get-AzContext
   if ($context -and $context.Account) {
       Write-Host "Authenticated as: $($context.Account.Id)"
   }
   ```

2. **Check User Variable Assignment:**
   ```powershell
   # Verify $global:currentUser is set in Initialize-AzAuth function
   # Should be: $global:currentUser = $context.Account.Id
   ```

## 🔍 Advanced Diagnostics

### Memory and Performance Issues

**Check Memory Usage:**
```powershell
# Monitor memory during large audits
[System.GC]::GetTotalMemory($false) / 1MB

# Enable verbose output
$VerbosePreference = "Continue"
```

**Performance Optimization:**
```powershell
# Use TestMode for validation
.\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Limit 3

# Check checkpoint functionality
.\Get-AKV_Roles-SecAuditCompliance.ps1 -Resume
```

### HTML Template Debugging

**Check Template Structure:**
```powershell
# Verify HTML template sections exist
$htmlSections = @(
    "Executive Summary",
    "Compliance Framework",
    "Data Categories",
    "Quick Actions",
    "Detailed Vault Analysis"
)

foreach ($section in $htmlSections) {
    $found = Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String $section
    if ($found) {
        Write-Host "✅ $section section found"
    } else {
        Write-Host "❌ $section section missing"
    }
}
```

**Validate CSS and JavaScript:**
```powershell
# Check for CSS styles
Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String "function sortTable|function filterTable"

# Verify responsive design
Get-Content './Get-AKV_Roles-SecAuditCompliance.ps1' | Select-String "grid-template-columns.*auto-fit"
```

### CSV Export Debugging

**Check CSV Structure:**
```powershell
# Verify CSV headers match PSCustomObject properties
$csv = Import-Csv './KeyVaultComprehensiveAudit_*.csv' | Select-Object -First 1
$csv.PSObject.Properties.Count  # Should be 62
```

**Test CSV-to-HTML Conversion:**
```powershell
# Test ReportFromCsv functionality
.\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "path/to/audit.csv"
```

## 📋 Validation Checklist

### Pre-Audit Validation
- [ ] PowerShell syntax valid
- [ ] Azure authentication successful
- [ ] Required modules installed
- [ ] Output directory writable
- [ ] User context properly detected

### Post-Audit Validation
- [ ] CSV file contains 62 columns
- [ ] HTML file generated successfully
- [ ] All data properly mapped to HTML
- [ ] No placeholder errors in HTML
- [ ] Executive summary statistics accurate
- [ ] Interactive features working (sorting, filtering)

### Cross-Mode Validation
- [ ] SingleVault mode uses comprehensive template
- [ ] Resume mode maintains feature parity
- [ ] ProcessPartial mode generates complete reports
- [ ] Full audit mode uses unified structure
- [ ] All modes generate identical column structure

## 🚨 Emergency Recovery

### If HTML Generation Completely Fails
```powershell
# Generate basic CSV-only report
.\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Limit 1
# Then manually convert CSV to HTML using ReportFromCsv mode
.\Get-AKV_Roles-SecAuditCompliance.ps1 -ReportFromCsv -CsvFilePath "path/to/csv"
```

### If All Reporting Fails
```powershell
# Use ProcessPartial to extract data from checkpoints
.\Get-AKV_Roles-SecAuditCompliance.ps1 -ProcessPartial
# Select the most recent checkpoint for data extraction
```

### Script Corruption Recovery
```powershell
# Validate script integrity
$ast = [System.Management.Automation.Language.Parser]::ParseFile('./Get-AKV_Roles-SecAuditCompliance.ps1', [ref]$null, [ref]$null)
if (-not $ast) {
    Write-Host "Script file corrupted - restore from backup"
}
```

## 📞 Getting Help

### Log Analysis
Check these log files for detailed error information:
- `KeyVaultAudit_errors_TIMESTAMP.log` - General errors
- `KeyVaultAudit_permissions_TIMESTAMP.log` - Permission issues  
- `KeyVaultAudit_dataissues_TIMESTAMP.log` - Data collection problems

### Verbose Output
Enable detailed logging for troubleshooting:
```powershell
$VerbosePreference = "Continue"
.\Get-AKV_Roles-SecAuditCompliance.ps1 -TestMode -Limit 1
```

### Community Resources
- Review GitHub issues for similar problems
- Check Azure PowerShell module compatibility
- Verify PowerShell 7.x compatibility

Remember: The unified reporting system is designed for robustness and consistency. Most issues can be resolved by validating the basic requirements: proper Azure authentication, PowerShell 7.x, required modules, and appropriate permissions.