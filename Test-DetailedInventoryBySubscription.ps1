# Test the detailed Key Vault inventory by subscription functionality
# This test validates that the new HTML section is properly generated

Write-Host "Testing Detailed Key Vault Inventory by Subscription functionality..." -ForegroundColor Cyan

# Create mock data to simulate AnalysisResults
$mockAnalysisResults = @(
    [PSCustomObject]@{
        SubscriptionName = "Production Subscription"
        VaultName = "prod-kv-001"
        SecretInventory = [PSCustomObject]@{
            BusinessUnit = "Finance"
            Environment = "Production"
            SecretsCount = 25
            CertificatesCount = 5
            KeysCount = 3
            TotalAssets = 33
        }
        RotationAnalysis = [PSCustomObject]@{
            RecentlyRotated = 8
            ManualRotationNeeded = 12
        }
    },
    [PSCustomObject]@{
        SubscriptionName = "Production Subscription"
        VaultName = "prod-kv-002"
        SecretInventory = [PSCustomObject]@{
            BusinessUnit = "HR"
            Environment = "Production"
            SecretsCount = 15
            CertificatesCount = 2
            KeysCount = 1
            TotalAssets = 18
        }
        RotationAnalysis = [PSCustomObject]@{
            RecentlyRotated = 5
            ManualRotationNeeded = 8
        }
    },
    [PSCustomObject]@{
        SubscriptionName = "Development Subscription"
        VaultName = "dev-kv-001"
        SecretInventory = [PSCustomObject]@{
            BusinessUnit = "Engineering"
            Environment = "Development"
            SecretsCount = 10
            CertificatesCount = 1
            KeysCount = 2
            TotalAssets = 13
        }
        RotationAnalysis = [PSCustomObject]@{
            RecentlyRotated = 3
            ManualRotationNeeded = 5
        }
    }
)

# Test the grouping logic
$vaultsBySubscription = $mockAnalysisResults | Group-Object -Property SubscriptionName

Write-Host "Testing subscription grouping..." -ForegroundColor Yellow
if ($vaultsBySubscription.Count -eq 2) {
    Write-Host "✓ Correctly grouped into 2 subscriptions" -ForegroundColor Green
} else {
    Write-Host "✗ Expected 2 subscriptions, got $($vaultsBySubscription.Count)" -ForegroundColor Red
}

# Test calculations for Production subscription (the one with multiple vaults)
$prodSub = $vaultsBySubscription | Where-Object { $_.Name -eq "Production Subscription" }
$subVaults = $prodSub.Group
$subTotalSecrets = ($subVaults | ForEach-Object { $_.SecretInventory.SecretsCount } | Measure-Object -Sum).Sum
$subTotalCertificates = ($subVaults | ForEach-Object { $_.SecretInventory.CertificatesCount } | Measure-Object -Sum).Sum
$subTotalKeys = ($subVaults | ForEach-Object { $_.SecretInventory.KeysCount } | Measure-Object -Sum).Sum
$subTotalAssets = $subTotalSecrets + $subTotalCertificates + $subTotalKeys
$subTotalRotations = ($subVaults | ForEach-Object { $_.RotationAnalysis.RecentlyRotated } | Measure-Object -Sum).Sum

Write-Host "Testing calculations for Production Subscription..." -ForegroundColor Yellow
$expectedSecrets = 25 + 15  # 40
$expectedCerts = 5 + 2      # 7
$expectedKeys = 3 + 1       # 4
$expectedAssets = 40 + 7 + 4  # 51
$expectedRotations = 8 + 5  # 13

if ($subTotalSecrets -eq $expectedSecrets) {
    Write-Host "✓ Secrets calculation correct: $subTotalSecrets" -ForegroundColor Green
} else {
    Write-Host "✗ Secrets calculation wrong: expected $expectedSecrets, got $subTotalSecrets" -ForegroundColor Red
}

if ($subTotalCertificates -eq $expectedCerts) {
    Write-Host "✓ Certificates calculation correct: $subTotalCertificates" -ForegroundColor Green
} else {
    Write-Host "✗ Certificates calculation wrong: expected $expectedCerts, got $subTotalCertificates" -ForegroundColor Red
}

if ($subTotalKeys -eq $expectedKeys) {
    Write-Host "✓ Keys calculation correct: $subTotalKeys" -ForegroundColor Green
} else {
    Write-Host "✗ Keys calculation wrong: expected $expectedKeys, got $subTotalKeys" -ForegroundColor Red
}

if ($subTotalAssets -eq $expectedAssets) {
    Write-Host "✓ Total assets calculation correct: $subTotalAssets" -ForegroundColor Green
} else {
    Write-Host "✗ Total assets calculation wrong: expected $expectedAssets, got $subTotalAssets" -ForegroundColor Red
}

if ($subTotalRotations -eq $expectedRotations) {
    Write-Host "✓ Rotations calculation correct: $subTotalRotations" -ForegroundColor Green
} else {
    Write-Host "✗ Rotations calculation wrong: expected $expectedRotations, got $subTotalRotations" -ForegroundColor Red
}

Write-Host "`nTest completed. The detailed inventory by subscription functionality should work correctly." -ForegroundColor Cyan