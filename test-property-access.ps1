# Test script to debug property access in PowerShell 7
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)"

# Helper function for safe property access in PowerShell 7
function Get-SafeProperty {
    param($Object, $PropertyName, $DefaultValue = 'N/A')
    Write-Host "Testing property access for: $PropertyName on object type: $($Object.GetType().FullName)"
    
    if ($null -eq $Object) { 
        Write-Host "Object is null, returning default"
        return $DefaultValue 
    }
    try {
        # Use safer property access for PowerShell 7
        if ($Object -is [array] -and $PropertyName -eq 'Count') {
            Write-Host "Array count access: $($Object.Count)"
            return $Object.Count
        }
        Write-Host "Checking PSObject and PSObject.Properties..."
        Write-Host "Has PSObject: $($null -ne $Object.PSObject)"
        if ($Object.PSObject) {
            Write-Host "Has PSObject.Properties: $($null -ne $Object.PSObject.Properties)"
            if ($Object.PSObject.Properties) {
                Write-Host "Checking for property: $PropertyName"
                $hasProperty = $null -ne $Object.PSObject.Properties[$PropertyName]
                Write-Host "Has property $PropertyName : $hasProperty"
                if ($hasProperty) {
                    $value = $Object.$PropertyName
                    Write-Host "Property value: $value"
                    if ([string]::IsNullOrWhiteSpace($value)) { 
                        return $DefaultValue 
                    } else { 
                        return $value 
                    }
                } else {
                    Write-Host "Property not found, returning default"
                    return $DefaultValue
                }
            } else {
                Write-Host "PSObject.Properties is null, returning default"
                return $DefaultValue
            }
        } else {
            Write-Host "PSObject is null, returning default"
            return $DefaultValue
        }
    } catch {
        Write-Host "Exception: $_"
        return $DefaultValue
    }
}

# Test with a simple PSCustomObject
Write-Host "`n=== Testing with PSCustomObject ==="
$testObj = [PSCustomObject]@{
    TestProperty = "TestValue"
    Count = 5
}

$result = Get-SafeProperty -Object $testObj -PropertyName 'TestProperty'
Write-Host "Result: $result"

# Test with an array
Write-Host "`n=== Testing with Array ==="
$testArray = @(1, 2, 3)
$result = Get-SafeProperty -Object $testArray -PropertyName 'Count'
Write-Host "Result: $result"

# Test with hashtable
Write-Host "`n=== Testing with Hashtable ==="
$testHash = @{
    TestProperty = "TestValue"
    Count = 5
}
$result = Get-SafeProperty -Object $testHash -PropertyName 'TestProperty'
Write-Host "Result: $result"