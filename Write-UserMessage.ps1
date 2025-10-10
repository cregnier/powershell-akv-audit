function Write-UserMessage {
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