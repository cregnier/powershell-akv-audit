function Write-UserMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug', 'Progress')]
        [string]$Type = 'Info'
    )

    $color = switch ($Type) {
        'Info'     { 'Cyan' }
        'Warning'  { 'Yellow' }
        'Error'    { 'Red' }
        'Success'  { 'Green' }
        'Debug'    { 'Magenta' }
        'Progress' { 'Blue' }
        default    { 'White' }
    }

    Write-Host "[$Type] $Message" -ForegroundColor $color
}