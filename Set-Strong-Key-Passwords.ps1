# Generate strong random passwords and set them in this PowerShell terminal.
# Run this script before generating a new PKI.

$ErrorActionPreference = "Stop"

function New-StrongPassword {
    $bytes = New-Object byte[] 24
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).
        Replace("+", "-").
        Replace("/", "_").
        TrimEnd("=")
}

$env:ACG_CA_KEY_PASSWORD = New-StrongPassword
$env:ACG_SERVER_KEY_PASSWORD = New-StrongPassword
$env:ACG_CLIENT_KEY_PASSWORD = New-StrongPassword

Write-Host "Strong CA, server and client passwords were generated." -ForegroundColor Green
Write-Host "They are set only in this PowerShell terminal and were not printed."

# Terminal 2 is a different process and cannot read Terminal 1's environment.
# Copy only the client password so it can be transferred without displaying it.
Set-Clipboard -Value $env:ACG_CLIENT_KEY_PASSWORD
Write-Host "The client password was copied to the Windows clipboard." -ForegroundColor Yellow
Write-Host "In Terminal 2, run:"
Write-Host '  $env:ACG_CLIENT_KEY_PASSWORD = (Get-Clipboard).Trim(); Set-Clipboard -Value "CLEARED"'
Write-Host "Generate the PKI now with: python -m secure_transfer.pki"
