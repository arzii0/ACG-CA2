# Change the client private-key password and update this terminal environment.
# The newly generated password is intentionally not printed.

$ErrorActionPreference = "Stop"

if (-not $env:ACG_CLIENT_KEY_PASSWORD) {
    throw "ACG_CLIENT_KEY_PASSWORD is not set in this terminal."
}

$result = python -m secure_transfer.client change-password | ConvertFrom-Json
if (-not $result.ok) {
    throw "Client password change failed: $($result.error)"
}

$env:ACG_CLIENT_KEY_PASSWORD = $result.new_password
$result.new_password = $null

Write-Host "Client private-key password changed successfully." -ForegroundColor Green
Write-Host "ACG_CLIENT_KEY_PASSWORD was updated in this PowerShell terminal."
