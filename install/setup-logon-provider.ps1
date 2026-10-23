param([ValidateRange(5, 60)][int]$RollbackMinutes = 30)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}
$bundle = Join-Path (Split-Path -Parent $PSScriptRoot) 'downloads\windows-qr-signin-experimental.zip'
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) { throw "Windows sign-in package is missing: $bundle" }
$work = Join-Path $env:TEMP ('Thessley-Logon-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Expand-Archive -LiteralPath $bundle -DestinationPath $work
    $providerDir = Join-Path $work 'Thessley-QR-Windows-SignIn-Experimental\windows-logon-provider'
    $firstInstall = Join-Path $providerDir 'install-with-rollback.ps1'
    $update = Join-Path $providerDir 'update-with-rollback.ps1'
    if (-not (Test-Path -LiteralPath $firstInstall) -or -not (Test-Path -LiteralPath $update)) {
        throw 'The sign-in package is incomplete; no credential provider changes were made.'
    }
    $task = Get-ScheduledTask -TaskName 'ThessleyCredentialProviderRollback' -ErrorAction SilentlyContinue
    if ($task) { throw 'A sign-in rollback is already active. Confirm or wait for that rollback before installing again.' }
    $providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
    $registered = Test-Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
    if ($registered) {
        & $update -RollbackMinutes $RollbackMinutes
    } else {
        & $firstInstall -RollbackMinutes $RollbackMinutes
    }
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'The Windows sign-in provider installer reported a failure.' }
    Write-Host 'Keep the built-in PIN/password tiles available. Test Thessley at the sign-in screen before confirming setup.'
    Write-Host "After all tests succeed, run: powershell -ExecutionPolicy Bypass -File `"$(Join-Path $env:ProgramData 'ThessleyPamWin\confirm-setup.ps1')`""
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
