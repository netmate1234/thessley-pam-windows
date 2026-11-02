param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string] $ExpectedSha256
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this update from an elevated PowerShell session.'
}

$source = Join-Path $env:PUBLIC 'Documents\ThessleyCredentialProvider-local-filter.dll'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$registration = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$providerId\InprocServer32"
if (-not (Test-Path -LiteralPath $registration)) { throw 'The local Thessley provider registration was not found.' }
$target = [string](Get-Item -LiteralPath $registration).GetValue('')
if ([string]::IsNullOrWhiteSpace($target)) { throw 'The registered local provider DLL path is empty.' }
$target = [IO.Path]::GetFullPath($target)
if ([IO.Path]::GetDirectoryName($target) -ine [IO.Path]::GetFullPath($installDir) -or
    [IO.Path]::GetFileName($target) -notlike 'ThessleyCredentialProvider*.dll') {
    throw "Registered local provider DLL is outside the Thessley install directory: $target"
}
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Staged local provider DLL not found: $source" }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
    throw 'Staged local provider SHA-256 does not match the expected build.'
}

$newTarget = Join-Path $installDir "ThessleyCredentialProvider-$($ExpectedSha256.ToLowerInvariant()).dll"
$newFileCreated = $false
$registryKey = $null
$registryPathChanged = $false
try {
    if (-not (Test-Path -LiteralPath $newTarget -PathType Leaf)) {
        Copy-Item -LiteralPath $source -Destination $newTarget -ErrorAction Stop
        $newFileCreated = $true
        Set-Acl -LiteralPath $newTarget -AclObject (Get-Acl -LiteralPath $target)
    }
    if ((Get-FileHash -LiteralPath $newTarget -Algorithm SHA256).Hash -ne $ExpectedSha256.ToUpperInvariant()) {
        throw 'Versioned local provider DLL failed its SHA-256 check.'
    }

    $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SOFTWARE\Classes\CLSID\$providerId\InprocServer32", $true)
    if (-not $registryKey) { throw 'Could not open the local provider registration.' }
    if ([IO.Path]::GetFullPath([string]$registryKey.GetValue('')) -ine $target) {
        throw 'The local provider registration changed while the update was prepared.'
    }
    $registryKey.SetValue('', $newTarget, [Microsoft.Win32.RegistryValueKind]::String)
    $registryPathChanged = $true
    $registryKey.Flush()
    if ([IO.Path]::GetFullPath([string]$registryKey.GetValue('')) -ine [IO.Path]::GetFullPath($newTarget)) {
        throw 'The local provider registration did not retain the new DLL path.'
    }
} catch {
    if ($registryPathChanged -and $registryKey) {
        try { $registryKey.SetValue('', $target, [Microsoft.Win32.RegistryValueKind]::String); $registryKey.Flush() } catch { }
    }
    if ($newFileCreated) { Remove-Item -LiteralPath $newTarget -Force -ErrorAction SilentlyContinue }
    throw
} finally {
    if ($registryKey) { $registryKey.Dispose() }
}

Write-Output "Local provider DLL updated and verified ($ExpectedSha256)."
Write-Output "Registered DLL: $newTarget"
Write-Output "Previous DLL retained: $target"
Write-Output 'No timer, password policy, AD provider, or other sign-in registration was changed.'
