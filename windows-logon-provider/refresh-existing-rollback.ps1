$ErrorActionPreference = 'Stop'
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$taskName = 'ThessleyCredentialProviderRollback'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$dllSource = Join-Path $PSScriptRoot 'build\ThessleyCredentialProvider.dll'
$viewerSource = Join-Path $PSScriptRoot 'build\ThessleyQrViewer.exe'
$statePath = Join-Path $installDir 'branding-rollback.json'
$viewerPath = Join-Path $installDir 'ThessleyQrViewer.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}
if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'The rollback task is not active; refusing to replace the current login files.'
}
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw 'The rollback state is missing; refusing to replace the current login files.'
}
foreach ($path in @($dllSource, $viewerSource)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Build file not found: $path" }
}
if (Get-Process -Name 'ThessleyQrViewer' -ErrorAction SilentlyContinue) {
    throw 'Close the QR viewer before refreshing its executable.'
}

$dllHash = (Get-FileHash -LiteralPath $dllSource -Algorithm SHA256).Hash.Substring(0, 12).ToLowerInvariant()
$newDllPath = Join-Path $installDir "ThessleyCredentialProvider-$dllHash.dll"
Copy-Item -LiteralPath $dllSource -Destination $newDllPath -Force
Copy-Item -LiteralPath $viewerSource -Destination $viewerPath -Force

$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    $key = $base.OpenSubKey("SOFTWARE\Classes\CLSID\$providerId\InprocServer32", $true)
    if (-not $key) { throw 'The Thessley credential provider registration is missing.' }
    $key.SetValue('', $newDllPath, [Microsoft.Win32.RegistryValueKind]::String)
    $key.Dispose()
} finally { $base.Dispose() }

Write-Host 'Updated the branded files; the existing automatic rollback is unchanged.'
Write-Host 'Test QR sign-in and confirm only after a successful sign-in.'
