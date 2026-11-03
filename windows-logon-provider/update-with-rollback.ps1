param([ValidateRange(5,60)][int]$RollbackMinutes = 10)
$ErrorActionPreference = 'Stop'
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$taskName = 'ThessleyCredentialProviderRollback'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$dllSource = Join-Path $PSScriptRoot 'build\ThessleyCredentialProvider.dll'
$viewerSource = Join-Path $PSScriptRoot 'build\ThessleyQrViewer.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}
foreach ($path in @($dllSource, $viewerSource)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Build file not found: $path" }
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "A rollback timer already exists ($taskName). Resolve it before updating again."
}

$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
$classPath = "SOFTWARE\Classes\CLSID\$providerId\InprocServer32"
$viewerPath = Join-Path $installDir 'ThessleyQrViewer.exe'
$rollbackScript = Join-Path $installDir 'branding-rollback.ps1'
$statePath = Join-Path $installDir 'branding-rollback.json'
$dllHash = (Get-FileHash -LiteralPath $dllSource -Algorithm SHA256).Hash.Substring(0, 12).ToLowerInvariant()
$newDllPath = Join-Path $installDir "ThessleyCredentialProvider-$dllHash.dll"
$viewerBackup = Join-Path $installDir ("ThessleyQrViewer.exe.bak-branding-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))

try {
    $inproc = $base.OpenSubKey($classPath, $true)
    if (-not $inproc) { throw 'The Thessley credential provider is not registered; refusing to create a new installation during an update.' }
    $previousDllPath = [string]$inproc.GetValue('')
    if (-not $previousDllPath -or -not (Test-Path -LiteralPath $previousDllPath -PathType Leaf)) {
        throw "The currently registered provider DLL is missing: $previousDllPath"
    }
    if (-not (Test-Path -LiteralPath $viewerPath -PathType Leaf)) {
        throw "The installed QR viewer is missing: $viewerPath"
    }
    $dllChanged = $newDllPath -ne $previousDllPath

    # Store the current viewer separately from the provider DLL.
    Copy-Item -LiteralPath $viewerPath -Destination $viewerBackup -Force
    $state = [ordered]@{ PreviousDll = $previousDllPath; ViewerBackup = $viewerBackup; Viewer = $viewerPath }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding ascii

    $rollbackBody = @'
$ErrorActionPreference = 'Stop'
$taskName = 'ThessleyCredentialProviderRollback'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$statePath = Join-Path $installDir 'branding-rollback.json'
try {
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('SOFTWARE\Classes\CLSID\{B78189D3-4FE6-4E6B-A143-D63D6436E96B}\InprocServer32', $true)
        if (-not $key) { throw 'Credential provider registry key is missing.' }
        $key.SetValue('', [string]$state.PreviousDll, [Microsoft.Win32.RegistryValueKind]::String)
        $key.Dispose()
    } finally { $base.Dispose() }
    Copy-Item -LiteralPath $state.ViewerBackup -Destination $state.Viewer -Force
    Remove-Item -LiteralPath $statePath -Force
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output 'Previous Thessley provider DLL and QR viewer restored.'
} catch {
    $_ | Out-File -LiteralPath (Join-Path $installDir 'branding-rollback-error.log') -Append -Encoding utf8
    throw
}
'@
    Set-Content -LiteralPath $rollbackScript -Value $rollbackBody -Encoding ascii
    # Verify the future SYSTEM rollback before replacing either installed file.
    $rollback = & (Join-Path $PSScriptRoot 'register-verified-rollback.ps1') `
        -TaskName $taskName -RollbackFile $rollbackScript -RollbackMinutes $RollbackMinutes
    $deadlineLocal = ([DateTime]$rollback.DeadlineLocal).ToString('yyyy-MM-dd HH:mm:ss zzz')
    $deadlineUniversal = ([DateTime]$rollback.DeadlineUtc).ToString('yyyy-MM-dd HH:mm:ss')

    try {
        if ($dllChanged) { Copy-Item -LiteralPath $dllSource -Destination $newDllPath -Force }
        Copy-Item -LiteralPath $viewerSource -Destination $viewerPath -Force
        if ($dllChanged) { $inproc.SetValue('', $newDllPath, [Microsoft.Win32.RegistryValueKind]::String) }
    } catch {
        & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
            -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $rollbackScript
        throw
    }
} finally {
    if ($inproc) { $inproc.Dispose() }
    $base.Dispose()
}

Write-Host "Verified rollback timer is active. Thessley sign-in files installed. Automatic restore deadline: $deadlineLocal local / $deadlineUniversal UTC."
Write-Host 'Test a QR sign-in, then run elevated before the deadline:'
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $installDir 'confirm.ps1')`""
Write-Host 'If not confirmed, the prior provider DLL and QR viewer are restored automatically.'
