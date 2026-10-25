param([ValidateRange(5,60)][int]$RollbackMinutes = 10)
$ErrorActionPreference = 'Stop'
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$taskName = 'ThessleyCredentialProviderRollback'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$dllSource = Join-Path $PSScriptRoot 'build\ThessleyCredentialProvider.dll'
$dllHash = (Get-FileHash -LiteralPath $dllSource -Algorithm SHA256).Hash.Substring(0, 12).ToLowerInvariant()
$dllName = "ThessleyCredentialProvider-$dllHash.dll"
$viewerSource = Join-Path $PSScriptRoot 'build\ThessleyQrViewer.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'This build is x64 and requires 64-bit Windows.'
}
if (-not (Test-Path -LiteralPath $dllSource -PathType Leaf)) {
    throw "Provider DLL not found: $dllSource"
}
if (-not (Test-Path -LiteralPath $viewerSource -PathType Leaf)) {
    throw "QR viewer not found: $viewerSource"
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "A rollback timer already exists ($taskName). Resolve it before installing again."
}

$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
$providerPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$classPath = "SOFTWARE\Classes\CLSID\$providerId"
try {
    if ($base.OpenSubKey($providerPath) -or $base.OpenSubKey($classPath)) {
        throw 'The Thessley provider registry key already exists; refusing to overwrite it.'
    }
} finally {
    $base.Dispose()
}

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$acl = Get-Acl -LiteralPath $installDir
$acl.SetAccessRuleProtection($true, $false)
$adminsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl.SetOwner($adminsSid)
$acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $adminsSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
$acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $systemSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath $installDir -AclObject $acl
$rollbackFile = Join-Path $installDir 'rollback.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'rollback.ps1') -Destination $rollbackFile -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'confirm.ps1') -Destination (Join-Path $installDir 'confirm.ps1') -Force
Copy-Item -LiteralPath $dllSource -Destination (Join-Path $installDir $dllName) -Force
Copy-Item -LiteralPath $viewerSource -Destination (Join-Path $installDir 'ThessleyQrViewer.exe') -Force

$rollback = & (Join-Path $PSScriptRoot 'register-verified-rollback.ps1') `
    -TaskName $taskName -RollbackFile $rollbackFile -RollbackMinutes $RollbackMinutes -ArgumentsSuffix '-Quiet'
$deadlineLocal = ([DateTime]$rollback.DeadlineLocal).ToString('yyyy-MM-dd HH:mm:ss zzz')
$deadlineUniversal = ([DateTime]$rollback.DeadlineUtc).ToString('yyyy-MM-dd HH:mm:ss')

try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $provider = $base.CreateSubKey($providerPath)
        $provider.SetValue('', 'Thessley Passkey unlock', [Microsoft.Win32.RegistryValueKind]::String)
        $provider.Dispose()
        $inproc = $base.CreateSubKey("$classPath\InprocServer32")
        $inproc.SetValue('', (Join-Path $installDir $dllName), [Microsoft.Win32.RegistryValueKind]::String)
        $inproc.SetValue('ThreadingModel', 'Apartment', [Microsoft.Win32.RegistryValueKind]::String)
        $inproc.Dispose()
        $class = $base.CreateSubKey($classPath)
        $class.SetValue('', 'Thessley Passkey unlock', [Microsoft.Win32.RegistryValueKind]::String)
        $class.Dispose()
    } finally {
        $base.Dispose()
    }
} catch {
    & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $rollbackFile -Quiet
    throw
}

Write-Host "Verified rollback timer is active. Thessley unlock tile registered. Automatic rollback deadline: $deadlineLocal local / $deadlineUniversal UTC."
Write-Host 'Test one unlock and confirm the normal PIN tile is still present. Then run elevated:'
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $installDir 'confirm.ps1')`""
Write-Host 'If you do not confirm, the scheduled task removes only the Thessley provider registry keys.'
