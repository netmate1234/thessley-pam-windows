param([switch]$Quiet)
$ErrorActionPreference = 'Stop'
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$taskName = 'ThessleyCredentialProviderRollback'
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    foreach ($path in @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId",
        "SOFTWARE\Classes\CLSID\$providerId")) {
        if ($base.OpenSubKey($path)) {
            $base.DeleteSubKeyTree($path, $false)
        }
    }
} finally {
    $base.Dispose()
}
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
if (-not $Quiet) {
    Write-Host 'Thessley unlock tile registration was removed. Built-in Windows sign-in methods were not changed.'
}
