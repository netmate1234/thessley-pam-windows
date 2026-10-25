param([ValidateRange(5,60)][int]$RollbackMinutes = 15)
$ErrorActionPreference = 'Stop'
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$rollbackTask = 'ThessleyCredentialProviderRollback'
$startupTask = 'ThessleyPamWin'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$appDir = Join-Path $env:ProgramData 'ThessleyPamWin\app\thessley_pam_win'
$dllSource = Join-Path $PSScriptRoot 'build\ThessleyCredentialProvider.dll'
$viewerSource = Join-Path $PSScriptRoot 'build\ThessleyQrViewer.exe'
$daemonSource = Join-Path $PSScriptRoot 'daemon.py'
$daemonTarget = Join-Path $appDir 'daemon.py'
$viewerTarget = Join-Path $installDir 'ThessleyQrViewer.exe'
$statePath = Join-Path $installDir 'qr-startup-rollback.json'
$rollbackScript = Join-Path $installDir 'qr-startup-rollback.ps1'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}
foreach ($path in @($dllSource, $viewerSource, $daemonSource, $daemonTarget, $viewerTarget)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file not found: $path" }
}
if (Get-ScheduledTask -TaskName $rollbackTask -ErrorAction SilentlyContinue) {
    throw "A rollback timer already exists ($rollbackTask). Resolve it before updating."
}
$startup = Get-ScheduledTask -TaskName $startupTask -ErrorAction Stop
$startupXml = Export-ScheduledTask -TaskName $startupTask
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
$classPath = "SOFTWARE\Classes\CLSID\$providerId\InprocServer32"
$inproc = $base.OpenSubKey($classPath, $true)
if (-not $inproc) { $base.Dispose(); throw 'The Thessley provider is not registered.' }
$previousDll = [string]$inproc.GetValue('')
if (-not $previousDll -or -not (Test-Path -LiteralPath $previousDll -PathType Leaf)) {
    $inproc.Dispose(); $base.Dispose(); throw "The current provider DLL is missing: $previousDll"
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$daemonBackup = Join-Path $appDir "daemon.py.bak-qr-startup-$stamp"
$viewerBackup = Join-Path $installDir "ThessleyQrViewer.exe.bak-qr-startup-$stamp"
$taskXmlBackup = Join-Path $installDir "ThessleyPamWin.xml.bak-qr-startup-$stamp"
Copy-Item -LiteralPath $daemonTarget -Destination $daemonBackup
Copy-Item -LiteralPath $viewerTarget -Destination $viewerBackup
Set-Content -LiteralPath $taskXmlBackup -Value $startupXml -Encoding Unicode
$state = [ordered]@{
    PreviousDll = $previousDll
    DaemonTarget = $daemonTarget
    DaemonBackup = $daemonBackup
    ViewerTarget = $viewerTarget
    ViewerBackup = $viewerBackup
    TaskXmlBackup = $taskXmlBackup
}
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding ascii

$rollbackBody = @'
$ErrorActionPreference = 'Stop'
$rollbackTask = 'ThessleyCredentialProviderRollback'
$startupTask = 'ThessleyPamWin'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$statePath = Join-Path $installDir 'qr-startup-rollback.json'
try {
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    Stop-ScheduledTask -TaskName $startupTask -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $state.DaemonBackup -Destination $state.DaemonTarget -Force
    Copy-Item -LiteralPath $state.ViewerBackup -Destination $state.ViewerTarget -Force
    Register-ScheduledTask -TaskName $startupTask -Xml (Get-Content -Raw -LiteralPath $state.TaskXmlBackup) -Force | Out-Null
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('SOFTWARE\Classes\CLSID\{B78189D3-4FE6-4E6B-A143-D63D6436E96B}\InprocServer32', $true)
        if (-not $key) { throw 'Credential provider registry key is missing.' }
        $key.SetValue('', [string]$state.PreviousDll, [Microsoft.Win32.RegistryValueKind]::String)
        $key.Dispose()
    } finally { $base.Dispose() }
    Start-ScheduledTask -TaskName $startupTask
    Remove-Item -LiteralPath $statePath -Force
    Unregister-ScheduledTask -TaskName $rollbackTask -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output 'Previous QR provider and network-aware startup configuration restored.'
} catch {
    $_ | Out-File -LiteralPath (Join-Path $installDir 'qr-startup-rollback-error.log') -Append -Encoding utf8
    throw
}
'@
Set-Content -LiteralPath $rollbackScript -Value $rollbackBody -Encoding ascii

$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackScript`""
$deadlineUtc = [DateTimeOffset]::UtcNow.AddMinutes($RollbackMinutes)
$trigger = New-ScheduledTaskTrigger -Once -At $deadlineUtc.LocalDateTime
$trigger.StartBoundary = $deadlineUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
$runAsSystem = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $rollbackTask -Action $action -Trigger $trigger -Principal $runAsSystem -Settings $settings -Description 'Restores the previous Thessley QR login and startup configuration unless confirmed.' | Out-Null

try {
    $dllHash = (Get-FileHash -LiteralPath $dllSource -Algorithm SHA256).Hash.Substring(0, 12).ToLowerInvariant()
    $newDllPath = Join-Path $installDir "ThessleyCredentialProvider-$dllHash.dll"
    Copy-Item -LiteralPath $dllSource -Destination $newDllPath -Force
    Copy-Item -LiteralPath $viewerSource -Destination $viewerTarget -Force
    Copy-Item -LiteralPath $daemonSource -Destination $daemonTarget -Force

    [xml]$xml = $startupXml
    $ns = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $delay = $xml.SelectSingleNode('/t:Task/t:Triggers/t:BootTrigger/t:Delay', $ns)
    if ($delay) { [void]$delay.ParentNode.RemoveChild($delay) }
    Stop-ScheduledTask -TaskName $startupTask -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $startupTask -Xml $xml.OuterXml -Force | Out-Null
    $inproc.SetValue('', $newDllPath, [Microsoft.Win32.RegistryValueKind]::String)
    Start-ScheduledTask -TaskName $startupTask
} catch {
    & $powerShell -NoProfile -ExecutionPolicy Bypass -File $rollbackScript
    throw
} finally {
    $inproc.Dispose()
    $base.Dispose()
}

$deadlineLocal = $deadlineUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
$deadlineUniversal = $deadlineUtc.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
Write-Host "QR startup update installed. Automatic restore deadline: $deadlineLocal local / $deadlineUniversal UTC."
Write-Host 'Test a reboot and the QR sign-in, then run elevated before the deadline:'
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $installDir 'confirm.ps1')`""
