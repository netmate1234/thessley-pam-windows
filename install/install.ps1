<#
  Installs the Thessley approval service for ssh logins to this computer.

  Run in an ADMINISTRATOR PowerShell, from the repository folder:

      powershell -ExecutionPolicy Bypass -File install\install.ps1 -Python "C:\Program Files\Python313\python.exe"

  What it does (and nothing else):
    1. checks that the Python you name sits in a folder normal users cannot write to (the service runs as SYSTEM,
       so anything it loads must be out of their reach);
    2. installs the pinned runtime libraries into a private staged directory, without changing machine Python;
    3. stages and import-checks the program, then swaps it into C:\ProgramData\ThessleyPamWin\app and restores the
       previous application and scheduled tasks automatically if activation fails; locks the folder down (SYSTEM + Administrators
       write; everybody else may only read the program, and cannot see who is enrolled);
    4. writes gate.cmd (what sshd will run) and thessley-pam-win.cmd (the admin tool);
    5. creates a scheduled task that starts the service as SYSTEM at boot, and starts it.

  It does NOT change sshd_config, accounts or groups. -OpenFirewall and -OpenWebFirewall allow the Thessley ports from
  LocalSubnet and the default VPN ranges 10.8.0.0/24 and 10.8.1.0/24. When OpenSSH is installed, a separate VPN-only
  rule is also added for TCP 22; pass -VpnClientSubnets '' to omit these VPN rules. Add -CloudAccess to scope those requested
  listeners to any remote IP, and -OpenSshFirewall to also allow TCP 22 from any IP. Provider security-group rules
  are managed separately.
#>
param(
    [Parameter(Mandatory = $true)][string]$Python,
    [switch]$OpenFirewall,
    [switch]$OpenWebFirewall,   # also allow the admin web page's port (47820) from the local subnet
    [switch]$CloudAccess,        # use RemoteAddress Any for the Thessley listeners
    [switch]$OpenSshFirewall,    # add a separate TCP 22 rule; only valid with CloudAccess
    [string]$VpnClientSubnets = '10.8.0.0/24,10.8.1.0/24',
    [ValidateSet('Private', 'Any')][string]$FirewallProfile = 'Any'   # local-subnet-only rules also work when Windows calls the network Public
)
$ErrorActionPreference = 'Stop'

if ($OpenSshFirewall -and -not $CloudAccess) {
    throw 'OpenSshFirewall requires CloudAccess so the TCP 22 rule has an explicit cloud scope.'
}

if ($VpnClientSubnets) {
    $vpnAddresses = @($VpnClientSubnets -split '\s*,\s*')
    $cidrPattern = '^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])/(?:[0-9]|[12][0-9]|3[0-2])$'
    if (@($vpnAddresses | Where-Object { $_ -notmatch $cidrPattern }).Count -gt 0) {
        throw 'VpnClientSubnets must be comma-separated IPv4 CIDR subnets, such as 10.8.0.0/24,10.8.1.0/24.'
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an administrator PowerShell.'
}

$repo = Split-Path -Parent $PSScriptRoot
$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$app  = Join-Path $base 'app'
$task = 'ThessleyPamWin'
$webTask = 'ThessleyPamWinWeb'

# --- 1. the Python must be out of reach of normal users --------------------------------------------------------------
$Python = (Resolve-Path $Python).Path
if (-not $Python.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase) -and -not $Python.StartsWith(${env:ProgramFiles(x86)}, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Python must be installed for all users, under Program Files (it is $Python). Install one with:  winget install --id Python.Python.3.13 --scope machine"
}
$riskyRights = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Write
foreach ($p in @((Split-Path $Python), (Split-Path (Split-Path $Python)))) {
    foreach ($ace in (Get-Acl $p).Access) {
        $who = $ace.IdentityReference.Value
        if ($ace.AccessControlType -eq 'Allow' -and ($who -match '\\Users$|^Everyone$|Authenticated Users') -and ($ace.FileSystemRights -band $riskyRights)) {
            throw "Normal users can write to $p ($who). The service would run code they can change. Use a Python installed for all users."
        }
    }
}
& $Python -c "import sys; assert sys.version_info >= (3, 10)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10 or newer is needed.' }

# --- 2. stage and verify a complete candidate before stopping the live tasks -----------------------------------------
New-Item -ItemType Directory -Force $base | Out-Null
# Lock the installation root before creating stage files; SYSTEM will execute the installed code.
icacls $base /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
icacls $base /grant '*S-1-5-32-545:(RX)' | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'confirm-setup.ps1') -Destination (Join-Path $base 'confirm-setup.ps1') -Force

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$stage = Join-Path $base "app.stage-$stamp"
$backupRoot = Join-Path $base 'backups'
$upgradeBackup = Join-Path $backupRoot "upgrade-$stamp"
$previousApp = Join-Path $upgradeBackup 'app'
$failedApp = Join-Path $upgradeBackup 'failed-app'
New-Item -ItemType Directory -Force $stage, $backupRoot, $upgradeBackup | Out-Null

# The account that ran this elevated installer can manage the web page even if
# the group lookup is unavailable to the SYSTEM web task.
$installerAccount = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$installerAccount = (($installerAccount -split '\\')[-1] -split '@')[0].ToLowerInvariant()
if ($installerAccount -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw 'Could not safely identify the account running the elevated installer; no service files were changed.'
}
$webAdminsPath = Join-Path $base 'web-admins.json'
$webAdmins = @()
if (Test-Path -LiteralPath $webAdminsPath -PathType Leaf) {
    try {
        $existingWebAdmins = Get-Content -Raw -LiteralPath $webAdminsPath | ConvertFrom-Json
        if ($existingWebAdmins -and $existingWebAdmins.users) { $webAdmins = @($existingWebAdmins.users) }
        Copy-Item -LiteralPath $webAdminsPath -Destination (Join-Path $upgradeBackup 'web-admins.json') -Force
    } catch {
        throw "Could not safely read the existing web administrator list at $webAdminsPath. No service tasks were changed."
    }
}
$webAdmins = @($webAdmins + $installerAccount | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
    Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' } | Sort-Object -Unique)
$webAdminsTemp = "$webAdminsPath.tmp-$stamp"
$webAdminsJson = @{ version = 1; users = $webAdmins } | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($webAdminsTemp, $webAdminsJson + "`n", [Text.UTF8Encoding]::new($false))
if (Test-Path -LiteralPath $webAdminsPath -PathType Leaf) {
    $webAdminsReplaceBackup = Join-Path $upgradeBackup 'web-admins.pre-replace.json'
    [IO.File]::Replace($webAdminsTemp, $webAdminsPath, $webAdminsReplaceBackup)
} else {
    Move-Item -LiteralPath $webAdminsTemp -Destination $webAdminsPath
}
Write-Host "Web administrator access granted to the installer account: $installerAccount"

try {
    Copy-Item -Recurse -Force (Join-Path $repo 'thessley_pam_win') $stage
    Get-ChildItem (Join-Path $stage 'thessley_pam_win') -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force

    # Install exact locked versions into the candidate only; failed installs leave both system Python and the live app alone.
    $requirements = Join-Path $PSScriptRoot '..\requirements.lock'
    $vendor = Join-Path $stage 'vendor'
    Write-Host 'Installing pinned Python dependencies into a private staging folder. This can take a few minutes; the live app is untouched during this step.'
    & $Python -m pip install --quiet --disable-pip-version-check --only-binary=:all: --target $vendor --requirement $requirements
    if ($LASTEXITCODE -ne 0) { throw 'pip could not install the pinned dependencies into the staged app. The live install was not changed.' }
    Write-Host 'Dependencies are ready. Verifying versions and importing the staged service...'
    $env:THESSLEY_VENDOR = $vendor
    $verifyDeps = "import importlib.metadata as m,os; got={d.metadata['Name'].lower():d.version for d in m.distributions(path=[os.environ['THESSLEY_VENDOR']])}; expected={'asn1crypto':'1.5.1','cffi':'2.1.1','cryptography':'50.0.2','pycparser':'3.11','qrcode':'8.2'}; assert all(got.get(k)==v for k,v in expected.items()), (got,expected)"
    & $Python -I -c $verifyDeps
    if ($LASTEXITCODE -ne 0) { throw 'A staged dependency version failed verification. The live install was not changed.' }

    foreach ($entry in @(@('daemon_main.py', 'daemon'), @('gate_main.py', 'gate'), @('cli_main.py', 'cli'), @('web_main.py', 'web'))) {
        @"
import os
import sys

root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(root, 'vendor'))
sys.path.insert(0, root)  # -I removes the script folder from the path
from thessley_pam_win.$($entry[1]) import main

raise SystemExit(main())
"@ | Set-Content -Encoding ascii (Join-Path $stage $entry[0])
    }

    $env:THESSLEY_STAGE = $stage
    $env:THESSLEY_VENDOR = Join-Path $stage 'vendor'
    & $Python -I -c "import os,sys; sys.path.insert(0,os.environ['THESSLEY_VENDOR']); sys.path.insert(0,os.environ['THESSLEY_STAGE']); import thessley_pam_win.daemon,thessley_pam_win.web,thessley_pam_win.cli,thessley_pam_win.gate"
    if ($LASTEXITCODE -ne 0) { throw 'The staged application failed its Python import check; the installed version is still running.' }

    icacls $stage /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    icacls $stage /grant '*S-1-5-32-545:(OI)(CI)RX' /T /C | Out-Null
    foreach ($d in 'users', 'grants') { New-Item -ItemType Directory -Force (Join-Path $base $d) | Out-Null }

    # Record the working scheduled-task definitions before touching either task.
    $oldService = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    $oldWeb = Get-ScheduledTask -TaskName $webTask -ErrorAction SilentlyContinue
    $serviceExisted = [bool]$oldService
    $webExisted = [bool]$oldWeb
    $appExisted = Test-Path -LiteralPath $app -PathType Container
    $restorePreviousTasks = $appExisted
    $serviceWasEnabled = $serviceExisted -and $oldService.State -ne 'Disabled'
    $webWasEnabled = $false
    $configPath = Join-Path $base 'config.json'
    if ($appExisted -and $webExisted -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        try {
            $previousConfig = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
            $webWasEnabled = ($oldWeb.State -ne 'Disabled') -and [bool]$previousConfig.web.enabled
        } catch {
            throw "Could not safely read the existing web page setting from $configPath. Nothing was changed."
        }
    }
    if ($serviceExisted) { Export-ScheduledTask -TaskName $task | Set-Content -LiteralPath (Join-Path $upgradeBackup 'service.xml') -Encoding Unicode }
    if ($webExisted) { Export-ScheduledTask -TaskName $webTask | Set-Content -LiteralPath (Join-Path $upgradeBackup 'web.xml') -Encoding Unicode }
    $gateLauncher = Join-Path $base 'gate.cmd'
    $cliLauncher = Join-Path $base 'thessley-pam-win.cmd'
    $gateLauncherExisted = Test-Path -LiteralPath $gateLauncher -PathType Leaf
    $cliLauncherExisted = Test-Path -LiteralPath $cliLauncher -PathType Leaf
    if ($gateLauncherExisted) { Copy-Item -LiteralPath $gateLauncher -Destination (Join-Path $upgradeBackup 'gate.cmd') }
    if ($cliLauncherExisted) { Copy-Item -LiteralPath $cliLauncher -Destination (Join-Path $upgradeBackup 'thessley-pam-win.cmd') }
    $action = New-ScheduledTaskAction -Execute $Python -Argument "-I -X utf8 `"$app\daemon_main.py`""
    $webAction = New-ScheduledTaskAction -Execute $Python -Argument "-I -X utf8 `"$app\web_main.py`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 30 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    $oldAppMoved = $false
    $newAppMoved = $false

    try {
        Write-Host 'Activating the staged app and checking the scheduled service...'
        if ($serviceExisted) { Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue }
        if ($webExisted) { Stop-ScheduledTask -TaskName $webTask -ErrorAction SilentlyContinue }
        foreach ($name in @($task, $webTask)) {
            for ($i = 0; $i -lt 15; $i++) {
                $stopped = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
                if (-not $stopped -or $stopped.State -ne 'Running') { break }
                Start-Sleep -Seconds 1
            }
            $stopped = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if ($stopped -and $stopped.State -eq 'Running') { throw "Task $name did not stop; the installed app was left in place." }
        }
        if ($appExisted) { Move-Item -LiteralPath $app -Destination $previousApp; $oldAppMoved = $true }
        Move-Item -LiteralPath $stage -Destination $app
        $newAppMoved = $true

        $run = "`"$Python`" -I -X utf8"
        Set-Content -Encoding ascii -LiteralPath $gateLauncher -Value "@$run `"$app\gate_main.py`""
        Set-Content -Encoding ascii -LiteralPath $cliLauncher -Value "@$run `"$app\cli_main.py`" %*"
        icacls $gateLauncher /grant '*S-1-5-32-545:(RX)' | Out-Null
        icacls $cliLauncher /grant '*S-1-5-32-545:(RX)' | Out-Null

        Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Thessley Passkey approvals for ssh logins' -Force | Out-Null
        Register-ScheduledTask -TaskName $webTask -Action $webAction -Trigger $trigger -Principal $principal -Settings $settings -Description 'Thessley admin web page' -Force | Out-Null
        if ($webWasEnabled) { Enable-ScheduledTask -TaskName $webTask | Out-Null } else { Disable-ScheduledTask -TaskName $webTask | Out-Null }
        Start-ScheduledTask -TaskName $task
        $serviceReady = $false
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Seconds 1
            $current = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            if ($current -and $current.State -eq 'Running') {
                $probe = [Net.Sockets.TcpClient]::new()
                try { $probe.Connect('127.0.0.1', 47800); $serviceReady = $true; break }
                catch { }
                finally { $probe.Dispose() }
            }
        }
        if (-not $serviceReady) { throw 'The approval service task did not become healthy on 127.0.0.1:47800.' }
        if ($webWasEnabled) {
            Write-Host 'Checking that the previously enabled web page stays running...'
            Start-ScheduledTask -TaskName $webTask
            $webReady = $false
            for ($i = 0; $i -lt 20; $i++) {
                Start-Sleep -Seconds 1
                $current = Get-ScheduledTask -TaskName $webTask -ErrorAction SilentlyContinue
                if ($current -and $current.State -eq 'Running') { $webReady = $true; break }
            }
            if (-not $webReady) { throw 'The web task was enabled before the upgrade but did not remain running.' }
        }
    } catch {
        Write-Warning "Activation failed; restoring the previous application and scheduled tasks: $($_.Exception.Message)"
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName $webTask -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $webTask -Confirm:$false -ErrorAction SilentlyContinue
        if ($newAppMoved -and (Test-Path -LiteralPath $app)) { Move-Item -LiteralPath $app -Destination $failedApp -Force }
        if ($oldAppMoved -and (Test-Path -LiteralPath $previousApp)) { Move-Item -LiteralPath $previousApp -Destination $app -Force }
        if ($gateLauncherExisted) { Copy-Item -LiteralPath (Join-Path $upgradeBackup 'gate.cmd') -Destination $gateLauncher -Force }
        else { Remove-Item -LiteralPath $gateLauncher -Force -ErrorAction SilentlyContinue }
        if ($cliLauncherExisted) { Copy-Item -LiteralPath (Join-Path $upgradeBackup 'thessley-pam-win.cmd') -Destination $cliLauncher -Force }
        else { Remove-Item -LiteralPath $cliLauncher -Force -ErrorAction SilentlyContinue }
        if ($restorePreviousTasks -and $serviceExisted) {
            Register-ScheduledTask -TaskName $task -Xml (Get-Content -Raw -LiteralPath (Join-Path $upgradeBackup 'service.xml')) -Force | Out-Null
            if ($serviceWasEnabled) { Enable-ScheduledTask -TaskName $task | Out-Null; Start-ScheduledTask -TaskName $task }
            else { Disable-ScheduledTask -TaskName $task | Out-Null }
        }
        if ($restorePreviousTasks -and $webExisted) {
            Register-ScheduledTask -TaskName $webTask -Xml (Get-Content -Raw -LiteralPath (Join-Path $upgradeBackup 'web.xml')) -Force | Out-Null
            if ($webWasEnabled) { Enable-ScheduledTask -TaskName $webTask | Out-Null; Start-ScheduledTask -TaskName $webTask }
            else { Disable-ScheduledTask -TaskName $webTask | Out-Null }
        }
        throw
    }

    if ($appExisted) { Write-Host "Previous application retained for recovery at: $previousApp" }
    $downloadSource = Join-Path $repo 'downloads'
    $downloadTarget = Join-Path $base 'downloads'
    New-Item -ItemType Directory -Force $downloadTarget | Out-Null
    if (Test-Path $downloadSource) {
        try { Copy-Item -Path (Join-Path $downloadSource '*') -Destination $downloadTarget -Force }
        catch { Write-Warning "The service is installed, but helper download bundles could not be refreshed: $($_.Exception.Message)" }
    }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\THESSLEY_STAGE -ErrorAction SilentlyContinue
}

Write-Host 'The approval service is healthy. Refreshing bundled helper downloads...'

# --- 5. optional firewall rule for the phone/app to reach the approval window --------------------------------------------
if ($OpenFirewall) {
    Remove-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName 'Thessley Passkey approvals VPN' -ErrorAction SilentlyContinue
    $approvalRemoteAddress = if ($CloudAccess) { 'Any' } else { 'LocalSubnet' }
    New-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47810 `
        -Program $Python -Profile $FirewallProfile -RemoteAddress $approvalRemoteAddress | Out-Null
    Write-Host "Firewall: allowed phone approvals and enrollment on TCP 47810 from $approvalRemoteAddress ($FirewallProfile networks)."
    if ($VpnClientSubnets) {
        Remove-NetFirewallRule -DisplayName 'Thessley Passkey approvals VPN' -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName 'Thessley Passkey approvals VPN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47810 `
            -Program $Python -Profile $FirewallProfile -RemoteAddress $vpnAddresses | Out-Null
        Write-Host "Firewall: also allowed phone approvals and enrollment on TCP 47810 from VPN client subnets $($vpnAddresses -join ', ')."
    }
}

if ($OpenWebFirewall) {
    Remove-NetFirewallRule -DisplayName 'Thessley admin web page' -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName 'Thessley admin web page VPN' -ErrorAction SilentlyContinue
    $webRemoteAddress = if ($CloudAccess) { 'Any' } else { 'LocalSubnet' }
    New-NetFirewallRule -DisplayName 'Thessley admin web page' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47820 `
        -Program $Python -Profile $FirewallProfile -RemoteAddress $webRemoteAddress | Out-Null
    Write-Host "Firewall: allowed TCP 47820 (the admin web page) from $webRemoteAddress ($FirewallProfile networks)."
    if ($VpnClientSubnets) {
        Remove-NetFirewallRule -DisplayName 'Thessley admin web page VPN' -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName 'Thessley admin web page VPN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47820 `
            -Program $Python -Profile $FirewallProfile -RemoteAddress $vpnAddresses | Out-Null
        Write-Host "Firewall: also allowed TCP 47820 from VPN client subnets $($vpnAddresses -join ', ')."
    }
}

# OpenSSH keeps its existing LocalSubnet rule. Add a separate, narrow VPN
# allowance so VPN clients can reach QR-gated SSH without widening LAN access.
Remove-NetFirewallRule -DisplayName 'Thessley OpenSSH VPN access' -ErrorAction SilentlyContinue
if ($VpnClientSubnets -and -not $CloudAccess -and (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Thessley OpenSSH VPN access' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 `
        -Profile Any -RemoteAddress $vpnAddresses | Out-Null
    Write-Host "Firewall: also allowed OpenSSH on TCP 22 from VPN client subnets $($vpnAddresses -join ', ')."
}

if ($OpenSshFirewall) {
    Remove-NetFirewallRule -DisplayName 'Thessley OpenSSH cloud access' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'Thessley OpenSSH cloud access' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 `
        -Profile Any -RemoteAddress Any | Out-Null
    Write-Host 'Firewall: allowed OpenSSH on TCP 22 from any remote address for cloud access.'
}

$cli = Join-Path $base 'thessley-pam-win.cmd'
& $cli status
Write-Host @"

Installed. This installer did not change sshd_config or Windows login policy.

The guided installer will print a direct FIRST-PHONE ENROLLMENT LINK for your administrator account when needed.
If you ran install\install.ps1 manually, create that one-time link with:
  & '$cli' web bootstrap --user YOUR_ADMIN_ACCOUNT

After enrolling the administrator phone, open Admin > Users to manage QR approval and SSH blocking for each local
account. The guided installer enables QR by default and preserves current OpenSSH key/password settings. Keep a working
SSH session open while testing any changed account.

To undo, turn off the affected QR checkboxes in Admin or restore the sshd_config backup shown there, then run
install\uninstall.ps1 as Administrator.
"@
