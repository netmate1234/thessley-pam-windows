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

  It does NOT change sshd_config, the firewall (unless you pass -OpenFirewall; -FirewallProfile Any includes "Public" networks), accounts or groups. Those are left
  to you; the last lines print what to do.
#>
param(
    [Parameter(Mandatory = $true)][string]$Python,
    [switch]$OpenFirewall,
    [switch]$OpenWebFirewall,   # also allow the admin web page's port (47820) from the local subnet
    [ValidateSet('Private', 'Any')][string]$FirewallProfile = 'Private'   # 'Any' also covers networks Windows calls Public
)
$ErrorActionPreference = 'Stop'

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
try {
    Copy-Item -Recurse -Force (Join-Path $repo 'thessley_pam_win') $stage
    Get-ChildItem (Join-Path $stage 'thessley_pam_win') -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force

    # Install exact locked versions into the candidate only; failed installs leave both system Python and the live app alone.
    $requirements = Join-Path $PSScriptRoot '..\requirements.lock'
    $vendor = Join-Path $stage 'vendor'
    & $Python -m pip install --quiet --disable-pip-version-check --only-binary=:all: --target $vendor --requirement $requirements
    if ($LASTEXITCODE -ne 0) { throw 'pip could not install the pinned dependencies into the staged app. The live install was not changed.' }
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
    $webWasEnabled = $webExisted -and $oldWeb.State -ne 'Disabled'
    if ($serviceExisted) { Export-ScheduledTask -TaskName $task | Set-Content -LiteralPath (Join-Path $upgradeBackup 'service.xml') -Encoding Unicode }
    if ($webExisted) { Export-ScheduledTask -TaskName $webTask | Set-Content -LiteralPath (Join-Path $upgradeBackup 'web.xml') -Encoding Unicode }
    $appExisted = Test-Path -LiteralPath $app -PathType Container
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
        if ($serviceExisted) { Register-ScheduledTask -TaskName $task -Xml (Get-Content -Raw -LiteralPath (Join-Path $upgradeBackup 'service.xml')) -Force | Out-Null }
        if ($webExisted) {
            Register-ScheduledTask -TaskName $webTask -Xml (Get-Content -Raw -LiteralPath (Join-Path $upgradeBackup 'web.xml')) -Force | Out-Null
            if ($webWasEnabled) { Enable-ScheduledTask -TaskName $webTask | Out-Null; Start-ScheduledTask -TaskName $webTask }
            else { Disable-ScheduledTask -TaskName $webTask | Out-Null }
        }
        if ($serviceExisted) { Enable-ScheduledTask -TaskName $task | Out-Null; Start-ScheduledTask -TaskName $task }
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

# --- 5. optional firewall rule for the phone/app to reach the approval window --------------------------------------------
if ($OpenFirewall) {
    Remove-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47810 `
        -Program $Python -Profile $FirewallProfile -RemoteAddress LocalSubnet | Out-Null
    Write-Host "Firewall: allowed TCP 47810 from the local subnet ($FirewallProfile networks)."
}

if ($OpenWebFirewall) {
    Remove-NetFirewallRule -DisplayName 'Thessley admin web page' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'Thessley admin web page' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47820 `
        -Program $Python -Profile $FirewallProfile -RemoteAddress LocalSubnet | Out-Null
    Write-Host "Firewall: allowed TCP 47820 (the admin web page) from the local subnet ($FirewallProfile networks)."
}

$cli = Join-Path $base 'thessley-pam-win.cmd'
& $cli status
Write-Host @"

Installed. Next steps (nothing below has been done for you):

  1. Add an approver for your Windows account (phone, or the desktop app):
       & '$cli' enroll --user YOURNAME
  2. Allow the phone to reach this computer while a login waits (TCP 47810, same Wi-Fi). Either re-run this
     script with -OpenFirewall, or add your own rule. A phone on a network Windows calls "Public" will not get through.
  3. Print the sshd_config lines for your account:
       & '$cli' sshd-config --user YOURNAME
     Add them at the END of C:\ProgramData\ssh\sshd_config, check with  sshd -t , then  Restart-Service sshd.
  4. Keep one session open and try a login from another computer.

To undo: remove the Match block from sshd_config FIRST (otherwise those logins are refused), restart sshd, then
run install\uninstall.ps1.
"@
