<#
  Installs the Thessley approval service for ssh logins to this computer.

  Run in an ADMINISTRATOR PowerShell, from the repository folder:

      powershell -ExecutionPolicy Bypass -File install\install.ps1 -Python "C:\Program Files\Python313\python.exe"

  What it does (and nothing else):
    1. checks that the Python you name sits in a folder normal users cannot write to (the service runs as SYSTEM,
       so anything it loads must be out of their reach);
    2. installs the two libraries it needs (cryptography, qrcode) into that Python;
    3. copies the program to C:\ProgramData\ThessleyPamWin\app and locks the folder down (SYSTEM + Administrators
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

# --- 2. libraries ---------------------------------------------------------------------------------------------------
& $Python -m pip install --quiet --disable-pip-version-check cryptography qrcode asn1crypto
if ($LASTEXITCODE -ne 0) { throw 'pip could not install cryptography, qrcode and asn1crypto.' }

# --- 3. program and permissions --------------------------------------------------------------------------------------
New-Item -ItemType Directory -Force $base, $app | Out-Null
Remove-Item -Recurse -Force (Join-Path $app 'thessley_pam_win') -ErrorAction SilentlyContinue
Copy-Item -Recurse -Force (Join-Path $repo 'thessley_pam_win') $app
Get-ChildItem (Join-Path $app 'thessley_pam_win') -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force

foreach ($entry in @(@('daemon_main.py', 'daemon'), @('gate_main.py', 'gate'), @('cli_main.py', 'cli'), @('web_main.py', 'web'))) {
    @"
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I removes the script folder from the path
from thessley_pam_win.$($entry[1]) import main

raise SystemExit(main())
"@ | Set-Content -Encoding ascii (Join-Path $app $entry[0])
}

$run = "`"$Python`" -I -X utf8"
Set-Content -Encoding ascii (Join-Path $base 'gate.cmd') "@$run `"$app\gate_main.py`""
Set-Content -Encoding ascii (Join-Path $base 'thessley-pam-win.cmd') "@$run `"$app\cli_main.py`" %*"

# Lock down: SYSTEM and Administrators everything; Users may only open the folder, read the program and run gate.cmd.
icacls $base /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
icacls $base /grant '*S-1-5-32-545:(RX)' | Out-Null                      # Users: this folder only, to reach what is below
icacls $app /grant '*S-1-5-32-545:(OI)(CI)RX' | Out-Null                 # Users: the program (the gate runs as them)
icacls (Join-Path $base 'gate.cmd') /grant '*S-1-5-32-545:(RX)' | Out-Null
# Users may run the admin tool too: only `enroll` (for their own account) works without administrator rights; the service
# decides who is asking and what is allowed, and the data folders stay closed to them.
icacls (Join-Path $base 'thessley-pam-win.cmd') /grant '*S-1-5-32-545:(RX)' | Out-Null
foreach ($d in 'users', 'grants') { New-Item -ItemType Directory -Force (Join-Path $base $d) | Out-Null }

# --- 4. the service ------------------------------------------------------------------------------------------------
# On an upgrade the old service may still be running (and holding its port): stop it first. Passes end with it.
Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
$action    = New-ScheduledTaskAction -Execute $Python -Argument "-I -X utf8 `"$app\daemon_main.py`""
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Thessley Passkey approvals for ssh logins' | Out-Null
Start-ScheduledTask -TaskName $task

# The admin web page (docs\WEB.md) is its own task, also SYSTEM at boot. It stays OFF until `thessley-pam-win web on`; an
# upgrade keeps it on if it was on.
$webWasOn = $false
$old = Get-ScheduledTask -TaskName $webTask -ErrorAction SilentlyContinue
if ($old -and $old.State -ne 'Disabled') { $webWasOn = $true }
Stop-ScheduledTask -TaskName $webTask -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $webTask -Confirm:$false -ErrorAction SilentlyContinue
$webAction = New-ScheduledTaskAction -Execute $Python -Argument "-I -X utf8 `"$app\web_main.py`""
Register-ScheduledTask -TaskName $webTask -Action $webAction -Trigger $trigger -Principal $principal -Settings $settings -Description 'Thessley admin web page' | Out-Null
if ($webWasOn) { Start-ScheduledTask -TaskName $webTask } else { Disable-ScheduledTask -TaskName $webTask | Out-Null }
Start-Sleep -Seconds 3

# --- 5. optional firewall rule for the phone/app to reach the approval window --------------------------------------------
if ($OpenFirewall) {
    Remove-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47810-47819 `
        -Program $Python -Profile $FirewallProfile -RemoteAddress LocalSubnet | Out-Null
    Write-Host "Firewall: allowed TCP 47810-47819 from the local subnet ($FirewallProfile networks)."
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
  2. Allow the phone to reach this computer while a login waits (TCP 47810-47819, same Wi-Fi). Either re-run this
     script with -OpenFirewall, or add your own rule. A phone on a network Windows calls "Public" will not get through.
  3. Print the sshd_config lines for your account:
       & '$cli' sshd-config --user YOURNAME
     Add them at the END of C:\ProgramData\ssh\sshd_config, check with  sshd -t , then  Restart-Service sshd.
  4. Keep one session open and try a login from another computer.

To undo: remove the Match block from sshd_config FIRST (otherwise those logins are refused), restart sshd, then
run install\uninstall.ps1.
"@
