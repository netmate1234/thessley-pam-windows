<#
  Removes the Thessley approval service. Run in an administrator PowerShell.

  FIRST remove the "Match User ..." block (the one with ForceCommand ...gate.cmd) from C:\ProgramData\ssh\sshd_config and
  restart sshd. If it is still there, those users are refused at login, because the gate is gone.

      powershell -ExecutionPolicy Bypass -File install\uninstall.ps1 [-RemoveData]

  -RemoveData also deletes the enrolled approvers, passes and the log.
#>
param([switch]$RemoveData)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an administrator PowerShell.'
}
$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
if ((Test-Path $cfg) -and (Select-String -Path $cfg -Pattern 'ThessleyPamWin' -Quiet)) {
    throw "sshd_config still mentions ThessleyPamWin. Remove that Match block and restart sshd first, or those logins will be refused."
}
Stop-ScheduledTask -TaskName 'ThessleyPamWin' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'ThessleyPamWin' -Confirm:$false -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'ThessleyPamWinWeb' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'ThessleyPamWinWeb' -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Thessley admin web page' -ErrorAction SilentlyContinue
if ($RemoveData) {
    Remove-Item -Recurse -Force $base
    Write-Host 'Removed the program and all data.'
} else {
    foreach ($f in 'app', 'gate.cmd', 'thessley-pam-win.cmd') { Remove-Item -Recurse -Force (Join-Path $base $f) -ErrorAction SilentlyContinue }
    Write-Host "Removed the program. Approvers and the log are kept in $base (use -RemoveData to delete them)."
}
