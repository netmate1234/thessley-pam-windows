<#
  Removes a previous Thessley Passkey installation so the guided installer can start clean. Run it in an ELEVATED PowerShell
  at the computer itself (console, RDP or an existing elevated session), not only over a gated SSH login: this restarts sshd.

      powershell -ExecutionPolicy Bypass -File .\remove-for-reinstall.ps1            # dry run: prints what it would do, changes nothing
      powershell -ExecutionPolicy Bypass -File .\remove-for-reinstall.ps1 -Apply     # does it

  What -Apply does, in this order:
    1. copies the approvers, passes, web settings and logs to C:\ThessleyRemoval-<date-time> (a way back)
    2. backs up sshd_config, removes the Match blocks that run the Thessley gate, validates the file with sshd -t, restarts sshd
       (if the new file does not validate, the old one is restored and nothing else is touched)
    3. stops and removes the Thessley scheduled tasks
    4. removes the Windows sign-in tile registration (registry only; built-in sign-in methods are not changed)
    5. removes the Thessley firewall rules (the plain OpenSSH rule stays)
    6. removes C:\ProgramData\ThessleyPamWin
  Local user accounts and their ssh keys are never touched, and neither are your files.
#>
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated (Administrator) PowerShell.'
}

$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
if (-not (Test-Path $sshd)) { $sshd = Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "C:\ThessleyRemoval-$stamp"
$providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$taskNames = 'ThessleyPamWin', 'ThessleyPamWinWeb', 'ThessleyPamWinUpdate', 'ThessleyCredentialProviderRollback', 'ThessleySSHConfigRollback-Setup'

function Step($text) { Write-Host ("[{0}] {1}" -f $(if ($Apply) { 'DO ' } else { 'DRY' }), $text) }

# the sshd_config without the Match blocks that mention ThessleyPamWin; the other blocks stay exactly as they are
function Strip-ThessleyBlocks([string[]]$lines) {
    $out = New-Object System.Collections.Generic.List[string]
    $block = New-Object System.Collections.Generic.List[string]
    $inMatch = $false
    $flush = {
        if ($block.Count) {
            if (-not (($block -join "`n") -match 'ThessleyPamWin')) { $out.AddRange($block) }
            $block.Clear()
        }
    }
    foreach ($l in $lines) {
        if ($l -match '^\s*Match\s') { & $flush; $inMatch = $true; $block.Add($l); continue }
        if ($inMatch) { $block.Add($l) } else { $out.Add($l) }
    }
    & $flush
    # Thessley's own "# BEGIN/END THESSLEY ..." marker comments: the opening ones sit just above a Match line and so stay behind
    # when the block is cut. Left alone they look like an unfinished block to the guided installer, so they go too.
    $clean = @($out.ToArray() | Where-Object { $_ -notmatch '^\s*#\s*(BEGIN|END)\s+THESSLEY\b' })
    return , $clean
}

Write-Host "Computer: $env:COMPUTERNAME   Mode: $(if ($Apply) { 'APPLY' } else { 'dry run (add -Apply to do it)' })"
if (-not (Test-Path $base)) { Write-Host "No $base found; the data and task steps will be skipped." }

# 1. a copy of what is worth keeping
Step "copy approvers, passes, web settings and logs to $backup"
if ($Apply -and (Test-Path $base)) {
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    foreach ($item in 'users', 'grants', 'web', 'config.json', 'web-admins.json', 'service.log') {
        $src = Join-Path $base $item
        if (Test-Path $src) { Copy-Item -Recurse -Force $src (Join-Path $backup $item) }
    }
    if (Test-Path $cfg) { Copy-Item -Force $cfg (Join-Path $backup 'sshd_config') }
}

# 2. sshd_config
if (Test-Path $cfg) {
    $old = [IO.File]::ReadAllLines($cfg)
    $new = Strip-ThessleyBlocks $old
    $removed = $old.Count - $new.Count
    Step "sshd_config: remove $removed lines of Thessley Match blocks, check with sshd -t, restart sshd"
    if ($Apply -and $removed -gt 0) {
        $copy = "$cfg.before-thessley-removal-$stamp"
        Copy-Item -Force $cfg $copy
        [IO.File]::WriteAllLines($cfg, $new, (New-Object Text.UTF8Encoding($false)))
        & $sshd -t -f $cfg
        if ($LASTEXITCODE -ne 0) {
            Copy-Item -Force $copy $cfg
            throw "sshd -t rejected the edited file; the original sshd_config was put back and nothing else was changed."
        }
        if ($env:SSH_CONNECTION -or $env:SSH_CLIENT -or $env:SSH_TTY) {
            # Restarting sshd ends this ssh session and with it the rest of this run: do it a minute from now instead.
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -Command "Restart-Service sshd -Force; Unregister-ScheduledTask -TaskName ThessleySshdRestartOnce -Confirm:$false"'
            $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(60)
            Register-ScheduledTask -TaskName 'ThessleySshdRestartOnce' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
            Write-Host "sshd restarts in about a minute (this ssh session ends then; log in again). The previous file is $copy"
        } else {
            Restart-Service sshd
            Write-Host "sshd restarted. The previous file is $copy"
        }
    }
}

# 3. scheduled tasks
foreach ($t in $taskNames) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Step "remove scheduled task $t"
        if ($Apply) {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $t -Confirm:$false
        }
    }
}

# 4. sign-in tile registration (registry only)
$cp = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
$clsid = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$providerId"
foreach ($k in $cp, $clsid) {
    if (Test-Path $k) {
        Step "remove registry key $($k -replace '^Registry::','')"
        if ($Apply) { Remove-Item -Recurse -Force $k }
    }
}

# 5. firewall
Get-NetFirewallRule -DisplayName 'Thessley*' -ErrorAction SilentlyContinue | ForEach-Object {
    Step "remove firewall rule '$($_.DisplayName)'"
    if ($Apply) { Remove-NetFirewallRule -Name $_.Name }
}

# 6. program and data (a copy of the data is in $backup)
if (Test-Path $base) {
    Step "remove $base"
    if ($Apply) { Remove-Item -Recurse -Force $base }
}

if ($Apply) {
    Write-Host "Done. Backup of the approvers and settings: $backup"
    Write-Host "Restart Windows once so the sign-in screen forgets the tile, then run the guided installer."
} else {
    Write-Host "Dry run only: nothing was changed."
}
