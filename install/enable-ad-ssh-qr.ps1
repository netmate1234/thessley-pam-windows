<#
  Development-only AD-account QR SSH gate.
  It adds a ForceCommand for exactly one DOMAIN\user and arms a separate
  automatic rollback before restarting sshd. It does not change auth factors,
  firewall rules, local-account QR behavior, or Windows sign-in providers.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$')][string]$Domain,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$UserName,
    [ValidateRange(5, 60)][int]$RollbackMinutes = 15
)
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
$forceCommand = Join-Path $base 'ad-ssh-gate.cmd'
$taskName = "ThessleyADSSHConfigRollback-$($Domain)-$($UserName)"
if (-not (Test-Path -LiteralPath $sshd -PathType Leaf)) { throw 'OpenSSH Server is not installed.' }
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw "OpenSSH config is missing: $config" }
if (-not (Test-Path -LiteralPath $forceCommand -PathType Leaf)) { throw 'Update/install Thessley Passkey first; ad-ssh-gate.cmd is missing.' }
if (-not (Get-ScheduledTask -TaskName 'ThessleyPamWin' -ErrorAction SilentlyContinue)) {
    throw 'The Thessley SYSTEM approval service is not installed.'
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "A rollback is already armed for $Domain\$UserName. Confirm or let it expire first."
}

$original = [IO.File]::ReadAllText($config)
$newline = if ($original.Contains("`r`n")) { "`r`n" } else { "`n" }
$account = "$($Domain.ToLowerInvariant())\$($UserName.ToLowerInvariant())"
$existingMatchPattern = '(?im)^\s*Match\s+User\s+.*' + [regex]::Escape($account)
if ($original -match $existingMatchPattern) {
    throw "sshd_config already contains a Match User rule for $Domain\$UserName; merge it manually."
}
$lines = [regex]::Split($original, "\r?\n")
$firstMatch = -1
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^\s*Match\s+') { $firstMatch = $i; break }
}
$commandQuoted = '"' + $forceCommand.Replace('"', '\"') + '"'
$block = @(
    "# BEGIN THESSLEY AD SSH QR $account",
    "Match User $account",
    '    AllowTcpForwarding no',
    '    AllowAgentForwarding no',
    '    PermitTTY yes',
    "    ForceCommand $commandQuoted",
    "# END THESSLEY AD SSH QR $account"
)
if ($firstMatch -ge 0) {
    $newLines = @()
    if ($firstMatch -gt 0) { $newLines += $lines[0..($firstMatch - 1)] }
    $newLines += $block
    $newLines += $lines[$firstMatch..($lines.Length - 1)]
} else {
    $newLines = @($lines) + $block
}
$newText = $newLines -join $newline
if ($original.EndsWith("`n")) { $newText += $newline }

$backupDir = Join-Path $base 'backups'
New-Item -ItemType Directory -Force $backupDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $backupDir "sshd_config.ad-$($Domain)-$($UserName).$stamp.bak"
Copy-Item -LiteralPath $config -Destination $backup
$rollbackScript = Join-Path $base "rollback-ad-ssh-$($Domain)-$($UserName).ps1"
$configLiteral = "'" + $config.Replace("'", "''") + "'"
$backupLiteral = "'" + $backup.Replace("'", "''") + "'"
$taskLiteral = "'" + $taskName.Replace("'", "''") + "'"
$rollbackBody = @"
`$ErrorActionPreference = 'Stop'
Copy-Item -LiteralPath $backupLiteral -Destination $configLiteral -Force
Restart-Service sshd -Force
Unregister-ScheduledTask -TaskName $taskLiteral -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'Original sshd_config restored by AD SSH QR rollback.'
"@
Set-Content -LiteralPath $rollbackScript -Value $rollbackBody -Encoding ascii
$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackScript`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Restores sshd_config unless AD SSH QR for $Domain\$UserName is verified." | Out-Null
try {
    $rollbackTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $rollbackInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
    $expectedSystemSid = 'S-1-5-18'
    $principalName = [string]$rollbackTask.Principal.UserId
    $actualPrincipalSid = if ($principalName -match '^S-1-[0-9-]+$') {
        $principalName
    } else {
        ([Security.Principal.NTAccount]::new($principalName)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    $expectedLatest = (Get-Date).AddMinutes($RollbackMinutes + 2)
    if (-not $rollbackTask.Settings.Enabled -or $actualPrincipalSid -ne $expectedSystemSid -or
        $rollbackInfo.NextRunTime -le (Get-Date) -or $rollbackInfo.NextRunTime -gt $expectedLatest) {
        throw "Rollback task verification failed (state=$($rollbackTask.State), principal=$actualPrincipalSid, next run=$($rollbackInfo.NextRunTime))."
    }
} catch {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw "The SSH config rollback could not be verified. sshd_config was not changed. $($_.Exception.Message)"
}

try {
    [IO.File]::WriteAllText($config, $newText, [Text.UTF8Encoding]::new($false))
    $validation = & $sshd -t -f $config 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sshd_config validation failed: $($validation -join ' ')" }
    # Windows OpenSSH's -T -C user=DOMAIN\user context fails to resolve some
    # valid AD principals even though the same Match User rule works for an
    # authenticated SSH session. Validate the complete config with -t, then
    # verify the exact managed Match/ForceCommand block on disk; the guarded
    # real SSH login is the final applicability check.
    $written = [IO.File]::ReadAllText($config)
    if (-not $written.Contains("Match User $account") -or
        -not $written.Contains("ForceCommand $commandQuoted")) {
        throw "The AD QR Match/ForceCommand block for $Domain\$UserName is missing from sshd_config."
    }
    Restart-Service sshd -Force
    if ((Get-Service sshd).Status -ne 'Running') { throw 'sshd did not return to Running.' }
} catch {
    Copy-Item -LiteralPath $backup -Destination $config -Force
    Restart-Service sshd -Force -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}

Write-Host "AD QR SSH approval enabled for $Domain\$UserName; existing SSH authentication remains in force."
Write-Host "Config backup: $backup"
Write-Host "Automatic rollback in $RollbackMinutes minutes. Keep an existing admin SSH session open and test a second login."
Write-Host "After the AD SSH test works, run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'confirm-ad-ssh-qr.ps1')`" -Domain '$Domain' -UserName '$UserName'"
Write-Host 'SFTP subsystem sessions are not supported by this shell gate; do not use this rule for SFTP-only accounts.'
