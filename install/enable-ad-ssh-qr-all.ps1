<#
  Gate SSH for every account except the local Administrator with the AD phone approval.
  This is the installer's "enable everywhere" step for a PC paired with the AD service:
  members of the AD sign-in group approve on the phone, and the local Administrator stays
  as break-glass for automation. It keeps a timed rollback like the per-account variant.
#>
param([ValidateRange(5, 60)][int]$RollbackMinutes = 30)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = @(
    (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'),
    (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$forceCommand = Join-Path $base 'ad-ssh-gate.cmd'
$pythonGate = Join-Path $base 'app\ad_ssh_gate_main.py'
$taskName = 'ThessleyADSSHConfigRollback-AllUsers'
if (-not $sshd) { throw 'OpenSSH Server is not installed.' }
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw "OpenSSH config is missing: $config" }
if (-not (Test-Path -LiteralPath $forceCommand -PathType Leaf) -or -not (Test-Path -LiteralPath $pythonGate -PathType Leaf)) {
    throw 'Update/install Thessley Passkey first; the AD SSH gate is missing.'
}
if (-not (Get-ScheduledTask -TaskName 'ThessleyPamWin' -ErrorAction SilentlyContinue)) {
    throw 'The Thessley SYSTEM approval service is not installed.'
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'An all-users AD SSH rollback is already armed. Confirm or let it expire first.'
}

$original = [IO.File]::ReadAllText($config)
$newline = if ($original.Contains("`r`n")) { "`r`n" } else { "`n" }
$launcherText = [IO.File]::ReadAllText($forceCommand)
$pythonMatch = [regex]::Match($launcherText, '"([^"\r\n]+python\.exe)"', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
if (-not $pythonMatch.Success) { throw 'Could not determine the installed Python executable from ad-ssh-gate.cmd.' }
$python = $pythonMatch.Groups[1].Value
$commandQuoted = '"' + $python.Replace('"', '\"') + '" -I -X utf8 "' + $pythonGate.Replace('"', '\"') + '"'

$markerStart = '# BEGIN THESSLEY AD SSH QR all-users'
$markerEnd = '# END THESSLEY AD SSH QR all-users'
$block = @(
    $markerStart,
    'Match User *,!*dministrator*',
    '    AllowTcpForwarding no',
    '    AllowAgentForwarding no',
    '    PermitTTY yes',
    "    ForceCommand $commandQuoted",
    $markerEnd
)

$lines = [regex]::Split($original, "\r?\n")
$startIndex = -1
$endIndex = -1
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -ceq $markerStart) { $startIndex = $i }
    if ($lines[$i] -ceq $markerEnd) { $endIndex = $i }
}
if (($startIndex -ge 0) -or ($endIndex -ge 0)) {
    if ($startIndex -lt 0 -or $endIndex -le $startIndex) {
        throw 'The existing all-users Thessley AD SSH block is malformed; sshd_config was not changed.'
    }
    $newLines = @()
    if ($startIndex -gt 0) { $newLines += $lines[0..($startIndex - 1)] }
    $newLines += $block
    if ($endIndex -lt $lines.Length - 1) { $newLines += $lines[($endIndex + 1)..($lines.Length - 1)] }
} else {
    $firstMatch = -1
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match '^\s*Match\s+') { $firstMatch = $i; break }
    }
    if ($firstMatch -ge 0) {
        $newLines = @()
        if ($firstMatch -gt 0) { $newLines += $lines[0..($firstMatch - 1)] }
        $newLines += $block
        $newLines += $lines[$firstMatch..($lines.Length - 1)]
    } else {
        $newLines = @($lines) + $block
    }
}

$newText = $newLines -join $newline
if ($original.EndsWith("`n")) { $newText += $newline }

$backupDir = Join-Path $base 'backups'
New-Item -ItemType Directory -Force $backupDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $backupDir "sshd_config.ad-all-users.$stamp.bak"
Copy-Item -LiteralPath $config -Destination $backup

try {
    [IO.File]::WriteAllText($config, $newText)
    $check = & $sshd -t -f $config -o UseDNS=no 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('sshd rejected the updated config: ' + ($check -join ' ')) }
    # A -C probe resolves the account through the domain and can fail for a bare domain name,
    # so the check is the accepted configuration plus the managed block being present.
    $applied = Select-String -LiteralPath $config -Pattern '^Match User \*,!\*dministrator\*$', 'ad_ssh_gate_main\.py' -ErrorAction SilentlyContinue
    if (-not $applied) {
        throw 'The AD SSH gate block was not written; sshd_config was restored.'
    }
} catch {
    Copy-Item -LiteralPath $backup -Destination $config -Force
    throw
}

Restart-Service sshd -Force

$rollbackScript = Join-Path $base 'rollback-ad-ssh-all-users.ps1'
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

$register = Join-Path $PSScriptRoot '..\windows-logon-provider\register-verified-rollback.ps1'
if (Test-Path -LiteralPath $register) {
    & $register -TaskName $taskName -RollbackFile $rollbackScript -RollbackMinutes $RollbackMinutes | Out-Null
} else {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$rollbackScript`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
}

# One phone approval covers later logins from the same client IP for four hours.
$cli = Join-Path $base 'thessley-pam-win.cmd'
if (Test-Path -LiteralPath $cli) { & $cli grace --hours 4 | Out-Null }

Write-Output 'AD QR SSH approval enabled for every account except the local Administrator.'
Write-Output 'One approval now covers SSH logins from the same client IP for 4 hours.'
Write-Output "Config backup: $backup"
Write-Output "Automatic rollback in $RollbackMinutes minutes. Test a fresh SSH login as a domain account, then keep it with:"
Write-Output "  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
