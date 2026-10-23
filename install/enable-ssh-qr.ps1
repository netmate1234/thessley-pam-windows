<#
  Add a Thessley QR approval gate to one Windows OpenSSH account.
  The original sshd_config is backed up and a SYSTEM rollback task restores it
  automatically unless the operator confirms a successful second SSH login.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$UserName,
    [Parameter(Mandatory = $true)][string]$Python,
    [ValidateSet('key', 'password', 'key-password')][string]$Factor = 'key',
    [ValidateRange(5, 60)][int]$RollbackMinutes = 15
)
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
if (-not (Test-Path -LiteralPath $sshd)) { $sshd = Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe' }
if (-not (Test-Path -LiteralPath $sshd)) { throw 'OpenSSH Server (sshd.exe) is not installed. Repair that feature before enabling the QR gate.' }
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw "OpenSSH configuration was not found: $config" }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python was not found: $Python" }
$service = Get-Service sshd -ErrorAction SilentlyContinue
if (-not $service) { throw 'The sshd service is missing. Repair OpenSSH Server before enabling the QR gate.' }
$taskName = "ThessleySSHConfigRollback-$UserName"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "A rollback timer already exists ($taskName). Resolve it before running setup again."
}

$original = [System.IO.File]::ReadAllText($config)
$newline = if ($original.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = [regex]::Split($original, "\r?\n")
$userPattern = '(?i)^\s*Match\s+User\s+.*(?:^|[\s,])' + [regex]::Escape($UserName) + '(?:$|[\s,])'
if ($original -match $userPattern) {
    if ($original -match ('(?is)Match\s+User\s+' + [regex]::Escape($UserName) + '[^\r\n]*.*?ForceCommand[^\r\n]*gate_main\.py')) {
        Write-Host "A Thessley QR gate is already configured for $UserName; validating it without changing sshd_config."
        $effective = & $sshd -T -f $config -C "user=$UserName,host=localhost,addr=127.0.0.1" 2>&1
        if ($LASTEXITCODE -ne 0 -or (($effective -join "`n") -notmatch '(?im)^forcecommand .*gate_main\.py')) {
            throw "The existing Match block for $UserName is not effective. Resolve the sshd_config match ordering manually."
        }
        return
    }
    throw "sshd_config already has a Match User block for $UserName. Review it and merge the Thessley settings there; no changes were made."
}

if ($Factor -in @('key', 'key-password')) {
    $keyFiles = @(
        (Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'),
        (Join-Path $env:USERPROFILE ".ssh\authorized_keys"),
        (Join-Path (Join-Path $env:SystemDrive "Users\$UserName") '.ssh\authorized_keys')
    ) | Select-Object -Unique
    if (-not ($keyFiles | Where-Object { (Test-Path -LiteralPath $_ -PathType Leaf) -and (Get-Item -LiteralPath $_).Length -gt 0 } | Select-Object -First 1)) {
        throw "No standard authorized_keys file was found. Set up and test this account's SSH key first, or choose password as the first factor."
    }
}

$firstMatch = -1
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^\s*Match\s+') { $firstMatch = $i; break }
}
$auth = switch ($Factor) {
    'key' { "    PasswordAuthentication no`n    PubkeyAuthentication yes`n    AuthenticationMethods publickey" }
    'password' { "    PasswordAuthentication yes`n    PubkeyAuthentication no`n    AuthenticationMethods password" }
    'key-password' { "    PasswordAuthentication yes`n    PubkeyAuthentication yes`n    AuthenticationMethods publickey,password" }
}
$gate = Join-Path $env:ProgramData 'ThessleyPamWin\app\gate_main.py'
if (-not (Test-Path -LiteralPath $gate)) { throw 'The Thessley approval service is not installed. Run the main installer first.' }
$pythonQuoted = '"' + $Python.Replace('"', '\"') + '"'
$gateQuoted = '"' + $gate + '"'
$block = @(
    "# Thessley phone approval for $UserName",
    "Match User $UserName"
) + ($auth -split "`n") + @(
    '    KbdInteractiveAuthentication no',
    '    AllowTcpForwarding no',
    '    AllowAgentForwarding no',
    '    X11Forwarding no',
    '    PermitTunnel no',
    '    PermitTTY yes',
    "    ForceCommand $pythonQuoted -I -X utf8 $gateQuoted"
)
if ($firstMatch -ge 0) {
    $newLines = @()
    if ($firstMatch -gt 0) { $newLines += $lines[0..($firstMatch - 1)] }
    $newLines += $block
    $newLines += $lines[$firstMatch..($lines.Length - 1)]
} else {
    $newLines = @($lines) + $block
}
$newText = ($newLines -join $newline)
if ($original.EndsWith("`n")) { $newText += $newline }

$backupDir = Join-Path $env:ProgramData 'ThessleyPamWin\backups'
New-Item -ItemType Directory -Force $backupDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $backupDir "sshd_config.$UserName.$stamp.bak"
Copy-Item -LiteralPath $config -Destination $backup
$rollbackScript = Join-Path $env:ProgramData 'ThessleyPamWin' "rollback-sshd-$UserName.ps1"
$configLiteral = "'" + $config.Replace("'", "''") + "'"
$backupLiteral = "'" + $backup.Replace("'", "''") + "'"
$taskLiteral = "'" + $taskName.Replace("'", "''") + "'"
$rollbackBody = @"
`$ErrorActionPreference = 'Stop'
Copy-Item -LiteralPath $backupLiteral -Destination $configLiteral -Force
Restart-Service sshd -Force
Unregister-ScheduledTask -TaskName $taskLiteral -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'Original sshd_config restored by Thessley rollback.'
"@
Set-Content -LiteralPath $rollbackScript -Value $rollbackBody -Encoding ascii
$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackScript`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Restores sshd_config unless Thessley QR SSH for $UserName is verified." | Out-Null

try {
    [System.IO.File]::WriteAllText($config, $newText, [System.Text.UTF8Encoding]::new($false))
    $validation = & $sshd -t -f $config 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sshd_config validation failed: $($validation -join ' ')" }
    $effective = & $sshd -T -f $config -C "user=$UserName,host=localhost,addr=127.0.0.1" 2>&1
    if ($LASTEXITCODE -ne 0 -or (($effective -join "`n") -notmatch '(?im)^forcecommand .*gate_main\.py')) {
        throw "sshd did not apply the Thessley gate to $UserName."
    }
    if ($Factor -eq 'key' -and (($effective -join "`n") -notmatch '(?im)^authenticationmethods publickey$')) {
        throw 'The effective SSH policy is not key-only plus the Thessley gate.'
    }
    Restart-Service sshd -Force
    if ((Get-Service sshd).Status -ne 'Running') { throw 'The sshd service did not return to Running.' }
} catch {
    Copy-Item -LiteralPath $backup -Destination $config -Force
    Restart-Service sshd -Force -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}

Write-Host "Thessley QR SSH gate enabled for $UserName (first factor: $Factor)."
Write-Host "Original config backup: $backup"
Write-Host "Automatic rollback: $((Get-Date).AddMinutes($RollbackMinutes)). Keep this session open and test a new SSH login."
Write-Host "After the new login succeeds, confirm all requested setup changes with:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $env:ProgramData 'ThessleyPamWin\confirm-setup.ps1')`""
