<#
  Allow only the domain Administrator (and the local Administrator) to log in over SSH.
  The QR gate still applies to that account. Refuses to lock everyone out: it validates
  sshd -t, keeps a backup, and arms a timed rollback.
#>
param([ValidateRange(5, 60)][int]$RollbackMinutes = 20)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$config = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = @(
    (Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'),
    (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$backupDir = Join-Path $env:ProgramData 'ThessleyPamWin\backups'
$taskName = 'ThessleyAdminOnlySshRollback'
if (-not $sshd) { throw 'OpenSSH Server is not installed.' }
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw "OpenSSH config is missing: $config" }
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'An admin-only SSH rollback is already armed. Confirm or let it expire first.'
}

$domain = $env:USERDOMAIN
if (-not $domain) {
    $fqdn = (Get-CimInstance Win32_ComputerSystem).Domain
    if ($fqdn -and $fqdn -notmatch '^(WORKGROUP)?$' -and $fqdn.Contains('.')) { $domain = $fqdn.Split('.')[0] }
}
if (-not $domain -or $domain -eq 'WORKGROUP') { $domain = $env:COMPUTERNAME }
$accounts = @("$domain\administrator".ToLowerInvariant(), 'administrator') | Select-Object -Unique

$text = [IO.File]::ReadAllText($config)
$nl = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = [regex]::Split($text, "\r?\n")
$first = $lines.Length
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^\s*Match\s+') { $first = $i; break }
}
$allowLine = 'AllowUsers ' + ($accounts -join ' ')
$new = @()
if ($first -gt 0) { $new += $lines[0..($first - 1)] }
$new += $allowLine
if ($first -lt $lines.Length) { $new += $lines[$first..($lines.Length - 1)] }

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $backupDir "sshd_config.adminonly.$stamp.bak"
Copy-Item -LiteralPath $config -Destination $backup
[IO.File]::WriteAllText($config, (($new -join $nl) + $nl))

& $sshd -t -f $config -o UseDNS=no 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Copy-Item -LiteralPath $backup -Destination $config -Force
    throw 'sshd rejected the change; the previous config was restored.'
}
Restart-Service sshd -Force

$rb = Join-Path $backupDir 'rollback-adminonly.ps1'
$body = @"
`$ErrorActionPreference = 'Stop'
Copy-Item -LiteralPath '$backup' -Destination '$config' -Force
Restart-Service sshd -Force
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'Admin-only SSH restriction removed.'
"@
Set-Content -LiteralPath $rb -Value $body -Encoding ascii
$action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$rb`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Write-Output "Only these accounts may log in over SSH now: $($accounts -join ', ')"
Write-Output "Keep it with: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
Write-Output "Rollback in $RollbackMinutes minutes restores the previous sshd_config."
