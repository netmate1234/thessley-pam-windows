<# Arm verified timed SSH recovery before the guided installer edits sshd_config. #>
param(
    [ValidateRange(5,60)][int]$RollbackMinutes = 30,
    [string]$OriginalConfigBackup = ''
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run SSH recovery setup from an administrator PowerShell.'
}
$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
if (-not (Test-Path $sshd)) { $sshd = Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe' }
$imagePath = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -Name ImagePath).ImagePath
if ($imagePath -match '^\s*"?(.+?sshd\.exe)"?(?:\s|$)') { $sshd = [Environment]::ExpandEnvironmentVariables($matches[1]) }
if ($imagePath -match '(?:^|\s)-f\s+(?:"([^"]+)"|(\S+))') {
    $config = if ($matches[1]) { $matches[1] } else { $matches[2] }
}
if (-not (Test-Path $config -PathType Leaf) -or -not (Test-Path $sshd -PathType Leaf)) { throw 'OpenSSH executable or configuration is missing.' }
$taskName = 'ThessleySSHConfigRollback-Setup'
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
$root = $scheduler.GetFolder('\')
$existing = @($root.GetTasks(0) | Where-Object { $_.Name -eq $taskName })
if ($existing.Count) {
    $pending = $existing[0]
    if (-not $pending.Enabled -or $pending.NextRunTime -le (Get-Date)) { throw 'An old SSH setup recovery task exists but is not armed. Resolve it before changing SSH.' }
    Write-Host ('Existing SSH setup rollback remains active until '+$pending.NextRunTime+'; its deadline was not extended.')
    [pscustomobject]@{ TaskName=$taskName; Deadline=$pending.NextRunTime; Existing=$true }
    return
}
$source = if ($OriginalConfigBackup) { (Resolve-Path -LiteralPath $OriginalConfigBackup).Path } else { $config }
& $sshd -t -f $source
if ($LASTEXITCODE -ne 0) { throw 'The original SSH configuration failed validation; no policy changes are permitted.' }
$backup = Join-Path $base ('backups\ssh-setup-recovery-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $backup | Out-Null
$snapshot = Join-Path $backup 'sshd_config.before'
Copy-Item -LiteralPath $source -Destination $snapshot
Get-Acl -LiteralPath $config | Export-Clixml -LiteralPath (Join-Path $backup 'sshd-acl.xml')
$recovery = Join-Path $backup 'restore-ssh.ps1'
@{ Config=$config; Sshd=$sshd; Snapshot=$snapshot; TaskName=$taskName } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'state.json') -Encoding utf8
@'
$ErrorActionPreference = 'Stop'
$state = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'state.json') | ConvertFrom-Json
try {
    [IO.File]::WriteAllBytes($state.Config,[IO.File]::ReadAllBytes($state.Snapshot))
    Set-Acl -LiteralPath $state.Config -AclObject (Import-Clixml (Join-Path $PSScriptRoot 'sshd-acl.xml'))
    & $state.Sshd -t -f $state.Config
    if ($LASTEXITCODE -ne 0) { throw 'Restored SSH configuration did not validate; service was not restarted.' }
    Restart-Service sshd -Force
    if ((Get-Service sshd).Status -ne 'Running') { throw 'SSH did not return to Running after recovery.' }
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $scheduler.GetFolder('\').DeleteTask($state.TaskName,0)
    ('SSH configuration restored at '+[DateTime]::UtcNow.ToString('o')) | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'recovered.txt')
} catch {
    $_ | Out-File -LiteralPath (Join-Path $PSScriptRoot 'recovery-error.log') -Append
    throw
}
'@ | Set-Content -LiteralPath $recovery -Encoding ascii
$deadline = [DateTimeOffset]::Now.AddMinutes($RollbackMinutes)
$definition = $scheduler.NewTask(0)
$definition.RegistrationInfo.Description = 'Restores the pre-setup SSH configuration unless the administrator confirms a fresh login.'
$definition.Principal.UserId = 'S-1-5-18'
$definition.Principal.LogonType = 5
$definition.Principal.RunLevel = 1
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false
$definition.Settings.ExecutionTimeLimit = 'PT5M'
$definition.Settings.RestartCount = 3
$definition.Settings.RestartInterval = 'PT1M'
$trigger = $definition.Triggers.Create(1)
$trigger.StartBoundary = $deadline.ToString("yyyy-MM-dd'T'HH:mm:sszzz",[Globalization.CultureInfo]::InvariantCulture)
$trigger.Enabled = $true
$action = $definition.Actions.Create(0)
$action.Path = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$recovery+'"'
try {
    $task = $root.RegisterTaskDefinition($taskName,$definition,2,'SYSTEM',$null,5,$null)
    $task = $root.GetTask($taskName)
    $delta = [Math]::Abs((([DateTime]$task.NextRunTime)-$deadline.LocalDateTime).TotalSeconds)
    if (-not $task.Enabled -or $task.State -eq 1 -or $task.NextRunTime -le (Get-Date).AddMinutes(1) -or $delta -gt 90) {
        throw 'Task Scheduler did not verify an enabled future SSH recovery timer.'
    }
} catch {
    try { $root.DeleteTask($taskName,0) } catch {}
    throw
}
Write-Host ('Verified SSH setup rollback is active until '+$task.NextRunTime+' local / '+$deadline.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')+' UTC.')
Write-Host ('Original SSH configuration saved at: '+$snapshot)
Write-Host 'Test a fresh SSH login, then use Admin > Setup rollback > Keep setup and stop rollback.'
[pscustomobject]@{ TaskName=$taskName; Deadline=$task.NextRunTime; Snapshot=$snapshot; RecoveryScript=$recovery; Existing=$false }
