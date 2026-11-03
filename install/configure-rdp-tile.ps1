<#
  RDP as a tile-first sign-in: NLA off plus "always prompt", so a connection lands on the
  session's Thessley tile. RDP is limited to administrators by clearing Remote Desktop Users
  (members of Administrators can always connect). Timed rollback restores everything
  unless -Keep makes the change permanent (the installer uses -Keep).
#>
param(
    [switch]$Keep,
    [ValidateRange(5, 60)][int]$RollbackMinutes = 20
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$rdpTcp = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$backupDir = Join-Path $env:ProgramData 'ThessleyPamWin\backups'
$taskName = 'ThessleyRdpTileRollback'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
if (-not $Keep -and (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'An RDP rollback is already armed. Confirm or let it expire first.'
}

$users = @()
try {
    $users = @(Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop |
        Select-Object -ExpandProperty Name)
} catch { $users = @() }

$before = @{
    UserAuthentication = (Get-ItemProperty -Path $rdpTcp -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    fPromptForPassword  = (Get-ItemProperty -Path $policy -Name fPromptForPassword -ErrorAction SilentlyContinue).fPromptForPassword
    remoteDesktopUsers  = $users
}
$statePath = Join-Path $backupDir 'rdp-tile-before.json'
$before | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding utf8

Set-ItemProperty -Path $rdpTcp -Name UserAuthentication -Value 0 -Type DWord
New-Item -Path $policy -Force | Out-Null
Set-ItemProperty -Path $policy -Name fPromptForPassword -Value 1 -Type DWord

foreach ($name in $users) {
    try { Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $name -ErrorAction Stop }
    catch { Write-Warning "Could not remove $name from Remote Desktop Users: $($_.Exception.Message)" }
}

Restart-Service TermService -Force
Start-Sleep -Seconds 2

$rb = Join-Path $backupDir 'rollback-rdp-tile.ps1'
$restore = @"
`$ErrorActionPreference = 'Stop'
`$state = Get-Content -LiteralPath '$statePath' -Raw | ConvertFrom-Json
Set-ItemProperty -Path '$rdpTcp' -Name UserAuthentication -Value ([int]`$state.UserAuthentication) -Type DWord
if (`$state.fPromptForPassword) { Set-ItemProperty -Path '$policy' -Name fPromptForPassword -Value ([int]`$state.fPromptForPassword) -Type DWord }
else { Remove-ItemProperty -Path '$policy' -Name fPromptForPassword -ErrorAction SilentlyContinue }
foreach (`$name in @(`$state.remoteDesktopUsers)) {
    if (`$name) { try { Add-LocalGroupMember -Group 'Remote Desktop Users' -Member `$name -ErrorAction Stop } catch { } }
}
Restart-Service TermService -Force
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'RDP settings restored.'
"@
Set-Content -LiteralPath $rb -Value $restore -Encoding ascii
if (-not $Keep) {
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$rb`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

"UserAuthentication = $((Get-ItemProperty -Path $rdpTcp -Name UserAuthentication).UserAuthentication)"
"fPromptForPassword = $((Get-ItemProperty -Path $policy -Name fPromptForPassword).fPromptForPassword)"
"Remote Desktop Users: $((Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue | Measure-Object).Count) member(s); administrators keep access"
if ($Keep) {
    "Settings kept permanently. Previous values saved in $statePath (rollback script $rb)."
} else {
    "Rollback in $RollbackMinutes minutes (task $taskName)."
}
