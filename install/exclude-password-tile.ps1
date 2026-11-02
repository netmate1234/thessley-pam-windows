<#
  Hide the built-in Windows password sign-in tile and keep the Thessley tile (and PIN) as the
  way in. Refuses to run unless the Thessley provider is registered, and arms a timed rollback.
#>
param([ValidateRange(5, 60)][int]$RollbackMinutes = 20)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$thessleyProvider = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
$passwordProvider = '{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}'
$policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$policyName = 'ExcludedCredentialProviders'
$backupDir = Join-Path $env:ProgramData 'ThessleyPamWin\backups'
$taskName = 'ThessleyPasswordTileRollback'

if (-not (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$thessleyProvider")) {
    throw 'The Thessley sign-in tile is not registered; install it first so the password tile is not the only option.'
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A password-tile rollback is already armed. Confirm or let it expire first.'
}

$previous = (Get-ItemProperty -Path $policyPath -Name $policyName -ErrorAction SilentlyContinue).$policyName
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$statePath = Join-Path $backupDir 'password-tile-before.json'
@{ previous = $previous } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8

$entries = @()
if ($previous) { $entries = @($previous -split ';' | Where-Object { $_ }) }
if ($entries -notcontains $passwordProvider) { $entries += $passwordProvider }
$value = ($entries -join ';')
New-Item -Path $policyPath -Force | Out-Null
Set-ItemProperty -Path $policyPath -Name $policyName -Value $value -Type String

$rb = Join-Path $backupDir 'restore-password-tile.ps1'
$restore = @"
`$ErrorActionPreference = 'Stop'
`$p = '$policyPath'
`$name = '$policyName'
`$json = Get-Content -LiteralPath '$statePath' -Raw | ConvertFrom-Json
if (`$json.previous) { Set-ItemProperty -Path `$p -Name `$name -Value `$json.previous -Type String }
else { Remove-ItemProperty -Path `$p -Name `$name -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'Password sign-in tile restored.'
"@
Set-Content -LiteralPath $rb -Value $restore -Encoding ascii

$action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$rb`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Write-Output 'The Windows password tile is hidden; the Thessley tile and PIN remain.'
Write-Output "ExcludedCredentialProviders = $value"
Write-Output "Lock the screen to test. Keep it with: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
Write-Output "Rollback in $RollbackMinutes minutes restores the password tile automatically."
