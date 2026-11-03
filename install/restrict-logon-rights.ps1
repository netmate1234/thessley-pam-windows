<#
  Limit who may sign in at this PC: interactive logon for Administrators (plus one optional
  group), Remote Desktop for Administrators only. Writes the rights with secedit, verifies the
  result, and arms a timed rollback that restores the previous rights.
#>
param(
    [string]$InteractiveGroup = '',
    [ValidateRange(5, 60)][int]$RollbackMinutes = 20
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$backupDir = Join-Path $env:ProgramData 'ThessleyPamWin\backups'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$taskName = 'ThessleyLogonRightsRollback'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'A logon-rights rollback is already armed. Confirm or let it expire first.'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$before = Join-Path $backupDir "user-rights-before.$stamp.inf"
& secedit /export /cfg $before /areas USER_RIGHTS | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $before)) {
    throw 'Could not export the current user rights.'
}

$adminsSid = 'S-1-5-32-544'
$interactive = @("*$adminsSid")
$groupSid = $null
if ($InteractiveGroup) {
    try {
        $groupSid = (New-Object System.Security.Principal.NTAccount($InteractiveGroup)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Could not resolve the group '$InteractiveGroup'. Use a local or domain group name."
    }
    $interactive += "*$groupSid"
}

$text = Get-Content -LiteralPath $before -Raw
$text = [regex]::Replace($text, '(?im)^SeInteractiveLogonRight\s*=.*$', 'SeInteractiveLogonRight = ' + ($interactive -join ','))
$text = [regex]::Replace($text, '(?im)^SeRemoteInteractiveLogonRight\s*=.*$', 'SeRemoteInteractiveLogonRight = *' + $adminsSid)
$text = [regex]::Replace($text, '(?im)^SeDenyInteractiveLogonRight\s*=.*$', '')
$text = [regex]::Replace($text, '(?im)^SeDenyRemoteInteractiveLogonRight\s*=.*$', '')
$after = Join-Path $backupDir "user-rights-after.$stamp.inf"
Set-Content -LiteralPath $after -Value $text -Encoding unicode

$db = Join-Path $env:TEMP "thessley-rights-$stamp.sdb"
& secedit /configure /db $db /cfg $after /areas USER_RIGHTS /quiet | Out-Null
if ($LASTEXITCODE -ne 0) {
    Copy-Item -LiteralPath $before -Destination $after -Force
    throw 'secedit rejected the change; the previous rights file is intact.'
}

$check = Join-Path $env:TEMP "thessley-rights-check-$stamp.inf"
& secedit /export /cfg $check /areas USER_RIGHTS | Out-Null
$verified = Select-String -LiteralPath $check -Pattern '^SeInteractiveLogonRight' | ForEach-Object { $_.Line }
if ($verified -notmatch [regex]::Escape($adminsSid)) {
    & secedit /configure /db $db /cfg $before /areas USER_RIGHTS /quiet | Out-Null
    throw 'Verification failed (Administrators missing); the previous rights were restored.'
}

$rb = Join-Path $backupDir 'rollback-logon-rights.ps1'
$body = @"
`$ErrorActionPreference = 'Stop'
& secedit /configure /db `"`$env:TEMP\thessley-rights-restore.sdb`" /cfg '$before' /areas USER_RIGHTS /quiet | Out-Null
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
Write-Output 'Logon rights restored.'
"@
Set-Content -LiteralPath $rb -Value $body -Encoding ascii
$action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$rb`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Write-Output "Interactive logon: Administrators$([string]::Concat($(if ($groupSid) { " + $InteractiveGroup ($groupSid)" } else { '' })))"
Write-Output 'Remote Desktop: Administrators only'
Write-Output "Rollback in $RollbackMinutes minutes (task $taskName)."
