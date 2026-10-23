$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}
$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -eq 'ThessleyCredentialProviderRollback' -or $_.TaskName -like 'ThessleySSHConfigRollback-*'
})
if (-not $tasks.Count) {
    Write-Host 'No pending Thessley setup rollback timers were found.'
    exit 0
}
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
    Write-Host "Confirmed and retained: $($task.TaskName)"
}
Write-Host 'Setup rollback timers cancelled. Keep the Windows PIN/password recovery options available.'
