$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}
# Thessley registers setup recovery tasks in the scheduler root. Query that
# folder directly instead of loading the ScheduledTasks module and walking
# every Microsoft task, which can exceed the web request timeout on a VM.
$scheduler = New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
$root = $scheduler.GetFolder('\')
$tasks = @($root.GetTasks(0) | Where-Object {
    $_.Name -eq 'ThessleyCredentialProviderRollback' -or $_.Name -match '^ThessleySSHConfigRollback-[A-Za-z0-9_.-]{1,64}$'
})
if (-not $tasks.Count) {
    Write-Host 'No pending Thessley setup rollback timers were found.'
    exit 0
}
foreach ($task in $tasks) {
    if ($task.State -eq 4) { throw "Rollback has already started ($($task.Name)); it cannot be confirmed now." }
    $task.Enabled = $false
    $root.DeleteTask($task.Name, 0)
    Write-Host "Confirmed and retained: $($task.Name)"
}
$remaining = @($root.GetTasks(0) | Where-Object {
    $_.Name -eq 'ThessleyCredentialProviderRollback' -or $_.Name -match '^ThessleySSHConfigRollback-[A-Za-z0-9_.-]{1,64}$'
})
if ($remaining.Count) { throw 'A Thessley rollback task remains; setup was not fully confirmed.' }
Write-Host 'Setup rollback timers cancelled. Keep the Windows PIN/password recovery options available.'
