$ErrorActionPreference = 'Stop'
$taskName = 'ThessleyCredentialProviderRollback'
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Host 'No pending Thessley rollback timer was found.'
    exit 0
}
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Write-Host 'Rollback timer cancelled. The Thessley unlock tile remains registered; Windows PIN and password tiles remain available.'
