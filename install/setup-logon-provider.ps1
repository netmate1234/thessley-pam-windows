param([ValidateRange(5, 60)][int]$RollbackMinutes = 30)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}
$bundle = Join-Path (Split-Path -Parent $PSScriptRoot) 'downloads\windows-qr-signin-experimental.zip'
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) { throw "Windows sign-in package is missing: $bundle" }
$work = Join-Path $env:TEMP ('Thessley-Logon-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Expand-Archive -LiteralPath $bundle -DestinationPath $work
    $providerDir = Join-Path $work 'Thessley-QR-Windows-SignIn-Experimental\windows-logon-provider'
    $firstInstall = Join-Path $providerDir 'install-with-rollback.ps1'
    $update = Join-Path $providerDir 'update-with-rollback.ps1'
    if (-not (Test-Path -LiteralPath $firstInstall) -or -not (Test-Path -LiteralPath $update)) {
        throw 'The sign-in package is incomplete; no credential provider changes were made.'
    }
    $task = Get-ScheduledTask -TaskName 'ThessleyCredentialProviderRollback' -ErrorAction SilentlyContinue
    if ($task) { throw 'A sign-in rollback is already active. Do not install the tile again yet. In Thessley Admin > Settings, test the current sign-in, then choose Keep setup and stop rollback; or let the timer finish.' }
    $providerId = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
    $registered = Test-Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerId"
    if ($registered) {
        & $update -RollbackMinutes $RollbackMinutes
        $rollbackTarget = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider\branding-rollback.ps1'
    } else {
        & $firstInstall -RollbackMinutes $RollbackMinutes
        $rollbackTarget = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider\rollback.ps1'
    }

    # The provider package performs its own verification before touching the
    # sign-in files. Check again at the guided-installer boundary so a package
    # regression cannot be reported as a successful setup with no live timer.
    $taskName = 'ThessleyCredentialProviderRollback'
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $taskInfo = $null
    if ($task) { $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue }
    $nextRun = if ($taskInfo) { [DateTime]$taskInfo.NextRunTime } else { [DateTime]::MinValue }
    $hasRollbackAction = $false
    if ($task) {
        $hasRollbackAction = (@($task.Actions | Where-Object {
            $_.Arguments -like '*ThessleyPamWin\credential-provider\*rollback.ps1*'
        }).Count -gt 0)
    }
    if (-not $task -or $task.State -eq 'Disabled' -or -not $hasRollbackAction `
        -or $nextRun -le [DateTime]::Now.AddMinutes(1) `
        -or $nextRun -gt [DateTime]::Now.AddMinutes($RollbackMinutes + 2)) {
        $rollbackSucceeded = $false
        if (Test-Path -LiteralPath $rollbackTarget -PathType Leaf) {
            $powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            & $powerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $rollbackTarget
            $rollbackSucceeded = ($LASTEXITCODE -eq 0)
        }
        if (-not $rollbackSucceeded) {
            throw "The sign-in rollback timer is invalid, and automatic recovery did not complete. Run this recovery script elevated immediately: $rollbackTarget"
        }
        throw 'The sign-in rollback timer was missing, disabled, or not scheduled in the future. The provider was rolled back and setup was stopped.'
    }
    $deadlineLocal = $nextRun.ToString('yyyy-MM-dd HH:mm:ss zzz')
    $deadlineUtc = ([DateTimeOffset]$nextRun).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "Verified Windows sign-in rollback task: $taskName; deadline $deadlineLocal local / $deadlineUtc UTC."
    Write-Host 'Keep the built-in PIN/password tiles available. Test Thessley at the sign-in screen before confirming setup.'
    Write-Host "After all tests succeed, run: powershell -ExecutionPolicy Bypass -File `"$(Join-Path $env:ProgramData 'ThessleyPamWin\confirm-setup.ps1')`""
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
