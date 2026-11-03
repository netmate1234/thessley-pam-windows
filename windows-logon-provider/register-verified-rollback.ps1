param(
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$RollbackFile,
    [Parameter(Mandatory = $true)][ValidateRange(5, 60)][int]$RollbackMinutes,
    [string]$ArgumentsSuffix = ''
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $RollbackFile -PathType Leaf)) {
    throw "Rollback script is missing: $RollbackFile"
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw "A rollback timer already exists ($TaskName). Resolve it before continuing."
}

# Use Task Scheduler's local-time trigger directly. Do not replace StartBoundary
# with a hand-built UTC string: a once trigger created with -At is already
# timezone/DST aware, while a literal Z can be interpreted differently by the
# ScheduledTasks provider and leave the task outside the intended 5-60 minute window.
$deadline = [DateTime]::Now.AddMinutes($RollbackMinutes)
$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$RollbackFile`" $ArgumentsSuffix".Trim()
$action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Once -At $deadline
$runAsSystem = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $runAsSystem -Settings $settings `
        -Description 'Restores the previous Thessley Windows sign-in configuration unless an administrator confirms it.' `
        -ErrorAction Stop | Out-Null

    # Registration can return without a usable future trigger (for example, if
    # Task Scheduler normalizes a boundary unexpectedly). Read it back and fail
    # closed before the caller changes the sign-in provider or its files.
    $verified = $false
    $lastError = 'Task Scheduler did not report a future run time.'
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
            $nextRun = [DateTime]$info.NextRunTime
            # Get-ScheduledTask can return a localized account label (for
            # example, "Système" on French Windows). Verify the canonical SID
            # from the task XML, then fall back to translating the display name.
            $principalIds = @([string]$task.Principal.UserId)
            try {
                $taskXml = [xml](Export-ScheduledTask -TaskName $TaskName -ErrorAction Stop)
                $principalIds += [string]$taskXml.Task.Principals.Principal.UserId
            } catch { }
            $systemPrincipal = $false
            foreach ($principalId in $principalIds) {
                if ($principalId -eq 'S-1-5-18') {
                    $systemPrincipal = $true
                    break
                }
                try {
                    $principalSid = ([Security.Principal.NTAccount]::new($principalId)).Translate(
                        [Security.Principal.SecurityIdentifier]).Value
                    if ($principalSid -eq 'S-1-5-18') {
                        $systemPrincipal = $true
                        break
                    }
                } catch { }
            }
            $taskAction = @($task.Actions | Where-Object {
                $_.Execute -ieq $powerShell -and $_.Arguments -like "*`"$RollbackFile`"*"
            })
            $enabled = ($task.State -ne 'Disabled') -and ($task.Settings.Enabled -ne $false)
            $boundaryDeltaSeconds = [Math]::Abs(($nextRun - $deadline).TotalSeconds)
            if ($enabled -and $systemPrincipal -and $taskAction.Count -gt 0 `
                -and $nextRun -gt [DateTime]::Now.AddMinutes(1) `
                -and $boundaryDeltaSeconds -le 90) {
                $verified = $true
                break
            }
            $lastError = "Rollback task verification failed (state=$($task.State), principal=$($task.Principal.UserId), next run=$nextRun)."
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $verified) {
        throw "The rollback timer could not be verified. No Windows sign-in changes were applied. $lastError"
    }
} catch {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}

[pscustomobject]@{
    DeadlineLocal = $deadline
    DeadlineUtc = ([DateTimeOffset]$deadline).ToUniversalTime().UtcDateTime
}
