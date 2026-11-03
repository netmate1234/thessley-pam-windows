<#
  SYSTEM scheduled update for the Thessley Windows approval service.
  Verifies the published ZIP against the hash embedded in the HTTPS bootstrap,
  then reuses install.ps1's staged activation and rollback. It never edits SSH
  policy or Windows Firewall rules.
#>
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$taskName = 'ThessleyPamWin'
$statePath = Join-Path $base 'update-state.json'
$logDir = Join-Path $base 'logs'
$logPath = Join-Path $logDir 'update.log'
$bootstrapUrl = 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/install.ps1'
$packageUrl = 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-ssh-webgui.zip'
$mutex = $null
$work = $null
$exitCode = 0
$state = @{ version = 1; installed_package_sha256 = ''; last_check_utc = ''; last_success_utc = ''; last_error = '' }

function Write-UpdateLog([string]$Message) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 1048576) {
        Move-Item -LiteralPath $logPath -Destination "$logPath.1" -Force
    }
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K') $Message"
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
}

function Save-UpdateState {
    $temporary = "$statePath.tmp-$PID"
    $json = $state | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($temporary, $json + "`n", [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
}

try {
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The scheduled updater is not running with administrator rights.'
    }

    $mutex = [Threading.Mutex]::new($false, 'Global\ThessleyPamWinUpdate')
    if (-not $mutex.WaitOne(0)) {
        Write-UpdateLog 'Skipped: another Thessley update is already running.'
        return
    }

    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        try {
            $previous = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
            if ($previous -and $previous.installed_package_sha256 -match '^[0-9a-fA-F]{64}$') {
                $state.installed_package_sha256 = $previous.installed_package_sha256.ToLowerInvariant()
            }
            if ($previous.last_success_utc) { $state.last_success_utc = [string]$previous.last_success_utc }
        } catch {
            Write-UpdateLog 'Previous updater status was unreadable; continuing without its installed-package hash.'
        }
    }
    $state.last_check_utc = [DateTime]::UtcNow.ToString('o')
    $state.last_error = ''

    $serviceTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $python = @($serviceTask.Actions | Where-Object { $_.Execute } | Select-Object -ExpandProperty Execute | Select-Object -First 1)[0]
    if (-not $python -or -not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'Could not find the installed machine-wide Python executable in the Thessley service task.'
    }
    if (-not $python.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase) -and
        -not $python.StartsWith(${env:ProgramFiles(x86)}, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The configured service Python is not under Program Files; refusing the automatic update.'
    }
    & $python -c 'import sys; assert sys.version_info >= (3,12)'
    if ($LASTEXITCODE -ne 0) { throw 'The configured service Python is not version 3.12 or newer.' }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $work = Join-Path $base ('update-work-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $bootstrapPath = Join-Path $work 'install.ps1'
    $zipPath = Join-Path $work 'windows-ssh-webgui.zip'

    Write-UpdateLog 'Checking the published Windows package.'
    Invoke-WebRequest -UseBasicParsing -Uri $bootstrapUrl -OutFile $bootstrapPath -TimeoutSec 60
    $bootstrap = [IO.File]::ReadAllText($bootstrapPath)
    $hashMatches = [regex]::Matches($bootstrap, '(?m)^\s*\$expectedHash\s*=\s*''([0-9a-fA-F]{64})''\s*$')
    if ($hashMatches.Count -ne 1) { throw 'The hosted installer did not contain exactly one valid package hash; update refused.' }
    $expectedHash = $hashMatches[0].Groups[1].Value.ToLowerInvariant()

    Invoke-WebRequest -UseBasicParsing -Uri $packageUrl -OutFile $zipPath -TimeoutSec 180
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw 'The downloaded package hash did not match the installer pin; update refused.' }
    if ($state.installed_package_sha256 -eq $actualHash) {
        Write-UpdateLog 'No package change is available; the installed package hash matches.'
        Save-UpdateState
        return
    }

    $expanded = Join-Path $work 'package'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $expanded
    $packageRoot = Join-Path $expanded 'Thessley-Windows-SSH-WebGUI'
    $installer = Join-Path $packageRoot 'install\install.ps1'
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'The verified package did not contain the expected installer.' }

    Write-UpdateLog "Applying verified package $actualHash. New SSH phone approvals may pause briefly during activation."
    & $installer -Python $python -PreserveFirewall

    $healthy = $false
    for ($i = 0; $i -lt 30; $i++) {
        $currentTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($currentTask -and $currentTask.State -eq 'Running') {
            $probe = [Net.Sockets.TcpClient]::new()
            try { $probe.Connect('127.0.0.1', 47800); $healthy = $true; break }
            catch { }
            finally { $probe.Dispose() }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $healthy) { throw 'The updated approval service did not pass its local health check; installer rollback should have restored the previous app.' }

    $state.installed_package_sha256 = $actualHash
    $state.last_success_utc = [DateTime]::UtcNow.ToString('o')
    $state.last_error = ''
    Save-UpdateState
    Write-UpdateLog 'Update completed; the approval service passed its local health check.'
} catch {
    $exitCode = 1
    $message = [string]$_.Exception.Message
    if ($message.Length -gt 240) { $message = $message.Substring(0, 240) }
    $state.last_check_utc = [DateTime]::UtcNow.ToString('o')
    $state.last_error = $message
    try { Save-UpdateState } catch { }
    try { Write-UpdateLog "Update failed: $message" } catch { }
} finally {
    if ($work -and (Test-Path -LiteralPath $work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
    if ($mutex) {
        try { $mutex.ReleaseMutex() } catch { }
        $mutex.Dispose()
    }
}

exit $exitCode
