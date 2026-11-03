<#
  Hot-patches ad_ssh_gate.py and daemon.py into the installed Thessley app (scp/SFTP pass support) and restarts the
  service. Run in an elevated PowerShell with both files in the current user's profile folder. Backs up the two files
  first and restores them if the import check or the restart fails. The scheduled updater overwrites this patch once a
  published package with the same change is installed.
#>
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:ProgramData 'ThessleyPamWin'
$root = Join-Path $base 'app'
$app = Join-Path $root 'thessley_pam_win'
$task = 'ThessleyPamWin'
$files = 'ad_ssh_gate.py', 'daemon.py'

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Not elevated: run as an administrator.' }
if (-not (Test-Path -LiteralPath $app -PathType Container)) { throw "Thessley is not installed at $app." }
foreach ($f in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $env:USERPROFILE $f) -PathType Leaf)) { throw "$f is missing from $env:USERPROFILE." }
}
$launcher = [IO.File]::ReadAllText((Join-Path $base 'ad-ssh-gate.cmd'))
$m = [regex]::Match($launcher, '"([^"\r\n]+python\.exe)"', 'IgnoreCase')
if (-not $m.Success) { throw 'Could not find the Python used by ad-ssh-gate.cmd.' }
$python = $m.Groups[1].Value

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path (Join-Path $base 'backups') "scp-sftp-pass-$stamp"
New-Item -ItemType Directory -Force $backup | Out-Null
foreach ($f in $files) { Copy-Item -LiteralPath (Join-Path $app $f) -Destination $backup -Force }
Write-Host "Backup: $backup"

function Restore-Backup {
    foreach ($f in $files) { Copy-Item -LiteralPath (Join-Path $backup $f) -Destination (Join-Path $app $f) -Force }
    Start-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
}

try {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    foreach ($f in $files) { Copy-Item -LiteralPath (Join-Path $env:USERPROFILE $f) -Destination (Join-Path $app $f) -Force }
    $env:THESSLEY_ROOT = $root
    & $python -I -c "import os,sys; r=os.environ['THESSLEY_ROOT']; sys.path.insert(0,os.path.join(r,'vendor')); sys.path.insert(0,r); import thessley_pam_win.daemon, thessley_pam_win.ad_ssh_gate as g; assert g.is_sftp_command('sftp-server.exe') and g.is_scp_command('scp -t x')"
    if ($LASTEXITCODE -ne 0) { throw 'Import check of the new files failed.' }
    Start-ScheduledTask -TaskName $task
    $up = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        if (Get-NetTCPConnection -LocalPort 47800 -State Listen -ErrorAction SilentlyContinue) { $up = $true; break }
    }
    if (-not $up) { throw 'The approval service is not listening on 127.0.0.1:47800 after the restart.' }
} catch {
    Write-Host "FAILED: $($_.Exception.Message) - restoring the backup."
    Restore-Backup
    exit 1
}

Write-Host 'Deployed; service is listening.'
& (Join-Path $base 'thessley-pam-win.cmd') grace
Get-Content -LiteralPath (Join-Path $env:ProgramData 'ssh\sshd_config') | Select-String -Pattern '^\s*Subsystem' | ForEach-Object { Write-Host $_.Line }
