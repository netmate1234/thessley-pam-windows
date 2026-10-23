$ErrorActionPreference = 'Stop'
$source = Join-Path $env:USERPROFILE 'qr-startup-update\web.py'
$target = Join-Path $env:ProgramData 'ThessleyPamWin\app\thessley_pam_win\web.py'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Updated web module not found: $source" }
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Installed web module not found: $target" }
$backup = "$target.bak-dhcp-startup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $target -Destination $backup
try {
    Copy-Item -LiteralPath $source -Destination $target -Force
} catch {
    Copy-Item -LiteralPath $backup -Destination $target -Force
    throw
}
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
Write-Host "Installed DHCP-aware web startup ($hash). Existing running page was not restarted. Backup: $backup"
