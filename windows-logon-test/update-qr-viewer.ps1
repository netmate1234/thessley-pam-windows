$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'build\ThessleyQrViewer.exe'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider'
$target = Join-Path $installDir 'ThessleyQrViewer.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "QR viewer build not found: $source" }
if (Get-Process -Name 'ThessleyQrViewer' -ErrorAction SilentlyContinue) {
    throw 'Close the QR viewer before updating it.'
}

$backup = Join-Path $installDir ("ThessleyQrViewer.exe.bak-top-left-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
Copy-Item -LiteralPath $target -Destination $backup
try {
    Copy-Item -LiteralPath $source -Destination $target -Force
} catch {
    Copy-Item -LiteralPath $backup -Destination $target -Force
    throw
}
Write-Host "Updated the Thessley QR viewer. Previous executable saved at $backup"
