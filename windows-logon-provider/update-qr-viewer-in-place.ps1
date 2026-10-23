$ErrorActionPreference = 'Stop'
$source = Join-Path $env:USERPROFILE 'qr-startup-update\build\ThessleyQrViewer.exe'
$target = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider\ThessleyQrViewer.exe'
$rollbackTask = Get-ScheduledTask -TaskName 'ThessleyCredentialProviderRollback' -ErrorAction Stop
$state = Join-Path $env:ProgramData 'ThessleyPamWin\credential-provider\qr-startup-rollback.json'
if (-not (Test-Path -LiteralPath $state -PathType Leaf)) {
    throw 'The automatic rollback state is missing; refusing to replace the QR viewer.'
}
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Viewer build not found: $source" }
if (Get-Process -Name 'ThessleyQrViewer' -ErrorAction SilentlyContinue) {
    Stop-Process -Name 'ThessleyQrViewer' -Force
    Start-Sleep -Milliseconds 500
}
Copy-Item -LiteralPath $source -Destination $target -Force
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
Write-Host "Corrected QR viewer installed ($hash). The existing startup rollback remains active."
