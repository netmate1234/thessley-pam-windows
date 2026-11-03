# Small bootstrap downloaded by the Windows installation page.
# The package checksum is injected by scripts/build_downloads.py.
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator, then run the short install command again.'
}

$packageUrl = 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-ssh-webgui.zip'
$expectedHash = 'ce9e93fdeb3955547a49a8957bd205be90f31d7e2fc28d73744990d9ed25293f'
$work = Join-Path $env:TEMP ('Thessley-Install-' + [guid]::NewGuid().ToString('N'))
$zip = "$work.zip"

try {
    Write-Host 'Downloading the Windows package...'
    Invoke-WebRequest -UseBasicParsing -Uri $packageUrl -OutFile $zip
    Write-Host 'Checking the package SHA-256 before extraction...'
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw 'The downloaded package checksum did not match. Nothing was installed.'
    }
    Write-Host 'Checksum verified. Extracting the installer...'
    Expand-Archive -LiteralPath $zip -DestinationPath $work
    # The bootstrap is commonly piped to iex, but the guided installer is a .ps1 file.
    # Let this PowerShell process run that verified local script even when the user's
    # machine default is Restricted. This does not change the machine or user policy.
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Write-Host 'Starting the verified guided installer...'
    & (Join-Path $work 'Thessley-Windows-SSH-WebGUI/guided-install.ps1')
}
finally {
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
