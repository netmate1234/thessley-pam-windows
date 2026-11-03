# QR-only Windows sign-in design

The experimental credential provider now has a QR-only sign-in flow after setup for local and Microsoft accounts. Thessley phone approval gates use of a machine-protected copy of the user's existing Windows password. The provider submits that password through the account's existing Windows credential serialization path. Setup requires entering the current Windows password once, and a password change requires updating the saved value.

This design removes repeated password entry from the Thessley tile; it does not make the Windows account password unrecoverable or remove Windows password authentication. The built-in Windows PIN and password tiles remain available for recovery. DPAPI machine protection and the install directory ACL protect the vault from ordinary users, but local administrators and SYSTEM retain machine-level access.

The vault implementation is in `windows-logon-provider/password_vault.cpp`; the provider only loads it after the phone approval has succeeded. The installer protects the provider directory for SYSTEM and Administrators. `ReportResult` saves a newly entered password only after Windows reports successful authentication. It never writes the password to diagnostics.

## Install and test over SSH

The provider can be staged and registered from an elevated SSH PowerShell session, but it cannot be fully tested from
the SSH shell: first-time setup and QR sign-in are interactive Windows sign-in-screen flows. Keep an existing SSH session
open as a recovery path, retain the normal Windows PIN/password tiles, and have local console or Remote Desktop access
available before beginning. The SSH QR gate and this Windows logon provider are separate integrations; install and test
the Thessley service and phone enrollment first. If the target account has no phone enrolled, enroll it from the elevated
PowerShell session and compare the pairing code on the phone and terminal before confirming:

```powershell
& "$env:ProgramData\ThessleyPamWin\thessley-pam-win.cmd" enroll --user YOURNAME
```

Allow TCP 47810 only from the trusted LAN or VPN client subnet when the firewall needs an enrollment rule; see
`docs/SSH.md` for the scoped rule and details.

Connect with an interactive PowerShell session and verify its administrator token:

```powershell
ssh -t WINDOWS_ADMIN@WINDOWS_IP powershell.exe -NoProfile
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

Continue only if the result is `True`. Download and extract the experimental package on the Windows PC, then verify its
SHA-256 against the published `SHA256SUMS.txt` before running anything:

```powershell
$zip = Join-Path $env:TEMP 'windows-qr-signin-experimental.zip'
$sums = Join-Path $env:TEMP 'thessley-windows-SHA256SUMS.txt'
Invoke-WebRequest 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-qr-signin-experimental.zip' -OutFile $zip
Invoke-WebRequest 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/SHA256SUMS.txt' -OutFile $sums
$expected = ((Get-Content $sums | Where-Object { $_ -match 'windows-qr-signin-experimental\.zip$' }) -split '\s+')[0]
if (-not $expected -or (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw 'Package checksum mismatch; stop without extracting or installing.' }
$package = Join-Path $env:TEMP 'Thessley-QR-Windows-SignIn-Experimental'
Expand-Archive -LiteralPath $zip -DestinationPath $package -Force
Set-Location (Join-Path $package 'Thessley-QR-Windows-SignIn-Experimental\windows-logon-provider')
```

For a **first install**, use the install script. For an **existing provider**, use the update script so the previous DLL and
QR viewer can be restored. Set a longer rollback window for a remote test; the scripts allow 5–60 minutes:

```powershell
# First install only
.\install-with-rollback.ps1 -RollbackMinutes 30

# Existing provider update only; use this instead of the first-install command above
# .\update-with-rollback.ps1 -RollbackMinutes 30
```

The first-install rollback removes only Thessley's credential-provider registration; the update rollback restores the
previous provider files. Neither script disables Windows PIN/password sign-in. Do not install over a pending rollback
task; resolve that timer first.

Now use the Windows console or Remote Desktop to reach the sign-in screen. Select the Thessley tile, choose **Set up
QR-only sign-in**, approve the request on the enrolled phone, enter the account's current Windows password once, and
complete sign-in. Then verify a second Thessley QR sign-in. If either attempt fails, use the built-in PIN/password tile
or let the rollback timer expire. Only after a real QR sign-in succeeds, return to the still-open elevated SSH session
and confirm the install before the deadline:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\ThessleyPamWin\credential-provider\confirm.ps1"
```

Phone enrollment and approval use the normal network connection between Windows and the phone. No Android Debug Bridge
(ADB), USB debugging, or phone-to-PC cable is part of installation or enrollment.

The custom LSA authentication-package route remains a separate, unimplemented option. It could avoid storing a recoverable Windows password, but would require a much more complex authentication package and stronger recovery planning. Do not register an experimental LSA package on the everyday PC.

Token2's [fido-local-logon proof of concept](https://github.com/token2/fido-local-logon) informed the credential-provider vault approach. It is an unaudited GPL-2.0 project; its code was not copied here.
