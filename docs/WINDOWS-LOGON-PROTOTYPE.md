# Windows sign-in prototype

The first prototype step is a regular Windows desktop app that requests the same one-time phone approval planned for a future unlock tile. It shows the QR code and approval result, but does not submit a Windows credential, register a Credential Provider, or change login policy. The built-in Windows PIN and password choices are not affected.

## Desktop test app

`windows-logon-test/ThessleySignInTest.exe` connects to the local Thessley service at `127.0.0.1:47800`. Run it as the Windows account being tested. The service checks the connecting process token against the requested account, uses the existing signed `login` approval type, and neither consumes nor creates an SSH grace pass. Closing or cancelling the app drops the pending request.

The app also has an **Enroll this account** action. It can add the first approver for its current Windows account when self-enrollment is enabled. The person scans the enrollment QR, compares the pairing code shown by the phone with the code shown in the app, and confirms the match in the app. An existing account with approvers still needs its current approver to approve adding another device.

Build the portable app on Ubuntu with MinGW-w64:

```sh
windows-logon-test/build.sh
```

The executable is written to `windows-logon-test/build/ThessleySignInTest.exe`. The app needs the Thessley service already running and an active enrolled phone. Copying or running this app does not register a Windows sign-in component.

## Experimental credential provider with QR-only sign-in after setup

### Opt-in Drupal approval server prototype

The Windows service can now use the separate Thessley Windows Access Drupal
module as the phone-approval server for one local Windows account. Accounts
without this per-account agent configuration keep using the existing local
approval service. To prepare the account, open an elevated PowerShell and run:

```powershell
& 'C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd' drupal-setup --user sshuser --server 'https://192.168.1.200:10443' --tls-sha256 'PASTE_THE_64_CHARACTER_FINGERPRINT_FROM_DRUPAL_SETTINGS'
```

The command creates a software ECDSA P-256 key and prints the machine ID,
computer name, account SID hash, public key, and server details. Enter those
values in **Drupal Admin → Thessley Windows Access → Enroll Windows account**,
link the binding to the intended Drupal user, grant that Drupal role only
**Windows sign-in** on the test computer, and scan the resulting enrollment
QR with the phone. The phone receives the account in **Computers**. The
machine and phone must be able to reach the HTTPS origin in the generated
link. The exact leaf-certificate SHA-256 fingerprint is pinned before
Windows sends any signed request, and HTTP redirects are refused. Update the
pin deliberately whenever the server certificate is renewed.

After enrollment, the next use of the Thessley lock-screen tile obtains its
phone request from Drupal, shows the Drupal PAM link as a QR, and polls the
signed status endpoint. A revoked phone or removed Drupal grant denies the
attempt. Other accounts continue to use the existing local approval flow.
This prototype key is protected by SYSTEM/Administrators ACLs, but is not
TPM-backed. It still gates the existing saved-password credential provider;
it does not make Windows sign-in passwordless. Keep PIN/password recovery
available and test on a disposable VM first. Do not use `--rotate`: key
rotation must also update the Drupal account binding, and this prototype
refuses to replace an existing key.

`windows-logon-provider` contains an experimental Credential Provider based on Microsoft's V2 sample. It supports workstation unlock (`CPUS_UNLOCK_WORKSTATION`) and interactive logon (`CPUS_LOGON`). It calls the service's `windows-logon` operation, which is accepted only from SYSTEM. First select **Set up QR-only sign-in**, approve the phone request, enter the account's current Windows password, and submit. The provider writes that password to a DPAPI machine-protected file only after Windows reports a successful sign-in. Later Thessley tile sign-ins request phone approval and submit the saved password without showing a password field. Password changes require the **Update saved QR sign-in** flow. If the stored password is rejected, the tile reveals that update flow. This vault is keyed by the Windows account SID and supports both local and Microsoft accounts through their existing credential serialization paths. The built-in Windows PIN and password providers remain separate recovery choices.

This is a credential-provider password vault, not passwordless Windows authentication: the Windows password is reversibly encrypted at rest and supplied to the regular Windows authentication package after approval. The vault is scoped to the account SID and stored under the installer-protected `C:\ProgramData\ThessleyPamWin\credential-provider` directory. Local administrators and SYSTEM can access machine-protected data, as they can administer the machine.

Build the x64 DLL on Ubuntu with MinGW-w64 using `windows-logon-provider/build.sh`. The output is `windows-logon-provider/build/ThessleyCredentialProvider.dll`.

The provider build also compiles `windows-logon-test/ThessleySignInTest.cpp` as
`windows-logon-provider/build/ThessleyQrViewer.exe`. The secure sign-in desktop uses this separate
native window to render the QR code. The viewer can be resized or maximized; it redraws from the
complete QR matrix at each new size, maps every module edge into the available square, and rejects
incomplete or malformed matrices instead of displaying a partial symbol. The status header is white,
with the logo and status text laid out separately so they do not overlap. The logo uses the
alpha-enabled Thessley icon resource, allowing its transparent corners to show the white header.
These changes affect only the viewer UI, not provider registration, saved credentials, account policy,
or PIN/password recovery tiles.

`install-with-rollback.ps1` is for a first install: it registers the Thessley provider and schedules `rollback.ps1` to remove only its registration after ten minutes by default. For an existing install, use `update-with-rollback.ps1`; it keeps the current provider DLL and QR viewer, schedules their restoration, and then switches to the new version. If correcting the files while that timer is already active, `refresh-existing-rollback.ps1` updates the files and leaves the current rollback untouched. After reaching the desktop and confirming QR sign-in, an administrator can run the installed `confirm.ps1` to cancel the timer. The built-in Windows PIN and password providers remain separate recovery choices. The provider writes lifecycle and enumeration results to `C:\ProgramData\ThessleyPamWin\credential-provider\provider.log`; it does not log usernames, passwords, QR payloads, or approval data. Do not cancel a rollback timer until a real sign-in has succeeded.

### Wake-from-sleep behavior and LogonUI crashes

After the computer wakes, Windows may show the sign-in screen before the selected phone-network adapter has re-associated or received its IPv4 address. The Thessley tile now shows a waiting message and waits up to three minutes for that adapter before starting the normal phone-approval window. This network wait is separate from the phone approval timeout. The phone listener binds on local IPv4 interfaces so a brief network reconnect does not leave its socket attached to a stale adapter state; Windows Firewall source scopes continue to control which networks can reach it.

If Event Viewer reports `LogonUI.exe` failing in `ThessleyCredentialProvider-*.dll` with exception `0x40000015` (`STATUS_FATAL_APP_EXIT`), check the timestamp against `provider.log`. A credential worker previously could release its final COM reference on its own still-joinable `std::thread`, causing `std::terminate` and taking down LogonUI. The fixed provider transfers that release to a Windows worker-pool thread and records `ApprovalWorkerFinished`; a pool-queue failure is logged instead of crashing the sign-in process.

To update only the QR viewer on an existing installation, rebuild it with
`windows-logon-test/build.sh`. This produces both the desktop test app and
`windows-logon-test/build/ThessleyQrViewer.exe`. From elevated PowerShell, run
`windows-logon-test/update-qr-viewer.ps1`; it saves a timestamped copy of the installed viewer before
replacing it and restores the backup if copying the new executable fails. Keep the existing rollback
task and PIN/password recovery methods in place while updating.

### Remote installation over SSH

You can download, verify, extract, and run the provider installer through an interactive elevated SSH PowerShell session.
First install the Thessley Windows service, start it, enroll the target Windows account's phone, and verify phone approval
works. The Windows logon provider is separate from the SSH gate. If the phone is not enrolled for the target Windows
account, enroll it from the elevated PowerShell session and compare the pairing code on both screens before confirming:

```powershell
& "$env:ProgramData\ThessleyPamWin\thessley-pam-win.cmd" enroll --user YOURNAME
```

Allow the approval/enrollment port range from the trusted LAN or VPN client subnet as described in `docs/SSH.md`. Keep
the SSH session open, retain the Windows PIN and password tiles, and make sure you can reach the Windows sign-in screen
locally or through Remote Desktop. An SSH shell cannot display or complete the interactive first-time QR sign-in for you.

Connect with a PTY, then check that the session has an administrator token. Continue only if this prints `True`:

```powershell
ssh -t WINDOWS_ADMIN@WINDOWS_IP powershell.exe -NoProfile
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

Download the experimental ZIP and checksum file on Windows, verify the hash, and extract the package:

```powershell
$zip = Join-Path $env:TEMP 'windows-qr-signin-experimental.zip'
$sums = Join-Path $env:TEMP 'thessley-windows-SHA256SUMS.txt'
Invoke-WebRequest 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-qr-signin-experimental.zip' -OutFile $zip
Invoke-WebRequest 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/SHA256SUMS.txt' -OutFile $sums
$expected = ((Get-Content $sums | Where-Object { $_ -match 'windows-qr-signin-experimental\.zip$' }) -split '\s+')[0]
if (-not $expected -or (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw 'Package checksum mismatch; stop without installing.' }
$package = Join-Path $env:TEMP 'Thessley-QR-Windows-SignIn-Experimental'
Expand-Archive -LiteralPath $zip -DestinationPath $package -Force
Set-Location (Join-Path $package 'Thessley-QR-Windows-SignIn-Experimental\windows-logon-provider')
```

For a first-time installation, run `install-with-rollback.ps1`. For an already registered provider, use
`update-with-rollback.ps1` instead. A longer timer gives time to reach the sign-in screen and test; the scripts accept
5–60 minutes:

```powershell
# First install
.\install-with-rollback.ps1 -RollbackMinutes 30

# Update an existing provider instead (do not run both commands)
# .\update-with-rollback.ps1 -RollbackMinutes 30
```

At the Windows sign-in screen, use the Thessley tile, select **Set up QR-only sign-in**, approve on the enrolled phone,
enter the current Windows password once, and complete sign-in. Test the QR tile a second time. If it fails, use the
built-in PIN/password tile or leave rollback armed. After a successful QR sign-in, return to the still-open elevated SSH
PowerShell and run:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\ThessleyPamWin\credential-provider\confirm.ps1"
```

Do not confirm before a real sign-in. If the test fails, do not cancel rollback; its first-install action removes the
Thessley provider registration, while its update action restores the previous provider files. Phone enrollment and
approvals happen over the normal network. No ADB, USB debugging, or cable is required.

### If the Thessley tile is missing

The QR viewer (`ThessleyQrViewer.exe`) only draws the QR window. Installing or replacing that executable by itself
does not create a Windows sign-in tile. The tile is provided by `ThessleyCredentialProvider.dll`, which the
rollback-protected installer registers in the 64-bit Windows Credential Provider registry. If the tile is absent,
check whether the rollback timer ran before the installation was confirmed. From elevated PowerShell:

```powershell
Get-ScheduledTask -TaskName ThessleyCredentialProviderRollback -ErrorAction SilentlyContinue |
  Select-Object TaskName,State
Test-Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{B78189D3-4FE6-4E6B-A143-D63D6436E96B}'
Test-Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{B78189D3-4FE6-4E6B-A143-D63D6436E96B}\InprocServer32'
```

If both registry checks return `False`, the provider is not registered. Use `install-with-rollback.ps1` for a first
install, or `update-with-rollback.ps1` only when a provider is already registered. Keep PIN and password recovery
available, test QR sign-in, and confirm the rollback only after sign-in succeeds. If the rollback task is still
present, understand its pending action before starting another install. Phone enrollment is needed to complete QR
sign-in setup, but it does not control whether the tile appears.

The Thessley sign-in-method tile uses an isolated shield-and-key mark on a pure-white field, without the blue rounded-square app tile or gray corners. The QR viewer separately remembers its most recently resized window dimensions in `HKLM\SOFTWARE\ThessleyPamWin\QrViewer` and clamps them to the current display work area when it opens.
