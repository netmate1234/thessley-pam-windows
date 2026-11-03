These downloads work with the Thessley Passkey app. The SSH service and HTTPS admin page are companion software for a Windows computer; they are separate from the WordPress plugin itself.

## Downloads

- [Windows SSH + Web GUI package](https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-ssh-webgui.zip) — Windows OpenSSH QR approval service, HTTPS admin page, installer, and setup guides.
- [Desktop approval helper](https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-desktop-approval.zip) — a small Windows app for approving SSH requests and enrolling a phone. Requires the Windows service.
- [Experimental QR sign-in provider](https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/windows-qr-signin-experimental.zip) — changes the Windows sign-in screen. It is experimental; retain the built-in Windows PIN and password choices and follow the included rollback steps.
- [SHA-256 checksums](https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/SHA256SUMS.txt)

The ZIP files are unsigned. Verify a download against the checksum file before extracting it. The experimental credential provider is optional and is not needed for QR-approved SSH or the web admin page.

## Install Windows SSH and Web GUI

### 1. Prepare Windows

Use Windows 11 and an administrator account. Install Python 3.12 or newer for all users under `C:\Program Files`. For example, from an administrator PowerShell:

```powershell
winget install --id Python.Python.3.13 --scope machine
```

Download and extract `windows-ssh-webgui.zip`, for example to `C:\Thessley\Windows-SSH-WebGUI`.

### 2. Install the Thessley service

In an administrator PowerShell, run the installer from the extracted folder. Adjust the Python path if your installed version differs:

```powershell
Set-Location C:\Thessley\Windows-SSH-WebGUI
powershell -ExecutionPolicy Bypass -File .\install\install.ps1 `
  -Python "C:\Program Files\Python313\python.exe" `
  -OpenFirewall -OpenWebFirewall
```

The firewall options allow the shared phone approval and enrollment service (TCP 47810) and the web page (TCP 47820) from `LocalSubnet` on all Windows network profiles by default. The remote source stays restricted to the local subnet, rather than all internet addresses. Pass `-FirewallProfile Private` to restrict the rules to Private profiles. Web and command-line enrollment register concurrent request paths on the service-owned listener; enrollment does not require or open additional ports. The installer does not edit `sshd_config` or restart OpenSSH.

### Install over an existing SSH connection

Install Windows OpenSSH Server and verify an ordinary SSH login before installing Thessley. From a trusted computer, open
an interactive PowerShell session on Windows:

```powershell
ssh -t WINDOWS_ADMIN@WINDOWS_IP powershell.exe -NoProfile
```

Check that the session has an administrator token. Continue only when this prints `True`:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

Then run the guided bootstrap in that session:

```powershell
irm https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/install.ps1 | iex
```

The installer must be able to prompt interactively. If the token check prints `False`, install from Administrator
PowerShell at the Windows console; do not weaken UAC or expose remote-management ports. Enroll the phone and confirm the
pairing codes match before changing SSH policy. For an SSH gate, follow the backup, five-minute automatic rollback,
configuration validation, and second-session verification steps in the package's `docs/SSH.md`. Keep the original SSH
session open until the new login and phone approval both work.

### 3. Enrol the phone and open the web admin page

Run the included `ThessleySignInTest.exe` from the desktop-approval ZIP, select **Enroll this account**, and follow the pairing prompts. Compare the pairing codes in the phone and Windows app before confirming.

Turn on the web page and read its certificate fingerprint:

```powershell
& "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" web on
& "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" web status
```

Open `https://<Windows-computer-IP>:47820/` from the local network and approve the page sign-in on the enrolled phone. The browser warns about the self-signed certificate; compare its fingerprint with `web status` before accepting it. The Admin page can restrict the web page to `127.0.0.1`; remote access then requires an SSH tunnel.

### 4. Configure SSH QR approval

Keep an existing administrator session open while changing SSH settings. Back up `C:\ProgramData\ssh\sshd_config` first. Generate the account-specific configuration block:

```powershell
& "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" sshd-config --user YOURNAME --factor password
```

Choose the first factor deliberately:

- `--factor password`: Windows account password, then phone approval.
- `--factor key`: SSH key, then phone approval.
- `--factor key-password`: SSH key and account password, then phone approval.

Back up `sshd_config`, arm automatic rollback, and add the generated `Match User` block in the correct order for existing
`Match` rules. For an administrator account, ensure its user block is evaluated before the stock `Match Group administrators`
block. Validate before restarting:

```powershell
& "C:\Program Files\OpenSSH\sshd.exe" -t
Restart-Service sshd
```

Test from a second computer while keeping the original session available for recovery. If validation fails, do not restart `sshd`.

## Remove the service

First remove the Thessley `Match User` block from `sshd_config`, validate it with `sshd -t`, and restart `sshd`. Then run `install\uninstall.ps1` as administrator. The uninstall script refuses to remove the gate while `sshd_config` still refers to it.

## Experimental Windows QR sign-in

The optional credential-provider bundle affects the Windows logon screen. It stores a machine-protected copy of the existing account password so it can submit it after phone approval; it does not remove the Windows password or PIN authentication providers. Treat this as a separate integration from QR-approved SSH.

You can stage and install it over an interactive elevated SSH PowerShell session, but QR setup and the real sign-in test must be completed at the Windows sign-in screen, using the local console or Remote Desktop. First ensure the Thessley service is running and the phone is enrolled for the Windows account. If needed, enroll it over SSH with `& "$env:ProgramData\ThessleyPamWin\thessley-pam-win.cmd" enroll --user YOURNAME` and compare the pairing code on the phone and terminal before confirming. Allow TCP 47810 only from the trusted LAN or VPN client subnet if the firewall requires it. Keep the SSH session open and retain the built-in PIN/password tiles.

In the SSH PowerShell, verify the administrator token and download, verify, and extract the package as shown in `docs/WINDOWS-LOGON-PROTOTYPE.md` inside the ZIP. For a first install run `install-with-rollback.ps1 -RollbackMinutes 30`; to update an existing provider run `update-with-rollback.ps1 -RollbackMinutes 30` instead. Do not run both scripts. At the Windows sign-in screen, select the Thessley tile, choose **Set up QR-only sign-in**, approve on the enrolled phone, enter the current Windows password once, and complete sign-in. Test a second QR sign-in. Only then, from the still-open elevated SSH session, run:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\ThessleyPamWin\credential-provider\confirm.ps1"
```

If QR sign-in fails, use the built-in PIN/password choice or leave the automatic rollback timer armed. Phone enrollment and approvals use the normal network connection; installation does not need ADB, USB debugging, or a phone cable.
