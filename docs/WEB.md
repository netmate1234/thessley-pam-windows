# The admin web page (Windows)

Sign in with your account name and an approval (the Thessley Passkey phone app or desktop app), then manage your
approvers in a browser. It is the Windows counterpart of the page in thessley-pam-linux (`docs/WEB.md` there) and works the
same way. There are no passwords.

## What to do on the Windows computer

The **Admin > Setup rollback** card lists pending SSH setup and Windows sign-in recovery timers separately. Guided setup
arms and verifies a 30-minute SSH recovery timer before enabling QR access. Installing the optional Windows sign-in tile
creates its own timer later. After testing every enabled login method, choose **Keep setup and stop rollback** and approve
the fresh request on your phone. The page verifies that the tasks were removed. Until then, SSH recovery restores the
pre-setup configuration at its deadline; enrollment keys remain installed. No pending timer is expected before login
changes start or after you confirm the setup.

Do these in an **administrator PowerShell**, in the repository folder, after pulling the latest version
(`git pull`). The page is a second scheduled task next to the approval service; it stays **off** until you switch it on.

1. **Update the program and create the page's task** (use the Python you installed with last time):

       powershell -ExecutionPolicy Bypass -File install\install.ps1 -Python "C:\Program Files\Python313\python.exe" -OpenFirewall -OpenWebFirewall

   `-OpenWebFirewall` allows TCP 47820 from the local subnet on all Windows profiles by default. For a cloud host,
   `-CloudAccess` changes requested Thessley listener rules to any remote IP; `-OpenSshFirewall` separately opens SSH
   port 22 from any IP. The guided installer asks before enabling each port and keeps remote web access (47820) opt-in.
   Cloud-provider security-group rules still need to allow the selected ports. Pass `-FirewallProfile Private` to
   restrict the Thessley rules to Private networks. An upgrade keeps the page on if it was already on.

2. **Switch the page on** and read its address and certificate fingerprint:

       & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" web on
       & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" web status

3. **Open the address** (for example `https://192.168.1.190:47820/`) from a computer on the same network. The browser warns
   about the certificate once, because the page made its own: compare the fingerprint it shows with the one `web status`
   printed, then accept. For a certificate your browsers already trust:
   `thessley-pam-win web cert CERT.pem KEY.pem`.

4. **Sign in:** type your account name (the Windows account, for example `sshuser`). The page shows a QR code and a text link:
   approve it on the phone ("Approve admin page sign-in"), or on a computer with
   `thessley-passkey respond 'LINK' --approve`, or paste the link into the desktop app. The account needs at least one
   approver enrolled (`thessley-pam-win enroll`).

### First phone setup without an enrolled approver

The guided installer enables the web page before it configures optional QR SSH or the Windows sign-in tile. If the current
administrator has no device yet, it can issue a one-time first-phone setup link:

    & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" web bootstrap --user martin

The guided installer shows the ordinary Admin page address once. For first-phone setup it then prints a separate enrollment
URL in the form `https://WINDOWS-IP:47820/TOKEN`, followed by an eight-digit setup code. Copy the complete line labelled
**FIRST-PHONE ENROLLMENT LINK**. Open that link, enter the code, and start enrollment in the browser. The link and code expire
after ten minutes and can be used once. The old `/bootstrap?token=...` form is still accepted for an unexpired link. The
resulting browser session can only enroll that administrator's first phone; it cannot view keys, change settings, or manage
other accounts. After the phone is added, the temporary session ends and normal web sign-in uses phone approval.

This bootstrap is only available for a local administrator with no device records. It cannot replace a phone after one has
already been enrolled. Keep the link and setup password private and use them only on a trusted network.

Switch it off any time: `thessley-pam-win web off`. Other settings: `web listen ADDRESS` (default: this computer's LAN address;
`0.0.0.0` listens everywhere, only for networks you trust), `web port N`, `web session MINUTES` (15 idle, 8 h at most).

Administrators can also switch **Admin page available only on 127.0.0.1** on or off under **Admin**. When on, the listener
accepts connections only from this Windows computer; open `https://127.0.0.1:47820/` locally, or use an SSH tunnel for
remote access. Turning it on disconnects browsers on other computers. Turning it off restores the configured `web listen`
address (or the computer's LAN address when set to `auto`).

## Keep the page off the network (ssh tunnel)

The page can listen on this computer only, so nothing on the network can reach it, and you open it through an ssh
tunnel (your ssh login is approved with a device too). Approvals are not affected: the device talks to the short-lived
listener on this computer's LAN address (TCP port 47810), never to the page, so the QR code and the link work as before.

    thessley-pam-win web listen 127.0.0.1
    thessley-pam-win web on                       (restarts the page with the new address)
    ssh -N -L 127.0.0.1:47821:127.0.0.1:47820 user@this-computer      (on your own computer; leave it running)

Then open `https://127.0.0.1:47821/` (the certificate is self-signed, so the browser warns once). To go back to the LAN
address: `thessley-pam-win web listen auto`. Every page says which computer it is for ("Thessley Passkeys for computer-name").

## What you can do in it

The page opens in dark mode. Use the **Light mode** button in the header to switch themes; the choice is remembered in that browser.

- **Your approvers:** a list with a *Details* fold-out for each (kind: phone or app; where a phone's key lives: StrongBox, TEE
  or software; key fingerprint; use count and last use; passes it granted), and *rename*, *switch off/on*, *remove*, *add a
  phone or app* (QR and link, compare the 6-digit codes, press "The codes match").
- **Every change asks for a fresh approval first** ("Approve a change to your keys", or "Approve adding a device"), so a stolen
  browser session can look but not change anything. A sign-in or a change never uses a pass and never grants one.
- **Administrators** (members of the local Administrators group) can pick any account and change the settings
  (how long one approval counts, whether users may enrol their own first approver). Their own phone approves each change.
- **Allowed source networks:** Admin → Settings defaults to local networks plus the VPN client ranges
  `10.8.0.0/24` and `10.8.1.0/24`. Administrators can select all IPs, local networks, VPN ranges, and/or a chosen
  CIDR list. Saving requires a fresh phone approval and updates the Windows Firewall scopes for the default OpenSSH
  rule and Thessley listeners on TCP 47810 and 47820. The browser's current network must stay selected.
- **Passes:** under your approvers, the ssh approvals that currently let your account in without asking your device again
  (the grace hours), each with an **End this pass** button, and **End all passes**. The next login then asks your device again.
  Ending a pass only takes access away, so it needs no fresh approval.
- **Activity:** the newest 3,000 approvals, refusals, pass grants and enrolments from `service.log` and its five bounded rotations, shown 20 per page (administrators can see everyone's). Reuse of an existing pass is not logged.
- **AD users:** authenticated local administrators can view the paired computer's AD user directory, enabled state, current authorization, and enrolled phone-key labels and dates. Keys are scoped to this computer; private key data is never displayed. Enroll or revoke a key from its user card; each action requires a fresh approval from the administrator's phone. Enrollment is available only for enabled accounts allowed by the AD service's configured group policy. The page does not modify AD accounts or groups. Windows Home can use this paired service view, but this does not enable domain join or AD Windows sign-in on Home.
- Administrators can set maximum concurrent web requests, the bounded IP rate-limit cache, and log file size/rotation count under **Admin**. Dependency versions are pinned in `requirements.lock` and installed into a private directory beside the app, leaving machine-wide Python unchanged.
- **Automatic updates:** enabled by default, the SYSTEM task checks each Sunday at 03:00 local time. It verifies the downloaded ZIP against the SHA-256 pin in the HTTPS bootstrap and then uses the installer's staging, service health check, and rollback. The update preserves firewall rules, SSH policy, enrolled phones, and passes, but restarts the approval service briefly; a new phone-gated SSH login may pause during that restart while existing SSH sessions stay open. Use **Turn automatic updates off** here to disable future runs. Status and errors are in `C:\ProgramData\ThessleyPamWin\update-state.json` and `C:\ProgramData\ThessleyPamWin\logs\update.log`. This uses the same HTTPS publisher trust as the interactive installer and does not use a separate code-signing signature.
- **Keep four-hour SSH approvals after service restarts:** on by default. Existing passes retain their original expiry and still require the same client IP and active enrolled approver. Turning this off makes the next approval-service start clear all passes; it does not revoke passes immediately. Every change requires fresh phone approval.
- **Setup rollback timer:** after testing the configured login methods, an administrator can review pending Thessley rollback tasks under **Admin → Settings** and choose **Confirm setup and cancel rollback**. The action requires a fresh phone approval and removes only the Thessley SSH/credential-provider recovery timers.
- The guided installer enables QR approval for current local accounts by default while preserving their configured OpenSSH factor. Until a phone is enrolled, the default fallback allows the account's existing key/password login; after enrollment, QR is required. Administrators manage each account from **Admin → Users**, with separate QR and **Block SSH** checkboxes. A custom exact `Match User NAME` rule is preserved while the QR command is added; complex custom rules remain unchanged. Every change asks for a fresh admin approval, backs up `C:\ProgramData\ssh\sshd_config`, validates it with OpenSSH, then restarts `sshd`; the page reports the backup path. The fallback can be switched off in Admin. Domain accounts are not listed.

The ZIP packages are built with `python scripts/build_downloads.py` and distributed separately from the authenticated web GUI.

## TPM proof

When the Thessley Passkey desktop app enrols a key that is held in a TPM chip (protection "TPM chip + PIN", and so on), it
also sends a proof, and this computer checks it: the chip's own manufacturer certificate chain (against the roots in
`thessley_pam_win\\tpm_roots\\`, Intel and AMD shipped), a challenge only that chip can answer (credential activation), and
the chip's certification that the new key was created inside it and cannot leave it. A key that passes shows "TPM 2.0 proof:
verified, a genuine chip from INTC ADL" under **Details** here, and in `thessley-pam-win list`; a key that fails shows why.

- **To use it on an existing installation:** pull, re-run `install\\install.ps1` (it now also installs `asn1crypto`, which reads
  TPM certificates), and enrol the desktop app again with a TPM protection. A key enrolled earlier has no proof.
- **It never blocks an enrolment:** without a proof the key is still added, and the page says so.
- **What it does not cover:** revocation lists are not checked, nor the security of the chip's firmware. A maker whose root
  is not in `tpm_roots` (Infineon, STMicro, Nuvoton ...) is not trusted until you add its root certificate there as a `.pem`
  file, then re-run `install.ps1`.
- The same checks, the same code and the same roots as thessley-pam-linux. The proof itself was tested against a real TPM
  (Intel PTT) and with a synthetic one (`tests/test_tpmproof.py`); not yet tried with a TPM on a Windows computer.

## How it is kept safe

- Sign-in needs a signature from an approver already enrolled for the account; an account with none, or that does not
  exist, gets the same answer, and sign-in requests are limited per address.
- A strict content policy (no outside scripts or frames), an HttpOnly, Secure, SameSite=Strict session cookie, a token on every form,
  everything escaped, and everything the page acts on looked up from the signed-in account against a strict pattern.
- It runs as SYSTEM, because the approver lists are SYSTEM-only. Anyone who can approve for an account can sign in as that
  account on this page: treat an approver like a key to the account.

## What has and has not been tested

Tested (on Linux, with the Windows-only parts stubbed): the whole page against a real HTTPS server and a stand-in phone:
sign-in, refusals, unsigned refusals, timeouts, a stolen request id, rate limiting, cookie flags, form tokens, every change
needing an approval, adding an approver, who may do what, escaping, the log, key details (`tests/test_web.py`, 35 tests).

**Not yet run on Windows. Please check these when you first use it, and tell me what you see:**
- `web on` / `web off` / `web status` start, stop and describe the scheduled task `ThessleyPamWinWeb` (they call `schtasks`).
- *Administrators* are found with `Get-LocalGroupMember -SID S-1-5-32-544` (by SID, so in any language). If the Admin page does not
  show for an administrator, run that command by hand in PowerShell as SYSTEM-like context and send me the output.
- The page draws the QR on a canvas from the QR modules. The text approval link remains available as a fallback.
- The page's certificate lives in `C:\ProgramData\ThessleyPamWin\web\` and inherits the locked-down permissions of that folder.
- The firewall rule for TCP 47820 (`-OpenWebFirewall`).

## Undo

`thessley-pam-win web off`, and `install\uninstall.ps1` removes the page's task and its firewall rule with the rest (keys and
settings stay unless you pass `-RemoveData`).
