# The admin web page (Windows)

Sign in with your account name and an approval (the Thessley Passkey phone app or desktop app), then manage your
approvers in a browser. It is the Windows counterpart of the page in thessley-pam-linux (`docs/WEB.md` there) and works the
same way. There are no passwords.

## What to do on the Windows computer

Do these in an **administrator PowerShell**, in the repository folder, after pulling the latest version
(`git pull`). The page is a second scheduled task next to the approval service; it stays **off** until you switch it on.

1. **Update the program and create the page's task** (use the Python you installed with last time):

       powershell -ExecutionPolicy Bypass -File install\install.ps1 -Python "C:\Program Files\Python313\python.exe" -OpenFirewall -OpenWebFirewall

   `-OpenWebFirewall` is new: it allows TCP 47820 from the local subnet (Private networks; add `-FirewallProfile Any` for
   networks Windows calls Public). Leave it out and add your own rule if you prefer. Nothing else is touched. An upgrade
   keeps the page on if it was already on.

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

Switch it off any time: `thessley-pam-win web off`. Other settings: `web listen ADDRESS` (default: this computer's LAN address;
`0.0.0.0` listens everywhere, only for networks you trust), `web port N`, `web session MINUTES` (15 idle, 8 h at most).

## Keep the page off the network (ssh tunnel)

The page can listen on this computer only, so nothing on the network can reach it, and you open it through an ssh
tunnel (your ssh login is approved with a device too). Approvals are not affected: the device talks to the short-lived
listener on this computer's LAN address (ports 47810-47819), never to the page, so the QR code and the link work as before.

    thessley-pam-win web listen 127.0.0.1
    thessley-pam-win web on                       (restarts the page with the new address)
    ssh -N -L 127.0.0.1:47821:127.0.0.1:47820 user@this-computer      (on your own computer; leave it running)

Then open `https://127.0.0.1:47821/` (the certificate is self-signed, so the browser warns once). To go back to the LAN
address: `thessley-pam-win web listen auto`. Every page says which computer it is for ("Thessley Passkeys for computer-name").

## What you can do in it

- **Your approvers:** a list with a *Details* fold-out for each (kind: phone or app; where a phone's key lives: StrongBox, TEE
  or software; key fingerprint; use count and last use; passes it granted), and *rename*, *switch off/on*, *remove*, *add a
  phone or app* (QR and link, compare the 6-digit codes, press "The codes match").
- **Every change asks for a fresh approval first** ("Approve a change to your keys", or "Approve adding a device"), so a stolen
  browser session can look but not change anything. A sign-in or a change never uses a pass and never grants one.
- **Administrators** (members of the local Administrators group) can pick any account and change the two settings
  (how long one approval counts, whether users may enrol their own first approver). Their own phone approves each change.
- **Activity:** the recent approvals, refusals, passes and enrolments from `service.log` (administrators can see everyone's).

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
- The QR code image is drawn by the `qrcode` library's SVG output (installed by `install.ps1`).
- The page's certificate lives in `C:\ProgramData\ThessleyPamWin\web\` and inherits the locked-down permissions of that folder.
- The firewall rule for TCP 47820 (`-OpenWebFirewall`).

## Undo

`thessley-pam-win web off`, and `install\uninstall.ps1` removes the page's task and its firewall rule with the rest (keys and
settings stay unless you pass `-RemoveData`).
