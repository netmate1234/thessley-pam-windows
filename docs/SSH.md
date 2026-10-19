# ssh to Windows 11: password first, then a phone or desktop-app approval

For chosen Windows accounts, `ssh` asks for the account's **password** (or accepts its **ssh key**, see
"Key instead of password") and then shows a **QR code and a `thessleypam://` link**. The login continues only after an enrolled phone (or the Thessley Passkey desktop app) approves
it with a signature. Optionally, one approval then counts for N hours from the same address or, in configurable cloud
mode, from any client address (a "pass").

This is the Windows counterpart of [thessley-pam-linux](../../thessley-pam-linux/docs/SSH.md). It speaks the same
protocol, so the same phone app and the same desktop app (`thessley-passkey respond` / "Paste a link") approve it.

## How it works, and how it differs from Linux

Windows OpenSSH has no PAM, so the approval cannot sit inside the authentication step. It sits right after it:

1. `sshd` checks the first factor: the password (`AuthenticationMethods password`) or the ssh key (`publickey`). A wrong password
   or an unknown key never gets further.
2. For the chosen account, `sshd_config` has `ForceCommand gate.cmd`. `sshd` starts the **gate** instead of the user's shell.
3. The gate (runs as the user, standard library only) asks the **approval service** over `127.0.0.1:47800`, prints what the
   service says (the link and the QR code) into the ssh terminal, and waits.
4. The service (runs as **SYSTEM**) registers the request with its shared HTTPS listener on TCP 47810. The listener uses a
   stable certificate whose SHA-256 is in the link and routes each signed phone response to its matching request. It handles
   concurrent approvals on one port; an SSH login does not open or hold a separate port. It then answers the gate yes or no.
   A **refusal** (`deny`) may arrive without a signature, so the phone does not ask for a fingerprint to say no: it then
   carries the request's own nonce, which only the person who saw the link has. An approval always needs the signature, and
   an unsigned answer from a phone that is not enrolled for the account is refused. (Same rule as thessley-pam-linux.)
   The link also carries two display-only fields, `s` (the service, `sshd`) and `r` (the client's address), so the apps can say
   "ssh login from ..." instead of a bare "sudo"; the signature does not cover them, so they can mislead but never approve.
5. Only a clear yes makes the gate start the person's shell, or the command they gave to `ssh`. Denial, timeout, a bad
   signature, no approver enrolled, the service not running, any error: the connection ends. Refused by default.

Why a SYSTEM service: the gate runs as the person who just logged in, so it must not be the one that reads the list of
approvers or writes passes, or that person could add their own phone or forge a pass. On Linux root does this job.

| | Linux (thessley-pam-linux) | Windows (this) |
|---|---|---|
| Where the approval sits | inside PAM, before the session | `ForceCommand`, after the password, before the shell |
| Who keeps approvers and passes | root | a SYSTEM service; the folder is closed to normal users |
| First factor | ssh key (then phone) | account password or ssh key (then phone), your choice per account |
| Passes end | on reboot (tmpfs) | when the service starts (every boot) |
| Wire protocol, apps | same | same |

### What a pass does and does not do

A pass is tied to the user and the client's address (from `SSH_CONNECTION`), to the approver that granted it, and has a
fixed end. It does not know which password was used: whoever gets past the password step for that account from the same
address during the window skips the approval. Behind a shared (NAT) address that can be more than one machine. Keep
the window short; `thessley-pam-win end-pass` ends passes at once. Turned off by default (`grace 0`).

### Limits to know about

- The gate protects the shell and the commands. Port forwarding, agent and X11 forwarding are switched off for the account
  in the `Match` block (below); without that a forwarding-only connection would never reach the gate.
- `sftp` and `scp` go through the gate too (they are forced commands); that path is **not tested** here.
- **Gating an administrator account** is possible but weakens what the gate protects: the session then runs elevated, so
  it can change `C:\ProgramData\ThessleyPamWin` (add an approver, forge a pass), and a pass is then 4 hours of administrator
  access from that address. Windows also reads that account's key from `administrators_authorized_keys`, not from its own
  `.ssh` folder. Prefer a normal account for ssh, and use `runas` or an elevated local session for administration.
- Only accounts named in a `Match User` block are gated. Every other account keeps the settings in `sshd_config`.
- Account names may contain only letters, digits, `.`, `_`, `-` (the signed message cannot carry spaces).
- Treat the approver like the phone: screen lock, disk encryption. If the only phone is lost nobody can log in over ssh:
  enrol a second approver while the first works, and keep a console or a non-gated admin account to repair this.

## Setup

1. **Python for all users** (the service runs as SYSTEM and must not load code a normal user can change):

       winget install --id Python.Python.3.13 --scope machine

   Pick a version you do **not** already have installed just for your own user: Windows Installer treats the all-users and
   per-user builds of the same Python version as one product, so installing the same version both ways fails (error 1603).

2. In an **administrator** PowerShell, from this folder:

       powershell -ExecutionPolicy Bypass -File install\install.ps1 -Python "C:\Program Files\Python313\python.exe" -OpenFirewall

   It refuses a Python that normal users can write to, installs the pinned dependencies from `requirements.lock` and verifies
   their versions and dependency consistency, copies the program to
   `C:\ProgramData\ThessleyPamWin`, closes the data folders to normal users, creates the scheduled task that runs the
   service as SYSTEM at boot, and starts it. `-OpenFirewall` adds one rule: TCP 47810-47819 from the local subnet, Private
   networks only, for that Python. It never touches `sshd_config`, accounts or groups.

3. **Enrol an approver.** An administrator can do it as below; users can also enrol themselves, without administrator rights
   (see "Enrolling without an administrator"). Administrator terminal (see "Second approver" for the desktop app):

       & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" enroll --user YOURNAME

   Scan the QR code with the phone app, or paste the link into the desktop app, compare the 6-digit code on both screens
   and type `yes`.

4. **Edit `C:\ProgramData\ssh\sshd_config`.** The tool prints the exact lines:

       & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" sshd-config --user YOURNAME

   They go at the **end** of the file (a `Match` block must be last):

       Match User YOURNAME
           PasswordAuthentication yes
           PubkeyAuthentication no
           KbdInteractiveAuthentication no
           AuthenticationMethods password
           AllowTcpForwarding no
           AllowAgentForwarding no
           X11Forwarding no
           PermitTunnel no
           PermitTTY yes
           ForceCommand C:\ProgramData\ThessleyPamWin\gate.cmd

   Then, always in this order (administrator):

       & "C:\Program Files\OpenSSH\sshd.exe" -t        # refuses to continue if the config is invalid
       Restart-Service sshd

   Keep one working session open while you try a new login, and keep a copy of `sshd_config`.
   The command prints a password-first block by default. Select the first factor explicitly with
   `sshd-config --user YOURNAME --factor password|key|key-password`. Keep one working session open, back up the file,
   validate with `sshd -t`, and only then restart the service.

   If `YOURNAME` is an **administrator**, the stock `Match Group administrators` block at the end of the file also
   applies. Put your `Match User` block **above** it (sshd uses the first value it finds for each setting).

**Select the first factor**

Windows OpenSSH authenticates the account before it starts `gate.cmd`; the gate then asks for phone approval. Pick one
of these first-factor choices when generating the `Match User` block:

- `--factor password`: account password, then phone approval. SSH keys are disabled for this account.
- `--factor key`: SSH key, then phone approval. Account passwords are disabled for this account.
- `--factor key-password`: SSH key and then account password, then phone approval.

The key-only block looks like this:

    Match User YOURNAME
        PasswordAuthentication no
        PubkeyAuthentication yes
        KbdInteractiveAuthentication no
        AuthenticationMethods publickey
        AllowTcpForwarding no
        AllowAgentForwarding no
        X11Forwarding no
        PermitTunnel no
        PermitTTY yes
        ForceCommand C:\ProgramData\ThessleyPamWin\gate.cmd

The password is then not accepted at all for that account. The strictest option requires a key and **then** password
before phone approval; generate it with `--factor key-password`.

**Windows limitation:** unlike the Linux PAM module, this gate cannot provide QR-only authentication or let a user
fall back to a password after phone approval fails. OpenSSH must accept a first factor before it launches the gate.
The admin web page describes these choices but deliberately does not edit `sshd_config` or restart the SSH service.

On Windows the key must be where `sshd` looks, with permissions it accepts, or it is silently ignored:

- an account that is **not** an administrator: `C:\Users\NAME\.ssh\authorized_keys`;
- an **administrator** account: `C:\ProgramData\ssh\administrators_authorized_keys` (the stock `Match Group administrators`
  block); only SYSTEM and Administrators may have access to it;
- the file must be readable only by that account, SYSTEM and Administrators (OpenSSH ships
  `FixUserFilePermissions.ps1` / `FixHostFilePermissions.ps1` in `C:\Program Files\OpenSSH` for this).

If the key is lost, nobody can log in to that account over ssh. Keep a second way in (another account, or the console).

5. **Firewall for ssh itself** (port 22) is a separate matter and not touched here. The OpenSSH installer's rule covers
   Private networks only.

6. **Optional: passes.** Off by default, so every login asks. To let one approval count for 4 hours from the same address
   (administrator):

       & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" grace --hours 4

   On a cloud host whose SSH clients can arrive from changing addresses, use `grace --hours 4 --ip-scope any` instead.
   This is a per-computer setting; switch back with `grace --hours 4 --ip-scope same`. A pass still requires an enrolled
   approver and applies only until its fixed expiry.

   It prints the configured address scope. In a window that is not elevated it only says to run it as administrator and
   changes nothing. The pass is created by the next approval *after* you set this; in same-IP mode, a login from another
   address asks again.

7. Log in from another computer:

       ssh YOURNAME@this-computer
       (password)
       Approve the ssh login for YOURNAME on THIS-COMPUTER with Thessley Passkey (within 90 s):
       Link: thessleypam://sudo?...
       <QR code>
       (approve on the phone, or:  thessley-passkey respond 'thessleypam://sudo?...' --approve )

## Second approver (desktop app)

The Thessley Passkey desktop app (`thessley-passkey-linux`) enrols and approves with the same protocol:

    thessley-passkey enroll 'thessleypam://enroll?...' --protect tpm+pin --label "my laptop"
    thessley-passkey respond 'thessleypam://sudo?...' --approve

or paste the link into the app. The approver must reach this computer on TCP 47810 while an SSH login waits, and the two
clocks must agree within a minute.

## Enrolling without an administrator

Any user can add an approver for **their own account** (not for anyone else's) from a normal terminal:

    & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" enroll

It shows the same link and QR code, you compare the 6-digit code on both screens and type `yes`. The tool talks to the approval
service (SYSTEM), which does the work and applies these rules:

- **Who is asking is not taken from the request.** The service asks Windows which account owns the connection and refuses a
  request for any other account, so a user can only ever add approvers for themselves. An administrator can add one for anyone
  (`enroll --user NAME` in an administrator terminal, as before).
- **The first approver of an account** can be added by the user themselves, with no code, when the account has no approver at
  all. A gated account with no approver is refused at ssh login, so nobody can get a remote shell on it to run this: it has to be a
  session on the computer itself (console, remote desktop, or any shell already open as that user).
  **Trade-off:** whoever can run such a session as that account (it takes the account's password) can enrol their own phone first.
  If you do not want that, turn it off and let only administrators add the first approver:

      thessley-pam-win self-enroll off        (administrator; `on` restores it; no argument shows the setting)

- **More approvers** (a second phone, the desktop app) need a fresh approval from an approver that is already enrolled; the
  new-device request appears on that phone as "adding a device". A pass never counts for this and none is created, so a stolen
  password, a stolen key or a live pass cannot add a device.
- **A lost phone needs an administrator.** If the account's approvers exist but are all switched off, nobody can add one
  themselves, which keeps a lost phone from reopening the first-come route.
- One enrolment per account at a time. Closing the terminal cancels it and frees the approval port at once.
- The user cannot list or remove approvers, change the pass length or read the data folders; those stay administrator-only.

For a user to run the tool, `thessley-pam-win.cmd` has to be readable by Users. `install.ps1` now does that; on an existing
installation re-run it, or in an administrator PowerShell:

    icacls C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd /grant "*S-1-5-32-545:(RX)"

## Daily use (administrator terminal)

    thessley-pam-win status                      is the service running; pass length
    thessley-pam-win list                        approvers
    thessley-pam-win disable|enable --user N ID  switch an approver off or on (its passes end with it)
    thessley-pam-win remove --user N ID          forget an approver
    thessley-pam-win self-enroll [on|off]        may an account with no approver enrol its first one itself
    thessley-pam-win grace --hours 4 [--ip-scope same|any] one approval counts for 4 h (0 = every login asks)
    thessley-pam-win passes                      who holds a pass
    thessley-pam-win end-pass [--user N]         end passes now

The service writes `C:\ProgramData\ThessleyPamWin\service.log` (approvals, denials, bad signatures, passes used).

## Undo

1. Remove the `Match User ...` block from `sshd_config`, `Restart-Service sshd`. (Do this first: while the block is there,
   that account is refused, because the gate is gone.)
2. `powershell -ExecutionPolicy Bypass -File install\uninstall.ps1` (`-RemoveData` also deletes the approvers and the log).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "the approval service is not running. Refusing." | The scheduled task `ThessleyPamWin` is not running: `Start-ScheduledTask ThessleyPamWin`, check `service.log` |
| "no phone or app is enrolled for this account" | `thessley-pam-win list` shows nothing for that name: enrol, and use the same account name |
| The QR code appears on every login although `grace` was set | Not elevated when `grace` ran (it only printed a hint), or the login comes from another address than the approval. `service.log` shows `pass granted` / `pass used`; `thessley-pam-win passes` lists live passes |
| `enroll` says "you can only add an approver for your own account" | You named another account without being an administrator; leave out `--user`, or use an administrator terminal |
| `enroll` says every approver is switched off, or the first one needs an administrator | By design (lost phone, or `self-enroll off`): ask an administrator |
| The desktop app says "This computer is not enrolled with ..." when you paste a link | You pasted the **first** link of an add-device enrolment ("Approve adding a device"). That one is answered by the phone or app that is **already** enrolled; the new device gets the second link, which appears after the approval |
| Enrolling the desktop app with a TPM protection asks for administrator rights, or fails without a prompt | Fixed in thessley-passkey-linux `1a173d0`: enrolling as an approver for a computer needs no administrator rights (only a website's TPM proof does). Update the app |
| `enroll` is denied or cannot start for a normal user | `thessley-pam-win.cmd` is not readable by Users: re-run `install.ps1` (see above) |
| The phone cannot reach the computer | The network is "Public" in Windows (the rule is Private only), or the phone is on mobile data, or a third-party firewall blocks TCP 47810 |
| "Phone clock is off by more than a minute" | Fix the time on the phone or on this computer |
| The login ends right after the password with no QR code | `gate.cmd` failed to start: check the path in `ForceCommand`, and that Python is where `gate.cmd` says |
| QR code looks broken | The terminal is not UTF-8 or too narrow; use the `Link:` line with the desktop app |
| An ssh key is added but the password is still asked | The account's `Match` block says `PubkeyAuthentication no` (the password variant). Use the key block above and restart `sshd` |
| The key is ignored although the block allows keys | Wrong file (`C:\Users\NAME\.ssh\authorized_keys`, or `administrators_authorized_keys` for an administrator) or permissions too open: `sshd` ignores it without saying so; the OpenSSH event log shows the reason |
| Still asked for a public key | A `Match` block for the user is missing, or above a more general block that sets `PubkeyAuthentication` |
| `Restart-Service sshd` fails | Run `sshd.exe -t` and read the line it names |

## What has and has not been tested

Tested (`python -m pytest`): the approval flow, deny, wrong and forged signatures, replays, another user's phone,
timeouts, passes (fixed length, ended by removing or disabling the approver), the gate and the service
end to end on localhost with a stand-in phone that signs like the real apps, and that the gate refuses on anything but a
clear yes.

**Supervised test on Windows 11 (2026-10-16), and what it showed:**

- The installer ran as administrator; the scheduled task started the service, which listens on `127.0.0.1:47800` only.
- The folder lockdown holds for a normal user: `users\` and `service.log` are unreadable, nothing in the program folder or
  `gate.cmd` can be changed, and the admin tool is closed to them.
- The running service refuses an account that is not enrolled, and rejects garbage, a bad address and a path-trick user name.
- After `sshd` was restarted with the `Match User` block, a password login for that account from another computer on the
  LAN was accepted, the QR code and link were shown, and `service.log` recorded `approved by '<phone>' ... for <user>`.
  The approval came from the phone, over the pinned-certificate listener, not from the ssh client.
- **Key instead of password** works: with the `publickey` block, `sshd` accepted the account's ed25519 key and the gate then
  ran without a new approval inside the pass window. Pass reuse is not written to `service.log`. A fresh key login that
  needs a new approval was not separately exercised, but it takes the same gate path.
- **Passes** work with a real `sshd`. After `grace --hours 4`, the first approval wrote `pass granted to <user> (from
  <address>, 4 h)`, and the next login from the same address went straight in, with no QR code. Reuse is intentionally not
  logged.

- **Enrolling without an administrator** works with real devices. A normal user (not an administrator) ran `enroll`; the
  service asked for an approval to add a device, the phone approved it (`approved by '<phone>' ... (from -)`), and the
  desktop app then enrolled as a second approver (`enrolled '<label>' <id> for <user> (by themselves)`). It is also covered
  by tests against the real service and a stand-in phone (own account only, first approver, approval by an existing
  approver, pass ignored, lost phone, switch off, closing the terminal, one at a time, the command line as a normal user).
  The first-approver route (no approver yet) was only tested with the stand-in phone.

- **Refusal without a signature** (the phone's "no" without a fingerprint) and the display-only link fields are covered by
  tests with a stand-in phone: an unsigned deny with the real nonce works; an unsigned approval, a wrong, missing or
  non-ASCII nonce, and an unenrolled or other user's phone are refused. Not yet tried with the updated phone app.

**Still not tested:** the service's run-as-SYSTEM status was inferred (it writes a log normal users cannot read), not
read from the task; `sftp`/`scp` and `ssh host command` through the gate; two approvers at once; the desktop app as the
approver; a pass from a different address (it should ask again); and a pass ending after its 4 h.
Do those first on an account you can recover, with a second session open.

## Things that went wrong on the first install (and the fix)

- **`winget install --scope machine` fails with 1603** when the *same Python version* is already installed just for your
  user: Windows Installer treats the two as one product. Install a different version for all users (3.13 above).
- **`sshd` reads `sshd_config` only when it starts.** A login right after editing the file runs on the old rules, so there
  is no gate and no QR code. Restart the service (administrator), after `sshd.exe -t` prints nothing.
- **"Cannot open service sshd"** means the PowerShell window is not elevated.
- After a failed `Restart-Service` the service briefly looked missing (error 1060 from a normal window). `New-Service`
  then said it already existed, and `sc.exe sidtype sshd unrestricted` plus `Start-Service sshd` brought it up (and left it
  on Automatic start). The cause was not determined.
- **Notepad does not show `sshd_config`**: `C:\ProgramData` is hidden and the file has no extension. Use
  `notepad C:\ProgramData\ssh\sshd_config` from an administrator PowerShell.
- Windows classes many home Wi-Fi networks as **Public**; the approval firewall rule is Private-only unless you install with
  `-OpenFirewall -FirewallProfile Any` (still limited to the local subnet).
