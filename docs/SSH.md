# ssh to Windows 11: password first, then a phone or desktop-app approval

For chosen Windows accounts, `ssh` asks for the account's **password** and then shows a **QR code and a
`thessleypam://` link**. The login continues only after an enrolled phone (or the Thessley Passkey desktop app) approves
it with a signature. Optionally, one approval then counts for N hours from the same address (a "pass").

This is the Windows counterpart of [thessley-pam-linux](../../thessley-pam-linux/docs/SSH.md). It speaks the same
protocol, so the same phone app and the same desktop app (`thessley-passkey respond` / "Paste a link") approve it.

## How it works, and how it differs from Linux

Windows OpenSSH has no PAM, so the approval cannot sit inside the authentication step. It sits right after it:

1. `sshd` checks the password (`AuthenticationMethods password`). A wrong password never gets further.
2. For the chosen account, `sshd_config` has `ForceCommand gate.cmd`. `sshd` starts the **gate** instead of the user's shell.
3. The gate (runs as the user, standard library only) asks the **approval service** over `127.0.0.1:47800`, prints what the
   service says (the link and the QR code) into the ssh terminal, and waits.
4. The service (runs as **SYSTEM**) opens a short-lived HTTPS listener with a throw-away certificate whose SHA-256 is in the
   link, waits for a signed `approve` from one of the account's enrolled approvers, and answers the gate yes or no.
5. Only a clear yes makes the gate start the person's shell, or the command they gave to `ssh`. Denial, timeout, a bad
   signature, no approver enrolled, the service not running, any error: the connection ends. Refused by default.

Why a SYSTEM service: the gate runs as the person who just logged in, so it must not be the one that reads the list of
approvers or writes passes, or that person could add their own phone or forge a pass. On Linux root does this job.

| | Linux (thessley-pam-linux) | Windows (this) |
|---|---|---|
| Where the approval sits | inside PAM, before the session | `ForceCommand`, after the password, before the shell |
| Who keeps approvers and passes | root | a SYSTEM service; the folder is closed to normal users |
| First factor | ssh key (then phone) | account password (then phone) |
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

   It refuses a Python that normal users can write to, installs `cryptography` and `qrcode` into it, copies the program to
   `C:\ProgramData\ThessleyPamWin`, closes the data folders to normal users, creates the scheduled task that runs the
   service as SYSTEM at boot, and starts it. `-OpenFirewall` adds one rule: TCP 47810-47819 from the local subnet, Private
   networks only, for that Python. It never touches `sshd_config`, accounts or groups.

3. **Enrol an approver** (administrator terminal; see "Second approver" for the desktop app):

       & "C:\ProgramData\ThessleyPamWin\thessley-pam-win.cmd" enroll --user YOURNAME --link

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

   If `YOURNAME` is an **administrator**, the stock `Match Group administrators` block at the end of the file also
   applies. Put your `Match User` block **above** it (sshd uses the first value it finds for each setting).

5. **Firewall for ssh itself** (port 22) is a separate matter and not touched here. The OpenSSH installer's rule covers
   Private networks only.

6. Log in from another computer:

       ssh YOURNAME@this-computer
       (password)
       Approve the ssh login for YOURNAME on THIS-COMPUTER with Thessley Passkey (within 60 s):
       Link: thessleypam://sudo?...
       <QR code>
       (approve on the phone, or:  thessley-passkey respond 'thessleypam://sudo?...' --approve )

## Second approver (desktop app)

The Thessley Passkey desktop app (`thessley-passkey-linux`) enrols and approves with the same protocol:

    thessley-passkey enroll 'thessleypam://enroll?...' --protect tpm+pin --label "my laptop"
    thessley-passkey respond 'thessleypam://sudo?...' --approve

or paste the link into the app. The approver must reach this computer on TCP 47810-47819 while a login waits, and the two
clocks must agree within a minute.

## Daily use (administrator terminal)

    thessley-pam-win status                      is the service running; pass length
    thessley-pam-win list                        approvers
    thessley-pam-win disable|enable --user N ID  switch an approver off or on (its passes end with it)
    thessley-pam-win remove --user N ID          forget an approver
    thessley-pam-win grace --hours 4             one approval counts for 4 h from the same address (0 = every login asks)
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
| The phone cannot reach the computer | The network is "Public" in Windows (the rule is Private only), or the phone is on mobile data, or a third-party firewall blocks 47810-47819 |
| "Phone clock is off by more than a minute" | Fix the time on the phone or on this computer |
| The login ends right after the password with no QR code | `gate.cmd` failed to start: check the path in `ForceCommand`, and that Python is where `gate.cmd` says |
| QR code looks broken | The terminal is not UTF-8 or too narrow; use the `Link:` line with the desktop app |
| Still asked for a public key | A `Match` block for the user is missing, or above a more general block that sets `PubkeyAuthentication` |
| `Restart-Service sshd` fails | Run `sshd.exe -t` and read the line it names |

## What has and has not been tested

Tested (`python -m pytest`): the approval flow, deny, wrong and forged signatures, replays, another user's phone,
timeouts, passes (same address only, fixed length, ended by removing or disabling the approver), the gate and the service
end to end on localhost with a stand-in phone that signs like the real apps, and that the gate refuses on anything but a
clear yes.

**Supervised test on Windows 11 (2026-10-16), and what it showed:**

- The installer ran as administrator; the scheduled task started the service, which listens on `127.0.0.1:47800` only.
- The folder lockdown holds for a normal user: `users\` and `service.log` are unreadable, nothing in the program folder or
  `gate.cmd` can be changed, and the admin tool is closed to them.
- The running service refuses an account that is not enrolled, and rejects garbage, a bad address and a path-trick user name.
- After `sshd` was restarted with the `Match User` block, a password login for that account from another computer on the
  LAN was accepted, and the account's owner said it "seems to work". The QR code, the link and the approval were not
  confirmed in `service.log` (administrators only); that line was not inspected.

**Still not tested:** the service's run-as-SYSTEM status was inferred, not read; `sftp`/`scp` and `ssh host command`
through the gate; two approvers at once; passes with a real `sshd`; and the real phone app against this server.
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
