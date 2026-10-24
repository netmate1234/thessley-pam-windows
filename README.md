# thessley-pam-windows

Approve ssh logins to a **Windows 11** computer with the Thessley Passkey phone app or desktop app: the account's password
first, then a QR code and a `thessleypam://` link that a phone (or the desktop app) approves with a signature.

It is the Windows counterpart of `thessley-pam-linux` and speaks the same protocol (`thessley_pam_v1`), so the same
apps work. Windows OpenSSH has no PAM, so the approval runs as a `ForceCommand` right after the password; a small service
running as SYSTEM keeps the approvers and passes where a logged-in user cannot change them.

Read [docs/SSH.md](docs/SSH.md) first: it explains the design, limits, remote SSH installation, phone enrollment, timed rollback,
and what has and has not been tested.

For a guided Windows 11 setup, extract this ZIP and run `guided-install.ps1` from an **Administrator PowerShell**. It
installs the core service and offers the optional web page, firewall rules, per-user SSH QR gate, and experimental
Windows QR sign-in tile. When OpenSSH is running, the wizard enables QR approval for current local accounts by default
and preserves their existing key/password settings. Accounts without an enrolled phone can use the configured fallback
until enrollment; afterward, QR approval is required. In **Admin → Users**, administrators can change each account's QR
requirement, block SSH, and select its first factor. Changes require fresh admin phone approval, back up and validate
`sshd_config`, and restart OpenSSH. Keep a working SSH session and Windows PIN/password recovery available while changing login settings; the sign-in
tile has its own rollback. Confirm only
after testing every selected login method with `C:\ProgramData\ThessleyPamWin\confirm-setup.ps1`. Python 3.12+ for all
users is required; if it is missing, the wizard offers to install Python 3.13 with winget. It detects a missing
OpenSSH service and stops before changing SSH policy.
Under **Admin → Settings**, administrators can select allowed source networks for SSH, phone approvals, and the web page.
The default is local networks plus VPN client ranges `10.8.0.0/24` and `10.8.1.0/24`; chosen CIDRs can be added.
For local hosts, the firewall defaults to local networks plus VPN client ranges `10.8.0.0/24` and `10.8.1.0/24`
for SSH, phone approvals, and the admin page. The installer adds a separate VPN-only SSH firewall rule, preserving
the existing local-subnet rule. The guided installer lets you skip those VPN ranges or enter custom CIDRs.
For cloud hosts, choose Cloud access in the wizard; it can open the Windows firewall for TCP 22 and 47810 from any
remote address, with TCP 47820 optional. Set the matching provider security-group rules separately.

The installer builds the new app and its pinned dependencies in a private staging directory, import-checks them, then
swaps them in. If the service or previously enabled web task fails its startup check, it restores the prior app and
scheduled task definitions. The last working app is kept under `C:\ProgramData\ThessleyPamWin\backups`; user keys,
passes, web settings and certificates remain outside the app directory. Dependencies are installed beside the app,
not into machine-wide Python.

You can also install over an existing SSH connection. First install and test Windows OpenSSH independently, then connect
with an interactive PowerShell session and confirm it has an administrator token. Use the hosted one-line bootstrap or
transfer this package and run `guided-install.ps1`. Enroll and verify the phone first; keep the current SSH session open
while the wizard applies and tests the SSH gate.

| Piece | What it does |
|---|---|
| `thessley_pam_win/gate.py` | what sshd runs instead of the shell; asks the service, then starts the shell or command |
| `thessley_pam_win/daemon.py` | the approval service (SYSTEM, `127.0.0.1:47800`) |
| `thessley_pam_win/approve.py` | the approval flow: link, QR code, signed answer, passes |
| `thessley_pam_win/cli.py` | `thessley-pam-win enroll / list / remove / grace / passes / status / sshd-config` |
| `thessley_pam_win/store.py`, `grants.py` | approvers and passes under `C:\ProgramData\ThessleyPamWin` |
| `thessley_pam_win/web.py` | the admin web page: sign in with an approval, manage your approvers, settings, activity ([docs/WEB.md](docs/WEB.md), has the Windows steps) |
| `thessley_pam_win/enroll.py`, `peer.py` | adding an approver (shared by the admin tool and the service); finding out which Windows account is on the other end of a local connection |
| `thessley_pam_win/protocol.py` | **copied unchanged** from thessley-pam-linux (`05065e3`); keep byte-identical with the Android app |
| `thessley_pam_win/listener.py` | exclusive-use HTTPS listeners for the web page and the daemon's shared, concurrent SSH approval listener |
| `install/install.ps1`, `uninstall.ps1` | administrator scripts: service, folder permissions, optional firewall rule |

Needs Python 3.12+ installed for all users. The installer fetches the pinned runtime wheels into its private app directory.
Tests: `pip install -e .[test]` then `python -m pytest`.
