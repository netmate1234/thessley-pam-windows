"""thessley-pam-win: manage who may approve ssh logins to this Windows computer.

Anyone may run `enroll` for their OWN account (the approval service checks who is asking and applies the rules in daemon.py).
An administrator may use the same service to add a device for another account. Both use the service-owned TCP 47810 listener.

    thessley-pam-win enroll [--user NAME]            add a phone or the desktop app as an approver (link and QR code, then a code check)
    thessley-pam-win list [--user NAME]              show approvers
    thessley-pam-win remove --user NAME ID           forget an approver (its passes end with it)
    thessley-pam-win disable|enable --user NAME ID   switch an approver off or on without forgetting it
    thessley-pam-win grace [--hours H]               show or set how long one approval counts (0 = every login asks)
    thessley-pam-win passes                          who holds a pass right now
    thessley-pam-win end-pass [--user NAME]          end passes at once
    thessley-pam-win self-enroll [on|off]            may an account with no approver enrol its first one itself
    thessley-pam-win status                          is the approval service running, and what is set
    thessley-pam-win ad-enroll --server URL --tls-sha256 HASH   pair this PC with the standalone AD service
    thessley-pam-win ad-status                       show standalone AD machine pairing
    thessley-pam-win ad-check                        verify pinned TLS and machine authentication
    thessley-pam-win sshd-config --user NAME [--factor password|key|key-password]
                                                    print a safe sshd_config block (QR approval always follows)
"""

import argparse
import ctypes
import datetime
import json
import os
import queue
import socket
import subprocess
import sys
import threading

from . import ad_agent, drupal_agent, enroll, grants, machine, qr, ssh_policy, store
from .daemon import HOST, PORT
from .gate import current_user

CONFIRM_WAIT = enroll.CONFIRM_WAIT
GATE_SCRIPT = os.path.join(store.BASE, "app", "gate_main.py")


def _need_admin() -> None:
    if not _is_admin():
        sys.exit("Run this in an administrator terminal: it changes who may log in to this computer.")


def _user(arg: str | None) -> str:
    if not arg:
        sys.exit("Say which Windows account with --user NAME.")
    try:
        return store.normalize_user(arg)
    except ValueError as e:
        sys.exit(str(e))


def _ask_yes(prompt: str, timeout: int) -> bool:
    """A yes typed by a person at this terminal, within `timeout` seconds."""
    answer: queue.Queue = queue.Queue()

    def read():
        try:
            answer.put(input(prompt))
        except EOFError:
            answer.put("")
    threading.Thread(target=read, daemon=True).start()
    try:
        return answer.get(timeout=timeout).strip().lower() in ("y", "yes")
    except queue.Empty:
        print("\nNo answer in time.")
        return False


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _enroll_via_service(username: str, op: str = "enroll") -> int:
    """The service verifies the caller and handles enrollment on its one shared phone port."""
    try:
        sock = socket.create_connection((HOST, PORT), timeout=5)
    except OSError:
        print("The approval service is not running, so nothing can be added. Ask an administrator.")
        return 1
    with sock:
        sock.settimeout(None)
        sock.sendall((json.dumps({"op": op, "user": username}) + "\n").encode("utf-8"))
        stream = sock.makefile("rw", encoding="utf-8")
        for raw in stream:
            msg = json.loads(raw)
            if "say" in msg:
                print(msg["say"], flush=True)
            if "ask" in msg:
                answer = "yes" if _ask_yes(msg["ask"], int(msg.get("timeout", CONFIRM_WAIT))) else "no"
                stream.write(json.dumps({"answer": answer}) + "\n")
                stream.flush()
            if msg.get("done"):
                return 0 if msg.get("ok") else 1
    print("The approval service closed the connection. Nothing was added.")
    return 1


def cmd_enroll(args) -> int:
    me = store.normalize_user(current_user())
    target = _user(args.user) if args.user else me
    if _is_admin():  # administrator terminal: runs here, in this process, and may add an approver for any account
        return _enroll_via_service(target, "admin-enroll")
    if target != me:
        sys.exit("Only an administrator can add an approver for another account. For your own account, leave out --user.")
    return _enroll_via_service(target)


def cmd_self_enroll(args) -> int:
    _need_admin()
    if args.state in ("on", "off"):
        grants.set_self_enroll_first(args.state == "on")
    if grants.self_enroll_first():
        print("On: an account with no approver at all may enrol its first one itself (from a session on this computer).")
    else:
        print("Off: only an administrator can add the first approver of an account.")
    print("Adding more approvers always needs an approval from one that is already enrolled, or an administrator.")
    return 0


def cmd_list(args) -> int:
    _need_admin()
    names = [_user(args.user)] if args.user else sorted(
        n[:-5] for n in os.listdir(store.users_dir()) if n.endswith(".json") and not n.startswith("."))
    shown = False
    for username in names:
        for d in store.devices(username):
            when = datetime.datetime.fromtimestamp(d["enrolled_at"]).strftime("%Y-%m-%d %H:%M")
            att = d.get("attestation") or {}
            proof = (f"  TPM verified ({(att.get('maker', '') + ' ' + att.get('model', '')).strip() or 'maker not named'})" if att.get("level") == "tpm"
                     else "  TPM claimed, not verified" if att.get("level") == "unverified" else "")
            print(f"{username:<16} {d['credential_id']}  {d['label']:<24} enrolled {when}" + proof + ("  (disabled)" if d.get("disabled") else ""))
            shown = True
    if not shown:
        print("No approvers enrolled.")
    return 0


def cmd_remove(args) -> int:
    _need_admin()
    username = _user(args.user)
    if store.remove_device(username, args.credential_id):
        print(f"Removed {args.credential_id} for {username}.")
        return 0
    print(f"No approver {args.credential_id} for {username}.")
    return 1


def cmd_disable(args, disabled: bool = True) -> int:
    _need_admin()
    username = _user(args.user)
    if store.set_disabled(username, args.credential_id, disabled):
        print(f"{'Disabled' if disabled else 'Enabled'} {args.credential_id} for {username}.")
        return 0
    print(f"No approver {args.credential_id} for {username}.")
    return 1


def cmd_grace(args) -> int:
    _need_admin()
    if args.hours is not None:
        grants.set_grace(args.hours, args.ip_scope)
        if args.hours <= 0:
            print(f"Passes ended: {grants.revoke()}")
    hours = grants.grace_hours()
    scope = "any client IP" if grants.grace_any_ip() else "the same client IP"
    print(f"One approval counts for {hours:g} h from {scope}." if hours else "Every ssh login asks for an approval.")
    return 0


def cmd_passes(args) -> int:
    _need_admin()
    live = grants.all_passes()
    if not live:
        print("No passes.")
    for p in live:
        username = p.get("display_user") or p["user"]
        print(f"{username:<32} from {p['rhost']:<18} {grants.remaining(p)} left   (approved by {p['credential']})")
    return 0


def cmd_end_pass(args) -> int:
    _need_admin()
    print(f"Ended {grants.revoke(_user(args.user) if args.user else None)} pass(es).")
    return 0


def cmd_status(args) -> int:
    try:
        socket.create_connection((HOST, PORT), timeout=2).close()
        print(f"Approval service: running ({HOST}:{PORT}).")
    except OSError:
        print("Approval service: NOT running. ssh logins that use the gate are refused.")
    print(f"Data folder: {store.BASE}")
    print(f"Pass length: {grants.grace_hours():g} h" if grants.grace_hours() else "Pass length: off (every login asks)")
    return 0


def cmd_ssh_defaults(args) -> int:
    _need_admin()
    backup, added, skipped = ssh_policy.enable_default_policies()
    if added:
        print("QR approval enabled for: " + ", ".join(added))
        print("Current OpenSSH key/password settings are preserved. Accounts with no enrolled phone use the configured fallback.")
        print(f"Validated sshd_config backup: {backup}")
    else:
        print("No new QR policies were needed.")
    if skipped:
        print("Not changed: " + ", ".join(skipped))
    return 0


def cmd_drupal_setup(args) -> int:
    """Create the prototype's protected agent key and print Drupal form values."""
    _need_admin()
    try:
        values = drupal_agent.initialize(args.user, args.server, args.tls_sha256)
    except (drupal_agent.AgentError, OSError, ValueError) as exc:
        sys.exit(f"Could not prepare the Drupal Windows agent: {exc}")
    print("Prototype agent identity created. Import these fields in Thessley Windows Access > Enroll Windows account:")
    print(json.dumps(values, indent=2, ensure_ascii=False))
    print("The private key stays in the SYSTEM/Administrators-only ProgramData folder. It is a software key, not TPM-backed.")
    print("Windows sign-in will use the Drupal server for phone approval for this account; local approval remains for other accounts.")
    return 0


def cmd_drupal_enroll(args) -> int:
    """Submit this PC's account details using a short-lived Drupal pairing code."""
    _need_admin()
    try:
        result = drupal_agent.submit_pairing(args.user, args.pair_code, args.server, args.tls_sha256)
    except (drupal_agent.AgentError, OSError, ValueError) as exc:
        sys.exit(f"Windows enrollment was not confirmed: {exc}\nThe protected PC key was kept so you can retry with a fresh Drupal pairing code.")
    link = result["app_link"]
    print(f"Windows account registered: {result.get('account', args.user)} on {result.get('machine', machine.hostname())}.")
    print("Scan this enrollment QR with Thessley Passkey. The request expires in five minutes:")
    rows = qr.lines(link, border=1)
    if rows:
        print("\n".join(rows))
        print("If the QR is clipped, open this complete one-time link in Thessley Passkey:")
        print(link)
    else:
        print("QR support is unavailable in this installation. Open this link on the phone:")
        print(link)
    return 0


def cmd_drupal_enroll_v2(args) -> int:
    """Enroll one local/domain Windows principal, identified by its account SID."""
    _need_admin()
    try:
        result = drupal_agent.submit_pairing_v2(
            args.user, args.scope, args.authority, args.pair_code, args.server, args.tls_sha256,
        )
    except (drupal_agent.AgentError, OSError, ValueError) as exc:
        sys.exit(f"Windows SID enrollment was not confirmed: {exc}\nThe protected PC key was kept so you can retry with a fresh Drupal pairing code.")
    link = result["app_link"]
    print(f"Windows {args.scope} account registered: {result.get('account', args.user)} on {result.get('machine', machine.hostname())}.")
    print("Scan this enrollment QR with Thessley Passkey. The request expires in five minutes:")
    rows = qr.lines(link, border=1)
    if rows:
        print("\n".join(rows))
        print("If the QR is clipped, open this complete one-time link in Thessley Passkey:")
        print(link)
    else:
        print("QR support is unavailable in this installation. Open this link on the phone:")
        print(link)
    return 0


def cmd_ad_enroll(args) -> int:
    """Pair this Windows machine with the standalone AD service."""
    _need_admin()
    import getpass

    code = (args.code or "").strip()
    if not code:
        code = getpass.getpass("One-time Thessley AD machine enrollment code: ").strip()
    try:
        machine_id = ad_agent.enroll_machine(args.server, args.tls_sha256, code)
    except (ad_agent.AgentError, OSError, ValueError) as exc:
        sys.exit(f"Windows machine enrollment was not confirmed: {exc}")
    print(f"This Windows machine is paired with the standalone AD service ({machine_id}).")
    print("The machine signing key is DPAPI protected and restricted to SYSTEM and local Administrators.")
    print("This pairs the computer only; a domain account still needs its own phone enrollment and a Windows certificate sign-in provider.")
    return 0


def cmd_ad_status(_args) -> int:
    if not ad_agent.configured():
        print("This Windows machine is not paired with the standalone Thessley AD service.")
        return 1
    try:
        config, _key, host, port, pin = ad_agent._load()
    except ad_agent.AgentError as exc:
        print(f"Standalone AD machine configuration needs repair: {exc}")
        return 1
    print(f"Standalone AD service: https://{host}:{port}")
    print(f"Machine ID: {config['machine_id']}")
    print(f"Certificate SHA-256: {pin}")
    return 0


def cmd_ad_check(_args) -> int:
    try:
        result = ad_agent.check_connection()
    except (ad_agent.AgentError, OSError, ValueError) as exc:
        sys.exit(f"Standalone AD service check failed: {exc}")
    print(f"Standalone AD service authenticated this computer ({result['machine_id']}).")
    return 0


WEB_TASK = "ThessleyPamWinWeb"


def _task(*args: str) -> subprocess.CompletedProcess:
    # schtasks answers in the console's code page (on a French Windows with accents); only the exit code matters here, so a
    # byte that is not valid UTF-8 must not raise
    return subprocess.run(["schtasks", *args], capture_output=True, text=True, errors="replace", check=False)


def web_page_host(st: dict) -> tuple[str, str | None]:
    """The address the one-time first-phone link must name, and a problem to report if the page does not answer there.

    The page records the address it really listens on; a guess (the default-route address) can differ from it when the computer has
    several adapters (Wi-Fi plus a VPN adapter), which gives a link to an address nothing listens on."""
    port = int(st["port"])
    recorded = ""
    try:
        with open(os.path.join(store.BASE, "web", "listening.txt"), encoding="ascii") as f:
            host, _, rec_port = f.read().strip().partition(" ")
        if host and rec_port == str(port):
            recorded = host
    except OSError:
        pass
    listen = st["listen"]
    guess = listen if listen and listen not in ("0.0.0.0", "::") else ""
    if not guess:
        try:
            guess = machine.lan_ip()
        except OSError:
            guess = ""
    for host in dict.fromkeys(h for h in (recorded, guess) if h):
        try:
            with socket.create_connection((host, port), timeout=3):
                return host, None
        except OSError:
            continue
    tried = ", ".join(dict.fromkeys(h for h in (recorded, guess) if h)) or "no address"
    return (recorded or guess), (f"The admin page does not answer on port {port} at {tried}. Check that the web task is running "
                                 f"(thessley-pam-win web status) and that this computer has a network address the phone can reach.")


def cmd_web(args) -> int:
    """The admin web page: settings, and the scheduled task that runs it (see web.py)."""
    action, values = args.action or "status", args.values
    if action == "serve":
        from . import web
        return web.serve()
    _need_admin()
    if action == "bootstrap":
        if not args.user:
            sys.exit("Usage: thessley-pam-win web bootstrap --user ADMIN_ACCOUNT")
        if not grants.web_settings()["enabled"]:
            sys.exit("Turn on the admin web page first: thessley-pam-win web on")
        username = _user(args.user)
        from . import web
        if not web.is_admin(username):
            sys.exit("The bootstrap account must be a member of the local Administrators group.")
        st = grants.web_settings()
        if st["localhost_only"]:
            sys.exit("The web page is restricted to this computer. Temporarily allow LAN access before issuing a first-phone link.")
        ip, problem = web_page_host(st)  # before the token exists: a link nobody can open must not block the next one
        if problem:
            sys.exit(problem)
        try:
            token, code, expires = grants.create_web_bootstrap(username, replace_active=args.replace_active)
        except ValueError as exc:
            sys.exit(str(exc))
        print("\nFIRST-PHONE ENROLLMENT LINK - copy this complete line:")
        print(f"https://{ip}:{st['port']}/{token}")
        print(f"ONE-TIME SETUP CODE (expires in 10 minutes): {code}")
        print(f"This enrolls only the first phone for {username}; it cannot open settings or other accounts.")
        return 0
    if action in ("on", "off"):
        if (action == "on" and grants.web_settings()["port"] == 47820
                and _task("/Query", "/TN", "ThessleyADApi").returncode == 0):
            sys.exit("The Thessley AD service is installed on this computer and owns TCP 47820 "
                     "(its /admin/ page). Leave the PAM web page off, or give it another port first: "
                     "thessley-pam-win web port NUMBER.")
        grants.set_web(enabled=(action == "on"))
        if action == "on":
            _task("/Change", "/TN", WEB_TASK, "/ENABLE")
            _task("/End", "/TN", WEB_TASK)  # a restart picks up new settings
            started = _task("/Run", "/TN", WEB_TASK)
            if started.returncode != 0:
                print("The web page's task is not installed yet: re-run install\\install.ps1 (it creates it).")
        else:
            _task("/End", "/TN", WEB_TASK)
            _task("/Change", "/TN", WEB_TASK, "/DISABLE")
    elif action == "listen":
        grants.set_web(listen=(values[0] if values and values[0] not in ("auto", "lan") else ""))
    elif action in ("port", "session"):
        if len(values) != 1 or not values[0].isdigit():
            sys.exit(f"Usage: thessley-pam-win web {action} NUMBER")
        grants.set_web(**({"port": int(values[0])} if action == "port" else {"session_minutes": int(values[0])}))
    elif action == "cert":
        if len(values) != 2:
            sys.exit("Usage: thessley-pam-win web cert CERT_FILE KEY_FILE   (a certificate your browsers trust)")
        grants.set_web(cert=values[0], key=values[1])
    elif action != "status":
        sys.exit("Say status, on, off, serve, listen, port, session, cert or bootstrap --user ADMIN_ACCOUNT.")
    from . import web
    st = grants.web_settings()
    ip = "127.0.0.1" if st["localhost_only"] else (st["listen"] or machine.lan_ip())
    cert, _ = (st["cert"], st["key"]) if st["cert"] and st["key"] else web.default_cert_paths()
    print(f"Admin page base URL ({'ON' if st['enabled'] else 'off'}; first-phone enrollment uses a separate one-time link): https://{ip}:{st['port']}/   (sessions end after {st['session_minutes']} min idle)")
    if os.path.exists(cert):
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with open(cert, "rb") as f:
            der = x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)
        print(f"Certificate SHA-256: {hashlib.sha256(der).hexdigest()}")
    if st["listen"] in ("0.0.0.0", "::"):
        print("It listens on every network address: make sure only networks you trust can reach this port.")
    return 0


def cmd_sshd_config(args) -> int:
    username = _user(args.user)
    factor = args.factor
    if factor == "password":
        first_factor = """    PasswordAuthentication yes
    PubkeyAuthentication no
    AuthenticationMethods password"""
    elif factor == "key":
        first_factor = """    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey"""
    else:
        first_factor = """    PasswordAuthentication yes
    PubkeyAuthentication yes
    AuthenticationMethods publickey,password"""
    force_command = f'"{sys.executable}" -I -X utf8 "{GATE_SCRIPT}"'
    print(f"""Add this to C:\\ProgramData\\ssh\\sshd_config in the correct Match User section (see docs before changing it):

Match User {username}
{first_factor}
    KbdInteractiveAuthentication no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY yes
    ForceCommand {force_command}

Check it first with:   & "$env:WINDIR\\System32\\OpenSSH\\sshd.exe" -t      (or C:\\Program Files\\OpenSSH\\sshd.exe -t)
Then (administrator):  Restart-Service sshd
Keep one working session open while you try a new login.

This first factor is followed by phone QR approval via the gate. Windows OpenSSH starts the gate only after
authentication; QR-only and bypass-on-QR-failure policies are not supported by this Windows design.""")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="thessley-pam-win", description="Approve ssh logins to this Windows computer with Thessley Passkey")
    sub = p.add_subparsers(dest="cmd", required=True)
    en = sub.add_parser("enroll", help="add a phone or the desktop app as an approver")
    en.add_argument("--user", help="administrators only: another account (default: your own)")
    en.add_argument("--link", action="store_true", help="accepted, no longer needed: the link is always printed (as in thessley-pam-linux)")
    ls = sub.add_parser("list", help="show approvers")
    ls.add_argument("--user")
    rm = sub.add_parser("remove", help="forget an approver")
    rm.add_argument("--user")
    rm.add_argument("credential_id")
    for name in ("disable", "enable"):
        d = sub.add_parser(name, help=f"{name} an approver without forgetting it")
        d.add_argument("--user")
        d.add_argument("credential_id")
    g = sub.add_parser("grace", help="show or set how long one approval counts")
    g.add_argument("--hours", type=float)
    g.add_argument("--ip-scope", choices=("same", "any"), help="limit the pass to its original client IP, or allow any IP")
    sub.add_parser("passes", help="who holds a pass")
    ep = sub.add_parser("end-pass", help="end passes")
    ep.add_argument("--user")
    sub.add_parser("status", help="is the service running")
    sub.add_parser("ssh-defaults", help="require QR approval for current local SSH accounts, with setup fallback")
    se = sub.add_parser("self-enroll", help="may an account with no approver enrol its first one itself")
    se.add_argument("state", nargs="?", choices=["on", "off"])
    wb = sub.add_parser("web", help="the admin web page: sign in with an approval, manage your approvers")
    wb.add_argument("action", nargs="?", choices=("status", "on", "off", "serve", "listen", "port", "session", "cert", "bootstrap"))
    wb.add_argument("values", nargs="*")
    wb.add_argument("--user", help="administrator account for one-time first-phone setup")
    wb.add_argument("--replace-active", action="store_true", help="invalidate an existing active first-phone link and issue a new one")
    sc = sub.add_parser("sshd-config", help="the sshd_config lines for a user")
    sc.add_argument("--user")
    sc.add_argument("--factor", choices=("password", "key", "key-password"), default="password",
                    help="required sshd first factor(s); phone QR approval still follows")
    ds = sub.add_parser("drupal-setup", help="prepare an account key for the distributed Drupal login prototype")
    ds.add_argument("--user", required=True, help="local Windows account to enroll")
    ds.add_argument("--server", required=True, help="HTTPS Drupal site origin")
    ds.add_argument("--tls-sha256", required=True, help="64-character certificate fingerprint from Drupal settings")
    de = sub.add_parser("drupal-enroll", help="enroll this Windows account with a one-time Drupal pairing code")
    de.add_argument("--user", required=True, help="local Windows account to enroll")
    de.add_argument("--server", required=True, help="HTTPS Drupal site origin")
    de.add_argument("--tls-sha256", required=True, help="64-character certificate fingerprint from Drupal settings")
    de.add_argument("--pair-code", required=True, help="eight-digit one-time code from the Drupal enrollment page")
    de2 = sub.add_parser("drupal-enroll-v2", help="enroll a SID-scoped local or domain Windows account")
    de2.add_argument("--user", required=True, help="short Windows account name")
    de2.add_argument("--scope", choices=("local", "domain"), required=True, help="local account or domain principal")
    de2.add_argument("--authority", default="", help="domain NetBIOS name; omitted for a local account")
    de2.add_argument("--server", required=True, help="HTTPS Drupal site origin")
    de2.add_argument("--tls-sha256", required=True, help="64-character certificate fingerprint from Drupal settings")
    de2.add_argument("--pair-code", required=True, help="eight-digit one-time code from the Drupal enrollment page")
    ad = sub.add_parser("ad-enroll", help="pair this computer with the standalone Thessley AD service")
    ad.add_argument("--server", required=True, help="pinned HTTPS origin of the standalone AD service")
    ad.add_argument("--tls-sha256", required=True, help="64-character certificate fingerprint from the service")
    ad.add_argument("--code", default=None,
                    help="one-time pairing code; omit to be asked for it without echoing")
    sub.add_parser("ad-status", help="show whether this computer is paired with the standalone AD service")
    sub.add_parser("ad-check", help="verify pinned TLS and machine authentication with the standalone AD service")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # the QR code is drawn with block characters
    a = p.parse_args(argv)
    return {
        "enroll": cmd_enroll, "list": cmd_list, "remove": cmd_remove,
        "disable": lambda x: cmd_disable(x, True), "enable": lambda x: cmd_disable(x, False),
        "grace": cmd_grace, "passes": cmd_passes, "end-pass": cmd_end_pass, "status": cmd_status,
        "ssh-defaults": cmd_ssh_defaults,
        "sshd-config": cmd_sshd_config, "self-enroll": cmd_self_enroll, "web": cmd_web,
        "drupal-setup": cmd_drupal_setup,
        "drupal-enroll": cmd_drupal_enroll,
        "drupal-enroll-v2": cmd_drupal_enroll_v2,
        "ad-enroll": cmd_ad_enroll,
        "ad-status": cmd_ad_status,
        "ad-check": cmd_ad_check,
    }[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
