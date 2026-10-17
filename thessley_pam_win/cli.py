"""thessley-pam-win: manage who may approve ssh logins to this Windows computer.

Anyone may run `enroll` for their OWN account (the approval service checks who is asking and applies the rules in daemon.py).
Everything else needs an administrator terminal.

    thessley-pam-win enroll [--user NAME]            add a phone or the desktop app as an approver (link and QR code, then a code check)
    thessley-pam-win list [--user NAME]              show approvers
    thessley-pam-win remove --user NAME ID           forget an approver (its passes end with it)
    thessley-pam-win disable|enable --user NAME ID   switch an approver off or on without forgetting it
    thessley-pam-win grace [--hours H]               show or set how long one approval counts (0 = every login asks)
    thessley-pam-win passes                          who holds a pass right now
    thessley-pam-win end-pass [--user NAME]          end passes at once
    thessley-pam-win self-enroll [on|off]            may an account with no approver enrol its first one itself
    thessley-pam-win status                          is the approval service running, and what is set
    thessley-pam-win sshd-config --user NAME         the lines to add to sshd_config for that user
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

from . import approve, enroll, grants, machine, store
from .daemon import HOST, PORT
from .gate import current_user

CONFIRM_WAIT = enroll.CONFIRM_WAIT
GATE = r"C:\ProgramData\ThessleyPamWin\gate.cmd"


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


def _enroll_via_service(username: str) -> int:
    """A normal user adding an approver for their own account: the service checks who is asking and what is allowed."""
    try:
        sock = socket.create_connection((HOST, PORT), timeout=5)
    except OSError:
        print("The approval service is not running, so nothing can be added. Ask an administrator.")
        return 1
    with sock:
        sock.settimeout(None)
        sock.sendall((json.dumps({"op": "enroll", "user": username}) + "\n").encode("utf-8"))
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
        return 0 if enroll.run(target, print, _ask_yes, port=args.port) else 1  # the link is always printed, above the QR code
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
            print(f"{username:<16} {d['credential_id']}  {d['label']:<24} enrolled {when}" + ("  (disabled)" if d.get("disabled") else ""))
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
        grants.set_grace(args.hours)
        if args.hours <= 0:
            print(f"Passes ended: {grants.revoke()}")
    hours = grants.grace_hours()
    print(f"One approval counts for {hours:g} h from the same address." if hours else "Every ssh login asks for an approval.")
    return 0


def cmd_passes(args) -> int:
    _need_admin()
    live = grants.all_passes()
    if not live:
        print("No passes.")
    for p in live:
        print(f"{p['user']:<16} from {p['rhost']:<18} {grants.remaining(p)} left   (approved by {p['credential']})")
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


WEB_TASK = "ThessleyPamWinWeb"


def _task(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True, check=False)


def cmd_web(args) -> int:
    """The admin web page: settings, and the scheduled task that runs it (see web.py)."""
    action, values = args.action or "status", args.values
    if action == "serve":
        from . import web
        return web.serve()
    _need_admin()
    if action in ("on", "off"):
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
        sys.exit("Say status, on, off, serve, listen, port, session or cert.")
    from . import web
    st = grants.web_settings()
    ip = st["listen"] or machine.lan_ip()
    cert, _ = (st["cert"], st["key"]) if st["cert"] and st["key"] else web.default_cert_paths()
    print(f"Admin web page: {'ON' if st['enabled'] else 'off'}   https://{ip}:{st['port']}/   (sessions end after {st['session_minutes']} min idle)")
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
    print(f"""Add this to the END of C:\\ProgramData\\ssh\\sshd_config (a Match block must be last), then restart sshd:

Match User {username}
    PasswordAuthentication yes
    PubkeyAuthentication no
    KbdInteractiveAuthentication no
    AuthenticationMethods password
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY yes
    ForceCommand {GATE}

Check it first with:   & "$env:WINDIR\\System32\\OpenSSH\\sshd.exe" -t      (or C:\\Program Files\\OpenSSH\\sshd.exe -t)
Then (administrator):  Restart-Service sshd
Keep one working session open while you try a new login.""")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="thessley-pam-win", description="Approve ssh logins to this Windows computer with Thessley Passkey")
    sub = p.add_subparsers(dest="cmd", required=True)
    en = sub.add_parser("enroll", help="add a phone or the desktop app as an approver")
    en.add_argument("--user", help="administrators only: another account (default: your own)")
    en.add_argument("--link", action="store_true", help="accepted, no longer needed: the link is always printed (as in thessley-pam-linux)")
    en.add_argument("--port", type=int, default=approve.PORT)
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
    sub.add_parser("passes", help="who holds a pass")
    ep = sub.add_parser("end-pass", help="end passes")
    ep.add_argument("--user")
    sub.add_parser("status", help="is the service running")
    se = sub.add_parser("self-enroll", help="may an account with no approver enrol its first one itself")
    se.add_argument("state", nargs="?", choices=["on", "off"])
    wb = sub.add_parser("web", help="the admin web page: sign in with an approval, manage your approvers")
    wb.add_argument("action", nargs="?", choices=("status", "on", "off", "serve", "listen", "port", "session", "cert"))
    wb.add_argument("values", nargs="*")
    sc = sub.add_parser("sshd-config", help="the sshd_config lines for a user")
    sc.add_argument("--user")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # the QR code is drawn with block characters
    a = p.parse_args(argv)
    return {
        "enroll": cmd_enroll, "list": cmd_list, "remove": cmd_remove,
        "disable": lambda x: cmd_disable(x, True), "enable": lambda x: cmd_disable(x, False),
        "grace": cmd_grace, "passes": cmd_passes, "end-pass": cmd_end_pass, "status": cmd_status,
        "sshd-config": cmd_sshd_config, "self-enroll": cmd_self_enroll, "web": cmd_web,
    }[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
