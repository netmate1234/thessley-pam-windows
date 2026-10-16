"""thessley-pam-win: manage who may approve ssh logins to this Windows computer. Run it in an administrator terminal.

    thessley-pam-win enroll --user NAME [--link]     add a phone or the desktop app as an approver (QR code, then a code check)
    thessley-pam-win list [--user NAME]              show approvers
    thessley-pam-win remove --user NAME ID           forget an approver (its passes end with it)
    thessley-pam-win disable|enable --user NAME ID   switch an approver off or on without forgetting it
    thessley-pam-win grace [--hours H]               show or set how long one approval counts (0 = every login asks)
    thessley-pam-win passes                          who holds a pass right now
    thessley-pam-win end-pass [--user NAME]          end passes at once
    thessley-pam-win status                          is the approval service running, and what is set
    thessley-pam-win sshd-config --user NAME         the lines to add to sshd_config for that user
"""

import argparse
import ctypes
import datetime
import queue
import secrets
import socket
import sys
import threading
from urllib.parse import urlencode

from . import approve, grants, machine, protocol, qr, store
from .daemon import HOST, PORT
from .listener import Listener  # noqa: F401  (approve._listening wraps it)

ENROLL_WAIT = 180   # seconds the QR code stays valid
CONFIRM_WAIT = 90   # seconds to type "yes" once the codes are shown
GATE = r"C:\ProgramData\ThessleyPamWin\gate.cmd"
LABEL = __import__("re").compile(r"^[\w .,'()+-]{1,64}$")


def _need_admin() -> None:
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        is_admin = False
    if not is_admin:
        sys.exit("Run this in an administrator terminal: it changes who may log in to this computer.")


def _user(arg: str | None) -> str:
    if not arg:
        sys.exit("Say which Windows account with --user NAME.")
    try:
        return store.normalize_user(arg)
    except ValueError as e:
        sys.exit(str(e))


def _show_qr(link: str) -> None:
    for line in qr.lines(link, border=2):
        print(line)


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


def cmd_enroll(args) -> int:
    _need_admin()
    username = _user(args.user)
    mid, host, ip = machine.machine_id(), machine.hostname(), machine.lan_ip()
    request_id = secrets.token_urlsafe(12)
    nonce = secrets.token_urlsafe(16)

    pending: queue.Queue = queue.Queue(maxsize=1)  # the one verified approver waiting for the person's yes/no
    decided = threading.Event()
    decision: dict = {}
    taken = threading.Lock()

    def respond(client_ip: str, body: dict) -> tuple[int, dict]:
        try:
            public_key = str(body["public_key"])
            signature = str(body["proof_signature"])
            timestamp = int(body["timestamp"])
            label = str(body.get("label") or "Phone").strip()
            chain = [str(c) for c in body.get("attestation_chain") or []][:10]
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        if not LABEL.match(label):
            label = "Phone"
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Phone clock is off by more than a minute."}
        msg = protocol.canonical("enroll", request_id, mid, username, nonce, timestamp, "register")
        if not protocol.verify(public_key, signature, msg):
            return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This code has already been used."}
        pending.put({"client_ip": client_ip, "public_key": public_key, "label": label, "chain": chain})
        if not decided.wait(CONFIRM_WAIT + 10) or not decision.get("ok"):
            return 200, {"result": "denied", "message": "Not confirmed on the computer."}
        return 200, {"result": "ok", "credential_id": decision["credential_id"], "username": username, "hostname": host}

    path = f"/thessley-pam/v1/enroll/{request_id}/respond"
    with approve._listening(ip, {path: respond}, args.port) as lst:
        link = "thessleypam://enroll?" + urlencode({
            "h": ip, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
            "m": mid, "hn": host, "u": username,
        })
        print(f"\nAdd a phone or app that may approve ssh logins for '{username}' on {host}.\n")
        _show_qr(link)
        if args.link:
            print(f"Link: {link}\n")  # for the Thessley Passkey desktop app, which cannot scan a code
        print(f"In Thessley Passkey: scan the QR code (or paste the link). Valid for {ENROLL_WAIT // 60} minutes. Ctrl+C to cancel.",
              flush=True)
        try:
            item = pending.get(timeout=ENROLL_WAIT)
        except queue.Empty:
            print("Timed out. Nothing was added.")
            return 1
        code = protocol.pairing_code(item["public_key"])
        print(f"\n'{item['label']}' ({item['client_ip']}) answered.\n\n    Code:  {code}\n")
        ok = _ask_yes("Does it show the same code? Type yes to add it: ", CONFIRM_WAIT)
        if ok:
            device = store.add_device(username, item["public_key"], item["label"], item["chain"])
            decision.update(ok=True, credential_id=device["credential_id"])
        decided.set()
        threading.Event().wait(1.5)  # let the answer reach the phone before the listener shuts down
    if ok:
        print(f"Added '{item['label']}' as {decision['credential_id']} for {username}.")
        return 0
    print("Not added.")
    return 1


def cmd_list(args) -> int:
    _need_admin()
    names = [_user(args.user)] if args.user else sorted(
        n[:-5] for n in __import__("os").listdir(store.users_dir()) if n.endswith(".json") and not n.startswith("."))
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
    en.add_argument("--user")
    en.add_argument("--link", action="store_true", help="also print the link (for the desktop app)")
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
    sc = sub.add_parser("sshd-config", help="the sshd_config lines for a user")
    sc.add_argument("--user")
    a = p.parse_args(argv)
    return {
        "enroll": cmd_enroll, "list": cmd_list, "remove": cmd_remove,
        "disable": lambda x: cmd_disable(x, True), "enable": lambda x: cmd_disable(x, False),
        "grace": cmd_grace, "passes": cmd_passes, "end-pass": cmd_end_pass, "status": cmd_status,
        "sshd-config": cmd_sshd_config,
    }[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
