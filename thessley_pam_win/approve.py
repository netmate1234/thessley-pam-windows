"""The approval step of an ssh login: ask the user's enrolled approvers (phone, desktop app) and wait for a signed answer.

Same flow and wire protocol as thessley-pam-linux (pam.py). Runs inside the service (SYSTEM), which sends every line
passed to `say` on to the person's ssh terminal. Returns True only for a valid, signed "approve" from one of the
user's active approvers, or for a pass from an earlier approval. Everything else (deny, timeout, bad signature,
unreachable phone, no approver enrolled, any error) returns False: refused by default.
"""

import contextlib
import errno
import os
import secrets
import threading
import time
from typing import Callable
from urllib.parse import urlencode

from . import grants, machine, protocol, qr, store
from .listener import Listener

PORT = 47810
PORT_TRIES = 10  # logins at the same time each need a listener; the next free port from PORT is used
WAIT = 60        # seconds to approve
REQUEST_TYPE = "sudo"  # what the apps call an approval for a command-line login (thessley-pam uses the same for ssh)


@contextlib.contextmanager
def _listening(ip: str, routes: dict, port: int = PORT):
    """A listener on `port`, or on the next free port when another login is still waiting for its approval.
    The port travels in the link, so the phone and the desktop app go wherever it ended up."""
    lst = None
    for p in range(port, port + PORT_TRIES):
        candidate = Listener(ip, p, routes)
        try:
            candidate.__enter__()
        except OSError as e:
            if e.errno != errno.EADDRINUSE and getattr(e, "winerror", 0) != 10048:
                raise
            continue
        lst = candidate
        break
    if lst is None:
        raise OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))
    try:
        yield lst
    finally:
        lst.__exit__(None, None, None)


def run(username: str, rhost: str, tty: str, say: Callable[[str], None], log: Callable[[str, bool], None] | None = None,
        *, ip: str | None = None, port: int = PORT, wait: float = WAIT, cancel: threading.Event | None = None) -> bool:
    """Ask for an approval for `username` logging in from `rhost`. `say(line)` shows a line to the person."""
    log = log or (lambda msg, warn=False: None)
    try:
        username = store.normalize_user(username)
        devices = store.active_devices(username)
    except ValueError:
        log(f"unsupported user name {username!r}", True)
        say("Thessley Passkey: this account name is not supported. Refusing.")
        return False
    if not devices:
        say("Thessley Passkey: no phone or app is enrolled for this account, so this login is refused.")
        log(f"no approver for {username}; refused", True)
        return False

    rhost = rhost or grants.LOCAL
    grace = grants.grace_hours()
    if grace > 0:
        try:
            held = grants.valid(username, rhost, {d["credential_id"] for d in devices})
        except OSError:
            held = None
        if held:
            say(f"Thessley Passkey: approved earlier, valid for another {grants.remaining(held)}.")
            log(f"pass used for {username} (from {rhost}, {grants.remaining(held)} left)", False)
            return True

    by_id = {d["credential_id"]: d for d in devices}
    mid, host = machine.machine_id(), machine.hostname()
    ip = ip or machine.lan_ip()
    request_id = secrets.token_urlsafe(12)
    nonce = secrets.token_urlsafe(16)
    done = threading.Event()
    outcome: dict = {}
    taken = threading.Lock()

    def respond(client_ip: str, body: dict) -> tuple[int, dict]:
        try:
            cred = str(body["credential_id"])
            action = str(body["action"])
            timestamp = int(body["timestamp"])
            signature = str(body["signature"])
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        device = by_id.get(cred)
        if device is None:
            return 403, {"result": "error", "message": "This phone is not enrolled for this user here."}
        if action not in ("approve", "deny"):
            return 400, {"result": "error", "message": "Unknown action."}
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Phone clock is off by more than a minute."}
        msg = protocol.canonical(REQUEST_TYPE, request_id, mid, username, nonce, timestamp, action)
        if not protocol.verify(device["public_key"], signature, msg):
            log(f"bad signature from {client_ip} for {username} ({cred})", True)
            return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This request has already been answered."}
        outcome.update(action=action, cred=cred, label=device.get("label", ""), ip=client_ip)
        done.set()
        return 200, {"result": "ok"}

    path = f"/thessley-pam/v1/{REQUEST_TYPE}/{request_id}/respond"
    try:
        with _listening(ip, {path: respond}, port) as lst:
            link = f"thessleypam://{REQUEST_TYPE}?" + urlencode({
                "h": ip, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
                "m": mid, "hn": host, "u": username, "tty": "ssh",
            })
            say(f"Approve the ssh login for {username} on {host} with Thessley Passkey (within {int(wait)} s):")
            say(f"Link: {link}")  # above the QR code, so it stays in view when the code scrolls the screen
            for line in qr.lines(link):
                say(line)
            if grace > 0:
                say(f"After you approve, your next login from {rhost} needs no approval for {grace:g} h.")
            say("Waiting for the approval...")
            deadline = time.monotonic() + wait
            answered = False
            while time.monotonic() < deadline:
                if done.wait(0.5):
                    answered = True
                    break
                if cancel is not None and cancel.is_set():
                    log(f"login of {username} dropped before an answer", False)
                    return False
            time.sleep(0.5)  # let the phone receive its reply before the listener closes
    except OSError as e:
        say(f"Thessley Passkey: could not start ({e.strerror or e}). Refusing.")
        log(f"listener failed for {username}: {e}", True)
        return False

    if not answered:
        say("Thessley Passkey: no answer. Refusing.")
        log(f"timeout for {username} (from {rhost})", True)
        return False
    if outcome["action"] != "approve":
        say("Thessley Passkey: denied.")
        log(f"denied by {outcome['label']!r} ({outcome['cred']}) for {username} (from {rhost})", True)
        return False

    try:
        store.touch(username, outcome["cred"])
    except OSError:
        pass  # last_used is informational; never fail a valid approval over it
    if grace > 0:
        try:
            grants.add(username, rhost, grace, outcome["cred"])
            say(f"Thessley Passkey: approved. Your next login from {rhost} needs no approval for {grace:g} h.")
            log(f"pass granted to {username} (from {rhost}, {grace:g} h)", False)
        except OSError as e:
            log(f"could not record the pass for {username}: {e}", True)  # the login itself is still approved
    log(f"approved by {outcome['label']!r} ({outcome['cred']}) from {outcome['ip']} for {username} (from {rhost})", False)
    return True
