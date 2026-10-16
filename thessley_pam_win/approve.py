"""The approval step of an ssh login: ask the user's enrolled approvers (phone, desktop app) and wait for a signed answer.

Same flow and wire protocol as thessley-pam-linux (pam.py). Runs inside the service (SYSTEM), which sends every line
passed to `say` on to the person's ssh terminal. Returns True only for a valid, signed "approve" from one of the
user's active approvers, or for a pass from an earlier approval. Everything else (deny, timeout, bad signature,
unreachable phone, no approver enrolled, any error) returns False: refused by default.
"""

import contextlib
import errno
import hmac
import os
import re
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


def _display_fields(service: str, rhost: str) -> dict:
    """Optional link fields the apps show ("ssh login from 192.168.1.111" instead of a bare "sudo"). Display only:
    the signature does not cover them, so a wrong value can mislead a person but never approve anything."""
    out = {}
    svc = re.sub(r"[^a-z0-9_-]", "", service.lower())[:32]
    if svc:
        out["s"] = svc
    if rhost and rhost != grants.LOCAL and re.fullmatch(r"[0-9A-Fa-f.:]{1,45}", rhost):
        out["r"] = rhost
    return out


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
            if e.errno != errno.EADDRINUSE and getattr(e, "winerror", 0) not in (10048, 10013):  # in use / exclusive-use clash
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
        *, ip: str | None = None, port: int = PORT, wait: float = WAIT, cancel: threading.Event | None = None,
        use_pass: bool = True, grant_pass: bool = True) -> bool:
    """Ask for an approval for `username` logging in from `rhost`. `say(line)` shows a line to the person.

    `use_pass=False` ignores an existing pass and `grant_pass=False` records none: used when the approval is for adding
    an approver, which must never ride on a pass."""
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
    if grace > 0 and use_pass:
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
            # A "deny" may come without a signature (the phone does not ask for a fingerprint to say no); it must then
            # carry the request's nonce, which only the person who saw the link has. A refusal grants nothing.
            signature = str(body["signature"]) if "signature" in body else ""
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        device = by_id.get(cred)
        if device is None:
            return 403, {"result": "error", "message": "This phone is not enrolled for this user here."}
        if action not in ("approve", "deny"):
            return 400, {"result": "error", "message": "Unknown action."}
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Phone clock is off by more than a minute."}
        unsigned = not signature
        if unsigned:
            # compared as bytes: a non-ASCII value must be a plain mismatch, not an error
            if action != "deny" or not hmac.compare_digest(str(body.get("nonce", "")).encode("utf-8"), nonce.encode("utf-8")):
                log(f"unsigned answer refused from {client_ip} for {username} ({cred}, {action})", True)
                return 400, {"result": "error", "message": "Only a refusal can be sent without a signature."}
        else:
            msg = protocol.canonical(REQUEST_TYPE, request_id, mid, username, nonce, timestamp, action)
            if not protocol.verify(device["public_key"], signature, msg):
                log(f"bad signature from {client_ip} for {username} ({cred})", True)
                return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This request has already been answered."}
        outcome.update(action=action, cred=cred, label=device.get("label", ""), ip=client_ip, unsigned=unsigned)
        done.set()
        return 200, {"result": "ok"}

    path = f"/thessley-pam/v1/{REQUEST_TYPE}/{request_id}/respond"
    try:
        with _listening(ip, {path: respond}, port) as lst:
            link = f"thessleypam://{REQUEST_TYPE}?" + urlencode({
                "h": ip, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
                "m": mid, "hn": host, "u": username, "tty": tty,
                **(_display_fields("sshd", rhost) if tty == "ssh" else {}),
            })
            what = "adding a device for" if tty == "add-device" else "the ssh login for"
            say(f"Approve {what} {username} on {host} with Thessley Passkey (within {int(wait)} s):")
            say(f"Link: {link}")  # above the QR code, so it stays in view when the code scrolls the screen
            for line in qr.lines(link, border=2):
                say(line)
            if grace > 0 and grant_pass:
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
        how = ", no signature" if outcome.get("unsigned") else ""
        log(f"denied by {outcome['label']!r} ({outcome['cred']}{how}) for {username} (from {rhost})", True)
        return False

    try:
        store.touch(username, outcome["cred"])
    except OSError:
        pass  # last_used is informational; never fail a valid approval over it
    if grace > 0 and grant_pass:
        try:
            grants.add(username, rhost, grace, outcome["cred"])
            say(f"Thessley Passkey: approved. Your next login from {rhost} needs no approval for {grace:g} h.")
            log(f"pass granted to {username} (from {rhost}, {grace:g} h)", False)
        except OSError as e:
            log(f"could not record the pass for {username}: {e}", True)  # the login itself is still approved
    log(f"approved by {outcome['label']!r} ({outcome['cred']}) from {outcome['ip']} for {username} (from {rhost})", False)
    return True
