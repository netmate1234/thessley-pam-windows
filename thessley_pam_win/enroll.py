"""Adding an approver (a phone, or the desktop app) for one Windows account.

One flow, used from two places: the administrator command line (in its own process) and the approval service (for a
user enrolling themselves). Both pass in how to show a line (`say`) and how to ask for a typed "yes" (`ask_yes`).

The phone proves it holds its key by signing the enrolment request; the person then compares a 6-digit code on both
screens and types yes. Nothing is stored unless both happen.
"""

import queue
import re
import secrets
import threading
import time
from typing import Callable
from urllib.parse import urlencode

from . import approve, machine, protocol, qr, store

ENROLL_WAIT = 180   # seconds the QR code stays valid
CONFIRM_WAIT = 90   # seconds to type "yes" once the codes are shown
LABEL = re.compile(r"^[\w .,'()+-]{1,64}$")


def run(username: str, say: Callable[[str], None], ask_yes: Callable[[str, int], bool], *, ip: str | None = None,
        port: int = approve.PORT, wait: float = ENROLL_WAIT, confirm_wait: float = CONFIRM_WAIT, show_link: bool = True,
        qr_border: int = 2, cancel: threading.Event | None = None) -> dict | None:
    """Enrol one approver for `username`. Returns the stored device, or None (timed out, refused, not confirmed)."""
    username = store.normalize_user(username)
    mid, host = machine.machine_id(), machine.hostname()
    ip = ip or machine.lan_ip()
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
        if not decided.wait(confirm_wait + 10) or not decision.get("ok"):
            return 200, {"result": "denied", "message": "Not confirmed on the computer."}
        return 200, {"result": "ok", "credential_id": decision["credential_id"], "username": username, "hostname": host}

    path = f"/thessley-pam/v1/enroll/{request_id}/respond"
    device = None
    with approve._listening(ip, {path: respond}, port) as lst:
        link = "thessleypam://enroll?" + urlencode({
            "h": ip, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
            "m": mid, "hn": host, "u": username,
        })
        say(f"Add a phone or app that may approve ssh logins for '{username}' on {host}.")
        if show_link:
            say(f"Link: {link}")  # for the Thessley Passkey desktop app, which cannot scan a code
        for line in qr.lines(link, border=qr_border):
            say(line)
        say(f"In Thessley Passkey: scan the QR code (or paste the link). Valid for {int(wait) // 60} minutes.")

        item = None
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                item = pending.get(timeout=0.5)
                break
            except queue.Empty:
                if cancel is not None and cancel.is_set():
                    break
        if item is None:
            say("Timed out or cancelled. Nothing was added.")
            return None

        code = protocol.pairing_code(item["public_key"])
        say(f"'{item['label']}' ({item['client_ip']}) answered.")
        say(f"    Code:  {code}")
        if ask_yes("Does it show the same code? Type yes to add it: ", int(confirm_wait)):
            device = store.add_device(username, item["public_key"], item["label"], item["chain"])
            decision.update(ok=True, credential_id=device["credential_id"])
        decided.set()
        time.sleep(1.5)  # let the answer reach the phone before the listener shuts down
    say(f"Added '{device['label']}' as {device['credential_id']} for {username}." if device else "Not added.")
    return device
