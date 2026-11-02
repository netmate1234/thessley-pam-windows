"""Adding an approver (a phone, or the desktop app) for one Windows account.

One flow, used from two places: the administrator command line (in its own process) and the approval service (for a
user enrolling themselves). Both pass in how to show a line (`say`) and how to ask for a typed "yes" (`ask_yes`).

The phone proves it holds its key by signing the enrolment request; the person then compares a 6-digit code on both
screens and types yes. Nothing is stored unless both happen.
"""

import base64
import hashlib
import hmac
import os
import queue
import re
import secrets
import threading
import time
from typing import Callable
from urllib.parse import urlencode

from . import approve, attestation as key_attestation, machine, protocol, qr, store, tpmproof

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
    tpm_state: dict = {}  # what the one TPM challenge of this enrolment issued (one challenge, one attempt)

    def b64(raw: bytes) -> str:
        return base64.b64encode(raw).decode()

    def tpm_challenge(client_ip: str, body: dict) -> tuple[int, dict]:
        """Step 1 of the TPM proof: the app sends its endorsement key certificates and a fresh attestation key; we check
        the certificates against the manufacturer roots and answer with a secret only that chip can recover."""
        def refused(reason: str):
            return 400, {"result": "error", "message": f"The TPM could not be verified: {reason}."}
        if tpm_state:
            return 409, {"result": "error", "message": "A TPM challenge was already issued for this enrolment."}
        try:
            certs, ak = body["ek_certs"], body["ak_public"]
            if not isinstance(certs, list) or not isinstance(ak, str) or len(ak) > 1024:
                raise ValueError
            ders = [base64.b64decode(c, validate=True) for c in certs]
            ak_public = base64.b64decode(ak, validate=True)
        except (KeyError, ValueError, TypeError):
            return 400, {"result": "error", "message": "Missing TPM details."}
        ek = tpmproof.verify_ek_chain(ders)
        if ek is None:
            return refused("the TPM certificate chain is not one we trust")
        try:
            attributes = tpmproof.parse_public(ak_public)["attributes"]
            need = tpmproof.ATTR_FIXEDTPM | tpmproof.ATTR_FIXEDPARENT | tpmproof.ATTR_RESTRICTED | tpmproof.ATTR_SIGN
            if attributes & need != need:
                return refused("attestation key is not a restricted signing key")
            secret = os.urandom(32)
            cred = tpmproof.make_credential(ek["x"], ek["y"], tpmproof.name(ak_public), secret)
        except tpmproof.TpmProofError:
            return refused("could not build the challenge")
        tpm_state.update(ak=hashlib.sha256(ak_public).digest(), secret=hashlib.sha256(secret).digest(),
                         maker=ek["manufacturer"], model=ek["model"])
        return 200, {"credential_blob": b64(cred["credential_blob"]), "secret": b64(cred["secret"])}

    def check_tpm(public_key: str, tpm: dict | None) -> dict | None:
        """Step 2: the app's proof that its signing key lives in the TPM we challenged. What this computer concluded."""
        state = dict(tpm_state)
        tpm_state.clear()  # one challenge, one attempt
        if tpm is None:
            return None

        def no(reason: str) -> dict:
            return {"level": "unverified", "reason": reason}
        if not state:
            return no("no challenge was issued")
        try:
            field = {k: base64.b64decode(str(tpm[k]), validate=True)
                     for k in ("ak_public", "activated_secret", "certify_info", "certify_signature", "key_public")}
            spki = base64.b64decode(public_key, validate=True)
        except (KeyError, ValueError, TypeError):
            return no("incomplete proof")
        if not hmac.compare_digest(state["ak"], hashlib.sha256(field["ak_public"]).digest()):
            return no("a different attestation key than the one challenged")
        if not hmac.compare_digest(state["secret"], hashlib.sha256(field["activated_secret"]).digest()):
            return no("the activation secret does not match (the key and the TPM certificate are not in the same chip)")
        reason = tpmproof.verify_certification(field["ak_public"], field["certify_info"], field["certify_signature"],
                                               field["key_public"], nonce.encode("ascii"), spki)
        if reason:
            return no(reason)
        return {"level": "tpm", "maker": state["maker"], "model": state["model"], "checked_at": int(time.time())}

    def respond(client_ip: str, body: dict) -> tuple[int, dict]:
        try:
            public_key = str(body["public_key"])
            signature = str(body["proof_signature"])
            timestamp = int(body["timestamp"])
            label = str(body.get("label") or "Device").strip()
            chain = [str(c) for c in body.get("attestation_chain") or []][:10]
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        if not LABEL.match(label):
            label = "Device"
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Device clock is off by more than a minute."}
        msg = protocol.canonical("enroll", request_id, mid, username, nonce, timestamp, "register")
        if not protocol.verify(public_key, signature, msg):
            return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This code has already been used."}
        tpm = body.get("tpm")
        attestation = check_tpm(public_key, tpm if isinstance(tpm, dict) else None)
        # Where the phone's signing key actually lives, proven against Google's
        # attestation roots with the enrolment nonce as the challenge.
        try:
            expected_key = base64.b64decode(public_key, validate=True)
        except (ValueError, TypeError):
            expected_key = None
        key_attest = key_attestation.verify_chain(
            chain, expected_challenge=nonce.encode("ascii"), expected_public_key_spki=expected_key)
        pending.put({"client_ip": client_ip, "public_key": public_key, "label": label, "chain": chain,
                     "attestation": attestation, "key_attestation": key_attest})
        if not decided.wait(confirm_wait + 10) or not decision.get("ok"):
            if decision.get("error"):
                return 500, {"result": "error", "message": "The computer could not save this device: " + decision["error"]}
            return 200, {"result": "denied", "message": "Not confirmed on the computer."}
        return 200, {"result": "ok", "credential_id": decision["credential_id"], "username": username, "hostname": host,
                     "attestation": "tpm" if (attestation or {}).get("level") == "tpm" else "",
                     "attestation_status": key_attest.get("status", "unverified"),
                     "attestation_reason": key_attest.get("reason", "")}

    path = f"/thessley-pam/v1/enroll/{request_id}/respond"
    tpm_path = f"/thessley-pam/v1/enroll/{request_id}/tpm-challenge"
    device = None
    with approve._listening(ip, {path: respond, tpm_path: tpm_challenge}, port) as lst:
        link = "thessleypam://enroll?" + urlencode({
            "h": ip, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
            "m": mid, "hn": host, "u": username,
        })
        say(f"Add a device that may approve ssh logins for '{username}' on {host}.")
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
            say("Cancelled. Nothing was added." if cancel is not None and cancel.is_set() else "Timed out. Nothing was added.")
            return None

        code = protocol.pairing_code(item["public_key"])
        say(f"'{item['label']}' ({item['client_ip']}) answered.")
        say(f"    Code:  {code}")
        att = item.get("attestation")
        if att:
            say("    TPM:   " + (f"verified, a genuine TPM 2.0 chip ({(att['maker'] + ' ' + att['model']).strip() or 'maker not named'})"
                                 if att["level"] == "tpm" else f"claimed but NOT verified ({att['reason']})"))
        try:
            if ask_yes("Does it show the same code? Type yes to add it: ", int(confirm_wait)):
                key = item.get("key_attestation") or {}
                device = store.add_device(
                    username, item["public_key"], item["label"], item["chain"], item.get("attestation"),
                    key_attestation_status=str(key.get("status", "unverified")),
                    key_attestation_reason=str(key.get("reason", "")))
                decision.update(ok=True, credential_id=device["credential_id"])
        except OSError as exc:
            decision["error"] = str(exc)
            say(f"Could not save the device: {exc}")
        finally:
            decided.set()  # always answer the device, or it waits for the full timeout
        time.sleep(1.5)  # let the answer reach the device before the listener shuts down
    say(f"Added '{device['label']}' as {device['credential_id']} for {username}." if device else "Not added.")
    return device
