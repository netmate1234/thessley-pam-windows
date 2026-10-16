"""A stand-in for the phone / desktop app: enrols a P-256 key and answers approval links the way the real apps do."""

import base64
import hashlib
import http.client
import json
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from thessley_pam_win import protocol, store


class FakePhone:
    def __init__(self, username: str, label: str = "Test phone"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        spki = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = base64.b64encode(spki).decode()
        self.username = username
        self.device = store.add_device(username, self.public_key, label, [])
        self.credential_id = self.device["credential_id"]

    def sign(self, type_, request_id, machine_id, nonce, timestamp, action) -> str:
        msg = protocol.canonical(type_, request_id, machine_id, self.username, nonce, timestamp, action)
        return base64.b64encode(self.key.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()

    def answer(self, link: str, action: str = "approve", *, timestamp=None, tamper=False, credential_id=None):
        """POST the signed answer to the computer named in `link`, trusting only the certificate in the link."""
        parts = urlsplit(link)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        ts = int(time.time()) if timestamp is None else timestamp
        sig = self.sign(parts.netloc, q["id"], q["m"], q["n"], ts, "deny" if tamper else action)
        body = {"credential_id": credential_id or self.credential_id, "action": action, "timestamp": ts, "signature": sig}
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(q["h"], int(q["p"]), context=ctx, timeout=10)
        conn.connect()
        fp = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        assert fp == q["fp"], "certificate does not match the link"  # what the real apps enforce
        raw = json.dumps(body).encode()
        conn.request("POST", f"/thessley-pam/v1/{parts.netloc}/{q['id']}/respond", raw, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        return resp.status, data


def link_from(lines):
    for line in lines:
        if line.startswith("Link: "):
            return line[len("Link: "):]
    return None


def wait_for_link(lines, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        link = link_from(list(lines))
        if link:
            return link
        time.sleep(0.05)
    raise AssertionError("no link was shown")
