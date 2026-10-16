"""A stand-in for a phone that enrols itself (the other stand-in, fakephone.FakePhone, is already enrolled)."""

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

from thessley_pam_win import protocol


class EnrollingPhone:
    """Makes a key, signs the enrolment request and posts it, as the real apps do."""

    def __init__(self, username: str, label: str = "New phone"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        spki = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = base64.b64encode(spki).decode()
        self.username, self.label = username, label
        self.result = None
        self.thread = None

    def _post(self, link: str) -> None:
        parts = urlsplit(link)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        ts = int(time.time())
        msg = protocol.canonical("enroll", q["id"], q["m"], self.username, q["n"], ts, "register")
        sig = base64.b64encode(self.key.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()
        body = {"public_key": self.public_key, "proof_signature": sig, "timestamp": ts, "label": self.label,
                "attestation_chain": []}
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(q["h"], int(q["p"]), context=ctx, timeout=30)
        conn.connect()
        assert hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() == q["fp"]  # what the real apps enforce
        conn.request("POST", f"/thessley-pam/v1/enroll/{q['id']}/respond", json.dumps(body).encode(),
                     {"Content-Type": "application/json"})
        resp = conn.getresponse()
        self.result = (resp.status, json.loads(resp.read()))
        conn.close()

    def enroll(self, link: str) -> None:
        """The computer answers only after the person confirmed the code, so this runs in a thread."""
        self.thread = threading.Thread(target=self._post, args=(link,), daemon=True)
        self.thread.start()

    def wait(self, timeout=30):
        self.thread.join(timeout)
        return self.result
