"""The signed message and the checks every response goes through.

Both ends build the same string and the phone signs it with its Keystore key (ECDSA P-256, SHA-256, DER):

    thessley_pam_v1|<type>|<request_id>|<machine_id>|<username>|<nonce>|<timestamp>|<action>

It has its own version tag, so a signature made for a website login (thessley_passkey_v1) can never be
replayed here or the other way round. machine_id and username bind it to one computer and one account.
Must stay byte-identical to PamCanonicalString.kt in the Android app.
"""

import base64
import hashlib
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SIG_VERSION = "thessley_pam_v1"
CLOCK_SKEW = 60  # seconds either way, same as the website protocol

ACTIONS = {"register", "approve", "deny"}
TYPES = {"enroll", "sudo", "login"}

_FIELD = re.compile(r"^[^|\s]+$")


def canonical(type_: str, request_id: str, machine_id: str, username: str, nonce: str, timestamp: int,
              action: str) -> bytes:
    if type_ not in TYPES or action not in ACTIONS:
        raise ValueError("unknown type or action")
    fields = [SIG_VERSION, type_, request_id, machine_id, username, nonce, str(int(timestamp)), action]
    if not all(_FIELD.match(f) for f in fields):
        raise ValueError("empty field or field containing '|' or whitespace")
    return "|".join(fields).encode()


def load_public_key(spki_b64: str) -> ec.EllipticCurvePublicKey:
    """A base64 X.509 SubjectPublicKeyInfo, which must be an EC P-256 key."""
    key = serialization.load_der_public_key(base64.b64decode(spki_b64, validate=True))
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("public key is not EC P-256")
    return key


def verify(spki_b64: str, signature_b64: str, message: bytes) -> bool:
    try:
        key = load_public_key(spki_b64)
        key.verify(base64.b64decode(signature_b64, validate=True), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def timestamp_ok(ts: int, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return abs(int(ts) - now) <= CLOCK_SKEW


def pairing_code(spki_b64: str) -> str:
    """Six digits both screens show while enrolling, derived from the phone's public key.

    Matching codes mean the key the computer received is the one this phone made. Must match
    PamCanonicalString.pairingCode() in the app.
    """
    digest = hashlib.sha256(base64.b64decode(spki_b64)).digest()
    n = int.from_bytes(digest[:4], "big") % 1_000_000
    return f"{n:06d}"[:3] + " " + f"{n:06d}"[3:]
