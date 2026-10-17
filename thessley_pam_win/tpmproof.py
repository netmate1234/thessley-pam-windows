"""Checks that an enrolled key lives inside a genuine TPM 2.0 chip: the computer's side of the proof.

A Python port of the verifier in thessley-passkey-server (class-tpm.php), same rules, same wire formats, so the same
desktop app produces the proof for a site and for a computer. The device proves three things:

  1. Its endorsement key (EK) certificate chains to a TPM manufacturer root we trust (the PEM files in tpm_roots/).
  2. Credential activation: we encrypt a random secret to that EK, bound to the name of a fresh attestation key (AK).
     Only a TPM that holds both the EK and the AK can recover it.
  3. That AK certifies (signs) the signing key's name over this enrolment's nonce, and the certified attributes say the
     key is fixed to the chip and was generated inside it.

What is proven: the key is non-exportable and lives in a TPM whose maker is the one named in the certificate.
What is not: revocation (CRLs are not checked) and the security of the chip's firmware. Only ECC P-256 endorsement keys
with SHA-256 names are supported. Anything not understood fails: a proof that cannot be checked counts as no proof.

Nothing here talks to a TPM or to the network; it only checks bytes the device sent.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALG_ECC, ALG_SHA256, ALG_NULL, ALG_ECDSA, ALG_AES = 0x0023, 0x000B, 0x0010, 0x0018, 0x0006
CURVE_P256 = 0x0003
MAGIC = 0xFF544347
ST_CERTIFY = 0x8017

ATTR_FIXEDTPM = 0x00000002
ATTR_FIXEDPARENT = 0x00000010
ATTR_SENSITIVEDATAORIGIN = 0x00000020
ATTR_RESTRICTED = 0x00010000
ATTR_DECRYPT = 0x00020000
ATTR_SIGN = 0x00040000

P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
EKU_EK_CERTIFICATE = "2.23.133.8.1"
OID_TPM_MANUFACTURER = "2.23.133.2.1"
OID_TPM_MODEL = "2.23.133.2.2"
MAX_CERTS = 8
MAX_CERT_BYTES = 8192


class TpmProofError(ValueError):
    """The proof is malformed or does not hold; the message is a short reason."""


def roots_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "tpm_roots")


def root_files() -> list[str]:
    d = roots_dir()
    try:
        return sorted(os.path.join(d, n) for n in os.listdir(d) if n.endswith(".pem"))
    except OSError:
        return []


# ---- small parsing helpers ------------------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise TpmProofError("truncated TPM structure")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())

    def done(self) -> bool:
        return self.pos == len(self.data)


def pad32(b: bytes) -> bytes:
    b = b.lstrip(b"\0")
    if len(b) > 32:
        raise TpmProofError("value too long for P-256")
    return b.rjust(32, b"\0")


def parse_public(raw: bytes) -> dict:
    """An ECC TPMT_PUBLIC (not the TPM2B wrapper): type, nameAlg, attributes, scheme, curve, x, y."""
    r = _Reader(raw)
    typ, name_alg, attributes = r.u16(), r.u16(), r.u32()
    auth_policy = r.tpm2b()
    if typ != ALG_ECC or name_alg != ALG_SHA256:
        raise TpmProofError("only ECC keys named with SHA-256 are supported")
    sym = r.u16()
    if sym != ALG_NULL:
        if sym != ALG_AES:
            raise TpmProofError("unsupported symmetric algorithm")
        r.u16()
        r.u16()
    scheme = r.u16()
    if scheme != ALG_NULL:
        r.u16()
    curve, kdf = r.u16(), r.u16()
    if kdf != ALG_NULL:
        r.u16()
    x, y = r.tpm2b(), r.tpm2b()
    if not r.done():
        raise TpmProofError("trailing bytes after the public area")
    if curve != CURVE_P256:
        raise TpmProofError("only the P-256 curve is supported")
    return {"type": typ, "nameAlg": name_alg, "attributes": attributes, "authPolicy": auth_policy, "scheme": scheme,
            "curve": curve, "x": pad32(x), "y": pad32(y)}


def name(tpmt_public: bytes) -> bytes:
    """TPM object name: nameAlg || H(TPMT_PUBLIC)."""
    return struct.pack(">H", ALG_SHA256) + hashlib.sha256(tpmt_public).digest()


def _public_key(x: bytes, y: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()


def spki_to_point(spki_der: bytes) -> tuple[bytes, bytes] | None:
    """The (x, y) of an SPKI DER P-256 key, or None if it is not one."""
    n = len(P256_SPKI_PREFIX)
    if len(spki_der) != n + 65 or not spki_der.startswith(P256_SPKI_PREFIX) or spki_der[n] != 4:
        return None
    point = spki_der[n + 1:]
    return point[:32], point[32:]


# ---- 1. the EK certificate chain --------------------------------------------------------------------------------
#
# TPM makers' certificates are not always strict DER (Intel's encode default values), which the strict parser in
# `cryptography` rejects and OpenSSL accepts. asn1crypto reads them as they are and keeps the exact signed bytes; the
# signatures themselves are still checked with `cryptography`.

from asn1crypto import x509 as asn1_x509  # noqa: E402

# (hash, key type) for the signature algorithms accepted when linking a chain.
_SIG_ALGOS = {"sha256_ecdsa": (hashes.SHA256, "ec"), "sha384_ecdsa": (hashes.SHA384, "ec"),
              "sha256_rsa": (hashes.SHA256, "rsa"), "sha384_rsa": (hashes.SHA384, "rsa")}


def _load_cert(der) -> "asn1_x509.Certificate | None":
    if not isinstance(der, (bytes, bytearray)) or not der or len(der) > MAX_CERT_BYTES:
        return None
    try:
        cert = asn1_x509.Certificate.load(bytes(der))
        ids = {e["extn_id"].native for e in (cert["tbs_certificate"]["extensions"] or [])}
        if ids & {"name_constraints", "policy_constraints"}:  # not evaluated here: refuse rather than ignore
            return None
        cert["tbs_certificate"].dump()
        return cert
    except (ValueError, TypeError, KeyError):
        return None


def _load_roots(files) -> list:
    out = []
    for path in files or []:
        try:
            with open(path, "rb") as f:
                text = f.read()
        except OSError:
            continue
        for block in re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S):
            try:
                import base64
                cert = _load_cert(base64.b64decode(b"".join(block.split())))
            except ValueError:
                cert = None
            if cert is not None:
                out.append(cert)
    return out


def _der(cert) -> bytes:
    return cert.dump()


def _signed_by(cert, issuer) -> bool:
    """The certificate's signature, checked with the issuer's key (ECDSA or RSA PKCS#1, SHA-256 or SHA-384 only)."""
    algo = _SIG_ALGOS.get(cert["signature_algorithm"]["algorithm"].native)
    if algo is None:
        return False
    hash_cls, kind = algo
    try:
        key = serialization.load_der_public_key(issuer.public_key.dump())
        tbs, sig = cert["tbs_certificate"].dump(), cert["signature_value"].native
        if kind == "ec" and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, tbs, ec.ECDSA(hash_cls()))
        elif kind == "rsa" and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, tbs, padding.PKCS1v15(), hash_cls())
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _within(cert, at: float) -> bool:
    validity = cert["tbs_certificate"]["validity"]
    return validity["not_before"].native.timestamp() <= at <= validity["not_after"].native.timestamp()


def verify_ek_chain(der_certs: list[bytes], files=None, at: float | None = None) -> dict | None:
    """Check the EK certificate chain against the trusted roots (see _verify_ek_chain). Anything that cannot be read or
    checked, however it fails, counts as not trusted: a malformed certificate must never crash an enrolment."""
    try:
        return _verify_ek_chain(der_certs, files, at)
    except Exception:  # noqa: BLE001 - strict by design: any trouble is a refusal
        return None


def _verify_ek_chain(der_certs: list[bytes], files=None, at: float | None = None) -> dict | None:
    """Check the EK certificate chain against the trusted roots.

    der_certs: the EK certificate first, then any intermediates, as DER. Returns the EK's P-256 point and the maker and
    model named in the certificate, or None if the chain does not verify. Certificates are linked to their issuer by
    issuer name or by key identifier (AMD's do not match by name); every signature is verified, every issuer must be a CA
    within its validity and path length, and the top must be one of the trusted root files, byte for byte."""
    at = time.time() if at is None else at
    roots = _load_roots(root_files() if files is None else files)
    if not der_certs or len(der_certs) > MAX_CERTS or not roots:
        return None
    leaf = _load_cert(der_certs[0])
    sent = [c for c in (_load_cert(d) for d in der_certs[1:]) if c is not None]
    if leaf is None or not _within(leaf, at):
        return None
    root_ders = {_der(r) for r in roots}
    cert, trusted = leaf, False
    for below in range(MAX_CERTS):
        issuer = None
        for cand in list(roots) + sent:
            if _der(cand) == _der(cert):
                continue
            by_name = cand.subject.dump() == cert.issuer.dump()
            aki, ski = cert.authority_key_identifier, cand.key_identifier
            by_key = bool(aki and ski and aki == ski)
            if not (by_name or by_key):
                continue
            pathlen = cand.max_path_length
            if not cand.ca or not _within(cand, at) or (pathlen is not None and below > pathlen):
                continue
            if _signed_by(cert, cand):
                issuer = cand
                break
        if issuer is None:
            return None
        if _der(issuer) in root_ders:
            trusted = True
            break
        cert = issuer
    if not trusted:
        return None

    try:
        key = serialization.load_der_public_key(leaf.public_key.dump())
    except (ValueError, TypeError):
        return None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        return None
    eku = leaf.extended_key_usage_value
    if eku is not None and EKU_EK_CERTIFICATE not in [e.dotted for e in eku]:
        return None  # a certificate with no extended key usage at all is accepted, as on the sites' server
    maker = model = ""
    san = leaf.subject_alt_name_value
    for general in san or []:
        if general.name != "directory_name":
            continue
        for rdn in general.chosen.chosen:
            for tv in rdn:
                oid, value = tv["type"].dotted, str(tv["value"].native)
                if oid == OID_TPM_MANUFACTURER:
                    m = re.fullmatch(r"id:([0-9A-Fa-f]{8})", value)
                    if m:
                        maker = bytes.fromhex(m.group(1)).decode("latin-1").strip("\0 ")
                elif oid == OID_TPM_MODEL:
                    model = value.strip()[:32]
    nums = key.public_numbers()
    return {"x": pad32(nums.x.to_bytes(32, "big")), "y": pad32(nums.y.to_bytes(32, "big")),
            "manufacturer": maker, "model": model}


# ---- 2. credential activation ---------------------------------------------------------------------------------

def kdfa(key: bytes, label: bytes, context_u: bytes, context_v: bytes, bits: int) -> bytes:
    """TPM2 KDFa (SP 800-108 counter mode, HMAC-SHA256)."""
    out, counter = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(key, struct.pack(">I", counter) + label + b"\0" + context_u + context_v + struct.pack(">I", bits),
                        hashlib.sha256).digest()
        counter += 1
    return out[:bits // 8]


def make_credential(ek_x: bytes, ek_y: bytes, ak_name: bytes, secret: bytes) -> dict:
    """TPM2_MakeCredential for an ECC P-256 EK: encrypts `secret` so only the TPM holding the EK and a loaded object named
    `ak_name` can recover it. Returns credential_blob and secret: marshalled TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET."""
    if not 1 <= len(secret) <= 32:
        raise TpmProofError("credential must be 1-32 bytes")
    eph = ec.generate_private_key(ec.SECP256R1())
    nums = eph.public_key().public_numbers()
    qe_x, qe_y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
    z = pad32(eph.exchange(ec.ECDH(), _public_key(ek_x, ek_y)))
    # Seed: concatenation KDF (SP 800-56A) over SHA-256, one block.
    seed = hashlib.sha256(struct.pack(">I", 1) + z + b"IDENTITY\0" + qe_x + pad32(ek_x)).digest()
    sym_key = kdfa(seed, b"STORAGE", ak_name, b"", 128)
    enc = Cipher(algorithms.AES(sym_key), modes.CFB(b"\0" * 16)).encryptor()
    enc_secret = enc.update(struct.pack(">H", len(secret)) + secret) + enc.finalize()
    hmac_key = kdfa(seed, b"INTEGRITY", b"", b"", 256)
    outer = hmac.new(hmac_key, enc_secret + ak_name, hashlib.sha256).digest()
    id_obj = struct.pack(">H", len(outer)) + outer + enc_secret
    return {"credential_blob": struct.pack(">H", len(id_obj)) + id_obj,
            "secret": struct.pack(">H", 2 + 32 + 2 + 32) + struct.pack(">H", 32) + qe_x + struct.pack(">H", 32) + qe_y}


# ---- 3. certification of the signing key ------------------------------------------------------------------------

def verify_certification(ak_public: bytes, attest: bytes, signature: bytes, key_public: bytes, nonce: bytes,
                         submitted_spki: bytes) -> str | None:
    """Verify the AK's certification of the signing key. None when everything checks out, otherwise a short reason."""
    try:
        ak, key = parse_public(ak_public), parse_public(key_public)
    except TpmProofError:
        return "unparseable public area"
    # The AK must be a restricted signing key fixed to the chip: otherwise it could be made to sign anything.
    ak_need = ATTR_FIXEDTPM | ATTR_FIXEDPARENT | ATTR_RESTRICTED | ATTR_SIGN
    if ak["attributes"] & ak_need != ak_need or ak["attributes"] & ATTR_DECRYPT:
        return "attestation key is not a restricted, fixed signing key"
    # The certified key: generated inside and tied to this TPM, and a plain signing key.
    key_need = ATTR_FIXEDTPM | ATTR_FIXEDPARENT | ATTR_SENSITIVEDATAORIGIN | ATTR_SIGN
    if key["attributes"] & key_need != key_need or key["attributes"] & (ATTR_RESTRICTED | ATTR_DECRYPT):
        return "signing key is not fixed to the TPM"
    point = spki_to_point(submitted_spki)
    if point is None or not hmac.compare_digest(point[0], key["x"]) or not hmac.compare_digest(point[1], key["y"]):
        return "certified key is not the submitted key"

    try:  # the signature, by the AK
        r = _Reader(signature)
        alg, hash_alg, sig_r, sig_s = r.u16(), r.u16(), r.tpm2b(), r.tpm2b()
        if not r.done():
            return "unexpected signature algorithm"
    except TpmProofError:
        return "unparseable signature"
    if alg != ALG_ECDSA or hash_alg != ALG_SHA256:
        return "unexpected signature algorithm"
    try:
        _public_key(ak["x"], ak["y"]).verify(
            utils.encode_dss_signature(int.from_bytes(sig_r, "big"), int.from_bytes(sig_s, "big")), attest, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return "bad certification signature"

    try:  # what was signed
        a = _Reader(attest)
        magic, typ = a.u32(), a.u16()
        a.tpm2b()                      # qualifiedSigner
        extra = a.tpm2b()              # extraData: the qualifying data
        a.take(8 + 4 + 4 + 1 + 8)      # clock info and firmware version
        certified = a.tpm2b()          # the name of the certified key
        a.tpm2b()                      # its qualified name
        if not a.done():
            return "trailing bytes in the attestation"
    except TpmProofError:
        return "unparseable attestation"
    if magic != MAGIC or typ != ST_CERTIFY:
        return "not a TPM certification"
    # Some chips (AMD) take at most a SHA-256 digest of qualifying data, so a longer nonce comes back hashed.
    if not hmac.compare_digest(nonce, extra) and not (len(nonce) > 32 and hmac.compare_digest(hashlib.sha256(nonce).digest(), extra)):
        return "certification is not bound to this enrolment"
    if not hmac.compare_digest(name(key_public), certified):
        return "certified name does not match the key"
    return None
