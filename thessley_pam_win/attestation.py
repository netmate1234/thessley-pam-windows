"""Classify Android Keystore keys from Google-rooted attestation evidence.

Used when a phone enrols for SSH, sudo, the screen, the VPN or the web page:
the certificate chain the phone sends is checked back to Google's roots, so
the admin page and the phone can say whether the key really lives in a TEE or
StrongBox. Software-backed keys stay usable but are classified separately.

The Android security-level values and KeyDescription layout follow the AOSP
Key and ID attestation specification.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ObjectIdentifier, SignatureAlgorithmOID


KEY_DESCRIPTION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
SECURITY_SOFTWARE = 0
SECURITY_TEE = 1
SECURITY_STRONGBOX = 2
HARDWARE_LEVELS = {SECURITY_TEE, SECURITY_STRONGBOX}

# Google Android Key Attestation roots. Google announced CA1 starts signing
# chains on 2026-02-01; retain the legacy RSA root for older factory keys.
GOOGLE_LEGACY_ROOT_SPKI_B64 = (
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/"
    "dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3ii"
    "KkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1"
    "FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW"
    "7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70v"
    "E0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghz"
    "q8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJ"
    "KnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS8"
    "2ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WE"
    "g5UmAGMCAwEAAQ=="
)
GOOGLE_CA1_ROOT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----"""
_ROOT_SERIAL_NUMBER = "f92009e853b6b045"
_REVOCATION_URL = "https://android.googleapis.com/attestation/status"
_REVOCATION_LOCK = threading.Lock()
_REVOCATION_CACHE: tuple[float, dict[str, dict]] | None = None


def _google_root_keys() -> tuple[object, ...]:
    legacy_der = base64.b64decode(GOOGLE_LEGACY_ROOT_SPKI_B64, validate=True)
    ca1 = x509.load_pem_x509_certificate(GOOGLE_CA1_ROOT_CERT_PEM.encode("ascii"))
    return (
        serialization.load_der_public_key(legacy_der),
        ca1.public_key(),
    )


def _revocation_entries(now: datetime) -> dict[str, dict] | None:
    """Fetch Google's cache-controlled status list; None means unknown/stale."""
    global _REVOCATION_CACHE
    timestamp = now.timestamp()
    with _REVOCATION_LOCK:
        if _REVOCATION_CACHE is not None and _REVOCATION_CACHE[0] > timestamp:
            return _REVOCATION_CACHE[1]
        request = urllib.request.Request(
            _REVOCATION_URL,
            headers={"Accept": "application/json", "User-Agent": "Thessley-AD-Attestation/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    return None
                payload = json.loads(raw.decode("utf-8"))
                entries = payload.get("entries") if isinstance(payload, dict) else None
                if not isinstance(entries, dict) or len(entries) > 100000:
                    return None
                if any(not re.fullmatch(r"[a-f0-9]{1,64}", key)
                       or not isinstance(value, dict)
                       or value.get("status") not in {"REVOKED", "SUSPENDED"}
                       for key, value in entries.items()):
                    return None
                cache_control = response.headers.get("Cache-Control", "")
                match = re.search(r"(?:^|,)\s*max-age=(\d+)", cache_control, re.I)
                ttl = min(86400, max(60, int(match.group(1)))) if match else 3600
                _REVOCATION_CACHE = (timestamp + ttl, entries)
                return entries
        except (OSError, urllib.error.URLError, TimeoutError, ValueError, UnicodeError):
            return None


def _read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one bounded DER TLV; reject indefinite/non-canonical lengths."""
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated DER element")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number DER is not expected here")
    cursor = offset + 1
    first = data[cursor]
    cursor += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise ValueError("invalid DER length")
        if data[cursor] == 0:
            raise ValueError("non-canonical DER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        if length < 0x80:
            raise ValueError("non-canonical DER length")
        cursor += count
    end = cursor + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[cursor:end], end


def _parse_key_description(extension_der: bytes) -> tuple[int, int, bytes]:
    # X.509 extnValue normally exposes the inner SEQUENCE. Accept a single
    # OCTET STRING wrapper as some OpenSSL/PHP versions expose it that way.
    tag, value, end = _read_tlv(extension_der)
    if end != len(extension_der):
        raise ValueError("trailing DER bytes")
    if tag == 0x04:
        wrapped = value
        tag, value, end = _read_tlv(wrapped)
        if end != len(wrapped):
            raise ValueError("trailing wrapped DER bytes")
    if tag != 0x30:
        raise ValueError("attestation KeyDescription is not a SEQUENCE")
    children: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(value):
        child_tag, child_value, cursor = _read_tlv(value, cursor)
        children.append((child_tag, child_value))
    if len(children) != 8:
        raise ValueError("unexpected KeyDescription field count")
    if children[0][0] != 0x02 or children[1][0] != 0x0A or children[2][0] != 0x02:
        raise ValueError("invalid KeyDescription version/security fields")
    if children[3][0] != 0x0A or children[4][0] != 0x04:
        raise ValueError("invalid KeyDescription key security/challenge fields")
    if children[5][0] != 0x04 or children[6][0] != 0x30 or children[7][0] != 0x30:
        raise ValueError("invalid KeyDescription authorization lists")

    def enum_value(raw: bytes) -> int:
        if (not raw or len(raw) > 4 or raw[0] & 0x80
                or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80)):
            raise ValueError("invalid security level")
        return int.from_bytes(raw, "big")

    return enum_value(children[1][1]), enum_value(children[3][1]), children[4][1]


def _verify_certificate_signature(certificate: x509.Certificate, issuer_key: object) -> None:
    signature = certificate.signature
    data = certificate.tbs_certificate_bytes
    algorithm = certificate.signature_hash_algorithm
    if isinstance(issuer_key, rsa.RSAPublicKey):
        parameters = getattr(certificate, "signature_algorithm_parameters", None)
        if isinstance(parameters, (padding.PSS, padding.PKCS1v15)):
            chosen_padding = parameters
        elif certificate.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
            raise ValueError("RSA-PSS parameters are unavailable")
        else:
            chosen_padding = padding.PKCS1v15()
        if algorithm is None:
            raise ValueError("certificate hash algorithm is unavailable")
        issuer_key.verify(signature, data, chosen_padding, algorithm)
    elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
        if algorithm is None:
            raise ValueError("certificate hash algorithm is unavailable")
        issuer_key.verify(signature, data, ec.ECDSA(algorithm))
    elif isinstance(issuer_key, ed25519.Ed25519PublicKey):
        issuer_key.verify(signature, data)
    else:
        raise ValueError("unsupported certificate issuer key")


def _decode_chain(chain: object) -> list[x509.Certificate]:
    if not isinstance(chain, list) or not 1 <= len(chain) <= 10:
        raise ValueError("invalid attestation chain length")
    result: list[x509.Certificate] = []
    total = 0
    for item in chain:
        if not isinstance(item, str) or not 256 <= len(item) <= 16384:
            raise ValueError("invalid attestation certificate")
        der = base64.b64decode(item, validate=True)
        if base64.b64encode(der).decode("ascii") != item or not 128 <= len(der) <= 12288:
            raise ValueError("invalid attestation certificate encoding")
        total += len(der)
        if total > 30 * 1024:
            raise ValueError("attestation chain is too large")
        certificate = x509.load_der_x509_certificate(der)
        if certificate.public_bytes(serialization.Encoding.DER) != der:
            raise ValueError("non-canonical attestation certificate")
        result.append(certificate)
    return result


def verify_chain(
    chain: object,
    *,
    expected_challenge: bytes | None = None,
    expected_public_key_spki: bytes | None = None,
    now: datetime | None = None,
    trusted_root_spki_der: bytes | None = None,
) -> dict:
    """Return the attestation classification for a phone's key.

    ``expected_challenge`` is the enrolment nonce; pass ``None`` for devices
    enrolled before this check existed (the nonce is not stored), which still
    proves the key's protection level but not that it was minted for that
    particular enrolment.

    ``verified_software`` means the Google-rooted attestation is valid but
    proves a software security level. The caller may allow its use while
    warning that it does not have TEE/StrongBox protection.
    """
    if expected_challenge is not None and (
            not isinstance(expected_challenge, bytes) or not expected_challenge):
        return {"status": "unverified", "reason": "invalid_expected_challenge"}
    if expected_public_key_spki is not None and (
            not isinstance(expected_public_key_spki, bytes) or not expected_public_key_spki):
        return {"status": "unverified", "reason": "invalid_expected_public_key"}
    try:
        certificates = _decode_chain(chain)
        trusted_roots = ((serialization.load_der_public_key(trusted_root_spki_der),)
                         if trusted_root_spki_der is not None else _google_root_keys())
        current = now or datetime.now(timezone.utc)
        for index, certificate in enumerate(certificates[:-1]):
            issuer = certificates[index + 1]
            if certificate.issuer != issuer.subject:
                raise ValueError("issuer_name_mismatch")
            _verify_certificate_signature(certificate, issuer.public_key())

        last = certificates[-1]
        last_spki = last.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        trusted_root = None
        trusted_root_der = None
        for candidate in trusted_roots:
            candidate_der = candidate.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if last_spki == candidate_der:
                trusted_root = candidate
                trusted_root_der = candidate_der
                break
            try:
                _verify_certificate_signature(last, candidate)
                trusted_root = candidate
                trusted_root_der = candidate_der
                break
            except Exception:
                continue
        if trusted_root is None or trusted_root_der is None:
            raise ValueError("untrusted_attestation_root")

        legacy_root_der = serialization.load_der_public_key(
            base64.b64decode(GOOGLE_LEGACY_ROOT_SPKI_B64, validate=True)
        ).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        factory_chain = trusted_root_der == legacy_root_der and any(
            attribute.value.casefold() == _ROOT_SERIAL_NUMBER
            for certificate in certificates
            for name in (certificate.subject, certificate.issuer)
            for attribute in name.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)
        )
        # AOSP recommends continuing to trust legacy factory-key chains
        # with Google's f920... subject serial even after their certificates
        # expire. RKP chains still require current certificate validity.
        if not factory_chain:
            for certificate in certificates:
                not_before = getattr(certificate, "not_valid_before_utc", None)
                not_after = getattr(certificate, "not_valid_after_utc", None)
                if not_before is None:
                    not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
                if current < not_before or current > not_after:
                    raise ValueError("certificate_out_of_validity")

        revocations = _revocation_entries(current)
        if revocations is None:
            raise ValueError("revocation_status_unavailable")
        for certificate in certificates:
            status = revocations.get(format(certificate.serial_number, "x"))
            if status is None:
                continue
            expires = status.get("expires")
            if isinstance(expires, str):
                try:
                    if current.date() > datetime.fromisoformat(expires).date():
                        continue
                except ValueError:
                    raise ValueError("invalid_revocation_expiry")
            raise ValueError("attestation_certificate_" + status["status"].lower())

        attestation_certificate = None
        extension = None
        # Android documents provisioning chains where the first trusted
        # key-attestation extension is not on chain[0]. Ignore later copies.
        for certificate in certificates:
            try:
                candidate_extension = certificate.extensions.get_extension_for_oid(KEY_DESCRIPTION_OID).value
            except x509.ExtensionNotFound:
                continue
            if not isinstance(candidate_extension, x509.UnrecognizedExtension):
                raise ValueError("unexpected_key_description_type")
            attestation_certificate = certificate
            extension = candidate_extension
            break
        if attestation_certificate is None or extension is None:
            raise ValueError("missing_key_description")
        if expected_public_key_spki is not None and attestation_certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != expected_public_key_spki:
            raise ValueError("attested_key_mismatch")
        attestation_level, key_level, challenge = _parse_key_description(extension.value)
        if expected_challenge is not None and challenge != expected_challenge:
            raise ValueError("challenge_mismatch")
        if attestation_level not in (SECURITY_SOFTWARE, *HARDWARE_LEVELS):
            raise ValueError("unknown_attestation_security_level")
        if key_level not in (SECURITY_SOFTWARE, *HARDWARE_LEVELS):
            raise ValueError("unknown_key_security_level")
        # Require both the attestation signer and the keymaster holding the
        # private key to be hardware-backed before calling this verified.
        if attestation_level == SECURITY_SOFTWARE or key_level == SECURITY_SOFTWARE:
            if attestation_level == key_level == SECURITY_SOFTWARE:
                return {"status": "verified_software", "reason": "software_backed"}
            raise ValueError("inconsistent_security_levels")
        status = "verified_strongbox" if key_level == SECURITY_STRONGBOX else "verified_tee"
        reason = ("hardware_attestation_valid" if expected_challenge is not None
                  else "hardware_attestation_valid_challenge_unchecked")
        return {"status": status, "reason": reason}
    except Exception as error:
        # Unknown evidence is not called hardware-backed, but the caller may
        # still record the user's proof-of-possession key with a warning.
        reason = str(error)[:96] or "invalid_attestation"
        return {"status": "unverified", "reason": reason}
