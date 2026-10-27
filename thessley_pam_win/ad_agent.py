"""Machine-authenticated client for the standalone Thessley AD service.

This is deliberately separate from ``drupal_agent`` and from the existing
Windows QR credential provider. It establishes the Windows machine identity,
creates SID-bound phone approvals, and retrieves their one-use result. An
approval is not itself a Windows credential: callers must not report a
successful Windows sign-in until a certificate/PKINIT provider completes the
KDC exchange.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import time
from ctypes import wintypes
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import qr

SERVICE_PORT = 47810
MACHINE_SIGNATURE_DOMAIN = "thessley_ad_machine_v1"
MAX_BODY = 64 * 1024
_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_PIN = re.compile(r"^[a-f0-9]{64}$")
_SID = re.compile(r"^S-1-(?:[0-9]+-)+[0-9]+$", re.IGNORECASE)
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")


class AgentError(RuntimeError):
    """The standalone service could not safely complete an operation."""


def _folder() -> str:
    if os.name != "nt":
        raise AgentError("The standalone AD agent is supported on Windows only.")
    return os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "ThessleyPamWin", "ad-agent")


def _lock_acl(path: str, directory: bool = False) -> None:
    args = ["icacls.exe", path, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]
    if directory:
        args.extend(["/T", "/C"])
    try:
        result = subprocess.run(args, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError("Could not restrict access to the AD machine key.") from exc
    if result.returncode:
        raise AgentError("Could not restrict access to the AD machine key.")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi(data: bytes, *, decrypt: bool) -> bytes:
    """Protect the machine signing key with machine-scope Windows DPAPI."""
    if os.name != "nt":
        raise AgentError("Windows DPAPI is unavailable on this platform.")
    if not data or len(data) > 64 * 1024:
        raise AgentError("Invalid DPAPI input.")
    source = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    source_blob = _DataBlob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte)))
    output_blob = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if decrypt:
        call = crypt32.CryptUnprotectData
        call.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        call.restype = wintypes.BOOL
        ok = call(ctypes.byref(source_blob), None, None, None, None, 0x1, ctypes.byref(output_blob))
    else:
        call = crypt32.CryptProtectData
        call.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        call.restype = wintypes.BOOL
        # CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN. ACLs still
        # restrict the resulting blob to SYSTEM and local Administrators.
        ok = call(ctypes.byref(source_blob), "Thessley AD machine key", None, None, None,
                  0x4 | 0x1, ctypes.byref(output_blob))
    if not ok:
        raise AgentError("Windows could not protect or unlock the AD machine key.")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(output_blob.pbData)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection trusting only the exact leaf certificate fingerprint."""

    def __init__(self, host: str, port: int, pin: str, timeout: float):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=context)
        self._pin = bytes.fromhex(pin)

    def connect(self) -> None:
        super().connect()
        try:
            cert = self.sock.getpeercert(binary_form=True)
            digest = hashlib.sha256(cert).digest()
            if not secrets.compare_digest(digest, self._pin):
                raise AgentError("The AD service certificate does not match the configured fingerprint.")
        except Exception:
            self.close()
            raise


def _server(value: str, pin: str) -> tuple[str, int, str]:
    parsed = urlsplit(str(value).strip())
    if (parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Use an HTTPS service origin, for example https://thessley.example.net:47810.")
    if not isinstance(pin, str) or not _PIN.fullmatch(pin.lower()):
        raise ValueError("The service certificate fingerprint must be 64 hexadecimal characters.")
    try:
        port = parsed.port or SERVICE_PORT
    except ValueError as exc:
        raise ValueError("The service URL has an invalid port.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("The service URL has an invalid port.")
    return parsed.hostname, port, pin.lower()


def _post(host: str, port: int, pin: str, path: str, body: dict,
          headers: dict[str, str] | None = None, timeout: float = 8.0) -> dict:
    if not re.fullmatch(r"/thessley-ad/v1/[a-z0-9_/-]{1,160}", path):
        raise AgentError("Invalid standalone AD API path.")
    raw = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_BODY:
        raise AgentError("The AD service request is too large.")
    conn = _PinnedHTTPSConnection(host, port, pin, timeout)
    request_headers = {"Content-Type": "application/json", "Accept": "application/json",
                       "Connection": "close"}
    if headers:
        request_headers.update(headers)
    try:
        conn.request("POST", path, body=raw, headers=request_headers)
        response = conn.getresponse()
        payload = response.read(MAX_BODY + 1)
        if len(payload) > MAX_BODY:
            raise AgentError("The AD service response is too large.")
        if response.status < 200 or response.status >= 300:
            try:
                detail = json.loads(payload).get("message", "")
            except (ValueError, AttributeError):
                detail = ""
            raise AgentError(str(detail)[:240] or f"The AD service returned HTTP {response.status}.")
        try:
            result = json.loads(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AgentError("The AD service returned invalid JSON.") from exc
        if not isinstance(result, dict):
            raise AgentError("The AD service returned an invalid response.")
        return result
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        if isinstance(exc, AgentError):
            raise
        raise AgentError("Could not reach the pinned Thessley AD service.") from exc
    finally:
        conn.close()


def enroll_machine(server_url: str, tls_sha256: str, code: str, machine_name: str | None = None) -> str:
    """Pair this Windows machine using an administrator-issued, single-use code."""
    if os.name != "nt":
        raise AgentError("Machine enrollment is supported on Windows only.")
    host, port, pin = _server(server_url, tls_sha256)
    name = machine_name or socket.gethostname()
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise ValueError("The Windows computer name contains unsupported characters.")
    folder = _folder()
    os.makedirs(folder, exist_ok=True)
    _lock_acl(folder, directory=True)
    config_path = os.path.join(folder, "machine.json")
    key_path = os.path.join(folder, "machine-key.dpapi")
    if os.path.exists(config_path) or os.path.exists(key_path):
        raise AgentError("This Windows machine is already paired. Revoke its old key before replacing it.")

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_der = private_key.private_bytes(serialization.Encoding.DER,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
    protected_key = _dpapi(private_der, decrypt=False)
    public_der = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    payload = _post(host, port, pin, "/thessley-ad/v1/machines/enroll", {
        "code": code,
        "machine_name": name,
        "public_key_spki_b64": base64.b64encode(public_der).decode("ascii"),
    })
    machine_id = payload.get("machine_id")
    if payload.get("result") != "enrolled" or not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
        raise AgentError("The AD service did not confirm machine enrollment.")

    # Persist only after the server has accepted the public key. If a local
    # write fails here, the service administrator can revoke the orphaned key.
    tmp_key, tmp_config = key_path + ".new", config_path + ".new"
    try:
        with open(tmp_key, "xb") as stream:
            stream.write(protected_key)
            stream.flush()
            os.fsync(stream.fileno())
        with open(tmp_config, "x", encoding="utf-8") as stream:
            json.dump({"version": 1, "server_url": f"https://{host}:{port}",
                       "tls_sha256": pin, "machine_id": machine_id,
                       "machine_name": name}, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        _lock_acl(folder, directory=True)
        os.replace(tmp_key, key_path)
        os.replace(tmp_config, config_path)
        _lock_acl(folder, directory=True)
    except OSError as exc:
        for path in (tmp_key, tmp_config, key_path, config_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        raise AgentError("Machine enrollment succeeded remotely, but its local key could not be saved; revoke the orphaned machine and pair again.") from exc
    return machine_id


def configured() -> bool:
    try:
        return os.path.isfile(os.path.join(_folder(), "machine.json")) and os.path.isfile(
            os.path.join(_folder(), "machine-key.dpapi"))
    except AgentError:
        return False


def check_connection() -> dict:
    """Verify the pinned TLS connection and machine signature with the service."""
    result = _signed_post("/thessley-ad/v1/machines/authenticate", {})
    config, _key, _host, _port, _pin = _load()
    if result.get("result") != "authenticated" or result.get("machine_id") != config["machine_id"]:
        raise AgentError("The AD service did not confirm this machine identity.")
    return result


def _load() -> tuple[dict, ec.EllipticCurvePrivateKey, str, int, str]:
    folder = _folder()
    config_path = os.path.join(folder, "machine.json")
    key_path = os.path.join(folder, "machine-key.dpapi")
    try:
        with open(config_path, encoding="utf-8") as stream:
            config = json.load(stream)
        with open(key_path, "rb") as stream:
            protected_key = stream.read(64 * 1024 + 1)
    except (OSError, ValueError, TypeError) as exc:
        raise AgentError("This Windows machine is not paired with the Thessley AD service.") from exc
    if (not isinstance(config, dict) or set(config) != {"version", "server_url", "tls_sha256", "machine_id", "machine_name"}
            or isinstance(config.get("version"), bool) or config.get("version") != 1
            or not isinstance(config.get("server_url"), str)
            or not isinstance(config.get("tls_sha256"), str)
            or not isinstance(config.get("machine_id"), str)
            or not _MACHINE_ID.fullmatch(config["machine_id"])
            or not isinstance(config.get("machine_name"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", config["machine_name"])):
        raise AgentError("The local AD machine configuration is invalid.")
    try:
        host, port, pin = _server(config["server_url"], config["tls_sha256"])
    except ValueError as exc:
        raise AgentError("The local AD service URL or certificate pin is invalid.") from exc
    if not protected_key or len(protected_key) > 64 * 1024:
        raise AgentError("The protected AD machine key file is invalid.")
    try:
        private_der = _dpapi(protected_key, decrypt=True)
        key = serialization.load_der_private_key(private_der, password=None)
    except (ValueError, TypeError) as exc:
        raise AgentError("The protected AD machine key could not be loaded.") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise AgentError("The stored AD machine key has an unsupported type.")
    return config, key, host, port, pin


def _signed_post(path: str, body: dict, timeout: float = 8.0) -> dict:
    config, key, host, port, pin = _load()
    machine_id = config["machine_id"]
    raw = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    timestamp = int(time.time())
    nonce = secrets.token_urlsafe(24)
    if not _NONCE.fullmatch(nonce):
        raise AgentError("Could not create a valid machine request nonce.")
    canonical = "\n".join((MACHINE_SIGNATURE_DOMAIN, "POST", path, machine_id,
                           str(timestamp), nonce, hashlib.sha256(raw).hexdigest())).encode("ascii")
    signature = base64.b64encode(key.sign(canonical, ec.ECDSA(hashes.SHA256()))).decode("ascii")
    headers = {
        "X-Thessley-Machine-ID": machine_id,
        "X-Thessley-Timestamp": str(timestamp),
        "X-Thessley-Nonce": nonce,
        "X-Thessley-Signature": signature,
    }
    return _post(host, port, pin, path, body, headers, timeout)


def start_login(sid: str, context: str) -> dict:
    """Ask AD-backed service to authorize the selected domain SID and create a phone request."""
    if not isinstance(sid, str) or not _SID.fullmatch(sid) or context not in ("interactive", "unlock"):
        raise AgentError("The selected domain SID or Windows logon context is invalid.")
    principal_id = hashlib.sha256(sid.upper().encode("ascii")).hexdigest()
    result = _signed_post("/thessley-ad/v1/requests", {"sid": sid.upper(), "context": context})
    request = result.get("request")
    link = result.get("app_link")
    if result.get("result") != "created" or not isinstance(request, dict) or not isinstance(link, str):
        raise AgentError("The AD service did not return a valid phone request.")
    config, _key, host, port, pin = _load()
    request_id = request.get("request_id")
    nonce = request.get("nonce")
    if (not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
            or not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", nonce)
            or request.get("machine_id") != config["machine_id"]
            or request.get("principal_id") != principal_id or request.get("context") != context
            or request.get("principal_type") != "domain"):
        raise AgentError("The AD service returned a request for a different account or sign-in context.")
    try:
        parsed = urlsplit(link)
        query = parse_qs(parsed.query, strict_parsing=True)
    except ValueError as exc:
        raise AgentError("The AD service returned a malformed phone link.") from exc
    required = ("h", "p", "fp", "id", "n", "m", "hn", "u", "pv", "sid", "scope", "auth", "ctx", "api")
    if (parsed.scheme != "thessleypam" or parsed.netloc != "login"
            or any(len(query.get(name, [])) != 1 for name in required)
            or query.get("api") != ["ad"] or query.get("pv") != ["2"]
            or query.get("id") != [request_id]
            or query.get("sid") != [principal_id]
            or query.get("ctx") != [context]
            or query.get("m") != [config["machine_id"]]
            or query.get("fp", [""])[0].lower() != pin
            or query.get("h", [""])[0].lower() != host.lower()
            or query.get("p") != [str(port)]):
        raise AgentError("The AD service returned a phone link with mismatched machine, SID, or certificate details.")
    for key, value in (("n", nonce), ("u", request.get("username")),
                       ("auth", request.get("authority")), ("scope", "domain")):
        if query.get(key) != [value]:
            raise AgentError("The AD service returned a phone link for a different account.")
    return {"request_id": request_id, "link": link,
            "qr_matrix": "/".join(qr.bitmap_rows(link, border=2))}


def poll_login(request_id: str, cancel, say=lambda _message: None, timeout: int = 95) -> bool:
    """Poll a one-use machine-bound AD approval result. Does not perform Windows logon."""
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
        raise AgentError("Invalid AD sign-in request id.")
    deadline = time.monotonic() + max(1, min(int(timeout), 120))
    while time.monotonic() < deadline:
        if cancel.is_set():
            return False
        result = _signed_post("/thessley-ad/v1/requests/result", {"request_id": request_id}, timeout=8.0)
        state = result.get("status")
        if state == "approved":
            say("Phone approval verified. Windows certificate sign-in is not yet connected.")
            return True
        if state in ("denied", "expired", "consumed"):
            say("Phone approval was denied or expired.")
            return False
        if state != "pending":
            raise AgentError("The AD service returned an unknown sign-in status.")
        cancel.wait(1.0)
    say("Phone approval timed out.")
    return False


def start_phone_enrollment(sid: str) -> dict:
    """Create an Android phone-enrollment QR for an authorized domain SID."""
    if not isinstance(sid, str) or not _SID.fullmatch(sid):
        raise AgentError("The domain account SID is invalid.")
    result = _signed_post("/thessley-ad/v1/enrollments", {"sid": sid.upper()})
    request = result.get("request")
    link = result.get("app_link")
    if result.get("result") != "created" or not isinstance(request, dict) or not isinstance(link, str):
        raise AgentError("The AD service did not return a valid phone enrollment request.")
    config, _key, host, port, pin = _load()
    request_id, nonce = request.get("request_id"), request.get("nonce")
    principal_id = hashlib.sha256(sid.upper().encode("ascii")).hexdigest()
    if (not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
            or not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", nonce)
            or request.get("machine_id") != config["machine_id"]
            or request.get("principal_id") != principal_id
            or request.get("principal_type") != "domain"
            or request.get("context") != "enrollment"):
        raise AgentError("The AD service returned an enrollment for a different machine or account.")
    try:
        parsed = urlsplit(link)
        query = parse_qs(parsed.query, strict_parsing=True)
    except ValueError as exc:
        raise AgentError("The AD service returned a malformed phone link.") from exc
    required = ("h", "p", "fp", "id", "n", "m", "hn", "u", "pv", "sid", "scope", "auth", "ctx", "api")
    if (parsed.scheme != "thessleypam" or parsed.netloc != "enroll"
            or any(len(query.get(name, [])) != 1 for name in required)
            or query.get("api") != ["ad"] or query.get("pv") != ["2"]
            or query.get("id") != [request_id] or query.get("n") != [nonce]
            or query.get("m") != [config["machine_id"]] or query.get("sid") != [principal_id]
            or query.get("scope") != ["domain"] or query.get("ctx") != ["enrollment"]
            or query.get("fp", [""])[0].lower() != pin
            or query.get("h", [""])[0].lower() != host.lower()
            or query.get("p") != [str(port)]
            or query.get("u") != [request.get("username")]
            or query.get("auth") != [request.get("authority")]):
        raise AgentError("The AD service returned a phone link with mismatched account or certificate details.")
    return {"request_id": request_id, "link": link,
            "qr_matrix": "/".join(qr.bitmap_rows(link, border=2)),
            "username": request.get("username"), "authority": request.get("authority")}


def phone_enrollment_status(request_id: str) -> dict:
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
        raise AgentError("Invalid phone enrollment request id.")
    result = _signed_post("/thessley-ad/v1/enrollments/status", {"request_id": request_id})
    if result.get("status") not in ("pending", "ready", "confirmed", "expired", "denied"):
        raise AgentError("The AD service returned an unknown phone enrollment state.")
    if result.get("status") == "ready" and (
            not isinstance(result.get("pairing_code"), str)
            or not re.fullmatch(r"[0-9]{3} [0-9]{3}", result["pairing_code"])):
        raise AgentError("The AD service returned an invalid phone pairing code.")
    return result


def confirm_phone_enrollment(request_id: str, pairing_code: str) -> None:
    if (not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
            or not isinstance(pairing_code, str) or not re.fullmatch(r"[0-9]{3} [0-9]{3}", pairing_code)):
        raise AgentError("Invalid phone enrollment confirmation.")
    result = _signed_post("/thessley-ad/v1/enrollments/confirm", {
        "request_id": request_id, "pairing_code": pairing_code,
    })
    if result.get("result") != "confirmed":
        raise AgentError("The AD service did not confirm phone enrollment.")


def cancel_phone_enrollment(request_id: str) -> None:
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
        raise AgentError("Invalid phone enrollment request id.")
    result = _signed_post("/thessley-ad/v1/enrollments/cancel", {"request_id": request_id})
    if result.get("result") not in ("cancelled", "error"):
        raise AgentError("The AD service did not confirm cancellation.")
