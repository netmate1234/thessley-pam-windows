"""Opt-in Windows sign-in prototype backed by a Thessley Drupal server.

The service owns an account-scoped ECDSA key under ProgramData. Drupal stores
only its public half. The configured leaf-certificate SHA-256 pin is checked
before sending a request; redirects are rejected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import time
from urllib.parse import parse_qs, quote, urlsplit
from urllib.parse import urlunsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import machine, store

SIG_VERSION = "thessley_win_agent_v1"
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


class AgentError(RuntimeError):
    """Remote request failed or returned an invalid response."""


def _paths(username: str) -> tuple[str, str]:
    name = store.normalize_user(username)
    folder = os.path.join(store.BASE, "drupal-agent")
    return os.path.join(folder, name + ".json"), os.path.join(folder, name + ".pem")


def _lock_windows_acl(path: str, directory: bool = False) -> None:
    """Restrict agent material to LocalSystem and local Administrators."""
    if os.name != "nt":
        raise AgentError("Drupal agent identity setup is supported on Windows only.")
    flags = ["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]
    if directory:
        flags.extend(["/T", "/C"])
    result = subprocess.run(["icacls.exe", path, *flags], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AgentError("Could not restrict access to the Drupal agent key files.")


def _server_url(value: str) -> str:
    parsed = urlsplit(str(value).strip())
    if (parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Use an HTTPS Drupal site origin, for example https://login.example.com.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("The Drupal server URL has an invalid port.") from exc
    return f"https://{parsed.netloc.lower()}"


def _sid_hash(username: str) -> str:
    if os.name != "nt":
        raise AgentError("The Windows account SID can only be read on Windows.")
    # The current prototype supports local Windows accounts. Constructing the
    # NTAccount explicitly keeps the result independent of the admin who runs
    # this elevated setup command.
    escaped = username.replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f"$account=[System.Security.Principal.NTAccount]::new($env:COMPUTERNAME,'{escaped}'); "
        "$sid=$account.Translate([System.Security.Principal.SecurityIdentifier]).Value; "
        "Write-Output $sid"
    )
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, errors="replace", timeout=20, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError("Could not resolve that local Windows account to a SID.") from exc
    sid = result.stdout.strip()
    if not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid):
        raise AgentError("Windows returned an invalid account SID.")
    return hashlib.sha256(sid.encode("ascii")).hexdigest()


def initialize(username: str, server_url: str, tls_sha256: str) -> dict:
    """Create a protected software key and return fields for Drupal enrollment."""
    username = store.normalize_user(username)
    if not USER_RE.fullmatch(username):
        raise AgentError("The account name is not supported by the current Drupal PAM protocol.")
    config_path, key_path = _paths(username)
    resolved_server = _server_url(server_url)
    tls_sha256 = str(tls_sha256).strip().lower().replace(":", "")
    if not re.fullmatch(r"[a-f0-9]{64}", tls_sha256):
        raise ValueError("Enter the 64-character SHA-256 fingerprint shown in Drupal Windows Access settings.")
    sid_hash = _sid_hash(username)
    folder = os.path.dirname(config_path)
    os.makedirs(folder, exist_ok=True)
    if os.path.exists(config_path) or os.path.exists(key_path):
        raise AgentError("A Drupal agent key already exists for this account. Keep it and update its Drupal binding.")

    # Lock the directory before writing either key material or configuration.
    _lock_windows_acl(folder, directory=True)
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    config = {
        "version": 1,
        "server_url": resolved_server,
        "tls_sha256": tls_sha256,
        "machine_id": machine.machine_id(),
        "username": username,
        "key_file": key_path,
    }
    try:
        with open(key_path, "xb") as stream:
            stream.write(private_pem)
            stream.flush()
            os.fsync(stream.fileno())
        with open(config_path, "x", encoding="utf-8") as stream:
            json.dump(config, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        _lock_windows_acl(key_path)
        _lock_windows_acl(config_path)
    except BaseException:
        for path in (config_path, key_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        raise
    return {
        "machine_id": config["machine_id"],
        "hostname": machine.hostname(),
        "username": username,
        "sid_sha256": sid_hash,
        "agent_public_key_b64_der": base64.b64encode(public_der).decode("ascii"),
        "server_url": config["server_url"],
        "tls_sha256": tls_sha256,
    }


def configured(username: str) -> bool:
    config_path, key_path = _paths(username)
    return os.path.isfile(config_path) and os.path.isfile(key_path)


def _load(username: str) -> tuple[dict, ec.EllipticCurvePrivateKey]:
    config_path, key_path = _paths(username)
    try:
        with open(config_path, encoding="utf-8") as stream:
            config = json.load(stream)
        if config.get("version") != 1 or config.get("username") != store.normalize_user(username):
            raise ValueError("account mismatch")
        if not re.fullmatch(r"[a-f0-9]{64}", str(config.get("tls_sha256", ""))):
            raise ValueError("invalid TLS pin")
        if os.path.normcase(os.path.abspath(config.get("key_file", ""))) != os.path.normcase(os.path.abspath(key_path)):
            raise ValueError("key path mismatch")
        config["server_url"] = _server_url(config.get("server_url", ""))
        with open(key_path, "rb") as stream:
            key = serialization.load_pem_private_key(stream.read(8192), password=None)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise AgentError("The Drupal agent configuration or private key is unavailable.") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise AgentError("The Drupal agent key is not an ECDSA P-256 key.")
    return config, key


def _canonical(fields: list[str]) -> bytes:
    if any(not value or re.search(r"[|\s\x00-\x1f\x7f]", value) for value in fields):
        raise AgentError("Invalid field in signed Drupal request.")
    return "|".join([SIG_VERSION, *fields]).encode("utf-8")


def _post(url: str, payload: dict, tls_sha256: str, timeout: float = 8.0) -> dict:
    target = urlsplit(url)
    if target.scheme != "https" or not target.hostname or target.username or target.password or target.fragment:
        raise AgentError("Refusing a non-HTTPS or malformed Drupal endpoint.")
    port = target.port or 443
    path = urlunsplit(("", "", target.path or "/", target.query, ""))
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    # The first prototype uses the Drupal admin's separately copied SHA-256
    # certificate fingerprint, matching the phone's pinned server identity.
    # Do not send a request until the leaf certificate matches that pin.
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_context.check_hostname = False
    tls_context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        target.hostname,
        port,
        timeout=timeout,
        context=tls_context,
    )
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True) if connection.sock else b""
        actual_pin = hashlib.sha256(certificate).hexdigest()
        if not hmac.compare_digest(actual_pin, tls_sha256):
            raise AgentError("Drupal's TLS certificate does not match the configured fingerprint.")
        connection.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",
        })
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            raise AgentError("Drupal redirected a signed request; refusing to follow it.")
        if response.status != 200:
            raise AgentError(f"Drupal rejected the request (HTTP {response.status}).")
        raw = response.read(16385)
    except AgentError:
        raise
    except (http.client.HTTPException, TimeoutError, OSError, ValueError) as exc:
        raise AgentError("The Drupal approval server could not be reached securely.") from exc
    finally:
        connection.close()
    if len(raw) > 16384:
        raise AgentError("Drupal returned an oversized response.")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentError("Drupal returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise AgentError("Drupal returned an invalid response.")
    return data


def _signature(key: ec.EllipticCurvePrivateKey, fields: list[str]) -> str:
    return base64.b64encode(key.sign(_canonical(fields), ec.ECDSA(hashes.SHA256()))).decode("ascii")


def _validate_app_link(link: str, config: dict, request_id: str, nonce: str) -> None:
    parsed = urlsplit(link)
    try:
        query = parse_qs(parsed.query, strict_parsing=True)
    except ValueError as exc:
        raise AgentError("Drupal returned a malformed phone approval link.") from exc
    server = urlsplit(config["server_url"])
    expected_port = server.port or 443
    required = ("h", "p", "fp", "id", "n", "m", "u")
    if any(len(query.get(name, [])) != 1 for name in required):
        raise AgentError("Drupal returned an incomplete phone approval link.")
    try:
        link_port = int(query["p"][0])
    except ValueError as exc:
        raise AgentError("Drupal returned an incomplete phone approval link.") from exc
    if (parsed.scheme != "thessleypam" or parsed.netloc != "login"
            or query.get("h", [""])[0].lower() != (server.hostname or "").lower()
            or link_port != expected_port
            or query["fp"][0].lower() != config["tls_sha256"]
            or query.get("id", [""])[0] != request_id
            or query.get("n", [""])[0] != nonce
            or query.get("m", [""])[0] != config["machine_id"]
            or query.get("u", [""])[0] != config["username"]
            or not re.fullmatch(r"[a-f0-9]{64}", query["fp"][0])):
        raise AgentError("Drupal returned a phone link for a different server or Windows account.")


def run_login(username: str, say, cancel, log=None) -> bool:
    """Create the signed Drupal challenge, show its PAM link, and fail closed polling."""
    log = log or (lambda _message, _warn=False: None)
    config, key = _load(username)
    username = config["username"]
    machine_id = config["machine_id"]
    root = config["server_url"]
    route = f"{root}/thessley-windows/v1/{machine_id}/{quote(username, safe='')}/challenge/login"
    timestamp = int(time.time())
    client_nonce = secrets.token_urlsafe(32)
    signature = _signature(key, ["challenge", machine_id, username, client_nonce, str(timestamp)])
    response = _post(route, {"client_nonce": client_nonce, "timestamp": timestamp, "signature": signature}, config["tls_sha256"])
    if response.get("result") != "ok":
        raise AgentError(str(response.get("message") or "Drupal did not start the approval."))
    request_id = response.get("request_id")
    nonce = response.get("nonce")
    link = response.get("app_link")
    expires_in = response.get("expires_in")
    if (not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", request_id)
            or not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", nonce)
            or not isinstance(link, str) or not isinstance(expires_in, int) or not 30 <= expires_in <= 600):
        raise AgentError("Drupal returned an invalid approval request.")
    _validate_app_link(link, config, request_id, nonce)
    say("Link: " + link)
    say("Waiting for phone approval...")

    deadline = time.monotonic() + min(expires_in, 120)
    while time.monotonic() < deadline:
        if cancel.is_set():
            return False
        timestamp = int(time.time())
        poll_signature = _signature(key, ["poll", machine_id, username, request_id, nonce, str(timestamp)])
        status_url = f"{root}/thessley-windows/v1/{machine_id}/{quote(username, safe='')}/requests/{request_id}/status"
        result = _post(status_url, {"timestamp": timestamp, "signature": poll_signature}, config["tls_sha256"], timeout=5.0)
        status = result.get("result")
        if status == "approved":
            say("Phone approval accepted.")
            return True
        if status in ("denied", "expired", "consumed"):
            say("Phone approval was not accepted.")
            return False
        if status != "pending":
            raise AgentError("Drupal returned an unknown approval status.")
        cancel.wait(1.0)
    say("Phone approval timed out.")
    return False
