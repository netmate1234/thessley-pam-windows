"""A short-lived HTTPS listener the phone talks to while one request is open.

Each run makes a throwaway self-signed certificate; its SHA-256 goes into the QR code and the app trusts
exactly that certificate (PinnedClient.kt). Nothing about the TLS key is kept after the run.
"""

import datetime
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

MAX_BODY = 64 * 1024
SHARED_PORT = 47810

# (path, parsed JSON body) -> (HTTP status, JSON reply). Raise nothing; return an error reply instead.
Route = Callable[[str, dict], tuple[int, dict]]


def _make_cert(ip: str, tmp: str) -> tuple[str, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(tmp, "cert.pem")
    key_path = os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


class Listener:
    """POST-only JSON server for the routes given. Use as a context manager."""

    def __init__(self, ip: str, port: int, routes: dict[str, Route]):
        self.ip, self.port, self.routes = ip, port, routes
        self.fingerprint = ""
        self._tmp = None
        self._httpd = None

    def __enter__(self) -> "Listener":
        self._tmp = tempfile.TemporaryDirectory(prefix="thessley-pam-")
        cert_path, key_path, self.fingerprint = _make_cert(self.ip, self._tmp.name)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        # The key is loaded; nothing needs it on disk any more.
        self._tmp.cleanup()

        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                route = routes.get(self.path)
                if route is None:
                    self._reply(404, {"result": "error", "message": "Not found."})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0 or length > MAX_BODY:
                    self._reply(400, {"result": "error", "message": "Bad request body."})
                    return
                try:
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    self._reply(400, {"result": "error", "message": "Body is not a JSON object."})
                    return
                status, reply = route(self.client_address[0], body)
                self._reply(status, reply)

            def log_message(self, fmt, *a):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            # Windows differs from Linux here: with SO_REUSEADDR (the default) a second listener can bind a port that is
            # already in use, so two logins could share one port and the phone would reach the wrong one. Bind exclusively.
            allow_reuse_address = False

            def server_bind(self):
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()

            def handle_error(self, request, client_address):
                pass  # a phone that hangs up mid-request (e.g. after a certificate mismatch) is not an error here

        self._httpd = Server((self.ip, self.port), Handler)
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


class SharedListener:
    """One permanent HTTPS listener that routes concurrent requests to temporary approvals."""

    def __init__(self, ip: str, cert_path: str, key_path: str, fingerprint: str):
        self.ip, self.cert_path, self.key_path = ip, cert_path, key_path
        self.fingerprint = fingerprint
        self.routes: dict[str, Route] = {}
        self.lock = threading.Lock()
        self.httpd = None
        self.thread = None

    def start(self) -> None:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _reply(self, status: int, body: dict) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True

            def do_POST(self):
                with owner.lock:
                    route = owner.routes.get(self.path)
                if route is None:
                    self._reply(404, {"result": "error", "message": "Not found."})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                if length <= 0 or length > MAX_BODY:
                    self._reply(400, {"result": "error", "message": "Bad request body."})
                    return
                try:
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        raise ValueError
                except (ValueError, json.JSONDecodeError):
                    self._reply(400, {"result": "error", "message": "Body is not a JSON object."})
                    return
                try:
                    status, reply = route(self.client_address[0], body)
                except Exception:
                    status, reply = 500, {"result": "error", "message": "Could not process this response."}
                self._reply(status, reply)

            def log_message(self, fmt: str, *args) -> None:
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = False

            def server_bind(self):
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()

            def handle_error(self, request, client_address):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert_path, self.key_path)
        httpd = Server((self.ip, SHARED_PORT), Handler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        self.httpd = httpd
        self.thread = threading.Thread(target=httpd.serve_forever, name="approval-https", daemon=True)
        self.thread.start()

    @contextmanager
    def register(self, routes: dict[str, Route]):
        with self.lock:
            if any(path in self.routes for path in routes):
                raise OSError("An approval route is already active.")
            self.routes.update(routes)
        try:
            yield SimpleNamespace(port=SHARED_PORT, fingerprint=self.fingerprint)
        finally:
            with self.lock:
                for path in routes:
                    self.routes.pop(path, None)

    def close(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
