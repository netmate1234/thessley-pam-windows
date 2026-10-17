"""The admin web page: sign in with your account name and an approval, then manage your Thessley approvers.

    thessley-pam-win web on|off|status|serve        (serve is what the scheduled task runs)
    thessley-pam-win web listen ADDRESS             which address to listen on ("" = this computer's LAN address)
    thessley-pam-win web port N | session MINUTES | cert FILE KEY

It is the Windows counterpart of thessley-pam-linux's page (see its docs/WEB.md) and works the same way:

  * No passwords. You type your account name; the page shows the same QR code and text link as an ssh login, and an
    enrolled phone or desktop app approves it with its signature ("admin page sign-in" on the phone).
  * Anything that changes approvers or settings asks for a fresh approval first ("a change to your keys"; adding one is
    "adding a device"), so a stolen browser session can look but not change anything.
  * You manage your own approvers. Administrators (members of the local Administrators group) can also pick any account
    and change the settings (how long one approval counts, whether users may enrol their own first approver).
  * It runs as SYSTEM in its own scheduled task (the approvers and passes are SYSTEM-only), and never takes a command or a
    path from the browser: everything it acts on is looked up from the signed-in account against a strict pattern.

Served over HTTPS with a certificate of its own, made on first start (the browser warns once; `web cert` takes a real
one). `web status` prints its fingerprint.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import approve, enroll, grants, machine, store

TTY_LOGIN, TTY_CHANGE, TTY_DEVICE = "web", "web-change", "add-device"  # what approve.run is told (it names them for the apps)

CRED_RE = re.compile(r"^c_[0-9a-f]{16}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")

MAX_BODY = 8 * 1024
SESSION_MAX_SECONDS = 8 * 3600
FLOW_KEEP_SECONDS = 15 * 60
LOGIN_RATE = (8, 300)  # at most 8 sign-in requests per client address in 300 s
MAX_FLOWS = 40


def now() -> float:
    return time.time()


# ---- who is an administrator -------------------------------------------------------------------------------------

_ADMIN_CACHE: dict = {"at": 0.0, "names": set()}


def admin_names() -> set[str]:
    """The members of the local Administrators group (by its well-known SID, so any language), as plain account names."""
    if now() - _ADMIN_CACHE["at"] < 120:
        return _ADMIN_CACHE["names"]
    names: set[str] = set()
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }"],
            capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            try:
                names.add(store.normalize_user(line))
            except ValueError:
                continue
    except (OSError, subprocess.TimeoutExpired):
        pass
    _ADMIN_CACHE.update(at=now(), names=names)
    return names


def is_admin(username: str) -> bool:
    try:
        return store.normalize_user(username) in admin_names()
    except ValueError:
        return False


# ---- one approval or enrolment in progress -----------------------------------------------------------------------

class Flow:
    """A sign-in, a step-up approval or an enrolment, driven by a thread; the page polls its state."""

    def __init__(self, kind: str, user: str, description: str = "", on_approved=None, owner: str | None = None):
        self.id = secrets.token_hex(16)
        self.owner = owner or user  # the signed-in account that started it (an administrator may act on another account)
        self.secret = secrets.token_hex(16)  # only the browser that started it knows this (a cookie)
        self.kind, self.user, self.description = kind, user, description
        self.on_approved = on_approved
        self.state = "starting"   # starting, waiting, confirm (enrolment: codes shown), approved, refused, timeout, done, failed
        self.lines: list[str] = []
        self.link = ""
        self.code = ""
        self.label = ""
        self.created = now()
        self.cancel = threading.Event()
        self.answer: bool | None = None
        self.answered = threading.Event()
        self.executed = False
        self.result_url = ""
        self.flash = ""
        self.lock = threading.Lock()

    def say(self, text: str) -> None:
        for line in str(text).splitlines():
            self.lines.append(line)
            m = re.match(r"Link: (thessleypam://\S+)", line)
            if m:
                self.link = m.group(1)
            m = re.search(r"Code:\s+(\d{3} \d{3})", line)
            if m:
                self.code = m.group(1)
            m = re.match(r"Phone '(.*)' \(", line)
            if m:
                self.label = m.group(1)


class Session:
    def __init__(self, user: str, minutes: int):
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(24)
        self.user = user
        self.created = self.last = now()
        self.minutes = minutes
        self.flash = ""

    def valid(self) -> bool:
        t = now()
        return t - self.last < self.minutes * 60 and t - self.created < SESSION_MAX_SECONDS


class WebApp:
    """All state and rules, apart from HTTP. Tests drive it directly or through the server."""

    def __init__(self, journal=None, qr=None, log=None):
        self.log = log or (lambda msg, warn=False: None)
        self.sessions: dict[str, Session] = {}
        self.flows: dict[str, Flow] = {}
        self.attempts: dict[str, list[float]] = {}
        self.lock = threading.Lock()
        self.journal = journal or journal_lines
        self.qr = qr or qr_svg

    # -- housekeeping
    def settings(self) -> dict:
        return grants.web_settings()

    def sweep(self) -> None:
        t = now()
        with self.lock:
            for token in [k for k, s in self.sessions.items() if not s.valid()]:
                del self.sessions[token]
            for fid in [k for k, f in self.flows.items() if t - f.created > FLOW_KEEP_SECONDS]:
                self.flows[fid].cancel.set()
                self.flows[fid].answered.set()
                del self.flows[fid]

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self.lock:
            s = self.sessions.get(token)
            if s is None:
                return None
            if not s.valid():
                del self.sessions[token]
                return None
            s.last = now()
            return s

    def rate_ok(self, ip: str) -> bool:
        limit, window = LOGIN_RATE
        t = now()
        with self.lock:
            hits = [x for x in self.attempts.get(ip, []) if t - x < window]
            if len(hits) >= limit:
                self.attempts[ip] = hits
                return False
            hits.append(t)
            self.attempts[ip] = hits
            return True

    # -- starting flows
    def _new_flow(self, flow: Flow) -> Flow | None:
        self.sweep()
        with self.lock:
            if len(self.flows) >= MAX_FLOWS:
                return None
            self.flows[flow.id] = flow
        return flow

    def _approval_thread(self, flow: Flow, tty: str, ip: str) -> None:
        flow.state = "waiting"
        try:
            # never a pass, and none granted: a web sign-in or a change must be approved afresh each time
            ok = approve.run(flow.user, ip, tty, flow.say, self.log, port=approve.PORT, use_pass=False, grant_pass=False)
        except Exception as exc:  # strict: any trouble is a refusal
            flow.say(f"error: {exc!r}")
            ok = False
        text = "\n".join(flow.lines)
        flow.state = "approved" if ok else ("timeout" if "no answer" in text else "refused")

    def usable(self, user: str) -> bool:
        """An account with at least one approver that may approve (approve.run refuses the rest, but say so up front)."""
        try:
            return bool(store.active_devices(store.normalize_user(user)))
        except (ValueError, OSError):
            return False

    def start_login(self, user: str, ip: str) -> Flow | None:
        if not self.usable(user):
            return None
        user = store.normalize_user(user)
        flow = self._new_flow(Flow("login", user, "Sign in"))
        if flow:
            threading.Thread(target=self._approval_thread, args=(flow, TTY_LOGIN, ip), daemon=True).start()
        return flow

    def start_change(self, session: Session, ip: str, description: str, action, tty: str = TTY_CHANGE) -> Flow | None:
        """A fresh approval by the signed-in account's phone, then `action()` runs once (it returns (url, message))."""
        if not self.usable(session.user):
            return None
        flow = self._new_flow(Flow("change", session.user, description, on_approved=action, owner=session.user))
        if flow:
            threading.Thread(target=self._approval_thread, args=(flow, tty, ip), daemon=True).start()
        return flow

    def start_enroll(self, user: str, owner: str | None = None) -> Flow | None:
        flow = self._new_flow(Flow("enroll", user, "Add a phone or app", owner=owner))
        if flow is None:
            return None

        def ask_yes(prompt: str, timeout: float) -> bool:
            flow.state = "confirm"
            flow.answered.wait(timeout)
            return flow.answer is True and not flow.cancel.is_set()

        def work():
            flow.state = "waiting"
            try:
                device = enroll.run(user, flow.say, ask_yes, port=approve.PORT, cancel=flow.cancel, show_link=True)
            except Exception as exc:
                flow.say(f"error: {exc!r}")
                device = None
            flow.state = "done" if device else "failed"

        threading.Thread(target=work, daemon=True).start()
        return flow

    def flow(self, fid: str) -> Flow | None:
        if not ID_RE.match(fid or ""):
            return None
        with self.lock:
            return self.flows.get(fid)

    def finish(self, flow: Flow) -> tuple[str, str]:
        """Once an approval came: for a sign-in the caller makes the session; for a change, run it (once)."""
        with flow.lock:
            if flow.state == "approved" and flow.kind == "change" and not flow.executed:
                flow.executed = True
                try:
                    flow.result_url, flow.flash = flow.on_approved()
                except Exception as exc:
                    flow.result_url, flow.flash = "/keys", f"That did not work: {exc}"
            return flow.result_url, flow.flash

    def new_session(self, user: str) -> Session:
        s = Session(user, self.settings()["session_minutes"])
        with self.lock:
            self.sessions[s.token] = s
        return s

    def drop_session(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    # -- what a signed-in account may touch
    def target(self, session: Session, wanted: str | None) -> str | None:
        """The account whose keys are shown: your own, or (administrators) any account that has a key list."""
        if not wanted or wanted == session.user:
            return session.user
        try:
            wanted = store.normalize_user(wanted)
        except ValueError:
            return None
        if is_admin(session.user) and wanted in store.all_users():
            return wanted
        return None

    # -- the changes (each runs only after an approval)
    def change_rename(self, user: str, cred: str, label: str):
        def run():
            if not store.rename_device(user, cred, label):
                raise ValueError("no such key")
            return f"/keys?user={user}", f"Renamed to {label}."
        return run

    def change_disable(self, user: str, cred: str, off: bool):
        def run():
            if not store.set_disabled(user, cred, off):
                raise ValueError("no such key")
            return f"/keys?user={user}", "Switched off." if off else "Switched on."
        return run

    def change_remove(self, user: str, cred: str):
        def run():
            if not store.remove_device(user, cred):
                raise ValueError("no such key")
            return f"/keys?user={user}", "Removed. Its passes ended with it."
        return run

    def change_begin_enroll(self, user: str, owner: str):
        def run():
            flow = self.start_enroll(user, owner)
            if flow is None:
                raise ValueError("too many requests at once, try again in a minute")
            return f"/enroll/{flow.id}", ""
        return run

    def change_setting(self, name: str, value: str):
        def run():
            if name == "grace":
                grants.set_grace(float(value))
                return "/admin", f"One approval now counts for {float(value):g} h (0 = every login asks)."
            if name == "self_enroll":
                grants.set_self_enroll_first(value == "on")
                return "/admin", "Users enrolling their own first approver: " + ("on." if value == "on" else "off.")
            raise ValueError("unknown setting")
        return run

    # -- per-key details
    def key_usage(self) -> dict[str, tuple[int, str, str]]:
        """credential id -> (times it approved, when last, from which address) from the journal."""
        out: dict[str, list] = {}
        pattern = re.compile(r"approved by '.*?' \((?P<cred>c_\w+)\) from (?P<ip>[\d.:]+) for \S+ \(from ")
        for line in self.journal():
            m = LOG_LINE.match(line)
            hit = pattern.search(m.group(2)) if m else None
            if hit:
                entry = out.setdefault(hit["cred"], [0, "", ""])
                entry[0] += 1
                entry[1], entry[2] = m.group(1), hit["ip"]
        return {k: (v[0], v[1], v[2]) for k, v in out.items()}

    def key_details(self, user: str, device: dict, usage: dict) -> list[tuple[str, str]]:
        """Everything worth knowing about one key, as (name, value) rows."""
        cred = device["credential_id"]
        rows = attestation_facts(device.get("attestation_chain") or [], device.get("attestation")) + public_key_facts(device.get("public_key", ""))
        count, when, ip = usage.get(cred, (0, "", ""))
        rows.append(("Approvals in the log", f"{count}" + (f", the last on {when} from {ip}" if count else "")))
        try:
            held = [p for p in grants.all_passes() if p.get("user") == user and p.get("credential") == cred]
        except OSError:
            held = []
        rows.append(("Passes it granted that are still valid",
                     "; ".join(f"from {p['rhost']} ({grants.remaining(p)} left)" for p in held) or "none"))
        return rows

    # -- the activity log
    def activity(self, user: str | None) -> list[tuple[str, str]]:
        out = []
        for line in self.journal():
            parsed = parse_activity(line, user)
            if parsed:
                out.append(parsed)
        return out[-80:][::-1]


# ---- what is known about a key -----------------------------------------------------------------------------------

ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"  # Android key attestation: the extension that says where the key lives
SECURITY_LEVELS = {0: "Software only", 1: "Trusted environment (TEE)", 2: "StrongBox (separate secure chip)"}


def _der(data: bytes, pos: int) -> tuple[int, int, int]:
    """One DER element at pos: (tag, start of its content, end of its content)."""
    tag = data[pos]
    first = data[pos + 1]
    if first < 0x80:
        length, start = first, pos + 2
    else:
        n = first & 0x7F
        length, start = int.from_bytes(data[pos + 2:pos + 2 + n], "big"), pos + 2 + n
    if start + length > len(data):
        raise ValueError("truncated")
    return tag, start, start + length


def parse_key_description(raw: bytes) -> dict:
    """The first fields of an Android KeyDescription: attestation version and where the key was made and is kept."""
    tag, start, end = _der(raw, 0)
    if tag != 0x30:
        raise ValueError("not a sequence")
    values, pos = [], start
    for _ in range(4):  # attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel
        t, s, e = _der(raw, pos)
        values.append(int.from_bytes(raw[s:e], "big"))
        pos = e
    return {"version": values[0], "attestation_level": values[1], "key_level": values[3]}


def public_key_facts(public_key_b64: str) -> list[tuple[str, str]]:
    """Algorithm and fingerprint of a stored public key (base64 SubjectPublicKeyInfo)."""
    try:
        der = base64.b64decode(public_key_b64)
        key = serialization.load_der_public_key(der)
    except Exception:
        return [("Public key", "could not be read")]
    algo = "unknown"
    if isinstance(key, ec.EllipticCurvePublicKey):
        algo = f"ECDSA on {key.curve.name} (signs with SHA-256)"
    digest = hashlib.sha256(der).hexdigest()
    return [("Algorithm", algo), ("Key fingerprint (SHA-256)", ":".join(digest[i:i + 4] for i in range(0, 32, 4)) + "…")]


def tpm_proof_facts(record: dict | None) -> list[tuple[str, str]]:
    """What this computer itself concluded about a TPM key at enrolment (see tpmproof.py)."""
    if not record:
        return []
    if record.get("level") == "tpm":
        maker = (str(record.get("maker", "")) + " " + str(record.get("model", ""))).strip() or "a maker that is not named"
        when = ""
        if record.get("checked_at"):
            when = " on " + datetime.datetime.fromtimestamp(int(record["checked_at"])).strftime("%Y-%m-%d %H:%M")
        return [("TPM 2.0 proof", f"Verified by this computer{when}: a genuine TPM 2.0 chip from {maker} holds this key. It was "
                                  "created inside the chip and cannot leave it. Checked against the manufacturer roots shipped "
                                  "with this program; revocation lists are not checked."),
                ("TPM maker", maker)]
    return [("TPM 2.0 proof", f"The app claimed a TPM-held key but this computer could not verify it: {record.get('reason', 'no reason given')}.")]


def attestation_facts(chain: list[str], record: dict | None = None) -> list[tuple[str, str]]:
    """What a stored attestation chain (a phone) or this computer's own TPM check (an app) says about a key. A phone's chain
    is kept but not checked against a root of trust."""
    if not chain:
        if record and record.get("level") == "tpm":
            return [("Kind", "An app key (Thessley Passkey desktop app) held in a TPM chip, proven at enrolment.")] + tpm_proof_facts(record)
        return [("Kind", "An app key (Thessley Passkey desktop app): no hardware attestation was sent. Its protection (PIN, TPM chip, "
                         "security key) is set on that computer."),
                ("Hardware attestation", "none")] + tpm_proof_facts(record)
    facts = [("Kind", "A phone key (Android Keystore)")]
    try:
        certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in chain]
    except Exception:
        return facts + [("Hardware attestation", f"{len(chain)} certificates stored, but they could not be read")]
    facts.append(("Hardware attestation", f"{len(certs)} certificates stored; this computer does not check them against a root of trust"))
    try:
        ext = certs[0].extensions.get_extension_for_oid(x509.ObjectIdentifier(ATTESTATION_OID))
        info = parse_key_description(ext.value.value)
        facts.append(("Where the key lives", SECURITY_LEVELS.get(info["key_level"], f"level {info['key_level']}")))
        facts.append(("Attestation made by", SECURITY_LEVELS.get(info["attestation_level"], f"level {info['attestation_level']}")
                      + f" (attestation version {info['version']})"))
    except (x509.ExtensionNotFound, ValueError, IndexError):
        facts.append(("Where the key lives", "the certificate carries no attestation record"))
    facts.append(("Certificate issued", certs[0].not_valid_before_utc.strftime("%Y-%m-%d")))
    return facts


# ---- certificate, QR, journal --------------------------------------------------------------------------------------

def default_cert_paths() -> tuple[str, str]:
    d = os.path.join(store.BASE, "web")
    return os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")


def ensure_cert(cert_path: str, key_path: str, ips: list[str]) -> str:
    """A certificate for this page, made once and kept (so a browser asks only once). Returns its SHA-256."""
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        os.makedirs(os.path.dirname(cert_path), mode=0o700, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
        when = datetime.datetime.now(datetime.timezone.utc)
        sans = [x509.DNSName(socket.gethostname())]
        for ip in ips:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(when - datetime.timedelta(minutes=5))
                .not_valid_after(when + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False).sign(key, hashes.SHA256()))
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(cert_path, "rb") as f:
        leaf = x509.load_pem_x509_certificate(f.read())
    return hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()


def qr_svg(link: str) -> bytes:
    """The QR code for a link as an SVG image (the qrcode library, which the service already needs)."""
    import qrcode
    import qrcode.image.svg
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=2, image_factory=qrcode.image.svg.SvgPathImage)
    q.add_data(link)
    q.make(fit=True)
    buf = io.BytesIO()
    q.make_image().save(buf)
    return buf.getvalue()


def journal_lines() -> list[str]:
    """The service's own log (C:\\ProgramData\\ThessleyPamWin\\service.log, and the one before it)."""
    out: list[str] = []
    base = os.path.join(store.BASE, "service.log")
    for path in (base + ".old", base):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                out.extend(f.read().splitlines())
        except OSError:
            continue
    return out


LOG_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?:INFO|WARN) (.*)$")


ACTIVITY = (
    (re.compile(r"approved by '(?P<who>.*?)' \((?P<cred>c_\w+)\) from (?P<ip>[\d.:]+) for (?P<user>\S+) \(from (?P<rhost>[^)]*)\)"),
     lambda m: f"Approved by {m['who']} for {m['user']} (from {m['rhost']})"),
    (re.compile(r"denied by '(?P<who>.*?)' \((?P<cred>c_\w+)[^)]*\) for (?P<user>\S+) \(from (?P<rhost>[^)]*)\)"),
     lambda m: f"Denied by {m['who']} for {m['user']} (from {m['rhost']})"),
    (re.compile(r"timeout for (?P<user>\S+) \(from (?P<rhost>[^)]*)\)"),
     lambda m: f"No answer in time for {m['user']} (from {m['rhost']}): refused"),
    (re.compile(r"pass granted to (?P<user>\S+) \(from (?P<ip>[^,]+), (?P<h>[\d.]+) h"),
     lambda m: f"Pass granted to {m['user']} from {m['ip']} for {m['h']} h"),
    (re.compile(r"pass used for (?P<user>\S+) \(from (?P<ip>[^,]+),"),
     lambda m: f"Pass used by {m['user']} from {m['ip']}"),
    (re.compile(r"no approver for (?P<user>[^;]+); refused"),
     lambda m: f"Refused {m['user']}: no approver enrolled"),
    (re.compile(r"enrolled '(?P<label>.*?)' (?P<cred>c_\w+) for (?P<user>\S+)"),
     lambda m: f"Added {m['label']} for {m['user']}"),
    (re.compile(r"(?P<user>\S+) enrols their first approver"),
     lambda m: f"{m['user']} started adding their first approver"),
    (re.compile(r"bad signature from (?P<ip>[\d.:]+) for (?P<user>\S+)"),
     lambda m: f"Bad signature for {m['user']} from {m['ip']}: refused"),
)


def parse_activity(line: str, only_user: str | None) -> tuple[str, str] | None:
    """(time, sentence) for a service-log line, or None; only_user limits it to one account (None = everyone)."""
    m = LOG_LINE.match(line)
    if not m:
        return None
    when, text = m.group(1), m.group(2)
    for pattern, render in ACTIVITY:
        hit = pattern.search(text)
        if hit:
            who = hit.groupdict().get("user")
            if only_user is not None and who != only_user:
                return None
            return when, render(hit)
    return None


# ---- HTML ------------------------------------------------------------------------------------------------------

CSS = """
:root{--bg:#fff;--fg:#1c1c1e;--dim:#6b6b70;--card:#f2f2f5;--line:#d8d8de;--accent:#2563eb;--danger:#c0262d;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#1a1b1e;--fg:#ececf0;--dim:#9a9aa3;--card:#25272c;--line:#3a3d44;--accent:#6ea1ff;--danger:#ff7b7f;--ok:#4ac26b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:20px 16px 48px}
header{display:flex;align-items:center;gap:12px;justify-content:space-between;flex-wrap:wrap;margin-bottom:8px}
h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.1rem;margin:1.6rem 0 .5rem}
nav a,.link{color:var(--accent);text-decoration:none;margin-right:14px}nav{margin:6px 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.dim{color:var(--dim);font-size:.9rem}.ok{color:var(--ok)}.bad{color:var(--danger)}
input[type=text]{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:1rem}
button{padding:9px 14px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:.95rem;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.danger{color:var(--danger);border-color:var(--danger)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}.row form{display:inline}
.flash{border-left:4px solid var(--ok);padding:8px 12px;margin:10px 0;background:var(--card)}
code,.mono{font-family:ui-monospace,monospace;word-break:break-all;font-size:.85rem}
.qr{display:block;margin:12px auto;background:#fff;padding:6px;border-radius:8px;width:min(80vw,280px);height:auto}
table{width:100%;border-collapse:collapse}td{padding:6px 4px;border-bottom:1px solid var(--line);vertical-align:top;font-size:.92rem}
.big{font-size:2rem;letter-spacing:.2rem;text-align:center;margin:10px 0}
"""


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, body: str, nonce: str, session: Session | None = None, admin: bool = False) -> str:
    nav = ""
    if session:
        nav = ('<nav><a href="/keys">Your keys</a><a href="/log">Activity</a>'
               + ('<a href="/admin">Admin</a>' if admin else "")
               + f'<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{esc(session.csrf)}">'
                 '<button>Sign out</button></form></nav>')
    who = f'<span class="dim">Signed in as {esc(session.user)}</span>' if session else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} · Thessley keys</title><style>{CSS}</style></head><body><main>'
            f'<header><h1>Thessley keys</h1>{who}</header>{nav}{body}</main></body></html>')


def flash_html(text: str) -> str:
    return f'<div class="flash">{esc(text)}</div>' if text else ""


def login_page(message: str = "") -> str:
    return (flash_html(message) + '<div class="card"><h2 style="margin-top:0">Sign in</h2>'
            '<p class="dim">Type your account name on this computer. You will approve the sign-in on your phone or in the '
            'Thessley Passkey app, with a QR code or a link. No password.</p>'
            '<form method="post" action="/login"><label for="user" class="dim">Account name</label>'
            '<input type="text" id="user" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus>'
            '<div class="row"><button class="primary">Continue</button></div></form></div>')


def wait_page(flow: Flow, nonce: str, session: Session | None, heading: str, note: str) -> str:
    script = """
const id = %s;
const live = document.getElementById('live');
let last = '';
function el(tag, text, cls) { const e = document.createElement(tag); if (text) e.textContent = text; if (cls) e.className = cls; return e; }
async function tick() {
  let again = true;
  try {
    const r = await fetch('/status/' + id, {credentials: 'same-origin'});
    const s = await r.json();
    if (s.next) { location.href = s.next; return; }
    const key = JSON.stringify(s);
    if (key !== last) {
      last = key;
      live.replaceChildren();
      if (s.link) {
        const img = el('img', '', 'qr'); img.alt = 'QR code'; img.src = '/qr/' + id + '.svg';
        live.append(img, el('p', 'Or open this link in the Thessley Passkey app (paste it, or run thessley-passkey respond):', 'dim'), el('p', s.link, 'mono'));
      } else if (!s.message) {
        live.append(el('p', 'Getting the request ready…', 'dim'));
      }
      if (s.state === 'confirm') {
        live.append(el('p', 'Compare this code with the one on the new phone:'), el('div', s.code, 'big'));
        const f = document.createElement('form'); f.method = 'post'; f.action = '/enroll/' + id + '/confirm';
        const h = document.createElement('input'); h.type = 'hidden'; h.name = 'csrf'; h.value = s.csrf; f.append(h);
        const row = el('div', '', 'row');
        for (const [v, t, c] of [['yes', 'The codes match', 'primary'], ['no', 'They differ', 'danger']]) {
          const b = el('button', t, c); b.name = 'answer'; b.value = v; row.append(b);
        }
        f.append(row); live.append(f);
      }
      if (s.message) live.append(el('p', s.message, s.bad ? 'bad' : 'ok'), (() => { const a = el('a', 'Back', 'link'); a.href = '/'; return a; })());
    }
    if (s.state === 'refused' || s.state === 'timeout' || s.state === 'failed' || s.state === 'gone') again = false;
  } catch (e) {}
  if (again) setTimeout(tick, 1500);
}
tick();
""" % json.dumps(flow.id)
    return (f'<div class="card"><h2 style="margin-top:0">{esc(heading)}</h2><p class="dim">{esc(note)}</p>'
            f'<div id="live"><p class="dim">Getting the request ready…</p></div></div>'
            f'<script nonce="{esc(nonce)}">{script}</script>')


def keys_page(user: str, viewer: Session, flash: str, admin: bool, users: list[str], details=None) -> str:
    rows = []
    devices = store.devices(user)
    for d in devices:
        cred = d["credential_id"]
        when = datetime.datetime.fromtimestamp(d.get("enrolled_at") or 0).strftime("%Y-%m-%d %H:%M") if d.get("enrolled_at") else "?"
        used = datetime.datetime.fromtimestamp(d["last_used"]).strftime("%Y-%m-%d %H:%M") if d.get("last_used") else "never"
        off = bool(d.get("disabled"))
        hidden = f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}"><input type="hidden" name="user" value="{esc(user)}"><input type="hidden" name="cred" value="{esc(cred)}">'
        rows.append(
            f'<div class="card"><strong>{esc(d.get("label", ""))}</strong> '
            f'{"<span class=bad>(switched off)</span>" if off else "<span class=ok>(active)</span>"}'
            f'<div class="dim">Added {esc(when)} · last used {esc(used)}</div><div class="mono dim">{esc(cred)}</div>'
            + key_details_html(details(d) if details else []) +
            f'<div class="row">'
            f'<form method="post" action="/keys/rename">{hidden}<input type="text" name="label" value="{esc(d.get("label", ""))}" maxlength="64" style="width:12rem"><button>Rename</button></form>'
            f'<form method="post" action="/keys/{"enable" if off else "disable"}">{hidden}<button>{"Switch on" if off else "Switch off"}</button></form>'
            f'<form method="post" action="/keys/remove">{hidden}<button class="danger">Remove</button></form>'
            f'</div></div>')
    if not devices:
        rows.append('<div class="card dim">No keys are enrolled for this account.</div>')
    who = ""
    if admin:
        opts = "".join(f'<option value="{esc(u)}"{" selected" if u == user else ""}>{esc(u)}</option>' for u in users)
        who = (f'<form method="get" action="/keys" class="row"><label class="dim">Account</label>'
               f'<select name="user" style="padding:8px">{opts}</select><button>Show</button></form>')
    add = (f'<form method="post" action="/keys/add"><input type="hidden" name="csrf" value="{esc(viewer.csrf)}">'
           f'<input type="hidden" name="user" value="{esc(user)}"><div class="row"><button class="primary">Add a phone or app</button></div></form>')
    note = ('<p class="dim">Changes ask your phone for a fresh approval first, so nobody who only has this browser can change them.</p>')
    return flash_html(flash) + f"<h2>Keys for {esc(user)}</h2>{who}{note}{''.join(rows)}{add}"


def key_details_html(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return ""
    body = "".join(f"<tr><td class='dim' style='white-space:nowrap'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in rows)
    return f"<details style='margin-top:8px'><summary class='link' style='cursor:pointer'>Details</summary><table>{body}</table></details>"


def log_page(rows: list[tuple[str, str]], who: str) -> str:
    body = "".join(f"<tr><td class='mono' style='white-space:nowrap'>{esc(t)}</td><td>{esc(s)}</td></tr>" for t, s in rows)
    return (f"<h2>Activity for {esc(who)}</h2><p class='dim'>The newest first. Approvals, refusals, passes and enrolments "
            f"recorded on this computer.</p><div class='card'><table>{body or '<tr><td class=dim>Nothing recorded yet.</td></tr>'}</table></div>")


def admin_page(viewer: Session, flash: str) -> str:
    grace_h = grants.grace_hours()
    on = lambda flag: "on" if flag else "off"  # noqa: E731
    hidden = f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}">'
    first = grants.self_enroll_first()
    grace = (f'<div class="card"><strong>How long one approval counts</strong>: {grace_h:g} h'
             f'<div class="dim">After one approval, logins from the same address need no new one for this long. 0 means every login asks.</div>'
             f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="grace">'
             f'<input type="text" name="value" value="{grace_h:g}" style="width:6rem"> hours <button>Change</button></form></div>')
    toggle = (f'<div class="card"><strong>Users may enrol their own first approver</strong>: <span class="{"ok" if first else "bad"}">{on(first)}</span>'
              f'<div class="dim">An account with no approver at all can add its first one itself (thessley-pam-win enroll). More approvers always need an approval.</div>'
              f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="self_enroll">'
              f'<button name="value" value="{"off" if first else "on"}">Switch {"off" if first else "on"}</button></form></div>')
    return (flash_html(flash) + "<h2>Settings for this computer</h2>"
            "<p class='dim'>Only administrators see this page. Every change asks your phone for a fresh approval.</p>"
            + grace + toggle + f"<p class='dim'>Passes held right now: {esc(len(grants.all_passes()))}.</p>")


# ---- HTTP ------------------------------------------------------------------------------------------------------

def make_handler(app: WebApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ThessleyWeb"
        sys_version = ""
        timeout = 30

        def log_message(self, fmt, *args):  # nothing about requests in the logs: names and paths are not worth keeping
            pass

        # -- helpers
        def ip(self) -> str:
            return self.client_address[0]

        def cookies(self) -> dict:
            out = {}
            for part in (self.headers.get("Cookie") or "").split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    out[k] = v
            return out

        def session(self) -> Session | None:
            return app.session(self.cookies().get("thessley_session"))

        def form(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length < 0 or length > MAX_BODY:
                return {}
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        def send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: list[tuple[str, str]] | None = None,
                 nonce: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            script = f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
            self.send_header("Content-Security-Policy",
                             f"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; "
                             f"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; {script}")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def html(self, status: int, title: str, body: str, session: Session | None = None, extra=None) -> None:
            nonce = secrets.token_urlsafe(12)
            admin = bool(session and is_admin(session.user))
            body = body.replace("{NONCE}", nonce)
            self.send(status, page(title, body, nonce, session, admin).encode(), extra=extra, nonce=nonce)

        def redirect(self, url: str, extra=None) -> None:
            self.send_response(303)
            self.send_header("Location", url)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()

        def json(self, obj: dict, extra=None) -> None:
            self.send(200, json.dumps(obj).encode(), "application/json", extra)

        def cookie(self, name: str, value: str, max_age: int | None = None) -> tuple[str, str]:
            age = f"; Max-Age={max_age}" if max_age is not None else ""
            return ("Set-Cookie", f"{name}={value}; HttpOnly; Secure; SameSite=Strict; Path=/{age}")

        def need_session(self) -> Session | None:
            s = self.session()
            if s is None:
                self.redirect("/")
            return s

        def csrf_ok(self, s: Session, data: dict) -> bool:
            ok = hmac.compare_digest(str(data.get("csrf", "")), s.csrf)
            if not ok:
                self.html(400, "Refused", flash_html("That form was not valid (it may be old). Go back and try again."), s)
            return ok

        def flow_for(self, fid: str, s: Session | None) -> Flow | None:
            """A flow, only for the browser that started it: the wait cookie (sign-in) or the signed-in account (others)."""
            f = app.flow(fid)
            if f is None:
                return None
            if f.kind == "login":
                return f if hmac.compare_digest(self.cookies().get("thessley_wait", ""), f.secret) else None
            return f if s is not None and s.user == f.owner else None

        # -- routes
        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path)
            route, query = path.path, {k: v[0] for k, v in parse_qs(path.query).items()}
            s = self.session()
            if route == "/":
                return self.redirect("/keys") if s else self.html(200, "Sign in", login_page())
            m = re.fullmatch(r"/wait/([0-9a-f]{32})", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None:
                    return self.html(404, "Not found", flash_html("That request is no longer here. Start again."), s)
                heading = "Approve the sign-in" if f.kind == "login" else f"Approve: {f.description}"
                note = ("Scan the code with the Thessley Passkey app, or open the link. You have 90 seconds." if f.kind != "enroll"
                        else "Scan the code with the new phone's Thessley Passkey app, or open the link on the new app.")
                return self.html(200, heading, wait_page(f, "{NONCE}", s, heading, note), s)
            m = re.fullmatch(r"/status/([0-9a-f]{32})", route)
            if m:
                return self.status(m.group(1), s)
            m = re.fullmatch(r"/qr/([0-9a-f]{32})\.svg", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None or not f.link:
                    return self.send(404, b"", "text/plain")
                try:
                    return self.send(200, app.qr(f.link), "image/svg+xml")
                except (OSError, subprocess.SubprocessError):
                    return self.send(500, b"", "text/plain")
            m = re.fullmatch(r"/enroll/([0-9a-f]{32})", route)
            if m:
                s = self.need_session()
                if s is None:
                    return
                f = self.flow_for(m.group(1), s)
                if f is None or f.kind != "enroll":
                    return self.html(404, "Not found", flash_html("That request is no longer here."), s)
                return self.html(200, "Add a phone or app", wait_page(f, "{NONCE}", s, "Add a phone or app",
                                 "Scan the code with the new phone's Thessley Passkey app, or open the link on the new app."), s)
            if route == "/keys":
                s = self.need_session()
                if s is None:
                    return
                target = app.target(s, query.get("user"))
                if target is None:
                    return self.html(403, "Not allowed", flash_html("You can only see your own keys."), s)
                flash, s.flash = s.flash, ""
                users = store.all_users() if is_admin(s.user) else []
                usage = app.key_usage()
                return self.html(200, "Your keys", keys_page(target, s, flash, is_admin(s.user), users,
                                                              lambda d: app.key_details(target, d, usage)), s)
            if route == "/log":
                s = self.need_session()
                if s is None:
                    return
                everyone = is_admin(s.user) and query.get("all") == "1"
                rows = app.activity(None if everyone else s.user)
                return self.html(200, "Activity", log_page(rows, "everyone" if everyone else s.user), s)
            if route == "/admin":
                s = self.need_session()
                if s is None:
                    return
                if not is_admin(s.user):
                    return self.html(403, "Not allowed", flash_html("Only administrators can open this page."), s)
                flash, s.flash = s.flash, ""
                return self.html(200, "Admin", admin_page(s, flash), s)
            self.html(404, "Not found", flash_html("There is nothing here."), s)

        def do_POST(self):  # noqa: N802
            route = urlsplit(self.path).path
            data = self.form()
            s = self.session()
            if route == "/login":
                user = (data.get("user") or "").strip()
                if not app.rate_ok(self.ip()):
                    return self.html(429, "Slow down", login_page("Too many sign-in requests from this address. Wait a few minutes."))
                flow = app.start_login(user, self.ip())
                if flow is None:  # the same words for an unknown account and one with no key: no hint which it is
                    return self.html(200, "Sign in", login_page("That account cannot sign in here: it has no key enrolled, or it does not exist."))
                return self.redirect(f"/wait/{flow.id}", [self.cookie("thessley_wait", flow.secret, 600)])
            if route == "/logout":
                if s and hmac.compare_digest(str(data.get("csrf", "")), s.csrf):
                    app.drop_session(s.token)
                return self.redirect("/", [self.cookie("thessley_session", "", 0)])
            if s is None:
                return self.redirect("/")
            if not self.csrf_ok(s, data):
                return
            m = re.fullmatch(r"/enroll/([0-9a-f]{32})/confirm", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None or f.kind != "enroll" or f.state != "confirm":
                    return self.redirect("/keys")
                f.answer = data.get("answer") == "yes"
                f.answered.set()
                return self.redirect(f"/enroll/{f.id}")
            if route.startswith("/keys/"):
                return self.keys_action(route[len("/keys/"):], data, s)
            if route == "/admin/set":
                if not is_admin(s.user):
                    return self.html(403, "Not allowed", flash_html("Only administrators can change settings."), s)
                return self.admin_action(data, s)
            self.html(404, "Not found", flash_html("There is nothing here."), s)

        def start_change(self, s: Session, description: str, action, tty: str = TTY_CHANGE) -> None:
            flow = app.start_change(s, self.ip(), description, action, tty)
            if flow is None:
                return self.html(503, "Busy", flash_html("Could not start the approval (too many at once, or no key is enrolled for you)."), s)
            self.redirect(f"/wait/{flow.id}", [self.cookie("thessley_wait", flow.secret, 600)])

        def keys_action(self, action: str, data: dict, s: Session) -> None:
            target = app.target(s, data.get("user"))
            cred = data.get("cred", "")
            if target is None:
                return self.html(403, "Not allowed", flash_html("You can only change your own keys."), s)
            if action == "add":
                return self.start_change(s, f"adding a phone or app for {target}", app.change_begin_enroll(target, s.user), TTY_DEVICE)
            known = {d["credential_id"]: d for d in store.devices(target)}
            if not CRED_RE.match(cred) or cred not in known:
                return self.html(404, "Not found", flash_html("No such key."), s)
            label = known[cred].get("label", "")
            if action == "rename":
                new = (data.get("label") or "").strip()
                if not enroll.LABEL.match(new):
                    return self.html(400, "Not valid", flash_html("Use 1 to 64 letters, digits, spaces and . , ' ( ) + - in the name."), s)
                return self.start_change(s, f"renaming {label} to {new}", app.change_rename(target, cred, new))
            if action in ("disable", "enable"):
                return self.start_change(s, f"{'switching off' if action == 'disable' else 'switching on'} {label} for {target}",
                                         app.change_disable(target, cred, action == "disable"))
            if action == "remove":
                return self.start_change(s, f"removing {label} from {target}", app.change_remove(target, cred))
            return self.html(404, "Not found", flash_html("There is nothing here."), s)

        def admin_action(self, data: dict, s: Session) -> None:
            name, value = data.get("name", ""), (data.get("value") or "").strip()
            if name == "grace":
                try:
                    hours = float(value)
                except ValueError:
                    hours = -1
                if not 0 <= hours <= grants.MAX_HOURS:
                    return self.html(400, "Not valid", flash_html(f"Give a number of hours from 0 to {grants.MAX_HOURS:g}."), s)
            elif name == "self_enroll":
                if value not in ("on", "off"):
                    return self.html(400, "Not valid", flash_html("Choose on or off."), s)
            else:
                return self.html(404, "Not found", flash_html("No such setting."), s)
            self.start_change(s, f"changing a setting ({name})", app.change_setting(name, value))

        def status(self, fid: str, s: Session | None) -> None:
            f = self.flow_for(fid, s)
            if f is None:
                return self.json({"state": "gone", "message": "This request is no longer here. Start again.", "bad": True})
            extra = None
            out = {"state": f.state, "link": f.link, "code": f.code, "message": "", "bad": False}
            if f.kind == "login" and f.state == "approved":
                session = app.new_session(f.user)
                f.state = "done"
                out.update(state="done", next="/keys")
                extra = [self.cookie("thessley_session", session.token), self.cookie("thessley_wait", "", 0)]
            elif f.kind == "change" and f.state == "approved":
                url, flash = app.finish(f)
                if s is not None:
                    s.flash = flash
                out.update(next=url or "/keys")
            elif f.kind == "enroll" and f.state == "confirm":
                out["csrf"] = s.csrf if s else ""
            elif f.state == "refused":
                out.update(message="It was refused or denied. Nothing was changed.", bad=True)
            elif f.state == "timeout":
                out.update(message="No answer in time. Nothing was changed.", bad=True)
            elif f.state == "failed":
                out.update(message="The new phone was not added.", bad=True)
            elif f.state == "done" and f.kind == "enroll":
                if s is not None:
                    s.flash = f"Added {f.label or 'the new phone'}."
                out.update(next="/keys" if s is None or f.user == s.user else f"/keys?user={f.user}")
            self.json(out, extra)

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Windows differs from Linux here: with SO_REUSEADDR (the default) another program can bind the very port this page
    # serves, and share or take over its connections. Bind exclusively, as listener.py does.
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def handle_error(self, request, client_address):  # a browser that hangs up mid-request is not an error here
        pass


def make_server(app: WebApp, ip: str, port: int, cert: str, key: str) -> Server:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    httpd = Server((ip, port), make_handler(app))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main() -> int:
    """What the scheduled task runs."""
    return serve()


def serve() -> int:
    st = grants.web_settings()
    if not st["enabled"]:
        print("The admin web page is switched off (sudo thessley-pam web on).")
        return 0
    ip = st["listen"] or machine.lan_ip()
    cert, key = (st["cert"], st["key"]) if st["cert"] and st["key"] else default_cert_paths()
    fingerprint = ensure_cert(cert, key, [ip, "127.0.0.1"])
    httpd = make_server(WebApp(), ip, st["port"], cert, key)
    print(f"Thessley admin page: https://{ip}:{st['port']}/   certificate SHA-256 {fingerprint}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
