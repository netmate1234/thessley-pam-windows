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
import errno
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
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import enroll, firewall, grants, machine, ssh_policy, store

TTY_LOGIN, TTY_CHANGE, TTY_DEVICE = "web", "web-change", "add-device"  # what approve.run is told (it names them for the apps)

CRED_RE = re.compile(r"^c_[0-9a-f]{16}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")

MAX_BODY = 8 * 1024
SESSION_MAX_SECONDS = 8 * 3600
FLOW_KEEP_SECONDS = 15 * 60
LOGIN_RATE = (8, 300)  # at most 8 sign-in requests per client address in 300 s
MAX_FLOWS = 40
WEB_WAIT = 180          # seconds to approve a sign-in or a change (a person at a browser, the device in a pocket)
WEB_CONFIRM_WAIT = 180  # seconds to compare the codes and press the button when adding a device
WEB_ENROLL_WAIT = 300   # seconds the new device has to scan the code
SERVICE_HOST, SERVICE_PORT = "127.0.0.1", 47800

def now() -> float:
    return time.time()


# ---- who is an administrator -------------------------------------------------------------------------------------

_ADMIN_CACHE: dict = {"at": 0.0, "names": set()}


def admin_names() -> set[str]:
    """The members of the local Administrators group (by its well-known SID, so any language), as plain account names."""
    if now() - _ADMIN_CACHE["at"] >= 120:
        names: set[str] = set()
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        powershell = os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        if not os.path.isfile(powershell):
            powershell = "powershell.exe"
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command",
                 "Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }"],
                capture_output=True, text=True, errors="replace", timeout=20)
            for line in result.stdout.splitlines():
                try:
                    names.add(store.normalize_user(line))
                except ValueError:
                    continue
        except (OSError, subprocess.TimeoutExpired):
            pass
        _ADMIN_CACHE.update(at=now(), names=names)
    return set(_ADMIN_CACHE["names"]) | grants.web_admins()


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
        self.qr_path = ""
        self.qr_size = 0
        self.qr_rows: list[str] = []
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
            m = re.match(r"(?:(?:Device|Phone) )?'(.*)' \(", line)
            if m:
                self.label = m.group(1)


class Session:
    def __init__(self, user: str, minutes: int, bootstrap: bool = False):
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(24)
        self.user = user
        self.created = self.last = now()
        self.minutes = minutes
        self.flash = ""
        self.bootstrap = bootstrap
        self.bootstrap_flow_id = ""

    def valid(self) -> bool:
        t = now()
        absolute_limit = grants.WEB_BOOTSTRAP_SECONDS if self.bootstrap else SESSION_MAX_SECONDS
        return t - self.last < self.minutes * 60 and t - self.created < absolute_limit


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
        self.httpd = None
        self.rebind_requested = False

    def rebind(self) -> None:
        """Restart the listener after an administrator changes its bind address."""
        self.rebind_requested = True
        server = self.httpd
        if server is not None:
            timer = threading.Timer(1.5, server.shutdown)
            timer.daemon = True
            timer.start()

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
            cap = grants.web_settings()["rate_limit_entries"]
            if len(self.attempts) > cap or (len(self.attempts) >= cap and ip not in self.attempts):
                for old_ip, times in list(self.attempts.items()):
                    fresh = [x for x in times if t - x < window]
                    if fresh:
                        self.attempts[old_ip] = fresh
                    else:
                        self.attempts.pop(old_ip, None)
                while len(self.attempts) > cap or (len(self.attempts) >= cap and ip not in self.attempts):
                    oldest = min(self.attempts, key=lambda key: self.attempts[key][-1] if self.attempts[key] else 0)
                    self.attempts.pop(oldest, None)
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
            # The SYSTEM service owns the one phone listener. Routing through it lets concurrent web approvals
            # share TCP 47810 instead of selecting a fallback port.
            ok = self._service_flow(flow, "web-approve", rhost=ip,
                                    service={TTY_CHANGE: "web-change", TTY_DEVICE: "add-device"}.get(tty, "web"))
        except Exception as exc:  # strict: any trouble is a refusal
            flow.say(f"error: {exc!r}")
            ok = False
        text = "\n".join(flow.lines)
        flow.state = "approved" if ok else ("timeout" if "no answer" in text else "refused")

    def _service_flow(self, flow: Flow, op: str, *, rhost: str = "", service: str = "") -> bool:
        """Relay one web flow through the SYSTEM daemon, which owns the shared TCP 47810 listener."""
        request = {"op": op, "user": flow.user}
        if rhost:
            request["rhost"] = rhost
        if service:
            request["service"] = service
        try:
            sock = socket.create_connection((SERVICE_HOST, SERVICE_PORT), timeout=5)
        except OSError as exc:
            flow.say(f"The approval service is not available: {exc}")
            return False

        def cancel_socket():
            flow.cancel.wait()
            if flow.cancel.is_set():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watcher = threading.Thread(target=cancel_socket, daemon=True)
        watcher.start()
        try:
            sock.settimeout(None)
            stream = sock.makefile("rw", encoding="utf-8", newline="\n")
            stream.write(json.dumps(request) + "\n")
            stream.flush()
            for raw in stream:
                message = json.loads(raw)
                if "say" in message:
                    flow.say(message["say"])
                if "qr_matrix" in message:
                    flow.qr_rows = str(message["qr_matrix"]).split("/")
                if "ask" in message:
                    flow.state = "confirm"
                    flow.answer = None
                    flow.answered.clear()
                    flow.answered.wait(max(1, int(message.get("timeout", WEB_CONFIRM_WAIT))))
                    answer = "yes" if flow.answer is True and not flow.cancel.is_set() else "no"
                    stream.write(json.dumps({"answer": answer}) + "\n")
                    stream.flush()
                if message.get("done"):
                    return bool(message.get("ok"))
        except (OSError, ValueError, TypeError) as exc:
            if not flow.cancel.is_set():
                flow.say(f"Approval service connection ended: {exc}")
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return False

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
        """A fresh approval by the signed-in account's device, then `action()` runs once (it returns (url, message))."""
        if not self.usable(session.user):
            return None
        flow = self._new_flow(Flow("change", session.user, description, on_approved=action, owner=session.user))
        if flow:
            threading.Thread(target=self._approval_thread, args=(flow, tty, ip), daemon=True).start()
        return flow

    def start_enroll(self, user: str, owner: str | None = None) -> Flow | None:
        flow = self._new_flow(Flow("enroll", user, "Add a device", owner=owner))
        if flow is None:
            return None

        def work():
            flow.state = "waiting"
            device = None
            try:
                if self._service_flow(flow, "web-enroll"):
                    stored = [d for d in store.devices(user) if flow.label and d.get("label") == flow.label
                              and (d.get("enrolled_at") or 0) >= int(flow.created)]
                    if stored:
                        device = stored[-1]
            except Exception as exc:
                flow.say(f"error: {exc!r}")
            if not device:  # whatever went wrong, a device that was stored during this flow counts as added
                stored = [d for d in store.devices(user) if flow.label and d.get("label") == flow.label
                          and (d.get("enrolled_at") or 0) >= int(flow.created)]
                if stored:
                    device = stored[-1]
                    flow.label = flow.label or str(device.get("label", ""))
            flow.state = "done" if device else "failed"
            # Flow output contains the temporary enrollment URI and pairing code.
            self.log(f"web page: adding a device for {user} (asked by {flow.owner}): {flow.state}"
                     + (f" ({device.get('credential_id', '')})" if device else ""), False)

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

    def new_session(self, user: str, bootstrap: bool = False) -> Session:
        # A bootstrap session can only enroll the first device and lasts ten minutes.
        s = Session(user, 10 if bootstrap else self.settings()["session_minutes"], bootstrap=bootstrap)
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

    def change_setting(self, name: str, value: str, details: dict | None = None):
        details = details or {}
        def run():
            if name == "grace":
                grants.set_grace(float(value))
                return "/admin", f"One approval now counts for {float(value):g} h (0 = every login asks)."
            if name == "session":
                grants.set_web(session_minutes=int(float(value)))
                return "/admin", f"You are now signed out after {int(float(value))} minutes without activity (from the next sign-in)."
            if name == "web_limits":
                connections, buckets = map(int, value.split(",", 1))
                grants.set_web(max_connections=connections, rate_limit_entries=buckets)
                return "/admin", "Web connection and rate-limit memory limits saved."
            if name == "log_limits":
                size, count = map(int, value.split(",", 1))
                grants.set_web(log_max_bytes=size, log_rotations=count)
                return "/admin", "Log size and rotation retention saved."
            if name == "localhost_only":
                local_only = value == "on"
                grants.set_web(localhost_only=local_only)
                self.rebind()
                st = grants.web_settings()
                host = "127.0.0.1" if local_only else (st["listen"] or machine.lan_ip())
                if host in ("0.0.0.0", "::"):
                    host = machine.lan_ip()
                return f"https://{host}:{st['port']}/admin", (
                    f"Admin page is now restricted to this computer at https://127.0.0.1:{st['port']}"
                    if local_only else f"Admin page is available at https://{host}:{st['port']}."
                )
            if name == "self_enroll":
                grants.set_self_enroll_first(value == "on")
                return "/admin", "Users enrolling their own first approver: " + ("on." if value == "on" else "off.")
            if name == "ssh_fallback_unenrolled":
                grants.set_ssh_fallback_unenrolled(value == "on")
                return "/admin", "Unenrolled-account SSH fallback: " + ("on." if value == "on" else "off.")
            if name == "ssh_source_policy":
                modes = details["modes"]
                vpn_subnets = details["vpn_subnets"]
                addresses = details["addresses"]
                old = grants.ssh_source_policy()
                firewall.apply_ssh_source_policy(modes, vpn_subnets, addresses, sys.executable)
                try:
                    grants.set_ssh_source_policy(modes, vpn_subnets, addresses)
                except Exception:
                    try:
                        firewall.apply_ssh_source_policy(old["modes"], old["vpn_subnets"], old["addresses"], sys.executable)
                    except Exception:
                        pass
                    raise
                labels = {"all": "All IPs", "local": "Local networks", "vpn": "VPN networks", "custom": "Chosen list"}
                summary = ", ".join(labels[mode] for mode in modes)
                self.log(f"web page: SSH source policy changed to {summary}", False)
                return "/admin", "Windows Firewall source policy saved: " + summary + "."
            raise ValueError("unknown setting")
        return run

    def change_ssh_access(self, username: str, qr_enabled: bool, blocked: bool, factor: str):
        target = store.normalize_user(username)
        if factor not in ("native", "key", "password", "key-password"):
            raise ValueError("Choose existing OpenSSH settings, SSH key, account password, or both.")

        def run():
            backup = ssh_policy.set_access(target, qr_enabled, blocked, factor)
            state = f"SSH {'blocked' if blocked else 'allowed'}; QR {'required when enrolled' if qr_enabled else 'not required'}"
            self.log(f"web page: {state} for SSH account {target}; backup {backup}", False)
            return "/admin", f"{state} for {target}. sshd was validated and restarted; config backup: {backup}"
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
        return out[-3000:][::-1]


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


def qr_vector(link: str) -> tuple[int, str, list[str]]:
    """Return QR modules and an SVG path from the encoded module matrix."""
    import qrcode
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
    q.add_data(link)
    q.make(fit=True)
    matrix = q.get_matrix()
    size = len(matrix)
    cells = "".join(f"M{x} {y}h1v1h-1z" for y, row in enumerate(matrix)
                    for x, dark in enumerate(row) if dark)
    rows = ["".join("1" if dark else "0" for dark in row) for row in matrix]
    return size, cells, rows


def qr_svg(link: str) -> bytes:
    """Build a simple SVG image, suitable for direct download or an image viewer."""
    size, cells, _ = qr_vector(link)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="520" height="520" '
           f'viewBox="0 0 {size} {size}" shape-rendering="crispEdges">'
           '<rect width="100%" height="100%" fill="#fff"/>'
           f'<path fill="#000" d="{cells}"/></svg>')
    return svg.encode("ascii")


def journal_lines() -> list[str]:
    """The service log and its bounded rotated files."""
    out: list[str] = []
    base = os.path.join(store.BASE, "service.log")
    # Read newest first across the current file and bounded rotations.
    rotations = grants.web_settings()["log_rotations"]
    paths = [base + f".{i}" for i in range(rotations, 0, -1)] + [base + ".old", base]
    for path in paths:
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
:root{--bg:#1a1b1e;--fg:#ececf0;--dim:#9a9aa3;--card:#25272c;--line:#3a3d44;--accent:#6ea1ff;--danger:#ff7b7f;--ok:#4ac26b;color-scheme:dark}
:root[data-theme="light"]{--bg:#fff;--fg:#1c1c1e;--dim:#6b6b70;--card:#f2f2f5;--line:#d8d8de;--accent:#2563eb;--danger:#c0262d;--ok:#1a7f37;color-scheme:light}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif}
main{width:min(100%,760px);margin:0 auto;padding:20px 16px 48px}
header{display:flex;align-items:center;gap:12px;justify-content:space-between;flex-wrap:wrap;margin-bottom:8px;min-width:0}
header>span{max-width:100%;min-width:0}
h1{font-size:1.5rem;line-height:1.25;margin:.2rem 0;overflow-wrap:anywhere}h2{font-size:1.1rem;margin:1.6rem 0 .5rem}
nav{display:flex;align-items:center;flex-wrap:wrap;gap:4px 14px;margin:6px 0 14px}
nav a,.link{color:var(--accent);text-decoration:none}nav a{display:inline-flex;align-items:center;min-height:44px}nav form{margin-left:auto}nav button{min-height:44px}
.card{min-width:0;overflow-wrap:anywhere;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.user-section{margin:30px 0 38px;padding-bottom:18px;border-bottom:2px solid var(--line)}
.user-section h3{margin:0 0 .45rem}.user-section>p{margin:0 0 14px}
.dim{color:var(--dim);font-size:.9rem}.ok{color:var(--ok)}.bad{color:var(--danger)}
input[type=text]{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:1rem}
button{min-height:44px;padding:9px 14px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:.95rem;cursor:pointer}
.btn{display:inline-block;padding:11px 18px;border-radius:8px;background:var(--accent);color:#fff;text-decoration:none;font-weight:600}
.btn.small{padding:7px 12px;font-size:.9rem}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.danger{color:var(--danger);border-color:var(--danger)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px;min-width:0}.row form{display:flex;gap:8px;flex-wrap:wrap;align-items:center;max-width:100%;min-width:0}
.ssh-source-form{display:grid;gap:8px;margin-top:10px;min-width:0}.ssh-source-options{display:grid;gap:8px;margin:10px 0}
.ssh-source-options label{display:flex;gap:9px;align-items:flex-start;min-width:0}.ssh-source-options input[type=checkbox]{width:1.1rem;height:1.1rem;flex:0 0 auto;margin:.2rem 0 0}
.ssh-source-form input[type=text]{width:100%;min-width:0;max-width:100%}
.flash{border-left:4px solid var(--ok);padding:8px 12px;margin:10px 0;background:var(--card)}
code,.mono{font-family:ui-monospace,monospace;word-break:break-all;font-size:.85rem}
.qr{display:block;margin:12px auto;background:#fff;padding:6px;border-radius:8px;width:min(100%,520px);max-width:100%;height:auto;aspect-ratio:1;object-fit:contain;image-rendering:pixelated}
table{width:100%;border-collapse:collapse}td{padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top;font-size:.92rem;overflow-wrap:anywhere}
.table-wrap{width:100%;max-width:100%;overflow-x:auto;overscroll-behavior-x:contain;-webkit-overflow-scrolling:touch}
.key-details{margin-top:8px;border-top:1px solid var(--line)}
.key-details summary{display:flex;align-items:center;justify-content:space-between;min-height:44px;cursor:pointer;list-style:none}
.key-details summary::-webkit-details-marker{display:none}
.key-details summary::after{content:"+";font-size:1.2rem;line-height:1}
.key-details[open] summary::after{content:"−"}
.key-detail-list{margin:0}
.key-detail-row{display:grid;grid-template-columns:minmax(8rem,30%) minmax(0,1fr);gap:8px;padding:8px 0;border-top:1px solid var(--line)}
.key-detail-row dt{color:var(--dim);font-size:.85rem}
.key-detail-row dd{margin:0;min-width:0;overflow-wrap:anywhere}
.pagination{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin:12px 0}
.pagination .page-status{color:var(--dim);font-size:.9rem;text-align:center;flex:1 1 auto}
.pagination a[aria-disabled='true']{opacity:.45;pointer-events:none}
.activity-time-cell{white-space:nowrap;padding-right:10px}
.activity-time{display:flex;gap:8px;align-items:baseline;white-space:nowrap;font-variant-numeric:tabular-nums}
.big{font-size:2rem;letter-spacing:.2rem;text-align:center;margin:10px 0}
@media(max-width:600px){
 main{padding:14px 12px 32px}
 header{align-items:flex-start;gap:8px}
 header h1{font-size:1.25rem;flex:1 1 100%}
 header>span{width:100%;justify-content:space-between}
 .card{padding:12px}
 .row{align-items:stretch}
 .row>button,.row form button,.row .btn{min-height:44px}
 nav{gap:0 10px}
 nav:not(.pagination) form{margin-left:0}
 nav:not(.pagination) button{white-space:nowrap;padding:8px 10px}
 .pagination{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:8px;margin:10px 0}
 .pagination .page-status{grid-column:1 / -1;grid-row:1;white-space:normal}
 .pagination>a{min-height:44px;justify-content:center;padding:8px 10px}
 .activity-time-cell{width:5rem;min-width:5rem;white-space:normal;padding-right:6px}
 .activity-time{display:block;white-space:normal;line-height:1.3}
 .activity-time-date,.activity-time-clock{display:block;font-size:.72rem;white-space:nowrap}
 .key-detail-row{grid-template-columns:minmax(0,1fr);gap:2px}
 .key-detail-row dt{font-size:.78rem}
}
@media(max-width:360px){main{padding-left:10px;padding-right:10px}.btn{padding-left:12px;padding-right:12px}}
"""


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, body: str, nonce: str, session: Session | None = None, admin: bool = False) -> str:
    nav = ""
    if session:
        if session.bootstrap:
            nav = (f'<nav><form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{esc(session.csrf)}">'
                   '<button>Cancel setup</button></form></nav>')
        else:
            nav = ('<nav><a href="/keys">Your keys</a><a href="/log">Activity</a>'
                   + ('<a href="/admin">Admin</a>' if admin else "")
                   + f'<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{esc(session.csrf)}">'
                     '<button>Sign out</button></form></nav>')
    who = f'<span class="dim">Signed in as {esc(session.user)}</span>' if session else ""
    # On every page: opens the Thessley Passkey app on the computer or device this browser runs on (no request needed).
    opener = '<a class="btn small" href="thessleypam://open">Open the Thessley app</a>'
    host = machine.hostname()  # which computer these keys are for (the address in the browser may be a tunnel's)
    return (f'<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} · Thessley Passkeys for {esc(host)}</title><style>{CSS}</style>'
            f'<script nonce="{esc(nonce)}">try{{if(localStorage.getItem("thessley-theme")==="light")document.documentElement.dataset.theme="light"}}catch(e){{}}</script>'
            f'</head><body><main>'
            f'<header><h1>Thessley Passkeys for {esc(host)}</h1><span style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">{who}{opener}'
            '<button id="theme-toggle" type="button" aria-pressed="true">Light mode</button></span></header>'
            f'{nav}{body}</main><script nonce="{esc(nonce)}">(()=>{{const b=document.getElementById("theme-toggle");const apply=theme=>{{document.documentElement.dataset.theme=theme;const dark=theme==="dark";b.textContent=dark?"Light mode":"Dark mode";b.setAttribute("aria-pressed",String(dark));try{{localStorage.setItem("thessley-theme",theme)}}catch(e){{}}}};apply(document.documentElement.dataset.theme||"dark");b.addEventListener("click",()=>apply(document.documentElement.dataset.theme==="dark"?"light":"dark"))}})()</script></body></html>')


def flash_html(text: str) -> str:
    return f'<div class="flash">{esc(text)}</div>' if text else ""


def login_page(message: str = "") -> str:
    return (flash_html(message) + '<div class="card"><h2 style="margin-top:0">Sign in</h2>'
            '<p class="dim">Type your account name on this computer. You will approve the sign-in on your device or in the '
            'Thessley Passkey app, with a QR code or a link. No password.</p>'
            '<form method="post" action="/login"><label for="user" class="dim">Account name</label>'
            '<input type="text" id="user" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus>'
            '<div class="row"><button class="primary">Continue</button></div></form></div>')


def bootstrap_page(token: str, message: str = "") -> str:
    safe_token = token if re.fullmatch(r"[0-9a-f]{64}", token or "") else ""
    return (flash_html(message) + '<div class="card"><h2 style="margin-top:0">First phone setup</h2>'
            '<p class="dim">Enter the one-time setup password printed by the installer. It can only enroll the first phone '
            'for this administrator, expires after ten minutes, and cannot open settings or other accounts.</p>'
            '<form method="post" action="/bootstrap"><input type="hidden" name="token" value="' + esc(safe_token) + '">'
            '<label for="code" class="dim">One-time setup password</label>'
            '<input type="password" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" '
            'pattern="[0-9]{8}" maxlength="8" required autofocus>'
            '<div class="row"><button class="primary">Continue to first phone setup</button></div></form></div>')


def bootstrap_setup_page(session: Session, flash: str = "") -> str:
    return (flash_html(flash) + '<div class="card"><h2 style="margin-top:0">Enroll the first phone</h2>'
            f'<p class="dim">This one-time setup is limited to the first phone for {esc(session.user)}. '
            'It cannot view keys or change settings. The setup session ends in ten minutes.</p>'
            f'<form method="post" action="/bootstrap/enroll"><input type="hidden" name="csrf" value="{esc(session.csrf)}">'
            '<div class="row"><button class="primary">Start phone enrollment</button></div></form></div>')


def bootstrap_done_page() -> str:
    return ('<div class="card"><h2 style="margin-top:0">First phone enrolled</h2>'
            '<p>Your one-time setup link is spent. Sign in with the new phone to manage keys and settings.</p>'
            '<p><a class="btn primary" href="/">Go to sign in</a></p></div>')


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
        if (s.link.startsWith('thessleypam://')) {
          const open = el('a', 'Open this request in the Thessley app', 'btn'); open.href = s.link;
          live.append(open, el('p', 'On a computer or device that has the app, this opens it with this request ready.', 'dim'));
        }
        if (s.qr_rows && s.qr_size) {
          const qr = el('canvas', '', 'qr'); qr.setAttribute('role', 'img'); qr.setAttribute('aria-label', 'QR code');
          const modulePixels = Math.max(8, Math.ceil(520 / s.qr_size));
          qr.width = qr.height = s.qr_size * modulePixels;
          const ctx = qr.getContext('2d');
          if (ctx) {
            ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, qr.width, qr.height); ctx.fillStyle = '#000';
            for (let y = 0; y < s.qr_rows.length; y++) {
              const row = s.qr_rows[y];
              for (let x = 0; x < row.length; x++) if (row[x] === '1') ctx.fillRect(x * modulePixels, y * modulePixels, modulePixels, modulePixels);
            }
            live.append(qr);
          } else {
            live.append(el('p', 'Your browser could not draw the QR code. Use the approval link below.', 'bad'));
          }
        } else {
          live.append(el('p', 'The QR code is being prepared. Use the approval link below if it does not appear.', 'bad'));
        }
        live.append(el('p', 'Or open this link in the Thessley Passkey app (paste it, or run thessley-passkey respond):', 'dim'), el('p', s.link, 'mono'));
      } else if (!s.message) {
        live.append(el('p', 'Getting the request ready…', 'dim'));
      }
      if (s.state === 'confirm') {
        live.append(el('p', 'Compare this code with the one on the new device:'), el('div', s.code, 'big'));
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
           f'<input type="hidden" name="user" value="{esc(user)}"><div class="row"><button class="primary">Add a device</button></div></form>')
    note = ('<p class="dim">Changes ask your device for a fresh approval first, so nobody who only has this browser can change them.</p>')
    return flash_html(flash) + f"<h2>Keys for {esc(user)}</h2>{who}{note}{''.join(rows)}{add}{passes_html(user, viewer, devices)}"


def passes_html(user: str, viewer: Session, devices: list[dict]) -> str:
    """The approvals that let this account in over ssh without asking its device again (the 4 h passes), each with a button
    that ends it. Ending a pass only takes access away, so it needs no fresh approval; the next login asks the device again."""
    labels = {d["credential_id"]: d.get("label", "") for d in devices}
    hidden = f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}"><input type="hidden" name="user" value="{esc(user)}">'
    rows = []
    for p in grants.passes_of(user):
        by = labels.get(p.get("credential", ""), "") or "a removed device"
        rows.append(
            f'<div class="card"><strong>ssh login</strong> from {esc(p.get("rhost", ""))} '
            f'<span class="dim">· approved by {esc(by)} · {esc(grants.remaining(p))} left</span>'
            f'<form method="post" action="/passes/end" class="row">{hidden}'
            f'<input type="hidden" name="rhost" value="{esc(p.get("rhost", ""))}"><button class="danger">End this pass</button></form></div>')
    if not rows:
        body = '<div class="card dim">No pass is active: every login asks your device.</div>'
    else:
        body = "".join(rows) + (f'<form method="post" action="/passes/end" class="row">{hidden}'
                                '<input type="hidden" name="all" value="1"><button class="danger">End all passes</button></form>')
    return ("<h2>Passes</h2><p class='dim'>After one approval, the same account from the same address is let in without asking "
            "your device again, for a few hours. End a pass to make the next login ask again.</p>" + body)


def key_details_html(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return ""
    body = "".join(f"<div class='key-detail-row'><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in rows)
    return f"<details class='key-details'><summary class='link'>Details</summary><dl class='key-detail-list'>{body}</dl></details>"


def log_page(rows: list[tuple[str, str]], who: str, page_number: int = 1, everyone: bool = False) -> str:
    page_size = 20
    total = len(rows)
    page_count = max(1, (total + page_size - 1) // page_size)
    page_number = max(1, min(page_number, page_count))
    start = (page_number - 1) * page_size
    visible = rows[start:start + page_size]

    def pager() -> str:
        query = "?all=1" if everyone else ""
        separator = "&" if query else "?"
        previous = (f'<a class="btn small" href="/log{query}{separator}page={page_number - 1}" aria-label="Previous page">Previous</a>'
                    if page_number > 1 else '<a class="btn small" aria-disabled="true" tabindex="-1">Previous</a>')
        following = (f'<a class="btn small" href="/log{query}{separator}page={page_number + 1}" aria-label="Next page">Next</a>'
                     if page_number < page_count else '<a class="btn small" aria-disabled="true" tabindex="-1">Next</a>')
        status = (f"{start + 1}–{min(start + page_size, total)} of {total} · Page {page_number} of {page_count}"
                  if total else "Page 1 of 1")
        return f'<nav class="pagination" aria-label="Activity pages">{previous}<span class="page-status">{status}</span>{following}</nav>'

    def timestamp(value: str) -> str:
        date, separator, clock = value.partition(" ")
        if not separator:
            return esc(value)
        return (f"<time class='activity-time' datetime='{esc(date)}T{esc(clock)}'>"
                f"<span class='activity-time-date'>{esc(date)}</span><span class='activity-time-clock'>{esc(clock)}</span></time>")

    body = "".join(f"<tr><td class='mono activity-time-cell'>{timestamp(t)}</td><td>{esc(s)}</td></tr>" for t, s in visible)
    return (f"<h2>Activity for {esc(who)}</h2><p class='dim'>The newest first. Approvals, refusals, passes and enrolments "
            f"recorded on this computer.</p>{pager()}<div class='card'><div class='table-wrap'><table>{body or '<tr><td class=dim>Nothing recorded yet.</td></tr>'}</table></div></div>{pager()}")


def admin_page(viewer: Session, flash: str, listener_host: str = "") -> str:
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
    fallback = grants.ssh_fallback_unenrolled()
    ssh_fallback = (f'<div class="card"><strong>SSH fallback when a user has never enrolled a phone</strong>: '
                    f'<span class="{"ok" if fallback else "bad"}">{on(fallback)}</span>'
                    '<div class="dim">When on, a QR-enabled account with no enrolled phone can still use its configured OpenSSH key/password. '
                    'Once a phone is enrolled, QR approval is required. Accounts with a disabled or lost phone do not use this fallback.</div>'
                    f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="ssh_fallback_unenrolled">'
                    f'<button name="value" value="{"off" if fallback else "on"}">Switch {"off" if fallback else "on"}</button></form></div>')
    session = grants.web_settings()["session_minutes"]
    settings = grants.web_settings()
    grace += (f'<div class="card"><strong>Stay signed in to this page</strong>: {session} minutes without activity'
              f'<div class="dim">After this long without clicking anything you are signed out (always after 8 hours). '
              f'Applies from the next sign-in. 1 to 240 minutes.</div>'
              f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="session">'
              f'<input type="text" name="value" value="{session}" style="width:6rem"> minutes <button>Change</button></form></div>')
    limits = (f'<div class="card"><strong>Web service resource limits</strong>'
              f'<div class="dim">Limits are enforced immediately. Current: {settings["max_connections"]} concurrent connections and '
              f'{settings["rate_limit_entries"]} remembered IP buckets; old buckets expire or are evicted at capacity.</div>'
              f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="web_limits">'
              f'<input type="number" name="connections" min="4" max="256" value="{settings["max_connections"]}" aria-label="Maximum concurrent connections"> connections '
              f'<input type="number" name="buckets" min="64" max="100000" value="{settings["rate_limit_entries"]}" aria-label="Rate limit entries"> IP buckets '
              f'<button>Save limits</button></form></div>')
    logging = (f'<div class="card"><strong>Log rotation</strong><div class="dim">Each file is capped at {settings["log_max_bytes"] // 1000} KB; '
               f'keep {settings["log_rotations"]} rotated files plus the current log. Approximate maximum: '
               f'{(settings["log_max_bytes"] * (settings["log_rotations"] + 1)) // 1000000} MB.</div>'
               f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="log_limits">'
               f'<input type="number" name="size" min="100000" max="10000000" step="100000" value="{settings["log_max_bytes"]}" aria-label="Maximum log file bytes"> bytes/file '
               f'<input type="number" name="count" min="1" max="20" value="{settings["log_rotations"]}" aria-label="Rotated log count"> backups '
               f'<button>Save rotation</button></form></div>')
    # Show the address the live socket is actually bound to. This avoids stale or
    # default configuration values making the help text point at loopback when
    # the listener is serving the LAN (or vice versa).
    web_host = "127.0.0.1" if settings["localhost_only"] else (listener_host or settings["listen"] or machine.lan_ip())
    if web_host in ("0.0.0.0", "::"):
        web_host = machine.lan_ip()
    local_only = (f'<div class="card"><strong>Admin page available only on 127.0.0.1</strong>: '
                  f'<span class="{"ok" if settings["localhost_only"] else "bad"}">{on(settings["localhost_only"])}</span>'
                  f'<div class="dim">When on, only this computer can connect at https://127.0.0.1:{settings["port"]}/. '
                  f'When off, it listens at https://{esc(web_host)}:{settings["port"]}/. Changing this restarts the web listener; '
                  'turning it on disconnects browsers on other computers.</div>'
                  f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="localhost_only">'
                  f'<button name="value" value="{"off" if settings["localhost_only"] else "on"}">Switch {"off" if settings["localhost_only"] else "on"}</button></form></div>')
    ssh_help = ("<div class='card'><strong>SSH login policy on Windows</strong>"
                "<p>QR approval is enabled by default for local accounts. OpenSSH checks the account's configured key or password first. "
                "If that account has never enrolled a phone, the fallback setting below lets its normal SSH login work so it can be set up. "
                "After a phone is enrolled, QR approval is required. A disabled phone does not count as an unconfigured account.</p>"
                "<p>Use <em>Block SSH</em> to deny that account regardless of its key, password, or phone. Clear both controls to restore ordinary SSH access. "
                "Every change asks for a fresh admin phone approval, backs up <code>sshd_config</code>, validates it, and restarts OpenSSH.</p></div>")
    source = grants.ssh_source_policy()
    source_modes = source["modes"] if source["modes"] != ["invalid"] else ["local", "vpn"]
    source_error = "The saved network policy is malformed. Save a valid policy to repair it." if source["modes"] == ["invalid"] else ""
    local_networks = machine.interface_networks("local")
    source_policy = (
        "<div class='card'><strong>Allowed source networks for Thessley SSH logins</strong>"
        + (f"<p class='bad'>{esc(source_error)}</p>" if source_error else "")
        + "<p class='dim'>Check one or more source types. All IPs is exclusive. Clients outside the selected networks are refused before phone approval. "
          "This applies to accounts using the Thessley SSH controls. The four-hour approval pass remains tied to its original client IP.</p>"
        + "<p class='dim'>The selected sources also scope the default OpenSSH firewall rule and the Thessley approval (TCP 47810) and Admin page (TCP 47820) listeners. "
          "The browser's current network must remain selected when saving. Other firewall allow rules can also grant access.</p>"
        + f"<form method='post' action='/admin/set' class='ssh-source-form'>{hidden}<input type='hidden' name='name' value='ssh_source_policy'>"
        + "<div class='ssh-source-options'>"
        + f"<label><input id='ssh-source-all' type='checkbox' name='all' value='on'{ ' checked' if source_modes == ['all'] else ''} "
          "onchange=\"if(this.checked)document.querySelectorAll('.ssh-source-restrict').forEach(x=>x.checked=false)\"> All IPs</label>"
        + f"<label><input class='ssh-source-restrict' type='checkbox' name='local' value='on'{ ' checked' if 'local' in source_modes else ''} "
          "onchange=\"if(this.checked)document.getElementById('ssh-source-all').checked=false\"> Local networks</label>"
        + f"<label><input class='ssh-source-restrict' type='checkbox' name='vpn' value='on'{ ' checked' if 'vpn' in source_modes else ''} "
          "onchange=\"if(this.checked)document.getElementById('ssh-source-all').checked=false\"> VPN networks</label>"
        + f"<label><input class='ssh-source-restrict' type='checkbox' name='custom' value='on'{ ' checked' if 'custom' in source_modes else ''} "
          "onchange=\"if(this.checked)document.getElementById('ssh-source-all').checked=false\"> Chosen list</label></div>"
        + "<label for='vpn-subnets'>VPN client subnets</label>"
        + f"<input id='vpn-subnets' type='text' name='vpn_subnets' value='{esc(', '.join(source['vpn_subnets']))}' placeholder='10.8.0.0/24, 10.8.1.0/24'>"
        + "<label for='ssh-source-addresses'>Additional IP addresses or CIDR ranges for Chosen list</label>"
        + f"<input id='ssh-source-addresses' type='text' name='addresses' value='{esc(', '.join(source['addresses']))}' placeholder='Example: 203.0.113.7, 198.51.100.0/24'>"
        + f"<p class='dim'>Detected local networks: {esc(', '.join(local_networks) or 'none')}. Enter your VPN client subnet above if automatic detection is unavailable.</p>"
        + "<button>Save network access</button></form></div>")
    ssh_accounts_html = ""
    try:
        accounts = ssh_policy.local_accounts()
        active_policies = ssh_policy.policies()
        custom_users = ssh_policy.custom_match_users()
        rows = []
        for account in accounts:
            username = account["name"]
            normalized = store.normalize_user(username)
            factor = active_policies.get(normalized)
            if factor == "manual" or normalized in custom_users:
                blocked = normalized in ssh_policy.blocked_users()
                blocked_checked = " checked" if blocked else ""
                qr_checked = " checked" if factor != "manual" else ""
                rows.append(
                    "<form method='post' action='/admin/set' class='card ssh-policy-row'>" + hidden +
                    "<input type='hidden' name='name' value='ssh_policy'>" +
                    f"<input type='hidden' name='user' value='{esc(username)}'>" +
                    "<input type='hidden' name='factor' value='native'>" +
                    f"<label><input type='checkbox' name='enabled' value='on'{qr_checked}> Require QR approval</label> "
                    f"<label><input type='checkbox' name='blocked' value='on'{blocked_checked}> Block SSH for <strong>{esc(username)}</strong></label> "
                    f"<button>Save</button><div class='dim'>A custom <code>Match User</code> rule exists. Its current key/password settings are preserved; this page only adds or removes the QR gate and SSH block.</div></form>"
                )
                continue
            device_ready = bool(store.active_devices(normalized))
            qr_checked = " checked" if normalized in active_policies else ""
            blocked = normalized in ssh_policy.blocked_users()
            blocked_checked = " checked" if blocked else ""
            factor = factor or "native"
            device_note = ("An active phone is enrolled; QR approval is required." if device_ready else
                           f"No active phone. The configured fallback applies until {esc(username)} enrolls one. "
                           f"<a href='/keys?user={esc(username)}'>Manage {esc(username)}'s devices</a>.")
            rows.append(
                "<form method='post' action='/admin/set' class='card ssh-policy-row'>" + hidden +
                "<input type='hidden' name='name' value='ssh_policy'>" +
                f"<input type='hidden' name='user' value='{esc(username)}'>" +
                f"<label><input type='checkbox' name='enabled' value='on'{qr_checked}> Require QR approval</label> "
                f"<label><input type='checkbox' name='blocked' value='on'{blocked_checked}> Block SSH for <strong>{esc(username)}</strong></label> "
                "<label>First factor <select name='factor'>" + "".join(
                    f"<option value='{value}'{' selected' if factor == value else ''}>{label}</option>"
                    for value, label in (("native", "Current OpenSSH settings"), ("key", "SSH key"), ("password", "Account password"),
                                         ("key-password", "SSH key and account password"))) +
                f"</select></label> <button>Save</button><div class='dim'>{device_note}</div></form>"
            )
        if rows:
            ssh_accounts_html = ("<section class='user-section'><h3>Users</h3><p class='dim'>QR approval is the default. "
                                "The first factor dropdown selects the existing OpenSSH method or an explicit key/password requirement. "
                                "Domain accounts are not listed. You can block each local account independently.</p>" +
                                "".join(rows) + "</section>")
        else:
            ssh_accounts_html = "<p class='dim'>No supported enabled local accounts were found.</p>"
    except Exception as exc:
        ssh_accounts_html = f"<p class='bad'>Could not read local SSH accounts: {esc(str(exc))}</p>"
    return (flash_html(flash) + "<h2>Settings for this computer</h2>"
            "<p class='dim'>Only administrators see this page. Every change asks your device for a fresh approval.</p>"
            + source_policy + ssh_help + ssh_accounts_html + ssh_fallback + limits + logging + local_only + grace + toggle + f"<p class='dim'>Passes held right now: {esc(len(grants.all_passes()))}.</p>")


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
            if s is not None and s.bootstrap:
                return f if f.kind == "enroll" and s.bootstrap_flow_id == f.id and s.user == f.owner else None
            return f if s is not None and s.user == f.owner else None

        # -- routes
        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path)
            route, query = path.path, {k: v[0] for k, v in parse_qs(path.query).items()}
            s = self.session()
            if s is not None and s.bootstrap:
                allowed = (route in ("/", "/bootstrap", "/bootstrap/setup", "/bootstrap/done")
                           or re.fullmatch(r"/(?:wait|status)/[0-9a-f]{32}", route)
                           or re.fullmatch(r"/qr/[0-9a-f]{32}\.svg", route)
                           or re.fullmatch(r"/enroll/[0-9a-f]{32}", route))
                if not allowed:
                    return self.redirect("/bootstrap/setup")
            if route == "/":
                if s is not None and s.bootstrap:
                    return self.redirect("/bootstrap/setup")
                return self.redirect("/keys") if s else self.html(200, "Sign in", login_page())
            if route == "/bootstrap":
                return self.html(200, "First phone setup", bootstrap_page(query.get("token", "")))
            token_route = re.fullmatch(r"/([0-9a-f]{64})", route)
            if token_route:
                return self.html(200, "First phone setup", bootstrap_page(token_route.group(1)))
            if route == "/bootstrap/setup":
                s = self.need_session()
                if s is None:
                    return
                if not s.bootstrap:
                    return self.redirect("/keys")
                if not is_admin(s.user) or store.devices(s.user):
                    app.drop_session(s.token)
                    return self.redirect("/bootstrap/done", [self.cookie("thessley_session", "", 0)])
                if s.bootstrap_flow_id:
                    flow = app.flow(s.bootstrap_flow_id)
                    if flow is not None and flow.state not in ("failed", "timeout", "refused"):
                        return self.redirect(f"/wait/{flow.id}")
                    s.bootstrap_flow_id = ""
                flash, s.flash = s.flash, ""
                return self.html(200, "Enroll first phone", bootstrap_setup_page(s, flash), s)
            if route == "/bootstrap/done":
                return self.html(200, "First phone enrolled", bootstrap_done_page())
            m = re.fullmatch(r"/wait/([0-9a-f]{32})", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None:
                    return self.html(404, "Not found", flash_html("That request is no longer here. Start again."), s)
                heading = "Approve the sign-in" if f.kind == "login" else f"Approve: {f.description}"
                note = (f"Scan the code with the Thessley Passkey app, or open the link. You have {WEB_WAIT // 60} minutes." if f.kind != "enroll"
                        else "Scan the code with the new device's Thessley Passkey app, or open the link on the new app.")
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
                return self.html(200, "Add a device", wait_page(f, "{NONCE}", s, "Add a device",
                                 "Scan the code with the new device's Thessley Passkey app, or open the link on the new app."), s)
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
                page_text = query.get("page", "1")
                page_number = int(page_text) if page_text.isdigit() else 1
                return self.html(200, "Activity", log_page(rows, "everyone" if everyone else s.user,
                                                              page_number, everyone), s)
            if route == "/admin":
                s = self.need_session()
                if s is None:
                    return
                if not is_admin(s.user):
                    return self.html(403, "Not allowed", flash_html("Only administrators can open this page."), s)
                flash, s.flash = s.flash, ""
                listener_host = str(app.httpd.server_address[0]) if app.httpd is not None else ""
                return self.html(200, "Admin", admin_page(s, flash, listener_host), s)
            self.html(404, "Not found", flash_html("There is nothing here."), s)

        def do_POST(self):  # noqa: N802
            route = urlsplit(self.path).path
            data = self.form()
            s = self.session()
            if route == "/bootstrap":
                if not app.rate_ok(self.ip()):
                    return self.html(429, "Slow down", bootstrap_page(data.get("token", ""),
                                    "Too many setup attempts from this address. Wait a few minutes."))
                if not grants.web_settings()["enabled"]:
                    return self.html(200, "First phone setup", bootstrap_page(data.get("token", ""),
                                    "The web page is off. Start setup again from the installer."))
                user = grants.consume_web_bootstrap(data.get("token", ""), data.get("code", ""))
                if user is None or not is_admin(user) or store.devices(user):
                    return self.html(200, "First phone setup", bootstrap_page(data.get("token", ""),
                                    "That one-time link or password is invalid, expired, or already used."))
                session = app.new_session(user, bootstrap=True)
                app.log(f"web page: one-time first-device setup started for {user}", False)
                return self.redirect("/bootstrap/setup", [self.cookie("thessley_session", session.token)])
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
            if s.bootstrap and route != "/bootstrap/enroll" and not re.fullmatch(r"/enroll/[0-9a-f]{32}/confirm", route):
                return self.redirect("/bootstrap/setup")
            if not self.csrf_ok(s, data):
                return
            if route == "/bootstrap/enroll":
                if not s.bootstrap or not is_admin(s.user):
                    return self.redirect("/")
                if store.devices(s.user):
                    app.drop_session(s.token)
                    return self.redirect("/bootstrap/done", [self.cookie("thessley_session", "", 0)])
                if s.bootstrap_flow_id:
                    flow = app.flow(s.bootstrap_flow_id)
                    if flow is not None and flow.state not in ("failed", "timeout", "refused"):
                        return self.redirect(f"/wait/{flow.id}")
                    s.bootstrap_flow_id = ""
                flow = app.start_enroll(s.user, owner=s.user)
                if flow is None:
                    return self.html(503, "Busy", flash_html("Enrollment could not start. Try again."), s)
                s.bootstrap_flow_id = flow.id
                return self.redirect(f"/wait/{flow.id}")
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
            if route == "/passes/end":
                return self.passes_end(data, s)
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
                return self.start_change(s, f"adding a device for {target}", app.change_begin_enroll(target, s.user), TTY_DEVICE)
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

        def passes_end(self, data: dict, s: Session) -> None:
            """End one pass, or all of an account's. Only takes access away, so no fresh approval is asked."""
            target = app.target(s, data.get("user"))
            if target is None:
                return self.html(403, "Not allowed", flash_html("You can only end your own passes."), s)
            if data.get("all"):
                ended = grants.revoke(username=target)
            else:
                rhost = str(data.get("rhost", ""))
                if not rhost or len(rhost) > 64:
                    return self.html(400, "Not valid", flash_html("No such pass."), s)
                ended = grants.revoke_one(target, rhost)
            app.log(f"web page: {s.user} ended {ended} pass(es) of {target}", False)
            s.flash = (f"Ended {ended} pass{'es' if ended != 1 else ''}. The next login asks your device again." if ended
                       else "That pass had already ended.")
            return self.redirect("/keys" if target == s.user else f"/keys?user={target}")

        def admin_action(self, data: dict, s: Session) -> None:
            name, value = data.get("name", ""), (data.get("value") or "").strip()
            details = {}
            if name == "ssh_policy":
                target, factor = (data.get("user") or "").strip(), (data.get("factor") or "native").strip()
                try:
                    target_key = store.normalize_user(target)
                    known = {store.normalize_user(row["name"]) for row in ssh_policy.local_accounts()}
                except (ValueError, RuntimeError, OSError):
                    return self.html(400, "Not valid", flash_html("Could not verify that local Windows account."), s)
                if target_key not in known:
                    return self.html(400, "Not valid", flash_html("Choose an enabled local Windows account from this page."), s)
                if factor not in ("native", "key", "password", "key-password"):
                    return self.html(400, "Not valid", flash_html("Choose the current OpenSSH settings, an SSH key, account password, or both."), s)
                enabled = data.get("enabled") == "on"
                blocked = data.get("blocked") == "on"
                description = f"updating SSH access for account {target_key}"
                return self.start_change(s, description, app.change_ssh_access(target_key, enabled, blocked, factor))
            if name == "ssh_source_policy":
                if data.get("all") == "on":
                    if any(data.get(option) == "on" for option in ("local", "vpn", "custom")):
                        return self.html(400, "Not valid", flash_html("All IPs cannot be combined with restricted source types."), s)
                    modes = ["all"]
                else:
                    modes = [option for option in ("local", "vpn", "custom") if data.get(option) == "on"]
                if not modes:
                    return self.html(400, "Not valid", flash_html("Choose All IPs or at least one restricted source type."), s)
                try:
                    vpn_subnets = grants.parse_ipv4_networks(data.get("vpn_subnets") or "")
                    addresses = grants.parse_ipv4_networks(data.get("addresses") or "") if "custom" in modes else []
                except ValueError as exc:
                    return self.html(400, "Not valid", flash_html(str(exc)), s)
                if "vpn" in modes and not vpn_subnets:
                    return self.html(400, "Not valid", flash_html("Enter at least one VPN client subnet or uncheck VPN networks."), s)
                if "custom" in modes and not addresses:
                    return self.html(400, "Not valid", flash_html("Enter at least one IP address or CIDR range for Chosen list."), s)
                if not grants.ssh_source_client_allowed(self.ip(), modes, vpn_subnets, addresses):
                    return self.html(400, "Not allowed", flash_html(f"This would block the browser you are using ({self.ip()}). Keep its network selected."), s)
                details = {"modes": modes, "vpn_subnets": vpn_subnets, "addresses": addresses}
                return self.start_change(s, "changing Windows Firewall source networks",
                                         app.change_setting(name, "ssh_source_policy", details))
            if name == "grace":
                try:
                    hours = float(value)
                except ValueError:
                    hours = -1
                if not 0 <= hours <= grants.MAX_HOURS:
                    return self.html(400, "Not valid", flash_html(f"Give a number of hours from 0 to {grants.MAX_HOURS:g}."), s)
            elif name == "session":
                try:
                    minutes = float(value)
                except ValueError:
                    minutes = -1
                if not 1 <= minutes <= 240:
                    return self.html(400, "Not valid", flash_html("Give a number of minutes from 1 to 240."), s)
            elif name in ("web_limits", "log_limits"):
                try:
                    first = int(data.get("connections" if name == "web_limits" else "size", ""))
                    second = int(data.get("buckets" if name == "web_limits" else "count", ""))
                except ValueError:
                    first, second = 0, 0
                valid = (4 <= first <= 256 and 64 <= second <= 100000) if name == "web_limits" else (100000 <= first <= 10000000 and 1 <= second <= 20)
                if not valid:
                    return self.html(400, "Not valid", flash_html("Check the resource or rotation values."), s)
                value = f"{first},{second}"
            elif name in ("self_enroll", "ssh_fallback_unenrolled"):
                if value not in ("on", "off"):
                    return self.html(400, "Not valid", flash_html("Choose on or off."), s)
            elif name == "localhost_only":
                if value not in ("on", "off"):
                    return self.html(400, "Not valid", flash_html("Choose on or off."), s)
            else:
                return self.html(404, "Not found", flash_html("No such setting."), s)
            self.start_change(s, f"changing a setting ({name})", app.change_setting(name, value, details))

        @staticmethod
        def failure_text(f: Flow) -> str:
            """Why an enrolment ended without a new device, in words that say which of the cases it was."""
            text = "\n".join(f.lines)
            if "Timed out" in text:
                return f"No device answered in {WEB_ENROLL_WAIT // 60} minutes, so nothing was added. Start again and scan the code in time."
            if "Cancelled" in text:
                return "This was cancelled, so nothing was added."
            if "Not added" in text:
                return "The codes were not confirmed in time or did not match, so nothing was added."
            if "error:" in text:
                return "Something went wrong on this computer, so nothing was added. Check the device list before trying again."
            return "The new device was not added."

        def status(self, fid: str, s: Session | None) -> None:
            f = self.flow_for(fid, s)
            if f is None:
                return self.json({"state": "gone", "message": "This request is no longer here. Start again.", "bad": True})
            extra = None
            out = {"state": f.state, "link": f.link, "code": f.code, "message": "", "bad": False}
            if f.link:
                with f.lock:
                    if not f.qr_rows:
                        f.qr_size, f.qr_path, f.qr_rows = qr_vector(f.link)
                    out["qr_size"] = f.qr_size
                    out["qr_rows"] = f.qr_rows
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
                out.update(message=self.failure_text(f), bad=True)
            elif f.state == "done" and f.kind == "enroll":
                if s is not None and s.bootstrap:
                    app.drop_session(s.token)
                    extra = [self.cookie("thessley_session", "", 0)]
                    out.update(next="/bootstrap/done")
                elif s is not None:
                    s.flash = f"Added {f.label or 'the new device'}."
                    out.update(next="/keys" if f.user == s.user else f"/keys?user={f.user}")
                else:
                    out.update(next="/keys")
            self.json(out, extra)

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Windows differs from Linux here: with SO_REUSEADDR (the default) another program can bind the very port this page
    # serves, and share or take over its connections. Bind exclusively, as listener.py does.
    allow_reuse_address = False

    def __init__(self, *args, **kwargs):
        self._worker_lock = threading.Lock()
        self._active_workers = 0
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        return request, address

    def process_request(self, request, client_address):
        with self._worker_lock:
            if self._active_workers >= grants.web_settings()["max_connections"]:
                # Do not perform a TLS handshake in the accept loop for rejected work.
                self.shutdown_request(request)
                return
            self._active_workers += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._worker_lock:
                self._active_workers -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._worker_lock:
                self._active_workers -= 1

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
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    return httpd


def main() -> int:
    """What the scheduled task runs."""
    return serve()


def serve() -> int:
    app = WebApp()
    last_network_log = 0.0
    while True:
        st = grants.web_settings()
        if not st["enabled"]:
            print("The admin web page is switched off (thessley-pam-win web on).")
            return 0
        local_only = st["localhost_only"]
        try:
            ip = "127.0.0.1" if local_only else (st["listen"] or machine.lan_ip())
        except OSError as exc:
            now = time.monotonic()
            if now - last_network_log >= 30:
                print(f"Waiting for a network address before starting the admin page: {exc}", flush=True)
                last_network_log = now
            time.sleep(1)
            continue
        if not local_only and not st["listen"]:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                address = None
            if address is None or address.is_loopback or address.is_link_local or address.is_unspecified:
                now = time.monotonic()
                if now - last_network_log >= 30:
                    print("Waiting for DHCP to provide a usable LAN address before starting the admin page.", flush=True)
                    last_network_log = now
                time.sleep(1)
                continue
        cert, key = (st["cert"], st["key"]) if st["cert"] and st["key"] else default_cert_paths()
        fingerprint = ensure_cert(cert, key, [ip, "127.0.0.1"])
        try:
            httpd = make_server(app, ip, st["port"], cert, key)
        except OSError as exc:
            # A DHCP address can become available just before Windows finishes assigning it to the interface.
            if getattr(exc, "winerror", None) != 10049 and getattr(exc, "errno", None) != errno.EADDRNOTAVAIL:
                raise
            now = time.monotonic()
            if now - last_network_log >= 30:
                print(f"Waiting for the LAN address to become bindable before starting the admin page: {exc}", flush=True)
                last_network_log = now
            time.sleep(1)
            continue
        app.httpd = httpd
        app.rebind_requested = False
        print(f"Thessley admin page: https://{ip}:{st['port']}/   certificate SHA-256 {fingerprint}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            app.httpd = None
            httpd.server_close()
        if not app.rebind_requested:
            break
    return 0
