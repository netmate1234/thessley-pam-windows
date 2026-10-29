"""The approval service. Runs as SYSTEM (a scheduled task started at boot) and is the only part that reads the list of
approvers and writes passes, so a logged-in user cannot add themselves as an approver or forge a pass.

The gate that sshd starts (gate.py) and the enrol command (cli.py) run as the logged-in user; they connect here. One line of
JSON each way over 127.0.0.1 (more lines follow while the request runs):

    client -> service   {"op": "approve", "user": "alice", "rhost": "192.168.1.50"}
                        {"op": "enroll",  "user": "alice"}
    service -> client   {"say": "text line"}                          show this
                        {"ask": "prompt", "timeout": 90}              the client answers {"answer": "yes"}
                        {"done": true, "ok": true|false}              the end

`enroll` is for a user adding an approver for THEIR OWN account without being an administrator. The service does not trust the
user name in the request: it asks Windows which account owns the connection (peer.py) and refuses anything else. Then:

  * an account with no approver at all may enrol its first one (switch: `thessley-pam-win self-enroll on|off`). A gated account
    with no approver cannot get a shell over ssh, so this means a session on the computer itself;
  * an account that has approvers, but none usable (all disabled, e.g. a lost phone), needs an administrator;
  * otherwise a fresh approval from an enrolled approver is needed first. A pass never counts, and none is created.
"""

import ipaddress
import json
import os
import re
import select
import socket
import socketserver
import threading
import time

from . import ad_agent, approve, drupal_agent, enroll, grants, machine, peer, qr, store, web
from .listener import SharedListener

HOST, PORT = "127.0.0.1", 47800
MAX_REQUEST = 2048
MAX_ACTIVE = 8          # approvals waiting at once
LOGON_NETWORK_WAIT = 180  # let the selected adapter recover after sleep before starting the phone timer
_log_lock = threading.Lock()


def log_path() -> str:
    return os.path.join(store.BASE, "service.log")


def log(msg: str, warn: bool = False) -> None:
    try:
        path = log_path()
        with _log_lock:
            settings = grants.web_settings()
            log_limit = settings["log_max_bytes"]
            rotations = settings["log_rotations"]
            for index in range(rotations + 1, 21):
                try:
                    os.remove(f"{path}.{index}")
                except FileNotFoundError:
                    pass
            if os.path.exists(path) and os.path.getsize(path) >= log_limit:
                try:
                    os.remove(f"{path}.{rotations}")
                except FileNotFoundError:
                    pass
                for index in range(rotations - 1, 0, -1):
                    source, target = f"{path}.{index}", f"{path}.{index + 1}"
                    if os.path.exists(source):
                        os.replace(source, target)
                os.replace(path, path + ".1")
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {'WARN' if warn else 'INFO'} {msg}\n")
    except OSError:
        pass


def valid_rhost(rhost) -> bool:
    if rhost == grants.LOCAL:
        return True
    try:
        ipaddress.ip_address(rhost)
        return True
    except (ValueError, TypeError):
        return False


class Handler(socketserver.StreamRequestHandler):
    timeout = 10

    def _send(self, obj: dict) -> bool:
        try:
            self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))
            self.wfile.flush()
            return True
        except OSError:
            return False

    def handle(self):
        try:
            req = json.loads(self.rfile.readline(MAX_REQUEST + 1))
            assert isinstance(req, dict)
            op = req.get("op")
            assert op in (
                "approve", "enroll", "admin-enroll", "web-approve", "web-enroll",
                "windows-logon", "windows-logon-test", "ad-ssh-approve")
            if op == "ad-ssh-approve":
                assert set(req) == {"op", "sid", "rhost"}
                sid = req["sid"]
                assert isinstance(sid, str) and re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid, re.IGNORECASE)
                rhost = req["rhost"]
                assert valid_rhost(rhost) and rhost != grants.LOCAL
                user, scope, context = "", "domain", "ssh"
            else:
                user = req["user"]
                assert isinstance(user, str)
                sid = req.get("sid", "")
                scope = req.get("principal_type", "")
                context = req.get("logon_context", "")
                assert isinstance(sid, str) and isinstance(scope, str) and isinstance(context, str)
                rhost = req.get("rhost") or grants.LOCAL
                assert op in ("enroll", "windows-logon") or valid_rhost(rhost)
        except Exception:
            self._send({"done": True, "ok": False, "error": "bad request"})
            return
        slots: threading.BoundedSemaphore = self.server.slots
        if not slots.acquire(blocking=False):
            self._send({"say": "Thessley Passkey: too many requests are waiting. Refusing."})
            self._send({"done": True, "ok": False})
            return
        cancel = threading.Event()
        try:
            if req["op"] == "approve":
                ok = self._approve(user, rhost, cancel)
            elif req["op"] == "web-approve":
                ok = self._web_approve(user, rhost, req.get("service", "web"), cancel)
            elif req["op"] == "web-enroll":
                ok = self._web_enroll(user, cancel)
            elif req["op"] == "admin-enroll":
                ok = self._admin_enroll(user, cancel)
            elif req["op"] == "windows-logon":
                ok = self._windows_logon(user, cancel, sid, scope, context)
            elif req["op"] == "windows-logon-test":
                ok = self._windows_logon_test(user, cancel)
            elif req["op"] == "ad-ssh-approve":
                ok = self._ad_ssh_approve(sid, rhost, cancel)
            else:
                ok = self._enroll(user, cancel)
        except Exception as e:  # strict: any unexpected failure refuses
            log(f"error for {user!r}: {e!r}", True)
            self._send({"say": "Thessley Passkey: internal error. Refusing."})
            ok = False
        finally:
            slots.release()
        self._send({"done": True, "ok": bool(ok)})

    def _say(self, cancel: threading.Event):
        def say(line: str) -> None:
            if not self._send({"say": line}):
                cancel.set()
        return say

    def _approve(self, user: str, rhost: str, cancel: threading.Event) -> bool:
        self.connection.settimeout(None)

        try:
            normalized = store.normalize_user(user)
            if not store.devices(normalized) and grants.ssh_fallback_unenrolled(normalized):
                self._send({"say": "No phone is enrolled for this account; continuing with its configured OpenSSH authentication."})
                log(f"{normalized} used the configured OpenSSH factor because no phone is enrolled", False)
                return True
        except (OSError, ValueError):
            pass

        def watch():  # the client hangs up (ssh session dropped): stop waiting
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()
        return approve.run(user, rhost, "ssh", self._say(cancel), log, cancel=cancel)

    def _ad_ssh_approve(self, sid: str, rhost: str, cancel: threading.Event) -> bool:
        """Phone-gate AD SSH, reusing the configured short-lived pass when still valid."""
        self.connection.settimeout(None)
        identity = peer.client_identity(self.client_address, self.server.server_address[1])
        if (not identity or identity.get("sid_type") != 1
                or str(identity.get("sid", "")).casefold() != sid.casefold()
                or not identity.get("authority")
                or identity["authority"].casefold() == socket.gethostname().casefold()
                or identity["authority"].casefold() in ("builtin", "nt authority", "nt service")):
            self._send({"say": "Thessley AD SSH: caller identity check failed. Refusing."})
            log("AD SSH approval refused because the SSH process token was not the requested domain user", True)
            return False

        if not ad_agent.configured():
            self._send({"say": "Thessley AD SSH: this PC is not paired with the AD approval service. Refusing."})
            log("AD SSH approval refused because this PC is not paired with the AD service", True)
            return False

        grace = grants.grace_hours()
        pass_rhost = "*" if grants.grace_any_ip() else rhost
        if grace > 0:
            try:
                principal = ad_agent.resolve_principal(sid)
                if not principal["authorized"]:
                    self._send({"say": "Thessley AD SSH: this account is no longer authorized on this computer. Refusing."})
                    log(f"AD SSH approval refused because {principal['authority']}\\{principal['username']} is no longer authorized", True)
                    return False
                active_credentials = {
                    key["credential_id"] for key in ad_agent.phone_keys()
                    if key["principal_id"] == principal["principal_id"]
                }
            except (ad_agent.AgentError, OSError, ValueError) as exc:
                self._send({"say": "Thessley AD SSH: could not verify current AD access and phone keys. Refusing."})
                log(f"AD SSH authorization/pass check failed ({type(exc).__name__})", True)
                return False
            held = grants.valid(principal["principal_id"], pass_rhost, active_credentials)
            if held:
                remaining = grants.remaining(held)
                self._send({"say": f"Thessley AD SSH: approved earlier; this login is covered ({remaining} remain)."})
                log(f"AD SSH pass used for {principal['authority']}\\{principal['username']} from {rhost} ({remaining} remain)")
                return True

        def watch():
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()
        try:
            started = ad_agent.start_login(sid, "ssh")
        except (ad_agent.AgentError, OSError, ValueError) as exc:
            self._send({"say": "Thessley AD SSH: approval could not be started. Refusing."})
            log(f"AD SSH request creation failed ({type(exc).__name__})", True)
            return False

        if not self._send({"say": "Scan this AD account SSH approval with Thessley Passkey."}) or not self._send(
                {"qr_link": started["link"]}):
            cancel.set()
            return False
        try:
            approving_credential = ad_agent.poll_login(
                started["request_id"], cancel,
                say=lambda message: self._send({"say": message}), timeout=120,
            )
        except (ad_agent.AgentError, OSError, ValueError) as exc:
            self._send({"say": "Thessley AD SSH: approval check failed. Refusing."})
            log(f"AD SSH approval polling failed ({type(exc).__name__})", True)
            return False
        if not approving_credential:
            log(f"AD SSH phone approval denied or expired from {rhost}", True)
            return False

        if grace > 0:
            display_user = f"{started['authority']}\\{started['username']}"
            try:
                grants.add(started["principal_id"], pass_rhost, grace, approving_credential,
                           display_user=display_user)
                scope = "any client IP" if grants.grace_any_ip() else rhost
                self._send({"say": f"Approved. Your next SSH login from {scope} needs no approval for {grace:g} h."})
                log(f"AD SSH pass granted to {display_user} (from {scope}, {grace:g} h)")
            except (OSError, ValueError) as exc:
                log(f"could not record the AD SSH pass for {display_user}: {exc}", True)
        log(f"AD SSH phone approval succeeded from {rhost}")
        return True

    def _web_approve(self, user: str, rhost: str, service: str, cancel: threading.Event) -> bool:
        """Serve web approvals from the daemon so all phones use its one shared HTTPS listener."""
        if not peer.client_is_system(self.client_address, self.server.server_address[1]):
            log(f"web approval refused for {user!r}: caller is not SYSTEM", True)
            return False
        if service not in ("web", "web-change", "add-device") or not valid_rhost(rhost):
            return False
        self.connection.settimeout(None)

        def watch():
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()
        return approve.run(user, rhost, service, self._say(cancel), log, cancel=cancel,
                           use_pass=False, grant_pass=False, wait=web.WEB_WAIT)

    def _web_enroll(self, user: str, cancel: threading.Event) -> bool:
        """Run admin-web enrollment inside the listener-owning service, on the shared single port."""
        if not peer.client_is_system(self.client_address, self.server.server_address[1]):
            log(f"web enrollment refused for {user!r}: caller is not SYSTEM", True)
            return False
        return self._run_enrollment(user, cancel)

    def _admin_enroll(self, user: str, cancel: threading.Event) -> bool:
        """Route the administrator CLI through the same shared listener rather than opening a second port."""
        caller = peer.client_user(self.client_address, self.server.server_address[1])
        if (caller is None or not web.is_admin(caller)
                or not peer.client_is_elevated(self.client_address, self.server.server_address[1])):
            log(f"administrator enrollment refused for {user!r}: caller was {caller!r}", True)
            self._send({"say": "Thessley Passkey: administrator rights are required to add a device for another account."})
            return False
        return self._run_enrollment(user, cancel)

    def _run_enrollment(self, user: str, cancel: threading.Event) -> bool:
        """Run enrollment in the listener-owning daemon; parallel enrollments share its port."""
        try:
            user = store.normalize_user(user)
        except ValueError:
            self._send({"say": "Thessley Passkey: this account name is not supported. Refusing."})
            return False

        stop_watching = self._watch(cancel)
        with self.server.enrolling_lock:
            if user in self.server.enrolling:
                self._send({"say": "Thessley Passkey: an enrolment for this account is already running. Refusing."})
                return False
            self.server.enrolling.add(user)
        try:
            # The SYSTEM web process has already enforced the signed-in session, admin scope, and (for
            # existing accounts) the required step-up approval. Do not ask for that same approval twice.
            self.connection.settimeout(None)

            def enroll_say(line: str) -> None:
                self._say(cancel)(line)

            device = enroll.run(user, enroll_say, self._ask_yes(cancel, stop_watching), cancel=cancel,
                                wait=web.WEB_ENROLL_WAIT, confirm_wait=web.WEB_CONFIRM_WAIT, show_link=True)
            log(f"web page: {'enrolled ' + repr(device['label']) + ' ' + device['credential_id'] if device else 'enrolment not completed'} "
                f"for {user}", device is None)
            return device is not None
        finally:
            stop_watching.set()
            with self.server.enrolling_lock:
                self.server.enrolling.discard(user)

    def _windows_logon(self, user: str, cancel: threading.Event, sid: str = "", scope: str = "", context: str = "") -> bool:
        """A one-time phone approval for the Windows unlock tile, called by LogonUI as SYSTEM.

        Do not accept this operation from ordinary local processes, and never consume or create an SSH grace pass.
        The Windows authentication package still validates the user's password after the phone approves.
        """
        caller = peer.client_user(self.client_address, self.server.server_address[1])
        if not peer.client_is_system(self.client_address, self.server.server_address[1]):
            self._send({"say": "Thessley Passkey: Windows unlock approval is only available to the lock screen."})
            log(f"Windows unlock approval refused for {user!r}: caller was {caller!r}", True)
            return False

        self.connection.settimeout(None)

        def watch():
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()

        # After resume, LogonUI can be ready before Wi-Fi has re-associated or
        # DHCP has restored the configured adapter's address. Wait here so the
        # phone approval timer does not start before its QR URL is reachable.
        # The lock-screen request remains cancellable; normal Windows PIN and
        # password recovery stays available if the network never returns.
        deadline = time.monotonic() + LOGON_NETWORK_WAIT
        next_notice = 0.0
        phone_ip = None
        while not cancel.is_set():
            try:
                candidate_ip = machine.lan_ip()
                parsed_ip = ipaddress.ip_address(candidate_ip)
                if not (parsed_ip.is_loopback or parsed_ip.is_link_local or parsed_ip.is_unspecified):
                    phone_ip = str(parsed_ip)
                    break
                network_error = OSError("the selected phone network is not ready")
            except (OSError, ValueError) as exc:
                network_error = exc

            now = time.monotonic()
            if now >= deadline:
                self._send({"say": "The phone network is still unavailable. Choose PIN or password, or select Thessley to retry."})
                log(f"Windows unlock network did not become ready for {user!r}: {network_error!r}", True)
                return False
            if now >= next_notice:
                if not self._send({"say": "Waiting for the phone network after wake. Approval starts when it is ready."}):
                    cancel.set()
                    return False
                next_notice = now + 5
            cancel.wait(1)
        if cancel.is_set():
            return False

        def say(line: str) -> None:
            if line.startswith("Link: "):
                link = line[6:]
                if not self._send({"say": "Scan this QR code with Thessley Passkey to unlock."}):
                    cancel.set()
                    return
                rows = qr.bitmap_rows(link, border=2)
                if not rows or not self._send({"qr_matrix": "/".join(rows)}):
                    cancel.set()
                return
            if any(char in line for char in "▄▀█"):
                return  # native UI receives the same QR as a matrix above
            if not self._send({"say": line}):
                cancel.set()

        # Windows SIDs are case-insensitive. Canonicalize before deriving the
        # SID-scoped filename/hash, which is case-sensitive at the byte level.
        if sid:
            sid = sid.strip().upper()

        # For local sign-in, Windows' local account database is authoritative.
        # Resolve the selected local name back to its SID so a stale or
        # differently-cased SID from LogonUI cannot send an enrolled account
        # through the ambiguous legacy username-key route. Never infer a SID
        # this way for domain accounts.
        if scope == "local" or (not sid and scope != "domain"):
            try:
                resolved_sid = drupal_agent._account_sid(user)
            except drupal_agent.AgentError:
                resolved_sid = ""
            if resolved_sid and drupal_agent.configured_sid(resolved_sid):
                if sid and sid.casefold() != resolved_sid.casefold():
                    log(f"Windows provider SID did not match the local account SID for {user!r}; using the exact local SID.", True)
                sid = resolved_sid
                log(f"Resolved local Windows login for {user!r} to its enrolled SID-bound Drupal key.")

        if sid and drupal_agent.configured_sid(sid):
            if not context:
                context = "interactive"
                log(f"Windows login context was omitted for {user!r}; using interactive sign-in.")
            try:
                return drupal_agent.run_login_v2(sid, context, say, cancel, log)
            except drupal_agent.AgentError as exc:
                self._send({"say": "Thessley Passkey: the distributed approval service is unavailable. Choose PIN or password, or retry."})
                log(f"Drupal Windows approval refused for {user!r}: {exc}", True)
                return False

        if sid and scope == "domain":
            self._send({"say": "This domain account has no SID-bound Thessley enrollment. Choose PIN or password, or enroll this exact account in Drupal."})
            log(f"Unenrolled domain principal refused for {user!r}", True)
            return False

        if sid and scope == "local" and drupal_agent.configured_legacy_local_sid(user, sid):
            try:
                return drupal_agent.run_login(user, say, cancel, log)
            except drupal_agent.AgentError as exc:
                self._send({"say": "Thessley Passkey: the distributed approval service is unavailable. Choose PIN or password, or retry."})
                log(f"Legacy Drupal Windows approval refused for {user!r}: {exc}", True)
                return False

        # Older providers do not supply a SID. Preserve their legacy username-based behavior until the tile is updated.
        if not sid and drupal_agent.configured(user):
            try:
                return drupal_agent.run_login(user, say, cancel, log)
            except drupal_agent.AgentError as exc:
                self._send({"say": "Thessley Passkey: the distributed approval service is unavailable. Choose PIN or password, or retry."})
                log(f"Legacy Drupal Windows approval refused for {user!r}: {exc}", True)
                return False

        return approve.run(
            user, grants.LOCAL, "windows-logon", say, log, cancel=cancel,
            ip=phone_ip, use_pass=False, grant_pass=False, request_type="login",
        )

    def _windows_logon_test(self, user: str, cancel: threading.Event) -> bool:
        """Desktop-only prototype request. Restrict it to the connecting user's own account."""
        caller = peer.client_user(self.client_address, self.server.server_address[1])
        try:
            same_user = caller is not None and store.normalize_user(caller) == store.normalize_user(user)
        except ValueError:
            same_user = False
        if not same_user:
            self._send({"say": "Thessley test: request refused because the app must run as the account being tested."})
            log(f"Windows sign-in test refused for {user!r}: caller was {caller!r}", True)
            return False

        self.connection.settimeout(None)

        def watch():
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()

        def say(line: str) -> None:
            if line.startswith("Link: "):
                if not self._send({"say": "Scan this QR code with Thessley Passkey."}):
                    cancel.set()
                    return
                rows = qr.bitmap_rows(line[6:], border=2)
                if not rows or not self._send({"qr_matrix": "/".join(rows)}):
                    cancel.set()
                return
            if any(char in line for char in "▄▀█"):
                return
            if not self._send({"say": line}):
                cancel.set()

        return approve.run(
            user, grants.LOCAL, "windows-logon", say, log, cancel=cancel,
            use_pass=False, grant_pass=False, request_type="login",
        )

    # -- a user adding an approver for their own account ---------------------------------------------------------------

    def _watch(self, cancel: threading.Event):
        """Cancel when the client hangs up (the terminal was closed). Returns an event that stops the watching."""
        stop = threading.Event()

        def run():
            while not stop.is_set() and not cancel.is_set():
                try:
                    ready, _, _ = select.select([self.connection], [], [], 0.5)
                    if ready:
                        if self.connection.recv(1, socket.MSG_PEEK) == b"":
                            cancel.set()
                            return
                        time.sleep(0.2)  # data is waiting: the client has answered; leave it for the reader
                except OSError:
                    cancel.set()
                    return
        threading.Thread(target=run, daemon=True).start()
        return stop

    def _ask_yes(self, cancel: threading.Event, stop_watching: threading.Event):
        def ask(prompt: str, timeout: int) -> bool:
            stop_watching.set()  # from here the connection is read for the answer
            if not self._send({"ask": prompt, "timeout": timeout}):
                cancel.set()
                return False
            self.connection.settimeout(timeout + 5)
            try:
                reply = json.loads(self.rfile.readline(MAX_REQUEST + 1))
                return str(reply.get("answer", "")).strip().lower() in ("y", "yes")
            except (OSError, ValueError, AttributeError):
                return False
        return ask

    def _enroll(self, user: str, cancel: threading.Event) -> bool:
        say = self._say(cancel)
        try:
            user = store.normalize_user(user)
        except ValueError:
            say("Thessley Passkey: this account name is not supported. Refusing.")
            return False
        caller = peer.client_user(self.client_address, self.server.server_address[1])
        try:
            same = caller is not None and store.normalize_user(caller) == user
        except ValueError:
            same = False
        if not same:
            say("Thessley Passkey: you can only add an approver for your own account. An administrator can add one for others.")
            log(f"enrol for {user} refused: asked by {caller!r}", True)
            return False

        stop_watching = self._watch(cancel)
        with self.server.enrolling_lock:
            if user in self.server.enrolling:
                say("Thessley Passkey: an enrolment for this account is already running. Refusing.")
                return False
            self.server.enrolling.add(user)
        try:
            if not self._allowed_to_enroll(user, say, cancel):
                return False
            self.connection.settimeout(None)
            def enroll_say(line: str) -> None:
                if line.startswith("Link: "):
                    rows = qr.bitmap_rows(line[6:], border=2)
                    if rows:
                        self._send({"qr_matrix": "/".join(rows)})
                say(line)

            device = enroll.run(user, enroll_say, self._ask_yes(cancel, stop_watching), cancel=cancel, show_link=True)
            log(f"{'enrolled ' + repr(device['label']) + ' ' + device['credential_id'] if device else 'enrolment not completed'} "
                f"for {user} (by themselves)", device is None)
            return device is not None
        finally:
            stop_watching.set()
            with self.server.enrolling_lock:
                self.server.enrolling.discard(user)

    def _allowed_to_enroll(self, user: str, say, cancel: threading.Event) -> bool:
        everything = store.devices(user)          # including disabled ones
        if not everything:
            if grants.self_enroll_first():
                log(f"{user} enrols their first approver", False)
                return True
            say("Thessley Passkey: adding the first approver needs an administrator on this computer.")
            log(f"first enrolment for {user} refused: self-enrolment is off", True)
            return False
        if not store.active_devices(user):
            say("Thessley Passkey: every approver of this account is switched off. An administrator has to add a new one.")
            log(f"enrolment for {user} refused: all approvers disabled", True)
            return False
        say("This account already has an approver. Approve adding a new device on it first.")
        if approve.run(user, grants.LOCAL, "add-device", say, log, cancel=cancel, use_pass=False, grant_pass=False):
            return True
        log(f"enrolment for {user} refused: not approved by an existing approver", True)
        return False


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr=(HOST, PORT)):
        super().__init__(addr, Handler)
        self.slots = threading.BoundedSemaphore(MAX_ACTIVE)
        self.enrolling: set[str] = set()
        self.enrolling_lock = threading.Lock()


def main() -> int:
    store.ensure_dirs()
    if not grants.web_settings()["preserve_passes_on_restart"]:
        grants.clear_all()
    cert_dir = os.path.join(store.BASE, "approvals")
    cert_path, key_path = os.path.join(cert_dir, "cert.pem"), os.path.join(cert_dir, "key.pem")
    shared = None
    last_network_log = 0.0
    while shared is None:
        try:
            ip = machine.lan_ip()
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.is_loopback or parsed_ip.is_link_local or parsed_ip.is_unspecified:
                raise OSError("no usable LAN address yet")
            fingerprint = web.ensure_cert(cert_path, key_path, [ip])
            candidate = SharedListener(ip, cert_path, key_path, fingerprint)
            candidate.start()
            shared = candidate
        except (OSError, ValueError) as e:
            now = time.monotonic()
            if now - last_network_log >= 30:
                log(f"waiting for a usable network address before starting the approval listener: {e}", True)
                last_network_log = now
            time.sleep(1)
    approve.set_shared_listener(shared)
    server = Server()
    log(f"service started on {HOST}:{server.server_address[1]} and HTTPS approval listener {ip}:47810")
    drupal_sync_stop = threading.Event()
    threading.Thread(
        target=drupal_agent.sync_loop,
        args=(drupal_sync_stop, log),
        name="ThessleyDrupalPolicySync",
        daemon=True,
    ).start()
    try:
        server.serve_forever()
    finally:
        drupal_sync_stop.set()
        server.server_close()
        shared.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
