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
import select
import socket
import socketserver
import threading
import time

from . import approve, enroll, grants, peer, store

HOST, PORT = "127.0.0.1", 47800
MAX_REQUEST = 2048
MAX_ACTIVE = 8          # approvals waiting at once
LOG_LIMIT = 1_000_000   # bytes; the log is cut when it gets larger


def log_path() -> str:
    return os.path.join(store.BASE, "service.log")


def log(msg: str, warn: bool = False) -> None:
    try:
        path = log_path()
        if os.path.exists(path) and os.path.getsize(path) > LOG_LIMIT:
            os.replace(path, path + ".old")
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
            assert isinstance(req, dict) and req.get("op") in ("approve", "enroll")
            user = req["user"]
            assert isinstance(user, str)
            rhost = req.get("rhost") or grants.LOCAL
            assert req["op"] == "enroll" or valid_rhost(rhost)
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

        def watch():  # the client hangs up (ssh session dropped): stop waiting
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()
        return approve.run(user, rhost, "ssh", self._say(cancel), log, cancel=cancel)

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
            device = enroll.run(user, say, self._ask_yes(cancel, stop_watching), cancel=cancel)
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
    grants.clear_all()  # a restart ends every pass
    server = Server()
    log(f"service started on {HOST}:{server.server_address[1]}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
