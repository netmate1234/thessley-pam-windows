"""The approval service. Runs as SYSTEM (a scheduled task started at boot) and is the only part that reads the list of
approvers and writes passes, so a logged-in user cannot add themselves as an approver or forge a pass.

The gate that sshd starts (gate.py) runs as the user who just logged in; it connects here, shows what this service says
and reports back "approved or not". One line of JSON each way over 127.0.0.1:

    gate -> service   {"op": "approve", "user": "alice", "rhost": "192.168.1.50"}
    service -> gate   {"say": "text line"} ...  then  {"done": true, "ok": true|false}
"""

import ipaddress
import json
import os
import socketserver
import threading
import time

from . import approve, grants, store

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
            assert isinstance(req, dict) and req.get("op") == "approve"
            user, rhost = req["user"], req.get("rhost") or grants.LOCAL
            assert isinstance(user, str) and valid_rhost(rhost)
        except Exception:
            self._send({"done": True, "ok": False, "error": "bad request"})
            return
        slots: threading.BoundedSemaphore = self.server.slots
        if not slots.acquire(blocking=False):
            self._send({"say": "Thessley Passkey: too many logins are waiting. Refusing."})
            self._send({"done": True, "ok": False})
            return
        cancel = threading.Event()
        self.connection.settimeout(None)

        def watch():  # the client hangs up (ssh session dropped): stop waiting
            try:
                while self.connection.recv(1):
                    pass
            except OSError:
                pass
            cancel.set()

        threading.Thread(target=watch, daemon=True).start()

        def say(line: str) -> None:
            if not self._send({"say": line}):
                cancel.set()

        try:
            ok = approve.run(user, rhost, "ssh", say, log, cancel=cancel)
        except Exception as e:  # strict: any unexpected failure refuses
            log(f"error for {user!r}: {e!r}", True)
            say("Thessley Passkey: internal error. Refusing.")
            ok = False
        finally:
            slots.release()
        self._send({"done": True, "ok": bool(ok)})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr=(HOST, PORT)):
        super().__init__(addr, Handler)
        self.slots = threading.BoundedSemaphore(MAX_ACTIVE)


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
