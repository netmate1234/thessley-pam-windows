"""Separate SSH ForceCommand gate for AD accounts.

This is deliberately not the local-account QR gate. The user process sends its
token SID to the SYSTEM service, which verifies the connecting process token
before using the machine-protected AD key to request phone approval.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys

from . import gate, peer, qr

HOST, PORT = "127.0.0.1", 47800
WAIT_FOR_SERVICE = 150


def ssh_client_address(env) -> str | None:
    """Read sshd's client address and reject malformed/non-IP values."""
    parts = (env.get("SSH_CONNECTION") or "").split()
    if len(parts) != 4:
        return None
    try:
        return str(ipaddress.ip_address(parts[0]))
    except ValueError:
        return None


def ask_ad(sid: str, rhost: str, out, address=(HOST, PORT), timeout=WAIT_FOR_SERVICE) -> bool:
    """Request a SID-bound AD SSH approval; all ambiguous outcomes refuse."""
    try:
        sock = socket.create_connection(address, timeout=5)
    except OSError:
        print("Thessley AD SSH: approval service unavailable. Refusing.", file=out, flush=True)
        return False
    try:
        sock.settimeout(timeout)
        request = {"op": "ad-ssh-approve", "sid": sid, "rhost": rhost}
        sock.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
        with sock.makefile("r", encoding="utf-8") as lines:
            for raw in lines:
                msg = json.loads(raw)
                if "say" in msg:
                    print(str(msg["say"]), file=out, flush=True)
                link = msg.get("qr_link")
                if isinstance(link, str) and len(link) <= 4096 and link.startswith("thessleypam://"):
                    rendered = qr.lines(link, border=2)
                    if rendered:
                        print("\n".join(rendered), file=out, flush=True)
                        print(f"Phone approval link: {link}", file=out, flush=True)
                    else:
                        print(f"Open this approval link on your phone: {link}", file=out, flush=True)
                if msg.get("done"):
                    return msg.get("ok") is True
    except KeyboardInterrupt:
        print("Thessley AD SSH: cancelled. Refusing.", file=out, flush=True)
        return False
    except (OSError, ValueError, TypeError):
        pass
    finally:
        sock.close()
    print("Thessley AD SSH: no approval response. Refusing.", file=out, flush=True)
    return False


def main(env=None, out=None, address=(HOST, PORT), run=subprocess.call, sid=None) -> int:
    env = os.environ if env is None else env
    out = gate.messages_stream(env) if out is None else out
    if hasattr(out, "reconfigure"):
        out.reconfigure(encoding="utf-8", errors="replace")
    if not env.get("SSH_TTY"):
        print(
            "Thessley AD SSH: this approval needs an interactive terminal. "
            "Reconnect with ssh -tt so Ctrl+C can cancel the QR request.",
            file=out, flush=True,
        )
        return 1
    identity = peer.process_identity(os.getpid()) if sid is None else {"sid": sid}
    if not identity or not isinstance(identity.get("sid"), str):
        print("Thessley AD SSH: cannot identify this account. Refusing.", file=out, flush=True)
        return 1
    rhost = ssh_client_address(env)
    if rhost is None:
        print("Thessley AD SSH: SSH client address is unavailable. Refusing.", file=out, flush=True)
        return 1
    original = env.get("SSH_ORIGINAL_COMMAND") or ""
    if re.match(r"(?i)^\s*(?:internal-sftp|sftp-server(?:\.exe)?)(?:\s|$)", original):
        print("Thessley AD SSH: SFTP sessions are not supported by this gate. Refusing.", file=out, flush=True)
        return 1
    if not ask_ad(identity["sid"], rhost, out, address):
        return 1
    return run(gate.shell_command(gate.default_shell(), original))


if __name__ == "__main__":
    raise SystemExit(main())
