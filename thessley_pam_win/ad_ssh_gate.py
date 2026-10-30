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
import time

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


SCP_COMMAND = re.compile(r"(?i)^\s*scp(?:\.exe)?(?:\s+-[A-Za-z0-9]+)*\s+-[tf](?:\s|$)")
SHELL_METACHARACTERS = re.compile(r"[&|<>^%;`$\x00-\x1f\x7f]")


SFTP_SUBSYSTEM = re.compile(r"(?i)^\s*sftp-server(?:\.exe)?(?:\s+-[A-Za-z](?:\s+[\w.-]+)?)*\s*$")
SFTP_ANY = re.compile(r"(?i)^\s*(?:internal-sftp|sftp-server(?:\.exe)?)(?:\s|$)")


def is_scp_command(original: str) -> bool:
    """True for the remote side of scp (`scp -t` receiving, `scp -f` sending) with nothing a shell could chain onto it."""
    return bool(SCP_COMMAND.match(original)) and not SHELL_METACHARACTERS.search(original)


def is_sftp_command(original: str) -> bool:
    """True for the SFTP subsystem command sshd hands a ForceCommand (`sftp-server.exe`, optionally with plain flags).
    `internal-sftp` is not accepted: only sshd itself can run it, not a command started by this gate."""
    return bool(SFTP_SUBSYSTEM.match(original)) and not SHELL_METACHARACTERS.search(original)


def is_file_transfer_command(original: str) -> bool:
    return is_scp_command(original) or is_sftp_command(original)


def ask_ad(sid: str, rhost: str, out, address=(HOST, PORT), timeout=WAIT_FOR_SERVICE, pass_only: bool = False) -> bool:
    """Request a SID-bound AD SSH approval; all ambiguous outcomes refuse.

    `pass_only` asks the service to accept an unexpired pass and otherwise refuse, never to start a phone request."""
    try:
        sock = socket.create_connection(address, timeout=5)
    except OSError:
        print("Thessley AD SSH: approval service unavailable. Refusing.", file=out, flush=True)
        return False
    try:
        # Windows socket reads can delay Python's Ctrl+C handling for the
        # entire socket timeout. Poll in short intervals so KeyboardInterrupt
        # is handled promptly while the phone approval is pending.
        sock.settimeout(0.5)
        deadline = time.monotonic() + timeout
        request = {"op": "ad-ssh-approve", "sid": sid, "rhost": rhost}
        if pass_only:
            request["pass_only"] = True
        sock.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
        pending = bytearray()
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            pending.extend(chunk)
            while b"\n" in pending:
                raw, _, remainder = pending.partition(b"\n")
                pending = bytearray(remainder)
                if not raw:
                    continue
                msg = json.loads(raw)
                if "say" in msg:
                    print(str(msg["say"]), file=out, flush=True)
                link = msg.get("qr_link")
                if isinstance(link, str) and len(link) <= 4096 and link.startswith("thessleypam://"):
                    rendered = qr.lines(link, border=2)
                    print(f"Phone approval link: {link}", file=out, flush=True)
                    if rendered:
                        print("\n".join(rendered), file=out, flush=True)
                    else:
                        print("QR rendering is unavailable; use the approval link above.", file=out, flush=True)
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
    original = env.get("SSH_ORIGINAL_COMMAND") or ""
    # Without a terminal there is nowhere to show the QR code or take Ctrl+C, so a phone request is never started. scp
    # (and SFTP) may still go through when an earlier approval, a pass, is valid for this account and client address.
    pass_only = not env.get("SSH_TTY")
    if pass_only and not is_file_transfer_command(original):
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
    if SFTP_ANY.match(original) and not (pass_only and is_sftp_command(original)):
        print("Thessley AD SSH: SFTP sessions are only supported without a terminal, using an earlier approval. Refusing.",
              file=out, flush=True)
        return 1
    if not ask_ad(identity["sid"], rhost, out, address, pass_only=pass_only):
        return 1
    return run(gate.shell_command(gate.default_shell(), original))


if __name__ == "__main__":
    raise SystemExit(main())
