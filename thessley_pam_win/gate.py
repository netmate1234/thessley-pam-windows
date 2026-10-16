"""The gate: what sshd runs (ForceCommand) after the password was accepted, in place of the user's shell.

It asks the approval service for an approval, shows its lines (the link and the QR code) in the ssh terminal and, only
if the answer is a clear yes, starts what the person asked for: their shell, or the command given to ssh. Anything
else (no answer, denied, service not running, an error) ends the connection: refused by default.

It runs as the logged-in user and needs nothing but the standard library. It trusts nothing from the environment
except what sshd itself sets (SSH_CONNECTION, SSH_ORIGINAL_COMMAND), and the user name comes from the process token.
"""

import ctypes
import json
import os
import socket
import subprocess
import sys

HOST, PORT = "127.0.0.1", 47800
WAIT_FOR_SERVICE = 150  # seconds: the approval itself is 90 (approve.WAIT), plus margin


def current_user() -> str:
    """The account this process runs as, from the process token (not from an environment variable)."""
    size = ctypes.c_ulong(257)
    buf = ctypes.create_unicode_buffer(size.value)
    if not ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size)):
        raise OSError("cannot tell who is logged in")
    return buf.value


def client_address(env) -> str:
    """The ssh client's address from SSH_CONNECTION ('client_ip client_port server_ip server_port'), set by sshd."""
    parts = (env.get("SSH_CONNECTION") or "").split()
    return parts[0] if parts else "-"


def ask(user: str, rhost: str, out, address=(HOST, PORT), timeout: float = WAIT_FOR_SERVICE) -> bool:
    """Run the approval through the service. True only when it answers {"done": true, "ok": true}."""
    try:
        sock = socket.create_connection(address, timeout=5)
    except OSError:
        print("Thessley Passkey: the approval service is not running. Refusing.", file=out, flush=True)
        return False
    try:
        sock.settimeout(timeout)
        sock.sendall((json.dumps({"op": "approve", "user": user, "rhost": rhost}) + "\n").encode("utf-8"))
        with sock.makefile("r", encoding="utf-8") as lines:
            for raw in lines:
                msg = json.loads(raw)
                if "say" in msg:
                    print(str(msg["say"]), file=out, flush=True)
                if msg.get("done"):
                    return msg.get("ok") is True
    except (OSError, ValueError):
        pass
    finally:
        sock.close()
    # Reaching this point (the service hung up, bad data, no "done") is a refusal.
    print("Thessley Passkey: no answer from the approval service. Refusing.", file=out, flush=True)
    return False


def default_shell() -> str:
    """The shell sshd uses on this computer (the OpenSSH DefaultShell setting, else cmd.exe)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OpenSSH") as key:
            value = winreg.QueryValueEx(key, "DefaultShell")[0]
            if value and os.path.exists(value):
                return value
    except OSError:
        pass
    return os.environ.get("COMSPEC") or r"C:\Windows\System32\cmd.exe"


def shell_command(shell: str, original: str | None) -> str:
    """The command line that starts `shell`, interactively or for one command."""
    name = os.path.basename(shell).lower()
    if not original:
        return f'"{shell}"'
    if name in ("cmd.exe", "cmd"):
        return f'"{shell}" /s /c "{original}"'
    if name in ("powershell.exe", "pwsh.exe"):
        return f'"{shell}" -NoLogo -Command {subprocess.list2cmdline([original])}'
    return f'"{shell}" -c {subprocess.list2cmdline([original])}'


def main(env=None, out=None, address=(HOST, PORT), run=subprocess.call, user=None) -> int:
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    if hasattr(out, "reconfigure"):
        out.reconfigure(encoding="utf-8", errors="replace")
    try:
        who = user or current_user()
    except OSError:
        print("Thessley Passkey: cannot tell who is logged in. Refusing.", file=out, flush=True)
        return 1
    if not ask(who, client_address(env), out, address):
        return 1
    return run(shell_command(default_shell(), env.get("SSH_ORIGINAL_COMMAND")))


if __name__ == "__main__":
    raise SystemExit(main())
