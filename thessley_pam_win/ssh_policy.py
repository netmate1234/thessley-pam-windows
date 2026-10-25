"""Per-account Windows OpenSSH QR policy management.

The web service runs as SYSTEM. It is the only process that edits sshd_config;
the browser supplies only a validated account name, an enabled flag, and a
fixed first-factor choice. Changes are backed up, validated by sshd, then
restarted transactionally.
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from . import store

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BEGIN = "# BEGIN THESSLEY SSH QR USER "
_END = "# END THESSLEY SSH QR USER "
_COMMAND_BEGIN = "# BEGIN THESSLEY SSH QR COMMAND "
_COMMAND_END = "# END THESSLEY SSH QR COMMAND "
_BLOCK_BEGIN = "# BEGIN THESSLEY SSH BLOCKED USERS"
_BLOCK_END = "# END THESSLEY SSH BLOCKED USERS"


class UnresolvableAccount(RuntimeError):
    """sshd cannot look the account up by name (for example a Microsoft account), so no Match User rule can apply to it."""


class UnsupportedMatchRule(RuntimeError):
    """A custom Match User block cannot be safely extended by the admin UI."""


def _paths() -> tuple[Path, Path]:
    root = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    config = root / "ssh" / "sshd_config"
    sshd = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "OpenSSH" / "sshd.exe"
    if not sshd.exists():
        sshd = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "OpenSSH" / "sshd.exe"
    if not sshd.exists():
        # OpenSSH can also be installed from the Win32 port rather than the
        # Windows capability. Its service ImagePath is the authoritative exe.
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services\sshd") as key:
                image_path = winreg.QueryValueEx(key, "ImagePath")[0]
            image_path = os.path.expandvars(str(image_path))
            match = re.match(r'^\s*"?(.+?sshd\.exe)"?(?:\s|$)', image_path, re.I)
            if match:
                candidate = Path(match.group(1))
                if candidate.is_file():
                    sshd = candidate
            config_arg = re.search(r'(?:^|\s)-f\s+(?:"([^"]+)"|(\S+))', image_path, re.I)
            if config_arg:
                candidate_config = Path(config_arg.group(1) or config_arg.group(2))
                if candidate_config.is_file():
                    config = candidate_config
        except (OSError, ImportError):
            pass
    return config, sshd


_LOCAL_ACCOUNTS_CACHE: list[dict[str, str]] | None = None
_LOCAL_ACCOUNTS_AT = 0.0
_LOCAL_ACCOUNTS_LOCK = threading.Lock()
_LOCAL_ACCOUNTS_REFRESHING = False


def _fetch_local_accounts() -> list[dict[str, str]]:
    """Query Windows and replace the local-account cache."""
    global _LOCAL_ACCOUNTS_CACHE, _LOCAL_ACCOUNTS_AT
    script = ("Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(501|503|504)$' } | "
              "Select-Object Name,@{Name='SID';Expression={$_.SID.Value}} | ConvertTo-Json -Compress")
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, errors="replace", timeout=12)
    except (OSError, subprocess.SubprocessError):
        result = None
    if result is None or result.returncode:
        # Older PowerShell builds may not expose Get-LocalUser; retain the WMI fallback.
        fallback = ("Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True AND Disabled=False' | "
                    "Where-Object { $_.SID -notmatch '-(501|503|504)$' } | "
                    "Select-Object Name,SID | ConvertTo-Json -Compress")
        try:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fallback],
                                    capture_output=True, text=True, errors="replace", timeout=20)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("Could not list local Windows accounts.") from exc
        if result.returncode:
            raise RuntimeError("Could not list local Windows accounts.")
    import json
    raw = json.loads(result.stdout or "[]")
    if isinstance(raw, dict):
        raw = [raw]
    accounts = []
    for item in raw:
        name = str(item.get("Name", ""))
        if _NAME.fullmatch(name):
            accounts.append({"name": name, "sid": str(item.get("SID", ""))})
    accounts = sorted(accounts, key=lambda x: x["name"].casefold())
    with _LOCAL_ACCOUNTS_LOCK:
        _LOCAL_ACCOUNTS_CACHE, _LOCAL_ACCOUNTS_AT = accounts, time.monotonic()
    return [dict(row) for row in accounts]


def _refresh_local_accounts_background() -> None:
    global _LOCAL_ACCOUNTS_REFRESHING
    try:
        _fetch_local_accounts()
    except Exception:
        pass  # Keep showing the last known list; a failed refresh must not slow or break Admin.
    finally:
        with _LOCAL_ACCOUNTS_LOCK:
            _LOCAL_ACCOUNTS_REFRESHING = False


def local_accounts(refresh: bool = False) -> list[dict[str, str]]:
    """Return enabled local accounts; refresh stale cached data in the background."""
    global _LOCAL_ACCOUNTS_REFRESHING
    with _LOCAL_ACCOUNTS_LOCK:
        cached = _LOCAL_ACCOUNTS_CACHE
        if not refresh and cached is not None:
            if time.monotonic() - _LOCAL_ACCOUNTS_AT >= 60 and not _LOCAL_ACCOUNTS_REFRESHING:
                _LOCAL_ACCOUNTS_REFRESHING = True
                threading.Thread(target=_refresh_local_accounts_background, daemon=True).start()
            return [dict(row) for row in cached]
    return _fetch_local_accounts()


def policies() -> dict[str, str]:
    config, _ = _paths()
    try:
        text = config.read_text(encoding="utf-8-sig")
    except OSError:
        return {}
    out: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith(_BEGIN):
            user = line[len(_BEGIN):].strip().casefold()
            block = []
            i += 1
            while i < len(lines) and lines[i].strip() != _END + user:
                block.append(lines[i].strip().casefold())
                i += 1
            factor = "native"
            if "authenticationmethods password" in block:
                factor = "password"
            elif "authenticationmethods publickey,password" in block:
                factor = "key-password"
            elif "authenticationmethods publickey" in block:
                factor = "key"
            out[user] = factor
        i += 1
    # A QR command can be added inside a pre-existing exact `Match User NAME`
    # stanza. Read its first factor from that surrounding stanza while treating
    # its per-account settings as managed by Thessley.
    for i, line in enumerate(lines):
        marker = line.strip()
        if not marker.startswith(_COMMAND_BEGIN):
            continue
        user = marker[len(_COMMAND_BEGIN):].strip().casefold()
        stanza_start = next((j for j in range(i - 1, -1, -1)
                             if re.match(r"^\s*Match\s+", lines[j], re.I)), None)
        if stanza_start is None:
            continue
        conditions = re.match(r"^\s*Match\s+(.+)$", lines[stanza_start], re.I).group(1)
        account = re.fullmatch(r"User\s+([A-Za-z0-9][A-Za-z0-9._-]{0,63})", conditions, re.I)
        if account and account.group(1).casefold() == user:
            stanza_end = next((j for j in range(stanza_start + 1, len(lines)
                                                ) if re.match(r"^\s*Match\s+", lines[j], re.I)), len(lines))
            block = [item.strip().casefold() for item in lines[stanza_start + 1:stanza_end]]
            factor = "native"
            if "authenticationmethods password" in block:
                factor = "password"
            elif "authenticationmethods publickey,password" in block:
                factor = "key-password"
            elif "authenticationmethods publickey" in block:
                factor = "key"
            out[user] = factor
    current_users: set[str] = set()
    for line in lines + ["Match all"]:
        match = re.match(r"^\s*Match\s+(.+)$", line, re.I)
        if match:
            for user in current_users:
                out.setdefault(user, "manual")
            conditions = match.group(1)
            user_match = re.search(r"(?:^|\s)User\s+([^#]+)", conditions, re.I)
            current_users = {item.strip().casefold() for item in re.split(r"[\s,]+", user_match.group(1))} if user_match else set()
    return out


def custom_match_users() -> set[str]:
    """Exact per-user Match rules that were not created as Thessley QR blocks."""
    config, _ = _paths()
    try:
        lines = config.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return set()
    managed_starts: set[int] = set()
    for i, line in enumerate(lines):
        marker = line.strip()
        if not marker.startswith(_BEGIN):
            continue
        user = marker[len(_BEGIN):].strip().casefold()
        for j in range(i + 1, len(lines)):
            match = re.match(r"^\s*Match\s+User\s+([^\s#]+)\s*$", lines[j], re.I)
            if match:
                if match.group(1).casefold() == user:
                    managed_starts.add(j)
                break
            if re.match(r"^\s*Match\s+", lines[j], re.I):
                break
    custom: set[str] = set()
    for i, line in enumerate(lines):
        match = re.match(r"^\s*Match\s+User\s+([A-Za-z0-9][A-Za-z0-9._-]{0,63})\s*$", line, re.I)
        if match and i not in managed_starts:
            custom.add(match.group(1).casefold())
    return custom


def blocked_users() -> set[str]:
    """The users explicitly denied SSH by the managed global DenyUsers rule."""
    config, sshd = _paths()
    if not config.is_file():
        return set()
    lines = config.read_text(encoding="utf-8-sig").splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip().casefold() == _BLOCK_BEGIN.casefold()]
    if len(starts) > 1:
        raise RuntimeError("Duplicate Thessley SSH block markers found; no changes were made.")
    if not starts:
        return set()
    start = starts[0]
    stop = next((i for i in range(start + 1, len(lines)) if lines[i].strip().casefold() == _BLOCK_END.casefold()), None)
    if stop is None:
        raise RuntimeError("The managed SSH block rule is incomplete; no changes were made.")
    users: set[str] = set()
    for line in lines[start + 1:stop]:
        match = re.match(r"^\s*DenyUsers\s+(.+?)\s*(?:#.*)?$", line, re.I)
        if match:
            users.update(item.casefold() for item in re.split(r"[\s,]+", match.group(1)) if _NAME.fullmatch(item))
    return users


def _remove_block(lines: list[str], begin: str, end: str, label: str) -> None:
    starts = [i for i, line in enumerate(lines) if line.strip().casefold() == begin.casefold()]
    if len(starts) > 1:
        raise RuntimeError(f"Duplicate Thessley {label} markers found; no changes were made.")
    if starts:
        start = starts[0]
        stop = next((i for i in range(start + 1, len(lines)) if lines[i].strip().casefold() == end.casefold()), None)
        if stop is None:
            raise RuntimeError(f"The Thessley {label} block is incomplete (the line {lines[start].strip()!r} has no matching "
                               f"{end!r}); no changes were made. Remove that one line from sshd_config, or run "
                               "install\\remove-for-reinstall.ps1, then run the installer again.")
        del lines[start:stop + 1]


def inside_ssh_session() -> bool:
    """True when this process was started from an ssh login, which a restart of sshd would cut off."""
    return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT") or os.environ.get("SSH_TTY"))


def _restart_sshd_later(delay_seconds: int = 90) -> str:
    """Restart sshd from a one-shot SYSTEM task a minute or two from now.

    Restarting sshd ends every ssh session, including the one the guided installer is running in, so the installer would lose its
    own output (and its last steps) half way. The task runs after the installer has finished and deletes itself. Returns the time."""
    name = "ThessleySshdRestartOnce"
    when = (datetime.datetime.now() + datetime.timedelta(seconds=delay_seconds)).strftime("%H:%M")
    command = f'powershell.exe -NoProfile -Command "Restart-Service sshd -Force; schtasks /Delete /TN {name} /F"'
    made = subprocess.run(["schtasks", "/Create", "/TN", name, "/SC", "ONCE", "/ST", when, "/RU", "SYSTEM", "/RL", "HIGHEST",
                           "/TR", command, "/F"], capture_output=True, text=True, errors="replace", timeout=30)
    if made.returncode:
        raise RuntimeError("Could not schedule the sshd restart: " + (made.stderr or made.stdout).strip())
    return when


def _restart_sshd() -> None:
    if inside_ssh_session():
        when = _restart_sshd_later()
        print(f"sshd will restart at {when}. This ssh session ends then; log in again to continue (the setup rollback timer stays armed).")
        return
    restart = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                              "Restart-Service sshd -Force; if ((Get-Service sshd).Status -ne 'Running') { exit 1 }"],
                             capture_output=True, text=True, timeout=30)
    if restart.returncode:
        raise RuntimeError("sshd did not restart successfully: " + (restart.stderr or restart.stdout).strip())


def set_access(username: str, qr_enabled: bool, blocked: bool, factor: str = "native", *, restart_service: bool = True) -> str:
    """Set a user's QR gate and SSH deny state in one backed-up, validated sshd_config transaction."""
    name = store.normalize_user(username)
    if not _NAME.fullmatch(name):
        raise ValueError("Unsupported Windows account name.")
    if factor not in ("native", "key", "password", "key-password"):
        raise ValueError("Choose existing SSH settings, SSH key, account password, or both.")
    config, sshd = _paths()
    if not config.is_file() or not sshd.is_file():
        raise RuntimeError("Windows OpenSSH Server is not installed or its configuration is missing.")
    text = config.read_text(encoding="utf-8-sig")
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    key = name.casefold()
    _remove_block(lines, _BEGIN + key, _END + key, f"SSH QR policy for {name}")
    _remove_block(lines, _COMMAND_BEGIN + key, _COMMAND_END + key, f"SSH QR command for {name}")
    _remove_block(lines, _BLOCK_BEGIN, _BLOCK_END, "SSH blocked-users")

    denied = blocked_users()
    if blocked:
        denied.add(key)
    else:
        denied.discard(key)

    if qr_enabled:
        if factor in ("key", "key-password"):
            program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
            system_drive = Path(os.environ.get("SystemDrive", "C:"))
            key_files = [program_data / "ssh" / "administrators_authorized_keys",
                         system_drive / "Users" / name / ".ssh" / "authorized_keys"]
            if not any(path.is_file() and path.stat().st_size > 0 for path in key_files):
                raise RuntimeError(f"No standard authorized_keys file was found for {name}. Set up and test that account's SSH key first, or select account password.")
        matching_stanzas = []
        for index, line in enumerate(lines):
            match = re.match(r"^\s*Match\s+(.+)$", line, re.I)
            if match:
                conditions = match.group(1).strip()
                user_match = re.search(r"(?:^|\s)User\s+([^#]+)", conditions, re.I)
                if user_match:
                    patterns = {item.strip().casefold() for item in re.split(r"[\s,]+", user_match.group(1))}
                    if name.casefold() in patterns or "*" in patterns:
                        if re.fullmatch(rf"User\s+{re.escape(name)}", conditions, re.I):
                            matching_stanzas.append(index)
                        else:
                            raise UnsupportedMatchRule(f"sshd_config has a complex custom Match User rule for {name}; the page left that rule unchanged.")
        if len(matching_stanzas) > 1:
            raise UnsupportedMatchRule(f"sshd_config has multiple custom Match User rules for {name}; the page left those rules unchanged.")

    if qr_enabled or denied:
        program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        launcher = program_data / "ThessleyPamWin" / "gate.cmd"
        gate = program_data / "ThessleyPamWin" / "app" / "gate_main.py"
        if qr_enabled and (not gate.is_file() or not launcher.is_file()):
            raise RuntimeError("The Thessley approval service is not installed.")
        if qr_enabled:
            launcher_text = launcher.read_text(encoding="utf-8", errors="replace")
            match = re.search(r'"([^"\r\n]+python\.exe)"', launcher_text, re.I)
            if not match:
                raise RuntimeError("Could not determine the installed trusted Python path.")
            py = Path(match.group(1))
            quote = lambda p: '"' + str(p).replace('"', '\\"') + '"'
            auth = {
                "native": [],
                "key": ["    PasswordAuthentication no", "    PubkeyAuthentication yes", "    AuthenticationMethods publickey"],
                "password": ["    PasswordAuthentication yes", "    PubkeyAuthentication no", "    AuthenticationMethods password"],
                "key-password": ["    PasswordAuthentication yes", "    PubkeyAuthentication yes", "    AuthenticationMethods publickey,password"],
            }[factor]
            if matching_stanzas:
                start = matching_stanzas[0]
                stop = next((i for i in range(start + 1, len(lines))
                             if re.match(r"^\s*Match\s+", lines[i], re.I)), len(lines))
                stanza = lines[start + 1:stop]
                if any(re.match(r"^\s*ForceCommand\b", line, re.I) for line in stanza):
                    raise UnsupportedMatchRule(f"sshd_config already sets a custom ForceCommand for {name}; the page left that rule unchanged.")
                command_block = [_COMMAND_BEGIN + key,
                                 f"    ForceCommand {quote(py)} -I -X utf8 {quote(gate)}",
                                 _COMMAND_END + key]
                lines[stop:stop] = command_block
            else:
                qr_block = [_BEGIN + key, f"Match User {name}", *auth,
                            "    KbdInteractiveAuthentication no", "    AllowTcpForwarding no",
                            "    AllowAgentForwarding no", "    X11Forwarding no", "    PermitTunnel no",
                            "    PermitTTY yes", f"    ForceCommand {quote(py)} -I -X utf8 {quote(gate)}", _END + key]
                first_match = next((i for i, line in enumerate(lines) if re.match(r"^\s*Match\s+", line, re.I)), len(lines))
                lines[first_match:first_match] = qr_block
        if denied:
            deny_block = [_BLOCK_BEGIN, "DenyUsers " + " ".join(sorted(denied)), _BLOCK_END]
            first_match = next((i for i, line in enumerate(lines) if re.match(r"^\s*Match\s+", line, re.I)), len(lines))
            lines[first_match:first_match] = deny_block

    updated = newline.join(lines) + (newline if text.endswith(("\n", "\r")) else "")
    backup_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ThessleyPamWin" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"sshd_config.web-{key}-{time.strftime('%Y%m%d-%H%M%S')}.bak"
    shutil.copy2(config, backup)
    # Open the existing file in place to retain its Windows ACL.
    try:
        config.write_text(updated, encoding="utf-8", newline="")
        check = subprocess.run([str(sshd), "-t", "-f", str(config)], capture_output=True, text=True, timeout=20)
        if check.returncode:
            raise RuntimeError("sshd rejected the updated config: " + (check.stderr or check.stdout).strip())
        if qr_enabled:
            effective = subprocess.run([str(sshd), "-T", "-f", str(config), "-C",
                                         f"user={name},host=localhost,addr=127.0.0.1"],
                                        capture_output=True, text=True, timeout=20)
            if effective.returncode or not re.search(r"(?im)^forcecommand .*gate_main\.py", effective.stdout):
                if "unable to resolve user" in (effective.stderr + effective.stdout).casefold():
                    raise UnresolvableAccount(f"sshd cannot look up the account {name} by that name; QR approval was not applied to it.")
                raise RuntimeError(f"sshd did not apply the Thessley gate to {name}.")
            expected_auth = {"key": "authenticationmethods publickey", "password": "authenticationmethods password",
                             "key-password": "authenticationmethods publickey,password"}.get(factor)
            if expected_auth and expected_auth not in effective.stdout.casefold().splitlines():
                raise RuntimeError(f"sshd did not apply the selected {factor} first factor to {name}.")
        if restart_service:
            _restart_sshd()
    except Exception:
        shutil.copyfile(backup, config)
        if restart_service:
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                            "Restart-Service sshd -Force"], capture_output=True, timeout=30)
        raise
    return str(backup)


def set_policy(username: str, enabled: bool, factor: str = "native") -> str:
    """Compatibility wrapper for callers that manage QR alone."""
    name = store.normalize_user(username)
    return set_access(name, enabled, name.casefold() in blocked_users(), factor)


def enable_default_policies() -> tuple[str | None, list[str], list[str]]:
    """Require QR for current local accounts while retaining OpenSSH's configured first factor."""
    existing = policies()
    blocked = blocked_users()
    added: list[str] = []
    skipped: list[str] = []
    backup = None
    config, _ = _paths()
    try:
        for account in local_accounts():
            username = store.normalize_user(account["name"])
            current = existing.get(username)
            if current is not None and current != "manual":
                continue
            try:
                path = set_access(username, True, username in blocked, "native", restart_service=False)
            except UnsupportedMatchRule:
                skipped.append(account["name"])
                continue
            except UnresolvableAccount:
                # one account sshd cannot resolve must not stop the others; set_access already put the config back as it was
                skipped.append(f"{account['name']} (sshd cannot look this account up, so it was left as it was)")
                continue
            if backup is None:
                backup = path
            added.append(account["name"])
            existing[username] = "native"
        if added:
            _restart_sshd()
    except Exception:
        if backup is not None:
            shutil.copyfile(backup, config)
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                            "Restart-Service sshd -Force"], capture_output=True, timeout=30)
        raise
    return backup, added, skipped
