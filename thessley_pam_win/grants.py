"""Passes: after one approval, the same user logging in over ssh from the same address needs no new approval for a
set number of hours.

    thessley-pam-win grace --hours 4         turn it on (0 = every login asks, the default)
    thessley-pam-win passes                  who holds a pass right now
    thessley-pam-win end-pass [--user NAME]  end passes at once

A pass is one entry in C:\\ProgramData\\ThessleyPamWin\\grants\\<user>.json (SYSTEM and Administrators only; the service
empties the folder every time it starts, so a restart ends every pass):

    rhost        where the login came from (the client's address from SSH_CONNECTION)
    credential   the approver that approved; if it is removed or switched off the pass stops working
    expires_at   fixed from the moment of the approval; using a pass does not extend it

What a pass does NOT know: which password or key was used. It is tied to the user and the client's address, so whoever
gets past the password step from the same address during the window is let through without a new approval. Keep the
window short and end passes (end-pass) when in doubt.
"""

import json
import os
import shutil
import tempfile
import time

from . import store

MAX_HOURS = 24.0
LOCAL = "-"


def _config_path() -> str:
    return os.path.join(store.BASE, "config.json")


def _grants_dir() -> str:
    return os.path.join(store.BASE, "grants")


def _load_config() -> dict:
    try:
        with open(_config_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def grace_any_ip() -> bool:
    """Whether grace passes apply regardless of the SSH client's address."""
    return _load_config().get("grace_any_ip") is True


def grace_hours() -> float:
    """Hours an approval stays valid; 0 means every login asks (the default)."""
    try:
        hours = float(_load_config().get("grace", 0))
    except (TypeError, ValueError):
        return 0.0
    return min(max(hours, 0.0), MAX_HOURS)


def set_grace(hours: float, ip_scope: str | None = None) -> None:
    hours = min(max(float(hours), 0.0), MAX_HOURS)
    if ip_scope not in (None, "same", "any"):
        raise ValueError("IP scope must be 'same' or 'any'.")
    store.ensure_dirs()
    data = _load_config()
    if hours > 0:
        data["grace"] = hours
    else:
        data.pop("grace", None)
    if ip_scope is not None:
        if ip_scope == "any":
            data["grace_any_ip"] = True
        else:
            data.pop("grace_any_ip", None)
    _atomic_write(_config_path(), data, store.BASE)


def self_enroll_first() -> bool:
    """May an account with no approver at all enrol its first one itself? On by default; `self-enroll off` closes it."""
    return _load_config().get("self_enroll_first", True) is not False


def set_self_enroll_first(on: bool) -> None:
    store.ensure_dirs()
    data = _load_config()
    if on:
        data.pop("self_enroll_first", None)
    else:
        data["self_enroll_first"] = False
    _atomic_write(_config_path(), data, store.BASE)


WEB_DEFAULTS = {"enabled": False, "listen": "", "port": 47820, "session_minutes": 15, "cert": "", "key": "",
                "max_connections": 32, "rate_limit_entries": 4096, "log_max_bytes": 1000000, "log_rotations": 5}


def web_settings() -> dict:
    """The admin web page's settings (thessley-pam-win web ...). listen "" means this computer's LAN address."""
    out = dict(WEB_DEFAULTS)
    raw = _load_config().get("web", {})
    if isinstance(raw, dict):
        out.update({k: v for k, v in raw.items() if k in WEB_DEFAULTS})
    try:
        out["port"] = min(max(int(out["port"]), 1), 65535)
        out["session_minutes"] = min(max(int(out["session_minutes"]), 1), 240)
        out["max_connections"] = min(max(int(out["max_connections"]), 4), 256)
        out["rate_limit_entries"] = min(max(int(out["rate_limit_entries"]), 64), 100000)
        out["log_max_bytes"] = min(max(int(out["log_max_bytes"]), 100000), 10000000)
        out["log_rotations"] = min(max(int(out["log_rotations"]), 1), 20)
    except (TypeError, ValueError):
        out["port"], out["session_minutes"] = WEB_DEFAULTS["port"], WEB_DEFAULTS["session_minutes"]
        out["max_connections"], out["rate_limit_entries"] = WEB_DEFAULTS["max_connections"], WEB_DEFAULTS["rate_limit_entries"]
        out["log_max_bytes"], out["log_rotations"] = WEB_DEFAULTS["log_max_bytes"], WEB_DEFAULTS["log_rotations"]
    out["enabled"] = bool(out["enabled"])
    return out


def set_web(**changes) -> dict:
    unknown = set(changes) - set(WEB_DEFAULTS)
    if unknown:
        raise ValueError(f"unknown web setting: {sorted(unknown)}")
    store.ensure_dirs()
    data = _load_config()
    web = data.get("web") if isinstance(data.get("web"), dict) else {}
    web.update(changes)
    data["web"] = web
    _atomic_write(_config_path(), data, store.BASE)
    return web_settings()


def _atomic_write(path: str, data, directory: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _path(username: str) -> str:
    return os.path.join(_grants_dir(), f"{store.normalize_user(username)}.json")


def _load(username: str) -> list[dict]:
    try:
        with open(_path(username), encoding="utf-8") as f:
            items = json.load(f)
        return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []
    except (OSError, ValueError):
        return []


def _save(username: str, items: list[dict]) -> None:
    path = _path(username)
    if not items:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    os.makedirs(_grants_dir(), exist_ok=True)
    _atomic_write(path, items, _grants_dir())


def _live(items: list[dict], now: float) -> list[dict]:
    return [i for i in items if isinstance(i.get("expires_at"), (int, float)) and i["expires_at"] > now]


def clear_all() -> None:
    """Forget every pass (the service does this when it starts)."""
    shutil.rmtree(_grants_dir(), ignore_errors=True)


def valid(username: str, rhost: str, active_credentials, now: float | None = None) -> dict | None:
    """The pass that lets this login through, or None. `active_credentials`: credential ids of the user's approvers
    that may still approve (a pass of a removed or switched-off approver is worthless)."""
    now = time.time() if now is None else now
    rhost = rhost or LOCAL
    active = set(active_credentials)
    for item in _live(_load(username), now):
        if item.get("rhost") == rhost and item.get("credential") in active:
            return item
    return None


def add(username: str, rhost: str, hours: float, credential: str, now: float | None = None) -> dict:
    """Record an approval. An earlier pass for the same user and place is replaced."""
    now = time.time() if now is None else now
    rhost = rhost or LOCAL
    hours = min(max(float(hours), 0.0), MAX_HOURS)
    entry = {"rhost": rhost, "credential": credential, "approved_at": int(now), "expires_at": int(now + hours * 3600)}
    items = [i for i in _live(_load(username), now) if i.get("rhost") != rhost]
    items.append(entry)
    _save(username, items)
    return entry


def all_passes(now: float | None = None) -> list[dict]:
    """Every live pass on this computer, with the user's name added."""
    now = time.time() if now is None else now
    out = []
    try:
        names = sorted(n[:-5] for n in os.listdir(_grants_dir()) if n.endswith(".json") and not n.startswith("."))
    except OSError:
        return out
    for name in names:
        out.extend({"user": name, **i} for i in _live(_load(name), now))
    return out


def passes_of(username: str, now: float | None = None) -> list[dict]:
    """The live passes of one account."""
    now = time.time() if now is None else now
    return _live(_load(username), now)


def revoke_one(username: str, rhost: str) -> int:
    """End the one pass for this user and client address. Returns how many ended (0 or 1)."""
    items = _load(username)
    keep = [i for i in items if i.get("rhost") != rhost]
    if len(keep) != len(items):
        _save(username, keep)
    return len(items) - len(keep)


def revoke(username: str | None = None) -> int:
    """End passes (all of a user's, or everyone's). Returns how many ended."""
    ended = 0
    users = [username] if username else sorted({p["user"] for p in all_passes()})
    for name in users:
        ended += len(_load(name))
        _save(name, [])
    return ended


def revoke_credential(username: str, credential: str) -> int:
    """End every pass that one approver granted (called when it is removed or switched off)."""
    items = _load(username)
    keep = [i for i in items if i.get("credential") != credential]
    if len(keep) != len(items):
        _save(username, keep)
    return len(items) - len(keep)


def remaining(entry: dict, now: float | None = None) -> str:
    seconds = max(0, int(entry["expires_at"] - (time.time() if now is None else now)))
    h, m = divmod(seconds // 60, 60)
    return f"{h} h {m:02d} min" if h else f"{m} min"
