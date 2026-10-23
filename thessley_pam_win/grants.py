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
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import tempfile
import threading
import time

from . import machine, store

MAX_HOURS = 24.0
LOCAL = "-"
SSH_SOURCE_MODES = ("all", "local", "vpn", "custom")
SSH_SOURCE_DEFAULTS = {"modes": ["local", "vpn"], "vpn_subnets": ["10.8.0.0/24", "10.8.1.0/24"], "addresses": []}


def parse_ipv4_networks(value: str | list[str] | tuple[str, ...]) -> list[str]:
    """Normalize a comma/space separated set of IPv4 addresses and CIDR ranges."""
    if isinstance(value, str):
        items = value.replace(",", " ").split()
    elif isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise ValueError("Enter IPv4 addresses or CIDR ranges.")
    if len(items) > 64:
        raise ValueError("Enter no more than 64 IPv4 addresses or networks.")
    networks = []
    for item in items:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 address or CIDR range: {item}") from exc
        if network.version != 4:
            raise ValueError("Use IPv4 addresses and CIDR ranges for Windows Firewall.")
        normalized = str(network)
        if normalized not in networks:
            networks.append(normalized)
    return networks


def ssh_source_policy() -> dict:
    config = _load_config()
    modes = config.get("ssh_source_modes", SSH_SOURCE_DEFAULTS["modes"])
    if (not isinstance(modes, list) or not modes or any(mode not in SSH_SOURCE_MODES for mode in modes)
            or len(modes) != len(set(modes)) or ("all" in modes and len(modes) != 1)):
        modes = ["invalid"]
    try:
        vpn_subnets = parse_ipv4_networks(config.get("vpn_client_subnets", SSH_SOURCE_DEFAULTS["vpn_subnets"]))
        addresses = parse_ipv4_networks(config.get("ssh_allowed_ips", []))
    except ValueError:
        vpn_subnets, addresses = [], []
        modes = ["invalid"]
    return {"modes": modes, "vpn_subnets": vpn_subnets, "addresses": addresses}


def set_ssh_source_policy(modes: list[str] | tuple[str, ...], vpn_subnets, addresses) -> None:
    if (not isinstance(modes, (list, tuple)) or not modes or any(mode not in SSH_SOURCE_MODES for mode in modes)
            or len(modes) != len(set(modes)) or ("all" in modes and len(modes) != 1)):
        raise ValueError("Choose All IPs alone, or one or more of local, VPN, and chosen-list access.")
    vpn_subnets = parse_ipv4_networks(vpn_subnets)
    addresses = parse_ipv4_networks(addresses)
    if "vpn" in modes and not vpn_subnets:
        raise ValueError("Enter at least one VPN client subnet or uncheck VPN networks.")
    if "custom" in modes and not addresses:
        raise ValueError("Enter at least one address or CIDR range for Chosen list.")
    store.ensure_dirs()
    data = _load_config()
    data["ssh_source_modes"] = list(modes)
    data["vpn_client_subnets"] = vpn_subnets
    if "custom" in modes:
        data["ssh_allowed_ips"] = addresses
    else:
        data.pop("ssh_allowed_ips", None)
    _atomic_write(_config_path(), data, store.BASE)


def ssh_source_client_allowed(client_ip: str, modes, vpn_subnets, addresses) -> bool:
    if modes == ["all"]:
        return True
    try:
        address = ipaddress.ip_address(client_ip)
        networks = []
        if "local" in modes:
            networks.extend(ipaddress.ip_network(item) for item in machine.interface_networks("local"))
            if address.is_loopback:
                return True
        if "vpn" in modes:
            networks.extend(ipaddress.ip_network(item) for item in vpn_subnets)
        if "custom" in modes:
            networks.extend(ipaddress.ip_network(item) for item in addresses)
        return any(address.version == network.version and address in network for network in networks)
    except (TypeError, ValueError, OSError):
        return False


def _config_path() -> str:
    return os.path.join(store.BASE, "config.json")


def _web_admins_path() -> str:
    return os.path.join(store.BASE, "web-admins.json")


def web_admins() -> set[str]:
    """Explicit administrators recorded by the elevated installer, in addition to Windows group members."""
    try:
        with open(_web_admins_path(), encoding="utf-8") as f:
            raw = json.load(f)
        users = raw.get("users", []) if isinstance(raw, dict) else []
        return {store.normalize_user(user) for user in users if isinstance(user, str)}
    except (OSError, ValueError, TypeError):
        return set()


def add_web_admin(username: str) -> None:
    """Add one installer-authorized account without altering service or web settings."""
    username = store.normalize_user(username)
    path = _web_admins_path()
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        users = raw.get("users", []) if isinstance(raw, dict) else []
    except FileNotFoundError:
        users = []
    if not isinstance(users, list):
        raise ValueError("Could not safely read the web administrator list.")
    normalized = {store.normalize_user(user) for user in users if isinstance(user, str)}
    normalized.add(username)
    store.ensure_dirs()
    _atomic_write(path, {"version": 1, "users": sorted(normalized)}, store.BASE)


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
                "max_connections": 32, "rate_limit_entries": 4096, "log_max_bytes": 1000000, "log_rotations": 5,
                "localhost_only": False}


def ssh_fallback_unenrolled() -> bool:
    """Allow normal SSH only for accounts that have never enrolled a phone; default on for setup recovery."""
    return _load_config().get("ssh_fallback_unenrolled", True) is not False


def set_ssh_fallback_unenrolled(enabled: bool) -> None:
    store.ensure_dirs()
    data = _load_config()
    data["ssh_fallback_unenrolled"] = bool(enabled)
    _atomic_write(_config_path(), data, store.BASE)

WEB_BOOTSTRAP_SECONDS = 10 * 60
_web_bootstrap_lock = threading.Lock()


def _web_bootstrap_path() -> str:
    return os.path.join(store.BASE, "web-bootstrap.json")


def create_web_bootstrap(username: str) -> tuple[str, str, int]:
    """Create a short-lived, one-use credential that can only start first-device enrollment."""
    username = store.normalize_user(username)
    with _web_bootstrap_lock:
        if store.devices(username):
            raise ValueError("This account already has a device; web bootstrap is only for first enrollment.")
        store.ensure_dirs()
        token = secrets.token_hex(32)
        code = f"{secrets.randbelow(100_000_000):08d}"
        expires = int(time.time() + WEB_BOOTSTRAP_SECONDS)
        record = {
            "user": username,
            "token_hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "code_hash": hashlib.sha256(f"{token}:{code}".encode("ascii")).hexdigest(),
            "expires_at": expires,
        }
        # Do not replace a live grant unexpectedly; issue another after expiry or consumption.
        path = _web_bootstrap_path()
        try:
            with open(path, encoding="utf-8") as f:
                current = json.load(f)
            active_until = current.get("expires_at", 0) if isinstance(current, dict) else 0
            if not isinstance(active_until, (int, float)):
                raise ValueError("Could not safely check an existing first-phone setup link.")
            if active_until > time.time():
                raise ValueError("A first-phone setup link is already active. Wait for it to expire before creating another.")
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            if isinstance(exc, ValueError) and ("already active" in str(exc) or "safely check" in str(exc)):
                raise
            raise ValueError("Could not safely check an existing first-phone setup link.") from exc
        _atomic_write(path, record, store.BASE)
        return token, code, expires


def consume_web_bootstrap(token: str, code: str, now: float | None = None) -> str | None:
    """Atomically consume the one-time bootstrap credential; return its account only if still unused and empty."""
    if not re.fullmatch(r"[0-9a-f]{64}", token or "") or not re.fullmatch(r"\d{8}", code or ""):
        return None
    path = _web_bootstrap_path()
    with _web_bootstrap_lock:
        return _consume_web_bootstrap_locked(path, token, code, now)


def _consume_web_bootstrap_locked(path: str, token: str, code: str, now: float | None = None) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, ValueError):
        return None

    def matches(candidate: dict) -> bool:
        try:
            username = store.normalize_user(candidate.get("user", ""))
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            code_hash = hashlib.sha256(f"{token}:{code}".encode("ascii")).hexdigest()
            return (candidate.get("expires_at", 0) > (time.time() if now is None else now)
                    and hmac.compare_digest(str(candidate.get("token_hash", "")), token_hash)
                    and hmac.compare_digest(str(candidate.get("code_hash", "")), code_hash)
                    and not store.devices(username))
        except (TypeError, ValueError, OSError):
            return False

    if not isinstance(record, dict) or not matches(record):
        return None
    claimed = path + ".used." + secrets.token_hex(8)
    try:
        # Rename is atomic on the same volume. Only one concurrent request can claim this file.
        os.rename(path, claimed)
    except OSError:
        return None
    try:
        with open(claimed, encoding="utf-8") as f:
            claimed_record = json.load(f)
        if not isinstance(claimed_record, dict) or not matches(claimed_record):
            return None
        username = store.normalize_user(claimed_record["user"])
        # Recheck after claiming. Another enrollment path may have won the race between
        # the initial check and the atomic rename.
        if store.devices(username):
            return None
        return username
    except (OSError, ValueError, KeyError):
        return None
    finally:
        try:
            os.unlink(claimed)
        except OSError:
            pass


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
    out["localhost_only"] = bool(out["localhost_only"])
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
