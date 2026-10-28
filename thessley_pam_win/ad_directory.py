"""Cached AD user view fetched over the paired, pinned Thessley AD channel."""

from __future__ import annotations

import hashlib
import re
import threading
import time

from . import ad_agent


CACHE_SECONDS = 45
_CACHE_LOCK = threading.Lock()
_CACHE_AT = 0.0
_CACHE: dict | None = None


def _error(message: str) -> dict:
    return {"ok": False, "message": message, "domain": "", "truncated": False, "users": []}


def _query() -> dict:
    if not ad_agent.configured():
        return _error("This computer is not paired with the Thessley AD service. An administrator must pair it first.")
    try:
        result = ad_agent.directory_users()
    except (ad_agent.AgentError, OSError, ValueError):
        return _error("The paired Thessley AD service could not return the directory. Check its connection and pairing.")
    users = result.get("users")
    domain = result.get("domain")
    if not isinstance(users, list) or not isinstance(domain, str):
        return _error("The Thessley AD service returned a directory response this page could not read.")
    checked = []
    for item in users:
        if not isinstance(item, dict):
            continue
        sam, name, upn = item.get("sam"), item.get("name"), item.get("upn", "")
        sid = item.get("sid")
        if (not isinstance(sam, str) or not sam or len(sam) > 64 or not isinstance(name, str)
                or not isinstance(sid, str) or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid)):
            continue
        if not isinstance(upn, str):
            upn = ""
        checked.append({"sam": sam, "sid": sid, "principal_id": hashlib.sha256(sid.encode("ascii", "strict")).hexdigest(),
                        "name": name[:256], "upn": upn[:256],
                        "enabled": item.get("enabled") is True,
                        "authorized": item.get("authorized") is True})
    try:
        keys = ad_agent.phone_keys()
        keys_available = True
    except (ad_agent.AgentError, OSError, ValueError):
        keys, keys_available = [], False
    by_principal: dict[str, list[dict]] = {}
    for key in keys:
        by_principal.setdefault(key["principal_id"], []).append(key)
    for user in checked:
        user["keys"] = by_principal.get(user["principal_id"], [])
    return {"ok": True, "message": "", "domain": domain[:256],
            "truncated": result.get("truncated") is True, "users": checked,
            "keys_available": keys_available}


def directory_snapshot(refresh: bool = False) -> dict:
    """Return copied cached data; do not contact AD during ordinary page loads."""
    global _CACHE, _CACHE_AT
    with _CACHE_LOCK:
        if not refresh and _CACHE is not None and time.monotonic() - _CACHE_AT < CACHE_SECONDS:
            return {**_CACHE, "users": [dict(user) for user in _CACHE["users"]]}
    value = _query()
    with _CACHE_LOCK:
        _CACHE = value
        _CACHE_AT = time.monotonic()
        return {**value, "users": [dict(user) for user in value["users"]]}
