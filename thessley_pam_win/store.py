"""Enrolled approvers (phones, desktop apps), one JSON file per Windows user.

    C:\\ProgramData\\ThessleyPamWin\\             SYSTEM and Administrators only
    C:\\ProgramData\\ThessleyPamWin\\users\\<user>.json

Only public keys live here, but the files decide who may log in, so a normal user must neither read nor change them.
The installer sets those permissions. The gate that sshd starts never reads this folder: it asks the service
(running as SYSTEM), which does.
"""

import json
import os
import re
import secrets
import tempfile
import time

BASE = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ThessleyPamWin")

# Letters, digits and . _ - only. No spaces: the signed message cannot carry them (protocol.canonical).
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def users_dir() -> str:
    return os.path.join(BASE, "users")


def normalize_user(name: str) -> str:
    """The account name as used in file names and in the signed message: no DOMAIN\\ or @domain, lower case.

    Raises ValueError for anything that is not a plain account name (so it can never be a path)."""
    short = str(name or "").strip().split("\\")[-1].split("@")[0].lower()
    if not _NAME.match(short):
        raise ValueError(f"unsupported user name: {name!r}")
    return short


def _path(username: str) -> str:
    return os.path.join(users_dir(), f"{normalize_user(username)}.json")


def ensure_dirs() -> None:
    os.makedirs(users_dir(), exist_ok=True)


def load(username: str) -> dict:
    username = normalize_user(username)
    try:
        with open(_path(username), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 1, "username": username, "devices": []}
    data.setdefault("devices", [])
    return data


def save(username: str, data: dict) -> None:
    ensure_dirs()
    path = _path(username)
    fd, tmp = tempfile.mkstemp(dir=users_dir(), prefix=".tmp.", suffix=".json")
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


def devices(username: str) -> list[dict]:
    """Every enrolled approver, including disabled ones (for listing and managing)."""
    return load(username)["devices"]


def active_devices(username: str) -> list[dict]:
    """The approvers that may approve things: not disabled. A user whose approvers are all disabled has none."""
    return [d for d in devices(username) if not d.get("disabled")]


def set_disabled(username: str, credential_id: str, disabled: bool) -> bool:
    """Switch an approver off (or on) without forgetting its key. False if there is no such approver."""
    data = load(username)
    for d in data["devices"]:
        if d["credential_id"] == credential_id:
            if disabled:
                d["disabled"] = True
            else:
                d.pop("disabled", None)
            save(username, data)
            if disabled:
                _end_passes(username, credential_id)
            return True
    return False


def rename_device(username: str, credential_id: str, label: str) -> bool:
    """Change the name an approver is listed under. False if there is no such approver."""
    data = load(username)
    for d in data["devices"]:
        if d["credential_id"] == credential_id:
            d["label"] = label
            save(username, data)
            return True
    return False


def all_users() -> list[str]:
    """Every account that has an approver list (enrolled now or earlier), sorted."""
    try:
        return sorted(n[:-5] for n in os.listdir(users_dir()) if n.endswith(".json") and not n.startswith("."))
    except OSError:
        return []


def add_device(username: str, public_key: str, label: str, attestation_chain: list[str],
               attestation: dict | None = None,
               key_attestation_status: str = "", key_attestation_reason: str = "") -> dict:
    """Store one approver. `attestation` is what this computer itself checked at enrolment (TPM proof), if anything:
    {"level": "tpm", "maker": ..., "model": ..., "checked_at": ...} or {"level": "unverified", "reason": ...}."""
    data = load(username)
    device = {
        "credential_id": "c_" + secrets.token_hex(8),
        "public_key": public_key,
        "label": label,
        "enrolled_at": int(time.time()),
        "last_used": None,
        "attestation_chain": attestation_chain,
    }
    if attestation:
        device["attestation"] = attestation
    if key_attestation_status:
        device["attestation_status"] = key_attestation_status
        device["attestation_reason"] = key_attestation_reason
    data["devices"].append(device)
    save(username, data)
    return device


def touch(username: str, credential_id: str) -> None:
    data = load(username)
    for d in data["devices"]:
        if d["credential_id"] == credential_id:
            d["last_used"] = int(time.time())
            save(username, data)
            return


def _end_passes(username: str, credential_id: str) -> None:
    """An approver that is removed or switched off takes the passes it granted with it."""
    from . import grants
    try:
        grants.revoke_credential(username, credential_id)
    except OSError:
        pass


def remove_device(username: str, credential_id: str) -> bool:
    data = load(username)
    before = len(data["devices"])
    data["devices"] = [d for d in data["devices"] if d["credential_id"] != credential_id]
    if len(data["devices"]) == before:
        return False
    save(username, data)
    _end_passes(username, credential_id)
    return True
