"""Small helpers for the SYSTEM-owned weekly update task."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone

from . import store

TASK_NAME = "ThessleyPamWinUpdate"
SCHEDULE_DESCRIPTION = "Every Sunday at 03:00 local time"


def set_enabled(enabled: bool) -> None:
    """Enable or disable future scheduled runs; never stop an update already running."""
    switch = "/ENABLE" if enabled else "/DISABLE"
    try:
        result = subprocess.run(
            ["schtasks.exe", "/Change", "/TN", TASK_NAME, switch],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not update the Windows scheduled task. Rerun the Thessley installer and try again.") from exc
    if result.returncode != 0:
        raise RuntimeError("The automatic-update task is missing or could not be changed. Rerun the Thessley installer.")


def last_run() -> dict:
    """Return only the small status record written by the updater; never expose package contents."""
    path = os.path.join(store.BASE, "update-state.json")
    try:
        with open(path, encoding="utf-8-sig") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(record, dict):
        return {}
    return {
        "last_check_utc": str(record.get("last_check_utc", ""))[:32],
        "last_success_utc": str(record.get("last_success_utc", ""))[:32],
        "last_error": str(record.get("last_error", ""))[:240],
    }


def display_time(value: str) -> str:
    if not value:
        return "not yet"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    except (ValueError, OverflowError):
        return "unknown"
