"""Isolated command-line entry point for the experimental AD login agent.

This deliberately does not import the existing local Windows QR/PAM CLI or
register/change a Windows credential provider.
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import re
import subprocess
import sys
import threading
import time

from . import ad_agent, qr


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _sid_for_account(account: str) -> str:
    if not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\\[A-Za-z0-9_.-]{1,64}", account):
        raise ValueError("Use a qualified account such as THESSLEYLAB\\martin.")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$account=[System.Security.Principal.NTAccount]::new('{account}'); "
        "$account.Translate([System.Security.Principal.SecurityIdentifier]).Value"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=15, check=False,
    )
    sid = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid, re.IGNORECASE):
        raise ValueError(result.stderr.strip()[:240] or "Windows could not resolve that account SID.")
    return sid


def _current_user_sid() -> str:
    script = (
        "$ErrorActionPreference='Stop'; "
        "$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent(); "
        "$local=Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | "
        "Where-Object { $_.SID -eq $identity.User.Value }; "
        "if ($local) { 'LOCAL_ACCOUNT' } else { $identity.User.Value }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=15, check=False,
    )
    sid = result.stdout.strip()
    if sid == "LOCAL_ACCOUNT":
        raise ValueError(
            "This is a local Windows account. Sign in to the domain account first, "
            "or use enroll-phone --user DOMAIN\\name from an administrator shell."
        )
    if result.returncode or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid, re.IGNORECASE):
        raise ValueError(result.stderr.strip()[:240] or "Windows could not resolve the signed-in account SID.")
    return sid


def _require_domain_joined() -> None:
    script = (
        "$ErrorActionPreference='Stop'; "
        "[bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, errors="replace", timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Windows could not check domain membership.") from exc
    if result.returncode or result.stdout.strip().lower() != "true":
        raise ValueError(
            "AD phone sign-in requires a domain-joined Windows Pro or higher PC. "
            "Use the local Thessley QR tile on Windows Home."
        )


def _show_qr(link: str) -> None:
    rows = qr.lines(link, border=2)
    if rows:
        print("\n".join(rows))
    else:
        print("QR rendering is unavailable; open this complete link on the phone:")
        print(link)


def _phone_enroll(account: str | None = None, sid: str | None = None) -> int:
    try:
        _require_domain_joined()
        sid = sid or _sid_for_account(account)
        started = ad_agent.start_phone_enrollment(sid)
    except (ad_agent.AgentError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Could not start AD phone enrollment: {exc}", file=sys.stderr)
        return 1
    print(f"Scan with Thessley Passkey to enroll for {started['authority']}\\{started['username']}:")
    _show_qr(started["link"])
    print("\nWaiting for the phone. Compare the pairing codes before confirming.", flush=True)
    deadline = time.monotonic() + 115
    while time.monotonic() < deadline:
        try:
            state = ad_agent.phone_enrollment_status(started["request_id"])
        except (ad_agent.AgentError, OSError, ValueError) as exc:
            print(f"Could not check phone enrollment: {exc}", file=sys.stderr)
            return 1
        if state["status"] == "ready":
            code = state["pairing_code"]
            print(f"Pairing code: {code}")
            try:
                matched = input("Does the phone show the same code? Confirm only if it matches [y/N]: ")
            except (EOFError, KeyboardInterrupt):
                matched = ""
            if matched.strip().lower() not in ("y", "yes"):
                try:
                    ad_agent.cancel_phone_enrollment(started["request_id"])
                except (ad_agent.AgentError, OSError, ValueError):
                    pass
                print("Enrollment cancelled; no phone key was activated.")
                return 1
            try:
                ad_agent.confirm_phone_enrollment(started["request_id"], code)
            except (ad_agent.AgentError, OSError, ValueError) as exc:
                print(f"Could not confirm phone enrollment: {exc}", file=sys.stderr)
                return 1
            print("Phone enrolled for this domain account and Windows computer.")
            return 0
        if state["status"] in ("expired", "denied"):
            print("Phone enrollment expired or was cancelled.")
            return 1
        time.sleep(1)
    try:
        ad_agent.cancel_phone_enrollment(started["request_id"])
    except (ad_agent.AgentError, OSError, ValueError):
        pass
    print("Phone enrollment timed out. No phone key was activated.")
    return 1


def _approval_test(account: str, context: str) -> int:
    try:
        _require_domain_joined()
        started = ad_agent.start_login(_sid_for_account(account), context)
    except (ad_agent.AgentError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Could not start AD phone-approval test: {exc}", file=sys.stderr)
        return 1
    print(f"Scan with Thessley Passkey for {account} ({context}):")
    _show_qr(started["link"])
    print("This test checks QR approval only. It does not log in to Windows.", flush=True)
    try:
        approved = ad_agent.poll_login(
            started["request_id"], threading.Event(), say=lambda message: print(message, flush=True), timeout=95,
        )
    except (ad_agent.AgentError, OSError, ValueError) as exc:
        print(f"AD phone-approval test failed: {exc}", file=sys.stderr)
        return 1
    return 0 if approved else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="thessley-ad-test", description="Isolated Thessley AD sign-in prototype")
    commands = parser.add_subparsers(dest="command", required=True)
    pair = commands.add_parser("pair-machine", help="pair this Windows PC to the standalone AD service")
    pair.add_argument("--server", required=True, help="pinned HTTPS service origin")
    pair.add_argument("--tls-sha256", required=True, help="64-character TLS certificate SHA-256")
    commands.add_parser("status", help="show machine pairing state")
    commands.add_parser("check", help="check the pinned machine-authenticated service connection")
    enroll = commands.add_parser("enroll-phone", help="admin-assisted phone enrollment for a domain account")
    enroll.add_argument("--user", required=True, help="qualified domain account, e.g. THESSLEYLAB\\martin")
    commands.add_parser("enroll-current-user", help="enroll a phone for the currently signed-in AD account")
    approval = commands.add_parser("approval-test", help="test phone approval without changing Windows logon")
    approval.add_argument("--user", required=True, help="qualified domain account")
    approval.add_argument("--context", choices=("interactive", "unlock"), default="interactive")
    args = parser.parse_args(argv)

    try:
        if args.command == "pair-machine":
            if not _is_admin():
                print("Run pair-machine from an Administrator PowerShell window.", file=sys.stderr)
                return 1
            _require_domain_joined()
            code = getpass.getpass("One-time AD machine-pairing code: ").strip()
            machine_id = ad_agent.enroll_machine(args.server, args.tls_sha256, code)
            print(f"This Windows PC is paired with Thessley AD ({machine_id}).")
            return 0
        if args.command == "status":
            if not ad_agent.configured():
                print("This Windows PC is not paired with Thessley AD.")
                return 1
            config, _key, host, port, pin = ad_agent._load()
            print(f"Service: https://{host}:{port}\nMachine ID: {config['machine_id']}\nTLS SHA-256: {pin}")
            return 0
        if args.command == "check":
            result = ad_agent.check_connection()
            print(f"Signed service check succeeded for machine {result['machine_id']}.")
            return 0
        if args.command == "enroll-phone":
            return _phone_enroll(args.user)
        if args.command == "enroll-current-user":
            return _phone_enroll(sid=_current_user_sid())
        if args.command == "approval-test":
            return _approval_test(args.user, args.context)
    except (ad_agent.AgentError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
