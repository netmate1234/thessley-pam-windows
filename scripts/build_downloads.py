#!/usr/bin/env python3
"""Build the Windows ZIP files served by the authenticated Thessley web GUI."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "downloads"
RELEASE_OUT = ROOT.parent / "dist" / "windows"


def add_files(archive: zipfile.ZipFile, paths: list[Path], prefix: str) -> None:
    for path in paths:
        if path.is_file():
            archive.write(path, Path(prefix) / path.relative_to(ROOT))


def files_under(directory: Path, suffixes: set[str]) -> list[Path]:
    return sorted(path for path in directory.rglob("*") if path.is_file() and path.suffix.lower() in suffixes)


def build(name: str, files: list[Path], prefix: str, readme: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUT / name, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=8) as archive:
        archive.writestr(f"{prefix}/README.txt", readme)
        add_files(archive, files, prefix)


def main() -> None:
    desktop = ROOT / "windows-logon-test" / "build" / "ThessleySignInTest.exe"
    build(
        "windows-desktop-approval.zip", [desktop], "Thessley-Desktop-Approval",
        "Thessley Desktop Approval helper\n\n"
        "Run ThessleySignInTest.exe as the Windows account being enrolled or tested. The Thessley service must\n"
        "already be installed and running on this computer, and an enrolled phone must be available. This app does\n"
        "not change Windows sign-in or login policy.\n",
    )

    provider = ROOT / "windows-logon-provider"
    provider_files = files_under(provider, {".ps1", ".dll", ".exe", ".reg", ".bmp", ".md"})
    # `stage/` contains frozen deployment snapshots from earlier experiments. Do not ship
    # those stale binaries/scripts beside the current rollback-protected installer.
    provider_files = [path for path in provider_files if "stage" not in path.relative_to(provider).parts]
    provider_files += [ROOT / "docs" / "WINDOWS-LOGON-PROTOTYPE.md"]
    build(
        "windows-qr-signin-experimental.zip", provider_files, "Thessley-QR-Windows-SignIn-Experimental",
        "EXPERIMENTAL: Thessley QR Windows sign-in credential provider\n\n"
        "This replaces part of the Windows sign-in experience and is not a routine desktop app. Read\n"
        "docs/WINDOWS-LOGON-PROTOTYPE.md and the included rollback instructions first. It can be staged over SSH,\n"
        "but first-time QR setup must be completed at the Windows sign-in screen. Keep PIN/password sign-in available;\n"
        "do not cancel rollback until a real QR sign-in succeeds. No ADB or USB debugging is needed.\n",
    )

    service_files = [ROOT / "requirements.lock", ROOT / "guided-install.ps1", ROOT / "install" / "install.ps1",
                     ROOT / "install" / "uninstall.ps1", ROOT / "install" / "enable-ssh-qr.ps1",
                     ROOT / "install" / "confirm-setup.ps1", ROOT / "install" / "setup-logon-provider.ps1"]
    service_files += files_under(ROOT / "thessley_pam_win", {".py", ".pem"})
    service_files += [ROOT / "docs" / "SSH.md", ROOT / "docs" / "WEB.md",
                      OUT / "windows-desktop-approval.zip",
                      OUT / "windows-qr-signin-experimental.zip"]
    build(
        "windows-ssh-webgui.zip", service_files, "Thessley-Windows-SSH-WebGUI",
        "Thessley Windows SSH + Web GUI\n\n"
        "This package installs the Thessley QR approval service for Windows OpenSSH and its HTTPS admin web GUI.\n"
        "Read docs/SSH.md and docs/WEB.md before installing. Requires Windows 11, administrator PowerShell, and\n"
        "Python 3.10+ installed for all users under Program Files. The guided installer can optionally configure\n"
        "the HTTPS admin page, where administrators manage per-account SSH QR requirements and first factors. It can also\n"
        "allow phone and web traffic from VPN client subnets (Y/Enter accepts 10.8.0.0/24 and 10.8.1.0/24, N skips, or enter custom CIDRs),\n"
        "or configure cloud mode for changing public client IPs (TCP 22/47810, optionally 47820). Cloud-provider firewall rules are separate.\n"
        "install or update the experimental\n"
        "Windows QR sign-in tile with its own rollback. Both are opt-in; retain an SSH session and PIN/password\n"
        "recovery until tested. Other Windows helper app bundles are included in downloads/.\n",
    )

    RELEASE_OUT.mkdir(parents=True, exist_ok=True)
    package_hash = hashlib.sha256((OUT / "windows-ssh-webgui.zip").read_bytes()).hexdigest()
    bootstrap = (ROOT / "quick-install.ps1").read_text(encoding="utf-8").replace("__PACKAGE_SHA256__", package_hash)
    # Keep the bootstrap BOM-free: `irm URL | iex` otherwise treats U+FEFF as a
    # stray command before the first comment on Windows PowerShell.
    (OUT / "install.ps1").write_text(bootstrap, encoding="utf-8")
    shutil.copy2(OUT / "install.ps1", RELEASE_OUT / "install.ps1")
    for package in sorted(OUT.glob("*.zip")):
        shutil.copy2(package, RELEASE_OUT / package.name)
    (RELEASE_OUT / "README.txt").write_text(
        "Thessley Windows distribution files\n\n"
        "windows-ssh-webgui.zip: Windows OpenSSH QR approval service and HTTPS admin web GUI. Includes installer,\n"
        "setup guides, and the two companion bundles below.\n\n"
        "windows-desktop-approval.zip: standalone approval/enrollment helper. Requires the Thessley Windows service.\n\n"
        "windows-qr-signin-experimental.zip: experimental Windows credential provider. Read its included rollback\n"
        "instructions before use; keep built-in PIN/password sign-in available. It can be staged over SSH, but\n"
        "complete QR setup at the Windows sign-in screen and confirm only after a real sign-in succeeds. No ADB\n"
        "or USB debugging is required.\n\n"
        "The packages are unsigned. Windows may show a security prompt when opening them.\n"
        "Rebuild with: python3 thessley-pam-windows-update/scripts/build_downloads.py\n",
        encoding="utf-8",
    )
    sums = []
    for package in sorted(RELEASE_OUT.glob("*.zip")):
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        sums.append(f"{digest}  {package.name}")
    (RELEASE_OUT / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
