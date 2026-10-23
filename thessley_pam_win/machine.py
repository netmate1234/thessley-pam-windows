"""Facts about this computer that go into QR codes."""

import hashlib
import ipaddress
import re
import socket
import subprocess


def machine_id() -> str:
    """A stable id for this computer, derived from the Windows MachineGuid without revealing it.

    The phone stores computers under this, not the IP address, so a new DHCP lease doesn't break anything.
    Same derivation as thessley-pam-linux (which uses /etc/machine-id), so the app treats both alike.
    """
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                        access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        raw = str(winreg.QueryValueEx(key, "MachineGuid")[0]).strip()
    return hashlib.sha256(f"thessley-pam-v1:{raw}".encode()).hexdigest()[:32]


def hostname() -> str:
    return socket.gethostname()


def lan_ip() -> str:
    """The address this computer uses to reach its default gateway (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]


def interface_networks(kind: str = "local") -> list[str]:
    """Return IPv4 networks on Windows interfaces, optionally filtering VPN adapter names."""
    if kind not in ("local", "vpn"):
        raise ValueError("Network kind must be local or vpn.")
    command = (
        "$ErrorActionPreference='Stop'; "
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | "
        "ForEach-Object { Write-Output ($_.IPAddress + '/' + $_.PrefixLength + '|' + $_.InterfaceAlias) }"
    )
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, errors="replace", timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return []
    vpn_name = re.compile(r"(?:^|[^a-z0-9])(vpn|openvpn|ovpn|wintun|tun|tap|wireguard|wg|tailscale|zerotier|zt)(?:$|[^a-z0-9])", re.I)
    found = set()
    for line in result.stdout.splitlines():
        address, separator, alias = line.strip().partition("|")
        if not separator or (kind == "vpn") != bool(vpn_name.search(alias)):
            continue
        try:
            interface = ipaddress.ip_interface(address)
        except ValueError:
            continue
        if interface.ip.is_loopback or interface.ip.is_link_local or interface.ip.is_multicast:
            continue
        if kind == "local" and not interface.ip.is_private:
            continue
        found.add(str(interface.network))
    return sorted(found)
