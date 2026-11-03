"""Facts about this computer that go into QR codes."""

import hashlib
import ipaddress
import os
import re
import socket
import subprocess
import ctypes
import struct
import threading
import time
from ctypes import wintypes

_NETWORK_CACHE: dict[str, tuple[float, list[str]]] = {}
_NETWORK_CACHE_LOCK = threading.Lock()
_NETWORK_REFRESHING: set[str] = set()


class _MibIpAddrRow(ctypes.Structure):
    """IPv4 address row returned by Windows IP Helper's GetIpAddrTable."""

    _fields_ = [("address", wintypes.DWORD), ("index", wintypes.DWORD), ("mask", wintypes.DWORD),
                ("broadcast", wintypes.DWORD), ("reassembly_size", wintypes.DWORD),
                ("unused1", wintypes.WORD), ("unused2", wintypes.WORD)]


def _ipv4_for_interface(index: int) -> str:
    """Read an interface's current IPv4 address without starting PowerShell per approval."""
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    get_table = iphlpapi.GetIpAddrTable
    get_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    get_table.restype = wintypes.DWORD

    size = wintypes.ULONG(0)
    result = get_table(None, ctypes.byref(size), False)
    if result not in (0, 122):  # NO_ERROR or ERROR_INSUFFICIENT_BUFFER
        raise OSError(result, "GetIpAddrTable could not size the address table")
    if not size.value:
        raise OSError("GetIpAddrTable returned an empty address table")

    table = ctypes.create_string_buffer(size.value)
    result = get_table(table, ctypes.byref(size), False)
    if result != 0:
        raise OSError(result, "GetIpAddrTable could not read the address table")

    count = wintypes.DWORD.from_buffer(table).value
    rows = (_MibIpAddrRow * count).from_buffer(table, ctypes.sizeof(wintypes.DWORD))
    for row in rows:
        if row.index != index:
            continue
        address = socket.inet_ntoa(struct.pack("<I", row.address))
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4 and not (parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified
                                        or parsed.is_multicast):
            return str(parsed)
    raise OSError(f"the configured phone network adapter {index} has no usable IPv4 address")


def _powershell_ipv4_for_interface(index: int) -> str:
    """Compatibility fallback for Windows versions where IP Helper lookup fails."""
    command = (
        "$ErrorActionPreference='Stop'; "
        f"Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 -AddressState Preferred | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | "
        "Select-Object -First 1 -ExpandProperty IPAddress"
    )
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, errors="replace", timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"the configured phone network adapter {index} has no usable IPv4 address") from exc
    for address in result.stdout.strip().splitlines():
        try:
            parsed = ipaddress.ip_address(address.strip())
        except ValueError:
            continue
        if parsed.version == 4 and not (parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified
                                        or parsed.is_multicast):
            return str(parsed)
    raise OSError(f"the configured phone network adapter {index} has no usable IPv4 address")


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
    """Return the phone-facing IPv4 address, following the installer-selected adapter when set."""
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    index_path = os.path.join(program_data, "ThessleyPamWin", "phone-interface-index.txt")
    try:
        with open(index_path, encoding="ascii") as f:
            raw_index = f.read().strip()
    except FileNotFoundError:
        raw_index = ""
    except OSError as exc:
        raise OSError("cannot read the configured phone network adapter") from exc

    if raw_index:
        if not raw_index.isdecimal() or not 1 <= int(raw_index) <= 65535:
            raise OSError("the configured phone network adapter index is invalid")
        try:
            return _ipv4_for_interface(int(raw_index))
        except OSError as exc:
            try:
                return _powershell_ipv4_for_interface(int(raw_index))
            except OSError:
                raise OSError(f"the configured phone network adapter {raw_index} has no usable IPv4 address") from exc

    # Automatic mode: use Windows' chosen default route (no packet is sent).
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]


def _fetch_interface_networks(kind: str) -> list[str]:
    """Fetch interface networks and refresh the cache."""
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
        raise
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
    networks = sorted(found)
    with _NETWORK_CACHE_LOCK:
        _NETWORK_CACHE[kind] = (time.monotonic(), networks)
    return list(networks)


def _refresh_networks_background(kind: str) -> None:
    try:
        _fetch_interface_networks(kind)
    except Exception:
        pass  # Keep the last known values available to the Admin page.
    finally:
        with _NETWORK_CACHE_LOCK:
            _NETWORK_REFRESHING.discard(kind)


def interface_networks(kind: str = "local", refresh: bool = False) -> list[str]:
    """Return IPv4 networks on Windows interfaces, optionally filtering VPN adapter names."""
    if kind not in ("local", "vpn"):
        raise ValueError("Network kind must be local or vpn.")
    with _NETWORK_CACHE_LOCK:
        cached = _NETWORK_CACHE.get(kind)
        stale = cached is not None
        expired = cached is None or time.monotonic() - cached[0] >= 60
        if not refresh and stale:
            if expired and kind not in _NETWORK_REFRESHING:
                _NETWORK_REFRESHING.add(kind)
                threading.Thread(target=_refresh_networks_background, args=(kind,), daemon=True).start()
            return list(cached[1])
    try:
        return _fetch_interface_networks(kind)
    except (OSError, subprocess.SubprocessError):
        if cached is not None:
            return list(cached[1])
        return []
