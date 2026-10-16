"""Facts about this computer that go into QR codes."""

import hashlib
import socket


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
