"""Who is on the other end of a local connection?

The approval service listens on 127.0.0.1, where any program can connect. For requests that must come from one particular
person (adding an approver for your own account) it asks Windows instead of believing the request: find the process that
owns the client's end of the connection, and read the account in that process's token. A program cannot make itself look
like another user this way (an administrator or SYSTEM process could, but they can change the data anyway).
"""

import ctypes
import socket
from ctypes import wintypes

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_ELEVATION = 20
WIN_LOCAL_SYSTEM_SID = 22  # WELL_KNOWN_SID_TYPE.WinLocalSystemSid
LOOPBACK = 0x0100007F  # 127.0.0.1 as Windows stores it (little endian)


class _TcpRow(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("local_addr", wintypes.DWORD), ("local_port", wintypes.DWORD),
                ("remote_addr", wintypes.DWORD), ("remote_port", wintypes.DWORD), ("pid", wintypes.DWORD)]


def _port(value: int) -> int:
    return socket.ntohs(value & 0xFFFF)


def owner_pid(client_port: int, server_port: int) -> int | None:
    """The process that holds the client end (127.0.0.1:client_port -> 127.0.0.1:server_port)."""
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    for _ in range(3):  # the table can grow between the two calls
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = wintypes.DWORD(len(buf))
        if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            break
    else:
        return None
    count = ctypes.c_uint32.from_buffer(buf).value
    rows = (_TcpRow * count).from_buffer(buf, 4)
    for row in rows:
        if (row.local_addr == LOOPBACK and row.remote_addr == LOOPBACK
                and _port(row.local_port) == client_port and _port(row.remote_port) == server_port):
            return int(row.pid)
    return None


def process_user(pid: int) -> str | None:
    """The account name (without domain) in the token of process `pid`, or None."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.LookupAccountSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
                                           wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        return None
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            return None
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER, buf, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.c_void_p.from_buffer(buf).value  # TOKEN_USER starts with the SID pointer
        name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
        name_len, domain_len, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
        if not advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(name_len), domain, ctypes.byref(domain_len), ctypes.byref(use)):
            return None
        return name.value
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def process_identity(pid: int) -> dict | None:
    """Return the token SID and its resolved account authority for a process."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.LookupAccountSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        return None
    token = wintypes.HANDLE()
    sid_text = wintypes.LPWSTR()
    try:
        if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            return None
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER, buf, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.c_void_p.from_buffer(buf).value
        if not sid or not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            return None

        name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
        name_len, domain_len, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
        if not advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(name_len), domain,
                                         ctypes.byref(domain_len), ctypes.byref(use)):
            return None
        return {"sid": sid_text.value, "username": name.value, "authority": domain.value,
                "sid_type": int(use.value)}
    finally:
        if sid_text:
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            kernel32.LocalFree(sid_text)
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def client_user(client_address: tuple, server_port: int) -> str | None:
    """The account behind a connection that arrived from `client_address` (127.0.0.1, port) at `server_port`."""
    host, port = client_address[0], client_address[1]
    if host != "127.0.0.1":
        return None
    pid = owner_pid(port, server_port)
    return process_user(pid) if pid else None


def client_identity(client_address: tuple, server_port: int) -> dict | None:
    """Resolve the SID and account authority of a loopback client process."""
    host, port = client_address[0], client_address[1]
    if host != "127.0.0.1":
        return None
    pid = owner_pid(port, server_port)
    return process_identity(pid) if pid else None


def process_is_system(pid: int) -> bool | None:
    """Whether process `pid` has the well-known LocalSystem SID, independent of UI language."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.IsWellKnownSid.argtypes = [ctypes.c_void_p, ctypes.c_int]
    advapi32.IsWellKnownSid.restype = wintypes.BOOL
    process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        return None
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            return None
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TOKEN_USER, buf, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.c_void_p.from_buffer(buf).value
        return bool(advapi32.IsWellKnownSid(sid, WIN_LOCAL_SYSTEM_SID))
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def client_is_system(client_address: tuple, server_port: int) -> bool:
    """Check the peer process token against LocalSystem's SID rather than its localized account name."""
    host, port = client_address[0], client_address[1]
    if host != "127.0.0.1":
        return False
    pid = owner_pid(port, server_port)
    return bool(pid and process_is_system(pid))


def process_is_elevated(pid: int) -> bool:
    """Whether the process token has an enabled elevated administrator token."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        return False
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            return False
        elevation = wintypes.DWORD()
        needed = wintypes.DWORD()
        if not advapi32.GetTokenInformation(token, TOKEN_ELEVATION, ctypes.byref(elevation),
                                             ctypes.sizeof(elevation), ctypes.byref(needed)):
            return False
        return bool(elevation.value)
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def client_is_elevated(client_address: tuple, server_port: int) -> bool:
    """Check that the local RPC caller is running with an elevated Windows token."""
    host, port = client_address[0], client_address[1]
    if host != "127.0.0.1":
        return False
    pid = owner_pid(port, server_port)
    return bool(pid and process_is_elevated(pid))
