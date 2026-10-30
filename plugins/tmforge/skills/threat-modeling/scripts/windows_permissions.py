from __future__ import annotations

import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

INHERIT_ONLY_ACE = 0x08


@contextmanager
def windows_directory_handle(path: Path) -> Generator[None, None, None]:
    """Keep a non-reparse directory from being renamed while it is in use."""
    if sys.platform != "win32":
        raise ValueError("Windows directory handles require Windows")
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x81, 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = (wintypes.DWORD * 2)()
        if not kernel.GetFileInformationByHandleEx(
            handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes[0] & 0x400 or not attributes[0] & 0x10:
            raise ValueError(
                f"directory must not be a symlink or reparse point: {path}"
            )
        yield
    finally:
        kernel.CloseHandle(handle)


def windows_permissions(path: Path, private: bool) -> None:
    if sys.platform != "win32":
        raise ValueError("Windows storage permission checks require Windows")
    import ctypes
    import struct
    from ctypes import wintypes

    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    security.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
    ]
    security.GetNamedSecurityInfoW.restype = wintypes.DWORD
    security.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    security.OpenProcessToken.restype = wintypes.BOOL
    security.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        pointer,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.GetTokenInformation.restype = wintypes.BOOL
    security.ConvertSidToStringSidW.argtypes = [
        pointer,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    security.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    security.GetAce.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer

    def sid_text(sid: object) -> str:
        text = wintypes.LPWSTR()
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value or ""
        finally:
            kernel.LocalFree(text)

    token = wintypes.HANDLE()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(
            token, 1, buffer, needed.value, ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        current_user_sid = pointer.from_buffer_copy(buffer)
        current_user = sid_text(current_user_sid)
    finally:
        kernel.CloseHandle(token)

    owner, acl, descriptor = pointer(), pointer(), pointer()
    result = security.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000005,
        ctypes.byref(owner),
        None,
        ctypes.byref(acl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise ctypes.WinError(result)
    try:
        entries: list[tuple[int, int, int, str]] = []
        if acl.value is None:
            raise ValueError(f"Storage path has an unrestricted Windows DACL: {path}")
        count = struct.unpack("<BBHHH", ctypes.string_at(acl, 8))[3]
        for index in range(count):
            address = pointer()
            if not security.GetAce(acl, index, ctypes.byref(address)):
                raise ctypes.WinError(ctypes.get_last_error())
            kind, flags, size, mask = struct.unpack(
                "<BBHI", ctypes.string_at(address, 8)
            )
            if kind == 1 or flags & INHERIT_ONLY_ACE:
                continue
            if kind != 0 or size < 16 or address.value is None:
                raise ValueError(
                    f"Cannot verify this Windows storage ACL entry: {path}"
                )
            entries.append((kind, flags, mask, sid_text(pointer(address.value + 8))))
        validate_windows_acl(sid_text(owner), current_user, entries, private)
    finally:
        kernel.LocalFree(descriptor)


def validate_windows_acl(
    owner: str,
    current_user: str,
    entries: list[tuple[int, int, int, str]],
    private: bool,
) -> None:
    """Allow ancestor child creation, never replacement or writes to private entries."""
    trusted = {current_user, "S-1-5-18", "S-1-5-32-544"}
    if not private:
        trusted.add("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
    if owner not in trusted:
        raise ValueError("Storage paths must have a trusted owner")
    write_access = 0x500D0150
    if private:
        write_access |= 0x2 | 0x4
    for kind, flags, mask, trustee in entries:
        if kind == 1 or flags & INHERIT_ONLY_ACE:
            continue
        if kind != 0:
            raise ValueError("Cannot verify this Windows storage ACL entry")
        if trustee == "S-1-3-4":
            trustee = owner
        if mask & write_access and trustee not in trusted:
            raise ValueError(
                "Storage paths must not grant write access to other Windows principals"
            )
