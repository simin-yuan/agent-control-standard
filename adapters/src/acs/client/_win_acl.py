"""The NTFS access check that stands in for the POSIX 0600 rule on Windows.

``stat()`` reports ``0o666`` for every ordinary file on Windows, so
``_check_secret_file_perms`` cannot evaluate owner/group/other there. What the platform
does carry is the file's DACL, and the question that has to be answered is not "is this
0600" but "can anyone but root read this". Three identities count as root: SYSTEM holds
``SeBackupPrivilege``; BUILTIN\\Administrators can take ownership and rewrite the DACL;
and the account running the adapter owns the file.

``OWNER RIGHTS`` (``S-1-3-4``) is trusted only because ownership is checked against the
running account first, which is what gives that SID its meaning. Without that ordering it
would be a blank cheque to whoever the owner happens to be.

The DACL is read from an open handle rather than the path, so the file that was checked is
the file that is read: a rename or a reparse point between the check and the ``open``
cannot substitute a different object.

What this does not claim: the file's *contents* may still leave the machine through a cloud
sync directory (OneDrive redirects Desktop and Documents), and who may delete or rename the
file is decided by the parent directory's ACL, not this one. A passing check means the
local NTFS DACL confines reads to the owner, nothing wider.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import NamedTuple

# --- policy: platform independent, so it is testable everywhere ------------

# An allow ACE naming one of these grants no read that could not already be arranged:
# SYSTEM and Administrators can both take the file and read it either way.
TRUSTED_SIDS = frozenset({
    "S-1-5-18",      # NT AUTHORITY\SYSTEM
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-3-4",       # OWNER RIGHTS, inert unless the owner is the running account
})

ACE_ALLOWED = 0
ACE_DENIED = 1
ACE_AUDIT = 2
ACE_ALARM = 3
ACE_ALLOWED_OBJECT = 5
ACE_ALLOWED_CALLBACK = 9


class Ace(NamedTuple):
    """One access-control entry, reduced to what the policy needs."""

    type: int
    mask: int
    sid: str
    inherited: bool


def acl_violations(aces: Sequence[Ace], *, owner_sid: str, user_sid: str) -> list[str]:
    """Every reason this DACL does not confine the file to its owner, as sentences.

    Empty means the DACL is as narrow as Windows can express for a file the running
    account has to read. A deny ACE only removes access and an audit ACE carries none, so
    both are skipped: skipping them can make this check stricter than Windows, never
    looser. An ACE type this function does not understand is a violation rather than a
    pass, because an unread grant is the one failure a permission check must not have.
    """
    if owner_sid != user_sid:
        return [
            f"the file is owned by {owner_sid}, not by {user_sid} (the account running the "
            f"adapter); an owner can always grant itself access"
        ]
    allowed = TRUSTED_SIDS | {user_sid}
    problems: list[str] = []
    for ace in aces:
        if ace.type in (ACE_DENIED, ACE_AUDIT, ACE_ALARM):
            continue
        if ace.type not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT, ACE_ALLOWED_CALLBACK):
            problems.append(f"ACE type {ace.type} grants {ace.sid} access and this check cannot read it")
        elif ace.sid not in allowed:
            where = "inherited from a parent directory" if ace.inherited else "set on the file"
            problems.append(f"grants {ace.sid} access ({where}, mask {ace.mask:#010x})")
    return problems


# --- reading the DACL: Windows only ---------------------------------------

if sys.platform == "win32":  # pragma: no cover - the policy above is what runs on CI
    import ctypes
    import ctypes.wintypes as _wt
    import msvcrt

    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _ACL_SIZE_INFORMATION_CLASS = 2
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _ACE_FLAG_INHERITED = 0x10
    _ACE_OBJECT_FLAG_INHERIT_OBJECT_TYPE = 0x2
    _ACE_OBJECT_FLAG_HAS_OBJECT_TYPE = 0x1

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", _wt.DWORD),
            ("AclBytesInUse", _wt.DWORD),
            ("AclBytesFree", _wt.DWORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", ctypes.c_ushort),
        ]

    # Every Win32 call gets a full prototype: without one, ctypes truncates a HANDLE to a
    # C int and the call fails in a way that looks like a permissions problem.
    _kernel32.GetCurrentProcess.restype = _wt.HANDLE
    _kernel32.CloseHandle.argtypes = [_wt.HANDLE]
    _kernel32.CloseHandle.restype = _wt.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    _advapi32.OpenProcessToken.argtypes = [_wt.HANDLE, _wt.DWORD, ctypes.POINTER(_wt.HANDLE)]
    _advapi32.OpenProcessToken.restype = _wt.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        _wt.HANDLE, ctypes.c_int, ctypes.c_void_p, _wt.DWORD, ctypes.POINTER(_wt.DWORD)
    ]
    _advapi32.GetTokenInformation.restype = _wt.BOOL
    _advapi32.GetSecurityInfo.argtypes = [
        _wt.HANDLE, ctypes.c_int, _wt.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetSecurityInfo.restype = _wt.DWORD
    _advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, _wt.DWORD, ctypes.c_int
    ]
    _advapi32.GetAclInformation.restype = _wt.BOOL
    _advapi32.GetAce.argtypes = [ctypes.c_void_p, _wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.GetAce.restype = _wt.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_wt.LPWSTR)
    ]
    _advapi32.ConvertSidToStringSidW.restype = _wt.BOOL

    def _sid_to_string(sid_ptr: int) -> str:
        out = _wt.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
            return f"<SID unreadable, error {ctypes.get_last_error()}>"
        try:
            return out.value or "<empty SID>"
        finally:
            _kernel32.LocalFree(out)

    def _current_user_sid() -> str:
        token = _wt.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            needed = _wt.DWORD()
            _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
            buf = ctypes.create_string_buffer(needed.value)
            if not _advapi32.GetTokenInformation(
                token, _TOKEN_USER, buf, needed, ctypes.byref(needed)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            return _sid_to_string(sid_ptr)
        finally:
            _kernel32.CloseHandle(token)

    def _sid_offset(ace_type: int, raw: bytes) -> int:
        """Where the SID starts inside one ACE, in bytes from its first byte.

        An object ACE puts the mask, an object-flags word, and up to two GUIDs before the
        SID; every other type carries the mask and then the SID. Reading an object ACE as
        an ordinary one would compare a GUID half against the trusted list.
        """
        if ace_type not in (ACE_ALLOWED_OBJECT, 6):
            return 8
        if len(raw) < 12:
            return len(raw)
        obj_flags = int.from_bytes(raw[8:12], "little")
        offset = 12
        if obj_flags & _ACE_OBJECT_FLAG_HAS_OBJECT_TYPE:
            offset += 16
        if obj_flags & _ACE_OBJECT_FLAG_INHERIT_OBJECT_TYPE:
            offset += 16
        return offset

    def _read_dacl(fd: int) -> tuple[str, list[Ace], str]:
        """The owner SID, the ACEs, and a problem sentence when the DACL cannot be read."""
        handle = msvcrt.get_osfhandle(fd)
        owner = ctypes.c_void_p()
        group = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        sacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        rc = _advapi32.GetSecurityInfo(
            handle, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), ctypes.byref(group),
            ctypes.byref(dacl), ctypes.byref(sacl), ctypes.byref(descriptor),
        )
        if rc != 0:
            return "", [], (
                f"the DACL could not be read (Windows error {rc}); a volume without NTFS "
                f"permissions cannot carry this check"
            )
        try:
            owner_sid = _sid_to_string(owner.value) if owner.value else ""
            if not dacl.value:
                # A NULL DACL grants every account full control. There is no narrower
                # reading of it.
                return owner_sid, [], "the file has no DACL, which grants every account full control"
            info = _ACL_SIZE_INFORMATION()
            if not _advapi32.GetAclInformation(
                dacl, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION_CLASS
            ):
                return owner_sid, [], (
                    f"the DACL could not be enumerated (Windows error {ctypes.get_last_error()})"
                )
            aces: list[Ace] = []
            for index in range(info.AceCount):
                ace_ptr = ctypes.c_void_p()
                if not _advapi32.GetAce(dacl, index, ctypes.byref(ace_ptr)) or not ace_ptr.value:
                    return owner_sid, [], (
                        f"ACE {index} of {info.AceCount} could not be read "
                        f"(Windows error {ctypes.get_last_error()})"
                    )
                header = ctypes.cast(ace_ptr, ctypes.POINTER(_ACE_HEADER)).contents
                raw = ctypes.string_at(ace_ptr, header.AceSize)
                if len(raw) < 8:
                    aces.append(Ace(header.AceType, 0, "<truncated ACE>", False))
                    continue
                offset = _sid_offset(raw[0], raw)
                sid = (
                    _sid_to_string(ace_ptr.value + offset)
                    if offset < len(raw) else "<truncated SID>"
                )
                aces.append(Ace(
                    type=raw[0],
                    mask=int.from_bytes(raw[4:8], "little"),
                    sid=sid,
                    inherited=bool(raw[1] & _ACE_FLAG_INHERITED),
                ))
            return owner_sid, aces, ""
        finally:
            if descriptor.value:
                _kernel32.LocalFree(descriptor)

    def file_acl_violations(fd: int) -> list[str]:
        """Reasons this open file's DACL does not confine reads to its owner; [] when it does."""
        owner_sid, aces, problem = _read_dacl(fd)
        if problem:
            return [problem]
        if not owner_sid:
            return ["the file's owner could not be read"]
        return acl_violations(aces, owner_sid=owner_sid, user_sid=_current_user_sid())

else:  # pragma: no cover - importable everywhere, used only on Windows

    def file_acl_violations(fd: int) -> list[str]:
        raise RuntimeError("the NTFS ACL check only runs on Windows")


__all__ = [
    "ACE_ALLOWED",
    "ACE_ALLOWED_CALLBACK",
    "ACE_ALLOWED_OBJECT",
    "Ace",
    "TRUSTED_SIDS",
    "acl_violations",
    "file_acl_violations",
]
