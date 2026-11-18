from __future__ import annotations

import os
import stat
import sys

from acs.client._audit import audit_event
from acs.client._win_acl import file_acl_violations


class SecretFilePermissionsError(RuntimeError):
    """ACS_HMAC_SECRET_FILE exists but its permissions / ownership leak the secret."""


class SecretFileUnreadableError(RuntimeError):
    """ACS_HMAC_SECRET_FILE is configured but cannot be read, or is empty."""


class SigningMaterialMissing(RuntimeError):
    """No usable secret or label, so nothing may be sent: ACS-Core signs every request (§10)."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause


# §10: the secret MUST be at least 32 bytes from a cryptographically secure random source.
MIN_SECRET_BYTES = 32

# Windows carries no owner/group/other bits: stat() reports 0o666 for every ordinary file, so the
# 0600 rule below cannot be evaluated there. The equivalent control is the file's NTFS DACL.
_IS_WINDOWS = os.name == "nt"
_ALLOW_UNCHECKED_ENV = "ACS_ALLOW_UNCHECKED_KEY_PERMS"
_ACL_FIX = (
    'cmd.exe:  icacls "{path}" /inheritance:r /grant:r "%USERNAME%:R"   '
    'PowerShell:  icacls "{path}" /inheritance:r /grant:r "${{env:USERNAME}}:R"'
)


def _windows_acl_error(path: str, fd: int) -> str | None:
    """The reason this file's DACL is wider than the 0600 rule, or None when it is not."""
    problems = file_acl_violations(fd)
    if not problems:
        return None
    return (
        f"ACS_HMAC_SECRET_FILE {path!r} is not confined to this account: "
        f"{'; '.join(problems)}. Windows has no owner/group/other mode bits, so this DACL "
        f"check is what stands in for 0600. Restrict the file first — {_ACL_FIX.format(path=path)} "
        f"— and set {_ALLOW_UNCHECKED_ENV}=1 only to start without this check."
    )


def _check_secret_file_perms(path: str, fd: int) -> None:
    # Both platforms inspect the open handle, so the file that was checked is the file that
    # gets read: there is no stat()-then-open() window for a rename to step into.
    if _IS_WINDOWS:
        # Refuse by default: an unchecked secret is an unknown quantity, not a permitted one.
        # Starting anyway takes an explicit opt-in and says so on stderr, which is where the
        # Guardian's operator looks.
        if os.environ.get(_ALLOW_UNCHECKED_ENV) != "1":
            reason = _windows_acl_error(path, fd)
            if reason:
                raise SecretFilePermissionsError(reason)
            return
        print(
            f"[acs] WARNING: {_ALLOW_UNCHECKED_ENV}=1 — {path} was not checked against its "
            f"NTFS ACL; verify it yourself with: icacls \"{path}\"",
            file=sys.stderr,
        )
        return
    st = os.fstat(fd)
    problem = _posix_mode_error(path, st.st_mode, st.st_uid, getattr(os, "geteuid", lambda: None)())
    if problem:
        raise SecretFilePermissionsError(problem)


def _posix_mode_error(path: str, mode: int, uid: int, euid: int | None) -> str | None:
    """The reason this mode breaks the 0600 rule, or None when it does not.

    Split from the fstat() call so the rule can be tested without replacing os.fstat, which
    open() itself uses: patching it process-wide breaks every file opened in the test.
    """
    permissions = stat.S_IMODE(mode)
    if permissions & 0o077:
        return (
            f"ACS_HMAC_SECRET_FILE {path!r} mode {oct(permissions)} is too permissive; "
            f"must be 0600 or 0400 (no group/other access). "
            f"Fix: chmod 600 {path}")
    if euid is not None and uid != euid:
        return (
            f"ACS_HMAC_SECRET_FILE {path!r} owned by uid {uid}, "
            f"adapter is running as uid {euid}; refusing")
    return None


def load_hmac_secret() -> bytes:
    """The input keying material from ACS_HMAC_SECRET_FILE (owner-only, no symlink) or ACS_HMAC_SECRET; b"" when neither is set."""
    path = os.environ.get("ACS_HMAC_SECRET_FILE", "").strip()
    if path:
        try:
            # A symlink is refused before it is opened: its target can change behind the
            # visible path, and the check would then describe whichever file it landed on.
            if os.path.islink(path):
                raise SecretFilePermissionsError(
                    f"ACS_HMAC_SECRET_FILE {path!r} is a symlink; refusing to follow")
            with open(path, "rb") as f:
                _check_secret_file_perms(path, f.fileno())
                secret = f.read().rstrip(b"\r\n\t ")
            if not secret:
                raise OSError(f"{path} is empty")
            return secret
        except SecretFilePermissionsError:
            raise
        except OSError as e:
            # Configured-but-unreadable is an incident, not a missing secret.
            audit_event("hmac_secret_file_unreadable", path=path, error=str(e))
            raise SecretFileUnreadableError(
                f"ACS_HMAC_SECRET_FILE {path!r} is configured but cannot "
                f"be read ({e})"
            ) from e
    env_val = os.environ.get("ACS_HMAC_SECRET", "")
    return env_val.encode("utf-8") if env_val else b""


def load_key_id() -> str:
    """ACS_HMAC_KEY_ID, the deployment's label for the secret (§10); "" when unset."""
    return os.environ.get("ACS_HMAC_KEY_ID", "").strip()


def load_signing_material() -> tuple[bytes, str]:
    """The secret and the label that names it; raises SigningMaterialMissing when either is missing or the secret is under 32 bytes (§10)."""
    secret = load_hmac_secret()
    if not secret:
        raise SigningMaterialMissing("secret_missing", "no ACS_HMAC_SECRET_FILE or ACS_HMAC_SECRET is configured; "
                                                       "ACS-Core signs every request (§10)")
    if len(secret) < MIN_SECRET_BYTES:
        raise SigningMaterialMissing("secret_too_short", f"the secret is {len(secret)} bytes; "
                                                         f"§10 requires at least {MIN_SECRET_BYTES}")
    label = load_key_id()
    if not label:
        raise SigningMaterialMissing("key_id_missing", "ACS_HMAC_KEY_ID is not set; it names the configured secret (§10)")
    return secret, label
