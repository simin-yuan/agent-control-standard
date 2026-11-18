"""The secret file check must fail closed on every platform.

Windows has no owner/group/other bits, so the POSIX 0600 rule cannot be evaluated there.
The NTFS DACL carries the same decision and ``_win_acl`` reads it. The policy half of that
module is pure Python and is tested on every platform; the half that talks to advapi32 runs
only on Windows, and each of those tests sets its own DACL through SDDL instead of assuming
what the runner inherits — the runner's default is not ours to promise.

These are ``unittest.TestCase`` rather than bare pytest functions because
``run_conformance.py`` — the suite the ubuntu job actually runs — discovers with
``unittest.TestLoader``, which does not collect ``test_*`` functions. A pytest-style file
here is collected by pytest and by nothing else, so its checks never execute in CI.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

from acs.client import _secrets, _win_acl
from acs.client._secrets import SecretFilePermissionsError

ME = "S-1-5-21-1000-1001-1002-1003"
SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
OWNER_RIGHTS = "S-1-3-4"
EVERYONE = "S-1-1-0"
NTFS_ONLY = "NTFS ACLs exist on Windows only"


def _ace(type_=None, mask=0x120089, sid=EVERYONE, inherited=False):
    return _win_acl.Ace(
        type=_win_acl.ACE_ALLOWED if type_ is None else type_,
        mask=mask, sid=sid, inherited=inherited,
    )


# --- the policy, on every platform ----------------------------------------

class AclPolicy(unittest.TestCase):
    def test_owner_and_the_two_root_equivalents_are_accepted(self):
        aces = [_ace(sid=SYSTEM), _ace(sid=ADMINISTRATORS), _ace(sid=ME)]
        self.assertEqual(_win_acl.acl_violations(aces, owner_sid=ME, user_sid=ME), [])

    def test_owner_rights_is_accepted_because_the_owner_is_the_runner(self):
        aces = [_ace(sid=SYSTEM), _ace(sid=ADMINISTRATORS), _ace(sid=OWNER_RIGHTS)]
        self.assertEqual(_win_acl.acl_violations(aces, owner_sid=ME, user_sid=ME), [])

    def test_everyone_is_a_violation(self):
        problems = _win_acl.acl_violations([_ace(sid=EVERYONE)], owner_sid=ME, user_sid=ME)
        self.assertEqual(len(problems), 1)
        self.assertIn(EVERYONE, problems[0])

    def test_owner_rights_does_not_rescue_a_different_owner(self):
        # OWNER RIGHTS means "whoever owns the file", so it is only safe once the owner is us.
        problems = _win_acl.acl_violations(
            [_ace(sid=OWNER_RIGHTS)], owner_sid="S-1-5-21-9-9-9-9", user_sid=ME
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("owned by", problems[0])

    def test_a_deny_ace_is_skipped_not_treated_as_a_grant(self):
        aces = [_ace(type_=_win_acl.ACE_DENIED, sid=EVERYONE), _ace(sid=ME)]
        self.assertEqual(_win_acl.acl_violations(aces, owner_sid=ME, user_sid=ME), [])

    def test_an_ace_type_this_check_cannot_read_is_a_violation(self):
        problems = _win_acl.acl_violations([_ace(type_=18)], owner_sid=ME, user_sid=ME)
        self.assertEqual(len(problems), 1)
        self.assertIn("cannot read", problems[0])

    def test_inherited_aces_say_where_they_came_from(self):
        problems = _win_acl.acl_violations(
            [_ace(sid=EVERYONE, inherited=True)], owner_sid=ME, user_sid=ME
        )
        self.assertIn("inherited from a parent directory", problems[0])

    def test_an_object_ace_is_a_grant_and_is_judged_by_its_sid(self):
        problems = _win_acl.acl_violations(
            [_ace(type_=_win_acl.ACE_ALLOWED_OBJECT)], owner_sid=ME, user_sid=ME
        )
        self.assertEqual(len(problems), 1)


# --- the Windows branch of the check, forced on any platform --------------

class WindowsBranch(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "hmac.key")
        with open(self.path, "wb") as f:
            f.write(b"a" * 64)

    def tearDown(self):
        self._dir.cleanup()

    def _check(self):
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            _secrets._check_secret_file_perms(self.path, fd)
        finally:
            os.close(fd)

    def test_refuses_when_the_dacl_is_wide(self):
        wide = mock.patch.object(
            _secrets, "file_acl_violations", lambda _fd: [f"grants {EVERYONE} access"]
        )
        with mock.patch.object(_secrets, "_IS_WINDOWS", True), wide, \
                mock.patch.dict(os.environ, {_secrets._ALLOW_UNCHECKED_ENV: "0"}):
            with self.assertRaises(SecretFilePermissionsError) as caught:
                self._check()
        message = str(caught.exception)
        self.assertIn(EVERYONE, message)
        self.assertIn("icacls", message)
        self.assertIn(_secrets._ALLOW_UNCHECKED_ENV, message)

    def test_passes_when_the_dacl_is_narrow(self):
        narrow = mock.patch.object(_secrets, "file_acl_violations", lambda _fd: [])
        with mock.patch.object(_secrets, "_IS_WINDOWS", True), narrow, \
                mock.patch.dict(os.environ, {_secrets._ALLOW_UNCHECKED_ENV: "0"}):
            self._check()

    def test_opt_in_skips_the_check_and_warns(self):
        def _must_not_run(_fd):
            raise AssertionError("the ACL must not be read once the opt-in is set")

        skipped = mock.patch.object(_secrets, "file_acl_violations", _must_not_run)
        with mock.patch.object(_secrets, "_IS_WINDOWS", True), skipped, \
                mock.patch("sys.stderr") as err, \
                mock.patch.dict(os.environ, {_secrets._ALLOW_UNCHECKED_ENV: "1"}):
            self._check()
        self.assertIn("WARNING", "".join(c.args[0] for c in err.write.call_args_list))


# --- the POSIX rule, unchanged --------------------------------------------

class PosixRule(unittest.TestCase):
    def test_refuses_group_or_other_access(self):
        problem = _secrets._posix_mode_error("/tmp/hmac.key", 0o100644, uid=1000, euid=1000)
        self.assertIsNotNone(problem)
        self.assertIn("too permissive", problem)

    def test_owner_only_modes_pass(self):
        for mode in (0o100600, 0o100400):
            with self.subTest(mode=mode):
                self.assertIsNone(
                    _secrets._posix_mode_error("/tmp/hmac.key", mode, uid=1000, euid=1000)
                )

    def test_refuses_a_file_owned_by_another_account(self):
        problem = _secrets._posix_mode_error("/tmp/hmac.key", 0o100600, uid=0, euid=1000)
        self.assertIsNotNone(problem)
        self.assertIn("owned by uid 0", problem)

    def test_owner_check_is_skipped_where_geteuid_does_not_exist(self):
        # os.geteuid is absent on Windows, where the ACL branch runs instead.
        self.assertIsNone(
            _secrets._posix_mode_error("/tmp/hmac.key", 0o100600, uid=0, euid=None)
        )


class SymlinkIsRefused(unittest.TestCase):
    def test_a_symlink_to_the_secret_is_refused(self):
        with mock.patch.object(_secrets.os.path, "islink", lambda _p: True), \
                mock.patch.dict(os.environ, {"ACS_HMAC_SECRET_FILE": "/tmp/hmac.key"}):
            with self.assertRaises(SecretFilePermissionsError) as caught:
                _secrets.load_hmac_secret()
        self.assertIn("symlink", str(caught.exception))


# --- the real DACL, on Windows only ---------------------------------------

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes as _wt

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SDDL_REVISION_1 = 1

    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        _wt.LPCWSTR, _wt.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(_wt.DWORD)
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = _wt.BOOL
    _advapi32.SetFileSecurityW.argtypes = [_wt.LPCWSTR, _wt.DWORD, ctypes.c_void_p]
    _advapi32.SetFileSecurityW.restype = _wt.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _apply_sddl(path, sddl):
        descriptor = ctypes.c_void_p()
        size = _wt.DWORD()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(size)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not _advapi32.SetFileSecurityW(path, _DACL_SECURITY_INFORMATION, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _kernel32.LocalFree(descriptor)

    def _violations(path):
        fd = os.open(path, os.O_RDONLY | os.O_BINARY)
        try:
            return _win_acl.file_acl_violations(fd)
        finally:
            os.close(fd)


@unittest.skipUnless(sys.platform == "win32", NTFS_ONLY)
class RealDacl(unittest.TestCase):
    """Each case writes the DACL it asserts on; none of them trusts an inherited default."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "hmac.key")
        with open(self.path, "wb") as f:
            f.write(b"a" * 64)

    def tearDown(self):
        self._dir.cleanup()

    def test_a_dacl_with_only_the_owner_and_root_equivalents_passes(self):
        _apply_sddl(
            self.path,
            f"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{_win_acl._current_user_sid()})",
        )
        self.assertEqual(_violations(self.path), [])

    def test_a_dacl_that_grants_everyone_read_is_refused(self):
        _apply_sddl(
            self.path,
            f"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{_win_acl._current_user_sid()})"
            f"(A;;FR;;;{EVERYONE})",
        )
        problems = _violations(self.path)
        self.assertEqual(len(problems), 1)
        self.assertIn(EVERYONE, problems[0])

    def test_a_file_with_no_dacl_is_refused(self):
        _apply_sddl(self.path, "D:NO_ACCESS_CONTROL")
        problems = _violations(self.path)
        self.assertEqual(len(problems), 1)
        self.assertIn("no DACL", problems[0])
