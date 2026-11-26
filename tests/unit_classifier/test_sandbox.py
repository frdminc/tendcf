"""The fixture Sandbox's own contract, on a temporary directory: no root, no systemd, any Unix.

Review finding 1: restoring a regular file that a fixture replaced with a symlink must replace
the link, never write through it (a mask to /dev/null was written and chmodded, and the unit
stayed masked). And a restoration, stop or reload that fails must fail the run.

    python3 -m unittest discover -s tests/unit_classifier -p test_sandbox.py
"""
import errno
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from s1lib import CleanupError, Sandbox  # noqa: E402


def read(p):
    with open(p) as f:
        return f.read()


def ok(argv):
    return subprocess.CompletedProcess(argv, 0, "", "")


class Restore(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="tendcf-s1-sbx-")
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", self.d]))
        self.path = os.path.join(self.d, "unit.service")
        with open(self.path, "w") as f:
            f.write("original\n")
        os.chmod(self.path, 0o640)
        os.utime(self.path, ns=(1_000_000_000_000_000_000, 1_100_000_000_000_000_000))

    def sandbox(self, run=None):
        return Sandbox(roots=[self.d], run=run)

    def test_file_replaced_by_a_symlink_to_another_file_is_restored_without_touching_the_target(self):
        decoy = os.path.join(self.d, "decoy")
        with open(decoy, "w") as f:
            f.write("decoy bytes\n")
        os.chmod(decoy, 0o600)
        before = os.stat(decoy)
        with self.sandbox() as sb:
            sb.symlink(self.path, decoy)
            self.assertTrue(os.path.islink(self.path))
        self.assertFalse(os.path.islink(self.path))
        self.assertEqual(read(self.path), "original\n")
        self.assertEqual(stat.S_IMODE(os.lstat(self.path).st_mode), 0o640)
        self.assertEqual(os.lstat(self.path).st_mtime_ns, 1_100_000_000_000_000_000)
        after = os.stat(decoy)
        self.assertEqual(read(decoy), "decoy bytes\n")
        self.assertEqual((after.st_mode, after.st_mtime_ns, after.st_ino), (before.st_mode, before.st_mtime_ns, before.st_ino))

    def test_file_masked_with_dev_null_is_restored_and_dev_null_is_untouched(self):
        before = os.stat("/dev/null")
        with self.sandbox() as sb:
            sb.symlink(self.path, "/dev/null")
        self.assertFalse(os.path.islink(self.path))
        self.assertEqual(read(self.path), "original\n")
        self.assertEqual(stat.S_IMODE(os.lstat(self.path).st_mode), 0o640)
        after = os.stat("/dev/null")
        self.assertTrue(stat.S_ISCHR(after.st_mode))
        self.assertEqual((after.st_mode, after.st_rdev, after.st_uid), (before.st_mode, before.st_rdev, before.st_uid))

    def test_file_rewritten_by_write_is_restored(self):
        with self.sandbox() as sb:
            sb.write(self.path, "changed\n", mode=0o600)
        self.assertEqual(read(self.path), "original\n")
        self.assertEqual(stat.S_IMODE(os.lstat(self.path).st_mode), 0o640)

    def test_symlink_replaced_by_a_file_is_restored_as_the_same_symlink(self):
        link = os.path.join(self.d, "link.service")
        os.symlink("/dev/null", link)
        with self.sandbox() as sb:
            sb.write(link, "x\n")
        self.assertEqual(os.readlink(link), "/dev/null")

    def test_new_paths_and_directories_are_removed(self):
        newdir = os.path.join(self.d, "new.d")
        with self.sandbox() as sb:
            sb.write(os.path.join(newdir, "a.conf"), "x\n")
        self.assertFalse(os.path.lexists(newdir))

    def test_no_restore_sibling_is_left_behind(self):
        with self.sandbox() as sb:
            sb.symlink(self.path, "/dev/null")
        self.assertEqual(sorted(os.listdir(self.d)), ["unit.service"])

    def test_writes_outside_the_roots_are_refused(self):
        with self.sandbox() as sb:
            with self.assertRaises(AssertionError):
                sb.write("/tmp/tendcf-s1-outside", "x")


class Failures(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="tendcf-s1-sbx-")
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", self.d]))

    def test_a_restore_step_that_fails_raises_and_the_other_steps_still_run(self):
        a, b = os.path.join(self.d, "a"), os.path.join(self.d, "b")
        with self.assertRaises(CleanupError) as cm:
            with Sandbox(roots=[self.d], run=None) as sb:
                sb.write(a, "x")
                sb.write(b, "x")
                os.unlink(a)
                os.mkdir(a)             # a new path that is now a directory: unlink fails
        self.assertIn("restore step", str(cm.exception))
        self.assertFalse(os.path.lexists(b), "later steps must still be attempted")

    def test_a_failing_daemon_reload_raises(self):
        def run(argv):
            return subprocess.CompletedProcess(argv, 1 if argv[1:2] == ["daemon-reload"] else 0, "", "boom")
        with self.assertRaises(CleanupError) as cm:
            with Sandbox(roots=[self.d], run=run):
                pass
        self.assertIn("daemon-reload", str(cm.exception))

    def test_a_failing_stop_raises(self):
        def run(argv):
            return subprocess.CompletedProcess(argv, 1 if argv[1:2] == ["stop"] else 0, "", "no such unit")
        sb = Sandbox(roots=[self.d], run=run)
        sb.started.append("x.service")
        with self.assertRaises(CleanupError) as cm:
            sb.__exit__(None, None, None)
        self.assertIn("stop x.service", str(cm.exception))

    def _raising(self, verb):
        def run(argv):
            if argv[1:2] == [verb]:
                raise OSError("cannot spawn systemctl")
            return ok(argv)
        return run

    def _exception_leaves_nothing_unrestored(self, verb):
        path = os.path.join(self.d, "unit.service")
        with open(path, "w") as f:
            f.write("original\n")
        calls = []
        base = self._raising(verb)

        def run(argv):
            calls.append(argv[1])
            return base(argv)
        sb = Sandbox(roots=[self.d], run=run)
        sb.started.append("x.service")
        sb.symlink(path, "/dev/null")           # something to restore
        with self.assertRaises(CleanupError) as cm:
            sb.__exit__(None, None, None)
        self.assertIn(verb + " x.service" if verb != "daemon-reload" else verb, str(cm.exception))
        self.assertFalse(os.path.islink(path), "the undo steps must still run")
        with open(path) as f:
            self.assertEqual(f.read(), "original\n")
        self.assertEqual(calls[-1], "daemon-reload", "the later operations must still run")
        return calls

    def test_a_stop_that_raises_does_not_skip_restoration(self):
        calls = self._exception_leaves_nothing_unrestored("stop")
        self.assertIn("reset-failed", calls)

    def test_a_reset_failed_that_raises_does_not_skip_restoration(self):
        calls = self._exception_leaves_nothing_unrestored("reset-failed")
        self.assertIn("stop", calls)

    def test_a_daemon_reload_that_raises_is_a_cleanup_error(self):
        self._exception_leaves_nothing_unrestored("daemon-reload")

    def test_reset_failed_rc_1_is_not_a_failure(self):
        def run(argv):
            return subprocess.CompletedProcess(argv, 1 if argv[1:2] == ["reset-failed"] else 0, "", "not failed")
        sb = Sandbox(roots=[self.d], run=run)
        sb.started.append("x.service")
        sb.__exit__(None, None, None)

    def test_start_goes_through_the_injected_runner_and_is_stopped_on_exit(self):
        calls = []

        def run(argv):
            calls.append(argv[1:])
            return ok(argv)
        with Sandbox(roots=[self.d], run=run) as sb:
            sb.start("x.service")
        self.assertEqual(calls[0], ["start", "x.service"])
        self.assertIn(["stop", "x.service"], calls)

    def test_a_sandbox_without_a_manager_cannot_start_a_unit(self):
        with Sandbox(roots=[self.d], run=None) as sb:
            with self.assertRaises(RuntimeError):
                sb.start("x.service")

    def test_a_failed_start_raises_and_the_unit_is_still_stopped(self):
        calls = []

        def run(argv):
            calls.append(argv[1])
            return subprocess.CompletedProcess(argv, 1 if argv[1] == "start" else 0, "", "boom")
        sb = Sandbox(roots=[self.d], run=run)
        with self.assertRaises(RuntimeError):
            sb.start("x.service")
        sb.__exit__(None, None, None)
        self.assertIn("stop", calls)

    def test_a_runner_that_returns_none_is_a_cleanup_error_not_silence(self):
        sb = Sandbox(roots=[self.d], run=lambda argv: None)
        with self.assertRaises(CleanupError) as cm:
            sb.__exit__(None, None, None)
        self.assertIn("no result", str(cm.exception))

    def test_a_clean_exit_with_a_working_manager_does_not_raise(self):
        with Sandbox(roots=[self.d], run=ok) as sb:
            sb.write(os.path.join(self.d, "a"), "x")


class CreatedDirectories(unittest.TestCase):
    """A directory the sandbox creates for a path is 0755 whatever the umask (issue 51: systemd
    runs what lies in /etc/systemd/system-generators as root), and is removed again."""

    def test_created_directory_mode_does_not_depend_on_the_umask(self):
        d = tempfile.mkdtemp(prefix="tendcf-s1-sbx-")
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", d]))
        old = os.umask(0)
        try:
            with Sandbox(roots=[d], run=None) as sb:
                sb.write(os.path.join(d, "gen", "sub", "g"), "x", mode=0o755)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "gen")).st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "gen", "sub")).st_mode), 0o755)
        finally:
            os.umask(old)
        self.assertFalse(os.path.exists(os.path.join(d, "gen")))


class WriteFileModeAndCleanup(unittest.TestCase):
    """Issue #85 (B3): Sandbox.write creates files with O_CREAT|O_EXCL|O_NOFOLLOW at 0o600
    before fchmod, so under umask 0 there is never a world-writable window, and cleans up
    without leaking an fd on failure."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="tendcf-s1-sbx-")
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", self.d]))

    def test_write_mode_is_exact_under_zero_umask(self):
        old = os.umask(0)
        try:
            with Sandbox(roots=[self.d], run=None) as sb:
                p644 = sb.write(os.path.join(self.d, "unit.service"), "x\n", mode=0o644)
                p755 = sb.write(os.path.join(self.d, "gen"), "#!/bin/sh\n", mode=0o755)
                self.assertEqual(stat.S_IMODE(os.lstat(p644).st_mode), 0o644)
                self.assertEqual(stat.S_IMODE(os.lstat(p755).st_mode), 0o755)
        finally:
            os.umask(old)

    def test_write_uses_atomic_restricted_open_before_fchmod(self):
        real_open = os.open
        real_fchmod = os.fchmod
        seen_open = []
        mode_before_fchmod = []
        target = os.path.join(self.d, "gen")

        def spy_open(path, flags, mode=0o777, *args, **kwargs):
            seen_open.append((path, flags, mode))
            return real_open(path, flags, mode, *args, **kwargs)

        def spy_fchmod(fd, mode):
            mode_before_fchmod.append(stat.S_IMODE(os.fstat(fd).st_mode))
            return real_fchmod(fd, mode)

        old = os.umask(0)
        try:
            with mock.patch("os.open", side_effect=spy_open), mock.patch("os.fchmod", side_effect=spy_fchmod):
                with Sandbox(roots=[self.d], run=None) as sb:
                    sb.write(target, "#!/bin/sh\n", mode=0o755)
                    self.assertEqual(stat.S_IMODE(os.lstat(target).st_mode), 0o755)
        finally:
            os.umask(old)

        self.assertEqual(seen_open, [(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)])
        self.assertEqual(mode_before_fchmod, [0o600])

    def test_write_cleans_up_and_closes_fd_when_fdopen_raises(self):
        real_open = os.open
        opened_fds = []
        target = os.path.join(self.d, "fail-fdopen")

        def spy_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.append(fd)
            return fd

        with mock.patch("os.open", side_effect=spy_open), mock.patch("os.fdopen", side_effect=OSError("fdopen failed")):
            with Sandbox(roots=[self.d], run=None) as sb:
                with self.assertRaisesRegex(OSError, "fdopen failed"):
                    sb.write(target, "x\n")
                self.assertFalse(os.path.lexists(target))

        self.assertEqual(len(opened_fds), 1)
        with self.assertRaises(OSError) as cm:
            os.fstat(opened_fds[0])
        self.assertEqual(cm.exception.errno, errno.EBADF)

    def test_write_cleans_up_without_fd_leak_and_restores_prior_file_when_fchmod_raises(self):
        real_open = os.open
        opened_fds = []
        target = os.path.join(self.d, "existing.service")
        with open(target, "w") as f:
            f.write("original\n")
        os.chmod(target, 0o640)

        def spy_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.append(fd)
            return fd

        with Sandbox(roots=[self.d], run=None) as sb:
            with mock.patch("os.open", side_effect=spy_open), mock.patch("os.fchmod", side_effect=OSError("fchmod failed")):
                with self.assertRaisesRegex(OSError, "fchmod failed"):
                    sb.write(target, "replacement\n", mode=0o755)
            self.assertFalse(os.path.lexists(target), "partial file must be unlinked on failure")

        # Sandbox.__exit__ still restores the pre-existing file from its snapshot.
        self.assertEqual(read(target), "original\n")
        self.assertEqual(stat.S_IMODE(os.lstat(target).st_mode), 0o640)
        self.assertEqual(len(opened_fds), 1)
        with self.assertRaises(OSError) as cm:
            os.fstat(opened_fds[0])
        self.assertEqual(cm.exception.errno, errno.EBADF)


if __name__ == "__main__":
    unittest.main()
