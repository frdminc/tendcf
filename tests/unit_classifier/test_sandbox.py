"""The fixture Sandbox's own contract, on a temporary directory: no root, no systemd, any Unix.

Review finding 1: restoring a regular file that a fixture replaced with a symlink must replace
the link, never write through it (a mask to /dev/null was written and chmodded, and the unit
stayed masked). And a restoration, stop or reload that fails must fail the run.

    python3 -m unittest discover -s tests/unit_classifier -p test_sandbox.py
"""
import os
import stat
import subprocess
import sys
import tempfile
import unittest

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

    def test_a_clean_exit_with_a_working_manager_does_not_raise(self):
        with Sandbox(roots=[self.d], run=ok) as sb:
            sb.write(os.path.join(self.d, "a"), "x")


if __name__ == "__main__":
    unittest.main()
