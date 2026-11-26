"""The probe's exit status (review finding 5): a step that raised, a command with an unexpected
exit status or a failed cleanup must make the probe exit nonzero, after every step has run.
Observations that are nonzero on purpose (a template `show`, a dpkg miss) stay observations.

No root, no systemd: steps and cleanup are injected.

    python3 -m unittest discover -s tests/unit_classifier -p test_probe.py
"""
import ast
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s1_probe  # noqa: E402
from s1lib import CleanupError, Sandbox  # noqa: E402


def run(steps, cleanup=lambda: None):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = s1_probe.main(steps=steps, cleanup=cleanup, gate=False)
    return rc, buf.getvalue(), err.getvalue()


class ProbeExitStatus(unittest.TestCase):
    def test_all_steps_fine_exits_zero(self):
        def good():
            s1_probe.rec("fine", ["true"])
        self.assertEqual(run([good])[0], 0)

    def test_a_step_exception_fails_the_run_and_later_steps_still_run(self):
        ran = []

        def broken():
            raise RuntimeError("setup failed")

        def later():
            ran.append(1)
        rc, out, err = run([broken, later])
        self.assertEqual(rc, 1)
        self.assertEqual(ran, [1])
        self.assertIn("step broken raised", out)
        self.assertIn("1 unexpected failure", err)

    def test_an_unexpected_command_status_fails_the_run(self):
        def step():
            s1_probe.rec("must succeed", ["false"])
        rc, out, _ = run([step])
        self.assertEqual(rc, 1)
        self.assertIn("must succeed: rc=1", out)

    def test_an_intended_nonzero_observation_stays_an_observation(self):
        def step():
            s1_probe.rec("template show refusal", ["sh", "-c", "exit 1"], ok=s1_probe.OBSERVED_NONZERO)
        self.assertEqual(run([step])[0], 0)

    def test_an_unlisted_status_is_still_a_failure_even_for_an_observation(self):
        def step():
            s1_probe.rec("crash", ["sh", "-c", "exit 2"], ok=s1_probe.OBSERVED_NONZERO)
        self.assertEqual(run([step])[0], 1)

    def test_a_step_exception_hidden_by_a_cleanup_error_is_still_reported(self):
        def step():
            try:
                raise RuntimeError("the observation itself failed")
            except RuntimeError:
                raise OSError("cleanup error that replaced it")     # __context__ is the first exception
        rc, out, _ = run([step])
        self.assertEqual(rc, 1)
        self.assertIn("cleanup error that replaced it", out)
        self.assertIn("the observation itself failed", out)

    def test_a_failing_cleanup_fails_the_run(self):
        def cleanup():
            raise RuntimeError("daemon-reload failed")
        rc, out, _ = run([lambda: None], cleanup)
        self.assertEqual(rc, 1)
        self.assertIn("cleanup after", out)

    def test_failures_do_not_leak_between_runs(self):
        run([lambda: s1_probe.rec("x", ["false"])])
        self.assertEqual(run([lambda: None])[0], 0)


class Stub:
    """Stands for s1lib.TestDb: only what the observation reads."""
    dir = "/stub-db"


def fake_sh(failing):
    """A replacement for s1lib.sh: rc 2 for the argv `failing` selects, rc 0 (with some output) for every other."""
    def f(argv, **kw):
        return subprocess.CompletedProcess(argv, 2 if failing(argv) else 0, "line one\nline two\n", "")
    return f


def run_with(failing, *calls):
    with mock.patch.object(s1_probe, "sh", fake_sh(failing)):
        return run(list(calls))


class EveryObservationIsChecked(unittest.TestCase):
    """Review 4 finding 3: no observed command's status is printed and forgotten."""

    def test_rc_2_from_a_hand_written_database_query_fails_the_probe(self):
        for label, path in s1_probe.HANDWRITTEN_QUERIES:      # each of the three, with the others succeeding
            with self.subTest(label=label):
                rc, out, _ = run_with(lambda a: "--admindir" in a and a[-1] == path,
                                      lambda: s1_probe.handwritten_db_items(Stub()),
                                      lambda: s1_probe.real_db_spellings())
                self.assertEqual(rc, 1)
                self.assertIn("%s (hand-written database): rc=2" % label, out)

    def test_rc_2_from_the_real_database_query_fails_the_probe(self):
        rc, out, _ = run_with(lambda a: a[0] == "dpkg-query" and a[-1] == "/usr/lib/systemd/system/ssh.service",
                              lambda: s1_probe.handwritten_db_items(Stub()),
                              lambda: s1_probe.real_db_spellings())
        self.assertEqual(rc, 1)
        self.assertIn("/usr/lib spelling of the same file: rc=2", out)

    def test_the_lib_spelling_miss_is_an_observation_but_rc_2_is_not(self):
        rc, _, _ = run_with(lambda a: False, lambda: s1_probe.real_db_spellings())
        self.assertEqual(rc, 0)
        rc, out, _ = run_with(lambda a: a[-1] == "/lib/systemd/system/ssh.service", lambda: s1_probe.real_db_spellings())
        self.assertEqual(rc, 1)

    def test_trimming_never_hides_the_producers_status(self):
        rc, out, _ = run_with(lambda a: True, lambda: s1_probe.rec("producer", ["x"], lines=1, grep="line", sort=True))
        self.assertEqual(rc, 1)
        self.assertIn("producer: rc=2", out)

    def test_trimming_is_done_in_python(self):
        rc, out, _ = run_with(lambda a: False, lambda: s1_probe.rec("trim", ["x"], lines=1, grep="two"))
        self.assertEqual(rc, 0)
        self.assertIn("line two", out)
        self.assertNotIn("line one", out)

    def test_rec_refuses_a_shell_string(self):
        with self.assertRaises(TypeError):
            s1_probe.rec("compound", "ls; ls")

    def test_no_observation_in_the_probe_goes_through_a_shell_or_a_pipeline(self):
        with open(s1_probe.__file__) as f:
            src = f.read()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "rec":
                self.assertIsInstance(node.args[1], (ast.List, ast.BinOp, ast.Name, ast.Call), "rec(%s) takes a string" % ast.unparse(node.args[0]))
                if isinstance(node.args[1], ast.BinOp):      # `["x"] + parts` is fine, `"x %s" % y` is not
                    self.assertNotIsInstance(node.args[1].left, ast.Constant)
        self.assertNotIn('"sh", "-c"', src)


class Item3Observations(unittest.TestCase):
    """Issue 51, PR 83 fix round 1: the /run observation never fails the probe on its own, the
    leftover check does fail it, and the asserted generator's name check judges both names."""

    def quiet(self, fn, *a, **kw):
        del s1_probe.FAILURES[:]
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            result = fn(*a, **kw)
        return result, buf.getvalue(), list(s1_probe.FAILURES)

    def test_diag_records_a_missing_program_and_does_not_fail(self):
        def missing(argv, **kw):
            raise FileNotFoundError(2, "No such file or directory", argv[0])
        with mock.patch.object(s1_probe, "sh", missing):
            result, text, failures = self.quiet(s1_probe.diag, "no findmnt", ["findmnt", "-x"])
        self.assertIsNone(result)
        self.assertEqual(failures, [])
        self.assertIn("not run:", text)

    def test_diag_accepts_every_exit_status_including_a_signal_death(self):
        for rc in (0, 1, 2, 127, 255, -9, -15):
            with self.subTest(rc=rc), mock.patch.object(s1_probe, "sh", lambda argv, **kw: subprocess.CompletedProcess(argv, rc, "x\n", "")):
                _, _, failures = self.quiet(s1_probe.diag, "any status", ["whatever"])
                self.assertEqual(failures, [])

    def test_rec_still_fails_on_a_signal_death_that_is_not_an_observation(self):
        with mock.patch.object(s1_probe, "sh", lambda argv, **kw: subprocess.CompletedProcess(argv, -9, "", "")):
            _, _, failures = self.quiet(s1_probe.rec, "must succeed", ["whatever"])
        self.assertEqual(len(failures), 1)

    def test_journal_records_a_missing_journalctl_and_does_not_fail(self):
        def missing(argv, **kw):
            raise FileNotFoundError(2, "No such file or directory", "journalctl")
        with mock.patch.object(s1_probe, "sh", missing):
            result, text, failures = self.quiet(s1_probe.journal, "j", "2026-01-01 00:00:00", "x")
        self.assertIsNone(result)
        self.assertEqual(failures, [])
        self.assertIn("not run:", text)

    def test_journal_filters_by_regex_and_caps_the_lines(self):
        lines = "".join("Failed to execute %d\nother %d\n" % (i, i) for i in range(5))
        with mock.patch.object(s1_probe, "sh", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, lines, "")):
            _, text, failures = self.quiet(s1_probe.journal, "j", "2026-01-01 00:00:00", "Failed to execute", limit=3)
        self.assertEqual(failures, [])
        self.assertEqual(text.count("Failed to execute 0") + text.count("Failed to execute 2"), 2)
        self.assertNotIn("other", text)
        self.assertNotIn("Failed to execute 3", text)

    def make_dirs(self):
        root = tempfile.mkdtemp(prefix="tendcf-s1-probe-test-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        etc, run_, outd = (os.path.join(root, n) for n in ("etc-gen", "run-gen", "generator.late"))
        return etc, run_, outd

    def leftovers(self, existed, etc, run_, outd):
        return self.quiet(s1_probe.item3_leftovers, existed, dirs=(etc, run_), out_glob=os.path.join(os.path.dirname(outd), "generator*"))

    def test_leftovers_pass_when_nothing_remains(self):
        etc, run_, outd = self.make_dirs()
        left, text, failures = self.leftovers({etc: False, run_: False}, etc, run_, outd)
        self.assertEqual((left, failures), ([], []))
        self.assertIn("item 3 leftovers: none", text)

    def test_leftovers_fail_on_a_file_in_each_place(self):
        for which in ("etc", "run", "out"):
            with self.subTest(which=which):
                etc, run_, outd = self.make_dirs()
                d = {"etc": etc, "run": run_, "out": outd}[which]
                os.makedirs(d)
                open(os.path.join(d, "tendcf-s1-genrun"), "w").close()
                existed = {etc: True, run_: True}      # the directories are not the finding here
                left, text, failures = self.leftovers(existed, etc, run_, outd)
                self.assertEqual(len(left), 1)
                self.assertEqual(len(failures), 1)
                self.assertIn("item 3 leftovers: FOUND", text)
                self.assertNotIn("leftovers: none", text)

    def test_leftovers_fail_on_a_created_directory_still_there_but_not_on_a_preexisting_one(self):
        etc, run_, outd = self.make_dirs()
        os.makedirs(etc)
        os.makedirs(run_)
        left, _, failures = self.leftovers({etc: False, run_: True}, etc, run_, outd)
        self.assertEqual([x.split(" ")[0] for x in left], [etc])
        self.assertEqual(len(failures), 1)

    def test_a_file_unrelated_to_the_probe_is_not_a_leftover(self):
        etc, run_, outd = self.make_dirs()
        os.makedirs(etc)
        open(os.path.join(etc, "systemd-gpt-auto-generator"), "w").close()
        left, _, failures = self.leftovers({etc: True, run_: False}, etc, run_, outd)
        self.assertEqual((left, failures), ([], []))

    def test_leftovers_fail_on_dot_prefixed_sandbox_temp_file_and_ignore_other_dotfiles(self):
        for which in ("etc", "run", "out"):
            with self.subTest(which=which):
                etc, run_, outd = self.make_dirs()
                d = {"etc": etc, "run": run_, "out": outd}[which]
                os.makedirs(d)
                stale = os.path.join(d, ".tendcf-s1-restore-1234-1")
                open(stale, "w").close()
                open(os.path.join(d, ".keep"), "w").close()
                existed = {etc: True, run_: True}
                left, text, failures = self.leftovers(existed, etc, run_, outd)
                self.assertEqual(left, [stale])
                self.assertEqual(len(failures), 1)
                self.assertIn("item 3 leftovers: FOUND", text)
        etc, run_, outd = self.make_dirs()
        for d in (etc, run_, outd):
            os.makedirs(d)
            open(os.path.join(d, ".keep"), "w").close()
        left, text, failures = self.leftovers({etc: True, run_: True}, etc, run_, outd)
        self.assertEqual((left, failures), ([], []))
        self.assertIn("item 3 leftovers: none", text)

    def test_the_name_check_judges_both_generated_units(self):
        both = "tendcf-s1-gen-nosrc.service generated -\ntendcf-s1-gen.service       generated -\n"
        self.assertEqual(s1_probe.missing_generated(both), [])
        self.assertEqual(s1_probe.missing_generated("tendcf-s1-gen-nosrc.service generated -\n"), ["tendcf-s1-gen.service"])
        self.assertEqual(s1_probe.missing_generated("tendcf-s1-gen.service generated -\n"), ["tendcf-s1-gen-nosrc.service"])
        self.assertEqual(len(s1_probe.missing_generated("")), 2)

    def _run_gen_in_run(self, *, sh_fn, reload_fn, sandbox_run):
        root = tempfile.mkdtemp(prefix="tendcf-s1-genrun-test-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        run_gen = os.path.join(root, "run-gen")

        def make_sandbox(extra_roots=(), **kw):
            return Sandbox(roots=[run_gen], run=sandbox_run)

        with (
            mock.patch.object(s1_probe, "GEN_RUN", run_gen),
            mock.patch.object(s1_probe, "Sandbox", side_effect=make_sandbox),
            mock.patch.object(s1_probe, "daemon_reload", side_effect=reload_fn),
            mock.patch.object(s1_probe, "sh", side_effect=sh_fn),
        ):
            rc, out, err = run([s1_probe.item3_generator_in_run])
        return rc, out, err, run_gen

    def test_item3_generator_in_run_fails_when_daemon_reload_raises(self):
        def ok_sh(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, "", "")

        def bad_reload():
            raise RuntimeError("systemctl daemon-reload rc=1: manager busy")

        rc, out, _, run_gen = self._run_gen_in_run(sh_fn=ok_sh, reload_fn=bad_reload, sandbox_run=ok_sh)
        self.assertEqual(rc, 1)
        self.assertEqual(len(s1_probe.FAILURES), 1)
        self.assertIn("step item3_generator_in_run raised", out)
        self.assertIn("manager busy", out)
        self.assertFalse(os.path.exists(run_gen), "Sandbox must still tear down the temp generator dir")

    def test_item3_generator_in_run_fails_when_sandbox_cleanup_raises(self):
        def ok_sh(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, "", "")

        def failing_sandbox_run(argv):
            if argv[:2] == ["systemctl", "daemon-reload"]:
                return subprocess.CompletedProcess(argv, 1, "", "reload failed on teardown")
            return subprocess.CompletedProcess(argv, 0, "", "")

        rc, out, _, _ = self._run_gen_in_run(sh_fn=ok_sh, reload_fn=lambda: None, sandbox_run=failing_sandbox_run)
        self.assertEqual(rc, 1)
        self.assertEqual(len(s1_probe.FAILURES), 1)
        self.assertIn(CleanupError.__name__, out)
        self.assertIn("reload failed on teardown", out)

    def test_item3_generator_in_run_stays_observation_on_noexec_empty_or_nonzero_listing(self):
        for list_rc in (0, 1):
            with self.subTest(list_rc=list_rc):
                def sh_fn(argv, **kw):
                    if argv[:2] == ["systemctl", "list-unit-files"]:
                        return subprocess.CompletedProcess(argv, list_rc, "", "")
                    if argv[:1] == ["findmnt"]:
                        return subprocess.CompletedProcess(argv, 0, "/run tmpfs rw,nosuid,nodev,noexec,relatime\n", "")
                    if argv[:1] == ["journalctl"]:
                        return subprocess.CompletedProcess(
                            argv, 0, "systemd: Failed to execute /run/systemd/system-generators/tendcf-s1-genrun: Permission denied\n", ""
                        )
                    return subprocess.CompletedProcess(argv, 0, "Amazon EC2\n", "")

                rc, out, _, run_gen = self._run_gen_in_run(
                    sh_fn=sh_fn,
                    reload_fn=lambda: None,
                    sandbox_run=lambda argv: subprocess.CompletedProcess(argv, 0, "", ""),
                )
                self.assertEqual(rc, 0)
                self.assertEqual(s1_probe.FAILURES, [])
                self.assertIn("did not run: no units were generated", out)
                self.assertFalse(os.path.exists(run_gen))


if __name__ == "__main__":
    unittest.main()
