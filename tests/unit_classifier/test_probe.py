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
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s1_probe  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
