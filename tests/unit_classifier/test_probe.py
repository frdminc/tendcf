"""The probe's exit status (review finding 5): a step that raised, a command with an unexpected
exit status or a failed cleanup must make the probe exit nonzero, after every step has run.
Observations that are nonzero on purpose (a template `show`, a dpkg miss) stay observations.

No root, no systemd: steps and cleanup are injected.

    python3 -m unittest discover -s tests/unit_classifier -p test_probe.py
"""
import contextlib
import io
import os
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
