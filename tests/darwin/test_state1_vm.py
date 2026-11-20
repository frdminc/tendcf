"""Tests for the state 1 macOS VM driver and ssh wrapper (issue 70, slice A).

No VM, no tart, no network: `tart`, `ssh` and `ssh-keyscan` are a fake world injected
through the driver's runner, and the wrapper's real subprocess path is exercised
against a PATH stub `ssh`. Run from the repo root:

    python3 -m unittest discover -s tests/darwin -v
"""

import contextlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VMDIR = REPO / "deploy" / "darwin" / "state1-vm"
sys.path.insert(0, str(VMDIR))

import state1_vm as drv
import vmssh

IMAGE = json.loads((VMDIR / "image.json").read_text())
REF = f"{IMAGE['repository']}@{IMAGE['digest']}"
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVewWW4HVzE8lVQ22rOM+FVbIHyT4rdrpU9su5NmRpL test@example"
KEYSCAN_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIMd8AIkJ2VPKUkoZQk3Qx8+mTcfsLV1N4ywO4z8ezRpW"
GOLDEN = IMAGE["golden_name"]


class Interrupt(drv.Interrupted):
    pass


class FakeProc:
    def __init__(self, world, name):
        self.world, self.name, self.exited = world, name, False

    def poll(self):
        return 0 if self.exited else None

    def wait(self, timeout):
        return 0 if self.exited else None

    def kill(self):
        self.exited = True


class FakeWorld:
    """A tiny tart + guest simulator behind the driver's runner interface."""

    def __init__(self):
        self.vms = {}  # name -> {"Running": bool}
        self.oci = {REF}
        self.calls = []  # (argv, env) in order
        self.procs = {}
        self.boot = 1
        self.ssh_down = 0
        self.password_login = True
        self.key_installed = False
        self.files = {}
        self.stdin_seen = []
        # failure switches
        self.ssh_never_up = False
        self.fail_prep = False
        self.fail_remote = set()  # remote argv[0] (or "sw_vers") that should fail
        self.run_exits_on_reboot = False
        self.interrupt_on = None
        self.hostkey_mismatch = False

    # -- helpers
    def argvs(self, prefix):
        return [a for a, _ in self.calls if a[: len(prefix)] == prefix]

    def tart_calls(self, *sub):
        return [a for a in self.argvs(["tart", *sub])]

    # -- runner interface
    def run(self, argv, *, input_text=None, env=None, timeout=None, log_path=None):
        self.calls.append((list(argv), dict(env) if env else None))
        if argv[0] == "tart":
            return self._tart(argv[1:], log_path)
        if argv[0] == "ssh-keyscan":
            return drv.Result(
                0,
                f"# {argv[-1]}:22 SSH-2.0-OpenSSH\n{argv[-1]} ssh-ed25519 {KEYSCAN_BLOB}\n",
            )
        if argv[0] == "ssh":
            return self._ssh(argv, input_text, env or {})
        raise AssertionError(f"unexpected command {argv}")

    def start(self, argv, *, log_path):
        self.calls.append((list(argv), None))
        name = argv[-1]
        if self.vms[name]["Running"]:
            raise AssertionError("tart run on a running VM")
        self.vms[name]["Running"] = True
        self.procs[name] = FakeProc(self, name)
        return self.procs[name]

    def _tart(self, a, log_path):
        if a[0] == "--version":
            return drv.Result(0, "2.42.0\n")
        if a[0] == "list":
            if a[2] == "local":
                rows = [
                    {
                        "Source": "local",
                        "Name": n,
                        "Running": v["Running"],
                        "State": "running" if v["Running"] else "stopped",
                    }
                    for n, v in sorted(self.vms.items())
                ]
            else:
                rows = [
                    {"Source": "OCI", "Name": n, "Running": False, "State": "stopped"}
                    for n in sorted(self.oci)
                ]
            return drv.Result(0, json.dumps(rows))
        if a[0] == "pull":
            self.oci.add(a[1])
            return drv.Result(0, "pulled")
        if a[0] == "clone":
            src, dst = a[1], a[2]
            if src not in self.vms and src not in self.oci:
                return drv.Result(1, "", "no such image")
            self.vms[dst] = {"Running": False}
            return drv.Result(0)
        if a[0] == "ip":
            if a[-1] not in self.vms or not self.vms[a[-1]]["Running"]:
                return drv.Result(1, "", "no IP address found")
            return drv.Result(0, "192.168.64.10\n")
        if a[0] == "stop":
            vm = self.vms.get(a[1])
            if not vm or not vm["Running"]:
                return drv.Result(1, "", "VM not running")
            vm["Running"] = False
            if a[1] in self.procs:
                self.procs[a[1]].exited = True
            return drv.Result(0)
        if a[0] == "delete":
            vm = self.vms.get(a[1])
            if vm is None:
                return drv.Result(1, "", "no such VM")
            if vm["Running"]:
                return drv.Result(1, "", "VM is running")
            del self.vms[a[1]]
            return drv.Result(0)
        if a[0] == "rename":
            self.vms[a[2]] = self.vms.pop(a[1])
            return drv.Result(0)
        raise AssertionError(f"unexpected tart command {a}")

    def _ssh(self, argv, input_text, env):
        password = "BatchMode=no" in argv
        remote = shlex.split(argv[-1])
        if self.hostkey_mismatch:
            return drv.Result(255, "", "Host key verification failed.")
        if self.ssh_never_up:
            return drv.Result(255, "", "ssh: connect to host: Connection refused")
        if self.ssh_down > 0:
            self.ssh_down -= 1
            return drv.Result(255, "", "ssh: connect to host: Connection refused")
        if password and not self.password_login:
            return drv.Result(
                255, "", "admin@192.168.64.10: Permission denied (publickey)."
            )
        if not password and not self.key_installed:
            return drv.Result(255, "", "Permission denied (publickey).")
        if self.interrupt_on and remote[0] == self.interrupt_on:
            raise Interrupt("SIGINT")
        return self._guest(remote, input_text)

    def _guest(self, r, input_text):
        if r[0] in self.fail_remote:
            return drv.Result(1, "", f"{r[0]} failed")
        if r == ["true"]:
            return drv.Result(0)
        if r[:3] == ["/bin/sh", "-c", drv.INSTALL_KEY_SH]:
            self.key_installed = True
            self.stdin_seen.append(input_text)
            return drv.Result(0)
        if r[:3] == ["/bin/sh", "-c", drv.PUT_FILE_SH]:
            self.files[r[4]] = input_text
            return drv.Result(0)
        if r[:2] == ["rm", "-f"]:
            self.files.pop(r[2], None)
            return drv.Result(0)
        if r[:3] == ["sudo", "-n", "/bin/sh"]:
            script = self.files[r[3]]
            if "prep.sh" in r[3] or "-prep-" in r[3]:
                if self.fail_prep:
                    return drv.Result(1, "", "prep.sh: Gatekeeper is not enabled")
                self.password_login = False
                return drv.Result(
                    0, "prep: ok\nPREP-RESULT disabled=3 absent=22 failed=0\n"
                )
            assert "install-python" in r[3] or "-python-" in r[3], r
            assert script
            return drv.Result(0, f"INSTALL-PYTHON-RESULT version={r[4]} path=/x\n")
        if r == ["sudo", "-n", "sh", "-c", "id -u"]:
            return drv.Result(0, "0\n")
        if r == ["sw_vers", "-productVersion"]:
            return drv.Result(0, "27.2\n")
        if r == ["csrutil", "status"]:
            return drv.Result(0, "System Integrity Protection status: enabled.\n")
        if r == ["spctl", "--status"]:
            return drv.Result(0, "assessments enabled\n")
        if r[:3] == ["sudo", "-n", "/usr/sbin/sshd"]:
            return drv.Result(
                0,
                "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\n",
            )
        if r[:4] == ["sudo", "-n", "mdutil", "-a"]:
            return drv.Result(0, "/:\n\tIndexing disabled.\n")
        if r[0] == "defaults":
            return drv.Result(0, "0\n")
        if r[0].endswith("python3.14"):
            return drv.Result(0, "3.14.10\n")
        if r[0] == "stat":
            return drv.Result(0, "root:wheel 755\n")
        if r[:3] == ["sysctl", "-n", "kern.boottime"]:
            return drv.Result(0, f"{{ sec = {self.boot}, usec = 0 }}\n")
        if r[:3] == ["sudo", "-n", "shutdown"]:
            self.boot += 1
            self.ssh_down = 2
            if self.run_exits_on_reboot:
                name = next(n for n, v in self.vms.items() if v["Running"])
                self.vms[name]["Running"] = False
                self.procs[name].exited = True
            return drv.Result(0)
        raise AssertionError(f"unexpected guest command {r}")


class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += s

    def now(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tendcf-vmtest-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.world = FakeWorld()
        self.clock = Clock()
        self.errs = []
        self.ctx = drv.Ctx(
            state_dir=self.tmp / "state",
            runner=self.world,
            sleep=self.clock.sleep,
            monotonic=self.clock.now,
            err=self.errs.append,
            run_id="20261120T000000Z-test",
        )
        self.pub = self.tmp / "id_test.pub"
        self.pub.write_text(PUBKEY + "\n")

    def run_cmd(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = drv.main(list(argv), self.ctx)
        text = out.getvalue()
        return rc, (json.loads(text) if text.strip() else None)

    def steps(self, summary):
        return {s["step"]: s for s in summary["steps"]}

    def make_golden(self):
        self.world.vms[GOLDEN] = {"Running": False}
        self.ctx.state_dir.mkdir(parents=True, exist_ok=True)
        (self.ctx.state_dir / "known_hosts").write_text(
            f"{vmssh.HOST_ALIAS} ssh-ed25519 {KEYSCAN_BLOB}\n"
        )
        self.world.key_installed = True
        self.world.password_login = False

    def golden_args(self, *extra):
        return ["golden", "--pubkey", str(self.pub), *extra]


class VmsshArgv(unittest.TestCase):
    def test_key_mode_argv(self):
        t = vmssh.Target("192.168.64.10", "/kh", identity="/id")
        argv = vmssh.ssh_argv(t, ["echo", "a b", "$(rm -rf /)", "it's"])
        self.assertEqual(argv[0], "ssh")
        for opt in (
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "PasswordAuthentication=no",
            "IdentitiesOnly=yes",
            "HostKeyAlias=state1-vm",
            "UserKnownHostsFile=/kh",
            "GlobalKnownHostsFile=/dev/null",
            "ForwardAgent=no",
        ):
            self.assertIn(opt, argv)
        self.assertEqual(argv[argv.index("-F") + 1], "/dev/null")
        self.assertEqual(argv[argv.index("-i") + 1], "/id")
        self.assertEqual(argv[-3:-1], ["--", "admin@192.168.64.10"])
        # the remote command is one shlex-quoted string, so nothing is re-split or expanded
        self.assertEqual(shlex.split(argv[-1]), ["echo", "a b", "$(rm -rf /)", "it's"])
        self.assertNotIn("SSH_ASKPASS", " ".join(argv))

    def test_password_mode_keeps_the_secret_off_argv(self):
        t = vmssh.Target("192.168.64.10", "/kh", auth="password", accept_new=True)
        argv = vmssh.ssh_argv(t, ["true"])
        self.assertIn("BatchMode=no", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)
        self.assertNotIn("-i", argv)
        env = vmssh.ssh_env(t, {"PATH": "/usr/bin"})
        self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")
        self.assertEqual(env["SSH_ASKPASS"], str(vmssh.ASKPASS))
        self.assertTrue(os.access(vmssh.ASKPASS, os.X_OK))
        self.assertNotIn(
            vmssh.DEFAULT_BOOTSTRAP_PW, [a for a in argv if a != "admin@192.168.64.10"]
        )
        key_env = vmssh.ssh_env(
            vmssh.Target("192.168.64.10", "/kh", identity="/id"), {"PATH": "/usr/bin"}
        )
        self.assertNotIn("SSH_ASKPASS", key_env)
        self.assertNotIn(vmssh.BOOTSTRAP_PW_ENV, key_env)

    def test_target_rejects_option_injection(self):
        for kw in (
            {"ip": "-oProxyCommand=evil"},
            {"ip": "host.example"},
            {"user": "-oFoo"},
            {"identity": "-oFoo"},
        ):
            args = {
                "ip": "192.168.64.10",
                "known_hosts": "/kh",
                "identity": "/id",
                **kw,
            }
            with self.assertRaises(ValueError):
                vmssh.Target(**args)
        with self.assertRaises(ValueError):
            vmssh.Target("192.168.64.10", "/kh")  # key login needs an identity
        with self.assertRaises(ValueError):
            vmssh.remote_command([])


class VmsshStub(unittest.TestCase):
    """The wrapper's real subprocess path, against a stub `ssh` on PATH."""

    def stub(self, rc):
        d = Path(tempfile.mkdtemp(prefix="tendcf-sshstub-"))
        self.addCleanup(shutil.rmtree, d, True)
        log = d / "argv.log"
        exe = d / "ssh"
        exe.write_text(
            f'#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done > {shlex.quote(str(log))}\nenv | grep -c SSH_ASKPASS >> {shlex.quote(str(log))} || true\nexit {rc}\n'
        )
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        return d, log

    def run_main(self, rc, *extra):
        d, log = self.stub(rc)
        old = os.environ["PATH"]
        os.environ["PATH"] = f"{d}:{old}"
        try:
            got = vmssh.main(
                [
                    "--ip",
                    "192.168.64.10",
                    "--known-hosts",
                    "/kh",
                    "--identity",
                    "/id",
                    *extra,
                    "--",
                    "sh",
                    "-c",
                    "exit 7",
                ]
            )
        finally:
            os.environ["PATH"] = old
        return got, log.read_text().splitlines()

    def test_exit_status_propagates(self):
        for rc in (0, 7, 255):
            got, lines = self.run_main(rc)
            self.assertEqual(got, rc)
            self.assertEqual(
                shlex.split(lines[-2])[-3:], ["sh", "-c", "exit 7"]
            )  # last argv is the quoted command
            self.assertEqual(lines[-1], "0")  # no SSH_ASKPASS in key mode

    def test_password_flag_sets_askpass_in_env_only(self):
        d, log = self.stub(0)
        old = os.environ["PATH"]
        os.environ["PATH"] = f"{d}:{old}"
        try:
            vmssh.main(
                [
                    "--ip",
                    "192.168.64.10",
                    "--known-hosts",
                    "/kh",
                    "--password",
                    "--accept-new",
                    "--",
                    "true",
                ]
            )
        finally:
            os.environ["PATH"] = old
        lines = log.read_text().splitlines()
        self.assertNotIn(
            "admin", lines[:-1][:-1]
        )  # only admin@ip, never a bare password
        self.assertEqual(
            int(lines[-1]), 2
        )  # SSH_ASKPASS and SSH_ASKPASS_REQUIRE in the environment


class PullAndResolve(Base):
    def test_pull_pulls_once_and_is_a_noop_when_cached(self):
        self.world.oci.clear()
        rc, s = self.run_cmd("pull")
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.world.tart_calls("pull"), [["tart", "pull", REF]])
        rc, s = self.run_cmd("pull")
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.world.tart_calls("pull")), 1)
        self.assertIn("already cached", s["steps"][0]["evidence"])

    def test_pull_failure_is_reported(self):
        self.world.oci.clear()
        self.world.run_orig = self.world.run

        def failing(argv, **kw):
            r = self.world.run_orig(argv, **kw)
            return drv.Result(1, "boom") if argv[:2] == ["tart", "pull"] else r

        self.world.run = failing
        self.world.oci.clear()
        rc, s = self.run_cmd("pull")
        self.assertEqual(rc, 1)
        self.assertFalse(s["ok"])

    def test_resolve_uses_the_registry_not_tart(self):
        seen = []

        def fetch(url, headers, method):
            seen.append((url, method))
            if method == "GET-JSON":
                return 200, {"token": "t"}
            return 200, {"Docker-Content-Digest": "sha256:" + "a" * 64}

        self.ctx.fetch = fetch
        rc, s = self.run_cmd("resolve")
        self.assertEqual(rc, 0)
        self.assertEqual(s["digest"], "sha256:" + "a" * 64)
        self.assertIn("tag has moved", s["steps"][0]["evidence"])
        self.assertEqual([m for _, m in seen], ["GET-JSON", "HEAD"])
        self.assertEqual(self.world.calls, [])  # no tart


class Golden(Base):
    def test_refuses_without_the_cached_image_and_never_pulls(self):
        self.world.oci.clear()
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 2)
        self.assertIn("run `state1_vm.py pull` first", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("pull"), [])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])

    def test_refuses_at_the_two_vm_cap(self):
        self.world.vms = {"a": {"Running": True}, "b": {"Running": True}}
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 2)
        self.assertIn("allows 2 macOS VMs", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])

    def test_happy_path(self):
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        self.assertTrue(s["ok"])
        self.assertEqual(
            [x["step"] for x in s["steps"] if x["step"].startswith("g")],
            [f"g{i}" for i in range(1, 11)],
        )
        # clone from the pinned digest, then boot headless, then rename into place
        subs = [a[1] for a in (c for c, _ in self.world.calls) if a[0] == "tart"]
        self.assertLess(subs.index("clone"), subs.index("run"))
        self.assertEqual(
            self.world.tart_calls("clone"), [["tart", "clone", REF, f"{GOLDEN}-build"]]
        )
        self.assertEqual(
            self.world.tart_calls("run"),
            [["tart", "run", "--no-graphics", f"{GOLDEN}-build"]],
        )
        self.assertEqual(
            self.world.tart_calls("rename"),
            [["tart", "rename", f"{GOLDEN}-build", GOLDEN]],
        )
        self.assertEqual(sorted(self.world.vms), [GOLDEN])
        self.assertFalse(self.world.vms[GOLDEN]["Running"])
        self.assertEqual(self.world.tart_calls("pull"), [])
        # the public key (only) went to the guest on stdin; scripts were removed afterwards
        self.assertEqual(self.world.stdin_seen, [PUBKEY + "\n"])
        self.assertEqual(self.world.files, {})
        # the host key is pinned under the alias, and the record exists
        kh = (self.ctx.state_dir / "known_hosts").read_text()
        self.assertEqual(kh, f"state1-vm ssh-ed25519 {KEYSCAN_BLOB}\n")
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertEqual(rec["image"], REF)
        self.assertEqual(rec["python"], "3.14.10")
        self.assertFalse((self.ctx.state_dir / "tmp" / self.ctx.run_id).exists())

    def test_password_is_confined_to_the_bootstrap_calls(self):
        self.run_cmd(*self.golden_args())
        pw_calls, key_calls = [], []
        for argv, env in self.world.calls:
            if argv[0] != "ssh":
                continue
            (pw_calls if "BatchMode=no" in argv else key_calls).append((argv, env))
            self.assertNotIn(vmssh.BOOTSTRAP_PW_ENV, " ".join(argv))
        self.assertTrue(pw_calls)
        for argv, env in pw_calls:
            self.assertIn("SSH_ASKPASS", env)
            self.assertNotIn(
                "sudo", shlex.split(argv[-1])
            )  # nothing privileged over the password login
        for _, env in key_calls:
            self.assertNotIn("SSH_ASKPASS", env)
        # first connections trust on first use into a scratch file; the rest are strict
        strict = [a for a, _ in key_calls if "StrictHostKeyChecking=yes" in a]
        self.assertTrue(strict)
        self.assertTrue(
            all(
                "tmp" in next(o for o in a if o.startswith("UserKnownHostsFile="))
                for a, _ in self.world.calls
                if a[0] == "ssh"
            )
        )

    def test_idempotent_when_golden_exists(self):
        self.run_cmd(*self.golden_args())
        before = len(self.world.calls)
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0)
        self.assertEqual(s["steps"][-1]["step"], "exists")
        new = [a for a, _ in self.world.calls[before:]]
        self.assertTrue(
            all(
                a[:2] in (["tart", "--version"], ["tart", "list"])
                or a[:2] == ["tart", "list"]
                for a in new
            ),
            new,
        )
        self.assertEqual(len(self.world.tart_calls("clone")), 1)

    def test_rebuild_replaces_the_existing_golden(self):
        self.run_cmd(*self.golden_args())
        self.world.password_login = True
        self.world.key_installed = False
        rc, s = self.run_cmd(*self.golden_args("--rebuild"))
        self.assertEqual(rc, 0, s)
        self.assertEqual(len(self.world.tart_calls("clone")), 2)
        self.assertEqual(self.world.tart_calls("delete"), [["tart", "delete", GOLDEN]])
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_failure_cleans_up_and_leaves_no_golden(self):
        self.world.fail_prep = True
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["g6"]["status"], "fail")
        self.assertNotIn("g7", st)
        self.assertEqual(self.world.vms, {})  # the build VM was stopped and deleted
        self.assertEqual(st["cleanup"]["status"], "pass")
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())

    def test_keep_on_failure_leaves_the_build_for_inspection(self):
        self.world.fail_prep = True
        rc, _ = self.run_cmd(*self.golden_args("--keep-on-failure"))
        self.assertEqual(rc, 1)
        self.assertIn(f"{GOLDEN}-build", self.world.vms)

    def test_sweeps_a_half_built_vm_from_an_interrupted_run(self):
        self.world.vms[f"{GOLDEN}-build"] = {"Running": True}
        self.world.procs[f"{GOLDEN}-build"] = FakeProc(self.world, f"{GOLDEN}-build")
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        self.assertIn(
            ["tart", "stop", f"{GOLDEN}-build"], self.world.tart_calls("stop")
        )
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_interrupt_is_reported_and_cleaned_up(self):
        self.world.interrupt_on = "sudo"
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 130)
        self.assertEqual(self.world.vms, {})
        self.assertIn("interrupted", self.steps(s))

    def test_bad_public_key_files_are_refused(self):
        bad = self.tmp / "bad.pub"
        bad.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")
        rc, _ = self.run_cmd("golden", "--pubkey", str(bad))
        self.assertEqual(rc, 2)
        bad.write_text(PUBKEY + "\n" + PUBKEY + "\n")
        rc, _ = self.run_cmd("golden", "--pubkey", str(bad))
        self.assertEqual(rc, 2)
        self.assertEqual(self.world.calls, [])


class Check(Base):
    def setUp(self):
        super().setUp()
        self.make_golden()

    def test_happy_path_covers_every_step_and_cleans_up(self):
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 0, s)
        st = self.steps(s)
        self.assertTrue(s["ok"])
        self.assertEqual(s["schema"], drv.SCHEMA)
        for sid in (
            "1",
            "2a",
            "2b",
            "2c",
            "2d",
            "2e",
            "2f",
            "2g",
            "2h",
            "2i",
            "10",
            "10a",
            "11",
        ):
            self.assertEqual(st[sid]["status"], "pass", (sid, st[sid]))
        self.assertEqual(st["3"]["status"], "skip")
        self.assertIn("needs the renderer slice", st["3"]["evidence"])
        for sid in "456789":
            self.assertEqual(st[sid]["status"], "skip")
            self.assertEqual(st[sid]["evidence"], "SKIP: renderer slice")
        self.assertEqual(st["10b"]["status"], "skip")
        self.assertEqual(
            sorted(self.world.vms), [GOLDEN]
        )  # the throwaway clone is gone
        self.assertEqual(self.world.tart_calls("pull"), [])
        clone = s["clone"]
        self.assertEqual(
            self.world.tart_calls("clone"), [["tart", "clone", GOLDEN, clone]]
        )
        self.assertEqual(self.world.tart_calls("delete"), [["tart", "delete", clone]])
        # the pinned host key was used strictly, every time
        for argv, _ in self.world.calls:
            if argv[0] == "ssh":
                self.assertIn("StrictHostKeyChecking=yes", argv)
                self.assertTrue(
                    next(
                        o for o in argv if o.startswith("UserKnownHostsFile=")
                    ).endswith("/state/known_hosts")
                )
        json.dumps(s)

    def test_summary_file_instead_of_stdout(self):
        out = self.tmp / "summary.json"
        rc, s = self.run_cmd("--summary", str(out), "check", "--identity", "/id")
        self.assertEqual(rc, 0)
        self.assertIsNone(s)
        self.assertTrue(json.loads(out.read_text())["ok"])

    def test_reboot_restarts_tart_run_when_it_exits(self):
        self.world.run_exits_on_reboot = True
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 0, s)
        self.assertEqual(len(self.world.tart_calls("run")), 2)

    def test_refuses_at_the_two_vm_cap_without_starting_anything(self):
        self.world.vms["x"] = {"Running": True}
        self.world.vms["y"] = {"Running": True}
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 2)
        self.assertFalse(s["ok"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])
        self.assertEqual(self.world.tart_calls("delete"), [])

    def test_one_running_vm_is_allowed(self):
        self.world.vms["x"] = {"Running": True}
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 0, s)
        self.assertTrue(self.world.vms["x"]["Running"])  # never touched

    def test_step_failure_still_deletes_the_clone_and_exits_nonzero(self):
        self.world.fail_remote = {"csrutil"}
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["2b"]["status"], "fail")
        self.assertEqual(st["2a"]["status"], "pass")
        self.assertEqual(st["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_ssh_never_coming_up_fails_step_1_and_cleans_up(self):
        self.world.ssh_never_up = True
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["1"]["status"], "fail")
        self.assertIn("blocked", st)
        self.assertNotIn("2a", st)
        self.assertEqual(st["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_host_key_mismatch_fails_fast(self):
        self.world.hostkey_mismatch = True
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 1)
        self.assertIn("host key mismatch", self.steps(s)["1"]["evidence"])
        self.assertLess(self.clock.t, 60)  # no five-minute retry loop
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_interrupt_deletes_the_clone(self):
        self.world.interrupt_on = "spctl"
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 130)
        self.assertEqual(self.steps(s)["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_sweeps_a_clone_left_by_an_interrupted_run(self):
        self.world.vms[drv.CHECK_PREFIX + "old"] = {"Running": True}
        self.world.procs[drv.CHECK_PREFIX + "old"] = FakeProc(self.world, "x")
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 0, s)
        self.assertEqual(sorted(self.world.vms), [GOLDEN])
        self.assertIn(drv.CHECK_PREFIX + "old", self.steps(s)["preflight"]["evidence"])

    def test_refuses_without_golden_or_pinned_key(self):
        del self.world.vms[GOLDEN]
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 2)
        self.assertIn("golden", s["steps"][-1]["evidence"])
        self.make_golden()
        (self.ctx.state_dir / "known_hosts").unlink()
        rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 2)
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_a_second_driver_is_refused_while_the_lock_is_held(self):
        with drv.driver_lock(self.ctx):
            rc, s = self.run_cmd("check", "--identity", "/id")
        self.assertEqual(rc, 2)
        self.assertIn("lock", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])


class Helpers(unittest.TestCase):
    def test_perm_ok(self):
        self.assertTrue(drv.perm_ok("root", "755"))
        self.assertTrue(drv.perm_ok("root", "644"))
        self.assertFalse(drv.perm_ok("root", "775"))
        self.assertFalse(drv.perm_ok("root", "757"))
        self.assertFalse(drv.perm_ok("admin", "755"))

    def test_fingerprint_matches_ssh_keygen(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("no ssh-keygen")
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "k"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
            )
            line = (Path(d) / "k.pub").read_text().strip()
            out = subprocess.run(
                ["ssh-keygen", "-lf", str(key) + ".pub"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            self.assertEqual(drv.fingerprint(line), out.split()[1])

    def test_summary_status_and_ok(self):
        s = drv.Summary("x", "r")
        s.add("1", "a", "pass")
        s.add("2", "b", "skip")
        self.assertTrue(s.ok)
        s.add("3", "c", "fail", "x" * 5000)
        self.assertFalse(s.ok)
        self.assertLess(len(s.steps[-1]["evidence"]), 2100)
        with self.assertRaises(AssertionError):
            s.add("4", "d", "weird")

    def test_image_pin_is_well_formed(self):
        self.assertRegex(IMAGE["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(IMAGE["python"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(
            IMAGE["python"]["url"].startswith("https://www.python.org/ftp/python/")
        )
        self.assertTrue(
            re.fullmatch(drv.NAME_RE.pattern, IMAGE["golden_name"] + "-build")
        )


class GuestScripts(unittest.TestCase):
    SCRIPTS = ("prep.sh", "install-python.sh", "bootstrap-askpass.sh")

    def test_syntax(self):
        for name in self.SCRIPTS:
            r = subprocess.run(
                ["/bin/sh", "-n", str(VMDIR / "guest" / name)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 0, (name, r.stderr))

    def test_strict_mode_and_root_guard(self):
        for name in ("prep.sh", "install-python.sh"):
            text = (VMDIR / "guest" / name).read_text()
            self.assertIn("set -eu", text)
            self.assertIn('[ "$(id -u)" -eq 0 ]', text)

    def test_shellcheck_when_available(self):
        if not shutil.which("shellcheck"):
            self.skipTest("no shellcheck")
        r = subprocess.run(
            ["shellcheck", *[str(VMDIR / "guest" / n) for n in self.SCRIPTS]],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_prep_snapshots_before_changing_anything(self):
        text = (VMDIR / "guest" / "prep.sh").read_text()
        self.assertLess(
            text.index("snapshot before.partial"), text.index("mdutil -a -i off")
        )
        self.assertLess(
            text.index("snapshot before.partial"), text.index("launchctl disable")
        )
        self.assertNotIn("csrutil disable", text)
        self.assertNotIn("authenticated-root", text)


if __name__ == "__main__":
    unittest.main()
