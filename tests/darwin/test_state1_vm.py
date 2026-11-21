"""Tests for the state 1 macOS VM driver and ssh wrapper (issue 70, slice A).

No VM, no tart, no network: `tart`, `ssh` and `ssh-keyscan` are a fake world injected
through the driver's runner, and the wrapper's real subprocess path is exercised
against a PATH stub `ssh`. The fake world models what bit the first version: the guest's
current ssh host key (changed by prep.sh, checked against the known_hosts file and mode
of every ssh call), python.org's real `root:admin 775` framework, the two-VM cap in
`tart run`, and a server that still offers password login. Run from the repo root:

    python3 -m unittest discover -s tests/darwin -v
"""

import base64
import contextlib
import errno
import fcntl
import io
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
VMDIR = REPO / "deploy" / "darwin" / "state1-vm"
sys.path.insert(0, str(VMDIR))

import state1_vm as drv
import vmssh

IMAGE = json.loads((VMDIR / "image.json").read_text())
REF = f"{IMAGE['repository']}@{IMAGE['digest']}"
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVewWW4HVzE8lVQ22rOM+FVbIHyT4rdrpU9su5NmRpL test@example"
# Three distinct, valid ed25519 host-key blobs: the vanilla image's, the one prep.sh
# generates, and an impostor's.
VANILLA_BLOB = PUBKEY.split()[1]
NEW_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIMd8AIkJ2VPKUkoZQk3Qx8+mTcfsLV1N4ywO4z8ezRpW"
OTHER_BLOB = base64.b64encode(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"z" * 32
).decode()
GOLDEN = IMAGE["golden_name"]
FW_PYTHON_ORIGINAL = "root:admin 775"  # what python.org's postflight really leaves
FW_PYTHON_FIXED = "root:wheel 755"
FW_ROOT = drv.FRAMEWORK_ROOT
# `sshd -T` on macOS 27.2 (26B123, OpenSSH_10.5p1) prints CamelCase option names (observed on the
# first real run, issue 70); stock OpenSSH prints them lowercase. Both must be accepted.
MDUTIL_OFF = "/:\n\tIndexing disabled.\n/System/Volumes/Data:\n\tIndexing disabled.\n"
MDUTIL_TRANSITIONING = (
    "/:\n\tError: unexpected indexing state.  kMDConfigSearchLevelTransitioning\n"
    "/System/Volumes/Data:\n\tError: unexpected indexing state.  kMDConfigSearchLevelTransitioning\n"
)
MDUTIL_ON = "/:\n\tIndexing enabled.\n"
SU_OFF = "Automatic checking for updates is turned off\n"
SU_ON = "Automatic checking for updates is turned on\n"
SECURE_TOKEN_AFTER = (
    "prep: secure token status (after): 2026-11-21 22:41:08.682 sysadminctl[422:2528] "
    "Secure token is ENABLED for user Managed via Tart \n"
)
SSHD_CAMEL = (
    "UsePAM yes\nPermitRootLogin no\nPubkeyAuthentication yes\n"
    "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthOptions none\n"
)
SSHD_LOWER = (
    "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\n"
    "pubkeyauthentication yes\npermitrootlogin no\n"
)


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
        self.hostkeys = {}  # VM name -> the guest's current ed25519 host key blob
        self.oci = {REF}
        self.calls = []  # (argv, env) in order
        self.ssh_calls = []  # (argv, env) of ssh only
        self.script_calls = []  # (kind, argv, script) for guest scripts run as root
        self.procs = {}
        self.last_started = None
        self.boot = 1
        self.ssh_down = 0
        self.password_login = True  # the server accepts password logins (vanilla image)
        self.prepped = False
        self.key_installed = False
        self.installed_blob = None  # the key blob in authorized_keys
        self.stdin_seen = []
        self.console_pw_default = False  # the vanilla 'admin' still logs in
        self.dscl_error = None  # the text of a dscl failure (default: wrong password)
        self.dscl_rc = 14  # its exit status
        self.prep_console_lines = 1
        self.fw_owner = FW_PYTHON_ORIGINAL  # Versions/X.Y (and the root's own stat)
        # Versions/, Versions/Current and the top-level links: python.org leaves these
        # root:admin 775 too, and a fix-up scoped to Versions/X.Y does not reach them.
        self.fw_versions = FW_PYTHON_ORIGINAL
        self.stat_overrides = {}  # path -> "owner:group mode" for the ancestor stat
        self.signal_on_tart = (
            None  # deliver a real SIGTERM when this tart subcommand runs
        )
        self.signals_sent = 0
        self.screensharing_on = False
        self.sshd_output = SSHD_CAMEL  # what `sudo -n sshd -T -C ...` prints
        self.sshd_rc = 0
        self.sshd_raw_newlines = []  # the raw_newlines flag of each sshd -T call
        # `sudo -n mdutil -a -s`: the answers still to give, in order ((rc, stdout)), then
        # mdutil_default for ever; mdutil_calls counts the calls
        self.mdutil_outputs = []
        self.mdutil_default = (0, MDUTIL_OFF)
        self.mdutil_calls = 0
        # `sudo -n softwareupdate --schedule` and the `defaults read` answers per key
        self.su_schedule = (0, SU_OFF)
        self.su_outputs = []  # answers still to give before su_schedule
        self.defaults_values = {}  # key -> (rc, stdout, stderr)
        # what prep.sh logs after the rotation, and noise before the PREP-RESULT line
        self.prep_token_line = SECURE_TOKEN_AFTER
        self.prep_noise = ""
        # behaviour switches
        self.new_hostkey = NEW_BLOB
        self.keyscan_blob = None  # None: the guest's real current key
        self.prep_hostkey_lines = 1
        self.prep_leaves_password = False
        self.ssh_never_up = False
        self.fail_prep = False
        self.fail_remote = set()  # remote argv[0] that should fail
        self.fail_tart = set()  # tart subcommands that fail with rc 1
        self.run_exits_on_reboot = False
        self.die_after_reboot = False
        self.intruders_on_reboot = 0
        self.rebooted = False
        self.reboot_changes_uuid = True
        self.shutdown_hangs = False
        self.interrupt_on = None
        self.interrupt_after_tart = None
        self.signal_on = None  # deliver a real SIGTERM to this process
        self.hostkey_mismatch = False
        self.cur_argv = None
        self.no_tty_calls = []

    # -- helpers
    def argvs(self, prefix):
        return [a for a, _ in self.calls if a[: len(prefix)] == prefix]

    def tart_calls(self, *sub):
        return list(self.argvs(["tart", *sub]))

    def current_key(self):
        return self.hostkeys.get(self.last_started)

    # -- runner interface
    def run(
        self,
        argv,
        *,
        input_text=None,
        env=None,
        timeout=None,
        log_path=None,
        no_tty=False,
        raw_newlines=False,
    ):
        self._raw_newlines = raw_newlines
        self.calls.append((list(argv), dict(env) if env else None))
        if no_tty:
            self.no_tty_calls.append(list(argv))
        if argv[0] == "tart":
            if self.signal_on_tart == argv[1]:
                self.signals_sent += 1
                os.kill(os.getpid(), signal.SIGTERM)
            res = self._tart(argv[1:], log_path)
            if self.interrupt_after_tart == argv[1]:
                raise Interrupt("SIGINT")
            return res
        if argv[0] == "ssh-keygen":  # a real one: the minted key must be a real key
            r = subprocess.run(argv, capture_output=True, text=True, check=False)
            return drv.Result(r.returncode, r.stdout, r.stderr)
        if argv[0] == "ssh-keyscan":
            blob = self.keyscan_blob or self.current_key()
            return drv.Result(
                0,
                f"# {argv[-1]}:22 SSH-2.0-OpenSSH\n{argv[-1]} ssh-ed25519 {blob}\n",
            )
        if argv[0] == "ssh":
            self.ssh_calls.append((list(argv), dict(env) if env else None))
            return self._ssh(argv, input_text, env or {})
        raise AssertionError(f"unexpected command {argv}")

    def start(self, argv, *, log_path, env=None):
        self.calls.append((list(argv), dict(env) if env else None))
        name = argv[-1]
        if self.vms[name]["Running"]:
            raise AssertionError("tart run on a running VM")
        others = [n for n, v in self.vms.items() if v["Running"] and n != name]
        if len(others) >= 2:
            raise AssertionError(
                f"tart run would be the third running VM ({others}): the licence cap"
            )
        self.vms[name]["Running"] = True
        self.last_started = name
        self.procs[name] = FakeProc(self, name)
        if self.die_after_reboot and self.rebooted:
            self.vms[name]["Running"] = False
            self.procs[name].exited = True
        return self.procs[name]

    def _tart(self, a, log_path):
        if a[0] in self.fail_tart:
            return drv.Result(1, "", f"tart {a[0]}: boom")
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
            if src in self.oci:  # a fresh vanilla image: password login, vanilla key
                self.password_login, self.key_installed, self.prepped = (
                    True,
                    False,
                    False,
                )
                self.hostkeys[dst] = VANILLA_BLOB
            else:
                self.hostkeys[dst] = self.hostkeys[src]
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
            self.hostkeys.pop(a[1], None)
            return drv.Result(0)
        if a[0] == "rename":
            self.vms[a[2]] = self.vms.pop(a[1])
            self.hostkeys[a[2]] = self.hostkeys.pop(a[1])
            if self.last_started == a[1]:
                self.last_started = a[2]
            return drv.Result(0)
        raise AssertionError(f"unexpected tart command {a}")

    # -- ssh: host key identity first, then authentication, then the guest
    def _hostkey(self, argv):
        kh = Path(
            next(
                o.split("=", 1)[1] for o in argv if o.startswith("UserKnownHostsFile=")
            )
        )
        mode = next(
            o.split("=", 1)[1] for o in argv if o.startswith("StrictHostKeyChecking=")
        )
        known = set()
        if kh.exists():
            for line in kh.read_text().splitlines():
                p = line.split()
                if p[:2] == [vmssh.HOST_ALIAS, "ssh-ed25519"]:
                    known.add(p[2])
        cur = self.current_key()
        if known:
            if cur not in known:
                return drv.Result(
                    255,
                    "",
                    "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.",
                )
        elif mode == "yes":
            return drv.Result(
                255, "", "No ED25519 host key is known.\nHost key verification failed."
            )
        else:  # accept-new
            with open(kh, "a") as fh:
                fh.write(f"{vmssh.HOST_ALIAS} ssh-ed25519 {cur}\n")
        return None

    def _denied(self, methods):
        return drv.Result(
            255, "", f"admin@192.168.64.10: Permission denied ({methods})."
        )

    def _ssh(self, argv, input_text, env):
        self.cur_argv = argv
        password = "BatchMode=no" in argv
        remote = shlex.split(argv[-1])
        if self.hostkey_mismatch:
            return drv.Result(255, "", "Host key verification failed.")
        if self.ssh_never_up:
            return drv.Result(255, "", "ssh: connect to host: Connection refused")
        if self.ssh_down > 0:
            self.ssh_down -= 1
            return drv.Result(255, "", "ssh: connect to host: Connection refused")
        bad = self._hostkey(argv)
        if bad:
            return bad
        if password:
            if not self.password_login:
                return self._denied("publickey")
            if self.prepped:  # still offers password, and this one is wrong
                return self._denied("publickey,password,keyboard-interactive")
        elif not self.key_installed:
            return self._denied("publickey")
        else:  # key login: the offered key must be the one in authorized_keys
            ident = Path(argv[argv.index("-i") + 1])
            try:
                offered = Path(str(ident) + ".pub").read_text().split()[1]
            except (OSError, IndexError):
                offered = None
            if offered != self.installed_blob:
                return self._denied("publickey")
        if self.interrupt_on and remote[0] == self.interrupt_on:
            raise Interrupt("SIGINT")
        if self.signal_on and remote[0] == self.signal_on:
            os.kill(os.getpid(), signal.SIGTERM)  # the handler raises right here
        return self._guest(remote, input_text)

    def _stop_current(self):
        name = self.last_started
        self.vms[name]["Running"] = False
        self.procs[name].exited = True

    def _guest(self, r, input_text):
        if r[0] in self.fail_remote:
            return drv.Result(1, "", f"{r[0]} failed")
        if r == ["true"]:
            return drv.Result(0)
        if r[:3] == ["/bin/sh", "-c", drv.INSTALL_KEY_SH]:
            self.key_installed = True
            self.installed_blob = input_text.split()[1]
            self.stdin_seen.append(input_text)
            return drv.Result(0)
        if r[:3] == ["/bin/sh", "-c", drv.RUN_SCRIPT_SH]:
            return self._run_script(r[4:], input_text)
        if r[:3] == ["/bin/sh", "-c", drv.TREE_CHECK_SH]:
            bad = "" if self.fw_owner == FW_PYTHON_FIXED else f"{r[4]}\n"
            if r[4] == FW_ROOT and self.fw_versions != FW_PYTHON_FIXED:
                bad += f"{FW_ROOT}/Versions\n"
            return drv.Result(0, bad)
        if r == ["sudo", "-n", "sh", "-c", "id -u"]:
            return drv.Result(0, "0\n")
        if r == ["sw_vers", "-productVersion"]:
            return drv.Result(0, "27.2\n")
        if r == ["csrutil", "status"]:
            return drv.Result(0, "System Integrity Protection status: enabled.\n")
        if r == ["spctl", "--status"]:
            return drv.Result(0, "assessments enabled\n")
        if r[:3] == ["sudo", "-n", "/usr/sbin/sshd"]:
            # the output goes through the real runner's decode (a real printf), so the
            # production newline handling applies, not the fake's
            self.sshd_raw_newlines.append(self._raw_newlines)
            real = drv.RealRunner().run(
                ["/usr/bin/printf", "%s", self.sshd_output],
                raw_newlines=self._raw_newlines,
            )
            return drv.Result(self.sshd_rc, real.stdout, real.stderr)
        if r[:4] == ["sudo", "-n", "mdutil", "-a"]:
            self.mdutil_calls += 1
            rc, out = (
                self.mdutil_outputs.pop(0)
                if self.mdutil_outputs
                else self.mdutil_default
            )
            return drv.Result(rc, out)
        if r == ["sudo", "-n", "softwareupdate", "--schedule"]:
            return drv.Result(
                *(self.su_outputs.pop(0) if self.su_outputs else self.su_schedule)
            )
        if r[:4] == ["sudo", "-n", "launchctl", "print-disabled"]:
            on = self.screensharing_on
            return drv.Result(
                0,
                '{\n\t"com.apple.xpc.foo" => enabled\n'
                + ("" if on else '\t"com.apple.screensharing" => disabled\n')
                + "}\n",
            )
        if r[:3] == ["netstat", "-an", "-p"]:
            return drv.Result(
                0,
                "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n"
                "tcp4       0      0  *.22                   *.*                    LISTEN\n"
                + (
                    "tcp4       0      0  *.5900                 *.*                    LISTEN\n"
                    if self.screensharing_on
                    else ""
                ),
            )
        if r[0] == "dscl" or r[:3] == ["sudo", "-n", "dscl"]:
            # exactly the vanilla-password probe, without sudo: nothing else may be asked
            assert r == ["dscl", ".", "-authonly", "admin", "admin"], r
            if self.dscl_error is not None:
                return drv.Result(self.dscl_rc, "", self.dscl_error)
            if self.console_pw_default:
                return drv.Result(0)
            return drv.Result(
                14,
                "",
                "Authentication for node /Local/Default failed. (-14090, eDSAuthFailed)\n",
            )
        if r[0] == "defaults":
            if r[-1] in self.defaults_values:
                return drv.Result(*self.defaults_values[r[-1]])
            return drv.Result(0, "0\n")
        if r[0].endswith("python3.14"):
            return drv.Result(0, "3.14.10\n")
        if r[:3] == ["stat", "-f", "%N %Su:%Sg %Lp"]:
            return drv.Result(
                0,
                "".join(
                    f"{p} {self.stat_overrides.get(p, FW_PYTHON_FIXED)}\n"
                    for p in r[3:]
                ),
            )
        if r[:3] == ["stat", "-f", "%Su:%Sg %Lp"]:
            return drv.Result(0, self.fw_owner + "\n")
        if r[:3] == ["sysctl", "-n", "kern.bootsessionuuid"]:
            n = self.boot if self.reboot_changes_uuid else 1
            return drv.Result(0, f"3F2A-uuid-{n}\n")
        if r[:4] == ["sudo", "-n", "shutdown", "-h"]:
            if not self.shutdown_hangs:
                self._stop_current()
            return drv.Result(255, "", "Connection closed")
        if r[:4] == ["sudo", "-n", "shutdown", "-r"]:
            self.boot += 1
            self.rebooted = True
            self.ssh_down = 2
            for i in range(self.intruders_on_reboot):
                self.vms[f"intruder{i}"] = {"Running": True}
            if self.run_exits_on_reboot or self.die_after_reboot:
                self._stop_current()
            return drv.Result(255, "", "Connection closed")
        raise AssertionError(f"unexpected guest command {r}")

    def _run_script(self, args, script):
        self.script_calls.append((script, list(self.cur_argv)))
        if "PREP-RESULT" in script:
            if self.fail_prep:
                return drv.Result(1, "", "prep.sh: Gatekeeper is not enabled")
            old = self.current_key()
            self.hostkeys[self.last_started] = (
                self.new_hostkey
            )  # takes effect for later sessions
            self.prepped = True
            self.password_login = self.prep_leaves_password
            key = (
                f"PREP-HOSTKEY ssh-ed25519 {self.new_hostkey}\n"
                * self.prep_hostkey_lines
                # the marker is printed only if the real script says it would print it
                + "PREP-CONSOLE-PW rotated\n"
                * (
                    self.prep_console_lines
                    if 'echo "PREP-CONSOLE-PW rotated"' in script
                    else 0
                )
            )
            assert old != self.new_hostkey
            token = (
                self.prep_token_line if "secure token status (after)" in script else ""
            )
            return drv.Result(
                0,
                f"prep: ok\n{self.prep_noise}{token}{key}"
                "PREP-RESULT disabled=3 absent=22 failed=0\n",
            )
        assert "INSTALL-PYTHON-RESULT" in script, script[:80]
        # The real script's fix-up cannot run here; its presence in the text is what the
        # fake honours. Without it the framework stays python.org's root:admin 775.
        # The whole framework (fwroot) is what the fix-up must cover; a fix-up scoped to
        # Versions/X.Y ("$fw") leaves Versions/ at root:admin 775.
        if (
            f"fwroot={FW_ROOT}\n" in script
            and 'chown -hR root:wheel "$fwroot"' in script
            and 'chmod -R go-w "$fwroot"' in script
        ):
            self.fw_owner = self.fw_versions = FW_PYTHON_FIXED
        elif 'chown -hR root:wheel "$fw"' in script and 'chmod -R go-w "$fw"' in script:
            self.fw_owner = FW_PYTHON_FIXED
        return drv.Result(0, f"INSTALL-PYTHON-RESULT version={args[0]} path=/x\n")


class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += s

    def now(self):
        return self.t


def write_marker(
    ctx, state_dir=None, state="final", key_id=None, host_key=None, **more
):
    """An owner marker as the driver writes it (for a state of the world a test sets up)."""
    path = drv.owner_path(ctx, GOLDEN)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "golden": GOLDEN,
        "state_dir": state_dir or os.path.realpath(ctx.state_dir),
        "tart_home": ctx.tart_home,
        "key_id": key_id or "20261119T000000Z-made",
        "host_key": host_key
        or "ssh-ed25519 " + drv.fingerprint(f"ssh-ed25519 {NEW_BLOB}"),
        "state": state,
    }
    body.update(more)
    path.write_text(json.dumps(body))


def drop_tart_home(ctx):
    path = drv.owner_path(ctx, GOLDEN)
    body = json.loads(path.read_text())
    del body["tart_home"]
    path.write_text(json.dumps(body))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tendcf-vmtest-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.world = FakeWorld()
        self.clock = Clock()
        self.errs = []
        self.ctx = self.make_ctx(self.tmp / "state")
        self.golden_key_id = "20261119T000000Z-made"

    def make_ctx(self, state_dir, run_id="20261120T000000Z-test", tart_home=""):
        return drv.Ctx(
            state_dir=state_dir,
            runner=self.world,
            sleep=self.clock.sleep,
            monotonic=self.clock.now,
            err=self.errs.append,
            run_id=run_id,
            lock_path=self.tmp / "lockdir" / "driver.lock",
            tart_home=tart_home,
        )

    def second_run_ctx(self, run_id="20261121T000000Z-second"):
        # every real run has its own run id, hence its own key id
        return self.make_ctx(self.ctx.state_dir, run_id=run_id)

    def run_cmd(self, *argv, ctx=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = drv.main(list(argv), ctx or self.ctx)
        text = out.getvalue()
        return rc, (json.loads(text) if text.strip() else None)

    def steps(self, summary):
        return {s["step"]: s for s in summary["steps"]}

    def make_golden(self):
        self.world.vms[GOLDEN] = {"Running": False}
        self.world.hostkeys[GOLDEN] = NEW_BLOB
        self.ctx.state_dir.mkdir(parents=True, exist_ok=True)
        (self.ctx.state_dir / "known_hosts").write_text(
            f"{vmssh.HOST_ALIAS} ssh-ed25519 {NEW_BLOB}\n"
        )
        self.world.key_installed = True
        self.world.password_login = False
        self.world.prepped = True
        self.world.fw_owner = self.world.fw_versions = FW_PYTHON_FIXED
        # the golden's own minted key, as `golden` would have left it
        pub, priv = drv.mint_keypair(self.ctx, self.golden_key_id)
        (self.ctx.state_dir / "golden.json").write_text(
            self.record_json(self.golden_key_id, drv.fingerprint(pub))
        )
        self.world.installed_blob = pub.split()[1]
        self.ident = priv  # the golden's private key (a path)

    def record_json(self, key_id, authorized_key):
        """A golden.json as `golden` writes it (the fields the driver reads back), host_key
        agreeing with the pin make_golden writes."""
        host_key = "ssh-ed25519 " + drv.fingerprint(f"ssh-ed25519 {NEW_BLOB}")
        return json.dumps(
            {"key_id": key_id, "authorized_key": authorized_key, "host_key": host_key}
        )

    def key_dirs(self):
        root = self.ctx.state_dir / "keys"
        return sorted(p.name for p in root.iterdir()) if root.is_dir() else []

    def golden_args(self, *extra):
        return ["golden", *extra]

    def check_args(self, *extra):
        return [*extra, "check"]

    def image_file(self, **changes):
        image = json.loads((VMDIR / "image.json").read_text())
        image.update(changes)
        path = self.tmp / "image-test.json"
        path.write_text(json.dumps(image))
        return str(path)


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

    def test_the_operators_agent_is_left_alone_only_when_asked(self):
        plain = vmssh.ssh_argv(
            vmssh.Target("192.168.64.10", "/kh", identity="/id"), ["x"]
        )
        self.assertNotIn("IdentityAgent=none", plain)  # standalone `.pub` + agent mode
        driver = vmssh.ssh_argv(
            vmssh.Target("192.168.64.10", "/kh", identity="/id", no_agent=True), ["x"]
        )
        self.assertIn("IdentityAgent=none", driver)
        self.assertIn("IdentitiesOnly=yes", driver)
        pw = vmssh.ssh_argv(
            vmssh.Target("192.168.64.10", "/kh", auth="password", no_agent=True), ["x"]
        )
        # ssh still opens the agent socket in password mode, so it is told not to
        self.assertIn("IdentityAgent=none", pw)
        pw_plain = vmssh.ssh_argv(
            vmssh.Target("192.168.64.10", "/kh", auth="password"), ["x"]
        )
        self.assertNotIn("IdentityAgent=none", pw_plain)

    def test_every_word_is_quoted_even_a_leading_equals(self):
        # the guest shell is zsh: a bare `=ls` expands to /bin/ls
        cmd = vmssh.remote_command(["echo", "=ls", "plain", "", "it's"])
        self.assertEqual(cmd, "'echo' '=ls' 'plain' '' 'it'\"'\"'s'")
        self.assertEqual(shlex.split(cmd), ["echo", "=ls", "plain", "", "it's"])

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

    def test_paths_ssh_would_split_or_expand_are_rejected(self):
        for bad in (
            "/a b/kh",
            "/a\tb",
            "/x/%h/kh",
            "/x/${HOME}/kh",
            "/x/$HOME",
            "~/kh",
        ):
            with self.assertRaises(ValueError, msg=bad):
                vmssh.Target("192.168.64.10", bad, identity="/id")
            with self.assertRaises(ValueError, msg=bad):
                vmssh.Target("192.168.64.10", "/kh", identity=bad)
        vmssh.Target(
            "192.168.64.10", "/ok/known_hosts-1.pinned", identity="/ok/id_ed25519"
        )


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
        self.world.fail_tart = {"pull"}
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

    def test_resolve_network_error_is_a_failed_step_not_a_traceback(self):
        def fetch(url, headers, method):
            raise urllib.error.URLError("name resolution failed")

        self.ctx.fetch = fetch
        rc, s = self.run_cmd("resolve")
        self.assertEqual(rc, 1)
        self.assertFalse(s["ok"])
        self.assertIn("registry request failed", s["steps"][0]["evidence"])

    def test_unreadable_or_bad_image_pins_are_refused_with_exit_2(self):
        for cmd in ("resolve", "pull", "golden", "check"):
            extra = []
            rc, _ = self.run_cmd("--image", str(self.tmp / "missing.json"), cmd, *extra)
            self.assertEqual(rc, 2, cmd)
            for bad in (
                {"golden_name": "-x"},
                {"golden_name": "a b"},
                {"tag": "-t"},
                {"repository": "-r/x"},
                {"digest": "sha256:zz"},
            ):
                if cmd == "resolve" and "digest" in bad:
                    continue  # resolve is how a missing or stale digest gets found
                rc, _ = self.run_cmd("--image", self.image_file(**bad), cmd, *extra)
                self.assertEqual(rc, 2, (cmd, bad))
        self.assertEqual(self.world.calls, [])


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
        self.assertIn("2 VMs already running", s["steps"][-1]["evidence"])
        self.assertEqual(s["steps"][-1]["step"], "refused")
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])

    def test_golden_refuses_when_any_other_vm_is_running(self):
        # No other guest may share the vmnet while the host key is pinned (README).
        self.world.vms = {"other": {"Running": True}}
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 2)
        self.assertEqual(s["steps"][-1]["step"], "refused")
        self.assertIn("other", s["steps"][-1]["evidence"])
        self.assertIn("to itself", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])
        # a stopped VM is fine
        self.world.vms = {"other": {"Running": False}}
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)

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
        clone_env = next(e for a, e in self.world.calls if a[:2] == ["tart", "clone"])
        self.assertEqual(clone_env["TART_NO_AUTO_PRUNE"], "1")  # a clone never prunes
        self.assertEqual(
            self.world.tart_calls("run"),
            [["tart", "run", "--no-graphics", f"{GOLDEN}-build"]],
        )
        self.assertEqual(
            self.world.tart_calls("rename"),
            [["tart", "rename", f"{GOLDEN}-build", GOLDEN]],
        )
        # the guest halted itself: tart stop (a power-off) was never needed
        self.assertEqual(self.world.tart_calls("stop"), [])
        self.assertIn("shut down cleanly", self.steps(s)["g10"]["evidence"])
        self.assertEqual(sorted(self.world.vms), [GOLDEN])
        self.assertFalse(self.world.vms[GOLDEN]["Running"])
        self.assertEqual(self.world.tart_calls("pull"), [])
        # the public key (only) went to the guest on stdin; no script was left anywhere
        minted = (
            self.ctx.state_dir / "keys" / self.ctx.run_id / "id_ed25519.pub"
        ).read_text()
        self.assertEqual(self.world.stdin_seen, [minted.strip() + "\n"])
        # the host key printed by prep.sh is the pinned one, under the alias
        kh = (self.ctx.state_dir / "known_hosts").read_text()
        self.assertEqual(kh, f"state1-vm ssh-ed25519 {NEW_BLOB}\n")
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertEqual(rec["image"], REF)
        self.assertEqual(rec["python"], "3.14.10")
        # the full public key line (what image.json's vanilla_host_key takes), not a hash
        self.assertEqual(rec["vanilla_host_key_seen"], f"ssh-ed25519 {VANILLA_BLOB}")
        self.assertRegex(rec["vanilla_host_key_seen_fingerprint"], r"^SHA256:")
        self.assertFalse((self.ctx.state_dir / "tmp" / self.ctx.run_id).exists())
        self.assertEqual(self.world.fw_owner, FW_PYTHON_FIXED)
        self.assertEqual(self.world.fw_versions, FW_PYTHON_FIXED)  # the parents too

    def test_ssh_trust_model_exact_files_and_modes(self):
        """Before prep: accept-new into the scratch file only. After prep: strict, pinned file."""
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        scratch = self.ctx.state_dir / "tmp" / self.ctx.run_id
        kh_scratch = f"UserKnownHostsFile={scratch / 'known_hosts'}"
        kh_pinned = f"UserKnownHostsFile={scratch / 'known_hosts.pinned'}"
        prep_argv = next(a for sc, a in self.world.script_calls if "PREP-RESULT" in sc)
        prep_at = next(
            i for i, (a, _) in enumerate(self.world.ssh_calls) if a == prep_argv
        )
        before, after = (
            self.world.ssh_calls[: prep_at + 1],
            self.world.ssh_calls[prep_at + 1 :],
        )
        self.assertTrue(before and after)
        for argv, _ in before:
            self.assertIn(kh_scratch, argv)
            self.assertIn("StrictHostKeyChecking=accept-new", argv)
        for (
            argv,
            _,
        ) in after:  # the python step, the password check, the shutdown: all strict
            self.assertIn(kh_pinned, argv)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertNotIn("StrictHostKeyChecking=accept-new", argv)
        # accept-new never touches the state-dir file; nothing ever uses =no
        for argv, _ in self.world.ssh_calls:
            self.assertNotIn("StrictHostKeyChecking=no", argv)
            kh = next(o for o in argv if o.startswith("UserKnownHostsFile="))
            self.assertTrue(
                kh in (kh_scratch, kh_pinned), kh
            )  # never the state-dir known_hosts
        # the python install ran after the pin, on the strict file, and prep ran first
        py_argv = next(
            a for sc, a in self.world.script_calls if "INSTALL-PYTHON-RESULT" in sc
        )
        self.assertGreater(
            next(i for i, (a, _) in enumerate(self.world.ssh_calls) if a == py_argv),
            prep_at,
        )
        self.assertIn(kh_pinned, py_argv)

    def test_scripts_are_streamed_in_one_session_with_nothing_left_behind(self):
        self.run_cmd(*self.golden_args())
        self.assertEqual(len(self.world.script_calls), 2)
        for script, argv in self.world.script_calls:
            remote = shlex.split(argv[-1])
            self.assertEqual(remote[:3], ["/bin/sh", "-c", drv.RUN_SCRIPT_SH])
            # the script text travels on stdin; no path to it is an argument
            self.assertNotIn("/var/tmp", " ".join(remote[4:]))
            self.assertIn("set -eu", script)
        self.assertIn("mktemp", drv.RUN_SCRIPT_SH)
        self.assertIn("trap", drv.RUN_SCRIPT_SH)
        self.assertEqual(
            [
                a
                for a, _ in self.world.ssh_calls
                if shlex.split(a[-1])[:2] == ["rm", "-f"]
            ],
            [],
        )

    def test_keyscan_that_disagrees_with_prep_fails_and_pins_nothing(self):
        self.world.keyscan_blob = OTHER_BLOB
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["g6"]["status"], "pass")
        self.assertEqual(st["g7"]["status"], "fail")
        self.assertIn("different ed25519 key", st["g7"]["evidence"])
        self.assertNotIn("g8", st)  # the python install never ran
        self.assertFalse((self.ctx.state_dir / "known_hosts").exists())
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())
        self.assertEqual(self.world.vms, {})

    def test_g6_evidence_carries_the_secure_token_after_line_even_from_long_output(
        self,
    ):
        # issue 78: the line sits far from the end of a long prep output and still reaches g6
        self.world.prep_noise = "".join(
            f"prep: disabled com.apple.example{i}\n" for i in range(400)
        )
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["g6"]["evidence"]
        self.assertIn("PREP-RESULT disabled=3 absent=22 failed=0", ev)
        self.assertIn("secure token status (after):", ev)
        self.assertIn("Secure token is ENABLED for user Managed via Tart", ev)
        self.assertNotIn("example399", ev)  # it is the one line, not the noise

    def test_g6_says_so_when_prep_printed_no_secure_token_line(self):
        self.world.prep_token_line = ""
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(
            rc, 0, s
        )  # evidence for issue 78, never a reason to fail the build
        self.assertIn(
            "secure token status (after): not printed by prep.sh",
            self.steps(s)["g6"]["evidence"],
        )

    def test_prep_must_print_exactly_one_valid_hostkey_line(self):
        for n in (0, 2):
            self.world.prep_hostkey_lines = n
            self.world.vms.clear()
            rc, s = self.run_cmd(*self.golden_args())
            self.assertEqual(rc, 1, n)
            self.assertEqual(self.steps(s)["g6"]["status"], "fail")
            self.assertIn("PREP-HOSTKEY", self.steps(s)["g6"]["evidence"])
        self.world.vms.clear()
        with self.assertRaises(drv.StepFail):
            drv.parse_prep_hostkey("PREP-HOSTKEY ssh-ed25519 not*base64\n")

    def test_golden_then_check_end_to_end_in_one_world(self):
        """The key rotation and python.org's ownership both bite across the two commands."""
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)
        self.assertEqual(st["2i"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_a_fixup_scoped_to_versions_x_y_leaves_the_parents_and_2i_fails(self):
        """The old fix-up (chown on "$fw") reaches Versions/X.Y but not Versions/ itself."""
        orig = self.world._run_script

        def old_script(args, script):
            script = script.replace("$fwroot", "$fw")
            return orig(args, script)

        self.world._run_script = old_script
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)  # golden does not run the checks; check does
        self.assertEqual(self.world.fw_owner, FW_PYTHON_FIXED)
        self.assertEqual(self.world.fw_versions, FW_PYTHON_ORIGINAL)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["2i"]["status"], "fail")
        self.assertIn("Python.framework/Versions", self.steps(s)["2i"]["evidence"])

    def test_password_is_confined_to_the_bootstrap_calls(self):
        self.run_cmd(*self.golden_args())
        pw_calls, key_calls = [], []
        for argv, env in self.world.ssh_calls:
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
                or a[:5]
                == [
                    "ssh-keygen",
                    "-y",
                    "-P",
                    "",
                    "-f",
                ]  # the record and key are validated
                for a in new
            ),
            new,
        )
        self.assertEqual(len(self.world.tart_calls("clone")), 1)

    def test_rebuild_replaces_the_existing_golden_only_at_the_rename(self):
        self.run_cmd(*self.golden_args())
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 0, s)
        self.assertEqual(len(self.world.tart_calls("clone")), 2)
        self.assertEqual(self.world.tart_calls("delete"), [["tart", "delete", GOLDEN]])
        self.assertEqual(sorted(self.world.vms), [GOLDEN])
        order = [a[1] for a in (c for c, _ in self.world.calls) if a[0] == "tart"]
        last = lambda name: max(i for i, x in enumerate(order) if x == name)
        # the old golden goes after the new build exists and ran, right before the rename
        self.assertGreater(last("delete"), last("clone"))
        self.assertGreater(last("delete"), last("run"))
        self.assertLess(last("delete"), last("rename"))

    def test_a_failed_rebuild_keeps_the_working_golden(self):
        self.run_cmd(*self.golden_args())
        self.world.fail_prep = True
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 1)
        self.assertIn(GOLDEN, self.world.vms)  # still there
        self.assertEqual(
            self.world.tart_calls("delete"), [["tart", "delete", f"{GOLDEN}-build"]]
        )
        self.assertEqual(self.steps(s)["g6"]["status"], "fail")

    def test_rename_failure_keeps_the_finished_build_and_says_how_to_finish(self):
        self.world.fail_tart = {"rename"}
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        ev = self.steps(s)["g10"]["evidence"]
        self.assertIn(f"tart rename {GOLDEN}-build {GOLDEN}", ev)
        self.assertEqual(
            sorted(self.world.vms), [f"{GOLDEN}-build"]
        )  # kept, not deleted
        self.assertNotIn("cleanup", self.steps(s))

    def test_rename_failure_on_a_rebuild_after_the_old_golden_is_gone(self):
        self.run_cmd(*self.golden_args())
        self.world.fail_tart = {"rename"}
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["rebuild"]["status"], "pass")  # the old one went
        self.assertEqual(
            sorted(self.world.vms), [f"{GOLDEN}-build"]
        )  # the new one is kept

    def test_a_guest_that_does_not_halt_fails_g10_and_nothing_is_saved(self):
        self.world.shutdown_hangs = True
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(len(self.world.tart_calls("stop")), 1)  # the forced one
        st = self.steps(s)
        self.assertEqual(st["g10"]["status"], "fail")
        self.assertIn("powered it off", st["g10"]["evidence"])
        self.assertIn("not saved", st["g10"]["evidence"])
        self.assertGreaterEqual(self.clock.t, drv.GUEST_SHUTDOWN_WAIT)
        self.assertEqual(self.world.tart_calls("rename"), [])
        self.assertEqual(self.world.vms, {})  # the build is removed ...
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())
        self.assertFalse((self.ctx.state_dir / "known_hosts").exists())

    def test_a_forced_power_off_keeps_the_build_only_with_keep_on_failure(self):
        self.world.shutdown_hangs = True
        rc, _ = self.run_cmd(*self.golden_args("--keep-on-failure"))
        self.assertEqual(rc, 1)
        self.assertEqual(sorted(self.world.vms), [f"{GOLDEN}-build"])  # ... kept
        self.assertFalse(self.world.vms[f"{GOLDEN}-build"]["Running"])
        self.assertEqual(self.world.tart_calls("rename"), [])
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())

    def test_a_failed_old_golden_delete_on_a_rebuild_keeps_everything_and_the_old_record(
        self,
    ):
        self.run_cmd(*self.golden_args())
        old_kh = (self.ctx.state_dir / "known_hosts").read_text()
        old_rec = (self.ctx.state_dir / "golden.json").read_text()
        self.world.new_hostkey = OTHER_BLOB  # the rebuilt guest has a different key
        self.world.fail_tart = {"delete"}
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)
        self.assertEqual(st["g10"]["status"], "fail")
        self.assertIn("removing the old", st["g10"]["evidence"])
        # the finished build's record is parked and names its key, so the key is not orphaned
        pending = json.loads((self.ctx.state_dir / "golden.json.pending").read_text())
        self.assertEqual(pending["key_id"], "20261121T000000Z-second")
        self.assertTrue((self.ctx.state_dir / "known_hosts.pending").exists())
        self.assertIn("golden.json.pending", st["g10"]["evidence"])
        self.assertEqual(
            self.key_dirs(), sorted([self.ctx.run_id, "20261121T000000Z-second"])
        )
        self.assertNotIn("cleanup", st)  # the finished build is not deleted
        self.assertEqual(sorted(self.world.vms), sorted([GOLDEN, f"{GOLDEN}-build"]))
        self.assertEqual(
            len(self.world.tart_calls("rename")), 1
        )  # only the first run's
        # the old golden still matches its own record: check's pin and record are unchanged
        self.assertEqual((self.ctx.state_dir / "known_hosts").read_text(), old_kh)
        self.assertEqual((self.ctx.state_dir / "golden.json").read_text(), old_rec)

    def test_a_signal_between_the_old_golden_delete_and_the_rename_is_masked(self):
        self.run_cmd(*self.golden_args())
        self.world.new_hostkey = OTHER_BLOB
        self.world.signal_on_tart = "rename"  # a real SIGTERM, right after the delete
        old = signal.getsignal(signal.SIGTERM)
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(self.world.signals_sent, 1)  # it was really sent
        self.assertEqual(rc, 0, s)  # ignored: the commit is not torn
        self.assertEqual(sorted(self.world.vms), [GOLDEN])
        kh = (self.ctx.state_dir / "known_hosts").read_text()
        self.assertEqual(kh, f"state1-vm ssh-ed25519 {OTHER_BLOB}\n")  # the new record
        self.assertEqual(signal.getsignal(signal.SIGTERM), old)

    def test_records_are_written_only_after_the_rename_succeeds(self):
        self.world.fail_tart = {"rename"}
        rc, _ = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        self.assertFalse((self.ctx.state_dir / "known_hosts").exists())
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())
        # the new record is parked beside them, so finishing by hand does not need a rebuild
        self.assertTrue((self.ctx.state_dir / "known_hosts.pending").exists())
        rec = json.loads((self.ctx.state_dir / "golden.json.pending").read_text())
        self.assertEqual(rec["image"], REF)
        self.assertEqual(
            (self.ctx.state_dir / "known_hosts.pending").read_text(),
            f"{vmssh.HOST_ALIAS} ssh-ed25519 {NEW_BLOB}\n",
        )

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

    def test_cleanup_failure_is_reported_and_exits_1(self):
        self.world.fail_prep = True
        self.world.fail_tart = {"delete"}
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["cleanup"]["status"], "fail")
        self.assertIn("delete", st["cleanup"]["evidence"])
        self.assertFalse(s["ok"])

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

    def test_interrupt_during_the_clone_still_removes_a_clone_that_completed(self):
        self.world.interrupt_after_tart = (
            "clone"  # the clone finished, then the kill came
        )
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 130)
        self.assertEqual(self.world.vms, {})
        self.assertEqual(self.steps(s)["cleanup"]["status"], "pass")
        self.assertEqual(self.world.tart_calls("run"), [])

    def test_a_real_sigterm_is_caught_and_cleaned_up(self):
        self.world.signal_on = "sudo"  # os.kill(getpid(), SIGTERM) from inside the run
        old = signal.getsignal(signal.SIGTERM)
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 130)
        self.assertIn("SIGTERM", self.steps(s)["interrupted"]["evidence"])
        self.assertEqual(self.world.vms, {})
        self.assertEqual(signal.getsignal(signal.SIGTERM), old)  # handlers restored

    def test_server_that_still_offers_password_login_fails_the_build(self):
        # The wrong-password false pass: "Permission denied" alone proves nothing.
        self.world.prep_leaves_password = True
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["g9"]["status"], "fail")
        self.assertIn("still offers", st["g9"]["evidence"])
        self.assertNotIn("g10", st)
        self.assertNotIn(GOLDEN, self.world.vms)

    def test_a_pinned_vanilla_host_key_makes_the_bootstrap_leg_strict(self):
        image = self.image_file(vanilla_host_key=f"ssh-ed25519 {VANILLA_BLOB}")
        rc, s = self.run_cmd("--image", image, *self.golden_args())
        self.assertEqual(rc, 0, s)
        pre = [
            a
            for a, _ in self.world.ssh_calls
            if any(o.endswith("known_hosts.vanilla") for o in a)
        ]
        self.assertTrue(pre)
        for argv in pre:
            self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertFalse(
            any(
                "StrictHostKeyChecking=accept-new" in a for a, _ in self.world.ssh_calls
            )
        )

    def test_a_vanilla_host_key_that_does_not_match_the_pin_stops_the_build(self):
        image = self.image_file(vanilla_host_key=f"ssh-ed25519 {OTHER_BLOB}")
        rc, s = self.run_cmd("--image", image, *self.golden_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["g3"]["status"], "fail")
        self.assertIn("host key mismatch", self.steps(s)["g3"]["evidence"])
        self.assertEqual(self.world.vms, {})

    def test_the_operator_key_flags_are_gone(self):
        for argv in (
            ["golden", "--pubkey", "k.pub"],
            ["golden", "--identity", "k"],
            ["check", "--identity", "k"],
        ):
            with (
                self.assertRaises(SystemExit) as cm,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                drv.main(argv, self.ctx)
            self.assertEqual(cm.exception.code, 2, argv)
        self.assertEqual(self.world.calls, [])

    def test_golden_mints_its_own_key_and_every_login_offers_only_it(self):
        operator_dir = str(Path.home() / ("." + "ssh"))
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        key_dir = self.ctx.state_dir / "keys" / self.ctx.run_id
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])
        self.assertEqual(stat.S_IMODE(key_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((key_dir / "id_ed25519").stat().st_mode), 0o600)
        pub = (key_dir / "id_ed25519.pub").read_text().strip()
        self.assertTrue(pub.startswith("ssh-ed25519 "))
        self.assertNotIn(pub.split()[1], (VANILLA_BLOB, NEW_BLOB))
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertEqual(rec["key_id"], self.ctx.run_id)
        self.assertEqual(rec["authorized_key"], drv.fingerprint(pub))
        # every key login offers the minted key, never anything of the operator's
        offered = {
            argv[argv.index("-i") + 1]
            for argv, _ in self.world.ssh_calls
            if "-i" in argv
        }
        self.assertEqual(offered, {str(key_dir / "id_ed25519")})
        for argv, _ in self.world.ssh_calls:
            if "-i" in argv:  # the operator's agent is never consulted either
                self.assertIn("IdentityAgent=none", argv)
                self.assertIn("IdentitiesOnly=yes", argv)
        # a substring check on top of the options above, not instead of them
        for argv, _ in self.world.calls:
            self.assertFalse(any(operator_dir in a for a in argv), argv)
        self.assertNotIn(
            "PRIVATE KEY", (self.ctx.state_dir / "golden.json").read_text()
        )

    def test_a_golden_and_check_run_cannot_prompt(self):
        from unittest import mock

        with mock.patch.dict(os.environ):
            os.environ.pop(vmssh.BOOTSTRAP_PW_ENV, None)
            rc, out = self.run_cmd(*self.golden_args())
            self.assertEqual(rc, 0, out)
            rc, out = self.run_cmd(*self.check_args())
            self.assertEqual(rc, 0, out)
        # what makes it promptless: key logins are BatchMode, the bootstrap login takes its
        # password from SSH_ASKPASS (forced), ssh-keygen gets an empty passphrase
        key_calls = [(a, e) for a, e in self.world.ssh_calls if "-i" in a]
        self.assertTrue(key_calls)
        for argv, _ in key_calls:
            self.assertIn("BatchMode=yes", argv)
        pw_calls = [(a, e) for a, e in self.world.ssh_calls if "-i" not in a]
        self.assertTrue(pw_calls)
        for _, env in pw_calls:
            self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")
            self.assertIn("SSH_ASKPASS", env)
        keygen = [a for a, _ in self.world.calls if a[0] == "ssh-keygen" and "-t" in a]
        self.assertEqual(len(keygen), 1)
        self.assertEqual(keygen[0][keygen[0].index("-N") + 1], "")
        # and a child process never inherits a terminal: stdin is /dev/null without input
        r = drv.RealRunner().run(["/bin/cat"], timeout=10)
        self.assertEqual((r.rc, r.stdout), (0, ""))

    def test_a_rebuild_mints_a_new_key_and_removes_the_old_one(self):
        self.run_cmd(*self.golden_args())
        first = self.ctx.run_id
        old_pub = (self.ctx.state_dir / "keys" / first / "id_ed25519.pub").read_text()
        second = "20261121T000000Z-test2"
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id=second)
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx2)
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.key_dirs(), [second])  # the old private key is gone
        new_pub = (self.ctx.state_dir / "keys" / second / "id_ed25519.pub").read_text()
        self.assertNotEqual(old_pub.split()[1], new_pub.split()[1])
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertEqual(rec["key_id"], second)
        self.assertEqual(self.steps(s)["keys"]["evidence"], f"removed {first}")
        rc, s = self.run_cmd(*self.check_args(), ctx=ctx2)  # check uses the new key
        self.assertEqual(rc, 0, s)

    def mkkeys(self, *names):
        keys = self.ctx.state_dir / "keys"
        keys.mkdir(parents=True, mode=0o700)
        os.chmod(keys, 0o700)
        for n in names:
            (keys / n).mkdir(mode=0o700)
            os.chmod(keys / n, 0o700)
            (keys / n / "id_ed25519").write_text("x")
        return keys

    def test_stale_keys_of_other_goldens_are_swept_but_not_symlinks_or_strays(self):
        keys = self.mkkeys("old-golden", "current")
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "precious").write_text("keep")
        (keys / "linked").symlink_to(outside)
        (keys / "stray-file").write_text("x")
        gone, failed = drv.sweep_stale_keys(self.ctx, keep="current")
        self.assertEqual((gone, failed), (["old-golden"], []))
        self.assertTrue((outside / "precious").exists())
        self.assertTrue((keys / "stray-file").exists())
        self.assertTrue((keys / "current").exists())

    def test_the_sweep_never_follows_a_symlinked_keys_root(self):
        outside = self.tmp / "outside"
        (outside / "victim").mkdir(parents=True, mode=0o700)
        os.chmod(outside, 0o700)
        (outside / "victim" / "id").write_text("keep")
        self.ctx.state_dir.mkdir(parents=True)
        (self.ctx.state_dir / "keys").symlink_to(outside)
        with self.assertRaises(drv.Refusal) as cm:
            drv.sweep_stale_keys(self.ctx, keep="current")
        self.assertIn("real directory", str(cm.exception))
        self.assertTrue((outside / "victim" / "id").exists())

    def test_the_sweep_reports_what_it_could_not_remove(self):
        from unittest import mock

        keys = self.mkkeys("old-golden", "loose-one")
        os.chmod(keys / "loose-one", 0o755)  # not ours to remove blindly
        with mock.patch.object(drv.shutil, "rmtree"):  # a removal that does nothing
            gone, failed = drv.sweep_stale_keys(self.ctx, keep="current")
        self.assertEqual(gone, [])
        self.assertEqual(len(failed), 2, failed)
        self.assertTrue(any("old-golden" in f and "still present" in f for f in failed))
        self.assertTrue(any("loose-one" in f for f in failed))
        self.assertTrue((keys / "old-golden").exists())

    def test_a_key_that_cannot_be_removed_fails_the_keys_step(self):
        from unittest import mock

        self.run_cmd(*self.golden_args())
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id="20261121T000000Z-second")
        with mock.patch.object(drv.shutil, "rmtree"):
            rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx2)
        self.assertEqual(rc, 1)
        st = self.steps(s)["keys"]
        self.assertEqual(st["status"], "fail")
        self.assertIn("NOT removed", st["evidence"])
        self.assertIn(self.ctx.run_id, st["evidence"])

    def test_a_symlinked_keys_root_stops_golden_before_anything_is_written(self):
        outside = self.tmp / "outside"
        outside.mkdir(mode=0o700)
        os.chmod(outside, 0o755)
        self.ctx.state_dir.mkdir(parents=True)
        (self.ctx.state_dir / "keys").symlink_to(outside)
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 2)
        self.assertIn("real directory", s["steps"][-1]["evidence"])
        self.assertEqual(list(outside.iterdir()), [])  # nothing minted through the link
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)  # and no chmod

    def test_an_existing_key_directory_is_never_deleted_by_the_run_that_collides(self):
        keys = self.mkkeys(self.ctx.run_id)  # the same run id: an injected collision
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        self.assertIn("already exists", self.steps(s)["error"]["evidence"])
        self.assertEqual((keys / self.ctx.run_id / "id_ed25519").read_text(), "x")

    def test_golden_with_a_usable_record_and_key_does_nothing(self):
        self.run_cmd(*self.golden_args())
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id="20261121T000000Z-second")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx2)
        self.assertEqual(rc, 0, s)
        self.assertIn("nothing to do", self.steps(s)["exists"]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])

    def rebuilt_unattended(self, damage):
        self.run_cmd(*self.golden_args())
        damage()
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id="20261121T000000Z-second")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx2)  # no --rebuild
        self.assertEqual(rc, 0, s)
        self.exists_evidence = self.steps(s)["exists"]["evidence"]
        self.assertIn("rebuilding it unattended", self.exists_evidence)
        self.assertEqual(len(self.world.tart_calls("clone")), 2)
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertEqual(rec["key_id"], "20261121T000000Z-second")
        self.assertEqual(self.key_dirs(), ["20261121T000000Z-second"])
        rc, s = self.run_cmd(*self.check_args(), ctx=ctx2)
        self.assertEqual(rc, 0, s)
        return s

    def test_a_golden_with_no_record_in_this_state_dir_is_never_replaced_unasked(self):
        self.run_cmd(*self.golden_args())
        (
            self.ctx.state_dir / "golden.json"
        ).unlink()  # pre-records, or another state dir's
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id="20261121T000000Z-second")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx2)
        self.assertEqual(rc, 2)
        self.assertIn("no record of it", s["steps"][-1]["evidence"])
        self.assertIn("--rebuild", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        self.assertEqual(self.world.tart_calls("delete"), [])
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])  # nothing minted or swept
        # asked for by name, it replaces the golden
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx2)
        self.assertEqual(rc, 0, s)
        self.assertEqual(len(self.world.tart_calls("clone")), 2)

    def owner_file(self):
        return drv.owner_path(self.ctx, GOLDEN)

    def test_the_commit_writes_an_owner_marker_beside_the_driver_lock(self):
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        path = self.owner_file()
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertEqual(
            json.loads(path.read_text()),
            {
                "golden": GOLDEN,
                "state_dir": os.path.realpath(self.ctx.state_dir),
                "tart_home": self.ctx.tart_home,
                "key_id": self.ctx.run_id,
                "host_key": rec["host_key"],
                "state": "final",
            },
        )
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        # atomic write: no temp file left beside it
        self.assertEqual(
            sorted(p.name for p in path.parent.iterdir()),
            sorted(["driver.lock", path.name]),
        )
        # the record's host_key is the pin's fingerprint
        pin = drv.kh_fingerprint(self.ctx.state_dir / "known_hosts")
        self.assertEqual(rec["host_key"], f"ssh-ed25519 {pin}")

    def test_two_state_dirs_only_the_owner_rebuilds_unasked(self):
        self.run_cmd(*self.golden_args())  # state dir A owns the golden
        dir_b = self.tmp / "stateB"
        ctx_b = self.make_ctx(dir_b, run_id="20261121T000000Z-b")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx_b)
        self.assertEqual(rc, 2)  # B has no record at all
        self.assertIn("no record of it", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx_b)  # B takes it
        self.assertEqual(rc, 0, s)
        owner = json.loads(self.owner_file().read_text())
        self.assertEqual(owner["state_dir"], os.path.realpath(dir_b))
        self.assertEqual(owner["key_id"], "20261121T000000Z-b")
        clones, deletes = (
            len(self.world.tart_calls("clone")),
            self.world.tart_calls("delete"),
        )
        self.assertEqual(clones, 2)
        # A's record is stale (it describes the replaced golden), B's golden is valid: A
        # must not rebuild over it
        ctx_a2 = self.second_run_ctx("20261122T000000Z-a2")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx_a2)
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn(os.path.realpath(dir_b), ev)  # names the owner
        self.assertIn("--rebuild", ev)
        self.assertEqual(len(self.world.tart_calls("clone")), clones)
        self.assertEqual(self.world.tart_calls("delete"), deletes)
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])  # nothing minted or swept
        # the owner still says "nothing to do"
        ctx_b2 = self.make_ctx(dir_b, run_id="20261122T000000Z-b2")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx_b2)
        self.assertEqual(rc, 0, s)
        self.assertIn("nothing to do", self.steps(s)["exists"]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), clones)

    def test_a_golden_with_no_owner_file_is_never_replaced_unasked(self):
        # a golden from before owner markers: its record and pin are fine, the marker is absent
        self.run_cmd(*self.golden_args())
        self.owner_file().unlink()
        ctx2 = self.second_run_ctx()
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx2)
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn("no owner file", ev)
        self.assertIn("--rebuild", ev)
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        self.assertEqual(self.world.tart_calls("delete"), [])
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])
        # check does not need the marker: it only asks whether this state dir can log in
        rc, s = self.run_cmd(*self.check_args(), ctx=ctx2)
        self.assertEqual(rc, 0, s)
        # asked for by name it replaces the golden and this state dir becomes its owner
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx2)
        self.assertEqual(rc, 0, s)
        self.assertEqual(
            json.loads(self.owner_file().read_text())["key_id"], ctx2.run_id
        )

    def test_an_owner_file_that_disagrees_with_the_record_is_refused(self):
        self.run_cmd(*self.golden_args())
        good = self.owner_file().read_text()
        ctx2 = self.second_run_ctx()
        for what, mutate, want in [
            ("key id", lambda o: o.update(key_id="other"), "did not all land"),
            ("host key", lambda o: o.update(host_key="x"), "did not all land"),
            ("golden", lambda o: o.update(golden="someone-else"), "someone-else"),
        ]:
            owner = json.loads(good)
            mutate(owner)
            self.owner_file().write_text(json.dumps(owner))
            rc, s = self.run_cmd(*self.golden_args(), ctx=ctx2)
            self.assertEqual(rc, 2, what)
            self.assertIn(want, s["steps"][-1]["evidence"], what)
        self.owner_file().write_text("not json")
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx2)
        self.assertEqual(rc, 2)
        self.assertIn("unreadable owner file", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        self.assertEqual(self.world.tart_calls("delete"), [])

    def test_a_pin_that_disagrees_with_the_records_host_key_is_rebuilt_without_asking(
        self,
    ):
        # a kill between the two commit writes: the new known_hosts landed, golden.json (and
        # the owner marker, written after it) still describe the old golden
        self.rebuilt_unattended(
            lambda: (self.ctx.state_dir / "known_hosts").write_text(
                f"{vmssh.HOST_ALIAS} ssh-ed25519 {OTHER_BLOB}\n"
            )
        )
        self.assertIn("does not match the pin", self.exists_evidence)
        # golden rebuilds by itself: it does not tell the reader to run `golden`
        self.assertNotIn("run `golden`", self.exists_evidence)

    def test_golden_usable_compares_the_records_host_key_with_the_pin(self):
        self.run_cmd(*self.golden_args())
        self.assertTrue(drv.golden_usable(self.ctx, GOLDEN))
        kh = self.ctx.state_dir / "known_hosts"
        good = kh.read_text()
        kh.write_text(f"{vmssh.HOST_ALIAS} ssh-ed25519 {OTHER_BLOB}\n")
        with self.assertRaises(drv.Refusal) as cm:
            drv.golden_usable(self.ctx, GOLDEN)
        self.assertIn("does not match the pin", str(cm.exception))
        rc, s = self.run_cmd(
            *self.check_args()
        )  # check refuses on it too, before a clone
        self.assertEqual(rc, 2)
        self.assertIn("does not match the pin", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        # a record with no host_key at all is no better
        kh.write_text(good)
        rec_path = self.ctx.state_dir / "golden.json"
        rec = json.loads(rec_path.read_text())
        del rec["host_key"]
        rec_path.write_text(json.dumps(rec))
        with self.assertRaises(drv.Refusal) as cm:
            drv.golden_usable(self.ctx, GOLDEN)
        self.assertIn("has no host_key", str(cm.exception))
        self.assertNotIn("did not both land", str(cm.exception))

    # ---- PR 80 round 1: the intent marker, crash windows, hardening ----------------------

    def failing_writes(self, plan):
        """Patch atomic_write so the commit stops at the n-th write of a destination name.
        plan: {name: n}. Returns the patcher and the list of (name, text) writes seen."""
        from unittest import mock

        real = drv.atomic_write
        seen, counts = [], {}

        def wrapper(dest, text, mode=0o600):
            name = Path(dest).name
            counts[name] = counts.get(name, 0) + 1
            seen.append((name, text))
            if plan.get(name) == counts[name]:
                raise OSError(28, "No space left on device")
            return real(dest, text, mode)

        return mock.patch.object(drv, "atomic_write", wrapper), seen

    def two_dirs(self):
        """A built the golden; returns (ctx_a2, ctx_b): plain `golden` contexts for A and B."""
        self.run_cmd(*self.golden_args())
        ctx_b = self.make_ctx(self.tmp / "stateB", run_id="20261121T000000Z-b")
        return self.second_run_ctx("20261122T000000Z-a2"), ctx_b

    def plain(self, ctx):
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx)
        ev = " | ".join(x["evidence"] for x in s["steps"])
        return rc, ev, s

    def test_the_commit_invalidates_the_marker_before_any_destructive_step(self):
        patcher, seen = self.failing_writes({})
        with patcher:
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        marker = drv.owner_path(self.ctx, GOLDEN).name
        order = [
            (n, json.loads(t)["state"] if n == marker else "")
            for n, t in seen
            if n in (marker, "known_hosts", "golden.json")
        ]
        # intent first (before the delete and the rename), the final marker last
        self.assertEqual(
            order,
            [
                (marker, "committing"),
                ("known_hosts", ""),
                ("golden.json", ""),
                (marker, "final"),
            ],
        )

    def test_a_commit_that_stops_at_any_write_never_leaves_a_stale_blessing(self):
        # Fable F1 table: every row, takeover by B and a rebuild by A itself
        rows = [
            ("intent", {"MARKER": 1}, "untouched"),
            ("known_hosts", {"known_hosts": 1}, "stopped"),
            ("golden.json", {"golden.json": 1}, "stopped"),
            ("final marker", {"MARKER": 2}, "stopped"),
        ]
        for takeover in (True, False):
            for what, plan, kind in rows:
                with self.subTest(what=what, takeover=takeover):
                    self.tearDown_world()
                    ctx_a2, ctx_b = self.two_dirs()
                    plan = {
                        (
                            drv.owner_path(self.ctx, GOLDEN).name
                            if k == "MARKER"
                            else k
                        ): v
                        for k, v in plan.items()
                    }
                    committer = ctx_b if takeover else ctx_a2
                    patcher, _ = self.failing_writes(plan)
                    with patcher:
                        rc, s = self.run_cmd(
                            *self.golden_args("--rebuild"), ctx=committer
                        )
                    self.assertEqual(rc, 1, s)
                    rc_a, ev_a, _ = self.plain(ctx_a2)
                    rc_b, ev_b, _ = self.plain(ctx_b)
                    if kind == "untouched":
                        # nothing changed: A still owns it and says so; B is refused
                        self.assertEqual(rc_a, 0, ev_a)
                        self.assertIn("nothing to do", ev_a)
                        self.assertEqual(rc_b, 2)
                    else:
                        for who, rc_x, ev_x in (("A", rc_a, ev_a), ("B", rc_b, ev_b)):
                            self.assertEqual(rc_x, 2, (who, ev_x))
                            self.assertNotIn("nothing to do", ev_x)
                            self.assertIn("--rebuild", ev_x)
                        self.assertIn("did not finish", ev_a + ev_b)

    def tearDown_world(self):
        """Fresh world and state for the next row of a table test."""
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.tmp.mkdir()
        self.world = FakeWorld()
        self.ctx = self.make_ctx(self.tmp / "state")

    def test_a_failed_rename_finished_by_hand_over_another_state_dir_is_not_blessed_for_it(
        self,
    ):
        # Fable F1 case 1 and F2: B --rebuild, rename fails, the operator finishes by hand
        ctx_a2, ctx_b = self.two_dirs()
        self.world.fail_tart = {"rename"}
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx_b)
        self.assertEqual(rc, 1)
        ev = self.steps(s)["g10"]["evidence"]
        marker = drv.owner_path(self.ctx, GOLDEN)
        for pending in (
            "known_hosts.pending",
            "golden.json.pending",
            marker.name + ".pending",
        ):
            self.assertIn(pending, ev)  # all three are named, and so is the third mv
        # the golden is absent while the rename is undone (a plain `golden` builds it again);
        # the owner file says the commit did not finish
        self.assertEqual(json.loads(marker.read_text())["state"], "committing")
        # the hand finish: tart rename, then the three mv
        self.world.vms[GOLDEN] = self.world.vms.pop(f"{GOLDEN}-build")
        os.replace(
            ctx_b.state_dir / "known_hosts.pending", ctx_b.state_dir / "known_hosts"
        )
        os.replace(
            ctx_b.state_dir / "golden.json.pending", ctx_b.state_dir / "golden.json"
        )
        os.replace(str(marker) + ".pending", marker)
        # B: plain `golden` says nothing to do, check's pre-boot test passes
        rc, evb, _ = self.plain(ctx_b)
        self.assertEqual(rc, 0, evb)
        self.assertIn("nothing to do", evb)
        self.assertTrue(drv.golden_usable(ctx_b, GOLDEN))
        # A (stale record, damaged or not): refused, naming B; `check` names B too
        rc, eva, _ = self.plain(ctx_a2)
        self.assertEqual(rc, 2)
        self.assertIn(os.path.realpath(ctx_b.state_dir), eva)
        clones = len(self.world.tart_calls("clone"))
        rc, s = self.run_cmd(*self.check_args(), ctx=ctx_a2)
        self.assertEqual(rc, 2)
        self.assertIn(os.path.realpath(ctx_b.state_dir), s["steps"][-1]["evidence"])
        self.assertEqual(
            len(self.world.tart_calls("clone")), clones
        )  # before any clone
        (
            ctx_a2.state_dir / "known_hosts"
        ).unlink()  # even damaged, A never rebuilds over B
        rc, eva, _ = self.plain(ctx_a2)
        self.assertEqual(rc, 2, eva)

    def test_a_failed_old_golden_delete_restores_the_previous_marker(self):
        self.run_cmd(*self.golden_args())
        marker = drv.owner_path(self.ctx, GOLDEN)
        before = marker.read_text()
        self.world.fail_tart = {"delete"}
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 1)
        self.assertEqual(marker.read_text(), before)
        self.assertIn("restored", self.steps(s)["g10"]["evidence"])
        # no previous marker (a pre-change golden): the intent marker is removed again
        marker.unlink()
        self.world.vms.pop(f"{GOLDEN}-build", None)  # the first run left its build
        rc, s = self.run_cmd(
            *self.golden_args("--rebuild"),
            ctx=self.second_run_ctx("20261123T000000Z-x"),
        )
        self.assertEqual(rc, 1)
        self.assertFalse(marker.exists())
        self.assertIn("removed again", self.steps(s)["g10"]["evidence"])

    def test_an_oserror_in_a_commit_write_is_a_g10_failure_naming_what_landed(self):
        marker = drv.owner_path(self.ctx, GOLDEN).name
        for fail, landed in (
            ("known_hosts", "nothing"),
            ("golden.json", "known_hosts"),
        ):
            self.tearDown_world()
            patcher, _ = self.failing_writes({fail: 1})
            with patcher:
                rc, s = self.run_cmd(*self.golden_args())
            self.assertEqual(rc, 1, fail)
            ev = self.steps(s)["g10"]["evidence"]
            self.assertEqual(self.steps(s)["g10"]["status"], "fail")
            self.assertIn(f"writing {fail} failed", ev)
            self.assertIn(f"written before it: {landed}", ev)
            self.assertIn(marker + ".pending", ev)
        # the intent write itself: nothing else was touched
        self.tearDown_world()
        patcher, _ = self.failing_writes({marker: 1})
        with patcher:
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        self.assertIn("as it was", self.steps(s)["g10"]["evidence"])
        self.assertEqual(sorted(self.world.vms), [f"{GOLDEN}-build"])

    def test_atomic_write_fsyncs_the_file_and_then_the_directory(self):
        from unittest import mock

        with (
            mock.patch.object(drv, "F_FULLFSYNC", None),
            mock.patch.object(drv.os, "fsync", wraps=os.fsync) as fs,
        ):
            drv.atomic_write(self.tmp / "x" / "f", "data")
        self.assertEqual(fs.call_count, 2)  # the temp file, then the directory

    def test_the_marker_is_read_safely(self):
        self.run_cmd(*self.golden_args())
        marker = drv.owner_path(self.ctx, GOLDEN)
        good = marker.read_text()
        ctx2 = self.second_run_ctx()
        elsewhere = self.tmp / "elsewhere.json"
        elsewhere.write_text(good)

        def as_symlink():
            marker.unlink()
            marker.symlink_to(elsewhere)

        def as_fifo():
            marker.unlink()
            os.mkfifo(marker)

        def as_dir():
            marker.unlink()
            marker.mkdir()

        def as_big():
            marker.write_text(good + " " * (drv.OWNER_MAX_BYTES + 1))

        for what, setup in (
            ("symlink", as_symlink),
            ("FIFO", as_fifo),
            ("directory", as_dir),
            ("too big", as_big),
            ("JSON list", lambda: marker.write_text("[]")),
            ("JSON string", lambda: marker.write_text('"x"')),
        ):
            if os.path.lexists(marker):
                if marker.is_dir() and not marker.is_symlink():
                    marker.rmdir()
                else:
                    marker.unlink()
            marker.write_text(good)
            setup()
            rc, ev, _ = self.plain(ctx2)  # a FIFO must not hang the run
            self.assertEqual(rc, 2, what)
            self.assertIn("unreadable owner file", ev, what)
        self.assertEqual(len(self.world.tart_calls("clone")), 1)
        # a marker that is not ours
        from unittest import mock

        if marker.is_dir():
            marker.rmdir()
        else:
            marker.unlink()
        marker.write_text(good)
        with (
            mock.patch.object(drv.os, "getuid", return_value=os.getuid() + 1),
            self.assertRaises(drv.Refusal) as cm,
        ):
            drv.read_owner_raw(marker)
        self.assertIn("not owned by you", str(cm.exception))

    def test_the_lock_directory_must_be_ours_and_not_group_or_world_writable(self):
        self.ctx.lock_path.parent.mkdir(mode=0o700)
        os.chmod(self.ctx.lock_path.parent, 0o777)
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 2)
        self.assertIn("not group or world writable", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        os.chmod(self.ctx.lock_path.parent, 0o700)
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)

    def test_an_owner_file_with_a_different_spelling_of_this_state_dir(self):
        self.run_cmd(*self.golden_args())
        marker = drv.owner_path(self.ctx, GOLDEN)
        alias = self.tmp / "alias"
        alias.symlink_to(self.ctx.state_dir)
        owner = json.loads(marker.read_text())
        owner["state_dir"] = str(
            alias
        )  # another spelling (a symlink) of this directory
        marker.write_text(json.dumps(owner))
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 0, ev)
        self.assertIn("nothing to do", ev)
        # a moved or renamed state dir (the recorded path is gone) is a different owner
        owner["state_dir"] = str(self.tmp / "moved-away")
        marker.write_text(json.dumps(owner))
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2)
        self.assertIn("moved-away", ev)
        self.assertIn("moved or renamed", ev)
        del owner["state_dir"]
        marker.write_text(json.dumps(owner))
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2)
        self.assertIn("no state_dir", ev)

    def test_a_symlinked_and_a_relative_state_dir_are_the_same_owner(self):
        self.run_cmd(*self.golden_args())
        link = self.tmp / "statelink"
        link.symlink_to(self.ctx.state_dir)
        rc, ev, _ = self.plain(self.make_ctx(link, run_id="20261122T000000Z-l"))
        self.assertEqual(rc, 0, ev)
        self.assertIn("nothing to do", ev)
        old = os.getcwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.tmp)
        rc, ev, _ = self.plain(
            self.make_ctx(Path("state"), run_id="20261122T000001Z-r")
        )
        self.assertEqual(rc, 0, ev)
        self.assertIn("nothing to do", ev)

    def test_an_owner_rebuild_refreshes_the_markers_key_and_host_key(self):
        self.run_cmd(*self.golden_args())
        marker = drv.owner_path(self.ctx, GOLDEN)
        first = json.loads(marker.read_text())
        self.world.new_hostkey = OTHER_BLOB
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 0, s)
        now = json.loads(marker.read_text())
        self.assertEqual(now["key_id"], "20261121T000000Z-second")
        self.assertNotEqual(now["host_key"], first["host_key"])
        self.assertEqual(
            now["host_key"],
            "ssh-ed25519 " + drv.fingerprint(f"ssh-ed25519 {OTHER_BLOB}"),
        )
        self.assertEqual(now["state"], "final")

    def test_check_after_another_state_dirs_takeover_exits_2_naming_it(self):
        ctx_a2, ctx_b = self.two_dirs()
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx_b)
        self.assertEqual(rc, 0, s)
        clones = len(self.world.tart_calls("clone"))
        rc, s = self.run_cmd(*self.check_args(), ctx=ctx_a2)
        self.assertEqual(rc, 2)
        self.assertIn(os.path.realpath(ctx_b.state_dir), s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), clones)

    def test_a_golden_whose_key_is_gone_is_rebuilt_without_asking(self):
        def damage():
            shutil.rmtree(self.ctx.state_dir / "keys" / self.ctx.run_id)

        self.rebuilt_unattended(damage)

    def test_a_golden_whose_pinned_known_hosts_is_missing_is_rebuilt_without_asking(
        self,
    ):
        # check refuses on this too, so golden may not call the golden "nothing to do"
        self.rebuilt_unattended((self.ctx.state_dir / "known_hosts").unlink)

    def test_a_golden_whose_known_hosts_has_no_pinned_key_is_rebuilt_without_asking(
        self,
    ):
        self.rebuilt_unattended(
            lambda: (self.ctx.state_dir / "known_hosts").write_text(
                "# nothing pinned\n"
            )
        )

    def test_golden_and_check_share_one_usability_test(self):
        self.run_cmd(*self.golden_args())
        self.assertTrue(drv.golden_usable(self.ctx, GOLDEN))
        (self.ctx.state_dir / "known_hosts").unlink()
        with self.assertRaises(drv.Refusal):
            drv.golden_usable(self.ctx, GOLDEN)
        rc, _ = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)

    def test_a_passphrase_protected_key_is_refused_not_asked_about(self):
        self.run_cmd(*self.golden_args())
        priv = self.ctx.state_dir / "keys" / self.ctx.run_id / "id_ed25519"
        priv.unlink()
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "secret", "-f", str(priv)],
            check=True,
        )
        before = len(self.world.calls)
        with self.assertRaises(drv.Refusal) as cm:
            drv.golden_identity(self.ctx)
        self.assertIn("passphrase", str(cm.exception))
        keygen = [a for a, _ in self.world.calls[before:] if a[0] == "ssh-keygen"]
        self.assertEqual(len(keygen), 1)
        # an empty passphrase on the command line, never a prompt, and no terminal
        self.assertEqual(keygen[0][:5], ["ssh-keygen", "-y", "-P", "", "-f"])
        self.assertIn(keygen[0], self.world.no_tty_calls)

    def test_the_real_runner_can_detach_a_child_from_the_terminal(self):
        # start_new_session: the child leads its own session, so it has no controlling tty
        code = "import os; print(os.getsid(0) == os.getpid())"
        here = drv.RealRunner().run([sys.executable, "-c", code], timeout=30)
        gone = drv.RealRunner().run(
            [sys.executable, "-c", code], timeout=30, no_tty=True
        )
        self.assertEqual(here.stdout.strip(), "False")
        self.assertEqual(gone.stdout.strip(), "True")

    def test_a_failed_build_removes_its_key_unless_kept_for_inspection(self):
        self.world.fail_prep = True
        rc, _ = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.key_dirs(), [])
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id="20261121T000000Z-keep")
        rc, _ = self.run_cmd(*self.golden_args("--keep-on-failure"), ctx=ctx2)
        self.assertEqual(rc, 1)
        self.assertEqual(
            self.key_dirs(), ["20261121T000000Z-keep"]
        )  # the kept build needs it

    def test_a_failed_build_says_when_its_key_could_not_be_removed(self):
        from unittest import mock

        self.world.fail_prep = True
        with mock.patch.object(drv.shutil, "rmtree"):  # a removal that does nothing
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)["cleanup-key"]
        self.assertEqual(st["status"], "fail")
        self.assertIn("still present", st["evidence"])
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])

    def test_a_failed_rebuild_keeps_the_working_goldens_key(self):
        self.run_cmd(*self.golden_args())
        working_blob = self.world.installed_blob
        self.world.fail_prep = True
        ctx2 = self.make_ctx(self.ctx.state_dir, run_id="20261121T000000Z-bad")
        rc, _ = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx2)
        self.assertEqual(rc, 1)
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])  # still the old golden's
        self.world.fail_prep = False
        # the fake has one guest state; the working golden's disk still holds its own key
        self.world.installed_blob = working_blob
        # likewise the failed build's bootstrap state
        self.world.password_login = False
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)

    def test_a_rename_failure_keeps_the_new_key_and_records_it_in_the_pending_file(
        self,
    ):
        self.world.fail_tart = {"rename"}
        rc, _ = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.key_dirs(), [self.ctx.run_id])
        rec = json.loads((self.ctx.state_dir / "golden.json.pending").read_text())
        self.assertEqual(rec["key_id"], self.ctx.run_id)

    def test_prep_must_confirm_the_console_password_rotation(self):
        for n in (0, 2):
            self.world.prep_console_lines = n
            rc, s = self.run_cmd(*self.golden_args())
            self.assertEqual(rc, 1, n)
            self.assertEqual(self.steps(s)["g6"]["status"], "fail", n)
            self.assertIn("console password", self.steps(s)["g6"]["evidence"])
            self.assertFalse((self.ctx.state_dir / "golden.json").exists())

    def test_the_console_password_is_recorded_as_never_stored(self):
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        self.assertIn("never stored", rec["console_password"])
        # the host holds no console password: no file but the minted key is secret material
        files = sorted(p.name for p in self.ctx.state_dir.rglob("*") if p.is_file())
        self.assertEqual(
            sorted(
                set(files)
                - {"known_hosts", "golden.json", "id_ed25519.pub", "id_ed25519"}
            ),
            [],
        )

    # ---- PR 80 round 2 ---------------------------------------------------------------------

    def landing_writes(self, plan, fail=None):
        """Patch atomic_write so the n-th write of a destination name lands, then reports
        that its directory could not be synced. plan: {name: n}; fail: {name: n} writes that
        fail outright."""
        real = drv.atomic_write
        counts = {}

        def wrapper(dest, text, mode=0o600):
            name = Path(dest).name
            counts[name] = counts.get(name, 0) + 1
            if (fail or {}).get(name) == counts[name]:
                raise OSError(28, "No space left on device")
            real(dest, text, mode)
            if plan.get(name) == counts[name]:
                raise drv.LandedNotDurable(5, "Input/output error")

        return mock.patch.object(drv, "atomic_write", wrapper)

    def pending_files(self):
        return sorted(
            p.name
            for d in (self.ctx.state_dir, self.ctx.lock_path.parent)
            for p in d.glob("*.pending")
        )

    def test_each_tart_home_has_its_own_marker_and_a_copied_one_is_refused(self):
        x = os.path.realpath(self.tmp / "tartX")
        y = os.path.realpath(self.tmp / "tartY")
        ctx_x = self.make_ctx(self.ctx.state_dir, "20261120T000000Z-x", tart_home=x)
        ctx_y = self.make_ctx(self.ctx.state_dir, "20261123T000000Z-y", tart_home=y)
        self.assertNotEqual(
            drv.owner_path(ctx_x, GOLDEN), drv.owner_path(ctx_y, GOLDEN)
        )
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx_x)
        self.assertEqual(rc, 0, s)
        marker_x = drv.owner_path(ctx_x, GOLDEN)
        self.assertEqual(json.loads(marker_x.read_text())["tart_home"], x)
        rc, s = self.run_cmd(
            *self.golden_args(),
            ctx=self.make_ctx(ctx_x.state_dir, "20261121T000000Z-x2", tart_home=x),
        )
        self.assertEqual(rc, 0, s)  # the same tart home: nothing to do
        self.assertIn("nothing to do", self.steps(s)["exists"]["evidence"])
        clones = len(self.world.tart_calls("clone"))
        # the same state dir under another tart home sees no marker of its own: exit 2, and
        # the old (unkeyed or other) file is never read
        rc, ev, _ = self.plain(ctx_y)
        self.assertEqual(rc, 2, ev)
        self.assertIn("no owner file", ev)
        self.assertIn("--rebuild", ev)
        # a marker copied or forged under Y's name still names X: refused, naming it
        shutil.copy(marker_x, drv.owner_path(ctx_y, GOLDEN))
        rc, ev, _ = self.plain(ctx_y)
        self.assertEqual(rc, 2, ev)
        self.assertIn("tart home", ev)
        self.assertIn(x, ev)
        rc, s = self.run_cmd(*self.check_args(), ctx=ctx_y)
        self.assertEqual(rc, 2)
        self.assertIn("tart home", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), clones)
        self.assertEqual(self.world.tart_calls("delete"), [])

    def test_the_tart_home_is_resolved_the_way_tart_does(self):
        pw = Path(drv.pwd.getpwuid(os.getuid()).pw_dir)
        self.assertEqual(
            drv.resolve_tart_home({"TART_HOME": "/a/b"}), os.path.realpath("/a/b")
        )
        # set but empty: tart uses it as given, which is the cwd
        self.assertEqual(
            drv.resolve_tart_home({"TART_HOME": ""}), os.path.realpath(os.getcwd())
        )
        self.assertEqual(drv.resolve_tart_home({}), os.path.realpath(pw / ".tart"))
        self.assertEqual(
            drv.resolve_tart_home({"CFFIXED_USER_HOME": "/cf"}),
            os.path.realpath("/cf/.tart"),
        )
        # $HOME is not consulted at all
        self.assertEqual(
            drv.resolve_tart_home({"HOME": str(self.tmp / "fake")}),
            os.path.realpath(pw / ".tart"),
        )
        # an empty CFFIXED_USER_HOME is the cwd, as in Foundation (not the passwd home)
        self.assertEqual(
            drv.resolve_tart_home({"CFFIXED_USER_HOME": ""}),
            os.path.realpath(os.path.join(os.getcwd(), ".tart")),
        )
        # a name that is not UTF-8 still gets a key
        self.assertRegex(drv.tart_key(os.fsdecode(b"/x/\xff/.tart")), r"^[0-9a-f]{8}$")

    def test_a_second_home_of_the_same_user_has_the_same_lock_marker_and_tart_home(
        self,
    ):
        before = drv.Ctx(state_dir=self.tmp / "s")
        fake = self.tmp / "fakehome"
        with mock.patch.dict(os.environ, {"HOME": str(fake)}):
            os.environ.pop("TART_HOME", None)
            under = drv.Ctx(state_dir=self.tmp / "s")
        self.assertEqual(under.tart_home, before.tart_home)
        self.assertEqual(under.lock_path, before.lock_path)
        self.assertEqual(drv.owner_path(under, GOLDEN), drv.owner_path(before, GOLDEN))
        self.assertEqual(before.lock_path.parent, drv.DEFAULT_STATE_DIR)
        self.assertNotIn(str(fake), str(under.lock_path))

    def test_every_tart_call_carries_the_resolved_tart_home(self):
        x = os.path.realpath(self.tmp / "tartX")
        ctx = self.make_ctx(self.ctx.state_dir, "20261120T000000Z-x", tart_home=x)
        with mock.patch.dict(os.environ, {"TART_HOME": "/somewhere/else"}):
            rc, s = self.run_cmd(*self.golden_args(), ctx=ctx)
            self.assertEqual(rc, 0, s)
            rc, s = self.run_cmd(
                *self.check_args(),
                ctx=self.make_ctx(ctx.state_dir, "20261121T000000Z-c", tart_home=x),
            )
            self.assertEqual(rc, 0, s)
        tart = [(a, e) for a, e in self.world.calls if a[0] == "tart"]
        self.assertTrue(any(a[1] == "run" for a, _ in tart))  # `tart run` (start) too
        self.assertTrue(any(a[1] == "clone" for a, _ in tart))
        for argv, env in tart:
            self.assertIsNotNone(env, argv)
            self.assertEqual(env["TART_HOME"], x, argv)

    def test_a_golden_that_appears_during_the_build_is_never_deleted_without_rebuild(
        self,
    ):
        real = self.world.run
        build = f"{GOLDEN}-build"

        def appears(argv, **kw):
            res = real(argv, **kw)
            if argv[:2] == ["tart", "clone"] and argv[-1] == build:
                # a hand `tart rename`, or a driver under another TART_HOME
                self.world.vms[GOLDEN] = {"Running": False}
            return res

        with mock.patch.object(self.world, "run", appears):
            rc, ev, _ = self.plain(self.ctx)
        self.assertEqual(rc, 2, ev)
        self.assertIn("nothing was replaced", ev)
        self.assertNotIn(["tart", "delete", GOLDEN], [c for c, _ in self.world.calls])
        self.assertNotIn(
            ["tart", "rename", build, GOLDEN], [c for c, _ in self.world.calls]
        )
        self.assertIn(GOLDEN, self.world.vms)
        self.assertFalse(self.owner_file().exists())  # no intent marker was written
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())
        # asked for by name it replaces it
        self.world.vms.pop(GOLDEN)
        self.world.vms.pop(build, None)
        with mock.patch.object(self.world, "run", appears):
            rc, s = self.run_cmd(
                *self.golden_args("--rebuild"), ctx=self.second_run_ctx()
            )
        self.assertEqual(rc, 0, s)
        self.assertIn(["tart", "delete", GOLDEN], [c for c, _ in self.world.calls])

    # ---- PR 80 round 3 --------------------------------------------------------------------

    def test_a_marker_without_a_tart_home_is_refused_with_the_true_reason(self):
        self.run_cmd(*self.golden_args())
        drop_tart_home(self.ctx)
        clones = len(self.world.tart_calls("clone"))
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2, ev)
        self.assertIn("has no tart_home", ev)
        self.assertIn("earlier build of this change", ev)
        self.assertIn("--rebuild", ev)
        self.assertNotIn("None", ev)
        self.assertEqual(len(self.world.tart_calls("clone")), clones)
        self.assertEqual(self.world.tart_calls("delete"), [])

    def test_the_recheck_refuses_when_the_marker_names_another_state_dir(self):
        # B took the golden over, it was then deleted by hand, A still has its old record, and
        # a golden appears during A's build: the owner answer, not only "no record", decides
        self.run_cmd(*self.golden_args())
        other = self.tmp / "stateB"
        other.mkdir(mode=0o700)
        owner = json.loads(self.owner_file().read_text())
        owner["state_dir"] = str(other)
        self.owner_file().write_text(json.dumps(owner))
        self.world.vms.pop(GOLDEN)
        real = self.world.run
        build = f"{GOLDEN}-build"

        def appears(argv, **kw):
            res = real(argv, **kw)
            if argv[:2] == ["tart", "clone"] and argv[-1] == build:
                self.world.vms[GOLDEN] = {"Running": False}
            return res

        with mock.patch.object(self.world, "run", appears):
            rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2, ev)
        self.assertIn(str(other), ev)
        self.assertIn("nothing was replaced", ev)
        self.assertIn(GOLDEN, self.world.vms)
        self.assertNotIn(["tart", "delete", GOLDEN], [c for c, _ in self.world.calls])

    def appears_after_the_intent(self):
        """Patch atomic_write so the golden shows up right after the intent owner file."""
        real = drv.atomic_write
        seen = []

        def wrapper(dest, text, mode=0o600):
            real(dest, text, mode)
            if Path(dest).name == self.owner_file().name and not seen:
                seen.append(text)  # the intent file is down: now the golden shows up
                self.world.vms[GOLDEN] = {"Running": False}

        return mock.patch.object(drv, "atomic_write", wrapper)

    def check_late_appearance(self, s, since=0):
        build = f"{GOLDEN}-build"
        self.assertEqual(s["ok"], False)
        ev = " | ".join(x["evidence"] for x in s["steps"])
        self.assertIn("appeared after the owner check", ev)
        self.assertIn("--rebuild", ev)
        self.assertIn("no records were parked", ev)
        self.assertIn("sweeps it", ev)
        calls = [c for c, _ in self.world.calls[since:]]
        self.assertNotIn(["tart", "delete", GOLDEN], calls)
        self.assertNotIn(["tart", "rename", build, GOLDEN], calls)
        self.assertIn(GOLDEN, self.world.vms)
        self.assertIn(build, self.world.vms)  # the finished build is kept
        # no marker blesses a golden nobody checked: the intent file stays
        self.assertEqual(
            json.loads(self.owner_file().read_text())["state"], "committing"
        )

    def test_a_golden_that_appears_after_the_recheck_is_kept_and_so_is_the_build(self):
        with self.appears_after_the_intent():
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        self.check_late_appearance(s)
        self.assertFalse((self.ctx.state_dir / "golden.json").exists())
        # the next plain golden refuses (this state dir has no record of that golden)
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2, ev)
        self.assertIn("--rebuild", ev)

    def test_a_late_golden_does_not_restore_a_previous_final_marker(self):
        self.run_cmd(*self.golden_args())
        self.assertEqual(json.loads(self.owner_file().read_text())["state"], "final")
        self.world.vms.pop(
            GOLDEN
        )  # deleted by hand; the final marker and record remain
        since = len(self.world.calls)
        with self.appears_after_the_intent():
            rc, s = self.run_cmd(*self.golden_args(), ctx=self.second_run_ctx())
        self.assertEqual(rc, 1, s)
        self.check_late_appearance(s, since)
        # the next plain golden must not say "nothing to do" over a golden nobody checked
        rc, ev, _ = self.plain(self.second_run_ctx("20261123T000000Z-next"))
        self.assertEqual(rc, 2, ev)
        self.assertNotIn("nothing to do", ev)

    def test_a_marker_state_dir_with_control_characters_is_refused_and_printed_safely(
        self,
    ):
        self.run_cmd(*self.golden_args())
        bad = "/tmp/x\x1b[31m\nfake: ok"
        owner = json.loads(self.owner_file().read_text())
        owner["state_dir"] = bad
        self.owner_file().write_text(json.dumps(owner))
        self.assertFalse(drv.same_state_dir(self.ctx, bad))
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2, ev)
        self.assertIn("absolute printable path", ev)
        self.assertIn(repr(bad), ev)
        self.assertNotIn("\x1b", ev)
        self.assertNotIn("\n", ev)
        # a marker of another state dir with such a name is no better: check refuses too
        rc, s = self.run_cmd(
            *self.check_args(), ctx=self.second_run_ctx("20261122T000000Z-c")
        )
        self.assertEqual(rc, 2)
        cev = s["steps"][-1]["evidence"]
        self.assertIn("absolute printable path", cev)
        self.assertNotIn("\x1b", cev)

    def test_a_state_dir_is_resolved_once_and_its_parents_are_made_0700(self):
        # missing parents are made 0700 whatever the umask
        deep = self.tmp / "a" / "b" / "c"
        old = os.umask(0)
        try:
            ctx = self.make_ctx(deep, run_id="20261121T000000Z-deep")
            rc, ev, _ = self.plain(ctx)
        finally:
            os.umask(old)
        self.assertEqual(rc, 0, ev)
        for d in (deep, deep.parent, deep.parent.parent):
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700, str(d))
        # a symlink of ours to a directory of ours is the operator's choice: resolved once
        real_dir = self.tmp / "real-dir"
        real_dir.mkdir(mode=0o700)
        link = self.tmp / "link"
        link.symlink_to(real_dir)
        ctx = self.make_ctx(link, run_id="20261121T000000Z-ln")
        self.assertEqual(ctx.state_dir, Path(os.path.realpath(real_dir)))
        link.unlink()  # a later retarget cannot move it
        self.assertEqual(ctx.state_dir, Path(os.path.realpath(real_dir)))
        # a relative path becomes absolute before anything uses it
        back = os.getcwd()
        try:
            os.chdir(self.tmp)
            rel = self.make_ctx(Path("rel-state"), run_id="20261121T000000Z-rel")
        finally:
            os.chdir(back)
        self.assertTrue(rel.state_dir.is_absolute())
        self.assertEqual(rel.state_dir, Path(os.path.realpath(self.tmp / "rel-state")))
        # a symlink to a file is not a state dir
        afile = self.tmp / "afile"
        afile.write_text("x")
        flink = self.tmp / "flink"
        flink.symlink_to(afile)
        rc, ev, _ = self.plain(self.make_ctx(flink, run_id="20261121T000000Z-fl"))
        self.assertEqual(rc, 2, ev)
        self.assertIn("not a directory", ev)

    def test_a_symlink_state_dir_that_dangles_is_refused_and_creates_nothing(self):
        target = self.tmp / "elsewhere" / "target"
        link = self.tmp / "dangling"
        link.symlink_to(target)
        for cmd in (self.golden_args(), self.check_args()):
            rc, s = self.run_cmd(*cmd, ctx=self.make_ctx(link, "20261121T000000Z-dg"))
            self.assertEqual(rc, 2, s)
            self.assertIn("points nowhere", s["steps"][-1]["evidence"])
        self.assertFalse(target.exists())
        self.assertFalse(target.parent.exists())
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_the_account_home_falls_back_to_home_only_without_a_passwd_entry(self):
        pw = drv.pwd.getpwuid(os.getuid()).pw_dir
        self.assertEqual(drv.account_home({"HOME": "/ignored"}), pw)
        with mock.patch.object(drv.pwd, "getpwuid", side_effect=KeyError("uid")):
            self.assertEqual(drv.account_home({"HOME": "/h"}), "/h")
            self.assertEqual(drv.account_home({}), "/")
            self.assertEqual(
                drv.resolve_tart_home({"HOME": "/h"}), os.path.realpath("/h/.tart")
            )
            ctx = self.make_ctx(self.tmp / "nopw", "20261121T000000Z-np")
        self.assertTrue(ctx.tart_home)  # no traceback for a uid without a passwd entry

    def test_a_dangling_link_planted_right_after_the_realpath_is_still_refused(self):
        link = self.tmp / "late-link"
        target = self.tmp / "late-parent" / "target"
        real_rp = os.path.realpath

        def plant_after(path, *a, **kw):
            res = real_rp(path, *a, **kw)
            if os.fspath(path) == str(link) and not link.is_symlink():
                link.symlink_to(target)  # the planter wins the window
            return res

        with mock.patch.object(drv.os.path, "realpath", plant_after):
            ctx = self.make_ctx(link, "20261121T000000Z-lw")
        self.assertIn("points nowhere", ctx.state_dir_refusal)
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx)
        self.assertEqual(rc, 2, s)
        self.assertFalse(target.parent.exists())

    def test_a_link_planted_at_the_resolved_state_dir_is_not_followed(self):
        real_dir = self.tmp / "planted-real"
        real_dir.mkdir(mode=0o700)
        path = self.tmp / "fresh-state"
        ctx = self.make_ctx(
            path, "20261121T000000Z-pl"
        )  # missing: nothing to refuse yet
        self.assertEqual(ctx.state_dir_refusal, "")
        path.symlink_to(real_dir)  # planted between startup and the check
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx)
        self.assertEqual(rc, 2, s)
        self.assertIn("not a directory", s["steps"][-1]["evidence"])
        self.assertEqual(list(real_dir.iterdir()), [])

    def test_a_lock_directory_that_cannot_be_made_is_a_clean_refusal(self):
        blocker = self.tmp / "blocker"
        blocker.write_text("a file")
        ctx = self.make_ctx(self.tmp / "state-x", "20261121T000000Z-lk")
        ctx.lock_path = blocker / "sub" / "driver.lock"
        for cmd in (self.golden_args(), self.check_args()):
            rc, s = self.run_cmd(*cmd, ctx=ctx)
            self.assertEqual(rc, 2, s)
            ev = s["steps"][-1]["evidence"]
            self.assertIn("cannot create the lock directory", ev)
            self.assertIn(str(blocker), ev)

    def test_a_symlink_state_dir_that_is_not_ours_is_refused(self):
        real_dir = self.tmp / "theirs"
        real_dir.mkdir(mode=0o700)
        link = self.tmp / "foreign"
        link.symlink_to(real_dir)
        # the link's owner is "someone else" for the Ctx that reads it (the caller's own
        # identity stays real: a uid with no passwd entry would break the tart home lookup)
        real_lstat = os.lstat

        def foreign_lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            if os.fspath(path) == str(link):
                fields = list(st)
                fields[stat.ST_UID] = st.st_uid + 1
                return os.stat_result(fields)
            return st

        with mock.patch.object(drv.os, "lstat", foreign_lstat):
            ctx = self.make_ctx(link, "20261121T000000Z-fo")
        self.assertIn("not you", ctx.state_dir_refusal)
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx)
        self.assertEqual(rc, 2, s)
        self.assertIn("refusing to follow", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(list(real_dir.iterdir()), [])  # nothing written into it

    def test_full_fsync_falls_back_only_when_the_filesystem_cannot_do_it(self):
        f = self.tmp / "ff"
        f.write_text("x")
        fd = os.open(f, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        for code in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL, errno.ENOTTY):
            with (
                mock.patch.object(drv, "F_FULLFSYNC", 51),
                mock.patch.object(drv.fcntl, "fcntl", side_effect=OSError(code, "no")),
                mock.patch.object(drv.os, "fsync") as fs,
            ):
                drv.full_fsync(fd)
            self.assertEqual(fs.call_count, 1, errno.errorcode[code])
        with (
            mock.patch.object(drv, "F_FULLFSYNC", 51),
            mock.patch.object(
                drv.fcntl, "fcntl", side_effect=OSError(errno.EIO, "EIO")
            ),
            mock.patch.object(drv.os, "fsync") as fs,
            self.assertRaises(OSError) as cm,
        ):
            drv.full_fsync(fd)
        self.assertEqual(cm.exception.errno, errno.EIO)
        self.assertEqual(fs.call_count, 0)  # a failed flush is never reported as done

    @unittest.skipUnless(sys.platform == "darwin", "F_FULLFSYNC is a macOS control")
    def test_the_module_uses_the_real_f_fullfsync_on_macos(self):
        self.assertEqual(drv.F_FULLFSYNC, fcntl.F_FULLFSYNC)

    def test_parked_file_paths_are_shell_quoted(self):
        sd = (
            self.tmp / "my;state"
        )  # ssh paths may not hold whitespace; `;` still needs quoting
        rc, s = self.run_cmd(
            *self.golden_args(), ctx=self.make_ctx(sd, "20261121T000000Z-sp")
        )
        self.assertEqual(rc, 0, s)
        self.world.fail_tart = {"delete"}
        ctx2 = self.make_ctx(sd, "20261122T000000Z-sp2")
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=ctx2)
        self.assertEqual(rc, 1)
        ev = " | ".join(x["evidence"] for x in s["steps"])
        for name in (
            "known_hosts.pending",
            "golden.json.pending",
            "known_hosts",
            "golden.json",
        ):
            self.assertIn(shlex.quote(str(ctx2.state_dir / name)), ev, name)
        self.assertNotIn(f" {ctx2.state_dir}/known_hosts", ev)

    def test_a_parked_file_that_landed_is_parked_not_failed(self):
        self.run_cmd(*self.golden_args())
        self.world.fail_tart = {"delete"}
        with self.landing_writes({"known_hosts.pending": 1}):
            rc, s = self.run_cmd(
                *self.golden_args("--rebuild"), ctx=self.second_run_ctx()
            )
        self.assertEqual(rc, 1)
        ev = " | ".join(x["evidence"] for x in s["steps"])
        self.assertIn("the new record is parked as", ev)
        self.assertNotIn("could not be parked", ev)
        self.assertEqual(
            self.pending_files(),
            [
                drv.owner_path(self.ctx, GOLDEN).name + ".pending",
                "golden.json.pending",
                "known_hosts.pending",
            ],
        )

    def test_a_custom_state_dir_must_be_ours_and_not_group_or_world_writable(self):
        sd = self.tmp / "custom"
        for mode in (0o777, 0o775, 0o757):
            sd.mkdir(exist_ok=True)
            os.chmod(sd, mode)
            ctx = self.make_ctx(sd, run_id="20261121T000000Z-sd")
            rc, ev, _ = self.plain(ctx)
            self.assertEqual(rc, 2, oct(mode))
            self.assertIn("not group or world writable", ev)
            self.assertIn(str(sd), ev)
            self.assertEqual(self.world.tart_calls("clone"), [], oct(mode))
        os.chmod(sd, 0o755)
        rc, ev, _ = self.plain(self.make_ctx(sd, run_id="20261121T000000Z-sd2"))
        self.assertEqual(rc, 0, ev)
        # a state dir the driver makes is 0700, whatever the umask
        fresh = self.tmp / "fresh" / "dir"
        old = os.umask(0)
        try:
            rc, ev, _ = self.plain(self.make_ctx(fresh, run_id="20261121T000000Z-sd3"))
        finally:
            os.umask(old)
        for d in (fresh, fresh.parent):
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700, f"{d}: {ev}")

    def test_a_marker_state_dir_that_is_not_absolute_is_a_torn_or_forged_marker(self):
        self.run_cmd(*self.golden_args())
        good = self.owner_file().read_text()
        owner = json.loads(good)
        owner["state_dir"] = "."
        self.owner_file().write_text(json.dumps(owner))
        old = os.getcwd()
        os.chdir(self.ctx.state_dir)  # "." IS this state dir: it must not count as one
        try:
            self.assertFalse(drv.same_state_dir(self.ctx, "."))
            rc, ev, _ = self.plain(self.second_run_ctx())
            self.assertEqual(rc, 2, ev)
            self.assertIn("absolute printable path", ev)
            rc, s = self.run_cmd(*self.check_args(), ctx=self.second_run_ctx())
            self.assertEqual(rc, 2)
            self.assertIn("absolute printable path", s["steps"][-1]["evidence"])
        finally:
            os.chdir(old)
        self.assertEqual(len(self.world.tart_calls("clone")), 1)

    def test_paths_in_a_suggested_command_are_shell_quoted(self):
        self.run_cmd(*self.golden_args())
        odd = self.tmp / "my state; touch pwned"
        odd.mkdir()
        owner = json.loads(self.owner_file().read_text())
        owner["state_dir"] = str(odd)
        self.owner_file().write_text(json.dumps(owner))
        quoted = shlex.quote(str(odd))
        # a state dir with no record of the golden: the hint names the owner to use
        ctx_c = self.make_ctx(self.tmp / "stateC", run_id="20261121T000000Z-c")
        rc, ev, _ = self.plain(ctx_c)
        self.assertEqual(rc, 2)
        self.assertIn(f"--state-dir {quoted}", ev)
        self.assertNotIn(f"--state-dir {odd}", ev)
        # and check, when this state dir has a record but the marker is final for another
        rc, s = self.run_cmd(*self.check_args(), ctx=self.second_run_ctx())
        self.assertEqual(rc, 2)
        self.assertIn(f"--state-dir {quoted}", s["steps"][-1]["evidence"])

    def test_an_unreadable_marker_is_not_described_as_no_owner_file(self):
        self.run_cmd(*self.golden_args())
        self.owner_file().write_text("not json")
        (self.ctx.state_dir / "golden.json").unlink()
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 2)
        self.assertIn("unreadable", ev)
        self.assertNotIn("(no owner file)", ev)

    def test_atomic_write_reports_a_write_that_landed_when_only_the_directory_sync_fails(
        self,
    ):
        dest = self.tmp / "d" / "f"
        dest.parent.mkdir()
        dest.write_text("old")
        real = drv.full_fsync

        def dir_fails(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "Input/output error")
            real(fd)

        with (
            mock.patch.object(drv, "full_fsync", dir_fails),
            self.assertRaises(drv.LandedNotDurable) as cm,
        ):
            drv.atomic_write(dest, "new")
        self.assertIsInstance(cm.exception, OSError)
        self.assertEqual(dest.read_text(), "new")  # it landed
        self.assertEqual([p.name for p in dest.parent.iterdir()], ["f"])  # no temp left
        # a failure before the replace is a plain OSError and leaves the destination alone
        with (
            mock.patch.object(drv, "full_fsync", side_effect=OSError(5, "EIO")),
            self.assertRaises(OSError) as cm,
        ):
            drv.atomic_write(dest, "newer")
        self.assertNotIsInstance(cm.exception, drv.LandedNotDurable)
        self.assertEqual(dest.read_text(), "new")

    def test_a_landed_intent_write_is_reported_as_landed_and_the_previous_marker_restored(
        self,
    ):
        self.run_cmd(*self.golden_args())
        before = self.owner_file().read_text()
        self.world.vms.pop(f"{GOLDEN}-build", None)
        with self.landing_writes({self.owner_file().name: 1}):
            rc, s = self.run_cmd(
                *self.golden_args("--rebuild"), ctx=self.second_run_ctx()
            )
        self.assertEqual(rc, 1)
        ev = self.steps(s)["g10"]["evidence"]
        self.assertIn("could not be made durable", ev)
        self.assertIn("restored", ev)
        self.assertNotIn("nothing else", ev)
        self.assertEqual(self.owner_file().read_text(), before)
        # the old golden was not touched
        self.assertIn(GOLDEN, self.world.vms)
        self.assertNotIn(["tart", "delete", GOLDEN], [c for c, _ in self.world.calls])

    def test_a_commit_write_that_landed_is_not_called_failed(self):
        with self.landing_writes({"known_hosts": 1}):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        ev = self.steps(s)["g10"]["evidence"]
        self.assertIn("known_hosts landed", ev)
        self.assertIn("known_hosts (landed, durability unconfirmed)", ev)
        self.assertNotIn("writing known_hosts failed", ev)
        self.assertIn("refuses", ev)  # the owner file says the commit did not finish
        # the final owner file landed too: the commit is complete, so a warning step and rc 0
        self.tearDown_world()
        with self.landing_writes({self.owner_file().name: 2}):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        step = self.steps(s)["owner"]
        self.assertEqual(step["status"], "pass")
        self.assertIn("durability unconfirmed", step["evidence"])
        self.assertIn("the commit is complete", step["evidence"])
        self.assertNotIn("refuses", json.dumps(s))
        self.assertEqual(json.loads(self.owner_file().read_text())["state"], "final")
        self.assertEqual(self.pending_files(), [])  # the cleanup ran
        rc, ev, _ = self.plain(self.second_run_ctx())
        self.assertEqual(rc, 0, ev)
        self.assertIn("nothing to do", ev)

    def test_fsync_asks_the_drive_to_flush_on_macos_and_falls_back_to_fsync(self):
        with (
            mock.patch.object(drv, "F_FULLFSYNC", 51),
            mock.patch.object(drv.fcntl, "fcntl") as fc,
            mock.patch.object(drv.os, "fsync", wraps=os.fsync) as fs,
        ):
            drv.atomic_write(self.tmp / "x" / "f", "data")
        self.assertEqual([c.args[1] for c in fc.call_args_list], [51, 51])  # file, dir
        self.assertEqual(fs.call_count, 0)
        with (
            mock.patch.object(drv, "F_FULLFSYNC", 51),
            mock.patch.object(drv.fcntl, "fcntl", side_effect=OSError(25, "ENOTTY")),
            mock.patch.object(drv.os, "fsync", wraps=os.fsync) as fs,
        ):
            drv.atomic_write(self.tmp / "x" / "g", "data")
        self.assertEqual(fs.call_count, 2)
        self.assertEqual((self.tmp / "x" / "g").read_text(), "data")

    def test_a_successful_commit_removes_the_parked_files_of_an_earlier_one(self):
        self.run_cmd(*self.golden_args())
        self.world.fail_tart = {
            "delete"
        }  # the old golden cannot be removed: records parked
        rc, s = self.run_cmd(*self.golden_args("--rebuild"), ctx=self.second_run_ctx())
        self.assertEqual(rc, 1)
        self.assertEqual(
            self.pending_files(),
            [
                drv.owner_path(self.ctx, GOLDEN).name + ".pending",
                "golden.json.pending",
                "known_hosts.pending",
            ],
        )
        self.world.fail_tart = set()
        self.world.vms.pop(f"{GOLDEN}-build", None)
        rc, s = self.run_cmd(
            *self.golden_args("--rebuild"),
            ctx=self.second_run_ctx("20261123T000000Z-x"),
        )
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.pending_files(), [])
        ev = self.steps(s)["pending"]["evidence"]
        for name in ("known_hosts.pending", "golden.json.pending", ".json.pending"):
            self.assertIn(name, ev)
        # a commit with nothing parked says nothing about it
        rc, s = self.run_cmd(
            *self.golden_args("--rebuild"),
            ctx=self.second_run_ctx("20261124T000000Z-y"),
        )
        self.assertEqual(rc, 0, s)
        self.assertNotIn("pending", self.steps(s))

    def test_a_hand_finish_message_is_not_promised_when_parking_failed_too(self):
        patcher, _ = self.failing_writes({"known_hosts": 1, "known_hosts.pending": 1})
        with patcher:
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        ev = self.steps(s)["g10"]["evidence"]
        self.assertIn("could not be parked", ev)
        self.assertNotIn("to finish by hand", ev)


class Check(Base):
    def setUp(self):
        super().setUp()
        self.make_golden()

    def test_happy_path_covers_every_step_and_cleans_up(self):
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)
        self.assertTrue(s["ok"])
        self.assertEqual(s["schema"], drv.SCHEMA)
        for sid in (
            "1", "2a", "2b", "2c", "2d", "2e", "2f", "2g", "2h", "2i", "2j", "2k", "2l",
            "10", "10a", "11",
        ):  # fmt: skip
            self.assertEqual(st[sid]["status"], "pass", (sid, st[sid]))
        self.assertEqual(st["3"]["status"], "skip")
        self.assertIn("needs the renderer slice", st["3"]["evidence"])
        for sid in "456789":
            self.assertEqual(st[sid]["status"], "skip")
            self.assertEqual(st[sid]["evidence"], "SKIP: renderer slice")
        for sid in ("10b", "11a"):
            self.assertEqual(st[sid]["status"], "skip")
            self.assertIn("renderer slice", st[sid]["evidence"])
        self.assertEqual(
            sorted(self.world.vms), [GOLDEN]
        )  # the throwaway clone is gone
        self.assertEqual(self.world.tart_calls("pull"), [])
        clone = s["clone"]
        self.assertEqual(
            self.world.tart_calls("clone"), [["tart", "clone", GOLDEN, clone]]
        )
        clone_env = next(e for a, e in self.world.calls if a[:2] == ["tart", "clone"])
        self.assertEqual(clone_env["TART_NO_AUTO_PRUNE"], "1")
        self.assertEqual(self.world.tart_calls("delete"), [["tart", "delete", clone]])
        # the pinned host key was used strictly, every time, from the state dir
        kh = f"UserKnownHostsFile={self.ctx.state_dir / 'known_hosts'}"
        self.assertTrue(self.world.ssh_calls)
        for argv, _ in self.world.ssh_calls:
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn(kh, argv)
        json.dumps(s)

    def test_summary_file_instead_of_stdout(self):
        out = self.tmp / "summary.json"
        rc, s = self.run_cmd(*self.check_args("--summary", str(out)))
        self.assertEqual(rc, 0)
        self.assertIsNone(s)
        self.assertTrue(json.loads(out.read_text())["ok"])

    def test_sshd_effective_config_accepts_camelcase_and_lowercase_output(self):
        # macOS 27.2 prints CamelCase (the default fake); stock OpenSSH prints lowercase.
        for name, out in (
            ("camelcase", SSHD_CAMEL),
            ("lowercase", SSHD_LOWER),
            ("ascii upper case", SSHD_CAMEL.upper()),  # grep -i accepts it too
            # a line with non-ASCII text elsewhere in the output is just another line
            ("non-ascii line elsewhere", SSHD_CAMEL + "Banner /café\n"),
        ):
            with self.subTest(name):
                self.world.sshd_output = out
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 0, s)
                self.assertEqual(self.steps(s)["2e"]["status"], "pass", name)

    def test_sshd_effective_config_still_fails_on_a_wrong_or_missing_line(self):
        wrong = SSHD_CAMEL.replace(
            "PasswordAuthentication no", "PasswordAuthentication yes"
        )
        # F1 (PR 86 review): a quoted value (Banner, ...) can carry a separator that
        # str.splitlines() honours, so one printed line would fake the wanted one.
        smuggled = [
            (f"smuggled line after U+{ord(sep):04X}", wrong + f"Banner /x{sep}PasswordAuthentication no\n")
            for sep in ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
        ]  # fmt: skip
        cases = (
            ("password login on", wrong, "passwordauthentication no"),
            *((n, o, "passwordauthentication no") for n, o in smuggled),
            # prep.sh's grep -qixF rejects padding and a CR, so the driver does too
            (
                "trailing padding",
                SSHD_CAMEL.replace(
                    "PasswordAuthentication no\n", "PasswordAuthentication no  \n"
                ),
                "passwordauthentication no",
            ),
            (
                "trailing CR",
                SSHD_CAMEL.replace(
                    "PasswordAuthentication no\n", "PasswordAuthentication no\r\n"
                ),
                "passwordauthentication no",
            ),
            (
                "leading space",
                SSHD_CAMEL.replace(
                    "PasswordAuthentication no\n", " PasswordAuthentication no\n"
                ),
                "passwordauthentication no",
            ),
            (
                "option missing",
                SSHD_CAMEL.replace("KbdInteractiveAuthentication no\n", ""),
                "kbdinteractiveauthentication no",
            ),
            (  # a whole-line match: a longer line does not stand in for the wanted one
                "only a longer line",
                SSHD_CAMEL.replace("PermitRootLogin no", "PermitRootLogin no-password"),
                "permitrootlogin no",
            ),
            ("empty output", "", "passwordauthentication no"),
        )
        for name, out, missing in cases:
            with self.subTest(name):
                self.world.sshd_output = out
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)["2e"]
                self.assertEqual(st["status"], "fail", name)
                self.assertIn(missing, st["evidence"], name)

    def test_sshd_effective_config_fails_when_sshd_exits_non_zero_with_good_output(
        self,
    ):
        self.world.sshd_rc = 255
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)["2e"]
        self.assertEqual(st["status"], "fail")
        self.assertIn("rc 255", st["evidence"])
        self.assertIn("missing []", st["evidence"])  # the output alone was fine

    def test_sshd_effective_config_reads_raw_bytes_and_fails_on_any_cr(self):
        # A5 (PR 86 review): in text mode Python turns a lone CR (and CRLF) into "\n" before the
        # matcher runs, so a CR inside a quoted value could fake a line. 2e (and 10a, which
        # reuses it) must run sshd -T with raw_newlines and fail on a CR; the sshd output
        # reaches the matcher through the real runner's decode (a real printf), not the fake's.
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertGreaterEqual(len(self.world.sshd_raw_newlines), 2)  # 2e and 10a
        self.assertTrue(all(self.world.sshd_raw_newlines))
        wrong = SSHD_CAMEL.replace(
            "PasswordAuthentication no", "PasswordAuthentication yes"
        )
        for name, out in (
            ("lone CR smuggles a line", wrong + "Banner /x\rPasswordAuthentication no\n"),
            ("all lines end in CRLF", SSHD_CAMEL.replace("\n", "\r\n")),
            ("one CR in good output", SSHD_CAMEL.replace("UsePAM yes", "UsePAM yes\r")),
        ):  # fmt: skip
            with self.subTest(name):
                self.world.sshd_output = out
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)["2e"]
                self.assertEqual(st["status"], "fail", name)
                self.assertIn("carriage return", st["evidence"], name)

    # -- 2g / 10a: Spotlight off, with a bounded settle (issue 70 run 2)
    def test_2g_waits_out_transitioning_and_records_polls_and_seconds(self):
        self.world.mdutil_outputs = [
            (0, MDUTIL_TRANSITIONING),
            (0, MDUTIL_TRANSITIONING),
        ]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)["2g"]
        self.assertEqual(st["status"], "pass")
        self.assertIn("polls=3 waited=4s", st["evidence"])  # 2 s between polls

    def test_2g_transitioning_until_the_timeout_fails_with_the_last_output(self):
        self.world.mdutil_default = (0, MDUTIL_TRANSITIONING)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)["2g"]
        self.assertEqual(st["status"], "fail")
        self.assertIn("still transitioning", st["evidence"])
        self.assertIn("kMDConfigSearchLevelTransitioning", st["evidence"])
        self.assertIn("polls=61 waited=120s", st["evidence"])  # bounded at 120 s

    def test_2g_never_retries_indexing_enabled_or_other_text_into_a_pass(self):
        for name, first, polls in (
            ("enabled", (0, MDUTIL_ON), 1),
            ("enabled after transitioning", (0, MDUTIL_TRANSITIONING), 2),
            ("non-zero exit", (1, MDUTIL_OFF), 1),
            ("unexpected text", (0, MDUTIL_OFF + "\tSomething else happened\n"), 1),
            ("no state at all", (0, ""), 1),
        ):
            with self.subTest(name):
                self.world.mdutil_outputs = (
                    [first, (0, MDUTIL_ON)] if polls == 2 else [first, (0, MDUTIL_OFF)]
                )
                self.world.mdutil_calls = 0
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)["2g"]
                self.assertEqual(st["status"], "fail", name)
                self.assertIn(f"polls={polls} ", st["evidence"], name)
                self.world.mdutil_outputs = []

    def test_10a_passes_after_a_post_reboot_settle_and_says_how_long_it_took(self):
        # 2g passes at once, then the post-reboot read says Transitioning three times
        self.world.mdutil_outputs = [
            (0, MDUTIL_OFF),
            (0, MDUTIL_TRANSITIONING),
            (0, MDUTIL_TRANSITIONING),
            (0, MDUTIL_TRANSITIONING),
        ]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)
        self.assertIn("polls=1 waited=0s", st["2g"]["evidence"])
        self.assertEqual(st["10a"]["status"], "pass")
        self.assertIn("2g after the reboot: polls=4 waited=6s", st["10a"]["evidence"])

    # -- 2h / 10a: automatic updates off, by what softwareupdate itself says
    def test_2h_passes_on_turned_off_and_does_not_need_the_automaticcheckenabled_key(
        self,
    ):
        self.world.defaults_values["AutomaticCheckEnabled"] = (
            1,
            "",
            "Could not find key 'AutomaticCheckEnabled' in domain 'com.apple.SoftwareUpdate'.",
        )
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)["2h"]
        self.assertEqual(st["status"], "pass")
        self.assertIn("Automatic checking for updates is turned off", st["evidence"])
        self.assertIn("AutomaticDownload=0", st["evidence"])
        self.assertIn("AutomaticallyInstallMacOSUpdates=0", st["evidence"])
        self.assertNotIn("AutomaticCheckEnabled", st["evidence"])
        reads = [
            a[-1] for a, _ in self.world.ssh_calls if "AutomaticCheckEnabled" in a[-1]
        ]
        self.assertEqual(reads, [])  # never read at all

    def test_2h_fails_unless_softwareupdate_says_automatic_checking_is_off(self):
        cases = (
            ("turned on", (0, SU_ON)),
            ("empty answer", (0, "")),
            ("non-zero exit with the right words", (1, SU_OFF)),
            ("both words", (0, SU_OFF + SU_ON)),
            ("something else", (0, "Software Update is disabled\n")),
        )
        for name, answer in cases:
            with self.subTest(name):
                self.world.su_schedule = answer
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)
                self.assertEqual(st["2h"]["status"], "fail", name)
                self.assertIn("schedule rc", st["2h"]["evidence"], name)

    def test_2h_still_needs_download_and_install_to_read_zero(self):
        for key in ("AutomaticDownload", "AutomaticallyInstallMacOSUpdates"):
            with self.subTest(key):
                self.world.defaults_values[key] = (0, "1\n", "")
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)["2h"]
                self.assertEqual(st["status"], "fail")
                self.assertIn(f"{key}=1", st["evidence"])

    def test_10a_reruns_2h_and_reports_a_schedule_that_turned_back_on(self):
        # the golden says "off" at the first read; after the reboot it says "on"
        self.world.su_outputs = [(0, SU_OFF), (0, SU_ON)]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)
        self.assertEqual(st["2h"]["status"], "pass")
        self.assertEqual(st["10a"]["status"], "fail")
        self.assertIn("2h automatic updates off: schedule rc 0", st["10a"]["evidence"])
        self.assertIn("turned on", st["10a"]["evidence"])

    def test_reboot_restarts_tart_run_when_it_exits(self):
        self.world.run_exits_on_reboot = True
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertEqual(len(self.world.tart_calls("run")), 2)

    def test_reboot_proof_is_the_boot_session_uuid_not_the_boot_time_string(self):
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        sysctls = [
            a[-1] for a, _ in self.world.ssh_calls if "sysctl" in shlex.split(a[-1])
        ]
        self.assertTrue(all("kern.bootsessionuuid" in c for c in sysctls))
        self.assertNotIn("kern.boottime", " ".join(sysctls))

    def test_a_guest_that_does_not_really_reboot_fails_step_10(self):
        self.world.reboot_changes_uuid = False
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["10"]["status"], "fail")
        self.assertEqual(st["10a"]["status"], "skip")
        self.assertEqual(st["11"]["status"], "pass")

    def test_a_third_vm_during_the_reboot_refuses_the_restart(self):
        self.world.run_exits_on_reboot = True
        self.world.intruders_on_reboot = 2  # two other VMs grab the licence slots
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["10"]["status"], "fail")
        self.assertIn("restart refused", st["10"]["evidence"])
        self.assertEqual(len(self.world.tart_calls("run")), 1)  # never started a third
        self.assertEqual(st["11"]["status"], "pass")

    def test_tart_run_that_keeps_dying_is_not_restarted_forever(self):
        self.world.die_after_reboot = True
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertIn("not restarting it again", self.steps(s)["10"]["evidence"])
        self.assertEqual(len(self.world.tart_calls("run")), 1 + drv.VM_RESTARTS_MAX)
        self.assertEqual(self.steps(s)["11"]["status"], "pass")

    def test_refuses_at_the_two_vm_cap_without_starting_anything(self):
        self.world.vms["x"] = {"Running": True}
        self.world.vms["y"] = {"Running": True}
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertFalse(s["ok"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])
        self.assertEqual(self.world.tart_calls("delete"), [])

    def test_one_running_vm_is_allowed(self):
        self.world.vms["x"] = {"Running": True}
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertTrue(self.world.vms["x"]["Running"])  # never touched

    def test_refuses_while_golden_itself_is_running(self):
        self.world.vms[GOLDEN]["Running"] = True
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("is running", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_step_failure_still_deletes_the_clone_and_exits_nonzero(self):
        self.world.fail_remote = {"csrutil"}
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["2b"]["status"], "fail")
        self.assertEqual(st["2a"]["status"], "pass")
        self.assertEqual(st["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_screen_sharing_on_fails_2j_and_2k_before_and_after_the_reboot(self):
        self.world.screensharing_on = True
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["2j"]["status"], "fail")
        self.assertEqual(st["2k"]["status"], "fail")
        self.assertIn("5900", st["2k"]["evidence"])
        self.assertEqual(st["10a"]["status"], "fail")  # and again after the reboot
        self.assertIn("2j", st["10a"]["evidence"])

    def test_framework_group_admin_775_fails_the_ownership_assertion(self):
        self.world.fw_owner = FW_PYTHON_ORIGINAL
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["2i"]["status"], "fail")

    def test_ownership_helper_asserts_group_wheel_and_the_whole_tree(self):
        t = vmssh.Target(
            "192.168.64.10",
            str(self.ctx.state_dir / "known_hosts"),
            identity=str(self.ident),
        )
        self.world.last_started = GOLDEN
        self.world.vms[GOLDEN]["Running"] = True
        for owner, tree_ok, want in (
            (FW_PYTHON_FIXED, True, True),
            ("root:admin 755", True, False),  # group is not wheel
            ("root:wheel 775", True, False),  # group writable
            ("admin:wheel 755", True, False),
        ):
            self.world.fw_owner = owner
            ok, ev = drv.check_root_owned(self.ctx, t, "/fw")
            self.assertEqual(ok, want, (owner, ev))
        self.world.fw_owner = FW_PYTHON_FIXED
        ok, ev = drv.check_root_owned(self.ctx, t, "/fw", tree=True)
        self.assertTrue(ok, ev)
        self.assertIn("whole tree", ev)
        self.assertIn("ancestors root-owned", ev)
        # a stat that passes while something below it does not: the tree form catches it
        self.world.fw_owner = "root:wheel 755"
        orig = self.world._guest

        def tree_dirty(r, input_text):
            if r[:3] == ["/bin/sh", "-c", drv.TREE_CHECK_SH]:
                return drv.Result(0, "/fw/lib/x.so\n")
            return orig(r, input_text)

        self.world._guest = tree_dirty
        ok, ev = drv.check_root_owned(self.ctx, t, "/fw", tree=True)
        self.assertFalse(ok)
        self.assertIn("/fw/lib/x.so", ev)

    def test_ownership_helper_checks_every_ancestor_up_to_root(self):
        t = vmssh.Target(
            "192.168.64.10",
            str(self.ctx.state_dir / "known_hosts"),
            identity=str(self.ident),
        )
        self.world.last_started = GOLDEN
        self.world.vms[GOLDEN]["Running"] = True
        self.world.fw_owner = FW_PYTHON_FIXED
        path = f"{FW_ROOT}/Versions/3.14"
        self.assertEqual(
            drv.ancestors_of(path),
            [f"{FW_ROOT}/Versions", FW_ROOT, "/Library/Frameworks", "/Library", "/"],
        )
        ok, ev = drv.check_root_owned(self.ctx, t, path)
        self.assertTrue(ok, ev)
        for parent, bad in (
            (f"{FW_ROOT}/Versions", "root:admin 775"),  # python.org: the BLOCK case
            (FW_ROOT, "root:wheel 775"),
            ("/Library/Frameworks", "admin:wheel 755"),  # not owned by root
            ("/Library", "root:wheel 757"),  # world writable
            ("/", "root:wheel 1777"),  # sticky does not excuse world write
        ):
            self.world.stat_overrides = {parent: bad}
            ok, ev = drv.check_root_owned(self.ctx, t, path)
            self.assertFalse(ok, (parent, bad))
            self.assertIn(f"{parent} {bad}", ev)
        # a stat that cannot report an ancestor fails closed
        self.world.stat_overrides = {}
        orig = self.world._guest

        def silent(r, input_text):
            if r[:3] == ["stat", "-f", "%N %Su:%Sg %Lp"]:
                return drv.Result(1, "", "stat: boom")
            return orig(r, input_text)

        self.world._guest = silent
        ok, ev = drv.check_root_owned(self.ctx, t, path)
        self.assertFalse(ok)

    def test_a_server_that_still_offers_password_login_fails_2f(self):
        self.world.password_login = (
            True  # prepped stays True: the password given is wrong
        )
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["2f"]["status"], "fail")
        self.assertIn("still offers", self.steps(s)["2f"]["evidence"])

    def test_ssh_never_coming_up_fails_step_1_and_cleans_up(self):
        self.world.ssh_never_up = True
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["1"]["status"], "fail")
        self.assertIn("blocked", st)
        self.assertNotIn("2a", st)
        self.assertEqual(st["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_host_key_mismatch_fails_fast(self):
        self.world.hostkeys[GOLDEN] = (
            OTHER_BLOB  # the clone's real key is not the pinned one
        )
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertIn("host key mismatch", self.steps(s)["1"]["evidence"])
        self.assertLess(self.clock.t, 60)  # no five-minute retry loop
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_interrupt_deletes_the_clone(self):
        self.world.interrupt_on = "spctl"
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 130)
        self.assertEqual(self.steps(s)["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_interrupt_during_the_clone_does_not_report_no_clone_was_made(self):
        self.world.interrupt_after_tart = "clone"
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 130)
        st = self.steps(s)
        self.assertEqual(st["11"]["status"], "pass")
        self.assertIn("deleted", st["11"]["evidence"])
        self.assertNotIn("no clone was made", st["11"]["evidence"])
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_a_real_sigterm_deletes_the_clone_and_exits_130(self):
        self.world.signal_on = "spctl"
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 130)
        self.assertIn("SIGTERM", self.steps(s)["interrupted"]["evidence"])
        self.assertEqual(self.steps(s)["11"]["status"], "pass")
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_cleanup_failure_fails_step_11_and_the_run(self):
        self.world.fail_tart = {"delete"}
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["11"]["status"], "fail")
        self.assertFalse(s["ok"])

    def test_sweeps_a_clone_left_by_an_interrupted_run(self):
        self.world.vms[drv.CHECK_PREFIX + "old"] = {"Running": True}
        self.world.procs[drv.CHECK_PREFIX + "old"] = FakeProc(self.world, "x")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertEqual(sorted(self.world.vms), [GOLDEN])
        self.assertIn(drv.CHECK_PREFIX + "old", self.steps(s)["preflight"]["evidence"])

    def test_check_hints_depend_on_who_owns_the_golden(self):
        good_rec = (self.ctx.state_dir / "golden.json").read_text()
        # no record, no owner file (pre-change golden, or another state dir's, unknown):
        # plain `golden` refuses it, so the hint names --rebuild and says what it replaces
        (self.ctx.state_dir / "golden.json").unlink()
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn("no record of the golden", ev)
        self.assertIn("`golden --rebuild`", ev)
        self.assertIn("no owner file", ev)
        # no record, and the owner file names ANOTHER state dir: it is named, and the hint says
        # that --rebuild here breaks its logins
        other = self.tmp / "elsewhere"
        other.mkdir()
        write_marker(self.ctx, state_dir=str(other))
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn(str(other), ev)
        self.assertIn("break", ev)
        self.assertEqual(self.world.tart_calls("clone"), [])
        # a record, a final marker that is ours and agrees: plain `golden` rebuilds it
        (self.ctx.state_dir / "golden.json").write_text(good_rec)
        write_marker(self.ctx)
        (self.ctx.state_dir / "known_hosts").unlink()
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("run `golden` (it rebuilds", s["steps"][-1]["evidence"])
        # a record but no owner file: `golden` would refuse, the hint says so
        drv.owner_path(self.ctx, GOLDEN).unlink()
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn("`golden` will refuse", ev)
        self.assertIn("no owner file", ev)

    def test_known_hosts_must_be_exactly_the_one_line_the_driver_writes(self):
        kh = self.ctx.state_dir / "known_hosts"
        canon = f"{vmssh.HOST_ALIAS} ssh-ed25519 {NEW_BLOB}\n"
        self.assertEqual(kh.read_text(), canon)
        self.assertTrue(drv.golden_usable(self.ctx, GOLDEN))
        bad = {
            "an extra line": canon + f"{vmssh.HOST_ALIAS} ssh-ed25519 {OTHER_BLOB}\n",
            "a line before it": f"other ssh-ed25519 {OTHER_BLOB}\n" + canon,
            "a pattern list": f"{vmssh.HOST_ALIAS},x ssh-ed25519 {NEW_BLOB}\n",
            "a wildcard": f"* ssh-ed25519 {NEW_BLOB}\n" + canon,
            "a hashed name": f"|1|abc=|def= ssh-ed25519 {NEW_BLOB}\n" + canon,
            "a cert authority": f"@cert-authority * ssh-ed25519 {OTHER_BLOB}\n" + canon,
            "a revoked key": f"@revoked {vmssh.HOST_ALIAS} ssh-ed25519 {OTHER_BLOB}\n"
            + canon,
            "junk base64": f"{vmssh.HOST_ALIAS} ssh-ed25519 {NEW_BLOB}!!\n",
            "a comment": f"{vmssh.HOST_ALIAS} ssh-ed25519 {NEW_BLOB} comment\n",
            "no newline": canon.rstrip("\n"),
            "crlf": canon.replace("\n", "\r\n"),
        }
        for what, text in bad.items():
            kh.write_text(text)
            with self.assertRaises(drv.Refusal, msg=what):
                drv.golden_usable(self.ctx, GOLDEN)
            rc, s = self.run_cmd(*self.check_args())
            self.assertEqual(rc, 2, what)
            self.assertIn("--rebuild", s["steps"][-1]["evidence"], what)
            self.assertEqual(self.world.tart_calls("clone"), [], what)
        # the single-line refusal says why
        kh.write_text(bad["an extra line"])
        with self.assertRaises(drv.Refusal) as cm:
            drv.golden_usable(self.ctx, GOLDEN)
        self.assertIn("single", str(cm.exception))

    def test_refuses_without_golden_or_pinned_key_or_identity(self):
        del self.world.vms[GOLDEN]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("golden", s["steps"][-1]["evidence"])
        self.world.vms[GOLDEN] = {"Running": False}
        (self.ctx.state_dir / "known_hosts").unlink()
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_check_refuses_without_the_goldens_key(self):
        priv = Path(self.ident)
        rec_path = self.ctx.state_dir / "golden.json"
        good = rec_path.read_text()

        def refused(want):
            rc, s = self.run_cmd(*self.check_args())
            self.assertEqual(rc, 2, want)
            self.assertIn(want, s["steps"][-1]["evidence"])

        rec_path.unlink()
        refused("no usable golden record")
        # an id that tries to leave the keys directory
        rec_path.write_text(self.record_json("../../etc", "SHA256:x"))
        refused("unsafe key id")
        # a record for a key that is not there
        rec_path.write_text(self.record_json("nope", "SHA256:x"))
        refused("is missing")
        # the right key but a wrong fingerprint in the record
        rec_path.write_text(self.record_json(self.golden_key_id, "SHA256:wrong"))
        refused("does not belong to this golden")
        # a private key other users can read
        rec_path.write_text(good)
        os.chmod(priv, 0o644)
        refused("mode 0600")
        # a symlinked private key
        os.chmod(priv, 0o600)
        real = priv.with_name("real")
        priv.rename(real)
        priv.symlink_to(real)
        refused("not a regular file")
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])

    def test_check_logs_in_with_the_minted_key_only(self):
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        offered = {
            argv[argv.index("-i") + 1]
            for argv, _ in self.world.ssh_calls
            if "-i" in argv
        }
        self.assertEqual(offered, {self.ident})
        for argv, _ in self.world.ssh_calls:
            if "-i" in argv:  # the password-refusal probe has no identity at all
                self.assertIn("IdentityAgent=none", argv)  # never the operator's agent

    def test_check_refuses_a_swapped_private_key(self):
        other = self.tmp / "other-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)],
            check=True,
        )
        shutil.copyfile(other, self.ident)  # keeps the 0600 of the target
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("does not belong to this golden", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_check_refuses_symlinks_and_loose_modes_above_the_key(self):
        keys = self.ctx.state_dir / "keys"
        kid = keys / self.golden_key_id

        def refused(want):
            rc, s = self.run_cmd(*self.check_args())
            self.assertEqual(rc, 2, want)
            self.assertIn(want, s["steps"][-1]["evidence"])
            self.assertEqual(self.world.tart_calls("clone"), [])

        # the key directory is a symlink to somewhere else holding a real, matching key
        elsewhere = self.tmp / "elsewhere"
        kid.rename(elsewhere)
        kid.symlink_to(elsewhere)
        refused("real directory")
        kid.unlink()
        elsewhere.rename(kid)
        # the keys directory itself is a symlink
        moved = self.tmp / "moved-keys"
        keys.rename(moved)
        keys.symlink_to(moved)
        refused("real directory")
        keys.unlink()
        moved.rename(keys)
        # group/world access on either directory
        os.chmod(kid, 0o750)
        refused("no group or world access")
        os.chmod(kid, 0o700)
        os.chmod(keys, 0o755)
        refused("no group or world access")
        os.chmod(keys, 0o700)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)  # restored: it passes again

    def test_check_never_offers_a_key_through_a_link_to_another_directory(self):
        # the operator-key scenario: the record names the fingerprint of a key that lives
        # elsewhere, and the key directory is a link to it
        elsewhere = self.tmp / "operators-dir"
        elsewhere.mkdir(mode=0o700)
        key = str(elsewhere / "id_ed25519")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True
        )
        fp = drv.fingerprint((elsewhere / "id_ed25519.pub").read_text())
        kid = self.ctx.state_dir / "keys" / "linked-id"
        kid.symlink_to(elsewhere)
        (self.ctx.state_dir / "golden.json").write_text(
            self.record_json("linked-id", fp)
        )
        rc, _ = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertEqual(self.world.ssh_calls, [])  # nothing was ever offered

    def test_the_key_and_its_directories_must_be_owned_by_the_caller(self):
        from unittest import mock

        with (
            mock.patch.object(drv.os, "getuid", return_value=os.getuid() + 1),
            self.assertRaises(drv.Refusal) as cm,
        ):
            drv.golden_identity(self.ctx)
        self.assertIn("owned by you", str(cm.exception))
        self.assertEqual(drv.golden_identity(self.ctx), self.ident)

    def test_2l_console_password_must_not_be_the_vanilla_one(self):
        self.world.console_pw_default = True  # 'admin' still authenticates
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["2l"]["status"], "fail")
        self.assertEqual(self.steps(s)["10a"]["status"], "fail")  # and after the reboot

    def test_2l_only_the_wrong_password_code_counts(self):
        generic = "Authentication for node /Local/Default failed. ({code}, {name})\n"
        refused_cases = {
            "record not found": (14, generic.format(code=-14136, name="eDSRecordNotFound")),
            "account disabled": (14, generic.format(code=-14167, name="eDSAuthAccountDisabled")),
            "password expired": (14, generic.format(code=-14170, name="eDSAuthPasswordExpired")),
            "read-style message": (
                1, "<main> attribute status: eDSRecordNotFound\nInvalid Path",
            ),
            "no output": (14, ""),
            "unparseable": (14, "Segmentation fault: 11"),
            "two codes": (
                14,
                generic.format(code=-14090, name="eDSAuthFailed")
                + generic.format(code=-14167, name="eDSAuthAccountDisabled"),
            ),
            "right number, wrong name": (14, generic.format(code=-14090, name="eDSNotAuthorized")),
            "another eDS name beside the pair": (
                14,
                generic.format(code=-14090, name="eDSAuthFailed")
                + "<main> attribute status: eDSRecordNotFound\n",
            ),
            "ssh's own failure": (255, generic.format(code=-14090, name="eDSAuthFailed")),
        }  # fmt: skip
        for label, (rc_, text) in refused_cases.items():
            with self.subTest(label):
                self.world.dscl_error, self.world.dscl_rc = text, rc_
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, label)
                self.assertEqual(self.steps(s)["2l"]["status"], "fail", label)
        for label, text in {
            "generic form": generic.format(code=-14090, name="eDSAuthFailed"),
            "dscl_cmd form": "<dscl_cmd> DS Error: -14090 (eDSAuthFailed)\n",
        }.items():
            with self.subTest(label):
                self.world.dscl_error, self.world.dscl_rc = text, 14
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 0, (label, s))
                self.assertEqual(self.steps(s)["2l"]["status"], "pass", label)

    def test_2l_asks_dscl_without_sudo(self):
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        asked = [
            a
            for a, _ in self.world.calls
            if a[0] == "ssh" and "dscl" in shlex.split(a[-1])
        ]
        self.assertTrue(asked)
        for a in asked:
            self.assertEqual(
                shlex.split(a[-1]), ["dscl", ".", "-authonly", "admin", "admin"]
            )

    def test_a_second_driver_is_refused_while_the_lock_is_held(self):
        with drv.driver_lock(self.ctx):
            rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("lock", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_the_lock_is_host_wide_whatever_state_dir_says(self):
        other = self.make_ctx(
            self.tmp / "other-state"
        )  # same lock path, other state dir
        other.run_id = "20261120T000000Z-other"
        # no golden record in the other state dir: the lock refuses before it is read
        with drv.driver_lock(self.ctx):
            rc, s = self.run_cmd(
                *self.check_args("--state-dir", str(other.state_dir)), ctx=other
            )
        self.assertEqual(rc, 2)
        self.assertIn("lock", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        # and the default lock path does not depend on the state dir at all
        a, b = drv.Ctx(state_dir=Path("/x/a")), drv.Ctx(state_dir=Path("/x/b"))
        self.assertEqual(a.lock_path, b.lock_path)
        # one fixed file under the passwd home, the name master uses, whatever the tart home
        self.assertEqual(a.lock_path, drv.DEFAULT_STATE_DIR / "driver.lock")
        c = drv.Ctx(state_dir=Path("/x/a"), tart_home="/some/other/.tart")
        self.assertNotEqual(c.tart_home, a.tart_home)
        self.assertEqual(c.lock_path, a.lock_path)
        # while the marker is per tart home
        self.assertNotEqual(drv.owner_path(c, GOLDEN), drv.owner_path(a, GOLDEN))

    def test_the_default_state_dir_is_the_passwd_homes_whatever_home_says(self):
        fake = self.tmp / "fakehome"
        r = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                (
                    "import sys; sys.path.insert(0, sys.argv[1]); import state1_vm; "
                    "print(state1_vm.DEFAULT_STATE_DIR)"
                ),
                str(drv.HERE),
            ],
            env={**os.environ, "HOME": str(fake)},
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=True,
        )
        pw = drv.pwd.getpwuid(os.getuid()).pw_dir
        self.assertEqual(
            r.stdout.strip(), str(Path(pw) / ".local" / "state" / "tendcf-state1-vm")
        )
        self.assertNotIn(str(fake), r.stdout)

    def test_the_lock_never_follows_a_symlink(self):
        victim = self.tmp / "victim"
        victim.write_text("precious")
        self.ctx.lock_path.parent.mkdir(parents=True)
        self.ctx.lock_path.symlink_to(victim)
        with self.assertRaises(drv.Refusal), drv.driver_lock(self.ctx):
            pass
        self.assertEqual(victim.read_text(), "precious")

    # ---- PR 80 round 2 ---------------------------------------------------------------------

    def test_check_lets_the_login_decide_on_another_dirs_unfinished_commit(self):
        other = self.tmp / "elsewhere"
        other.mkdir()
        # B's takeover stopped before it touched the golden: it is still ours, and the login
        # proves it; the marker only becomes an evidence line
        write_marker(self.ctx, state_dir=str(other), state="committing")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertIn(
            "did not finish; the golden is the old or the new build",
            self.steps(s)["owner"]["evidence"],
        )
        self.assertIn(str(other), self.steps(s)["owner"]["evidence"])
        clones = len(self.world.tart_calls("clone"))
        self.assertEqual(clones, 1)
        # a FINAL marker of another state dir still refuses before any clone
        write_marker(self.ctx, state_dir=str(other))
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("owned by state dir", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), clones)

    def test_check_refuses_a_final_marker_of_this_dir_with_another_key(self):
        write_marker(self.ctx, key_id="20261120T000000Z-someone-else")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn("another golden of this state dir's", ev)
        self.assertIn("golden --rebuild", ev)
        self.assertEqual(self.world.tart_calls("clone"), [])
        # the same key: it goes on to the login
        write_marker(self.ctx)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)

    def test_check_refuses_a_final_marker_written_for_another_tart_home(self):
        write_marker(self.ctx, tart_home="/nowhere/else/.tart")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn("tart home", ev)
        self.assertIn("/nowhere/else/.tart", ev)
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_check_notes_this_dirs_own_unfinished_commit_and_lets_the_login_decide(
        self,
    ):
        write_marker(self.ctx, state="committing")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["owner"]["evidence"]
        self.assertIn("a commit by this state dir", ev)
        self.assertIn("did not finish; the golden is the old or the new build", ev)
        self.assertEqual(len(self.world.tart_calls("clone")), 1)

    def test_check_refuses_a_final_marker_without_a_tart_home_and_does_not_blame_ssh(
        self,
    ):
        write_marker(self.ctx)
        drop_tart_home(self.ctx)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        ev = s["steps"][-1]["evidence"]
        self.assertIn("has no tart_home", ev)
        self.assertIn("golden --rebuild", ev)
        self.assertNotIn("would fail at ssh", ev)
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_check_refuses_a_state_dir_others_can_write(self):
        os.chmod(self.ctx.state_dir, 0o777)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("not group or world writable", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])


class RawNewlines(unittest.TestCase):
    """A5 (PR 86 review): the real runner, with real local commands, no fake world."""

    PRINTF = "/usr/bin/printf"

    def printf(self, text, **kw):
        return drv.RealRunner().run([self.PRINTF, "%s", text], timeout=30, **kw)

    def test_default_still_translates_newlines_and_raw_does_not(self):
        r = drv.RealRunner().run([self.PRINTF, "a\\rb\\r\\n"], timeout=30)
        self.assertEqual(r.stdout, "a\nb\n")  # the default is unchanged
        r = drv.RealRunner().run(
            [self.PRINTF, "a\\rb\\r\\n"], timeout=30, raw_newlines=True
        )
        self.assertEqual((r.rc, r.stdout), (0, "a\rb\r\n"))

    def test_raw_decodes_utf8_with_replacement_and_passes_input_through(self):
        r = drv.RealRunner().run([self.PRINTF, "\\377x"], timeout=30, raw_newlines=True)
        self.assertEqual(r.stdout, "�x")
        r = drv.RealRunner().run(
            ["/bin/cat"], input_text="x\r\ny\r", timeout=30, raw_newlines=True
        )
        self.assertEqual(r.stdout, "x\r\ny\r")

    def test_2e_matcher_on_real_runner_output(self):
        wrong = SSHD_CAMEL.replace(
            "PasswordAuthentication no", "PasswordAuthentication yes"
        )
        smuggled = wrong + "Banner /x\rPasswordAuthentication no\n"
        # the real, observed CamelCase output passes, raw or not
        for raw in (True, False):
            ok, ev = drv.sshd_key_only(self.printf(SSHD_CAMEL, raw_newlines=raw))
            self.assertTrue(ok, ev)
        # a CR-smuggled line and a trailing CR fail on the raw bytes ...
        for name, text in (
            ("smuggled", smuggled),
            ("trailing CR", SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication no\r\n")),
        ):  # fmt: skip
            ok, ev = drv.sshd_key_only(self.printf(text, raw_newlines=True))
            self.assertFalse(ok, (name, ev))
            self.assertIn("carriage return", ev)
        # ... while the default runner's decode would have shown the matcher a fake line
        ok, _ = drv.sshd_key_only(self.printf(smuggled))
        self.assertTrue(ok, "the default decode turns the CR into a newline")


class DsclCodes(unittest.TestCase):
    def test_only_the_exact_wrong_password_result_is_accepted(self):
        ok = (
            "Authentication for node /Local/Default failed. (-14090, eDSAuthFailed)",
            "<dscl_cmd> DS Error: -14090 (eDSAuthFailed)",
            "<dscl_cmd> DS Error: -14090 (eDSAuthFailed)\n(-14090, eDSAuthFailed)",
        )
        bad = (
            "",
            "authentication failed",
            "Authentication for node /Local/Default failed. (-14136, eDSRecordNotFound)",
            "(-14167, eDSAuthAccountDisabled)",
            "(-14090, eDSAuthFailed)\n(-14167, eDSAuthAccountDisabled)",
            "(-14090, eDSNotAuthorized)",
            "DS Error: -14091 (eDSAuthFailed)",
            # the one wrong-password pair plus any other eDS name anywhere, as prep.sh does
            "(-14090, eDSAuthFailed)\n<main> attribute status: eDSRecordNotFound",
        )
        for t in ok:
            self.assertTrue(drv.dscl_auth_failed(t), t)
        for t in bad:
            self.assertFalse(drv.dscl_auth_failed(t), t)


class Helpers(unittest.TestCase):
    def test_perm_ok(self):
        self.assertTrue(drv.perm_ok("root", "wheel", "755"))
        self.assertTrue(drv.perm_ok("root", "wheel", "644"))
        self.assertFalse(drv.perm_ok("root", "wheel", "775"))
        self.assertFalse(drv.perm_ok("root", "wheel", "757"))
        self.assertFalse(drv.perm_ok("admin", "wheel", "755"))
        self.assertFalse(drv.perm_ok("root", "admin", "755"))

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
        drv.load_image(
            VMDIR / "image.json"
        )  # the shipped pin passes its own validation

    def test_run_script_sh_removes_its_temp_file_and_exits_on_a_signal_trap(self):
        self.assertIn("trap 'exit 129' HUP INT TERM", drv.RUN_SCRIPT_SH)
        self.assertIn("trap 'rm -f \"$f\"' EXIT;", drv.RUN_SCRIPT_SH)
        before = set(Path("/var/tmp").glob("tendcf-state1.*"))
        r = subprocess.run(
            [
                "/bin/sh",
                "-c",
                'sudo() { shift; "$@"; }\n' + drv.RUN_SCRIPT_SH,
                "sh",
                "arg1",
            ],
            input='echo "ran $1"\n',
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual((r.returncode, r.stdout), (0, "ran arg1\n"), r.stderr)
        self.assertEqual(set(Path("/var/tmp").glob("tendcf-state1.*")), before)

    def test_python_signer_is_validated_as_one_line_name_and_team_id(self):
        base = json.loads((VMDIR / "image.json").read_text())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "image.json"

            def read(signer=None, drop=False):
                image = json.loads(json.dumps(base))
                if drop:
                    del image["python"]["signer"]
                else:
                    image["python"]["signer"] = signer
                path.write_text(json.dumps(image))
                return drv.read_image_json(path)

            read("Python Software Foundation (BMM5U3QVKW)")  # the shipped shape passes
            for bad in (
                None,
                7,
                "",
                "Python Software Foundation",  # no team id
                "Python Software Foundation (bmm5u3qvkw)",  # lower case
                "Python Software Foundation (BMM5U3QVK)",  # nine characters
                "Python Software Foundation (BMM5U3QVKW)\n",  # trailing newline
                "x\ny (BMM5U3QVKW)",  # two lines
                " (BMM5U3QVKW)",  # no name
            ):
                with self.assertRaises(drv.Refusal, msg=repr(bad)):
                    read(bad)
            with self.assertRaises(drv.Refusal):
                read(drop=True)  # missing: a refusal, not a KeyError in g8

    def test_second_signal_inside_the_handler_is_ignored(self):
        old = {s: signal.getsignal(s) for s in drv.SIGNALS}
        with self.assertRaises(drv.Interrupted), drv.signals_to_exception():
            os.kill(os.getpid(), signal.SIGTERM)
        # in the cleanup after the first signal, any further one must not raise again; the
        # test fails (an Interrupted escapes the `with`) if the handler stops ignoring them
        reached_end_of_cleanup = False
        with drv.signals_to_exception():
            try:
                os.kill(os.getpid(), signal.SIGTERM)
            except drv.Interrupted:
                os.kill(os.getpid(), signal.SIGINT)  # ignored, no exception
                os.kill(os.getpid(), signal.SIGHUP)
                os.kill(os.getpid(), signal.SIGTERM)
                reached_end_of_cleanup = True
        self.assertTrue(reached_end_of_cleanup)
        self.assertEqual({s: signal.getsignal(s) for s in drv.SIGNALS}, old)

    def test_atomic_write_never_follows_a_planted_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            victim = d / "victim"
            victim.write_text("precious")
            dest = d / "out.json"
            (d / f"out.json.tmp{os.getpid()}").symlink_to(
                victim
            )  # the old predictable name
            dest.symlink_to(victim)
            drv.atomic_write(dest, "new", 0o600)
            self.assertEqual(victim.read_text(), "precious")
            self.assertFalse(dest.is_symlink())
            self.assertEqual(dest.read_text(), "new")
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
            self.assertEqual(
                sorted(p.name for p in d.iterdir() if p.name.startswith("out.json.")),
                [f"out.json.tmp{os.getpid()}"],  # only the planted link remains
            )


class GuestScripts(unittest.TestCase):
    SCRIPTS = ("prep.sh", "install-python.sh", "bootstrap-askpass.sh")

    def text(self, name):
        return (VMDIR / "guest" / name).read_text()

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
            text = self.text(name)
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
        text = self.text("prep.sh")
        self.assertLess(
            text.index("snapshot before.partial"), text.index("mdutil -a -i off")
        )
        self.assertLess(
            text.index("snapshot before.partial"), text.index("launchctl disable")
        )
        self.assertNotIn("csrutil disable", text)
        self.assertNotIn("authenticated-root", text)

    def test_prep_turns_screen_sharing_off_fatally_and_verifies_it(self):
        text = self.text("prep.sh")
        for want in (
            "launchctl disable system/com.apple.screensharing",
            "launchctl bootout system/com.apple.screensharing",
            "is_disabled system com.apple.screensharing || die",
            "5900",
        ):
            self.assertIn(want, text)
        # fatal and before the (non-fatal) hygiene list and before the host keys change
        self.assertLess(
            text.index("launchctl disable system/com.apple.screensharing"),
            text.index("# 5. Named unused launchd jobs"),
        )

    def test_prep_records_the_secure_token_status_before_anything_changes(self):
        text = self.text("prep.sh")
        self.assertIn("sysadminctl -secureTokenStatus admin", text)
        self.assertIn("secure token status (before)", text)
        self.assertNotIn("sysadminctl -resetPasswordFor", text)  # status only
        self.assertNotIn("-secureTokenOn", text)
        self.assertNotIn("-secureTokenOff", text)

    def test_prep_console_password_is_random_verified_and_never_printed(self):
        text = self.text("prep.sh")
        a = text.index("pw=$(LC_ALL=C tr")
        b = text.index('log "console password: rotated', a)
        b = text.index("\n", b) + 1
        snippet = text[a:b]
        for ln in snippet.splitlines():  # the password is only ever an argument to dscl
            if "pw" in ln.replace("password", ""):
                self.assertRegex(
                    ln,
                    r'^(pw=\$\(LC_ALL=C tr .*urandom.*|\[ "\$\{#pw\}".*|\s*dscl \. -(passwd /Users/admin( admin)?|authonly admin) "\$pw".*|unset pw)$',
                    ln,
                )
        self.assertLess(text.index("pw=$(LC_ALL=C tr"), text.index("snapshot after"))
        self.assertLess(
            text.index('echo "PREP-CONSOLE-PW rotated"'),
            text.index('echo "PREP-RESULT'),
        )
        stub = (
            'log() { printf "prep: %s\\n" "$*"; }\n'
            'die() { printf "prep.sh: %s\\n" "$*" >&2; exit 1; }\n'
            "dscl() {\n"
            '  case "$2" in\n'
            '    -passwd) echo "$#" >>"$LOG"; return "$PASSWD_RC";;\n'
            "    -authonly)\n"
            '      if [ "$4" = admin ]; then\n'
            '        n=$(cat "$CNT" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$CNT"\n'
            '        if [ "$n" = 1 ]; then return "$PRE_RC"; fi\n'
            '        [ -z "$POST_OUT" ] || printf "%s\\n" "$POST_OUT" >&2\n'
            '        return "$POST_RC"\n'
            "      fi\n"
            '      [ "${#4}" -eq 32 ] || return 99\n'
            '      return "$NEW_RC";;\n'
            "  esac\n"
            "}\n"
        )
        wrong = "Authentication for node /Local/Default failed. (-14090, eDSAuthFailed)"
        base = {
            "PASSWD_RC": "0", "PRE_RC": "0", "NEW_RC": "0", "POST_RC": "14", "POST_OUT": wrong,
        }  # fmt: skip
        cases = (
            # first run: the vanilla password works, so old-and-new form (5 words)
            ({}, 0, "rotated", "5"),
            # re-run: the vanilla one is already dead, so the root form (4 words)
            ({"PRE_RC": "14"}, 0, "rotated", "4"),
            ({"PASSWD_RC": "1"}, 1, "dscl -passwd", None),
            ({"NEW_RC": "1"}, 1, "does not authenticate", None),
            ({"POST_RC": "0", "POST_OUT": ""}, 1, "still works", None),
            (
                {"POST_OUT": "(-14136, eDSRecordNotFound)"},
                1,
                "another reason",
                None,
            ),
            (
                {"POST_OUT": "(-14167, eDSAuthAccountDisabled)"},
                1,
                "another reason",
                None,
            ),
            ({"POST_OUT": ""}, 1, "another reason", None),
            (
                {"POST_OUT": wrong + " (-14170, eDSAuthPasswordExpired)"},
                1,
                "another reason",
                None,
            ),
            ({"POST_OUT": "(-1, eDSAuthFailed)"}, 1, "did not report -14090", None),
        )
        for over, want_rc, want_msg, want_words in cases:
            tmp = Path(tempfile.mkdtemp(prefix="tendcf-prep8-"))
            self.addCleanup(shutil.rmtree, tmp, True)
            env = {
                "PATH": "/usr/bin:/bin",
                "LOG": str(tmp / "log"),
                "CNT": str(tmp / "cnt"),
                **base,
                **over,
            }
            r = subprocess.run(
                ["/bin/sh", "-c", stub + "set -eu\n" + snippet],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(r.returncode, want_rc, (over, r.stdout, r.stderr))
            self.assertIn(want_msg, r.stdout + r.stderr)
            self.assertNotRegex(
                r.stdout + r.stderr, r"[A-Za-z0-9]{32}"
            )  # never printed
            if want_words is not None:
                self.assertEqual((tmp / "log").read_text().strip(), want_words, over)
                # the form that ran is in the log, so the first real run shows it
                form = (
                    "old-and-new dscl form" if want_words == "5" else "root dscl form"
                )
                self.assertIn(form, r.stdout, over)

    def test_prep_checks_sshd_effective_config_ignoring_case(self):
        # the loop that asserts `sshd -T` shows key-only login, run against a fake sshd
        text = self.text("prep.sh")
        a = text.index("effective=$(/usr/sbin/sshd -T")
        b = text.index('log "sshd: key login only"', a)
        snippet = text[a:b]
        tmp = Path(tempfile.mkdtemp(prefix="tendcf-prep7-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        fake = tmp / "sshd"
        fake.write_text('#!/bin/sh\nprintf "%s" "$SSHD_OUT"\nexit "${SSHD_RC:-0}"\n')
        fake.chmod(0o755)
        snippet = snippet.replace("/usr/sbin/sshd", str(fake))
        # A2/A6: the replace must have taken, and the slice must be exactly the expected text
        # (comments aside), so any widening fails here instead of running on the host: it can
        # then never run the host's sshd or write anything on the host.
        self.assertNotIn("/usr/sbin/sshd", snippet)
        self.assertIn(str(fake), snippet)
        code = "".join(
            ln + "\n" for ln in snippet.split("\n") if ln and not ln.startswith("#")
        )
        self.assertEqual(
            code,
            f"effective=$({fake} -T -C user=admin,host=localhost,addr=127.0.0.1)\n"
            "for want in 'passwordauthentication no' 'kbdinteractiveauthentication no'"
            " 'pubkeyauthentication yes' 'permitrootlogin no'; do\n"
            """    printf '%s\\n' "$effective" | LC_ALL=C grep -qixF "$want" """
            """|| die "sshd -T does not show: $want"\n"""
            "done\n",
        )
        stub = 'die() { printf "prep.sh: %s\\n" "$*" >&2; exit 1; }\n'
        cases = (
            (SSHD_CAMEL, 0, ""),  # macOS 27.2, as observed
            (SSHD_LOWER, 0, ""),  # stock OpenSSH
            (SSHD_CAMEL.replace("PasswordAuthentication no", "PasswordAuthentication yes"),
             1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PubkeyAuthentication yes", "PubkeyAuthentication no"),
             1, "pubkeyauthentication yes"),
            (SSHD_CAMEL.replace("PermitRootLogin no", "PermitRootLogin no-password"),
             1, "permitrootlogin no"),  # whole line, not a prefix
            ("", 1, "passwordauthentication no"),
            # padding, a CR and a leading space are not the wanted line (and the driver agrees)
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication no  \n"),
             1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication no\r\n"),
             1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", " PasswordAuthentication no\n"),
             1, "passwordauthentication no"),
            # a separator inside a quoted value does not make a second line, in grep either
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication yes\n")
             + "Banner /x\x0cPasswordAuthentication no\n", 1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication yes\n")
             + "Banner /x\u2028PasswordAuthentication no\n", 1, "passwordauthentication no"),
        )  # fmt: skip
        for out, want_rc, want_msg in cases:
            r = subprocess.run(
                ["/bin/sh", "-c", stub + "set -eu\n" + snippet],
                capture_output=True,
                text=True,
                check=False,
                env={"PATH": "/usr/bin:/bin", "SSHD_OUT": out},
            )
            self.assertEqual(r.returncode, want_rc, (out, r.stdout, r.stderr))
            self.assertIn(want_msg, r.stdout + r.stderr)
        # a lone CR inside a quoted value is part of that line for grep, as for the driver
        smuggled = (
            SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication yes\n")
            + "Banner /x\rPasswordAuthentication no\n"
        )  # fmt: skip
        # sshd -T failing: the command substitution dies under set -e with sshd's own status,
        # even when what it printed looks right, and nothing after it runs
        for out, rc_env, want_rc in ((smuggled, "0", 1), (SSHD_CAMEL, "3", 3)):
            r = subprocess.run(
                ["/bin/sh", "-c", stub + "set -eu\n" + snippet + "echo REACHED\n"],
                capture_output=True,
                text=True,
                check=False,
                env={"PATH": "/usr/bin:/bin", "SSHD_OUT": out, "SSHD_RC": rc_env},
            )
            self.assertEqual(r.returncode, want_rc, (rc_env, r.stdout, r.stderr))
            self.assertNotIn("REACHED", r.stdout)

    def fake_bin(self, name, body):
        d = Path(tempfile.mkdtemp(prefix="tendcf-prep-fake-"))
        self.addCleanup(shutil.rmtree, d, True)
        f = d / name
        f.write_text("#!/bin/sh\n" + body)
        f.chmod(0o755)
        return d

    def run_snippet(self, snippet, fakes, env=None):
        """Run a slice of prep.sh with fake tools first on PATH: nothing on the host is touched."""
        bins = [self.fake_bin(n, b) for n, b in fakes.items()]
        stub = (
            'die() { printf "prep.sh: %s\\n" "$*" >&2; exit 1; }\n'
            'log() { printf "prep: %s\\n" "$*"; }\n'
        )
        path = ":".join(str(b) for b in bins) + ":/usr/bin:/bin"
        return subprocess.run(
            ["/bin/sh", "-c", stub + "set -eu\n" + snippet],
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": path, **(env or {})},
        )

    def test_prep_settles_mdutil_with_a_bounded_retry(self):
        text = self.text("prep.sh")
        a = text.index("mdutil_polls=1")
        b = text.index('log "spotlight: off', a)
        snippet = text[a : text.index("\n", b) + 1]
        self.assertNotIn("/usr/bin/mdutil", snippet)
        seq = Path(tempfile.mkdtemp(prefix="tendcf-prep-seq-"))
        self.addCleanup(shutil.rmtree, seq, True)
        fakes = {
            # the Nth call prints $SEQ/out.N, else $SEQ/out.last; the exit status is MDUTIL_RC
            "mdutil": 'D=$SEQ; n=$(cat "$D/n" 2>/dev/null || echo 0); n=$((n + 1)); '
            'echo "$n" >"$D/n"; f="$D/out.$n"; [ -f "$f" ] || f="$D/out.last"; '
            'cat "$f"; exit "${MDUTIL_RC:-0}"\n',
            "sleep": 'echo "$1" >>"$SEQ/slept"\n',
        }

        def run(outs, last, rc="0"):
            for f in seq.iterdir():
                f.unlink()
            for i, o in enumerate(outs, 1):
                (seq / f"out.{i}").write_text(o)
            (seq / "out.last").write_text(last)
            return self.run_snippet(snippet, fakes, {"SEQ": str(seq), "MDUTIL_RC": rc})

        slept = lambda: (
            (seq / "slept").read_text().split() if (seq / "slept").exists() else []
        )
        r = run([MDUTIL_TRANSITIONING] * 2, MDUTIL_OFF)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("3 poll(s), 4 s waited", r.stdout)
        self.assertEqual(slept(), ["2", "2"])
        r = run([], MDUTIL_TRANSITIONING)  # never settles: 60 waits of 2 s, then dies
        self.assertEqual(r.returncode, 1)
        self.assertIn("still transitioning after 120 s", r.stderr)
        self.assertEqual(len(slept()), 60)
        r = run([MDUTIL_ON], MDUTIL_OFF)  # enabled is never retried into a pass
        self.assertEqual(r.returncode, 1)
        self.assertIn("still enabled", r.stderr)
        self.assertEqual(slept(), [])
        r = run([MDUTIL_TRANSITIONING], MDUTIL_ON)
        self.assertEqual(r.returncode, 1)
        self.assertIn("still enabled", r.stderr)
        r = run([], "something else\n")  # not the wanted answer, and not retried
        self.assertEqual(r.returncode, 1)
        self.assertIn("did not report 'Indexing disabled'", r.stderr)
        self.assertEqual(slept(), [])
        r = run([], MDUTIL_OFF, rc="1")  # a failing mdutil dies, whatever it printed
        self.assertEqual(r.returncode, 1)
        self.assertIn("mdutil -a -s failed", r.stderr)

    def test_prep_turns_automatic_update_checks_off_through_softwareupdate(self):
        text = self.text("prep.sh")
        loop = text[
            text.index("for key in ") : text.index("done", text.index("for key in "))
        ]
        self.assertNotIn("AutomaticCheckEnabled", loop)  # macOS 27.2 drops that raw key
        for key in (
            "AutomaticDownload",
            "AutomaticallyInstallMacOSUpdates",
            "ConfigDataInstall",
            "CriticalUpdateInstall",
        ):
            self.assertIn(key, loop)
        a = text.index("su_set=$(softwareupdate --schedule off")
        b = text.index('is turned off"*)', a)
        snippet = text[a : text.index("\n", b) + 1]
        code = [ln for ln in snippet.split("\n") if ln and not ln.startswith("#")]
        self.assertEqual(
            len(code), 4, code
        )  # set, read back, two case checks: nothing else
        fakes = {
            # `--schedule off` -> rc SU_SET_RC; `--schedule` -> prints SU_OUT, rc SU_RC
            "softwareupdate": 'if [ "$2" = off ]; then echo "set"; exit "${SU_SET_RC:-0}"; fi; '
            'printf "%s" "$SU_OUT"; exit "${SU_RC:-0}"\n',
        }
        off = "Automatic checking for updates is turned off\n"
        on = "Automatic checking for updates is turned on\n"
        for name, env, want_rc, want_msg in (
            ("off", {"SU_OUT": off}, 0, ""),
            ("still on", {"SU_OUT": on}, 1, "still on"),
            ("both words", {"SU_OUT": off + on}, 1, "still on"),
            ("empty answer", {"SU_OUT": ""}, 1, "did not say 'turned off'"),
            ("other words", {"SU_OUT": "disabled\n"}, 1, "did not say 'turned off'"),
            (
                "set fails",
                {"SU_OUT": off, "SU_SET_RC": "1"},
                1,
                "--schedule off failed",
            ),
            ("read-back fails", {"SU_OUT": off, "SU_RC": "1"}, 1, "--schedule failed"),
        ):
            with self.subTest(name):
                r = self.run_snippet(snippet, fakes, env)
                self.assertEqual(r.returncode, want_rc, (r.stdout, r.stderr))
                self.assertIn(want_msg, r.stderr)
        # it runs after the defaults loop and before Gatekeeper, and the old raw write is gone
        self.assertLess(text.index("su_set=$("), text.index("# 3. Gatekeeper on"))

    def test_prep_records_the_secure_token_status_after_the_rotation(self):
        text = self.text("prep.sh")
        self.assertIn("secure token status (after)", text)
        self.assertLess(
            text.index('log "console password: rotated'),
            text.index("secure token status (after)"),
        )
        self.assertLess(
            text.index("secure token status (after)"), text.index("snapshot after")
        )
        self.assertNotIn("-resetPasswordFor", text)  # status only
        self.assertNotIn("-secureTokenOn", text)

    def test_prep_prints_the_host_key_from_inside_the_session(self):
        text = self.text("prep.sh")
        self.assertIn("PREP-HOSTKEY", text)
        self.assertIn("/etc/ssh/ssh_host_ed25519_key.pub", text)
        self.assertLess(text.index("ssh-keygen -A"), text.index('echo "PREP-HOSTKEY'))
        self.assertIn("'permitrootlogin no'", text)

    def test_python_install_fixes_and_asserts_ownership_after_the_installer(self):
        text = self.text("install-python.sh")
        i = text.index("installer -pkg")
        for want in (
            'chown -hR root:wheel "$fwroot"',
            'chmod -R go-w "$fwroot"',
            'find "$fwroot" \\( ! -user root',
            'find "$fwroot" ! -type l',
            "! -group wheel",
            "-perm -020 -o -perm -002",
        ):
            self.assertIn(want, text)
            self.assertGreater(text.index(want), i, want)
        # the fix-up and assertion are not inside the "already installed" skip
        self.assertGreater(text.index("chown -hR"), text.index("\nfi\n"))
        self.assertIn("--proto '=https' --proto-redir '=https'", text)
        # the fix-up and both assertions start at the framework, not at Versions/X.Y
        self.assertIn("fwroot=/Library/Frameworks/Python.framework\n", text)
        self.assertNotIn('chown -hR root:wheel "$fw"', text)
        self.assertNotIn('find "$fw" ', text)

    def test_prep_netstat_check_fails_closed(self):
        text = self.text("prep.sh")
        a = text.index("netstat_out=$(")
        b = text.index("\nfi\n", a) + 4
        snippet = text[a:b]
        cases = (
            ("netstat() { return 1; }", 1, "failed"),
            ("netstat() { return 0; }", 1, "printed nothing"),
            ("netstat() { echo 'tcp4 0 0 *.5900 *.* LISTEN'; }", 1, "5900"),
            ("netstat() { echo 'tcp4 0 0 *.22 *.* LISTEN'; }", 0, ""),
        )
        for stub, want_rc, want_msg in cases:
            r = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    'die() { echo "DIE: $*"; exit 1; }; ' + stub + "\n" + snippet,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, want_rc, (stub, r.stdout, r.stderr))
            self.assertIn(want_msg, r.stdout)

    def pkgutil_check(
        self, output, rc=0, signer="Python Software Foundation (BMM5U3QVKW)"
    ):
        """Run install-python.sh's real check_signature against a stub pkgutil."""
        text = self.text("install-python.sh")
        a = text.index("check_signature() {")
        b = text.index("\nif installed; then")
        d = Path(tempfile.mkdtemp(prefix="tendcf-pkgutil-"))
        self.addCleanup(shutil.rmtree, d, True)
        stub = d / "pkgutil"
        (d / "out.txt").write_text(output)
        stub.write_text(f'#!/bin/sh\ncat "{d}/out.txt"\nexit {rc}\n')
        stub.chmod(0o755)
        driver = d / "run.sh"
        driver.write_text(
            'die() { echo "install-python.sh: $*" >&2; exit 1; }\n'
            f"signer={shlex.quote(signer)}\n"
            + text[a:b]
            + "\ncheck_signature /nonexistent.pkg\n"
        )
        return subprocess.run(
            ["/bin/sh", str(driver)],
            env={"PATH": f"{d}:/usr/bin:/bin"},
            capture_output=True,
            text=True,
            check=False,
        )

    GOOD_SIG = (
        'Package "python.pkg":\n'
        "   Status: signed by a developer certificate issued by Apple for distribution\n"
        "   Notarization: trusted by the Apple notary service\n"
        "   Signed with a trusted timestamp on: 2026-11-04 17:28:59 +0000\n"
        "   Certificate Chain:\n"
        "    1. Developer ID Installer: Python Software Foundation (BMM5U3QVKW)\n"
        "       Expires: 2031-02-01 22:12:15 +0000\n"
        "    2. Developer ID Certification Authority\n"
    )

    def test_signature_check_accepts_the_real_shape(self):
        r = self.pkgutil_check(self.GOOD_SIG)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_signature_check_rejects_what_a_substring_grep_would_accept(self):
        # not signed by Apple's distribution chain, though the name appears in the output
        bad_status = self.GOOD_SIG.replace(
            "signed by a developer certificate issued by Apple for distribution",
            "signed with a certificate that is not trusted",
        )
        self.assertNotEqual(self.pkgutil_check(bad_status).returncode, 0)
        # the signer name only as a substring of another certificate's name
        other = self.GOOD_SIG.replace(
            "Developer ID Installer: Python Software Foundation (BMM5U3QVKW)",
            "Developer ID Installer: Evil Python Software Foundation (BMM5U3QVKW) Inc",
        )
        self.assertNotEqual(self.pkgutil_check(other).returncode, 0)
        # the right name, but as a non-leaf certificate
        not_leaf = self.GOOD_SIG.replace(
            "    1. Developer ID Installer: Python Software Foundation (BMM5U3QVKW)\n",
            "    1. Developer ID Installer: Somebody Else (XXXXXXXXXX)\n"
            "    2. Developer ID Installer: Python Software Foundation (BMM5U3QVKW)\n",
        )
        self.assertNotEqual(self.pkgutil_check(not_leaf).returncode, 0)
        # pkgutil itself failing, whatever it printed
        self.assertNotEqual(self.pkgutil_check(self.GOOD_SIG, rc=1).returncode, 0)


if __name__ == "__main__":
    unittest.main()
