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
import hashlib
import io
import json
import os
import plistlib
import re
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
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
# Full macOS 27.2 three-volume listing observed in issue 70 run 4.
MDUTIL_OFF_3 = (
    "/:\n\tIndexing disabled.\n"
    "/System/Volumes/Data:\n\tIndexing disabled.\n"
    "/System/Volumes/Preboot:\n\tIndexing disabled.\n"
)
MDUTIL_TRANSITIONING = (
    "/:\n\tError: unexpected indexing state.  kMDConfigSearchLevelTransitioning\n"
    "/System/Volumes/Data:\n\tError: unexpected indexing state.  kMDConfigSearchLevelTransitioning\n"
)
MDUTIL_ON = "/:\n\tIndexing enabled.\n"
SU_OFF = "Automatic checking for updates is turned off\n"
SU_ON = "Automatic checking for updates is turned on\n"
# the keys prep.sh writes and check 2h reads (AutomaticCheckEnabled is neither; SplatEnabled is
# believed to be Background Security Improvements — inferred, not documented by Apple; operator
# ruling 2026-11-21)
UPDATE_KEYS = (
    "AutomaticDownload",
    "AutomaticallyInstallMacOSUpdates",
    "ConfigDataInstall",
    "CriticalUpdateInstall",
    "SplatEnabled",
)
SECURE_TOKEN_AFTER = (
    "prep: secure token status (after): 2026-11-21 22:41:08.682 sysadminctl[422:2528] "
    "Secure token is ENABLED for user Managed via Tart \n"
)
SSHD_CAMEL = (
    "UsePAM yes\nPermitRootLogin no\nPubkeyAuthentication yes\n"
    "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
    "GSSAPIAuthentication no\nHostbasedAuthentication no\n"
    "AuthenticationMethods publickey\nPubkeyAuthOptions none\n"
)
SSHD_LOWER = (
    "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\n"
    "pubkeyauthentication yes\npermitrootlogin no\n"
    "gssapiauthentication no\nhostbasedauthentication no\n"
    "authenticationmethods publickey\n"
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
        self.stat_overrides = {}  # path -> "owner:group mode [perm]" for the ancestor stat
        self.acl_paths = set()  # paths that report a macOS ACL on /bin/ls -lde
        self.acl_check_fail = False
        self.signal_on_tart = (
            None  # deliver a real SIGTERM when this tart subcommand runs
        )
        self.signals_sent = 0
        self.screensharing_on = False
        self.admin_uid_result = (0, "501\n", "")
        self.uid_raw_newlines = []
        self.print_disabled_rc = {}  # domain -> non-zero rc override
        self.print_disabled_override = {}  # domain -> raw stdout override
        self.launchctl_raw_newlines = []
        self.hygiene_enabled = set()  # {(domain, label)} reported as => enabled
        self.hygiene_missing = set()  # {(domain, label)} omitted from print-disabled
        self.hygiene_use_true = False
        self.extra_vz_vms = 0  # extra other Virtualization.framework VM processes
        self.extra_ps_comms = []  # extra non-VZ process paths in `/bin/ps -axww -o comm=`
        self.ps_raw_newlines = []
        self.ps_fail = False
        self.sshd_output = SSHD_CAMEL  # what `sudo -n sshd -T -C ...` prints
        self.sshd_spec_outputs = {}  # spec -> output override for multi-spec tests
        self.sshd_specs_seen = []  # every -C spec passed to `sudo -n sshd -T -C`
        self.sshd_call_order = []  # order of "match" vs "sshd-T" calls in 2e/10a
        self.sshd_rc = 0
        self.sshd_raw_newlines = []  # the raw_newlines flag of each sshd -T call
        self.sshd_match_rc = 0
        self.sshd_match_output = ""
        self.password_login_after_reboot = False
        # `sudo -n mdutil -a -s`: the answers still to give, in order ((rc, stdout)), then
        # mdutil_default for ever; mdutil_calls counts the calls
        self.mdutil_outputs = []
        self.mdutil_default = (0, MDUTIL_OFF)
        self.mdutil_calls = 0
        self.mdutil_raw_newlines = []  # the raw_newlines flag of each mdutil -a -s call
        # `sudo -n softwareupdate --schedule` and the `defaults read` answers per key
        self.su_schedule = (0, SU_ON)  # the real guest: checking cannot be turned off
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
        # renderer / darwin installer simulation (steps 3-9, 9a, 10b, 11a)
        self.gh_fail = False
        self.gh_api_fail = False
        self.gh_run_meta = {
            "head_repository": {"full_name": drv.GH_REPO},
            "event": "push",
            "name": "macOS fork build",
            "path": ".github/workflows/macos-fork-build.yml",
            "head_branch": "spike/macos-fork-build",
        }
        self.gh_tarball_bytes = b"fake-tarball-payload"
        self.gh_bad_sha = False
        self.stage_bundles = []  # raw tar.gz bytes uploaded to guest
        self.guest_stage_dir = "/var/tmp/tendcf-stage.abc123"
        self.workdir = "/opt/tendcf/var/libntech"
        self.workdir_override = None
        self.install_count = 0
        self.enable_count = 0
        self.install_fail = False
        self.install_rerun_changes = False
        self.tendcf_tree_bad = False
        self.policy_tree_bad = False
        self.data_mode = "root:wheel 600"
        self.quarantine_left = False
        self.xattr_fail = False
        self.run_once_fail = False
        self.run_once_rerun_repairs = False
        self.run_once_rerun_reloads = False
        self.canary_plist_bytes = drv.CANARY_GOLDEN.read_text(encoding="utf-8")
        self.canary_plist_mode = "root:wheel 644"
        self.canary_plutil_fail = False
        self.canary_backup_present = False
        self.canary_loaded = False
        self.canary_pid = 400
        self.canary_args = [drv.CANARY_PROG, drv.CANARY_ARG]
        self.canary_drifted = False
        self.drift_unrepaired = False
        self.drift_no_reload = False
        self.kickstart_fail = False
        self.kickstart_same_pid = False
        self.canary_absent_data = False
        self.canary_teardown_keeps_plist = False
        self.canary_teardown_keeps_loaded = False
        self.canary_lost_after_reboot = False
        self.nonroot_installer_succeeds = False
        self.nonroot_cfagent_mutates = False
        self.nonroot_cfagent_rc0_no_refusal = False
        self.nonroot_bootstrap_succeeds = False
        self.execd_enable_fail = False
        self.execd_enable_rerun_changes = False
        self.execd_plist_present = False
        self.execd_plist_mode = "root:wheel 644"
        self.execd_loaded = False
        self.execd_state = "running"
        self.execd_program = drv.EXECD_PROG
        self.execd_pid = 500
        self.execd_user = "root"
        self.execd_comm = "/opt/tendcf/bin/cf-execd"
        self.execd_lost_after_reboot = False
        self.execd_disable_fail = False
        self.execd_disable_keeps_loaded = False
        self.stage_removed = False

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
        input_bytes=None,
        env=None,
        timeout=None,
        log_path=None,
        no_tty=False,
        raw_newlines=False,
    ):
        self._raw_newlines = raw_newlines
        self._input_bytes = input_bytes
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
        if argv == ["/bin/ps", "-axww", "-o", "comm="]:
            self.ps_raw_newlines.append(raw_newlines)
            if self.ps_fail:
                return drv.Result(1, "", "ps: failed")
            n_running = sum(1 for v in self.vms.values() if v.get("Running"))
            lines = [
                "/sbin/launchd",
                "/usr/sbin/syslogd",
                *self.extra_ps_comms,
                *([drv.VZ_VM_COMM] * (n_running + self.extra_vz_vms)),
            ]
            out_s = "\n".join(lines) + "\n"
            if "\r" in out_s:
                out_s = (
                    drv.RealRunner()
                    .run(["/usr/bin/printf", "%s", out_s], raw_newlines=raw_newlines)
                    .stdout
                )
            return drv.Result(0, out_s)
        if argv[0] == "gh":
            return self._gh(argv[1:])
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

    def _gh(self, a):
        if a[:1] == ["api"] and len(a) == 2 and a[1].startswith(f"repos/{drv.GH_REPO}/actions/runs/"):
            if self.gh_api_fail:
                return drv.Result(1, "", "gh: HTTP 404 Not Found")
            return drv.Result(0, json.dumps(self.gh_run_meta))
        if a[:2] == ["run", "download"]:
            if self.gh_fail:
                return drv.Result(1, "", "gh: artifact not found")
            name = a[a.index("-n") + 1]
            dest = Path(a[a.index("-D") + 1])
            dest.mkdir(parents=True, exist_ok=True)
            tar_name = f"{name}.tar.gz"
            (dest / tar_name).write_bytes(self.gh_tarball_bytes)
            digest = (
                "0" * 64
                if self.gh_bad_sha
                else hashlib.sha256(self.gh_tarball_bytes).hexdigest()
            )
            (dest / f"{tar_name}.sha256").write_text(
                f"{digest}  {tar_name}\n", encoding="utf-8"
            )
            return drv.Result(0, "")
        raise AssertionError(f"unexpected gh command {a}")

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
        if r[:3] == ["/bin/sh", "-c", drv.STAGE_UPLOAD_SH]:
            self.stage_bundles.append(self._input_bytes)
            return drv.Result(0, self.guest_stage_dir + "\n")
        if (
            r[:3] == ["/bin/sh", "-c", drv.TREE_CHECK_SH]
            or r[:5] == ["sudo", "-n", "/bin/sh", "-c", drv.TREE_CHECK_SH]
            or r[:5] == ["sudo", "-n", "/bin/sh", "-c", drv.TREE_CHECK_NO_LINKS_SH]
        ):
            is_root = r[0] == "sudo"
            path = r[6] if is_root else r[4]
            if path == drv.TENDCF_PREFIX:
                if not is_root:
                    return drv.Result(
                        0, "", "find: /opt/tendcf/var/libntech/ppkeys: Permission denied\n"
                    )
                return drv.Result(0, f"{path}/bin/cf-agent\n" if self.tendcf_tree_bad else "")
            if path == f"{self.workdir}/inputs":
                return drv.Result(0, f"{path}/promises.cf\n" if self.policy_tree_bad else "")
            bad = "" if self.fw_owner == FW_PYTHON_FIXED else f"{path}\n"
            if path == FW_ROOT and self.fw_versions != FW_PYTHON_FIXED:
                bad += f"{FW_ROOT}/Versions\n"
            return drv.Result(0, bad)
        if r[:3] == ["sudo", "-n", f"{self.guest_stage_dir}/tendcf-install.sh"]:
            return self._guest_installer(r[3:])
        if r[:1] == [f"{self.guest_stage_dir}/tendcf-install.sh"]:
            if self.nonroot_installer_succeeds:
                return drv.Result(0, "ok\n")
            return drv.Result(1, "", "tendcf-install: run as root\n")
        if r == [
            "env",
            f"CFENGINE_TEST_OVERRIDE_WORKDIR={self.workdir}",
            f"{drv.TENDCF_PREFIX}/bin/cf-agent",
            "-K",
            "-f",
            f"{self.workdir}/inputs/promises.cf",
        ]:
            if self.nonroot_cfagent_mutates:
                self.canary_plist_bytes = self.canary_plist_bytes + "<!-- mutated -->\n"
                return drv.Result(0, "")
            if self.nonroot_cfagent_rc0_no_refusal:
                return drv.Result(0, "R: tendcf: benign status line\n")
            return drv.Result(1, "", "error: permission denied\n")
        if r == ["/bin/launchctl", "bootstrap", "system", drv.CANARY_PLIST]:
            if self.nonroot_bootstrap_succeeds:
                return drv.Result(0, "")
            return drv.Result(1, "", "Bootstrap failed: 1: Operation not permitted\n")
        if r == ["sudo", "-n", "/usr/bin/stat", "-f", "%Su:%Sg %Lp", f"{self.workdir}/data/host_specific.json"]:
            return drv.Result(0, self.data_mode + "\n")
        if r == [
            "sudo",
            "-n",
            "/usr/bin/find",
            drv.TENDCF_PREFIX,
            "!",
            "-type",
            "s",
            "-exec",
            "/usr/bin/xattr",
            "-s",
            "{}",
            "+",
        ]:
            if self.xattr_fail:
                return drv.Result(1, "", "xattr: operation not permitted\n")
            return drv.Result(
                0,
                f"{drv.TENDCF_PREFIX}/bin/cf-agent: com.apple.quarantine\n"
                if self.quarantine_left
                else "",
            )
        if (
            r[:5] == ["sudo", "-n", "/bin/sh", "-c", 'test -f "$1" && ! test -L "$1" && /usr/bin/stat -f "%Su:%Sg %Lp" "$1"']
            and len(r) == 7
        ):
            p = r[6]
            if p == drv.CANARY_PLIST:
                if not self.canary_plist_bytes:
                    return drv.Result(1, "", "")
                return drv.Result(0, self.canary_plist_mode + "\n")
            if p == drv.EXECD_PLIST:
                if not self.execd_plist_present:
                    return drv.Result(1, "", "")
                return drv.Result(0, self.execd_plist_mode + "\n")
        if r[:4] == ["sudo", "-n", "/usr/bin/plutil", "-lint"]:
            if r[4] == drv.CANARY_PLIST and self.canary_plutil_fail:
                return drv.Result(1, "", f"{r[4]}: malformed plist\n")
            return drv.Result(0, f"{r[4]}: OK\n")
        if r[:5] == ["sudo", "-n", "/bin/sh", "-c", '! test -e "$1.cf-before-edit"']:
            return drv.Result(1 if self.canary_backup_present else 0, "")
        if r[:5] == ["sudo", "-n", "/bin/sh", "-c", '! test -e "$1"'] and len(r) == 7:
            p = r[6]
            if p == drv.CANARY_PLIST:
                return drv.Result(1 if self.canary_plist_bytes else 0, "")
            if p == drv.EXECD_PLIST:
                return drv.Result(1 if self.execd_plist_present else 0, "")
        if r == ["sudo", "-n", "/bin/cat", drv.CANARY_PLIST]:
            return drv.Result(0, self.canary_plist_bytes)
        if r[:4] == ["sudo", "-n", "/usr/bin/shasum", "-a"] and r[4] == "256":
            if r[5] == drv.CANARY_PLIST:
                digest = hashlib.sha256(self.canary_plist_bytes.encode("utf-8")).hexdigest()
                return drv.Result(0, f"{digest}  {r[5]}\n")
            return drv.Result(1, "", "No such file")
        if r == ["sudo", "-n", "/usr/bin/plutil", "-replace", "ProgramArguments.1", "-string", drv.CANARY_DRIFT_ARG, drv.CANARY_PLIST]:
            self.canary_plist_bytes = self.canary_plist_bytes.replace(
                f"<string>{drv.CANARY_ARG}</string>",
                f"<string>{drv.CANARY_DRIFT_ARG}</string>",
            )
            self.canary_drifted = True
            return drv.Result(0, "")
        if r[:4] == ["sudo", "-n", "/bin/launchctl", "print"]:
            target = r[4]
            if target == f"system/{drv.CANARY_LABEL}":
                if not self.canary_loaded or (self.rebooted and self.canary_lost_after_reboot):
                    return drv.Result(113, "", "Could not find service\n")
                args_lines = "\n".join(f"\t\t{a}" for a in self.canary_args)
                return drv.Result(
                    0,
                    f"system/{drv.CANARY_LABEL} = {{\n"
                    f"\tpath = {drv.CANARY_PLIST}\n"
                    "\ttype = LaunchDaemon\n"
                    "\tstate = running\n"
                    f"\tprogram = {self.canary_args[0]}\n"
                    "\targuments = {\n"
                    f"{args_lines}\n"
                    "\t}\n"
                    f"\tpid = {self.canary_pid}\n"
                    "}\n",
                )
            if target == f"system/{drv.EXECD_LABEL}":
                if not self.execd_loaded or (self.rebooted and self.execd_lost_after_reboot):
                    return drv.Result(113, "", "Could not find service\n")
                return drv.Result(
                    0,
                    f"system/{drv.EXECD_LABEL} = {{\n"
                    f"\tpath = {drv.EXECD_PLIST}\n"
                    "\ttype = LaunchDaemon\n"
                    f"\tstate = {self.execd_state}\n"
                    f"\tprogram = {self.execd_program}\n"
                    "\targuments = {\n"
                    f"\t\t{self.execd_program}\n"
                    "\t\t--no-fork\n"
                    "\t}\n"
                    f"\tpid = {self.execd_pid}\n"
                    "}\n",
                )
        if r == ["sudo", "-n", "/bin/launchctl", "kickstart", "-k", f"system/{drv.CANARY_LABEL}"]:
            if self.kickstart_fail:
                return drv.Result(1, "", "kickstart failed\n")
            if not self.kickstart_same_pid:
                self.canary_pid += 1
            return drv.Result(0, "")
        if r[:3] == ["ps", "-o", "user=,comm="] and r[3] == "-p":
            if r[4] == str(self.execd_pid):
                return drv.Result(0, f"{self.execd_user} {self.execd_comm}\n")
            return drv.Result(1, "", "")
        if r == ["/bin/rm", "-rf", self.guest_stage_dir]:
            self.stage_removed = True
            return drv.Result(0, "")
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
            spec = r[r.index("-C") + 1] if "-C" in r else ""
            self.sshd_specs_seen.append(spec)
            self.sshd_call_order.append("sshd-T")
            out = self.sshd_spec_outputs.get(spec, self.sshd_output)
            real = drv.RealRunner().run(
                ["/usr/bin/printf", "%s", out],
                raw_newlines=self._raw_newlines,
            )
            return drv.Result(self.sshd_rc, real.stdout, real.stderr)
        if r[:5] == ["sudo", "-n", "/bin/sh", "-c", drv.SSHD_MATCH_CHECK_SH]:
            self.sshd_call_order.append("match")
            return drv.Result(self.sshd_match_rc, self.sshd_match_output, "")
        if r[:4] == ["sudo", "-n", "mdutil", "-a"]:
            self.mdutil_calls += 1
            self.mdutil_raw_newlines.append(self._raw_newlines)
            raw_res = drv.Result(
                *(
                    self.mdutil_outputs.pop(0)
                    if self.mdutil_outputs
                    else self.mdutil_default
                )
            )
            # Run CR-bearing stdout/stderr through the real runner's decode (like sshd above),
            # so omitting raw_newlines=True translates CR/CRLF to LF as in production.
            out_s = (
                drv.RealRunner()
                .run(
                    ["/usr/bin/printf", "%s", raw_res.stdout],
                    raw_newlines=self._raw_newlines,
                )
                .stdout
                if "\r" in raw_res.stdout
                else raw_res.stdout
            )
            err_s = (
                drv.RealRunner()
                .run(
                    ["/usr/bin/printf", "%s", raw_res.stderr],
                    raw_newlines=self._raw_newlines,
                )
                .stdout
                if "\r" in raw_res.stderr
                else raw_res.stderr
            )
            return drv.Result(raw_res.rc, out_s, err_s, raw_res.timed_out)
        if r == ["sudo", "-n", "softwareupdate", "--schedule"]:
            return drv.Result(
                *(self.su_outputs.pop(0) if self.su_outputs else self.su_schedule)
            )
        if r == ["id", "-u", "admin"]:
            self.uid_raw_newlines.append(self._raw_newlines)
            rc_u, out_u, err_u = self.admin_uid_result
            if "\r" in out_u:
                out_u = (
                    drv.RealRunner()
                    .run(
                        ["/usr/bin/printf", "%s", out_u],
                        raw_newlines=self._raw_newlines,
                    )
                    .stdout
                )
            return drv.Result(rc_u, out_u, err_u)
        if r[:4] == ["sudo", "-n", "launchctl", "print-disabled"] and len(r) == 5:
            dom = r[4]
            self.launchctl_raw_newlines.append(self._raw_newlines)
            if dom in self.print_disabled_rc:
                return drv.Result(
                    self.print_disabled_rc[dom],
                    "",
                    f"launchctl print-disabled {dom}: failed\n",
                )
            if dom.startswith("gui/"):
                # Real headless post-rotation macOS 27.2 clones have no Aqua gui/<uid> session.
                return drv.Result(
                    125,
                    "",
                    "Could not print cache: 125: Domain does not support specified action\n",
                )
            if dom in self.print_disabled_override:
                out_d = self.print_disabled_override[dom]
                if "\r" in out_d:
                    out_d = (
                        drv.RealRunner()
                        .run(
                            ["/usr/bin/printf", "%s", out_d],
                            raw_newlines=self._raw_newlines,
                        )
                        .stdout
                    )
                return drv.Result(0, out_d)
            val = "true" if self.hygiene_use_true else "disabled"
            if dom == "system":
                lines = ['\t"com.apple.xpc.foo" => enabled']
                if not self.screensharing_on:
                    lines.append('\t"com.apple.screensharing" => disabled')
                for d, lbl in drv.HYGIENE_DISABLE_LIST:
                    if d != "system":
                        continue
                    if (d, lbl) in self.hygiene_missing:
                        continue
                    if (d, lbl) in self.hygiene_enabled:
                        lines.append(f'\t"{lbl}" => enabled')
                    else:
                        lines.append(f'\t"{lbl}" => {val}')
            elif dom.startswith("user/"):
                lines = ['\t"com.apple.xpc.user.foo" => enabled']
                for d, lbl in drv.HYGIENE_DISABLE_LIST:
                    if d != "gui":
                        continue
                    if (d, lbl) in self.hygiene_missing:
                        continue
                    if (d, lbl) in self.hygiene_enabled:
                        lines.append(f'\t"{lbl}" => enabled')
                    else:
                        lines.append(f'\t"{lbl}" => {val}')
            else:
                return drv.Result(125, "", f"unsupported domain {dom}\n")
            return drv.Result(0, "disabled services = {\n" + "\n".join(lines) + "\n}\n")
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
        if r[:3] == ["stat", "-f", "%N %Su:%Sg %Lp %Sp"] or r[:5] == [
            "sudo",
            "-n",
            "stat",
            "-f",
            "%N %Su:%Sg %Lp %Sp",
        ]:
            paths = r[5:] if r[0] == "sudo" else r[3:]
            lines = []
            for p in paths:
                val = self.stat_overrides.get(p, FW_PYTHON_FIXED)
                if len(val.split()) == 2:
                    val = val + " drwxr-xr-x"
                lines.append(f"{p} {val}\n")
            return drv.Result(0, "".join(lines))
        if r[:2] == ["/bin/ls", "-lde"] or r[:4] == ["sudo", "-n", "/bin/ls", "-lde"]:
            if self.acl_check_fail:
                return drv.Result(1, "", "ls: permission denied\n")
            paths = r[4:] if r[0] == "sudo" else r[2:]
            lines = []
            for p in paths:
                if p in self.acl_paths:
                    lines.append(f"drwxr-xr-x+  2 root  wheel  64 Nov 25 00:00 {p}\n")
                    lines.append(" 0: user:admin allow add_file\n")
                else:
                    lines.append(f"drwxr-xr-x   2 root  wheel  64 Nov 25 00:00 {p}\n")
            return drv.Result(0, "".join(lines))
        if r[:3] == ["stat", "-f", "%Su:%Sg %Lp %Sp"] or r[:5] == [
            "sudo",
            "-n",
            "stat",
            "-f",
            "%Su:%Sg %Lp %Sp",
        ]:
            target_p = r[5] if r[0] == "sudo" else r[3]
            if target_p in (drv.TENDCF_PREFIX, f"{self.workdir}/inputs"):
                val = FW_PYTHON_FIXED
            else:
                val = self.fw_owner
            if len(val.split()) == 2:
                val = val + " drwxr-xr-x"
            return drv.Result(0, val + "\n")
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
            if self.rebooted and self.password_login_after_reboot:
                self.password_login = True
            if self.run_exits_on_reboot or self.die_after_reboot:
                self._stop_current()
            return drv.Result(255, "", "Connection closed")
        raise AssertionError(f"unexpected guest command {r}")

    def _guest_installer(self, args):
        sub = args[0]
        if sub == "install":
            self.install_count += 1
            if self.install_fail:
                return drv.Result(1, "", "tendcf-install: sha256 mismatch\n")
            if self.install_count > 1 and not self.install_rerun_changes:
                return drv.Result(0, "tendcf-install: no change (CFEngine Core 3.29.0a)\n")
            return drv.Result(0, "tendcf-install: installed: CFEngine Core 3.29.0a\n")
        if sub == "workdir":
            return drv.Result(0, (self.workdir_override or self.workdir) + "\n")
        if sub == "data":
            self.canary_absent_data = args[1].endswith("host_specific-absent.json")
            return drv.Result(0, "tendcf-install: data installed\n")
        if sub == "run-once":
            if self.run_once_fail:
                return drv.Result(1, "", "cf-agent failed\n")
            if self.canary_absent_data:
                if not self.canary_teardown_keeps_plist:
                    self.canary_plist_bytes = ""
                if not self.canary_teardown_keeps_loaded:
                    self.canary_loaded = False
                return drv.Result(0, "info: deleted canary\n")
            if not self.canary_loaded:
                self.canary_loaded = True
                self.canary_args = [drv.CANARY_PROG, drv.CANARY_ARG]
                return drv.Result(0, "info: Created file and bootstrapped\n")
            if self.canary_drifted:
                if not self.drift_unrepaired:
                    self.canary_plist_bytes = drv.CANARY_GOLDEN.read_text(encoding="utf-8")
                    self.canary_args = [drv.CANARY_PROG, drv.CANARY_ARG]
                if not self.drift_no_reload:
                    self.canary_pid += 1
                self.canary_drifted = False
                return drv.Result(0, "info: Updated rendering and reloaded\n")
            # idempotent re-run
            if self.run_once_rerun_reloads:
                self.canary_pid += 1
            if self.run_once_rerun_repairs:
                return drv.Result(0, "info: Updated rendering of plist\n")
            return drv.Result(0, "")
        if sub == "enable":
            self.enable_count += 1
            if self.execd_enable_fail:
                return drv.Result(1, "", "tendcf-install: bootstrap failed\n")
            self.execd_plist_present = True
            self.execd_loaded = True
            if self.enable_count > 1 and not self.execd_enable_rerun_changes:
                return drv.Result(0, "tendcf-install: no change (org.tendcf.execd already loaded)\n")
            return drv.Result(0, "tendcf-install: enabled: org.tendcf.execd\n")
        if sub == "disable":
            if self.execd_disable_fail:
                return drv.Result(1, "", "tendcf-install: bootout failed\n")
            self.execd_plist_present = False
            if not self.execd_disable_keeps_loaded:
                self.execd_loaded = False
            return drv.Result(0, "tendcf-install: disabled: org.tendcf.execd\n")
        raise AssertionError(f"unexpected guest installer subcommand {args}")

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

    def test_g6_evidence_counts_repeated_secure_token_lines(self):
        # F7b: more than one line is said, not hidden; still never a failure
        self.world.prep_token_line = SECURE_TOKEN_AFTER * 2
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["g6"]["evidence"]
        self.assertIn("[2 such lines in the prep output; first shown]", ev)

    def test_g6_shows_the_last_prep_result_line_and_counts_a_forged_earlier_one(self):
        # a guest command's lone CR becomes a line break in text mode: a line that looks like
        # PREP-RESULT can come before prep.sh's own, which is printed last (evidence only)
        self.world.prep_noise = "PREP-RESULT disabled=0 absent=0 failed=0\n"
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["g6"]["evidence"]
        self.assertIn("PREP-RESULT disabled=3 absent=22 failed=0", ev)
        self.assertNotIn("disabled=0 absent=0", ev)
        self.assertIn("[2 PREP-RESULT lines in the prep output; last shown]", ev)

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

    def test_issue81_check_adopt_and_golden_adopt_explicit_flags(self):
        # Build a golden, then remove its owner marker to simulate a pre-marker golden
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)
        marker = self.owner_file()
        rec = json.loads((self.ctx.state_dir / "golden.json").read_text())
        marker.unlink()

        # Plain check passes and NEVER writes the missing marker
        rc, s = self.run_cmd(*self.check_args(), ctx=self.second_run_ctx("20261125T000001Z-c"))
        self.assertEqual(rc, 0, s)
        self.assertFalse(marker.exists())
        # Plain golden stays strictly fail-closed
        rc, ev, _ = self.plain(self.second_run_ctx("20261125T000002Z-g"))
        self.assertEqual(rc, 2, ev)

        # check --adopt on a FAILING check does NOT write the marker
        self.world.fail_remote.add("spctl")
        rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000003Z-cf"))
        self.world.fail_remote.discard("spctl")
        self.assertEqual(rc, 1)
        self.assertFalse(marker.exists())
        self.assertEqual(self.steps(s)["adopt"]["status"], "skip")

        # check --adopt on a PASSING check writes the final owner marker
        rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000004Z-ca"))
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.steps(s)["adopt"]["status"], "pass")
        self.assertTrue(marker.exists())
        written = json.loads(marker.read_text())
        self.assertEqual(written["state"], "final")
        self.assertEqual(written["golden"], GOLDEN)
        self.assertEqual(written["state_dir"], os.path.realpath(self.ctx.state_dir))
        self.assertEqual(written["tart_home"], self.ctx.tart_home)
        self.assertEqual(written["key_id"], rec["key_id"])
        self.assertEqual(written["host_key"], rec["host_key"])

        # Subsequent plain golden now accepts it as ours ("nothing to do")
        rc, ev, _ = self.plain(self.second_run_ctx("20261125T000005Z-g2"))
        self.assertEqual(rc, 0, ev)
        self.assertIn("nothing to do", ev)

        # check --adopt is idempotent when final marker already matches this state dir
        rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000006Z-ca2"))
        self.assertEqual(rc, 0, s)
        self.assertIn("already owned", self.steps(s)["adopt"]["evidence"])

        # check --adopt refuses fail-closed if a final marker belongs to a DIFFERENT state dir
        other_dir = self.tmp / "other-state"
        other_dir.mkdir(mode=0o700)
        write_marker(self.ctx, state_dir=os.path.realpath(other_dir), state="final", key_id=rec["key_id"], host_key=rec["host_key"])
        clones_before = len(self.world.tart_calls("clone"))
        rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000007Z-ca3"))
        self.assertEqual(rc, 2)
        self.assertEqual(len(self.world.tart_calls("clone")), clones_before)

        # check --adopt refuses fail-closed if a committing marker exists (even for this state dir)
        write_marker(self.ctx, state="committing", key_id=rec["key_id"], host_key=rec["host_key"])
        rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000008Z-ca4"))
        self.assertEqual(rc, 2)
        self.assertIn("committing", s["steps"][-1]["evidence"])
        self.assertIn("golden --adopt", s["steps"][-1]["evidence"])
        self.assertEqual(len(self.world.tart_calls("clone")), clones_before)

        # Race check: if a committing marker appears mid-check before adoption writes, check --adopt refuses
        marker.unlink()
        orig_reboot = self.world._guest

        def plant_committing_on_reboot(r, input_text):
            if r[:4] == ["sudo", "-n", "shutdown", "-r"]:
                write_marker(self.ctx, state="committing", key_id=rec["key_id"], host_key=rec["host_key"])
            return orig_reboot(r, input_text)

        with mock.patch.object(self.world, "_guest", plant_committing_on_reboot):
            rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000009Z-race"))
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(marker.read_text())["state"], "committing")

        # PR 112 R1 Group 5 (Adversary B2): swapping golden.json/key mid-check before adoption
        # writes is refused (even if the new record still passes golden_usable, it does not match
        # the initial SSH-verified credentials).
        marker.unlink()
        new_key_id = "20261125T000099Z-swap"
        swap_pub, _ = drv.mint_keypair(self.ctx, new_key_id)
        swap_rec = {
            **rec,
            "key_id": new_key_id,
            "authorized_key": drv.fingerprint(swap_pub),
        }

        def swap_record_after_reboot_checks(r, input_text):
            res = orig_reboot(r, input_text)
            if r[0] == "dscl" and self.world.rebooted:
                (self.ctx.state_dir / "golden.json").write_text(json.dumps(swap_rec))
            return res

        with mock.patch.object(self.world, "_guest", swap_record_after_reboot_checks):
            rc, s = self.run_cmd("check", "--adopt", ctx=self.second_run_ctx("20261125T000009Z-swap"))
        self.assertEqual(rc, 2, s)
        self.assertIn("changed during check", s["steps"][-1]["evidence"])
        self.assertFalse(marker.exists())

    def test_issue81_golden_adopt_promotes_matching_committing_marker_and_refuses_otherwise(self):
        # Simulate a commit that stopped between golden.json and the final owner marker
        marker_name = self.owner_file().name
        patcher, _ = self.failing_writes({marker_name: 2})
        with patcher:
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1)
        marker = self.owner_file()
        self.assertEqual(json.loads(marker.read_text())["state"], "committing")

        # Plain golden stays strictly fail-closed
        rc, ev, _ = self.plain(self.second_run_ctx("20261125T000010Z-p"))
        self.assertEqual(rc, 2, ev)
        self.assertIn("did not finish", ev)

        # --adopt combined with --rebuild or --keep-on-failure is refused
        for bad_flag in ("--rebuild", "--keep-on-failure"):
            rc, s = self.run_cmd("golden", "--adopt", bad_flag, ctx=self.second_run_ctx("20261125T000011Z-bad"))
            self.assertEqual(rc, 2)
            self.assertIn("cannot be combined", s["steps"][-1]["evidence"])

        # Mismatched key_id or host_key in committing marker is refused fail-closed
        good_committing = marker.read_text()
        for field, bad_val in (("key_id", "wrong-key"), ("host_key", "ssh-ed25519 SHA256:wrong")):
            m_data = json.loads(good_committing)
            m_data[field] = bad_val
            marker.write_text(json.dumps(m_data))
            rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000012Z-mm"))
            self.assertEqual(rc, 2, field)
            self.assertEqual(json.loads(marker.read_text())["state"], "committing")

        # Committing marker owned by another state dir is refused
        other_dir = self.tmp / "other-state-2"
        other_dir.mkdir(mode=0o700)
        m_data = json.loads(good_committing)
        m_data["state_dir"] = os.path.realpath(other_dir)
        marker.write_text(json.dumps(m_data))
        rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000013Z-ot"))
        self.assertEqual(rc, 2)
        self.assertIn("belongs to state dir", s["steps"][-1]["evidence"])

        # Missing marker is refused by golden --adopt (directs to check --adopt)
        marker.unlink()
        rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000014Z-no"))
        self.assertEqual(rc, 2)
        self.assertIn("check --adopt", s["steps"][-1]["evidence"])

        # Missing golden VM in tart list is refused even with a matching committing marker
        marker.write_text(good_committing)
        saved_vm = self.world.vms.pop(GOLDEN)
        rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000015Z-vm"))
        self.assertEqual(rc, 2)
        self.assertIn("does not exist", s["steps"][-1]["evidence"])
        self.world.vms[GOLDEN] = saved_vm

        # PR 112 R1 Group 6 (Adversary B3): leftover <golden>-build VM refuses golden --adopt
        self.world.vms[f"{GOLDEN}-build"] = {"Running": False}
        rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000015Z-bld"))
        self.assertEqual(rc, 2)
        self.assertIn("leftover build VM", s["steps"][-1]["evidence"])
        self.assertEqual(json.loads(marker.read_text())["state"], "committing")
        self.world.vms.pop(f"{GOLDEN}-build")

        # Happy path: golden --adopt promotes the matching committing marker to final AND
        # cleans up parked .pending files left by the earlier interrupted commit (Group 6).
        self.assertTrue(self.pending_files(), "expected parked .pending files before adopt")
        rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000016Z-ok"))
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.steps(s)["adopt"]["status"], "pass")
        self.assertEqual(self.steps(s)["pending"]["status"], "pass")
        self.assertEqual(self.pending_files(), [])
        self.assertEqual(json.loads(marker.read_text())["state"], "final")

        # Idempotent when already final and matching
        rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000017Z-id"))
        self.assertEqual(rc, 0, s)
        self.assertIn("already final", self.steps(s)["adopt"]["evidence"])

        # Plain golden now says "nothing to do"
        rc, ev, _ = self.plain(self.second_run_ctx("20261125T000018Z-p2"))
        self.assertEqual(rc, 0, ev)
        self.assertIn("nothing to do", ev)

        # PR 112 R2 (Opus L7): OSError while unlinking parked .pending returns 1 (summary.ok False)
        marker.write_text(good_committing)
        stuck_pending = self.ctx.state_dir / "golden.json.pending"
        stuck_pending.write_text("{}")
        stuck_real = os.path.realpath(stuck_pending)
        orig_unlink = Path.unlink

        def fail_pending_unlink(p_self, *a, **kw):
            if os.path.realpath(p_self) == stuck_real:
                raise PermissionError("simulated pending unlink failure")
            return orig_unlink(p_self, *a, **kw)

        with mock.patch.object(Path, "unlink", fail_pending_unlink):
            rc, s = self.run_cmd("golden", "--adopt", ctx=self.second_run_ctx("20261125T000019Z-pf"))
        self.assertEqual(rc, 1, s)
        self.assertFalse(s["ok"])
        self.assertEqual(self.steps(s)["pending"]["status"], "fail")
        stuck_pending.unlink()

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

    def test_issue78_mid_build_intruder_vm_fails_boot_and_pin(self):
        # Issue #78 (Fable R1 / adversary r3 low 1): an intruder VM started after preflight
        # fails g2 (boot) and an intruder VM started before pin() fails g7 (pin) without pinning.
        # Case 1: intruder starts right after tart clone -> g2 fails
        real_run = self.world.run

        def start_intruder_after_clone(argv, **kw):
            res = real_run(argv, **kw)
            if argv[:2] == ["tart", "clone"]:
                self.world.vms["intruder-boot"] = {"Running": True}
            return res

        with mock.patch.object(self.world, "run", start_intruder_after_clone):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["g2"]["status"], "fail")
        self.assertIn("intruder-boot", self.steps(s)["g2"]["evidence"])
        self.assertNotIn(f"{GOLDEN}-build", self.world.vms)

        # Case 2: intruder starts right after prep.sh -> g7 (pin) fails before keyscan/pinning
        self.tearDown_world()
        real_run2 = self.world.run

        def start_intruder_after_prep(argv, **kw):
            res = real_run2(argv, **kw)
            if argv[:1] == ["ssh"] and "PREP-RESULT" in (kw.get("input_text") or ""):
                self.world.vms["intruder-pin"] = {"Running": True}
            return res

        with mock.patch.object(self.world, "run", start_intruder_after_prep):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["g7"]["status"], "fail")
        self.assertIn("intruder-pin", self.steps(s)["g7"]["evidence"])
        self.assertFalse((self.ctx.state_dir / "known_hosts").exists())
        self.assertNotIn(f"{GOLDEN}-build", self.world.vms)

    def test_f23_non_tart_vz_vm_refuses_golden_and_fails_boot_and_pin(self):
        # F23: other Virtualization.framework VM processes block golden preflight (limit=1),
        # assert_no_other_vm, boot() (g2), and pin() (g7), while non-VZ "Virtual" procs do not.
        # (c1) 1 other VZ VM at preflight -> Refusal (exit 2) and StepFail in assert_no_other_vm
        self.world.extra_vz_vms = 1
        with self.assertRaises(drv.StepFail) as cm:
            drv.assert_no_other_vm(self.ctx)
        self.assertIn("1 other Virtualization.framework VM", str(cm.exception))
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 2)
        self.assertEqual(s["steps"][-1]["step"], "refused")
        self.assertIn("1 other Virtualization.framework VM", s["steps"][-1]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])

        # (d1) Direct assert_no_other_vm(allowed=build): 1 VZ matching allowed passes; 2 VZ fails
        build = f"{GOLDEN}-build"
        self.world.vms = {build: {"Running": True}}
        self.world.extra_vz_vms = 0
        drv.assert_no_other_vm(self.ctx, allowed=build)  # 1 VZ == allowed_running -> ok
        self.world.extra_vz_vms = 1
        with self.assertRaises(drv.StepFail) as cm:
            drv.assert_no_other_vm(self.ctx, allowed=build)
        self.assertIn("1 other Virtualization.framework VM", str(cm.exception))

        # (c2) Other VZ VM starts right after tart clone -> boot() (g2) fails
        self.tearDown_world()
        real_run1 = self.world.run

        def start_vz_after_clone(argv, **kw):
            res = real_run1(argv, **kw)
            if argv[:2] == ["tart", "clone"]:
                self.world.extra_vz_vms = 1
            return res

        with mock.patch.object(self.world, "run", start_vz_after_clone):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["g2"]["status"], "fail")
        self.assertIn(
            "1 other Virtualization.framework VM", self.steps(s)["g2"]["evidence"]
        )
        self.assertNotIn(build, self.world.vms)

        # (d2) Other VZ VM starts right after prep.sh -> pin() (g7) fails before pinning
        self.tearDown_world()
        real_run2 = self.world.run

        def start_vz_after_prep(argv, **kw):
            res = real_run2(argv, **kw)
            if argv[:1] == ["ssh"] and "PREP-RESULT" in (kw.get("input_text") or ""):
                self.world.extra_vz_vms = 1
            return res

        with mock.patch.object(self.world, "run", start_vz_after_prep):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["g7"]["status"], "fail")
        self.assertIn(
            "1 other Virtualization.framework VM", self.steps(s)["g7"]["evidence"]
        )
        self.assertFalse((self.ctx.state_dir / "known_hosts").exists())
        self.assertNotIn(build, self.world.vms)

        # (e) Non-VZ processes with "Virtual" in the name, trailing/leading space, or \r are NOT counted
        self.tearDown_world()
        self.world.extra_ps_comms = [
            "/Library/Application Support/org.pqrs/Karabiner-VirtualHIDDevice",
            "/usr/local/bin/VirtualBoxVM",
            drv.VZ_VM_COMM + ".helper",
            drv.VZ_VM_COMM + " ",
            " " + drv.VZ_VM_COMM,
            drv.VZ_VM_COMM + "\r",
            drv.VZ_VM_COMM + "\r/sbin/launchd",
        ]
        self.assertEqual(drv.vz_vm_count(self.ctx), 0)
        self.assertTrue(self.world.ps_raw_newlines and all(self.world.ps_raw_newlines))
        rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 0, s)

    def test_issue78_tart_list_failing_during_commit_reports_unknown_state_and_keeps_build(
        self,
    ):
        # Issue #78 (Fable R5): if tart list fails during commit AFTER the committing marker
        # was written, g10 raises a ToolError clearly stating the build is kept and golden's
        # state is unknown.
        real_write = drv.atomic_write
        marker_name = self.owner_file().name
        intent_written = False

        def fail_list_after_intent(dest, text, mode=0o600):
            nonlocal intent_written
            res = real_write(dest, text, mode)
            if Path(dest).name == marker_name and not intent_written:
                intent_written = True
                self.world.fail_tart = {"list"}
            return res

        with mock.patch.object(drv, "atomic_write", fail_list_after_intent):
            rc, s = self.run_cmd(*self.golden_args())
        self.assertEqual(rc, 1, s)
        ev = self.steps(s)["g10"]["evidence"]
        self.assertIn("during commit failed", ev)
        self.assertIn("unknown", ev)
        self.assertIn(f"kept as {GOLDEN}-build", ev)
        self.assertIn(f"{GOLDEN}-build", self.world.vms)
        self.assertEqual(json.loads(self.owner_file().read_text())["state"], "committing")

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
            self.assertEqual(drv.account_home({"HOME": "relative/home"}), "/")
            self.assertEqual(drv.account_home({}), "/")
            self.assertEqual(
                drv.resolve_tart_home({"HOME": "/h"}), os.path.realpath("/h/.tart")
            )
            ctx = self.make_ctx(self.tmp / "nopw", "20261121T000000Z-np")
        self.assertTrue(ctx.tart_home)  # no traceback for a uid without a passwd entry

    def test_issue82_state_dir_ancestors_dangling_symlink_wording_and_paths(self):
        # Item 1: non-sticky group/world-writable ancestor is refused before creating anything
        parent = self.tmp / "writable-parent"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o777)
        target = parent / "sub" / "state"
        rc, s = self.run_cmd(
            *self.golden_args(), ctx=self.make_ctx(target, "20261125T000000Z-a1")
        )
        self.assertEqual(rc, 2, s)
        self.assertIn("must not be group or world writable unless sticky", s["steps"][-1]["evidence"])
        self.assertFalse((parent / "sub").exists())

        # Sticky world-writable ancestor owned by us (like /tmp 1777) is allowed
        os.chmod(parent, 0o1777)
        rc, s = self.run_cmd(
            *self.golden_args(), ctx=self.make_ctx(target, "20261125T000000Z-a2")
        )
        self.assertEqual(rc, 0, s)

        # Item 5: dangling symlink in an ancestor (--state-dir /tmp/link/sub) creates nothing
        dangling_target = self.tmp / "dangling-anc-target"
        dangling_link = self.tmp / "dangling-anc"
        dangling_link.symlink_to(dangling_target)
        rc, s = self.run_cmd(
            *self.golden_args(),
            ctx=self.make_ctx(dangling_link / "sub", "20261125T000000Z-a3"),
        )
        self.assertEqual(rc, 2, s)
        self.assertIn("points nowhere", s["steps"][-1]["evidence"])
        self.assertFalse(dangling_target.exists())

        # Item 6: root-owned leaf symlink wording + PermissionError != "points nowhere"
        real_dir = self.tmp / "root-target"
        real_dir.mkdir(mode=0o700)
        root_link = self.tmp / "root-link"
        root_link.symlink_to(real_dir)
        real_lstat = os.lstat

        def root_lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            if os.fspath(path) == os.path.abspath(root_link):
                fields = list(st)
                fields[stat.ST_UID] = 0
                return os.stat_result(fields)
            return st

        if os.geteuid() != 0:
            with mock.patch.object(drv.os, "lstat", root_lstat):
                msg = drv.state_dir_link_problem(root_link)
            self.assertIn("root-owned symlink (uid 0), not owned by you", msg)
            self.assertNotIn("owned by uid 0, not you", msg)

        real_dir_rp = os.path.realpath(real_dir)
        real_dir_str = str(real_dir)

        def eacces_lstat(path, *a, **kw):
            p_str = os.fspath(path)
            if p_str in (real_dir_rp, real_dir_str):
                raise PermissionError(errno.EACCES, "Permission denied", p_str)
            return real_lstat(path, *a, **kw)

        with mock.patch.object(drv.os, "lstat", eacces_lstat):
            msg = drv.state_dir_link_problem(root_link)
        self.assertIn("Permission denied", msg)
        self.assertNotIn("points nowhere", msg)

        # PR 112 R1 Group 4 (Adversary B1 + Neon #5):
        # 1) Lexical `..` must NOT bypass a foreign symlink ancestor (/tmp/foreign_link/../sub)
        tmp_rp = os.path.realpath(self.tmp)
        foreign_target = self.tmp / "foreign-dotdot-target"
        foreign_target.mkdir(mode=0o700)
        foreign_anc = self.tmp / "foreign-anc-link"
        foreign_anc.symlink_to(foreign_target)
        dotdot_path = foreign_anc / ".." / "sub"

        def foreign_anc_lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            if os.fspath(path) in (str(foreign_anc), tmp_rp + "/foreign-anc-link"):
                fields = list(st)
                fields[stat.ST_UID] = os.geteuid() + 1
                return os.stat_result(fields)
            return st

        with mock.patch.object(drv.os, "lstat", foreign_anc_lstat):
            msg = drv.state_dir_link_problem(dotdot_path)
        self.assertIn("not you or root", msg)

        # 2) Multi-hop symlink chain (my_link -> hop2_foreign -> real_dir) checks every hop
        hop2 = self.tmp / "hop2-foreign"
        hop2.symlink_to(real_dir)
        hop1 = self.tmp / "hop1-mine"
        hop1.symlink_to(hop2)

        def hop2_foreign_lstat(path, *a, **kw):
            st = real_lstat(path, *a, **kw)
            if os.fspath(path) in (str(hop2), tmp_rp + "/hop2-foreign"):
                fields = list(st)
                fields[stat.ST_UID] = os.geteuid() + 1
                return os.stat_result(fields)
            return st

        with mock.patch.object(drv.os, "lstat", hop2_foreign_lstat):
            msg = drv.state_dir_link_problem(hop1)
        self.assertIn("not you", msg)

        # 3) Symlink loop fails cleanly with Too many levels of symbolic links
        loop_a = self.tmp / "loop-a"
        loop_b = self.tmp / "loop-b"
        loop_a.symlink_to(loop_b)
        loop_b.symlink_to(loop_a)
        msg = drv.state_dir_link_problem(loop_a)
        self.assertIn("Too many levels of symbolic links", msg)
        self.assertNotIn("points nowhere", msg)

        # 4) Macroscope 4696228708: `..` after a missing component or regular file must not
        # bypass symlink checks via later os.path.realpath() lexical collapse.
        msg = drv.state_dir_link_problem(
            self.tmp / "missing-dir" / ".." / "foreign-anc-link" / "state"
        )
        self.assertIn("missing component", msg)
        msg = drv.state_dir_link_problem(self.tmp / "missing-dir" / "..")
        self.assertIn("missing component", msg)
        reg_file = self.tmp / "regular-file"
        reg_file.write_text("x")
        msg = drv.state_dir_link_problem(
            reg_file / ".." / "foreign-anc-link" / "state"
        )
        self.assertIn("not a directory", msg)
        # Normal missing tail with no `..` after missing still passes
        self.assertEqual(
            drv.state_dir_link_problem(self.tmp / "new_parent" / "new_state"), ""
        )

        # PR 112 R1 Group 8c: driver_lock refuses a non-sticky world-writable lock ancestor
        bad_lock_parent = self.tmp / "bad-lock-anc"
        bad_lock_parent.mkdir(mode=0o700)
        os.chmod(bad_lock_parent, 0o777)
        ctx_bad_lock = self.make_ctx(self.tmp / "state-lk", "20261125T000000Z-lka")
        ctx_bad_lock.lock_path = bad_lock_parent / "sub" / "driver.lock"
        rc, s = self.run_cmd(*self.golden_args(), ctx=ctx_bad_lock)
        self.assertEqual(rc, 2, s)
        self.assertIn("must not be group or world writable unless sticky", s["steps"][-1]["evidence"])
        os.chmod(bad_lock_parent, 0o700)

        # Item 4: resolved paths are consistent (ctx.lock_path.parent resolved like state_dir)
        ctx_paths = self.make_ctx(self.tmp / "state-consistent", "20261125T000000Z-a4")
        self.assertEqual(
            str(ctx_paths.lock_path.parent),
            os.path.realpath(self.tmp / "lockdir"),
        )

    def test_issue82_remove_vm_post_delete_local_vms_failure_keeps_committing_marker(self):
        # Item 2: when local_vms() raises AFTER `tart delete` actually deleted the old golden,
        # the handler must re-list on a best-effort basis and NEVER restore the old final marker
        # when the golden is gone or the re-list fails.
        for case in ("gone_on_relist", "relist_fails_too"):
            with self.subTest(case=case):
                self.tearDown_world()
                rc, s = self.run_cmd(*self.golden_args())
                self.assertEqual(rc, 0, s)
                marker = drv.owner_path(self.ctx, GOLDEN)
                self.assertEqual(json.loads(marker.read_text())["state"], "final")
                real_run = self.world.run
                deleted_golden = False
                post_delete_lists = 0

                def flaky_after_delete(argv, **kw):
                    nonlocal deleted_golden, post_delete_lists
                    if argv[:3] == ["tart", "delete", GOLDEN]:
                        res = real_run(argv, **kw)
                        deleted_golden = True
                        return res
                    if deleted_golden and argv[:3] == ["tart", "list", "--source"]:
                        post_delete_lists += 1
                        if post_delete_lists == 1 or case == "relist_fails_too":
                            return drv.Result(1, "", "tart list: transient error")
                    return real_run(argv, **kw)

                with mock.patch.object(self.world, "run", flaky_after_delete):
                    rc, s = self.run_cmd(
                        *self.golden_args("--rebuild"), ctx=self.second_run_ctx()
                    )
                self.assertEqual(rc, 1, s)
                ev = self.steps(s)["g10"]["evidence"]
                self.assertEqual(json.loads(marker.read_text())["state"], "committing")
                self.assertNotIn("restored", ev)
                if case == "gone_on_relist":
                    self.assertIn("now gone", ev)
                else:
                    self.assertIn("unknown", ev)
                # If a golden is present while the marker is committing, plain golden refuses (exit 2)
                self.world.vms[GOLDEN] = {"Running": False}
                rc2, ev2, _ = self.plain(self.second_run_ctx("20261125T000000Z-plain"))
                self.assertEqual(rc2, 2, ev2)
                self.assertIn("did not finish", ev2)

    def test_issue82_canonical_tart_home_folds_case_and_firmlink(self):
        # Item 3: two spellings of one TART_HOME produce the same canonical tart_home & marker
        d = self.tmp / "TartHomeCase"
        d.mkdir(mode=0o700)
        resolved = drv.canonical_dir_path(str(d))
        if sys.platform == "darwin":
            # Firmlink spelling (/System/Volumes/Data/...) and uppercase spelling (on case-insensitive APFS)
            sv_data = Path("/System/Volumes/Data" + resolved)
            if sv_data.exists():
                self.assertEqual(drv.canonical_dir_path(str(sv_data)), resolved)
                self.assertEqual(
                    drv.canonical_dir_path(str(sv_data / "nonexistent-sub")),
                    os.path.join(resolved, "nonexistent-sub"),
                )
            upper = str(d.parent / "TARTHOMECASE")
            if os.path.exists(upper) and os.path.samefile(upper, d):
                ctx1 = self.make_ctx(self.ctx.state_dir, "20261125T000000Z-c1", tart_home=str(d))
                ctx2 = self.make_ctx(self.ctx.state_dir, "20261125T000000Z-c2", tart_home=upper)
                self.assertEqual(ctx1.tart_home, ctx2.tart_home)
                self.assertEqual(drv.owner_path(ctx1, GOLDEN), drv.owner_path(ctx2, GOLDEN))
        # Also test F_GETPATH path explicitly on all platforms (including Linux CI) via mock
        with (
            mock.patch.object(drv, "F_GETPATH", 50),
            mock.patch.object(
                drv.fcntl,
                "fcntl",
                return_value=b"/Users/alice/.tart\x00" + b"\x00" * 1005,
            ),
        ):
            self.assertEqual(drv.canonical_dir_path(str(d)), "/Users/alice/.tart")
            self.assertEqual(
                drv.canonical_dir_path(str(d / "sub")), "/Users/alice/.tart/sub"
            )

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
            "1", "2a", "2b", "2c", "2d", "2e", "2f", "2g", "2h", "2i", "2j", "2k", "2l", "2m",
            "10", "10a", "11",
        ):  # fmt: skip
            self.assertEqual(st[sid]["status"], "pass", (sid, st[sid]))
        self.assertEqual(st["3"]["status"], "skip")
        self.assertIn("no artifact supplied", st["3"]["evidence"])
        for sid in ("4", "5", "6", "7", "8", "9", "9a"):
            self.assertEqual(st[sid]["status"], "skip")
            self.assertIn("no artifact supplied", st[sid]["evidence"])
        for sid in ("10b", "11a"):
            self.assertEqual(st[sid]["status"], "skip")
            self.assertIn("no artifact supplied", st[sid]["evidence"])
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

    def test_sshd_hardening_multi_spec_exact_once_extra_keys_match_and_10a_2f(self):
        # Issue #87: multi-spec -C (admin + root, loopback + guest/gateway IP),
        # A7 exact-once keys, extra auth settings, Match refusal, and 2f repeated in 10a.
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        expected_specs = {
            "user=admin,host=localhost,addr=127.0.0.1",
            "user=root,host=localhost,addr=127.0.0.1",
            "user=admin,host=192.168.64.10,addr=192.168.64.10",
            "user=root,host=192.168.64.10,addr=192.168.64.10",
            "user=admin,host=192.168.64.10,addr=192.168.64.1",
            "user=root,host=192.168.64.10,addr=192.168.64.1",
        }
        self.assertTrue(expected_specs.issubset(set(self.world.sshd_specs_seen)))

        # AuthenticationMethods any (macOS default on existing goldens) is accepted in 2e
        self.world.sshd_output = SSHD_CAMEL.replace(
            "AuthenticationMethods publickey", "AuthenticationMethods any"
        )
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)

        # Relaxing only the host-facing client spec or root spec fails 2e
        self.world.sshd_output = SSHD_CAMEL
        for bad_spec in (
            "user=admin,host=192.168.64.10,addr=192.168.64.1",
            "user=root,host=localhost,addr=127.0.0.1",
        ):
            with self.subTest(bad_spec=bad_spec):
                self.world.sshd_spec_outputs = {
                    bad_spec: SSHD_CAMEL.replace(
                        "PasswordAuthentication no", "PasswordAuthentication yes"
                    )
                }
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1)
                self.assertEqual(self.steps(s)["2e"]["status"], "fail")
                self.assertIn(bad_spec, self.steps(s)["2e"]["evidence"])
        self.world.sshd_spec_outputs = {}

        # A7 exact-once + extra auth keys + NUL rejection
        for name, out, want in (
            (
                "duplicate conflicting PasswordAuthentication",
                SSHD_CAMEL + "PasswordAuthentication yes\n",
                "duplicate keys",
            ),
            (
                "duplicate identical PasswordAuthentication",
                SSHD_CAMEL + "PasswordAuthentication no\n",
                "duplicate keys",
            ),
            (
                "GSSAPIAuthentication yes",
                SSHD_CAMEL.replace("GSSAPIAuthentication no", "GSSAPIAuthentication yes"),
                "gssapiauthentication no",
            ),
            (
                "HostbasedAuthentication yes",
                SSHD_CAMEL.replace("HostbasedAuthentication no", "HostbasedAuthentication yes"),
                "hostbasedauthentication no",
            ),
            (
                "AuthenticationMethods password",
                SSHD_CAMEL.replace("AuthenticationMethods publickey", "AuthenticationMethods password"),
                "authenticationmethods",
            ),
            (
                "NUL byte in sshd output",
                SSHD_CAMEL + "Banner /x\x00y\n",
                "NUL byte",
            ),
            (
                "non-ASCII duplicate PasswordAuthentication (PR 112 R1 Group 3)",
                SSHD_CAMEL + "PasswordAuthentication \ufffdno\n",
                "duplicate keys",
            ),
        ):
            with self.subTest(name):
                ok, ev = drv.sshd_key_only(drv.Result(0, out))
                self.assertFalse(ok, (name, ev))
                self.assertIn(want, ev, name)

        # PR 112 R3 (Codex M3): SSHD_MATCH_CHECK_SH runs BEFORE sshd -T on passing checks,
        # and a match/include check failure prevents sshd -T from ever being invoked
        # (so a FIFO Include target cannot hang sshd).
        self.world.sshd_call_order.clear()
        self.world.sshd_specs_seen.clear()
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertGreaterEqual(len(self.world.sshd_call_order), 2)
        self.assertEqual(self.world.sshd_call_order[0], "match")
        self.assertEqual(self.world.sshd_call_order[1], "sshd-T")

        # Uncommented Match block fails 2e BEFORE sshd -T is invoked
        self.world.sshd_call_order.clear()
        self.world.sshd_specs_seen.clear()
        self.world.sshd_match_rc = 2
        self.world.sshd_match_output = "/etc/ssh/crypto.conf:3: Match Address 192.168.64.0/20\n"
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["2e"]["status"], "fail")
        self.assertIn("Match", self.steps(s)["2e"]["evidence"])
        # Both 2e and 10a run match check first and skip sshd -T on failure
        self.assertEqual(self.world.sshd_call_order, ["match", "match"])
        self.assertEqual(self.world.sshd_specs_seen, [])
        self.world.sshd_match_rc = 0
        self.world.sshd_match_output = ""

        # Live password refusal (2f) is repeated after reboot in 10a
        self.world.password_login_after_reboot = True
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertEqual(self.steps(s)["2f"]["status"], "pass")
        self.assertEqual(self.steps(s)["10a"]["status"], "fail")
        self.assertIn("2f", self.steps(s)["10a"]["evidence"])
        self.assertIn("still offers", self.steps(s)["10a"]["evidence"])

    def test_sshd_match_check_sh_traverses_includes_prevents_cycles_and_catches_match(self):
        # Run SSHD_MATCH_CHECK_SH directly against real config trees with nested Includes
        base = Path(tempfile.mkdtemp(prefix="tendcf-sshd-match-"))
        self.addCleanup(shutil.rmtree, base, True)
        (base / "sshd_config.d").mkdir()
        (base / "crypto").mkdir()
        (base / "crypto" / "apple.conf").write_text("# comment\nCiphers aes256-gcm@openssh.com\n")
        (base / "crypto.conf").symlink_to(base / "crypto" / "apple.conf")
        (base / "sshd_config.d" / "100-macos.conf").write_text(
            "UsePAM yes\nInclude crypto.conf\n"
        )
        (base / "sshd_config").write_text(
            "# Match User foo\nInclude sshd_config.d/*\nPasswordAuthentication no\n"
        )
        run_check = lambda: subprocess.run(
            ["/bin/sh", "-c", drv.SSHD_MATCH_CHECK_SH, "sh", str(base / "sshd_config"), str(base)],
            capture_output=True,
            text=True,
            check=False,
        )
        r = run_check()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))

        # Include cycle does not infinite-loop
        (base / "crypto" / "apple.conf").write_text(
            f"Include {base / 'sshd_config.d' / '100-macos.conf'}\n"
        )
        r = run_check()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))

        # Uncommented Match inside a recursively included symlinked file fails closed
        (base / "crypto" / "apple.conf").write_text(
            "Match Address 192.168.64.0/20\n    PasswordAuthentication yes\n"
        )
        r = run_check()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("Match Address", r.stdout)

        # PR 112 R1 Group 1: all 5 bypasses + NUL + mid-line # + quoted keywords
        (base / "crypto" / "apple.conf").write_text("Ciphers aes256-gcm@openssh.com\n")
        # 1) Drop-in filename with space via glob
        spaced = base / "sshd_config.d" / "99 custom.conf"
        spaced.write_text("Match User root\n")
        r = run_check()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("Match User", r.stdout)
        spaced.unlink()

        # 2) Quoted Include with spaces in path ("dir with space/a.conf") + mid-token # + trailing # comment
        (base / "dir with space").mkdir()
        (base / "dir with space" / "a.conf").write_text('"Match" all\n')
        (base / "sshd_config").write_text(
            'Include a#nonexistent.conf "dir with space/a.conf" # trailing \'comment\'\n'
        )
        r = run_check()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("Match", r.stdout)

        # 3) Relative Include *.conf with a colliding file in cwd must expand under $base, not cwd
        colliding_cwd = Path(tempfile.mkdtemp(prefix="tendcf-sshd-cwd-"))
        self.addCleanup(shutil.rmtree, colliding_cwd, True)
        (colliding_cwd / "clean.conf").write_text("# clean in cwd\n")
        (base / "evil.conf").write_text("Match all\n")
        (base / "sshd_config").write_text("Include *.conf\n")
        r = subprocess.run(
            ["/bin/sh", "-c", drv.SSHD_MATCH_CHECK_SH, "sh", str(base / "sshd_config"), str(base)],
            cwd=str(colliding_cwd),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("Match all", r.stdout)
        (base / "evil.conf").unlink()

        # 4) Filename containing glob metacharacters (* and ?) cannot fool visited dedup
        (base / "sshd_config.d" / "a?b.conf").write_text("# harmless\n")
        (base / "sshd_config.d" / "a1b.conf").write_text("Match all\n")
        (base / "sshd_config").write_text("Include sshd_config.d/*\n")
        r = run_check()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("Match all", r.stdout)
        (base / "sshd_config.d" / "a?b.conf").unlink()
        (base / "sshd_config.d" / "a1b.conf").unlink()

        # 5) CRLF Include and Match\rall
        (base / "crlf_evil.conf").write_bytes(b"Match\rall\r\n")
        (base / "sshd_config").write_bytes(b"Include crlf_evil.conf\r\n")
        r = run_check()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("Match", r.stdout)
        (base / "crlf_evil.conf").unlink()

        # 6) NUL byte in config fails closed
        (base / "sshd_config").write_bytes(b"PasswordAuthentication no\x00\n")
        r = run_check()
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("NUL byte", r.stderr)

        # PR 112 R2 (Opus H1 + L5): obfuscated Match/Include keywords, single quotes,
        # backslash escapes, mid-token/unclosed quotes, leading ~, and non-regular FIFO targets
        (base / "d").mkdir()
        (base / "d" / "x.conf").write_text("Match User admin\n  PasswordAuthentication yes\n")
        (base / "sshd_config").write_text('M"atch" User admin\n  PasswordAuthentication yes\n')
        r = run_check()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn('M"atch"', r.stdout)

        for cfg_line, want_err in (
            (f'I"nclude" {base}/d/x.conf\n', "obfuscated Include keyword"),
            (f"In'cl'ude {base}/d/x.conf\n", "obfuscated Include keyword"),
            (f"Inc\\lude {base}/d/x.conf\n", "obfuscated Include keyword"),
            (f"Include '{base}/dir with space/a.conf'\n", "unsupported quote/escape"),
            (f"Include {base}/dir\\ with\\ space/a.conf\n", "unsupported quote/escape"),
            (f'Include {base}/d/"x".conf\n', "unsupported quote/escape"),
            (f'Include "{base}/d/""x".conf\n', "unsupported mid-token quote"),
            (f'Include "{base}/d/x.conf\n', "unclosed quote"),
            ("Include ~/evil.conf\n", "unsupported tilde"),
            ('Include "~/evil.conf"\n', "unsupported Include target"),
        ):
            (base / "sshd_config").write_text(cfg_line)
            r = run_check()
            self.assertEqual(r.returncode, 1, (cfg_line, r.stdout, r.stderr))
            self.assertIn(want_err, r.stderr, (cfg_line, r.stderr))

        # Opus L5: non-regular FIFO target matched by Include glob fails closed
        fifo = base / "sshd_config.d" / "50-pipe.conf"
        os.mkfifo(fifo)
        (base / "sshd_config").write_text("Include sshd_config.d/*\n")
        r = run_check()
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("non-regular sshd config target", r.stderr)
        fifo.unlink()

        # PR 112 R3 (Codex #1, #2, #4a, #4b): strdelim_internal closing-quote boundaries,
        # unclosed keyword quotes, interior CR / control bytes, and zero-argument Include
        for match_line, want_tok in (
            ('"Match"User admin\n  PasswordAuthentication yes\n', '"Match"'),
            ('M"atch"User admin\n  PasswordAuthentication yes\n', 'M"atch"'),
            ('"Match User admin\n  PasswordAuthentication yes\n', '"Match'),
        ):
            (base / "sshd_config").write_text(match_line)
            r = run_check()
            self.assertEqual(r.returncode, 2, (match_line, r.stdout, r.stderr))
            self.assertIn(want_tok, r.stdout)

        for cfg_line, want_err in (
            (f'"Include"{base}/d/x.conf\n', "ambiguous quoted keyword boundary"),
            (f'"Include"={base}/d/x.conf\n', "ambiguous quoted keyword boundary"),
            (f'"Include" = {base}/d/x.conf\n', "unsafe character in Include target"),
            (f'I"nclude"{base}/d/x.conf\n', "ambiguous quoted keyword boundary"),
            (f'"Include {base}/d/x.conf\n', "unclosed quote in sshd keyword"),
            ('"Unknown foo\n', "unclosed quote in sshd keyword"),
            ("Include\n", "Include directive with no arguments"),
            ("Include # comment\n", "Include directive with no arguments"),
            ("Include =\n", "Include directive with no arguments"),
        ):
            (base / "sshd_config").write_text(cfg_line)
            r = run_check()
            self.assertEqual(r.returncode, 1, (cfg_line, r.stdout, r.stderr))
            self.assertIn(want_err, r.stderr, (cfg_line, r.stderr))

        # Interior CR in Include filename fails closed (not rewritten into spaces)
        (base / "sshd_config").write_bytes(f"Include {base}/a\rb.conf\n".encode())
        r = run_check()
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("interior CR or control byte", r.stderr)

        # PR 112 R4 (Codex empty first keyword): leading "=" or "" fails closed;
        # blank lines and indented "# = Match" / '# "" Include' comments pass cleanly
        for cfg_line in (
            "= Match User admin\n  PasswordAuthentication yes\n",
            f"= Include {base}/d/x.conf\n",
            '"" Match User admin\n  PasswordAuthentication yes\n',
            f'"" Include {base}/d/x.conf\n',
        ):
            (base / "sshd_config").write_text(cfg_line)
            r = run_check()
            self.assertEqual(r.returncode, 1, (cfg_line, r.stdout, r.stderr))
            self.assertIn("empty sshd keyword", r.stderr, (cfg_line, r.stderr))
        (base / "sshd_config").write_text(
            '\n   \t\n# = Match User admin\n  # "" Include /etc/ssh/a.conf\nPasswordAuthentication no\n'
        )
        r = run_check()
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))

    def test_sshd_match_check_real_sshd_parity(self):
        # Verify against real /usr/sbin/sshd that every OpenSSH strdelim()/argv_split()
        # syntax variant that honours a Match in sshd -T is refused by BOTH
        # SSHD_MATCH_CHECK_SH and prep.sh's check_sshd_no_match.
        sshd_bin = Path("/usr/sbin/sshd")
        ssh_keygen = shutil.which("ssh-keygen")
        if not (sshd_bin.is_file() and os.access(sshd_bin, os.X_OK) and ssh_keygen):
            self.skipTest("/usr/sbin/sshd or ssh-keygen unavailable")
        base = Path(tempfile.mkdtemp(prefix="tendcf-sshd-parity-"))
        self.addCleanup(shutil.rmtree, base, True)
        hk = base / "host_ed25519"
        subprocess.run(
            [ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(hk)],
            check=True,
            capture_output=True,
        )
        (base / "dir with space").mkdir()
        (base / "dir with space" / "a.conf").write_text(
            "Match User admin\n  PasswordAuthentication yes\n"
        )
        (base / "d").mkdir()
        (base / "d" / "x.conf").write_text(
            "Match User admin\n  PasswordAuthentication yes\n"
        )
        (base / "cr\rx.conf").write_text(
            "Match User admin\n  PasswordAuthentication yes\n"
        )
        (base / "clean.conf").write_text("Ciphers aes256-gcm@openssh.com\n")
        prep_text = (VMDIR / "guest" / "prep.sh").read_text()
        a = prep_text.index("sshd_canon() {")
        b = prep_text.index('check_sshd_no_match "${SSHD_CONFIG:-/etc/ssh/sshd_config}"')
        prep_fn = (
            'die() { printf "prep.sh: %s\\n" "$*" >&2; exit 1; }\n'
            "set -eu\n"
            + prep_text[a:b]
            + 'check_sshd_no_match "$1"\n'
        )
        cfg = base / "sshd_config"

        # Clean baseline with blank lines, indented "# = Match" / '# "" Include' comments,
        # and trailing # comment containing a single quote: sshd keeps
        # PasswordAuthentication no, and both checkers pass.
        cfg.write_text(
            f'\n   \n# = Match User admin\n  # "" Include {base}/d/x.conf\n'
            f"PasswordAuthentication no\nInclude {base}/clean.conf # admin's comment\n"
        )
        r_sshd = subprocess.run(
            [str(sshd_bin), "-T", "-h", str(hk), "-f", str(cfg), "-C", "user=admin,host=x,addr=10.0.0.9"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_sshd.returncode, 0, r_sshd.stderr)
        self.assertIn("passwordauthentication no", r_sshd.stdout.lower().splitlines())
        r_drv = subprocess.run(
            ["/bin/sh", "-c", drv.SSHD_MATCH_CHECK_SH, "sh", str(cfg), str(base)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_drv.returncode, 0, (r_drv.stdout, r_drv.stderr))
        r_prep = subprocess.run(
            ["/bin/sh", "-c", prep_fn, "sh", str(cfg)],
            env={"PATH": "/usr/bin:/bin", "SSHD_BASE_DIR": str(base)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_prep.returncode, 0, (r_prep.stdout, r_prep.stderr))

        # All 14 live OpenSSH bypass variants (R2 Opus H1 + R3 Codex #1/#2 + R4 Codex empty keyword)
        variants = (
            (b'M"atch" User admin\n  PasswordAuthentication yes\n', "mid-token quoted Match"),
            (f'I"nclude" {base}/d/x.conf\n'.encode(), "mid-token quoted Include"),
            (f"Include '{base}/dir with space/a.conf'\n".encode(), "single-quoted Include"),
            (f"Include {base}/dir\\ with\\ space/a.conf\n".encode(), "backslash-escaped Include"),
            (f'Include {base}/d/"x".conf\n'.encode(), "mid-token quoted Include arg"),
            (f'"Include"{base}/d/x.conf\n'.encode(), "adjacent quoted Include"),
            (b'"Match"User admin\n  PasswordAuthentication yes\n', "adjacent quoted Match"),
            (b'M"atch"User admin\n  PasswordAuthentication yes\n', "adjacent mid-quoted Match"),
            (f'I"nclude"{base}/d/x.conf\n'.encode(), "adjacent mid-quoted Include"),
            (f"Include {base}/cr\rx.conf\n".encode(), "interior CR in Include filename"),
            (b"= Match User admin\n  PasswordAuthentication yes\n", "leading = before Match"),
            (f"= Include {base}/d/x.conf\n".encode(), "leading = before Include"),
            (b'"" Match User admin\n  PasswordAuthentication yes\n', "empty quoted keyword before Match"),
            (f'"" Include {base}/d/x.conf\n'.encode(), "empty quoted keyword before Include"),
        )
        for body, label in variants:
            cfg.write_bytes(b"PasswordAuthentication no\n" + body)
            r_sshd = subprocess.run(
                [str(sshd_bin), "-T", "-h", str(hk), "-f", str(cfg), "-C", "user=admin,host=x,addr=10.0.0.9"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_sshd.returncode, 0, (label, r_sshd.stderr))
            self.assertIn(
                "passwordauthentication yes",
                r_sshd.stdout.lower().splitlines(),
                f"{label}: expected real sshd to honour Match",
            )
            r_drv = subprocess.run(
                ["/bin/sh", "-c", drv.SSHD_MATCH_CHECK_SH, "sh", str(cfg), str(base)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_drv.returncode, 0, f"{label}: SSHD_MATCH_CHECK_SH failed to refuse")
            r_prep = subprocess.run(
                ["/bin/sh", "-c", prep_fn, "sh", str(cfg)],
                env={"PATH": "/usr/bin:/bin", "SSHD_BASE_DIR": str(base)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_prep.returncode, 0, f"{label}: prep.sh failed to refuse")

        # Additional R3 fail-closed cases (quoted keyword + "=", unclosed keyword quote, zero-arg Include)
        for body, label in (
            (f'"Include"={base}/d/x.conf\n'.encode(), "quoted Include with ="),
            (f'"Include {base}/d/x.conf\n'.encode(), "unclosed keyword quote"),
            (b"Include # comment\n", "zero-arg Include with comment"),
        ):
            cfg.write_bytes(b"PasswordAuthentication no\n" + body)
            r_drv = subprocess.run(
                ["/bin/sh", "-c", drv.SSHD_MATCH_CHECK_SH, "sh", str(cfg), str(base)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_drv.returncode, 0, f"{label}: SSHD_MATCH_CHECK_SH failed to refuse")
            r_prep = subprocess.run(
                ["/bin/sh", "-c", prep_fn, "sh", str(cfg)],
                env={"PATH": "/usr/bin:/bin", "SSHD_BASE_DIR": str(base)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_prep.returncode, 0, f"{label}: prep.sh failed to refuse")

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
        self.assertIn("listing:", st["10a"]["evidence"])
        self.assertIn("/System/Volumes/Data:", st["10a"]["evidence"])

    # -- 2h / 10a: automatic download and install are off; the schedule text is information only
    def test_2h_passes_with_checking_on_and_the_keys_at_zero(self):
        # what the real macOS 27.2 guest says: "turned on", and nothing can change that
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)["2h"]
        self.assertEqual(st["status"], "pass")
        self.assertIn("schedule (info): rc 0:", st["evidence"])
        self.assertIn("turned on", st["evidence"])
        for key in UPDATE_KEYS:
            self.assertIn(f"{key}=0", st["evidence"])

    def test_2h_never_reads_automaticcheckenabled(self):
        # softwareupdated deletes the key about 30 s after a write (addendum 4, method B)
        self.world.defaults_values["AutomaticCheckEnabled"] = (0, "1\n", "")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)["2h"]
        self.assertEqual(st["status"], "pass")
        self.assertNotIn("AutomaticCheckEnabled", st["evidence"])
        for argv in self.world.argvs(["defaults", "read"]):
            self.assertNotIn("AutomaticCheckEnabled", argv)

    def test_2h_schedule_text_is_information_and_never_decides(self):
        for name, answer in (
            ("turned on", (0, SU_ON)),
            ("turned off", (0, SU_OFF)),
            ("empty", (0, "")),
            ("both words", (0, SU_OFF + SU_ON)),
            ("something else", (0, "Software Update is disabled\n")),
            ("on on stderr", (0, SU_OFF, SU_ON)),
        ):
            with self.subTest(name):
                self.world.su_schedule = answer
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 0, s)
                st = self.steps(s)["2h"]
                self.assertEqual(st["status"], "pass", name)
                self.assertIn("schedule (info): rc 0:", st["evidence"], name)

    def test_2h_fails_when_the_schedule_command_fails(self):
        for name, answer in (
            ("exit 1 saying on", (1, SU_ON)),
            ("exit 1 saying off", (1, SU_OFF)),
            ("exit 1 empty", (1, "")),
            ("timeout", (124, "")),
        ):
            with self.subTest(name):
                self.world.su_schedule = answer
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)["2h"]
                self.assertEqual(st["status"], "fail", name)
                self.assertIn(f"schedule (info): rc {answer[0]}:", st["evidence"])

    def test_2h_needs_all_the_keys_prep_writes_at_zero(self):
        for key in UPDATE_KEYS:
            for name, answer in (
                ("reads 1", (0, "1\n", "")),
                ("key missing", (1, "", f"Error: Could not find key '{key}'.")),
                ("read error", (1, "", "Operation not permitted")),
                ("exit 1 with 0 on stdout", (1, "0\n", "")),
                ("0 then 1", (0, "0\n1\n", "")),
                ("0 only on stderr", (0, "", "0")),
            ):
                with self.subTest(key=key, case=name):
                    self.world.defaults_values[key] = answer
                    rc, s = self.run_cmd(*self.check_args())
                    self.assertEqual(rc, 1, s)
                    st = self.steps(s)["2h"]
                    self.assertEqual(st["status"], "fail")
                    self.assertIn(f"{key}=", st["evidence"])
                    if answer[0]:  # a non-0 exit is shown, never "Key=0"
                        self.assertIn(f"{key}=rc {answer[0]} ", st["evidence"])
                        self.assertNotIn(f"{key}=0", st["evidence"])
                        if not answer[1].strip() and answer[2].strip():
                            self.assertIn(
                                f"{key}=rc {answer[0]} stderr ", st["evidence"]
                            )
                    elif not answer[1].strip() and answer[2].strip():
                        # R5: a value read only from stderr is marked so the evidence says where it came from
                        self.assertIn(
                            f"{key}=stderr {answer[2].strip()!r}", st["evidence"]
                        )
                        self.assertNotIn(f"{key}=0", st["evidence"])
                    del self.world.defaults_values[key]

    def test_2h_does_not_mark_stderr_when_stdout_also_has_a_value(self):
        # T2 (kills F5/F7): when stdout has a value alongside stderr noise, stdout is shown
        # without a stderr mark.
        for rc_, prefix in ((0, ""), (1, "rc 1 ")):
            with self.subTest(rc=rc_):
                self.world.defaults_values["AutomaticDownload"] = (
                    rc_,
                    "1\n",
                    "warning\n",
                )
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                ev = self.steps(s)["2h"]["evidence"]
                self.assertEqual(self.steps(s)["2h"]["status"], "fail")
                self.assertIn(f"AutomaticDownload={prefix}'1'", ev)
                self.assertNotIn("AutomaticDownload=stderr", ev)
                self.assertNotIn(f"AutomaticDownload={prefix}stderr", ev)
                self.assertNotIn("warning", ev)
        del self.world.defaults_values["AutomaticDownload"]

    def test_2h_splatenabled_is_one_of_the_keys(self):
        self.assertIn("SplatEnabled", drv.UPDATES_KEYS)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertIn("SplatEnabled=0", self.steps(s)["2h"]["evidence"])

    def test_2h_evidence_clips_each_value_so_one_cannot_push_out_the_rest(self):
        self.world.defaults_values["AutomaticDownload"] = (1, "", "x" * 3000)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        ev = self.steps(s)["2h"]["evidence"]
        self.assertLess(len(ev), 1500)
        for key in UPDATE_KEYS[1:]:
            self.assertIn(f"{key}=0", ev)

    def test_2h_schedule_evidence_clips_at_200_and_escapes_control_chars(self):
        # M10: schedule text is clipped at 200 chars so long output cannot crowd out the keys
        self.world.su_schedule = (0, "s" * 500)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["2h"]["evidence"]
        self.assertIn("[+300 chars]", ev)
        self.assertNotIn("s" * 250, ev)
        for key in UPDATE_KEYS:
            self.assertIn(f"{key}=0", ev)
        # M11: !r escapes control characters and quotes the schedule text
        self.world.su_schedule = (0, "turned on\r\x1b[31mred\nline2")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["2h"]["evidence"]
        self.assertNotIn("\r", ev)
        self.assertNotIn("\n", ev)
        self.assertNotIn("\x1b", ev)
        self.assertIn("schedule (info): rc 0: 'turned on\\r\\x1b[31mred\\nline2'", ev)

    def test_2h_evidence_shows_stdout_and_stderr_of_the_schedule_command(self):
        self.world.su_schedule = (0, SU_OFF, "warning on stderr\n")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["2h"]["evidence"]
        self.assertIn("turned off", ev)
        self.assertIn("warning on stderr", ev)

    def test_10a_reruns_2h_with_the_same_rule(self):
        # the schedule text changing between the two reads does not matter ...
        self.world.su_outputs = [(0, SU_OFF), (0, SU_ON)]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.steps(s)["10a"]["status"], "pass")

    def test_10a_fails_when_the_schedule_command_fails_after_the_reboot(self):
        # ... but the command failing does
        self.world.su_outputs = [(0, SU_ON), (1, "")]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)
        self.assertEqual(st["2h"]["status"], "pass")
        self.assertEqual(st["10a"]["status"], "fail")
        self.assertIn(
            "2h automatic download and install off: schedule (info): rc 1:",
            st["10a"]["evidence"],
        )

    # -- PR 88 round r1: the order of the 2g rule, the per-volume rule, structured 10a note
    def test_2g_retries_transitioning_whatever_the_exit_status_was(self):
        # F1: the exit status of mdutil while Transitioning was never recorded
        self.world.mdutil_outputs = [
            (1, MDUTIL_TRANSITIONING),
            (1, MDUTIL_TRANSITIONING),
        ]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["2g"]["evidence"]
        self.assertEqual(self.steps(s)["2g"]["status"], "pass")
        self.assertIn("polls=3 waited=4s", ev)
        self.assertIn(
            "rcs=[1, 1, 0]", ev
        )  # every poll's exit status is in the evidence

    def test_2g_transitioning_with_exit_1_to_the_timeout_fails(self):
        self.world.mdutil_default = (1, MDUTIL_TRANSITIONING)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)["2g"]
        self.assertEqual(st["status"], "fail")
        self.assertIn("still transitioning", st["evidence"])
        self.assertIn("rc=1 polls=61 waited=120s", st["evidence"])

    def test_2g_wants_every_volume_with_exactly_one_disabled_line(self):
        root = "/:\n\tIndexing disabled.\n"
        cases = (
            ("header with no status", root + "/System/Volumes/Data:\n", "no status for"),
            (
                "header with no status, then another volume",
                root + "/System/Volumes/Data:\n/System/Volumes/Preboot:\n\tIndexing disabled.\n",
                "no status for /System/Volumes/Data:",
            ),
            (
                "status line ending in a colon",
                root + "/System/Volumes/Data:\n\tIndexing state:\n",
                "unexpected line",
            ),
            (
                "two statuses for one volume",
                root + "\tIndexing disabled.\n",
                "two statuses for /:",
            ),
            (
                "disabled and an unknown error",
                root + "/System/Volumes/Data:\n\tError: unknown indexing state.\n",
                "unexpected line",
            ),
            ("no root volume", "/System/Volumes/Data:\n\tIndexing disabled.\n", "no / volume"),
            ("no Data volume", root, "no /System/Volumes/Data volume"),
            (
                "similar Data path is not /System/Volumes/Data",
                root + "/Volumes/Data:\n\tIndexing disabled.\n",
                "no /System/Volumes/Data volume",
            ),
            (
                "root and Preboot without Data volume",
                root + "/System/Volumes/Preboot:\n\tIndexing disabled.\n",
                "no /System/Volumes/Data volume",
            ),
            ("status before any volume", "\tIndexing disabled.\n" + root, "status before any volume"),
            (
                "a CR is not a line break (CRLF)",
                "/:\r\n\tIndexing disabled.\r\n/System/Volumes/Data:\r\n\tIndexing disabled.\r\n",
                "unexpected line",
            ),
            (
                "a lone CR is not a line break",
                "/:\r\tIndexing disabled.\r/System/Volumes/Data:\r\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "CR-joined header hides an error status (H1)",
                MDUTIL_OFF_3 + "/Volumes/X:\r\tError: unknown indexing state.\r/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "FF-joined header hides an error status (H1)",
                MDUTIL_OFF_3 + "/Volumes/X:\x0c\tError: unknown indexing state.\x0c/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "VT inside header is unexpected",
                MDUTIL_OFF_3 + "/Volumes/X:\x0b\tError: unknown indexing state.\x0b/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "NUL inside header is unexpected",
                MDUTIL_OFF_3 + "/Volumes/X\x00:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "DEL inside header is unexpected",
                MDUTIL_OFF_3 + "/Volumes/X\x7f:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            ("a form feed is not a line break", root + "\x0c/Data:\n", "unexpected line"),
            (
                "header not starting with / is rejected",
                "foo:\n\tIndexing disabled.\n" + MDUTIL_OFF,
                "unexpected line",
            ),
            (
                "error-like header not starting with / is rejected",
                "Error: unknown:\n\tIndexing disabled.\n" + MDUTIL_OFF,
                "unexpected line",
            ),
            (
                "spoofed note header not starting with / is rejected",
                "polls=9 waited=99s:\n\tIndexing disabled.\n" + MDUTIL_OFF,
                "unexpected line",
            ),
            (
                "tab-joined header hiding error status is rejected",
                MDUTIL_OFF_3 + "/Volumes/X:\tError: unknown indexing state.\t/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "tab inside header path is rejected",
                MDUTIL_OFF_3 + "/Volumes/X\tY:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
        )  # fmt: skip
        for name, out, why in cases:
            with self.subTest(name):
                self.world.mdutil_default = (0, out)
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, s)
                st = self.steps(s)["2g"]
                self.assertEqual(st["status"], "fail", name)
                self.assertIn(why, st["evidence"], name)
        self.world.mdutil_default = (0, MDUTIL_OFF)

    def test_2g_passes_on_the_real_three_volume_listing(self):
        # T3/N4: the full macOS 27.2 listing observed in issue 70 run 4 passes 2g and 10a
        for name, listing in (
            ("three-volume listing", MDUTIL_OFF_3),
            (
                "extra volume with space in path",
                MDUTIL_OFF_3 + "/Volumes/Macintosh HD:\n\tIndexing disabled.\n",
            ),
            (
                # Opus N1 accepted trade-off: spaces and colons are legal in macOS volume
                # names, so a space-joined /...: line matches the header grammar (while
                # Indexing enabled / Transitioning remain checked across full output first).
                "space-joined /...: header trade-off",
                MDUTIL_OFF_3
                + "/Volumes/X: Error: unknown indexing state. /Volumes/Y:\n\tIndexing disabled.\n",
            ),
        ):
            with self.subTest(name):
                self.world.mdutil_default = (0, listing)
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 0, s)
                self.assertEqual(self.steps(s)["2g"]["status"], "pass")
                self.assertEqual(self.steps(s)["10a"]["status"], "pass")
                self.assertIn(
                    "/System/Volumes/Preboot:", self.steps(s)["10a"]["evidence"]
                )
        # Even inside a space-joined /...: header, Indexing enabled still fails immediately
        self.world.mdutil_default = (
            0,
            MDUTIL_OFF_3
            + "/Volumes/X: Indexing enabled. /Volumes/Y:\n\tIndexing disabled.\n",
        )
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["2g"]["status"], "fail")
        self.world.mdutil_default = (0, MDUTIL_OFF)

    def test_2g_and_10a_read_mdutil_with_raw_newlines(self):
        # Issue 89 item 2 (F8/A9): both 2g and 10a pass raw_newlines=True to rssh, so a CR
        # on stdout or stderr reaches mdutil_volumes_problem untranslated.
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertEqual(self.world.mdutil_raw_newlines, [True, True])
        crlf = MDUTIL_OFF.replace("\n", "\r\n")
        self.world.mdutil_default = (0, "", crlf)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["2g"]["status"], "fail")
        self.assertIn("unexpected line", self.steps(s)["2g"]["evidence"])
        self.world.mdutil_default = (0, MDUTIL_OFF)

    def test_2g_reads_stderr_too(self):
        hdrs = "/:\n/System/Volumes/Data:\n"
        # Transitioning only on stderr is retried, never passed; Indexing enabled on stderr fails
        self.world.mdutil_outputs = [
            (
                0,
                hdrs,
                "\tError: unexpected indexing state.  kMDConfigSearchLevelTransitioning\n",
            )
        ]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertIn("polls=2 ", self.steps(s)["2g"]["evidence"])
        self.world.mdutil_default = (0, MDUTIL_OFF, "\tIndexing enabled.\n")
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        self.assertIn("polls=1 ", self.steps(s)["2g"]["evidence"])
        self.world.mdutil_default = (0, MDUTIL_OFF)
        # the whole answer on stderr is read like stdout
        self.world.mdutil_default = (0, "", MDUTIL_OFF)
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.world.mdutil_default = (0, MDUTIL_OFF)

    def test_2g_one_volume_transitioning_with_the_others_disabled_is_retried(self):
        mixed = "/:\n\tIndexing disabled.\n" + MDUTIL_TRANSITIONING.split("\n", 2)[2]
        self.world.mdutil_outputs = [(0, mixed), (0, mixed)]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        self.assertIn("polls=3 waited=4s", self.steps(s)["2g"]["evidence"])
        self.world.mdutil_default = (0, mixed)  # and never passed while it lasts
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1, s)
        self.assertIn("still transitioning", self.steps(s)["2g"]["evidence"])
        self.world.mdutil_default = (0, MDUTIL_OFF)

    def test_10a_settle_note_is_the_drivers_own_value_not_guest_text(self):
        # A4 + Opus N4: a guest header containing the exact settle-note prefix must not be
        # taken for the driver's settle note; the real note appears strictly before listing:.
        spoof = (
            "/Volumes/2g after the reboot: polls=9 waited=99s:\n\tIndexing disabled.\n"
            + MDUTIL_OFF
        )
        self.world.mdutil_outputs = [(0, MDUTIL_OFF), (0, spoof)]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["10a"]["evidence"]
        self.assertIn("2g after the reboot: polls=1 waited=0s; listing: ", ev)
        self.assertLess(
            ev.index("2g after the reboot: polls=1 waited=0s"), ev.index("listing: ")
        )
        self.assertGreater(ev.index("polls=9 waited=99s"), ev.index("listing: "))
        self.assertIn("/Volumes/2g after the reboot: polls=9 waited=99s:", ev)

    def test_10a_pass_evidence_records_and_clips_post_reboot_mdutil_listing(self):
        # Issue 92 item 5: 10a pass evidence carries a clipped copy of the post-reboot
        # mdutil -a -s listing (not the pre-reboot 2g one).
        self.world.mdutil_outputs = [(0, MDUTIL_OFF), (0, MDUTIL_OFF_3)]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)
        self.assertNotIn("/System/Volumes/Preboot:", st["2g"]["evidence"])
        self.assertEqual(st["10a"]["status"], "pass")
        self.assertIn("listing: ", st["10a"]["evidence"])
        self.assertIn("/System/Volumes/Preboot:", st["10a"]["evidence"])

        long_vol = "/Volumes/" + "V" * 350 + ":\n\tIndexing disabled.\n"
        self.world.mdutil_outputs = [(0, MDUTIL_OFF), (0, MDUTIL_OFF + long_vol)]
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        ev = self.steps(s)["10a"]["evidence"]
        self.assertIn("...[+", ev)
        self.assertNotIn("V" * 320, ev)

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
            ("root:wheel 755 lrwxr-xr-x", True, False),  # PR 112 R1 Group 2: target symlink refused
        ):
            self.world.fw_owner = owner
            ok, ev = drv.check_root_owned(self.ctx, t, "/fw")
            self.assertEqual(ok, want, (owner, ev))
        # tree=True also rejects symlink target or non-directory regular file target
        for bad_target in ("root:wheel 755 lrwxr-xr-x", "root:wheel 644 -rw-r--r--"):
            self.world.fw_owner = bad_target
            ok, ev = drv.check_root_owned(self.ctx, t, "/fw", tree=True)
            self.assertFalse(ok, (bad_target, ev))
            self.assertIn("symlink or non-directory refused", ev)
        # Verify TREE_CHECK_SH itself rejects symlinks and checks dotfiles via `find -exec /bin/ls -lde`
        self.assertIn('test ! -L "$1" && test -d "$1"', drv.TREE_CHECK_SH)
        self.assertIn('find "$1" -exec /bin/ls -lde {} +', drv.TREE_CHECK_SH)
        td = Path(tempfile.mkdtemp(prefix="tendcf-tree-acl-"))
        self.addCleanup(shutil.rmtree, td, True)
        (td / ".hidden_dir").mkdir()
        hidden_f = td / ".hidden_dir" / ".secret"
        hidden_f.write_text("x")
        sym = td / "sym"
        sym.symlink_to(td / ".hidden_dir")
        # Symlink target to TREE_CHECK_SH fails non-zero
        r_sym = subprocess.run(
            ["/bin/sh", "-c", drv.TREE_CHECK_SH, "sh", str(sym)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(r_sym.returncode, 0)
        # Stub /bin/ls-like check: prove TREE_CHECK_SH's find -exec reaches hidden dotfiles
        fake_bin = Path(tempfile.mkdtemp(prefix="tendcf-tree-ls-"))
        self.addCleanup(shutil.rmtree, fake_bin, True)
        fake_ls = fake_bin / "ls"
        fake_ls.write_text(
            '#!/bin/sh\n'
            'for p in "$@"; do\n'
            '  case "$p" in\n'
            '    */.secret) echo "-rw-r--r--+ 1 root wheel 1 Nov 25 00:00 $p"; echo " 0: user:admin allow write" ;;\n'
            '  esac\n'
            'done\n'
        )
        fake_ls.chmod(0o755)
        tree_sh_test = drv.TREE_CHECK_SH.replace("/bin/ls", str(fake_ls))
        r_acl = subprocess.run(
            ["/bin/sh", "-c", tree_sh_test, "sh", str(td)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn("ACL:", r_acl.stdout)
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
            if r[:3] == ["stat", "-f", "%N %Su:%Sg %Lp %Sp"]:
                return drv.Result(1, "", "stat: boom")
            return orig(r, input_text)

        self.world._guest = silent
        ok, ev = drv.check_root_owned(self.ctx, t, path)
        self.assertFalse(ok)
        self.world._guest = orig

        # Issue #78: a symlink ancestor (e.g. /var -> /private/var) fails closed
        self.world.stat_overrides = {"/Library": "root:wheel 755 lrwxr-xr-x"}
        ok, ev = drv.check_root_owned(self.ctx, t, path)
        self.assertFalse(ok, ev)
        self.assertIn("lrwxr-xr-x", ev)
        self.world.stat_overrides = {}

        # Issue #78: macOS ACL on the target path or any ancestor fails closed even when tree=False
        for acl_p in (path, "/Library"):
            with self.subTest(acl_path=acl_p):
                self.world.acl_paths = {acl_p}
                ok, ev = drv.check_root_owned(self.ctx, t, path)
                self.assertFalse(ok, ev)
                self.assertIn("ACL check failed", ev)
        self.world.acl_paths = set()

        self.world.acl_check_fail = True
        ok, ev = drv.check_root_owned(self.ctx, t, path)
        self.assertFalse(ok, ev)
        self.assertIn("ACL check failed", ev)
        self.world.acl_check_fail = False

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

    def test_f20_hygiene_disable_list_matches_prep_sh(self):
        # F20: HYGIENE_DISABLE_LIST in state1_vm.py must stay in exact parity with prep.sh.
        prep_text = (VMDIR / "guest" / "prep.sh").read_text(encoding="utf-8")
        m = re.search(r"^DISABLE_LIST='\n(.*?)\n'$", prep_text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(m, "DISABLE_LIST block not found in prep.sh")
        parsed = tuple(
            tuple(line.split())
            for line in m.group(1).splitlines()
            if line.strip()
        )
        self.assertEqual(drv.HYGIENE_DISABLE_LIST, parsed)
        self.assertEqual(len(drv.HYGIENE_DISABLE_LIST), 25)
        self.assertEqual(
            sum(1 for d, _ in drv.HYGIENE_DISABLE_LIST if d == "system"), 6
        )
        self.assertEqual(sum(1 for d, _ in drv.HYGIENE_DISABLE_LIST if d == "gui"), 19)

    def test_f20_2m_and_10a_fail_on_system_hygiene_enabled_or_missing(self):
        for kind, attr, target_label in (
            ("system enabled", "hygiene_enabled", "com.apple.apsd"),
            ("system missing", "hygiene_missing", "com.apple.analyticsd"),
        ):
            with self.subTest(kind):
                self.world.hygiene_enabled = set()
                self.world.hygiene_missing = set()
                setattr(self.world, attr, {("system", target_label)})
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, kind)
                st = self.steps(s)
                self.assertEqual(st["2m"]["status"], "fail", kind)
                self.assertIn(f"system/{target_label}", st["2m"]["evidence"])
                self.assertEqual(st["10a"]["status"], "fail", kind)
                self.assertIn(f"system/{target_label}", st["10a"]["evidence"])

    def test_f20_2m_and_10a_fail_on_gui_hygiene_enabled_or_missing(self):
        for kind, attr, target_label in (
            ("user enabled", "hygiene_enabled", "com.apple.bird"),
            ("user missing", "hygiene_missing", "com.apple.tipsd"),
        ):
            with self.subTest(kind):
                self.world.hygiene_enabled = set()
                self.world.hygiene_missing = set()
                setattr(self.world, attr, {("gui", target_label)})
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, kind)
                st = self.steps(s)
                self.assertEqual(st["2m"]["status"], "fail", kind)
                self.assertIn(f"user/501/{target_label}", st["2m"]["evidence"])
                self.assertEqual(st["10a"]["status"], "fail", kind)
                self.assertIn(f"user/501/{target_label}", st["10a"]["evidence"])

    def test_f20_2m_and_10a_fail_closed_on_print_disabled_error_and_bad_uid(self):
        # launchctl print-disabled non-zero on system or user/<uid>
        for dom in ("system", "user/501"):
            with self.subTest(print_disabled_fail=dom):
                self.world.print_disabled_rc = {dom: 1}
                self.world.admin_uid_result = (0, "501\n", "")
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, dom)
                st = self.steps(s)
                self.assertEqual(st["2m"]["status"], "fail", dom)
                self.assertIn(dom, st["2m"]["evidence"])
                self.assertEqual(st["10a"]["status"], "fail", dom)
        self.world.print_disabled_rc = {}

        # id -u admin non-zero, empty, zero, leading-zero, whitespace, CR, NUL, out-of-range, or multi-line
        for label, res in (
            ("non-zero rc", (1, "", "id: admin: no such user\n")),
            ("empty output", (0, "", "")),
            ("zero uid", (0, "0\n", "")),
            ("leading zero", (0, "0501\n", "")),
            ("leading space", (0, " 501\n", "")),
            ("trailing space", (0, "501 \n", "")),
            ("crlf", (0, "501\r\n", "")),
            ("nul byte", (0, "501\x00\n", "")),
            ("out of uint32 range", (0, "4294967296\n", "")),
            ("non-numeric", (0, "admin\n", "")),
            ("negative", (0, "-501\n", "")),
            ("double newline", (0, "501\n\n", "")),
            ("multi-line", (0, "501\n502\n", "")),
        ):
            with self.subTest(bad_uid=label):
                self.world.admin_uid_result = res
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, label)
                st = self.steps(s)
                self.assertEqual(st["2m"]["status"], "fail", label)
                self.assertIn("id -u admin", st["2m"]["evidence"])
                self.assertEqual(st["10a"]["status"], "fail", label)

        # `=> true` variant passes cleanly (same semantics as 2j / prep.sh) and uses raw_newlines=True
        self.world.admin_uid_result = (0, "501\n", "")
        self.world.hygiene_use_true = True
        self.world.launchctl_raw_newlines.clear()
        self.world.uid_raw_newlines.clear()
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)
        st = self.steps(s)
        self.assertEqual(st["2m"]["status"], "pass")
        self.assertIn("25/25 hygiene jobs disabled (6 system, 19 user/501)", st["2m"]["evidence"])
        self.assertEqual(st["10a"]["status"], "pass")
        self.assertIn("2a-2m re-checked", st["10a"]["evidence"])
        self.assertTrue(
            self.world.launchctl_raw_newlines and all(self.world.launchctl_raw_newlines)
        )
        self.assertTrue(self.world.uid_raw_newlines and all(self.world.uid_raw_newlines))

    def test_r1_parse_launchctl_disabled_strict_fail_closed(self):
        # PR #113 R1 (Adversary M1/L1 + Neon M1): strict block parser rejects trailing garbage,
        # duplicates/contradictions, control bytes, malformed lines outside/inside `{ ... }`,
        # unclosed/nested blocks, and non-exact label matches (regex metachars, prefix/suffix).
        bad_blocks = (
            ("trailing garbage -no", 'disabled services = {\n\t"com.apple.apsd" => disabled-no\n}\n'),
            ("trailing garbage semicolon", 'disabled services = {\n\t"com.apple.apsd" => true; enabled\n}\n'),
            ("trailing garbage arrow", 'disabled services = {\n\t"com.apple.apsd" => disabled => enabled\n}\n'),
            (
                "duplicate disabled then enabled",
                'disabled services = {\n\t"com.apple.apsd" => disabled\n\t"com.apple.apsd" => enabled\n}\n',
            ),
            (
                "duplicate enabled then disabled",
                'disabled services = {\n\t"com.apple.apsd" => enabled\n\t"com.apple.apsd" => disabled\n}\n',
            ),
            (
                "duplicate disabled twice",
                'disabled services = {\n\t"com.apple.apsd" => disabled\n\t"com.apple.apsd" => disabled\n}\n',
            ),
            ("bare CR", 'disabled services = {\r\n\t"com.apple.apsd" => disabled\n}\n'),
            ("NUL byte", 'disabled services = {\n\t"com.apple.apsd" => disabled\x00\n}\n'),
            ("VT control byte", 'disabled services = {\n\t"com.apple.apsd" => disabled\x0b\n}\n'),
            ("line before open brace", 'noise\ndisabled services = {\n\t"com.apple.apsd" => disabled\n}\n'),
            ("line after close brace", 'disabled services = {\n\t"com.apple.apsd" => disabled\n}\nnoise\n'),
            ("malformed inside block", 'disabled services = {\n\tnot an entry\n}\n'),
            ("unclosed brace", 'disabled services = {\n\t"com.apple.apsd" => disabled\n'),
            ("missing open brace", '\t"com.apple.apsd" => disabled\n}\n'),
            ("nested open brace", 'disabled services = {\n{\n\t"com.apple.apsd" => disabled\n}\n}\n'),
            (
                "second block",
                'disabled services = {\n\t"com.apple.apsd" => disabled\n}\ndisabled services = {\n}\n',
            ),
        )
        for label, payload in bad_blocks:
            with self.subTest(parse_reject=label):
                with self.assertRaises(drv.StepFail):
                    drv.parse_launchctl_disabled(payload)

        # Regex metacharacter non-match and prefix/suffix non-match
        parsed = drv.parse_launchctl_disabled(
            'disabled services = {\n'
            '\t"comXappleXapsd" => disabled\n'
            '\t"com.apple.apsd.extra" => disabled\n'
            '\t"prefix.com.apple.apsd" => disabled\n'
            '}\n'
        )
        self.assertNotIn("com.apple.apsd", parsed)

        # End-to-end check: contradictory/malformed system output fails 2j, 2m, and 10a
        sys_good = "\n".join(
            ['\t"com.apple.screensharing" => disabled']
            + [
                f'\t"{lbl}" => disabled'
                for d, lbl in drv.HYGIENE_DISABLE_LIST
                if d == "system"
            ]
        )
        for label, bad_sys in (
            ("duplicate enabled after disabled", f'disabled services = {{\n{sys_good}\n\t"com.apple.apsd" => enabled\n}}\n'),
            ("trailing garbage", f'disabled services = {{\n{sys_good}\n\t"com.apple.foo" => true; enabled\n}}\n'),
            ("bare CR", f'disabled services = {{\r\n{sys_good}\n}}\n'),
        ):
            with self.subTest(e2e_system=label):
                self.world.print_disabled_override = {"system": bad_sys}
                rc, s = self.run_cmd(*self.check_args())
                self.assertEqual(rc, 1, label)
                st = self.steps(s)
                self.assertEqual(st["2j"]["status"], "fail", label)
                self.assertEqual(st["2m"]["status"], "fail", label)
                self.assertEqual(st["10a"]["status"], "fail", label)

        # End-to-end check: regex metachar / suffix spoofing in system fails 2m & 10a
        spoof_lines = ['\t"com.apple.screensharing" => disabled'] + [
            f'\t"{lbl.replace(".", "X") if lbl == "com.apple.apsd" else lbl}" => disabled'
            for d, lbl in drv.HYGIENE_DISABLE_LIST
            if d == "system"
        ] + ['\t"com.apple.apsd.extra" => disabled']
        self.world.print_disabled_override = {
            "system": "disabled services = {\n" + "\n".join(spoof_lines) + "\n}\n"
        }
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 1)
        st = self.steps(s)
        self.assertEqual(st["2j"]["status"], "pass")
        self.assertEqual(st["2m"]["status"], "fail")
        self.assertIn("system/com.apple.apsd", st["2m"]["evidence"])
        self.assertEqual(st["10a"]["status"], "fail")
        self.world.print_disabled_override = {}

    def test_f23_non_tart_vz_vms_enforced_in_check_and_vm_cap(self):
        # (a) 2 other VZ processes (0 tart VMs) -> Refusal in assert_vm_cap and check
        self.world.extra_vz_vms = 2
        with self.assertRaises(drv.Refusal) as cm:
            drv.assert_vm_cap(self.ctx)
        self.assertIn("2 other Virtualization.framework VMs", str(cm.exception))
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn(
            "2 other Virtualization.framework VMs", s["steps"][-1]["evidence"]
        )
        self.assertEqual(self.world.tart_calls("clone"), [])
        self.assertEqual(self.world.tart_calls("run"), [])

        # (b) 1 tart VM + 1 other VZ process (2 total) -> Refusal naming both
        self.world.vms["x"] = {"Running": True}
        self.world.extra_vz_vms = 1
        with self.assertRaises(drv.Refusal) as cm:
            drv.assert_vm_cap(self.ctx)
        self.assertIn("x", str(cm.exception))
        self.assertIn("1 other Virtualization.framework VM", str(cm.exception))
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 2)
        self.assertIn("x", s["steps"][-1]["evidence"])
        self.assertIn(
            "1 other Virtualization.framework VM", s["steps"][-1]["evidence"]
        )
        self.assertEqual(self.world.tart_calls("clone"), [])

        # (e) Non-VZ processes with "Virtual" in the name, trailing/leading space, or \r are not counted
        del self.world.vms["x"]
        self.world.extra_vz_vms = 0
        self.world.extra_ps_comms = [
            "/Library/Application Support/org.pqrs/Karabiner-VirtualHIDDevice",
            "/usr/local/bin/VirtualBoxVM",
            drv.VZ_VM_COMM + ".helper",
            drv.VZ_VM_COMM + " ",
            " " + drv.VZ_VM_COMM,
            drv.VZ_VM_COMM + "\r",
            drv.VZ_VM_COMM + "\r/sbin/launchd",
        ]
        self.world.ps_raw_newlines.clear()
        self.assertEqual(drv.vz_vm_count(self.ctx), 0)
        self.assertTrue(self.world.ps_raw_newlines and all(self.world.ps_raw_newlines))
        rc, s = self.run_cmd(*self.check_args())
        self.assertEqual(rc, 0, s)

        # (f) ps returning non-zero fails closed with ToolError
        self.world.ps_fail = True
        with self.assertRaises(drv.ToolError):
            drv.vz_vm_count(self.ctx)
        with self.assertRaises(drv.ToolError):
            drv.assert_vm_cap(self.ctx)
        with self.assertRaises(drv.ToolError):
            drv.assert_no_other_vm(self.ctx)

    def test_f22_clone_vm_passes_tart_no_auto_prune_1(self):
        # F22: clone_vm() always passes TART_NO_AUTO_PRUNE=1 (overriding os.environ too)
        self.world.vms["src-vm"] = {"Running": False}
        self.world.hostkeys["src-vm"] = NEW_BLOB
        with mock.patch.dict(os.environ, {"TART_NO_AUTO_PRUNE": "0"}, clear=False):
            r = drv.clone_vm(self.ctx, "src-vm", "dst-vm", 60)
        self.assertEqual(r.rc, 0)
        clone_call = next(
            (a, e)
            for a, e in reversed(self.world.calls)
            if a == ["tart", "clone", "src-vm", "dst-vm"]
        )
        self.assertEqual(clone_call[1]["TART_NO_AUTO_PRUNE"], "1")
        self.assertEqual(clone_call[1]["TART_HOME"], self.ctx.tart_home)

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
        self.assertEqual(r.stdout, "\ufffdx")
        r = drv.RealRunner().run(
            ["/bin/cat"], input_text="x\r\ny\r", timeout=30, raw_newlines=True
        )
        self.assertEqual(r.stdout, "x\r\ny\r")

    def test_default_text_mode_decodes_invalid_utf8_with_replacement(self):
        # Issue #87 Fable r3 nit 4: default text-mode path replaces invalid UTF-8
        # instead of crashing with an uncaught UnicodeDecodeError.
        r = drv.RealRunner().run([self.PRINTF, "\\377x"], timeout=30)
        self.assertEqual((r.rc, r.stdout), (0, "\ufffdx"))

    def test_raw_newlines_combined_with_log_path_is_refused(self):
        # Issue #87 Fable r3 nit 3: raw_newlines=True + log_path raises ValueError.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                drv.RealRunner().run(
                    [self.PRINTF, "ok"],
                    timeout=30,
                    raw_newlines=True,
                    log_path=Path(d) / "out.log",
                )

    def test_2e_matcher_on_real_runner_output(self):
        wrong = SSHD_CAMEL.replace(
            "PasswordAuthentication no", "PasswordAuthentication yes"
        )
        smuggled = wrong + "Banner /x\rPasswordAuthentication no\n"
        smuggled_missing = (
            SSHD_CAMEL.replace("PasswordAuthentication no\n", "")
            + "Banner /x\rPasswordAuthentication no\n"
        )
        # the real, observed CamelCase output passes, raw or not
        for raw in (True, False):
            ok, ev = drv.sshd_key_only(self.printf(SSHD_CAMEL, raw_newlines=raw))
            self.assertTrue(ok, ev)
        # a CR-smuggled line and a trailing CR fail on the raw bytes ...
        for name, text in (
            ("smuggled over wrong", smuggled),
            ("smuggled over missing", smuggled_missing),
            ("trailing CR", SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication no\r\n")),
        ):  # fmt: skip
            ok, ev = drv.sshd_key_only(self.printf(text, raw_newlines=True))
            self.assertFalse(ok, (name, ev))
            self.assertIn("carriage return", ev)
        # ... with A7 exact-once, smuggled over wrong fails even in default text mode as a duplicate,
        # while smuggled over missing still proves why raw_newlines=True is required
        ok, ev = drv.sshd_key_only(self.printf(smuggled))
        self.assertFalse(ok, ev)
        self.assertIn("duplicate keys", ev)
        ok, _ = drv.sshd_key_only(self.printf(smuggled_missing))
        self.assertTrue(ok, "the default decode turns the CR into a newline")

    def test_2g_matcher_on_real_runner_output(self):
        for raw in (True, False):
            r = self.printf(MDUTIL_OFF_3, raw_newlines=raw)
            self.assertIsNone(drv.mdutil_volumes_problem(r.stdout))
        for name, text in (
            ("CRLF", MDUTIL_OFF.replace("\n", "\r\n")),
            ("lone CR", MDUTIL_OFF.replace("\n", "\r")),
        ):
            r_raw = self.printf(text, raw_newlines=True)
            prob = drv.mdutil_volumes_problem(r_raw.stdout)
            self.assertIsNotNone(prob, name)
            self.assertIn("unexpected line", prob, name)
            # default text mode would have translated CR/CRLF to LF and let it pass
            r_default = self.printf(text, raw_newlines=False)
            self.assertIsNone(drv.mdutil_volumes_problem(r_default.stdout), name)
        # H1: CR-joined and FF-joined headers also fail on real raw runner output
        for name, sep in (("CR-joined header", "\r"), ("FF-joined header", "\x0c")):
            joined = (
                MDUTIL_OFF_3
                + f"/Volumes/X:{sep}\tError: unknown indexing state.{sep}/Volumes/Y:\n\tIndexing disabled.\n"
            )
            r_raw = self.printf(joined, raw_newlines=True)
            prob = drv.mdutil_volumes_problem(r_raw.stdout)
            self.assertIsNotNone(prob, name)
            self.assertIn("unexpected line", prob, name)


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
        # Issue #78 (Fable R3): actually deliver SIGTERM while the child script sleeps and
        # assert rc 129 and zero leftover temp files in /var/tmp.
        p = subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                'sudo() { shift; "$@"; }\n' + drv.RUN_SCRIPT_SH,
                "sh",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            assert p.stdin is not None and p.stdout is not None
            p.stdin.write("echo READY; sleep 30\n")
            p.stdin.close()
            self.assertEqual(p.stdout.readline(), "READY\n")
            during = set(Path("/var/tmp").glob("tendcf-state1.*")) - before
            self.assertEqual(len(during), 1, f"expected temp script while running: {during}")
            os.killpg(p.pid, signal.SIGTERM)
            rc = p.wait(timeout=10)
            self.assertEqual(rc, 129)
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
            for stream in (p.stdout, p.stderr):
                if stream is not None:
                    stream.close()
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
        # R2-1 / R4 / R5: slice line 85 and prove CR+LF flattening and LC_ALL=C survival
        a = text.index('log "secure token status (before):')
        snippet = text[a : text.index("\n", a) + 1]
        snap = Path(tempfile.mkdtemp(prefix="tendcf-prep-st-before-"))
        self.addCleanup(shutil.rmtree, snap, True)
        (snap / "before").mkdir()
        st_file = snap / "before" / "securetoken.txt"
        with self.subTest("CR and LF flattened, cannot forge after line"):
            st_file.write_bytes(
                b"Secure token is ENABLED\rprep: secure token status (after): FORGED\nline2\n"
            )
            r = self.run_snippet(
                snippet,
                {},
                {"SNAP": str(snap), "LC_ALL": "en_US.UTF-8"},
                links=("tr",),
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(b"\r", r.stdout)
            lines = [ln for ln in r.stdout.split(b"\n") if ln]
            self.assertEqual(len(lines), 1, lines)
            self.assertFalse(
                any(
                    ln.startswith(b"prep: secure token status (after):") for ln in lines
                )
            )
        with self.subTest("invalid UTF-8 under UTF-8 locale does not truncate"):
            st_file.write_bytes(b"before\xffafter\r\n")
            r = self.run_snippet(
                snippet,
                {},
                {"SNAP": str(snap), "LC_ALL": "en_US.UTF-8"},
                links=("tr",),
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            decoded = r.stdout.decode("utf-8")
            self.assertIn("before?after", decoded)
            self.assertNotIn(b"\xff", r.stdout)
            self.assertNotIn(b"\r", r.stdout)
            self.assertNotIn(b"Illegal byte sequence", r.stderr)

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
        # Issue #87: prep.sh step 7 checks Match blocks across recursive Includes, multi-spec
        # sshd -T -C (admin + root, loopback + host-facing), exact-once keys (A7), extra auth
        # keys, and NUL byte preservation via a temp file (A8).
        text = self.text("prep.sh")
        a = text.index("sshd_canon() {")
        b = text.index('log "sshd: key login only"', a)
        snippet = text[a:b]
        tmp = Path(tempfile.mkdtemp(prefix="tendcf-prep7-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        state_dir = tmp / "state"
        state_dir.mkdir()
        ssh_dir = tmp / "ssh"
        (ssh_dir / "sshd_config.d").mkdir(parents=True)
        (ssh_dir / "crypto.conf").write_text("Ciphers aes256-gcm@openssh.com\n")
        (ssh_dir / "sshd_config.d" / "100-macos.conf").write_text("Include crypto.conf\n")
        (ssh_dir / "sshd_config").write_text("Include sshd_config.d/*\n")
        specs_log = tmp / "specs.log"
        fake = tmp / "sshd"
        fake.write_text(
            '#!/bin/sh\n'
            'echo "$*" >>"$SPECS_LOG"\n'
            'if [ -n "${SSHD_FILE:-}" ]; then cat "$SSHD_FILE"; else printf "%s" "$SSHD_OUT"; fi\n'
            'exit "${SSHD_RC:-0}"\n'
        )
        fake.chmod(0o755)
        snippet = snippet.replace("/usr/sbin/sshd", str(fake))
        self.assertNotIn("/usr/sbin/sshd", snippet)
        self.assertIn(str(fake), snippet)
        stub = 'die() { printf "prep.sh: %s\\n" "$*" >&2; exit 1; }\n'
        base_env = {
            "PATH": "/usr/bin:/bin",
            "STATE_DIR": str(state_dir),
            "SSHD_CONFIG": str(ssh_dir / "sshd_config"),
            "SSHD_BASE_DIR": str(ssh_dir),
            "SSHD_CLIENT_ADDRS": "192.168.64.1",
            "SPECS_LOG": str(specs_log),
        }

        def run_step7(out=None, *, raw_bytes=None, rc_env="0"):
            if specs_log.exists():
                specs_log.unlink()
            env = {**base_env, "SSHD_RC": rc_env}
            if raw_bytes is not None:
                bf = tmp / "sshd.bin"
                bf.write_bytes(raw_bytes)
                env["SSHD_FILE"] = str(bf)
            else:
                env["SSHD_OUT"] = out
            r = subprocess.run(
                ["/bin/sh", "-c", stub + "set -eu\n" + snippet + "echo REACHED\n"],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(list(state_dir.iterdir()), [], "leaked sshd temp file")
            return r

        cases = (
            (SSHD_CAMEL, 0, ""),  # macOS 27.2, as observed
            (SSHD_LOWER, 0, ""),  # stock OpenSSH
            (SSHD_CAMEL.replace("PasswordAuthentication no", "PasswordAuthentication yes"),
             1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PubkeyAuthentication yes", "PubkeyAuthentication no"),
             1, "pubkeyauthentication yes"),
            (SSHD_CAMEL.replace("PermitRootLogin no", "PermitRootLogin no-password"),
             1, "permitrootlogin no"),  # whole line, not a prefix
            (SSHD_CAMEL.replace("GSSAPIAuthentication no", "GSSAPIAuthentication yes"),
             1, "gssapiauthentication no"),
            (SSHD_CAMEL.replace("HostbasedAuthentication no", "HostbasedAuthentication yes"),
             1, "hostbasedauthentication no"),
            (SSHD_CAMEL.replace("AuthenticationMethods publickey", "AuthenticationMethods any"),
             1, "authenticationmethods publickey"),
            (SSHD_CAMEL + "PasswordAuthentication yes\n", 1, "duplicate key: passwordauthentication"),
            ("", 1, "passwordauthentication no"),
            # padding, a CR on a wanted line, and a leading space are rejected
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication no  \n"),
             1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication no\r\n"),
             1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", " PasswordAuthentication no\n"),
             1, "passwordauthentication no"),
            # a CR on an unrelated line passes prep.sh (driver rejects any CR: Fable r3 nit 1)
            (SSHD_CAMEL.replace("UsePAM yes\n", "UsePAM yes\r\n"), 0, ""),
            # a separator inside a quoted value does not make a second line
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication yes\n")
             + "Banner /x\x0cPasswordAuthentication no\n", 1, "passwordauthentication no"),
            (SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication yes\n")
             + "Banner /x\u2028PasswordAuthentication no\n", 1, "passwordauthentication no"),
        )  # fmt: skip
        for out, want_rc, want_msg in cases:
            r = run_step7(out)
            self.assertEqual(r.returncode, want_rc, (out, r.stdout, r.stderr))
            self.assertIn(want_msg, r.stdout + r.stderr)
        # Verify all 4 specs (admin+root x loopback+host-facing) were evaluated on pass
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 0, r.stderr)
        seen_specs = specs_log.read_text().splitlines()
        for want_spec in (
            "-T -C user=admin,host=localhost,addr=127.0.0.1",
            "-T -C user=root,host=localhost,addr=127.0.0.1",
            "-T -C user=admin,host=192.168.64.1,addr=192.168.64.1",
            "-T -C user=root,host=192.168.64.1,addr=192.168.64.1",
        ):
            self.assertIn(want_spec, seen_specs)
        # A8: NUL bytes are preserved via the temp file and fail closed
        r = run_step7(raw_bytes=SSHD_CAMEL.encode() + b"Banner /x\x00y\n")
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("NUL byte", r.stderr)
        self.assertNotIn("REACHED", r.stdout)
        # CR-smuggled line and non-zero sshd exit fail closed
        smuggled = (
            SSHD_CAMEL.replace("PasswordAuthentication no\n", "PasswordAuthentication yes\n")
            + "Banner /x\rPasswordAuthentication no\n"
        )  # fmt: skip
        for out, rc_env in ((smuggled, "0"), (SSHD_CAMEL, "3")):
            r = run_step7(out, rc_env=rc_env)
            self.assertEqual(r.returncode, 1, (rc_env, r.stdout, r.stderr))
            self.assertNotIn("REACHED", r.stdout)
        # Uncommented Match in a recursively included file fails closed
        (ssh_dir / "crypto.conf").write_text("Match Address 192.168.64.0/20\n")
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("Match block", r.stderr)
        self.assertNotIn("REACHED", r.stdout)

        # PR 112 R1 Group 1 & 8a in prep.sh: space in globbed drop-in, quoted Include with space,
        # relative Include *.conf with colliding cwd, glob metachars (*, ?), CRLF Include/Match,
        # mid-line #, NUL byte in config, and sshd_specs dedup + invalid IP filtering.
        (ssh_dir / "crypto.conf").write_text("Ciphers aes256-gcm@openssh.com\n")
        # 1) Space in globbed drop-in
        spaced = ssh_dir / "sshd_config.d" / "99 custom.conf"
        spaced.write_text("Match User root\n")
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("Match block", r.stderr)
        spaced.unlink()
        # 2) Quoted Include with space + mid-token # + trailing # comment
        (ssh_dir / "dir with space").mkdir()
        (ssh_dir / "dir with space" / "a.conf").write_text('"Match" all\n')
        (ssh_dir / "sshd_config").write_text(
            'Include a#ignored.conf "dir with space/a.conf" # trailing \'comment\'\n'
        )
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("Match block", r.stderr)
        # 3) Relative Include *.conf with colliding file in cwd
        cwd_dir = Path(tempfile.mkdtemp(prefix="tendcf-prep7-cwd-"))
        self.addCleanup(shutil.rmtree, cwd_dir, True)
        (cwd_dir / "clean.conf").write_text("# clean\n")
        (ssh_dir / "bad.conf").write_text("Match all\n")
        (ssh_dir / "sshd_config").write_text("Include *.conf\n")
        r = subprocess.run(
            ["/bin/sh", "-c", stub + "set -eu\n" + snippet + "echo REACHED\n"],
            cwd=str(cwd_dir),
            capture_output=True,
            text=True,
            check=False,
            env={**base_env, "SSHD_OUT": SSHD_CAMEL, "SSHD_RC": "0"},
        )
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("Match block", r.stderr)
        (ssh_dir / "bad.conf").unlink()
        # 4) Filename containing ? does not swallow another filename via case wildcard
        (ssh_dir / "sshd_config.d" / "x?y.conf").write_text("# ok\n")
        (ssh_dir / "sshd_config.d" / "x1y.conf").write_text("Match all\n")
        (ssh_dir / "sshd_config").write_text("Include sshd_config.d/*\n")
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("Match block", r.stderr)
        (ssh_dir / "sshd_config.d" / "x?y.conf").unlink()
        (ssh_dir / "sshd_config.d" / "x1y.conf").unlink()
        # 5) CRLF Include + Match\rall
        (ssh_dir / "crlf.conf").write_bytes(b"Match\rall\r\n")
        (ssh_dir / "sshd_config").write_bytes(b"Include crlf.conf\r\n")
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("Match block", r.stderr)
        (ssh_dir / "crlf.conf").unlink()
        # 6) NUL byte in config file
        (ssh_dir / "sshd_config").write_bytes(b"PasswordAuthentication no\x00\n")
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("NUL byte", r.stderr)
        # 6b) PR 112 R2 (Opus H1 + L5): obfuscated Match/Include, single quotes, backslash,
        # mid-token/unclosed quotes, leading ~, and non-regular FIFO target in prep.sh
        (ssh_dir / "d").mkdir()
        (ssh_dir / "d" / "x.conf").write_text("Match User admin\n")
        for cfg_line, want_msg in (
            ('M"atch" User admin\n', "Match block"),
            (f'I"nclude" {ssh_dir}/d/x.conf\n', "obfuscated Include keyword"),
            (f"Include '{ssh_dir}/dir with space/a.conf'\n", "unsupported quote/escape"),
            (f"Include {ssh_dir}/dir\\ with\\ space/a.conf\n", "unsupported quote/escape"),
            (f'Include {ssh_dir}/d/"x".conf\n', "unsupported quote/escape"),
            ('Include "~/evil.conf"\n', "unsupported Include target"),
        ):
            (ssh_dir / "sshd_config").write_text(cfg_line)
            r = run_step7(SSHD_CAMEL)
            self.assertEqual(r.returncode, 1, (cfg_line, r.stdout, r.stderr))
            self.assertIn(want_msg, r.stderr, (cfg_line, r.stderr))
        fifo = ssh_dir / "sshd_config.d" / "50-pipe.conf"
        os.mkfifo(fifo)
        (ssh_dir / "sshd_config").write_text("Include sshd_config.d/*\n")
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("non-regular sshd config target", r.stderr)
        fifo.unlink()
        # 6c) PR 112 R3 (Codex #1, #2, #4a, #4b) in prep.sh: closing-quote boundaries,
        # unclosed keyword quote, interior CR in Include filename, and zero-arg Include
        for cfg_bytes, want_msg in (
            (b'"Match"User admin\n', "Match block"),
            (b'M"atch"User admin\n', "Match block"),
            (b'"Match User admin\n', "Match block"),
            (f'"Include"{ssh_dir}/d/x.conf\n'.encode(), "ambiguous quoted keyword boundary"),
            (f'"Include"={ssh_dir}/d/x.conf\n'.encode(), "ambiguous quoted keyword boundary"),
            (f'"Include {ssh_dir}/d/x.conf\n'.encode(), "unclosed quote in sshd keyword"),
            (f"Include {ssh_dir}/a\rb.conf\n".encode(), "interior CR or control byte"),
            (b"Include\n", "Include directive with no arguments"),
            (b"Include # comment\n", "Include directive with no arguments"),
            # PR 112 R4 (Codex empty first keyword)
            (b"= Match User admin\n", "empty sshd keyword"),
            (f"= Include {ssh_dir}/d/x.conf\n".encode(), "empty sshd keyword"),
            (b'"" Match User admin\n', "empty sshd keyword"),
            (f'"" Include {ssh_dir}/d/x.conf\n'.encode(), "empty sshd keyword"),
        ):
            (ssh_dir / "sshd_config").write_bytes(cfg_bytes)
            r = run_step7(SSHD_CAMEL)
            self.assertEqual(r.returncode, 1, (cfg_bytes, r.stdout, r.stderr))
            self.assertIn(want_msg, r.stderr, (cfg_bytes, r.stderr))
        # Positive control: blank lines and indented "# = Match" / '# "" Include' comments pass
        (ssh_dir / "sshd_config").write_text(
            '\n   \t\n# = Match User admin\n  # "" Include /etc/ssh/a.conf\nInclude sshd_config.d/*\n'
        )
        r = run_step7(SSHD_CAMEL)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        # 7) Group 8a: dedup 127.0.0.1 (via ,addr=) and skip non-IP tokens like link#4
        (ssh_dir / "sshd_config").write_text("Include sshd_config.d/*\n")
        if specs_log.exists():
            specs_log.unlink()
        r = subprocess.run(
            ["/bin/sh", "-c", stub + "set -eu\n" + snippet],
            capture_output=True,
            text=True,
            check=False,
            env={
                **base_env,
                "SSHD_CLIENT_ADDRS": "127.0.0.1 link#4 192.168.64.1 192.168.64.1",
                "SSHD_OUT": SSHD_CAMEL,
                "SSHD_RC": "0",
            },
        )
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        seen_dedup = specs_log.read_text().splitlines()
        self.assertEqual(len(seen_dedup), 4, seen_dedup)
        self.assertFalse(any("link#4" in s for s in seen_dedup))

    def fake_bin(self, name, body):
        d = Path(tempfile.mkdtemp(prefix="tendcf-prep-fake-"))
        self.addCleanup(shutil.rmtree, d, True)
        f = d / name
        f.write_text("#!/bin/sh\n" + body)
        f.chmod(0o755)
        return d

    def run_snippet(
        self, snippet, fakes, env=None, links=(), *, raw_bytes=False, pre="", cwd=None
    ):
        """Run a slice of prep.sh with only fake tools on PATH (plus the named host tools,
        symlinked into the fake directory): the host's own tools cannot be reached."""
        d = Path(tempfile.mkdtemp(prefix="tendcf-prep-fake-"))
        self.addCleanup(shutil.rmtree, d, True)
        for name, body in fakes.items():
            f = d / name
            f.write_text("#!/bin/sh\n" + body)
            f.chmod(0o755)
        for name in links:
            (d / name).symlink_to(shutil.which(name, path="/usr/bin:/bin"))
        stub = (
            'die() { printf "prep.sh: %s\\n" "$*" >&2; exit 1; }\n'
            'log() { printf "prep: %s\\n" "$*"; }\n'
        )
        return subprocess.run(
            ["/bin/sh", "-c", stub + "set -eu\n" + pre + snippet],
            capture_output=True,
            text=not raw_bytes,
            check=False,
            env={"PATH": str(d), **(env or {})},
            cwd=cwd,
        )

    def _prep_mdutil_snippet(self):
        text = self.text("prep.sh")
        a = text.index("SECONDS=0")
        b = text.index('log "spotlight: off', a)
        return text[a : text.index("\n", b) + 1]

    def test_prep_settles_mdutil_with_a_bounded_retry(self):
        snippet = self._prep_mdutil_snippet()
        for host in (
            "/usr/bin/mdutil",
            "/usr/bin/awk",
            "/bin/sleep",
            "/usr/bin/tr",
            "/usr/bin/mktemp",
        ):
            self.assertNotIn(host, snippet)
        self.assertNotIn("date +%s", snippet)
        self.assertNotIn("TMPDIR", snippet)
        self.assertIn('mktemp -- "$STATE_DIR/tendcf-mdutil.XXXXXX"', snippet)
        self.assertIn("trap 'exit 129' HUP INT TERM", snippet)
        self.assertIn("trap - EXIT HUP INT TERM", snippet)
        self.assertIn("LC_ALL=C tr", snippet)
        self.assertIn("LC_ALL=C awk", snippet)
        seq = Path(tempfile.mkdtemp(prefix="tendcf-prep-seq-"))
        self.addCleanup(shutil.rmtree, seq, True)
        state_check = Path(tempfile.mkdtemp(prefix="tendcf-prep-state-"))
        self.addCleanup(shutil.rmtree, state_check, True)
        fakes = {
            # the Nth call prints $SEQ/out.N (else out.last) and costs MDUTIL_COST seconds of
            # the fake clock; if BACKSTEP is set, call 2 steps the clock backwards by that many
            # seconds; sleep advances it; the shell wrappers below sync $SECONDS from $SEQ/clock;
            # the exit status is MDUTIL_RC
            "mdutil": 'D=$SEQ; n=$(cat "$D/n" 2>/dev/null || echo 0); n=$((n + 1)); '
            'echo "$n" >"$D/n"; echo "$n" >>"$D/calls"; f="$D/out.$n"; [ -f "$f" ] || f="$D/out.last"; '
            'c=$(cat "$D/clock"); '
            'if [ -n "${BACKSTEP:-}" ] && [ "$n" -eq 2 ]; then c=$((c - BACKSTEP)); fi; '
            'echo $((c + ${MDUTIL_COST:-0})) >"$D/clock"; '
            'cat "$f"; exit "${MDUTIL_RC:-0}"\n',
            "sleep": 'c=$(cat "$SEQ/clock"); echo $((c + $1)) >"$SEQ/clock"; echo "$1" >>"$SEQ/slept"\n',
        }
        clock_wrappers = (
            'mdutil() { _rc=0; command mdutil "$@" || _rc=$?; SECONDS=$(cat "$SEQ/clock"); return "$_rc"; }\n'
            'sleep() { command sleep "$@"; SECONDS=$(cat "$SEQ/clock"); }\n'
        )

        def run(
            outs,
            last,
            rc="0",
            cost="0",
            backstep="",
            extra_env=None,
            raw_bytes=False,
            state_dir=None,
            cwd=None,
        ):
            for f in seq.iterdir():
                f.unlink()
            check_dir = state_check if state_dir is None else Path(cwd or ".") / state_dir
            for f in check_dir.iterdir():
                f.unlink()
            for i, o in enumerate(outs, 1):
                (seq / f"out.{i}").write_text(o)
            if isinstance(last, bytes):
                (seq / "out.last").write_bytes(last)
            else:
                (seq / "out.last").write_text(last)
            (seq / "clock").write_text("0\n")
            res = self.run_snippet(
                snippet,
                fakes,
                {
                    "SEQ": str(seq),
                    "STATE_DIR": str(state_check) if state_dir is None else state_dir,
                    "TMPDIR": "/nonexistent-tmpdir-must-not-be-used",
                    "MDUTIL_RC": rc,
                    "MDUTIL_COST": cost,
                    "BACKSTEP": backstep,
                    **(extra_env or {}),
                },
                links=("awk", "cat", "mktemp", "tr", "rm"),
                raw_bytes=raw_bytes,
                pre=clock_wrappers,
                cwd=cwd,
            )
            # mktemp file under STATE_DIR must be cleaned up on every pass and failure path
            self.assertEqual(list(check_dir.iterdir()), [], "leaked mdutil mktemp file")
            return res

        def slept():
            f = seq / "slept"
            return f.read_text().split() if f.exists() else []

        def calls():
            f = seq / "calls"
            return len(f.read_text().split()) if f.exists() else 0

        r = run([MDUTIL_TRANSITIONING] * 2, MDUTIL_OFF)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = re.search(r"3 poll\(s\), (\d+) s elapsed", r.stdout)
        self.assertIsNotNone(m, r.stdout)
        self.assertGreaterEqual(int(m.group(1)), 4, r.stdout)
        self.assertLessEqual(int(m.group(1)), 6, r.stdout)
        self.assertEqual(slept(), ["2", "2"])
        # F1: Transitioning with exit 1 is retried; to the timeout it dies, 120 s elapsed
        r = run([MDUTIL_TRANSITIONING], MDUTIL_OFF, rc="1")
        self.assertEqual(r.returncode, 1)  # the final answer has exit 1: not a pass
        self.assertIn("mdutil -a -s failed (rc 1)", r.stderr)
        self.assertGreaterEqual(calls(), 2)
        r = run([], MDUTIL_TRANSITIONING, rc="1")
        self.assertEqual(r.returncode, 1)
        m = re.search(r"still transitioning after (\d+) s", r.stderr)
        self.assertIsNotNone(m, r.stderr)
        self.assertGreaterEqual(int(m.group(1)), 120, r.stderr)
        self.assertLessEqual(int(m.group(1)), 122, r.stderr)
        self.assertIn("(rc 1)", r.stderr)
        self.assertIn(len(slept()), (59, 60))
        # F4: real elapsed time, not the number of waits: a slow mdutil shortens the loop
        r = run([], MDUTIL_TRANSITIONING, cost="30")
        self.assertEqual(r.returncode, 1)
        self.assertIn("still transitioning after", r.stderr)
        self.assertLess(calls(), 10)
        # F9/A10 + Issue 92 item 4: a backwards clock step cannot stretch the loop past the
        # 65-poll cap, and printed elapsed seconds are clamped at >= 0 (never negative)
        r = run([], MDUTIL_TRANSITIONING, backstep="600")
        self.assertEqual(r.returncode, 1)
        self.assertIn("still transitioning after 0 s, 65 poll(s)", r.stderr)
        self.assertEqual(calls(), 65)
        self.assertEqual(len(slept()), 64)
        # Pass log elapsed seconds are also clamped at >= 0 after a backwards step
        r = run([MDUTIL_TRANSITIONING, MDUTIL_TRANSITIONING], MDUTIL_OFF, backstep="600")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("3 poll(s), 0 s elapsed", r.stdout)
        # enabled is never retried into a pass, before or after a Transitioning poll
        for outs in ([MDUTIL_ON], [MDUTIL_TRANSITIONING]):
            r = run(outs, MDUTIL_ON)
            self.assertEqual(r.returncode, 1)
            self.assertIn("still enabled", r.stderr)
        # the per-volume rule, same as the driver's
        root = "/:\n\tIndexing disabled.\n"
        for name, out, why in (
            ("header with no status", root + "/System/Volumes/Data:\n", "no status for"),
            (
                "header with no status, then another volume",
                root + "/System/Volumes/Data:\n/System/Volumes/Preboot:\n\tIndexing disabled.\n",
                "no status for /System/Volumes/Data:",
            ),
            ("status ending in a colon", root + "/Data:\n\tIndexing state:\n", "unexpected line"),
            ("two statuses", root + "\tIndexing disabled.\n", "two statuses for /:"),
            ("disabled and an unknown error", root + "/Data:\n\tError: unknown indexing state.\n", "unexpected line"),
            ("no root volume", "/System/Volumes/Data:\n\tIndexing disabled.\n", "no / volume listed"),
            ("no Data volume", root, "no /System/Volumes/Data volume listed"),
            (
                "similar Data path is not /System/Volumes/Data",
                root + "/Volumes/Data:\n\tIndexing disabled.\n",
                "no /System/Volumes/Data volume listed",
            ),
            (
                "root and Preboot without Data volume",
                root + "/System/Volumes/Preboot:\n\tIndexing disabled.\n",
                "no /System/Volumes/Data volume listed",
            ),
            ("empty", "", "no volume listed"),
            (
                "a CR is not a line break",
                "/:\r\n\tIndexing disabled.\r\n/System/Volumes/Data:\r\n\tIndexing disabled.\r\n",
                "unexpected line",
            ),
            (
                "CR-joined header hides an error status (H1)",
                MDUTIL_OFF_3 + "/Volumes/X:\r\tError: unknown indexing state.\r/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "FF-joined header hides an error status (H1)",
                MDUTIL_OFF_3 + "/Volumes/X:\x0c\tError: unknown indexing state.\x0c/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "VT inside header is unexpected",
                MDUTIL_OFF_3 + "/Volumes/X:\x0b\tError: unknown indexing state.\x0b/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "DEL inside header is unexpected",
                MDUTIL_OFF_3 + "/Volumes/X\x7f:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "header not starting with / is rejected",
                "foo:\n\tIndexing disabled.\n" + MDUTIL_OFF,
                "unexpected line",
            ),
            (
                "error-like header not starting with / is rejected",
                "Error: unknown:\n\tIndexing disabled.\n" + MDUTIL_OFF,
                "unexpected line",
            ),
            (
                "tab-joined header hiding error status is rejected",
                MDUTIL_OFF_3 + "/Volumes/X:\tError: unknown indexing state.\t/Volumes/Y:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
            (
                "tab inside header path is rejected",
                MDUTIL_OFF_3 + "/Volumes/X\tY:\n\tIndexing disabled.\n",
                "unexpected line",
            ),
        ):  # fmt: skip
            with self.subTest(name):
                r = run([], out)
                self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
                self.assertIn(why, r.stderr)
                self.assertEqual(slept(), [])
        # Issue 92 item 2 + PR 100 R1 Adversary #1: NUL bytes in mdutil output are preserved
        # via root-only $STATE_DIR mktemp + single LC_ALL=C tr -> $mdutil_out and rejected
        # (including EOF NUL and a NUL-joined header with NO tab, which specifically proves
        # NUL detection independently of item 1's tab rejection).
        for name, raw_out, want_msg in (
            (
                "NUL inside header is rejected",
                MDUTIL_OFF_3.encode() + b"/Volumes/X\x00:\n\tIndexing disabled.\n",
                b"unexpected line",
            ),
            (
                "NUL-joined header without tab hides error status",
                MDUTIL_OFF_3.encode()
                + b"/Volumes/X:\x00Error: unknown indexing state.\x00/Volumes/Y:\n\tIndexing disabled.\n",
                b"unexpected line",
            ),
            (
                "NUL splitting Indexing enabled is rejected",
                MDUTIL_OFF_3.encode() + b"/Volumes/X:\n\tIndexing\x00 enabled.\n",
                b"unexpected line",
            ),
            (
                "EOF NUL after valid listing is rejected",
                MDUTIL_OFF_3.encode() + b"\x00",
                b"unexpected line",
            ),
            (
                "only newlines is rejected as no volume listed",
                b"\n\n\n",
                b"no volume listed",
            ),
        ):
            with self.subTest(name):
                r = run([], raw_out, raw_bytes=True)
                self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
                self.assertIn(want_msg, r.stderr)
                self.assertEqual(slept(), [])
        r = run([], MDUTIL_OFF)  # all volumes disabled passes
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run([], MDUTIL_OFF_3)  # T3/N4: full real 27.2 three-volume listing passes
        self.assertEqual(r.returncode, 0, r.stderr)
        # Positive check for tightened grammar: spaces in volume names still pass, and
        # (Opus N1 accepted trade-off) a space-joined /...: line still matches header grammar
        # while Indexing enabled remains checked across the full output first.
        r = run([], MDUTIL_OFF_3 + "/Volumes/Macintosh HD:\n\tIndexing disabled.\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(
            [],
            MDUTIL_OFF_3
            + "/Volumes/X: Error: unknown indexing state. /Volumes/Y:\n\tIndexing disabled.\n",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(
            [],
            MDUTIL_OFF_3
            + "/Volumes/X: Indexing enabled. /Volumes/Y:\n\tIndexing disabled.\n",
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("still enabled", r.stderr)
        # PR 100 R1 Adversary #1/#3: mktemp -- and rm -f -- handle a leading '-' in STATE_DIR
        # cleanly, and TMPDIR is never consulted.
        dash_parent = Path(tempfile.mkdtemp(prefix="tendcf-prep-dash-"))
        self.addCleanup(shutil.rmtree, dash_parent, True)
        (dash_parent / "-dash-state").mkdir()
        r = run([], MDUTIL_OFF_3, state_dir="-dash-state", cwd=str(dash_parent))
        self.assertEqual(r.returncode, 0, r.stderr)
        # A1 / R2-2: acceptance under LC_ALL=en_US.UTF-8 on all platforms. Note (issue 92
        # item 3): on Linux CI (mawk/gawk), plain awk does not exhibit macOS BSD awk 20200816's
        # U+0085 [[:cntrl:]] / invalid-UTF-8 abort, so the BSD-awk mutation kill itself is
        # proved in test_prep_mdutil_lc_all_c_pin_kills_macos_bsd_awk_mutant (darwin-only).
        for name, out, raw_bytes in (
            (
                "U+0085 in extra volume under UTF-8 locale",
                MDUTIL_OFF_3 + "/Volumes/X\u0085Y:\n\tIndexing disabled.\n",
                False,
            ),
            (
                "invalid UTF-8 byte in extra volume under UTF-8 locale",
                MDUTIL_OFF_3.encode() + b"/Volumes/X\xffY:\n\tIndexing disabled.\n",
                True,
            ),
        ):
            with self.subTest(name):
                r = run(
                    [],
                    out,
                    extra_env={"LC_ALL": "en_US.UTF-8"},
                    raw_bytes=raw_bytes,
                )
                self.assertEqual(r.returncode, 0, r.stderr)
        r = run([], MDUTIL_OFF, rc="1")  # a failing mdutil dies, whatever it printed
        self.assertEqual(r.returncode, 1)
        self.assertIn("mdutil -a -s failed (rc 1)", r.stderr)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "BSD awk locale-dependent U+0085 / invalid-UTF-8 mutation kill only bites on macOS "
        "(Linux CI runs mawk/gawk)",
    )
    def test_prep_mdutil_lc_all_c_pin_kills_macos_bsd_awk_mutant(self):
        # Issue 92 item 3: on macOS (BSD awk 20200816), explicitly prove that removing
        # LC_ALL=C from prep.sh's awk fails on U+0085 and invalid UTF-8 (\xff) under
        # LC_ALL=en_US.UTF-8, while the real pinned snippet passes both. Skipped on Linux CI
        # so a green Linux run never implies BSD-awk mutation coverage.
        snippet = self._prep_mdutil_snippet()
        self.assertIn("LC_ALL=C awk", snippet)
        mutant = snippet.replace("LC_ALL=C awk", "awk", 1)
        self.assertNotEqual(mutant, snippet)
        seq = Path(tempfile.mkdtemp(prefix="tendcf-prep-awk-"))
        self.addCleanup(shutil.rmtree, seq, True)
        state_check = Path(tempfile.mkdtemp(prefix="tendcf-prep-awk-state-"))
        self.addCleanup(shutil.rmtree, state_check, True)
        fakes = {
            "mdutil": 'cat "$SEQ/out"\n',
            "sleep": "exit 0\n",
        }
        for name, raw_out in (
            (
                "U+0085 in extra volume",
                (MDUTIL_OFF_3 + "/Volumes/X\u0085Y:\n\tIndexing disabled.\n").encode(
                    "utf-8"
                ),
            ),
            (
                "invalid UTF-8 byte in extra volume",
                MDUTIL_OFF_3.encode() + b"/Volumes/X\xffY:\n\tIndexing disabled.\n",
            ),
        ):
            with self.subTest(name):
                (seq / "out").write_bytes(raw_out)
                env = {
                    "SEQ": str(seq),
                    "STATE_DIR": str(state_check),
                    "TMPDIR": "/nonexistent-tmpdir-must-not-be-used",
                    "LC_ALL": "en_US.UTF-8",
                }
                r_mut = self.run_snippet(
                    mutant,
                    fakes,
                    env,
                    links=("awk", "cat", "mktemp", "tr", "rm"),
                    raw_bytes=True,
                )
                self.assertNotEqual(
                    r_mut.returncode,
                    0,
                    f"expected unpinned macOS BSD awk mutant to fail on {name}",
                )
                self.assertEqual(
                    list(state_check.iterdir()),
                    [],
                    "leaked mdutil mktemp file on mutant fail",
                )
                r_pin = self.run_snippet(
                    snippet,
                    fakes,
                    env,
                    links=("awk", "cat", "mktemp", "tr", "rm"),
                    raw_bytes=True,
                )
                self.assertEqual(r_pin.returncode, 0, r_pin.stderr)
                self.assertEqual(
                    list(state_check.iterdir()),
                    [],
                    "leaked mdutil mktemp file on pinned pass",
                )

    def test_prep_turns_automatic_downloads_and_installs_off_and_only_reads_the_schedule(
        self,
    ):
        text = self.text("prep.sh")
        a = text.index("for key in AutomaticDownload")
        b = text.index('log "automatic download and install off;', a)
        snippet = text[a : text.index("\n", b) + 1]
        code = "\n".join(
            ln for ln in snippet.split("\n") if ln and not ln.startswith("#")
        )
        self.assertNotIn(
            "AutomaticCheckEnabled", code
        )  # a written one is gone in a minute
        self.assertNotIn("--schedule off", code)
        self.assertNotIn("turned off", code)
        self.assertNotIn("/usr/sbin/softwareupdate", snippet)
        self.assertNotIn("/usr/bin/defaults", snippet)
        fakes = {
            # records its arguments; prints SU_FILE (if set) or SU_OUT; exits SU_RC
            "softwareupdate": 'echo "$*" >>"$SEQ/su-calls"; '
            'if [ -n "${SU_FILE:-}" ]; then cat "$SU_FILE"; else printf "%s" "$SU_OUT"; fi; '
            'exit "${SU_RC:-0}"\n',
            # `read` answers 0 except for BAD_KEY, which answers BAD_VAL with exit BAD_RC
            "defaults": 'echo "$*" >>"$SEQ/defaults-calls"; '
            'if [ "$1" = read ]; then '
            'if [ "$3" = "${BAD_KEY:-}" ]; then printf "%s\\n" "${BAD_VAL:-1}"; exit "${BAD_RC:-0}"; fi; '
            "echo 0; fi\n",
        }
        seq = Path(tempfile.mkdtemp(prefix="tendcf-prep-su-"))
        self.addCleanup(shutil.rmtree, seq, True)

        def run(env, *, raw_bytes=False):
            for f in seq.iterdir():
                f.unlink()
            return self.run_snippet(
                snippet,
                fakes,
                {"SU_PLIST": "/plist", **env, "SEQ": str(seq)},
                links=("tr", "cut", "cat"),
                raw_bytes=raw_bytes,
            )

        def calls(name):
            f = seq / name
            return f.read_text().split("\n")[:-1] if f.exists() else []

        want = []
        for key in UPDATE_KEYS:
            want += [f"write /plist {key} -bool false", f"read /plist {key}"]
        want.append(
            "write /Library/Preferences/com.apple.commerce AutoUpdate -bool false"
        )
        off = "Automatic checking for updates is turned off\n"
        on = "Automatic checking for updates is turned on\n"
        for name, env, want_msg in (
            ("turned on is the real answer", {"SU_OUT": on}, "turned on"),
            ("turned off", {"SU_OUT": off}, "turned off"),
            ("both words", {"SU_OUT": off + on}, "turned on"),
            ("empty answer", {"SU_OUT": ""}, "schedule (info, rc 0):"),
            ("other words", {"SU_OUT": "disabled\n"}, "disabled"),
            ("two lines are flattened", {"SU_OUT": "a\nb\n"}, "a b"),
        ):
            with self.subTest(name):
                r = run(env)
                self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
                self.assertIn(want_msg, r.stdout)
                # the fakes, and only the fakes, ran: five keys written false and read back,
                # the schedule read exactly once and never with `off`, then the commerce write
                self.assertEqual(calls("defaults-calls"), want, name)
                self.assertEqual(calls("su-calls"), ["--schedule"], name)
        with self.subTest("a CR cannot forge a line, and the text is capped"):
            r = run({"SU_OUT": "on\rPREP-RESULT forged\n" + "x" * 1000})
            self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
            self.assertNotIn("\r", r.stdout)
            lines = r.stdout.split("\n")
            self.assertFalse([ln for ln in lines if ln.startswith("PREP-RESULT")])
            self.assertEqual(len([ln for ln in lines if ln]), 1, lines)
            self.assertLess(len(r.stdout), 330)
        with self.subTest("invalid UTF-8 under UTF-8 locale does not truncate"):
            su_bin = Path(tempfile.mkdtemp(prefix="tendcf-prep-subin-"))
            self.addCleanup(shutil.rmtree, su_bin, True)
            f = su_bin / "su.bin"
            f.write_bytes(b"on\xfftail\rPREP-RESULT forged\n")
            r = run(
                {"LC_ALL": "en_US.UTF-8", "SU_FILE": str(f)},
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            decoded = r.stdout.decode("utf-8")
            self.assertIn("on?tail", decoded)
            self.assertNotIn(b"\xff", r.stdout)
            self.assertNotIn(b"\r", r.stdout)
            self.assertNotIn(b"Illegal byte sequence", r.stderr)
            lines = [ln for ln in r.stdout.split(b"\n") if ln]
            self.assertEqual(len(lines), 1, lines)
            self.assertFalse(any(ln.startswith(b"PREP-RESULT") for ln in lines))
        with self.subTest("cut caps schedule text at 200 bytes under LC_ALL=C"):
            su_bin = Path(tempfile.mkdtemp(prefix="tendcf-prep-subin-"))
            self.addCleanup(shutil.rmtree, su_bin, True)
            f = su_bin / "su.bin"
            f.write_bytes("é".encode() * 120)  # 240 bytes, 120 chars
            r = run(
                {"LC_ALL": "en_US.UTF-8", "SU_FILE": str(f)},
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            r.stdout.decode("utf-8")
            prefix = (
                b"prep: automatic download and install off; schedule (info, rc 0): "
            )
            self.assertTrue(r.stdout.startswith(prefix), r.stdout)
            payload = r.stdout.removeprefix(prefix).rstrip(b"\n")
            self.assertEqual(payload, b"?" * 200)
        with self.subTest(
            "multibyte character straddling byte 200 stays valid UTF-8 (N1)"
        ):
            su_bin = Path(tempfile.mkdtemp(prefix="tendcf-prep-subin-"))
            self.addCleanup(shutil.rmtree, su_bin, True)
            f = su_bin / "su.bin"
            # byte 199 and 200 are the 2-byte UTF-8 sequence for é; cutting at 200 without
            # replacing non-ASCII first would emit a lone 0xc3 lead byte.
            f.write_bytes(b"a" * 199 + "é".encode() + b"TAIL")
            r = run(
                {"LC_ALL": "en_US.UTF-8", "SU_FILE": str(f)},
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            r.stdout.decode("utf-8")  # strict UTF-8 decode must succeed
            prefix = (
                b"prep: automatic download and install off; schedule (info, rc 0): "
            )
            self.assertTrue(r.stdout.startswith(prefix), r.stdout)
            payload = r.stdout.removeprefix(prefix).rstrip(b"\n")
            self.assertEqual(payload, b"a" * 199 + b"?")
        with self.subTest("a non-0 schedule exit dies"):
            r = run({"SU_OUT": on, "SU_RC": "1"})
            self.assertEqual(r.returncode, 1)
            self.assertIn("--schedule failed (rc 1)", r.stderr)
        for key in UPDATE_KEYS:
            with self.subTest(key=key, case="reads 1"):
                r = run({"BAD_KEY": key, "BAD_VAL": "1", "SU_OUT": on})
                self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
                self.assertIn(f"{key} did not read back as 0", r.stderr)
                self.assertEqual(calls("su-calls"), [])  # died before the schedule call
            with self.subTest(key=key, case="read exits 1 printing 0"):
                r = run({"BAD_KEY": key, "BAD_VAL": "0", "BAD_RC": "1", "SU_OUT": on})
                self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
                self.assertIn(f"defaults read {key} failed", r.stderr)
        # the loop runs before the schedule read, and all of it before Gatekeeper
        self.assertLess(text.index("su_rc=0"), text.index("# 3. Gatekeeper on"))
        self.assertLess(
            text.index("for key in AutomaticDownload"), text.index("su_rc=0")
        )
        self.assertIn("# 2. Automatic download and install off", text)
        self.assertIn("Spotlight off, automatic download and install off", text)

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
        # P12 / R2-2 / R5: slice line 277 and prove CR+LF flattening and LC_ALL=C survival
        a = text.index('log "secure token status (after):')
        snippet = text[a : text.index("\n", a) + 1]
        tmp = Path(tempfile.mkdtemp(prefix="tendcf-prep-st-after-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        st_file = tmp / "st.bin"
        fakes = {"sysadminctl": 'cat "$ST_FILE"\n'}
        with self.subTest("CR and LF flattened, cannot forge PREP-RESULT"):
            st_file.write_bytes(
                b"Secure token is ENABLED\rPREP-RESULT forged\nsecond\n"
            )
            r = self.run_snippet(
                snippet,
                fakes,
                {"ST_FILE": str(st_file), "LC_ALL": "en_US.UTF-8"},
                links=("tr", "cat"),
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(b"\r", r.stdout)
            lines = [ln for ln in r.stdout.split(b"\n") if ln]
            self.assertEqual(len(lines), 1, lines)
            self.assertFalse(any(ln.startswith(b"PREP-RESULT") for ln in lines))
        with self.subTest("invalid UTF-8 under UTF-8 locale does not truncate"):
            st_file.write_bytes(b"before\xffafter\r\n")
            r = self.run_snippet(
                snippet,
                fakes,
                {"ST_FILE": str(st_file), "LC_ALL": "en_US.UTF-8"},
                links=("tr", "cat"),
                raw_bytes=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            decoded = r.stdout.decode("utf-8")
            self.assertIn("before?after", decoded)
            self.assertNotIn(b"\xff", r.stdout)
            self.assertNotIn(b"\r", r.stdout)
            self.assertNotIn(b"Illegal byte sequence", r.stderr)

    def test_prep_prints_the_host_key_from_inside_the_session(self):
        text = self.text("prep.sh")
        self.assertIn("PREP-HOSTKEY", text)
        self.assertIn("/etc/ssh/ssh_host_ed25519_key.pub", text)
        self.assertLess(text.index("ssh-keygen -A"), text.index('echo "PREP-HOSTKEY'))
        self.assertIn('"permitrootlogin no"', text)

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
        if isinstance(output, bytes):
            (d / "out.txt").write_bytes(output)
        else:
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
        # Issue #78 A4: missing or untrusted Notarization line fails closed
        no_notary = self.GOOD_SIG.replace(
            "   Notarization: trusted by the Apple notary service\n", ""
        )
        self.assertNotEqual(self.pkgutil_check(no_notary).returncode, 0)
        bad_notary = self.GOOD_SIG.replace(
            "trusted by the Apple notary service", "not notarized"
        )
        self.assertNotEqual(self.pkgutil_check(bad_notary).returncode, 0)
        # PR 112 R1 Group 7 (Adversary B4): section anchoring, uniqueness, and CR/NUL rejection
        # Status inside Certificate Chain fails
        status_in_chain = self.GOOD_SIG.replace(
            "   Status: signed by a developer certificate issued by Apple for distribution\n",
            "",
        ) + "    Status: signed by a developer certificate issued by Apple for distribution\n"
        self.assertNotEqual(self.pkgutil_check(status_in_chain).returncode, 0)
        # Notarization inside Certificate Chain fails
        notary_in_chain = self.GOOD_SIG.replace(
            "   Notarization: trusted by the Apple notary service\n", ""
        ) + "    Notarization: trusted by the Apple notary service\n"
        self.assertNotEqual(self.pkgutil_check(notary_in_chain).returncode, 0)
        # Leaf 1. line outside (before) Certificate Chain fails
        leaf_before_chain = (
            "   1. Developer ID Installer: Python Software Foundation (BMM5U3QVKW)\n"
            + self.GOOD_SIG.replace(
                "    1. Developer ID Installer: Python Software Foundation (BMM5U3QVKW)\n",
                "",
            )
        )
        self.assertNotEqual(self.pkgutil_check(leaf_before_chain).returncode, 0)
        # Duplicate Status / Notarization / 1. lines fail even when one matches
        dup_status = self.GOOD_SIG.replace(
            "   Status: signed by a developer certificate issued by Apple for distribution\n",
            "   Status: untrusted\n"
            "   Status: signed by a developer certificate issued by Apple for distribution\n",
        )
        self.assertNotEqual(self.pkgutil_check(dup_status).returncode, 0)
        dup_notary = self.GOOD_SIG.replace(
            "   Notarization: trusted by the Apple notary service\n",
            "   Notarization: revoked\n"
            "   Notarization: trusted by the Apple notary service\n",
        )
        self.assertNotEqual(self.pkgutil_check(dup_notary).returncode, 0)
        dup_leaf = self.GOOD_SIG + "    1. Developer ID Installer: Evil (XXXXXXXXXX)\n"
        self.assertNotEqual(self.pkgutil_check(dup_leaf).returncode, 0)
        # CR and NUL bytes fail closed
        self.assertNotEqual(
            self.pkgutil_check(self.GOOD_SIG.replace("\n", "\r\n").encode()).returncode, 0
        )
        self.assertNotEqual(
            self.pkgutil_check(self.GOOD_SIG.encode() + b"\x00").returncode, 0
        )
        # PR 112 R2 (Opus L6): signer is passed via ENVIRON["SIGNER"], not awk -v, so
        # backslashes in signer are compared literally instead of being escape-expanded
        bs_signer = r"Python\nFoundation (BMM5U3QVKW)"
        bs_sig = self.GOOD_SIG.replace(
            "Python Software Foundation (BMM5U3QVKW)", bs_signer
        )
        self.assertEqual(self.pkgutil_check(bs_sig, signer=bs_signer).returncode, 0)


class CheckRenderer(Base):
    """Steps 3-9, 9a, 10b and 11a (issue 70 renderer slice + root cf-execd)."""

    def setUp(self):
        super().setUp()
        self.make_golden()
        self.tarball = self.tmp / "tendcf-fork-macos-arm64-4443504fdeb7ad0be247b26ee8ebdf8ee2ee5a28.tar.gz"
        self.tarball.write_bytes(b"fake-fork-tarball-content")
        self.sha_file = Path(str(self.tarball) + ".sha256")
        digest = hashlib.sha256(self.tarball.read_bytes()).hexdigest()
        self.sha_file.write_text(f"{digest}  {self.tarball.name}\n", encoding="utf-8")

    def tarball_args(self, *extra):
        return ["check", "--tarball", str(self.tarball), *extra]

    def test_full_happy_path_with_tarball_runs_every_step_live(self):
        rc, s = self.run_cmd(*self.tarball_args())
        self.assertEqual(rc, 0, s)
        self.assertTrue(s["ok"])
        st = self.steps(s)
        for sid in (
            "1", "2a", "2b", "2c", "2d", "2e", "2f", "2g", "2h", "2i", "2j", "2k", "2l", "2m",
            "3", "4", "5", "6", "7", "8", "9", "9a", "10", "10a", "10b", "11a", "11",
        ):  # fmt: skip
            self.assertEqual(st[sid]["status"], "pass", (sid, st[sid]))
        self.assertEqual(len(self.world.stage_bundles), 1)
        with tarfile.open(fileobj=io.BytesIO(self.world.stage_bundles[0]), mode="r:gz") as tf:
            names = set(tf.getnames())
        self.assertIn("tendcf-install.sh", names)
        self.assertIn(f"artifact/{self.tarball.name}", names)
        self.assertIn(f"artifact/{self.sha_file.name}", names)
        self.assertIn("policy/tendcf_services.cf", names)
        self.assertIn("canary/host_specific.json", names)
        self.assertIn("canary/host_specific-absent.json", names)
        self.assertTrue(self.world.stage_removed)
        self.assertEqual(sorted(self.world.vms), [GOLDEN])

    def test_artifact_run_downloads_verifies_and_passes(self):
        rc, s = self.run_cmd("check", "--artifact-run", "45093070656")
        self.assertEqual(rc, 0, s)
        self.assertTrue(s["ok"])
        self.assertEqual(s["artifact_run"], "45093070656")
        gh_calls = self.world.argvs(["gh", "run", "download"])
        self.assertEqual(len(gh_calls), 1)
        self.assertIn("45093070656", gh_calls[0])
        self.assertEqual(self.steps(s)["10b"]["status"], "pass")
        self.assertEqual(self.steps(s)["11a"]["status"], "pass")

    def test_refuses_bad_artifact_arguments_before_cloning(self):
        cases = (
            ("both tarball and artifact-run", ["check", "--tarball", str(self.tarball), "--artifact-run", "12345"]),
            ("sha256 without tarball", ["check", "--sha256", str(self.sha_file)]),
            ("non-numeric artifact-run", ["check", "--artifact-run", "abc123"]),
            ("missing tarball", ["check", "--tarball", str(self.tmp / "missing.tar.gz")]),
        )
        for name, argv in cases:
            with self.subTest(name):
                rc, s = self.run_cmd(*argv)
                self.assertEqual(rc, 2, (name, s))
                self.assertEqual(self.world.tart_calls("clone"), [], name)

    def test_refuses_mismatched_or_malformed_sha256_before_cloning(self):
        self.sha_file.write_text(f"{'0' * 64}  {self.tarball.name}\n", encoding="utf-8")
        rc, s = self.run_cmd(*self.tarball_args())
        self.assertEqual(rc, 2, s)
        self.assertIn("sha256 mismatch", self.steps(s)["refused"]["evidence"])
        self.assertEqual(self.world.tart_calls("clone"), [])

        self.sha_file.write_text("not-a-sha\n", encoding="utf-8")
        rc, s = self.run_cmd(*self.tarball_args())
        self.assertEqual(rc, 2, s)
        self.assertEqual(self.world.tart_calls("clone"), [])

        self.sha_file.write_bytes(b"\xff\xfe\x00\x80")
        rc, s = self.run_cmd(*self.tarball_args())
        self.assertEqual(rc, 2, s)
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_artifact_run_provenance_refusals(self):
        for name, meta in (
            (
                "wrong repository",
                {
                    "head_repository": {"full_name": "attacker/tendcf"},
                    "event": "workflow_dispatch",
                    "name": "macOS fork build",
                    "path": ".github/workflows/macos-fork-build.yml",
                },
            ),
            (
                "pull_request event",
                {
                    "head_repository": {"full_name": drv.GH_REPO},
                    "event": "pull_request",
                    "name": "macOS fork build",
                    "path": ".github/workflows/macos-fork-build.yml",
                },
            ),
            (
                "wrong workflow",
                {
                    "head_repository": {"full_name": drv.GH_REPO},
                    "event": "push",
                    "name": "Check",
                    "path": ".github/workflows/check.yml",
                },
            ),
        ):
            with self.subTest(name):
                self.setUp()
                self.world.gh_run_meta = meta
                rc, s = self.run_cmd("check", "--artifact-run", "45093070656")
                self.assertEqual(rc, 2, (name, s))
                self.assertEqual(self.world.tart_calls("clone"), [], name)
                self.assertEqual(self.world.argvs(["gh", "run", "download"]), [], name)

        self.setUp()
        self.world.gh_api_fail = True
        rc, s = self.run_cmd("check", "--artifact-run", "45093070656")
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["error"]["status"], "fail")
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_gh_download_failure_reports_error_without_cloning(self):
        self.world.gh_fail = True
        rc, s = self.run_cmd("check", "--artifact-run", "45093070656")
        self.assertEqual(rc, 1, s)
        self.assertEqual(self.steps(s)["error"]["status"], "fail")
        self.assertEqual(self.world.tart_calls("clone"), [])

    def test_step3_failures_skip_dependent_steps_and_still_clean_up(self):
        for name, mutate in (
            ("install fails", lambda w: setattr(w, "install_fail", True)),
            ("bad workdir traversal", lambda w: setattr(w, "workdir_override", "/opt/tendcf/../etc")),
            ("binary tree writable", lambda w: setattr(w, "tendcf_tree_bad", True)),
            ("policy tree writable", lambda w: setattr(w, "policy_tree_bad", True)),
            ("data mode 644", lambda w: setattr(w, "data_mode", "root:wheel 644")),
            ("quarantine left", lambda w: setattr(w, "quarantine_left", True)),
            ("xattr fails closed", lambda w: setattr(w, "xattr_fail", True)),
        ):
            with self.subTest(name):
                self.setUp()
                mutate(self.world)
                rc, s = self.run_cmd(*self.tarball_args())
                self.assertEqual(rc, 1, (name, s))
                st = self.steps(s)
                self.assertEqual(st["3"]["status"], "fail", (name, st["3"]))
                for sid in ("4", "5", "6", "7", "8", "9", "9a", "10b", "11a"):
                    self.assertEqual(st[sid]["status"], "skip", (name, sid))
                self.assertEqual(st["11"]["status"], "pass", name)
                self.assertEqual(sorted(self.world.vms), [GOLDEN], name)

    def test_step4_to_step9a_failure_paths(self):
        cases = (
            ("4", "run-once fails", lambda w: setattr(w, "run_once_fail", True)),
            ("4", "bad plist mode", lambda w: setattr(w, "canary_plist_mode", "root:wheel 664")),
            ("4", "plutil fails", lambda w: setattr(w, "canary_plutil_fail", True)),
            ("4", "backup file left", lambda w: setattr(w, "canary_backup_present", True)),
            ("5", "golden mismatch", lambda w: setattr(w, "canary_plist_bytes", "<plist>wrong</plist>\n")),
            ("6", "kickstart fails", lambda w: setattr(w, "kickstart_fail", True)),
            ("6", "kickstart same pid", lambda w: setattr(w, "kickstart_same_pid", True)),
            ("7", "rerun reports repair", lambda w: setattr(w, "run_once_rerun_repairs", True)),
            ("7", "rerun reloads daemon", lambda w: setattr(w, "run_once_rerun_reloads", True)),
            ("7", "installer rerun changes", lambda w: setattr(w, "install_rerun_changes", True)),
            ("8", "drift unrepaired", lambda w: setattr(w, "drift_unrepaired", True)),
            ("8", "drift not reloaded", lambda w: setattr(w, "drift_no_reload", True)),
            ("9", "nonroot installer ok", lambda w: setattr(w, "nonroot_installer_succeeds", True)),
            ("9", "nonroot cf-agent mutates", lambda w: setattr(w, "nonroot_cfagent_mutates", True)),
            ("9", "nonroot cf-agent rc0 no refusal", lambda w: setattr(w, "nonroot_cfagent_rc0_no_refusal", True)),
            ("9", "nonroot bootstrap ok", lambda w: setattr(w, "nonroot_bootstrap_succeeds", True)),
            ("9a", "execd enable fails", lambda w: setattr(w, "execd_enable_fail", True)),
            ("9a", "execd enable rerun changes", lambda w: setattr(w, "execd_enable_rerun_changes", True)),
            ("9a", "execd not running", lambda w: setattr(w, "execd_state", "spawn scheduled")),
            ("9a", "execd runs as nobody", lambda w: setattr(w, "execd_user", "nobody")),
            ("10b", "canary missing post-reboot", lambda w: setattr(w, "canary_lost_after_reboot", True)),
            ("10b", "execd missing post-reboot", lambda w: setattr(w, "execd_lost_after_reboot", True)),
            ("11a", "canary plist stays", lambda w: setattr(w, "canary_teardown_keeps_plist", True)),
            ("11a", "canary still loaded", lambda w: setattr(w, "canary_teardown_keeps_loaded", True)),
            ("11a", "execd disable fails", lambda w: setattr(w, "execd_disable_fail", True)),
            ("11a", "execd still loaded", lambda w: setattr(w, "execd_disable_keeps_loaded", True)),
        )
        for sid, name, mutate in cases:
            with self.subTest(step=sid, case=name):
                self.setUp()
                mutate(self.world)
                rc, s = self.run_cmd(*self.tarball_args())
                self.assertEqual(rc, 1, (sid, name, s))
                st = self.steps(s)
                self.assertEqual(st[sid]["status"], "fail", (sid, name, st[sid]))
                self.assertEqual(st["11"]["status"], "pass", (sid, name))

    def test_step10_reboot_failure_skips_10a_10b_11a(self):
        self.world.reboot_changes_uuid = False
        rc, s = self.run_cmd(*self.tarball_args())
        self.assertEqual(rc, 1, s)
        st = self.steps(s)
        self.assertEqual(st["10"]["status"], "fail")
        for sid in ("10a", "10b", "11a"):
            self.assertEqual(st[sid]["status"], "skip", sid)
            self.assertIn("step 10 failed", st[sid]["evidence"], sid)
        self.assertEqual(st["11"]["status"], "pass")


class DarwinInstallerAndSymlink(unittest.TestCase):
    """Static and hermetic checks on deploy/darwin/tendcf-install.sh and deploy/macos."""

    INSTALLER = REPO / "deploy" / "darwin" / "tendcf-install.sh"
    SYMLINK = REPO / "deploy" / "macos"

    def test_macos_symlink_is_relative_to_darwin(self):
        self.assertTrue(self.SYMLINK.is_symlink())
        self.assertEqual(os.readlink(self.SYMLINK), "darwin")
        self.assertEqual(
            (self.SYMLINK / "tendcf-install.sh").resolve(),
            self.INSTALLER.resolve(),
        )

    def test_installer_syntax_guards_and_plist_template(self):
        r = subprocess.run(
            ["/bin/bash", "-n", str(self.INSTALLER)], capture_output=True, text=True, check=False
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        text = self.INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        self.assertIn("set -euo pipefail", text)
        self.assertIn("/usr/bin/env -i TENDCF_CLEAN_ENV=1", text)
        self.assertIn("compgen -e", text)
        self.assertIn("unset DYLD_LIBRARY_PATH", text)
        self.assertIn('= 0 ] || die "run as root"', text)
        self.assertIn('= Darwin ] || die "Darwin only"', text)
        self.assertIn("/bin/cp -RP", text)
        self.assertIn("/bin/chmod -RN", text)
        self.assertIn("/usr/bin/chflags -R 0", text)
        self.assertIn("/bin/chmod -R a-s,go-w", text)
        self.assertIn('"$py" -I -', text)
        self.assertIn("LC_DYLD_ENVIRONMENT", text)
        self.assertIn("LC_LOAD_DYLINKER", text)
        self.assertIn("com.apple.quarantine", text)
        self.assertIn('! -type s -exec /usr/bin/xattr -s {} +', text)
        self.assertNotIn("/usr/bin/xattr -rs", text)
        self.assertIn("plutil -lint", text)
        self.assertIn("launchctl print", text)
        self.assertIn("org.tendcf.execd", text)
        self.assertIn("status) cmd_status ;;", text)

        # Render the embedded org.tendcf.execd plist heredoc and parse with plistlib.
        m = re.search(
            r'cat > "\$dest" <<EOF\n(.*?)\nEOF', text, re.DOTALL
        )
        self.assertIsNotNone(m)
        rendered = (
            m.group(1)
            .replace("$label", "org.tendcf.execd")
            .replace("$cf_execd", "/opt/tendcf/bin/cf-execd")
            .replace("$prefix", "/opt/tendcf")
            .replace("$workdir", "/opt/tendcf/var/libntech")
        )
        parsed = plistlib.loads(rendered.encode("utf-8"))
        self.assertEqual(parsed["Label"], "org.tendcf.execd")
        self.assertEqual(parsed["ProgramArguments"], ["/opt/tendcf/bin/cf-execd", "--no-fork"])
        self.assertEqual(parsed["UserName"], "root")
        self.assertTrue(parsed["RunAtLoad"])
        self.assertTrue(parsed["KeepAlive"])

    def test_embedded_macho_parser_accepts_valid_and_rejects_bad_deps(self):
        text = self.INSTALLER.read_text(encoding="utf-8")
        m = re.search(
            r'"\$py" -I - "\$prefix" "\$canon_root" "\$\{machos\[@\]\}" <<\'PY\'\n(.*?)\nPY',
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(m)
        py_code = m.group(1)

        def make_macho(
            dylibs=(),
            rpaths=(),
            *,
            dylinker="/usr/lib/dyld",
            dyld_env=None,
            endian="<",
        ):
            cmds = bytearray()
            ncmds = 0
            for d in dylibs:
                s = d.encode("utf-8") + b"\x00"
                raw_len = 24 + len(s)
                cmdsize = (raw_len + 7) & ~7
                cmds += struct.pack(endian + "IIIIII", 0x0C, cmdsize, 24, 0, 0, 0)
                cmds += s + b"\x00" * (cmdsize - raw_len)
                ncmds += 1
            for rp in rpaths:
                s = rp.encode("utf-8") + b"\x00"
                raw_len = 12 + len(s)
                cmdsize = (raw_len + 7) & ~7
                cmds += struct.pack(endian + "III", 0x8000001C, cmdsize, 12)
                cmds += s + b"\x00" * (cmdsize - raw_len)
                ncmds += 1
            if dylinker is not None:
                s = dylinker.encode("utf-8") + b"\x00"
                raw_len = 12 + len(s)
                cmdsize = (raw_len + 7) & ~7
                cmds += struct.pack(endian + "III", 0x0E, cmdsize, 12)
                cmds += s + b"\x00" * (cmdsize - raw_len)
                ncmds += 1
            if dyld_env is not None:
                s = dyld_env.encode("utf-8") + b"\x00"
                raw_len = 12 + len(s)
                cmdsize = (raw_len + 7) & ~7
                cmds += struct.pack(endian + "III", 0x27, cmdsize, 12)
                cmds += s + b"\x00" * (cmdsize - raw_len)
                ncmds += 1
            magic = 0xFEEDFACF if endian == "<" else 0xFEEDFACF
            # MH_CIGAM_64 when big-endian (read as little-endian gives 0xCFFAEDFE).
            hdr = struct.pack(endian + "IIIIIIII", magic, 0x0100000C, 0, 2, ncmds, len(cmds), 0, 0)
            return hdr + bytes(cmds)

        def make_fat(slices):
            # FAT_MAGIC big-endian header + 20-byte arch entries
            hdr = bytearray(struct.pack(">II", 0xCAFEBABE, len(slices)))
            off = 8 + 20 * len(slices)
            body = bytearray()
            for sl in slices:
                hdr += struct.pack(">IIIII", 0x0100000C, 0, off, len(sl), 0)
                body += sl
                off += len(sl)
            return bytes(hdr) + bytes(body)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bin").mkdir()
            (root / "lib").mkdir()
            lib_p = root / "lib" / "libpromises.3.dylib"
            lib_p.write_bytes(make_macho(["/usr/lib/libSystem.B.dylib"]))
            non_macho = root / "lib" / "not-macho.txt"
            non_macho.write_text("plain text", encoding="utf-8")
            good = root / "bin" / "cf-agent"
            good.write_bytes(
                make_macho(["/usr/lib/libSystem.B.dylib", "/opt/tendcf/lib/libpromises.3.dylib"])
            )
            r_ok = subprocess.run(
                [sys.executable, "-I", "-c", py_code, "/opt/tendcf", str(root), str(good), str(lib_p)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(r_ok.returncode, 0, r_ok.stderr)

            # Valid fat binary with little-endian and big-endian slices.
            fat_ok = root / "bin" / "fat-ok"
            fat_ok.write_bytes(
                make_fat([
                    make_macho(["/usr/lib/libSystem.B.dylib"], endian="<"),
                    make_macho(["/usr/lib/libSystem.B.dylib"], endian=">"),
                ])
            )
            r_fat_ok = subprocess.run(
                [sys.executable, "-I", "-c", py_code, "/opt/tendcf", str(root), str(fat_ok)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(r_fat_ok.returncode, 0, r_fat_ok.stderr)

            # Rejections
            bad_cases = (
                ("homebrew dylib", make_macho(["/opt/homebrew/lib/libssl.3.dylib"]), "outside /opt/tendcf"),
                ("missing in-prefix", make_macho(["/opt/tendcf/lib/libmissing.dylib"]), "missing in-prefix library"),
                ("non-macho target", make_macho(["/opt/tendcf/lib/not-macho.txt"]), "non-Mach-O target"),
                ("dylib .. traversal", make_macho(["/usr/lib/../../tmp/evil.dylib"]), "unsafe traversal"),
                ("dylib . segment", make_macho(["/usr/lib/./libSystem.B.dylib"]), "unsafe traversal"),
                ("dylib //", make_macho(["/usr/lib//libSystem.B.dylib"]), "unsafe dylib path"),
                ("rpath external", make_macho(["/usr/lib/libSystem.B.dylib"], rpaths=["/opt/homebrew/lib"]), "forbidden LC_RPATH"),
                ("rpath .. traversal", make_macho(["/usr/lib/libSystem.B.dylib"], rpaths=["/opt/tendcf/../tmp"]), "unsafe traversal"),
                ("LC_DYLD_ENVIRONMENT", make_macho(["/usr/lib/libSystem.B.dylib"], dyld_env="DYLD_INSERT_LIBRARIES=/tmp/x"), "LC_DYLD_ENVIRONMENT"),
                ("bad LC_LOAD_DYLINKER", make_macho(["/usr/lib/libSystem.B.dylib"], dylinker="/tmp/evil-dyld"), "LC_LOAD_DYLINKER"),
                ("fat nfat=0", struct.pack(">II", 0xCAFEBABE, 0), "nfat=0"),
                ("fat oob slice", struct.pack(">IIIIIII", 0xCAFEBABE, 1, 0, 0, 9999, 64, 0), "out-of-bounds"),
                ("fat bad 2nd slice", make_fat([make_macho(["/usr/lib/libSystem.B.dylib"]), make_macho(["/tmp/evil.dylib"])]), "outside /opt/tendcf"),
                (
                    "truncated dylib cmdsize",
                    struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
                    + struct.pack("<IIII", 0x0C, 16, 24, 0),
                    "truncated dylib cmdsize",
                ),
                (
                    "invalid dylib str_off",
                    struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
                    + struct.pack("<IIIIII", 0x0C, 24, 12, 0, 0, 0),
                    "invalid dylib string offset",
                ),
            )
            for name, payload, want in bad_cases:
                with self.subTest(name):
                    bf = root / "bin" / "bad-bin"
                    bf.write_bytes(payload)
                    r = subprocess.run(
                        [sys.executable, "-I", "-c", py_code, "/opt/tendcf", str(root), str(bf), str(lib_p)],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertNotEqual(r.returncode, 0, name)
                    self.assertIn(want, r.stderr, (name, r.stderr))
                    self.assertNotIn("Traceback", r.stderr, (name, r.stderr))


class TrailingNewlineRegexTests(unittest.TestCase):
    """Issue #55 R1: validation regexes in vmssh and state1_vm must use \\Z, not $."""

    def test_vmssh_target_rejects_user_with_trailing_newline(self):
        with self.assertRaises(ValueError):
            vmssh.Target(
                ip="127.0.0.1",
                known_hosts="/tmp/kh",
                identity="/tmp/id",
                user="admin\n",
            )
        # Valid user still accepted.
        t = vmssh.Target(
            ip="127.0.0.1",
            known_hosts="/tmp/kh",
            identity="/tmp/id",
            user="admin",
        )
        self.assertEqual(t.user, "admin")

    def test_state1_vm_regexes_reject_trailing_newline(self):
        cases = (
            ("RUN_ID_RE", drv.RUN_ID_RE, "123456789"),
            ("SHA256_LINE_RE", drv.SHA256_LINE_RE, "a" * 64 + "  file.tar.gz"),
            ("GUEST_STAGE_RE", drv.GUEST_STAGE_RE, "/var/tmp/tendcf-stage.abc123"),
            ("NAME_RE", drv.NAME_RE, "state1-golden"),
            ("REPO_RE", drv.REPO_RE, "ghcr.io/cirruslabs/macos-sequoia-vanilla"),
            ("TAG_RE", drv.TAG_RE, "latest"),
            ("DIGEST_RE", drv.DIGEST_RE, "sha256:" + "0" * 64),
            ("KEY_ID_RE", drv.KEY_ID_RE, "key-1"),
            ("WORKDIR_RE", drv.WORKDIR_RE, "/opt/tendcf/work"),
        )
        for label, rx, good in cases:
            with self.subTest(label):
                self.assertIsNotNone(rx.match(good), f"{label} rejected valid {good!r}")
                self.assertIsNone(
                    rx.match(good + "\n"),
                    f"{label} accepted trailing newline on {good!r}",
                )

    def test_read_image_json_rejects_trailing_newline_in_python_fields(self):
        for field in ("version", "sha256", "url", "signer"):
            with self.subTest(field):
                bad = json.loads(json.dumps(IMAGE))
                bad["python"][field] = bad["python"][field] + "\n"
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td) / "image.json"
                    p.write_text(json.dumps(bad), encoding="utf-8")
                    with self.assertRaises(drv.Refusal):
                        drv.read_image_json(p)


if __name__ == "__main__":
    unittest.main()
