"""Contract and hermetic rollback/security tests for deploy/darwin/tendcf-install.sh."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "deploy" / "darwin" / "tendcf-install.sh"
PROJECTOR = REPO / "tools" / "projector.py"
DARWIN_CANARY_PRESENT = REPO / "deploy" / "darwin" / "canary" / "host_specific.json"
DARWIN_CANARY_ABSENT = REPO / "deploy" / "darwin" / "canary" / "host_specific-absent.json"
DARWIN_OK_CF_SCRIPT = (
    "#!/bin/sh\n"
    "echo 'any   hardclass'\n"
    "echo 'tendcf_cmdb_evaluated   source=promise'\n"
    "exit 0\n"
)


def _extract_func(src: str, name: str) -> str:
    lines = src.splitlines(keepends=True)
    header_re = re.compile(rf"^{re.escape(name)}\(\) \{{")
    heredoc_re = re.compile(r"(?<!<)<<(?!<)-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
    start = None
    for idx, line in enumerate(lines):
        if header_re.match(line):
            start = idx
            break
    if start is None:
        raise AssertionError(f"function {name}() not found in {INSTALLER}")
    out: list[str] = []
    heredoc_end: str | None = None
    for line in lines[start:]:
        out.append(line)
        if heredoc_end is not None:
            if line.rstrip("\r\n") == heredoc_end:
                heredoc_end = None
            continue
        if not line.lstrip().startswith("#"):
            hm = heredoc_re.search(line)
            if hm is not None:
                heredoc_end = hm.group(1)
                continue
        if line.rstrip("\r\n") == "}":
            return "".join(out)
    raise AssertionError(f"unterminated function {name}() in {INSTALLER}")


class TendcfInstallUpgradeRollbackContract(unittest.TestCase):
    """Verify PR #97 R1c + R2 security and upgrade-rollback invariants."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.src = INSTALLER.read_text(encoding="utf-8")

    def test_bash_syntax_passes(self) -> None:
        r = subprocess.run(
            ["/bin/bash", "-n", str(INSTALLER)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_find_safe_otool_never_calls_usr_bin_otool_and_rejects_nonroot(self) -> None:
        # Non-comment lines must never invoke the standalone /usr/bin/otool xcrun shim
        # (direct /Library/Developer/CommandLineTools/usr/bin/otool and $dev_dir/... are allowed).
        non_comment = "\n".join(
            line for line in self.src.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIsNone(re.search(r"(?<![A-Za-z0-9_/.$-])/usr/bin/otool\b", non_comment))

        fn = _extract_func(self.src, "find_safe_otool")
        self.assertIn("/Library/Developer/CommandLineTools/usr/bin/otool", fn)
        self.assertIn("resolve_safe_binary_ok", fn)
        self.assertIn('"$real_otool" -L /bin/ls', fn)

        vm = _extract_func(self.src, "verify_macho_tree")
        vm_code = "\n".join(
            line for line in vm.splitlines() if not line.lstrip().startswith("#")
        )
        idx_stage = vm_code.find("make_stage")
        idx_otool = vm_code.find("find_safe_otool")
        idx_py = vm_code.find("find_real_python")
        self.assertNotEqual(idx_stage, -1)
        self.assertLess(idx_stage, idx_otool, "make_stage must run before find_safe_otool")
        self.assertLess(idx_stage, idx_py, "make_stage must run before find_real_python")
        self.assertIn('"$otool_bin" -L "$bin"', vm_code)
        self.assertIn('"$otool_bin" -l "$bin"', vm_code)

        # Hermetic behavioral test: resolve_safe_binary_ok rejects a non-root binary
        # (unless the test runner itself is uid 0).
        if os.geteuid() != 0:
            resolve_fn = _extract_func(self.src, "resolve_safe_binary_ok")
            with tempfile.TemporaryDirectory() as td:
                fake_otool = Path(td) / "otool"
                fake_otool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                fake_otool.chmod(0o755)
                script = (
                    "set -euo pipefail\n"
                    "check_ancestors_ok() { return 0; }\n"
                    "has_acl_path() { return 1; }\n"
                    f"{resolve_fn}\n"
                    f'resolve_safe_binary_ok "{fake_otool}"\n'
                )
                r = subprocess.run(
                    ["/bin/bash", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(
                    r.returncode,
                    0,
                    "resolve_safe_binary_ok must reject a non-root-owned binary",
                )

    def test_verify_python_candidate_ok_fails_closed_when_framework_absent(self) -> None:
        fn = _extract_func(self.src, "verify_python_candidate_ok")
        self.assertIn("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/*", fn)
        self.assertIn('check_ancestors_ok "$dev_dir"', fn)
        self.assertIn('check_ancestor_dir_ok "$dev_dir"', fn)
        self.assertIn('dev_py="$dev_dir/usr/bin/python3"', fn)
        self.assertIn('resolve_safe_binary_ok "$dev_py"', fn)
        self.assertIn("else\n                return 1", fn)

        find_py = _extract_func(self.src, "find_real_python")
        idx_clt = find_py.find("/Library/Developer/CommandLineTools/usr/bin/python3")
        idx_usr = find_py.find("verify_python_candidate_ok /usr/bin/python3")
        self.assertNotEqual(idx_clt, -1)
        self.assertNotEqual(idx_usr, -1)
        self.assertLess(idx_clt, idx_usr)

        # Hermetic behavioral test 1: when /usr/bin/python3 resolves to /usr/bin/python3
        # and xcode-select points at a directory lacking Python3.framework, return 1.
        with tempfile.TemporaryDirectory() as td:
            empty_dev = Path(td) / "Developer"
            empty_dev.mkdir()
            fake_xcode_select = Path(td) / "xcode-select"
            fake_xcode_select.write_text(f"#!/bin/sh\necho '{empty_dev}'\n", encoding="utf-8")
            fake_xcode_select.chmod(0o755)
            fake_py = Path(td) / "py-wrapper"
            fake_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_py.chmod(0o755)
            patched_fn = fn.replace("/usr/bin/xcode-select", str(fake_xcode_select))
            script = (
                "set -euo pipefail\n"
                "check_ancestors_ok() { return 0; }\n"
                "check_ancestor_dir_ok() { return 0; }\n"
                "root_tree_safe_ok() { return 0; }\n"
                'resolve_safe_binary_ok() { echo "/usr/bin/python3"; }\n'
                f"{patched_fn}\n"
                f'verify_python_candidate_ok "{fake_py}"\n'
            )
            r = subprocess.run(
                ["/bin/bash", "-c", script],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(
                r.returncode,
                0,
                "verify_python_candidate_ok must return 1 when Python3.framework is absent",
            )

        # Hermetic behavioral test 2: when Python3.framework exists but
        # $dev_dir/usr/bin/python3 is missing OR resolves outside $py_root / $dev_dir/usr/bin,
        # return 1 (fail closed).
        with tempfile.TemporaryDirectory() as td:
            dev_dir = Path(td) / "Developer"
            (dev_dir / "Library" / "Frameworks" / "Python3.framework").mkdir(parents=True)
            fake_xcode_select = Path(td) / "xcode-select"
            fake_xcode_select.write_text(f"#!/bin/sh\necho '{dev_dir}'\n", encoding="utf-8")
            fake_xcode_select.chmod(0o755)
            fake_py = Path(td) / "py-wrapper"
            fake_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_py.chmod(0o755)
            patched_fn = fn.replace("/usr/bin/xcode-select", str(fake_xcode_select))

            # Missing $dev_dir/usr/bin/python3
            r_missing = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    "check_ancestors_ok() { return 0; }\n"
                    "check_ancestor_dir_ok() { return 0; }\n"
                    "root_tree_safe_ok() { return 0; }\n"
                    'resolve_safe_binary_ok() { echo "/usr/bin/python3"; }\n'
                    f"{patched_fn}\n"
                    f'verify_python_candidate_ok "{fake_py}"\n',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(
                r_missing.returncode,
                0,
                "verify_python_candidate_ok must fail closed when $dev_dir/usr/bin/python3 is missing",
            )

            # Present $dev_dir/usr/bin/python3, but resolves to untrusted /tmp/evil-python3
            (dev_dir / "usr" / "bin").mkdir(parents=True)
            dev_py = dev_dir / "usr" / "bin" / "python3"
            dev_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            dev_py.chmod(0o755)
            r_outside = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    "check_ancestors_ok() { return 0; }\n"
                    "check_ancestor_dir_ok() { return 0; }\n"
                    "root_tree_safe_ok() { return 0; }\n"
                    f'resolve_safe_binary_ok() {{ if [ "$1" = "{fake_py}" ]; then echo "/usr/bin/python3"; else echo "/tmp/evil-python3"; fi; }}\n'
                    f"{patched_fn}\n"
                    f'verify_python_candidate_ok "{fake_py}"\n',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(
                r_outside.returncode,
                0,
                "verify_python_candidate_ok must fail closed when $dev_dir/usr/bin/python3 resolves outside dev_dir",
            )

    def test_chflags_before_chmod_and_check_tree_rechecks_clean(self) -> None:
        for fn_name in ("install_tarball", "check_tree", "place_policy"):
            fn = _extract_func(self.src, fn_name)
            idx_chflags = fn.find("/usr/bin/chflags -R 0")
            idx_chmod_rn = fn.find("/bin/chmod -RN")
            self.assertNotEqual(idx_chflags, -1, f"missing chflags -R 0 in {fn_name}")
            self.assertNotEqual(idx_chmod_rn, -1, f"missing chmod -RN in {fn_name}")
            self.assertLess(
                idx_chflags,
                idx_chmod_rn,
                f"chflags -R 0 must run BEFORE chmod -RN in {fn_name}",
            )

        ct = _extract_func(self.src, "check_tree")
        idx_repair_chmod = ct.find('/bin/chmod -R a-s,go-w "$prefix"')
        idx_recheck = ct.find('tree_is_clean "$prefix" || die', idx_repair_chmod)
        self.assertNotEqual(idx_repair_chmod, -1)
        self.assertNotEqual(
            idx_recheck,
            -1,
            "check_tree must re-run tree_is_clean and die if repair failed",
        )

    def test_print0_used_in_verify_macho_tree_validate_symlinks_and_extract_check(self) -> None:
        vm = _extract_func(self.src, "verify_macho_tree")
        self.assertIn('/usr/bin/find "$canon_root" -type f -print0', vm)
        self.assertIn("while IFS= read -r -d '' f; do", vm)

        vs = _extract_func(self.src, "validate_tree_symlinks_ok")
        self.assertIn('/usr/bin/find "$canon_root" -type l -print0', vs)
        self.assertIn("while IFS= read -r -d '' sl; do", vs)

        it = _extract_func(self.src, "install_tarball")
        self.assertIn('/usr/bin/find "$staged_tree" -print0', it)
        self.assertIn(r"tr -cd '\001-\037\177'", it)

    def test_prefix_var_symlink_checked_before_bootout_and_post_move_restores(self) -> None:
        fn = _extract_func(self.src, "install_tarball")
        idx_pre_check = fn.find('[ -L "$prefix/var" ]')
        idx_bootout = fn.find('/bin/launchctl bootout "system/$label"')
        idx_arm_loaded = fn.find("upgrade_was_loaded=1")
        idx_arm_rollback = fn.find("upgrade_rollback_armed=1")
        idx_post_check = fn.find('[ -L "$backup_prefix/var" ]')

        self.assertNotEqual(idx_pre_check, -1, 'missing pre-bootout [ -L "$prefix/var" ] check')
        self.assertNotEqual(idx_bootout, -1, "missing launchctl bootout in install_tarball")
        self.assertLess(
            idx_pre_check,
            idx_bootout,
            '[ -L "$prefix/var" ] must run BEFORE launchctl bootout',
        )
        self.assertNotEqual(idx_arm_loaded, -1)
        self.assertNotEqual(idx_arm_rollback, -1)
        self.assertLess(
            idx_arm_rollback,
            idx_bootout,
            "upgrade_rollback_armed must be armed before bootout",
        )
        self.assertNotEqual(
            idx_post_check,
            -1,
            'post-move belt-and-suspenders [ -L "$backup_prefix/var" ] check must remain',
        )
        self.assertGreater(idx_post_check, idx_bootout)
        idx_record_backup = fn.find('upgrade_backup_prefix="$backup_prefix"')
        self.assertNotEqual(idx_record_backup, -1)
        self.assertLess(idx_record_backup, idx_post_check)

    def test_backup_prefix_not_deleted_in_install_tarball_and_disarmed_only_after_enable_execd(self) -> None:
        install_fn = _extract_func(self.src, "install_tarball")
        idx_record_backup = install_fn.find('upgrade_backup_prefix="$backup_prefix"')
        self.assertNotEqual(idx_record_backup, -1)
        after_backup = install_fn[idx_record_backup:]
        self.assertNotIn(
            '"$backup_prefix"',
            "\n".join(line for line in after_backup.splitlines() if "rm " in line),
            "install_tarball must NOT delete backup_prefix once recorded for rollback",
        )
        idx_swap_mv = install_fn.rfind('/bin/mv "$staged_tree" "$prefix"')
        self.assertGreater(idx_swap_mv, idx_record_backup)
        after_swap = install_fn[idx_swap_mv:]
        self.assertNotIn(
            "rm -rf",
            after_swap,
            "install_tarball must NOT delete backup_prefix after the swap",
        )

        cmd_fn = _extract_func(self.src, "cmd_install")
        idx_preval = cmd_fn.find('prevalidate_install_inputs "$datafile"')
        idx_tarball = cmd_fn.find('install_tarball "$tarball" "$sha256_file"')
        idx_check_tree = cmd_fn.find("check_tree")
        idx_init_paths = cmd_fn.find("init_paths")
        idx_snapshot = cmd_fn.find("upgrade_snapshot_taken=1")
        idx_lay_out = cmd_fn.find("lay_out")
        idx_place_policy = cmd_fn.find("place_policy")
        idx_put_data = cmd_fn.find('put_data "$datafile"')
        idx_enable = cmd_fn.find("enable_execd")
        idx_disarm = cmd_fn.find("upgrade_rollback_armed=0")
        idx_rm_backup = cmd_fn.find('/bin/rm -rf "$upgrade_backup_prefix"')

        for label, idx in (
            ("prevalidate_install_inputs", idx_preval),
            ("install_tarball", idx_tarball),
            ("check_tree", idx_check_tree),
            ("init_paths", idx_init_paths),
            ("upgrade_snapshot_taken", idx_snapshot),
            ("lay_out", idx_lay_out),
            ("place_policy", idx_place_policy),
            ("put_data", idx_put_data),
            ("enable_execd", idx_enable),
            ("disarm", idx_disarm),
            ("rm_backup", idx_rm_backup),
        ):
            self.assertNotEqual(idx, -1, f"missing {label} in cmd_install")

        self.assertLess(idx_preval, idx_tarball)
        self.assertLess(idx_init_paths, idx_snapshot)
        self.assertLess(idx_snapshot, idx_lay_out)
        for step_idx in (
            idx_tarball,
            idx_check_tree,
            idx_init_paths,
            idx_snapshot,
            idx_lay_out,
            idx_place_policy,
            idx_put_data,
            idx_enable,
        ):
            self.assertLess(
                step_idx,
                idx_disarm,
                "upgrade_rollback_armed=0 must come AFTER all post-upgrade steps and enable_execd",
            )
        self.assertLess(idx_disarm, idx_rm_backup)

    def test_cleanup_stage_order_and_guards(self) -> None:
        fn = _extract_func(self.src, "cleanup_stage")
        idx_rb = fn.find('if [ "$upgrade_rollback_armed" -eq 1 ]; then')
        idx_bootout = fn.find("bootout_execd")
        idx_mv_failed = fn.find('/bin/mv "$prefix" "$failed_prefix"')
        idx_var_failed = fn.find('"$failed_prefix/var"')
        idx_var_staged = fn.find('"$upgrade_staged_tree/var"')
        idx_restore = fn.find('/bin/mv "$upgrade_backup_prefix" "$prefix"')
        idx_guard_rm = fn.find('if [ "$upgrade_moved_var" -eq 0 ] || [ ! -e "$failed_prefix/var" ]; then')
        idx_snap = fn.find('if [ "$upgrade_snapshot_taken" -eq 1 ]')
        idx_bootstrap = fn.find("bootstrap_execd_with_retry")
        idx_rm_stage = fn.find('/bin/rm -rf "$stage_dir"')

        for label, idx in (
            ("rollback guard", idx_rb),
            ("bootout before move", idx_bootout),
            ("move failed prefix", idx_mv_failed),
            ("failed_prefix/var rescue", idx_var_failed),
            ("staged_tree/var rescue", idx_var_staged),
            ("restore backup_prefix", idx_restore),
            ("guarded rm failed_prefix", idx_guard_rm),
            ("restore inputs/data snapshot", idx_snap),
            ("bootstrap_execd_with_retry", idx_bootstrap),
            ("rm stage_dir", idx_rm_stage),
        ):
            self.assertNotEqual(idx, -1, f"missing {label} in cleanup_stage")

        self.assertLess(idx_rb, idx_bootout)
        self.assertLess(idx_bootout, idx_mv_failed)
        self.assertLess(idx_mv_failed, idx_var_failed)
        self.assertLess(idx_var_failed, idx_var_staged)
        self.assertLess(idx_var_staged, idx_restore)
        self.assertLess(idx_restore, idx_guard_rm)
        self.assertLess(idx_guard_rm, idx_snap)
        self.assertLess(idx_snap, idx_bootstrap)
        self.assertLess(
            idx_bootstrap,
            idx_rm_stage,
            'upgrade rollback + snapshot restore must run BEFORE rm -rf "$stage_dir"',
        )
        self.assertIn("! execd_is_loaded", fn)
        self.assertIn('/bin/launchctl bootout "system/$label"', _extract_func(self.src, "bootout_execd"))
        self.assertIn(
            '/bin/launchctl bootstrap system "$plist_path"',
            _extract_func(self.src, "bootstrap_execd_with_retry"),
        )

    def test_cleanup_stage_executes_rollback_scenarios(self) -> None:
        cleanup_fn = _extract_func(self.src, "cleanup_stage")

        def run_cleanup(env_setup: str, exit_code: int = 1) -> subprocess.CompletedProcess[str]:
            script = (
                "set -euo pipefail\n"
                'label="org.tendcf.execd"\n'
                f"{env_setup}\n"
                f"{cleanup_fn}\n"
                "trap cleanup_stage EXIT\n"
                f"exit {exit_code}\n"
            )
            return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

        # Case 1: Post-place_policy / post-put_data failure restores old tree,
        # previous inputs/, previous host_specific.json, and re-bootstraps execd.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.123"
            stage = root / "stage"
            plist = root / "org.tendcf.execd.plist"
            plist.write_text("<plist/>\n", encoding="utf-8")
            log = root / "events.log"
            workdir = prefix / "var" / "libntech"

            (backup / "bin").mkdir(parents=True)
            (backup / "bin" / "version").write_text("old-v1\n", encoding="utf-8")

            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("new-v2\n", encoding="utf-8")
            (workdir / "inputs" / "tendcf").mkdir(parents=True)
            (workdir / "inputs" / "tendcf" / "tendcf_services.cf").write_text("new-policy\n", encoding="utf-8")
            (workdir / "data").mkdir(parents=True)
            (workdir / "data" / "host_specific.json").write_text('{"new":true}', encoding="utf-8")

            snap = stage / "upgrade-var-backup"
            (snap / "inputs" / "tendcf").mkdir(parents=True)
            (snap / "inputs" / "tendcf" / "tendcf_services.cf").write_text("old-policy\n", encoding="utf-8")
            (snap / "host_specific.json").write_text('{"old":true}', encoding="utf-8")

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=1\n"
                "upgrade_was_loaded=1\n"
                "upgrade_snapshot_taken=1\n"
                f'upgrade_saved_workdir="{workdir}"\n'
                "upgrade_saved_inputs=1\n"
                "upgrade_saved_data=1\n"
                "loaded=0\n"
                'execd_is_loaded() { [ "$loaded" -eq 1 ]; }\n'
                f'bootout_execd() {{ echo "bootout" >> "{log}"; loaded=0; }}\n'
                f'wait_execd_unloaded() {{ echo "wait_unloaded" >> "{log}"; }}\n'
                f'bootstrap_execd_with_retry() {{ echo "bootstrap" >> "{log}"; loaded=1; }}\n'
            )
            self.assertEqual(r.returncode, 1)
            self.assertIn("rolled back failed upgrade to previous", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")
            self.assertEqual(
                (workdir / "inputs" / "tendcf" / "tendcf_services.cf").read_text(encoding="utf-8"),
                "old-policy\n",
            )
            self.assertEqual(
                (workdir / "data" / "host_specific.json").read_text(encoding="utf-8"),
                '{"old":true}',
            )
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["bootstrap"])
            self.assertFalse(backup.exists())
            self.assertFalse(stage.exists())

        # Case 2: Newly created host_specific.json removed when upgrade_saved_data=0,
        # AND bootout runs BEFORE moving $prefix when execd_is_loaded is true.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.456"
            stage = root / "stage"
            plist = root / "org.tendcf.execd.plist"
            plist.write_text("<plist/>\n", encoding="utf-8")
            log = root / "events.log"
            workdir = prefix / "var" / "libntech"

            (backup / "bin").mkdir(parents=True)
            (backup / "bin" / "version").write_text("old-v1\n", encoding="utf-8")
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("new-v2\n", encoding="utf-8")
            (workdir / "data").mkdir(parents=True)
            (workdir / "data" / "host_specific.json").write_text('{"brand_new":true}', encoding="utf-8")
            (stage / "upgrade-var-backup").mkdir(parents=True)

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=1\n"
                "upgrade_was_loaded=1\n"
                "upgrade_snapshot_taken=1\n"
                f'upgrade_saved_workdir="{workdir}"\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "loaded=1\n"
                'execd_is_loaded() { [ "$loaded" -eq 1 ]; }\n'
                f'bootout_execd() {{ test -d "{prefix}" && echo "bootout_before_move" >> "{log}"; loaded=0; }}\n'
                f'wait_execd_unloaded() {{ echo "wait_unloaded" >> "{log}"; }}\n'
                f'bootstrap_execd_with_retry() {{ echo "bootstrap:$(cat "{prefix}/bin/version")" >> "{log}"; loaded=1; }}\n'
            )
            self.assertEqual(r.returncode, 1)
            self.assertIn("rolled back failed upgrade to previous", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")
            self.assertFalse((workdir / "data" / "host_specific.json").exists())
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["bootout_before_move", "wait_unloaded", "bootstrap:old-v1"],
            )
            self.assertFalse(stage.exists())

        # Case 3: Failure BETWEEN mv backup/var -> staged_tree/var AND mv staged_tree -> prefix
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.789"
            stage = root / "stage"
            staged_tree = stage / "extract" / "tendcf"
            (backup / "bin").mkdir(parents=True)
            (backup / "bin" / "version").write_text("old-v1\n", encoding="utf-8")
            (staged_tree / "var" / "libntech").mkdir(parents=True)
            (staged_tree / "var" / "libntech" / "key").write_text("host-key-2\n", encoding="utf-8")

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{root / "missing.plist"}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                f'upgrade_staged_tree="{staged_tree}"\n'
                "upgrade_moved_var=1\n"
                "upgrade_was_loaded=0\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "execd_is_loaded() { return 1; }\n"
                "bootout_execd() { return 0; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                "bootstrap_execd_with_retry() { return 0; }\n"
            )
            self.assertEqual(r.returncode, 1)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")
            self.assertEqual((prefix / "var" / "libntech" / "key").read_text(encoding="utf-8"), "host-key-2\n")
            self.assertFalse(backup.exists())
            self.assertFalse(stage.exists())

        # Case 4: Bootout-only failure (empty upgrade_backup_prefix) re-bootstraps
        # without moving $prefix and prints the aborted-upgrade restart message.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            stage = root / "stage"
            plist = root / "org.tendcf.execd.plist"
            plist.write_text("<plist/>\n", encoding="utf-8")
            log = root / "events.log"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("old-v1\n", encoding="utf-8")
            stage.mkdir()

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                'upgrade_backup_prefix=""\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=1\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "execd_is_loaded() { return 1; }\n"
                "bootout_execd() { return 0; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                f'bootstrap_execd_with_retry() {{ echo "restarted" >> "{log}"; }}\n'
            )
            self.assertEqual(r.returncode, 1)
            self.assertIn("restarted org.tendcf.execd after aborted upgrade", r.stderr)
            self.assertNotIn("rolled back failed upgrade", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["restarted"])
            self.assertFalse(stage.exists())

        # Case 5: Disarmed (upgrade succeeded) -> leaves new tree untouched, removes stage_dir.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            stage = root / "stage"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("new-v2\n", encoding="utf-8")
            stage.mkdir()

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{root / "missing.plist"}"\n'
                "upgrade_rollback_armed=0\n"
                'upgrade_backup_prefix=""\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=0\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "execd_is_loaded() { return 1; }\n"
                "bootout_execd() { return 0; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                "bootstrap_execd_with_retry() { return 0; }\n",
                exit_code=0,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("rolled back", r.stderr)
            self.assertNotIn("restarted", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "new-v2\n")
            self.assertFalse(stage.exists())

    def test_l2_stale_upgrade_dirs_fail_closed(self) -> None:
        """Issue #99 L2: detect stale /opt/tendcf.old.* or /opt/tendcf.failed.* before installing."""
        cmd_fn = _extract_func(self.src, "cmd_install")
        idx_preval = cmd_fn.find('prevalidate_install_inputs "$datafile"')
        idx_stale = cmd_fn.find("check_no_stale_upgrade_dirs")
        idx_tarball = cmd_fn.find('install_tarball "$tarball" "$sha256_file"')
        self.assertNotEqual(idx_stale, -1, "check_no_stale_upgrade_dirs must be called in cmd_install")
        self.assertLess(idx_preval, idx_stale)
        self.assertLess(idx_stale, idx_tarball)

        fn = _extract_func(self.src, "check_no_stale_upgrade_dirs")

        def run_check(prefix: Path, *, pre_nullglob: bool = False) -> subprocess.CompletedProcess[str]:
            pre = "shopt -s nullglob\n" if pre_nullglob else ""
            post = 'shopt -q nullglob || { echo "nullglob unexpectedly unset" >&2; exit 2; }\n' if pre_nullglob else ""
            script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                f'prefix="{prefix}"\n'
                f"{fn}\n"
                f"{pre}"
                "check_no_stale_upgrade_dirs\n"
                f"{post}"
            )
            return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            prefix.mkdir()
            # Clean: passes (both default and with nullglob pre-enabled under set -e)
            r_clean = run_check(prefix)
            self.assertEqual(r_clean.returncode, 0, r_clean.stderr)
            r_pre_ng = run_check(prefix, pre_nullglob=True)
            self.assertEqual(r_pre_ng.returncode, 0, r_pre_ng.stderr)

            # Stale .old.* fails closed
            stale_old = root / "tendcf.old.999"
            stale_old.mkdir()
            r_old = run_check(prefix)
            self.assertNotEqual(r_old.returncode, 0)
            self.assertIn(str(stale_old), r_old.stderr)
            stale_old.rmdir()

            # Dangling symlink .old.* also fails closed
            stale_dangling = root / "tendcf.old.dangling"
            stale_dangling.symlink_to(root / "nonexistent-target")
            r_dangling = run_check(prefix)
            self.assertNotEqual(r_dangling.returncode, 0)
            self.assertIn(str(stale_dangling), r_dangling.stderr)
            stale_dangling.unlink()

            # Stale .failed.* fails closed
            stale_failed = root / "tendcf.failed.888"
            stale_failed.mkdir()
            r_failed = run_check(prefix)
            self.assertNotEqual(r_failed.returncode, 0)
            self.assertIn(str(stale_failed), r_failed.stderr)

            # Both present: lists both
            stale_old.mkdir()
            r_both = run_check(prefix)
            self.assertNotEqual(r_both.returncode, 0)
            self.assertIn(str(stale_old), r_both.stderr)
            self.assertIn(str(stale_failed), r_both.stderr)

        # cmd_status also reports stale upgrade artifacts read-only.
        status_fn = _extract_func(self.src, "cmd_status")
        self.assertIn('"$prefix".old.*', status_fn)
        self.assertIn('"$prefix".failed.*', status_fn)
        self.assertIn("stale:", status_fn)

    def test_r3b_upgrade_rollback_removes_newly_created_plist_only(self) -> None:
        """Issue #99 R3-b: rollback removes newly created execd plist when absent beforehand."""
        install_fn = _extract_func(self.src, "install_tarball")
        idx_had = install_fn.find("upgrade_had_plist=1")
        idx_arm = install_fn.find("upgrade_rollback_armed=1")
        self.assertNotEqual(idx_had, -1)
        self.assertLess(idx_had, idx_arm, "upgrade_had_plist must be recorded before arming rollback")

        cleanup_fn = _extract_func(self.src, "cleanup_stage")

        def run_cleanup(env_setup: str) -> subprocess.CompletedProcess[str]:
            script = (
                "set -euo pipefail\n"
                'label="org.tendcf.execd"\n'
                f"{env_setup}\n"
                f"{cleanup_fn}\n"
                "trap cleanup_stage EXIT\n"
                "exit 1\n"
            )
            return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

        # Case A: No plist existed beforehand (upgrade_had_plist=0, upgrade_was_loaded=0),
        # failed upgrade created plist and loaded execd -> bootout + remove plist.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.321"
            stage = root / "stage"
            plist = root / "org.tendcf.execd.plist"
            log = root / "events.log"
            (backup / "bin").mkdir(parents=True)
            (backup / "bin" / "version").write_text("old-v1\n", encoding="utf-8")
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("new-v2\n", encoding="utf-8")
            plist.write_text("<plist>new</plist>\n", encoding="utf-8")
            stage.mkdir()

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=0\n"
                "upgrade_had_plist=0\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "loaded=1\n"
                'execd_is_loaded() { [ "$loaded" -eq 1 ]; }\n'
                f'bootout_execd() {{ echo "bootout" >> "{log}"; loaded=0; }}\n'
                f'wait_execd_unloaded() {{ echo "wait_unloaded" >> "{log}"; }}\n'
                f'bootstrap_execd_with_retry() {{ echo "bootstrap" >> "{log}"; }}\n'
            )
            self.assertEqual(r.returncode, 1)
            self.assertFalse(plist.exists(), "newly created plist must be removed on upgrade rollback")
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["bootout", "wait_unloaded"])
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")

        # Case B: Pre-existing plist (upgrade_had_plist=1, upgrade_was_loaded=0) -> preserved.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.322"
            stage = root / "stage"
            plist = root / "org.tendcf.execd.plist"
            (backup / "bin").mkdir(parents=True)
            (prefix / "bin").mkdir(parents=True)
            plist.write_text("<plist>preexisting</plist>\n", encoding="utf-8")
            stage.mkdir()

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=0\n"
                "upgrade_had_plist=1\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "execd_is_loaded() { return 1; }\n"
                "bootout_execd() { return 0; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                "bootstrap_execd_with_retry() { return 0; }\n"
            )
            self.assertEqual(r.returncode, 1)
            self.assertTrue(plist.exists(), "pre-existing plist must NOT be deleted on rollback")
            self.assertEqual(plist.read_text(encoding="utf-8"), "<plist>preexisting</plist>\n")

        # Case C: Symlink at plist_path is never deleted even when upgrade_had_plist=0.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.323"
            stage = root / "stage"
            target = root / "target.plist"
            target.write_text("keep\n", encoding="utf-8")
            plist = root / "org.tendcf.execd.plist"
            plist.symlink_to(target)
            (backup / "bin").mkdir(parents=True)
            (prefix / "bin").mkdir(parents=True)
            stage.mkdir()

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=0\n"
                "upgrade_had_plist=0\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "execd_is_loaded() { return 1; }\n"
                "bootout_execd() { return 0; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                "bootstrap_execd_with_retry() { return 0; }\n"
            )
            self.assertEqual(r.returncode, 1)
            self.assertTrue(plist.is_symlink(), "symlink at plist_path must never be deleted")
            self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

        # Case D: Empty upgrade_backup_prefix with loaded=1 exercises R3-b's own
        # bootout_execd + wait_execd_unloaded path (bypassing backup-restore block).
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            stage = root / "stage"
            plist = root / "org.tendcf.execd.plist"
            log = root / "events.log"
            (prefix / "bin").mkdir(parents=True)
            plist.write_text("<plist>new-only</plist>\n", encoding="utf-8")
            stage.mkdir()

            r = run_cleanup(
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{plist}"\n'
                "upgrade_rollback_armed=1\n"
                'upgrade_backup_prefix=""\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=0\n"
                "upgrade_had_plist=0\n"
                "upgrade_snapshot_taken=0\n"
                'upgrade_saved_workdir=""\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=0\n"
                "loaded=1\n"
                'execd_is_loaded() { [ "$loaded" -eq 1 ]; }\n'
                f'bootout_execd() {{ echo "bootout" >> "{log}"; loaded=0; }}\n'
                f'wait_execd_unloaded() {{ echo "wait_unloaded" >> "{log}"; }}\n'
                f'bootstrap_execd_with_retry() {{ echo "bootstrap" >> "{log}"; }}\n'
            )
            self.assertEqual(r.returncode, 1)
            self.assertFalse(plist.exists(), "R3-b must remove newly created plist when backup_prefix is empty")
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["bootout", "wait_unloaded"])


def _patch_darwin_funcs_for_hermetic(code: str, shim_dir: Path) -> str:
    """Redirect root/macOS-only tool invocations to hermetic shims so tests run
    as non-root on both macOS (using real /usr/bin/lockf and /usr/bin/mktemp)
    and Linux CI."""
    replacements = [
        ("/usr/sbin/chown", str(shim_dir / "chown")),
        ("/usr/bin/chflags", str(shim_dir / "chflags")),
        ("/usr/bin/xattr", str(shim_dir / "xattr")),
        ("/usr/bin/stat", str(shim_dir / "stat")),
        ("/usr/bin/install", str(shim_dir / "install")),
        ("/bin/chmod", str(shim_dir / "chmod")),
        ("/bin/cp", shutil.which("cp") or "/bin/cp"),
        ("/bin/cat", shutil.which("cat") or "/bin/cat"),
        ("/bin/mv", shutil.which("mv") or "/bin/mv"),
        ("/bin/rm", shutil.which("rm") or "/bin/rm"),
        ("/usr/bin/cmp", shutil.which("cmp") or "/usr/bin/cmp"),
        ("/usr/bin/awk", shutil.which("awk") or "/usr/bin/awk"),
        ("/usr/bin/sort", shutil.which("sort") or "/usr/bin/sort"),
        ("/usr/bin/tr", shutil.which("tr") or "/usr/bin/tr"),
        ("/usr/bin/wc", shutil.which("wc") or "/usr/bin/wc"),
        ("/usr/bin/mktemp", shutil.which("mktemp") or "/usr/bin/mktemp"),
        ("/usr/bin/dirname", shutil.which("dirname") or "/usr/bin/dirname"),
        ("/usr/bin/basename", shutil.which("basename") or "/usr/bin/basename"),
        ("/usr/bin/readlink", shutil.which("readlink") or "/usr/bin/readlink"),
        ("/usr/bin/shasum", str(shim_dir / "shasum")),
    ]
    if sys.platform != "darwin":
        replacements.append(("/usr/bin/lockf", str(shim_dir / "lockf")))
    for old, new in replacements:
        code = code.replace(old, new)
    return code


def _make_darwin_shims(shim_dir: Path) -> None:
    for noop in ("chown",):
        p = shim_dir / noop
        p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        p.chmod(0o755)

    # chflags shim: records invocations when CHFLAGS_LOG is set, clears fake flag file if present.
    chflags_p = shim_dir / "chflags"
    chflags_p.write_text(
        "#!/bin/sh\n"
        'if [ -n "${CHFLAGS_LOG:-}" ]; then echo "chflags $*" >> "$CHFLAGS_LOG"; fi\n'
        'if [ "$1" = "0" ] && [ -n "${FAKE_FLAG_FILE:-}" ] && [ "$2" = "$FAKE_FLAG_FILE" ]; then rm -f "$FAKE_FLAG_FILE.uchg"; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    chflags_p.chmod(0o755)

    # xattr shim: no quarantine xattr present unless FAKE_QUARANTINE_FILE matches
    xattr = shim_dir / "xattr"
    xattr.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    xattr.chmod(0o755)

    shasum_p = shim_dir / "shasum"
    shasum_p.write_text(
        f"#!{sys.executable}\n"
        "import hashlib, pathlib, sys\n"
        "p = sys.argv[-1]\n"
        "h = hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()\n"
        "print(f'{h}  {p}')\n",
        encoding="utf-8",
    )
    shasum_p.chmod(0o755)

    # chmod shim: ignore macOS `-N` ACL strip when on Linux or non-root
    real_chmod = shutil.which("chmod") or "/bin/chmod"
    chmod_p = shim_dir / "chmod"
    chmod_p.write_text(
        f"#!/bin/sh\nif [ \"$1\" = \"-N\" ]; then exit 0; fi\nexec {real_chmod} \"$@\"\n",
        encoding="utf-8",
    )
    chmod_p.chmod(0o755)

    stat_p = shim_dir / "stat"
    stat_p.write_text(
        f"#!{sys.executable}\n"
        "import os, stat, sys\n"
        "fmt = sys.argv[2]\n"
        "p = sys.argv[3]\n"
        "st = os.lstat(p)\n"
        "mode = stat.S_IMODE(st.st_mode)\n"
        "owner = 'nobody' if os.environ.get('FAKE_NONROOT_FILE') == p else 'root'\n"
        "if fmt == '%Su:%Sg %Lp':\n"
        "    print(f'{owner}:wheel {mode:o}')\n"
        "elif fmt == '%Su %Sg %Lp':\n"
        "    print(f'{owner} wheel {mode:o}')\n"
        "elif fmt == '%f':\n"
        "    print('2' if os.path.exists(p + '.uchg') else '0')\n"
        "else:\n"
        "    raise SystemExit(f'unexpected stat fmt: {fmt}')\n",
        encoding="utf-8",
    )
    stat_p.chmod(0o755)

    real_install = shutil.which("install") or "/usr/bin/install"
    install_p = shim_dir / "install"
    install_p.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"real = {real_install!r}\n"
        "args = [real]\n"
        "i = 1\n"
        "while i < len(sys.argv):\n"
        "    if sys.argv[i] in ('-o', '-g') and i + 1 < len(sys.argv):\n"
        "        i += 2\n"
        "    else:\n"
        "        args.append(sys.argv[i])\n"
        "        i += 1\n"
        "os.execv(real, args)\n",
        encoding="utf-8",
    )
    install_p.chmod(0o755)

    if sys.platform != "darwin":
        lockf_p = shim_dir / "lockf"
        lockf_p.write_text(
            f"#!{sys.executable}\n"
            "import fcntl, sys\n"
            "fd = int(sys.argv[-1])\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n",
            encoding="utf-8",
        )
        lockf_p.chmod(0o755)


class TendcfInstallHardeningContract(unittest.TestCase):
    """Issues #53, #57, #58 contract and hermetic behavioral tests for deploy/darwin/tendcf-install.sh."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.src = INSTALLER.read_text(encoding="utf-8")

    def test_contract_projector_gates_lockf_and_unique_paths(self) -> None:
        self.assertTrue(self.src.startswith("#!/bin/bash -p\n"))
        self.assertIn("/bin/bash -p \"$0\" \"$@\"", self.src)

        cmd_fn = _extract_func(self.src, "cmd_install")
        self.assertIn("--projector-src)", cmd_fn)
        self.assertIn("--projector-sha256)", cmd_fn)
        self.assertIn('[ -n "$2" ]', cmd_fn)
        idx_preval = cmd_fn.find('prevalidate_install_inputs "$datafile"')
        idx_acq = cmd_fn.find("acquire_publish_lock")
        idx_stale = cmd_fn.find("check_no_stale_upgrade_dirs")
        idx_prep = cmd_fn.find("prepare_projector_source")
        idx_tarball = cmd_fn.find('install_tarball "$tarball" "$sha256_file"')
        idx_detach = cmd_fn.find("detach_unsafe_installed_projector")
        idx_tree = cmd_fn.find("check_tree")
        idx_policy = cmd_fn.find("place_policy")
        idx_proj = cmd_fn.find("place_projector")
        idx_data = cmd_fn.find('put_data "$datafile"')
        idx_disarm = cmd_fn.find("upgrade_rollback_armed=0")
        idx_rel = cmd_fn.find("release_publish_lock")
        for lbl, idx in (
            ("prevalidate", idx_preval),
            ("acquire_publish_lock", idx_acq),
            ("check_no_stale_upgrade_dirs", idx_stale),
            ("prepare_projector_source", idx_prep),
            ("install_tarball", idx_tarball),
            ("detach_unsafe_installed_projector", idx_detach),
            ("check_tree", idx_tree),
            ("place_policy", idx_policy),
            ("place_projector", idx_proj),
            ("put_data", idx_data),
            ("disarm", idx_disarm),
            ("release_publish_lock", idx_rel),
        ):
            self.assertNotEqual(idx, -1, f"missing {lbl} in cmd_install")
        self.assertLess(idx_preval, idx_acq)
        self.assertLess(idx_acq, idx_stale)
        self.assertLess(idx_stale, idx_prep)
        self.assertLess(idx_prep, idx_tarball)
        self.assertLess(idx_tarball, idx_detach)
        self.assertLess(idx_detach, idx_tree)
        self.assertLess(idx_policy, idx_proj)
        self.assertLess(idx_proj, idx_data)
        self.assertLess(idx_disarm, idx_rel)

        # Codex #1: standalone `data)` dispatch acquires lock BEFORE init_paths.
        m_data_case = re.search(r"^\s+data\)\n(.*?)^\s+;;", self.src, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(m_data_case, "missing data) case in main dispatch")
        data_case = m_data_case.group(1)
        idx_d_acq = data_case.find("acquire_publish_lock")
        idx_d_init = data_case.find("init_paths")
        idx_d_put = data_case.find('put_data "$1"')
        idx_d_rel = data_case.find("release_publish_lock")
        self.assertNotEqual(idx_d_acq, -1)
        self.assertLess(idx_d_acq, idx_d_init)
        self.assertLess(idx_d_init, idx_d_put)
        self.assertLess(idx_d_put, idx_d_rel)

        # Codex #7: Darwin Mach-O verification Python fallback uses `-I -S -`.
        vm_fn = _extract_func(self.src, "verify_macho_tree")
        self.assertIn('9>&- "$py" -I -S - "$prefix" "$canon_root" "${machos[@]}"', vm_fn)

        preval_fn = _extract_func(self.src, "prevalidate_install_inputs")
        self.assertIn("resolve_projector_src", preval_fn)

        res_fn = _extract_func(self.src, "resolve_projector_src")
        self.assertLess(
            res_fn.find("$here/bin/projector.py"),
            res_fn.find("$here/../../tools/projector.py"),
            "sibling $here/bin/projector.py must take precedence over $here/../../tools/projector.py",
        )

        acq_fn = _extract_func(self.src, "acquire_publish_lock")
        self.assertIn('.tendcf-publish.lock', acq_fn)
        self.assertIn('[ -f "$lockfile" ] && [ ! -L "$lockfile" ]', acq_fn)
        self.assertIn("/usr/bin/lockf 9", acq_fn)

        cleanup_fn = _extract_func(self.src, "cleanup_stage")
        idx_put_rb = cleanup_fn.find('if [ "${put_data_rollback_armed:-0}" -eq 1 ]; then')
        idx_upg_rb = cleanup_fn.find('if [ "$upgrade_rollback_armed" -eq 1 ]; then')
        idx_fd9_close = cleanup_fn.rfind("exec 9>&-")
        self.assertNotEqual(idx_put_rb, -1)
        self.assertNotEqual(idx_upg_rb, -1)
        self.assertNotEqual(idx_fd9_close, -1)
        self.assertNotIn("exec 9>&- 2>/dev/null", cleanup_fn)
        self.assertLess(idx_put_rb, idx_fd9_close, "put_data rollback must complete BEFORE closing FD 9")
        self.assertLess(idx_upg_rb, idx_fd9_close, "upgrade rollback must complete BEFORE closing FD 9")

        proj_fn = _extract_func(self.src, "place_projector")
        proj_code = "\n".join(
            line for line in proj_fn.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("resolve_realpath_ok", proj_code)
        self.assertNotIn("$projector_src", proj_code)
        self.assertNotIn("prepare_projector_source", proj_code)
        self.assertIn("upgrade_prefix_swapped", proj_code)
        self.assertIn("installed_projector_originally_clean", proj_code)
        self.assertIn('/usr/bin/cmp -s "$prepared_projector_file" "$installed_projector"', proj_code)
        self.assertIn("installed_projector_clean_ok", proj_code)
        self.assertIn("stat -f '%f'", proj_code)
        self.assertIn('/usr/bin/chflags 0 "$installed_projector"', proj_code)

        detach_fn = _extract_func(self.src, "detach_unsafe_installed_projector")
        detach_code = "\n".join(
            line for line in detach_fn.splitlines() if not line.lstrip().startswith("#")
        )
        # Codex R7 #1: detach_unsafe_installed_projector NEVER mutates directory ownership/permissions/ACLs
        self.assertNotIn("chown", detach_code)
        self.assertNotIn("chmod", detach_code)
        idx_d_check = detach_code.find('check_dir_root_unwritable "$d"')
        idx_d_chflags = detach_code.find('/usr/bin/chflags 0 "$installed_projector"')
        idx_d_rm = detach_code.find('/bin/rm -f "$installed_projector"')
        self.assertNotEqual(idx_d_check, -1)
        self.assertNotEqual(idx_d_chflags, -1)
        self.assertNotEqual(idx_d_rm, -1)
        self.assertLess(idx_d_check, idx_d_rm, "existing parent chain must be verified BEFORE unlinking $installed_projector")
        self.assertLess(idx_d_chflags, idx_d_rm, "chflags 0 must run before rm -f in detach_unsafe_installed_projector")

        put_fn = _extract_func(self.src, "put_data")
        put_code = "\n".join(
            line for line in put_fn.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("$data.new", put_code)
        self.assertNotIn("$data.previous", put_code)
        self.assertIn("acquire_publish_lock", put_code)
        self.assertIn("release_publish_lock", put_code)
        self.assertIn(".host_specific.new.XXXXXX", put_code)
        self.assertIn(".host_specific.prev.XXXXXX", put_code)
        self.assertIn('"$py" -I -S "$installed_projector" --check "$staged_data" 9>&-', put_code)

        idx_acq_p = put_code.find("acquire_publish_lock")
        idx_ver_p = put_code.find("verify_installed_projector")
        idx_stage = put_code.find("make_stage")
        idx_py = put_code.find("find_real_python")
        idx_gate1 = put_code.find('"$installed_projector" --check "$staged_data" 9>&-')
        idx_gate2 = put_code.find('validate_cmdb_workdir "$stage_wd"')
        idx_bytes = put_code.find('data_bytes="$(/usr/bin/wc -c < "$staged_data"')
        idx_arm = put_code.find("put_data_rollback_armed=1")
        idx_mv = put_code.find('/bin/mv -f "$tmp" "$data"')
        idx_gate3 = put_code.find('validate_cmdb_workdir "$workdir" "$entry"', idx_mv)
        idx_unlock = put_code.rfind("release_publish_lock")
        self.assertLess(idx_acq_p, idx_ver_p, "acquire_publish_lock must run before verify_installed_projector")
        self.assertLess(idx_stage, idx_py, "make_stage must run before find_real_python")
        self.assertLess(idx_gate1, idx_gate2)
        self.assertLess(idx_gate2, idx_bytes)
        self.assertLess(idx_bytes, idx_arm)
        self.assertLess(idx_arm, idx_mv)
        self.assertLess(idx_mv, idx_gate3)
        self.assertLess(idx_gate3, idx_unlock)

        val_fn = _extract_func(self.src, "validate_cmdb_workdir")
        self.assertIn("--show-classes", val_fn)
        self.assertIn("9>&-", val_fn)
        self.assertIn("tendcf_cmdb_evaluated", val_fn)
        self.assertIn("source=promise", val_fn)
        self.assertIn("tendcf_cmdb_refused", val_fn)
        self.assertIn("tendcf_cmdb_problem_", val_fn)
        self.assertIn("awk_rc", val_fn)
        self.assertNotIn("| /usr/bin/sort", val_fn)

    def _build_env(
        self,
        root: Path,
        cf_promises_script: str,
        *,
        initial_data: bytes | None = None,
    ) -> dict[str, Path]:
        shim_dir = root / "shims"
        shim_dir.mkdir()
        _make_darwin_shims(shim_dir)

        prefix = root / "opt" / "tendcf"
        workdir = prefix / "var" / "libntech"
        stage_dir = root / "stage"
        stage_dir.mkdir(mode=0o700)
        (prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
        shutil.copy2(PROJECTOR, prefix / "share" / "tendcf" / "bin" / "projector.py")
        (prefix / "share" / "tendcf" / "bin" / "projector.py").chmod(0o644)

        (workdir / "inputs" / "tendcf").mkdir(parents=True)
        (workdir / "inputs" / "promises.cf").write_text("bundle agent main {}\n", encoding="utf-8")
        (workdir / "data").mkdir(parents=True, mode=0o700)
        (workdir / "ppkeys").mkdir(parents=True, mode=0o700)

        data_path = workdir / "data" / "host_specific.json"
        if initial_data is not None:
            data_path.write_bytes(initial_data)
            data_path.chmod(0o600)

        cf_promises = root / "fake-cf-promises"
        cf_promises.write_text(cf_promises_script, encoding="utf-8")
        cf_promises.chmod(0o755)

        return {
            "shim_dir": shim_dir,
            "prefix": prefix,
            "workdir": workdir,
            "stage_dir": stage_dir,
            "entry": workdir / "inputs" / "promises.cf",
            "data": data_path,
            "cf_promises": cf_promises,
            "installed_projector": prefix / "share" / "tendcf" / "bin" / "projector.py",
        }

    def _darwin_funcs(self, shim_dir: Path, names: tuple[str, ...]) -> str:
        raw = "\n".join(_extract_func(self.src, n) for n in names)
        return _patch_darwin_funcs_for_hermetic(raw, shim_dir)

    def _put_data_script(
        self,
        paths: dict[str, Path],
        src_file: Path,
        *,
        mv_override: str | None = None,
        rm_override: str | None = None,
        awk_override: str | None = None,
        stage_override: Path | None = None,
        extra_preamble: str = "",
    ) -> str:
        funcs = self._darwin_funcs(
            paths["shim_dir"],
            (
                "cleanup_stage",
                "check_dir_root_unwritable",
                "acquire_publish_lock",
                "release_publish_lock",
                "verify_installed_projector",
                "validate_cmdb_workdir",
                "put_data",
            ),
        )
        if mv_override is not None:
            real_mv = shutil.which("mv") or "/bin/mv"
            funcs = funcs.replace(real_mv, mv_override)
        if rm_override is not None:
            real_rm = shutil.which("rm") or "/bin/rm"
            funcs = funcs.replace(real_rm, rm_override)
        if awk_override is not None:
            real_awk = shutil.which("awk") or "/usr/bin/awk"
            funcs = funcs.replace(real_awk, awk_override)
        stage_p = stage_override or paths["stage_dir"]
        return (
            "set -euo pipefail\n"
            'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
            'say() { echo "tendcf-install: $*"; }\n'
            "has_acl_path() { return 1; }\n"
            "check_ancestors() { return 0; }\n"
            "make_stage() { return 0; }\n"
            f'find_real_python() {{ echo "{sys.executable}"; }}\n'
            f'prefix="{paths["prefix"]}"\n'
            f'workdir="{paths["workdir"]}"\n'
            f'stage_dir="{stage_p}"\n'
            f'entry="{paths["entry"]}"\n'
            f'data="{paths["data"]}"\n'
            f'cf_promises="{paths["cf_promises"]}"\n'
            f'installed_projector="{paths["installed_projector"]}"\n'
            "upgrade_rollback_armed=0\n"
            "publish_lock_held=0\n"
            "put_data_rollback_armed=0\n"
            "put_data_had_prev=0\n"
            'put_data_stage_wd=""\n'
            'put_data_tmp=""\n'
            'put_data_backup=""\n'
            'place_projector_tmp=""\n'
            "changed=0\n"
            f"{extra_preamble}\n"
            f"{funcs}\n"
            "trap cleanup_stage EXIT\n"
            "trap 'exit 130' INT\n"
            "trap 'exit 143' TERM\n"
            f'put_data "{src_file}"\n'
            'echo "CHANGED=$changed"\n'
        )

    def _run_put_data(
        self,
        paths: dict[str, Path],
        src_file: Path,
        *,
        extra_env: dict[str, str] | None = None,
        mv_override: str | None = None,
        rm_override: str | None = None,
        awk_override: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        script = self._put_data_script(
            paths, src_file, mv_override=mv_override, rm_override=rm_override, awk_override=awk_override
        )
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/bin/bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_place_projector_integrity_flags_precedence_and_put_data_gate1(self) -> None:
        proj_sha = hashlib.sha256(PROJECTOR.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            paths = self._build_env(root, DARWIN_OK_CF_SCRIPT, initial_data=orig)
            paths["installed_projector"].unlink()
            place_funcs = self._darwin_funcs(
                paths["shim_dir"],
                (
                    "ensure_dir",
                    "resolve_realpath_ok",
                    "resolve_projector_src",
                    "source_file_root_trusted_ok",
                    "check_source_file_root_trusted",
                    "check_dir_root_unwritable",
                    "verify_installed_projector",
                    "installed_projector_clean_ok",
                    "prepare_projector_source",
                    "detach_unsafe_installed_projector",
                    "place_projector",
                ),
            )

            def run_place(
                proj_src: str,
                *,
                sha: str = "",
                here_dir: Path | None = None,
                extra_env: dict[str, str] | None = None,
                post_cmds: str = 'echo "CHANGED=$changed"',
            ) -> subprocess.CompletedProcess[str]:
                env = dict(os.environ)
                if extra_env:
                    env.update(extra_env)
                script = (
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "has_acl_path() { return 1; }\n"
                    "check_ancestors() { return 0; }\n"
                    "check_ancestors_ok() { return 0; }\n"
                    "make_stage() { return 0; }\n"
                    f'prefix="{paths["prefix"]}"\n'
                    f'stage_dir="{paths["stage_dir"]}"\n'
                    f'here="{here_dir or root}"\n'
                    f'projector_src="{proj_src}"\n'
                    f'projector_sha256="{sha}"\n'
                    f'installed_projector="{paths["installed_projector"]}"\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    "upgrade_prefix_swapped=0\n"
                    "changed=0\n"
                    f"{place_funcs}\n"
                    "prepare_projector_source\n"
                    "detach_unsafe_installed_projector\n"
                    "place_projector\n"
                    f"{post_cmds}\n"
                )
                return subprocess.run(
                    ["/bin/bash", "-c", script],
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                )

            # 1. Non-root source without --projector-sha256 -> REFUSED
            r_unpinned = run_place(
                str(PROJECTOR),
                sha="",
                extra_env={"FAKE_NONROOT_FILE": str(PROJECTOR)},
            )
            self.assertNotEqual(r_unpinned.returncode, 0)
            self.assertIn("--projector-sha256", r_unpinned.stderr)

            # 2. Wrong --projector-sha256 -> REFUSED
            r_bad_sha = run_place(
                str(PROJECTOR),
                sha="0" * 64,
                extra_env={"FAKE_NONROOT_FILE": str(PROJECTOR)},
            )
            self.assertNotEqual(r_bad_sha.returncode, 0)
            self.assertIn("sha256 mismatch", r_bad_sha.stderr)

            # 3. Valid --projector-sha256 on non-root source -> ACCEPTED
            r_ok_sha = run_place(
                str(PROJECTOR),
                sha=proj_sha,
                extra_env={"FAKE_NONROOT_FILE": str(PROJECTOR)},
            )
            self.assertEqual(r_ok_sha.returncode, 0, r_ok_sha.stderr)
            self.assertIn("CHANGED=1", r_ok_sha.stdout)
            self.assertEqual(paths["installed_projector"].read_bytes(), PROJECTOR.read_bytes())

            # 4. Converged idempotent re-run -> CHANGED=0; same-realpath -> CHANGED=0
            r_idem_p = run_place(str(PROJECTOR), sha=proj_sha)
            self.assertEqual(r_idem_p.returncode, 0, r_idem_p.stderr)
            self.assertIn("CHANGED=0", r_idem_p.stdout)

            r_same = run_place(str(paths["installed_projector"]), sha="")
            self.assertEqual(r_same.returncode, 0, r_same.stderr)
            self.assertIn("CHANGED=0", r_same.stdout)

            # 5. Codex #9: flagged (uchg) destination with identical external source clears flags & repairs,
            #    followed by a changed external source replacing it cleanly.
            chflags_log = root / "chflags.log"
            flag_marker = Path(str(paths["installed_projector"]) + ".uchg")
            flag_marker.write_text("1", encoding="utf-8")
            r_flag_same = run_place(
                str(PROJECTOR),
                sha=proj_sha,
                extra_env={
                    "CHFLAGS_LOG": str(chflags_log),
                    "FAKE_FLAG_FILE": str(paths["installed_projector"]),
                },
            )
            self.assertEqual(r_flag_same.returncode, 0, r_flag_same.stderr)
            self.assertIn("CHANGED=1", r_flag_same.stdout)
            self.assertFalse(flag_marker.exists(), "chflags 0 must clear destination flag before mv")

            alt_proj = root / "alt-projector.py"
            alt_bytes = PROJECTOR.read_bytes() + b"\n# alt\n"
            alt_proj.write_bytes(alt_bytes)
            alt_sha = hashlib.sha256(alt_bytes).hexdigest()
            r_changed = run_place(str(alt_proj), sha=alt_sha)
            self.assertEqual(r_changed.returncode, 0, r_changed.stderr)
            self.assertIn("CHANGED=1", r_changed.stdout)
            self.assertEqual(paths["installed_projector"].read_bytes(), alt_bytes)
            # Restore original projector for Gate 1 test
            r_restore = run_place(str(PROJECTOR), sha=proj_sha)
            self.assertEqual(r_restore.returncode, 0, r_restore.stderr)

            # 6. Sibling $here/bin/projector.py wins over competing $here/../../tools/projector.py
            outer = root / "outer"
            (outer / "tools").mkdir(parents=True)
            (outer / "a" / "b" / "bin").mkdir(parents=True)
            (outer / "tools" / "projector.py").write_bytes(b"# outer\n")
            sib_bytes = PROJECTOR.read_bytes()
            (outer / "a" / "b" / "bin" / "projector.py").write_bytes(sib_bytes)
            r_prec = run_place(
                "",
                sha=proj_sha,
                here_dir=outer / "a" / "b",
                post_cmds='echo "CHOSEN=$projector_src"',
            )
            self.assertEqual(r_prec.returncode, 0, r_prec.stderr)
            self.assertIn(f"CHOSEN={outer / 'a' / 'b' / 'bin' / 'projector.py'}", r_prec.stdout)

            # 7. Symlink projector source refused
            link_src = root / "proj-link.py"
            link_src.symlink_to(PROJECTOR)
            r_link = run_place(str(link_src), sha=proj_sha)
            self.assertNotEqual(r_link.returncode, 0)
            self.assertIn("regular non-symlink", r_link.stderr)

            # 7b. R5 Fix #2 (Codex R5 #2): place_projector fails closed if $prepared_projector_file disappeared (never reopens $projector_src)
            paths["installed_projector"].unlink()
            missing_stage_script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                "has_acl_path() { return 1; }\n"
                "check_ancestors() { return 0; }\n"
                "check_ancestors_ok() { return 0; }\n"
                "make_stage() { return 0; }\n"
                f'prefix="{paths["prefix"]}"\n'
                f'stage_dir="{paths["stage_dir"]}"\n'
                f'here="{root}"\n'
                f'projector_src="{PROJECTOR}"\n'
                f'projector_sha256="{proj_sha}"\n'
                f'installed_projector="{paths["installed_projector"]}"\n'
                'place_projector_tmp=""\n'
                'prepared_projector_file=""\n'
                "projector_prepared=0\n"
                "installed_projector_originally_clean=0\n"
                "upgrade_prefix_swapped=0\n"
                "changed=0\n"
                f"{place_funcs}\n"
                "prepare_projector_source\n"
                'rm -f "$prepared_projector_file"\n'
                "place_projector\n"
            )
            r_missing_stage = subprocess.run(
                ["/bin/bash", "-c", missing_stage_script], capture_output=True, text=True, check=False
            )
            self.assertNotEqual(r_missing_stage.returncode, 0)
            self.assertIn("staged copy is missing", r_missing_stage.stderr)
            self.assertFalse(
                paths["installed_projector"].exists(),
                "place_projector must NOT reopen $projector_src when staged file disappeared",
            )
            # Re-install projector for Gate 1 test below
            r_reinstall = run_place(str(PROJECTOR), sha=proj_sha)
            self.assertEqual(r_reinstall.returncode, 0, r_reinstall.stderr)

            # 8. Gate 1 rejection leaves live data untouched
            before_ino = paths["data"].stat().st_ino
            bad = root / "bad.json"
            bad.write_bytes(orig + b"\n")
            r = self._run_put_data(paths, bad)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("projector rejected", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)
            self.assertEqual(paths["data"].stat().st_ino, before_ino)

            # 9. Idempotent re-run on identical valid data leaves changed=0
            paths["stage_dir"].mkdir(exist_ok=True, mode=0o700)
            r_idem = self._run_put_data(paths, DARWIN_CANARY_PRESENT)
            self.assertEqual(r_idem.returncode, 0, r_idem.stderr)
            self.assertIn("CHANGED=0", r_idem.stdout)

    def test_validate_cmdb_refused_prepublish_and_postpublish_rollback(self) -> None:
        # Pre-publish refusal (exit 0 with tendcf_cmdb_refused) -> live data untouched
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            probe_log = root / "live-during-gate2.log"
            paths = self._build_env(
                root,
                "#!/bin/sh\n"
                f'cat "{root / "opt/tendcf/var/libntech/data/host_specific.json"}" > "{probe_log}"\n'
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "echo 'tendcf_cmdb_problem_badkey   source=policy'\n"
                "echo 'tendcf_cmdb_refused   source=policy'\n"
                "exit 0\n",
                initial_data=orig,
            )
            before_ino = paths["data"].stat().st_ino
            r = self._run_put_data(paths, DARWIN_CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("tendcf_cmdb_refused", r.stderr)
            self.assertIn("tendcf_cmdb_problem_badkey", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)
            self.assertEqual(paths["data"].stat().st_ino, before_ino)
            self.assertEqual(probe_log.read_bytes(), orig)

        # Codex #5: empty / diagnostic-only / untagged marker / awk error -> all fail closed
        for label, cf_script, expect in (
            ("empty", "#!/bin/sh\nexit 0\n", "missing positive tendcf_cmdb_evaluated"),
            ("header only", "#!/bin/sh\necho 'Class name  Meta'\necho 'any  hardclass'\nexit 0\n", "missing positive tendcf_cmdb_evaluated"),
            ("wrong source tag", "#!/bin/sh\necho 'tendcf_cmdb_evaluated  source=cmdb'\nexit 0\n", "missing positive tendcf_cmdb_evaluated"),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                orig = DARWIN_CANARY_PRESENT.read_bytes()
                paths = self._build_env(root, cf_script, initial_data=orig)
                r = self._run_put_data(paths, DARWIN_CANARY_ABSENT)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(expect, r.stderr)
                self.assertEqual(paths["data"].read_bytes(), orig)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            paths = self._build_env(root, DARWIN_OK_CF_SCRIPT, initial_data=orig)
            awk_fail = paths["shim_dir"] / "awk-fail"
            awk_fail.write_text("#!/bin/sh\nexit 19\n", encoding="utf-8")
            awk_fail.chmod(0o755)
            r = self._run_put_data(paths, DARWIN_CANARY_ABSENT, awk_override=str(awk_fail))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("awk exit 19", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)

        # Post-publish Gate 3 refusal with prior data -> rolls back to previous backup
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=orig)
            r = self._run_put_data(paths, DARWIN_CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("previous data restored", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)
            leftovers = [
                p.name
                for p in (paths["workdir"] / "data").iterdir()
                if ".new." in p.name or ".prev." in p.name
            ]
            self.assertEqual(leftovers, [])

        # Post-publish Gate 3 refusal with initial_data=None -> removes newly published file
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=None)
            r = self._run_put_data(paths, DARWIN_CANARY_PRESENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("new data removed", r.stderr)
            self.assertFalse(paths["data"].exists())

        # Post-publish Gate 3 rollback mv failure -> backup is preserved (not deleted by cleanup_stage)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=orig)
            real_mv = shutil.which("mv") or "/bin/mv"
            mv_fail = paths["shim_dir"] / "mv-fail-rollback"
            mv_fail.write_text(
                f"#!/bin/sh\ncase \"$2\" in *.prev.*) exit 1 ;; esac\nexec {real_mv} \"$@\"\n",
                encoding="utf-8",
            )
            mv_fail.chmod(0o755)
            r = self._run_put_data(paths, DARWIN_CANARY_ABSENT, mv_override=str(mv_fail))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("rollback failed; backup preserved at", r.stderr)
            backups = [p for p in (paths["workdir"] / "data").iterdir() if ".host_specific.prev." in p.name]
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), orig)

    def test_sigterm_during_gate3_rolls_back_previous_or_removes_first_time(self) -> None:
        """Codex #4: catchable SIGTERM during Gate 3 rolls back under FD 9."""
        for label, init_bytes in (("with_prev", DARWIN_CANARY_PRESENT.read_bytes()), ("first_time", None)):
            with self.subTest(label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                live_wd = root / "opt" / "tendcf" / "var" / "libntech"
                gate3_ready = root / "gate3.ready"
                cf_script = (
                    "#!/bin/sh\n"
                    'wd=""\n'
                    'while [ $# -gt 0 ]; do\n'
                    '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                    'done\n'
                    f'if [ "$wd" = "{live_wd}" ]; then\n'
                    f'  echo ready > "{gate3_ready}"\n'
                    "  sleep 10\n"
                    "fi\n"
                    "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                    "exit 0\n"
                )
                paths = self._build_env(root, cf_script, initial_data=init_bytes)
                script = self._put_data_script(paths, DARWIN_CANARY_ABSENT)
                proc = subprocess.Popen(
                    ["/bin/bash", "-c", script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 10.0
                while not gate3_ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(gate3_ready.exists(), "Gate 3 cf-promises never started")
                os.killpg(proc.pid, signal.SIGTERM)
                _out, err = proc.communicate(timeout=10)
                self.assertNotEqual(proc.returncode, 0)
                if init_bytes is not None:
                    self.assertEqual(paths["data"].read_bytes(), init_bytes)
                    self.assertIn("previous data restored", err)
                else:
                    self.assertFalse(paths["data"].exists())
                    self.assertIn("removed unverified first-time data", err)
                leftovers = [
                    p.name
                    for p in (paths["workdir"] / "data").iterdir()
                    if ".new." in p.name or ".prev." in p.name
                ]
                self.assertEqual(leftovers, [])

    def test_failed_upgrade_rollback_serializes_with_concurrent_standalone_data(self) -> None:
        """Codex #1: standalone `data` blocks until failed upgrade rollback finishes and its bytes survive."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            new_bytes = DARWIN_CANARY_ABSENT.read_bytes()
            paths = self._build_env(root, DARWIN_OK_CF_SCRIPT, initial_data=orig)
            # Build backup_prefix representing the pre-upgrade tree
            backup_prefix = root / "opt" / "tendcf.old.777"
            (backup_prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
            shutil.copy2(PROJECTOR, backup_prefix / "share" / "tendcf" / "bin" / "projector.py")
            (backup_prefix / "share" / "tendcf" / "bin" / "projector.py").chmod(0o644)

            snap = paths["stage_dir"] / "upgrade-var-backup"
            snap.mkdir(parents=True)
            (snap / "host_specific.json").write_bytes(orig)

            upgrade_started = root / "upgrade.locked"
            order_log = root / "order.log"

            upg_funcs = self._darwin_funcs(
                paths["shim_dir"],
                ("check_dir_root_unwritable", "acquire_publish_lock", "release_publish_lock", "cleanup_stage"),
            )
            upg_script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                "has_acl_path() { return 1; }\n"
                "check_ancestors() { return 0; }\n"
                'label="org.tendcf.execd"\n'
                f'prefix="{paths["prefix"]}"\n'
                f'stage_dir="{paths["stage_dir"]}"\n'
                f'plist_path="{root / "missing.plist"}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup_prefix}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=1\n"
                "upgrade_was_loaded=0\n"
                "upgrade_had_plist=0\n"
                "upgrade_snapshot_taken=1\n"
                f'upgrade_saved_workdir="{paths["workdir"]}"\n'
                "upgrade_saved_inputs=0\n"
                "upgrade_saved_data=1\n"
                "publish_lock_held=0\n"
                "put_data_rollback_armed=0\n"
                "put_data_had_prev=0\n"
                'put_data_stage_wd=""\n'
                'put_data_tmp=""\n'
                'put_data_backup=""\n'
                'place_projector_tmp=""\n'
                "execd_is_loaded() { return 1; }\n"
                "bootout_execd() { return 0; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                "bootstrap_execd_with_retry() { return 0; }\n"
                f"{upg_funcs}\n"
                f'on_exit() {{ cleanup_stage; echo "UPGRADE_ROLLBACK_DONE" >> "{order_log}"; }}\n'
                "trap on_exit EXIT\n"
                "acquire_publish_lock\n"
                f'echo locked > "{upgrade_started}"\n'
                # Simulate post-swap upgrade work failing after 0.35s
                "sleep 0.35\n"
                "exit 1\n"
            )
            p_upg = subprocess.Popen(
                ["/bin/bash", "-c", upg_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 5.0
            while not upgrade_started.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(upgrade_started.exists(), "upgrade did not acquire lock")

            # Launch concurrent standalone `data` publisher while upgrade holds the lock
            data_stage = root / "stage-data"
            data_stage.mkdir(mode=0o700)
            data_script = (
                self._put_data_script(paths, DARWIN_CANARY_ABSENT, stage_override=data_stage)
                + f'echo "STANDALONE_DATA_DONE" >> "{order_log}"\n'
            )
            p_data = subprocess.Popen(
                ["/bin/bash", "-c", data_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            _uo, ue = p_upg.communicate(timeout=15)
            do, de = p_data.communicate(timeout=15)
            self.assertEqual(p_upg.returncode, 1)
            self.assertIn("rolled back failed upgrade", ue)
            self.assertEqual(p_data.returncode, 0, f"standalone data failed: {do}\n{de}")
            # Standalone data must have run AFTER upgrade rollback and its bytes must survive!
            self.assertEqual(paths["data"].read_bytes(), new_bytes)
            self.assertEqual(
                order_log.read_text(encoding="utf-8").splitlines(),
                ["UPGRADE_ROLLBACK_DONE", "STANDALONE_DATA_DONE"],
            )

    def test_concurrent_publishers_serialize_with_lockf(self) -> None:
        """Issue #58: concurrent Darwin put_data publishers serialize via /usr/bin/lockf 9."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trace = root / "cs.log"
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" != "{live_wd}" ]; then\n'
                f'  echo "ENTER $WORKER_ID" >> "{trace}"\n'
                "  sleep 0.08\n"
                f'  echo "LEAVE $WORKER_ID" >> "{trace}"\n'
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=DARWIN_CANARY_PRESENT.read_bytes())
            procs: list[subprocess.Popen[str]] = []
            for i in range(6):
                src = DARWIN_CANARY_ABSENT if i % 2 == 0 else DARWIN_CANARY_PRESENT
                w_stage = root / f"stage-{i}"
                w_stage.mkdir(mode=0o700)
                script = self._put_data_script(
                    paths, src, stage_override=w_stage, extra_preamble=f'export WORKER_ID="{i}"'
                )
                procs.append(
                    subprocess.Popen(
                        ["/bin/bash", "-c", script],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )
            for i, p in enumerate(procs):
                out, err = p.communicate(timeout=30)
                self.assertEqual(p.returncode, 0, f"worker {i} failed: {out}\n{err}")

            final = paths["data"].read_bytes()
            self.assertIn(final, (DARWIN_CANARY_PRESENT.read_bytes(), DARWIN_CANARY_ABSENT.read_bytes()))
            lines = trace.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 12)
            for idx in range(0, len(lines), 2):
                enter_tok = lines[idx].split()
                leave_tok = lines[idx + 1].split()
                self.assertEqual(enter_tok[0], "ENTER")
                self.assertEqual(leave_tok[0], "LEAVE")
                self.assertEqual(enter_tok[1], leave_tok[1], f"interleaved lock trace: {lines}")

            leftovers = [
                p.name
                for p in (paths["workdir"] / "data").iterdir()
                if p.name != "host_specific.json"
            ]
            self.assertEqual(leftovers, [])
            self.assertTrue((root / "opt" / ".tendcf-publish.lock").is_file())

    def test_cmd_install_checks_projector_trust_before_check_tree_and_replaces_inode(self) -> None:
        """R3 Fix #1 (Codex #3): Darwin check_tree must NOT launder writable projector; pinned replaces inode."""
        proj_sha = hashlib.sha256(PROJECTOR.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paths = self._build_env(root, DARWIN_OK_CF_SCRIPT, initial_data=None)
            prefix = paths["prefix"]
            (prefix / "bin").mkdir(parents=True)
            for b in ("cf-agent", "cf-promises", "cf-key", "cf-execd"):
                bp = prefix / "bin" / b
                bp.write_text("#!/bin/sh\necho 'CFEngine Core 3.21.0'\n", encoding="utf-8")
                bp.chmod(0o755)
            dst = paths["installed_projector"]
            os.chmod(dst, 0o666)  # group/world-writable BEFORE cmd_install!

            policy_dir = root / "policy"
            policy_dir.mkdir()
            (policy_dir / "tendcf_services.cf").write_text("# dummy\n", encoding="utf-8")

            funcs = self._darwin_funcs(
                paths["shim_dir"],
                (
                    "cleanup_stage",
                    "ensure_dir",
                    "check_dir_root_unwritable",
                    "acquire_publish_lock",
                    "release_publish_lock",
                    "check_no_stale_upgrade_dirs",
                    "resolve_realpath_ok",
                    "resolve_projector_src",
                    "source_file_root_trusted_ok",
                    "check_source_file_root_trusted",
                    "verify_installed_projector",
                    "installed_projector_clean_ok",
                    "check_tree",
                    "prepare_projector_source",
                    "detach_unsafe_installed_projector",
                    "place_projector",
                    "prevalidate_install_inputs",
                    "cmd_install",
                ),
            )
            real_find = shutil.which("find") or "/usr/bin/find"
            real_sed = shutil.which("sed") or "/usr/bin/sed"
            funcs = funcs.replace("/usr/bin/find", real_find).replace("/usr/bin/sed", real_sed)

            dirty_marker = prefix / "share" / "tendcf" / "dirty-marker"
            dirty_marker.write_text("dirty\n", encoding="utf-8")

            def run_cmd_install(extra_args: str, *, fail_place_policy: bool = False) -> subprocess.CompletedProcess[str]:
                paths["stage_dir"].mkdir(exist_ok=True, mode=0o700)
                os.chmod(dirty_marker, 0o666)
                place_pol_body = 'die "injected place_policy failure"' if fail_place_policy else "return 0"
                script = (
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    'say() { echo "tendcf-install: $*"; }\n'
                    "has_acl_path() { return 1; }\n"
                    "has_acl_tree() { return 1; }\n"
                    "check_ancestors() { return 0; }\n"
                    "check_ancestors_ok() { return 0; }\n"
                    "make_stage() { return 0; }\n"
                    "verify_macho_tree() { return 0; }\n"
                    "init_paths() { return 0; }\n"
                    "lay_out() { return 0; }\n"
                    "prepare_audit_log_source() { return 0; }\n"
                    "validate_existing_audit_state_before_repair() { return 0; }\n"
                    "detach_unsafe_installed_audit_log() { return 0; }\n"
                    "place_audit_log() { return 0; }\n"
                    "place_audit_shipper_state() { return 0; }\n"
                    "place_tripwire_rules() { return 0; }\n"
                    "enable_audit_shipper() { return 0; }\n"
                    f"place_policy() {{ {place_pol_body}; }}\n"
                    f'prefix="{prefix}"\n'
                    f'stage_dir="{paths["stage_dir"]}"\n'
                    f'cf_agent="{prefix}/bin/cf-agent"\n'
                    f'cf_promises="{prefix}/bin/cf-promises"\n'
                    f'cf_key="{prefix}/bin/cf-key"\n'
                    f'cf_execd="{prefix}/bin/cf-execd"\n'
                    f'here="{root}"\n'
                    f'policy_src="{policy_dir}"\n'
                    'projector_src=""\n'
                    'projector_sha256=""\n'
                    f'installed_projector="{dst}"\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    "upgrade_prefix_swapped=0\n"
                    "upgrade_rollback_armed=0\n"
                    'upgrade_backup_prefix=""\n'
                    'upgrade_staged_tree=""\n'
                    "upgrade_moved_var=0\n"
                    "upgrade_was_loaded=0\n"
                    "upgrade_had_plist=0\n"
                    "upgrade_snapshot_taken=0\n"
                    'upgrade_saved_workdir=""\n'
                    "upgrade_saved_inputs=0\n"
                    "upgrade_saved_data=0\n"
                    "upgrade_needs_execd_restart=0\n"
                    "publish_lock_held=0\n"
                    "put_data_rollback_armed=0\n"
                    "put_data_had_prev=0\n"
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    "changed=0\n"
                    f"{funcs}\n"
                    # Drive check_tree's repair path using dirty_marker so check_tree always runs chmod -R a-s,go-w
                    f'tree_is_clean() {{ local m; m="$({paths["shim_dir"] / "stat"} -f \'%Lp\' "{dirty_marker}")"; [ $((8#$m & 8#022)) -eq 0 ]; }}\n'
                    "trap cleanup_stage EXIT\n"
                    f'cmd_install --policy-src "{policy_dir}" {extra_args}\n'
                )
                # Ensure xattr shim prints nothing & returns 0 for `xattr -s`, returns 1 for `xattr -p`
                (paths["shim_dir"] / "xattr").write_text(
                    '#!/bin/sh\nif [ "$1" = "-p" ]; then exit 1; fi\nexit 0\n',
                    encoding="utf-8",
                )
                (paths["shim_dir"] / "xattr").chmod(0o755)
                # Allow stat -f '%Lp' in tree_is_clean helper
                (paths["shim_dir"] / "stat").write_text(
                    f"#!{sys.executable}\n"
                    "import os, stat, sys\n"
                    "fmt = sys.argv[2]\n"
                    "p = sys.argv[3]\n"
                    "st = os.lstat(p)\n"
                    "mode = stat.S_IMODE(st.st_mode)\n"
                    "if fmt == '%Su:%Sg %Lp': print(f'root:wheel {mode:o}')\n"
                    "elif fmt == '%Su %Sg %Lp': print(f'root wheel {mode:o}')\n"
                    "elif fmt == '%Lp': print(f'{mode:o}')\n"
                    "elif fmt == '%f': print('0')\n",
                    encoding="utf-8",
                )
                (paths["shim_dir"] / "stat").chmod(0o755)
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            # 1. Unpinned on writable packaged projector -> REFUSED BEFORE check_tree runs!
            r_unpinned = run_cmd_install(f'--projector-src "{dst}"')
            self.assertNotEqual(r_unpinned.returncode, 0)
            self.assertIn("--projector-sha256", r_unpinned.stderr)
            self.assertEqual(
                stat.S_IMODE(dst.stat().st_mode),
                0o666,
                "check_tree must NOT have run to launder writable projector before refusal",
            )

            # 2. R4 Fix #2 (Codex R4 #2): failure between check_tree and place_projector leaves unsafe dst DETACHED!
            ext_proj = root / "ext-projector.py"
            shutil.copy2(PROJECTOR, ext_proj)
            os.chmod(ext_proj, 0o644)
            for label, args in (
                ("external_src", f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}'),
                ("pinned_dst", f'--projector-src "{dst}" --projector-sha256 {proj_sha}'),
            ):
                with self.subTest(mid_fail=label):
                    shutil.copy2(PROJECTOR, dst)
                    os.chmod(dst, 0o666)
                    r_fail = run_cmd_install(args, fail_place_policy=True)
                    self.assertNotEqual(r_fail.returncode, 0)
                    self.assertIn("injected place_policy failure", r_fail.stderr)
                    self.assertFalse(
                        dst.exists() or dst.is_symlink(),
                        "unsafe installed_projector must be detached before check_tree, never laundered",
                    )
                    # Subsequent verify_installed_projector fails closed
                    r_ver = subprocess.run(
                        [
                            "/bin/bash",
                            "-c",
                            "set -euo pipefail\n"
                            'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                            "has_acl_path() { return 1; }\n"
                            "check_ancestors() { return 0; }\n"
                            f'prefix="{prefix}"\n'
                            f'installed_projector="{dst}"\n'
                            f"{funcs}\n"
                            "verify_installed_projector\n",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(r_ver.returncode, 0)
                    # Subsequent unpinned cmd_install pointing at missing $dst fails closed
                    r_retry = run_cmd_install(f'--projector-src "{dst}"')
                    self.assertNotEqual(r_retry.returncode, 0)

            # 3. R6 Fix #1 (Codex R6 #1): unsafe writable parent ($prefix/share/tendcf/bin mode 0777) MUST fail closed
            #    BEFORE mutating any directory mode/owner/ACL, for BOTH existing 0644 leaf and absent leaf!
            proj_bin_dir = prefix / "share" / "tendcf" / "bin"
            # (a) Writable parent + existing 0644 leaf -> fails closed, parent stays 0777, verify_installed_projector still refuses!
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o644)
            os.chmod(proj_bin_dir, 0o777)
            r_wparent_leaf = run_cmd_install(
                f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}',
            )
            self.assertNotEqual(r_wparent_leaf.returncode, 0)
            self.assertEqual(
                stat.S_IMODE(proj_bin_dir.stat().st_mode),
                0o777,
                "unsafe existing projector parent chain must NOT be mutated before refusing",
            )
            r_ver_wp = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "has_acl_path() { return 1; }\n"
                    "check_ancestors() { return 0; }\n"
                    f'prefix="{prefix}"\n'
                    f'installed_projector="{dst}"\n'
                    f"{funcs}\n"
                    "verify_installed_projector\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_ver_wp.returncode, 0, "verify_installed_projector must still refuse exposed leaf")

            # (b) Writable parent + absent leaf -> fails closed, parent stays 0777
            dst.unlink()
            os.chmod(proj_bin_dir, 0o777)
            r_wparent_absent = run_cmd_install(
                f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}',
            )
            self.assertNotEqual(r_wparent_absent.returncode, 0)
            self.assertEqual(
                stat.S_IMODE(proj_bin_dir.stat().st_mode),
                0o777,
                "unsafe existing projector parent chain with absent leaf must NOT be mutated",
            )
            os.chmod(proj_bin_dir, 0o755)

            # (c) Codex R7 #1: writable $prefix/share (0777) MUST fail closed with ZERO mutations whether
            #     $prefix/share/tendcf is absent OR contains a 0644 projector subtree!
            shutil.rmtree(prefix / "share" / "tendcf")
            dirty_marker_orig = dirty_marker
            alt_dirty = prefix / "share" / "dirty-marker"
            alt_dirty.write_text("dirty\n", encoding="utf-8")
            os.chmod(alt_dirty, 0o666)
            os.chmod(prefix / "share", 0o777)

            def run_cmd_install_alt_dirty(extra_args: str) -> subprocess.CompletedProcess[str]:
                paths["stage_dir"].mkdir(exist_ok=True, mode=0o700)
                return subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        "set -euo pipefail\n"
                        'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                        'say() { echo "tendcf-install: $*"; }\n'
                        "has_acl_path() { return 1; }\n"
                        "has_acl_tree() { return 1; }\n"
                        "check_ancestors() { return 0; }\n"
                        "check_ancestors_ok() { return 0; }\n"
                        "make_stage() { return 0; }\n"
                        "verify_macho_tree() { return 0; }\n"
                        "init_paths() { return 0; }\n"
                        "lay_out() { return 0; }\n"
                        "prepare_audit_log_source() { return 0; }\n"
                        "validate_existing_audit_state_before_repair() { return 0; }\n"
                        "detach_unsafe_installed_audit_log() { return 0; }\n"
                        "place_audit_log() { return 0; }\n"
                        "place_audit_shipper_state() { return 0; }\n"
                        "place_tripwire_rules() { return 0; }\n"
                        "enable_audit_shipper() { return 0; }\n"
                        "place_policy() { return 0; }\n"
                        f'prefix="{prefix}"\n'
                        f'stage_dir="{paths["stage_dir"]}"\n'
                        f'cf_agent="{prefix}/bin/cf-agent"\n'
                        f'cf_promises="{prefix}/bin/cf-promises"\n'
                        f'cf_key="{prefix}/bin/cf-key"\n'
                        f'cf_execd="{prefix}/bin/cf-execd"\n'
                        f'here="{root}"\n'
                        f'policy_src="{policy_dir}"\n'
                        'projector_src=""\n'
                        'projector_sha256=""\n'
                        f'installed_projector="{dst}"\n'
                        'place_projector_tmp=""\n'
                        'prepared_projector_file=""\n'
                        "projector_prepared=0\n"
                        "installed_projector_originally_clean=0\n"
                        "upgrade_prefix_swapped=0\n"
                        "upgrade_rollback_armed=0\n"
                        'upgrade_backup_prefix=""\n'
                        'upgrade_staged_tree=""\n'
                        "upgrade_moved_var=0\n"
                        "upgrade_was_loaded=0\n"
                        "upgrade_had_plist=0\n"
                        "upgrade_snapshot_taken=0\n"
                        'upgrade_saved_workdir=""\n'
                        "upgrade_saved_inputs=0\n"
                        "upgrade_saved_data=0\n"
                        "upgrade_needs_execd_restart=0\n"
                        "publish_lock_held=0\n"
                        "put_data_rollback_armed=0\n"
                        "put_data_had_prev=0\n"
                        'put_data_stage_wd=""\n'
                        'put_data_tmp=""\n'
                        'put_data_backup=""\n'
                        "changed=0\n"
                        f"{funcs}\n"
                        f'tree_is_clean() {{ local m; m="$({paths["shim_dir"] / "stat"} -f \'%Lp\' "{alt_dirty}")"; [ $((8#$m & 8#022)) -eq 0 ]; }}\n'
                        "trap cleanup_stage EXIT\n"
                        f'cmd_install --policy-src "{policy_dir}" {extra_args}\n',
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            r_wshare_absent = run_cmd_install_alt_dirty(f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}')
            self.assertNotEqual(r_wshare_absent.returncode, 0)
            self.assertEqual(
                stat.S_IMODE((prefix / "share").stat().st_mode),
                0o777,
                "writable $prefix/share must NOT be mutated before failing closed",
            )
            (prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o644)
            r_wshare_leaf = run_cmd_install_alt_dirty(f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}')
            self.assertNotEqual(r_wshare_leaf.returncode, 0)
            self.assertEqual(stat.S_IMODE((prefix / "share").stat().st_mode), 0o777)
            r_ver_ws = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "has_acl_path() { return 1; }\n"
                    "check_ancestors() { return 0; }\n"
                    f'prefix="{prefix}"\n'
                    f'installed_projector="{dst}"\n'
                    f"{funcs}\n"
                    "verify_installed_projector\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_ver_ws.returncode, 0)

            # (d) Fresh tree with ALREADY-trusted $prefix/$prefix/share (0755) and absent $prefix/share/tendcf -> succeeds!
            shutil.rmtree(prefix / "share" / "tendcf")
            os.chmod(prefix / "share", 0o755)
            r_fresh = run_cmd_install_alt_dirty(f'--projector-src "{ext_proj}" --projector-sha256 {proj_sha}')
            self.assertEqual(r_fresh.returncode, 0, r_fresh.stderr)
            self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)
            dirty_marker_orig.write_text("dirty\n", encoding="utf-8")

            # 4. R5 Fix #3 (Codex R5 #3): hold open writable FD on dst across cmd_install (prevents ext4 inode reuse
            #    and proves the old writable descriptor cannot tamper with the newly installed projector)
            shutil.copy2(PROJECTOR, dst)
            os.chmod(dst, 0o666)
            with dst.open("r+b") as held_fd:
                old_ino = os.fstat(held_fd.fileno()).st_ino
                r_pinned = run_cmd_install(f'--projector-src "{dst}" --projector-sha256 {proj_sha}')
                self.assertEqual(r_pinned.returncode, 0, r_pinned.stderr)
                self.assertEqual(dst.read_bytes(), PROJECTOR.read_bytes())
                self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)
                self.assertNotEqual(
                    dst.stat().st_ino,
                    old_ino,
                    "pinned install over formerly writable projector must replace inode",
                )
                held_fd.seek(0)
                held_fd.write(b"# tampered-old-fd\n")
                held_fd.flush()
                self.assertEqual(
                    dst.read_bytes(),
                    PROJECTOR.read_bytes(),
                    "writes through previously opened writable FD must NOT affect newly installed projector",
                )

    def test_cmd_install_tarball_prefix_swap_installs_pre_swap_staged_projector(self) -> None:
        """R4 Fix #1 (Codex R4 #1): Darwin tarball prefix swap installs pre-swap staged projector bytes without re-resolving $projector_src."""
        orig_bytes = PROJECTOR.read_bytes()
        for scenario in ("different_bytes", "omitted"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                paths = self._build_env(root, DARWIN_OK_CF_SCRIPT, initial_data=None)
                prefix = paths["prefix"]
                (prefix / "bin").mkdir(parents=True)
                for b in ("cf-agent", "cf-promises", "cf-key", "cf-execd"):
                    bp = prefix / "bin" / b
                    bp.write_text("#!/bin/sh\necho 'CFEngine Core 3.21.0'\n", encoding="utf-8")
                    bp.chmod(0o755)
                dst = paths["installed_projector"]
                dst.write_bytes(orig_bytes)
                os.chmod(dst, 0o644)

                # Build replacement tree that install_tarball will swap into $prefix
                new_tree = root / "new-prefix"
                (new_tree / "bin").mkdir(parents=True)
                for b in ("cf-agent", "cf-promises", "cf-key", "cf-execd"):
                    bp = new_tree / "bin" / b
                    bp.write_text("#!/bin/sh\necho 'CFEngine Core 3.22.0'\n", encoding="utf-8")
                    bp.chmod(0o755)
                if scenario == "different_bytes":
                    (new_tree / "share" / "tendcf" / "bin").mkdir(parents=True)
                    rogue = new_tree / "share" / "tendcf" / "bin" / "projector.py"
                    rogue.write_bytes(b"# rogue replacement tarball projector bytes\n")
                    os.chmod(rogue, 0o644)

                policy_dir = root / "policy"
                policy_dir.mkdir()
                (policy_dir / "tendcf_services.cf").write_text("# dummy\n", encoding="utf-8")
                fake_tar = root / "fake.tar.gz"
                fake_tar.write_bytes(b"tar")
                fake_sha = root / "fake.tar.gz.sha256"
                fake_sha.write_text("0" * 64 + "  fake.tar.gz\n", encoding="utf-8")

                funcs = self._darwin_funcs(
                    paths["shim_dir"],
                    (
                        "cleanup_stage",
                        "ensure_dir",
                        "check_dir_root_unwritable",
                        "acquire_publish_lock",
                        "release_publish_lock",
                        "check_no_stale_upgrade_dirs",
                        "resolve_projector_src",
                        "source_file_root_trusted_ok",
                        "check_source_file_root_trusted",
                        "verify_installed_projector",
                        "installed_projector_clean_ok",
                        "prepare_projector_source",
                        "detach_unsafe_installed_projector",
                        "place_projector",
                        "prevalidate_install_inputs",
                        "cmd_install",
                    ),
                )
                real_find = shutil.which("find") or "/usr/bin/find"
                real_sed = shutil.which("sed") or "/usr/bin/sed"
                funcs = funcs.replace("/usr/bin/find", real_find).replace("/usr/bin/sed", real_sed)

                script = (
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    'say() { echo "tendcf-install: $*"; }\n'
                    "has_acl_path() { return 1; }\n"
                    "has_acl_tree() { return 1; }\n"
                    "check_ancestors() { return 0; }\n"
                    "check_ancestors_ok() { return 0; }\n"
                    "make_stage() { return 0; }\n"
                    f'install_tarball() {{ rm -rf "{prefix}.prev"; mv "{prefix}" "{prefix}.prev"; mv "{new_tree}" "{prefix}"; upgrade_prefix_swapped=1; changed=1; }}\n'
                    "check_tree() { return 0; }\n"
                    "init_paths() { return 0; }\n"
                    "lay_out() { return 0; }\n"
                    "prepare_audit_log_source() { return 0; }\n"
                    "validate_existing_audit_state_before_repair() { return 0; }\n"
                    "detach_unsafe_installed_audit_log() { return 0; }\n"
                    "place_audit_log() { return 0; }\n"
                    "place_audit_shipper_state() { return 0; }\n"
                    "place_tripwire_rules() { return 0; }\n"
                    "enable_audit_shipper() { return 0; }\n"
                    "place_policy() { return 0; }\n"
                    f'prefix="{prefix}"\n'
                    f'stage_dir="{paths["stage_dir"]}"\n'
                    f'cf_agent="{prefix}/bin/cf-agent"\n'
                    f'cf_promises="{prefix}/bin/cf-promises"\n'
                    f'cf_key="{prefix}/bin/cf-key"\n'
                    f'cf_execd="{prefix}/bin/cf-execd"\n'
                    f'here="{root}"\n'
                    f'policy_src="{policy_dir}"\n'
                    'projector_src=""\n'
                    'projector_sha256=""\n'
                    f'installed_projector="{dst}"\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    "upgrade_prefix_swapped=0\n"
                    "upgrade_rollback_armed=0\n"
                    'upgrade_backup_prefix=""\n'
                    'upgrade_staged_tree=""\n'
                    "upgrade_moved_var=0\n"
                    "upgrade_was_loaded=0\n"
                    "upgrade_had_plist=0\n"
                    "upgrade_snapshot_taken=0\n"
                    'upgrade_saved_workdir=""\n'
                    "upgrade_saved_inputs=0\n"
                    "upgrade_saved_data=0\n"
                    "upgrade_needs_execd_restart=0\n"
                    "publish_lock_held=0\n"
                    "put_data_rollback_armed=0\n"
                    "put_data_had_prev=0\n"
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    "changed=0\n"
                    f"{funcs}\n"
                    "trap cleanup_stage EXIT\n"
                    f'cmd_install --tarball "{fake_tar}" --sha256 "{fake_sha}" --policy-src "{policy_dir}" --projector-src "{dst}"\n'
                )
                r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
                self.assertEqual(r.returncode, 0, f"scenario={scenario} failed:\n{r.stdout}\n{r.stderr}")
                self.assertTrue(dst.is_file() and not dst.is_symlink())
                self.assertEqual(
                    dst.read_bytes(),
                    orig_bytes,
                    f"scenario={scenario}: must install pre-swap staged bytes, not replacement tarball bytes",
                )
                self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o644)

    def test_relative_projector_src_normalized_and_checked_through_ancestors(self) -> None:
        """R3 Fix #1 (Macroscope #4701728688): Darwin relative --projector-src normalized via pwd -L."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            paths = self._build_env(root, DARWIN_OK_CF_SCRIPT, initial_data=None)
            paths["installed_projector"].unlink()

            # Override stat shim: ancestors ABOVE root look like root wheel 755; inside root use real modes.
            (paths["shim_dir"] / "stat").write_text(
                f"#!{sys.executable}\n"
                "import os, stat, sys\n"
                f"root_s = {str(root)!r}\n"
                "fmt = sys.argv[2]\n"
                "p = sys.argv[3]\n"
                "rp = os.path.realpath(p) if not os.path.islink(p) else p\n"
                "if rp != root_s and not rp.startswith(root_s + '/'):\n"
                "    mode = 0o755\n"
                "else:\n"
                "    mode = stat.S_IMODE(os.lstat(p).st_mode)\n"
                "if fmt == '%Su:%Sg %Lp': print(f'root:wheel {mode:o}')\n"
                "elif fmt == '%Su %Sg %Lp': print(f'root wheel {mode:o}')\n"
                "elif fmt == '%Su %Lp': print(f'root {mode:o}')\n"
                "elif fmt == '%f': print('0')\n",
                encoding="utf-8",
            )
            (paths["shim_dir"] / "stat").chmod(0o755)
            os.chmod(root, 0o755)
            os.chmod(root / "opt", 0o755)
            os.chmod(paths["prefix"], 0o755)

            trusted_pkg = root / "trusted_pkg"
            (trusted_pkg / "bin").mkdir(parents=True)
            os.chmod(trusted_pkg, 0o755)
            os.chmod(trusted_pkg / "bin", 0o755)
            shutil.copy2(PROJECTOR, trusted_pkg / "bin" / "projector.py")
            os.chmod(trusted_pkg / "bin" / "projector.py", 0o644)

            writable_pkg = root / "writable_pkg"
            (writable_pkg / "bin").mkdir(parents=True)
            os.chmod(writable_pkg, 0o777)
            os.chmod(writable_pkg / "bin", 0o755)
            shutil.copy2(PROJECTOR, writable_pkg / "bin" / "projector.py")
            os.chmod(writable_pkg / "bin" / "projector.py", 0o644)

            sym_proj = trusted_pkg / "bin" / "link.py"
            sym_proj.symlink_to(trusted_pkg / "bin" / "projector.py")

            funcs = self._darwin_funcs(
                paths["shim_dir"],
                (
                    "ensure_dir",
                    "check_ancestor_dir_ok",
                    "check_ancestors_ok",
                    "check_ancestors",
                    "check_dir_root_unwritable",
                    "resolve_realpath_ok",
                    "resolve_projector_src",
                    "source_file_root_trusted_ok",
                    "check_source_file_root_trusted",
                    "verify_installed_projector",
                    "installed_projector_clean_ok",
                    "prepare_projector_source",
                    "detach_unsafe_installed_projector",
                    "place_projector",
                ),
            )

            def run_rel(cwd: Path, rel_src: str) -> subprocess.CompletedProcess[str]:
                script = (
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "has_acl_path() { return 1; }\n"
                    "make_stage() { return 0; }\n"
                    f'prefix="{paths["prefix"]}"\n'
                    f'stage_dir="{paths["stage_dir"]}"\n'
                    f'here="{root}"\n'
                    f'projector_src="{rel_src}"\n'
                    'projector_sha256=""\n'
                    f'installed_projector="{paths["installed_projector"]}"\n'
                    'place_projector_tmp=""\n'
                    'prepared_projector_file=""\n'
                    "projector_prepared=0\n"
                    "installed_projector_originally_clean=0\n"
                    "upgrade_prefix_swapped=0\n"
                    "changed=0\n"
                    f"{funcs}\n"
                    f'cd "{cwd}"\n'
                    "prepare_projector_source\n"
                    "detach_unsafe_installed_projector\n"
                    "place_projector\n"
                )
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            r_ok = run_rel(trusted_pkg, "bin/projector.py")
            self.assertEqual(r_ok.returncode, 0, r_ok.stderr)
            self.assertEqual(paths["installed_projector"].read_bytes(), PROJECTOR.read_bytes())

            r_sym = run_rel(trusted_pkg, "bin/link.py")
            self.assertNotEqual(r_sym.returncode, 0)
            self.assertIn("regular non-symlink", r_sym.stderr)

            r_ww = run_rel(writable_pkg, "bin/projector.py")
            self.assertNotEqual(r_ww.returncode, 0)
            self.assertIn("--projector-sha256", r_ww.stderr)

    def test_standalone_data_dispatch_locks_before_init_paths_during_prefix_swap(self) -> None:
        """R3 Fix #2 (Codex #1): standalone `data)` dispatch acquires lock BEFORE init_paths so transient prefix swap never fails it."""
        m_data_case = re.search(r"^\s+data\)\n(.*?)^\s+;;", self.src, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(m_data_case)
        data_dispatch_body = m_data_case.group(1)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            new_bytes = DARWIN_CANARY_ABSENT.read_bytes()
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            # Fake cf-promises supports BOTH --show-vars (for init_paths) and --show-classes (for put_data)
            cf_script = (
                "#!/bin/sh\n"
                'for a in "$@"; do\n'
                '  if [ "$a" = "--show-vars" ]; then\n'
                f'    echo "default:sys.workdir  {live_wd}"\n'
                "    exit 0\n"
                "  fi\n"
                "done\n"
                "echo 'any   hardclass'\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=orig)
            prefix = paths["prefix"]
            (prefix / "bin").mkdir(parents=True)
            shutil.copy2(paths["cf_promises"], prefix / "bin" / "cf-promises")
            (prefix / "bin" / "cf-promises").chmod(0o755)

            swapped_ready = root / "prefix.swapped"
            order_log = root / "order.log"

            upg_funcs = self._darwin_funcs(
                paths["shim_dir"],
                ("check_dir_root_unwritable", "acquire_publish_lock", "release_publish_lock"),
            )
            upg_script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                "has_acl_path() { return 1; }\n"
                "check_ancestors() { return 0; }\n"
                f'prefix="{prefix}"\n'
                "publish_lock_held=0\n"
                "changed=0\n"
                f"{upg_funcs}\n"
                "acquire_publish_lock\n"
                f'mv "{prefix}" "{prefix}.swap.tmp"\n'
                f'echo swapped > "{swapped_ready}"\n'
                "sleep 0.35\n"
                f'mv "{prefix}.swap.tmp" "{prefix}"\n'
                f'echo "SWAP_RESTORED" >> "{order_log}"\n'
                "release_publish_lock\n"
            )
            p_upg = subprocess.Popen(
                ["/bin/bash", "-c", upg_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 5.0
            while not swapped_ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(swapped_ready.exists(), "upgrade never moved $prefix aside")
            self.assertFalse(prefix.exists(), "$prefix must be transiently absent when standalone data starts")

            # Run actual extracted `data)` dispatch body (with init_paths regex scoped to temp $prefix)
            data_stage = root / "stage-data"
            data_stage.mkdir(mode=0o700)
            data_funcs = self._darwin_funcs(
                paths["shim_dir"],
                (
                    "cleanup_stage",
                    "check_dir_root_unwritable",
                    "check_no_symlink_components_under_prefix",
                    "acquire_publish_lock",
                    "release_publish_lock",
                    "init_paths",
                    "verify_installed_projector",
                    "validate_cmdb_workdir",
                    "put_data",
                ),
            ).replace("^/opt/tendcf/", f"^{prefix}/")
            data_script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                'say() { echo "tendcf-install: $*"; }\n'
                "has_acl_path() { return 1; }\n"
                "tree_is_clean() { [ -d \"$1\" ]; }\n"
                "check_ancestors() { return 0; }\n"
                "make_stage() { return 0; }\n"
                f'find_real_python() {{ echo "{sys.executable}"; }}\n'
                f'prefix="{prefix}"\n'
                f'cf_promises="{prefix}/bin/cf-promises"\n'
                'workdir=""\n'
                'entry=""\n'
                'data=""\n'
                f'stage_dir="{data_stage}"\n'
                f'installed_projector="{paths["installed_projector"]}"\n'
                "upgrade_rollback_armed=0\n"
                "publish_lock_held=0\n"
                "put_data_rollback_armed=0\n"
                "put_data_had_prev=0\n"
                'put_data_stage_wd=""\n'
                'put_data_tmp=""\n'
                'put_data_backup=""\n'
                'place_projector_tmp=""\n'
                "changed=0\n"
                f"{data_funcs}\n"
                "trap cleanup_stage EXIT\n"
                f'set -- "{DARWIN_CANARY_ABSENT}"\n'
                f"{data_dispatch_body}\n"
                f'echo "DATA_DISPATCH_DONE" >> "{order_log}"\n'
            )
            p_data = subprocess.Popen(
                ["/bin/bash", "-c", data_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            uo, ue = p_upg.communicate(timeout=15)
            do, de = p_data.communicate(timeout=15)
            self.assertEqual(p_upg.returncode, 0, f"swap sim failed: {uo}\n{ue}")
            self.assertEqual(p_data.returncode, 0, f"standalone data dispatch failed: {do}\n{de}")
            self.assertEqual(paths["data"].read_bytes(), new_bytes)
            self.assertEqual(
                order_log.read_text(encoding="utf-8").splitlines(),
                ["SWAP_RESTORED", "DATA_DISPATCH_DONE"],
            )

    def test_first_publication_rollback_rm_failure_reports_error_and_live_path(self) -> None:
        """R3 Fix #3 (Codex #4): Darwin first-pub rollback rm failure must report error naming $data."""
        real_rm = shutil.which("rm") or "/bin/rm"

        # Case A: Synchronous Gate 3 refusal with failing rm on $data
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                "  echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=None)
            rm_fail = paths["shim_dir"] / "rm-fail-data"
            rm_fail.write_text(
                f"#!/bin/sh\n"
                'for a in "$@"; do case "$a" in */host_specific.json) exit 1 ;; esac; done\n'
                f'exec {real_rm} "$@"\n',
                encoding="utf-8",
            )
            rm_fail.chmod(0o755)
            r = self._run_put_data(paths, DARWIN_CANARY_PRESENT, rm_override=str(rm_fail))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("rollback could not remove unverified data at", r.stderr)
            self.assertIn(str(paths["data"]), r.stderr)
            self.assertNotIn("new data removed", r.stderr)
            self.assertTrue(paths["data"].exists())

        # Case B: EXIT-trap SIGTERM during Gate 3 with failing rm on $data
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live_wd = root / "opt" / "tendcf" / "var" / "libntech"
            gate3_ready = root / "gate3.ready"
            cf_script = (
                "#!/bin/sh\n"
                'wd=""\n'
                'while [ $# -gt 0 ]; do\n'
                '  if [ "$1" = "--workdir" ]; then wd="$2"; shift 2; else shift; fi\n'
                'done\n'
                f'if [ "$wd" = "{live_wd}" ]; then\n'
                f'  echo ready > "{gate3_ready}"\n'
                "  sleep 10\n"
                "fi\n"
                "echo 'tendcf_cmdb_evaluated   source=promise'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=None)
            rm_fail = paths["shim_dir"] / "rm-fail-data"
            rm_fail.write_text(
                f"#!/bin/sh\n"
                'for a in "$@"; do case "$a" in */host_specific.json) exit 1 ;; esac; done\n'
                f'exec {real_rm} "$@"\n',
                encoding="utf-8",
            )
            rm_fail.chmod(0o755)
            script = self._put_data_script(paths, DARWIN_CANARY_PRESENT, rm_override=str(rm_fail))
            proc = subprocess.Popen(
                ["/bin/bash", "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = time.monotonic() + 10.0
            while not gate3_ready.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(gate3_ready.exists(), "Gate 3 cf-promises never started")
            os.killpg(proc.pid, signal.SIGTERM)
            _out, err = proc.communicate(timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("ERROR: rollback could not remove unverified data at", err)
            self.assertIn(str(paths["data"]), err)
            self.assertNotIn("removed unverified first-time data", err)
            self.assertTrue(paths["data"].exists())

    def test_verify_macho_tree_python_fallback_uses_isolated_no_site_hermetically(self) -> None:
        """R3 Fix #5 (Codex #7): exercise verify_macho_tree's no-otool python3 -I -S - path hermetically."""
        def _build_macho64(dylinker: str, dylibs: list[str]) -> bytes:
            cmds = bytearray()
            # LC_LOAD_DYLINKER (0x0E): cmd, cmdsize, name_offset(12), NUL-padded string (8-byte aligned)
            dl_raw = dylinker.encode("utf-8") + b"\x00"
            dl_sz = (12 + len(dl_raw) + 7) & ~7
            cmds += struct.pack("<III", 0x0E, dl_sz, 12) + dl_raw.ljust(dl_sz - 12, b"\x00")
            # LC_LOAD_DYLIB (0x0C): cmd, cmdsize, name_offset(24), timestamp, cur_ver, compat_ver, NUL-padded string
            for dep in dylibs:
                dep_raw = dep.encode("utf-8") + b"\x00"
                dep_sz = (24 + len(dep_raw) + 7) & ~7
                cmds += struct.pack("<IIIIII", 0x0C, dep_sz, 24, 2, 0x10000, 0x10000) + dep_raw.ljust(dep_sz - 24, b"\x00")
            header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1 + len(dylibs), len(cmds), 0, 0)
            return header + bytes(cmds)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            shim_dir = root / "shims"
            shim_dir.mkdir()
            _make_darwin_shims(shim_dir)
            stage_dir = root / "stage"
            stage_dir.mkdir(mode=0o700)

            file_shim = shim_dir / "file"
            file_shim.write_text("#!/bin/sh\necho 'Mach-O 64-bit executable arm64'\n", encoding="utf-8")
            file_shim.chmod(0o755)
            codesign_shim = shim_dir / "codesign"
            codesign_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            codesign_shim.chmod(0o755)

            py_log = root / "py-args.log"
            py_wrap = shim_dir / "py-wrap"
            py_wrap.write_text(
                f"#!/bin/sh\necho \"$*\" > \"{py_log}\"\nexec \"{sys.executable}\" \"$@\"\n",
                encoding="utf-8",
            )
            py_wrap.chmod(0o755)

            vm_fn = self._darwin_funcs(shim_dir, ("verify_macho_tree",))
            real_find = shutil.which("find") or "/usr/bin/find"
            real_grep = shutil.which("grep") or "/usr/bin/grep"
            vm_fn = (
                vm_fn.replace("/usr/bin/file", str(file_shim))
                .replace("/usr/bin/codesign", str(codesign_shim))
                .replace("/usr/bin/find", real_find)
                .replace("/usr/bin/grep", real_grep)
            )

            tree = root / "tree"
            (tree / "bin").mkdir(parents=True)
            valid_macho = _build_macho64("/usr/lib/dyld", ["/usr/lib/libSystem.B.dylib"])
            for req in ("cf-agent", "cf-promises", "cf-key", "cf-execd"):
                p = tree / "bin" / req
                p.write_bytes(valid_macho)
                p.chmod(0o755)

            def run_vm() -> subprocess.CompletedProcess[str]:
                script = (
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "make_stage() { return 0; }\n"
                    "find_safe_otool() { return 1; }\n"
                    f'find_real_python() {{ echo "{py_wrap}"; }}\n'
                    'prefix="/opt/tendcf"\n'
                    f'stage_dir="{stage_dir}"\n'
                    f"{vm_fn}\n"
                    f'verify_macho_tree "{tree}"\n'
                )
                return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)

            # 1. Valid synthetic Mach-O tree passes via python3 -I -S -
            r_ok = run_vm()
            self.assertEqual(r_ok.returncode, 0, r_ok.stderr)
            self.assertTrue(py_log.read_text(encoding="utf-8").startswith("-I -S - "), py_log.read_text(encoding="utf-8"))

            # 2. Forbidden external dylib is rejected by the python3 -I -S - parser
            (tree / "bin" / "cf-agent").write_bytes(
                _build_macho64("/usr/lib/dyld", ["/tmp/evil.dylib"])
            )
            r_bad = run_vm()
            self.assertNotEqual(r_bad.returncode, 0)
            self.assertIn("outside /opt/tendcf", r_bad.stderr)

    def test_no_augments_on_cf_agent_entrypoints_only(self) -> None:
        """Issue #59: Darwin cf-agent invocations pass --no-augments; cf-promises does not."""
        place_fn = _extract_func(self.src, "place_policy")
        self.assertIn(
            'exec_command => "$(sys.cf_agent) --no-augments -f $(sys.inputdir)/promises.cf";',
            place_fn,
        )
        run_once_fn = _extract_func(self.src, "cmd_run_once")
        self.assertIn('"$cf_agent" --no-augments -K -I -f "$entry"', run_once_fn)

        # cf-promises does not support --no-augments; confirm none of its calls pass it.
        for fn_name in ("validate_cmdb_workdir", "init_paths", "try_init_paths"):
            self.assertNotIn("--no-augments", _extract_func(self.src, fn_name))

        # Hermetic behavioral check: cmd_run_once passes --no-augments to $cf_agent.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            args_log = root / "cf-agent.args"
            fake_agent = root / "cf-agent"
            fake_agent.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{args_log}\"\nexit 0\n",
                encoding="utf-8",
            )
            fake_agent.chmod(0o755)
            entry = root / "promises.cf"
            entry.write_text("bundle agent main {}\n", encoding="utf-8")
            data = root / "host_specific.json"
            data.write_text('{"vars":{}}\n', encoding="utf-8")
            script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                f'cf_agent="{fake_agent}"\n'
                f'entry="{entry}"\n'
                f'data="{data}"\n'
                f"{run_once_fn}\n"
                "cmd_run_once\n"
            )
            r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            argv = args_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(argv, ["--no-augments", "-K", "-I", "-f", str(entry)])


class DarwinAuditShipperAndTripwireContract(unittest.TestCase):
    """Issue #119 Slice 2: macOS audit shipper, osquery/eslogger tripwire rules, and uninstall."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.src = INSTALLER.read_text(encoding="utf-8")

    def test_cmd_install_orders_audit_log_and_tripwire_securely(self) -> None:
        cmd_fn = _extract_func(self.src, "cmd_install")
        self.assertIn("--audit-log-src)", cmd_fn)
        self.assertIn("--audit-log-sha256)", cmd_fn)
        order = [
            "acquire_publish_lock",
            "prepare_audit_log_source",
            "validate_existing_audit_state_before_repair",
            "detach_unsafe_installed_audit_log",
            "check_tree",
            "place_audit_log",
            "place_audit_shipper_state",
            "place_tripwire_rules",
        ]
        idxs = [cmd_fn.find(name) for name in order]
        for name, idx in zip(order, idxs):
            self.assertNotEqual(idx, -1, f"missing {name} in cmd_install")
        self.assertEqual(idxs, sorted(idxs))

        # M4: macOS osquery packs path must use /private/var/osquery/packs (not /var symlink).
        self.assertIn("osquery_packs_dir=/private/var/osquery/packs", self.src)
        self.assertNotIn("osquery_packs_dir=/var/osquery/packs", self.src)

        # H3: detach_unsafe_installed_audit_log checks parent chain BEFORE chflags/rm.
        da_fn = _extract_func(self.src, "detach_unsafe_installed_audit_log")
        self.assertLess(da_fn.find('check_dir_root_unwritable "$d"'), da_fn.find('/bin/rm -f "$installed_audit_log"'))

        # H4: install_tarball preserves etc/ and quiesces shipper; cleanup_stage restores etc/ & shipper.
        it_fn = _extract_func(self.src, "install_tarball")
        self.assertIn('upgrade_moved_etc=1', it_fn)
        self.assertIn('upgrade_shipper_was_loaded=1', it_fn)
        cs_fn = _extract_func(self.src, "cleanup_stage")
        self.assertIn('upgrade_moved_etc', cs_fn)
        self.assertIn('upgrade_shipper_was_loaded', cs_fn)

        # M1: standalone enable and disable serialize under acquire_publish_lock.
        self.assertIn("acquire_publish_lock", _extract_func(self.src, "cmd_enable"))
        self.assertIn("acquire_publish_lock", _extract_func(self.src, "cmd_disable"))

        pa_fn = _extract_func(self.src, "place_audit_log")
        pa_code = "\n".join(l for l in pa_fn.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("$audit_log_src", pa_code)
        self.assertNotIn("prepare_audit_log_source", pa_code)
        self.assertIn("$prepared_audit_log_file", pa_code)

        es_fn = _extract_func(self.src, "enable_audit_shipper")
        self.assertIn("find_real_python", es_fn)
        self.assertIn("render_shipper_plist", es_fn)
        self.assertIn("launchctl enable", es_fn)

    def test_hermetic_tripwire_plist_and_uninstall_lifecycle(self) -> None:
        import json as _json

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "opt" / "tendcf"
            workdir = prefix / "var" / "libntech"
            launchd_dir = root / "LaunchDaemons"
            osq_dir = root / "private" / "var" / "osquery" / "packs"
            (prefix / "share" / "tendcf" / "bin").mkdir(parents=True)
            (workdir / "inputs").mkdir(parents=True)
            (workdir / "data").mkdir(parents=True)
            (workdir / "outputs").mkdir(parents=True)
            launchd_dir.mkdir(parents=True)
            osq_dir.mkdir(parents=True)
            shutil.copy2(PROJECTOR, prefix / "share" / "tendcf" / "bin" / "projector.py")
            shutil.copy2(REPO / "tools" / "audit_log.py", prefix / "share" / "tendcf" / "bin" / "audit_log.py")

            fns = "\n".join(
                _extract_func(self.src, name)
                for name in (
                    "check_dir_root_unwritable",
                    "check_private_dir_exact",
                    "check_private_file_exact",
                    "validate_existing_audit_state_before_repair",
                    "place_audit_shipper_state",
                    "render_darwin_tripwire_osquery",
                    "render_darwin_tripwire_eslogger",
                    "install_managed_file_idempotent",
                    "place_tripwire_rules",
                    "render_shipper_plist",
                    "disable_audit_shipper",
                    "remove_managed_file_safe",
                    "purge_audit_spool_safe",
                    "cmd_uninstall",
                )
            )
            real_install = shutil.which("install") or "/usr/bin/install"
            install_shim = root / "install-shim"
            install_shim.write_text(
                f"#!{sys.executable}\n"
                "import os, sys\n"
                f"real = {real_install!r}\n"
                "args = [real]\n"
                "i = 1\n"
                "while i < len(sys.argv):\n"
                "    if sys.argv[i] in ('-o', '-g') and i + 1 < len(sys.argv):\n"
                "        i += 2\n"
                "    else:\n"
                "        args.append(sys.argv[i])\n"
                "        i += 1\n"
                "os.execv(real, args)\n",
                encoding="utf-8",
            )
            install_shim.chmod(0o755)
            stat_shim = root / "stat-shim"
            stat_shim.write_text(
                f"#!{sys.executable}\n"
                "import os, stat, sys\n"
                "fmt = sys.argv[2]\n"
                "p = sys.argv[3]\n"
                "st = os.lstat(p)\n"
                "mode = stat.S_IMODE(st.st_mode)\n"
                "if fmt == '%Su:%Sg %Lp': print(f'root:wheel {mode:o}')\n"
                "elif fmt == '%Su %Sg %Lp': print(f'root wheel {mode:o}')\n"
                "elif fmt == '%Su %Sg %Lp %l': print(f'root wheel {mode:o} {st.st_nlink}')\n"
                "elif fmt == '%d': print(f'{st.st_dev}')\n"
                "else: raise SystemExit(f'unexpected stat fmt: {fmt}')\n",
                encoding="utf-8",
            )
            stat_shim.chmod(0o755)
            noop_shim = root / "noop-shim"
            noop_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            noop_shim.chmod(0o755)
            plutil_bin = "/usr/bin/plutil" if Path("/usr/bin/plutil").exists() else str(noop_shim)

            fns_patched = (
                fns.replace("/usr/sbin/chown", str(noop_shim))
                .replace("/usr/bin/chflags", str(noop_shim))
                .replace("/usr/bin/install", str(install_shim))
                .replace("/usr/bin/stat", str(stat_shim))
                .replace("/usr/bin/plutil", plutil_bin)
                .replace("/bin/chmod -N", f"{noop_shim}")
                .replace("/bin/launchctl", str(noop_shim))
            )
            audit_cfg = prefix / "etc" / "tendcf-audit" / "audit-shipper.json"
            spool_dir = prefix / "var" / "audit-spool"
            trip_dir = prefix / "share" / "tendcf" / "tripwire"
            osq_pack = osq_dir / "tendcf-tripwire.conf"
            osq_conf_d_dir = root / "osquery_conf_d"
            osq_conf_d_dir.mkdir()
            osq_conf_d = osq_conf_d_dir / "99-tendcf-tripwire.conf"
            execd_plist = launchd_dir / "org.tendcf.execd.plist"
            shipper_plist = launchd_dir / "org.tendcf.audit-shipper.plist"
            execd_plist.write_text("<plist/>", encoding="utf-8")
            # Simulate packaged OpenSSL etc/ssl (mode 0755) from macos-fork-build.yml:
            # must coexist cleanly with private etc/tendcf-audit (0700).
            (prefix / "etc" / "ssl").mkdir(parents=True, mode=0o755)
            os.chmod(prefix / "etc", 0o755)
            os.chmod(prefix / "etc" / "ssl", 0o755)
            (prefix / "etc" / "ssl" / "openssl.cnf").write_text("# openssl\n", encoding="utf-8")

            env_setup = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                'say() { echo "tendcf-install: $*"; }\n'
                f'stage_dir="{root}/stage"\n'
                'mkdir -p "$stage_dir"\n'
                "make_stage() { :; }\n"
                "ensure_dir() { mkdir -p \"$2\"; chmod \"0$1\" \"$2\"; }\n"
                "has_acl_path() { return 1; }\n"
                "check_ancestors() { return 0; }\n"
                "check_ancestors_ok() { return 0; }\n"
                "check_ancestor_dir_ok() { return 0; }\n"
                "check_launchd_dir() { return 0; }\n"
                "acquire_publish_lock() { :; }\n"
                "release_publish_lock() { :; }\n"
                "execd_is_loaded() { return 1; }\n"
                "shipper_is_loaded() { return 1; }\n"
                "wait_execd_unloaded() { return 0; }\n"
                "wait_shipper_unloaded() { return 0; }\n"
                "changed=0\n"
                f'prefix="{prefix}"\n'
                f'workdir="{workdir}"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'launchd_dir="{launchd_dir}"\n'
                f'plist_path="{execd_plist}"\n'
                f'shipper_plist_path="{shipper_plist}"\n'
                f'installed_audit_log="{prefix}/share/tendcf/bin/audit_log.py"\n'
                f'audit_etc_dir="{prefix}/etc/tendcf-audit"\n'
                f'audit_shipper_cfg="{audit_cfg}"\n'
                f'audit_spool_dir="{spool_dir}"\n'
                f'tripwire_share_dir="{trip_dir}"\n'
                f'osquery_packs_dir="{osq_dir}"\n'
                f'osquery_pack_path="{osq_pack}"\n'
                f'osquery_conf_d_dir="{osq_conf_d_dir}"\n'
                f'osquery_conf_d_path="{osq_conf_d}"\n'
                f"{fns_patched}\n"
            )

            r = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    env_setup
                    + "validate_existing_audit_state_before_repair\n"
                    + "place_audit_shipper_state\n"
                    + "validate_existing_audit_state_before_repair\n"
                    + "place_tripwire_rules\n"
                    + f'render_shipper_plist "{shipper_plist}" "{sys.executable}"\n',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(audit_cfg.is_file())
            self.assertEqual(stat.S_IMODE(audit_cfg.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((prefix / "etc").stat().st_mode), 0o755, "packaged etc/ must stay 0755")
            self.assertTrue((prefix / "etc" / "ssl" / "openssl.cnf").is_file(), "packaged etc/ssl must remain intact")
            self.assertTrue(osq_conf_d.is_file(), "osquery.conf.d drop-in must register tripwire pack when osquery.conf.d exists")
            self.assertIn("tendcf_tripwire", osq_conf_d.read_text(encoding="utf-8"))
            self.assertIn("unverified until observed", r.stdout)
            # R8-M5: Verify osquery FIM pack watches parent dirs (not rename-replaced leaf files)
            # and SQL query filters shared dirs so unrelated files are excluded while atomic renames match.
            import sqlite3
            osq_pack_obj = _json.loads((trip_dir / "osquery-fim.conf").read_text(encoding="utf-8"))
            for cat, patterns in osq_pack_obj["file_paths"].items():
                for pat in patterns:
                    self.assertTrue(pat.endswith("/%") or pat.endswith("/%%"), f"R8-M5: {cat} watch {pat} must watch parent dir, not leaf file")
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE TABLE file_events (target_path TEXT, action TEXT, uid INT, gid INT, mode TEXT, sha256 TEXT, time INT)")
            conn.executemany(
                "INSERT INTO file_events VALUES (?, ?, 0, 0, '0600', 'abc', 1)",
                [
                    (f"{workdir}/data/host_specific.json", "UPDATED"),
                    (f"{audit_cfg}", "UPDATED"),
                    (str(shipper_plist), "UPDATED"),
                    ("/Library/LaunchDaemons/com.apple.unrelated.plist", "UPDATED"),
                    ("/private/etc/hosts", "UPDATED"),
                    ("/private/etc/sudoers", "UPDATED"),
                    ("/private/etc/sudoers.d/local", "CREATED"),
                    ("/var/root/.ssh/authorized_keys", "UPDATED"),
                ],
            )
            # Map each event row with its category column to test the exact rendered SQL query.
            conn.execute("ALTER TABLE file_events ADD COLUMN category TEXT")
            conn.execute("UPDATE file_events SET category='tendcf_policy_and_data' WHERE target_path LIKE ?", (f"{prefix}/%",))
            conn.execute("UPDATE file_events SET category='tendcf_launchd_and_trust' WHERE category IS NULL")
            sql_q = osq_pack_obj["queries"]["tendcf_file_events"]["query"]
            matched = {row[0] for row in conn.execute(sql_q).fetchall()}
            conn.close()
            self.assertIn(f"{workdir}/data/host_specific.json", matched)
            self.assertIn(str(audit_cfg), matched)
            self.assertIn(str(shipper_plist), matched)
            self.assertIn("/private/etc/sudoers", matched)
            self.assertIn("/private/etc/sudoers.d/local", matched)
            self.assertIn("/var/root/.ssh/authorized_keys", matched)
            self.assertNotIn("/Library/LaunchDaemons/com.apple.unrelated.plist", matched)
            self.assertNotIn("/private/etc/hosts", matched)

            # R8-M4: Legacy $prefix/etc/audit-shipper.json refused before mutation (both-present & legacy-only), preserving originals.
            legacy_cfg = prefix / "etc" / "audit-shipper.json"
            legacy_cfg.write_text('{"enabled":true,"legacy":1}\n', encoding="utf-8")
            os.chmod(legacy_cfg, 0o600)
            r_leg_both = subprocess.run(
                ["/bin/bash", "-c", env_setup + "validate_existing_audit_state_before_repair\n"],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(r_leg_both.returncode, 0, "R8-M4: legacy+new config must refuse")
            self.assertIn("legacy audit shipper config", r_leg_both.stderr)
            self.assertEqual(legacy_cfg.read_text(encoding="utf-8"), '{"enabled":true,"legacy":1}\n')
            audit_cfg_bak = audit_cfg.read_text(encoding="utf-8")
            audit_cfg.unlink()
            r_leg_only = subprocess.run(
                ["/bin/bash", "-c", env_setup + "place_audit_shipper_state\n"],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(r_leg_only.returncode, 0, "R8-M4: legacy-only config must refuse before writing default")
            self.assertFalse(audit_cfg.exists())
            self.assertEqual(legacy_cfg.read_text(encoding="utf-8"), '{"enabled":true,"legacy":1}\n')
            legacy_cfg.unlink()
            audit_cfg.write_text(audit_cfg_bak, encoding="utf-8")
            os.chmod(audit_cfg, 0o600)
            # When osquery.conf.d is absent, explicitly report staged-only status.
            r_staged = subprocess.run(
                ["/bin/bash", "-c", env_setup + f'osquery_conf_d_dir="{root}/no-conf-d"\nplace_tripwire_rules\n'],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(r_staged.returncode, 0, r_staged.stderr)
            self.assertIn("staged only", r_staged.stdout)
            self.assertTrue(shipper_plist.is_file())
            self.assertIn("--expected-spool-dir", shipper_plist.read_text(encoding="utf-8"))
            osq_obj = _json.loads((trip_dir / "osquery-fim.conf").read_text(encoding="utf-8"))
            self.assertIn("tendcf_file_events", osq_obj["queries"])
            self.assertEqual(osq_pack.read_text(encoding="utf-8"), (trip_dir / "osquery-fim.conf").read_text(encoding="utf-8"))
            es_obj = _json.loads((trip_dir / "eslogger-events.json").read_text(encoding="utf-8"))
            self.assertIn("unlink", es_obj["events"])
            self.assertIn(str(shipper_plist), es_obj["watched_paths"])

            # Verify idempotent re-run reports changed=0.
            r_idem = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    env_setup + 'changed=0\nplace_audit_shipper_state\nplace_tripwire_rules\necho "CHANGED=$changed"\n',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_idem.returncode, 0, r_idem.stderr)
            self.assertIn("CHANGED=0", r_idem.stdout)

            # H1: Dirty config (0644) fails validate_existing_audit_state_before_repair.
            os.chmod(audit_cfg, 0o644)
            r_dirty = subprocess.run(
                ["/bin/bash", "-c", env_setup + "validate_existing_audit_state_before_repair\n"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_dirty.returncode, 0)
            os.chmod(audit_cfg, 0o600)

            # H5/M1/M2: First verify empty spool purges cleanly under macOS /bin/bash 3.2 (set -u).
            r_empty = subprocess.run(
                ["/bin/bash", "-c", env_setup + "purge_audit_spool_safe\n"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_empty.returncode, 0, r_empty.stderr)
            self.assertFalse(spool_dir.exists())
            spool_dir.mkdir(mode=0o700)
            os.chmod(spool_dir, 0o700)

            # Populate spool with REAL AuditSpool (audit.jsonl, cursor.json, .spool.lock).
            unrelated_trip = trip_dir / "operator-custom.conf"
            unrelated_trip.write_text("keep me\n", encoding="utf-8")
            p_emit = subprocess.run(
                [
                    sys.executable, "-I", "-S",
                    str(prefix / "share" / "tendcf" / "bin" / "audit_log.py"),
                    "emit", "--spool-dir", str(spool_dir),
                    "--host", "macbook", "--src", "cf-agent", "--boot-id", "boot-1",
                    "--type", "heartbeat",
                    "--data-json",
                    '{"running_release":"release-1.0.0","goal_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111","projection_sha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222","converged":true,"unshipped_count":0}',
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_emit.returncode, 0, p_emit.stderr)
            self.assertTrue((spool_dir / "audit.jsonl").is_file())
            self.assertTrue((spool_dir / "cursor.json").is_file())
            self.assertTrue((spool_dir / ".spool.lock").is_file())
            r_un = subprocess.run(
                ["/bin/bash", "-c", env_setup + "cmd_uninstall\n"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_un.returncode, 0, r_un.stderr)
            for gone in (execd_plist, shipper_plist, osq_pack, osq_conf_d, audit_cfg, prefix / "share" / "tendcf" / "bin" / "audit_log.py"):
                self.assertFalse(gone.exists(), f"uninstall left {gone} behind")
            self.assertTrue(unrelated_trip.is_file(), "H5: unrelated file under tripwire/ must survive uninstall")
            self.assertTrue((spool_dir / "audit.jsonl").is_file())

            rogue_spool = spool_dir / "operator-notes.txt"
            rogue_spool.write_text("do not delete\n", encoding="utf-8")
            r_refuse = subprocess.run(
                ["/bin/bash", "-c", env_setup + "cmd_uninstall --purge-spool\n"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_refuse.returncode, 0)
            self.assertTrue(rogue_spool.is_file())
            rogue_spool.unlink()

            # Uninstall with --purge-spool removes real AuditSpool files & rmdir cleanly and re-run reports no change.
            r_purge = subprocess.run(
                ["/bin/bash", "-c", env_setup + "cmd_uninstall --purge-spool\nchanged=0\ncmd_uninstall --purge-spool\n"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_purge.returncode, 0, r_purge.stderr)
            self.assertFalse(spool_dir.exists())
            self.assertIn("no change (already uninstalled)", r_purge.stdout)

    def test_h4_cleanup_stage_restores_moved_etc_and_shipper_on_failed_upgrade(self) -> None:
        # H2/H4/M3: interrupted upgrade restores moved var/ & etc/ (even if interrupted before flag set),
        # restores ORIGINAL overwritten shipper plist bytes before re-bootstrapping, and retains stage_dir
        # if restoration fails.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "opt" / "tendcf"
            backup = root / "opt" / "tendcf.old.999"
            stage = root / "stage"
            staged_tree = stage / "extract" / "tendcf"
            (staged_tree / "etc" / "tendcf-audit").mkdir(parents=True)
            (staged_tree / "var" / "audit-spool").mkdir(parents=True)
            backup.mkdir(parents=True)
            enrolled = '{"enabled":true,"host":"macbook","spool_dir":"/opt/tendcf/var/audit-spool","src":"tendcf"}\n'
            (staged_tree / "etc" / "tendcf-audit" / "audit-shipper.json").write_text(enrolled, encoding="utf-8")
            (staged_tree / "var" / "audit-spool" / "audit.jsonl").write_text("rec1\n", encoding="utf-8")
            (staged_tree / "var" / "audit-spool" / "cursor.json").write_text('{"acked_seq":0}\n', encoding="utf-8")

            # M3: Save ORIGINAL shipper plist in stage_dir, then overwrite live shipper_plist with NEW content!
            old_plist = "<plist><string>OLD_V1_SHIPPER</string></plist>\n"
            new_plist = "<plist><string>NEW_V2_BROKEN_SHIPPER</string></plist>\n"
            saved_plist = stage / "upgrade-shipper.plist.prev"
            saved_plist.write_text(old_plist, encoding="utf-8")
            shipper_plist = root / "org.tendcf.audit-shipper.plist"
            shipper_plist.write_text(new_plist, encoding="utf-8")
            log_file = root / "actions.log"

            cs_fn = _extract_func(self.src, "cleanup_stage")
            # Simulate TERM arriving AFTER mv backup_prefix/{var,etc} -> staged_tree/{var,etc}
            # with upgrade_had_var=1, upgrade_had_etc=1 and upgrade_moved_var/etc=0 (H2/M2).
            script = (
                "set -euo pipefail\n"
                f'prefix="{prefix}"\n'
                f'upgrade_backup_prefix="{backup}"\n'
                f'upgrade_staged_tree="{staged_tree}"\n'
                'upgrade_rollback_armed=1\n'
                'upgrade_had_var=1\n'
                'upgrade_had_etc=1\n'
                'upgrade_moved_var=0\n'
                'upgrade_moved_etc=0\n'
                'upgrade_was_loaded=0\n'
                'upgrade_had_plist=0\n'
                'upgrade_shipper_was_loaded=1\n'
                'upgrade_touched_shipper=1\n'
                'upgrade_shipper_prior_disabled="enabled"\n'
                'upgrade_had_shipper_plist=1\n'
                f'upgrade_saved_shipper_plist="{saved_plist}"\n'
                'upgrade_snapshot_taken=0\n'
                'upgrade_saved_workdir=""\n'
                'upgrade_saved_inputs=0\n'
                'upgrade_saved_data=0\n'
                f'plist_path="{root}/execd.plist"\n'
                f'shipper_plist_path="{shipper_plist}"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'stage_dir="{stage}"\n'
                'publish_lock_held=0\n'
                'put_data_rollback_armed=0\n'
                'execd_is_loaded() { return 1; }\n'
                'shipper_is_loaded() { return 1; }\n'
                f'bootstrap_shipper_with_retry() {{ cat "{shipper_plist}" >> "{log_file}"; return 0; }}\n'
                f"{cs_fn}\n"
                "cleanup_stage\n"
            )
            r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((prefix / "etc" / "tendcf-audit" / "audit-shipper.json").read_text(encoding="utf-8"), enrolled)
            self.assertEqual((prefix / "var" / "audit-spool" / "audit.jsonl").read_text(encoding="utf-8"), "rec1\n")
            self.assertEqual(shipper_plist.read_text(encoding="utf-8"), old_plist, "M3: original shipper plist contents must be restored")
            self.assertIn("OLD_V1_SHIPPER", log_file.read_text(encoding="utf-8"), "M3: bootstrap must run AFTER old plist is restored")

            # H2: Verify stage_dir is RETAINED when moving var/ back from staging fails.
            stage2 = root / "stage2"
            st2 = stage2 / "extract" / "tendcf"
            (st2 / "var").mkdir(parents=True)
            (st2 / "var" / "keep.txt").write_text("precious\n", encoding="utf-8")
            backup2 = root / "opt" / "tendcf2.old"
            backup2.mkdir(parents=True)
            os.chmod(backup2, 0o500)  # make backup2 unwritable so mv back fails!
            try:
                script2 = (
                    "set -euo pipefail\n"
                    f'prefix="{root}/opt/tendcf2"\n'
                    f'upgrade_backup_prefix="{backup2}"\n'
                    f'upgrade_staged_tree="{st2}"\n'
                    'upgrade_rollback_armed=1\n'
                    'upgrade_had_var=1\n'
                    'upgrade_had_etc=0\n'
                    'upgrade_moved_var=1\n'
                    'upgrade_moved_etc=0\n'
                    'upgrade_was_loaded=0\n'
                    'upgrade_had_plist=0\n'
                    'upgrade_shipper_was_loaded=0\n'
                    'upgrade_shipper_prior_disabled="enabled"\n'
                    'upgrade_had_shipper_plist=0\n'
                    'upgrade_saved_shipper_plist=""\n'
                    'upgrade_snapshot_taken=0\n'
                    'upgrade_saved_workdir=""\n'
                    'upgrade_saved_inputs=0\n'
                    'upgrade_saved_data=0\n'
                    f'plist_path="{root}/execd2.plist"\n'
                    f'shipper_plist_path="{root}/shipper2.plist"\n'
                    'label="org.tendcf.execd"\n'
                    'shipper_label="org.tendcf.audit-shipper"\n'
                    f'stage_dir="{stage2}"\n'
                    'publish_lock_held=0\n'
                    'put_data_rollback_armed=0\n'
                    'execd_is_loaded() { return 1; }\n'
                    'shipper_is_loaded() { return 1; }\n'
                    f"{cs_fn}\n"
                    "cleanup_stage\n"
                )
                r2 = subprocess.run(["/bin/bash", "-c", script2], capture_output=True, text=True, check=False)
                self.assertEqual(r2.returncode, 0, r2.stderr)
                self.assertTrue((st2 / "var" / "keep.txt").is_file(), "H2: stage_dir must be retained when var/ restoration fails!")
            finally:
                for p_fix in (backup2, root / "opt" / "tendcf2"):
                    if p_fix.exists():
                        os.chmod(p_fix, 0o700)

            # M2: Interruption immediately after first prefix rename with originally ABSENT etc/:
            # must restore original prefix WITHOUT copying staged_tree/etc into it.
            stage3 = root / "stage3"
            st3 = stage3 / "extract" / "tendcf"
            (st3 / "etc").mkdir(parents=True)
            (st3 / "etc" / "from-new-tarball.json").write_text("new\n", encoding="utf-8")
            backup3 = root / "opt" / "tendcf3.old"
            (backup3 / "var").mkdir(parents=True)
            (backup3 / "var" / "orig.txt").write_text("orig\n", encoding="utf-8")
            prefix3 = root / "opt" / "tendcf3"
            script3 = (
                "set -euo pipefail\n"
                f'prefix="{prefix3}"\n'
                f'upgrade_backup_prefix="{backup3}"\n'
                f'upgrade_staged_tree="{st3}"\n'
                'upgrade_rollback_armed=1\n'
                'upgrade_had_var=1\n'
                'upgrade_had_etc=0\n'
                'upgrade_moved_var=0\n'
                'upgrade_moved_etc=0\n'
                'upgrade_was_loaded=0\n'
                'upgrade_had_plist=0\n'
                'upgrade_shipper_was_loaded=0\n'
                'upgrade_shipper_prior_disabled="enabled"\n'
                'upgrade_had_shipper_plist=0\n'
                'upgrade_saved_shipper_plist=""\n'
                'upgrade_snapshot_taken=0\n'
                'upgrade_saved_workdir=""\n'
                'upgrade_saved_inputs=0\n'
                'upgrade_saved_data=0\n'
                f'plist_path="{root}/execd3.plist"\n'
                f'shipper_plist_path="{root}/shipper3.plist"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'stage_dir="{stage3}"\n'
                'publish_lock_held=0\n'
                'put_data_rollback_armed=0\n'
                'execd_is_loaded() { return 1; }\n'
                'shipper_is_loaded() { return 1; }\n'
                f"{cs_fn}\n"
                "cleanup_stage\n"
            )
            r3 = subprocess.run(["/bin/bash", "-c", script3], capture_output=True, text=True, check=False)
            self.assertEqual(r3.returncode, 0, r3.stderr)
            self.assertEqual((prefix3 / "var" / "orig.txt").read_text(encoding="utf-8"), "orig\n")
            self.assertFalse((prefix3 / "etc").exists(), "M2: staged_tree/etc must NOT be copied into prefix that originally lacked etc/")

            # M3: Disabled override with ABSENT plist calls launchctl disable (and preserves stage_dir on failure).
            lc_shim = root / "fake_launchctl"
            lc_log = root / "lc_m3.log"
            lc_shim.write_text(
                f"#!/bin/sh\necho \"$*\" >> '{lc_log}'\nexit 0\n",
                encoding="utf-8",
            )
            lc_shim.chmod(0o755)
            cs_patched = cs_fn.replace("/bin/launchctl", str(lc_shim))
            new_plist4 = root / "shipper4.plist"
            new_plist4.write_text("<plist/>", encoding="utf-8")
            stage4 = root / "stage4"
            stage4.mkdir()
            script4 = (
                "set -euo pipefail\n"
                f'prefix="{root}/opt/tendcf4"\n'
                'upgrade_backup_prefix=""\n'
                'upgrade_staged_tree=""\n'
                'upgrade_rollback_armed=1\n'
                'upgrade_had_var=0\n'
                'upgrade_had_etc=0\n'
                'upgrade_moved_var=0\n'
                'upgrade_moved_etc=0\n'
                'upgrade_was_loaded=0\n'
                'upgrade_had_plist=0\n'
                'upgrade_shipper_was_loaded=0\n'
                'upgrade_touched_shipper=1\n'
                'upgrade_shipper_prior_disabled="disabled"\n'
                'upgrade_had_shipper_plist=0\n'
                'upgrade_saved_shipper_plist=""\n'
                'upgrade_snapshot_taken=0\n'
                'upgrade_saved_workdir=""\n'
                'upgrade_saved_inputs=0\n'
                'upgrade_saved_data=0\n'
                f'plist_path="{root}/execd4.plist"\n'
                f'shipper_plist_path="{new_plist4}"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'stage_dir="{stage4}"\n'
                'publish_lock_held=0\n'
                'put_data_rollback_armed=0\n'
                'execd_is_loaded() { return 1; }\n'
                'shipper_is_loaded() { return 1; }\n'
                f"{cs_patched}\n"
                "cleanup_stage\n"
            )
            r4 = subprocess.run(["/bin/bash", "-c", script4], capture_output=True, text=True, check=False)
            self.assertEqual(r4.returncode, 0, r4.stderr)
            self.assertFalse(new_plist4.exists())
            self.assertIn("disable system/org.tendcf.audit-shipper", lc_log.read_text(encoding="utf-8"))

            # Failed launchctl disable during rollback retains stage_dir and reports incomplete rollback.
            lc_shim.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stage5 = root / "stage5"
            stage5.mkdir()
            r5 = subprocess.run(
                ["/bin/bash", "-c", script4.replace(str(stage4), str(stage5))],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r5.returncode, 0, r5.stderr)
            self.assertTrue(stage5.is_dir(), "M3: failed disabled-state restoration must preserve stage_dir")
            self.assertIn("incomplete", r5.stderr)

            # H1: Unsafe pre-existing shipper plist (world-writable 0666) is refused BEFORE any launchctl call.
            # Use a portable BSD-stat shim so this test passes identically on Linux CI and macOS.
            bsd_stat_shim = root / "bsd_stat_shim"
            bsd_stat_shim.write_text(
                f"#!{sys.executable}\n"
                "import os, stat, sys\n"
                "st = os.lstat(sys.argv[-1])\n"
                "print(f'root wheel {stat.S_IMODE(st.st_mode):o} {st.st_nlink}')\n",
                encoding="utf-8",
            )
            bsd_stat_shim.chmod(0o755)
            no_xattr = root / "no_xattr"
            no_xattr.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            no_xattr.chmod(0o755)
            unsafe_plist = root / "unsafe_shipper.plist"
            unsafe_plist.write_text("<plist>UNTRUSTED</plist>\n", encoding="utf-8")
            os.chmod(unsafe_plist, 0o666)
            lc_h1_log = root / "lc_h1.log"
            lc_h1 = root / "lc_h1"
            lc_h1.write_text(f"#!/bin/sh\necho \"$*\" >> '{lc_h1_log}'\nexit 0\n", encoding="utf-8")
            lc_h1.chmod(0o755)
            fn_h1 = (
                _extract_func(self.src, "validate_existing_launchd_plist_trusted")
                + "\n"
                + _extract_func(self.src, "enable_audit_shipper")
            ).replace("/bin/launchctl", str(lc_h1)).replace("/usr/bin/stat", str(bsd_stat_shim)).replace("/usr/bin/xattr", str(no_xattr))
            inst_al = root / "audit_log.py"
            inst_al.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            r_h1 = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    "check_launchd_dir() { return 0; }\n"
                    "has_acl_path() { return 1; }\n"
                    f'installed_audit_log="{inst_al}"\n'
                    f'shipper_plist_path="{unsafe_plist}"\n'
                    'shipper_label="org.tendcf.audit-shipper"\n'
                    f"{fn_h1}\n"
                    "enable_audit_shipper\n",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(r_h1.returncode, 0, "H1: unsafe 0666 pre-existing plist must be refused")
            self.assertIn("untrusted metadata", r_h1.stderr)
            self.assertFalse(lc_h1_log.exists(), "H1: zero launchctl calls permitted on unsafe pre-existing plist")

            # H2: cmd_enable preflights BOTH existing plists before mutating EITHER execd or shipper.
            good_execd = root / "good_execd.plist"
            good_execd.write_text("<plist>GOOD</plist>\n", encoding="utf-8")
            os.chmod(good_execd, 0o644)
            bad_execd = root / "bad_execd.plist"
            bad_execd.write_text("<plist>BAD</plist>\n", encoding="utf-8")
            os.chmod(bad_execd, 0o666)
            good_ship = root / "good_ship.plist"
            good_ship.write_text("<plist>GOOD</plist>\n", encoding="utf-8")
            os.chmod(good_ship, 0o644)
            fn_h2 = "\n".join(
                _extract_func(self.src, n)
                for n in (
                    "validate_existing_launchd_plist_trusted",
                    "preflight_existing_launchd_plists",
                    "cmd_enable",
                )
            ).replace("/usr/bin/stat", str(bsd_stat_shim)).replace("/usr/bin/xattr", str(no_xattr))
            mut_log = root / "h2_mut.log"
            for case_name, ep, sp in (
                ("unsafe-execd", bad_execd, good_ship),
                ("unsafe-shipper", good_execd, unsafe_plist),
            ):
                if mut_log.exists():
                    mut_log.unlink()
                r_h2 = subprocess.run(
                    [
                        "/bin/bash", "-c",
                        "set -euo pipefail\n"
                        'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                        'say() { :; }\n'
                        "acquire_publish_lock() { return 0; }\n"
                        "release_publish_lock() { return 0; }\n"
                        "init_paths() { return 0; }\n"
                        "check_launchd_dir() { return 0; }\n"
                        "has_acl_path() { return 1; }\n"
                        f'enable_execd() {{ echo "execd" >> "{mut_log}"; }}\n'
                        f'enable_audit_shipper() {{ echo "shipper" >> "{mut_log}"; }}\n'
                        f'plist_path="{ep}"\n'
                        f'shipper_plist_path="{sp}"\n'
                        'label="org.tendcf.execd"\n'
                        'changed=0\n'
                        f"{fn_h2}\n"
                        "cmd_enable\n",
                    ],
                    capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(r_h2.returncode, 0, f"H2: cmd_enable must refuse {case_name}")
                self.assertFalse(mut_log.exists(), f"H2: zero daemon mutations allowed for {case_name}")

            # M1 (1): literal label matching in launchd_print_disabled_matches_label rejects unescaped dot spoof.
            fn_lbl = _extract_func(self.src, "launchd_print_disabled_matches_label")
            spoof_out = '\t"orgXtendcfXaudit-shipper" => disabled\n'
            real_out = '\t"org.tendcf.audit-shipper" => disabled\n'
            r_spoof = subprocess.run(
                ["/bin/bash", "-c", f"set -euo pipefail\n{fn_lbl}\nlaunchd_print_disabled_matches_label 'org.tendcf.audit-shipper'\n"],
                input=spoof_out, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(r_spoof.returncode, 0, "M1: unescaped dot spoof label must NOT match")
            r_real = subprocess.run(
                ["/bin/bash", "-c", f"set -euo pipefail\n{fn_lbl}\nlaunchd_print_disabled_matches_label 'org.tendcf.audit-shipper'\n"],
                input=real_out, capture_output=True, text=True, check=False,
            )
            self.assertEqual(r_real.returncode, 0, "M1: exact literal label must match")

            # M1 (2): Both execd and shipper previously loaded; execd stops cleanly but shipper fails bootout:
            # prefix must NOT be swapped, live shipper plist bytes must remain UNCHANGED, ZERO bootstraps
            # (including execd!) may run against the replacement tree, stage_dir preserved, incomplete reported.
            stage6 = root / "stage6"
            stage6.mkdir()
            saved6 = stage6 / "upgrade-shipper.plist.prev"
            saved6.write_text("<plist>OLD_V1</plist>\n", encoding="utf-8")
            live_plist6 = root / "shipper6.plist"
            live_plist6.write_text("<plist>NEW_V2_RUNNING</plist>\n", encoding="utf-8")
            execd_plist6 = root / "execd6.plist"
            execd_plist6.write_text("<plist>EXECD</plist>\n", encoding="utf-8")
            bs_log6 = root / "bs6.log"
            prefix6 = root / "opt" / "tendcf6"
            prefix6.mkdir(parents=True)
            (prefix6 / "marker").write_text("new-tree\n", encoding="utf-8")
            backup6 = root / "opt" / "tendcf6.old"
            backup6.mkdir(parents=True)
            (backup6 / "marker").write_text("old-tree\n", encoding="utf-8")
            script6 = (
                "set -euo pipefail\n"
                f'prefix="{prefix6}"\n'
                f'upgrade_backup_prefix="{backup6}"\n'
                'upgrade_staged_tree=""\n'
                'upgrade_rollback_armed=1\n'
                'upgrade_had_var=0\n'
                'upgrade_had_etc=0\n'
                'upgrade_moved_var=0\n'
                'upgrade_moved_etc=0\n'
                'upgrade_was_loaded=1\n'
                'upgrade_had_plist=1\n'
                'upgrade_shipper_was_loaded=1\n'
                'upgrade_touched_shipper=1\n'
                'upgrade_shipper_prior_disabled="enabled"\n'
                'upgrade_had_shipper_plist=1\n'
                f'upgrade_saved_shipper_plist="{saved6}"\n'
                'upgrade_snapshot_taken=0\n'
                'upgrade_saved_workdir=""\n'
                'upgrade_saved_inputs=0\n'
                'upgrade_saved_data=0\n'
                f'plist_path="{execd_plist6}"\n'
                f'shipper_plist_path="{live_plist6}"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'stage_dir="{stage6}"\n'
                'publish_lock_held=0\n'
                'put_data_rollback_armed=0\n'
                'execd_loaded=1\n'
                'execd_is_loaded() { [ "$execd_loaded" -eq 1 ]; }\n'
                'bootout_execd() { execd_loaded=0; return 0; }\n'
                'wait_execd_unloaded() { return 0; }\n'
                'shipper_is_loaded() { return 0; }\n'
                'bootout_shipper() { return 1; }\n'
                'wait_shipper_unloaded() { return 1; }\n'
                f'bootstrap_execd_with_retry() {{ echo "execd" >> "{bs_log6}"; return 0; }}\n'
                f'bootstrap_shipper_with_retry() {{ echo "shipper" >> "{bs_log6}"; return 0; }}\n'
                f"{cs_fn}\n"
                "cleanup_stage\n"
            )
            r6 = subprocess.run(["/bin/bash", "-c", script6], capture_output=True, text=True, check=False)
            self.assertEqual(r6.returncode, 0, r6.stderr)
            self.assertTrue(stage6.is_dir(), "M1: failed bootout must preserve stage_dir")
            self.assertIn("incomplete", r6.stderr)
            self.assertFalse(bs_log6.exists(), "M1: ZERO bootstraps allowed when prefix rollback could not proceed")
            self.assertEqual(live_plist6.read_text(encoding="utf-8"), "<plist>NEW_V2_RUNNING</plist>\n", "M1: live plist must remain unchanged when rollback cannot proceed")
            self.assertEqual((prefix6 / "marker").read_text(encoding="utf-8"), "new-tree\n", "M1: must not swap prefix under running unquiesced job")
            self.assertEqual((backup6 / "marker").read_text(encoding="utf-8"), "old-tree\n", "M1: backup prefix must remain intact for recovery")

            # R6-M1 & R7-N1: Successful prefix rename, but workdir host_specific.json snapshot restore fails
            # (forced via a failing /bin/cp stub so test is UID-independent even under root):
            # saved snapshot bytes MUST remain intact, ZERO bootstraps may run, and incomplete rollback reported.
            stage7 = root / "stage7"
            snap_dir7 = stage7 / "upgrade-var-backup"
            snap_dir7.mkdir(parents=True)
            saved_data7 = snap_dir7 / "host_specific.json"
            saved_data7.write_text('{"saved":"precious"}\n', encoding="utf-8")
            backup7 = root / "opt" / "tendcf7.old"
            wd7_data = backup7 / "var" / "libntech" / "data"
            wd7_data.mkdir(parents=True)
            prefix7 = root / "opt" / "tendcf7"
            bs_log7 = root / "bs7.log"
            fail_cp = root / "fail_cp"
            fail_cp.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            fail_cp.chmod(0o755)
            cs_fail_cp = cs_fn.replace("/bin/cp", str(fail_cp))
            script7 = (
                "set -euo pipefail\n"
                f'prefix="{prefix7}"\n'
                f'upgrade_backup_prefix="{backup7}"\n'
                'upgrade_staged_tree=""\n'
                'upgrade_rollback_armed=1\n'
                'upgrade_had_var=1\n'
                'upgrade_had_etc=0\n'
                'upgrade_moved_var=0\n'
                'upgrade_moved_etc=0\n'
                'upgrade_was_loaded=1\n'
                'upgrade_had_plist=1\n'
                'upgrade_shipper_was_loaded=1\n'
                'upgrade_touched_shipper=1\n'
                'upgrade_shipper_prior_disabled="enabled"\n'
                'upgrade_had_shipper_plist=1\n'
                'upgrade_saved_shipper_plist=""\n'
                'upgrade_snapshot_taken=1\n'
                f'upgrade_saved_workdir="{prefix7}/var/libntech"\n'
                'upgrade_saved_inputs=0\n'
                'upgrade_saved_data=1\n'
                f'plist_path="{execd_plist6}"\n'
                f'shipper_plist_path="{live_plist6}"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'stage_dir="{stage7}"\n'
                'publish_lock_held=0\n'
                'put_data_rollback_armed=0\n'
                'execd_is_loaded() { return 1; }\n'
                'shipper_is_loaded() { return 1; }\n'
                f'bootstrap_execd_with_retry() {{ echo "execd" >> "{bs_log7}"; return 0; }}\n'
                f'bootstrap_shipper_with_retry() {{ echo "shipper" >> "{bs_log7}"; return 0; }}\n'
                f"{cs_fail_cp}\n"
                "cleanup_stage\n"
            )
            r7 = subprocess.run(["/bin/bash", "-c", script7], capture_output=True, text=True, check=False)
            self.assertEqual(r7.returncode, 0, r7.stderr)
            self.assertTrue(saved_data7.is_file(), "R6-M1: saved snapshot bytes must remain intact when workdir restore fails")
            self.assertEqual(saved_data7.read_text(encoding="utf-8"), '{"saved":"precious"}\n')
            self.assertFalse(bs_log7.exists(), "R6-M1: ZERO bootstraps allowed when workdir snapshot restore fails")
            self.assertIn("incomplete", r7.stderr)

            # Macroscope #4714558789 & R8-M3: Early execd bootout failure before upgrade touched shipper
            # (even when shipper is loaded + disabled override + byte-identical plist!) must cause ZERO shipper mutations!
            stage8 = root / "stage8"
            stage8.mkdir()
            unchanged_plist = root / "shipper8.plist"
            unchanged_plist.write_text("<plist>SAME</plist>\n", encoding="utf-8")
            saved8 = stage8 / "upgrade-shipper.plist.prev"
            saved8.write_text("<plist>SAME</plist>\n", encoding="utf-8")
            bootout8_log = root / "bootout8.log"
            lc8_log = root / "lc8.log"
            lc8_shim = root / "lc8"
            lc8_shim.write_text(f"#!/bin/sh\necho \"$*\" >> '{lc8_log}'\nexit 0\n", encoding="utf-8")
            lc8_shim.chmod(0o755)
            cs_lc8 = cs_fn.replace("/bin/launchctl", str(lc8_shim))
            script8 = (
                "set -euo pipefail\n"
                f'prefix="{root}/opt/tendcf8"\n'
                'upgrade_backup_prefix=""\n'
                'upgrade_staged_tree=""\n'
                'upgrade_rollback_armed=1\n'
                'upgrade_had_var=0\n'
                'upgrade_had_etc=0\n'
                'upgrade_moved_var=0\n'
                'upgrade_moved_etc=0\n'
                'upgrade_was_loaded=1\n'
                'upgrade_had_plist=1\n'
                'upgrade_shipper_was_loaded=1\n'
                'upgrade_touched_shipper=0\n'
                'upgrade_shipper_prior_disabled="disabled"\n'
                'upgrade_had_shipper_plist=1\n'
                f'upgrade_saved_shipper_plist="{saved8}"\n'
                'upgrade_snapshot_taken=0\n'
                'upgrade_saved_workdir=""\n'
                'upgrade_saved_inputs=0\n'
                'upgrade_saved_data=0\n'
                f'plist_path="{execd_plist6}"\n'
                f'shipper_plist_path="{unchanged_plist}"\n'
                'label="org.tendcf.execd"\n'
                'shipper_label="org.tendcf.audit-shipper"\n'
                f'stage_dir="{stage8}"\n'
                'publish_lock_held=0\n'
                'put_data_rollback_armed=0\n'
                'execd_is_loaded() { return 0; }\n'
                'shipper_is_loaded() { return 0; }\n'
                f'bootout_shipper() {{ echo "booted_out" >> "{bootout8_log}"; return 0; }}\n'
                'wait_shipper_unloaded() { return 0; }\n'
                f'bootstrap_shipper_with_retry() {{ echo "bootstrapped" >> "{bootout8_log}"; return 0; }}\n'
                f"{cs_lc8}\n"
                "cleanup_stage\n"
            )
            r8 = subprocess.run(["/bin/bash", "-c", script8], capture_output=True, text=True, check=False)
            self.assertEqual(r8.returncode, 0, r8.stderr)
            self.assertFalse(bootout8_log.exists(), "R8-M3: untouched loaded+disabled shipper must NOT be booted out or re-bootstrapped")
            self.assertFalse(lc8_log.exists(), "R8-M3: untouched loaded+disabled shipper must cause ZERO launchctl calls")


if __name__ == "__main__":
    unittest.main()
