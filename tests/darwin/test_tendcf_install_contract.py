"""Contract and hermetic rollback/security tests for deploy/darwin/tendcf-install.sh."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "deploy" / "darwin" / "tendcf-install.sh"
PROJECTOR = REPO / "bin" / "projector.py"
DARWIN_CANARY_PRESENT = REPO / "deploy" / "darwin" / "canary" / "host_specific.json"
DARWIN_CANARY_ABSENT = REPO / "deploy" / "darwin" / "canary" / "host_specific-absent.json"


def _extract_func(src: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}\(\) \{{[^\n]*\n(.*?)^\}}", src, re.MULTILINE | re.DOTALL)
    if m is None:
        raise AssertionError(f"function {name}() not found in {INSTALLER}")
    return m.group(0)


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
        self.assertIn("else\n                return 1", fn)

        find_py = _extract_func(self.src, "find_real_python")
        idx_clt = find_py.find("/Library/Developer/CommandLineTools/usr/bin/python3")
        idx_usr = find_py.find("verify_python_candidate_ok /usr/bin/python3")
        self.assertNotEqual(idx_clt, -1)
        self.assertNotEqual(idx_usr, -1)
        self.assertLess(idx_clt, idx_usr)

        # Hermetic behavioral test: when /usr/bin/python3 resolves to /usr/bin/python3
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
    ]
    if sys.platform != "darwin":
        replacements.append(("/usr/bin/lockf", str(shim_dir / "lockf")))
    for old, new in replacements:
        code = code.replace(old, new)
    return code


def _make_darwin_shims(shim_dir: Path) -> None:
    for noop in ("chown", "chflags"):
        p = shim_dir / noop
        p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        p.chmod(0o755)

    # xattr shim: no quarantine xattr present
    xattr = shim_dir / "xattr"
    xattr.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    xattr.chmod(0o755)

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
        "if fmt == '%Su:%Sg %Lp':\n"
        "    print(f'root:wheel {mode:o}')\n"
        "elif fmt == '%Su %Sg %Lp':\n"
        "    print(f'root wheel {mode:o}')\n"
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
        cmd_fn = _extract_func(self.src, "cmd_install")
        self.assertIn("--projector-src)", cmd_fn)
        idx_policy = cmd_fn.find("place_policy")
        idx_proj = cmd_fn.find("place_projector")
        idx_data = cmd_fn.find('put_data "$datafile"')
        self.assertNotEqual(idx_proj, -1)
        self.assertLess(idx_policy, idx_proj)
        self.assertLess(idx_proj, idx_data)

        preval_fn = _extract_func(self.src, "prevalidate_install_inputs")
        self.assertIn("resolve_projector_src", preval_fn)

        put_fn = _extract_func(self.src, "put_data")
        put_code = "\n".join(
            line for line in put_fn.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("$data.new", put_code)
        self.assertNotIn("$data.previous", put_code)
        self.assertIn("/usr/bin/lockf 9", put_code)
        self.assertIn(".host_specific.new.XXXXXX", put_code)
        self.assertIn(".host_specific.prev.XXXXXX", put_code)
        self.assertIn('"$py" -I "$installed_projector" --check "$staged_data"', put_code)

        idx_stage = put_code.find("make_stage")
        idx_py = put_code.find("find_real_python")
        idx_gate1 = put_code.find('"$installed_projector" --check "$staged_data"')
        idx_gate2 = put_code.find('validate_cmdb_workdir "$stage_wd"')
        idx_mv = put_code.find('/bin/mv -f "$tmp" "$data"')
        idx_gate3 = put_code.find('validate_cmdb_workdir "$workdir" "$entry"', idx_mv)
        self.assertLess(idx_stage, idx_py, "make_stage must run before find_real_python")
        self.assertLess(idx_gate1, idx_gate2)
        self.assertLess(idx_gate2, idx_mv)
        self.assertLess(idx_mv, idx_gate3)

        val_fn = _extract_func(self.src, "validate_cmdb_workdir")
        self.assertIn("--show-classes", val_fn)
        self.assertIn("tendcf_cmdb_refused", val_fn)
        self.assertIn("tendcf_cmdb_problem_", val_fn)

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

    def _run_put_data(
        self,
        paths: dict[str, Path],
        src_file: Path,
        *,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        funcs = self._darwin_funcs(
            paths["shim_dir"],
            (
                "check_dir_root_unwritable",
                "verify_installed_projector",
                "validate_cmdb_workdir",
                "put_data",
            ),
        )
        script = (
            "set -euo pipefail\n"
            'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
            'say() { echo "tendcf-install: $*"; }\n'
            "has_acl_path() { return 1; }\n"
            "check_ancestors() { return 0; }\n"
            "make_stage() { return 0; }\n"
            f'find_real_python() {{ echo "{sys.executable}"; }}\n'
            f'prefix="{paths["prefix"]}"\n'
            f'workdir="{paths["workdir"]}"\n'
            f'stage_dir="{paths["stage_dir"]}"\n'
            f'entry="{paths["entry"]}"\n'
            f'data="{paths["data"]}"\n'
            f'cf_promises="{paths["cf_promises"]}"\n'
            f'installed_projector="{paths["installed_projector"]}"\n'
            'put_data_stage_wd=""\n'
            'put_data_tmp=""\n'
            'put_data_backup=""\n'
            "changed=0\n"
            f"{funcs}\n"
            'cleanup_put() { [ -n "$put_data_tmp" ] && rm -f "$put_data_tmp" || true; '
            '[ -n "$put_data_backup" ] && rm -f "$put_data_backup" || true; '
            '[ -n "$put_data_stage_wd" ] && rm -rf "$put_data_stage_wd" || true; }\n'
            "trap cleanup_put EXIT\n"
            f'put_data "{src_file}"\n'
            'echo "CHANGED=$changed"\n'
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

    def test_place_projector_and_put_data_rejects_bad_projection_without_touching_live_data(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            paths = self._build_env(root, "#!/bin/sh\necho 'any   hardclass'\n", initial_data=orig)
            # Test place_projector idempotency too
            paths["installed_projector"].unlink()
            place_funcs = self._darwin_funcs(
                paths["shim_dir"],
                (
                    "ensure_dir",
                    "resolve_realpath_ok",
                    "resolve_projector_src",
                    "check_dir_root_unwritable",
                    "verify_installed_projector",
                    "place_projector",
                ),
            )
            place_script = (
                "set -euo pipefail\n"
                'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                "has_acl_path() { return 1; }\n"
                "check_ancestors() { return 0; }\n"
                "make_stage() { return 0; }\n"
                f'prefix="{paths["prefix"]}"\n'
                f'stage_dir="{paths["stage_dir"]}"\n'
                f'here="{root}"\n'
                f'projector_src="{PROJECTOR}"\n'
                f'installed_projector="{paths["installed_projector"]}"\n'
                'place_projector_tmp=""\n'
                "changed=0\n"
                f"{place_funcs}\n"
                "place_projector\n"
                'echo "FIRST_CHANGED=$changed"\n'
                "changed=0\n"
                "place_projector\n"
                'echo "SECOND_CHANGED=$changed"\n'
            )
            rp = subprocess.run(["/bin/bash", "-c", place_script], capture_output=True, text=True, check=False)
            self.assertEqual(rp.returncode, 0, rp.stderr)
            self.assertIn("FIRST_CHANGED=1", rp.stdout)
            self.assertIn("SECOND_CHANGED=0", rp.stdout)
            self.assertEqual(paths["installed_projector"].read_bytes(), PROJECTOR.read_bytes())

            # Now test Gate 1 rejection leaves live data untouched
            before_ino = paths["data"].stat().st_ino
            bad = root / "bad.json"
            bad.write_bytes(orig + b"\n")
            r = self._run_put_data(paths, bad)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("projector rejected", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)
            self.assertEqual(paths["data"].stat().st_ino, before_ino)

            # Idempotent re-run on identical valid data leaves changed=0
            r_idem = self._run_put_data(paths, DARWIN_CANARY_PRESENT)
            self.assertEqual(r_idem.returncode, 0, r_idem.stderr)
            self.assertIn("CHANGED=0", r_idem.stdout)

    def test_validate_cmdb_refused_prepublish_and_postpublish_rollback(self) -> None:
        # Pre-publish refusal (exit 0 with tendcf_cmdb_refused) -> live data untouched
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            paths = self._build_env(
                root,
                "#!/bin/sh\necho 'any   hardclass'\necho 'tendcf_cmdb_problem_badkey   source=policy'\necho 'tendcf_cmdb_refused   source=policy'\nexit 0\n",
                initial_data=orig,
            )
            before_ino = paths["data"].stat().st_ino
            r = self._run_put_data(paths, DARWIN_CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("tendcf_cmdb_refused", r.stderr)
            self.assertIn("tendcf_cmdb_problem_badkey", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)
            self.assertEqual(paths["data"].stat().st_ino, before_ino)

        # Empty --show-classes -> fail closed
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            orig = DARWIN_CANARY_PRESENT.read_bytes()
            paths = self._build_env(root, "#!/bin/sh\nexit 0\n", initial_data=orig)
            r = self._run_put_data(paths, DARWIN_CANARY_ABSENT)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("empty output", r.stderr)
            self.assertEqual(paths["data"].read_bytes(), orig)

        # Post-publish Gate 3 refusal -> rolls back to previous backup
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
                "  echo 'any   hardclass'\n"
                "  echo 'tendcf_cmdb_refused   source=policy'\n"
                "  exit 0\n"
                "fi\n"
                "echo 'any   hardclass'\n"
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
                "echo 'any   hardclass'\n"
                "exit 0\n"
            )
            paths = self._build_env(root, cf_script, initial_data=DARWIN_CANARY_PRESENT.read_bytes())
            funcs = self._darwin_funcs(
                paths["shim_dir"],
                (
                    "check_dir_root_unwritable",
                    "verify_installed_projector",
                    "validate_cmdb_workdir",
                    "put_data",
                ),
            )
            procs: list[subprocess.Popen[str]] = []
            for i in range(6):
                src = DARWIN_CANARY_ABSENT if i % 2 == 0 else DARWIN_CANARY_PRESENT
                w_stage = root / f"stage-{i}"
                w_stage.mkdir(mode=0o700)
                script = (
                    "set -euo pipefail\n"
                    f'export WORKER_ID="{i}"\n'
                    'die() { echo "tendcf-install: $*" >&2; exit 1; }\n'
                    'say() { echo "tendcf-install: $*"; }\n'
                    "has_acl_path() { return 1; }\n"
                    "check_ancestors() { return 0; }\n"
                    "make_stage() { return 0; }\n"
                    f'find_real_python() {{ echo "{sys.executable}"; }}\n'
                    f'prefix="{paths["prefix"]}"\n'
                    f'workdir="{paths["workdir"]}"\n'
                    f'stage_dir="{w_stage}"\n'
                    f'entry="{paths["entry"]}"\n'
                    f'data="{paths["data"]}"\n'
                    f'cf_promises="{paths["cf_promises"]}"\n'
                    f'installed_projector="{paths["installed_projector"]}"\n'
                    'put_data_stage_wd=""\n'
                    'put_data_tmp=""\n'
                    'put_data_backup=""\n'
                    "changed=0\n"
                    f"{funcs}\n"
                    'cleanup_put() { [ -n "$put_data_tmp" ] && rm -f "$put_data_tmp" || true; '
                    '[ -n "$put_data_backup" ] && rm -f "$put_data_backup" || true; '
                    '[ -n "$put_data_stage_wd" ] && rm -rf "$put_data_stage_wd" || true; }\n'
                    "trap cleanup_put EXIT\n"
                    f'put_data "{src}"\n'
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
                if p.name not in ("host_specific.json", ".publish.lock")
            ]
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
