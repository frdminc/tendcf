"""Contract and hermetic rollback/security tests for deploy/darwin/tendcf-install.sh."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / "deploy" / "darwin" / "tendcf-install.sh"


def _extract_func(src: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}", src, re.MULTILINE | re.DOTALL)
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


if __name__ == "__main__":
    unittest.main()
