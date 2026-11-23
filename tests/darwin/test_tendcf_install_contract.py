"""Contract and hermetic rollback tests for deploy/darwin/tendcf-install.sh."""

from __future__ import annotations

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
    """Verify Macroscope R1c upgrade-rollback invariants and bash syntax."""

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

    def test_prefix_var_symlink_checked_before_bootout_and_post_move_restores(self) -> None:
        fn = _extract_func(self.src, "install_tarball")
        idx_pre_check = fn.find('[ -L "$prefix/var" ]')
        idx_bootout = fn.find('/bin/launchctl bootout "system/$label"')
        idx_arm_loaded = fn.find("upgrade_was_loaded=1")
        idx_arm_rollback = fn.find("upgrade_rollback_armed=1")
        idx_post_check = fn.find('[ -L "$backup_prefix/var" ]')

        self.assertNotEqual(idx_pre_check, -1, "missing pre-bootout [ -L \"$prefix/var\" ] check")
        self.assertNotEqual(idx_bootout, -1, "missing launchctl bootout in install_tarball")
        self.assertLess(
            idx_pre_check,
            idx_bootout,
            "[ -L \"$prefix/var\" ] must run BEFORE launchctl bootout",
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
            "post-move belt-and-suspenders [ -L \"$backup_prefix/var\" ] check must remain",
        )
        self.assertGreater(idx_post_check, idx_bootout)
        # Ensure backup_prefix is assigned to upgrade_backup_prefix before the post-move check
        # so die triggers cleanup_stage() to restore $prefix and restart org.tendcf.execd.
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
            ("lay_out", idx_lay_out),
            ("place_policy", idx_place_policy),
            ("put_data", idx_put_data),
            ("enable_execd", idx_enable),
            ("disarm", idx_disarm),
            ("rm_backup", idx_rm_backup),
        ):
            self.assertNotEqual(idx, -1, f"missing {label} in cmd_install")

        self.assertLess(idx_preval, idx_tarball)
        for step_idx in (
            idx_tarball,
            idx_check_tree,
            idx_init_paths,
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
        idx_var_failed = fn.find('"$failed_prefix/var"')
        idx_var_staged = fn.find('"$upgrade_staged_tree/var"')
        idx_restore = fn.find('/bin/mv "$upgrade_backup_prefix" "$prefix"')
        idx_bootstrap = fn.find('/bin/launchctl bootstrap system "$plist_path"')
        idx_rm_stage = fn.find('/bin/rm -rf "$stage_dir"')

        for label, idx in (
            ("rollback guard", idx_rb),
            ("failed_prefix/var rescue", idx_var_failed),
            ("staged_tree/var rescue", idx_var_staged),
            ("restore backup_prefix", idx_restore),
            ("bootstrap execd", idx_bootstrap),
            ("rm stage_dir", idx_rm_stage),
        ):
            self.assertNotEqual(idx, -1, f"missing {label} in cleanup_stage")

        self.assertLess(idx_rb, idx_var_failed)
        self.assertLess(idx_var_failed, idx_var_staged)
        self.assertLess(idx_var_staged, idx_restore)
        self.assertLess(idx_restore, idx_bootstrap)
        self.assertLess(
            idx_bootstrap,
            idx_rm_stage,
            "upgrade rollback must run BEFORE rm -rf \"$stage_dir\" so staged_tree/var can be rescued",
        )
        self.assertIn("! execd_is_loaded", fn)

    def test_cleanup_stage_executes_rollback_post_swap_and_pre_swap(self) -> None:
        cleanup_fn = _extract_func(self.src, "cleanup_stage")

        # Case 1: failure AFTER mv staged_tree -> prefix (var moved into new prefix)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.123"
            stage = root / "stage"
            (backup / "bin").mkdir(parents=True)
            (backup / "bin" / "version").write_text("old-v1\n", encoding="utf-8")
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("new-v2\n", encoding="utf-8")
            (prefix / "var" / "libntech").mkdir(parents=True)
            (prefix / "var" / "libntech" / "key").write_text("host-key\n", encoding="utf-8")
            stage.mkdir()

            script = (
                "set -euo pipefail\n"
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{root / "missing.plist"}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=1\n"
                "upgrade_was_loaded=0\n"
                "execd_is_loaded() { return 1; }\n"
                f"{cleanup_fn}\n"
                "trap cleanup_stage EXIT\n"
                "exit 1\n"
            )
            r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 1)
            self.assertIn("rolled back failed upgrade", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")
            self.assertEqual((prefix / "var" / "libntech" / "key").read_text(encoding="utf-8"), "host-key\n")
            self.assertFalse(backup.exists())
            self.assertFalse(stage.exists())

        # Case 2: failure BETWEEN mv backup/var -> staged_tree/var AND mv staged_tree -> prefix
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            backup = root / "tendcf.old.456"
            stage = root / "stage"
            staged_tree = stage / "extract" / "tendcf"
            (backup / "bin").mkdir(parents=True)
            (backup / "bin" / "version").write_text("old-v1\n", encoding="utf-8")
            (staged_tree / "var" / "libntech").mkdir(parents=True)
            (staged_tree / "var" / "libntech" / "key").write_text("host-key-2\n", encoding="utf-8")

            script = (
                "set -euo pipefail\n"
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{root / "missing.plist"}"\n'
                "upgrade_rollback_armed=1\n"
                f'upgrade_backup_prefix="{backup}"\n'
                f'upgrade_staged_tree="{staged_tree}"\n'
                "upgrade_moved_var=1\n"
                "upgrade_was_loaded=0\n"
                "execd_is_loaded() { return 1; }\n"
                f"{cleanup_fn}\n"
                "trap cleanup_stage EXIT\n"
                "exit 1\n"
            )
            r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 1)
            self.assertIn("rolled back failed upgrade", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "old-v1\n")
            self.assertEqual((prefix / "var" / "libntech" / "key").read_text(encoding="utf-8"), "host-key-2\n")
            self.assertFalse(backup.exists())
            self.assertFalse(stage.exists())

        # Case 3: disarmed (upgrade succeeded) -> leaves new tree untouched, removes stage_dir
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "tendcf"
            stage = root / "stage"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin" / "version").write_text("new-v2\n", encoding="utf-8")
            stage.mkdir()

            script = (
                "set -euo pipefail\n"
                f'prefix="{prefix}"\n'
                f'stage_dir="{stage}"\n'
                f'plist_path="{root / "missing.plist"}"\n'
                "upgrade_rollback_armed=0\n"
                'upgrade_backup_prefix=""\n'
                'upgrade_staged_tree=""\n'
                "upgrade_moved_var=0\n"
                "upgrade_was_loaded=0\n"
                "execd_is_loaded() { return 1; }\n"
                f"{cleanup_fn}\n"
                "trap cleanup_stage EXIT\n"
                "exit 0\n"
            )
            r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("rolled back", r.stderr)
            self.assertEqual((prefix / "bin" / "version").read_text(encoding="utf-8"), "new-v2\n")
            self.assertFalse(stage.exists())


if __name__ == "__main__":
    unittest.main()
