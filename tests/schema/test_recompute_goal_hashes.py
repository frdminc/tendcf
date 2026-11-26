"""Unit tests for bin/recompute_goal_hashes.py (issue #56 item 3 & R1 hardening)."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "recompute_goal_hashes.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("recompute_goal_hashes", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RecomputeGoalHashesTests(unittest.TestCase):
    def test_check_passes_on_current_repo(self) -> None:
        r = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OK", r.stdout)

    def test_updates_dependent_hashes_preserves_defects_and_ignores_root_projector(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-test-") as td:
            tmp_root = Path(td)
            shutil.copytree(REPO_ROOT / "examples", tmp_root / "examples")
            # Plant a poisoned bin/projector.py under --root to prove the helper
            # NEVER executes code from --root (always imports bundled projector).
            (tmp_root / "bin").mkdir()
            (tmp_root / "bin" / "projector.py").write_text(
                "raise RuntimeError('POISONED_ROOT_PROJECTOR_EXECUTED')\n",
                encoding="utf-8",
            )

            jcs = mod._load_bundled_jcs_dumps()
            for rel in (
                "examples/goal-file-baseline.json",
                "examples/goal-file.json",
                "examples/broken/52-ordinary-over-privileged-hunk/goal-file-baseline.json",
            ):
                p = tmp_root / rel
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc["schema_version"] = doc["schema_version"] + 1
                p.write_bytes(jcs(doc))

            new_top_base = mod.canonical_sha256(
                json.loads((tmp_root / "examples" / "goal-file-baseline.json").read_text(encoding="utf-8")),
                jcs,
            )
            new_top_prop = mod.canonical_sha256(
                json.loads((tmp_root / "examples" / "goal-file.json").read_text(encoding="utf-8")),
                jcs,
            )
            new_52_base = mod.canonical_sha256(
                json.loads(
                    (
                        tmp_root
                        / "examples"
                        / "broken"
                        / "52-ordinary-over-privileged-hunk"
                        / "goal-file-baseline.json"
                    ).read_text(encoding="utf-8")
                ),
                jcs,
            )

            case49_diff_before = json.loads(
                (tmp_root / "examples" / "broken" / "49-baseline-hash-mismatch" / "goal-diff.json").read_text(
                    encoding="utf-8"
                )
            )
            case201_before = json.loads(
                (
                    tmp_root
                    / "examples"
                    / "broken"
                    / "201-enrollment-with-proposed-sha256"
                    / "approval-enrollment.json"
                ).read_text(encoding="utf-8")
            )

            # 1. --check must fail (exit 1) and modify nothing.
            r_check = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_root), "--check"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_check.returncode, 1, r_check.stdout + r_check.stderr)
            self.assertIn("out of date", r_check.stdout)
            self.assertNotIn("POISONED_ROOT_PROJECTOR_EXECUTED", r_check.stderr)

            # 2. --dry-run must exit 0 and modify nothing.
            goal_diff_path = tmp_root / "examples" / "goal-diff.json"
            before_bytes = goal_diff_path.read_bytes()
            r_dry = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_root), "--dry-run"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_dry.returncode, 0, r_dry.stdout + r_dry.stderr)
            self.assertIn("would update", r_dry.stdout)
            self.assertEqual(goal_diff_path.read_bytes(), before_bytes)

            # 3. Real run updates dependent hashes cleanly.
            r_run = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_root)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_run.returncode, 0, r_run.stdout + r_run.stderr)

            for name in (
                "goal-diff.json",
                "approval-record.json",
                "approval-record-reject.json",
                "approval-application.json",
            ):
                p = tmp_root / "examples" / name
                raw = p.read_bytes()
                self.assertFalse(raw.endswith(b"\n"), f"{name} must have no trailing newline")
                doc = json.loads(raw.decode("utf-8"))
                self.assertEqual(doc["baseline_sha256"], new_top_base, name)
                self.assertEqual(doc["proposed_sha256"], new_top_prop, name)
                self.assertEqual(raw, jcs(doc), f"{name} not canonical JCS")

            for name in ("goal-diff.json", "approval-record.json", "approval-record-reject.json"):
                doc49 = json.loads(
                    (tmp_root / "examples" / "broken" / "49-baseline-hash-mismatch" / name).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(doc49["baseline_sha256"], case49_diff_before["baseline_sha256"], name)
                self.assertNotEqual(doc49["baseline_sha256"], new_top_base, name)
                self.assertEqual(doc49["proposed_sha256"], new_top_prop, name)

            for rel in (
                "50-hunk-inconsistency/goal-diff.json",
                "51-non-empty-migration/goal-diff.json",
                "54-no-op-hunk/goal-diff.json",
                "55-no-op-coverage-change/goal-diff.json",
            ):
                doc = json.loads((tmp_root / "examples" / "broken" / rel).read_text(encoding="utf-8"))
                self.assertEqual(doc["baseline_sha256"], new_top_base, rel)
                self.assertEqual(doc["proposed_sha256"], new_top_prop, rel)

            doc52 = json.loads(
                (tmp_root / "examples" / "broken" / "52-ordinary-over-privileged-hunk" / "goal-diff.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(doc52["baseline_sha256"], new_52_base)
            self.assertEqual(doc52["proposed_sha256"], new_top_prop)

            doc201 = json.loads(
                (
                    tmp_root
                    / "examples"
                    / "broken"
                    / "201-enrollment-with-proposed-sha256"
                    / "approval-enrollment.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(doc201["proposed_sha256"], case201_before["proposed_sha256"])

            doc274 = json.loads(
                (
                    tmp_root
                    / "examples"
                    / "broken"
                    / "274-approval-baseline-sha256-trailing-newline"
                    / "approval-application.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(doc274["baseline_sha256"], new_top_base + "\n")
            self.assertEqual(doc274["proposed_sha256"], new_top_prop)

            # 4. --check now passes cleanly (exit 0)!
            r_check2 = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_root), "--check"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_check2.returncode, 0, r_check2.stdout + r_check2.stderr)

    def test_rejects_symlinked_dir_and_symlinked_json_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-sym-") as td:
            root = Path(td)
            outside = root / "outside.json"
            outside.write_text('{"baseline_sha256":"sha256:' + "0" * 64 + '"}', encoding="utf-8")

            # Case 1: symlinked JSON file inside examples/
            tree1 = root / "tree1"
            shutil.copytree(REPO_ROOT / "examples", tree1 / "examples")
            target1 = tree1 / "examples" / "goal-diff.json"
            target1.unlink()
            target1.symlink_to(outside)
            r1 = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tree1)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r1.returncode, 2, r1.stdout + r1.stderr)
            self.assertIn("symlink", r1.stderr.lower())

            # Case 2: symlinked case directory inside examples/broken/
            tree2 = root / "tree2"
            shutil.copytree(REPO_ROOT / "examples", tree2 / "examples")
            ext_dir = root / "ext-case"
            ext_dir.mkdir()
            (ext_dir / "goal-diff.json").write_text(
                '{"baseline_sha256":"sha256:' + "0" * 64 + '"}', encoding="utf-8"
            )
            (tree2 / "examples" / "broken" / "999-symlink-case").symlink_to(ext_dir)
            r2 = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tree2)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r2.returncode, 2, r2.stdout + r2.stderr)
            self.assertIn("symlink", r2.stderr.lower())

    def test_failed_replace_preserves_original_and_cleans_up_temp_file(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-fail-") as td:
            tmp_root = Path(td)
            shutil.copytree(REPO_ROOT / "examples", tmp_root / "examples")
            jcs = mod._load_bundled_jcs_dumps()
            base_p = tmp_root / "examples" / "goal-file-baseline.json"
            base_doc = json.loads(base_p.read_text(encoding="utf-8"))
            base_doc["schema_version"] += 1
            base_p.write_bytes(jcs(base_doc))

            diff_p = tmp_root / "examples" / "goal-diff.json"
            orig_bytes = diff_p.read_bytes()

            with mock.patch.object(os, "replace", side_effect=OSError("simulated replace failure")):
                with self.assertRaises(OSError):
                    mod.recompute_hashes(tmp_root, write=True)

            self.assertEqual(diff_p.read_bytes(), orig_bytes)
            leftovers = list((tmp_root / "examples").glob("*.tmp"))
            self.assertEqual(leftovers, [], f"leftover temp files found: {leftovers}")

    def test_concurrent_recomputes_use_unique_temp_files_without_collision(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-conc-") as td:
            tmp_root = Path(td)
            shutil.copytree(REPO_ROOT / "examples", tmp_root / "examples")
            jcs = mod._load_bundled_jcs_dumps()
            base_p = tmp_root / "examples" / "goal-file-baseline.json"
            base_doc = json.loads(base_p.read_text(encoding="utf-8"))
            base_doc["schema_version"] += 1
            base_p.write_bytes(jcs(base_doc))

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                f1 = pool.submit(mod.recompute_hashes, tmp_root, write=True)
                f2 = pool.submit(mod.recompute_hashes, tmp_root, write=True)
                f1.result()
                f2.result()

            self.assertEqual(mod.recompute_hashes(tmp_root, write=False), [])
            leftovers = list((tmp_root / "examples").rglob("*.tmp"))
            self.assertEqual(leftovers, [], f"leftover temp files found: {leftovers}")

    def test_malformed_top_level_fixture_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-badtop-") as td:
            tmp_root = Path(td)
            shutil.copytree(REPO_ROOT / "examples", tmp_root / "examples")
            (tmp_root / "examples" / "goal-diff.json").write_text("{not-json", encoding="utf-8")
            r = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_root), "--check"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("invalid JSON in top-level fixture", r.stderr)


if __name__ == "__main__":
    unittest.main()
