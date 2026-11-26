"""Unit tests for bin/recompute_goal_hashes.py (issue #56 item 3)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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

    def test_updates_dependent_hashes_and_preserves_intentional_defects(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-test-") as td:
            tmp_root = Path(td)
            shutil.copytree(REPO_ROOT / "examples", tmp_root / "examples")
            # Copy bin/projector.py so _load_jcs_dumps resolves inside tmp_root too.
            (tmp_root / "bin").mkdir()
            shutil.copy2(REPO_ROOT / "bin" / "projector.py", tmp_root / "bin" / "projector.py")

            # Mutate both goal-file-baseline.json and goal-file.json (simulating a
            # schema_version bump) AND mutate case 52's local goal-file-baseline.json.
            jcs = mod._load_jcs_dumps(tmp_root)
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

            # Record intentional defect values before recomputing.
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

            # Verify top-level goal-diff & approval records updated and canonical (no trailing newline).
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

            # Verify case 49 preserved its intentional baseline mismatch while updating proposed_sha256!
            for name in ("goal-diff.json", "approval-record.json", "approval-record-reject.json"):
                doc49 = json.loads(
                    (tmp_root / "examples" / "broken" / "49-baseline-hash-mismatch" / name).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(doc49["baseline_sha256"], case49_diff_before["baseline_sha256"], name)
                self.assertNotEqual(doc49["baseline_sha256"], new_top_base, name)
                self.assertEqual(doc49["proposed_sha256"], new_top_prop, name)

            # Verify case 50, 51, 54, 55 updated against top-level hashes.
            for rel in (
                "50-hunk-inconsistency/goal-diff.json",
                "51-non-empty-migration/goal-diff.json",
                "54-no-op-hunk/goal-diff.json",
                "55-no-op-coverage-change/goal-diff.json",
            ):
                doc = json.loads((tmp_root / "examples" / "broken" / rel).read_text(encoding="utf-8"))
                self.assertEqual(doc["baseline_sha256"], new_top_base, rel)
                self.assertEqual(doc["proposed_sha256"], new_top_prop, rel)

            # Verify case 52 used its LOCAL goal-file-baseline.json hash and top-level proposed hash.
            doc52 = json.loads(
                (tmp_root / "examples" / "broken" / "52-ordinary-over-privileged-hunk" / "goal-diff.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(doc52["baseline_sha256"], new_52_base)
            self.assertEqual(doc52["proposed_sha256"], new_top_prop)

            # Verify case 201 preserved its intentional defect untouched.
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

            # Verify case 274 preserved its intentional trailing newline while updating the digest.
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


if __name__ == "__main__":
    unittest.main()
