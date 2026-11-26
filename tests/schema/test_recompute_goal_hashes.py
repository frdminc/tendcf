"""Unit tests for bin/recompute_goal_hashes.py (issue #56 item 3 & R1/R2 hardening)."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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

            # Case 3: symlinked examples/ directory itself
            tree3 = root / "tree3"
            tree3.mkdir()
            ext_ex = root / "ext-examples"
            shutil.copytree(REPO_ROOT / "examples", ext_ex)
            (tree3 / "examples").symlink_to(ext_ex)
            r3 = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), "--root", str(tree3)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r3.returncode, 2, r3.stdout + r3.stderr)
            self.assertIn("symlink", r3.stderr.lower())

    def test_dir_fd_anchored_reads_writes_fchmod_replace_and_cleanup(self) -> None:
        """Deterministic proof that all fixture traversal, reads, exclusive temp
        creation, fchmod, atomic replace, and failure unlink stay anchored to
        opened directory file descriptors (zero path-based os.chmod)."""
        mod = _load_module()
        with tempfile.TemporaryDirectory(prefix="tendcf-recompute-dirfd-") as td:
            tmp_root = Path(td)
            shutil.copytree(REPO_ROOT / "examples", tmp_root / "examples")
            jcs = mod._load_bundled_jcs_dumps()
            base_p = tmp_root / "examples" / "goal-file-baseline.json"
            base_doc = json.loads(base_p.read_text(encoding="utf-8"))
            base_doc["schema_version"] += 1
            base_p.write_bytes(jcs(base_doc))

            real_open = os.open
            real_fchmod = os.fchmod
            real_replace = os.replace
            real_unlink = os.unlink

            dir_opens: list[tuple[str, int, int | None]] = []
            read_opens: list[tuple[str, int, int | None]] = []
            tmp_opens: list[tuple[str, int, int, int | None]] = []
            fchmod_calls: list[tuple[int, int]] = []
            replace_calls: list[tuple[str, str, int | None, int | None]] = []
            unlink_calls: list[tuple[str, int | None]] = []

            def spy_open(path, flags, mode=0o777, *, dir_fd=None):
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
                if dir_fd is not None:
                    name = os.fspath(path)
                    if flags & os.O_DIRECTORY:
                        dir_opens.append((name, flags, dir_fd))
                    elif flags & os.O_CREAT:
                        tmp_opens.append((name, flags, mode, dir_fd))
                    else:
                        read_opens.append((name, flags, dir_fd))
                return fd

            def spy_fchmod(fd, mode):
                fchmod_calls.append((fd, mode))
                return real_fchmod(fd, mode)

            def spy_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                replace_calls.append((os.fspath(src), os.fspath(dst), src_dir_fd, dst_dir_fd))
                return real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            def spy_unlink(path, *, dir_fd=None):
                unlink_calls.append((os.fspath(path), dir_fd))
                return real_unlink(path, dir_fd=dir_fd)

            with (
                mock.patch.object(os, "open", side_effect=spy_open),
                mock.patch.object(os, "fchmod", side_effect=spy_fchmod),
                mock.patch.object(os, "chmod", side_effect=AssertionError("path-based os.chmod forbidden")),
                mock.patch.object(os, "replace", side_effect=spy_replace),
                mock.patch.object(os, "unlink", side_effect=spy_unlink),
            ):
                changes = mod.recompute_hashes(tmp_root, write=True)

            self.assertTrue(changes, "expected fixture updates")
            # 1. Directory traversal uses dir_fd + O_DIRECTORY | O_NOFOLLOW.
            opened_dir_names = {name for name, _, _ in dir_opens}
            self.assertIn("examples", opened_dir_names)
            self.assertIn("broken", opened_dir_names)
            for name, flags, dfd in dir_opens:
                self.assertNotIn("/", name)
                self.assertIsNotNone(dfd)
                self.assertTrue(flags & os.O_DIRECTORY)
                self.assertTrue(flags & os.O_NOFOLLOW)

            # 2. Regular-file reads use dir_fd + O_NOFOLLOW with bare names.
            self.assertTrue(read_opens)
            for name, flags, dfd in read_opens:
                self.assertNotIn("/", name)
                self.assertIsNotNone(dfd)
                self.assertTrue(flags & os.O_NOFOLLOW)

            # 3. Exclusive sibling temp creation uses O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, mode 0o600, dir_fd.
            self.assertEqual(len(tmp_opens), len(changes))
            for name, flags, mode, dfd in tmp_opens:
                self.assertNotIn("/", name)
                self.assertTrue(name.startswith(".") and name.endswith(".tmp"))
                self.assertEqual(mode, 0o600)
                self.assertIsNotNone(dfd)
                self.assertTrue(flags & os.O_WRONLY)
                self.assertTrue(flags & os.O_CREAT)
                self.assertTrue(flags & os.O_EXCL)
                self.assertTrue(flags & os.O_NOFOLLOW)

            # 4. Permissions applied via fchmod(fd, mode) while fd is open.
            self.assertEqual(len(fchmod_calls), len(changes))
            for fd, _mode in fchmod_calls:
                self.assertIsInstance(fd, int)
                self.assertGreaterEqual(fd, 0)

            # 5. Atomic replace uses matching src_dir_fd == dst_dir_fd with bare names.
            self.assertEqual(len(replace_calls), len(changes))
            for src, dst, src_dfd, dst_dfd in replace_calls:
                self.assertNotIn("/", src)
                self.assertNotIn("/", dst)
                self.assertIsNotNone(src_dfd)
                self.assertEqual(src_dfd, dst_dfd)
            self.assertEqual(unlink_calls, [], "successful writes should not unlink")

            # 6. Error cleanup unlinks via dir_fd with bare temp name.
            base_doc["schema_version"] += 1
            base_p.write_bytes(jcs(base_doc))
            unlink_calls.clear()
            with (
                mock.patch.object(os, "replace", side_effect=OSError("forced replace fail")),
                mock.patch.object(os, "unlink", side_effect=spy_unlink),
            ):
                with self.assertRaises(OSError):
                    mod.recompute_hashes(tmp_root, write=True)
            self.assertEqual(len(unlink_calls), 1)
            unlinked_name, unlinked_dfd = unlink_calls[0]
            self.assertNotIn("/", unlinked_name)
            self.assertTrue(unlinked_name.startswith(".") and unlinked_name.endswith(".tmp"))
            self.assertIsNotNone(unlinked_dfd)

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

            # Snapshot every top-level JSON file before the run so we assert the
            # exact file whose os.replace actually failed (not a hard-coded name).
            top_snapshots = {
                p.name: p.read_bytes()
                for p in (tmp_root / "examples").glob("*.json")
            }
            failed_targets: list[tuple[str, str, int | None, int | None]] = []

            def fail_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                failed_targets.append((os.fspath(src), os.fspath(dst), src_dir_fd, dst_dir_fd))
                raise OSError("simulated replace failure")

            with mock.patch.object(os, "replace", side_effect=fail_replace):
                with self.assertRaises(OSError):
                    mod.recompute_hashes(tmp_root, write=True)

            self.assertEqual(len(failed_targets), 1)
            _, failed_dst, src_dfd, dst_dfd = failed_targets[0]
            self.assertIn(failed_dst, top_snapshots)
            self.assertIsNotNone(src_dfd)
            self.assertEqual(src_dfd, dst_dfd)
            # Assert the exact file whose replace failed kept its exact original bytes.
            self.assertEqual((tmp_root / "examples" / failed_dst).read_bytes(), top_snapshots[failed_dst])
            for name, orig in top_snapshots.items():
                self.assertEqual((tmp_root / "examples" / name).read_bytes(), orig, name)
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

            # Deterministically overlap both threads on the first updated fixture
            # (`approval-application.json`): both read the stale file before either
            # writes it, then both meet at os.replace holding distinct live sibling
            # temp files simultaneously.
            target_name = "approval-application.json"
            read_barrier = threading.Barrier(2, timeout=10.0)
            replace_barrier = threading.Barrier(2, timeout=10.0)
            read_seen: set[int] = set()
            replace_seen: set[int] = set()
            seen_lock = threading.Lock()
            overlapping_tmp_names: list[str] = []

            real_read = mod._read_regular_file_at
            real_replace = os.replace

            def sync_read(dfd, name, display):
                res = real_read(dfd, name, display)
                if name == target_name and display.parent.name == "examples":
                    tid = threading.get_ident()
                    wait = False
                    with seen_lock:
                        if tid not in read_seen:
                            read_seen.add(tid)
                            wait = True
                    if wait:
                        read_barrier.wait()
                return res

            def sync_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                if os.fspath(dst) == target_name:
                    tid = threading.get_ident()
                    wait = False
                    with seen_lock:
                        if tid not in replace_seen:
                            replace_seen.add(tid)
                            overlapping_tmp_names.append(os.fspath(src))
                            wait = True
                    if wait:
                        replace_barrier.wait()
                return real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            with (
                mock.patch.object(mod, "_read_regular_file_at", side_effect=sync_read),
                mock.patch.object(os, "replace", side_effect=sync_replace),
            ):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    f1 = pool.submit(mod.recompute_hashes, tmp_root, write=True)
                    f2 = pool.submit(mod.recompute_hashes, tmp_root, write=True)
                    f1.result()
                    f2.result()

            self.assertEqual(len(overlapping_tmp_names), 2)
            self.assertEqual(len(set(overlapping_tmp_names)), 2, f"temp names collided: {overlapping_tmp_names}")
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
