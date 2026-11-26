#!/usr/bin/env python3
"""Recompute canonical JCS SHA-256 digests across goal-file family fixtures.

Used when a goal-file schema version bump or fixture edit changes the canonical
JCS bytes of `examples/goal-file.json`, `examples/goal-file-baseline.json`, or
a broken-case local `goal-file*.json` overlay (issue #56 item 3).

Updates `baseline_sha256` and `proposed_sha256` in:
  - `examples/goal-diff.json`
  - `examples/approval-*.json`
  - `examples/broken/*/*.json` (including cases 49-55, 56-60, 102, 108-109, etc.)

Preserves intentional negative-fixture defects (e.g. case 49's intentional
baseline hash mismatch, case 201's enrollment-with-proposed-sha256, and case
274's trailing newline on `baseline_sha256`) while keeping every valid companion
digest synchronized with the canonical JCS bytes (RFC 8785, no trailing
newline).

Security boundaries:
  - Always imports the bundled `bin/projector.py` next to this script (never
    loads code from `--root`).
  - Rejects symlinks on `examples/`, `examples/broken/`, every case directory,
    and every `.json` file (`O_RDONLY | O_NOFOLLOW` + regular-file check), and
    enforces resolved containment inside `examples/`.
  - Writes updates via an exclusive `O_CREAT | O_EXCL` sibling temp file
    (`tempfile.NamedTemporaryFile`) followed by `os.replace`, cleaning up on
    any error.

Exit codes:
  0  clean (or updated successfully)
  1  `--check` found one or more files out of date
  2  usage or input error
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

# Intentional hash defects in negative fixtures that MUST be preserved across
# recomputations:
#   (case_dir_name, filename_or_star, field_name) -> mode
#     "preserve": leave field verbatim (do not overwrite)
#     "trailing_newline": update digest to expected + "\n"
INTENTIONAL_DEFECTS: dict[tuple[str, str, str], str] = {
    ("49-baseline-hash-mismatch", "*", "baseline_sha256"): "preserve",
    ("201-enrollment-with-proposed-sha256", "approval-enrollment.json", "proposed_sha256"): "preserve",
    ("274-approval-baseline-sha256-trailing-newline", "approval-application.json", "baseline_sha256"): "trailing_newline",
}

# Broken-case fixtures that intentionally carry non-I-JSON values (e.g. integer
# 2**53) that strict stdlib RFC 8785 JCS rejects; scoped explicitly so silent
# fallbacks cannot mask unexpected JCS errors elsewhere.
COMPACT_JSON_FALLBACK_CASES: frozenset[str] = frozenset({
    "192-application-seq-above-2-53",
})

HASH_FIELDS = ("baseline_sha256", "proposed_sha256")


def _load_bundled_jcs_dumps():
    """Always load the bundled `bin/projector.py` beside this script — NEVER
    execute code from `--root`."""
    projector_path = REPO_ROOT / "bin" / "projector.py"
    if not projector_path.is_file() or projector_path.is_symlink():
        raise RuntimeError(f"bundled projector missing or symlink: {projector_path}")
    spec = importlib.util.spec_from_file_location("tendcf_projector_jcs", projector_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load bundled projector from {projector_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._jcs_dumps


def canonical_sha256(doc: Any, jcs_dumps) -> str:
    return "sha256:" + hashlib.sha256(jcs_dumps(doc)).hexdigest()


def _check_real_dir_contained(path: Path, root_real: Path) -> Path:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"refusing symlink directory: {path}")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"expected directory: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root_real):
        raise ValueError(f"directory escapes examples root: {path} -> {resolved}")
    return resolved


def _read_regular_file_contained(path: Path, root_real: Path) -> bytes:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"refusing symlink file: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"refusing non-regular file: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root_real):
        raise ValueError(f"file escapes examples root: {path} -> {resolved}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ValueError(f"refusing non-regular file descriptor: {path}")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _atomic_write_regular_contained(path: Path, data: bytes, root_real: Path) -> None:
    # Verify target and parent are still real, non-symlink, and inside root_real.
    _check_real_dir_contained(path.parent, root_real)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(f"refusing to replace non-regular or symlink target: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root_real):
        raise ValueError(f"target escapes examples root: {path} -> {resolved}")

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tf:
            tmp_path = Path(tf.name)
            tf.write(data)
            tf.flush()
            os.fsync(tf.fileno())
        os.chmod(tmp_path, stat.S_IMODE(st.st_mode))
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _defect_mode(case_dir: str | None, filename: str, field: str) -> str | None:
    if case_dir is None:
        return None
    mode = INTENTIONAL_DEFECTS.get((case_dir, filename, field))
    if mode is not None:
        return mode
    return INTENTIONAL_DEFECTS.get((case_dir, "*", field))


def _target_files(examples_dir: Path, examples_real: Path) -> list[tuple[Path, str | None]]:
    """Return sorted (path, broken_case_name_or_None) for every hash-coupled
    JSON fixture under `examples/`, rejecting symlinked dirs/files."""
    targets: list[tuple[Path, str | None]] = []
    for p in sorted(examples_dir.glob("*.json")):
        if p.name in ("goal-file.json", "goal-file-baseline.json", "host_specific.json"):
            continue
        targets.append((p, None))

    broken_dir = examples_dir / "broken"
    if broken_dir.exists() or broken_dir.is_symlink():
        _check_real_dir_contained(broken_dir, examples_real)
        for case_dir in sorted(broken_dir.iterdir()):
            if case_dir.is_symlink():
                raise ValueError(f"refusing symlink entry in examples/broken: {case_dir}")
            if not case_dir.is_dir():
                continue
            _check_real_dir_contained(case_dir, examples_real)
            for p in sorted(case_dir.glob("*.json")):
                if p.name in ("goal-file.json", "goal-file-baseline.json"):
                    continue
                targets.append((p, case_dir.name))
    return targets


def recompute_hashes(
    root: Path,
    *,
    write: bool = False,
) -> list[tuple[Path, dict[str, tuple[str, str]]]]:
    """Recompute expected hashes for all fixtures under `root/examples`.

    Returns a list of `(path, {field: (old_val, new_val)})` for every file whose
    canonical bytes differ from its current on-disk bytes. When `write=True`,
    writes the updated canonical JCS bytes (no trailing newline).
    """
    examples_dir = root / "examples"
    if not examples_dir.exists() and not examples_dir.is_symlink():
        raise FileNotFoundError(f"missing examples directory: {examples_dir}")
    st_ex = os.lstat(examples_dir)
    if stat.S_ISLNK(st_ex.st_mode) or not stat.S_ISDIR(st_ex.st_mode):
        raise ValueError(f"examples must be a real non-symlink directory: {examples_dir}")
    examples_real = examples_dir.resolve(strict=True)

    top_baseline_path = examples_dir / "goal-file-baseline.json"
    top_proposed_path = examples_dir / "goal-file.json"
    if not (top_baseline_path.exists() or top_baseline_path.is_symlink()):
        raise FileNotFoundError(f"missing {top_baseline_path}")
    if not (top_proposed_path.exists() or top_proposed_path.is_symlink()):
        raise FileNotFoundError(f"missing {top_proposed_path}")

    jcs_dumps = _load_bundled_jcs_dumps()
    top_baseline_hash = canonical_sha256(
        json.loads(_read_regular_file_contained(top_baseline_path, examples_real).decode("utf-8")),
        jcs_dumps,
    )
    top_proposed_hash = canonical_sha256(
        json.loads(_read_regular_file_contained(top_proposed_path, examples_real).decode("utf-8")),
        jcs_dumps,
    )

    dir_cache: dict[Path, tuple[str, str]] = {}

    def expected_for_dir(parent: Path) -> tuple[str, str]:
        if parent in dir_cache:
            return dir_cache[parent]
        local_base = parent / "goal-file-baseline.json"
        local_prop = parent / "goal-file.json"
        base_h = (
            canonical_sha256(
                json.loads(_read_regular_file_contained(local_base, examples_real).decode("utf-8")),
                jcs_dumps,
            )
            if (local_base.exists() or local_base.is_symlink())
            else top_baseline_hash
        )
        prop_h = (
            canonical_sha256(
                json.loads(_read_regular_file_contained(local_prop, examples_real).decode("utf-8")),
                jcs_dumps,
            )
            if (local_prop.exists() or local_prop.is_symlink())
            else top_proposed_hash
        )
        dir_cache[parent] = (base_h, prop_h)
        return base_h, prop_h

    changes: list[tuple[Path, dict[str, tuple[str, str]]]] = []
    for path, case_name in _target_files(examples_dir, examples_real):
        raw = _read_regular_file_contained(path, examples_real)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if case_name is None:
                raise ValueError(f"invalid JSON in top-level fixture {path}: {exc}") from exc
            continue
        if not isinstance(doc, dict):
            if case_name is None:
                raise ValueError(f"top-level fixture {path} must be a JSON object, got {type(doc).__name__}")
            continue
        if not any(k in doc for k in HASH_FIELDS):
            continue

        exp_base, exp_prop = expected_for_dir(path.parent)
        expected_map = {
            "baseline_sha256": exp_base,
            "proposed_sha256": exp_prop,
        }

        file_diffs: dict[str, tuple[str, str]] = {}
        for field in HASH_FIELDS:
            if field not in doc:
                continue
            mode = _defect_mode(case_name, path.name, field)
            if mode == "preserve":
                continue
            want = expected_map[field]
            if mode == "trailing_newline":
                want = want + "\n"
            cur = doc[field]
            if cur != want:
                file_diffs[field] = (str(cur), want)
                doc[field] = want

        if file_diffs:
            try:
                new_bytes = jcs_dumps(doc)
            except ValueError:
                # Only explicitly allowlisted broken-case fixtures that
                # intentionally carry non-I-JSON integers (e.g. case 192's
                # `application_seq: 2**53`) fall back to compact sorted JSON.
                if case_name not in COMPACT_JSON_FALLBACK_CASES:
                    raise
                new_bytes = json.dumps(
                    doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
            if new_bytes != raw:
                changes.append((path, file_diffs))
                if write:
                    _atomic_write_regular_contained(path, new_bytes, examples_real)

    return changes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute canonical JCS SHA-256 digests across examples/ fixtures."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root containing examples/ (default: parent of bin/).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="Check whether all fixture digests are up to date (exit 1 if any differ).",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned digest updates without modifying files (exit 0).",
    )
    args = parser.parse_args(argv)

    try:
        changes = recompute_hashes(
            args.root.resolve(),
            write=not (args.check or args.dry_run),
        )
    except Exception as exc:
        print(f"recompute_goal_hashes: error: {exc}", file=sys.stderr)
        return 2

    if not changes:
        if args.check:
            print("recompute_goal_hashes: OK (all goal-file family digests match)")
        elif args.dry_run:
            print("recompute_goal_hashes: no changes needed")
        else:
            print("recompute_goal_hashes: up to date (0 files modified)")
        return 0

    verb = "out of date" if args.check else ("would update" if args.dry_run else "updated")
    for path, diffs in changes:
        try:
            rel = path.relative_to(args.root.resolve())
        except ValueError:
            rel = path
        fields = ", ".join(f"{k}: {old[:20]}... -> {new[:20]}..." for k, (old, new) in diffs.items())
        print(f"{verb}: {rel} ({fields})")

    if args.check:
        print(
            f"recompute_goal_hashes: {len(changes)} file(s) out of date; "
            "run bin/recompute_goal_hashes.py to update",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
