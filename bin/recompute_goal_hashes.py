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
import sys
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

HASH_FIELDS = ("baseline_sha256", "proposed_sha256")


def _load_jcs_dumps(repo_root: Path):
    """Load `bin/projector.py`'s JCS serializer (uses rfc8785 when installed,
    pure-stdlib RFC 8785 fallback otherwise — byte-for-byte identical)."""
    projector_path = repo_root / "bin" / "projector.py"
    if not projector_path.is_file():
        projector_path = REPO_ROOT / "bin" / "projector.py"
    spec = importlib.util.spec_from_file_location("tendcf_projector_jcs", projector_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load projector from {projector_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._jcs_dumps


def canonical_sha256(doc: Any, jcs_dumps) -> str:
    return "sha256:" + hashlib.sha256(jcs_dumps(doc)).hexdigest()


def _defect_mode(case_dir: str | None, filename: str, field: str) -> str | None:
    if case_dir is None:
        return None
    mode = INTENTIONAL_DEFECTS.get((case_dir, filename, field))
    if mode is not None:
        return mode
    return INTENTIONAL_DEFECTS.get((case_dir, "*", field))


def _target_files(examples_dir: Path) -> list[tuple[Path, str | None]]:
    """Return sorted (path, broken_case_name_or_None) for every hash-coupled
    JSON fixture under `examples/`."""
    targets: list[tuple[Path, str | None]] = []
    for p in sorted(examples_dir.glob("*.json")):
        if p.name in ("goal-file.json", "goal-file-baseline.json", "host_specific.json"):
            continue
        targets.append((p, None))

    broken_dir = examples_dir / "broken"
    if broken_dir.is_dir():
        for case_dir in sorted(broken_dir.iterdir()):
            if not case_dir.is_dir():
                continue
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
    top_baseline_path = examples_dir / "goal-file-baseline.json"
    top_proposed_path = examples_dir / "goal-file.json"
    if not top_baseline_path.is_file() or not top_proposed_path.is_file():
        raise FileNotFoundError(
            f"missing {top_baseline_path} or {top_proposed_path}"
        )

    jcs_dumps = _load_jcs_dumps(root)
    top_baseline_hash = canonical_sha256(
        json.loads(top_baseline_path.read_text(encoding="utf-8")), jcs_dumps
    )
    top_proposed_hash = canonical_sha256(
        json.loads(top_proposed_path.read_text(encoding="utf-8")), jcs_dumps
    )

    dir_cache: dict[Path, tuple[str, str]] = {}

    def expected_for_dir(parent: Path) -> tuple[str, str]:
        if parent in dir_cache:
            return dir_cache[parent]
        local_base = parent / "goal-file-baseline.json"
        local_prop = parent / "goal-file.json"
        base_h = (
            canonical_sha256(
                json.loads(local_base.read_text(encoding="utf-8")), jcs_dumps
            )
            if local_base.is_file()
            else top_baseline_hash
        )
        prop_h = (
            canonical_sha256(
                json.loads(local_prop.read_text(encoding="utf-8")), jcs_dumps
            )
            if local_prop.is_file()
            else top_proposed_hash
        )
        dir_cache[parent] = (base_h, prop_h)
        return base_h, prop_h

    changes: list[tuple[Path, dict[str, tuple[str, str]]]] = []
    for path, case_name in _target_files(examples_dir):
        raw = path.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict):
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
                # Broken-case fixtures may intentionally carry non-I-JSON values
                # (e.g. case 192's `application_seq: 2**53`) that strict JCS
                # rejects; serialize compact sorted UTF-8 JSON for those cases.
                if case_name is None:
                    raise
                new_bytes = json.dumps(
                    doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
            if new_bytes != raw:
                changes.append((path, file_diffs))
                if write:
                    tmp = path.with_name(f".{path.name}.recompute.tmp")
                    tmp.write_bytes(new_bytes)
                    tmp.replace(path)

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
