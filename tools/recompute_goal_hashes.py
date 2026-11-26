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
  - Always imports the bundled `tools/projector.py` next to this script (never
    loads code from `--root`).
  - Anchors all fixture directory traversal, regular-file reads, exclusive
    sibling temp-file creation, `os.fchmod`, atomic `os.replace`, and error
    cleanup `os.unlink` to opened directory file descriptors (`O_RDONLY |
    O_DIRECTORY | O_NOFOLLOW` via `dir_fd`), closing every descriptor in
    `finally`.
  - Rejects symlinks on `examples/`, `examples/broken/`, every case directory,
    and every `.json` file (`O_NOFOLLOW` + `fstat` regular-file check).

Exit codes:
  0  clean (or updated successfully)
  1  `--check` found one or more files out of date
  2  usage or input error
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import secrets
import stat
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

# Broken-case fixtures that intentionally carry non-I-JSON values (e.g. integer
# 2**53) that strict stdlib RFC 8785 JCS rejects; scoped explicitly so silent
# fallbacks cannot mask unexpected JCS errors elsewhere.
COMPACT_JSON_FALLBACK_CASES: frozenset[str] = frozenset({
    "192-application-seq-above-2-53",
})

HASH_FIELDS = ("baseline_sha256", "proposed_sha256")
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _load_bundled_jcs_dumps():
    """Always load the bundled `tools/projector.py` beside this script — NEVER
    execute code from `--root`."""
    projector_path = REPO_ROOT / "tools" / "projector.py"
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


def _open_root_dir_fd(root: Path) -> int:
    """Open caller-specified `--root` as a directory descriptor."""
    resolved = root.resolve(strict=True)
    flags = os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC
    try:
        fd = os.open(resolved, flags)
    except NotADirectoryError as exc:
        raise ValueError(f"root is not a directory: {root}") from exc
    try:
        fst = os.fstat(fd)
        if not stat.S_ISDIR(fst.st_mode):
            raise ValueError(f"root is not a directory: {root}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_child_dir_fd(name: str, parent_fd: int, display: Path) -> int:
    """Open immediate child directory `name` relative to `parent_fd` without
    following symlinks."""
    if "/" in name or name in ("", ".", ".."):
        raise ValueError(f"invalid child directory name {name!r} at {display}")
    flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"refusing symlink directory: {display}") from exc
        if exc.errno == errno.ENOTDIR:
            # On Linux, O_DIRECTORY | O_NOFOLLOW may return ENOTDIR when a
            # symlink targets a non-directory; distinguish via lstat(dir_fd).
            try:
                st = os.lstat(name, dir_fd=parent_fd)
                if stat.S_ISLNK(st.st_mode):
                    raise ValueError(f"refusing symlink directory: {display}") from exc
            except OSError:
                pass
            raise ValueError(f"expected directory: {display}") from exc
        raise
    try:
        fst = os.fstat(fd)
        if not stat.S_ISDIR(fst.st_mode):
            raise ValueError(f"expected directory: {display}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular_file_at(dfd: int, name: str, display: Path) -> tuple[bytes, int]:
    """Read a regular non-symlink file `name` anchored to directory fd `dfd`.

    Returns `(raw_bytes, permission_mode)`.
    """
    if "/" in name or name in ("", ".", ".."):
        raise ValueError(f"invalid filename {name!r} at {display}")
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK
    try:
        fd = os.open(name, flags, dir_fd=dfd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"refusing symlink file: {display}") from exc
        raise
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ValueError(f"refusing non-regular file: {display}")
        mode = stat.S_IMODE(fst.st_mode)
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read(), mode
    finally:
        if fd >= 0:
            os.close(fd)


def _atomic_write_at(dfd: int, name: str, data: bytes, mode: int, display: Path) -> None:
    """Atomically replace regular file `name` inside opened directory `dfd`.

    Creates an exclusive sibling temp file with `O_WRONLY | O_CREAT | O_EXCL |
    O_NOFOLLOW` via `dir_fd=dfd`, writes + flushes + `os.fsync` + `os.fchmod`
    while the descriptor is open (zero path-based `os.chmod`), publishes via
    `os.replace(..., src_dir_fd=dfd, dst_dir_fd=dfd)`, and cleans up via
    `os.unlink(..., dir_fd=dfd)` on any failure.
    """
    if "/" in name or name in ("", ".", ".."):
        raise ValueError(f"invalid filename {name!r} at {display}")
    st = os.lstat(name, dir_fd=dfd)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(f"refusing to replace non-regular or symlink target: {display}")

    tmp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
    tmp_name: str | None = None
    tmp_fd = -1
    for _ in range(64):
        candidate = f".{name}.{secrets.token_hex(8)}.tmp"
        try:
            tmp_fd = os.open(candidate, tmp_flags, 0o600, dir_fd=dfd)
            tmp_name = candidate
            break
        except FileExistsError:
            continue
    if tmp_fd < 0 or tmp_name is None:
        raise RuntimeError(f"could not create exclusive temp file for {display}")

    try:
        with os.fdopen(tmp_fd, "wb") as tf:
            tmp_fd = -1
            tf.write(data)
            tf.flush()
            os.fsync(tf.fileno())
            os.fchmod(tf.fileno(), mode)
        os.replace(tmp_name, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp_name = None
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=dfd)
            except OSError:
                pass


def _defect_mode(case_dir: str | None, filename: str, field: str) -> str | None:
    if case_dir is None:
        return None
    mode = INTENTIONAL_DEFECTS.get((case_dir, filename, field))
    if mode is not None:
        return mode
    return INTENTIONAL_DEFECTS.get((case_dir, "*", field))


def _process_dir_fd(
    dfd: int,
    dir_path: Path,
    *,
    case_name: str | None,
    skip_names: frozenset[str],
    exp_base: str,
    exp_prop: str,
    jcs_dumps,
    write: bool,
    changes: list[tuple[Path, dict[str, tuple[str, str]]]],
) -> None:
    """Inspect (and optionally update) every hash-coupled `*.json` file in `dfd`."""
    expected_map = {
        "baseline_sha256": exp_base,
        "proposed_sha256": exp_prop,
    }
    for name in sorted(os.listdir(dfd)):
        if not name.endswith(".json") or name in skip_names:
            continue
        display = dir_path / name
        raw, mode = _read_regular_file_at(dfd, name, display)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if case_name is None:
                raise ValueError(f"invalid JSON in top-level fixture {display}: {exc}") from exc
            continue
        if not isinstance(doc, dict):
            if case_name is None:
                raise ValueError(
                    f"top-level fixture {display} must be a JSON object, got {type(doc).__name__}"
                )
            continue
        if not any(k in doc for k in HASH_FIELDS):
            continue

        file_diffs: dict[str, tuple[str, str]] = {}
        for field in HASH_FIELDS:
            if field not in doc:
                continue
            dmode = _defect_mode(case_name, name, field)
            if dmode == "preserve":
                continue
            want = expected_map[field]
            if dmode == "trailing_newline":
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
                changes.append((display, file_diffs))
                if write:
                    _atomic_write_at(dfd, name, new_bytes, mode, display)


def _optional_local_hash(dfd: int, name: str, dir_path: Path, default_hash: str, jcs_dumps) -> str:
    display = dir_path / name
    try:
        raw, _ = _read_regular_file_at(dfd, name, display)
    except FileNotFoundError:
        return default_hash
    return canonical_sha256(json.loads(raw.decode("utf-8")), jcs_dumps)


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
    jcs_dumps = _load_bundled_jcs_dumps()
    changes: list[tuple[Path, dict[str, tuple[str, str]]]] = []

    examples_path = root / "examples"
    root_fd = _open_root_dir_fd(root)
    examples_fd = -1
    broken_fd = -1
    try:
        try:
            examples_fd = _open_child_dir_fd("examples", root_fd, examples_path)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"missing examples directory: {examples_path}") from exc

        top_base_raw, _ = _read_regular_file_at(
            examples_fd, "goal-file-baseline.json", examples_path / "goal-file-baseline.json"
        )
        top_prop_raw, _ = _read_regular_file_at(
            examples_fd, "goal-file.json", examples_path / "goal-file.json"
        )
        top_baseline_hash = canonical_sha256(json.loads(top_base_raw.decode("utf-8")), jcs_dumps)
        top_proposed_hash = canonical_sha256(json.loads(top_prop_raw.decode("utf-8")), jcs_dumps)

        _process_dir_fd(
            examples_fd,
            examples_path,
            case_name=None,
            skip_names=frozenset({"goal-file.json", "goal-file-baseline.json", "host_specific.json"}),
            exp_base=top_baseline_hash,
            exp_prop=top_proposed_hash,
            jcs_dumps=jcs_dumps,
            write=write,
            changes=changes,
        )

        broken_path = examples_path / "broken"
        try:
            broken_fd = _open_child_dir_fd("broken", examples_fd, broken_path)
        except FileNotFoundError:
            broken_fd = -1

        if broken_fd >= 0:
            for entry_name in sorted(os.listdir(broken_fd)):
                entry_display = broken_path / entry_name
                st = os.lstat(entry_name, dir_fd=broken_fd)
                if stat.S_ISLNK(st.st_mode):
                    raise ValueError(f"refusing symlink entry in examples/broken: {entry_display}")
                if not stat.S_ISDIR(st.st_mode):
                    continue
                case_fd = _open_child_dir_fd(entry_name, broken_fd, entry_display)
                try:
                    case_base = _optional_local_hash(
                        case_fd, "goal-file-baseline.json", entry_display, top_baseline_hash, jcs_dumps
                    )
                    case_prop = _optional_local_hash(
                        case_fd, "goal-file.json", entry_display, top_proposed_hash, jcs_dumps
                    )
                    _process_dir_fd(
                        case_fd,
                        entry_display,
                        case_name=entry_name,
                        skip_names=frozenset({"goal-file.json", "goal-file-baseline.json"}),
                        exp_base=case_base,
                        exp_prop=case_prop,
                        jcs_dumps=jcs_dumps,
                        write=write,
                        changes=changes,
                    )
                finally:
                    os.close(case_fd)
    finally:
        if broken_fd >= 0:
            os.close(broken_fd)
        if examples_fd >= 0:
            os.close(examples_fd)
        os.close(root_fd)

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
            "run tools/recompute_goal_hashes.py to update",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
