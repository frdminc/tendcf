"""Pre-install wheel verifier, isolated plugin environment, and non-deduplicating entry-point scanner (#47).

Implements `docs/architecture/plugin-layout.md` §4 (Activation steps 2–3, 6), the #46/#48
adversary security requirements, and Fable R1 hardening (H1, M1, M2, M4, M6, M9, L3, L5, L6):
1. Verify BEFORE installing, reading each wheel ONCE into memory (zero TOCTOU, M1):
   - Wheels only (PEP 427 `.whl`; sdists refused), filename/dist-info tied to METADATA `Name`/`Version`.
   - Refuses `.pth`, `sitecustomize.py`, `usercustomize.py`, `.egg-link`, `.data/`, symlinks,
     traversal, duplicate/case-colliding ZIP members, and any top-level `tendcf`/`nix2cf` stem
     (including `.pyc` / `.so` / `.abi3.so`, L6).
   - Full `.dist-info/RECORD` SHA-256 verification and PEP 508 environment-marker evaluation
     for `Requires-Dist` transitive closure completeness (L5).
2. Install strictly into an isolated plugin environment (never `sys.prefix`, `tendcf/`, `tools/`,
   or `site-private`), refusing to overwrite non-empty non-plugin-env directories (M2), refusing
   cross-wheel file/version/SHA-256 collisions (M9), extracting strictly from in-memory verified
   wheel bytes, storing verified wheel copies in a shared SHA-256 wheel cache (M6) plus per-env
   `.verified-wheels/`, and verifying the staged dir BEFORE atomic promotion.
3. At load/verify time (H1): anchor every extracted file in `plugin_env` byte-for-byte to the
   SHA-256-verified pinned wheels, refuse ANY unlisted file or directory (including `__pycache__`
   and `.pyc`), verify receipt `plugin_set_digest(site_root=...)`, and scan `*.dist-info`
   without deduplication (never `importlib.metadata`).
"""

from __future__ import annotations

import base64
import configparser
import csv
import email.parser
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .plugin_manifest import (
    ALLOWED_ENTRY_POINT_GROUPS,
    FORBIDDEN_EXTERNAL_DISTRIBUTIONS,
    PluginManifestError,
    PluginPin,
    PluginReleaseManifest,
    SitePluginsConfig,
    normalize_dist_name,
    parse_wheel_filename_parts,
    read_regular_file_bytes,
    validate_wheel_filename,
)
from .plugins import RESERVED_PLUGIN_NAMES

MAX_WHEEL_BYTES = 50 * 1024 * 1024
MAX_WHEEL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_WHEEL_MEMBERS = 10_000

RECEIPT_FILENAME = ".tendcf-plugin-env.json"
RECEIPT_SCHEMA_VERSION = 1
VERIFIED_WHEELS_DIR = ".verified-wheels"

BASE_COMPILER_DISTRIBUTIONS: frozenset[str] = frozenset({"pyyaml", "jsonschema", "rfc8785"})

FORBIDDEN_TOPLEVEL_STEMS: frozenset[str] = frozenset({"tendcf", "nix2cf"})
FORBIDDEN_STARTUP_BASENAMES: frozenset[str] = frozenset({"sitecustomize.py", "usercustomize.py"})
FORBIDDEN_STARTUP_SUFFIXES: tuple[str, ...] = (".pth", ".egg-link")

FORBIDDEN_EP_GROUPS: frozenset[str] = frozenset({"tendcf.supervisors"})
PUBLIC_EP_GROUPS: frozenset[str] = frozenset(ALLOWED_ENTRY_POINT_GROUPS.values())

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_MARKER_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lparen>\() |
        (?P<rparen>\)) |
        (?P<op>===|==|!=|<=|>=|<|>|not\s+in\b|in\b|and\b|or\b) |
        (?P<str>'[^']*'|"[^"]*") |
        (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
    )""",
    re.VERBOSE,
)


class PluginEnvError(Exception):
    """Wheel verification, isolated environment staging, or entry-point discovery failed closed."""


@dataclass(frozen=True)
class VerifiedWheel:
    path: Path
    filename: str
    distribution: str
    normalized_distribution: str
    version: str
    sha256: str
    dist_info_dir: str
    requires_dist: tuple[str, ...]
    ep_map: dict[str, dict[str, str]]  # group -> {name -> module:attr}
    raw_bytes: bytes
    member_bytes: dict[str, bytes]


@dataclass(frozen=True)
class DiscoveredEntryPoint:
    group: str
    name: str
    value: str  # module:attr
    distribution: str
    version: str
    dist_info_dir: str


def _record_sha256_b64(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_entry_points_strict(text: str, *, context: str) -> dict[str, dict[str, str]]:
    """Parse PEP 621 / importlib `entry_points.txt` refusing duplicate sections or duplicate keys."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = lambda optionstr: optionstr  # type: ignore[assignment]
    try:
        parser.read_string(text, source=context)
    except configparser.Error as exc:
        raise PluginEnvError(f"{context}: invalid or duplicate entry_points.txt: {exc}") from exc
    out: dict[str, dict[str, str]] = {}
    for section in parser.sections():
        sec_map: dict[str, str] = {}
        for key, val in parser.items(section):
            k = key.strip()
            v = val.strip()
            if not k or not v:
                raise PluginEnvError(f"{context}: empty entry point in [{section}]")
            if k in sec_map:
                raise PluginEnvError(f"{context}: duplicate entry point {k!r} in [{section}]")
            sec_map[k] = v
        out[section.strip()] = sec_map
    return out


def _check_member_path(name: str, *, wheel_name: str) -> list[str]:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise PluginEnvError(f"wheel {wheel_name}: unsafe archive member path {name!r}")
    parts = [p for p in name.split("/") if p != ""]
    if not parts or any(p in (".", "..") for p in parts):
        raise PluginEnvError(f"wheel {wheel_name}: path traversal member {name!r}")
    if ":" in parts[0]:
        raise PluginEnvError(f"wheel {wheel_name}: drive-prefixed member {name!r}")

    # Refuse __pycache__ / .pyc / .pyo inside wheels so only verified source runs (H1).
    for part in parts:
        if part.lower() == "__pycache__":
            raise PluginEnvError(f"wheel {wheel_name}: precompiled __pycache__ entry refused: {name!r}")
    basename_lower = parts[-1].lower()
    if basename_lower.endswith((".pyc", ".pyo")):
        raise PluginEnvError(f"wheel {wheel_name}: precompiled bytecode file refused: {name!r}")
    if basename_lower in FORBIDDEN_STARTUP_BASENAMES or basename_lower.endswith(FORBIDDEN_STARTUP_SUFFIXES):
        raise PluginEnvError(
            f"wheel {wheel_name}: forbidden startup hook file {name!r} "
            "(.pth / sitecustomize.py / usercustomize.py / .egg-link are unconditionally refused)"
        )

    # L6: forbid ANY top-level member whose stem before the first dot is `tendcf` or `nix2cf`
    # (catches tendcf/, tendcf.py, tendcf.pyc, tendcf.cpython-*.so, tendcf.abi3.so, nix2cf.*).
    top_lower = parts[0].lower()
    top_stem = top_lower.split(".", 1)[0]
    if top_stem in FORBIDDEN_TOPLEVEL_STEMS:
        raise PluginEnvError(
            f"wheel {wheel_name}: dependency-confusion attempt — forbidden top-level tendcf/nix2cf entry {name!r}"
        )
    if top_lower.endswith(".dist-info"):
        dist_prefix = top_lower[: -len(".dist-info")].split("-", 1)[0]
        if normalize_dist_name(dist_prefix) in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
            raise PluginEnvError(
                f"wheel {wheel_name}: dependency-confusion attempt — forbidden dist-info {parts[0]!r}"
            )
    if top_lower.endswith(".data"):
        raise PluginEnvError(
            f"wheel {wheel_name}: .data/ wheel scheme entry refused ({name!r}); pure-wheel top-level layout required"
        )
    return parts


# --- Minimal PEP 508 environment marker evaluator (L5) ---

def _pep508_env() -> dict[str, str]:
    vi = sys.version_info
    py_ver = f"{vi.major}.{vi.minor}"
    py_full = f"{vi.major}.{vi.minor}.{vi.micro}"
    return {
        "os_name": os.name,
        "sys_platform": sys.platform,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_version": py_ver,
        "python_full_version": py_full,
        "implementation_name": sys.implementation.name,
        "implementation_version": py_full,
        "extra": "",  # Evaluating with NO optional extras active.
    }


def _ver_tuple(s: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", s)]
    return tuple(nums) if nums else (0,)


def _marker_is_active_without_extra(expr: str, *, context: str) -> bool:
    """Evaluate a PEP 508 marker expression with `extra == ''`. Fail closed (True) on unknown markers."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    n = len(expr)
    while pos < n:
        if expr[pos].isspace():
            pos += 1
            continue
        m = _MARKER_TOKEN_RE.match(expr, pos)
        if not m:
            raise PluginEnvError(f"{context}: cannot parse PEP 508 marker {expr!r} at offset {pos}")
        kind = m.lastgroup or ""
        val = m.group(kind)
        tokens.append((kind, re.sub(r"\s+", " ", val)))
        pos = m.end()

    env = _pep508_env()
    idx = 0

    def parse_or() -> bool:
        nonlocal idx
        left = parse_and()
        while idx < len(tokens) and tokens[idx] == ("op", "or"):
            idx += 1
            right = parse_and()
            left = left or right
        return left

    def parse_and() -> bool:
        nonlocal idx
        left = parse_atom()
        while idx < len(tokens) and tokens[idx] == ("op", "and"):
            idx += 1
            right = parse_atom()
            left = left and right
        return left

    def resolve_val() -> tuple[str, bool]:
        nonlocal idx
        if idx >= len(tokens):
            raise PluginEnvError(f"{context}: unexpected end of PEP 508 marker {expr!r}")
        kind, val = tokens[idx]
        idx += 1
        if kind == "str":
            return val[1:-1], False
        if kind == "ident":
            if val not in env:
                raise PluginEnvError(f"{context}: unknown PEP 508 marker variable {val!r}")
            return env[val], val in ("python_version", "python_full_version", "implementation_version")
        raise PluginEnvError(f"{context}: unexpected token {val!r} in PEP 508 marker {expr!r}")

    def parse_atom() -> bool:
        nonlocal idx
        if idx >= len(tokens):
            raise PluginEnvError(f"{context}: unexpected end of PEP 508 marker {expr!r}")
        if tokens[idx][0] == "lparen":
            idx += 1
            val = parse_or()
            if idx >= len(tokens) or tokens[idx][0] != "rparen":
                raise PluginEnvError(f"{context}: unmatched '(' in PEP 508 marker {expr!r}")
            idx += 1
            return val
        lhs, lhs_ver = resolve_val()
        if idx >= len(tokens) or tokens[idx][0] != "op":
            raise PluginEnvError(f"{context}: expected comparison operator in PEP 508 marker {expr!r}")
        op = tokens[idx][1]
        idx += 1
        rhs, rhs_ver = resolve_val()
        is_ver = lhs_ver or rhs_ver
        if op in ("==", "==="):
            return _ver_tuple(lhs) == _ver_tuple(rhs) if is_ver else lhs == rhs
        if op == "!=":
            return _ver_tuple(lhs) != _ver_tuple(rhs) if is_ver else lhs != rhs
        if op == "<":
            return _ver_tuple(lhs) < _ver_tuple(rhs) if is_ver else lhs < rhs
        if op == "<=":
            return _ver_tuple(lhs) <= _ver_tuple(rhs) if is_ver else lhs <= rhs
        if op == ">":
            return _ver_tuple(lhs) > _ver_tuple(rhs) if is_ver else lhs > rhs
        if op == ">=":
            return _ver_tuple(lhs) >= _ver_tuple(rhs) if is_ver else lhs >= rhs
        if op == "in":
            return lhs in rhs
        if op == "not in":
            return lhs not in rhs
        raise PluginEnvError(f"{context}: unsupported operator {op!r} in PEP 508 marker {expr!r}")

    res = parse_or()
    if idx != len(tokens):
        raise PluginEnvError(f"{context}: trailing tokens in PEP 508 marker {expr!r}")
    return res


def _parse_active_requires_dist(headers: list[str], *, wheel_name: str) -> list[str]:
    """Return normalized distribution names for all active (non-extra) Requires-Dist entries (L5)."""
    out: list[str] = []
    for raw in headers:
        req_part, sep, marker_part = raw.partition(";")
        if sep and marker_part.strip():
            if not _marker_is_active_without_extra(marker_part.strip(), context=f"wheel {wheel_name}"):
                continue
        m = _REQ_NAME_RE.match(req_part)
        if not m:
            raise PluginEnvError(f"wheel {wheel_name}: cannot parse Requires-Dist header {raw!r}")
        out.append(normalize_dist_name(m.group(1)))
    return out


def verify_wheel_bytes(
    raw_bytes: bytes,
    *,
    source_path: Path,
    expected_filename: str,
    expected_sha256: str,
    expected_distribution: str,
    expected_version: str,
    is_plugin_wheel: bool,
    expected_entry_point_group: str | None = None,
    expected_plugin_name: str | None = None,
    expected_entry_point: str | None = None,
) -> VerifiedWheel:
    """Cryptographically verify a `.whl` completely from in-memory bytes (zero TOCTOU, M1)."""
    try:
        validate_wheel_filename(expected_filename, label="expected wheel filename")
        fn_dist, fn_ver = parse_wheel_filename_parts(expected_filename)
    except PluginManifestError as exc:
        raise PluginEnvError(str(exc)) from exc

    norm_expected_dist = normalize_dist_name(expected_distribution)
    if norm_expected_dist in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
        raise PluginEnvError(f"refused external wheel for reserved distribution {expected_distribution!r}")
    if fn_dist != norm_expected_dist or fn_ver != expected_version:
        raise PluginEnvError(
            f"wheel filename {expected_filename!r} disagrees with distribution={expected_distribution!r} version={expected_version!r}"
        )

    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha != expected_sha256:
        raise PluginEnvError(
            f"wheel {expected_filename} SHA-256 mismatch: got {actual_sha}, expected {expected_sha256}"
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes), "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise PluginEnvError(f"wheel {expected_filename} is not a valid ZIP archive: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_WHEEL_MEMBERS:
            raise PluginEnvError(f"wheel {expected_filename} has too many archive members ({len(infos)})")

        seen_exact: set[str] = set()
        seen_lower: set[str] = set()
        total_uncompressed = 0
        dist_info_dirs: set[str] = set()
        file_bytes: dict[str, bytes] = {}

        for info in infos:
            member_name = info.filename
            if member_name in seen_exact:
                raise PluginEnvError(f"wheel {expected_filename}: duplicate ZIP entry {member_name!r}")
            seen_exact.add(member_name)
            lower_name = member_name.lower()
            if lower_name in seen_lower:
                raise PluginEnvError(
                    f"wheel {expected_filename}: case-colliding ZIP entry {member_name!r} (unsafe on APFS)"
                )
            seen_lower.add(lower_name)

            unix_mode = info.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                raise PluginEnvError(f"wheel {expected_filename}: symlink ZIP member refused: {member_name!r}")

            if info.is_dir():
                parts = _check_member_path(member_name.rstrip("/"), wheel_name=expected_filename)
                if parts[0].endswith(".dist-info"):
                    dist_info_dirs.add(parts[0])
                continue

            parts = _check_member_path(member_name, wheel_name=expected_filename)
            if parts[0].endswith(".dist-info"):
                dist_info_dirs.add(parts[0])

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_WHEEL_UNCOMPRESSED_BYTES:
                raise PluginEnvError(
                    f"wheel {expected_filename}: uncompressed size exceeds {MAX_WHEEL_UNCOMPRESSED_BYTES} bytes"
                )
            try:
                data = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, OSError) as exc:
                raise PluginEnvError(
                    f"wheel {expected_filename}: failed to read member {member_name!r}: {exc}"
                ) from exc
            if len(data) != info.file_size:
                raise PluginEnvError(f"wheel {expected_filename}: member {member_name!r} size header mismatch")
            file_bytes[member_name] = data

    if len(dist_info_dirs) != 1:
        raise PluginEnvError(
            f"wheel {expected_filename}: expected exactly one .dist-info directory (found {sorted(dist_info_dirs)})"
        )
    dist_info = next(iter(dist_info_dirs))

    # Note 3: tie .dist-info directory name to METADATA Name and Version.
    di_stem = dist_info[: -len(".dist-info")]
    di_dist_raw, di_sep, di_ver = di_stem.rpartition("-")
    if not di_sep or normalize_dist_name(di_dist_raw) != norm_expected_dist or di_ver != expected_version:
        raise PluginEnvError(
            f"wheel {expected_filename}: dist-info dir {dist_info!r} does not match "
            f"distribution={expected_distribution!r} version={expected_version!r}"
        )

    metadata_key = f"{dist_info}/METADATA"
    wheel_meta_key = f"{dist_info}/WHEEL"
    record_key = f"{dist_info}/RECORD"
    for req_key in (metadata_key, wheel_meta_key, record_key):
        if req_key not in file_bytes:
            raise PluginEnvError(f"wheel {expected_filename}: missing required {req_key}")

    try:
        record_text = file_bytes[record_key].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PluginEnvError(f"wheel {expected_filename}: RECORD is not UTF-8: {exc}") from exc

    record_entries: dict[str, tuple[str, str]] = {}
    for row_num, row in enumerate(csv.reader(io.StringIO(record_text)), start=1):
        if not row:
            continue
        if len(row) != 3:
            raise PluginEnvError(f"wheel {expected_filename}: malformed RECORD row {row_num} ({row!r})")
        rec_path, rec_hash, rec_size = row
        if rec_path in record_entries:
            raise PluginEnvError(f"wheel {expected_filename}: duplicate RECORD entry {rec_path!r}")
        record_entries[rec_path] = (rec_hash, rec_size)

    for member_name, data in file_bytes.items():
        if member_name == record_key:
            continue
        if member_name not in record_entries:
            raise PluginEnvError(
                f"wheel {expected_filename}: archive member {member_name!r} is missing from RECORD"
            )
        rec_hash, rec_size = record_entries[member_name]
        if not rec_hash.startswith("sha256="):
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD entry {member_name!r} must use sha256= digest (got {rec_hash!r})"
            )
        if rec_hash != _record_sha256_b64(data):
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD SHA-256 mismatch for {member_name!r}"
            )
        if rec_size != str(len(data)):
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD byte length mismatch for {member_name!r}"
            )
    for rec_path in record_entries:
        if rec_path != record_key and rec_path not in file_bytes:
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD lists missing archive member {rec_path!r}"
            )

    try:
        meta_msg = email.parser.Parser().parsestr(file_bytes[metadata_key].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PluginEnvError(f"wheel {expected_filename}: METADATA is not UTF-8: {exc}") from exc

    meta_name = (meta_msg.get("Name") or "").strip()
    meta_ver = (meta_msg.get("Version") or "").strip()
    if normalize_dist_name(meta_name) != norm_expected_dist:
        raise PluginEnvError(
            f"wheel {expected_filename}: METADATA Name {meta_name!r} does not match expected {expected_distribution!r}"
        )
    if meta_ver != expected_version:
        raise PluginEnvError(
            f"wheel {expected_filename}: METADATA Version {meta_ver!r} does not match expected {expected_version!r}"
        )
    req_headers = meta_msg.get_all("Requires-Dist") or []
    active_reqs = tuple(_parse_active_requires_dist(req_headers, wheel_name=expected_filename))

    ep_key = f"{dist_info}/entry_points.txt"
    parsed_eps: dict[str, dict[str, str]] = {}
    if ep_key in file_bytes:
        try:
            ep_text = file_bytes[ep_key].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PluginEnvError(f"wheel {expected_filename}: entry_points.txt is not UTF-8: {exc}") from exc
        parsed_eps = _parse_entry_points_strict(ep_text, context=f"{expected_filename}:{ep_key}")

    for forbidden_group in FORBIDDEN_EP_GROUPS:
        if forbidden_group in parsed_eps:
            raise PluginEnvError(
                f"wheel {expected_filename}: forbidden entry-point group [{forbidden_group}] "
                "(supervisor renderers are in-tree only)"
            )

    for grp in PUBLIC_EP_GROUPS:
        kind = "frontend" if grp == "tendcf.frontends" else "importer"
        for ep_name in parsed_eps.get(grp, {}):
            if ep_name in RESERVED_PLUGIN_NAMES.get(kind, frozenset()):
                raise PluginEnvError(
                    f"wheel {expected_filename}: entry point {ep_name!r} in [{grp}] claims reserved built-in name"
                )

    if is_plugin_wheel:
        assert expected_entry_point_group is not None
        assert expected_plugin_name is not None
        assert expected_entry_point is not None
        grp_eps = parsed_eps.get(expected_entry_point_group, {})
        if expected_plugin_name not in grp_eps:
            raise PluginEnvError(
                f"wheel {expected_filename}: missing entry point {expected_plugin_name!r} in "
                f"[{expected_entry_point_group}] (found: {sorted(grp_eps)})"
            )
        if grp_eps[expected_plugin_name] != expected_entry_point:
            raise PluginEnvError(
                f"wheel {expected_filename}: entry point {expected_plugin_name!r} is "
                f"{grp_eps[expected_plugin_name]!r}, expected {expected_entry_point!r}"
            )
    else:
        for grp in PUBLIC_EP_GROUPS:
            if grp in parsed_eps:
                raise PluginEnvError(
                    f"dependency wheel {expected_filename}: must not register tendcf entry points in [{grp}]"
                )

    return VerifiedWheel(
        path=source_path,
        filename=expected_filename,
        distribution=meta_name,
        normalized_distribution=norm_expected_dist,
        version=meta_ver,
        sha256=actual_sha,
        dist_info_dir=dist_info,
        requires_dist=active_reqs,
        ep_map=parsed_eps,
        raw_bytes=raw_bytes,
        member_bytes=file_bytes,
    )


def verify_wheel_artifact(
    wheel_path: Path,
    *,
    expected_filename: str,
    expected_sha256: str,
    expected_distribution: str,
    expected_version: str,
    is_plugin_wheel: bool,
    expected_entry_point_group: str | None = None,
    expected_plugin_name: str | None = None,
    expected_entry_point: str | None = None,
    allow_arbitrary_basename: bool = False,
) -> VerifiedWheel:
    """Read a `.whl` file ONCE via `O_NOFOLLOW` and verify it completely in memory."""
    if not allow_arbitrary_basename and wheel_path.name != expected_filename:
        raise PluginEnvError(
            f"wheel filename mismatch: got {wheel_path.name!r}, expected {expected_filename!r}"
        )
    try:
        raw_bytes = read_regular_file_bytes(
            wheel_path, max_bytes=MAX_WHEEL_BYTES, label=f"wheel {expected_filename}"
        )
    except PluginManifestError as exc:
        raise PluginEnvError(str(exc)) from exc
    return verify_wheel_bytes(
        raw_bytes,
        source_path=wheel_path.resolve(strict=True),
        expected_filename=expected_filename,
        expected_sha256=expected_sha256,
        expected_distribution=expected_distribution,
        expected_version=expected_version,
        is_plugin_wheel=is_plugin_wheel,
        expected_entry_point_group=expected_entry_point_group,
        expected_plugin_name=expected_plugin_name,
        expected_entry_point=expected_entry_point,
    )


def verify_release_wheels(
    manifest: PluginReleaseManifest,
    wheel_dir: Path,
) -> tuple[VerifiedWheel, tuple[VerifiedWheel, ...]]:
    """Verify the plugin wheel and full transitive dependency wheel closure BEFORE installation."""
    try:
        st_dir = os.lstat(wheel_dir)
    except OSError as exc:
        raise PluginEnvError(f"cannot inspect wheel directory {wheel_dir}: {exc}") from exc
    if stat.S_ISLNK(st_dir.st_mode) or not stat.S_ISDIR(st_dir.st_mode):
        raise PluginEnvError(f"wheel directory must be a real non-symlink directory: {wheel_dir}")
    resolved_dir = wheel_dir.resolve(strict=True)

    plugin_whl = verify_wheel_artifact(
        resolved_dir / manifest.wheel_filename,
        expected_filename=manifest.wheel_filename,
        expected_sha256=manifest.wheel_sha256,
        expected_distribution=manifest.distribution,
        expected_version=manifest.version,
        is_plugin_wheel=True,
        expected_entry_point_group=manifest.entry_point_group,
        expected_plugin_name=manifest.name,
        expected_entry_point=manifest.entry_point,
    )

    dep_wheels: list[VerifiedWheel] = []
    for dep in manifest.dependencies:
        dep_wheels.append(
            verify_wheel_artifact(
                resolved_dir / dep.filename,
                expected_filename=dep.filename,
                expected_sha256=dep.sha256,
                expected_distribution=dep.distribution,
                expected_version=dep.version,
                is_plugin_wheel=False,
            )
        )

    available_dists = (
        {plugin_whl.normalized_distribution}
        | {dw.normalized_distribution for dw in dep_wheels}
        | BASE_COMPILER_DISTRIBUTIONS
        | {"tendcf"}
    )
    for whl in (plugin_whl, *dep_wheels):
        missing = sorted(req for req in whl.requires_dist if req not in available_dists)
        if missing:
            raise PluginEnvError(
                f"incomplete transitive dependency closure: wheel {whl.filename} requires {missing}, "
                "which are not pinned in plugin-release.json dependencies[] (nor base compiler deps)"
            )

    return plugin_whl, tuple(dep_wheels)


def assert_isolated_plugin_env_path(
    plugin_env: Path,
    *,
    tendcf_root: Path | None = None,
    site_root: Path | None = None,
) -> Path:
    """Fail closed if `plugin_env` overlaps sys.prefix, gate/tools, tendcf checkout, or site-private."""
    if not str(plugin_env).strip() or "\x00" in str(plugin_env):
        raise PluginEnvError("plugin environment path must not be empty or contain NUL bytes")
    if ".." in plugin_env.parts:
        raise PluginEnvError(f"plugin environment path must not contain '..' segments: {plugin_env}")
    if plugin_env.is_symlink():
        raise PluginEnvError(f"plugin environment path must not be a symlink: {plugin_env}")

    resolved_env = plugin_env.resolve(strict=False)

    forbidden_roots: list[tuple[str, Path]] = [
        ("sys.prefix (active Python / gate environment)", Path(sys.prefix).resolve()),
        ("sys.base_prefix (base Python environment)", Path(sys.base_prefix).resolve()),
    ]
    if tendcf_root is not None:
        tr = tendcf_root.resolve()
        forbidden_roots.append(("tendcf checkout root", tr))
        forbidden_roots.append(("tendcf gate/tools directory", (tr / "tools").resolve()))
    if site_root is not None:
        forbidden_roots.append(("site-private git checkout", site_root.resolve()))

    for label, forbidden in forbidden_roots:
        if (
            resolved_env == forbidden
            or resolved_env.is_relative_to(forbidden)
            or forbidden.is_relative_to(resolved_env)
        ):
            raise PluginEnvError(
                f"plugin environment {resolved_env} overlaps forbidden {label} ({forbidden}); "
                "third-party plugins must install strictly into an isolated plugin environment"
            )
    return resolved_env


def default_plugin_env_dir(state_dir: Path, site_slug: str, plugin_set_digest: str) -> Path:
    """Default XDG isolated plugin environment directory keyed by site slug and plugin_set_digest."""
    return state_dir / "plugin-envs" / site_slug / plugin_set_digest[:16]


def default_wheel_cache_dir(state_dir: Path) -> Path:
    """Shared content-addressed wheel cache keyed strictly by wheel SHA-256 (M6)."""
    return state_dir / "wheel-cache"


def _cached_wheel_filename(sha256: str, filename: str) -> str:
    return f"{sha256}-{filename}"


def _assert_safe_to_replace_env_dir(resolved_env: Path) -> None:
    """Refuse to overwrite/delete an existing non-empty directory that is not a tendcf plugin env (M2)."""
    if not resolved_env.exists():
        return
    if resolved_env.is_symlink() or not resolved_env.is_dir():
        raise PluginEnvError(f"refusing to replace non-directory or symlink path: {resolved_env}")
    try:
        entries = list(os.scandir(resolved_env))
    except OSError as exc:
        raise PluginEnvError(f"cannot inspect existing plugin environment {resolved_env}: {exc}") from exc
    if not entries:
        return
    receipt_path = resolved_env / RECEIPT_FILENAME
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise PluginEnvError(
            f"refusing to overwrite non-empty directory {resolved_env} that is not a tendcf plugin "
            f"environment (missing {RECEIPT_FILENAME})"
        )
    try:
        raw = read_regular_file_bytes(receipt_path, max_bytes=MAX_WHEEL_BYTES, label="existing plugin env receipt")
        data = json.loads(raw.decode("utf-8"))
    except (PluginManifestError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginEnvError(
            f"refusing to overwrite directory {resolved_env} with invalid {RECEIPT_FILENAME}: {exc}"
        ) from exc
    if not isinstance(data, dict) or data.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise PluginEnvError(
            f"refusing to overwrite directory {resolved_env}: unrecognized {RECEIPT_FILENAME} schema"
        )


def _extract_verified_wheel_bytes(wheel: VerifiedWheel, target_dir: Path) -> None:
    """Extract strictly from in-memory verified `wheel.member_bytes` refusing cross-wheel overwrites (M1, M9)."""
    for member, data in sorted(wheel.member_bytes.items()):
        parts = _check_member_path(member, wheel_name=wheel.filename)
        dest = target_dir.joinpath(*parts)
        resolved_dest = dest.resolve(strict=False)
        if not resolved_dest.is_relative_to(target_dir):
            raise PluginEnvError(f"wheel {wheel.filename}: member {member!r} escapes {target_dir}")
        if dest.exists() or dest.is_symlink():
            raise PluginEnvError(
                f"cross-wheel file collision while extracting {wheel.filename}: {member!r} already exists"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)


def _collect_expected_pins_checked(
    config: SitePluginsConfig,
) -> list[tuple[str, str, str, str, bool, str | None, str | None, str | None]]:
    """Collect deduplicated wheel specs across all out-of-tree pins, refusing SHA-256/version conflicts (M9)."""
    # Maps for conflict detection across pins.
    by_filename: dict[str, str] = {}  # filename -> sha256
    by_dist: dict[str, tuple[str, str, str]] = {}  # norm_dist -> (version, sha256, filename)
    out: list[tuple[str, str, str, str, bool, str | None, str | None, str | None]] = []
    seen_key: set[tuple[str, str]] = set()  # (filename, sha256)

    def _register(
        dist: str,
        version: str,
        filename: str,
        sha256: str,
        is_plugin: bool,
        ep_group: str | None = None,
        plugin_name: str | None = None,
        ep_val: str | None = None,
    ) -> None:
        norm_d = normalize_dist_name(dist)
        if filename in by_filename and by_filename[filename] != sha256:
            raise PluginEnvError(
                f"cross-pin wheel collision: filename {filename!r} pinned with conflicting SHA-256 digests "
                f"({by_filename[filename]} vs {sha256})"
            )
        if norm_d in by_dist:
            prev_ver, prev_sha, prev_fn = by_dist[norm_d]
            if prev_ver != version or prev_sha != sha256:
                raise PluginEnvError(
                    f"cross-pin distribution conflict for {dist!r}: "
                    f"{prev_ver} ({prev_sha[:12]}, {prev_fn}) vs {version} ({sha256[:12]}, {filename})"
                )
        by_filename[filename] = sha256
        by_dist[norm_d] = (version, sha256, filename)
        if (filename, sha256) not in seen_key:
            seen_key.add((filename, sha256))
            out.append((dist, version, filename, sha256, is_plugin, ep_group, plugin_name, ep_val))

    for pin in sorted(config.plugins, key=lambda p: (p.kind, p.name)):
        if pin.source != "out-of-tree":
            continue
        assert pin.distribution and pin.version and pin.wheel_filename and pin.wheel_sha256 and pin.entry_point
        _register(
            pin.distribution,
            pin.version,
            pin.wheel_filename,
            pin.wheel_sha256,
            True,
            pin.entry_point_group,
            pin.name,
            pin.entry_point,
        )
        for dep in pin.dependencies:
            _register(dep.distribution, dep.version, dep.filename, dep.sha256, False)
    return out


def stage_plugin_env(
    plugin_env: Path,
    *,
    config: SitePluginsConfig,
    verified_wheels: list[VerifiedWheel],
    tendcf_root: Path | None = None,
    site_root: Path | None = None,
    wheel_cache_dir: Path | None = None,
    wheel_search_dirs: list[Path] | None = None,
) -> Path:
    """Atomically populate an isolated plugin environment strictly from in-memory verified wheels (H1/M1/M2/M6/M9)."""
    resolved_env = assert_isolated_plugin_env_path(
        plugin_env, tendcf_root=tendcf_root, site_root=site_root
    )
    _assert_safe_to_replace_env_dir(resolved_env)
    resolved_env.parent.mkdir(parents=True, exist_ok=True)
    if resolved_env.parent.is_symlink():
        raise PluginEnvError(f"plugin environment parent must not be a symlink: {resolved_env.parent}")

    # Index freshly verified wheels by (filename, sha256) so conflicting hashes can NEVER alias (M9).
    by_fn_sha: dict[tuple[str, str], VerifiedWheel] = {
        (w.filename, w.sha256): w for w in verified_wheels
    }

    existing_env_cache = resolved_env / VERIFIED_WHEELS_DIR
    specs = _collect_expected_pins_checked(config)

    all_needed: list[VerifiedWheel] = []
    for dist, version, filename, sha256, is_plugin, ep_group, plugin_name, ep_val in specs:
        if (filename, sha256) in by_fn_sha:
            all_needed.append(by_fn_sha[(filename, sha256)])
            continue

        # Search: 1) existing env's .verified-wheels/<sha256>-<filename>, 2) shared SHA-256 wheel cache (M6),
        # 3) optional explicit wheel_search_dirs (e.g. `tendcf plugin restage --wheel-dir`).
        found: VerifiedWheel | None = None
        candidates: list[tuple[Path, bool]] = []
        if existing_env_cache.is_dir() and not existing_env_cache.is_symlink():
            candidates.append((existing_env_cache / _cached_wheel_filename(sha256, filename), True))
            candidates.append((existing_env_cache / filename, False))
        if wheel_cache_dir is not None and wheel_cache_dir.is_dir() and not wheel_cache_dir.is_symlink():
            candidates.append((wheel_cache_dir / f"{sha256}.whl", True))
        for sdir in wheel_search_dirs or []:
            if sdir.is_dir() and not sdir.is_symlink():
                candidates.append((sdir / filename, False))

        for cand_path, allow_arb in candidates:
            if not cand_path.exists() and not cand_path.is_symlink():
                continue
            found = verify_wheel_artifact(
                cand_path,
                expected_filename=filename,
                expected_sha256=sha256,
                expected_distribution=dist,
                expected_version=version,
                is_plugin_wheel=is_plugin,
                expected_entry_point_group=ep_group,
                expected_plugin_name=plugin_name,
                expected_entry_point=ep_val,
                allow_arbitrary_basename=allow_arb,
            )
            break

        if found is None:
            raise PluginEnvError(
                f"missing verified wheel {filename!r} (sha256={sha256[:12]}) for {dist}=={version}; "
                "supply --wheel-dir or re-stage from a populated wheel cache"
            )
        all_needed.append(found)

    # Persist verified wheel copies into shared SHA-256 cache (atomic write, M6).
    if wheel_cache_dir is not None:
        if wheel_cache_dir.is_symlink():
            raise PluginEnvError(f"wheel cache directory must not be a symlink: {wheel_cache_dir}")
        wheel_cache_dir.mkdir(parents=True, exist_ok=True)
        for whl in all_needed:
            dest_cache = wheel_cache_dir / f"{whl.sha256}.whl"
            if dest_cache.is_symlink():
                raise PluginEnvError(f"wheel cache entry must not be a symlink: {dest_cache}")
            if not dest_cache.exists():
                fd, tmp_c = tempfile.mkstemp(prefix=".whl.", suffix=".tmp", dir=str(wheel_cache_dir))
                try:
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(whl.raw_bytes)
                        fh.flush()
                    os.chmod(tmp_c, 0o600)
                    os.replace(tmp_c, dest_cache)
                except BaseException:
                    Path(tmp_c).unlink(missing_ok=True)
                    raise

    stage_dir = Path(tempfile.mkdtemp(prefix=".plugin-env-stage.", dir=str(resolved_env.parent)))
    os.chmod(stage_dir, 0o700)
    try:
        stage_wheels_cache = stage_dir / VERIFIED_WHEELS_DIR
        stage_wheels_cache.mkdir(mode=0o700)
        seen_dist_infos: set[str] = set()
        receipt_wheels: list[dict[str, Any]] = []
        for whl in all_needed:
            if whl.dist_info_dir in seen_dist_infos:
                raise PluginEnvError(
                    f"duplicate dist-info directory {whl.dist_info_dir!r} while staging plugin environment"
                )
            seen_dist_infos.add(whl.dist_info_dir)
            _extract_verified_wheel_bytes(whl, stage_dir)
            # Write cached wheel strictly from in-memory verified bytes (M1: zero re-open!).
            (stage_wheels_cache / _cached_wheel_filename(whl.sha256, whl.filename)).write_bytes(whl.raw_bytes)
            receipt_wheels.append(
                {
                    "filename": whl.filename,
                    "distribution": whl.distribution,
                    "normalized_distribution": whl.normalized_distribution,
                    "version": whl.version,
                    "sha256": whl.sha256,
                    "dist_info_dir": whl.dist_info_dir,
                }
            )

        receipt = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "plugin_set_digest": config.plugin_set_digest(site_root=site_root),
            "wheels": sorted(receipt_wheels, key=lambda w: (w["normalized_distribution"], w["version"])),
        }
        (stage_dir / RECEIPT_FILENAME).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        # M9: Verify the staged directory end-to-end BEFORE swapping it live or writing plugins.toml!
        discover_env_entry_points(
            stage_dir,
            config=config,
            tendcf_root=tendcf_root,
            site_root=site_root,
            check_releasable=True,
        )

        # Atomic swap (replace existing verified plugin env cleanly if present).
        backup_dir: Path | None = None
        if resolved_env.exists():
            backup_dir = Path(tempfile.mkdtemp(prefix=".plugin-env-old.", dir=str(resolved_env.parent)))
            backup_dir.rmdir()
            os.replace(resolved_env, backup_dir)
        try:
            os.replace(stage_dir, resolved_env)
        except BaseException:
            if backup_dir is not None and backup_dir.exists() and not resolved_env.exists():
                os.replace(backup_dir, resolved_env)
            raise
        if backup_dir is not None and backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
    except BaseException:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise

    return resolved_env


def _verify_on_disk_dist_info_record(env_dir: Path, dist_info_path: Path) -> tuple[str, str]:
    """Re-verify every file listed in `<dist_info>/RECORD` against actual on-disk bytes."""
    metadata_path = dist_info_path / "METADATA"
    record_path = dist_info_path / "RECORD"
    if not metadata_path.is_file() or metadata_path.is_symlink():
        raise PluginEnvError(f"staged dist-info missing real METADATA: {dist_info_path}")
    if not record_path.is_file() or record_path.is_symlink():
        raise PluginEnvError(f"staged dist-info missing real RECORD: {dist_info_path}")

    try:
        meta_bytes = read_regular_file_bytes(metadata_path, max_bytes=MAX_WHEEL_BYTES, label="staged METADATA")
        meta_msg = email.parser.Parser().parsestr(meta_bytes.decode("utf-8"))
        rec_bytes = read_regular_file_bytes(record_path, max_bytes=MAX_WHEEL_BYTES, label="staged RECORD")
        rec_text = rec_bytes.decode("utf-8")
    except (PluginManifestError, UnicodeDecodeError) as exc:
        raise PluginEnvError(f"invalid staged dist-info in {dist_info_path}: {exc}") from exc

    dist_name = (meta_msg.get("Name") or "").strip()
    dist_ver = (meta_msg.get("Version") or "").strip()
    if not dist_name or not dist_ver:
        raise PluginEnvError(f"staged METADATA missing Name or Version: {metadata_path}")
    if normalize_dist_name(dist_name) in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
        raise PluginEnvError(
            f"dependency-confusion attempt in staged plugin env: forbidden distribution {dist_name!r}"
        )

    record_rel = f"{dist_info_path.name}/RECORD"
    for row_num, row in enumerate(csv.reader(io.StringIO(rec_text)), start=1):
        if not row:
            continue
        if len(row) != 3:
            raise PluginEnvError(f"malformed staged RECORD row {row_num} in {record_path}")
        rec_file, rec_hash, rec_size = row
        if rec_file == record_rel:
            continue
        parts = _check_member_path(rec_file, wheel_name=dist_info_path.name)
        disk_path = env_dir.joinpath(*parts)
        if disk_path.is_symlink() or not disk_path.is_file():
            raise PluginEnvError(f"staged file missing or symlinked: {disk_path}")
        resolved = disk_path.resolve(strict=True)
        if not resolved.is_relative_to(env_dir):
            raise PluginEnvError(f"staged file escapes plugin env: {disk_path}")
        try:
            data = read_regular_file_bytes(resolved, max_bytes=MAX_WHEEL_BYTES, label=f"staged file {rec_file}")
        except PluginManifestError as exc:
            raise PluginEnvError(str(exc)) from exc
        if not rec_hash.startswith("sha256=") or _record_sha256_b64(data) != rec_hash:
            raise PluginEnvError(
                f"tampered file detected in isolated plugin env: {rec_file} fails RECORD SHA-256 check"
            )
        if rec_size != str(len(data)):
            raise PluginEnvError(
                f"tampered file detected in isolated plugin env: {rec_file} fails RECORD byte length check"
            )
    return dist_name, dist_ver


def discover_env_entry_points(
    plugin_env: Path,
    *,
    config: SitePluginsConfig,
    tendcf_root: Path | None = None,
    site_root: Path | None = None,
    check_releasable: bool = False,
) -> dict[str, dict[str, DiscoveredEntryPoint]]:
    """Anchor an isolated plugin env byte-for-byte to `plugins.toml` pins and scan `*.dist-info` (H1).

    Refuses:
    - Any symlink, `.pth`, `sitecustomize.py`, `usercustomize.py`, `__pycache__`, `.pyc`/`.pyo`,
      `tendcf`/`nix2cf` top-level stem, or ANY unlisted file/directory inside `plugin_env` (H1.2).
    - Receipt `plugin_set_digest` mismatch (anchored to `site_root` keyring files too, M4).
    - Missing or hash-mismatched cached pinned wheel in `.verified-wheels/`, OR any extracted file
      whose bytes differ from the SHA-256-verified pinned wheel member (H1.1: stops forged RECORD!).
    - Duplicate distribution names or duplicate entry-point names within a group (no deduplication!).
    - Any entry point in `tendcf.supervisors` or claiming a reserved built-in plugin name.
    - Any unpinned distribution in `plugin_env` when `check_releasable=True`.
    """
    resolved_env = assert_isolated_plugin_env_path(
        plugin_env, tendcf_root=tendcf_root, site_root=site_root
    )
    if not resolved_env.is_dir():
        raise PluginEnvError(f"isolated plugin environment does not exist: {resolved_env}")

    # Verify receipt matches current plugins.toml + keyring digest (M4).
    receipt_path = resolved_env / RECEIPT_FILENAME
    try:
        receipt_bytes = read_regular_file_bytes(receipt_path, max_bytes=MAX_WHEEL_BYTES, label="plugin env receipt")
        receipt = json.loads(receipt_bytes.decode("utf-8"))
        expected_digest = config.plugin_set_digest(site_root=site_root)
    except (PluginManifestError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginEnvError(f"invalid or missing plugin env receipt {receipt_path}: {exc}") from exc
    if not isinstance(receipt, dict) or receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise PluginEnvError(f"unsupported plugin env receipt schema in {receipt_path}")
    if receipt.get("plugin_set_digest") != expected_digest:
        raise PluginEnvError(
            f"isolated plugin env receipt digest ({receipt.get('plugin_set_digest')}) does not match "
            f"current plugins.toml digest ({expected_digest}); re-stage with `tendcf plugin restage`"
        )

    # H1.1: Anchor every pinned wheel to its SHA-256-verified `.verified-wheels/<sha256>-<filename>` archive
    # and build the exact allowlist of expected extracted files and their exact byte contents!
    specs = _collect_expected_pins_checked(config)
    expected_extracted_bytes: dict[str, bytes] = {}
    expected_cache_files: set[str] = set()
    pinned_dists: dict[str, tuple[str, str]] = {}

    cache_dir = resolved_env / VERIFIED_WHEELS_DIR
    if specs:
        if cache_dir.is_symlink() or not cache_dir.is_dir():
            raise PluginEnvError(
                f"isolated plugin env missing {VERIFIED_WHEELS_DIR}/ wheel anchor directory: {cache_dir}"
            )

    for dist, version, filename, sha256, is_plugin, ep_group, plugin_name, ep_val in specs:
        pinned_dists[normalize_dist_name(dist)] = (version, sha256)
        cached_name = _cached_wheel_filename(sha256, filename)
        expected_cache_files.add(cached_name)
        cached_path = cache_dir / cached_name
        whl = verify_wheel_artifact(
            cached_path,
            expected_filename=filename,
            expected_sha256=sha256,
            expected_distribution=dist,
            expected_version=version,
            is_plugin_wheel=is_plugin,
            expected_entry_point_group=ep_group,
            expected_plugin_name=plugin_name,
            expected_entry_point=ep_val,
            allow_arbitrary_basename=True,
        )
        for member_rel, member_data in whl.member_bytes.items():
            if member_rel in expected_extracted_bytes:
                raise PluginEnvError(
                    f"cross-wheel file collision across pinned wheels for member {member_rel!r}"
                )
            expected_extracted_bytes[member_rel] = member_data

    # Build exact allowlist of expected directories for H1.2 tree sweep.
    expected_dirs: set[str] = set()
    for rel_file in expected_extracted_bytes:
        parts = rel_file.split("/")
        for i in range(1, len(parts)):
            expected_dirs.add("/".join(parts[:i]))

    # H1.2: Full tree sweep refusing symlinks, __pycache__/.pyc, startup hooks, tendcf/nix2cf stems,
    # and (when anchored to pins) ANY unlisted file or directory!
    found_extracted_files: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(resolved_env, followlinks=False):
        dp = Path(dirpath)
        rel_dp = dp.relative_to(resolved_env)
        rel_dp_posix = "" if rel_dp == Path(".") else rel_dp.as_posix()

        for d in list(dirnames):
            cand = dp / d
            if cand.is_symlink():
                raise PluginEnvError(f"symlinked directory forbidden in isolated plugin env: {cand}")
            if d.lower() == "__pycache__":
                raise PluginEnvError(
                    f"forbidden __pycache__ directory in isolated plugin env: {cand} (bytecode execution refused)"
                )
            if dp == resolved_env:
                if d == VERIFIED_WHEELS_DIR:
                    continue
                if d.lower().split(".", 1)[0] in FORBIDDEN_TOPLEVEL_STEMS:
                    raise PluginEnvError(f"forbidden tendcf/nix2cf package in isolated plugin env: {cand}")
            if rel_dp_posix == VERIFIED_WHEELS_DIR:
                raise PluginEnvError(f"unexpected subdirectory inside {VERIFIED_WHEELS_DIR}: {cand}")
            rel_d = f"{rel_dp_posix}/{d}" if rel_dp_posix else d
            if specs or check_releasable:
                if rel_d not in expected_dirs:
                    raise PluginEnvError(
                        f"unlisted directory {rel_d!r} in isolated plugin env (not part of any pinned wheel)"
                    )

        for fn in filenames:
            cand = dp / fn
            if cand.is_symlink():
                raise PluginEnvError(f"symlinked file forbidden in isolated plugin env: {cand}")
            fn_lower = fn.lower()
            if fn_lower.endswith((".pyc", ".pyo")):
                raise PluginEnvError(f"forbidden bytecode file in isolated plugin env: {cand}")
            if fn_lower in FORBIDDEN_STARTUP_BASENAMES or fn_lower.endswith(FORBIDDEN_STARTUP_SUFFIXES):
                raise PluginEnvError(f"forbidden startup hook file in isolated plugin env: {cand}")
            if dp == resolved_env:
                if fn == RECEIPT_FILENAME:
                    continue
                if fn_lower.split(".", 1)[0] in FORBIDDEN_TOPLEVEL_STEMS:
                    raise PluginEnvError(f"forbidden tendcf/nix2cf module in isolated plugin env: {cand}")
            if rel_dp_posix == VERIFIED_WHEELS_DIR:
                if fn not in expected_cache_files:
                    raise PluginEnvError(f"unlisted file {fn!r} inside {VERIFIED_WHEELS_DIR}/")
                continue

            rel_f = f"{rel_dp_posix}/{fn}" if rel_dp_posix else fn
            found_extracted_files.add(rel_f)
            if specs or check_releasable:
                if rel_f not in expected_extracted_bytes:
                    raise PluginEnvError(
                        f"unlisted file {rel_f!r} in isolated plugin env (not part of any pinned wheel)"
                    )
                try:
                    disk_bytes = read_regular_file_bytes(cand, max_bytes=MAX_WHEEL_BYTES, label=f"staged file {rel_f}")
                except PluginManifestError as exc:
                    raise PluginEnvError(str(exc)) from exc
                if disk_bytes != expected_extracted_bytes[rel_f]:
                    raise PluginEnvError(
                        f"tampered file detected in isolated plugin env: {rel_f!r} differs from "
                        "SHA-256-verified pinned wheel bytes"
                    )

    missing_extracted = sorted(set(expected_extracted_bytes) - found_extracted_files)
    if missing_extracted:
        raise PluginEnvError(
            f"isolated plugin env is missing pinned wheel file(s): {missing_extracted[:5]}"
        )

    # Non-deduplicating scan of EVERY *.dist-info directory at top level of plugin_env.
    dist_info_entries = sorted(
        (
            Path(e.path)
            for e in os.scandir(resolved_env)
            if e.is_dir(follow_symlinks=False) and e.name.endswith(".dist-info")
        ),
        key=lambda p: p.name,
    )

    seen_norm_dists: dict[str, str] = {}
    discovered: dict[str, dict[str, DiscoveredEntryPoint]] = {grp: {} for grp in PUBLIC_EP_GROUPS}

    for di_path in dist_info_entries:
        dist_name, dist_ver = _verify_on_disk_dist_info_record(resolved_env, di_path)
        norm_dist = normalize_dist_name(dist_name)
        if norm_dist in seen_norm_dists:
            raise PluginEnvError(
                f"duplicate distribution {dist_name!r} in isolated plugin env "
                f"({seen_norm_dists[norm_dist]} and {di_path.name}) — refused without deduplication"
            )
        seen_norm_dists[norm_dist] = di_path.name

        if norm_dist in pinned_dists:
            pinned_ver, _ = pinned_dists[norm_dist]
            if dist_ver != pinned_ver:
                raise PluginEnvError(
                    f"staged distribution {dist_name!r} version {dist_ver!r} does not match pinned {pinned_ver!r}"
                )
        elif check_releasable:
            raise PluginEnvError(
                f"unpinned distribution {dist_name!r} ({di_path.name}) present in isolated plugin env "
                "(forbidden under --check-releasable)"
            )

        ep_file = di_path / "entry_points.txt"
        if not ep_file.exists():
            continue
        try:
            ep_bytes = read_regular_file_bytes(
                ep_file, max_bytes=MAX_WHEEL_BYTES, label=f"{di_path.name}/entry_points.txt"
            )
            ep_text = ep_bytes.decode("utf-8")
        except (PluginManifestError, UnicodeDecodeError) as exc:
            raise PluginEnvError(f"cannot read {ep_file}: {exc}") from exc
        parsed_eps = _parse_entry_points_strict(ep_text, context=str(ep_file))

        for forbidden_group in FORBIDDEN_EP_GROUPS:
            if forbidden_group in parsed_eps:
                raise PluginEnvError(
                    f"forbidden entry-point group [{forbidden_group}] in {di_path.name} "
                    "(supervisor renderers are in-tree only)"
                )

        for grp in PUBLIC_EP_GROUPS:
            kind = "frontend" if grp == "tendcf.frontends" else "importer"
            for ep_name, ep_val in parsed_eps.get(grp, {}).items():
                if ep_name in RESERVED_PLUGIN_NAMES.get(kind, frozenset()):
                    raise PluginEnvError(
                        f"entry point {ep_name!r} in [{grp}] from {dist_name!r} ({di_path.name}) "
                        "claims reserved built-in plugin name (impersonation refused)"
                    )
                if ep_name in discovered[grp]:
                    prior = discovered[grp][ep_name]
                    raise PluginEnvError(
                        f"duplicate entry point {ep_name!r} in [{grp}]: "
                        f"{prior.distribution!r} ({prior.dist_info_dir}) and {dist_name!r} ({di_path.name})"
                    )
                discovered[grp][ep_name] = DiscoveredEntryPoint(
                    group=grp,
                    name=ep_name,
                    value=ep_val,
                    distribution=dist_name,
                    version=dist_ver,
                    dist_info_dir=di_path.name,
                )

    return discovered
