"""Pre-install wheel verifier, isolated plugin environment, and non-deduplicating entry-point scanner (#47).

Implements `docs/architecture/plugin-layout.md` §4 (Activation steps 2–3, 6) and the #46/#48
adversary security requirements incorporated into issue #47:
1. Verify BEFORE installing: inspect `.whl` zip archives strictly in memory (wheels only, no
   sdists, no build backends, no `.pth`/`sitecustomize.py`/`usercustomize.py`, no symlinks, no
   duplicate zip entries, full `.dist-info/RECORD` SHA-256 verification, `METADATA` Name/Version
   check, unconditional `Requires-Dist` transitive closure check, and `tendcf`/`nix2cf`
   dependency-confusion refusal).
2. Install strictly into an isolated plugin environment (NEVER `sys.prefix`, the gate environment,
   the signing environment, or `tendcf/tools/`), via pure-Python `zipfile` extraction + atomic
   promotion with a `.tendcf-plugin-env.json` receipt.
3. Discover out-of-tree entry points (`tendcf.frontends`, `tendcf.importers`) by scanning every
   `*.dist-info/entry_points.txt` directly inside the isolated plugin environment with ZERO
   deduplication by distribution name (never `importlib.metadata.entry_points()`), refusing
   duplicates, reserved built-in names, `tendcf.supervisors`, and post-staging file tampering.
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
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .plugin_manifest import (
    ALLOWED_ENTRY_POINT_GROUPS,
    FORBIDDEN_EXTERNAL_DISTRIBUTIONS,
    PluginPin,
    PluginReleaseManifest,
    SitePluginsConfig,
    WheelDependencyPin,
    normalize_dist_name,
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

# Locked compiler base dependencies that a plugin may depend on without re-shipping.
BASE_COMPILER_DISTRIBUTIONS: frozenset[str] = frozenset({"pyyaml", "jsonschema", "rfc8785"})

FORBIDDEN_TOPLEVEL_MODULES: frozenset[str] = frozenset({"tendcf", "tendcf.py", "nix2cf", "nix2cf.py"})
FORBIDDEN_STARTUP_BASENAMES: frozenset[str] = frozenset({"sitecustomize.py", "usercustomize.py"})
FORBIDDEN_STARTUP_SUFFIXES: tuple[str, ...] = (".pth", ".egg-link")

FORBIDDEN_EP_GROUPS: frozenset[str] = frozenset({"tendcf.supervisors"})
PUBLIC_EP_GROUPS: frozenset[str] = frozenset(ALLOWED_ENTRY_POINT_GROUPS.values())

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_EXTRA_MARKER_RE = re.compile(r"\bextra\s*(?:==|!=|in)\b")


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


@dataclass(frozen=True)
class DiscoveredEntryPoint:
    group: str
    name: str
    value: str  # module:attr
    distribution: str
    version: str
    dist_info_dir: str


def _sha256_file(path: Path) -> str:
    data = read_regular_file_bytes(path, max_bytes=MAX_WHEEL_BYTES, label=f"wheel {path.name}")
    return hashlib.sha256(data).hexdigest()


def _record_sha256_b64(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_entry_points_strict(text: str, *, context: str) -> dict[str, dict[str, str]]:
    """Parse PEP 621 / importlib `entry_points.txt` refusing duplicate sections or duplicate keys."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    # Preserve exact case of entry-point names.
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

    basename_lower = parts[-1].lower()
    if basename_lower in FORBIDDEN_STARTUP_BASENAMES or basename_lower.endswith(FORBIDDEN_STARTUP_SUFFIXES):
        raise PluginEnvError(
            f"wheel {wheel_name}: forbidden startup hook file {name!r} "
            "(.pth / sitecustomize.py / usercustomize.py / .egg-link are unconditionally refused)"
        )

    top_lower = parts[0].lower()
    if top_lower in FORBIDDEN_TOPLEVEL_MODULES:
        raise PluginEnvError(
            f"wheel {wheel_name}: dependency-confusion attempt — wheel contains forbidden top-level "
            f"tendcf/nix2cf entry {name!r}"
        )
    if top_lower.endswith(".dist-info"):
        dist_prefix = top_lower[: -len(".dist-info")].split("-", 1)[0]
        if normalize_dist_name(dist_prefix) in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
            raise PluginEnvError(
                f"wheel {wheel_name}: dependency-confusion attempt — forbidden dist-info {parts[0]!r}"
            )
    if top_lower.endswith(".data"):
        # Refuse purelib/platlib/scripts dropping tendcf/nix2cf or startup files.
        if len(parts) >= 3 and parts[1].lower() in ("purelib", "platlib"):
            if parts[2].lower() in FORBIDDEN_TOPLEVEL_MODULES:
                raise PluginEnvError(
                    f"wheel {wheel_name}: dependency-confusion attempt under .data: {name!r}"
                )
        if len(parts) >= 2 and parts[1].lower() in ("scripts", "data", "headers"):
            raise PluginEnvError(
                f"wheel {wheel_name}: wheel installs outside purelib/platlib via {name!r} (refused)"
            )
    return parts


def _parse_unconditional_requires_dist(headers: list[str], *, wheel_name: str) -> list[str]:
    """Return normalized distribution names for all unconditional (non-extra) Requires-Dist entries."""
    out: list[str] = []
    for raw in headers:
        req_part, sep, marker_part = raw.partition(";")
        if sep and _EXTRA_MARKER_RE.search(marker_part):
            continue
        m = _REQ_NAME_RE.match(req_part)
        if not m:
            raise PluginEnvError(f"wheel {wheel_name}: cannot parse Requires-Dist header {raw!r}")
        out.append(normalize_dist_name(m.group(1)))
    return out


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
) -> VerifiedWheel:
    """Inspect and cryptographically verify a `.whl` file completely BEFORE any extraction."""
    validate_wheel_filename(expected_filename, label="expected wheel filename")
    if wheel_path.name != expected_filename:
        raise PluginEnvError(
            f"wheel filename mismatch: got {wheel_path.name!r}, expected {expected_filename!r}"
        )

    raw_bytes = read_regular_file_bytes(wheel_path, max_bytes=MAX_WHEEL_BYTES, label=f"wheel {expected_filename}")
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha != expected_sha256:
        raise PluginEnvError(
            f"wheel {expected_filename} SHA-256 mismatch: got {actual_sha}, expected {expected_sha256}"
        )

    norm_expected_dist = normalize_dist_name(expected_distribution)
    if norm_expected_dist in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
        raise PluginEnvError(f"refused external wheel for reserved distribution {expected_distribution!r}")

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes), "r")
    except zipfile.BadZipFile as exc:
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

            # Reject symlinks stored in ZIP external attributes.
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
            data = zf.read(info)
            if len(data) != info.file_size:
                raise PluginEnvError(f"wheel {expected_filename}: member {member_name!r} size header mismatch")
            file_bytes[member_name] = data

    if len(dist_info_dirs) != 1:
        raise PluginEnvError(
            f"wheel {expected_filename}: expected exactly one .dist-info directory (found {sorted(dist_info_dirs)})"
        )
    dist_info = next(iter(dist_info_dirs))

    metadata_key = f"{dist_info}/METADATA"
    wheel_meta_key = f"{dist_info}/WHEEL"
    record_key = f"{dist_info}/RECORD"
    for req_key in (metadata_key, wheel_meta_key, record_key):
        if req_key not in file_bytes:
            raise PluginEnvError(f"wheel {expected_filename}: missing required {req_key}")

    # Verify RECORD completely against every non-RECORD member in the wheel.
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
        expected_b64 = _record_sha256_b64(data)
        if rec_hash != expected_b64:
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD SHA-256 mismatch for {member_name!r}"
            )
        if rec_size != str(len(data)):
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD byte length mismatch for {member_name!r} "
                f"(RECORD={rec_size!r}, actual={len(data)})"
            )
    for rec_path in record_entries:
        if rec_path != record_key and rec_path not in file_bytes:
            raise PluginEnvError(
                f"wheel {expected_filename}: RECORD lists missing archive member {rec_path!r}"
            )

    # Verify METADATA Name, Version, and extract unconditional Requires-Dist.
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
    unconditional_reqs = tuple(_parse_unconditional_requires_dist(req_headers, wheel_name=expected_filename))

    # Parse entry_points.txt if present and enforce strict tendcf entry-point rules.
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
        # Dependency wheels MUST NOT smuggle tendcf plugin entry points.
        for grp in PUBLIC_EP_GROUPS:
            if grp in parsed_eps:
                raise PluginEnvError(
                    f"dependency wheel {expected_filename}: must not register tendcf entry points in [{grp}]"
                )

    return VerifiedWheel(
        path=wheel_path.resolve(strict=True),
        filename=expected_filename,
        distribution=meta_name,
        normalized_distribution=norm_expected_dist,
        version=meta_ver,
        sha256=actual_sha,
        dist_info_dir=dist_info,
        requires_dist=unconditional_reqs,
        ep_map=parsed_eps,
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

    # Verify unconditional transitive Requires-Dist closure completeness.
    available_dists = (
        {plugin_whl.normalized_distribution}
        | {dw.normalized_distribution for dw in dep_wheels}
        | BASE_COMPILER_DISTRIBUTIONS
        | {"tendcf"}  # always supplied in-tree, never as an external wheel
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

    # Refuse symlinks on the target or any existing parent component we manage.
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


def _extract_verified_wheel(wheel: VerifiedWheel, target_dir: Path) -> None:
    """Extract a pre-verified `.whl` directly with pure-Python zipfile (zero build backends / .pth)."""
    with zipfile.ZipFile(wheel.path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member = info.filename
            parts = _check_member_path(member, wheel_name=wheel.filename)
            dest = target_dir.joinpath(*parts)
            resolved_dest = dest.resolve(strict=False)
            if not resolved_dest.is_relative_to(target_dir):
                raise PluginEnvError(f"wheel {wheel.filename}: member {member!r} escapes {target_dir}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info)
            dest.write_bytes(data)


def stage_plugin_env(
    plugin_env: Path,
    *,
    config: SitePluginsConfig,
    verified_wheels: list[VerifiedWheel],
    tendcf_root: Path | None = None,
    site_root: Path | None = None,
) -> Path:
    """Atomically populate an isolated plugin environment from pre-verified wheels only.

    For any other out-of-tree plugins still pinned in `config` whose wheels are not in
    `verified_wheels`, looks up and fully re-verifies their cached wheels in
    `<plugin_env>/.verified-wheels/` so multi-plugin `add`/`update`/`remove` stays atomic
    and leaves zero stale files behind.
    """
    resolved_env = assert_isolated_plugin_env_path(
        plugin_env, tendcf_root=tendcf_root, site_root=site_root
    )
    resolved_env.parent.mkdir(parents=True, exist_ok=True)
    if resolved_env.parent.is_symlink():
        raise PluginEnvError(f"plugin environment parent must not be a symlink: {resolved_env.parent}")

    # Collect all wheels needed for `config`, using freshly verified wheels first and
    # re-verifying any already-cached wheels from the existing env for untouched pins.
    by_filename: dict[str, VerifiedWheel] = {w.filename: w for w in verified_wheels}
    cache_dir = resolved_env / VERIFIED_WHEELS_DIR
    all_needed: list[VerifiedWheel] = []
    seen_need: set[str] = set()

    for pin in config.plugins:
        if pin.source != "out-of-tree":
            continue
        assert pin.wheel_filename is not None and pin.wheel_sha256 is not None
        assert pin.distribution is not None and pin.version is not None and pin.entry_point is not None
        if pin.wheel_filename not in seen_need:
            seen_need.add(pin.wheel_filename)
            if pin.wheel_filename in by_filename:
                all_needed.append(by_filename[pin.wheel_filename])
            elif cache_dir.is_dir() and not cache_dir.is_symlink():
                all_needed.append(
                    verify_wheel_artifact(
                        cache_dir / pin.wheel_filename,
                        expected_filename=pin.wheel_filename,
                        expected_sha256=pin.wheel_sha256,
                        expected_distribution=pin.distribution,
                        expected_version=pin.version,
                        is_plugin_wheel=True,
                        expected_entry_point_group=pin.entry_point_group,
                        expected_plugin_name=pin.name,
                        expected_entry_point=pin.entry_point,
                    )
                )
            else:
                raise PluginEnvError(
                    f"missing wheel {pin.wheel_filename!r} for pinned plugin {pin.name!r} "
                    f"(not supplied and not cached in {cache_dir})"
                )
        for dep in pin.dependencies:
            if dep.filename in seen_need:
                continue
            seen_need.add(dep.filename)
            if dep.filename in by_filename:
                all_needed.append(by_filename[dep.filename])
            elif cache_dir.is_dir() and not cache_dir.is_symlink():
                all_needed.append(
                    verify_wheel_artifact(
                        cache_dir / dep.filename,
                        expected_filename=dep.filename,
                        expected_sha256=dep.sha256,
                        expected_distribution=dep.distribution,
                        expected_version=dep.version,
                        is_plugin_wheel=False,
                    )
                )
            else:
                raise PluginEnvError(
                    f"missing dependency wheel {dep.filename!r} for pinned plugin {pin.name!r}"
                )

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
            _extract_verified_wheel(whl, stage_dir)
            shutil.copyfile(whl.path, stage_wheels_cache / whl.filename)
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
            "plugin_set_digest": config.plugin_set_digest(),
            "wheels": sorted(receipt_wheels, key=lambda w: (w["normalized_distribution"], w["version"])),
        }
        (stage_dir / RECEIPT_FILENAME).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        # Atomic swap (replace existing env cleanly if present).
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

    meta_bytes = read_regular_file_bytes(metadata_path, max_bytes=MAX_WHEEL_BYTES, label="staged METADATA")
    meta_msg = email.parser.Parser().parsestr(meta_bytes.decode("utf-8"))
    dist_name = (meta_msg.get("Name") or "").strip()
    dist_ver = (meta_msg.get("Version") or "").strip()
    if not dist_name or not dist_ver:
        raise PluginEnvError(f"staged METADATA missing Name or Version: {metadata_path}")
    if normalize_dist_name(dist_name) in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
        raise PluginEnvError(
            f"dependency-confusion attempt in staged plugin env: forbidden distribution {dist_name!r}"
        )

    rec_bytes = read_regular_file_bytes(record_path, max_bytes=MAX_WHEEL_BYTES, label="staged RECORD")
    record_rel = f"{dist_info_path.name}/RECORD"
    for row_num, row in enumerate(csv.reader(io.StringIO(rec_bytes.decode("utf-8"))), start=1):
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
        data = read_regular_file_bytes(resolved, max_bytes=MAX_WHEEL_BYTES, label=f"staged file {rec_file}")
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
    """Scan an isolated plugin env's `*.dist-info` dirs WITHOUT deduplication and verify integrity.

    Returns `{group: {name: DiscoveredEntryPoint}}` for `tendcf.frontends` and `tendcf.importers`.
    Refuses:
    - Any symlink, `.pth`, `sitecustomize.py`, `usercustomize.py`, or `tendcf`/`nix2cf` module in `plugin_env`.
    - Receipt `plugin_set_digest` mismatch or tampered on-disk RECORD file hashes.
    - Duplicate distribution names or duplicate entry-point names within a group (no deduplication!).
    - Any entry point in `tendcf.supervisors` or claiming a reserved built-in plugin name.
    - Any unpinned distribution in `plugin_env` when `check_releasable=True`.
    """
    resolved_env = assert_isolated_plugin_env_path(
        plugin_env, tendcf_root=tendcf_root, site_root=site_root
    )
    if not resolved_env.is_dir():
        raise PluginEnvError(f"isolated plugin environment does not exist: {resolved_env}")

    # Full tree sweep: refuse symlinks, startup hooks, and tendcf/nix2cf shadowing anywhere inside env.
    for dirpath, dirnames, filenames in os.walk(resolved_env, followlinks=False):
        dp = Path(dirpath)
        rel_dp = dp.relative_to(resolved_env)
        for d in list(dirnames):
            cand = dp / d
            if cand.is_symlink():
                raise PluginEnvError(f"symlinked directory forbidden in isolated plugin env: {cand}")
            if dp == resolved_env and d.lower() in FORBIDDEN_TOPLEVEL_MODULES:
                raise PluginEnvError(f"forbidden tendcf/nix2cf package in isolated plugin env: {cand}")
        for fn in filenames:
            cand = dp / fn
            if cand.is_symlink():
                raise PluginEnvError(f"symlinked file forbidden in isolated plugin env: {cand}")
            fn_lower = fn.lower()
            if fn_lower in FORBIDDEN_STARTUP_BASENAMES or fn_lower.endswith(FORBIDDEN_STARTUP_SUFFIXES):
                raise PluginEnvError(f"forbidden startup hook file in isolated plugin env: {cand}")
            if dp == resolved_env and fn_lower in FORBIDDEN_TOPLEVEL_MODULES:
                raise PluginEnvError(f"forbidden tendcf/nix2cf module in isolated plugin env: {cand}")

    # Verify receipt matches current plugins.toml plugin_set_digest.
    receipt_path = resolved_env / RECEIPT_FILENAME
    receipt_bytes = read_regular_file_bytes(receipt_path, max_bytes=MAX_WHEEL_BYTES, label="plugin env receipt")
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginEnvError(f"invalid plugin env receipt {receipt_path}: {exc}") from exc
    if not isinstance(receipt, dict) or receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise PluginEnvError(f"unsupported plugin env receipt schema in {receipt_path}")
    expected_digest = config.plugin_set_digest()
    if receipt.get("plugin_set_digest") != expected_digest:
        raise PluginEnvError(
            f"isolated plugin env receipt digest ({receipt.get('plugin_set_digest')}) does not match "
            f"current plugins.toml digest ({expected_digest}); re-stage with `tendcf plugin add/update`"
        )

    # Expected pinned distributions (all out-of-tree plugins + their transitive dependencies).
    pinned_dists: dict[str, tuple[str, str]] = {}  # norm_dist -> (version, sha256)
    for pin in config.plugins:
        if pin.source != "out-of-tree":
            continue
        assert pin.distribution is not None and pin.version is not None and pin.wheel_sha256 is not None
        pinned_dists[normalize_dist_name(pin.distribution)] = (pin.version, pin.wheel_sha256)
        for dep in pin.dependencies:
            pinned_dists[normalize_dist_name(dep.distribution)] = (dep.version, dep.sha256)

    # Non-deduplicating scan of EVERY *.dist-info directory at top level of plugin_env.
    dist_info_entries = sorted(
        (Path(e.path) for e in os.scandir(resolved_env) if e.is_dir(follow_symlinks=False) and e.name.endswith(".dist-info")),
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
        ep_bytes = read_regular_file_bytes(ep_file, max_bytes=MAX_WHEEL_BYTES, label=f"{di_path.name}/entry_points.txt")
        parsed_eps = _parse_entry_points_strict(ep_bytes.decode("utf-8"), context=str(ep_file))

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
