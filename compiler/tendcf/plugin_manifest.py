"""Site-private plugin manifest (`plugins.toml`) and signed release manifest (`plugin-release.json`).

Implements issue #47 (operator rulings 2026-11-28) and `docs/architecture/plugin-layout.md` §4:
- Offline deterministic trust store inside `site-private` (`plugins.toml` + `plugins/keyring/`).
- Bounded Web of Trust configuration (`max_depth` in 0..2, default 1; full & marginal thresholds;
  `max_validity_days` anti-freeze ceiling).
- Soft vs hard key revocations (`soft`: blocks add/update & future releases, permits pre-revocation
  historical rebuilds; `hard`: blocks all verification including historical rebuilds).
- Explicit plugin pins (`in-tree`, `contrib`, `out-of-tree` frontends/importers only; supervisors
  unconditionally refused), recording both `signer_fingerprint` (primary) and
  `signing_subkey_fingerprint` (signing key/subkey) for full revocation & rotation enforcement.
- Anti-rollback tombstones (`[[plugin_floors]]`) preserved on `remove` so `remove` + `add`
  cannot downgrade `release_seq` or swap signers silently.
- Dependency-confusion protection: `tendcf` and `nix2cf` are unconditionally forbidden as
  pinned external plugin or transitive dependency distributions.
- Deterministic RFC 8785 `plugin_set_digest(site_root=...)` covering `[external_import]`,
  `[trust]` (including SHA-256 of every imported keyring file when `site_root` is provided),
  `[[plugins]]`, and `[[plugin_floors]]` so Gate 5 detects every privileged trust or plugin change.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc8785

from .plugins import RESERVED_PLUGIN_NAMES, STATIC_PLUGIN_TABLE

PLUGINS_TOML_SCHEMA_VERSION = 1
RELEASE_MANIFEST_SCHEMA_VERSION = 1

MAX_TOML_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_KEY_DIGEST_FILE_BYTES = 1024 * 1024

DEFAULT_MAX_VALIDITY_DAYS = 365
MAX_ALLOWED_VALIDITY_DAYS = 3650

ALLOWED_WITHOUT_AI = frozenset({"require-human-ack", "warn", "refuse"})
ALLOWED_BACKENDS = frozenset({"auto", "sequoia", "gpg"})
ALLOWED_ANCHOR_ROLES = frozenset({"root", "direct"})
ALLOWED_REVOCATION_MODES = frozenset({"soft", "hard"})
ALLOWED_PLUGIN_SOURCES = frozenset({"in-tree", "contrib", "out-of-tree"})
ALLOWED_SITE_PLUGIN_KINDS = frozenset({"frontend", "importer"})
ALLOWED_ENTRY_POINT_GROUPS = {
    "frontend": "tendcf.frontends",
    "importer": "tendcf.importers",
}
FORBIDDEN_EXTERNAL_DISTRIBUTIONS = frozenset({"tendcf", "nix2cf"})
KEYRING_FILE_EXTS = frozenset({".asc", ".gpg", ".pgp", ".pub", ".rev"})

# Strict RFC 3339 UTC timestamp: YYYY-MM-DDTHH:MM:SSZ (no fractional seconds/offsets/newlines).
RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
# OpenPGP primary fingerprint: v4 (40 hex) or v6 (64 hex), uppercase hex.
FINGERPRINT_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})\Z")
SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*\Z")
DIST_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*\Z")
# Python entry point: pkg.mod:attr (no whitespace, path separators, or shell chars).
ENTRY_POINT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)
# Safe single filename (no directory separators, no leading dot, no NUL).
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
# PEP 427 wheel filename grammar.
WHEEL_FILENAME_RE = re.compile(
    r"^(?P<dist>[A-Za-z0-9](?:[A-Za-z0-9._]*[A-Za-z0-9])?)-(?P<ver>[A-Za-z0-9._+!]+)(?:-[0-9][A-Za-z0-9._]*)?-[A-Za-z0-9._]+-[A-Za-z0-9._]+-[A-Za-z0-9._]+\.whl\Z"
)

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class PluginManifestError(Exception):
    """Invalid, tampered, symlinked, or policy-refused plugin manifest / config."""


def normalize_dist_name(name: str) -> str:
    """PEP 503 canonical distribution name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def validate_fingerprint(value: Any, *, label: str = "fingerprint") -> str:
    if not isinstance(value, str):
        raise PluginManifestError(f"{label} must be a string")
    cleaned = value.strip().upper()
    if not FINGERPRINT_RE.match(cleaned):
        raise PluginManifestError(
            f"invalid {label} {value!r}: expected 40-hex (OpenPGP v4) or 64-hex (v6) fingerprint"
        )
    return cleaned


def validate_sha256(value: Any, *, label: str = "sha256") -> str:
    if not isinstance(value, str) or not SHA256_RE.match(value):
        raise PluginManifestError(f"invalid {label} {value!r}: expected 64 lowercase hex characters")
    return value


def parse_rfc3339_utc(value: Any, *, label: str = "timestamp") -> datetime:
    """Strictly parse `YYYY-MM-DDTHH:MM:SSZ` into an aware UTC datetime."""
    if not isinstance(value, str) or not RFC3339_UTC_RE.match(value):
        raise PluginManifestError(
            f"invalid {label} {value!r}: expected strict RFC 3339 UTC 'YYYY-MM-DDTHH:MM:SSZ'"
        )
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PluginManifestError(f"invalid calendar date in {label} {value!r}: {exc}") from exc
    return dt


def format_rfc3339_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def validate_plugin_name(name: Any, *, kind: str, source: str) -> str:
    if not isinstance(name, str) or not PLUGIN_NAME_RE.match(name) or len(name) > 64:
        raise PluginManifestError(
            f"invalid plugin name {name!r}: expected lowercase ASCII matching {PLUGIN_NAME_RE.pattern!r}"
        )
    if kind not in ALLOWED_SITE_PLUGIN_KINDS:
        raise PluginManifestError(
            f"plugin kind {kind!r} is forbidden in plugins.toml "
            "(supervisor renderers are in-tree only; allowed kinds: 'frontend', 'importer')"
        )
    if source in ("out-of-tree", "contrib") and name in RESERVED_PLUGIN_NAMES.get(kind, frozenset()):
        raise PluginManifestError(
            f"{source} {kind} plugin name {name!r} is reserved for built-in tendcf plugins (impersonation refused)"
        )
    if source == "in-tree" and name not in STATIC_PLUGIN_TABLE.get(kind, {}):
        known = sorted(STATIC_PLUGIN_TABLE.get(kind, {}))
        raise PluginManifestError(
            f"in-tree {kind} plugin {name!r} is not in tendcf's static plugin table (available: {known})"
        )
    return name


def validate_safe_filename(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not SAFE_FILENAME_RE.match(value) or value in (".", ".."):
        raise PluginManifestError(f"invalid {label} {value!r}: must be a plain filename without path separators")
    return value


def validate_wheel_filename(value: Any, *, label: str = "wheel filename") -> str:
    if not isinstance(value, str) or not WHEEL_FILENAME_RE.match(value) or "/" in value or "\\" in value:
        raise PluginManifestError(
            f"invalid {label} {value!r}: wheels only (PEP 427 *.whl filename required; sdists refused)"
        )
    return value


def parse_wheel_filename_parts(filename: str) -> tuple[str, str]:
    """Return `(normalized_dist, version)` from a validated PEP 427 wheel filename."""
    m = WHEEL_FILENAME_RE.match(filename)
    if not m:
        raise PluginManifestError(f"invalid PEP 427 wheel filename: {filename!r}")
    return normalize_dist_name(m.group("dist")), m.group("ver")


def validate_external_distribution(value: Any, *, label: str = "distribution") -> str:
    if not isinstance(value, str) or not DIST_NAME_RE.match(value) or len(value) > 128:
        raise PluginManifestError(f"invalid {label} {value!r}")
    norm = normalize_dist_name(value)
    if norm in FORBIDDEN_EXTERNAL_DISTRIBUTIONS:
        raise PluginManifestError(
            f"refused external distribution {value!r} (normalized {norm!r}): "
            "tendcf and nix2cf must never be supplied or overridden as external plugin distributions "
            "(dependency-confusion protection)"
        )
    return value


def validate_relative_dir(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\x00" in value or "\\" in value:
        raise PluginManifestError(f"invalid {label} {value!r}: must be a safe relative POSIX path")
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PluginManifestError(f"invalid {label} {value!r}: path traversal segments are forbidden")
    return "/".join(parts)


def validate_contrib_relpath(value: Any) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\x00" in value or "\\" in value:
        raise PluginManifestError(f"invalid contrib relpath {value!r}")
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts) or parts[0] != "contrib" or len(parts) < 2 or not parts[-1].endswith(".py"):
        raise PluginManifestError(
            f"invalid contrib relpath {value!r}: must be a .py file strictly under 'contrib/'"
        )
    return "/".join(parts)


def _reject_extra_keys(obj: Mapping[str, Any], allowed: frozenset[str], *, context: str) -> None:
    extra = sorted(set(obj.keys()) - allowed)
    if extra:
        raise PluginManifestError(f"{context}: unexpected field(s): {extra}")


def _require_int(value: Any, *, label: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PluginManifestError(f"{label} must be an integer, got {type(value).__name__}")
    if value < minimum:
        raise PluginManifestError(f"{label} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise PluginManifestError(f"{label} must be <= {maximum}, got {value}")
    return value


def read_regular_file_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Open `path` with `O_NOFOLLOW`, verify regular file and size bound, and read bytes."""
    try:
        st_l = os.lstat(path)
    except OSError as exc:
        raise PluginManifestError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(st_l.st_mode):
        raise PluginManifestError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(st_l.st_mode):
        raise PluginManifestError(f"{label} must be a regular file: {path}")

    flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
            raise PluginManifestError(f"{label} must not be a symlink: {path}") from exc
        raise PluginManifestError(f"cannot open {label} {path}: {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PluginManifestError(f"{label} must be a regular file: {path}")
        if st.st_size > max_bytes:
            raise PluginManifestError(f"{label} exceeds {max_bytes} bytes: {path}")
        fh = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise

    with fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PluginManifestError(f"{label} exceeds {max_bytes} bytes: {path}")
    return data


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for k, _ in pairs:
        if k in seen:
            raise PluginManifestError(f"duplicate JSON key {k!r} — refused rather than last-wins")
        seen.add(k)
    return dict(pairs)


def compute_keyring_file_digests(site_root: Path, keyring_rel: str) -> list[dict[str, str]]:
    """Return sorted `[{"filename": name, "sha256": hex}, ...]` for all imported keyring files.

    Returns `[]` if the keyring directory does not exist yet; fails closed on symlinks or escapes.
    """
    try:
        st_site = os.lstat(site_root)
    except OSError as exc:
        raise PluginManifestError(f"cannot inspect site directory {site_root}: {exc}") from exc
    if stat.S_ISLNK(st_site.st_mode) or not stat.S_ISDIR(st_site.st_mode):
        raise PluginManifestError(f"site directory must be a real non-symlink directory: {site_root}")
    resolved_site = site_root.resolve(strict=True)

    cur = resolved_site
    for part in keyring_rel.split("/"):
        if part in ("", ".", ".."):
            raise PluginManifestError(f"unsafe keyring_dir component in {keyring_rel!r}")
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise PluginManifestError(f"cannot inspect keyring directory {cur}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise PluginManifestError(f"keyring directory component must be a real non-symlink directory: {cur}")
    resolved_kr = cur.resolve(strict=True)
    if not resolved_kr.is_relative_to(resolved_site):
        raise PluginManifestError(f"keyring directory {resolved_kr} escapes site directory {resolved_site}")

    digests: list[dict[str, str]] = []
    for entry in sorted(os.scandir(resolved_kr), key=lambda e: e.name):
        if entry.name.startswith("."):
            continue
        p = Path(entry.path)
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            raise PluginManifestError(f"symlink forbidden inside site-private keyring: {p}")
        if not stat.S_ISREG(st.st_mode):
            continue
        if p.suffix.lower() not in KEYRING_FILE_EXTS:
            continue
        raw = read_regular_file_bytes(p, max_bytes=MAX_KEY_DIGEST_FILE_BYTES, label=f"keyring file {entry.name}")
        digests.append({"filename": entry.name, "sha256": hashlib.sha256(raw).hexdigest()})
    return digests


@dataclass(frozen=True)
class TrustAnchor:
    fingerprint: str
    label: str
    role: str  # "root" | "direct"
    key_file: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "label": self.label,
            "role": self.role,
            "key_file": self.key_file,
        }


@dataclass(frozen=True)
class KeyRevocation:
    fingerprint: str
    mode: str  # "soft" | "hard"
    revoked_at: str  # RFC 3339 UTC
    reason: str
    cert_file: str | None = None

    @property
    def revoked_at_dt(self) -> datetime:
        return parse_rfc3339_utc(self.revoked_at, label="revoked_at")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "mode": self.mode,
            "revoked_at": self.revoked_at,
            "reason": self.reason,
        }
        if self.cert_file is not None:
            out["cert_file"] = self.cert_file
        return out


@dataclass(frozen=True)
class TrustPolicy:
    keyring_dir: str = "plugins/keyring"
    max_depth: int = 1
    marginal_threshold: int = 2
    full_threshold: int = 1
    max_validity_days: int = DEFAULT_MAX_VALIDITY_DAYS
    backend: str = "auto"
    anchors: tuple[TrustAnchor, ...] = ()
    revocations: tuple[KeyRevocation, ...] = ()

    def to_dict(self, *, keyring_files: list[dict[str, str]] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "keyring_dir": self.keyring_dir,
            "max_depth": self.max_depth,
            "marginal_threshold": self.marginal_threshold,
            "full_threshold": self.full_threshold,
            "max_validity_days": self.max_validity_days,
            "backend": self.backend,
            "anchors": [a.to_dict() for a in sorted(self.anchors, key=lambda x: x.fingerprint)],
            "revocations": [r.to_dict() for r in sorted(self.revocations, key=lambda x: x.fingerprint)],
        }
        if keyring_files is not None:
            out["keyring_files"] = keyring_files
        return out


@dataclass(frozen=True)
class WheelDependencyPin:
    distribution: str
    version: str
    filename: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "distribution": self.distribution,
            "version": self.version,
            "filename": self.filename,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class PluginFloor:
    """Anti-rollback tombstone preserved across `remove` -> `add` (M5)."""

    name: str
    kind: str  # "frontend" | "importer"
    distribution: str
    min_release_seq: int
    signer_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "distribution": self.distribution,
            "min_release_seq": self.min_release_seq,
            "signer_fingerprint": self.signer_fingerprint,
        }


@dataclass(frozen=True)
class PluginPin:
    name: str
    kind: str  # "frontend" | "importer"
    source: str  # "in-tree" | "contrib" | "out-of-tree"
    # Contrib-only:
    relpath: str | None = None
    # Out-of-tree-only:
    distribution: str | None = None
    version: str | None = None
    entry_point: str | None = None
    wheel_filename: str | None = None
    wheel_sha256: str | None = None
    release_seq: int | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    manifest_sha256: str | None = None
    signer_fingerprint: str | None = None
    signing_subkey_fingerprint: str | None = None
    verified_at: str | None = None
    dependencies: tuple[WheelDependencyPin, ...] = ()

    @property
    def entry_point_group(self) -> str:
        return ALLOWED_ENTRY_POINT_GROUPS[self.kind]

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "source": self.source,
        }
        if self.source == "contrib":
            out["relpath"] = self.relpath
        elif self.source == "out-of-tree":
            out.update(
                {
                    "distribution": self.distribution,
                    "version": self.version,
                    "entry_point": self.entry_point,
                    "wheel_filename": self.wheel_filename,
                    "wheel_sha256": self.wheel_sha256,
                    "release_seq": self.release_seq,
                    "issued_at": self.issued_at,
                    "expires_at": self.expires_at,
                    "manifest_sha256": self.manifest_sha256,
                    "signer_fingerprint": self.signer_fingerprint,
                    "signing_subkey_fingerprint": self.signing_subkey_fingerprint or self.signer_fingerprint,
                    "verified_at": self.verified_at,
                    "dependencies": [
                        d.to_dict()
                        for d in sorted(self.dependencies, key=lambda x: normalize_dist_name(x.distribution))
                    ],
                }
            )
        return out


@dataclass(frozen=True)
class SitePluginsConfig:
    schema_version: int = PLUGINS_TOML_SCHEMA_VERSION
    without_ai: str = "require-human-ack"
    trust: TrustPolicy = TrustPolicy()
    plugins: tuple[PluginPin, ...] = ()
    plugin_floors: tuple[PluginFloor, ...] = ()

    def to_canonical_dict(self, *, site_root: Path | None = None) -> dict[str, Any]:
        keyring_files = (
            compute_keyring_file_digests(site_root, self.trust.keyring_dir)
            if site_root is not None
            else None
        )
        return {
            "schema_version": self.schema_version,
            "external_import": {"without_ai": self.without_ai},
            "trust": self.trust.to_dict(keyring_files=keyring_files),
            "plugins": [p.to_dict() for p in sorted(self.plugins, key=lambda x: (x.kind, x.name))],
            "plugin_floors": [
                f.to_dict() for f in sorted(self.plugin_floors, key=lambda x: (x.kind, x.name))
            ],
        }

    def plugin_set_digest(self, *, site_root: Path | None = None) -> str:
        """Deterministic SHA-256 over RFC 8785 canonical JSON of all trust, keyring, floor & plugin settings."""
        canonical = rfc8785.dumps(self.to_canonical_dict(site_root=site_root))
        return hashlib.sha256(canonical).hexdigest()

    def get_plugin(self, kind: str, name: str) -> PluginPin | None:
        for p in self.plugins:
            if p.kind == kind and p.name == name:
                return p
        return None

    def get_floor(self, kind: str, name: str) -> PluginFloor | None:
        for f in self.plugin_floors:
            if f.kind == kind and f.name == name:
                return f
        return None


@dataclass(frozen=True)
class PluginReleaseManifest:
    schema_version: int
    name: str
    kind: str
    distribution: str
    version: str
    entry_point_group: str
    entry_point: str
    release_seq: int
    issued_at: str
    expires_at: str
    wheel_filename: str
    wheel_sha256: str
    dependencies: tuple[WheelDependencyPin, ...]
    raw_bytes: bytes
    manifest_sha256: str

    @property
    def issued_at_dt(self) -> datetime:
        return parse_rfc3339_utc(self.issued_at, label="issued_at")

    @property
    def expires_at_dt(self) -> datetime:
        return parse_rfc3339_utc(self.expires_at, label="expires_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plugin": {
                "name": self.name,
                "kind": self.kind,
                "distribution": self.distribution,
                "version": self.version,
                "entry_point_group": self.entry_point_group,
                "entry_point": self.entry_point,
            },
            "release_seq": self.release_seq,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "wheel": {
                "filename": self.wheel_filename,
                "sha256": self.wheel_sha256,
            },
            "dependencies": [d.to_dict() for d in self.dependencies],
        }


def _parse_dependency(raw: Any, *, context: str) -> WheelDependencyPin:
    if not isinstance(raw, Mapping):
        raise PluginManifestError(f"{context}: dependency entry must be a table/object")
    _reject_extra_keys(raw, frozenset({"distribution", "version", "filename", "sha256"}), context=context)
    dist = validate_external_distribution(raw.get("distribution"), label=f"{context}.distribution")
    ver = raw.get("version")
    if not isinstance(ver, str) or not VERSION_RE.match(ver):
        raise PluginManifestError(f"{context}: invalid dependency version {ver!r}")
    fn = validate_wheel_filename(raw.get("filename"), label=f"{context}.filename")
    fn_dist, fn_ver = parse_wheel_filename_parts(fn)
    if fn_dist != normalize_dist_name(dist) or fn_ver != ver:
        raise PluginManifestError(
            f"{context}: wheel filename {fn!r} does not match distribution={dist!r} version={ver!r}"
        )
    sha = validate_sha256(raw.get("sha256"), label=f"{context}.sha256")
    return WheelDependencyPin(distribution=dist, version=ver, filename=fn, sha256=sha)


def parse_release_manifest_bytes(raw_bytes: bytes, *, source_label: str = "plugin-release.json") -> PluginReleaseManifest:
    """Strictly parse and validate a signed plugin release manifest from its exact bytes."""
    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        raise PluginManifestError(f"{source_label} exceeds {MAX_MANIFEST_BYTES} bytes")
    if b"\x00" in raw_bytes:
        raise PluginManifestError(f"{source_label} contains NUL bytes")
    try:
        text = raw_bytes.decode("utf-8")
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginManifestError(f"{source_label} is not valid UTF-8 JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise PluginManifestError(f"{source_label} root must be a JSON object")

    _reject_extra_keys(
        data,
        frozenset({"schema_version", "plugin", "release_seq", "issued_at", "expires_at", "wheel", "dependencies"}),
        context=source_label,
    )
    sv = _require_int(data.get("schema_version"), label=f"{source_label}.schema_version", minimum=1, maximum=1)
    if sv != RELEASE_MANIFEST_SCHEMA_VERSION:
        raise PluginManifestError(f"{source_label}: unsupported schema_version {sv}")

    plugin_obj = data.get("plugin")
    if not isinstance(plugin_obj, dict):
        raise PluginManifestError(f"{source_label}.plugin must be an object")
    _reject_extra_keys(
        plugin_obj,
        frozenset({"name", "kind", "distribution", "version", "entry_point_group", "entry_point"}),
        context=f"{source_label}.plugin",
    )
    kind = plugin_obj.get("kind")
    if kind not in ALLOWED_SITE_PLUGIN_KINDS:
        raise PluginManifestError(
            f"{source_label}.plugin.kind {kind!r} is forbidden (allowed: 'frontend', 'importer'; supervisors are in-tree only)"
        )
    name = validate_plugin_name(plugin_obj.get("name"), kind=kind, source="out-of-tree")
    dist = validate_external_distribution(plugin_obj.get("distribution"), label=f"{source_label}.plugin.distribution")
    version = plugin_obj.get("version")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        raise PluginManifestError(f"{source_label}.plugin.version invalid: {version!r}")
    ep_group = plugin_obj.get("entry_point_group")
    expected_group = ALLOWED_ENTRY_POINT_GROUPS[kind]
    if ep_group != expected_group:
        raise PluginManifestError(
            f"{source_label}.plugin.entry_point_group is {ep_group!r}, expected {expected_group!r} for kind {kind!r}"
        )
    ep = plugin_obj.get("entry_point")
    if not isinstance(ep, str) or not ENTRY_POINT_RE.match(ep):
        raise PluginManifestError(f"{source_label}.plugin.entry_point invalid: {ep!r}")

    release_seq = _require_int(data.get("release_seq"), label=f"{source_label}.release_seq", minimum=1)
    issued_at_dt = parse_rfc3339_utc(data.get("issued_at"), label=f"{source_label}.issued_at")
    expires_at_dt = parse_rfc3339_utc(data.get("expires_at"), label=f"{source_label}.expires_at")
    if expires_at_dt <= issued_at_dt:
        raise PluginManifestError(
            f"{source_label}: expires_at ({data.get('expires_at')}) must be strictly after issued_at ({data.get('issued_at')})"
        )

    wheel_obj = data.get("wheel")
    if not isinstance(wheel_obj, dict):
        raise PluginManifestError(f"{source_label}.wheel must be an object")
    _reject_extra_keys(wheel_obj, frozenset({"filename", "sha256"}), context=f"{source_label}.wheel")
    wheel_fn = validate_wheel_filename(wheel_obj.get("filename"), label=f"{source_label}.wheel.filename")
    fn_dist, fn_ver = parse_wheel_filename_parts(wheel_fn)
    if fn_dist != normalize_dist_name(dist) or fn_ver != version:
        raise PluginManifestError(
            f"{source_label}: wheel filename {wheel_fn!r} does not match distribution={dist!r} version={version!r}"
        )
    wheel_sha = validate_sha256(wheel_obj.get("sha256"), label=f"{source_label}.wheel.sha256")

    raw_deps = data.get("dependencies", [])
    if not isinstance(raw_deps, list):
        raise PluginManifestError(f"{source_label}.dependencies must be a list")
    deps: list[WheelDependencyPin] = []
    seen_dep_dists: set[str] = {normalize_dist_name(dist)}
    seen_dep_files: set[str] = {wheel_fn}
    for idx, item in enumerate(raw_deps):
        dep = _parse_dependency(item, context=f"{source_label}.dependencies[{idx}]")
        norm_d = normalize_dist_name(dep.distribution)
        if norm_d in seen_dep_dists:
            raise PluginManifestError(
                f"{source_label}: duplicate distribution {dep.distribution!r} in plugin/dependencies closure"
            )
        if dep.filename in seen_dep_files:
            raise PluginManifestError(
                f"{source_label}: duplicate wheel filename {dep.filename!r} in plugin/dependencies closure"
            )
        seen_dep_dists.add(norm_d)
        seen_dep_files.add(dep.filename)
        deps.append(dep)

    manifest_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    return PluginReleaseManifest(
        schema_version=sv,
        name=name,
        kind=kind,
        distribution=dist,
        version=version,
        entry_point_group=ep_group,
        entry_point=ep,
        release_seq=release_seq,
        issued_at=format_rfc3339_utc(issued_at_dt),
        expires_at=format_rfc3339_utc(expires_at_dt),
        wheel_filename=wheel_fn,
        wheel_sha256=wheel_sha,
        dependencies=tuple(deps),
        raw_bytes=raw_bytes,
        manifest_sha256=manifest_sha256,
    )


def load_release_manifest(path: Path) -> PluginReleaseManifest:
    raw = read_regular_file_bytes(path, max_bytes=MAX_MANIFEST_BYTES, label="plugin release manifest")
    return parse_release_manifest_bytes(raw, source_label=str(path))


def parse_site_plugins_toml(raw_bytes: bytes, *, source_label: str = "plugins.toml") -> SitePluginsConfig:
    """Parse and strictly validate `<site_private>/plugins.toml`."""
    if len(raw_bytes) > MAX_TOML_BYTES:
        raise PluginManifestError(f"{source_label} exceeds {MAX_TOML_BYTES} bytes")
    if b"\x00" in raw_bytes:
        raise PluginManifestError(f"{source_label} contains NUL bytes")
    try:
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PluginManifestError(f"{source_label}: invalid UTF-8 TOML: {exc}") from exc

    _reject_extra_keys(
        data,
        frozenset({"schema_version", "external_import", "trust", "plugins", "plugin_floors"}),
        context=source_label,
    )
    sv = _require_int(data.get("schema_version", 1), label=f"{source_label}.schema_version", minimum=1, maximum=1)

    ext_import = data.get("external_import", {})
    if not isinstance(ext_import, dict):
        raise PluginManifestError(f"{source_label}.external_import must be a table")
    _reject_extra_keys(ext_import, frozenset({"without_ai"}), context=f"{source_label}.external_import")
    without_ai = ext_import.get("without_ai", "require-human-ack")
    if without_ai not in ALLOWED_WITHOUT_AI:
        raise PluginManifestError(
            f"{source_label}.external_import.without_ai invalid: {without_ai!r} (expected one of {sorted(ALLOWED_WITHOUT_AI)})"
        )

    trust_raw = data.get("trust", {})
    if not isinstance(trust_raw, dict):
        raise PluginManifestError(f"{source_label}.trust must be a table")
    _reject_extra_keys(
        trust_raw,
        frozenset(
            {
                "keyring_dir",
                "max_depth",
                "marginal_threshold",
                "full_threshold",
                "max_validity_days",
                "backend",
                "anchors",
                "revocations",
            }
        ),
        context=f"{source_label}.trust",
    )
    keyring_dir = validate_relative_dir(
        trust_raw.get("keyring_dir", "plugins/keyring"),
        label=f"{source_label}.trust.keyring_dir",
    )
    max_depth = _require_int(
        trust_raw.get("max_depth", 1),
        label=f"{source_label}.trust.max_depth",
        minimum=0,
        maximum=2,
    )
    marginal_threshold = _require_int(
        trust_raw.get("marginal_threshold", 2),
        label=f"{source_label}.trust.marginal_threshold",
        minimum=1,
        maximum=10,
    )
    full_threshold = _require_int(
        trust_raw.get("full_threshold", 1),
        label=f"{source_label}.trust.full_threshold",
        minimum=1,
        maximum=10,
    )
    max_validity_days = _require_int(
        trust_raw.get("max_validity_days", DEFAULT_MAX_VALIDITY_DAYS),
        label=f"{source_label}.trust.max_validity_days",
        minimum=1,
        maximum=MAX_ALLOWED_VALIDITY_DAYS,
    )
    backend = trust_raw.get("backend", "auto")
    if backend not in ALLOWED_BACKENDS:
        raise PluginManifestError(
            f"{source_label}.trust.backend invalid: {backend!r} (expected one of {sorted(ALLOWED_BACKENDS)})"
        )

    raw_anchors = trust_raw.get("anchors", [])
    if not isinstance(raw_anchors, list):
        raise PluginManifestError(f"{source_label}.trust.anchors must be an array of tables")
    anchors: list[TrustAnchor] = []
    seen_anchor_fprs: set[str] = set()
    for idx, item in enumerate(raw_anchors):
        ctx = f"{source_label}.trust.anchors[{idx}]"
        if not isinstance(item, dict):
            raise PluginManifestError(f"{ctx} must be a table")
        _reject_extra_keys(item, frozenset({"fingerprint", "label", "role", "key_file"}), context=ctx)
        fpr = validate_fingerprint(item.get("fingerprint"), label=f"{ctx}.fingerprint")
        if fpr in seen_anchor_fprs:
            raise PluginManifestError(f"{ctx}: duplicate trust anchor fingerprint {fpr}")
        seen_anchor_fprs.add(fpr)
        label = item.get("label")
        if not isinstance(label, str) or not label.strip() or "\n" in label or "\x00" in label:
            raise PluginManifestError(f"{ctx}.label must be a non-empty single-line string")
        role = item.get("role", "root")
        if role not in ALLOWED_ANCHOR_ROLES:
            raise PluginManifestError(f"{ctx}.role invalid: {role!r} (expected 'root' or 'direct')")
        key_file = validate_safe_filename(item.get("key_file"), label=f"{ctx}.key_file")
        anchors.append(TrustAnchor(fingerprint=fpr, label=label.strip(), role=role, key_file=key_file))

    raw_revs = trust_raw.get("revocations", [])
    if not isinstance(raw_revs, list):
        raise PluginManifestError(f"{source_label}.trust.revocations must be an array of tables")
    revocations: list[KeyRevocation] = []
    seen_rev_fprs: set[str] = set()
    for idx, item in enumerate(raw_revs):
        ctx = f"{source_label}.trust.revocations[{idx}]"
        if not isinstance(item, dict):
            raise PluginManifestError(f"{ctx} must be a table")
        _reject_extra_keys(item, frozenset({"fingerprint", "mode", "revoked_at", "reason", "cert_file"}), context=ctx)
        fpr = validate_fingerprint(item.get("fingerprint"), label=f"{ctx}.fingerprint")
        if fpr in seen_rev_fprs:
            raise PluginManifestError(f"{ctx}: duplicate revocation fingerprint {fpr}")
        seen_rev_fprs.add(fpr)
        mode = item.get("mode")
        if mode not in ALLOWED_REVOCATION_MODES:
            raise PluginManifestError(f"{ctx}.mode invalid: {mode!r} (expected 'soft' or 'hard')")
        rev_dt = parse_rfc3339_utc(item.get("revoked_at"), label=f"{ctx}.revoked_at")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip() or "\n" in reason or "\x00" in reason:
            raise PluginManifestError(f"{ctx}.reason must be a non-empty single-line string")
        cert_file = None
        if "cert_file" in item and item["cert_file"] is not None:
            cert_file = validate_safe_filename(item["cert_file"], label=f"{ctx}.cert_file")
        revocations.append(
            KeyRevocation(
                fingerprint=fpr,
                mode=mode,
                revoked_at=format_rfc3339_utc(rev_dt),
                reason=reason.strip(),
                cert_file=cert_file,
            )
        )

    trust = TrustPolicy(
        keyring_dir=keyring_dir,
        max_depth=max_depth,
        marginal_threshold=marginal_threshold,
        full_threshold=full_threshold,
        max_validity_days=max_validity_days,
        backend=backend,
        anchors=tuple(anchors),
        revocations=tuple(revocations),
    )

    raw_plugins = data.get("plugins", [])
    if not isinstance(raw_plugins, list):
        raise PluginManifestError(f"{source_label}.plugins must be an array of tables")
    plugins: list[PluginPin] = []
    seen_plugins: set[tuple[str, str]] = set()
    for idx, item in enumerate(raw_plugins):
        ctx = f"{source_label}.plugins[{idx}]"
        if not isinstance(item, dict):
            raise PluginManifestError(f"{ctx} must be a table")
        source = item.get("source")
        if source not in ALLOWED_PLUGIN_SOURCES:
            raise PluginManifestError(
                f"{ctx}.source invalid: {source!r} (expected one of {sorted(ALLOWED_PLUGIN_SOURCES)})"
            )
        kind = item.get("kind")
        if kind not in ALLOWED_SITE_PLUGIN_KINDS:
            raise PluginManifestError(
                f"{ctx}.kind {kind!r} is forbidden (allowed: 'frontend', 'importer'; supervisors are in-tree only)"
            )
        name = validate_plugin_name(item.get("name"), kind=kind, source=source)
        if (kind, name) in seen_plugins:
            raise PluginManifestError(f"{ctx}: duplicate plugin ({kind!r}, {name!r}) — refused")
        seen_plugins.add((kind, name))

        if source == "in-tree":
            _reject_extra_keys(item, frozenset({"name", "kind", "source"}), context=ctx)
            plugins.append(PluginPin(name=name, kind=kind, source=source))
        elif source == "contrib":
            _reject_extra_keys(item, frozenset({"name", "kind", "source", "relpath"}), context=ctx)
            relpath = validate_contrib_relpath(item.get("relpath"))
            plugins.append(PluginPin(name=name, kind=kind, source=source, relpath=relpath))
        else:
            _reject_extra_keys(
                item,
                frozenset(
                    {
                        "name",
                        "kind",
                        "source",
                        "distribution",
                        "version",
                        "entry_point",
                        "wheel_filename",
                        "wheel_sha256",
                        "release_seq",
                        "issued_at",
                        "expires_at",
                        "manifest_sha256",
                        "signer_fingerprint",
                        "signing_subkey_fingerprint",
                        "verified_at",
                        "dependencies",
                    }
                ),
                context=ctx,
            )
            dist = validate_external_distribution(item.get("distribution"), label=f"{ctx}.distribution")
            ver = item.get("version")
            if not isinstance(ver, str) or not VERSION_RE.match(ver):
                raise PluginManifestError(f"{ctx}.version invalid: {ver!r}")
            ep = item.get("entry_point")
            if not isinstance(ep, str) or not ENTRY_POINT_RE.match(ep):
                raise PluginManifestError(f"{ctx}.entry_point invalid: {ep!r}")
            wfn = validate_wheel_filename(item.get("wheel_filename"), label=f"{ctx}.wheel_filename")
            fn_dist, fn_ver = parse_wheel_filename_parts(wfn)
            if fn_dist != normalize_dist_name(dist) or fn_ver != ver:
                raise PluginManifestError(
                    f"{ctx}: wheel_filename {wfn!r} does not match distribution={dist!r} version={ver!r}"
                )
            wsha = validate_sha256(item.get("wheel_sha256"), label=f"{ctx}.wheel_sha256")
            rseq = _require_int(item.get("release_seq"), label=f"{ctx}.release_seq", minimum=1)
            issued_dt = parse_rfc3339_utc(item.get("issued_at"), label=f"{ctx}.issued_at")
            expires_dt = parse_rfc3339_utc(item.get("expires_at"), label=f"{ctx}.expires_at")
            if expires_dt <= issued_dt:
                raise PluginManifestError(f"{ctx}: expires_at must be strictly after issued_at")
            msha = validate_sha256(item.get("manifest_sha256"), label=f"{ctx}.manifest_sha256")
            sfpr = validate_fingerprint(item.get("signer_fingerprint"), label=f"{ctx}.signer_fingerprint")
            sub_raw = item.get("signing_subkey_fingerprint")
            sub_fpr = (
                validate_fingerprint(sub_raw, label=f"{ctx}.signing_subkey_fingerprint")
                if sub_raw is not None
                else sfpr
            )
            ver_dt = parse_rfc3339_utc(item.get("verified_at"), label=f"{ctx}.verified_at")

            raw_deps = item.get("dependencies", [])
            if not isinstance(raw_deps, list):
                raise PluginManifestError(f"{ctx}.dependencies must be a list")
            deps: list[WheelDependencyPin] = []
            seen_d: set[str] = {normalize_dist_name(dist)}
            seen_f: set[str] = {wfn}
            for didx, ditem in enumerate(raw_deps):
                dep = _parse_dependency(ditem, context=f"{ctx}.dependencies[{didx}]")
                nd = normalize_dist_name(dep.distribution)
                if nd in seen_d:
                    raise PluginManifestError(f"{ctx}: duplicate dependency distribution {dep.distribution!r}")
                if dep.filename in seen_f:
                    raise PluginManifestError(f"{ctx}: duplicate dependency filename {dep.filename!r}")
                seen_d.add(nd)
                seen_f.add(dep.filename)
                deps.append(dep)

            plugins.append(
                PluginPin(
                    name=name,
                    kind=kind,
                    source=source,
                    distribution=dist,
                    version=ver,
                    entry_point=ep,
                    wheel_filename=wfn,
                    wheel_sha256=wsha,
                    release_seq=rseq,
                    issued_at=format_rfc3339_utc(issued_dt),
                    expires_at=format_rfc3339_utc(expires_dt),
                    manifest_sha256=msha,
                    signer_fingerprint=sfpr,
                    signing_subkey_fingerprint=sub_fpr,
                    verified_at=format_rfc3339_utc(ver_dt),
                    dependencies=tuple(deps),
                )
            )

    raw_floors = data.get("plugin_floors", [])
    if not isinstance(raw_floors, list):
        raise PluginManifestError(f"{source_label}.plugin_floors must be an array of tables")
    floors: list[PluginFloor] = []
    seen_floors: set[tuple[str, str]] = set()
    for idx, item in enumerate(raw_floors):
        ctx = f"{source_label}.plugin_floors[{idx}]"
        if not isinstance(item, dict):
            raise PluginManifestError(f"{ctx} must be a table")
        _reject_extra_keys(
            item,
            frozenset({"name", "kind", "distribution", "min_release_seq", "signer_fingerprint"}),
            context=ctx,
        )
        kind = item.get("kind")
        if kind not in ALLOWED_SITE_PLUGIN_KINDS:
            raise PluginManifestError(f"{ctx}.kind {kind!r} is forbidden")
        name = validate_plugin_name(item.get("name"), kind=kind, source="out-of-tree")
        if (kind, name) in seen_floors:
            raise PluginManifestError(f"{ctx}: duplicate plugin_floor ({kind!r}, {name!r})")
        seen_floors.add((kind, name))
        dist = validate_external_distribution(item.get("distribution"), label=f"{ctx}.distribution")
        min_seq = _require_int(item.get("min_release_seq"), label=f"{ctx}.min_release_seq", minimum=1)
        sfpr = validate_fingerprint(item.get("signer_fingerprint"), label=f"{ctx}.signer_fingerprint")
        floors.append(
            PluginFloor(
                name=name,
                kind=kind,
                distribution=dist,
                min_release_seq=min_seq,
                signer_fingerprint=sfpr,
            )
        )

    return SitePluginsConfig(
        schema_version=sv,
        without_ai=without_ai,
        trust=trust,
        plugins=tuple(plugins),
        plugin_floors=tuple(floors),
    )


def load_site_plugins_config(path: Path, *, allow_missing: bool = False) -> SitePluginsConfig:
    if not path.exists() and not path.is_symlink():
        if allow_missing:
            return SitePluginsConfig()
        raise PluginManifestError(f"plugins config not found: {path}")
    raw = read_regular_file_bytes(path, max_bytes=MAX_TOML_BYTES, label="plugins.toml")
    return parse_site_plugins_toml(raw, source_label=str(path))


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_site_plugins_toml(config: SitePluginsConfig) -> str:
    """Render deterministic TOML for `<site_private>/plugins.toml` (round-trip parse verified)."""
    lines: list[str] = [
        "# Managed by `tendcf plugin` (issue #47). Changes to this file are privileged",
        "# (gate-5 ceremony marker required per docs/architecture/plugin-layout.md §4).",
        f"schema_version = {config.schema_version}",
        "",
        "[external_import]",
        f"without_ai = {_toml_str(config.without_ai)}",
        "",
        "[trust]",
        f"keyring_dir = {_toml_str(config.trust.keyring_dir)}",
        f"max_depth = {config.trust.max_depth}",
        f"marginal_threshold = {config.trust.marginal_threshold}",
        f"full_threshold = {config.trust.full_threshold}",
        f"max_validity_days = {config.trust.max_validity_days}",
        f"backend = {_toml_str(config.trust.backend)}",
    ]

    for anchor in sorted(config.trust.anchors, key=lambda a: a.fingerprint):
        lines.extend(
            [
                "",
                "[[trust.anchors]]",
                f"fingerprint = {_toml_str(anchor.fingerprint)}",
                f"label = {_toml_str(anchor.label)}",
                f"role = {_toml_str(anchor.role)}",
                f"key_file = {_toml_str(anchor.key_file)}",
            ]
        )

    for rev in sorted(config.trust.revocations, key=lambda r: r.fingerprint):
        lines.extend(
            [
                "",
                "[[trust.revocations]]",
                f"fingerprint = {_toml_str(rev.fingerprint)}",
                f"mode = {_toml_str(rev.mode)}",
                f"revoked_at = {_toml_str(rev.revoked_at)}",
                f"reason = {_toml_str(rev.reason)}",
            ]
        )
        if rev.cert_file is not None:
            lines.append(f"cert_file = {_toml_str(rev.cert_file)}")

    for pin in sorted(config.plugins, key=lambda p: (p.kind, p.name)):
        lines.extend(
            [
                "",
                "[[plugins]]",
                f"name = {_toml_str(pin.name)}",
                f"kind = {_toml_str(pin.kind)}",
                f"source = {_toml_str(pin.source)}",
            ]
        )
        if pin.source == "contrib":
            assert pin.relpath is not None
            lines.append(f"relpath = {_toml_str(pin.relpath)}")
        elif pin.source == "out-of-tree":
            assert pin.distribution is not None
            assert pin.version is not None
            assert pin.entry_point is not None
            assert pin.wheel_filename is not None
            assert pin.wheel_sha256 is not None
            assert pin.release_seq is not None
            assert pin.issued_at is not None
            assert pin.expires_at is not None
            assert pin.manifest_sha256 is not None
            assert pin.signer_fingerprint is not None
            assert pin.verified_at is not None
            lines.extend(
                [
                    f"distribution = {_toml_str(pin.distribution)}",
                    f"version = {_toml_str(pin.version)}",
                    f"entry_point = {_toml_str(pin.entry_point)}",
                    f"wheel_filename = {_toml_str(pin.wheel_filename)}",
                    f"wheel_sha256 = {_toml_str(pin.wheel_sha256)}",
                    f"release_seq = {pin.release_seq}",
                    f"issued_at = {_toml_str(pin.issued_at)}",
                    f"expires_at = {_toml_str(pin.expires_at)}",
                    f"manifest_sha256 = {_toml_str(pin.manifest_sha256)}",
                    f"signer_fingerprint = {_toml_str(pin.signer_fingerprint)}",
                    f"signing_subkey_fingerprint = {_toml_str(pin.signing_subkey_fingerprint or pin.signer_fingerprint)}",
                    f"verified_at = {_toml_str(pin.verified_at)}",
                ]
            )
            if pin.dependencies:
                lines.append("dependencies = [")
                for dep in sorted(pin.dependencies, key=lambda d: normalize_dist_name(d.distribution)):
                    lines.append(
                        "  { "
                        f"distribution = {_toml_str(dep.distribution)}, "
                        f"version = {_toml_str(dep.version)}, "
                        f"filename = {_toml_str(dep.filename)}, "
                        f"sha256 = {_toml_str(dep.sha256)}"
                        " },"
                    )
                lines.append("]")
            else:
                lines.append("dependencies = []")

    for floor in sorted(config.plugin_floors, key=lambda f: (f.kind, f.name)):
        lines.extend(
            [
                "",
                "[[plugin_floors]]",
                f"name = {_toml_str(floor.name)}",
                f"kind = {_toml_str(floor.kind)}",
                f"distribution = {_toml_str(floor.distribution)}",
                f"min_release_seq = {floor.min_release_seq}",
                f"signer_fingerprint = {_toml_str(floor.signer_fingerprint)}",
            ]
        )

    rendered = "\n".join(lines) + "\n"
    parse_site_plugins_toml(rendered.encode("utf-8"), source_label="<rendered plugins.toml>")
    return rendered


def write_site_plugins_config(path: Path, config: SitePluginsConfig) -> None:
    """Atomically write `plugins.toml` after refusing any symlink at `path` or its parent."""
    if path.is_symlink():
        raise PluginManifestError(f"refusing to write plugins.toml through symlink: {path}")
    parent = path.parent
    if parent.is_symlink():
        raise PluginManifestError(f"refusing to write plugins.toml into symlinked directory: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    rendered = render_site_plugins_toml(config).encode("utf-8")

    fd, tmp_name = tempfile.mkstemp(prefix=".plugins.toml.", suffix=".tmp", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(rendered)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
