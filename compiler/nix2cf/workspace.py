"""Multi-site local ops workspace resolution for tendcf / nix2cf (issue #98).

Layout under `~/tendcf-ops` (override: `--ops-root` or `TENDCF_OPS_ROOT`):

  <ops_root>/
    tendcf/                    # optional local engine checkout (informational only; never auto-loaded by builds)
    tendcf-private-<site>/     # REQUIRED primary site root (D35: inventory private)
    tendcf-public-<site>/      # OPTIONAL publishable recipes/exports companion
    tendcf-public-<other>/     # OPTIONAL local read-only clones of foreign public sites
    .worktrees/                # excluded from site scan (worktrees live here or ~/src/)

Rules enforced here (operator rulings 2026-11-24, Ref: ANTIGRAVITY-we, ANTIGRAVITY-wf):

1. Pair-bound, fail-closed selection: a single validated `<site>` slug selects
   `(tendcf-private-<site>, tendcf-public-<site>)` together. Precedence:
   `--site-name` > `TENDCF_SITE` > XDG `active-site` file
   (`$XDG_CONFIG_HOME/tendcf/active-site` when absolute, else `~/.config/tendcf/active-site`),
   or an explicit `--config PATH` (mutually exclusive with `--site-name`, honored ahead of
   ambient `TENDCF_SITE` and failing closed if missing).
2. Zero silent guessing and zero legacy aliases: never glob a sole `tendcf-private-*`
   checkout; never accept bare `tendcf-private`, `site-private`, `.mysite`, or uncoupled
   public/private selectors.
3. No release build reads sibling checkouts (D21/D34/D35/D46). Explicit dev-only
   `--override-input <ns>=<path>` validates paths, warns loudly, records taint on
   `WorkspaceResolution` / `CompileResult`, blocks `-o` artifact writes without
   `--allow-tainted`, and fails `--check-releasable` / `assert_releasable()` (foreign-input
   substitution itself awaits `site.lock` composition; future release/signing pipelines must
   call the release gate and refuse override builds, per D46(9b)).
4. Mutable runtime state lives under XDG (`state_dir()`, `cache_dir()`), never inside
   git checkouts.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_OPS_ROOT_NAME = "tendcf-ops"
PRIVATE_PREFIX = "tendcf-private-"
PUBLIC_PREFIX = "tendcf-public-"
MAX_SLUG_LENGTH = 64
MAX_ACTIVE_SITE_BYTES = 4096

# Lowercase ASCII slug: <operator> or <operator>-<name> (e.g. djbclark, djbclark-lab).
# `\Z` (not `$`) refuses a trailing newline.
SITE_SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
OVERRIDE_NS_RE = SITE_SLUG_RE

# Worktree suffix reserved so stray worktrees inside ops_root are never mistaken for sites.
WORKTREE_SUFFIX = "-wt"

SITE_MODEL_FILENAMES = ("services.yml", "roles.yml", "launchd-writers.yml")


class WorkspaceError(Exception):
    """Workspace configuration, selection, override, or release-gate refusal."""


@dataclass(frozen=True)
class OverrideInput:
    """One explicit dev-only local checkout binding (`--override-input <ns>=<path>`)."""

    namespace: str
    path: Path

    def to_dict(self) -> dict[str, str]:
        return {"namespace": self.namespace, "path": str(self.path)}

    def format_spec(self) -> str:
        return f"{self.namespace}={self.path}"


@dataclass(frozen=True)
class DiscoveredSite:
    """One slug discovered directly under `ops_root` by `list_sites()`."""

    slug: str
    private_dir: Path | None
    public_dir: Path | None

    @property
    def role(self) -> str:
        return "site" if self.private_dir is not None else "foreign-public-only"

    def to_dict(self) -> dict[str, str | None]:
        return {
            "slug": self.slug,
            "role": self.role,
            "private_dir": str(self.private_dir) if self.private_dir is not None else None,
            "public_dir": str(self.public_dir) if self.public_dir is not None else None,
        }


@dataclass(frozen=True)
class SiteInventory:
    """Result of scanning direct children of `ops_root` without selecting a site."""

    ops_root: Path
    ops_root_source: str
    tendcf_dir: Path | None
    sites: tuple[DiscoveredSite, ...]
    warnings: tuple[str, ...]
    state_dir: Path
    cache_dir: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "ops_root": str(self.ops_root),
            "ops_root_source": self.ops_root_source,
            "tendcf_dir": str(self.tendcf_dir) if self.tendcf_dir is not None else None,
            "sites": [s.to_dict() for s in self.sites],
            "warnings": list(self.warnings),
            "state_dir": str(self.state_dir),
            "cache_dir": str(self.cache_dir),
        }


@dataclass(frozen=True)
class WorkspaceResolution:
    """Resolved pair-bound workspace for a single site slug.

    `tendcf_dir` is strictly informational (for `nix2cf workspace` inspection/tooling);
    `buildfile` never auto-loads schemas or `bin/projector.py` from `<ops_root>/tendcf`.
    """

    ops_root: Path
    ops_root_source: str
    site_slug: str
    selection_source: str
    private_dir: Path
    public_dir: Path | None
    tendcf_dir: Path | None
    overrides: tuple[OverrideInput, ...]
    state_dir: Path
    cache_dir: Path

    @property
    def tainted(self) -> bool:
        return bool(self.overrides)

    @property
    def release_blocked(self) -> bool:
        return self.tainted

    def assert_releasable(self) -> None:
        """Fail closed if any dev-only `--override-input` is active."""
        refuse_release_if_tainted(self.overrides)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ops_root": str(self.ops_root),
            "ops_root_source": self.ops_root_source,
            "site_slug": self.site_slug,
            "selection_source": self.selection_source,
            "private_dir": str(self.private_dir),
            "public_dir": str(self.public_dir) if self.public_dir is not None else None,
            "tendcf_dir": str(self.tendcf_dir) if self.tendcf_dir is not None else None,
            "overrides": [o.to_dict() for o in self.overrides],
            "tainted": self.tainted,
            "release_blocked": self.release_blocked,
            "state_dir": str(self.state_dir),
            "cache_dir": str(self.cache_dir),
        }


def _env_map(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def _home_dir(env: Mapping[str, str]) -> Path:
    raw = env.get("HOME", "")
    if raw and "\x00" not in raw:
        candidate = Path(raw)
        if candidate.is_absolute():
            return candidate
    return Path.home()


def _expand_path(raw: str, env: Mapping[str, str]) -> Path:
    """Expand strictly `~` and `~/...` against `_home_dir(env)`; reject `~otheruser/...`."""
    if "\x00" in raw:
        raise WorkspaceError("path contains a NUL byte")
    if raw == "~":
        return _home_dir(env)
    if raw.startswith("~/"):
        rest = raw[2:].lstrip("/")
        return _home_dir(env) / rest if rest else _home_dir(env)
    if raw.startswith("~"):
        raise WorkspaceError(
            f"unsupported tilde user expansion in path {raw!r}; only '~' and '~/...' are allowed"
        )
    return Path(raw)


def _safe_resolve(path: Path, *, label: str) -> Path:
    """Resolve `path` strictly, converting OSError and RuntimeError (symlink loop) to WorkspaceError."""
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceError(f"cannot resolve {label} {path}: {exc}") from exc


def _scandir_entries(directory: Path, *, label: str) -> list[os.DirEntry[str]]:
    try:
        with os.scandir(directory) as it:
            return list(it)
    except OSError as exc:
        raise WorkspaceError(f"cannot read {label} {directory}: {exc}") from exc


def _find_exact_entry(
    directory: Path,
    name: str,
    *,
    label: str,
) -> tuple[os.DirEntry[str] | None, os.DirEntry[str] | None]:
    """Return `(exact_match, case_mismatch)` among direct entries of `directory`."""
    exact: os.DirEntry[str] | None = None
    case_mismatch: os.DirEntry[str] | None = None
    target_lower = name.lower()
    for entry in _scandir_entries(directory, label=label):
        if entry.name == name:
            exact = entry
            break
        if case_mismatch is None and entry.name.lower() == target_lower:
            case_mismatch = entry
    return exact, case_mismatch


def _xdg_subdir(env: Mapping[str, str], var: str, fallback_parts: tuple[str, ...]) -> Path:
    """XDG Base Directory Specification: honor `$VAR` only when it is an absolute path."""
    raw = env.get(var, "")
    if raw and "\x00" not in raw:
        candidate = Path(raw)
        if candidate.is_absolute():
            return candidate / "tendcf"
    return _home_dir(env).joinpath(*fallback_parts, "tendcf")


def config_dir(env: Mapping[str, str] | None = None) -> Path:
    """XDG config directory (`$XDG_CONFIG_HOME/tendcf` or `~/.config/tendcf`)."""
    return _xdg_subdir(_env_map(env), "XDG_CONFIG_HOME", (".config",))


def active_site_config_path(env: Mapping[str, str] | None = None) -> Path:
    """Default XDG active-site file (`$XDG_CONFIG_HOME/tendcf/active-site`)."""
    return config_dir(env) / "active-site"


def state_dir(env: Mapping[str, str] | None = None) -> Path:
    """XDG mutable state directory (`$XDG_STATE_HOME/tendcf` or `~/.local/state/tendcf`)."""
    return _xdg_subdir(_env_map(env), "XDG_STATE_HOME", (".local", "state"))


def cache_dir(env: Mapping[str, str] | None = None) -> Path:
    """XDG cache directory (`$XDG_CACHE_HOME/tendcf` or `~/.cache/tendcf`)."""
    return _xdg_subdir(_env_map(env), "XDG_CACHE_HOME", (".cache",))


def validate_site_slug(slug: str, *, label: str = "site slug") -> str:
    """Validate `<site>` slug grammar (`<operator>` or `<operator>-<name>`)."""
    if not isinstance(slug, str) or not slug:
        raise WorkspaceError(f"{label} must not be empty")
    if "\x00" in slug:
        raise WorkspaceError(f"{label} contains a NUL byte")
    if len(slug) > MAX_SLUG_LENGTH:
        raise WorkspaceError(
            f"{label} {slug!r} exceeds maximum length of {MAX_SLUG_LENGTH} characters"
        )
    if not SITE_SLUG_RE.match(slug):
        raise WorkspaceError(
            f"invalid {label} {slug!r}: expected lowercase ASCII matching "
            f"{SITE_SLUG_RE.pattern!r} (e.g. 'djbclark' or 'djbclark-lab')"
        )
    if slug.endswith(WORKTREE_SUFFIX):
        raise WorkspaceError(
            f"invalid {label} {slug!r}: suffix {WORKTREE_SUFFIX!r} is reserved for worktrees "
            "(keep development worktrees in ~/src/ or <ops_root>/.worktrees/)"
        )
    return slug


def validate_override_namespace(namespace: str) -> str:
    """Validate an `--override-input` namespace identifier."""
    if not isinstance(namespace, str) or not namespace:
        raise WorkspaceError("override-input namespace must not be empty")
    if "\x00" in namespace:
        raise WorkspaceError("override-input namespace contains a NUL byte")
    if len(namespace) > MAX_SLUG_LENGTH:
        raise WorkspaceError(
            f"override-input namespace {namespace!r} exceeds maximum length of {MAX_SLUG_LENGTH} characters"
        )
    if not OVERRIDE_NS_RE.match(namespace):
        raise WorkspaceError(
            f"invalid override-input namespace {namespace!r}: expected lowercase ASCII matching "
            f"{OVERRIDE_NS_RE.pattern!r} (no path separators, dots, or uppercase)"
        )
    return namespace


def _inspect_real_subpath(
    parent: Path,
    name: str,
    *,
    expect: str,
    root_label: str,
) -> Path | None:
    """Verify exact-case non-symlink child (`dir` or `file`) under `parent`.

    Returns the resolved child Path if present and valid, `None` if absent,
    and raises `WorkspaceError` on symlink, case mismatch, wrong type, or containment failure.
    """
    exact, case_mismatch = _find_exact_entry(parent, name, label=root_label)
    if exact is None:
        if case_mismatch is not None:
            raise WorkspaceError(
                f"{root_label} entry {name!r} has wrong casing under {parent}: "
                f"found {case_mismatch.name!r}"
            )
        return None
    candidate = Path(exact.path)
    try:
        is_link = exact.is_symlink()
        is_dir = exact.is_dir(follow_symlinks=False)
        is_file = exact.is_file(follow_symlinks=False)
    except OSError as exc:
        raise WorkspaceError(f"cannot inspect {root_label} {candidate}: {exc}") from exc
    if is_link:
        raise WorkspaceError(
            f"{root_label} {candidate} is a symlink (refused; must be a real {expect})"
        )
    if expect == "dir" and not is_dir:
        raise WorkspaceError(f"{root_label} {candidate} exists but is not a directory")
    if expect == "file" and not is_file:
        raise WorkspaceError(f"{root_label} {candidate} exists but is not a regular file")
    resolved = _safe_resolve(candidate, label=root_label)
    if resolved.parent != parent:
        raise WorkspaceError(
            f"{root_label} resolves outside {parent}: {resolved}"
        )
    return resolved


def _check_tendcf_dir(ops_root: Path) -> Path | None:
    """Inspect `<ops_root>/tendcf` with exact-case, non-symlink, containment checks.

    Fails closed (`WorkspaceError`) if `<ops_root>/tendcf` exists as a symlink or
    non-directory, has wrong casing, or has symlinked/non-regular `schema/`,
    `schema/goal-file.schema.json`, `bin/`, or `bin/projector.py`.
    Returns `None` if `<ops_root>/tendcf` does not exist or is a plain directory
    that does not contain both checkout markers.
    """
    tendcf_root = _inspect_real_subpath(
        ops_root, "tendcf", expect="dir", root_label="local tendcf checkout"
    )
    if tendcf_root is None:
        return None
    schema_dir = _inspect_real_subpath(
        tendcf_root, "schema", expect="dir", root_label="local tendcf schema directory"
    )
    schema_file = (
        _inspect_real_subpath(
            schema_dir,
            "goal-file.schema.json",
            expect="file",
            root_label="local tendcf goal-file schema",
        )
        if schema_dir is not None
        else None
    )
    bin_dir = _inspect_real_subpath(
        tendcf_root, "bin", expect="dir", root_label="local tendcf bin directory"
    )
    projector_file = (
        _inspect_real_subpath(
            bin_dir,
            "projector.py",
            expect="file",
            root_label="local tendcf projector",
        )
        if bin_dir is not None
        else None
    )
    if schema_file is None or projector_file is None:
        return None
    return tendcf_root


def is_tendcf_checkout(path: Path) -> bool:
    """True iff `path` is a real non-symlink tendcf checkout with real schema and projector files."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    try:
        resolved = _safe_resolve(path, label="tendcf checkout")
        schema_dir = _inspect_real_subpath(
            resolved, "schema", expect="dir", root_label="tendcf schema directory"
        )
        if schema_dir is None:
            return False
        schema_file = _inspect_real_subpath(
            schema_dir, "goal-file.schema.json", expect="file", root_label="tendcf goal-file schema"
        )
        bin_dir = _inspect_real_subpath(
            resolved, "bin", expect="dir", root_label="tendcf bin directory"
        )
        if bin_dir is None:
            return False
        projector_file = _inspect_real_subpath(
            bin_dir, "projector.py", expect="file", root_label="tendcf projector"
        )
        return schema_file is not None and projector_file is not None
    except WorkspaceError:
        return False


def resolve_ops_root(
    arg: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[Path, str]:
    """Resolve ops root directory with precedence `--ops-root` > `TENDCF_OPS_ROOT` > `~/tendcf-ops`.

    Requires an absolute path (after expanding `~`) that exists and is a directory.
    Returns `(resolved_ops_root, source)`.
    """
    env_m = _env_map(env)
    if arg is not None:
        raw = str(arg)
        source = "cli"
        if not raw.strip():
            raise WorkspaceError("--ops-root must not be empty")
    elif "TENDCF_OPS_ROOT" in env_m:
        raw = env_m["TENDCF_OPS_ROOT"]
        source = "env:TENDCF_OPS_ROOT"
        if not raw.strip():
            raise WorkspaceError("TENDCF_OPS_ROOT is set but empty")
    else:
        raw = str(_home_dir(env_m) / DEFAULT_OPS_ROOT_NAME)
        source = "default"

    expanded = _expand_path(raw, env_m)
    if not expanded.is_absolute():
        raise WorkspaceError(
            f"ops root {raw!r} (from {source}) must be an absolute path (or start with '~/')"
        )
    try:
        lstat_res = os.lstat(expanded)
    except FileNotFoundError as exc:
        raise WorkspaceError(f"ops root does not exist: {expanded} (from {source})") from exc
    except OSError as exc:
        raise WorkspaceError(f"cannot inspect ops root {expanded} (from {source}): {exc}") from exc

    is_symlink = stat.S_ISLNK(lstat_res.st_mode)
    try:
        stat_res = os.stat(expanded)
    except FileNotFoundError as exc:
        if is_symlink:
            raise WorkspaceError(
                f"ops root {expanded} (from {source}) is a dangling symlink"
            ) from exc
        raise WorkspaceError(f"ops root does not exist: {expanded} (from {source})") from exc
    except OSError as exc:
        raise WorkspaceError(f"cannot access ops root {expanded} (from {source}): {exc}") from exc

    if not stat.S_ISDIR(stat_res.st_mode):
        raise WorkspaceError(f"ops root is not a directory: {expanded} (from {source})")
    return _safe_resolve(expanded, label=f"ops root (from {source})"), source


def _read_active_site_file(path: Path) -> str | None:
    """Read a plain single-line non-symlink active-site file; return None if missing."""
    try:
        is_link = path.is_symlink()
    except OSError as exc:
        raise WorkspaceError(f"cannot inspect active-site config {path}: {exc}") from exc
    if is_link:
        raise WorkspaceError(f"active-site config must not be a symlink: {path}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
            raise WorkspaceError(f"active-site config must not be a symlink: {path}") from exc
        raise WorkspaceError(f"cannot read active-site config {path}: {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise WorkspaceError(f"active-site config must be a regular file: {path}")
        if st.st_size > MAX_ACTIVE_SITE_BYTES:
            raise WorkspaceError(
                f"active-site config exceeds {MAX_ACTIVE_SITE_BYTES} bytes: {path}"
            )
        fh = os.fdopen(fd, "rb")
    except WorkspaceError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise WorkspaceError(f"cannot inspect active-site config {path}: {exc}") from exc
    except BaseException:
        os.close(fd)
        raise

    with fh:
        try:
            data = fh.read(MAX_ACTIVE_SITE_BYTES + 1)
        except OSError as exc:
            raise WorkspaceError(f"cannot read active-site config {path}: {exc}") from exc

    if len(data) > MAX_ACTIVE_SITE_BYTES:
        raise WorkspaceError(
            f"active-site config exceeds {MAX_ACTIVE_SITE_BYTES} bytes: {path}"
        )
    if b"\x00" in data:
        raise WorkspaceError(f"active-site config contains a NUL byte: {path}")
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkspaceError(f"active-site config is not valid UTF-8: {path}: {exc}") from exc

    normalized = raw.replace("\r\n", "\n")
    if "\r" in normalized:
        raise WorkspaceError(f"active-site config contains bare CR (\\r) characters: {path}")

    entries: list[str] = []
    for line in normalized.split("\n"):
        stripped = line.strip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(stripped)

    if not entries:
        raise WorkspaceError(f"active-site config has no site slug: {path}")
    if len(entries) > 1:
        raise WorkspaceError(
            f"active-site config is ambiguous ({len(entries)} entries): {path}; "
            "expected a single site slug line"
        )
    return validate_site_slug(entries[0], label=f"site slug in {path}")


def resolve_site_slug(
    arg: str | None = None,
    env: Mapping[str, str] | None = None,
    config_path: str | Path | None = None,
    *,
    read_config: bool = True,
) -> tuple[str, str]:
    """Resolve site slug with precedence `--site-name` > `TENDCF_SITE` > XDG `active-site`.

    An explicit `config_path` is mutually exclusive with `--site-name`, takes precedence
    over ambient `TENDCF_SITE`, and fails closed if that file is missing.
    Fails closed when no selector is present — never globs `ops_root`.
    Returns `(slug, selection_source)`.
    """
    env_m = _env_map(env)
    if arg is not None and config_path is not None:
        raise WorkspaceError("--site-name cannot be combined with --config")

    if arg is not None:
        return validate_site_slug(arg, label="--site-name"), "cli"

    if config_path is not None:
        raw_cfg = str(config_path)
        if not raw_cfg.strip():
            raise WorkspaceError("active-site config path must not be empty")
        cfg_path = _expand_path(raw_cfg, env_m)
        slug = _read_active_site_file(cfg_path)
        if slug is None:
            raise WorkspaceError(f"active-site config file not found: {cfg_path}")
        return slug, f"config:{cfg_path}"

    if "TENDCF_SITE" in env_m:
        raw_env = env_m["TENDCF_SITE"]
        if not raw_env:
            raise WorkspaceError("TENDCF_SITE is set but empty")
        return validate_site_slug(raw_env, label="TENDCF_SITE"), "env:TENDCF_SITE"

    default_cfg = active_site_config_path(env_m)
    if read_config:
        slug = _read_active_site_file(default_cfg)
        if slug is not None:
            return slug, f"config:{default_cfg}"

    raise WorkspaceError(
        "no site selected (refusing to guess or glob ops root); specify --site-name <slug>, "
        f"set TENDCF_SITE=<slug>, or write a single slug line to {default_cfg}"
    )


def _check_site_repo_dir(
    ops_root: Path,
    name: str,
    *,
    required: bool,
    role_label: str,
) -> Path | None:
    """Verify `<ops_root>/<name>` is an exact-case real directory inside `ops_root` (no symlinks)."""
    exact, case_mismatch = _find_exact_entry(ops_root, name, label="ops root")
    if exact is None:
        if case_mismatch is not None:
            raise WorkspaceError(
                f"{role_label} has wrong directory casing under {ops_root}: "
                f"found {case_mismatch.name!r}, expected exact {name!r}"
            )
        if required:
            raise WorkspaceError(
                f"{role_label} not found: {ops_root / name} "
                f"(expected directory {name!r} directly under {ops_root})"
            )
        return None

    candidate = Path(exact.path)
    try:
        is_link = exact.is_symlink()
        is_dir = exact.is_dir(follow_symlinks=False)
    except OSError as exc:
        raise WorkspaceError(f"cannot inspect {role_label} {candidate}: {exc}") from exc

    if is_link:
        try:
            target_exists = candidate.exists()
        except OSError:
            target_exists = False
        if not target_exists:
            raise WorkspaceError(
                f"{role_label} is a dangling symlink: {candidate} "
                "(refused; site repositories must be real directories)"
            )
        raise WorkspaceError(
            f"{role_label} is a symlink: {candidate} "
            "(refused; site repositories must be real directories to prevent aliasing "
            "and cross-site mismatch)"
        )
    if not is_dir:
        raise WorkspaceError(f"{role_label} exists but is not a directory: {candidate}")
    resolved = _safe_resolve(candidate, label=role_label)
    if resolved.parent != ops_root:
        raise WorkspaceError(
            f"{role_label} resolves outside ops root {ops_root}: {resolved}"
        )
    return resolved


def parse_override_inputs(
    raw_specs: Iterable[str] | None,
    env: Mapping[str, str] | None = None,
) -> tuple[OverrideInput, ...]:
    """Parse and validate repeatable `--override-input <ns>=<path>` arguments.

    Refuses malformed specs, invalid namespaces, duplicate namespaces (never last-wins),
    and missing or non-directory target paths. Records canonical resolved paths.
    """
    if not raw_specs:
        return ()
    env_m = _env_map(env)
    seen: dict[str, Path] = {}
    parsed: list[OverrideInput] = []
    for spec in raw_specs:
        if not isinstance(spec, str) or "=" not in spec:
            raise WorkspaceError(
                f"invalid --override-input {spec!r}: expected <namespace>=<path>"
            )
        raw_ns, _, raw_path = spec.partition("=")
        ns = validate_override_namespace(raw_ns)
        if ns in seen:
            raise WorkspaceError(
                f"duplicate --override-input namespace {ns!r} "
                f"(already bound to {seen[ns]}) — refused rather than last-wins"
            )
        if not raw_path.strip():
            raise WorkspaceError(
                f"invalid --override-input {spec!r}: path for namespace {ns!r} must not be empty"
            )
        expanded = _expand_path(raw_path, env_m)
        try:
            resolved = expanded.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise WorkspaceError(
                f"--override-input {ns!r}: path does not exist or is unreadable: {expanded} ({exc})"
            ) from exc
        try:
            is_dir = resolved.is_dir()
        except OSError as exc:
            raise WorkspaceError(
                f"--override-input {ns!r}: cannot inspect path {resolved}: {exc}"
            ) from exc
        if not is_dir:
            raise WorkspaceError(
                f"--override-input {ns!r}: path is not a directory: {resolved}"
            )
        seen[ns] = resolved
        parsed.append(OverrideInput(namespace=ns, path=resolved))
    return tuple(parsed)


def normalize_overrides(
    overrides: Iterable[OverrideInput] | Mapping[str, Path | str] | None,
) -> tuple[OverrideInput, ...]:
    """Validate and normalize `overrides` (sequence of `OverrideInput` or `{ns: Path}` mapping)."""
    if overrides is None:
        return ()
    if isinstance(overrides, (str, bytes)):
        raise WorkspaceError(
            "overrides must be a sequence of OverrideInput or a mapping of namespace -> Path"
        )
    items: list[OverrideInput] = []
    seen: set[str] = set()
    if isinstance(overrides, Mapping):
        for raw_ns, raw_path in overrides.items():
            if not isinstance(raw_ns, str):
                raise WorkspaceError(f"invalid override namespace {raw_ns!r}: expected str")
            ns = validate_override_namespace(raw_ns)
            if ns in seen:
                raise WorkspaceError(
                    f"duplicate override namespace {ns!r} — refused rather than last-wins"
                )
            if not isinstance(raw_path, (Path, str)):
                raise WorkspaceError(
                    f"invalid override path for {ns!r}: expected Path or str, got {type(raw_path).__name__}"
                )
            path_str = str(raw_path)
            if not path_str.strip() or "\x00" in path_str:
                raise WorkspaceError(f"invalid override path for {ns!r}: {raw_path!r}")
            seen.add(ns)
            items.append(OverrideInput(namespace=ns, path=Path(raw_path)))
        return tuple(items)

    try:
        iterator = iter(overrides)
    except TypeError as exc:
        raise WorkspaceError(
            f"invalid overrides {overrides!r}: expected sequence of OverrideInput or mapping"
        ) from exc

    for entry in iterator:
        if not isinstance(entry, OverrideInput):
            raise WorkspaceError(
                f"invalid override entry {entry!r}: expected OverrideInput"
            )
        ns = validate_override_namespace(entry.namespace)
        if ns in seen:
            raise WorkspaceError(
                f"duplicate override namespace {ns!r} — refused rather than last-wins"
            )
        if not isinstance(entry.path, Path):
            raise WorkspaceError(
                f"invalid override path for {ns!r}: expected Path, got {type(entry.path).__name__}"
            )
        path_str = str(entry.path)
        if not path_str.strip() or "\x00" in path_str:
            raise WorkspaceError(f"invalid override path for {ns!r}: {entry.path!r}")
        seen.add(ns)
        items.append(entry)
    return tuple(items)


def format_overrides_summary(
    overrides: Iterable[OverrideInput] | Mapping[str, Path | str] | None,
) -> str:
    items = normalize_overrides(overrides)
    return ", ".join(o.format_spec() for o in items)


def refuse_release_if_tainted(
    overrides: Iterable[OverrideInput] | Mapping[str, Path | str] | None,
) -> None:
    """Fail-closed release/publish gate: refuse signing or publishing when any override is active."""
    items = normalize_overrides(overrides)
    if not items:
        return
    details = ", ".join(o.format_spec() for o in items)
    raise WorkspaceError(
        "release signing/publishing refused: dev-only --override-input is active "
        f"({details}); remove all local overrides and pin inputs in site.lock before releasing"
    )


def _scan_site_model_files(directory: Path, private_root: Path) -> list[str]:
    """Inspect all `SITE_MODEL_FILENAMES` in `directory` via lstat and exact-case check.

    Refuses ANY symlink (including dangling or cross-site symlinks), non-regular file,
    wrong filename casing, or path resolving outside `private_root`.
    """
    entries_by_name = {
        e.name: e for e in _scandir_entries(directory, label="site input directory")
    }
    lower_to_name = {name.lower(): name for name in entries_by_name}
    hits: list[str] = []
    for name in SITE_MODEL_FILENAMES:
        candidate = directory / name
        if name in entries_by_name:
            entry = entries_by_name[name]
            try:
                st = os.lstat(entry.path)
            except OSError as exc:
                raise WorkspaceError(f"cannot inspect Site Model file {candidate}: {exc}") from exc
        else:
            if name.lower() in lower_to_name:
                actual = lower_to_name[name.lower()]
                raise WorkspaceError(
                    f"Site Model file under {directory} has wrong casing: "
                    f"found {actual!r}, expected exact {name!r}"
                )
            try:
                st = os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise WorkspaceError(f"cannot inspect Site Model file {candidate}: {exc}") from exc

        if stat.S_ISLNK(st.st_mode):
            raise WorkspaceError(
                f"Site Model file {candidate} is a symlink "
                f"(refused; Site Model files must be regular files inside {private_root})"
            )
        if not stat.S_ISREG(st.st_mode):
            raise WorkspaceError(
                f"Site Model file {candidate} is not a regular file"
            )
        resolved = _safe_resolve(candidate, label=f"Site Model file {candidate}")
        if not resolved.is_relative_to(private_root):
            raise WorkspaceError(
                f"Site Model file {candidate} resolves outside {private_root}: {resolved}"
            )
        hits.append(name)
    return hits


def resolve_site_input_dir(private_dir: Path) -> Path:
    """Locate the directory holding Site Model files inside `private_dir`.

    Supports either `<private_dir>/{services,roles,launchd-writers}.yml` or
    `<private_dir>/site/{services,roles,launchd-writers}.yml`. Inspects EVERY candidate
    file in BOTH locations with `lstat`, refusing symlinks (including dangling and
    cross-site symlinks), non-regular files, and files in both locations.
    """
    private_resolved = _safe_resolve(private_dir, label="primary site directory")
    root_hits = _scan_site_model_files(private_resolved, private_resolved)

    sub_entry, sub_case_mismatch = _find_exact_entry(
        private_resolved, "site", label="primary site directory"
    )
    if sub_entry is None and sub_case_mismatch is not None:
        raise WorkspaceError(
            f"site subdirectory under {private_resolved} has wrong casing: "
            f"found {sub_case_mismatch.name!r}, expected exact 'site'"
        )

    sub_resolved: Path | None = None
    sub_hits: list[str] = []
    if sub_entry is not None:
        sub_path = Path(sub_entry.path)
        try:
            sub_is_link = sub_entry.is_symlink()
            sub_is_dir = sub_entry.is_dir(follow_symlinks=False)
        except OSError as exc:
            raise WorkspaceError(f"cannot inspect {sub_path}: {exc}") from exc
        if sub_is_link:
            raise WorkspaceError(
                f"site subdirectory {sub_path} is a symlink "
                f"(refused; keep Site Model files inside {private_resolved})"
            )
        if sub_is_dir:
            sub_resolved = _safe_resolve(sub_path, label="site subdirectory")
            if sub_resolved.parent != private_resolved:
                raise WorkspaceError(
                    f"site subdirectory resolves outside {private_resolved}: {sub_resolved}"
                )
            sub_hits = _scan_site_model_files(sub_resolved, private_resolved)

    if root_hits and sub_hits:
        raise WorkspaceError(
            f"ambiguous Site Model layout in {private_resolved}: found files in both root "
            f"({', '.join(root_hits)}) and site/ ({', '.join(sub_hits)}); keep them in one location"
        )
    if sub_hits and sub_resolved is not None:
        return sub_resolved
    return private_resolved


def resolve_workspace(
    *,
    ops_root: str | Path | None = None,
    site_name: str | None = None,
    env: Mapping[str, str] | None = None,
    config_path: str | Path | None = None,
    overrides: Iterable[OverrideInput] | Mapping[str, Path | str] | None = None,
    read_config: bool = True,
) -> WorkspaceResolution:
    """Resolve the pair-bound workspace for one site slug, failing closed on any ambiguity."""
    env_m = _env_map(env)
    resolved_root, root_source = resolve_ops_root(ops_root, env_m)
    slug, sel_source = resolve_site_slug(
        site_name, env_m, config_path=config_path, read_config=read_config
    )
    private_dir = _check_site_repo_dir(
        resolved_root,
        f"{PRIVATE_PREFIX}{slug}",
        required=True,
        role_label=f"primary site repository for {slug!r}",
    )
    assert private_dir is not None  # required=True guarantees a Path or raises
    public_dir = _check_site_repo_dir(
        resolved_root,
        f"{PUBLIC_PREFIX}{slug}",
        required=False,
        role_label=f"public companion repository for {slug!r}",
    )
    tendcf_dir = _check_tendcf_dir(resolved_root)
    return WorkspaceResolution(
        ops_root=resolved_root,
        ops_root_source=root_source,
        site_slug=slug,
        selection_source=sel_source,
        private_dir=private_dir,
        public_dir=public_dir,
        tendcf_dir=tendcf_dir,
        overrides=normalize_overrides(overrides),
        state_dir=state_dir(env_m),
        cache_dir=cache_dir(env_m),
    )


def list_sites(
    *,
    ops_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> SiteInventory:
    """Scan direct children of `ops_root` for `tendcf-{private,public}-<slug>` repos.

    Excludes `.worktrees/` and hidden entries; flags stray `-wt` worktrees and
    malformed/symlinked site entries in `warnings` rather than treating them as sites.
    """
    env_m = _env_map(env)
    resolved_root, root_source = resolve_ops_root(ops_root, env_m)

    private_by_slug: dict[str, Path] = {}
    public_by_slug: dict[str, Path] = {}
    warnings: list[str] = []

    entries = sorted(_scandir_entries(resolved_root, label="ops root"), key=lambda e: e.name)
    for entry in entries:
        name = entry.name
        if name.startswith("."):
            # Explicitly skips `.worktrees/` and any dotfiles.
            continue
        if name.startswith(PRIVATE_PREFIX):
            kind = "private"
            raw_slug = name[len(PRIVATE_PREFIX) :]
        elif name.startswith(PUBLIC_PREFIX):
            kind = "public"
            raw_slug = name[len(PUBLIC_PREFIX) :]
        else:
            continue

        if raw_slug.endswith(WORKTREE_SUFFIX):
            warnings.append(
                f"stray worktree {name!r} inside {resolved_root}; "
                "development worktrees belong in ~/src/ or <ops_root>/.worktrees/"
            )
            continue
        try:
            slug = validate_site_slug(raw_slug, label=f"{kind} directory suffix")
        except WorkspaceError as exc:
            warnings.append(f"ignoring {name!r}: {exc}")
            continue
        try:
            is_link = entry.is_symlink()
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError as exc:
            warnings.append(f"ignoring {name!r}: cannot inspect ({exc})")
            continue
        if is_link:
            warnings.append(
                f"ignoring symlink {name!r} in {resolved_root} (site repositories must be real directories)"
            )
            continue
        if not is_dir:
            warnings.append(
                f"ignoring non-directory {name!r} in {resolved_root}"
            )
            continue

        try:
            resolved_child = _safe_resolve(Path(entry.path), label=name)
        except WorkspaceError as exc:
            warnings.append(f"ignoring {name!r}: {exc}")
            continue
        if resolved_child.parent != resolved_root:
            warnings.append(f"ignoring {name!r}: resolves outside {resolved_root}")
            continue
        if kind == "private":
            private_by_slug[slug] = resolved_child
        else:
            public_by_slug[slug] = resolved_child

    all_slugs = sorted(set(private_by_slug) | set(public_by_slug))
    sites = tuple(
        DiscoveredSite(
            slug=slug,
            private_dir=private_by_slug.get(slug),
            public_dir=public_by_slug.get(slug),
        )
        for slug in all_slugs
    )
    try:
        tendcf_dir = _check_tendcf_dir(resolved_root)
    except WorkspaceError as exc:
        tendcf_dir = None
        warnings.append(f"ignoring local tendcf entry: {exc}")

    return SiteInventory(
        ops_root=resolved_root,
        ops_root_source=root_source,
        tendcf_dir=tendcf_dir,
        sites=sites,
        warnings=tuple(warnings),
        state_dir=state_dir(env_m),
        cache_dir=cache_dir(env_m),
    )
