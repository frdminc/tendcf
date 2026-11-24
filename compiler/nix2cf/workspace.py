"""Multi-site local ops workspace resolution for tendcf / nix2cf (issue #98).

Layout under `~/tendcf-ops` (override: `--ops-root` or `TENDCF_OPS_ROOT`):

  <ops_root>/
    tendcf/                    # optional local engine checkout
    tendcf-private-<site>/     # REQUIRED primary site root (D35: inventory private)
    tendcf-public-<site>/      # OPTIONAL publishable recipes/exports companion
    tendcf-public-<other>/     # OPTIONAL local read-only clones of foreign public sites
    .worktrees/                # excluded from site scan (worktrees live here or ~/src/)

Rules enforced here (operator rulings 2026-11-24, Ref: ANTIGRAVITY-we, ANTIGRAVITY-wf):

1. Pair-bound, fail-closed selection: a single validated `<site>` slug selects
   `(tendcf-private-<site>, tendcf-public-<site>)` together. Precedence:
   `--site-name` > `TENDCF_SITE` > XDG `active-site` file
   (`$XDG_CONFIG_HOME/tendcf/active-site` when absolute, else `~/.config/tendcf/active-site`).
2. Zero silent guessing and zero legacy aliases: never glob a sole `tendcf-private-*`
   checkout; never accept bare `tendcf-private`, `site-private`, `.mysite`, or uncoupled
   public/private selectors.
3. No release build reads sibling checkouts (D21/D34/D35/D46). Explicit dev-only
   `--override-input <ns>=<path>` binds a local directory for preview/test compiles,
   taints the resolution/compile result, and refuses release signing/publishing.
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
    """Resolved pair-bound workspace for a single site slug."""

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
    if "\x00" in raw:
        raise WorkspaceError("path contains a NUL byte")
    if raw == "~":
        return _home_dir(env)
    if raw.startswith("~/"):
        return _home_dir(env) / raw[2:]
    return Path(raw).expanduser()


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


def is_tendcf_checkout(path: Path) -> bool:
    """True iff `path` looks like a real tendcf checkout (schema + reference projector)."""
    return (
        path.is_dir()
        and (path / "schema" / "goal-file.schema.json").is_file()
        and (path / "bin" / "projector.py").is_file()
    )


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
    if expanded.is_symlink() and not expanded.exists():
        raise WorkspaceError(f"ops root {expanded} (from {source}) is a dangling symlink")
    if not expanded.exists():
        raise WorkspaceError(f"ops root does not exist: {expanded} (from {source})")
    if not expanded.is_dir():
        raise WorkspaceError(f"ops root is not a directory: {expanded} (from {source})")
    return expanded.resolve(strict=True), source


def _read_active_site_file(path: Path) -> str | None:
    """Read a plain single-line non-symlink active-site file; return None if missing."""
    if path.is_symlink():
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
            os.close(fd)
            raise WorkspaceError(f"active-site config must be a regular file: {path}")
    except WorkspaceError:
        raise
    except OSError as exc:
        os.close(fd)
        raise WorkspaceError(f"cannot inspect active-site config {path}: {exc}") from exc

    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        try:
            raw = fh.read(4096)
            if fh.read(1):
                raise WorkspaceError(f"active-site config exceeds 4096 bytes: {path}")
        except UnicodeDecodeError as exc:
            raise WorkspaceError(f"active-site config is not valid UTF-8: {path}: {exc}") from exc

    entries: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
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

    Fails closed when no selector is present — never globs `ops_root`.
    Returns `(slug, selection_source)`.
    """
    env_m = _env_map(env)
    if arg is not None:
        return validate_site_slug(arg, label="--site-name"), "cli"

    if "TENDCF_SITE" in env_m:
        raw_env = env_m["TENDCF_SITE"]
        if not raw_env:
            raise WorkspaceError("TENDCF_SITE is set but empty")
        return validate_site_slug(raw_env, label="TENDCF_SITE"), "env:TENDCF_SITE"

    cfg_path: Path | None = None
    if config_path is not None:
        raw_cfg = str(config_path)
        if not raw_cfg.strip():
            raise WorkspaceError("active-site config path must not be empty")
        cfg_path = _expand_path(raw_cfg, env_m)
    elif read_config:
        cfg_path = active_site_config_path(env_m)

    if cfg_path is not None:
        slug = _read_active_site_file(cfg_path)
        if slug is not None:
            return slug, f"config:{cfg_path}"

    hint_cfg = cfg_path if cfg_path is not None else active_site_config_path(env_m)
    raise WorkspaceError(
        "no site selected (refusing to guess or glob ops root); specify --site-name <slug>, "
        f"set TENDCF_SITE=<slug>, or write a single slug line to {hint_cfg}"
    )


def _check_site_repo_dir(
    ops_root: Path,
    name: str,
    *,
    required: bool,
    role_label: str,
) -> Path | None:
    """Verify `<ops_root>/<name>` is a real directory inside `ops_root` (no symlinks)."""
    candidate = ops_root / name
    if candidate.is_symlink():
        if not candidate.exists():
            raise WorkspaceError(
                f"{role_label} is a dangling symlink: {candidate} "
                "(refused; site repositories must be real directories)"
            )
        raise WorkspaceError(
            f"{role_label} is a symlink: {candidate} "
            "(refused; site repositories must be real directories to prevent aliasing "
            "and cross-site mismatch)"
        )
    if not candidate.exists():
        if required:
            raise WorkspaceError(
                f"{role_label} not found: {candidate} "
                f"(expected directory {name!r} directly under {ops_root})"
            )
        return None
    if not candidate.is_dir():
        raise WorkspaceError(f"{role_label} exists but is not a directory: {candidate}")
    resolved = candidate.resolve(strict=True)
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
        except OSError as exc:
            raise WorkspaceError(
                f"--override-input {ns!r}: path does not exist or is unreadable: {expanded} ({exc})"
            ) from exc
        if not resolved.is_dir():
            raise WorkspaceError(
                f"--override-input {ns!r}: path is not a directory: {resolved}"
            )
        seen[ns] = resolved
        parsed.append(OverrideInput(namespace=ns, path=resolved))
    return tuple(parsed)


def _normalize_overrides(
    overrides: Iterable[OverrideInput] | Mapping[str, Path] | None,
) -> tuple[OverrideInput, ...]:
    if not overrides:
        return ()
    if isinstance(overrides, Mapping):
        return tuple(
            OverrideInput(namespace=str(k), path=Path(v))
            for k, v in overrides.items()
        )
    return tuple(overrides)


def format_overrides_summary(
    overrides: Iterable[OverrideInput] | Mapping[str, Path] | None,
) -> str:
    items = _normalize_overrides(overrides)
    return ", ".join(o.format_spec() for o in items)


def refuse_release_if_tainted(
    overrides: Iterable[OverrideInput] | Mapping[str, Path] | None,
) -> None:
    """Fail-closed release/publish gate: refuse signing or publishing when any override is active."""
    items = _normalize_overrides(overrides)
    if not items:
        return
    details = format_overrides_summary(items)
    raise WorkspaceError(
        "release signing/publishing refused: dev-only --override-input is active "
        f"({details}); remove all local overrides and pin inputs in site.lock before releasing"
    )


def resolve_site_input_dir(private_dir: Path) -> Path:
    """Locate the directory holding Site Model files inside `private_dir`.

    Supports either `<private_dir>/{services,roles,launchd-writers}.yml` or
    `<private_dir>/site/{services,roles,launchd-writers}.yml`. Fails closed if
    files exist in both locations (never silently picks one).
    """
    root_hits = [name for name in SITE_MODEL_FILENAMES if (private_dir / name).exists()]
    sub = private_dir / "site"
    if sub.is_symlink():
        raise WorkspaceError(
            f"site subdirectory {sub} is a symlink (refused; keep Site Model files inside {private_dir})"
        )
    sub_hits = (
        [name for name in SITE_MODEL_FILENAMES if (sub / name).exists()]
        if sub.is_dir()
        else []
    )
    if root_hits and sub_hits:
        raise WorkspaceError(
            f"ambiguous Site Model layout in {private_dir}: found files in both root "
            f"({', '.join(root_hits)}) and site/ ({', '.join(sub_hits)}); keep them in one location"
        )
    if sub_hits:
        return sub
    return private_dir


def resolve_workspace(
    *,
    ops_root: str | Path | None = None,
    site_name: str | None = None,
    env: Mapping[str, str] | None = None,
    config_path: str | Path | None = None,
    overrides: Iterable[OverrideInput] | None = None,
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
    tendcf_candidate = resolved_root / "tendcf"
    tendcf_dir = (
        tendcf_candidate.resolve(strict=True)
        if is_tendcf_checkout(tendcf_candidate)
        else None
    )
    return WorkspaceResolution(
        ops_root=resolved_root,
        ops_root_source=root_source,
        site_slug=slug,
        selection_source=sel_source,
        private_dir=private_dir,
        public_dir=public_dir,
        tendcf_dir=tendcf_dir,
        overrides=tuple(overrides) if overrides else (),
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

    for child in sorted(resolved_root.iterdir(), key=lambda p: p.name):
        name = child.name
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
        if child.is_symlink():
            warnings.append(
                f"ignoring symlink {name!r} in {resolved_root} (site repositories must be real directories)"
            )
            continue
        if not child.is_dir():
            warnings.append(
                f"ignoring non-directory {name!r} in {resolved_root}"
            )
            continue

        resolved_child = child.resolve(strict=True)
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
    tendcf_candidate = resolved_root / "tendcf"
    tendcf_dir = (
        tendcf_candidate.resolve(strict=True)
        if is_tendcf_checkout(tendcf_candidate)
        else None
    )
    return SiteInventory(
        ops_root=resolved_root,
        ops_root_source=root_source,
        tendcf_dir=tendcf_dir,
        sites=sites,
        warnings=tuple(warnings),
        state_dir=state_dir(env_m),
        cache_dir=cache_dir(env_m),
    )
