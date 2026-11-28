"""Plugin import table, verified realpath loader, and pinned out-of-tree loader (D46 Step 4 + #47).

Implements `docs/architecture/plugin-layout.md` §3–§4 (decision D-a + 2026-11-28 #47 rulings):

1. Every built-in in-tree plugin (frontends, supervisor renderers, importers) lives in
   `STATIC_PLUGIN_TABLE` — NEVER discovered through `importlib.metadata.entry_points()`.
   Supervisor renderers remain in-tree only; there is no public `tendcf.supervisors` group.
2. Before executing any in-tree (`plugins/`) or `contrib/` plugin module, `resolve_plugin_path()`
   / `resolve_contrib_plugin_path()` walks every path component refusing any symlink (`os.lstat`)
   or traversal segment, and `exec_verified_source_module()` opens the leaf with
   `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, verifies `S_ISREG(fstat)`, and compiles/execs source
   bytes directly from the fd (bypassing `__pycache__/*.pyc` and leaf symlink TOCTOU).
3. Out-of-tree plugins (`tendcf.frontends` and `tendcf.importers`, unlocked by #47) load ONLY
   when explicitly pinned in site-private `plugins.toml` (`source = "out-of-tree"`), unexpired,
   not revoked (primary OR signing subkey) and still reachable from current trust anchors (M3),
   anchored byte-for-byte against SHA-256-verified pinned wheels with zero `__pycache__`/`.pyc`
   (H1), and imported with `dont_write_bytecode=True` + private `pycache_prefix` + full
   post-import verification of newly loaded modules (H1.3, L6).
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import importlib
import importlib.machinery
import os
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any


class PluginError(Exception):
    """A plugin lookup, containment check, trust/pin check, or module load failed closed."""


@dataclass(frozen=True)
class PluginSpec:
    """One static in-tree plugin entry."""

    kind: str  # "frontend" | "supervisor" | "importer"
    name: str
    relpath: str  # POSIX relative path strictly under `plugins/`
    module_prefix: str
    description: str


VALID_PLUGIN_KINDS: frozenset[str] = frozenset({"frontend", "supervisor", "importer"})

# Authoritative static in-tree import table (never Python entry points).
STATIC_PLUGIN_TABLE: Mapping[str, Mapping[str, PluginSpec]] = MappingProxyType(
    {
        "frontend": MappingProxyType(
            {
                "yaml": PluginSpec(
                    kind="frontend",
                    name="yaml",
                    relpath="plugins/frontends/yaml/loader.py",
                    module_prefix="tendcf_plugin_frontend_yaml",
                    description="Built-in YAML/JSON Site Model frontend",
                ),
                "nix": PluginSpec(
                    kind="frontend",
                    name="nix",
                    relpath="plugins/frontends/nix/eval.py",
                    module_prefix="tendcf_plugin_frontend_nix",
                    description="Restricted Nix expression frontend (nix2cf)",
                ),
            }
        ),
        "supervisor": MappingProxyType(
            {
                "launchd": PluginSpec(
                    kind="supervisor",
                    name="launchd",
                    relpath="plugins/supervisors/launchd/renderer.py",
                    module_prefix="tendcf_plugin_supervisor_launchd",
                    description="macOS launchd unit renderer",
                ),
                "systemd": PluginSpec(
                    kind="supervisor",
                    name="systemd",
                    relpath="plugins/supervisors/systemd/renderer.py",
                    module_prefix="tendcf_plugin_supervisor_systemd",
                    description="Linux systemd unit renderer (stub until linux-targets step 6)",
                ),
                "runit": PluginSpec(
                    kind="supervisor",
                    name="runit",
                    relpath="plugins/supervisors/runit/renderer.py",
                    module_prefix="tendcf_plugin_supervisor_runit",
                    description="runit unit renderer (stub until linux-targets step 6)",
                ),
            }
        ),
        "importer": MappingProxyType({}),
    }
)

# Built-in plugin names reserved against impersonation by out-of-tree or contrib plugins.
RESERVED_PLUGIN_NAMES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "frontend": frozenset({"yaml", "nix", "nix2cf", "guix"}),
        "supervisor": frozenset({"launchd", "systemd", "runit", "nixos"}),
        "importer": frozenset({"ansible", "salt"}),
    }
)

# Cache loaded modules keyed by (kind, name, canonical_realpath_str) so tests
# passing distinct synthetic roots never receive another tree's cached module.
_LOADED_MODULES: dict[tuple[str, str, str], ModuleType] = {}

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _is_real_dir(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def _is_real_file(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def in_tree_tendcf_for_file(file_path: str | Path) -> Path | None:
    """Return the enclosing tendcf checkout root if `file_path` sits in `<root>/compiler/tendcf/<file>`.

    Accepts the root only when `tendcf/` and `compiler/` are real non-symlink
    directories with `compiler/pyproject.toml`, and `<root>` beside them holds
    real non-symlink `schema/goal-file.schema.json`, `tools/projector.py`, and
    `plugins/`. Any installed site-packages / pip --target layout returns `None`.
    """
    here = Path(file_path).resolve()
    if len(here.parents) < 3:
        return None
    pkg_dir, compiler_dir, root = here.parents[0], here.parents[1], here.parents[2]
    ok = (
        pkg_dir.name == "tendcf"
        and _is_real_dir(pkg_dir)
        and compiler_dir.name == "compiler"
        and _is_real_dir(compiler_dir)
        and _is_real_file(compiler_dir / "pyproject.toml")
        and _is_real_dir(root / "schema")
        and _is_real_file(root / "schema" / "goal-file.schema.json")
        and _is_real_dir(root / "tools")
        and _is_real_file(root / "tools" / "projector.py")
        and _is_real_dir(root / "plugins")
    )
    return root if ok else None


def in_tree_tendcf_root() -> Path | None:
    """Return the enclosing tendcf checkout root for this module."""
    return in_tree_tendcf_for_file(__file__)


def list_plugins(kind: str | None = None) -> tuple[PluginSpec, ...]:
    """List static in-tree plugin specs (all kinds, or one validated kind)."""
    if kind is None:
        out: list[PluginSpec] = []
        for k in sorted(STATIC_PLUGIN_TABLE):
            out.extend(STATIC_PLUGIN_TABLE[k].values())
        return tuple(out)
    if kind not in VALID_PLUGIN_KINDS:
        raise PluginError(f"unknown plugin kind {kind!r} (expected one of {sorted(VALID_PLUGIN_KINDS)})")
    return tuple(STATIC_PLUGIN_TABLE[kind].values())


def get_plugin_spec(kind: str, name: str) -> PluginSpec:
    """Look up a plugin strictly in `STATIC_PLUGIN_TABLE`; never consult entry points."""
    if kind not in VALID_PLUGIN_KINDS:
        raise PluginError(f"unknown plugin kind {kind!r} (expected one of {sorted(VALID_PLUGIN_KINDS)})")
    if not isinstance(name, str) or not name:
        raise PluginError(f"plugin name for kind {kind!r} must be a non-empty string")
    table = STATIC_PLUGIN_TABLE[kind]
    if name not in table:
        known = sorted(table)
        raise PluginError(f"unknown in-tree {kind} plugin {name!r} (available: {known})")
    return table[name]


def _verify_subdir_containment_path(resolved_root: Path, top_dir: str, relpath: str) -> Path:
    """Walk `relpath` strictly under `<resolved_root>/<top_dir>/`, refusing symlinks and escapes."""
    if not relpath or relpath.startswith("/") or "\x00" in relpath:
        raise PluginError(f"invalid {top_dir} plugin relative path: {relpath!r}")
    parts = relpath.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PluginError(f"unsafe traversal component in {top_dir} plugin path: {relpath!r}")
    if parts[0] != top_dir or len(parts) < 2 or not parts[-1].endswith(".py"):
        raise PluginError(f"{top_dir} plugin path must be a .py file under '{top_dir}/': {relpath!r}")

    base_dir = resolved_root / top_dir
    try:
        st_base = os.lstat(base_dir)
    except OSError as exc:
        raise PluginError(f"{top_dir} directory missing under {resolved_root}: {exc}") from exc
    if stat.S_ISLNK(st_base.st_mode) or not stat.S_ISDIR(st_base.st_mode):
        raise PluginError(f"{top_dir} directory must be a real non-symlink directory: {base_dir}")

    try:
        resolved_base = base_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"cannot resolve {top_dir} directory {base_dir}: {exc}") from exc
    if resolved_base.parent != resolved_root or resolved_base.name != top_dir:
        raise PluginError(
            f"{top_dir} directory {base_dir} resolves outside verified tendcf root {resolved_root}: {resolved_base}"
        )

    cur = resolved_base
    for idx, part in enumerate(parts[1:]):
        is_leaf = idx == len(parts[1:]) - 1
        cur = cur / part
        try:
            st = os.lstat(cur)
        except OSError as exc:
            raise PluginError(f"{top_dir} plugin path missing ({relpath}): {cur}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise PluginError(
                f"{top_dir} plugin path component is a symlink (refused; must be real in-tree file): {cur}"
            )
        if is_leaf:
            if not stat.S_ISREG(st.st_mode):
                raise PluginError(f"{top_dir} plugin is not a regular file: {cur}")
        else:
            if not stat.S_ISDIR(st.st_mode):
                raise PluginError(f"{top_dir} plugin directory component is not a directory: {cur}")

    try:
        resolved_file = cur.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"cannot resolve {top_dir} plugin {cur}: {exc}") from exc

    if not resolved_file.is_relative_to(resolved_base) or resolved_file == resolved_base:
        raise PluginError(
            f"{top_dir} plugin {cur} resolves outside {resolved_base}: {resolved_file}"
        )
    return resolved_file


def _resolve_verified_root(tendcf_root: Path | None, *, label: str) -> Path:
    root = tendcf_root if tendcf_root is not None else in_tree_tendcf_root()
    if root is None:
        raise PluginError(f"cannot locate verified in-tree tendcf checkout to load {label}")
    try:
        st_root = os.lstat(root)
    except OSError as exc:
        raise PluginError(f"cannot inspect tendcf root {root}: {exc}") from exc
    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise PluginError(f"tendcf root must be a real non-symlink directory: {root}")
    try:
        return root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"cannot resolve tendcf root {root}: {exc}") from exc


def resolve_plugin_path(
    kind: str,
    name: str,
    *,
    tendcf_root: Path | None = None,
) -> tuple[PluginSpec, Path]:
    """Resolve and verify an in-tree plugin's canonical file path BEFORE execution."""
    spec = get_plugin_spec(kind, name)
    resolved_root = _resolve_verified_root(tendcf_root, label=f"{kind} plugin {name!r}")
    resolved_file = _verify_subdir_containment_path(resolved_root, "plugins", spec.relpath)
    return spec, resolved_file


def resolve_contrib_plugin_path(
    kind: str,
    name: str,
    relpath: str,
    *,
    tendcf_root: Path | None = None,
) -> Path:
    """Resolve and verify a site-named in-tree `contrib/` plugin's canonical path BEFORE execution."""
    if kind not in ("frontend", "importer"):
        raise PluginError(
            f"contrib plugin kind {kind!r} is forbidden (supervisor renderers are in-tree plugins/ only)"
        )
    if name in RESERVED_PLUGIN_NAMES.get(kind, frozenset()):
        raise PluginError(f"contrib {kind} plugin name {name!r} is reserved for built-in plugins")
    resolved_root = _resolve_verified_root(tendcf_root, label=f"contrib {kind} plugin {name!r}")
    return _verify_subdir_containment_path(resolved_root, "contrib", relpath)


def exec_verified_source_module(module_name: str, resolved_file: Path) -> ModuleType:
    """Open `resolved_file` with `O_NOFOLLOW`, verify `S_ISREG`, and exec source directly."""
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK
    try:
        fd = os.open(resolved_file, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
            raise PluginError(
                f"in-tree module is a symlink (refused on open): {resolved_file}"
            ) from exc
        raise PluginError(f"cannot open verified module {resolved_file}: {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PluginError(f"verified module is not a regular file: {resolved_file}")
        fh = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise

    with fh:
        try:
            raw = fh.read()
        except OSError as exc:
            raise PluginError(f"cannot read verified module {resolved_file}: {exc}") from exc

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PluginError(f"verified module {resolved_file} is not valid UTF-8: {exc}") from exc

    try:
        code = compile(source, str(resolved_file), "exec")
    except SyntaxError as exc:
        raise PluginError(f"syntax error in verified module {resolved_file}: {exc}") from exc

    module = ModuleType(module_name)
    module.__file__ = str(resolved_file)
    module.__package__ = ""
    module.__spec__ = importlib.machinery.ModuleSpec(
        module_name, loader=None, origin=str(resolved_file)
    )
    sys.modules[module_name] = module
    try:
        exec(code, module.__dict__)  # noqa: S102 - verified in-tree source file
    except (KeyboardInterrupt, SystemExit):
        sys.modules.pop(module_name, None)
        raise
    except PluginError:
        sys.modules.pop(module_name, None)
        raise
    except Exception as exc:
        sys.modules.pop(module_name, None)
        raise PluginError(f"failed to execute verified module {resolved_file}: {exc}") from exc

    return module


def load_plugin(
    kind: str,
    name: str,
    *,
    tendcf_root: Path | None = None,
) -> Any:
    """Verify realpath containment under `<tendcf_root>/plugins/` and load an in-tree plugin."""
    spec, resolved_file = resolve_plugin_path(kind, name, tendcf_root=tendcf_root)
    cache_key = (spec.kind, spec.name, str(resolved_file))
    cached = _LOADED_MODULES.get(cache_key)
    if cached is not None:
        return cached

    path_tag = hashlib.sha256(str(resolved_file).encode("utf-8")).hexdigest()[:12]
    module_name = f"{spec.module_prefix}_{path_tag}"
    module = exec_verified_source_module(module_name, resolved_file)

    mod_kind = getattr(module, "PLUGIN_KIND", None)
    mod_name = getattr(module, "PLUGIN_NAME", None)
    if mod_kind != spec.kind or mod_name != spec.name:
        sys.modules.pop(module_name, None)
        raise PluginError(
            f"in-tree plugin {resolved_file} declared PLUGIN_KIND={mod_kind!r}, "
            f"PLUGIN_NAME={mod_name!r}; expected ({spec.kind!r}, {spec.name!r})"
        )

    _LOADED_MODULES[cache_key] = module
    return module


def load_contrib_plugin(
    kind: str,
    name: str,
    relpath: str,
    *,
    tendcf_root: Path | None = None,
) -> Any:
    """Verify realpath containment under `<tendcf_root>/contrib/` and load a named contrib plugin."""
    resolved_file = resolve_contrib_plugin_path(kind, name, relpath, tendcf_root=tendcf_root)
    cache_key = (f"contrib:{kind}", name, str(resolved_file))
    cached = _LOADED_MODULES.get(cache_key)
    if cached is not None:
        return cached

    path_tag = hashlib.sha256(str(resolved_file).encode("utf-8")).hexdigest()[:12]
    module_name = f"tendcf_contrib_{kind}_{name.replace('-', '_')}_{path_tag}"
    module = exec_verified_source_module(module_name, resolved_file)

    mod_kind = getattr(module, "PLUGIN_KIND", None)
    mod_name = getattr(module, "PLUGIN_NAME", None)
    if mod_kind != kind or mod_name != name:
        sys.modules.pop(module_name, None)
        raise PluginError(
            f"contrib plugin {resolved_file} declared PLUGIN_KIND={mod_kind!r}, "
            f"PLUGIN_NAME={mod_name!r}; expected ({kind!r}, {name!r})"
        )

    _LOADED_MODULES[cache_key] = module
    return module


@contextlib.contextmanager
def plugin_env_import_context(resolved_env: Path) -> Iterator[None]:
    """Scope `sys.path`, `sys.dont_write_bytecode`, and private `sys.pycache_prefix` for out-of-tree plugin execution (H1.3, L6)."""
    saved_path = list(sys.path)
    saved_dont_write = sys.dont_write_bytecode
    saved_pycache_prefix = sys.pycache_prefix
    with tempfile.TemporaryDirectory(prefix="tendcf-pycache.") as pycache_td:
        os.chmod(pycache_td, 0o700)
        sys.dont_write_bytecode = True
        sys.pycache_prefix = pycache_td
        sys.path.insert(0, str(resolved_env))
        importlib.invalidate_caches()
        try:
            yield
        finally:
            sys.path[:] = saved_path
            sys.dont_write_bytecode = saved_dont_write
            sys.pycache_prefix = saved_pycache_prefix
            importlib.invalidate_caches()


def _is_allowed_system_module_file(mod_file: Path, tendcf_root: Path | None) -> bool:
    """True for Python stdlib, base compiler package (`tendcf`), or locked base compiler deps."""
    stdlib_dir = Path(os.__file__).resolve().parent
    if mod_file.is_relative_to(stdlib_dir):
        return True
    if tendcf_root is not None and mod_file.is_relative_to((tendcf_root / "compiler").resolve()):
        return True
    # Base compiler deps (pyyaml, jsonschema, rfc8785) may already live in active interpreter prefix.
    prefix_dir = Path(sys.prefix).resolve()
    base_prefix_dir = Path(sys.base_prefix).resolve()
    return mod_file.is_relative_to(prefix_dir) or mod_file.is_relative_to(base_prefix_dir)


def load_out_of_tree_plugin(
    kind: str,
    name: str,
    *,
    config: Any,  # SitePluginsConfig
    plugin_env: Path,
    tendcf_root: Path | None = None,
    site_root: Path | None = None,
    check_releasable: bool = False,
    now: datetime | None = None,
) -> Any:
    """Load an explicitly pinned out-of-tree `frontend` or `importer` plugin from an isolated env.

    Enforces (H1, M3, L3, L6):
    - Supervisor renderers are never loadable out-of-tree; built-in names are reserved.
    - Exact pin must exist in `plugins.toml` (`source = "out-of-tree"`), unexpired (`expires_at > now`).
    - Primary AND signing subkey fingerprints must not be revoked; when `site_root` is provided and
      trust anchors exist, verifies signer is STILL reachable in the current Web of Trust (M3).
    - Isolated `plugin_env` passes full byte-for-byte pinned-wheel anchoring, zero `__pycache__`/`.pyc`,
      receipt digest, RECORD, and non-deduplicating `*.dist-info` checks (H1).
    - Imports with `dont_write_bytecode=True` and fresh private `sys.pycache_prefix`; verifies the
      target module resolves strictly inside `plugin_env` and checks every newly loaded module (H1.3, L6).
    """
    from .plugin_env import PluginEnvError, discover_env_entry_points
    from .plugin_manifest import (
        ALLOWED_ENTRY_POINT_GROUPS,
        PluginManifestError,
        normalize_dist_name,
        parse_rfc3339_utc,
        utc_now,
    )
    from .plugin_wot import PluginTrustError, evaluate_revocation_policy, verify_signer_reachable_in_wot

    if kind not in ("frontend", "importer"):
        raise PluginError(
            f"out-of-tree plugin kind {kind!r} is forbidden (supervisor renderers are in-tree only)"
        )
    if name in RESERVED_PLUGIN_NAMES.get(kind, frozenset()):
        raise PluginError(
            f"out-of-tree {kind} plugin name {name!r} is reserved for built-in tendcf plugins"
        )

    pin = config.get_plugin(kind, name)
    if pin is None or pin.source != "out-of-tree":
        raise PluginError(
            f"out-of-tree {kind} plugin {name!r} is not pinned in site-private plugins.toml"
        )

    current_time = now if now is not None else utc_now()
    try:
        expires_dt = parse_rfc3339_utc(pin.expires_at, label="pin.expires_at")
    except PluginManifestError as exc:
        raise PluginError(str(exc)) from exc
    if current_time >= expires_dt:
        raise PluginError(
            f"out-of-tree {kind} plugin {name!r} pin expired at {pin.expires_at} "
            "(anti-freeze protection; refresh with `tendcf plugin update`)"
        )

    try:
        # Check BOTH primary and signing subkey fingerprints against revocations (M3.2).
        for fpr in sorted({pin.signer_fingerprint, pin.signing_subkey_fingerprint or pin.signer_fingerprint}):
            evaluate_revocation_policy(
                fpr,
                config.trust,
                historical=False,
                as_of=current_time,
            )
        # Re-check live WoT reachability when site_root is present (M3.1 & M3.3: catches removed anchor / revoked introducer!).
        if site_root is not None:
            verify_signer_reachable_in_wot(
                pin.signer_fingerprint,
                signing_subkey_fingerprint=pin.signing_subkey_fingerprint,
                site_root=site_root,
                policy=config.trust,
                historical=False,
            )
    except PluginTrustError as exc:
        raise PluginError(str(exc)) from exc

    try:
        discovered = discover_env_entry_points(
            plugin_env,
            config=config,
            tendcf_root=tendcf_root,
            site_root=site_root,
            check_releasable=check_releasable,
        )
    except (PluginEnvError, PluginManifestError, OSError) as exc:
        raise PluginError(str(exc)) from exc

    group = ALLOWED_ENTRY_POINT_GROUPS[kind]
    ep = discovered.get(group, {}).get(name)
    if ep is None:
        raise PluginError(
            f"pinned out-of-tree {kind} plugin {name!r} not found in isolated plugin env {plugin_env} "
            f"(group [{group}])"
        )
    if normalize_dist_name(ep.distribution) != normalize_dist_name(pin.distribution) or ep.version != pin.version:
        raise PluginError(
            f"out-of-tree plugin {name!r} mismatch: env has {ep.distribution}=={ep.version}, "
            f"plugins.toml pins {pin.distribution}=={pin.version}"
        )
    if ep.value != pin.entry_point:
        raise PluginError(
            f"out-of-tree plugin {name!r} entry_point mismatch: env has {ep.value!r}, "
            f"plugins.toml pins {pin.entry_point!r}"
        )

    mod_name, _, attr_path = ep.value.partition(":")
    resolved_env = plugin_env.resolve(strict=True)

    top_pkg = mod_name.split(".", 1)[0]
    if top_pkg in ("tendcf", "nix2cf"):
        raise PluginError(f"out-of-tree plugin entry point {ep.value!r} attempts to shadow {top_pkg!r}")

    # Evict any prior cached copy of this plugin package loaded from a different directory.
    prior_mod = sys.modules.get(mod_name)
    if prior_mod is not None:
        prior_file = getattr(prior_mod, "__file__", None)
        if not prior_file or not Path(prior_file).resolve().is_relative_to(resolved_env):
            for k in [m for m in list(sys.modules) if m == top_pkg or m.startswith(top_pkg + ".")]:
                sys.modules.pop(k, None)

    before_modules = set(sys.modules)
    with plugin_env_import_context(resolved_env):
        try:
            mod = importlib.import_module(mod_name)
        except Exception as exc:
            raise PluginError(f"failed to import out-of-tree plugin module {mod_name!r}: {exc}") from exc

    mod_file = getattr(mod, "__file__", None)
    if not isinstance(mod_file, str):
        raise PluginError(f"out-of-tree plugin module {mod_name!r} has no __file__ (refused)")
    resolved_mod_file = Path(mod_file).resolve(strict=True)
    if resolved_mod_file.suffix.lower() in (".pyc", ".pyo") or "__pycache__" in resolved_mod_file.parts:
        raise PluginError(
            f"out-of-tree plugin module {mod_name!r} resolved to bytecode {resolved_mod_file} (refused)"
        )
    if not resolved_mod_file.is_relative_to(resolved_env):
        raise PluginError(
            f"out-of-tree plugin module {mod_name!r} loaded from {resolved_mod_file}, "
            f"outside isolated plugin env {resolved_env} (ambient shadowing refused)"
        )

    # L6: Verify every newly imported module came from resolved_env or allowed stdlib/base-compiler paths,
    # never from stray bytecode or an unrelated directory on sys.path.
    for new_name in sorted(set(sys.modules) - before_modules):
        new_mod = sys.modules.get(new_name)
        new_file = getattr(new_mod, "__file__", None)
        if not isinstance(new_file, str):
            continue
        p = Path(new_file).resolve(strict=False)
        if p.is_relative_to(resolved_env):
            if p.suffix.lower() in (".pyc", ".pyo") or "__pycache__" in p.parts:
                raise PluginError(
                    f"out-of-tree plugin import loaded unexpected bytecode inside plugin env: {p}"
                )
        elif not _is_allowed_system_module_file(p, tendcf_root):
            raise PluginError(
                f"out-of-tree plugin {name!r} imported unexpected external module {new_name!r} from {p} "
                f"(outside isolated plugin env {resolved_env})"
            )

    obj: Any = mod
    for part in attr_path.split("."):
        if not hasattr(obj, part):
            raise PluginError(
                f"out-of-tree plugin {name!r}: entry point {ep.value!r} missing attribute {part!r}"
            )
        obj = getattr(obj, part)
    return obj


def load_configured_plugin(
    kind: str,
    name: str,
    *,
    config: Any | None = None,
    plugin_env: Path | None = None,
    tendcf_root: Path | None = None,
    site_root: Path | None = None,
    check_releasable: bool = False,
    now: datetime | None = None,
) -> Any:
    """Resolve and load a `frontend` or `importer` plugin respecting `plugins.toml` activation rules."""
    if kind == "supervisor":
        return load_plugin("supervisor", name, tendcf_root=tendcf_root)

    if config is None:
        return load_plugin(kind, name, tendcf_root=tendcf_root)

    pin = config.get_plugin(kind, name)
    if pin is None:
        raise PluginError(
            f"{kind} plugin {name!r} is not named in site-private plugins.toml "
            "(D46 activation rule: only explicitly named plugins may load)"
        )
    if pin.source == "in-tree":
        return load_plugin(kind, name, tendcf_root=tendcf_root)
    if pin.source == "contrib":
        assert pin.relpath is not None
        return load_contrib_plugin(kind, name, pin.relpath, tendcf_root=tendcf_root)
    if plugin_env is None:
        raise PluginError(
            f"out-of-tree {kind} plugin {name!r} requires an isolated --plugin-env directory"
        )
    return load_out_of_tree_plugin(
        kind,
        name,
        config=config,
        plugin_env=plugin_env,
        tendcf_root=tendcf_root,
        site_root=site_root,
        check_releasable=check_releasable,
        now=now,
    )


def clear_plugin_cache() -> None:
    """Clear the loaded-plugin cache (for isolated tests)."""
    for mod in list(_LOADED_MODULES.values()):
        mod_name = getattr(mod, "__name__", None)
        if isinstance(mod_name, str):
            sys.modules.pop(mod_name, None)
    _LOADED_MODULES.clear()
