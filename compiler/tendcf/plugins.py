"""Static in-tree plugin import table and verified realpath loader (D46 Step 4).

Implements `docs/architecture/plugin-layout.md` §3–§4 (decision D-a, amended by
2026-11-14 operator ruling Smaller 5):

1. Every in-tree plugin (frontends, supervisor renderers, importers) is listed
   in `STATIC_PLUGIN_TABLE` — NEVER discovered through
   `importlib.metadata.entry_points()` (out-of-tree entry-point discovery is
   deferred until a user needs one and out-of-tree plugins can be pinned, #47).
2. Before executing any plugin module, `resolve_plugin_path()` resolves the
   verified tendcf root and `plugins/` directory, walks every path component
   under `plugins/` refusing any symlink (`os.lstat`) or traversal segment,
   verifies the resolved file is a regular file strictly inside
   `<resolved_root>/plugins/`, and only then executes it by file location via
   `importlib.util.spec_from_file_location`.
3. `sys.modules[mod_name]` is registered before `exec_module` (required on
   Python 3.14+ for `dataclasses` / postponed annotations) and cleaned up on
   failure.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any


class PluginError(Exception):
    """A plugin lookup, containment check, or module load failed closed."""


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

# Built-in plugin names reserved against impersonation if third-party entry
# points are ever revived (#47).
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


def in_tree_tendcf_root() -> Path | None:
    """Return the enclosing tendcf checkout root if this file sits in `<root>/compiler/tendcf/plugins.py`.

    Accepts the root only when `compiler/` is a real directory holding
    `pyproject.toml` and `<root>` beside it holds real `schema/goal-file.schema.json`,
    `tools/projector.py`, and `plugins/`. Any installed site-packages / pip --target
    layout returns `None`.
    """
    here = Path(__file__).resolve()
    if len(here.parents) < 3:
        return None
    compiler_dir, root = here.parents[1], here.parents[2]
    ok = (
        compiler_dir.name == "compiler"
        and _is_real_dir(compiler_dir)
        and _is_real_file(compiler_dir / "pyproject.toml")
        and _is_real_dir(root / "schema")
        and _is_real_file(root / "schema" / "goal-file.schema.json")
        and _is_real_dir(root / "tools")
        and _is_real_file(root / "tools" / "projector.py")
        and _is_real_dir(root / "plugins")
    )
    return root if ok else None


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


def _verify_containment_path(resolved_root: Path, relpath: str) -> Path:
    """Walk `relpath` under `resolved_root/plugins/`, refusing symlinks and escapes."""
    if not relpath or relpath.startswith("/") or "\x00" in relpath:
        raise PluginError(f"invalid static plugin relative path: {relpath!r}")
    parts = relpath.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PluginError(f"unsafe traversal component in static plugin path: {relpath!r}")
    if parts[0] != "plugins" or len(parts) < 2:
        raise PluginError(f"static plugin path must live under 'plugins/': {relpath!r}")

    plugins_dir = resolved_root / "plugins"
    try:
        st_plugins = os.lstat(plugins_dir)
    except OSError as exc:
        raise PluginError(f"plugins directory missing under {resolved_root}: {exc}") from exc
    if stat.S_ISLNK(st_plugins.st_mode) or not stat.S_ISDIR(st_plugins.st_mode):
        raise PluginError(f"plugins directory must be a real non-symlink directory: {plugins_dir}")

    try:
        resolved_plugins = plugins_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"cannot resolve plugins directory {plugins_dir}: {exc}") from exc
    if resolved_plugins.parent != resolved_root or resolved_plugins.name != "plugins":
        raise PluginError(
            f"plugins directory {plugins_dir} resolves outside verified tendcf root {resolved_root}: {resolved_plugins}"
        )

    # Walk every directory component and leaf under plugins/, rejecting any symlink.
    cur = resolved_plugins
    for idx, part in enumerate(parts[1:]):
        is_leaf = idx == len(parts[1:]) - 1
        cur = cur / part
        try:
            st = os.lstat(cur)
        except OSError as exc:
            raise PluginError(f"in-tree plugin path missing ({relpath}): {cur}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise PluginError(
                f"in-tree plugin path component is a symlink (refused; must be real in-tree file): {cur}"
            )
        if is_leaf:
            if not stat.S_ISREG(st.st_mode):
                raise PluginError(f"in-tree plugin is not a regular file: {cur}")
        else:
            if not stat.S_ISDIR(st.st_mode):
                raise PluginError(f"in-tree plugin directory component is not a directory: {cur}")

    try:
        resolved_file = cur.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"cannot resolve in-tree plugin {cur}: {exc}") from exc

    if not resolved_file.is_relative_to(resolved_plugins) or resolved_file == resolved_plugins:
        raise PluginError(
            f"in-tree plugin {cur} resolves outside {resolved_plugins}: {resolved_file}"
        )
    return resolved_file


def resolve_plugin_path(
    kind: str,
    name: str,
    *,
    tendcf_root: Path | None = None,
) -> tuple[PluginSpec, Path]:
    """Resolve and verify an in-tree plugin's canonical file path BEFORE execution."""
    spec = get_plugin_spec(kind, name)
    root = tendcf_root if tendcf_root is not None else in_tree_tendcf_root()
    if root is None:
        raise PluginError(
            f"cannot locate verified in-tree tendcf checkout to load {kind} plugin {name!r}"
        )
    try:
        st_root = os.lstat(root)
    except OSError as exc:
        raise PluginError(f"cannot inspect tendcf root {root}: {exc}") from exc
    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise PluginError(f"tendcf root must be a real non-symlink directory: {root}")
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"cannot resolve tendcf root {root}: {exc}") from exc

    resolved_file = _verify_containment_path(resolved_root, spec.relpath)
    return spec, resolved_file


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
    mod_spec = importlib.util.spec_from_file_location(module_name, resolved_file)
    if mod_spec is None or mod_spec.loader is None:
        raise PluginError(f"cannot create module spec for in-tree plugin {resolved_file}")
    module = importlib.util.module_from_spec(mod_spec)
    sys.modules[module_name] = module
    try:
        mod_spec.loader.exec_module(module)
    except BaseException as exc:
        sys.modules.pop(module_name, None)
        if isinstance(exc, PluginError):
            raise
        raise PluginError(f"failed to load in-tree {spec.kind} plugin {spec.name!r} ({resolved_file}): {exc}") from exc

    _LOADED_MODULES[cache_key] = module
    return module


def clear_plugin_cache() -> None:
    """Clear the loaded-plugin cache (for isolated tests)."""
    for mod in list(_LOADED_MODULES.values()):
        mod_name = getattr(mod, "__name__", None)
        if isinstance(mod_name, str):
            sys.modules.pop(mod_name, None)
    _LOADED_MODULES.clear()
