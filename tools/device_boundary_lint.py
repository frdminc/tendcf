#!/usr/bin/env python3
"""Enforce tendcf's structural device boundary and static-plugin-table invariants (D46 Step 4 + #47).

Pure stdlib (`python3 -I -S` compatible). Implements `docs/architecture/plugin-layout.md`
§4 ("The device boundary is structural, not a convention") and 2026-11-28 operator rulings
for #47 (lifting Smaller 5's out-of-tree discovery deferral while keeping built-in plugins
in `STATIC_PLUGIN_TABLE` and banning `importlib.metadata` everywhere so out-of-tree discovery
must use our non-deduplicating isolated-env `*.dist-info` scanner):

1. No leftover `bin/` directory, wrapper, or symlink at repository root.
2. No symlinked subdirectories or `.py` files anywhere under `tools/`,
   `compiler/tendcf/`, `compiler/scripts/`, `plugins/`, or `contrib/`.
3. Every Python script under `tools/` (including `projector.py`, `schema_lint.py`,
   `approval_enforce.py`, `unit_classifier.py`, `recompute_goal_hashes.py`, etc.):
   - Never imports `compiler`, `plugins`, `contrib`, `tendcf`, `nix2cf`,
     `importlib.metadata`, `importlib.machinery`, `pkg_resources`, `runpy`,
     or `pkgutil` (including via relative imports or aliases).
   - Never calls `entry_points`, accesses `.entry_points` or `importlib.metadata`,
     or bypasses via `getattr(..., "entry_points"|"metadata"|...)`.
   - Never calls `exec`, `eval`, `__import__`, `import_module`, or mutates
     `sys.path` (including `insert`/`append`/`extend`/`+=`/subscript assign).
   - Never passes forbidden path segments (`compiler`, `plugins`, `contrib`,
     `tendcf`, `nix2cf`) to `spec_from_file_location` (positional or keyword).
4. Every Python file under `compiler/tendcf/`, `compiler/scripts/`, `plugins/`,
   and `contrib/` (if present):
   - Never imports `importlib.metadata` or `pkg_resources`, and never invokes
     or accesses `entry_points` / `importlib.metadata` (built-in plugins use
     `STATIC_PLUGIN_TABLE`, and out-of-tree plugins in #47 are discovered via
     our non-deduplicating isolated-env `*.dist-info` scanner in
     `compiler/tendcf/plugin_env.py`, never `importlib.metadata.entry_points()`).
5. `compiler/pyproject.toml`:
   - Declares package name `tendcf`, CLI script `tendcf`, no `nix2cf` alias in
     `scripts` or `gui-scripts`, ZERO `[project.entry-points]` tables (built-ins
     are never entry points), and never lists `"entry-points"` in `project.dynamic`.
6. Every `PluginSpec(...)` call in `compiler/tendcf/plugins.py` must supply a
   constant string `relpath` ending in `.py` that resolves without symlinks
   to a regular file strictly under `plugins/`.

Exit codes: 0 clean, 1 boundary violation(s), 2 usage/IO error.
Run from repo root:  python3 -I -S tools/device_boundary_lint.py
"""

from __future__ import annotations

import argparse
import ast
import os
import stat
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_TOOL_ROOT_MODULES: frozenset[str] = frozenset(
    {"compiler", "plugins", "contrib", "tendcf", "nix2cf", "pkg_resources", "runpy", "pkgutil"}
)
FORBIDDEN_COMPILER_ROOT_MODULES: frozenset[str] = frozenset({"pkg_resources"})
FORBIDDEN_PATH_SEGMENTS: frozenset[str] = frozenset(
    {"compiler", "plugins", "contrib", "tendcf", "nix2cf"}
)
FORBIDDEN_TOOL_CALLS: frozenset[str] = frozenset({"exec", "eval", "__import__"})
FORBIDDEN_GETATTR_NAMES_ALL: frozenset[str] = frozenset({"entry_points", "metadata"})
FORBIDDEN_GETATTR_NAMES_TOOLS: frozenset[str] = frozenset(
    {
        "entry_points",
        "metadata",
        "__import__",
        "import_module",
        "spec_from_file_location",
        "SourceFileLoader",
    }
)


def _iter_string_literals(node: ast.AST) -> list[str]:
    out: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
    return out


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _root_module(name: str) -> str:
    return name.split(".", 1)[0]


def _resolve_alias_dotted(dotted: str, aliases: dict[str, str]) -> str:
    if not dotted:
        return ""
    parts = dotted.split(".")
    head = parts[0]
    if head in aliases:
        target = aliases[head]
        return ".".join([target, *parts[1:]]) if len(parts) > 1 else target
    return dotted


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    """Map every local imported symbol name to its canonical dotted module/symbol path."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name if alias.asname else alias.name.split(".", 1)[0]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{mod}.{alias.name}" if mod else alias.name
    return aliases


def _is_sys_path_target(node: ast.AST, aliases: dict[str, str]) -> bool:
    if isinstance(node, ast.Subscript):
        return _is_sys_path_target(node.value, aliases)
    resolved = _resolve_alias_dotted(_dotted_name(node), aliases)
    return resolved == "sys.path"


def _check_python_file(path: Path, root: Path, *, is_tool: bool) -> list[str]:
    rel = path.relative_to(root).as_posix()
    findings: list[str] = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel)
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return [f"{rel}: cannot parse Python AST: {exc}"]

    aliases = _collect_aliases(tree)
    forbidden_roots = FORBIDDEN_TOOL_ROOT_MODULES if is_tool else FORBIDDEN_COMPILER_ROOT_MODULES
    forbidden_getattrs = FORBIDDEN_GETATTR_NAMES_TOOLS if is_tool else FORBIDDEN_GETATTR_NAMES_ALL

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod == "importlib.metadata" or mod.startswith("importlib.metadata."):
                    findings.append(
                        f"{rel}:{node.lineno}: forbidden entry-point import {mod!r}"
                    )
                elif is_tool and (
                    mod == "importlib.machinery" or mod.startswith("importlib.machinery.")
                ):
                    findings.append(
                        f"{rel}:{node.lineno}: forbidden tool loader import {mod!r}"
                    )
                elif _root_module(mod) in forbidden_roots:
                    findings.append(
                        f"{rel}:{node.lineno}: forbidden import {mod!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "importlib.metadata" or mod.startswith("importlib.metadata."):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden entry-point import from {mod!r}"
                )
            elif mod == "importlib" and any(a.name == "metadata" for a in node.names):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden import 'from importlib import metadata'"
                )
            elif is_tool and (
                mod == "importlib.machinery"
                or mod.startswith("importlib.machinery.")
                or (mod == "importlib" and any(a.name == "machinery" for a in node.names))
            ):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden tool loader import from {mod!r}"
                )
            elif is_tool and mod == "importlib" and any(a.name == "import_module" for a in node.names):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden tool dynamic import 'from importlib import import_module'"
                )
            elif mod and _root_module(mod) in forbidden_roots:
                findings.append(
                    f"{rel}:{node.lineno}: forbidden import from {mod!r}"
                )
            if node.level > 0:
                for a in node.names:
                    if _root_module(a.name) in forbidden_roots:
                        findings.append(
                            f"{rel}:{node.lineno}: forbidden relative import of {a.name!r}"
                        )
            if any(a.name == "entry_points" for a in node.names):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden import of 'entry_points'"
                )
        elif isinstance(node, ast.Attribute):
            resolved_attr = _resolve_alias_dotted(_dotted_name(node), aliases)
            if node.attr == "entry_points":
                findings.append(
                    f"{rel}:{node.lineno}: forbidden attribute access '.entry_points'"
                )
            elif resolved_attr == "importlib.metadata" or resolved_attr.startswith("importlib.metadata."):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden access to 'importlib.metadata'"
                )
            elif is_tool and (
                resolved_attr == "importlib.machinery"
                or resolved_attr.startswith("importlib.machinery.")
            ):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden tool access to 'importlib.machinery'"
                )
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            if is_tool:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tgt in targets:
                    if _is_sys_path_target(tgt, aliases):
                        findings.append(
                            f"{rel}:{node.lineno}: tool mutates sys.path via assignment"
                        )
        elif isinstance(node, ast.Call):
            raw_callee = _dotted_name(node.func)
            callee = _resolve_alias_dotted(raw_callee, aliases)
            if raw_callee == "entry_points" or raw_callee.endswith(".entry_points") or callee.endswith(".entry_points"):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden call to {raw_callee!r}"
                )
            if callee == "getattr" or raw_callee == "getattr":
                attr_node = None
                if len(node.args) >= 2:
                    attr_node = node.args[1]
                for kw in node.keywords:
                    if kw.arg == "name":
                        attr_node = kw.value
                if isinstance(attr_node, ast.Constant) and isinstance(attr_node.value, str):
                    if attr_node.value in forbidden_getattrs:
                        findings.append(
                            f"{rel}:{node.lineno}: forbidden getattr(..., {attr_node.value!r})"
                        )
            if is_tool and (raw_callee in FORBIDDEN_TOOL_CALLS or callee in FORBIDDEN_TOOL_CALLS):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden dynamic execution/import call {raw_callee!r}"
                )
            if is_tool and callee in ("importlib.import_module", "import_module"):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden tool dynamic import call {callee!r}"
                )
            if not is_tool and callee in ("__import__", "importlib.import_module", "import_module"):
                all_arg_nodes = [*node.args, *(kw.value for kw in node.keywords)]
                for arg_node in all_arg_nodes:
                    for lit in _iter_string_literals(arg_node):
                        if lit == "importlib.metadata" or lit.startswith("importlib.metadata."):
                            findings.append(
                                f"{rel}:{node.lineno}: forbidden dynamic import of {lit!r}"
                            )
            if is_tool and callee in (
                "importlib.util.spec_from_file_location",
                "spec_from_file_location",
            ):
                check_nodes = [*node.args[1:], *(kw.value for kw in node.keywords)]
                for arg in check_nodes:
                    for lit in _iter_string_literals(arg):
                        segs = [s for s in lit.replace("\\", "/").split("/") if s]
                        if any(seg in FORBIDDEN_PATH_SEGMENTS for seg in segs):
                            findings.append(
                                f"{rel}:{node.lineno}: tool loads path referencing forbidden tree {lit!r}"
                            )
            if is_tool and isinstance(node.func, ast.Attribute) and _is_sys_path_target(node.func.value, aliases):
                if node.func.attr in ("insert", "append", "extend", "__iadd__"):
                    findings.append(
                        f"{rel}:{node.lineno}: tool mutates sys.path via .{node.func.attr}()"
                    )

    return findings


def _check_pyproject(root: Path) -> list[str]:
    findings: list[str] = []
    pyproject = root / "compiler" / "pyproject.toml"
    if not pyproject.is_file() or pyproject.is_symlink():
        return ["compiler/pyproject.toml: missing or symlink"]
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return [f"compiler/pyproject.toml: cannot parse TOML: {exc}"]

    project = data.get("project")
    if not isinstance(project, dict):
        return ["compiler/pyproject.toml: [project] table missing or not a table"]

    if project.get("name") != "tendcf":
        findings.append(
            f"compiler/pyproject.toml: [project].name is {project.get('name')!r}, expected 'tendcf'"
        )
    scripts = project.get("scripts")
    if not isinstance(scripts, dict):
        findings.append("compiler/pyproject.toml: [project.scripts] missing or not a table")
    else:
        if "tendcf" not in scripts:
            findings.append("compiler/pyproject.toml: [project.scripts] must declare 'tendcf'")
        if "nix2cf" in scripts:
            findings.append("compiler/pyproject.toml: [project.scripts] must not keep removed 'nix2cf' alias")

    gui_scripts = project.get("gui-scripts")
    if gui_scripts is not None:
        if not isinstance(gui_scripts, dict):
            findings.append("compiler/pyproject.toml: [project.gui-scripts] is not a table")
        elif "nix2cf" in gui_scripts:
            findings.append("compiler/pyproject.toml: [project.gui-scripts] must not keep removed 'nix2cf' alias")

    if "entry-points" in project:
        findings.append(
            "compiler/pyproject.toml: [project.entry-points] is forbidden (out-of-tree discovery deferred, Smaller 5)"
        )
    dynamic = project.get("dynamic")
    if isinstance(dynamic, list) and "entry-points" in dynamic:
        findings.append(
            "compiler/pyproject.toml: 'entry-points' in [project].dynamic is forbidden (Smaller 5)"
        )
    return findings


def _check_static_plugin_table(root: Path) -> list[str]:
    findings: list[str] = []
    plugins_py = root / "compiler" / "tendcf" / "plugins.py"
    if not plugins_py.is_file() or plugins_py.is_symlink():
        return ["compiler/tendcf/plugins.py: missing or symlink"]
    try:
        tree = ast.parse(plugins_py.read_text(encoding="utf-8"), filename="compiler/tendcf/plugins.py")
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return [f"compiler/tendcf/plugins.py: cannot parse AST: {exc}"]

    relpaths: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted_name(node.func) == "PluginSpec":
            rel_node: ast.AST | None = None
            for kw in node.keywords:
                if kw.arg == "relpath":
                    rel_node = kw.value
                    break
            if rel_node is None and len(node.args) >= 3:
                rel_node = node.args[2]
            if not (isinstance(rel_node, ast.Constant) and isinstance(rel_node.value, str)):
                findings.append(
                    f"compiler/tendcf/plugins.py:{node.lineno}: PluginSpec() must provide a constant string relpath"
                )
                continue
            relpaths.append(rel_node.value)

    if not relpaths:
        findings.append("compiler/tendcf/plugins.py: no PluginSpec(relpath=...) entries found")
        return findings

    resolved_root = root.resolve(strict=True)
    plugins_root = resolved_root / "plugins"
    try:
        st_p = os.lstat(plugins_root)
    except OSError as exc:
        return [f"plugins/: missing: {exc}"]
    if stat.S_ISLNK(st_p.st_mode) or not stat.S_ISDIR(st_p.st_mode):
        return ["plugins/: must be a real non-symlink directory"]
    resolved_plugins = plugins_root.resolve(strict=True)

    for relpath in relpaths:
        parts = relpath.split("/")
        if (
            relpath.startswith("/")
            or any(p in ("", ".", "..") for p in parts)
            or parts[0] != "plugins"
            or not parts[-1].endswith(".py")
        ):
            findings.append(f"compiler/tendcf/plugins.py: unsafe static plugin relpath {relpath!r}")
            continue
        cur = resolved_root
        bad_comp = False
        for idx, part in enumerate(parts):
            cur = cur / part
            try:
                st = os.lstat(cur)
            except OSError:
                findings.append(f"compiler/tendcf/plugins.py: static plugin path missing: {relpath}")
                bad_comp = True
                break
            if stat.S_ISLNK(st.st_mode):
                findings.append(f"compiler/tendcf/plugins.py: static plugin path has symlink component: {cur}")
                bad_comp = True
                break
            is_leaf = idx == len(parts) - 1
            if is_leaf and not stat.S_ISREG(st.st_mode):
                findings.append(f"compiler/tendcf/plugins.py: static plugin target is not a regular file: {relpath}")
                bad_comp = True
                break
            if not is_leaf and not stat.S_ISDIR(st.st_mode):
                findings.append(f"compiler/tendcf/plugins.py: static plugin parent is not a directory: {cur}")
                bad_comp = True
                break
        if bad_comp:
            continue
        resolved_target = cur.resolve(strict=True)
        if not resolved_target.is_relative_to(resolved_plugins):
            findings.append(f"compiler/tendcf/plugins.py: static plugin escapes plugins/: {relpath}")

    return findings


def _walk_python_tree(base: Path, root: Path, *, is_tool: bool) -> list[str]:
    """Walk `base` without following symlinks; report any symlinked subdir or `.py` file."""
    findings: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dp = Path(dirpath)
        # Skip __pycache__ directories from AST scanning, but still reject symlinks.
        kept_dirs: list[str] = []
        for d in sorted(dirnames):
            cand = dp / d
            if cand.is_symlink():
                findings.append(
                    f"{cand.relative_to(root).as_posix()}: symlinked directory forbidden in scanned tree"
                )
                continue
            if d == "__pycache__":
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fn in sorted(filenames):
            cand = dp / fn
            if not fn.endswith(".py"):
                continue
            if cand.is_symlink():
                findings.append(
                    f"{cand.relative_to(root).as_posix()}: symlinked Python file forbidden in scanned tree"
                )
                continue
            findings.extend(_check_python_file(cand, root, is_tool=is_tool))
    return findings


def check_repo(root: Path) -> list[str]:
    findings: list[str] = []

    bin_path = root / "bin"
    if bin_path.exists() or bin_path.is_symlink():
        findings.append("bin/: must not exist at repo root (replaced by tools/ with no symlink or wrapper)")

    required_trees = (
        (root / "tools", True, "tools/"),
        (root / "compiler" / "tendcf", False, "compiler/tendcf/"),
        (root / "plugins", False, "plugins/"),
    )
    for tree_dir, is_tool, label in required_trees:
        if not tree_dir.is_dir() or tree_dir.is_symlink():
            findings.append(f"{label}: missing or symlink")
        else:
            findings.extend(_walk_python_tree(tree_dir, root, is_tool=is_tool))

    optional_trees = (
        (root / "compiler" / "scripts", False, "compiler/scripts/"),
        (root / "contrib", False, "contrib/"),
    )
    for tree_dir, is_tool, label in optional_trees:
        if tree_dir.is_symlink():
            findings.append(f"{label}: symlink forbidden")
        elif tree_dir.is_dir():
            findings.extend(_walk_python_tree(tree_dir, root, is_tool=is_tool))

    findings.extend(_check_pyproject(root))
    findings.extend(_check_static_plugin_table(root))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(REPO_ROOT), help="repository root to check")
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"device-boundary-lint: ERROR: not a directory: {root}", file=sys.stderr)
        return 2
    findings = check_repo(root)
    if findings:
        for f in findings:
            print(f"device-boundary-lint: FAIL: {f}", file=sys.stderr)
        print(f"device-boundary-lint: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("device-boundary-lint: OK (tools/ isolated from compiler/plugins/contrib; static plugin table verified; no entry points; no bin/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
