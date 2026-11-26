#!/usr/bin/env python3
"""Enforce tendcf's structural device boundary and static-plugin-table invariants (D46 Step 4).

Pure stdlib (`python3 -I -S` compatible). Implements `docs/architecture/plugin-layout.md`
§4 ("The device boundary is structural, not a convention") and 2026-11-14 operator ruling
Smaller 5 (static in-tree import table only; no entry-point discovery):

1. No leftover `bin/` directory, wrapper, or symlink at repository root.
2. Every Python script under `tools/` (including `projector.py`, `schema_lint.py`,
   `approval_enforce.py`, `unit_classifier.py`, `recompute_goal_hashes.py`, etc.):
   - Never imports `compiler`, `plugins`, `contrib`, `tendcf`, `nix2cf`,
     `importlib.metadata`, or `pkg_resources`.
   - Never calls `entry_points` or accesses `.entry_points`.
   - Never dynamically loads modules from `compiler/`, `plugins/`, or `contrib/`
     via `importlib.import_module`, `__import__`, `spec_from_file_location`, or
     `sys.path` injection.
3. Every Python file under `compiler/tendcf/` and `plugins/`:
   - Never imports `importlib.metadata` or `pkg_resources`, and never invokes
     `entry_points` (out-of-tree discovery is deferred until #47).
4. `compiler/pyproject.toml`:
   - Declares package name `tendcf`, CLI script `tendcf`, no `nix2cf` alias,
     and ZERO `[project.entry-points]` tables.
5. Every static `relpath` in `compiler/tendcf/plugins.py` resolves without
   symlinks to a regular `.py` file strictly under `plugins/`.

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
    {"compiler", "plugins", "contrib", "tendcf", "nix2cf", "pkg_resources"}
)
FORBIDDEN_COMPILER_ROOT_MODULES: frozenset[str] = frozenset({"pkg_resources"})
FORBIDDEN_PATH_SEGMENTS: frozenset[str] = frozenset({"compiler", "plugins", "contrib"})
FORBIDDEN_DYNAMIC_MODULES: frozenset[str] = frozenset(
    {"compiler", "plugins", "contrib", "tendcf", "nix2cf", "importlib.metadata", "pkg_resources"}
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


def _check_python_file(path: Path, root: Path, *, is_tool: bool) -> list[str]:
    rel = path.relative_to(root).as_posix()
    findings: list[str] = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel)
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return [f"{rel}: cannot parse Python AST: {exc}"]

    forbidden_roots = FORBIDDEN_TOOL_ROOT_MODULES if is_tool else FORBIDDEN_COMPILER_ROOT_MODULES

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod == "importlib.metadata" or mod.startswith("importlib.metadata."):
                    findings.append(
                        f"{rel}:{node.lineno}: forbidden entry-point import {mod!r}"
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
            elif mod and _root_module(mod) in forbidden_roots:
                findings.append(
                    f"{rel}:{node.lineno}: forbidden import from {mod!r}"
                )
            if any(a.name == "entry_points" for a in node.names):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden import of 'entry_points'"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr == "entry_points":
                findings.append(
                    f"{rel}:{node.lineno}: forbidden attribute access '.entry_points'"
                )
        elif isinstance(node, ast.Call):
            callee = _dotted_name(node.func)
            if callee == "entry_points" or callee.endswith(".entry_points"):
                findings.append(
                    f"{rel}:{node.lineno}: forbidden call to {callee!r}"
                )
            if callee in ("__import__", "importlib.import_module", "import_module"):
                for lit in _iter_string_literals(node):
                    if lit == "importlib.metadata" or lit.startswith("importlib.metadata."):
                        findings.append(
                            f"{rel}:{node.lineno}: forbidden dynamic import of {lit!r}"
                        )
                    elif is_tool and (
                        lit in FORBIDDEN_DYNAMIC_MODULES
                        or _root_module(lit) in FORBIDDEN_TOOL_ROOT_MODULES
                    ):
                        findings.append(
                            f"{rel}:{node.lineno}: forbidden dynamic import of {lit!r}"
                        )
            if is_tool and callee in (
                "importlib.util.spec_from_file_location",
                "spec_from_file_location",
            ):
                for arg in node.args[1:]:
                    for lit in _iter_string_literals(arg):
                        segs = [s for s in lit.replace("\\", "/").split("/") if s]
                        if any(seg in FORBIDDEN_PATH_SEGMENTS for seg in segs):
                            findings.append(
                                f"{rel}:{node.lineno}: tool loads path referencing forbidden tree {lit!r}"
                            )
            if is_tool and callee in ("sys.path.insert", "sys.path.append"):
                for arg in node.args:
                    for lit in _iter_string_literals(arg):
                        segs = [s for s in lit.replace("\\", "/").split("/") if s]
                        if any(seg in FORBIDDEN_PATH_SEGMENTS for seg in segs):
                            findings.append(
                                f"{rel}:{node.lineno}: tool mutates sys.path with forbidden tree {lit!r}"
                            )

    return findings


def _check_pyproject(root: Path) -> list[str]:
    findings: list[str] = []
    pyproject = root / "compiler" / "pyproject.toml"
    if not pyproject.is_file() or pyproject.is_symlink():
        return [f"compiler/pyproject.toml: missing or symlink"]
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return [f"compiler/pyproject.toml: cannot parse TOML: {exc}"]

    project = data.get("project", {})
    if project.get("name") != "tendcf":
        findings.append(
            f"compiler/pyproject.toml: [project].name is {project.get('name')!r}, expected 'tendcf'"
        )
    scripts = project.get("scripts", {})
    if "tendcf" not in scripts:
        findings.append("compiler/pyproject.toml: [project.scripts] must declare 'tendcf'")
    if "nix2cf" in scripts:
        findings.append("compiler/pyproject.toml: [project.scripts] must not keep removed 'nix2cf' alias")
    if "entry-points" in project:
        findings.append(
            "compiler/pyproject.toml: [project.entry-points] is forbidden (out-of-tree discovery deferred, Smaller 5)"
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
            for kw in node.keywords:
                if kw.arg == "relpath" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    relpaths.append(kw.value.value)

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
        if relpath.startswith("/") or any(p in ("", ".", "..") for p in parts) or parts[0] != "plugins":
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


def check_repo(root: Path) -> list[str]:
    findings: list[str] = []

    bin_path = root / "bin"
    if bin_path.exists() or bin_path.is_symlink():
        findings.append("bin/: must not exist at repo root (replaced by tools/ with no symlink or wrapper)")

    tools_dir = root / "tools"
    if not tools_dir.is_dir() or tools_dir.is_symlink():
        findings.append("tools/: missing or symlink")
    else:
        for py in sorted(tools_dir.rglob("*.py")):
            findings.extend(_check_python_file(py, root, is_tool=True))

    compiler_pkg = root / "compiler" / "tendcf"
    if not compiler_pkg.is_dir() or compiler_pkg.is_symlink():
        findings.append("compiler/tendcf/: missing or symlink")
    else:
        for py in sorted(compiler_pkg.rglob("*.py")):
            findings.extend(_check_python_file(py, root, is_tool=False))

    plugins_dir = root / "plugins"
    if not plugins_dir.is_dir() or plugins_dir.is_symlink():
        findings.append("plugins/: missing or symlink")
    else:
        for py in sorted(plugins_dir.rglob("*.py")):
            findings.extend(_check_python_file(py, root, is_tool=False))

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
