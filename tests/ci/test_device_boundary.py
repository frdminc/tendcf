"""Unit tests for tools/device_boundary_lint.py (D46 Step 4 structural boundary check)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LINT_PATH = REPO / "tools" / "device_boundary_lint.py"


def _load_lint():
    spec = importlib.util.spec_from_file_location("device_boundary_lint", LINT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _plant_clean_repo(root: Path) -> None:
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "projector.py").write_text("import json\n", encoding="utf-8")
    (root / "compiler" / "tendcf").mkdir(parents=True)
    (root / "plugins" / "frontends" / "yaml").mkdir(parents=True)
    (root / "plugins" / "frontends" / "yaml" / "loader.py").write_text("X = 1\n", encoding="utf-8")
    (root / "compiler" / "tendcf" / "plugins.py").write_text(
        'from dataclasses import dataclass\n'
        '@dataclass(frozen=True)\n'
        'class PluginSpec:\n'
        '    kind: str\n'
        '    name: str\n'
        '    relpath: str\n'
        'TABLE = {"yaml": PluginSpec(kind="frontend", name="yaml", relpath="plugins/frontends/yaml/loader.py")}\n',
        encoding="utf-8",
    )
    (root / "compiler" / "pyproject.toml").write_text(
        '[project]\nname = "tendcf"\nversion = "0.0.1"\n\n[project.scripts]\ntendcf = "tendcf.cli:main"\n',
        encoding="utf-8",
    )


class DeviceBoundaryLintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lint = _load_lint()

    def test_real_repo_passes_under_isolated_stdlib_python(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-I", "-S", str(LINT_PATH)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("device-boundary-lint: OK", proc.stdout)

    def test_clean_synthetic_repo_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _plant_clean_repo(root)
            self.assertEqual(self.lint.check_repo(root), [])

    def test_refuses_leftover_bin_dir_or_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _plant_clean_repo(root)
            (root / "bin").symlink_to("tools")
            findings = self.lint.check_repo(root)
            self.assertTrue(any("bin/:" in f for f in findings), findings)

    def test_refuses_tool_imports_aliases_kwargs_and_indirect_bypasses(self) -> None:
        for snippet in (
            "import tendcf\n",
            "from compiler.tendcf import cli\n",
            "import plugins\n",
            "from contrib import foo\n",
            "import nix2cf\n",
            "from .. import compiler\n",
            "from importlib.metadata import entry_points\n",
            "import importlib.metadata\n",
            "from importlib import metadata\n",
            "import importlib\nx = importlib.metadata.distributions()\n",
            "import importlib as il\nil.import_module('tendcf')\n",
            "from importlib import import_module as im\nim('tendcf')\n",
            "from importlib.util import spec_from_file_location as s\ns('x', location='plugins/frontends/yaml/loader.py')\n",
            "import importlib.util\nimportlib.util.spec_from_file_location('x', 'plugins/frontends/yaml/loader.py')\n",
            "import importlib\ngetattr(importlib, 'metadata')\n",
            "import runpy\nrunpy.run_path('compiler/tendcf/cli.py')\n",
            "import pkgutil\n",
            "from importlib.machinery import SourceFileLoader\n",
            "exec('import tendcf')\n",
            "eval('1+1')\n",
            "import sys\nsys.path.insert(0, 'compiler')\n",
            "import sys as s\ns.path.extend(['compiler'])\n",
            "from sys import path\npath.append('compiler')\n",
            "import sys\nsys.path += ['compiler']\n",
            "import sys\nsys.path[0:0] = ['compiler']\n",
        ):
            with self.subTest(snippet=snippet.strip()):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    _plant_clean_repo(root)
                    (root / "tools" / "bad.py").write_text(snippet, encoding="utf-8")
                    findings = self.lint.check_repo(root)
                    self.assertTrue(findings, f"expected violation for {snippet!r}")

    def test_refuses_entry_points_in_compiler_plugins_contrib_scripts_and_pyproject(self) -> None:
        for rel_target, snippet in (
            ("compiler/tendcf/bad.py", "import importlib.metadata\neps = importlib.metadata.entry_points()\n"),
            ("compiler/tendcf/bad2.py", "import importlib as il\nx = il.metadata.distributions()\n"),
            ("compiler/tendcf/bad3.py", "import importlib\ngetattr(importlib, 'metadata')\n"),
            ("compiler/scripts/bad.py", "from importlib.metadata import entry_points\n"),
            ("contrib/bad.py", "import importlib.metadata\n"),
        ):
            with self.subTest(rel_target=rel_target):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    _plant_clean_repo(root)
                    p = root / rel_target
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(snippet, encoding="utf-8")
                    findings = self.lint.check_repo(root)
                    self.assertTrue(findings, f"expected violation in {rel_target}")

        for bad_toml, needle in (
            (
                '[project]\nname = "tendcf"\n[project.scripts]\ntendcf = "tendcf.cli:main"\n'
                '[project.entry-points."tendcf.frontends"]\nfoo = "foo:bar"\n',
                "entry-points",
            ),
            (
                '[project]\nname = "tendcf"\ndynamic = ["entry-points"]\n'
                '[project.scripts]\ntendcf = "tendcf.cli:main"\n',
                "dynamic",
            ),
            (
                '[project]\nname = "tendcf"\n[project.scripts]\ntendcf = "tendcf.cli:main"\n'
                '[project.gui-scripts]\nnix2cf = "tendcf.cli:main"\n',
                "gui-scripts",
            ),
            (
                'project = "malformed"\n',
                "[project] table",
            ),
        ):
            with self.subTest(needle=needle):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    _plant_clean_repo(root)
                    (root / "compiler" / "pyproject.toml").write_text(bad_toml, encoding="utf-8")
                    findings = self.lint.check_repo(root)
                    self.assertTrue(any(needle in f for f in findings), findings)

    def test_refuses_symlinks_and_non_constant_static_plugin_specs(self) -> None:
        # 1. Leaf symlink in plugins/
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _plant_clean_repo(root)
            outside = root / "evil.py"
            outside.write_text("X = 2\n", encoding="utf-8")
            target = root / "plugins" / "frontends" / "yaml" / "loader.py"
            target.unlink()
            target.symlink_to(outside)
            findings = self.lint.check_repo(root)
            self.assertTrue(any("symlink" in f for f in findings), findings)

        # 2. Nested symlinked subdirectory under tools/
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _plant_clean_repo(root)
            ext = root / "ext"
            ext.mkdir()
            (ext / "evil.py").write_text("import tendcf\n", encoding="utf-8")
            (root / "tools" / "sub").symlink_to(ext)
            findings = self.lint.check_repo(root)
            self.assertTrue(any("symlinked directory" in f for f in findings), findings)

        # 3. Positional/non-constant or non-.py PluginSpec relpath
        for bad_spec in (
            'PluginSpec("frontend", "evil", "../outside.py")\n',
            'VAR = "plugins/frontends/yaml/loader.py"\nPluginSpec(kind="frontend", name="x", relpath=VAR)\n',
            'PluginSpec(kind="frontend", name="x", relpath="plugins/frontends/yaml/loader.txt")\n',
        ):
            with self.subTest(bad_spec=bad_spec.strip()):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    _plant_clean_repo(root)
                    (root / "compiler" / "tendcf" / "plugins.py").write_text(
                        "class PluginSpec:\n    pass\n" + bad_spec,
                        encoding="utf-8",
                    )
                    findings = self.lint.check_repo(root)
                    self.assertTrue(findings, f"expected finding for {bad_spec!r}")


if __name__ == "__main__":
    unittest.main()
