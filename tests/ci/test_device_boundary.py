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
        '    relpath: str\n'
        'TABLE = {"yaml": PluginSpec(relpath="plugins/frontends/yaml/loader.py")}\n',
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

    def test_refuses_tool_importing_compiler_plugins_contrib_or_tendcf(self) -> None:
        for snippet in (
            "import tendcf\n",
            "from compiler.tendcf import cli\n",
            "import plugins\n",
            "from contrib import foo\n",
            "import nix2cf\n",
            "from importlib.metadata import entry_points\n",
            "import importlib.metadata\n",
            "from importlib import metadata\n",
            "import importlib\nimportlib.import_module('tendcf.cli')\n",
            "import importlib.util\nimportlib.util.spec_from_file_location('x', 'plugins/frontends/yaml/loader.py')\n",
            "import sys\nsys.path.insert(0, 'compiler')\n",
        ):
            with self.subTest(snippet=snippet.strip()):
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    _plant_clean_repo(root)
                    (root / "tools" / "bad.py").write_text(snippet, encoding="utf-8")
                    findings = self.lint.check_repo(root)
                    self.assertTrue(findings, f"expected violation for {snippet!r}")

    def test_refuses_entry_points_in_compiler_plugins_or_pyproject(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _plant_clean_repo(root)
            (root / "compiler" / "tendcf" / "bad.py").write_text(
                "import importlib.metadata\neps = importlib.metadata.entry_points()\n",
                encoding="utf-8",
            )
            findings = self.lint.check_repo(root)
            self.assertTrue(any("entry_points" in f or "importlib.metadata" in f for f in findings), findings)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _plant_clean_repo(root)
            (root / "compiler" / "pyproject.toml").write_text(
                '[project]\nname = "tendcf"\n\n[project.scripts]\ntendcf = "tendcf.cli:main"\n\n'
                '[project.entry-points."tendcf.frontends"]\nfoo = "foo:bar"\n',
                encoding="utf-8",
            )
            findings = self.lint.check_repo(root)
            self.assertTrue(any("entry-points" in f for f in findings), findings)

    def test_refuses_symlink_in_static_plugin_table(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
