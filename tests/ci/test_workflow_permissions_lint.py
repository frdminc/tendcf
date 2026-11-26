"""Unit tests for bin/workflow_permissions_lint.py (issue #63).

Run with:
    uv run --with pyyaml python -m unittest discover -s tests/ci -v
"""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
LINT_PATH = REPO / "bin" / "workflow_permissions_lint.py"

spec = importlib.util.spec_from_file_location("workflow_permissions_lint", LINT_PATH)
assert spec is not None and spec.loader is not None
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)


def _write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


class WorkflowPermissionsLintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="tendcf-wf-lint-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    # ---- Positive cases

    def test_real_repo_workflows_pass(self) -> None:
        checked, findings = lint.lint_workflows_dir(REPO / ".github" / "workflows")
        self.assertGreaterEqual(checked, 4)
        self.assertEqual(findings, [])

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = lint.main(["--workflows-dir", str(REPO / ".github" / "workflows")])
        self.assertEqual(rc, 0, err.getvalue())
        self.assertIn("OK", out.getvalue())

    def test_minimal_contents_read_passes(self) -> None:
        wf = """\
name: Spike
on:
  push:
    branches: ['spike/*']
permissions:
  contents: read
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "hello"
"""
        self.assertEqual(lint.lint_workflow_text(wf, "spike.yml"), [])

    def test_empty_permissions_and_explicit_none_scopes_pass(self) -> None:
        wf = """\
name: Locked
on: workflow_dispatch
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: none
      actions: none
      packages: none
      id-token: none
    steps:
      - run: echo ok
  b:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: none
    steps:
      - run: echo ok
"""
        self.assertEqual(lint.lint_workflow_text(wf, "locked.yml"), [])

    def test_literal_word_secrets_in_comments_and_plain_shell_passes(self) -> None:
        wf = """\
# No secrets are used in this workflow.
name: Echo
on: push
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    if: github.event_name != 'schedule'
    steps:
      - name: Check secrets policy
        run: echo "no secrets here"
      - name: Unrelated identifier in expression
        if: ${{ github.actor != 'my_secrets' && inputs.no_secrets != 'yes' }}
        run: echo "${{ matrix.secrets_mode }}"
"""
        self.assertEqual(lint.lint_workflow_text(wf, "echo.yml"), [])

    # ---- Negative cases: permissions

    def test_top_level_contents_write_fails(self) -> None:
        wf = """\
name: Bad
on: push
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf, "bad.yml")
        self.assertTrue(any("contents" in f and "write" in f for f in findings), findings)

    def test_top_level_write_all_and_read_all_fail(self) -> None:
        for val in ("write-all", "read-all"):
            with self.subTest(permissions=val):
                wf = f"""\
name: Bad
on: push
permissions: {val}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
                findings = lint.lint_workflow_text(wf, "bad.yml")
                self.assertTrue(any("mapping" in f for f in findings), findings)

    def test_missing_or_null_top_level_permissions_fails(self) -> None:
        wf_missing = """\
name: Missing
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_missing, "missing.yml")
        self.assertTrue(any("missing required top-level `permissions:`" in f for f in findings), findings)

        wf_null = """\
name: Null
on: push
permissions:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_null, "null.yml")
        self.assertTrue(any("mapping" in f for f in findings), findings)

    def test_job_level_elevated_permissions_fail(self) -> None:
        cases = [
            ("id-token: write", "    permissions:\n      id-token: write\n"),
            ("packages: read", "    permissions:\n      packages: read\n"),
            ("write-all", "    permissions: write-all\n"),
            ("read-all", "    permissions: read-all\n"),
            ("reusable workflow write", "    uses: org/repo/.github/workflows/w.yml@main\n    permissions:\n      contents: write\n"),
        ]
        for label, job_block in cases:
            with self.subTest(case=label):
                wf = f"""\
name: JobPerm
on: push
permissions:
  contents: read
jobs:
  bad:
    runs-on: ubuntu-latest
{job_block}    steps:
      - run: echo hi
"""
                findings = lint.lint_workflow_text(wf, "jobperm.yml")
                self.assertGreaterEqual(len(findings), 1, f"{label} should fail")
                self.assertTrue(any("jobs.bad.permissions" in f for f in findings), findings)

    def test_duplicate_permissions_key_fails(self) -> None:
        wf = """\
name: Dup
on: push
permissions:
  contents: read
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf, "dup.yml")
        self.assertTrue(any("duplicate key" in f for f in findings), findings)

    def test_duplicate_nested_permission_scope_fails(self) -> None:
        wf = """\
name: DupNested
on: push
permissions:
  contents: write
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf, "dupnested.yml")
        self.assertTrue(any("duplicate key" in f for f in findings), findings)

    def test_yaml_anchor_and_merge_smuggling_fails(self) -> None:
        wf_alias = """\
name: Anchor
on: push
x-elev: &elev
  contents: write
permissions: *elev
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_alias, "anchor.yml")
        self.assertTrue(any("contents" in f and "write" in f for f in findings), findings)

        wf_merge = """\
name: Merge
on: push
x-elev: &elev
  id-token: write
permissions:
  <<: *elev
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_merge, "merge.yml")
        self.assertTrue(any("id-token" in f and "write" in f for f in findings), findings)

        wf_merge_override = """\
name: MergeOverride
on: push
x-elev: &elev
  contents: write
permissions:
  <<: *elev
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_merge_override, "merge-override.yml")
        self.assertTrue(any("duplicate key" in f for f in findings), findings)

    # ---- Negative cases: secrets

    def test_expression_secrets_references_fail(self) -> None:
        expressions = [
            "${{ secrets.MY_SECRET }}",
            "${{ secrets['MY_SECRET'] }}",
            '${{ secrets["MY_SECRET"] }}',
            "${{ toJSON(secrets) }}",
            "${{ SECRETS.FOO }}",
            "${{ '}}' && secrets.HIDDEN }}",
        ]
        for expr in expressions:
            with self.subTest(expr=expr):
                wf = f"""\
name: SecExpr
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      TOK: {expr!r}
    steps:
      - run: echo hi
"""
                findings = lint.lint_workflow_text(wf, "secexpr.yml")
                self.assertTrue(any("secrets" in f for f in findings), findings)

    def test_bare_if_secrets_references_fail_at_job_and_step_levels(self) -> None:
        wf_job_if = """\
name: BareJobIf
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    if: secrets.MY_SECRET != ''
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_job_if, "jobif.yml")
        self.assertTrue(any("jobs.a.if" in f and "secrets" in f for f in findings), findings)

        wf_step_if = """\
name: BareStepIf
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - if: secrets.MY_SECRET != ''
        run: echo hi
"""
        findings = lint.lint_workflow_text(wf_step_if, "stepif.yml")
        self.assertTrue(any("jobs.a.steps[0].if" in f and "secrets" in f for f in findings), findings)

    def test_reusable_workflow_secrets_fail(self) -> None:
        wf_inherit = """\
name: ReuseInherit
on: push
permissions:
  contents: read
jobs:
  call:
    uses: org/repo/.github/workflows/other.yml@main
    secrets: inherit
"""
        findings = lint.lint_workflow_text(wf_inherit, "inherit.yml")
        self.assertTrue(any("jobs.call.secrets" in f for f in findings), findings)

        wf_map = """\
name: ReuseMap
on: push
permissions:
  contents: read
jobs:
  call:
    uses: org/repo/.github/workflows/other.yml@main
    secrets:
      tok: ${{ secrets.MY_TOK }}
"""
        findings = lint.lint_workflow_text(wf_map, "map.yml")
        self.assertTrue(any("jobs.call.secrets" in f for f in findings), findings)

        wf_callee = """\
name: Callee
on:
  workflow_call:
    secrets:
      my_secret:
        required: true
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_callee, "callee.yml")
        self.assertTrue(any("on.workflow_call.secrets" in f for f in findings), findings)

    # ---- Negative cases: filesystem & malformed YAML

    def test_symlinked_workflow_file_fails(self) -> None:
        outside = self.tmp / "outside.yml"
        outside.write_text(
            "name: Good\non: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
            encoding="utf-8",
        )
        wf_dir = self.tmp / "workflows"
        wf_dir.mkdir()
        os.symlink(outside, wf_dir / "linked.yml")

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = lint.main(["--workflows-dir", str(wf_dir)])
        self.assertEqual(rc, 1)
        self.assertIn("symlink not allowed", err.getvalue())

    def test_non_regular_entry_in_workflows_dir_fails(self) -> None:
        wf_dir = self.tmp / "workflows"
        wf_dir.mkdir()
        (wf_dir / "subdir").mkdir()
        _write(
            wf_dir,
            "ok.yml",
            "name: Ok\non: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        )
        _, findings = lint.lint_workflows_dir(wf_dir)
        self.assertTrue(any("non-regular file" in f for f in findings), findings)

    def test_malformed_yaml_fails(self) -> None:
        wf = "name: Broken\non: [push\npermissions:\n  contents: read\n"
        findings = lint.lint_workflow_text(wf, "broken.yml")
        self.assertTrue(any("YAML parse error" in f for f in findings), findings)

    def test_multi_document_yaml_fails(self) -> None:
        wf = """\
---
name: First
on: push
permissions:
  contents: read
jobs: {}
---
permissions: write-all
"""
        findings = lint.lint_workflow_text(wf, "multi.yml")
        self.assertTrue(any("YAML parse error" in f for f in findings), findings)


if __name__ == "__main__":
    unittest.main()
