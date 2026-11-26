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
from unittest import mock

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
    branches: ['spike/**']
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

    def test_literal_word_secrets_in_comments_plain_shell_and_single_quoted_expressions_passes(self) -> None:
        wf = """\
# No secrets are used in this workflow.
name: Echo
on: push
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    if: github.event_name != 'secrets' && github.actor != 'don''t leak secrets'
    snapshot:
      image-name: my-snap
      if: github.ref_name != 'secrets'
    env:
      LABEL: ${{ 'secrets' }}
      ESCAPED: ${{ 'don''t leak secrets' }}
      PROP: ${{ github.event.secrets }}
      SPACED_PROP: ${{ github.event . secrets }}
    steps:
      - name: Check secrets policy
        if: ${{ github.actor != 'secrets' }}
        run: echo "no secrets here ${{ 'secrets' }}"
      - name: Unrelated identifiers in expression
        if: ${{ github.actor != 'my_secrets' && inputs.no_secrets != 'yes' && inputs.secrets-foo != 'x' }}
        run: echo "${{ matrix.secrets_mode }} ${{ inputs.my_secrets }} ${{ inputs.secrets-foo }}"
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
        self.assertTrue(
            any("permissions.contents: disallowed permission level 'write'" in f for f in findings),
            findings,
        )

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
                self.assertTrue(any("must be an explicit YAML mapping" in f for f in findings), findings)

    def test_missing_empty_or_explicit_tagged_top_level_permissions_fails(self) -> None:
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
        self.assertTrue(any("missing required top-level `permissions:` mapping" in f for f in findings), findings)

        for label, perm_line, expected in (
            ("empty scalar", "permissions:", "must be an explicit YAML mapping"),
            ("empty string", 'permissions: ""', "must be an explicit YAML mapping"),
            ("tilde null", "permissions: ~", "must be an explicit YAML mapping"),
            ("explicit !!null", 'permissions: !!null ""', "YAML parse error"),
            ("explicit !!bool", "permissions: !!bool true", "YAML parse error"),
        ):
            with self.subTest(case=label):
                wf = f"""\
name: BadPerm
on: push
{perm_line}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
                findings = lint.lint_workflow_text(wf, "badperm.yml")
                self.assertTrue(any(expected in f for f in findings), findings)

    def test_job_level_elevated_permissions_fail(self) -> None:
        cases = [
            ("id-token: write", "    permissions:\n      id-token: write\n", "disallowed permission level 'write'"),
            ("packages: read", "    permissions:\n      packages: read\n", "disallowed permission level 'read'"),
            ("write-all", "    permissions: write-all\n", "must be an explicit YAML mapping"),
            ("read-all", "    permissions: read-all\n", "must be an explicit YAML mapping"),
            (
                "reusable workflow write",
                "    uses: org/repo/.github/workflows/w.yml@main\n    permissions:\n      contents: write\n",
                "disallowed permission level 'write'",
            ),
        ]
        for label, job_block, expected in cases:
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
                self.assertTrue(
                    any("jobs.bad.permissions" in f and expected in f for f in findings),
                    findings,
                )

    def test_duplicate_keys_exact_and_case_insensitive_fail(self) -> None:
        cases = [
            (
                "duplicate top-level permissions",
                "name: Dup\non: push\npermissions:\n  contents: read\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
            ),
            (
                "case-insensitive top-level Permissions",
                "name: DupCI\non: push\npermissions:\n  contents: read\nPermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
            ),
            (
                "duplicate nested permission scope",
                "name: DupNested\non: push\npermissions:\n  contents: write\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
            ),
            (
                "case-insensitive nested Contents scope",
                "name: DupNestedCI\non: push\npermissions:\n  contents: read\n  Contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
            ),
        ]
        for label, wf in cases:
            with self.subTest(case=label):
                findings = lint.lint_workflow_text(wf, "dup.yml")
                self.assertTrue(any("found duplicate key" in f for f in findings), findings)

    def test_case_insensitive_capitalized_policy_keys_are_enforced(self) -> None:
        wf = """\
name: Caps
ON:
  WORKFLOW_CALL:
    SECRETS:
      tok:
        required: true
Permissions:
  contents: write
JOBS:
  a:
    runs-on: ubuntu-latest
    PERMISSIONS:
      id-token: write
    SECRETS: inherit
    IF: secrets.FOO != ''
    SNAPSHOT:
      IF: secrets.BAR != ''
    STEPS:
      - IF: secrets.BAZ != ''
        run: echo hi
"""
        findings = lint.lint_workflow_text(wf, "caps.yml")
        self.assertTrue(any("permissions.contents: disallowed permission level 'write'" in f for f in findings), findings)
        self.assertTrue(any("on.workflow_call.secrets: secrets declaration is disallowed" in f for f in findings), findings)
        self.assertTrue(any("jobs.a.permissions.id-token: disallowed permission level 'write'" in f for f in findings), findings)
        self.assertTrue(any("jobs.a.secrets: secrets forwarding is disallowed" in f for f in findings), findings)
        self.assertTrue(any("JOBS.a.IF: expression references `secrets` context" in f for f in findings), findings)
        self.assertTrue(any("JOBS.a.SNAPSHOT.IF: expression references `secrets` context" in f for f in findings), findings)
        self.assertTrue(any("JOBS.a.STEPS[0].IF: expression references `secrets` context" in f for f in findings), findings)

    def test_yaml_anchor_alias_and_merge_keys_fail(self) -> None:
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
        self.assertTrue(
            any("permissions.contents: disallowed permission level 'write'" in f for f in findings),
            findings,
        )

        merge_cases = [
            (
                "single mapping merge",
                "name: M1\non: push\nx-e: &e\n  id-token: write\npermissions:\n  <<: *e\n  contents: read\njobs: {}\n",
            ),
            (
                "sequence merge",
                "name: M2\non: push\nx-a: &a\n  contents: read\nx-b: &b\n  contents: write\npermissions:\n  <<: [*a, *b]\njobs: {}\n",
            ),
            (
                "anchored key merge",
                "name: M3\non: push\nx-a: &a\n  contents: write\npermissions:\n  &mk <<: *a\njobs: {}\n",
            ),
            (
                "explicit !!merge tag",
                "name: M4\non: push\nx-a: &a\n  contents: write\npermissions:\n  !!merge <<: *a\njobs: {}\n",
            ),
        ]
        for label, wf in merge_cases:
            with self.subTest(case=label):
                findings = lint.lint_workflow_text(wf, "merge.yml")
                self.assertTrue(
                    any("YAML merge key '<<' is disallowed" in f for f in findings),
                    findings,
                )

    def test_yaml_11_python_dict_slot_collision_exploits_caught(self) -> None:
        """Adversary F2 [HIGH]: BaseLoader keeps keys as strings so `yes`/`1`, `no`/`0`,
        `on`/`1.0`, `2`/`2.0` cannot collide in Python dict slots and overwrite a secret."""
        cases = [
            ("env yes/1", '    env:\n      yes: "${{ secrets.EXFIL }}"\n      1: "benign"\n'),
            ("env no/0", '    env:\n      no: "${{ secrets.EXFIL }}"\n      0: "benign"\n'),
            ("env on/1.0", '    env:\n      on: "${{ secrets.EXFIL }}"\n      1.0: "benign"\n'),
            ("env 2/2.0", '    env:\n      2: "${{ secrets.EXFIL }}"\n      2.0: "benign"\n'),
            (
                "step with on/1",
                '    steps:\n      - uses: actions/checkout@v4\n        with:\n          on: "${{ secrets.EXFIL }}"\n          1: "benign"\n',
            ),
        ]
        for label, block in cases:
            with self.subTest(case=label):
                wf = f"""\
name: Collide
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
{block}"""
                findings = lint.lint_workflow_text(wf, "collide.yml")
                self.assertTrue(
                    any("expression references `secrets` context" in f for f in findings),
                    findings,
                )

    def test_alias_expansion_bomb_fails_closed_within_node_budget(self) -> None:
        lines = [
            "name: Bomb",
            "on: push",
            "permissions:",
            "  contents: read",
            "x-a0: &a0 [x, x]",
        ]
        for i in range(1, 25):
            lines.append(f"x-a{i}: &a{i} [*a{i - 1}, *a{i - 1}]")
        lines.append("jobs: {}")
        wf = "\n".join(lines) + "\n"
        findings = lint.lint_workflow_text(wf, "bomb.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("exceeds node traversal limit", findings[0])

    def test_preflight_node_limit_stops_before_permissions_and_jobs_prepass(self) -> None:
        wf_perms = """\
name: P
on: push
x-a: &a [v1, v2, v3]
permissions: [*a, *a]
jobs: {}
"""
        with mock.patch.object(lint, "MAX_WALK_NODES", 5):
            findings = lint.lint_workflow_text(wf_perms, "pre-perms.yml")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("exceeds node traversal limit (5)", findings[0])
        self.assertFalse(any("must be an explicit YAML mapping" in f for f in findings), findings)

        wf_jobs = """\
name: J
on: push
permissions:
  contents: read
x-s: &s
  - run: echo a
  - run: echo b
  - run: echo c
jobs:
  a:
    runs-on: ubuntu-latest
    secrets:
      tok: *s
    steps: *s
"""
        with mock.patch.object(lint, "MAX_WALK_NODES", 8):
            findings = lint.lint_workflow_text(wf_jobs, "pre-jobs.yml")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("exceeds node traversal limit (8)", findings[0])
        self.assertFalse(any("secrets forwarding is disallowed" in f for f in findings), findings)

    def test_preflight_depth_limit_stops_immediately_and_catches_cycles(self) -> None:
        wf_deep = """\
name: Deep
on: push
permissions: write-all
a:
  b:
    c:
      d:
        e: x
jobs: {}
"""
        with mock.patch.object(lint, "MAX_WALK_DEPTH", 3):
            findings = lint.lint_workflow_text(wf_deep, "deep.yml")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("exceeds nesting depth limit (3)", findings[0])
        self.assertFalse(any("must be an explicit YAML mapping" in f for f in findings), findings)

        wf_cycle = """\
name: Cycle
on: push
permissions:
  contents: read
x-c: &c
  - *c
jobs: {}
"""
        findings = lint.lint_workflow_text(wf_cycle, "cycle.yml")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("YAML parse error: found unconstructable recursive node", findings[0])

        cyclic: list[object] = []
        cyclic.append(cyclic)
        err = lint._check_structure_limits({"x": cyclic}, "memcycle.yml")
        self.assertIsNotNone(err)
        self.assertIn("exceeds nesting depth limit", err or "")

    def test_collection_diagnostics_use_type_size_summaries_not_raw_repr(self) -> None:
        wf_perm_seq = """\
name: SeqPerm
on: push
permissions: [sentinel_alpha, sentinel_beta]
jobs: {}
"""
        findings = lint.lint_workflow_text(wf_perm_seq, "seqperm.yml")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("must be an explicit YAML mapping", findings[0])
        self.assertIn("sequence (2 items)", findings[0])
        self.assertNotIn("sentinel_alpha", findings[0])
        self.assertNotIn("sentinel_beta", findings[0])

        wf_nested_perm = """\
name: NestedPerm
on: push
permissions:
  contents: [nested_sentinel]
jobs: {}
"""
        findings = lint.lint_workflow_text(wf_nested_perm, "nestedperm.yml")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("scope and level must be strings", findings[0])
        self.assertIn("sequence (1 items)", findings[0])
        self.assertNotIn("nested_sentinel", findings[0])

        wf_secrets_maps = """\
name: SecMaps
on:
  workflow_call:
    secrets:
      wc_key_sentinel:
        required: true
permissions:
  contents: read
jobs:
  call:
    uses: org/repo/.github/workflows/other.yml@main
    secrets:
      job_key_sentinel: job_val_sentinel
"""
        findings = lint.lint_workflow_text(wf_secrets_maps, "secmaps.yml")
        self.assertEqual(len(findings), 2, findings)
        self.assertTrue(
            any(
                "on.workflow_call.secrets: secrets declaration is disallowed (mapping (1 entries))" in f
                and "wc_key_sentinel" not in f
                for f in findings
            ),
            findings,
        )
        self.assertTrue(
            any(
                "jobs.call.secrets: secrets forwarding is disallowed (mapping (1 entries))" in f
                and "job_key_sentinel" not in f
                and "job_val_sentinel" not in f
                for f in findings
            ),
            findings,
        )

    def test_findings_cap_truncates_diagnostic_volume(self) -> None:
        wf = """\
name: Many
on: push
permissions:
  contents: write
  actions: write
  packages: write
  id-token: write
jobs: {}
"""
        with mock.patch.object(lint, "MAX_FINDINGS", 2):
            findings = lint.lint_workflow_text(wf, "many.yml")
        self.assertEqual(len(findings), 3, findings)
        self.assertIn("findings output truncated after 2 finding(s)", findings[-1])

    # ---- Negative cases: secrets & malformed expressions

    def test_expression_secrets_references_fail(self) -> None:
        expressions = [
            "${{ secrets.MY_SECRET }}",
            "${{ secrets . MY_SECRET }}",
            "${{ secrets['MY_SECRET'] }}",
            '${{ secrets["MY_SECRET"] }}',
            "${{ toJSON(secrets) }}",
            "${{ SECRETS.FOO }}",
            "${{ !secrets.FOO }}",
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
                self.assertTrue(
                    any("expression references `secrets` context" in f for f in findings),
                    findings,
                )

    def test_unclosed_expression_and_unclosed_single_quote_fail_closed(self) -> None:
        wf_unclosed_expr = """\
name: UnclosedExpr
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      X: "${{ 'unclosed }} ${{ secrets.FOO }}"
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_unclosed_expr, "unclosed-expr.yml")
        self.assertTrue(any("malformed expression (unclosed '${{' delimiter)" in f for f in findings), findings)
        self.assertTrue(any("malformed expression (unclosed single-quoted string literal)" in f for f in findings), findings)

        wf_unclosed_bare_if = """\
name: UnclosedIf
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    if: "'unclosed || secrets.FOO"
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_unclosed_bare_if, "unclosed-if.yml")
        self.assertTrue(
            any("jobs.a.if: malformed expression (unclosed single-quoted string literal)" in f for f in findings),
            findings,
        )

        wf_unclosed_tail_secret = """\
name: UnclosedTail
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      X: "${{ secrets.FOO"
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_unclosed_tail_secret, "unclosed-tail.yml")
        self.assertTrue(any("malformed expression (unclosed '${{' delimiter)" in f for f in findings), findings)
        self.assertTrue(any("expression references `secrets` context" in f for f in findings), findings)

    def test_bare_if_secrets_references_fail_at_job_step_and_snapshot_levels(self) -> None:
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
        self.assertTrue(
            any("jobs.a.if: expression references `secrets` context" in f for f in findings),
            findings,
        )

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
        self.assertTrue(
            any("jobs.a.steps[0].if: expression references `secrets` context" in f for f in findings),
            findings,
        )

        wf_snapshot_if = """\
name: BareSnapshotIf
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    snapshot:
      image-name: snap
      if: secrets.MY_SECRET != ''
    steps:
      - run: echo hi
"""
        findings = lint.lint_workflow_text(wf_snapshot_if, "snapif.yml")
        self.assertTrue(
            any("jobs.a.snapshot.if: expression references `secrets` context" in f for f in findings),
            findings,
        )

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
        self.assertTrue(
            any("jobs.call.secrets: secrets forwarding is disallowed" in f for f in findings),
            findings,
        )

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
        self.assertTrue(
            any("jobs.call.secrets: secrets forwarding is disallowed" in f for f in findings),
            findings,
        )
        self.assertTrue(
            any("expression references `secrets` context" in f for f in findings),
            findings,
        )

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
        self.assertTrue(
            any("on.workflow_call.secrets: secrets declaration is disallowed" in f for f in findings),
            findings,
        )

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
        self.assertTrue(any("non-regular file not allowed" in f for f in findings), findings)

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
