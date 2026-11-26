#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///
"""Enforce least-privilege permissions and no-secrets policy on GitHub workflows.

Policy (issue #63; AGENTS.md standing rule 3 spike-lane hardening, enforced repo-wide):

  1. Every entry in `.github/workflows/` must be a regular file (no symlinks,
     no directories/FIFOs); every `.yml`/`.yaml` file is parsed strictly with
     duplicate-key rejection and resolved anchors/merge keys.
  2. Every workflow must declare an explicit top-level `permissions:` mapping.
     Both top-level `permissions:` and any job-level `jobs.<id>.permissions:`
     (including reusable workflow jobs) must be YAML mappings whose entries are
     exclusively `contents: read`, `contents: none`, or `<scope>: none`.
     `read-all`, `write-all`, any `write` on any scope, and any `read` on any
     scope other than `contents` are rejected.
  3. No secrets may be referenced, forwarded, or declared:
     - `jobs.<id>.secrets` must not be present and non-empty (`inherit` or any
       mapping entries are rejected);
     - `on.workflow_call.secrets` must not be present and non-empty;
     - no `${{ ... }}` expression anywhere in the parsed document may reference
       the `secrets` context (case-insensitive);
     - no `jobs.<id>.if` or `jobs.<id>.steps[*].if` condition may reference the
       `secrets` context, even when `${{ ... }}` is omitted (bare expressions).

Exit 0 when all workflows pass, 1 on any policy violation or parse error.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOWS_DIR = ROOT / ".github" / "workflows"

# Matches the `secrets` context identifier inside a GitHub Actions expression
# (case-insensitive). Excludes hyphenated/underscored identifiers and dotted
# property names like `foo.secrets`, while matching `secrets.FOO`,
# `secrets['FOO']`, `secrets["FOO"]`, `toJSON(secrets)`, `SECRETS.FOO`, etc.
SECRETS_EXPR_RE = re.compile(r"(?<![A-Za-z0-9_.-])secrets(?![A-Za-z0-9_-])", re.IGNORECASE)


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that fails closed on duplicate mapping keys (including across `<<` merges)."""

    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )

        # First pass on raw node pairs: reject duplicate explicit keys or duplicate `<<` keys.
        raw_seen: set[tuple[type, object]] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raw_key: tuple[type, object] = (str, "<<")
            else:
                key = self.construct_object(key_node, deep=True)
                try:
                    hash(key)
                except TypeError as exc:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        "found unhashable key",
                        key_node.start_mark,
                    ) from exc
                raw_key = (type(key), key)
            if raw_key in raw_seen:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {raw_key[1]!r}",
                    key_node.start_mark,
                )
            raw_seen.add(raw_key)

        # Expand YAML `<<` merge keys, then construct and reject any duplicate keys.
        self.flatten_mapping(node)
        mapping: dict = {}
        seen: set[tuple[type, object]] = set()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found unhashable key",
                    key_node.start_mark,
                ) from exc
            typed_key = (type(key), key)
            if typed_key in seen:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(typed_key)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def extract_expressions(text: str) -> list[str]:
    """Extract all GitHub Actions `${{ ... }}` expression bodies from `text`.

    Respects single-quoted string literals (`'...'`, with `''` escaping a quote)
    inside an expression so `'}}'` inside a string cannot close the span early.
    An unclosed `${{` captures through end-of-string so malformed expressions
    still fail closed.
    """
    spans: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        start = text.find("${{", i)
        if start == -1:
            break
        j = start + 3
        in_quote = False
        end = -1
        while j < n:
            ch = text[j]
            if in_quote:
                if ch == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    in_quote = False
                j += 1
            else:
                if ch == "'":
                    in_quote = True
                    j += 1
                elif ch == "}" and j + 1 < n and text[j + 1] == "}":
                    end = j
                    break
                else:
                    j += 1
        if end == -1:
            spans.append(text[start + 3 :])
            break
        spans.append(text[start + 3 : end])
        i = end + 2
    return spans


def _check_permissions(val: object, where: str, findings: list[str]) -> None:
    if not isinstance(val, dict):
        findings.append(
            f"{where}: must be an explicit YAML mapping (e.g. `contents: read` or `{{}}`), "
            f"got {type(val).__name__} ({val!r})"
        )
        return
    for scope, level in val.items():
        if not isinstance(scope, str) or not isinstance(level, str):
            findings.append(
                f"{where}: scope and level must be strings, got {scope!r}: {level!r}"
            )
            continue
        if scope == "contents" and level in ("read", "none"):
            continue
        if level == "none":
            continue
        findings.append(
            f"{where}.{scope}: disallowed permission level {level!r} "
            f"(only `contents: read` and `<scope>: none` are permitted)"
        )


def _is_non_empty_secrets_field(val: object) -> bool:
    if val is None:
        return False
    if isinstance(val, dict):
        return len(val) > 0
    if isinstance(val, str):
        return val.strip() != ""
    return True


def _walk_for_secrets(
    obj: object,
    path: str,
    findings: list[str],
    *,
    bare_expr_paths: set[str],
) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_label = str(k)
            child_path = f"{path}.{key_label}" if path else key_label
            if isinstance(k, str):
                for expr in extract_expressions(k):
                    if SECRETS_EXPR_RE.search(expr):
                        findings.append(
                            f"{child_path} (mapping key): expression references `secrets` context: {expr.strip()!r}"
                        )
            _walk_for_secrets(v, child_path, findings, bare_expr_paths=bare_expr_paths)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _walk_for_secrets(item, f"{path}[{idx}]", findings, bare_expr_paths=bare_expr_paths)
    elif isinstance(obj, str):
        if path in bare_expr_paths:
            if SECRETS_EXPR_RE.search(obj):
                findings.append(
                    f"{path}: condition references `secrets` context: {obj.strip()!r}"
                )
            return
        for expr in extract_expressions(obj):
            if SECRETS_EXPR_RE.search(expr):
                findings.append(
                    f"{path}: expression references `secrets` context: {expr.strip()!r}"
                )


def lint_workflow_text(text: str, label: str) -> list[str]:
    """Validate a single workflow YAML document string. Returns list of finding strings."""
    findings: list[str] = []
    try:
        doc = yaml.load(text, Loader=_StrictLoader)
    except yaml.YAMLError as exc:
        return [f"{label}: YAML parse error: {exc}"]

    if not isinstance(doc, dict):
        return [f"{label}: workflow root must be a YAML mapping, got {type(doc).__name__}"]

    # YAML 1.1 parses bare `on:` as boolean True; reject having both `on` and `"on"`.
    if True in doc and "on" in doc:
        findings.append(f"{label}: duplicate 'on' trigger key (both unquoted on and quoted 'on')")

    # 1. Required explicit top-level permissions.
    if "permissions" not in doc:
        findings.append(f"{label}: missing required top-level `permissions:` mapping")
    else:
        _check_permissions(doc["permissions"], f"{label}: permissions", findings)

    # 2. Reusable workflow callee `on.workflow_call.secrets`.
    for on_key in ("on", True):
        on_val = doc.get(on_key)
        if isinstance(on_val, dict):
            wc = on_val.get("workflow_call")
            if isinstance(wc, dict) and "secrets" in wc and _is_non_empty_secrets_field(wc["secrets"]):
                findings.append(
                    f"{label}: on.workflow_call.secrets: secrets declaration is disallowed ({wc['secrets']!r})"
                )

    # 3. Job-level permissions, reusable-workflow secrets, and bare `if:` expression paths.
    bare_expr_paths: set[str] = set()
    if "jobs" in doc:
        jobs = doc["jobs"]
        if not isinstance(jobs, dict):
            findings.append(f"{label}: jobs: must be a YAML mapping, got {type(jobs).__name__}")
        else:
            for job_id, job in jobs.items():
                job_prefix = f"jobs.{job_id}"
                if not isinstance(job, dict):
                    findings.append(
                        f"{label}: {job_prefix}: must be a YAML mapping, got {type(job).__name__}"
                    )
                    continue
                if "permissions" in job:
                    _check_permissions(
                        job["permissions"],
                        f"{label}: {job_prefix}.permissions",
                        findings,
                    )
                if "secrets" in job and _is_non_empty_secrets_field(job["secrets"]):
                    findings.append(
                        f"{label}: {job_prefix}.secrets: secrets forwarding is disallowed ({job['secrets']!r})"
                    )
                if "if" in job and isinstance(job["if"], str):
                    bare_expr_paths.add(f"{job_prefix}.if")
                steps = job.get("steps")
                if isinstance(steps, list):
                    for idx, step in enumerate(steps):
                        if isinstance(step, dict) and "if" in step and isinstance(step["if"], str):
                            bare_expr_paths.add(f"{job_prefix}.steps[{idx}].if")

    # 4. Walk entire resolved document for `${{ ... }}` and bare `if:` `secrets` references.
    doc_findings: list[str] = []
    _walk_for_secrets(doc, "", doc_findings, bare_expr_paths=bare_expr_paths)
    for item in doc_findings:
        findings.append(f"{label}: {item}")

    return findings


def _read_regular_utf8(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"not a regular file: {path}")
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            return f.read()
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass


def lint_workflows_dir(workflows_dir: Path) -> tuple[int, list[str]]:
    """Lint every workflow in `workflows_dir`. Returns `(files_checked, findings)`."""
    findings: list[str] = []
    try:
        dir_st = os.lstat(workflows_dir)
    except OSError as exc:
        return 0, [f"{workflows_dir}: cannot stat workflows directory: {exc}"]

    if stat.S_ISLNK(dir_st.st_mode):
        return 0, [f"{workflows_dir}: workflows directory must not be a symlink"]
    if not stat.S_ISDIR(dir_st.st_mode):
        return 0, [f"{workflows_dir}: not a directory"]

    checked = 0
    for entry in sorted(workflows_dir.iterdir(), key=lambda p: p.name):
        label = entry.name
        try:
            st = os.lstat(entry)
        except OSError as exc:
            findings.append(f"{label}: cannot stat entry: {exc}")
            continue
        if stat.S_ISLNK(st.st_mode):
            findings.append(f"{label}: symlink not allowed in workflows directory")
            continue
        if not stat.S_ISREG(st.st_mode):
            findings.append(f"{label}: non-regular file not allowed in workflows directory")
            continue
        if entry.suffix.lower() not in (".yml", ".yaml"):
            continue
        checked += 1
        try:
            text = _read_regular_utf8(entry)
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(f"{label}: cannot read workflow file: {exc}")
            continue
        findings.extend(lint_workflow_text(text, label))

    if checked == 0 and not findings:
        findings.append(f"{workflows_dir}: no .yml/.yaml workflow files found")

    return checked, findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enforce `permissions: contents: read` (or none) and no-secrets policy on GitHub workflows."
    )
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        default=DEFAULT_WORKFLOWS_DIR,
        help="Directory containing GitHub Actions workflow files (default: <repo>/.github/workflows).",
    )
    args = parser.parse_args(argv)

    checked, findings = lint_workflows_dir(args.workflows_dir)
    if findings:
        print(
            f"workflow_permissions_lint: FAILED ({len(findings)} finding(s) across {checked} workflow file(s))",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(f"workflow_permissions_lint: OK ({checked} workflow file(s) checked, 0 findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
