#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///
"""Enforce least-privilege permissions and no-secrets policy on GitHub workflows.

Policy (issue #63; AGENTS.md standing rule 3 spike-lane hardening, enforced repo-wide):

  1. Every entry in `.github/workflows/` must be a regular file (no symlinks,
     no directories/FIFOs); every `.yml`/`.yaml` file is parsed with a strict
     `yaml.BaseLoader` subclass that keeps all scalars as strings (preventing
     YAML 1.1 bool/int/float key collisions), rejects duplicate mapping keys
     both exactly and case-insensitively (matching GitHub Actions'
     `StringComparer.OrdinalIgnoreCase`), rejects YAML `<<` merge keys, and
     bounds traversal against YAML alias bombs/cycles.
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
       the `secrets` context (case-insensitive, quote-aware tokenizer that
       ignores single-quoted string literals and fails closed on unclosed
       `${{` or unclosed single quotes);
     - no `jobs.<id>.if`, `jobs.<id>.steps[*].if`, or `jobs.<id>.snapshot.if`
       condition may reference the `secrets` context, even when `${{ ... }}`
       is omitted (bare expressions).

Enforcement boundary: this in-repo linter gates PRs targeting `master` and
checks pushes to `master` and `spike/**` via `.github/workflows/check.yml`.
Preventing a branch from bypassing CI or reading repo secrets also relies on
repository-level GitHub settings outside the repo (branch ruleset requiring
`check` on `master`, `default_workflow_permissions: read`, and keeping zero
repo-level secrets or scoping secrets to `master`-only Environments).

Exit 0 when all workflows pass, 1 on any policy violation or parse error.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOWS_DIR = ROOT / ".github" / "workflows"

# Generous finite node-visit budget for walking parsed YAML graphs so an
# exponential alias DAG ("billion laughs") or cyclic alias fails closed quickly.
MAX_WALK_NODES = 100_000

_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CONT = _IDENT_START | set("0123456789-")

_ALLOWED_YAML_TAGS = frozenset({
    "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:map",
})


class _StrictLoader(yaml.BaseLoader):
    """BaseLoader that keeps all scalars as strings, rejects unsupported explicit
    YAML tags (e.g. `!!null`, `!!bool`, `!!int`, `!!merge`), rejects YAML `<<`
    merge keys, and rejects duplicate mapping keys (both exact and
    case-insensitive)."""

    def construct_object(self, node: yaml.Node, deep: bool = False):
        if node.tag not in _ALLOWED_YAML_TAGS:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"unsupported YAML tag {node.tag!r}",
                node.start_mark,
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )

        mapping: dict = {}
        seen_lower: dict[str, str] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "YAML merge key '<<' is disallowed",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=True)
            if isinstance(key, str) and key == "<<":
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "YAML merge key '<<' is disallowed",
                    key_node.start_mark,
                )
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found unhashable key",
                    key_node.start_mark,
                ) from exc

            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            if isinstance(key, str):
                lower = key.lower()
                if lower in seen_lower:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {key!r} (case-insensitive conflict with {seen_lower[lower]!r})",
                        key_node.start_mark,
                    )
                seen_lower[lower] = key
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _ci_lookup(mapping: dict, target_lower: str) -> tuple[bool, str | None, object]:
    """Case-insensitive lookup on a mapping whose string keys are case-insensitively unique."""
    for k, v in mapping.items():
        if isinstance(k, str) and k.lower() == target_lower:
            return True, k, v
    return False, None, None


def extract_expressions(text: str) -> list[tuple[str, bool]]:
    """Extract all GitHub Actions `${{ ... }}` expression spans as `(body, is_unclosed)`.

    Respects single-quoted string literals (`'...'` with `''` escapes) inside
    expressions so `'}}'` inside a string cannot terminate the span early.
    """
    spans, _ = _split_expressions(text)
    return spans


def _split_expressions(text: str) -> tuple[list[tuple[str, bool]], list[str]]:
    """Split `text` into `(expressions, outside_chunks)`.

    Each item in `expressions` is `(body, is_unclosed)`. `outside_chunks` holds
    the substrings outside `${{ ... }}` delimiters.
    """
    spans: list[tuple[str, bool]] = []
    outside: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        start = text.find("${{", i)
        if start == -1:
            outside.append(text[i:])
            break
        if start > i:
            outside.append(text[i:start])
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
            spans.append((text[start + 3 :], True))
            break
        spans.append((text[start + 3 : end], False))
        i = end + 2
    return spans, outside


def scan_expression_for_secrets(expr: str) -> tuple[bool, bool]:
    """Single-pass quote-aware GitHub Actions expression tokenizer.

    Returns `(has_secrets_ref, has_unclosed_quote)`:
    - Single-quoted string literals (`'...'`, with `''` escapes) are skipped.
      Double quotes (`"`) are NOT string delimiters in GitHub Actions expressions.
    - An unclosed single-quoted literal sets `has_unclosed_quote=True` so callers
      fail closed.
    - Any identifier equal to `secrets` (case-insensitive) that is NOT immediately
      preceded by `.` (ignoring whitespace) sets `has_secrets_ref=True`.
    """
    has_secrets = False
    i = 0
    n = len(expr)
    prev_non_ws = ""

    while i < n:
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "'":
            i += 1
            closed = False
            while i < n:
                if expr[i] == "'":
                    if i + 1 < n and expr[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                return has_secrets, True
            prev_non_ws = "'"
            continue
        if ch in _IDENT_START:
            start = i
            i += 1
            while i < n and expr[i] in _IDENT_CONT:
                i += 1
            token = expr[start:i]
            if token.lower() == "secrets" and prev_non_ws != ".":
                has_secrets = True
            prev_non_ws = "A"
            continue
        if ch.isdigit():
            i += 1
            while i < n and expr[i] in _IDENT_CONT:
                i += 1
            prev_non_ws = "0"
            continue
        prev_non_ws = ch
        i += 1

    return has_secrets, False


def _check_expression_body(expr: str, is_unclosed: bool, where: str, findings: list[str]) -> None:
    if is_unclosed:
        findings.append(f"{where}: malformed expression (unclosed '${{{{' delimiter)")
    has_secrets, has_unclosed_quote = scan_expression_for_secrets(expr)
    if has_unclosed_quote:
        findings.append(f"{where}: malformed expression (unclosed single-quoted string literal)")
    if has_secrets:
        findings.append(f"{where}: expression references `secrets` context: {expr.strip()!r}")


def _check_string_value(text: str, where: str, *, is_bare_expr: bool, findings: list[str]) -> None:
    if is_bare_expr:
        if "${{" in text:
            spans, outside = _split_expressions(text)
            for expr, is_unclosed in spans:
                _check_expression_body(expr, is_unclosed, where, findings)
            for chunk in outside:
                if chunk.strip():
                    _check_expression_body(chunk, False, where, findings)
        else:
            _check_expression_body(text, False, where, findings)
        return

    for expr, is_unclosed in extract_expressions(text):
        _check_expression_body(expr, is_unclosed, where, findings)


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


def _format_path(path: tuple[str | int, ...]) -> str:
    parts: list[str] = []
    for elem in path:
        if isinstance(elem, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{elem}]"
            else:
                parts.append(f"[{elem}]")
        else:
            parts.append(elem)
    return ".".join(parts)


def _walk_for_secrets(
    root: object,
    findings: list[str],
    *,
    bare_expr_paths: set[tuple[str | int, ...]],
    max_nodes: int = MAX_WALK_NODES,
) -> None:
    """Iterative, node-budgeted traversal over the resolved YAML object graph."""
    stack: list[tuple[object, tuple[str | int, ...]]] = [(root, ())]
    visited = 0

    while stack:
        obj, path = stack.pop()
        visited += 1
        if visited > max_nodes:
            findings.append(
                f"YAML structure exceeds node traversal limit ({max_nodes}); "
                "possible alias expansion bomb or cycle"
            )
            return

        if isinstance(obj, dict):
            items = list(obj.items())
            for k, _ in items:
                if isinstance(k, str):
                    key_where = f"{_format_path(path + (k,))} (mapping key)"
                    _check_string_value(k, key_where, is_bare_expr=False, findings=findings)
            for k, v in reversed(items):
                stack.append((v, path + (str(k),)))
        elif isinstance(obj, list):
            for idx in range(len(obj) - 1, -1, -1):
                stack.append((obj[idx], path + (idx,)))
        elif isinstance(obj, str):
            _check_string_value(
                obj,
                _format_path(path),
                is_bare_expr=(path in bare_expr_paths),
                findings=findings,
            )


def lint_workflow_text(text: str, label: str, *, max_nodes: int = MAX_WALK_NODES) -> list[str]:
    """Validate a single workflow YAML document string. Returns list of finding strings."""
    findings: list[str] = []
    try:
        doc = yaml.load(text, Loader=_StrictLoader)
    except yaml.YAMLError as exc:
        return [f"{label}: YAML parse error: {exc}"]
    except RecursionError:
        return [f"{label}: YAML parse error: nesting depth exceeded recursion limit"]

    if not isinstance(doc, dict):
        return [f"{label}: workflow root must be a YAML mapping, got {type(doc).__name__}"]

    # 1. Required explicit top-level permissions (case-insensitive lookup).
    has_perms, _, perms_val = _ci_lookup(doc, "permissions")
    if not has_perms:
        findings.append(f"{label}: missing required top-level `permissions:` mapping")
    else:
        _check_permissions(perms_val, f"{label}: permissions", findings)

    # 2. Reusable workflow callee `on.workflow_call.secrets`.
    has_on, _, on_val = _ci_lookup(doc, "on")
    if has_on and isinstance(on_val, dict):
        has_wc, _, wc_val = _ci_lookup(on_val, "workflow_call")
        if has_wc and isinstance(wc_val, dict):
            has_wc_sec, _, wc_sec = _ci_lookup(wc_val, "secrets")
            if has_wc_sec and _is_non_empty_secrets_field(wc_sec):
                findings.append(
                    f"{label}: on.workflow_call.secrets: secrets declaration is disallowed ({wc_sec!r})"
                )

    # 3. Job-level permissions, reusable-workflow secrets, and bare `if:` expression paths.
    bare_expr_paths: set[tuple[str | int, ...]] = set()
    has_jobs, jobs_key, jobs_val = _ci_lookup(doc, "jobs")
    if has_jobs:
        assert jobs_key is not None
        if not isinstance(jobs_val, dict):
            findings.append(f"{label}: jobs: must be a YAML mapping, got {type(jobs_val).__name__}")
        else:
            for job_id, job in jobs_val.items():
                job_id_str = str(job_id)
                job_path: tuple[str | int, ...] = (jobs_key, job_id_str)
                job_prefix = f"jobs.{job_id_str}"
                if not isinstance(job, dict):
                    findings.append(
                        f"{label}: {job_prefix}: must be a YAML mapping, got {type(job).__name__}"
                    )
                    continue

                has_jp, _, jp_val = _ci_lookup(job, "permissions")
                if has_jp:
                    _check_permissions(jp_val, f"{label}: {job_prefix}.permissions", findings)

                has_js, _, js_val = _ci_lookup(job, "secrets")
                if has_js and _is_non_empty_secrets_field(js_val):
                    findings.append(
                        f"{label}: {job_prefix}.secrets: secrets forwarding is disallowed ({js_val!r})"
                    )

                has_jif, jif_key, jif_val = _ci_lookup(job, "if")
                if has_jif and jif_key is not None and isinstance(jif_val, str):
                    bare_expr_paths.add(job_path + (jif_key,))

                has_snap, snap_key, snap_val = _ci_lookup(job, "snapshot")
                if has_snap and snap_key is not None and isinstance(snap_val, dict):
                    has_sif, sif_key, sif_val = _ci_lookup(snap_val, "if")
                    if has_sif and sif_key is not None and isinstance(sif_val, str):
                        bare_expr_paths.add(job_path + (snap_key, sif_key))

                has_steps, steps_key, steps_val = _ci_lookup(job, "steps")
                if has_steps and steps_key is not None and isinstance(steps_val, list):
                    for idx, step in enumerate(steps_val):
                        if isinstance(step, dict):
                            has_stif, stif_key, stif_val = _ci_lookup(step, "if")
                            if has_stif and stif_key is not None and isinstance(stif_val, str):
                                bare_expr_paths.add(job_path + (steps_key, idx, stif_key))

    # 4. Walk entire resolved document for `${{ ... }}` and bare `if:` `secrets` references.
    doc_findings: list[str] = []
    _walk_for_secrets(doc, doc_findings, bare_expr_paths=bare_expr_paths, max_nodes=max_nodes)
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
