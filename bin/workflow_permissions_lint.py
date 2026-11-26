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

# Generous finite structural and diagnostic limits so an exponential alias DAG
# ("billion laughs"), cyclic alias, or pathological workflow fails closed quickly
# with bounded memory and output.
MAX_WALK_NODES = 100_000
MAX_WALK_DEPTH = 64
MAX_FINDINGS = 200

_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CONT = _IDENT_START | set("0123456789-")

_ALLOWED_YAML_TAGS = frozenset({
    "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:map",
})


def _describe_value(val: object, max_scalar: int = 80) -> str:
    """Return a bounded, non-recursive summary of `val` (never repr()s collections)."""
    if isinstance(val, dict):
        return f"mapping ({len(val)} entries)"
    if isinstance(val, list):
        return f"sequence ({len(val)} items)"
    if isinstance(val, str):
        if len(val) > max_scalar:
            return repr(val[:max_scalar] + "...")
        return repr(val)
    return type(val).__name__


class _FindingsCap:
    """Bounded findings collector that stops emitting after `max_findings` entries."""

    def __init__(self, max_findings: int, label: str) -> None:
        self.max_findings = max_findings
        self.label = label
        self.items: list[str] = []
        self.truncated = False

    def add(self, message: str) -> bool:
        if self.truncated:
            return False
        if len(self.items) >= self.max_findings:
            self.truncated = True
            self.items.append(
                f"{self.label}: findings output truncated after {self.max_findings} finding(s)"
            )
            return False
        self.items.append(f"{self.label}: {message}")
        return True


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
                    f"found duplicate key {_describe_value(key)}",
                    key_node.start_mark,
                )
            if isinstance(key, str):
                lower = key.lower()
                if lower in seen_lower:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {_describe_value(key)} (case-insensitive conflict with {_describe_value(seen_lower[lower])})",
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


def _check_expression_body(expr: str, is_unclosed: bool, where: str, emit) -> None:
    if is_unclosed:
        if not emit(f"{where}: malformed expression (unclosed '${{{{' delimiter)"):
            return
    has_secrets, has_unclosed_quote = scan_expression_for_secrets(expr)
    if has_unclosed_quote:
        if not emit(f"{where}: malformed expression (unclosed single-quoted string literal)"):
            return
    if has_secrets:
        emit(f"{where}: expression references `secrets` context: {_describe_value(expr.strip())}")


def _check_string_value(text: str, where: str, *, is_bare_expr: bool, emit) -> None:
    if is_bare_expr:
        if "${{" in text:
            spans, outside = _split_expressions(text)
            for expr, is_unclosed in spans:
                _check_expression_body(expr, is_unclosed, where, emit)
            for chunk in outside:
                if chunk.strip():
                    _check_expression_body(chunk, False, where, emit)
        else:
            _check_expression_body(text, False, where, emit)
        return

    for expr, is_unclosed in extract_expressions(text):
        _check_expression_body(expr, is_unclosed, where, emit)


def _check_permissions(val: object, where: str, emit) -> None:
    if not isinstance(val, dict):
        emit(
            f"{where}: must be an explicit YAML mapping (e.g. `contents: read` or `{{}}`), "
            f"got {_describe_value(val)}"
        )
        return
    for scope, level in val.items():
        if not isinstance(scope, str) or not isinstance(level, str):
            if not emit(
                f"{where}: scope and level must be strings, got {_describe_value(scope)}: {_describe_value(level)}"
            ):
                return
            continue
        if scope == "contents" and level in ("read", "none"):
            continue
        if level == "none":
            continue
        scope_label = scope if len(scope) <= 80 else _describe_value(scope)
        if not emit(
            f"{where}.{scope_label}: disallowed permission level {_describe_value(level)} "
            "(only `contents: read` and `<scope>: none` are permitted)"
        ):
            return


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


def _check_structure_limits(
    doc: object,
    label: str,
    *,
    max_nodes: int | None = None,
    max_depth: int | None = None,
) -> str | None:
    """Bounded iterator-stack preflight over `doc` before any policy pass runs.

    Accounts for every edge as it is encountered (never eagerly materializing
    child lists), rejecting excessive node counts (e.g. alias DAG bombs) or
    excessive nesting depth (e.g. cyclic aliases).
    """
    node_limit = MAX_WALK_NODES if max_nodes is None else max_nodes
    depth_limit = MAX_WALK_DEPTH if max_depth is None else max_depth

    visited = 1
    if visited > node_limit:
        return (
            f"{label}: YAML structure exceeds node traversal limit ({node_limit}); "
            "possible alias expansion bomb or cycle"
        )
    if 0 > depth_limit:
        return (
            f"{label}: YAML structure exceeds nesting depth limit ({depth_limit}); "
            "possible alias expansion bomb or cycle"
        )

    stack: list[tuple[object, int]] = []
    if isinstance(doc, dict) and doc:
        stack.append((iter(doc.values()), 1))
    elif isinstance(doc, list) and doc:
        stack.append((iter(doc), 1))

    while stack:
        it, child_depth = stack[-1]
        try:
            child = next(it)  # type: ignore[arg-type]
        except StopIteration:
            stack.pop()
            continue

        visited += 1
        if visited > node_limit:
            return (
                f"{label}: YAML structure exceeds node traversal limit ({node_limit}); "
                "possible alias expansion bomb or cycle"
            )
        if child_depth > depth_limit:
            return (
                f"{label}: YAML structure exceeds nesting depth limit ({depth_limit}); "
                "possible alias expansion bomb or cycle"
            )

        if isinstance(child, dict) and child:
            stack.append((iter(child.values()), child_depth + 1))
        elif isinstance(child, list) and child:
            stack.append((iter(child), child_depth + 1))

    return None


def _walk_for_secrets(
    root: object,
    collector: _FindingsCap,
    *,
    bare_expr_paths: set[tuple[str | int, ...]],
    max_nodes: int | None = None,
    max_depth: int | None = None,
) -> None:
    """Streaming, node- and depth-budgeted traversal over the resolved YAML graph."""
    node_limit = MAX_WALK_NODES if max_nodes is None else max_nodes
    depth_limit = MAX_WALK_DEPTH if max_depth is None else max_depth

    visited = 1
    if visited > node_limit:
        collector.add(
            f"YAML structure exceeds node traversal limit ({node_limit}); "
            "possible alias expansion bomb or cycle"
        )
        return
    if 0 > depth_limit:
        collector.add(
            f"YAML structure exceeds nesting depth limit ({depth_limit}); "
            "possible alias expansion bomb or cycle"
        )
        return

    stack: list[tuple[str, object, tuple[str | int, ...], int]] = []
    if isinstance(root, dict) and root:
        stack.append(("dict", iter(root.items()), (), 1))
    elif isinstance(root, list) and root:
        stack.append(("list", enumerate(root), (), 1))
    elif isinstance(root, str):
        _check_string_value(root, "", is_bare_expr=(() in bare_expr_paths), emit=collector.add)
        return

    while stack and not collector.truncated:
        kind, it, parent_path, child_depth = stack[-1]
        try:
            item = next(it)  # type: ignore[arg-type]
        except StopIteration:
            stack.pop()
            continue

        visited += 1
        if visited > node_limit:
            collector.add(
                f"YAML structure exceeds node traversal limit ({node_limit}); "
                "possible alias expansion bomb or cycle"
            )
            return
        if child_depth > depth_limit:
            collector.add(
                f"YAML structure exceeds nesting depth limit ({depth_limit}); "
                "possible alias expansion bomb or cycle"
            )
            return

        if kind == "dict":
            k, child = item
            child_path = parent_path + (str(k),)
            if isinstance(k, str):
                key_where = f"{_format_path(child_path)} (mapping key)"
                _check_string_value(k, key_where, is_bare_expr=False, emit=collector.add)
                if collector.truncated:
                    return
        else:
            idx, child = item
            child_path = parent_path + (idx,)

        if isinstance(child, dict) and child:
            stack.append(("dict", iter(child.items()), child_path, child_depth + 1))
        elif isinstance(child, list) and child:
            stack.append(("list", enumerate(child), child_path, child_depth + 1))
        elif isinstance(child, str):
            _check_string_value(
                child,
                _format_path(child_path),
                is_bare_expr=(child_path in bare_expr_paths),
                emit=collector.add,
            )


def lint_workflow_text(
    text: str,
    label: str,
    *,
    max_nodes: int | None = None,
    max_depth: int | None = None,
    max_findings: int | None = None,
) -> list[str]:
    """Validate a single workflow YAML document string. Returns list of finding strings."""
    try:
        doc = yaml.load(text, Loader=_StrictLoader)
    except yaml.YAMLError as exc:
        return [f"{label}: YAML parse error: {exc}"]
    except RecursionError:
        return [f"{label}: YAML parse error: nesting depth exceeded recursion limit"]

    if not isinstance(doc, dict):
        return [f"{label}: workflow root must be a YAML mapping, got {_describe_value(doc)}"]

    # 0. Bounded structural preflight BEFORE any policy pass or collection inspection.
    limit_err = _check_structure_limits(doc, label, max_nodes=max_nodes, max_depth=max_depth)
    if limit_err is not None:
        return [limit_err]

    finding_limit = MAX_FINDINGS if max_findings is None else max_findings
    collector = _FindingsCap(finding_limit, label)

    # 1. Required explicit top-level permissions (case-insensitive lookup).
    has_perms, _, perms_val = _ci_lookup(doc, "permissions")
    if not has_perms:
        collector.add("missing required top-level `permissions:` mapping")
    else:
        _check_permissions(perms_val, "permissions", collector.add)

    # 2. Reusable workflow callee `on.workflow_call.secrets`.
    has_on, _, on_val = _ci_lookup(doc, "on")
    if has_on and isinstance(on_val, dict):
        has_wc, _, wc_val = _ci_lookup(on_val, "workflow_call")
        if has_wc and isinstance(wc_val, dict):
            has_wc_sec, _, wc_sec = _ci_lookup(wc_val, "secrets")
            if has_wc_sec and _is_non_empty_secrets_field(wc_sec):
                collector.add(
                    f"on.workflow_call.secrets: secrets declaration is disallowed ({_describe_value(wc_sec)})"
                )

    # 3. Job-level permissions, reusable-workflow secrets, and bare `if:` expression paths.
    bare_expr_paths: set[tuple[str | int, ...]] = set()
    has_jobs, jobs_key, jobs_val = _ci_lookup(doc, "jobs")
    if has_jobs:
        assert jobs_key is not None
        if not isinstance(jobs_val, dict):
            collector.add(f"jobs: must be a YAML mapping, got {_describe_value(jobs_val)}")
        else:
            for job_id, job in jobs_val.items():
                if collector.truncated:
                    break
                job_id_str = str(job_id)
                job_path: tuple[str | int, ...] = (jobs_key, job_id_str)
                job_prefix = f"jobs.{job_id_str}"
                if not isinstance(job, dict):
                    collector.add(f"{job_prefix}: must be a YAML mapping, got {_describe_value(job)}")
                    continue

                has_jp, _, jp_val = _ci_lookup(job, "permissions")
                if has_jp:
                    _check_permissions(jp_val, f"{job_prefix}.permissions", collector.add)

                has_js, _, js_val = _ci_lookup(job, "secrets")
                if has_js and _is_non_empty_secrets_field(js_val):
                    collector.add(
                        f"{job_prefix}.secrets: secrets forwarding is disallowed ({_describe_value(js_val)})"
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
    if not collector.truncated:
        _walk_for_secrets(
            doc,
            collector,
            bare_expr_paths=bare_expr_paths,
            max_nodes=max_nodes,
            max_depth=max_depth,
        )

    return collector.items


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
