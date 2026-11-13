# compiler/ (nix2cf) — notes for AI sessions

`CLAUDE.md` is a symlink to this file.

This directory is the nix2cf compiler, imported into tendcf with its history
(it was `frdminc/nix2cf` until 2026-11-13). The standing rules for the whole
repo (pedantic verification, models, the cross-model frontier review, the
CFEngine reference book, worktrees and absolute paths) are in the root
[`AGENTS.md`](../AGENTS.md); they apply here unchanged and are not repeated.
Read it first. Where it names "tendcf and nix2cf" as the two most important
repos, both are now this one repository; plan reviews with
`route_agent.py plan --kinds frontier --repo tendcf`.

What is specific to the compiler:

- It generates tendcf goal files from Nix expressions, so CFEngine and
  goal-file semantics are load-bearing. The contract it targets is the
  schema in `../schema/`, consumed in-tree, never copied here.
- `scripts/check_schema_version.py` fails when the compiler's
  `GOAL_FILE_SCHEMA_VERSION` differs from the schema's `schema_version`
  const. A schema bump must update the compiler in the same change.
- Tests: from `compiler/`, `uv run pytest` (small Python suite; the root
  workflow runs it). By default the compiler finds tendcf at the enclosing
  repository root; `TENDCF_DIR` / `--tendcf` override that.
