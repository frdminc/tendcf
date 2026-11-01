# Notes for AI sessions working in this repo

`CLAUDE.md` is a symlink to this file.

## Handoffs are data — commit and push in place

`docs/handoffs/` is session-handoff memory (Tier 2 deep-recovery
documents), not code — an append-only log, one file per handoff, never
rewritten. Per the operator's explicit instruction (2026-08-15), this repo
has a push-in-place exception for that directory, matching the pattern
used elsewhere in the ops-djbclark suite (e.g. `site-private/memory/`):

- Commit handoff files directly to `master`, in place — no branch, no PR,
  no worktree required.
- Push immediately after committing. Don't leave it local awaiting a
  separate "ok to push" prompt.
- This exception is narrow: `docs/handoffs/` only. Ordinary code/doc
  changes in this repo still go through normal review as the operator
  directs in the moment — this file doesn't blanket-authorize pushing
  arbitrary work.

## Standing rule: most important work — be pedantic, pay for the best models (2026-10-31)

djbclark, 2026-10-31: tendcf and nix2cf are the most important work he is
doing, and getting it right outranks cost. This overrides `model-routing`'s
cost-first default and its "frontier models are scarce" gating (item 1b) **for
these two repos only**; every other repo keeps the default.

1. **Be pedantic.** Re-read what you changed. Verify every claim by running it,
   never by recall. Read the plan or spec section before changing what it
   describes. On a doubt, look it up (the CFEngine book, upstream source, the
   host itself) instead of assuming. Take the slower path; never narrow scope
   or call something verified that you did not run; say what you did not check.
2. **Models.** The lead session runs Opus 5.5 `high` (never Sonnet as lead;
   Fable is never a lead). Code slices run on Sonnet 5.5 `high` through
   `/bigteam` and climb a tier only on evidence of failure.
3. **Review is cross-vendor, never same-model.** An Opus review of Opus work is
   one model with a fresh context, not an independent check. No PR merges on a
   Claude-only review.
   - Every PR: one frontier review before merge. Order: Codex `gpt-6-astra`
     (`acp-dispatch codex --model gpt-6-astra --kind frontier --effort high`),
     then Fable `high` (`acp-dispatch claude --model fable --kind frontier
     --effort high`), then Gemini 4 Argon (`acp-run agy --model gemini-4-argon
     --effort high`; probed working 2026-10-31, own weekly window).
   - Design rulings (a `schema_version` bump, the privilege or enforcement scope
     on a host, a deploy plan, the unit-writer or consent-diff design): two
     independent frontier reviews, astra and Fable; Argon stands in for
     whichever of the two is short. A disagreement goes to djbclark, not to the
     lead to settle.
   - If all three are short, wait for the reset. Never merge on a weaker
     review, and never substitute an Opus review.
   - The PR body names each reviewer model and effort, quotes the verdict (or
     "no findings") and lists what was fixed.
4. **Limits that still hold.** The quota guard and in-flight reservation
   (`acp-dispatch` exit 5); no Fable `xhigh`/`max` without djbclark's approval;
   one astra slice at a time (four at once emptied Codex's 5-hour window on
   2026-10-18); every slice goes through `acp-dispatch` with `--kind frontier`.
5. **Gemini 4 Carbon** (announced 2026-10-28, not yet accessible to us): recheck
   weekly with `aiuse --available --json` and `acp-run agy`; when it is
   reachable, adopt it as the Google frontier model in place of Argon.

<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->
## CFEngine reference book — Basic Memory first, don't guess (2026-10-03, 2026-10-31)

`Learning CFEngine` (Diego Zamboni, 2nd ed.; covers CFEngine 3.12) is in the
local book knowledge base as slug `learning-cfengine` — 69 chapters, 210 code
blocks. It is **indexed in Basic Memory (project `books`): a cheap, high-value
source of correct CFEngine information, so use it heavily and early** (operator,
2026-10-31). Query it **before writing or reviewing policy and before any
CFEngine design, deployment or privilege question** — promise semantics,
`edit_line`, bundle/body syntax, class expressions, normal ordering, testing,
and also how the daemons fit together (`cf-execd`, `cf-serverd`, bootstrapping,
running as root or not, where policy and work directories live) — rather than
relying on recall or going straight to web search. A first question costs one
call and ~1–2k tokens; the answer names the chapter to read.

1. **Ask Basic Memory in plain words** (the first move). From a shell, no MCP
   needed: `bm tool search --project books "<question>"` (~5 s, ranked chapters
   with excerpts; checked 2026-10-31: "cf-execd runs cf-agent periodically as
   root" returned ch. 23, 35, 19 and 34). In an MCP session:
   `search_notes(project="books", query=…)`. Ranked by similarity, so a hit is
   **not** a match; use it to find the chapter.
2. **Confirm with the exact index:** `~/ops/site-private/bin/book-kb query
   '<regex>' learning-cfengine` — ~0.5–5k tokens, and **this is what proves a
   term is or is not in the book.**
3. **Read the one chapter:** `~/ops/site-private/bin/book-kb toc learning-cfengine`
   (~2.5k-token index; `--deep` for `file:line` anchors), then a single chapter
   (~1.2k median).

The book covers 3.12; for anything newer (`--simulate-json`, 3.2x features, the
MPF today) say so and check the current docs at docs.cfengine.com.

Never read `~/kb/raw/learning-cfengine.md`: that is the entire book, ~115k
tokens. The index exists so you don't have to. Full detail, including how to add
a book: `site-private/AGENTS.md` ("Book knowledge base").

## Verifying policy and the CFEngine build (2026-10-29, 2026-10-31)

- `tests/policy/run.sh --bindir DIR` runs the generic bundle against a real
  `cf-agent`/`cf-promises` (Mac dev build: `~/opt/cfengine-dev/bin`); it is
  platform-independent and is the test CI runs on Linux. Run it through
  `~/ops/site-private/bin/bg`. Two checks are opt-in because they reshape the
  host and need root: `TENDCF_TEST_SYSTEMD=1` (check 6, the real-systemd
  lifecycle; the ubuntu VM jobs) and `TENDCF_TEST_NIXOS_SHAPE=1` (check 7,
  `/etc/systemd/system` as a read-only store symlink; the `debian:13` job).
- `tests/deploy/linux-install.sh` (root, ubuntu VMs) proves the root-owned
  install, root `cf-execd` and the canary end to end;
  `tests/deploy/bare-host-libs.sh` (root, `debian:13`) proves the install on a
  host with no system `librsync`/`libb2`. `deploy/linux/canary/check.py` keeps
  the canary and passthrough goal files schema-valid and their projections
  byte-identical. Never run the two root scripts on a real host.
- Linux CI (`.github/workflows/linux.yml`) builds the fork at the commit in
  `overlay/fork.json` (`--prefix=/opt/tendcf`) and runs the fork's
  unit/acceptance subsets plus the scripts above on ubuntu-24.04/26.04/24.04-arm
  and a `debian:13` container, which also uploads the pastebin artifact. Moving
  the pin is a commit. `check.yml` runs `bin/schema_lint.py`,
  `bin/xref_lint.py`, `bin/overlay.py lint`, the canary check and `shellcheck`.
- Plan and status: `docs/architecture/linux-targets.md` §3; the NixOS side in
  `docs/architecture/nixos-passthrough-plan.md`. Live hosts: pastebin (root
  install, canary enforced), get.sipb.cloud (module installed, nothing scheduled).

## Editing in a worktree: absolute paths only (2026-10-31)

A session's working directory is usually the main checkout (`~/src/tendcf`)
while the work happens in a claimed worktree (`~/src/tendcf-<name>-wt`). The
`edit`, `read` and `write` tools resolve a relative path against that working
directory, so `edit AGENTS.md` lands in the main checkout, not the worktree
(happened three times on 2026-10-31, each caught only because `git status` in
the main checkout showed the stray change). **In a worktree, give every
`edit`/`read`/`write` the worktree's absolute path**, and run `git status` in
the main checkout before reporting a worktree change done: it must be clean.
