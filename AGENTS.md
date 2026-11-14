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
  changes in this repo go through the standing rule below (a PR with a
  cross-model frontier review); this file doesn't blanket-authorize
  pushing arbitrary work.

## Standing rule: most important work — be pedantic, pay for the best models (2026-10-31)

Native routing update: 2026-11-10 (Wave 6 A3/A4; admission limits preserved).

**Environment availability exception (operator, 2026-11-10):** requirements
below that name an agent or model unavailable in the current environment may
be overridden with an available, appropriately capable agent. This includes
the lead-model rule and the named frontier/cross-family reviewer requirement.
Use a separate reviewer with fresh context, disclose its actual model and
effort and the unavailable preferred route in the PR, and resolve findings
before merge. Do not describe a same-family review as cross-family review.
This exception does not waive review, CI, quota/headroom/reservation checks,
untrusted-input boundaries, or explicit operator approval for other actions.

djbclark, 2026-10-31: tendcf and nix2cf are the most important work he is
doing, and getting it right outranks cost. This lifts `model-routing` item 1b's
*reason* test for these two repos only: here a frontier review needs no "really
needs a frontier model" case, and a second opinion is reason enough. Every
other repo keeps the default. The mechanics stay: frontier allowance,
fresh quota readings, estimate floors and caps, headroom, per-wave limits
and in-flight reservations are not overridden. Native routing is described
in djbclark-ade's `skills/model-routing/SKILL.md`, sections D–E. Never
override a route, lower headroom, change the estimate or omit admission
checks to force a review. A printed native launch command or an
`ade.kind=frontier` label is not proof of admission. If the current native
path cannot preserve these checks, hold the review and report the missing check.

1. **Be pedantic.** Re-read what you changed. Verify every claim by running it,
   never by recall. Read the plan or spec section before changing what it
   describes. When in doubt, look it up (the CFEngine book, upstream source,
   the host itself) instead of assuming. Take the slower path. Never narrow
   scope or call something verified that you did not run, and say what you did
   not check.
2. **Models.** Every lead session runs Opus 5.5 `high`, pipeline-only sessions
   (merges, waiters) included; `[lead].pipeline_model` does not apply here.
   Never Sonnet as a lead, and Fable is never a lead. Code slices run on
   Sonnet 5.5 `high` or better (the antigravity provider's Opus pool is fine) on whichever pool
   `route_agent.py plan` picks, through `/bigteam`. Never use a weaker tier
   (GLM, Gemini Flash, Cursor Auto, `gpt-6-luna`) in these repos. A slice
   climbs a tier only on evidence of failure.
3. **Review is cross-model, never same-model.** An Opus review of Opus work is
   one model with a fresh context, not an independent check. No PR merges on a
   review by the model family that wrote the change. For Opus- or
   Sonnet-authored work, astra, Fable or Argon count; for a Codex-authored
   slice, Fable or Argon count.
   - Every PR, docs-only included (this rule's own PR was reviewed this way),
     gets one frontier review before merge. `docs/handoffs/` commits are not
     PRs and keep the push-in-place exception above. Try the reviewers in this
     order:
     1. Astra: Codex provider, `gpt-6-astra`, `high`.
     2. Fable: Claude provider, its current Fable frontier model, `high`.
     3. Gemini 4 Argon: Antigravity provider, `gemini-4-argon`, `high`.
        Argon is fallback-only when Astra or Fable is short. Require a fresh
        reading for its Google AI Pro subscription pool; an API entitlement is
        not a substitute.

     Plan each review with
     `~/src/djbclark-ade/bin/route_agent.py plan --kinds frontier --repo tendcf --json`.
     Keep the reviewer order and model-family independence above; a non-frontier model
     cannot satisfy this rule. Re-plan immediately before admission and launch.
     Record the reason `tendcf standing rule: cross-model review` in the brief
     and admission evidence.

     Use the current ADE review launch path after admission. Preserve the
     enforced `bin/review-launch` boundary when reviewing untrusted external
     input; do not replace it with an unrestricted invocation. Trusted own-agent
     work follows ADE's ordinary permission policy. For reviews relying on
     instructions rather than tool restrictions, direct the reviewer to change
     nothing and compare worktree status and diff before and after; do not claim
     that this is an enforced read-only sandbox.

     Native Paseo launches use the admitted provider/model and `--thinking high`,
     carry `ade.kind=frontier`, `ade.name`, `ade.lead` and `ade.task` labels,
     and use the explicit workspace and cwd verified under ADE's orchestration
     practices. Include the delivery footer in the positional brief. Do not
     translate retired launcher flags into unsupported native flags.
   - A pool is short when a fresh quota reading marks it unusable, the intended
     reviewer does not fit every relevant window with the required headroom,
     or admission refuses it for concurrency, reservation or preflight reasons.
     Missing or stale readings do not establish availability. Move to the next
     eligible reviewer and report the reason; never force admission.

     Read `aiuse --available --json` first, `paseo usage ls --json` second, and
     inspect the fresh planner's structured result. A Paseo report whose status
     is not `available` is unknown. Planner output is not proof that a subsequent
     launch passed admission; native commands do not inherit the old dispatcher's
     exit-code or dry-run contract. Preserve admission and actual launch results.

     **Astra's fallback estimate
     floor and estimate cap in these two repos are 20 percentage points**
     (djbclark, 2026-11-01). The `codex:frontier` estimate uses comparable
     measured history. The configured fallback floor applies separately when
     the scalar or a quota window has fewer than three comparable measurements;
     three measurements overall do not release every window's floor.
     In tendcf and nix2cf the fallback floor is 20, and the resulting scalar
     and per-window estimates are also capped at 20: a measured median of 70
     becomes 20, while a median of 2 from sufficient history stays 2.
     This is not a permanent minimum of 20% quota remaining; headroom, fit,
     in-flight reservation and the other dispatch checks still apply.
     The override is configured in djbclark-ade's `config/routing.toml` at
     `[dispatch.repo_overrides.<repo>.estimate_floor]`, selected explicitly with
     `plan --repo tendcf`. Every other repository keeps
     the configured 60-point `codex:frontier` fallback floor, which sufficient
     comparable history can replace. On 2026-10-31 a lead treated the 60% fallback as a
     permanent minimum and declared astra short at 45% remaining. That
     comparison alone did not establish that astra was short. Only fresh quota, fit and admission
     evidence establish availability.
   - Design rulings (a `schema_version` bump, the privilege or enforcement
     scope on a host, a deploy plan, the unit-writer or consent-diff design)
     get two independent frontier reviews, astra and Fable. Argon stands in
     for one of them and never counts twice. With both astra and Fable short,
     take the Argon review now and wait for a reset for the second. A
     disagreement goes to djbclark, not to the lead to settle.
   - If all three are short, wait for the reset. Never merge on a weaker
     review, and never substitute an Opus review. A GitHub app review (for
     example the chatgpt-codex-connector bot) is not the frontier review.
   - The additional adversary round still runs where the current ADE workflow
     calls for it, using an eligible judgment route. It never counts as the
     cross-model frontier review and must not revive the retired omp client.
   - The PR body names each reviewer model and effort, quotes the verdict (or
     "no findings") and lists what was fixed.
4. **Limits that still hold.** Preserve the effective frontier allowance
   and per-wave caps from ADE's `config/gates.toml [frontier]`, estimate
   floors/caps, headroom and in-flight reservation accounting. The 20-point
   Astra estimate override is not a permanent minimum quota balance and
   waives no other check. Fable remains advisory; execution or elevated
   effort requires the operator approvals prescribed by ADE. No Fable
   `xhigh`/`max` without djbclark's approval. At most one Astra slice at a time.

   Native `route_agent.py plan` checks fit against the remaining reading
   but does not subtract sibling in-flight reservations. Re-planning alone
   does not restore that protection. Until native reservation admission is
   verified, serialize launches only when one coordinator can establish
   exclusive control of the pool, account for every existing consumer, and
   retain the reservation through completion and refreshed usage
   reconciliation. If that cannot be proven, hold the review; do not launch
   unguarded or revive retired tools. Missing admission parity remains a
   blocker to operational migration completion.
5. **Gemini 4 Carbon** (announced 2026-10-28, availability unverified here):
   recheck weekly with `paseo provider models antigravity` and
   `aiuse --available --json`. Adopt it as the Google frontier model only
   after confirming the intended subscription pool, native routing and
   admission checks.

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
  the test CI runs on Linux. The policy-layer assertions (the cross-check's
  refusal, no actuation) run against any `cf-agent`. The assertions about the
  CMDB loader itself (its log strings, "this container was not installed")
  hold only for the pinned fork's all-or-nothing loader: a probe in check 4b
  decides once, and on any other build (the Mac dev build today) those
  assertions print `SKIP (loader not all-or-nothing): <name>`, never pass
  silently. The Linux CI legs set `TENDCF_REQUIRE_FORK_LOADER=1`, which makes
  a skip a failure. Whether the Mac dev build stays a test target is an open
  operator question. Run it through
  `~/ops/site-private/bin/bg`. Two checks are opt-in because they reshape the
  host and need root: `TENDCF_TEST_SYSTEMD=1` (check 6, the real-systemd
  lifecycle; the ubuntu VM jobs) and `TENDCF_TEST_NIXOS_SHAPE=1` (check 7,
  `/etc/systemd/system` as a read-only store symlink; the `debian:13` job).
- An ad-hoc `cf-agent` run needs `tests/policy/run.sh`'s scratch workdir
  (`CFENGINE_TEST_OVERRIDE_WORKDIR`, `ppkeys` from `cf-key`, `bin/` links to
  `cf-*`). Without it, an unprivileged agent uses `~/.cfagent`, cannot
  pre-validate, and runs the built-in failsafe (2026-11-02).
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
