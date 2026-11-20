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
  cross-model review whose depth is tiered by what the change can break;
  rule 3); this file doesn't blanket-authorize pushing arbitrary work.

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
3. **Review is cross-model, never same-model, and its depth is tiered by what
   the change can break.** An Opus review of Opus work is
   one model with a fresh context, not an independent check. No PR merges on a
   review by the model family that wrote the change. For Opus- or
   Sonnet-authored work, astra, Fable or Argon count; for a Codex-authored
   slice, Fable or Argon count. Operator ruling, 2026-11-14, B10: "1. Spike
   lane, 2. Tiered review, 3. Docs freeze" (options O1, O2 and O4). **O6 was
   not chosen** and O5 (dogfood the gate) was not asked; neither is in force.
   - **Tiered review (O2).** Operator ruling, 2026-11-14, B10 (record line
     L22): O2 is "tiered review (light for docs and spike notes, one frontier
     review for device code, two for root/trust-root/key/handshake code)".
     **Light** review for docs and spike notes; **one frontier review** for
     device code; **two frontier reviews** for root, trust-root, key and
     handshake code (the two are the independent astra-and-Fable pair
     described under design rulings below). This supersedes the earlier text
     "Every PR, docs-only included, gets one frontier review before merge"
     (this rule's own first PR was reviewed that way).
     Who may perform a light review: "2. Cheaper reviewer allowed" (operator
     ruling, 2026-11-14, PR 62 review Q2; record line L58): any model outside
     the author's family that is not on the weaker-tier ban list in rule 2
     (GLM, Gemini Flash, Cursor Auto, `gpt-6-luna`) may perform a light
     review; if the reviewer is a frontier model, the frontier checks (the
     frontier allowance, fresh quota readings, estimate floors and caps,
     reservation and admission) still apply to that launch.
     Lead and reviewer reading of Q2, **not part of the ruling**: the
     cross-model rule above is what says which families are "outside the
     author's family", and it implies that Opus and Sonnet are one family
     (an Opus review of Sonnet work, or the reverse, is not outside it),
     while Fable, astra and Argon count as outside it for Opus- or
     Sonnet-authored work. "Light" changes the depth and scope of the review.
     It does **not** waive model routing, quota readings, reservation or
     admission rules.
     **Lead notes in force until the operator rules otherwise.** The three
     notes below (the light-docs limits, the spike-workflow hardening worded
     under the spike lane, and the compiler, CI and tooling tier) are lead and
     reviewer text that is not part of the O1, O2 or Q2 rulings (except that
     limit (a)'s widening below is L64's own wording). They are "in force as
     lead practice until djbclark rules otherwise" (operator ruling,
     2026-11-14, PR 62 round-2 review, L64: "1. In force + widen"). Where this
     file says "not part of the ruling", that means the text is not the
     operator's wording; it does not mean the text is not in force. That
     sentence covers only these three notes and the readings this file labels
     as readings (the Q2 family reading above, and Android item 5), all of
     which only tighten. Those two readings are in force as lead practice, on
     the lead's authority; L64 covers only the three notes. A reading that
     loosens a rule needs an operator ruling; it is not in force on this
     file's say-so.
     1. **Four limits on what counts as "light docs"** (limit (a)'s widening is
        the operator's own L64 wording; limits (b) to (d) are lead practice, in
        force per L64). (a) Not light (operator ruling, 2026-11-14, PR 62
        round-2 review, L64): **every edit to this file, in any section**, and
        every doc that defines or instructs privileged, trust, consent, key,
        deploy or enforcement behaviour (an open "including ..." list, not a
        closed one). Such an edit takes **at least one frontier review, and two
        if the PR changes a design ruling** (the design-ruling tier below). L64
        names no files; the lead's current examples are the architecture map's
        trust, consent and privilege sections,
        `docs/architecture/change-process.md`,
        `docs/architecture/linux-targets.md` section 3,
        `docs/architecture/nixos-passthrough-plan.md` and
        `docs/architecture/tendcf-validate-proposal-2026-11-03.md`. (b) A PR that carries a design
        ruling takes the design-ruling tier below. (c) A mixed PR takes its
        highest tier. (d) Policy run by a root `cf-execd` counts as root code.
     2. **Spike workflow hardening** (lead practice, in force per L64): see the
        spike lane below.
     3. **Compiler, CI or tooling PRs keep one frontier review** (lead practice,
        in force per L64; the operator was not asked this sub-question when
        ruling O2). A PR that is neither docs, a spike note nor device code
        (compiler, CI or tooling, say) keeps the one frontier review this rule
        required of every PR before 2026-11-14.
   - **Spike lane (O1).** A `spike/*` branch is never merged, so it gets no
     frontier review. Each spike runs on a real, non-production device and
     leaves a one-page note, which is reviewed under the light tier. What a
     spike proves is then built in a normal PR that takes its own tier.
     Safety rails, word for word from the option the operator chose (O1,
     `docs/review-2026-11-13/13-premortem-and-ideas.md` X-pm-07): "a spike
     never runs as root on the daily-driver Mac and never on pastebin. It runs
     only on a test phone, a spare Mac or VM, or as an unprivileged user. It
     touches no real secrets and no keys used elsewhere."
     Hardening added by the lead and reviewers on PR 62, **not part of the
     operator's ruling O1**, and "in force as lead practice until djbclark
     rules otherwise" (operator ruling, 2026-11-14, PR 62 round-2 review, L64):
     a spike workflow runs with `permissions: contents: read` and no secrets.
   - **Docs freeze (O4).** No new design doc is written for a state-1 piece
     until a spike for that piece has run.
     Clarified and given a sunset: "1. Clarify + sunset" (operator ruling,
     2026-11-20, O4 docs-freeze chooser; the operator first said "Lets
     discuss the docs-freeze rule in general. It still being in place may be
     a bug."). The chosen option's text, word for word: "Keep O4, but schema
     files, fixtures, errata and operator-ordered design reviews (like Q4)
     are not frozen. The freeze lifts per piece once a spike has run or you
     order a design review. Issue 64 then proceeds as a schema PR plus
     errata." Items 1 to 3 are the lead's wording of that option, not the
     operator's words:
     1. **Not frozen:** files under `schema/`, `examples/` and test fixture
        directories, and errata items in existing docs, none of which is a
        design doc; and a design review the operator orders, with what it
        reviews (like Q4, record line L60: issue 64 proceeds as a schema
        PR plus errata, the option's words).
     2. **Sunset, per piece:** the freeze on a piece lifts once a spike for
        it has run or the operator orders a design review for it.
     3. **Unchanged:** the review tier for whatever is written (O2 with its
        limits (a) to (d), and the design-ruling tier below), and the intent
        of O4 (`docs/review-2026-11-13/13-premortem-and-ideas.md` A(i) items
        1 and 8).
     Lead reading, not part of the ruling (it only tightens): "orders" means
     an operator ruling that names the review, quoted and dated; the standing
     design-ruling tier below is not an order, and neither is a request from
     a lead, a reviewer or an issue. A lift by order covers what that review
     is ordered to decide, no wider. A spike "has run" when it ran under the
     spike lane above and its one-page note is merged. A new design section
     in an existing doc counts as a new design doc. The PR that relies on a
     lift cites the note or the ruling. Prefer errata and schema over new
     prose.
   - A PR that needs a frontier review gets it before merge. `docs/handoffs/`
     commits are not PRs and keep the push-in-place exception above. Try the
     reviewers in this order:
     1. Astra: Codex provider, `gpt-6-astra`, `high`.
     2. Fable: Claude provider, its current Fable frontier model, `high`.
     3. Gemini 4 Argon: Antigravity provider, `gemini-4-argon`, `high`.
        Argon is fallback-only when Astra or Fable is short. Require a fresh
        reading for its Google AI Pro subscription pool; an API entitlement is
        not a substitute.

     Plan each review with
     `~/src/djbclark-ade/bin/route_agent.py plan --kinds frontier --repo tendcf --json`.
     Keep the reviewer order and model-family independence above; a non-frontier model
     cannot satisfy a frontier review (it may do a light one, above). Re-plan immediately before admission and launch.
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
     scope on a host, a deploy plan, the unit-writer or consent-diff design),
     and root, trust-root, key and handshake code (O2, above), get two
     independent frontier reviews, astra and Fable. Argon stands in
     for one of them and never counts twice. With both astra and Fable short,
     take the Argon review now and wait for a reset for the second. A
     disagreement goes to djbclark, not to the lead to settle.
   - If all three are short, wait for the reset. Never merge on a weaker
     review, and never substitute an Opus review. A GitHub app review (for
     example the chatgpt-codex-connector bot) is not the frontier review.
   - The additional adversary round still runs where the current ADE workflow
     calls for it, using an eligible judgment route. It never counts as the
     cross-model frontier review and must not revive the retired omp client.
   - The PR body names each reviewer model and effort (for a light review,
     the reviewer and the tier), quotes the verdict (or "no findings") and
     lists what was fixed.
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
  the test CI runs on Linux. Policy-layer assertions that hold on any loader
  (most of the file) run against any `cf-agent`. Two kinds hold only with the
  pinned fork's all-or-nothing, strict-parse loader: loader assertions (its log
  strings, "this container was not installed") and loader+policy integration
  assertions (9b: the cross-check's refusal and no actuation for a repeated
  member, a repeated `vars`, trailing input; a lenient loader and the lenient
  `readjson` see the same surviving data, so there is nothing to refuse). A
  probe in check 4b decides once; on any other build each of those prints
  `SKIP (loader not all-or-nothing): <name>`, never passes silently, and the
  run is expected to pass with SKIP lines and a count (not yet run on the Mac:
  derived from the parser behaviour). The Mac dev build stays a target
  (operator ruling, 2026-11-14, B11 round 2 item 2, adversary D1 / Astra r2 B3:
  "1. Keep Mac, SKIPs"). The Linux CI legs set
  `TENDCF_REQUIRE_FORK_LOADER=1`, which makes a skip a failure. Follow-up of the
  same ruling: assertions that hold only with the strict loader (the
  `strict_case` policy refusals) are gated the same way, so a non-fork run
  passes with SKIPs rather than failing (implemented in the base: the
  `strict_case` calls with POLICY `fork` go through `fork_only` in
  `tests/policy/run.sh`). Run it through
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
  and a `debian:13` container, which also uploads the pastebin artifact. The
  `overlay-build` job builds upstream at the overlay bases plus `overlay/`
  (the all-or-nothing loader and the strict parse; `upstream-overlay.md` §4,
  §7) and runs `cmdb_test`, libntech's `json_test`/`mustache_test`, the
  `06_host_specific_data` acceptance directory and `run.sh` with
  `TENDCF_REQUIRE_FORK_LOADER=1` on it. Moving the pin is a commit. `check.yml` runs `bin/schema_lint.py`,
  `bin/xref_lint.py`, `bin/overlay.py lint`, the canary check and `shellcheck`.
- Plan and status: `docs/architecture/linux-targets.md` §3; the NixOS side in
  `docs/architecture/nixos-passthrough-plan.md`. Live hosts: pastebin (root
  install, canary enforced), get.sipb.cloud (module installed, nothing scheduled).
- **macOS check 8 of PR 52 (gate 2) ran on WarpBuild (historical gate).**
  Operator ruling, 2026-11-14, PR 52 gate 2: "let's finish the codewarp setup
  and then try running on their fastest mac setup". `frdminc/tendcf` is added
  to WarpBuild runner group 1 (the app already sees all repos); the spike
  branch `spike/macos-check8-warp` builds the fork pin on
  `warp-macos-26-arm64-12x` and runs `tests/policy/run.sh` (worker 68cf038a).
  The ruling's original gate text was: "Merge of PR 52 waits on that run."
  Outcome, 2026-11-14: the run ("macOS check 8 spike (WarpBuild)", branch
  `spike/macos-check8-warp` at 299f219, [run
  43602684071](https://github.com/frdminc/tendcf/actions/runs/43602684071))
  completed with conclusion success, and PR 52 merged at 2026-11-14T14:29:23Z
  (merge 2c78680). Like every spike branch (rule 3, spike lane) the branch is
  never merged.
- **PR 52 follow-ups: three issues and one tracker.** Operator ruling,
  2026-11-14, PR 52 follow-ups 1-8: "1. 3 issues + 1 tracker". Filed the same
  day, each linking PR 52: item 2 (install data skips the projector) is
  [frdminc/tendcf#53](https://github.com/frdminc/tendcf/issues/53), item 3
  (projector filter scope) is
  [frdminc/tendcf#54](https://github.com/frdminc/tendcf/issues/54), item 4 (re
  `$` before a trailing newline) is
  [frdminc/tendcf#55](https://github.com/frdminc/tendcf/issues/55), and the
  tracker, with checkboxes for items 1 and 5-8, is
  [frdminc/tendcf#56](https://github.com/frdminc/tendcf/issues/56).

## Android work: ShizukuTendCF builds (2026-11-14)

Operator ruling, 2026-11-14, Smaller 1 (ShizukuTendCF fleet-signer override,
C-android-03): "2. Dev mode + separate dev build" (the operator first asked
"Is there a way we could make this of equal high convienience to everyone?
Maybe have a development mode and/or build?").

1. **Every build has a developer mode, open to any owner:** an owner-enrolled
   standing approval for a signer of the owner's choice (the B2 mechanism);
   revoke and deny are always honoured; a persistent indicator shows the mode
   is on.
2. **A separate developer build** exists for tendcf contributors' test
   devices. It keeps the ignore-revoke override. It is never the published
   public build.
3. **Build only the appropriate flavour.** Operator ruling, 2026-11-14,
   Smaller 1 rider: "We don't have to always do both builds when in
   development, just the modt [sic] appropriate one for any given situation."
   A development task builds and tests only the flavour that fits it (the
   public build with developer mode, or the dev build), not both every time.
4. **Reading of the ruling, not new policy (adversary review of PR 62, finding
   5):** nothing in the ruling yet keeps the ignore-revoke dev build from
   shipping as the published build. A distinct `applicationId`, a distinct
   signing key, and a release pipeline that refuses the dev flavour are
   **recommended follow-ups, not ruled**.
5. **A reading of the ruling (L5, B2), not part of it (adversary review of PR
   62, finding 4; wording: lead decision, PR 62 review), updated for the
   operator rulings of 2026-11-19 below (issue 64):** every standing mode that
   applies a change without a per-change yes (hold window, standing approval)
   drops only the per-change nonce (DC-2's device nonce); its enrollment is
   signed by an owner-held trusted key, and each change it covers is signed by
   a signer the enrollment names; it keeps B1's other content checks (signed by
   trusted keys, fresh, names this device) and the rest of DC-2 (per-target
   validity, monotonic-counter single use or high-water mark, persisted
   rejects, which win over any grant); its ceremony class is still checked
   against the validator's derived requirement (§9.8); every standing mode
   (hold window, standing approval, standing "wait for user", standing
   refusal) is owner-enrolled and refusable, and none is a default; dropping
   any other check needs an operator ruling. Operator rulings, 2026-11-19
   (issue 64 choosers): "3. Include all classes" (a standing mode may cover
   `ordinary`, `privileged` and `baseline` changes, each class enrolled
   separately and explicitly); "1. Reusable grant (Recommended)" (one grant
   covers many changes, with persistent per-device replay state for each
   application: reusable, never replayable); "1. Owner-enrolled trusted
   signers (Recommended)" (outside developer mode the owner may enroll any
   explicitly trusted signer within a stated scope, automation and
   organisational signers included); "1. Bind both fields (Recommended)"
   (X-trust-06 adopted: `signer` and `sig_alg` are in the signed bytes, must
   match the actual verification, and cannot create trust or enable an
   unapproved algorithm). The shape is approval-record schema v7
   (`schema/approval-record.schema.json`; the goal-file family moves to v7
   together, PR 62 review Q4).

## Licensing: the review TUI is AGPL-3.0-only (2026-11-14)

Operator ruling, 2026-11-14, B12: "2. Borrow both freely; raise Python" (first:
"I am thinking 2, May 26th isn't that long ago, but see if there are any
important ignored issues or other traffic in the repos. AGPL is a fine license
for us, as long as it doesn't prevent us from using any other code we need.").

1. Toad and textual-diff-view (AGPL-3.0) may be borrowed as needed. The review
   TUI becomes **AGPL-3.0-only** and moves to **Python >=3.14** (Toad's floor;
   Toad pins `textual==8.2.7`).
2. **Keep licences that AGPL-3.0 cannot combine with out of the TUI module**:
   GPL-2.0-only, CDDL, EPL-2.0 without a secondary-licence designation, and
   proprietary code. Nothing tendcf uses today is affected (the licence
   research note, which is not in this repository, found no security or
   licence red flags).
3. Follow-ups: check that Python >=3.14 is available on Termux and on the Mac.

## Editing in a worktree: absolute paths only (2026-10-31)

A session's working directory is usually the main checkout (`~/src/tendcf`)
while the work happens in a claimed worktree (`~/src/tendcf-<name>-wt`). The
`edit`, `read` and `write` tools resolve a relative path against that working
directory, so `edit AGENTS.md` lands in the main checkout, not the worktree
(happened three times on 2026-10-31, each caught only because `git status` in
the main checkout showed the stray change). **In a worktree, give every
`edit`/`read`/`write` the worktree's absolute path**, and run `git status` in
the main checkout before reporting a worktree change done: it must be clean.
