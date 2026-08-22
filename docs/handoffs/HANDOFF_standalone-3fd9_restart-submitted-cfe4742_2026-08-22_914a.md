---
schema_version: 1
handoff_id: 914a
parent_handoff_ids: [9796]
lineage: deterministic
chain: [standalone-3fd9]
repo: tendcf
workspace: main
branch: master
head_sha: 86d9fc6fc7e85c3270ffc723b50e306b0fd54bcb
created_at: 2026-08-22T19:50:41-0400
writer: claude-code
---
# Handoff — Restart executed: CFE-4742 filed, cfengine/core#6332 open

## The Goal

Execute the upstream restart per olehermanse's closure protocol (core#6293
comment: ONE bug ticket + ONE small PR, human in the loop): implement PR1 =
the MapRemove-after-NULL bug in simulate mode, prove it on Linux as well as
macOS (new hard gate), and get it in front of upstream. Strategic stakes
(operator, verbatim intent): the restart exists to eventually land
`--simulate-json`; if that is permanently rejected, fork-only + cut comms.

## Where We Are

**The submission is COMPLETE and live. The ball is in upstream's court.**

- Upstream PR: https://github.com/cfengine/core/pull/6332 — one commit
  `5ddb6d97b` on upstream master `b14a380d0`, title
  `CFE-4742: Fixed simulate mode reporting both removal and install of the same package`.
- Jira ticket: https://northerntech.atlassian.net/browse/CFE-4742 (Bug,
  Open), filed via the operator's account (sudo-secretspec-brokered token,
  create permission verified via createmeta first). Description carries the
  operator's dictated disclosure: reviewed the fix's logic with AI guidance,
  saw no issues, but ~3 decades since C and cannot vouch for the code itself;
  correctness case = discriminating regression test + CI; if unacceptable,
  stopping there is fine.
- The fix: in `cf-agent/simulate_mode.c`, both `DiffPkgOperations()` and
  `ManifestPkgOperations()` called the cancellation
  `MapRemove(removed/absent, name_arch)` AFTER `MapInsert()` + `name_arch =
  NULL` (map takes key ownership), so cancellation no-ops exactly when an
  install message was inserted. Verified in libntech: release = silent no-op
  (`StringSafeCompare` treats NULL ≠ everything), debug = `assert(str !=
  NULL)` abort in `StringHash()` once the map leaves array stage. Fix =
  hoist the MapRemove above the insert block (6 lines moved per function).
- Regression test `tests/unit/simulate_mode_test.c` (+ 3-line Makefile.am
  hookup): writes `r,foo,,\r\n` + `i,foo,1.2.3,\r\n` to the chroot pkgs_ops
  file, captures stdout via dup2, asserts install line present AND removal
  line absent. Discrimination proven fail-before/pass-after on macOS arm64,
  Ubuntu 24.04 arm64 (dash) container, x86_64 CI — library rebuilt between
  runs each time.
- Fork records: bug issue djbclark/core#24; fork PR djbclark/core#25 (open
  as CI-evidence anchor, annotated with the upstream submission); three-zoom
  writeup #26 (upstream-terse / normal / ELI5-auditable + Status section).
- Fork CI: **first-ever runs** — Actions had never actually been enabled
  (0 registered workflows despite enabled permissions); the fork-repo
  "enable workflows" UI button was clicked this session (core by me via
  browser, libntech by the operator). All 8 workflows green twice: run
  32602383710 (pre-rebase 33f0d2b56) and 32603359614 (rebased 9ee0d1bfc).
  A third run (32606149163) covers the trailer-stamped 5ddb6d97b
  (code-identical to green 9ee0d1bfc) — assumed green, verify if paranoid.
- Both fork masters fast-forward-synced to upstream via
  `gh api -X POST repos/<fork>/merge-upstream -f branch=master`.
- djbclark/core#23 rewritten as the upstream-facing consolidated
  judgment-call ticket: 9 questions, most-useful-answer-first, I/II/III
  multiple choice (`1: III` / `4c: I` notation), codec cluster contiguous at
  1–3, defect batch as 4a–4f. Old comments deleted; internal tracking
  (sequencing, A1 resubmission checklist, test rig, grouping plan) in the
  single surviving comment.
- Register updated and pushed: tendcf@86d9fc6 ("RESTART EXECUTED
  2026-08-22" section at top).

## What We Tried

Chronological, failures included:

1. **Feature-first restart (rejected before this handoff's window, context
   carried):** leading with --simulate-json fails the maintainer's ask
   (bug-first in every sentence; the only 2 Won't Do of 26 were the
   features; the feature PR was +1549/−37). PR1 = bug extraction instead.
2. **Cherry-picking the fix from feature commit b3a6c3da5 directly — not
   possible**: entangled with a PkgOperationRecord→PkgOperation refactor.
   Re-extracted by hand against master's types.
3. **Container test run 1 failed** — script fetched the branch but
   `git fetch origin <branch>` doesn't create a local ref; checkout failed
   and it silently built master (`set -uxo` without `-e` let it continue).
   Fix: `git checkout -B <branch> FETCH_HEAD || exit 1`.
4. **Fork CI "discovered enabled" was FALSE** — earlier session read
   `{"enabled":true}` from the permissions API, but 0 workflows were
   registered and 0 runs had ever happened. The fork-disabled state is a
   separate UI-only button. Do not trust the permissions endpoint alone.
5. **PR opened before workflows enabled → no CI trigger.** Fix: enable,
   then close/reopen the PR to re-fire the pull_request event.
6. **Browser ref-click (`ref_227`) didn't register** on the enable button;
   coordinate click at (699,489) worked. Verify state after clicking, not
   after the call returns.
7. **Upstream-rebase container run failed on submodule fetch**: git's
   recursive submodule fetch chased gitlink 54e12b54 which exists on NO
   remote (unreachable historical commit). Fix:
   `git fetch --no-recurse-submodules` then `git submodule update --init
   libntech`. Also required syncing fork libntech master first (upstream
   had bumped libntech to 3c214791).
8. **grep-filtered container output came back empty** (failure happened
   before any pattern matched) — always tail the raw log too.

## Key Decisions

- **PR1 = MapRemove bug** (small, pre-existing, shipped code, clean
  reproduce + before/after story, keeps simulate as the thread). Rejected:
  feature-first (above); bundling other simulate defects (bite-sized rule).
- **One branch, one commit**: force-pushed the upstream-rebased commit onto
  `fix/simulate-pkg-mapremove` so fork PR #25, its CI, and upstream #6332
  all point at identical code. Rejected: parallel `-upstream` branch (two
  names for one change = confusion).
- **Commit trailer flow**: committed with `Ticket: None`, amended to
  `Ticket: CFE-4742` after filing, force-pushed. Title/body/trailers follow
  the upstream-cfengine-commit-style memory exactly.
- **Disclosure honesty over boilerplate**: the PR does NOT carry the stock
  "reviewed and verified by me" line — it says the operator reviewed the
  logic with AI guidance and cannot vouch for the C, deferring to
  test+CI. Operator dictated this; ticket carries the full version
  including the "10 more IQ points"/sysadmin history.
- **simulate-json question deliberately NOT raised in #6332** — the probe
  ("was CFE-4716's Won't Do a content judgment or volume reset?") comes as
  a short question AFTER the PR is reviewed. This is the operator's
  go/no-go signal for everything.
- **#23 is upstream-directed again** (operator): it is the consolidated
  judgment-call ticket we OFFERED upstream (question 2 of "the questions",
  unanswered — an offer we made, not something they requested). Delivered
  after #6332 resolves. A1 recast as resolved-context crediting the
  maintainer's spot-check as correct.
- **No adversarial panel was run on PR1** — decision by momentum, not
  explicit ruling: the evidence is mechanical (test flip on 3 platforms)
  rather than interpretive claims like A1. If upstream challenges anything
  substantive, panel it before replying (upstream-email-wait-for-full-panel
  memory applies to claims).

## Evidence & Data

- Commits: fork-based fix 33f0d2b56 → rebased 9ee0d1bfc → trailer-stamped
  5ddb6d97b (upstream master parent b14a380d0). tendcf register commit
  86d9fc6.
- CI: djbclark/core runs 32602383710 (success, all 8), 32603359614
  (success, all 8), 32606149163 (running at handoff time, code-identical).
- Jira: CFE-4742 created HTTP 201, description PUT 204, anonymous GET
  renders. Auth = Basic `djbclark@gmail.com` + `ATLASSIAN_CFENGINE_API_TOKEN`
  via `sudo-secretspec run --reason "..." -- sh -c '...'` (never echo).
  Create permission proven via `/rest/api/2/issue/createmeta?projectKeys=CFE`
  (types include Bug; `/rest/api/2/` accepts wiki-markup descriptions).
- Container rig: image `cfengine-build:u24`; scripts in session scratchpad
  `linuxgate/` (pr1_test.sh, pr1_upstream_test.sh — scratchpad is
  session-lived; the recipe survives in memory `linux-gate-before-upstream`
  and #23's internal-notes comment).
- libntech verification anchors: `ArrayMapRemove` → `StringEqual` →
  `StringSafeCompare` (NULL-safe not-equal); `StringHash` asserts non-NULL;
  `JsonDecodeStringWriter` default case passes unknown escapes through
  (verified before asserting in #23 question 2b).
- ELI5 calibration datum: operator answered "Not sure" to all four C-quiz
  questions (pointer identity, ownership-after-insert, NULL compare,
  assert-in-release) — #26 section 3 assumes zero C; reuse that register
  for future ELI5 writing.

## Operator Feedback

- Get to the simulate-json answer ASAP; permanent rejection ⇒ fork-only +
  cut comms (memory: simulate-json-is-the-point).
- Linux testing is a HARD gate before anything upstream (memory:
  linux-gate-before-upstream).
- Three-zoom-level issue format (#26) explicitly requested; ELI5 must let a
  non-C human find holes in the logic; quiz-first calibration welcomed.
- #23: no history, current-state only, upstream-facing, terse, whitespace,
  multiple-choice notation; ordering = most-useful-answer first; codec
  cluster (1–3) kept contiguous.
- The disclosure text in CFE-4742 was dictated by the operator — do not
  soften or "improve" it in future references.
- Operator pressed the libntech enable-workflows button personally; offered
  to click UI buttons when automation fights.

## Where We're Going

1. **WAIT for upstream reaction to cfengine/core#6332 / CFE-4742.** Next
   session: check `gh pr view 6332 --repo cfengine/core --json state,comments,reviews`
   and the ticket. Do NOT comment, do NOT push more commits, do NOT open
   anything else upstream meanwhile. If upstream CI fails on their side,
   diagnose and report to operator before acting.
2. If a maintainer reviews (any outcome): report to operator, then — per
   plan — the operator asks the short simulate-json probe question (was
   CFE-4716's Won't Do content or volume? would a --simulate-json surface
   proposal be welcome in principle?). Answer decides: continue upstream vs
   fork-only + cut comms.
3. After #6332 resolves: operator intends to offer #23 (consolidated
   judgment calls, now answer-ready with I/II/III notation) to upstream.
4. Housekeeping available any time: verify run 32606149163 finished green;
   remove stray `simulate_mode_test.xml` in ~/src/cfengine-core (untracked
   test artifact).

## Quick Start

```bash
# state of the submission
gh pr view 6332 --repo cfengine/core --json state,reviews,comments,statusCheckRollup | head -50
curl -s "https://northerntech.atlassian.net/rest/api/2/issue/CFE-4742?fields=status,comment" | python3 -m json.tool | head -40

# fork evidence anchors
gh pr view 25 --repo djbclark/core --json state
gh run list --repo djbclark/core --branch fix/simulate-pkg-mapremove --limit 3

# local branch (fix + test), based on upstream master
cd ~/src/cfengine-core && git log --oneline -3 fix/simulate-pkg-mapremove

# rebuild + rerun the discriminating test locally (macOS)
cd ~/src/cfengine-core && make -C cf-agent -j8 && make -C tests/unit simulate_mode_test && tests/unit/simulate_mode_test
```

Tests run this session: simulate_mode_test — pass with fix / fail without,
on macOS, Ubuntu 24.04 container, and x86_64 CI (all 8 upstream workflows
green twice). No other test suites run locally; CI covered the full suite.
