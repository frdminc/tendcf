# Slice: fix three unit-test regressions on `tendcf-integration` (djbclark/core)

## Context

`tendcf-integration` was refreshed today (report: `/tmp/tendcf-fork-integration/core-integration-report.md`, read its
SHAS, CONFLICTS and OPEN sections first). tendcf's Linux CI (https://github.com/frdminc/tendcf/pull/6, run
https://github.com/frdminc/tendcf/actions/runs/40862772751) built core `9fdf67cecf4e15bbb91801cc7fc9bee25897bf65`
(libntech `d379dce2cf79c4b95112cce482797e93ddcad5dc` via the submodule) on ubuntu-24.04, ubuntu-26.04,
ubuntu-24.04-arm and debian:13. Build and install pass everywhere. `make -C tests/unit check` fails identically on all
four:

1. `rlist_test`: `test_from_container_numbers` → `ERROR: rlist_test.c:1014 Failure!`. Line 1014 is the `fail()`
   inside the file's `JsonArrayCreate()` stub; the test (B-10 core half, `fix/json-number-rendering`) builds its input
   with `JsonParse`, which needs the real `JsonArrayCreate`. Find out whether the stub was added upstream after the fix
   branch was cut, or whether the branch itself never ran this test under `make check` (look at upstream PR
   https://github.com/cfengine/core/pull/6314 CI, and `git log -S'JsonArrayCreate' tests/unit/rlist_test.c`).
2. `mustache_test`: `test_spec` → `Testing sections:Implicit Iterator - Decimal ...FAIL` (spec: list `[1.10, 2.20,
   3.30, 4.40, 5.50]` renders `(1.1)(2.2)(3.3)(4.4)(5.5)`). libntech on this branch preserves a real's parsed lexeme
   (B-4/B-10/B-11, `fix/json-number-handling`), so `1.10` renders as `1.10`. This is a semantic conflict between
   lexeme preservation and the mustache spec's number normalisation. Establish how upstream passes it today and
   whether `fix/json-number-rendering` + `fix/json-number-handling` ever passed `mustache_test` together (CI of
   https://github.com/cfengine/core/pull/6314 and https://github.com/NorthernTechHQ/libntech/pull/294). Decide the
   smallest correct resolution and record it under `DECIDED:` with the reasoning: the lexeme guarantee is a documented
   fork property (`~/src/tendcf/docs/architecture/upstream-register.md` rows B-4, B-10, B-11), so do not silently drop
   it; a mustache-side normalisation of a real's lexeme only where the spec requires it, or an adjusted spec
   expectation with the register's rationale, are both candidates. If the two cannot both hold, make the first line
   `BLOCKED:` with the one-line question.
3. `timeout_test`: `test_pclose_leaves_the_alarm_its_process` → `ERROR: timeout_test.c:149 Failure!`
   (`assert_true(TimeOutHasFired())` false after `cf_pclose()` on a child doing `exec sleep 30` with a 2 s alarm).
   This is B-17/B-19 (`fix/exec-timeout-alarm-leak`, upstream https://github.com/cfengine/core/pull/6312, 6310) on
   top of B-2/B-8 (`fix/timeout-process-group-merged`), hand-merged in `libpromises/timeout.c`, `timeout.h`,
   `libpromises/pipes_unix.c`, `tests/unit/timeout_test.c` (report CONFLICTS). Diff the integration tree against each
   branch tip for those files (`git diff fix/exec-timeout-alarm-leak -- libpromises/timeout.c libpromises/pipes_unix.c
   libpromises/unix.c cf-agent/verify_exec.c`) and find which hunk the merge lost or reordered. Upstream's CI on
   #6312 shows whether the test passed on the branch alone.

## Targets

- `~/src/cfengine-core-integration-wt` (branch `tendcf-integration`, remote `origin` = https://github.com/djbclark/core).
- `~/src/libntech-integration-wt` (branch `tendcf-integration`, remote `fork` = https://github.com/djbclark/libntech),
  only if the mustache resolution lands in libntech; then bump core's submodule pointer in a commit as before.
- Read-only: `~/src/tendcf/docs/architecture/upstream-register.md`.

Non-goals: no new features, no edits in `~/src/tendcf`, no force-push, no rebase of `tendcf-integration`, no PRs to
cfengine/core or NorthernTechHQ.

## Where fixes go

The register's rule ("never develop on the integration branch; cherry-pick onto a clean per-fix branch") applies to
fixes that belong to a fix: if a failure is the fix branch's own defect (its test cannot run under `make check`, its
code is wrong), commit the fix on that per-fix branch (`fix/json-number-rendering`, `fix/exec-timeout-alarm-leak`,
libntech `fix/json-number-handling`), push it, and merge the branch into `tendcf-integration` again. If a failure is
a merge artefact (a hunk lost between two branches), fix it directly on `tendcf-integration` in a commit whose message
names both branches. Say which in the report, per failure.

## Linux test loop (you cannot run Linux locally)

Open a DRAFT pull request on the fork, `tendcf-integration` → `master` of https://github.com/djbclark/core, title
`ci: tendcf-integration check (never merge)`. The fork's `.github/workflows/ci.yml` runs on `pull_request` to
`master` and calls `unit_tests.yml`, then `asan_unit_tests.yml` and `acceptance_tests.yml`. Every push to
`tendcf-integration` re-runs it. Read results with `gh pr checks <n> --repo djbclark/core` and
`gh run view <id> --repo djbclark/core --log-failed`. Close (do not merge) that PR when done, and say so. If libntech
needs the same loop, the same trick on https://github.com/djbclark/libntech (`tendcf-integration` → `master`).

A Mac build through `/Users/djbclark/ops/site-private/bin/bg` is allowed only for a quick local reproduction of
failures 1 and 2 (platform-independent) if the CI round trip is too slow; record the CI decision first
(`~/src/djbclark-ade/bin/load-watch ci decide <worktree> local "<why>"`), `make -j2`, and run only the failing test
binary (`make -C tests/unit rlist_test && tests/unit/rlist_test`), never the whole suite. Failure 3 is Linux-specific
in effect (process-group/alarm paths differ on Darwin): CI only.

## Done means

`unit_tests` green on the fork's draft-PR CI for the final `tendcf-integration` tip; `asan_unit_tests` and
`acceptance_tests` results reported (fix if the failure is in B-5a/B-5b CMDB, simulate mode or exec_timeout areas,
otherwise report under OPEN). Both remotes fast-forwarded. Report: `STATUS`, `SHAS` (new core tip, libntech tip if
moved, submodule pointer), per failure `ROOT CAUSE` / `FIX` (commit, branch) / `WHERE` (per-fix branch or
integration), `DECIDED`, `OPEN`, `DONE`. Use `gsed`, never `sed`; `timeout 600` on every fetch/push; plain
`git commit` with explicit paths, never `-a`.
