# Slice: four cleanups on the CFEngine forks, then a refreshed `tendcf-integration`

Operator decisions, 2026-10-29 (`/steps`), after the two earlier slices (read both reports first:
`/tmp/tendcf-fork-integration/core-integration-report.md`, `/tmp/tendcf-fork-integration/fork-regressions-report.md`).
Current tips: core `tendcf-integration` `7363abf435fa9037433d1454741561b99079b3c1`, libntech `tendcf-integration`
`d379dce2cf79c4b95112cce482797e93ddcad5dc` (core submodule points at it).

## Targets

- `~/src/cfengine-core-integration-wt` (branch `tendcf-integration`, `origin` = https://github.com/djbclark/core,
  add `upstream` = https://github.com/cfengine/core if missing). Per-fix branches are checked out in this same
  worktree as needed (`git checkout <branch>`), then back to `tendcf-integration`.
- `~/src/libntech-integration-wt` only if a task below touches libntech (none should).
- Read-only: `~/src/tendcf/docs/architecture/upstream-register.md`.

Non-goals: no edits in `~/src/tendcf`; no force-push anywhere; no rebase of `tendcf-integration`; no new PRs to
cfengine/core (pushing to a branch that is already an open upstream PR head is expected and wanted for task 3).

## Tasks, in this order

1. **Fast-forward fork `master` to cfengine/core `master`.** `git fetch upstream master`, verify
   `git merge-base --is-ancestor origin/master upstream/master`, then `git push origin upstream/master:master`
   (plain push; it must be a fast-forward, if not, stop and report BLOCKED). Record old and new SHAs.

2. **Encoder decision: keep raw UTF-8, remove the dead workaround.** libntech now writes valid non-ASCII UTF-8
   verbatim (`fix/json-encode-raw-utf8`, merged into libntech `tendcf-integration`), so core's
   `RestoreUtf8InJson()` (`cf-agent/simulate_mode.c`, from branch `simulate-json-utf8`, commit `1b0fb89db`) is a
   pass-through with a stale comment. Remove the function, its call site(s) and the tests that exist only for it;
   keep any test that asserts raw UTF-8 bytes in the simulate-json document (those now pass through libntech and
   are the behaviour we want). Where: the register calls `simulate-json-utf8` the fork-only workaround branch, so
   commit the removal on `simulate-json-utf8` (it then becomes a branch whose content is only the kept tests;
   say so), push, re-merge into `tendcf-integration`. If a cleaner shape is to revert the workaround on
   `tendcf-integration` directly with a message naming the branch and the libntech fix, that is acceptable:
   record which under `DECIDED:`.

3. **Reformat the 11 files failing `cfengine format --check`, on their fix branches.** The list and their
   branches are in the regressions report OPEN 1 (keep_chroot*.cf on `simulate-keep-chroot`;
   `timeout_after_output_closed.cf` on `fix/exec-timeout-promise-outcome` / `timeout_kills_descendants.cf` on
   `fix/timeout-process-group-merged` and every later exec-timeout branch stacked on them; `null_values.cf` on
   `fix/def-json-null-crash`; `13-null-values.cf`, `13-null-values.cf.json`, `14…` on `fix/cmdb-null-value-crash`;
   the rest per that list). Install the tool the way upstream's `.github/workflows/cfengine_cli.yml` does (read it;
   it is the `cfengine` Python CLI, `pip`/`uv` install into a venv under `/tmp`, never system-wide). For each
   branch: checkout, run `cfengine format` on that branch's own files only, commit "Formatted <files> for the
   cfengine format gate", push (fast-forward; these are open upstream PR heads, updating them is intended). A
   stacked branch (`fix/exec-timeout-alarm-pid` on `-promise-outcome`, etc.) gets the fix by merging its base
   branch forward, not by a second reformat commit. Then merge every touched branch into `tendcf-integration`.
   Verify with `cfengine format --check` over the whole tree on `tendcf-integration`: zero findings.

4. **B-6 stale example output.** On `fix/eval-integral-result`: regenerate `examples/eval.cf`'s `#@` expected
   block (`examples/remake_outputs.pl`, read it first; it may need a built cf-agent, in which case edit the 12
   lines listed in the regressions report OPEN 5 by hand and say so), commit, push, re-merge into
   `tendcf-integration`.

## Prove it

Same CI loop as the regressions slice: a draft PR on djbclark/core from a throwaway branch equal to the
`tendcf-integration` tip, `→ master`, title `ci: tendcf-integration check (never merge)`. With task 3 done the
lint gate should pass and `unit_tests` run without the `needs:` bypass; if lint still fails, fix the formatting,
never bypass. Required green: `cfengine_cli / lint`, `unit_tests`, `acceptance_tests` (now with
`04_examples/outputs/check_outputs.cf` passing), `asan_unit_tests`. Close the draft PR (not merged), delete the
throwaway branch. `git ls-remote` both remotes and quote the heads.

## Report (`/tmp/tendcf-fork-integration/fork-cleanup-report.md`)

`STATUS`, `SHAS` (fork master old→new, core `tendcf-integration` new tip, libntech tip, submodule pointer, every
fix branch old→new), per task `DONE`/`WHERE`/`COMMITS`, `CI` table with the run URL, `DECIDED`, `OPEN`, then
`DONE`. Use `gsed`, never `sed`; `timeout 600` on every fetch/push; plain `git commit` with explicit paths, never
`-a`; one `make`/test run at a time through `/Users/djbclark/ops/site-private/bin/bg` if you build locally
(prefer CI).
