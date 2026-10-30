STATUS: done — all three unit-test regressions fixed; `unit_tests` green on the fork CI for the reported core tip; one unrelated acceptance failure (B-6 fixture) reported under OPEN

# tendcf-integration unit-test regressions — djbclark/core (2026-10-29)

## SHAS

| what | sha |
|---|---|
| core `tendcf-integration` tip (pushed, fast-forward `9fdf67cec..7363abf43`) | `7363abf435fa9037433d1454741561b99079b3c1` |
| core `fix/json-number-rendering` tip (pushed, fast-forward `13fff92dc..928c1c20f`) | `928c1c20f078bfe7e911c87d3897e9b0309f9aa6` |
| libntech `tendcf-integration` tip (not moved) | `d379dce2cf79c4b95112cce482797e93ddcad5dc` |
| core `libntech` submodule pointer (unchanged) | `d379dce2cf79c4b95112cce482797e93ddcad5dc` |
| throwaway CI branch `ci/tendcf-integration-check` (= integration tip + one `ci.yml` commit; deleted at the end) | `d2855fe6342f7c14f90f9b72211b37002a7a4bb9` |

## Failure 1 — `rlist_test: test_from_container_numbers` (`rlist_test.c:1014`)

ROOT CAUSE: the fix branch's own defect. `tests/unit/rlist_test.c` has carried `fail()` stubs for `JsonArrayCreate()`, `JsonObjectCreate()`, `JsonStringCreate()` and five `Json*Append*()` constructors since `857fefd83` (2012-02-13, "Stub out Json functions in Rlist test"); nothing added them later (`git log -S'JsonArrayCreate' tests/unit/rlist_test.c` shows only that commit). `libpromises.la` is a shared library (`projlib_LTLIBRARIES`), so the executable's stubs interpose over libutils' definitions and `JsonParse()` — which B-10's `test_from_container_numbers()` (13fff92dc) uses to build its input — lands in the `JsonArrayCreate()` stub. The branch was never run under a Linux `make check`: upstream PR cfengine/core#6314 has no workflow run at all (only `license/cla`; `check-runs` total 0 on 13fff92dc), the fork has no PR/run for the branch, and `rlist_test` is in `XFAIL_TESTS` on macOS (`tests/unit/Makefile.am` `if MACOSX`), where the test was written, so its failure there was expected and invisible.

FIX: `d6bf01788` "Let rlist_test use the real JSON constructors" — removes the eight JSON stubs (40 lines); the real libutils functions are used; no test relied on the stubs failing (`FnCallToJson` stub left: `rlist.c`'s is `static`).

WHERE: per-fix branch `fix/json-number-rendering` (pushed), merged into `tendcf-integration` as `3e522cfb4`.

## Failure 2 — `mustache_test: test_spec` "Implicit Iterator - Decimal"

ROOT CAUSE: semantic conflict, the number stack's own defect (core half never updated the fixture that pins the old renderer). Facts: the official mustache spec (`mustache/spec` `sections.yml`) has data `[1.10, 2.20, 3.30, 4.40, 5.50]` → `"(1.1)(2.2)(3.3)(4.4)(5.5)"`. Core's copy `tests/unit/data/mustache_sections.json` (imported `899be2478`, 2013-08-26, unchanged since except formatting) has data `[1.1, 2.2, 3.3, 4.4, 5.5]` and expectation `"(1.10)(2.20)(3.30)(4.40)(5.50)"` — i.e. the importer rewrote both sides to what `StringFromDouble()`'s `"%.2f"` produces (the interpolation fixture was rewritten the other way: data `1.210` → `1.21`). Upstream "passes" the spec only because the fixture encodes the `%.2f` artefact that B-4 removes (`0.00049` → `0.00`, register row B-4 "including through mustache templating"). With libntech `fix/json-number-handling` (`mustache.c` `RenderVariablePrimitive()` appends the parsed lexeme), `1.1` renders as `1.1`, so the fixture fails. The two fixes never ran together under this test: libntech's own `mustache_test.c` (B-22) does not run the spec fixtures (no `test_spec`, no `TESTDATADIR` use; data files only exist in core's test), NorthernTechHQ/libntech#294 and cfengine/core#6314 both have zero workflow runs, and core's branch still pins stock libntech `0c0620d`.

FIX: `928c1c20f` "Expect reals to render as parsed in the mustache sections spec" — expectation changed to `"(1.1)(2.2)(3.3)(4.4)(5.5)"` (the official spec's expected string), data unchanged. No code change in either repo; libntech not touched; submodule pointer unchanged.

WHERE: per-fix branch `fix/json-number-rendering` (B-4/B-10 core half; register says B-4 is "not independently landable"), merged into `tendcf-integration` in the same merge `3e522cfb4`. Note: the branch standing alone (stock libntech pointer) now renders `1.10` and fails this case until its submodule is bumped to the libntech half — the same coupling the register already documents for the reals fix; the upstream PR for the core half must carry a libntech bump.

## Failure 3 — `timeout_test: test_pclose_leaves_the_alarm_its_process` (`timeout_test.c:149`)

ROOT CAUSE: merge artefact between `fix/exec-timeout-alarm-leak` (B-17/B-19, CFE-4727/CFE-4735) and `fix/exec-timeout-prefork-race` (B-18, CFE-4734). Diffed the integration tree against both tips for `libpromises/timeout.c`, `timeout.h`, `pipes_unix.c`, `unix.c`, `cf-agent/verify_exec.c`: every code hunk of both branches is present (alarm-leak's `ClearAlarmedPid()`/`ALARM_PID = -1` after reap/`ClearTimeOut()` on the early return; prefork-race's `TIMEOUT_PENDING`, deferred `alarm()`, `StartTimeOutClock()` called from `GenericCreatePipeAndFork()` after `ALARM_PID` is published); the diffs are comment wording only. What was lost is a *test contract*: B-18 makes `SetTimeOut()` leave the clock stopped (non-MinGW) and updated every test on its base (`dbf759d16`) to call `StartTimeOutClock()` by hand. It was cut before alarm-leak added `test_pclose_leaves_the_alarm_its_process()`, which forks first, then `SetTimeOut(2); ALARM_PID = child;` and relies on `SetTimeOut()` having started the alarm. Merged, no alarm is ever started, `cf_pclose()` waits out the 30 s sleep, `TimeOutHasFired()` is false. Upstream #6312/#6310 have no CI runs (0 check-runs on 453cc264d), so "passed on the branch alone" is by construction only: on the alarm-leak tip `SetTimeOut()` still calls `alarm()` directly.

FIX: `7363abf43` "timeout_test: start the deferred clock in the CFE-4727 pclose test" — adds `StartTimeOutClock();` after `ALARM_PID = child;` (cf_popen()'s order, same as the sibling `test_clear_preserves_a_true_signalled_flag()`), comment updated. `test_leftover_alarm_does_not_kill_next_child()` (CFE-4735) still discriminates under B-18 and was left alone: with its `ClearTimeOut()` removed, the decoy's `cf_popen_sh()` would start the leftover 2 s budget and fire against the decoy.

WHERE: directly on `tendcf-integration`; commit message names both branches.

## CI

Fork draft PR djbclark/core#52 (`ci/tendcf-integration-check` → `master`, title "ci: tendcf-integration check (never merge)"), run https://github.com/djbclark/core/actions/runs/40864874497 on `d2855fe63` = `tendcf-integration` `7363abf43` + ci.yml ungate (DECIDED 3). Closed, not merged, branch deleted (`gh pr close 52 --delete-branch`); earlier #51 (from `tendcf-integration` itself, unit_tests skipped by the lint gate) closed with a comment. No open PR with a tendcf head remains.

| job | result | evidence |
|---|---|---|
| `unit_tests / Run Unit Tests` (ubuntu-24.04, `make -C tests/unit check`) | **success** | `All 79 tests passed`; `PASS: rlist_test` (`test_from_container_numbers: Test completed successfully`), `PASS: mustache_test` (`Testing sections:Implicit Iterator - Decimal ...OK`), `PASS: timeout_test` (`test_pclose_leaves_the_alarm_its_process: Test completed successfully`) — log saved `/tmp/tendcf-fork-integration/unit-123416979568.log` |
| `asan_unit_tests` | success | — |
| `macos_unit_tests` | success | — |
| `valgrind_check`, `static_check`, `shellcheck_tests` | success | — |
| `cfengine_cli / lint` | failure | `cfengine format --check`: the same 11 pre-existing files as on #51 (OPEN 1); none of this slice's files are flagged (`/tmp/tendcf-fork-integration/lint-123416979882.log`) |
| `acceptance_tests` | **failure: 1 unexpected** | `Passed 1674, Failed 1, Skipped 349, Soft failures 39`. The one failure is `04_examples/outputs/check_outputs.cf`: `examples/eval.cf`'s `#@` expected-output block still shows `'300.000000'`, `'27.000000'`, … while B-6 (`fix/eval-integral-result`, b74e8f4cf) makes `eval()` print `'300'`, `'27'` — the branch updated `tests/acceptance/01_vars/02_functions/eval.cf` and the unit test but not the example's expected output. Not in the B-5a/B-5b CMDB, simulate-mode or exec_timeout areas, so reported under OPEN, not fixed. Areas the brief named: `29_simulate_mode/*` 9/9 Pass (incl. `keep_chroot*`, `simulate_json`, `diff_mode`), `00_basics/06_host_specific_data/*` all Pass, `08_commands/04_exec_timeout/*` all Pass, `00_basics/def.json/*` Pass except the upstream soft-fail `augments_classes.cf` (CFE-2956). Log `/tmp/tendcf-fork-integration/acc-123418630425.log`. |

Both remotes: `git ls-remote` after the pushes — core `refs/heads/tendcf-integration` = `7363abf43…`, `refs/heads/fix/json-number-rendering` = `928c1c20f…`, `ci/tendcf-integration-check` gone; libntech `fork` `refs/heads/tendcf-integration` = `d379dce2…` (unchanged). Both worktrees `git status` clean, core worktree back on `tendcf-integration`, submodule at `d379dce2`.

Inbox `/tmp/tendcf-fork-integration/fork-regressions-report.md.inbox.md` never appeared.

## DECIDED

1. Mustache decimal case (failure 2): resolved by adjusting the core spec fixture's expectation, not by normalising a real's lexeme in `mustache.c`. Reasoning: (a) the lexeme guarantee is the documented fork property (register rows B-4, B-10, B-11: render/copy the number as parsed; B-4 explicitly names mustache); (b) the official spec's expected string for this case is exactly `(1.1)(2.2)(3.3)(4.4)(5.5)`, and with the fixture's 2013 data `[1.1, 2.2, …]` the lexeme renderer produces precisely that, so the two hold together — only the `%.2f` artefact `(1.10)` had to go; (c) a mustache-side trailing-zero strip would make `1.10` in a user's JSON render as `1.1`, i.e. drop the lexeme for one output path only, contradicting B-4's own statement and the register, and would need a hand-written float normaliser (exponents, `-0.0`, …) for a case that no real policy depends on. Residual divergence from the *official* spec data (`1.10` → `1.1`) is pre-existing (the importer already changed the data) and is the documented fork position: a real renders as written. The data was deliberately left as `[1.1, …]` rather than restored to the spec's `[1.10, …]`, which would have forced the normaliser.
2. Both json fixes live on `fix/json-number-rendering` (own defects of the number stack), failure 3 on `tendcf-integration` (merge artefact), per the brief's rule. Consequence recorded above: `fix/json-number-rendering` standing alone with stock libntech now fails the decimal case; its upstream PR must bump the libntech submodule to #294's head, which the register already requires for the reals half.
3. CI mechanics: the fork's `ci.yml` gates `unit_tests` on `cfengine_cli/lint`, and `cfengine format --check` fails on 11 policy/JSON files from merged fix branches (list under OPEN), so a draft PR from `tendcf-integration` itself (opened as djbclark/core#51) ran only lint+shellcheck and *skipped* `unit_tests`. #51 was closed with a comment and replaced by a draft PR from a throwaway branch `ci/tendcf-integration-check` = `tendcf-integration` tip + one commit `d2855fe63` deleting the `needs: cfengine_cli` line (djbclark/core#52). The tree under test differs from the integration tip only in `.github/workflows/ci.yml` (`git diff tendcf-integration ci/tendcf-integration-check --stat` = that one file, 1 deletion). `tendcf-integration` itself was not touched for CI; the throwaway branch is deleted at the end. No force-push anywhere.
4. No local Mac build: the CI round trip for `unit_tests` was ~4 min from push, so no `load-watch ci decide` record was needed.
5. libntech untouched (no commit, no push, no PR on djbclark/libntech); submodule pointer unchanged.

## OPEN

1. **Fork/upstream lint gate (not one of the three failures, not fixed):** `cfengine format --check` (upstream gate since `46c9f1116`/`32c45af82`, 2026-07) reports "needs reformatting" for: `tests/acceptance/29_simulate_mode/keep_chroot.cf`, `keep_chroot_parent_perms.cf`, `keep_chroot_path_limits.cf`, `keep_chroot_perms.cf` (P-1 `simulate-keep-chroot`, f6c06f9e2); `tests/acceptance/08_commands/04_exec_timeout/timeout_after_output_closed.cf` (B-8 0ab083c4d), `timeout_kills_descendants.cf` (B-2 3d8e90d68) — both in `fix/timeout-process-group-merged` and every later exec-timeout branch; `tests/acceptance/00_basics/def.json/null_values.cf` (B-21 dd917f09d); `tests/acceptance/00_basics/06_host_specific_data/13-null-values.cf`, `13-null-values.cf.json` (B-20), `14-dotted-keys.cf.json` (B-7), `15-variable-references-metadata-format.cf.json` (B-5a). Each belongs to a per-fix branch and would fail upstream's PR CI too; needs `cfengine format` on each branch and a re-merge. Until then any draft PR from `tendcf-integration` skips `unit_tests`.
2. `fix/json-number-rendering` alone pins stock libntech `0c0620d`; with `928c1c20f` its own `mustache_test` fails the decimal case until the submodule is bumped (see DECIDED 2).
3. `tests/unit/rlist_test.c` keeps a dead `FnCallToJson()` stub (rlist.c's is `static`); harmless, left as upstream has it.
4. The previous report's OPEN items (encoder semantics, fork `master` at 9118740ce, dead `RestoreUtf8InJson()`) are unchanged.
5. **Acceptance `04_examples/outputs/check_outputs.cf` fails (B-6's own defect):** `examples/eval.cf` lines 55–74 (`#@ R: math/infix eval(...)` block) still expect `'300.000000'`, `'100.000000'`, `'4.000000'`, `'0.000000'`, `'27.000000'`, `'2.000000'`, `'4.000000'` (ceil), `'3.000000'` (floor), `'1.000000'`, `'0.000000'` (the two `==`), `'100000000.000000'`, `'100000.000000'`; B-6 now prints `'300'`, `'100'`, `'4'`, `'0'`, `'27'`, `'2'`, `'4'`, `'3'`, `'1'`, `'0'`, `'100000000'`, `'100000'` (non-integral results such as `abs(-3.4)` = `'3.400000'` are unchanged). Fix belongs on `fix/eval-integral-result` (`examples/remake_outputs.pl` regenerates the block, or edit those 12 lines), then re-merge; the upstream PR for B-6 would fail the same acceptance job. The tendcf CI run in the brief never reached acceptance (it ran only `make -C tests/unit check`), so this was not visible there.

DONE
