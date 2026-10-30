STATUS: quiesced (operator-requested stop while CI was still running) — tasks 1–4 DONE, pushed (fast-forward) and merged into `tendcf-integration` `022be6ea4`; CI proof PARTIAL: lint + unit_tests + asan_unit_tests green, acceptance_tests still running at quiesce; draft PR #53 left OPEN (never merge)

# Fork cleanups + refreshed `tendcf-integration` — djbclark/core (2026-10-29)

## SHAS

| what | old → new |
|---|---|
| fork `master` (fast-forward to cfengine/core master) | `9118740ceea049ed0c68c33f1873fdbcb3df9b0e` → `b0f6da2dde82bc9cf350f89753b4661ac1c1f1b9` |
| core `tendcf-integration` (fast-forward push) | `7363abf435fa9037433d1454741561b99079b3c1` → `022be6ea49c5e5d31fe3696c00daa6a045d34ec3` |
| libntech `tendcf-integration` (not moved) | `d379dce2cf79c4b95112cce482797e93ddcad5dc` |
| core `libntech` submodule pointer (unchanged) | `d379dce2cf79c4b95112cce482797e93ddcad5dc` |
| `simulate-json-utf8` | `1b0fb89db` → `fba51cbbb3925d81c5e1bd1f8199e8bba76799f1` |
| `simulate-keep-chroot` | `f6c06f9e2` → `c614e4bb058ff667a0743967e7320bec7a3b4958` |
| `fix/exec-timeout-promise-outcome` (unchanged, see DECIDED 2) | `0ab083c4d1c5f34e71626c58c886c1974bb26500` |
| `fix/timeout-process-group-merged` | `0e06ad3d7` → `8800efc6c57d861f8c70272bb6c500dc441f3467` |
| `fix/exec-timeout-alarm-pid` | `8f4ebedbd` → `9d7d9848f72d46560ee338b18e9d8a47616a1693` |
| `fix/exec-timeout-alarm-leak` | `453cc264d` → `57d213cb144f1421a995d619cc750ae65652f407` |
| `fix/exec-timeout-prefork-race` | `ab98a5df4` → `03bc56e12288cf7533d2f3f4c9084800b76def98` |
| `fix/def-json-null-crash` | `dd917f09d` → `4fedc88ad48145e20bf11b429468afd7b102bed1` |
| `fix/cmdb-null-value-crash` | `87490bb8f` → `71d2de1d61cb1b9add68735fc7b46e31a083e3b9` |
| `fix/cmdb-dotted-key-warning` | `ee1f9d60c` → `7cccb1398554db101ff7f1824935747d1c43234e` |
| `fix/cmdb-name-offending-key` | `958d13949` → `5d739ff76c577da918eb5f22375f36f62bfca38a` |
| `fix/cmdb-one-bad-entry-skips-only-that-entry` | `8f0076b81` → `4b9571ca4a6b4d66bfcf2f0f897ac4c35e359951` |
| `fix/eval-integral-result` | `b74e8f4cf` → `e6cab364d29aaf8118326f4b9a6b2bd0fd8d99f3` |

All pushes were plain fast-forwards (`git push origin <branch>`); no force, no rebase of `tendcf-integration`.

## Task 1 — fast-forward fork `master`

DONE. `git fetch upstream master` (upstream/master `4eae47542..b0f6da2dd`), `git merge-base --is-ancestor origin/master upstream/master` → true, `git push origin upstream/master:master` → `9118740ce..b0f6da2dd`.
WHERE: `origin/master` only. COMMITS: none authored.

## Task 2 — remove dead `RestoreUtf8InJson()`

DONE. `cf-agent/simulate_mode.c` restored to its pre-`1b0fb89db` shape: `ValidUtf8SequenceLength()`, `GetJsonEscapedByte()`, `RestoreUtf8InJson()` and the `escaped`/`document` call site in `WriteChangesJson()` removed (−191 lines, +1); the document is `StringWriterClose(writer)` straight from `JsonWrite()` again. `ggrep RestoreUtf8InJson` over the tree (excluding libntech) → nothing.
Tests kept in `tests/unit/simulate_mode_test.c`: `read_output_file_raw()`, `test_special_characters_in_path()` (asserts raw `w\xC3\xA9ird` bytes and no `\u00c3` in the file) and `test_invalid_utf8_in_path()` (asserts a lone `\xE9` stays `\u00e9`). Both assert the document's bytes, which libntech's `JsonEncodeStringWriter()` (`fix/json-encode-raw-utf8`: valid UTF-8 verbatim, control chars and invalid bytes escaped; libntech `libutils/json.c` ~L1172–1187) now produces, so they pin the wanted behaviour at this call site. Their comments name no function and needed no change.
WHERE: committed on `simulate-json-utf8` (`fba51cbbb`), which is now a branch whose content over `simulate-json` (`d5cc2c4e0`) is only the two kept unit tests + helper. Merged into `tendcf-integration` as `a142037f2`; one merge conflict in `simulate_mode.c` (the removed block sat between later package-ops code) resolved by keeping the integration side minus the three functions. Call-site check on the tip: `JsonWrite(writer, json, 0); WriterWrite(writer, "\n"); JsonDestroy(json); char *document = StringWriterClose(writer);`.
COMMITS: `fba51cbbb` (branch), `a142037f2` (merge).

## Task 3 — `cfengine format` on the 11 files

DONE. Tool: `python3 -m venv /tmp/tendcf-fork-integration/cfengine-venv && pip install cfengine` → CFEngine CLI 0.23.3 (upstream's workflow does `pipx install cfengine`; same package, venv under /tmp, nothing system-wide). Baseline `cfengine format --check` on `tendcf-integration` listed exactly the 11 files from the regressions report OPEN 1.
Per branch (`cfengine format <that branch's files>`, commit "Formatted <files> for the cfengine format gate", push):
- `simulate-keep-chroot` `c614e4bb0`: `keep_chroot.cf`, `keep_chroot_parent_perms.cf`, `keep_chroot_path_limits.cf`, `keep_chroot_perms.cf` (4 files, +131/−67).
- `fix/timeout-process-group-merged` `8800efc6c`: `timeout_kills_descendants.cf`.
- `fix/exec-timeout-alarm-pid`: `76485d653` merge of `fix/timeout-process-group-merged` (comment-only conflict in `libpromises/timeout.c`, resolved to the wording `tendcf-integration` already carries), then `9d7d9848f`: `timeout_after_output_closed.cf` (see DECIDED 2: the misformat was introduced by this branch's `8f4ebedbd`, not by `fix/exec-timeout-promise-outcome`).
- `fix/exec-timeout-alarm-leak` `57d213cb1`: merge of `fix/exec-timeout-alarm-pid` forward (clean).
- `fix/exec-timeout-prefork-race` `03bc56e12`: merge of `fix/timeout-process-group-merged` forward (two comment-only conflicts in `libpromises/timeout.h`, resolved to the integration wording; `timeout.h` now identical to the integration tip).
- `fix/def-json-null-crash` `4fedc88ad`: `null_values.cf`.
- `fix/cmdb-null-value-crash` `71d2de1d6`: `13-null-values.cf`, `13-null-values.cf.json`.
- `fix/cmdb-dotted-key-warning` `7cccb1398`: `14-dotted-keys.cf.json` (B-7 lives here, not on a "B-7" branch).
- `fix/cmdb-name-offending-key` `5d739ff76`: `15-variable-references-metadata-format.cf.json` (B-5a's file was added by this branch's `958d13949`).
- `fix/cmdb-one-bad-entry-skips-only-that-entry` `4b9571ca4`: merge of `fix/cmdb-name-offending-key` forward (clean).
Every stacked branch got the fix by merging its base forward; no second reformat commit anywhere. `fix/exec-timeout-promise-outcome` was checked out and `cfengine format` run on `timeout_after_output_closed.cf`: no diff, so no commit (its version of the file is already clean).
Merged into `tendcf-integration`: `59031faf4`, `733731d6e`, `30bbd93e2`, `58f1bd651`, `efb7365a5`, `3a1313973`, `4163fc6cc`, `112900708`, `5c6ed7ba7`, `84e81dcd3` (`fix/exec-timeout-promise-outcome`: already up to date).
VERIFY: `cfengine format --check` over the whole tree on the `tendcf-integration` tip → no output, rc=0.

## Task 4 — B-6 stale `examples/eval.cf` output

DONE. `examples/remake_outputs.pl` runs each example through `--cfagent` (default `../cf-agent/cf-agent`), which does not exist here (no local build; brief prefers CI), so the 12 `#@ R: math/infix eval(...)` lines (file lines 55, 56, 58, 59, 61, 64, 66, 67, 69, 70, 73, 74) were edited by hand: `'N.000000'` → `'N'` (`300, 100, 4, 0, 27, 2, 4, 3, 1, 0, 100000000, 100000`); `'inf'`, `'3.400000'`, `sin/cos/sqrt/e/pi` lines untouched, matching the branch's own `tests/acceptance/01_vars/02_functions/eval.cf` expectations.
WHERE: `fix/eval-integral-result` `e6cab364d`, merged into `tendcf-integration` as `022be6ea4` (the tip).
COMMITS: `e6cab364d`, `022be6ea4`.

## CI

Draft PR djbclark/core#53 (`ci/tendcf-integration-check` → `master`, title "ci: tendcf-integration check (never merge)"), head `8997e1d192d363b2e5ae880ad118502021dba784` = `tendcf-integration` `022be6ea4` + empty commit `e42a1c2bb` + one ci.yml commit `8997e1d19` adding `push: branches: [ci/tendcf-integration-check]` (`git diff tendcf-integration ci/tendcf-integration-check --stat` = `.github/workflows/ci.yml | 4 +`). Run: https://github.com/djbclark/core/actions/runs/40887013480 (event `push`). The `pull_request` event never produced a run (see DECIDED 7). **PR #53 is still OPEN and must be closed, not merged** (`gh pr close 53 --repo djbclark/core --delete-branch`) once the run is read.

State at quiesce (~19 min into the run):

| job | result |
|---|---|
| `cfengine_cli / lint` (`cfengine lint` + `cfengine format --check`) | **success** — the format gate passes, so `unit_tests` ran without any `needs:` bypass |
| `unit_tests / Run Unit Tests` | **success** |
| `shellcheck_tests` | success |
| `valgrind_check` | failure — expected on a `push` event: `job-valgrind-check.yml` checks out masterfiles at `github.base_ref || github.ref`, which on push is `ci/tendcf-integration-check` (not in the required set); unrelated to the tree |
| `asan_unit_tests` | **success** (read from a late-arriving status poll after quiesce) |
| `acceptance_tests` | in_progress at quiesce — NOT READ (expected to clear `04_examples/outputs/check_outputs.cf` via task 4) |
| `static_check` | success |
| `macos_unit_tests` | queued at quiesce — NOT READ |

Next command to finish the proof: `gh run view 40887013480 --repo djbclark/core --json status,conclusion,jobs --jq '.status, .conclusion, (.jobs[] | "\(.name) | \(.status) | \(.conclusion)")'`; then `gh pr close 53 --repo djbclark/core --delete-branch`; then `timeout 600 git ls-remote origin | ggrep -E 'tendcf-integration|ci/'` to confirm the throwaway branch is gone.

Remote heads (`git ls-remote origin`, after all pushes): `master` `b0f6da2dd…`, `tendcf-integration` `022be6ea4…`, `simulate-json-utf8` `fba51cbbb…`, `simulate-keep-chroot` `c614e4bb0…`, `fix/exec-timeout-promise-outcome` `0ab083c4d…` (unchanged), `fix/timeout-process-group-merged` `8800efc6c…`, `fix/exec-timeout-alarm-pid` `9d7d9848f…`, `fix/exec-timeout-alarm-leak` `57d213cb1…`, `fix/exec-timeout-prefork-race` `03bc56e12…`, `fix/def-json-null-crash` `4fedc88ad…`, `fix/cmdb-null-value-crash` `71d2de1d6…`, `fix/cmdb-dotted-key-warning` `7cccb1398…`, `fix/cmdb-name-offending-key` `5d739ff76…`, `fix/cmdb-one-bad-entry-skips-only-that-entry` `4b9571ca4…`, `fix/eval-integral-result` `e6cab364d…`, `ci/tendcf-integration-check` `8997e1d19…` (to delete). libntech `fork` `refs/heads/tendcf-integration` = `d379dce2cf79c4b95112cce482797e93ddcad5dc` (unchanged). Full SHAs in the SHAS table. Core worktree: back on `tendcf-integration`, clean, submodule at `d379dce2`. Inbox file never appeared.

## DECIDED

1. Task 2 shape: removal committed on `simulate-json-utf8` (the register's fork-only workaround branch), not as a revert on `tendcf-integration`; the branch now carries only the kept unit tests over `simulate-json`. Both UTF-8 tests kept (the brief's "raw UTF-8 bytes" test, and the invalid-byte test too, since libntech escapes invalid bytes the same way and the test asserts the document, not the removed function).
2. `timeout_after_output_closed.cf`: the brief placed its reformat on `fix/exec-timeout-promise-outcome`, but that branch's version is already clean (`cfengine format` produced no diff there); the misformat came in with `8f4ebedbd` on `fix/exec-timeout-alarm-pid`, so the reformat commit is on `fix/exec-timeout-alarm-pid` (after merging `fix/timeout-process-group-merged` forward for `timeout_kills_descendants.cf`). `fix/exec-timeout-promise-outcome` unchanged.
3. Forward-merge conflicts (`timeout.c` on alarm-pid, `timeout.h` on prefork-race) were comment-only (process-group-merged's "Terser comments" `0e06ad3d7` vs. the stacked branches' longer comments); resolved to the exact wording `tendcf-integration` already has, so the merges into integration were clean and the integration tree's C code is unchanged by task 3.
4. Task 4 by hand edit, not `remake_outputs.pl` (needs a built cf-agent); recorded in the commit message.
5. `pip` venv under `/tmp/tendcf-fork-integration/cfengine-venv` instead of `pipx`: same `cfengine` PyPI package upstream's workflow installs; nothing touched outside `/tmp`.
6. libntech untouched (no commit/push); submodule pointer unchanged.
7. CI trigger: after task 1 the fork's `master` is 100 commits ahead of where `tendcf-integration` branched, and `tendcf-integration` is `CONFLICTING` with it (`cf-agent/simulate_mode.c`: upstream merged `eb6cf5f04`, `e55f9d8fe`, `8d6bc9ceb` simulate-diff fixes). GitHub creates no merge commit for a conflicting PR, so the `pull_request` event ran nothing on #53 (verified: no `github-actions` check suite on `022be6ea4`; close/reopen and an empty-commit push `e42a1c2bb` changed nothing). Rather than merge `master` into `tendcf-integration` (an integration job of its own, out of this slice's scope) or rewrite anything, the throwaway branch got one ci.yml commit adding a `push:` trigger for itself — same shape as the previous slice's one-commit ci.yml deviation — so the tree under test is the integration tip exactly (plus ci.yml). The draft PR exists as the brief asks but the run is the push run. Main was messaged with this at the time.

## OPEN

1. **`tendcf-integration` conflicts with the fast-forwarded fork `master`** (`cf-agent/simulate_mode.c`; 100 upstream commits `9118740ce..b0f6da2dd`, 179 files). Every fork fix branch is still based on `9118740ce`. A decision is needed on merging `master` forward into `tendcf-integration` (and when to rebase/retarget the per-fix branches onto the new master); until then no `pull_request`-triggered CI can run on an integration draft PR, only the push-trigger workaround (DECIDED 7).
2. CI proof incomplete at quiesce: `acceptance_tests` was still in progress (asan green) on run 40887013480; draft PR #53 OPEN with throwaway branch `ci/tendcf-integration-check` present. Commands under CI.
3. `valgrind_check` fails on a push-event run by construction (masterfiles ref); not in the required set, irrelevant to the tree.
4. Register wording: `fix/exec-timeout-alarm-pid` (not `fix/exec-timeout-promise-outcome`) is where `timeout_after_output_closed.cf` was last edited and reformatted (DECIDED 2); `14-dotted-keys.cf.json` is on `fix/cmdb-dotted-key-warning`, `15-…json` on `fix/cmdb-name-offending-key`.
5. `simulate-json-utf8` is now a tests-only branch over `simulate-json` (DECIDED 1); the register's description of it as the UTF-8 workaround branch is stale.
6. Earlier reports' OPEN items on encoder semantics are resolved by this slice (raw UTF-8 kept via libntech, workaround removed); fork `master` is no longer at `9118740ce`.

DONE
