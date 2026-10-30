STATUS: done

# tendcf-integration refresh — djbclark/core + djbclark/libntech (2026-10-29)

## SHAS

| what | sha |
|---|---|
| core `tendcf-integration` tip (pushed, `origin/tendcf-integration`) | `9fdf67cecf4e15bbb91801cc7fc9bee25897bf65` |
| libntech `tendcf-integration` tip (pushed, `fork/tendcf-integration`, branch newly created) | `d379dce2cf79c4b95112cce482797e93ddcad5dc` |
| core `libntech` submodule pointer (commit `9fdf67cec` "libntech: tendcf-integration d379dce…") | `d379dce2cf79c4b95112cce482797e93ddcad5dc` |
| core fork `origin/master` (merged first, commit `d43a4bc23`) | `9118740ceea0` (2026-09-29) |
| core effective upstream base after the merges | `4eae47542` (cfengine/core master 2026-10-20, carried in by `fix/simulate-pkg-unversioned-install-assert`; `fix/default-route-lowest-metric-v2` and the simulate series were cut from 10-07/10-09 upstream, all ancestors of it) |
| libntech `fork/master` == NorthernTechHQ `origin/master` == core master's old pin | `3c2147919c60` (2026-08-20) — no regression possible, no NorthernTechHQ merge needed |
| old core `tendcf-integration` (fast-forwarded, not force-pushed) | `28ad90021` → `9fdf67cec` |

Both pushes were plain fast-forwards (`28ad90021..9fdf67cec` on core; `[new branch]` on libntech). `git ls-remote` confirms both remote heads equal the SHAs above. Worktrees left in place: `~/src/cfengine-core-integration-wt`, `~/src/libntech-integration-wt`.

## MERGED

libntech (`~/src/libntech-integration-wt`, branch created from `fork/master` 3c21479; no `tendcf-integration` existed on the fork):

| branch | register | merge commit |
|---|---|---|
| `silent-digest-failure` (8023f45) | P-3 | `637256b` |
| `fix/json-number-handling` (eda43f0) | B-4 / B-10 / B-11 | `f7bf896` |
| `fix/json-double-decode` (3c9e457, contains B-13 90cf8cc) | B-13 + B-14 | `c6851e3` |
| `fix/mustache-minor-defects` (2f584b0, contains B-22 1b16ae8) | B-22 + B-23 | `7bfb9ff` |
| `fix/json-encode-raw-utf8` (1a3b12f) | — (djbclark/libntech#9, handoff 2026-10-08) | `d379dce` (conflicts, see below) |

core (`~/src/cfengine-core-integration-wt`), in merge order:

| branch | register | merge commit |
|---|---|---|
| `origin/master` 9118740ce | — | `d43a4bc23` (clean, no conflicts) |
| `fix/exec-timeout-poll-deadline` (179e95754) | B-1 | `562819941` |
| `fix/timeout-process-group-merged` (0e06ad3d7; contains B-8 `fix/exec-timeout-promise-outcome` 0ab083c4d) | B-2 + B-8 | `df9d9af35` |
| `fix/exec-timeout-alarm-leak` (453cc264d; contains B-17 `fix/exec-timeout-alarm-pid` 8f4ebedbd) | B-17 + B-19 | `4d0063be7` |
| `fix/exec-timeout-prefork-race` (ab98a5df4) | B-18 | `540c5fc0d` |
| `simulate-keep-chroot` (f6c06f9e2) | P-1 | `c6bffe185` |
| `fix/alarm-pid-reset-after-reap` (e7fd46c6d) | B-16 | `cc3505175` |
| `fix/process-darwin` (68ac0d6f5) | B-3 | `ad11527c2` — **retired, no-op merge** (see CONFLICTS) |
| `fix/json-number-rendering` (13fff92dc) | B-10 core half | `1718a0a20` |
| `fix/eval-integral-result` (b74e8f4cf) | B-6 | `e27b7549f` |
| `fix/cmdb-dotted-key-warning` (ee1f9d60c) | B-7 | `62005bc4b` |
| `fix/cmdb-null-value-crash` (87490bb8f) | B-20 | `ff300f90a` |
| `fix/def-json-null-crash` (dd917f09d) | B-21 | `73cdfd505` |
| `fix/cmdb-one-bad-entry-skips-only-that-entry` (8f0076b81; contains B-5a 958d13949) | B-5a + B-5b (overlay) | `ae0f4b225` |
| `fix/mount-options-timeout-leak-short` (a14792d42) | B-15 | `63d04d44f` |
| `pr-getopt-optstring-fixes` (98df4012f) | CFE-4736 | `9fb9f30ce` |
| `fix/default-route-lowest-metric-v2` (684043972) | B-12 | `128100eaa` |
| `simulate-json-packages` (e00b8990b; contains `fix/simulate-pkg-arch-version-swap` a5a6b6b6a and cherry-picks of the removal-with-version / unversioned-install fixes) | P-2 (PR 1 + PR 2 of handoff 2026-10-08) | `cf66493a8` |
| `simulate-json-utf8` (1b0fb89db) | P-2 fork-only UTF-8 workaround | `9ab373ce9` |
| `fix/simulate-pkg-map-key-collision` (c5e6a37fb) | — | `41d92a07b` |
| `fix/simulate-pkg-record-op-validation` (6eb70adaf) | — | `f97d678ab` |
| `fix/simulate-pkg-unversioned-install-assert` (d5052b786; contains `fix/simulate-pkg-removal-with-version` eb6cf5f04 and `-arch-version-swap`) | — | `5a8910881` |
| submodule bump | — | `9fdf67cec` |

22 new merge commits (26 `into tendcf-integration` merges on `origin/master..tendcf-integration` including the four pre-existing ones from August).

## SKIPPED

| branch | why |
|---|---|
| core `fix/exec-timeout-commands` | register sweep table: "superseded — tree is byte-identical to `fix/exec-timeout-poll-deadline`" |
| core `fix/exec-timeout-promise-result` | register: "superseded — tree is byte-identical to `fix/exec-timeout-promise-outcome`"; outcome itself is an ancestor of `fix/timeout-process-group-merged` (merged) |
| core `fix/timeout-process-group` | register: "absorbed — both commits are in #6305" (= `-merged`, verified `--is-ancestor`) |
| core `fix/exec-timeout-promise-outcome`, `fix/exec-timeout-alarm-pid`, `fix/cmdb-name-offending-key`, `fix/simulate-pkg-arch-version-swap`, `fix/simulate-pkg-removal-with-version` | bases of merged stacks (`git merge-base --is-ancestor` true); merging them again is a no-op |
| core `fix/mount-options-timeout-leak` (9dd5eb51c) | same 4-line `nfs.c` hunk as `-short` (verified identical `+/-` lines); `-short` is the 2026-09-30 resubmission on current master (handoff 2026-10-08: "parked #6308 resubmission is on `fix/mount-options-timeout-leak-short`"); register B-15 row names the fix, not a branch variant |
| core `fix/default-route-lowest-metric` (v1, 3d10206ee) | brief rule: v2 supersedes v1. Not an ancestor of v2 and a different (larger) patch; v2 is the 1-line fix + `sysinfo_test.c` on current master |
| core `simulate-json` (b3a6c3da5, 08-17, base 17eb78e6d) | superseded by `-v2` — verified: every file it touches is touched by v2/packages, its test file is a strict predecessor (patch-ids all differ, content evolved) |
| core `simulate-json-v2` (480acaf52) and `simulate-json-files` (f8342de12) | content-superseded by `simulate-json-packages` (which carries the newer rebase 94d325e88 of the same "Added --simulate-json" commit, handoff 2026-10-08 "PR 2 stacked on PR 1"). Verified: no unit test present in v2/files is missing from packages; no file touched by v2/files is untouched by packages; the only symbols in v2 absent from packages are `PkgOperationNew/Destroy`, renamed by packages' refactor 19f1ff672. Merging them would have produced only self-conflicts resolved by taking packages' files, so they are listed here instead of as empty merges |
| core `fix/simulate-pkg-mapremove` (17dd60d99) | already in `origin/master` (0 commits ahead; upstream #6332 merged) |
| core `3.x`, `2.2.10`, `ENT-*`, `handoffs`, `claudehelm/*` | brief: release/ENT/handoffs skipped |
| libntech `fix/json-number-fatal-exit` (11725b0) | tree byte-identical to `fix/json-number-handling` (`git diff` empty); register line 1016 names `fix/json-number-handling` as PR #294 |
| libntech `fix/json-real-precision` (cd545ab) | B-4 = "bottom two commits" of the number stack (register B-4 row); ancestor of both number branches |
| libntech `fix/json-string-codec` (90cf8cc) | ancestor of `fix/json-double-decode` (B-14 stacked on B-13) |
| libntech `test/mustache-coverage` (1b16ae8) | ancestor of `fix/mustache-minor-defects` (B-23 stacked on B-22) |
| libntech `silent-digest-failure-v2` (2136444) | abandoned WIP ("WIP: unverified draft of the P-3 digest-init failure test" on the old dc85a6f); register P-3 row and handoffs 2026-08-17/18 name `fork/silent-digest-failure` (8023f45) as the PR #291 head |
| libntech `craigcomstock-patch-1`, `ENT-14146/master`, `claudehelm/*` | not ours / not fixes |

## CONFLICTS

libntech (`fix/json-encode-raw-utf8` vs B-13's encoder, both in `libutils/json.c` + `tests/unit/json_test.c`):
- `libutils/json.c` (new helper block): kept B-13's `Utf8DecodeCodePoint()`/`Utf8EncodeCodePointWriter()` (the decoder needs them); dropped raw-utf8's duplicate `Utf8SequenceLength()` (same validation rules, would be an unused static).
- `libutils/json.c` (`JsonEncodeStringWriter()` default arm): **semantic conflict** — B-13 escapes every non-ASCII code point as `\uXXXX` (surrogate pairs above BMP); raw-utf8 writes valid UTF-8 verbatim. Resolved for raw-utf8's intent (the newer fix; the handoff says it replaces core's workaround): valid multi-byte UTF-8 is written as-is using B-13's validator, control characters and invalid bytes are escaped `\u00XX` as both branches agree. First cut wrote 0x01–0x1f/0x7f raw; caught by `json_test` (3 failures), fixed to `length <= 1` → escape. B-13's decoder side is untouched.
- `tests/unit/json_test.c`: kept both test sets; `test_string_encode_unicode` (B-13) now expects raw UTF-8 for valid sequences; `test_string_escape_utf8` (raw-utf8) invalid-byte cases made encode-only and its round-trip loop expects what the conformant decoder actually yields (`\u00e9` → `c3 a9`), since the old "same byte back" expectation only held while the decoder was non-conformant (the register's "codec round-trips its own corruption" trap).
- `main()` test list: both.

core:
- `cf-agent/verify_exec.c`, `libpromises/timeout.c`, `libpromises/timeout.h` (merge of `fix/timeout-process-group-merged`): old integration carried the August variants of the same fixes; upstream has not touched these files since 17eb78e6d (checked), so took the branch's files wholesale (verified byte-equal to the branch); only deltas lost were `bool`→`sig_atomic_t` and comment rewrites the branch itself made.
- `libpromises/timeout.c` (alarm-leak): comment-only; merged the terse wording with the branch's updated fact.
- `libpromises/timeout.h`, `tests/unit/timeout_test.c` (prefork-race): additive — `StartTimeOutClock()` declaration + terse comments; test list is the union; dropped a duplicated `#include <pipes.h>`.
- `libpromises/Makefile.am`, `tests/unit/Makefile.am` (process-darwin): **retired** — upstream `aae13c5e2` (2026-09-16) added `libpromises/process_macos.c` with the same `GetProcessStartTime()`/`GetProcessState()` and dropped `process_test` from the macOS XFAIL list. Took upstream; did not add `process_darwin.c` (merge commit is a tree no-op, message says so).
- `libpromises/cmdb.c` (null-value-crash vs dotted-key-warning): B-7 had changed `AddCMDBVariable()`'s signature/logging to a `VarRefToString()` address; B-20 adds null guards logging the bare key. Combined: both guards kept, `key` parameter restored (B-20's acceptance test `13-null-values.cf` matches `Invalid value in 'null_scalar'`), verbose "Installing" lines keep B-7's address form.
- `libpromises/cmdb.c` (one-bad-entry vs dotted-key): additive, both new functions kept.
- `cf-execd/cf-execd.c`, `cf-promises/cf-promises.c` (getopt): upstream had already removed `1` / `S`,`i:`; took the fix's strings, which also drop the duplicate `V`,`g` / `g:` and contain nothing upstream added since.
- `libenv/unix_iface.c` (default-route-v2 vs json-number-rendering): B-10's safe `StringToLong()` block kept, plus v2's `lowest_metric = metric_value;` assignment inside it.
- `cf-agent/cf-agent.c`, `libpromises/generic_agent.h` (simulate-json-packages vs simulate-keep-chroot): additive, both options kept (option table, hints, parsing, `--simulate`-only checks, config fields).
- `simulate-json-utf8` (7 files, add/add + content): the branch sits on an older rebase of the --simulate-json commit; took the packages versions of all seven and applied only the branch's own commit 1b0fb89db (`RestoreUtf8InJson()` + tests) with `git apply -3`. Its duplicate `test_special_characters_in_path` renamed `test_utf8_in_path` (MinGW-guarded like the packages one); `test_invalid_utf8_in_path`'s round-trip expectation adjusted for the conformant decoder (same point as libntech above, the register's documented P-2/B-13 interaction); raw-bytes assertions unchanged.
- `tests/unit/simulate_mode_test.c` (map-key-collision, record-op-validation): took ours, applied each branch's own test diff; both additive.
- `tests/unit/simulate_mode_test.c` (unversioned-install-assert): branch's tests already present via packages' cherry-picks (identical patch-ids `137133ef66b4`), `simulate_mode.c` had zero diff; took ours.

## DECIDED

1. Merged branch tips carry upstream commits newer than fork `origin/master` (up to cfengine/core `4eae47542`, 2026-10-20). Not rewound: they are upstream master commits and the fix branches were cut on them; `git diff --name-only 4eae47542..tendcf-integration` (62 files) ⊆ union of files the merged branches touch (checked, empty difference). Fork `master` itself was not moved.
2. Encoder semantics (libntech): raw UTF-8 for valid sequences wins over B-13's code-point escapes. Grounds: raw-utf8 is the later fix (2026-09-30), its commit message states the intent, the 2026-10-08 handoff says "the libntech fix replaces" core's `RestoreUtf8InJson()` workaround, and core's `--simulate-json` tests assert raw bytes in the document. B-13's decoder and invalid-byte handling are unchanged. Core's `RestoreUtf8InJson()` is kept (merged as instructed) and is a pass-through on this libntech; its header comment still describes the old per-byte escaping.
3. Tests that asserted a non-UTF-8 byte round-trips through `\u00XX` were changed to expect the conformant decoding (`c3 a9`), in both repos. Raw-output assertions (byte must be escaped, never written raw) were kept. The register already records this as needing an upstream design decision (replacement char / error / raw field); nothing was silently dropped.
4. `fix/process-darwin` treated as retired (upstream `process_macos.c`), per the brief's "take upstream and note it".
5. Only libntech was compiled, as the one hand-written semantic merge: `load-watch ci decide ~/src/libntech-integration-wt local` recorded, run via `~/ops/site-private/bin/bg`, `make -j2`; `json_test`, `hash_init_fail_test`, `mustache_test` all pass (`rc=0` each; mustache "All 17 tests passed"). The first run failed 3 json assertions and led to the `length <= 1` fix; the merge commit was amended before pushing. Core was not built (brief: prefer skipping; CI builds it).
6. Overlay check, quoted verbatim. `bin/overlay.py check` is an apply-test and cannot say "already present"; `retired` (patch-id match) is the mode that does:
   ```
   $ python3 bin/overlay.py check core --repo ~/src/cfengine-core-integration-wt --against tendcf-integration
   core: base a0bca6aaf310; checking against tendcf-integration = 9fdf67cecf4e  (NOT the pinned base: drift check)
   DRIFT: core/0001-Rejected-CMDB-data-now-names-the-offending-entry-and.patch does not apply to tendcf-integration (9fdf67cecf4e):
       error: patch failed: libpromises/cmdb.c:67
       error: tests/acceptance/.../12-variable-references-name-offender.cf: already exists in index   (…and 3 more "already exists")
   $ python3 bin/overlay.py retired core --repo ~/src/cfengine-core-integration-wt --against tendcf-integration
   core: 149 upstream commit(s) in a0bca6aaf310..tendcf-integration
     RETIRE  0001-Rejected-CMDB-data-now-names-the-offending-entry-and.patch: identical change is upstream as 958d13949d5b
     RETIRE  0002-Fixed-one-bad-CMDB-entry-discarding-every-entry-in-i.patch: identical change is upstream as 8f0076b814e8
   $ python3 bin/overlay.py retired libntech --repo ~/src/libntech-integration-wt --against tendcf-integration
   libntech: 13 upstream commit(s) in 0c0620d6c5f8..tendcf-integration
     RETIRE  0001-…JSON-string.patch: identical change is upstream as 90cf8cc08ca5
     RETIRE  0002-…decoding-backslash-esca.patch: identical change is upstream as 3c9e4573a595
     RETIRE  0003-Added-unit-tests-for-MustacheRender.patch: identical change is upstream as 1b16ae80cc61
     RETIRE  0004-…OOB-pointer.patch: identical change is upstream as 2f584b09184f
   ```
   i.e. all six overlay patches (B-5a, B-5b, B-13, B-14, B-22, B-23) are present on the integration branches as the exact fork commits; `check`'s DRIFT is the expected "already applied" failure mode of a `git apply` test.
7. `git status` clean in both worktrees; libntech worktree holds ignored build output from the test run.

## OPEN

1. Core is unbuilt locally; the only hand-combined core hunks are `cmdb.c` (B-7+B-20), `unix_iface.c` (B-10+B-12), `timeout.h`/`timeout_test.c` (B-18 on top of B-17/B-19) and `simulate_mode_test.c` (utf8/map-key/record-op on packages). CI should run at least `tests/unit` (`timeout_test`, `simulate_mode_test`, `sysinfo_test`, `rlist_test`) and `tests/acceptance/00_basics/06_host_specific_data`, `29_simulate_mode`, `08_commands/04_exec_timeout`.
2. The encoder decision (DECIDED 2) changes what `cf-agent` writes for non-ASCII in *every* JSON it emits, not only `--simulate-json`; the register's B-13 row called B-13 a "carrier" for that reason. If the operator wanted B-13's pure-ASCII output instead, revert the `else` branch in `JsonEncodeStringWriter()` to the `\u%04x`/surrogate-pair form and the two test files' expectations.
3. `fix/simulate-pkg-unversioned-install-assert` et al. pulled upstream master forward to 2026-10-20; if the fork's `master` is meant to track that, it still sits at 9118740ce (not touched here).
4. `cf-agent/simulate_mode.c` `RestoreUtf8InJson()` is now dead-in-effect code with a stale comment; removing it is a fix-branch change, out of scope here.

DONE
