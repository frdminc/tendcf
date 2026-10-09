---
schema_version: 1
handoff_id: fab1
parent_handoff_ids: [8d50]
lineage: deterministic
chain: [standalone-3fd9]
repo: cfengine-core
workspace: core-simjson
branch: simulate-json-packages
head_sha: 29fce4663966c01175095b19fe494ddeed437898
created_at: 2026-10-08T22:15:34-0400
writer: claude-code
---
# Handoff: `--simulate-json` split into three upstream-ready PRs

## The Goal

Get the `--simulate-json` feature (CFE-4716, rejected in the 2026-08-19 bulk closure) into cfengine/core. larsewi
invited it on cfengine/core#6332 (2026-09-23): "Feel free to open a PR. It would help if you split the work in
logical parts." Upstream wants small PRs, prose proportional to code, and the human (djbclark) in the loop.

## Where We Are

Three PRs are implemented, reviewed and green on the fork. **Nothing has been sent upstream.** The only remaining
gate is the operator reading the ELI5s and opening the PRs.

| PR | Fork branch (`origin` = djbclark/core) | Head | Fork PR | Status |
|---|---|---|---|---|
| 0: two simulate package-reporting fixes | `fix/simulate-pkg-arch-version-swap` | `98006a443` (commits `dba2a1032` swap, `98006a443` #38) | #39 (ELI5 in its description) | ready; send first |
| 1: `--simulate-json` for files and renames | `simulate-json-files` | `d5cc2c4e0` | #40 (ELI5 in its description) | ready; send second |
| 2: packages in the JSON | `simulate-json-packages` | `29fce4663` (cherry-picks `bd158d462`, `da443fd48` of PR 0, refactor `c1bf747ea`, feature `29fce4663`) | #41 (stacked on #40; full CI ran via the closed CI-only #42) | wait until PR 0 and PR 1 are accepted; needs its own ELI5 and upstream text |
| fork-only: UTF-8 path workaround | `simulate-json-utf8` | `1b0fb89db` (on PR 1) | none | never upstream; the libntech fix replaces it |

Related state:
1. libntech raw-UTF-8 encoder fix: djbclark/libntech#9, `1a3b12fef` on `fix/json-encode-raw-utf8`, worktree
   `~/src/libntech-utf8`. It is offered in PR 1's text, not sent.
2. The parked #6308 resubmission is on fork branch `fix/mount-options-timeout-leak-short` (`a14792d42`); notes on
   djbclark/core#16.
3. The tracker checklist is on djbclark/core#3, comment 5915355155.

Git state:
1. Main checkout `~/src/cfengine-core` is on `fix/simulate-pkg-mapremove` @ `5ddb6d97b`. `.gitignore` has a
   graft-added `/graft/` line again. It is harmless, since `.git/info/exclude` already covers it; don't commit it.
2. Worktree `~/src/core-simjson` is on `simulate-json-packages` @ `29fce4663`, clean apart from an untracked
   configure artifact `tests/asan-check/Makefile`. It is configured and built, installed to `~/opt/cfengine-simjson`.

Files changed this session (all on fork branches; see each commit): `cf-agent/cf-agent.c`, `cf-agent/simulate_mode.{c,h}`,
`libpromises/changes_chroot.c`, `tests/unit/simulate_mode_test.c`, `tests/acceptance/29_simulate_mode/simulate_json.cf{,.sub,.expected}`;
libntech `libutils/json.c`, `tests/unit/json_test.c`. Outside the code:
1. `~/src/cfengine-all/AGENTS.md`: the prose rule (not a git repo).
2. site-private `home-agents.md`, `969a65a`: the "never waste spent tokens" rule.
3. tendcf `526b1b4`: restored the `AGENTS.md` content that was lost to a symlink loop.

## What We Tried (failed or corrected, in order)

1. **Stale build artifacts gave false test results twice.** A libtool test binary built from another branch
   reported 13 tests instead of 11. Reverting a fix and running `make simulate_mode_test` alone said "up to date"
   and passed. Always `rm -f simulate_mode_test.o simulate_mode_test` and rebuild `cf-agent/libcf-agent.la` before
   proving a test fails without its fix.
2. **`BASE_WORKDIR` under `$TMPDIR` made the acceptance test fail falsely.** `$TMPDIR` ends in `/`, giving `T//wd`,
   and rename paths get the doubled slash normalised, so the expected-output substitution missed them. Use a path
   with no double slash.
3. **`make CFLAGS="-Werror -Wall"` fails on macOS clang** in untouched upstream code (`evalfunction.c`, unused
   parameter). Build normally and grep the log for warnings in the touched files.
4. **Upstream CI only runs for PRs into `master`, 3.27.x or 3.24.x**, so the stacked #41 got 2 checks. Fix: a
   CI-only fork PR from the same head into `master` (#42, now closed).
5. **The first fork CI run failed only on `cfengine format --check`**, and every dependent workflow was skipped.
   Run `cfengine format` on new `.cf` files.
6. **The temp name `<FILE>.%06d(rand())` was predictable**: `RandomSeed()` runs before `CFSTARTTIME` is set, so the
   seed is effectively `time(NULL)`. A planted file could block the report. Adding the pid was not enough either,
   because pids are predictable too. Fix: 8 bytes from `RAND_bytes()` as hex (precedent: `bootstrap.c`). Root cause
   filed as #33.
7. **The `failsafe_fallback` lookup also matched a policy-defined soft class**, so it could be spoofed. Fix:
   `!cls->is_soft`.
8. **The MinGW build broke** on `S_ISUID`/`S_ISGID`/`S_ISVTX`. It was caught only by Fable's cross-compile; upstream
   public CI doesn't build Windows.
9. **Encoding code points (`\u00e9`, as libntech#293 did) requires the decoder fix too**, which reopens the
   migration question (#23 Q3). The chosen libntech fix writes valid UTF-8 raw and changes only the encoder.
10. **An operator bulk cleanup deleted `~/src/core-simjson` twice mid-work**, along with local branches. The
    worktree was recreated; the unpushed `a14792d42` was preserved by pushing it to a new fork branch. Lesson: push
    WIP to fork branches early.
11. **I stopped the Fable review workflow to "pause" for quota and lost an in-flight agent.** The operator said
    "no don't stop it if we lose stuff", which is now a global rule.
12. **A size-analysis agent proposed replacing the atomic write with `safe_fopen`** (−60 lines). Rejected: it
    contradicts the security review and CFEngine precedent.

## Key Decisions (chosen; rejected)

1. **Three PRs, not one PR with commits.** Rejected: one ~960-line PR. Operator: "split as in 4.2".
2. **No Jira ticket** ("Just do PRs"). CFE-4716 is Rejected/Won't Do.
3. **UTF-8 via a libntech encoder fix that is offered, not sent.** Rejected: the core workaround as a third commit,
   at first accepted, then reversed after the libntech analysis.
4. **#38 is PR 0's second commit.** Rejected: a separate later PR. Reason: the AGENTS.md "bugs in the same code
   merge into one thematic change" rule, and the JSON would otherwise inherit the bug.
5. **Stale output after an early failure: keep the old file, write atomically, and rely on the exit code**
   (CFEngine precedent: `cf-net get -o`, `cf-promises -T`). Rejected: unlinking FILE up front, which no CFEngine
   code does. Recording run identity in the document is deferred to #32.
6. **`failsafe_fallback` is a field in the document.** Rejected: a new exit code, since cf-agent never uses exit
   codes for outcomes like this.
7. **The `simulate_mode` field is dropped** (the content doesn't depend on the mode). Kept: `format_version`.
8. **No `fsync`** (matches copy_from and edit_line); #30 tracks a libntech `FileWriteAtomic()` helper.
9. **`manifest-full` unchanged files are excluded**; #31 tracks that, including checking whether tendcf needs them.
10. **The non-root uid/gid warning goes in its own PR with #29.**
11. **Tests may be longer**; only exact duplicates were cut.
12. **AGENTS.md prose rule**: about 100 chars for a 2-line change is "the ceiling, not a target", and it doesn't
    scale with the diff.

## Evidence & Data

1. PR 0: each test fails without its fix (swap: 1 of 3 failed before; #38: 1 of 4 failed before). Manifest output
   was identical over 12,314 generated logs; 4,439 diff sections changed, each from "nothing" to "would be removed".
   `git merge-tree` with PR 1 is clean.
2. PR 1: +716 lines (tests about 400). Unit tests 11/11; acceptance passes, including the option checks.
3. PR 2: the refactor's old-vs-new comparison over 12,314 logs (151,455 lines) had zero diffs. Unit tests 15/15.
4. Linux gate (Ubuntu 24.04 arm64 container, dash): every commit green. Fork CI: 10/10 on #39, #40 and #42.
5. Reviews: Claude review, Fable xhigh workflow (4 dimensions plus adversarial verify: 5 confirmed, 0 refuted),
   final review, and delta review. No blockers remain.
6. libntech#9: 39/39 libntech test programs pass; core's unit tests pass against it; Python and jq decode `café`,
   `中` and the emoji correctly.

## Operator Feedback (verbatim where it matters)

1. "Just do PRs" (no Jira). "Go with your plan" (libntech offer). "split as in 4.2 and track what we are doing in
   our fork issue". "I think we can safely have tests be a bit longer."
2. "Do everything you recommend, and put anything else in issues in our fork so we don't forget."
3. Since they wanted us small: "consider putting 38 earlier in the submission queue."
4. AI disclosure wording, requested: "I can't vouch for the C syntax beyond a basic level, but I did look at the
   logic … and it seemed sound." An ELI5 is the gate for that sentence.
5. "no don't stop it if we lose stuff"; "remember to not do anything that will cause tokens to have been wasted
   without talking to me about it first"; then "The rule should go to all claude sessions everywhere".
6. The 100-character rule is an upper bound, not a goal.

## Where We're Going

1. **THE NEXT ACTION: the operator reads the ELI5s** in the descriptions of djbclark/core#39 and #40. The
   disclosure line in each upstream text is only true after that. Fix anything he finds unclear first.
2. **Then open upstream PR 0, then PR 1, on his explicit go.** The `upstream_review_gate.sh` hook denies `gh` writes
   to cfengine/core, so either he runs the commands or he lifts the gate for the session. The new global rule says
   "run commands yourself", but that doesn't override the gate. Recreate the body files from the texts below:
   ```
   gh pr create --repo cfengine/core --base master --head djbclark:fix/simulate-pkg-arch-version-swap \
     --title "Fixed two simulate mode package reporting bugs" --body-file pr0.md
   gh pr create --repo cfengine/core --base master --head djbclark:simulate-json-files \
     --title "Added --simulate-json option to write the simulated change set as JSON" --body-file pr1.md
   ```
   Afterwards, record both in tendcf `docs/architecture/upstream-register.md`, tick #3's checklist, and ping Hermes.
3. **After PR 0 and PR 1 are accepted**, PR 2:
   a. Rebase `simulate-json-packages` onto the new upstream master, dropping the PR 0 cherry-picks.
   b. Re-run the old-vs-new comparison and the Linux gate.
   c. Write PR 2's ELI5 (the refactor fact: store fields, format at print time; plus the packages array and its
      sort) and an upstream text, then the same send flow.
4. **If a maintainer wants the UTF-8 fix:** send libntech#9 upstream (NorthernTechHQ/libntech), on the operator's
   go only.
5. **Outside this work, found in the handoff sweep:** five repos have committed AGENTS.md↔CLAUDE.md symlink loops
   from the 2026-10-04 batch ("make CLAUDE.md a symlink"): `~/src/{secretspec-sqlite,ss-370,ss-ipc-proto,ss-sigpipe,sudo-secretspec}`.
   Agents in them get no instructions. The operator was pinged on Hermes. Fix recipe, as done for tendcf `526b1b4`:
   `rm AGENTS.md; git show <that commit>^:CLAUDE.md > AGENTS.md` (fix any "AGENTS.md is a symlink" line), keep
   `CLAUDE.md -> AGENTS.md`, then commit. Check with
   `for f in ~/src/*/AGENTS.md; do [ -L "$f" ] && ! [ -e "$f" ] && echo "$f"; done`.
6. **Backlog on the fork (all deferred deliberately):**
   a. #16: the parked #6308 resubmission.
   b. #28–#31.
   c. #32: run identity in the document.
   d. #33: rand() seeding.
   e. #34–#35: libntech bugs.
   f. #36–#38. #38 is fixed in PR 0; close it when PR 0 merges.
   g. #43: optional nits from the rework review.
7. **Cleanup after merge:** worktrees `~/src/core-simjson` and `~/src/libntech-utf8`, `~/opt/cfengine-simjson`, and
   the fork branches `simulate-json-v2`, `simulate-json-v2-orig` and `simulate-json` (history only).

## Detached jobs

none (no bigteam job records owned by this session; all background tasks and agents finished).

## Upstream texts (the scratch copies are gone; recreate pr0.md and pr1.md from these)

pr0.md:
```
Two simulate mode package reporting fixes, each with a regression test that fails without it:

1. Version and architecture were swapped: they were written in the reverse of the order they are read.
2. `--simulate=diff` omitted a removal with a version unless it cancelled a recorded install.

Fork CI, and the logic explained without C: https://github.com/djbclark/core/pull/39

AI-assisted. I can't vouch for the C syntax beyond a basic level, but I did look at the logic and it seemed sound.
```

pr1.md:
```
Follow-up to #6332, split as suggested there. This first part adds `--simulate-json=FILE`, which writes the files and renames of a `--simulate` run as one JSON document, so tools need not parse the prose output. Packages follow in a separate PR once this one is settled.

Non-ASCII paths come out byte-escaped because of how `JsonWrite()` escapes (`café` reads back as `cafÃ©`). I have a small libntech encoder fix ready if you want it, or I can work around it in core.

Fork CI, and the logic explained without C: https://github.com/djbclark/core/pull/40

AI-assisted. I can't vouch for the C syntax beyond a basic level, but I did look at the logic and it seemed sound.
```

## Quick Start

```sh
cd ~/src/cfengine-core && git fetch origin
for b in fix/simulate-pkg-arch-version-swap simulate-json-files simulate-json-packages; do git log --oneline upstream/master..origin/$b; done
for n in 39 40 41; do gh pr checks $n -R djbclark/core; done        # expect all green
gh pr list -R cfengine/core --author djbclark --state all --limit 3  # has anything been sent since?
gh pr view 6332 -R cfengine/core --json comments --jq '.comments[-2:][]|{a:.author.login,b:.body}'
```

Linux gate (Apple `container`, image `cfengine-build:u24`; recipe in the tendcf memory `linux-gate-before-upstream`).
Save as `gate.sh` in a scratch dir `$G`, `chmod +x`, then
`container run --rm -c 8 -m 8G -v ~/src/cfengine-core:/src:ro -v $G:/gate cfengine-build:u24 /gate/gate.sh <sha>...`:
```sh
#!/bin/sh
set -eu
git config --global --add safe.directory '*'; git config --global protocol.file.allow always
for ref in "$@"; do
    echo "################ $ref"
    rm -rf /build && git clone -q --no-checkout /src /build && cd /build && git checkout -q "$ref"
    git config submodule.libntech.url /src/.git/modules/libntech && git submodule update -q --init libntech
    NO_CONFIGURE=1 ./autogen.sh >/dev/null 2>&1
    ./configure -q --prefix=/var/cfengine --enable-debug >/tmp/configure.log 2>&1 || { tail -20 /tmp/configure.log; exit 1; }
    make -j"$(nproc)" >/tmp/make.log 2>&1 || { grep error /tmp/make.log | head; exit 1; }
    grep -E "simulate_mode.*warning" /tmp/make.log || echo "no warnings in simulate_mode"
    (cd tests/unit && make -s simulate_mode_test >/dev/null 2>&1 && ./simulate_mode_test 2>&1 | grep -E "tests? passed|failed")
    if [ -f tests/acceptance/29_simulate_mode/simulate_json.cf ]; then
        make -s install >/dev/null 2>&1; cd tests/acceptance
        export BASE_WORKDIR=/tmp/wd; rm -rf "$BASE_WORKDIR"; mkdir -p "$BASE_WORKDIR"
        ./testall --gainroot=env --bindir=/var/cfengine/bin 29_simulate_mode/simulate_json.cf 2>&1 | grep -E "^(Passed|Failed) tests"
        grep -q "^Failed tests: *0" summary.log 2>/dev/null || tail -60 test.log
    fi
done
```
