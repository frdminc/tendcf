# Slice: refresh `tendcf-integration` on the CFEngine forks (core + libntech)

## Goal

The operator ruled on 2026-10-29 (`~/src/tendcf/docs/architecture/upstream-overlay.md` §2, and chose option 1 of a
follow-up question today) that Linux CI and Linux hosts build **the full fork**: every fix branch on
`djbclark/core` and `djbclark/libntech` that is still current, plus the whole `--simulate-json` series, on top of
the forks' current `master`. Today no branch holds that: `tendcf-integration` (the documented build branch,
`~/src/tendcf/docs/architecture/upstream-register.md` "Branch layout") is at base `17eb78e6d` (2026-08-16) with only
the exec-timeout fixes, while the simulate-json work sits on master `9118740ce` (2026-09-29) as sibling branches.

Deliverable: `tendcf-integration` on **both** forks refreshed and pushed, with core's `libntech` submodule pointing at
libntech's refreshed `tendcf-integration` tip. The report names both final SHAs and lists what was merged, what was
skipped and why, and every conflict and how it was resolved.

## Targets

- `~/src/cfengine-core` (remote `origin` = https://github.com/djbclark/core, upstream = https://github.com/cfengine/core).
  Work in a NEW worktree: `git -C ~/src/cfengine-core worktree add ~/src/cfengine-core-integration-wt tendcf-integration`
  (after `git -C ~/src/cfengine-core fetch origin`). Never touch the existing checkout's branch.
- `~/src/libntech-fixes` (remote `fork` = https://github.com/djbclark/libntech, `origin` = NorthernTechHQ/libntech).
  Same: `git worktree add ~/src/libntech-integration-wt` on a `tendcf-integration` branch (create it from `fork/master`
  if the fork has none; check `git ls-remote --heads fork` first).
- Read-only reference: `~/src/tendcf/docs/architecture/upstream-register.md` (the B-register: which branch is
  canonical per fix, which are superseded or byte-identical duplicates, see its "PR-sharing sweep, 2026-08-18" table
  and the B-1..B-23 rows) and `~/src/tendcf/overlay/overlay.json` (the two core patches B-5a/B-5b and the libntech
  ones that shipped policy depends on; their `fork_ref` names the branch).

Non-goals: no new fixes, no rebases of per-fix branches, no PRs upstream, no edits in `~/src/tendcf`, no local
full build on this Mac (CI will build it; a local `./autogen.sh && ./configure && make -j2` is allowed ONLY if run
through `/Users/djbclark/ops/site-private/bin/bg` and bounded, and only to check that the merged tree compiles — prefer
skipping it and saying so).

## Method

1. `git fetch origin` in core; `git fetch fork` in libntech. List branches with dates:
   `git for-each-ref --sort=committerdate --format='%(refname:short) %(committerdate:short)' refs/remotes/origin`.
2. Build the merge list from the register, not from branch names alone. Rules:
   - One canonical branch per fix. The register's sweep table says which: e.g. `fix/exec-timeout-poll-deadline`
     supersedes `fix/exec-timeout-commands` (byte-identical), `fix/exec-timeout-promise-outcome` supersedes
     `fix/exec-timeout-promise-result`, `fix/timeout-process-group-merged` absorbs `fix/timeout-process-group`.
     `fix/default-route-lowest-metric-v2` supersedes `-v1`; `fix/mount-options-timeout-leak-short` vs
     `fix/mount-options-timeout-leak`: read both and the register row B-15, take the one the register calls current.
   - Stacked branches (`fix/exec-timeout-alarm-pid`, `-prefork-race`, `-alarm-leak` carry their bases): merge the
     tip of each stack; merging a base again is a no-op.
   - The simulate-json series: `simulate-json-v2`, `simulate-json-utf8`, `simulate-json-files`,
     `simulate-json-packages`, all six `fix/simulate-pkg-*`, and `simulate-keep-chroot`. Check containment
     (`git merge-base --is-ancestor`) before merging so you merge tips, not every intermediate. The old
     `simulate-json` (08-17, base 17eb78e6d) is superseded by `-v2` unless a diff shows otherwise; say which.
   - Overlay patches: `fix/cmdb-name-offending-key` (B-5a) and `fix/cmdb-one-bad-entry-skips-only-that-entry`
     (B-5b, contains 5a). After the merge, `~/src/tendcf/bin/overlay.py check core --repo ~/src/cfengine-core-integration-wt --against tendcf-integration`
     must report the overlay as already present/applies cleanly (read `bin/overlay.py --help`-equivalent docstring
     first; it is a plain Python script, read its usage from the source, never guess flags).
   - Also: `fix/process-darwin` (B-3), `fix/json-number-rendering` (B-10 core half), `pr-getopt-optstring-fixes`,
     `fix/eval-integral-result` (B-6), `fix/cmdb-dotted-key-warning` (B-7), `fix/cmdb-null-value-crash` (B-20),
     `fix/def-json-null-crash` (B-21), `fix/alarm-pid-reset-after-reap` (B-16). Skip release branches (`3.x`),
     `ENT-*`, `handoffs`.
   - libntech: `fix/json-number-fatal-exit` (B-4/B-10/B-11), `fix/json-string-codec` (B-13),
     `fix/json-double-decode` (B-14), `fix/json-encode-raw-utf8`, `fix/json-real-precision`,
     `fix/json-number-handling`, `silent-digest-failure-v2` (vs `-v1`: register decides), `test/mustache-coverage`
     (B-22) and `fix/mustache-minor-defects` (B-23, stacked on B-22). Check each against the register; drop
     duplicates the register marks superseded.
3. Merge order: first `origin/master` into `tendcf-integration` (expect conflicts in the exec-timeout files; the
   fixes are additive, few tight hunks, per register "Branch layout"), then per-fix branches oldest-base first,
   then the simulate series. One merge commit per branch, message `Merge branch 'X' into tendcf-integration`.
   Resolve conflicts preserving BOTH upstream's change and the fix's intent; when a fix's hunk is already upstream
   (the register's "retired" notion), take upstream and note it. Never resolve by dropping a fix silently.
4. libntech first, then in core: `git -C ~/src/cfengine-core-integration-wt submodule update --init libntech`,
   point the submodule at the libntech `tendcf-integration` tip (`git -C libntech fetch <fork-url> tendcf-integration && git -C libntech checkout FETCH_HEAD`), commit
   `libntech: tendcf-integration <sha>`. Core's master may already carry a newer libntech pointer than libntech's
   fork master; if the libntech fork master is behind core's pinned libntech, merge NorthernTechHQ `origin/master`
   into libntech `tendcf-integration` first so nothing regresses. State both SHAs.
5. Sanity, no full build: `git diff --stat origin/master..tendcf-integration` lists only files the merged branches
   touch; `git log --merges --oneline origin/master..tendcf-integration` lists every merge; `git status` clean.
   `autoreconf`/`./autogen.sh` on the Mac is optional. If you do compile, `bg` only, `make -j2`, and record the
   CI decision first (`~/src/djbclark-ade/bin/load-watch ci decide ~/src/cfengine-core-integration-wt local "<why>"`).
6. Push: `timeout 600 git push origin tendcf-integration` in both worktrees (libntech: `git push fork tendcf-integration`).
   The branch is ours, never for upstream; force-push is NOT needed and NOT allowed (merges fast-forward the old tip).
7. Leave both worktrees in place (the tendcf CI slice reads the SHAs from the report).

## Report (`/tmp/tendcf-fork-integration/core-integration-report.md`)

Sections: `STATUS`, `SHAS` (core tendcf-integration, libntech tendcf-integration, core libntech submodule pointer,
upstream master bases), `MERGED` (branch → register id → merge commit), `SKIPPED` (branch → why, citing the register
line), `CONFLICTS` (file → resolution in one line each), `DECIDED`, `OPEN` (anything you could not settle), then
`DONE`.

Commit with plain `git commit` here (fork integration branch, not an ops repo); never `git commit -a`, stage
explicitly. Use `gsed` not `sed`. Wrap every fetch/push in `timeout 600`.
