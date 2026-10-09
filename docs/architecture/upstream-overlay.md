# The upstream patch overlay on libntech and cfengine/core

**Date:** 2026-10-09. **Author:** Claude Fable 5.1 (ClaudeHelm worker).
**Status:** design and implementation for
[frdminc/tendcf#3](https://github.com/frdminc/tendcf/issues/3); the
mechanism is `bin/overlay.py`, the content is `overlay/`. The register of
every defect behind it stays
[`upstream-register.md`](upstream-register.md), and the standing rules for
talking to upstream stay in `~/src/cfengine-all/AGENTS.md`; this document
does not restate either.

## 1. Why there is an overlay at all

`policy/tendcf_services.cf` (the generic bundle, `222da45`) runs on three
CFEngine/libntech code paths in which this project found and fixed real
defects (guide §19): mustache rendering of every unit file, JSON string
decoding of every `host_specific.json` value containing a backslash, and
the CMDB loader that reads that file. The fixes exist on the forks
(`djbclark/libntech`, `djbclark/core`). Upstream closed the pull requests on
2026-08-19 for review volume, not on a finding, and since 2026-08-22 the
forks are the destination, not a staging area.

So a *correct* build of CFEngine for tendcf is upstream plus a small, named
set of patches, and the question #3 asks is how to hold that set without
paying for a full parallel fork: no permanent branch to rebase on every
upstream merge, no distribution burden, nothing a future session has to
re-derive from the register.

## 2. What may go in it

One rule, from the issue: **a patch is in the overlay only while it is
load-bearing for code this repository has shipped.** Today that is the
generic bundle and its projector input. The manifest records, per patch,
the shipped code it protects (`load_bearing_for`) or why it rides along
(`role: carrier`: a commit a load-bearing patch is stacked on).

Not in the overlay, by that rule:

- the `--simulate-json` series (fork branches `simulate-json-*`): a feature
  the consent path will want (guide §7), not something shipped policy
  depends on. It joins when the agent calls it.
- the other seventeen fork fixes in the register: real, kept on the forks,
  not load-bearing for anything shipped.
- tests-only commits, unless a load-bearing patch is stacked on them
  (B-22 is, under B-23).

The overlay is therefore small by construction, and it shrinks: §6.

## 3. Format and location

```
overlay/
  overlay.json          manifest (canonical JSON: sorted keys, 2-space indent)
  libntech/0001-….patch  git format-patch output, applied in order onto libntech.base
  core/0001-….patch      the same for cfengine/core
bin/overlay.py          lint · status · check · retired · apply · export · self-test
```

**The patch files are the artifact; the manifest is the provenance.** Each
`.patch` is `git format-patch` output from a fork branch, so its `From`
line is the fork commit and `git am` reproduces that commit's tree exactly.
The manifest holds, per component, the upstream URL, the fork URL, the
pinned base commit, and per patch: file, commit, subject, register id
(`B-14`), fork branch, upstream PR and its state, Jira key, what shipped
code it protects, and the retire condition. `bin/overlay.py lint` holds the
two together (every listed file present, every file listed, order, ids,
`From` line equal to the manifest commit).

Why patches in this repository rather than references to fork commits:

1. **The fork is not an archive.** On 2026-10-08 an operator bulk cleanup
   deleted local worktrees and branches mid-session (handoff `fab1`); the
   local merge `45c816c` that the #3 comment built and tested was never
   pushed to the fork and survives only in `~/src/libntech-overlay`. A
   patch file in git is the one copy that cannot be lost by tidying a
   checkout.
2. **The diff is what a reviewer reads.** A change to the overlay is a
   change to a `.patch` file, visible in this repository's own history and
   pull requests, not a pointer that moved.
3. **It is the shape a build consumes.** A Nix derivation is
   `src = fetchFromGitHub { rev = base; }; patches = [ ./0001-….patch … ];`
   with no further machinery; a plain `git am` is the same thing by hand.
   Debian's `debian/patches` and Homebrew's `patch do` are the same model.

The two bases are coherent by construction: core's base `a0bca6aaf` pins
its libntech submodule at exactly libntech's base `0c0620d`. Bumping one
without the other is allowed (upstream does it) but `check` against the
other component's pin is the right test before doing so.

## 4. How a build applies it

**Today** (local testing of `.cf` policy against a correct build, which is
all #3 asks for):

```bash
git clone https://github.com/cfengine/core ~/src/core-overlay
git -C ~/src/core-overlay checkout a0bca6aaf310515f69fef60e6c56b3e60bd337ac
git -C ~/src/core-overlay submodule update --init libntech        # lands on 0c0620d
bin/overlay.py apply core     --checkout ~/src/core-overlay
bin/overlay.py apply libntech --checkout ~/src/core-overlay/libntech
git -C ~/src/core-overlay add libntech                              # submodule now points at the applied HEAD
cd ~/src/core-overlay && NO_CONFIGURE=1 ./autogen.sh && ./configure --enable-debug && make -j4
```

That is the recipe the #3 comment executed by hand on 2026-08-19 (full
`make -j4` clean; `json_test` 74/74, `mustache_test` 17/17,
`06_host_specific_data` 14/14 under fakeroot). `apply` refuses a checkout
whose HEAD is not the pinned base and refuses a dirty tree, so the recipe
cannot silently build something else.

**Later**, when tendcf-agent has a build pipeline (map §13 Step 10+,
"builder/cache"): the same manifest feeds the derivation or the build
script, and the built agent enters a release only as a digest-bound
artifact (map §9.8). The overlay never travels to a device; what travels
is the binary's digest in the goal file. The change-process design
([`change-process.md`](change-process.md) §2) pins the overlay *through*
the tendcf input of `site.lock`, so a release's CFEngine build is
reproducible from the lockfile alone.

## 5. Drift detection

Drift is "the pinned series no longer applies where we want to build". Two
places want to know, and the same command serves both:

```bash
bin/overlay.py check libntech --repo <any repo with the objects> --against origin/master
bin/overlay.py check core     --repo ~/src/cfengine-core          --against 3.27.1-build7
```

`check` reads the target tree into a **temporary index** and `git apply
--cached`s the series into it in order, so the repository it is pointed at
is never touched (a shared checkout another session is using is safe). The
first patch that fails stops it with `DRIFT:`, the patch name, git's hunk
report, and the two ways out (rebase and re-export, or retire).

Where it runs:

- **Every push:** `lint` and `self-test`, hermetic. The self-test builds a
  synthetic upstream and fork, exports a sample series, and proves the
  thirteen behaviours the overlay must have: it applies; an unrelated
  upstream change still applies; a conflicting one makes `check` report
  `DRIFT` and makes `apply` fail, abort, and leave the checkout clean; a
  cherry-picked patch is reported by `retired`; a manifest that disagrees
  with its files is a lint finding.
- **Weekly and on demand** (`overlay-drift` job in `check.yml`): shallow
  clones of both upstreams, `check` against each `origin/master` (and the
  newest `3.27.*` tag for core), and `retired --strict`. Not hermetic, so
  not on every push. A red run is the overlay asking for §5's rebase or
  §6's retirement, nothing else.

**Rebasing the overlay** when it drifts: in the fork, rebase the branch
onto the new upstream commit and push it; then

```bash
bin/overlay.py export libntech --repo <fork checkout> --base <new upstream rev> --tip <branch tip> [--tip <second independent tip>]
bin/overlay.py check  libntech --repo <fork checkout>
```

and commit the regenerated files with the manifest. `export` keeps every
provenance field by commit id, so a rebase that changes commit ids needs
the register ids and PR links re-attached by hand (they are in the diff).
Update `upstream-register.md` in the same commit (its own rule).

## 6. How a patch retires

```bash
bin/overlay.py retired core --repo ~/src/cfengine-core --against upstream/master --strict
```

For each patch, `git patch-id --stable` is compared with every non-merge
commit in `base..upstream`. A match is `RETIRE`: upstream carries the
identical change. An upstream commit with the same subject but a different
patch-id is `VERIFY`: probably a reworked merge of the same fix; read it.
`--strict` turns either into exit 1, which is how the weekly job fails
loudly when upstream catches up.

Retiring is one commit: delete the `.patch`, delete its manifest entry, bump
that component's base to a commit that carries the upstream fix, run
`check` against the new base for the patches that remain, and mark the
register row. When a component's list is empty, delete the component. When
both are empty, #3 closes, exactly as its "Close when" says — or earlier if
a real build pipeline supersedes this with proper pinning, in which case
the manifest is the input to that pinning, not something it replaces.

A patch can also retire because the code it protects stops shipping
(`retire_when` says so). That is a judgment, recorded in the commit that
drops it.

## 7. State verified on 2026-10-09

| | libntech | core |
| --- | --- | --- |
| base | `0c0620d` (upstream master 2026-08-15) | `a0bca6aaf` (upstream master 2026-08-15; pins libntech `0c0620d`) |
| patches | 4: B-13 (carrier), **B-14**, B-22 (carrier), **B-23** | 2: B-5a (carrier), **B-5b** |
| upstream PRs | #293, #297, #296, #298 — all closed unmerged 2026-08-19 | #6315, #6320 — closed unmerged 2026-08-19 |
| `check` at base | 4/4 ok | 2/2 ok |
| `check --against` upstream master | ok at `3c21479` (master moved 2 commits, neither in `json.c`/`mustache.c`) | ok at `4b67bb7` (master moved 98 commits, none in `cmdb.c`) and at tag `3.27.1-build7` |
| `apply` into a clean clone at base | tree `5cbd6f7…`, **byte-identical to the local merge `45c816c`** the #3 comment built and tested | tree `c66a60d…`, **byte-identical to fork tip `8f0076b81`** |
| `retired --strict` against upstream master | nothing to retire | nothing to retire |
| `self-test` | 13/13 | |

So the overlay reproduces exactly the inputs whose build was verified on
2026-08-19, from this repository alone, and would still apply to a build
cut from today's upstream.

## 8. Rejected alternatives

1. **Fork branch references only** (manifest of `repo` + `commit`, no patch
   files). Smaller, but §3's first reason: the one copy that was built and
   tested was lost from the fork once already. Also a reviewer of a bump
   sees a hash change, not a diff.
2. **A long-lived merged branch (`overlay/tendcf-N`) as the artifact**,
   which is what the #3 comment made by hand. It is a full parallel fork in
   all but name: every upstream merge is a rebase or a merge of that
   branch, and the thing devices would build from is a moving ref. The
   merge commit is still useful as a local build convenience; it is not
   the record.
3. **Pointing a submodule at the fork.** Same as 2 with worse ergonomics,
   and it makes the fork load-bearing for a public repository's build.
4. **quilt / stgit / `git-series`.** Fine tools, but they add a dependency
   to a mechanism whose whole job is `git am` in order, and none of them
   gives the retirement check for free. `bin/overlay.py` is under 600 lines with
   no dependency but git.
5. **Vendoring libntech and core source into tendcf.** Rejected for the
   same reasons as vendoring in `change-process.md` §9: duplicated review,
   lost provenance, and an 80 MB public repository for 75 KB of patches.
6. **Waiting for upstream.** Every upstream PR here is closed; the register
   records that nothing was rebutted and the rules say nothing is re-sent
   without the operator. The overlay is what lets the policy be tested
   against a correct build while that stays true.

## 9. Open

- **Push the local merge `45c816c` to the fork** as `overlay/tendcf-3` so
  the by-hand build convenience survives the next cleanup; harmless, but a
  write to the fork, so the operator's call.
- **Whether the simulate-json series joins** once the agent calls
  `--simulate-json` (§2). Not before.
