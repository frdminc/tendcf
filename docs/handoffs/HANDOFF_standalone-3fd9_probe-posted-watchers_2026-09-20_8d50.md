---
schema_version: 1
handoff_id: 8d50
parent_handoff_ids: [914a]
lineage: deterministic
chain: [standalone-3fd9]
repo: tendcf
workspace: main
branch: master
head_sha: 7a700f52ece529a58edda4e868d8da21b1f0bfc1
created_at: 2026-09-20T23:05:00-0400
writer: claude-code
---
# Handoff — PR1 merged, simulate-json probe posted, watchers armed

## The Goal
Land `--simulate-json` upstream if the maintainers want it; if permanently
rejected, fork-only and cut comms (memory: `simulate-json-is-the-point`). The
restart began with a small bug PR to rebuild trust (parent handoff 914a).

## Where We Are
- **PR1 merged.** cfengine/core#6332 (CFE-4742, the MapRemove bug) merged by
  larsewi 2026-09-02 as `cef66778f`; review: "the core fix is correct";
  backported in #6338 and #6339. The squash + `-s` request of 2026-08-25 was
  never applied; it merged as two unsigned commits (`5ddb6d97b`, `17dd60d99`).
- **Probe posted 2026-09-20:**
  https://github.com/cfengine/core/pull/6332#issuecomment-5754799717 — asks
  whether upstream wants `--simulate-json` (~+1500 lines) and in what pieces;
  names CFE-4716 as history; says it stays on the fork if not wanted.
- Fork PR #25 and issue #24 closed with merge links. Forks `djbclark/core` and
  `djbclark/libntech` verified 0 ahead / 0 behind upstream master.
- Register updated (`docs/architecture/upstream-register.md`, "PR1 MERGED" and
  probe notes); pushed through `7a700f5`. Tests run this session: none (docs
  and tooling only).
- Working tree: only `graft/.cache/session/*.json` is modified (graft's own
  cache; not ours, left unstaged).
- Files changed this session: the register; memory files
  `upstream-cfengine-commit-style.md` and `hindsight-hook-local-patches.md`;
  new scripts outside the repo (below).

## What We Tried
- **Hindsight `hindsight_reflect` looked broken.** Real cause: the SessionStart
  hook hard-caps reflect at 25s (`HOOK_REFLECT_CAP_MS`) while reflect takes
  6-23s under load; 14 failed vs 7 ok in `/tmp/hindsight-plugin.log`. Config
  `reflectTimeoutMs` is `Math.min`'d with that constant, so only patching dist
  works. First guess (server broken) was wrong: reflect took 12s directly.
- **Model trial (deepseek vs minimax-m3 vs kimi-k3)** on `hermes-shared`,
  low budget: all three 3/5 facts, 2/2 traps, no tool errors. The two misses
  were identical across models because low-budget reflect only searched mental
  models/observations, never raw memories. So quality is budget-bound, not
  model-bound. Latency numbers are unreliable: load average was 128.
- **Second trial round (mid/high budget) never ran.** Trial servers failed to
  start: embedded-Postgres "Instance already running" race, then 31s DB
  acquires. Pointing `HINDSIGHT_API_DATABASE_URL` at the running pg0 instance
  (127.0.0.1:5432, db `hindsight`) avoids the pg0 race. Orphan trial
  servers survived SIGTERM once; `pkill -9` cleared them.
- **`hindsight_s1_search.py neighbours` KeyError:** search prints event ids
  truncated to 14 chars; neighbours needs the full 64-hex id. Also the script
  is not executable (run with `python3`).
- **`hindsight-shared` tools absent:** server was still connecting at session
  start; `/mcp` reconnect fixed it.

## Key Decisions
- **Do not reopen CFE-4716.** It was Won't Do in the 2026-08-19 bulk closure
  with zero reviews on PR #6294 (+1549/-37) and no maintainer design comment
  (discussion #6296 closed "in favor of CFE-4716"). Reopening reads as
  re-arguing, drags back stale text (MapRemove now merged as CFE-4742; UTF-8
  workaround depends on rejected CFE-4730/4731), and Jira reopen permission is
  unverified. Chosen: probe on #6332, then a NEW small ticket if yes.
- **Keep the Hindsight model (deepseek); raise budget instead.** SessionStart
  reflect budget `low`->`mid`, cap 25s->45s, patched in 12 dist hook files.
  Rejected: switching model now (tie on quality, shared-server restart risk).
- **GitHub Actions rejected for the reply watcher.** We cannot add workflows to
  upstream, a fork workflow cannot see upstream comments without polling, and
  the Hermes cron already exists for this.

## Evidence & Data
- Probe comment: `cfengine/core#6332` issuecomment-5754799717.
- Merge: `cef66778f`; backports #6338, #6339.
- Model latency, unique 'ok' prompts: deepseek 51/21.7/500/13.7s, kimi
  2.2-5.4s, minimax 0.8-1.3s; full reflect (2 LLM calls) 4-46s under load 128.
- Hermes jobs created: `4c1b4bf1f975` "Hindsight Hook Patch Watchdog" (6h);
  `61817e4f5f4f` "core#6332 simulate-json probe watch" (12h, telegram).
- Scripts: `~/.hindsight/bin/reapply-hook-patches.sh`,
  `~/.hermes/scripts/hindsight-hook-patch-watchdog.sh`,
  `~/.hermes/scripts/core-6332-probe-watch.sh` (state:
  `~/.hermes/state/core-6332-probe.json`). Both watchers were tested end to
  end (silent when fine, warn/notify paths fired on simulated input).

## Operator Feedback
- "Be sure to remember the 'do the squash and -s before pushing' step" —
  saved into `upstream-cfengine-commit-style`.
- Asked that reflect timeout be 45s, and for a watchdog that survives package
  updates — both done.
- Corrected my reading: the closed ticket meant is a Jira ticket (CFE-4716),
  not the PR.

## Where We're Going
1. **Wait for upstream's answer to the probe.** The Hermes job `61817e4f5f4f`
   notifies on a reply and reminds weekly if none. Send nothing else upstream
   meanwhile.
2. On **yes**: file a NEW small ticket for slice 1 (file changes only; no
   package ops, no UTF-8 workaround), linking CFE-4716 as prior art. Squash and
   `git commit --amend -s` before pushing (memory
   `upstream-cfengine-commit-style`); Linux gate applies (memory
   `linux-gate-before-upstream`).
3. On **no**: fork-only and cut comms.
4. Independent: answer the 16 decisions on djbclark/core#23.
5. Optional: re-run the mid/high budget reflect trial when load is low.

## Quick Start
```bash
cd ~/src/tendcf && git pull --rebase
gh pr view 6332 -R cfengine/core --json comments --jq '.comments[-3:][]|{a:.author.login,b:.body}'
hermes cron list | grep -A8 "probe watch"
~/.hermes/scripts/core-6332-probe-watch.sh     # silent = no reply yet
~/.hindsight/bin/reapply-hook-patches.sh       # if the patch watchdog fires
```
