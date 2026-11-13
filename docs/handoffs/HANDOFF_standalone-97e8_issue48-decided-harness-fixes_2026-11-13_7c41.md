---
schema_version: 1
handoff_id: 7c41
parent_handoff_ids: [3a99]
lineage: continues
chain: [standalone-97e8]
repo: tendcf
workspace: tendcf
branch: master
head_sha: 485957ba3f2ec0dd7c10e5939121582b5c3b6178
created_at: 2026-11-13T11:40:00-05:00
writer: claude-code
---
# Handoff: issue 48 decided; four slices in flight (3 djbclark-ade, 1 tendcf docs)

Lead: Paseo agent 475563a7-7d37-4de3-b970-7fc37cb83410 (Claude session 29622301-22fe-4727-ad21-3f30b54dcfec), Opus 5.5, thinking `auto` (tendcf rule wants `high`: launch the successor with `--thinking high`). Predecessor e1ef4aa9 archived after ack.

## Where We Are

1. **Issue 48 D-a..D-d decided** by djbclark via /steps. Recorded in https://github.com/frdminc/tendcf/issues/48#issuecomment-6857866487 (boxes ticked) and `/Users/djbclark/.local/state/agent-reports/29622301/issue48-decisions.md` (authoritative, verbatim quotes). D-c assumption to confirm with djbclark: default two-job signer keeps the key as a GitHub environment secret (VM variant not chosen).
2. **djbclark-ade PR 649** https://github.com/djbclark/djbclark-ade/pull/649 (self-session handoff from a non-git cwd). Adversary: round 1 BLOCK, round 2 APPROVE at a5083fce; head now 32a9c1d0 (fragment PR number only). Checks were pending at 16:40Z; `bin/ade-merge-ready merge-now --prs 649 --yes` refused `tests_pending`, `adversary_marker=missing`. Owner PR: gate should pass without a marker once Tests are green; re-run merge-now. Worktree `~/src/djbclark-ade-self-session-nongit-wt` (claim `self-session-nongit`): remove after merge.
3. **djbclark-ade router stale-pool fix** (branch `fix/router-stale-pool`, worktree `~/src/djbclark-ade-router-stale-pool-wt`, claim `router-stale-pool`): aiuse payload `fresh=False` from one rate-limited pool (antigravity) made route_agent read every pool stale, so `plan` returned no route. Writer (Agent-tool sub-agent of the old session) is on repair round 2 after adversary BLOCK (Medium: malformed `stale_pools` entry made a stale pool read available). Report `/Users/djbclark/.local/state/agent-reports/29622301/router-stale-pool-out.md`, done marker `router-stale-pool.done`; adversary report `adv-router-out.md`. After repair: re-run adversary, open PR, fill `(#0)` in `changelog.d/fix-router-stale-pool.md`. ~40 pre-existing strict-ruff findings in route_agent.py / its tests left unfixed (import order near sys.path.insert): raise with djbclark (rule "always fix ruff").
4. **djbclark-ade Fable wait-not-degrade** (branch `fix/fable-wait-not-degrade`, worktree `~/src/djbclark-ade-fable-wait-wt`, claim `fable-wait`): djbclark ruling 2026-11-13 "If we are out of Fable use for a time period we should wait, not automatically degrade. If we already automatically degraded, we should make a list of stuff for Fable 5.2 to check on when it comes back, and we should have a timer to start up work 1 minute after the next time window starts." Removes `route_agent.py suggest_model` Fable→Opus swap; adds `bin/fable-wait add|ls|arm|fire` (one-shot wake at resetsAt+60 s via ade-sched, messages lead + hermes-ping). Report `fable-wait-out.md`, marker `fable-wait.done`. Then adversary, PR. Rule also landed in `~/CLAUDE.md` item 32 (site-public ca0da01) and memory `feedback_fable_short_wait_never_degrade.md` (site-private).
5. **tendcf docs PR** (branch `docs/d46-issue48-decisions`, worktree `~/src/tendcf-d46-decisions-wt`): Sonnet 5.5 high writer amends D46 + plugin-layout.md §4/§7 with D-a..D-d, F6-F10 wording, "planned" tags; must verify Nix flags. Report `/Users/djbclark/.local/state/agent-reports/29622301/d46-docs-out.md`, marker `d46-docs.done`. Not pushed as a PR: next is Astra (`gpt-6-astra` high) + Fable 5.2 high reviews (design ruling: both; plan with `route_agent.py plan --kinds frontier --repo tendcf --json`) + adversary, then PR; body names reviewers and verdicts.

All report files are under `/Users/djbclark/.local/state/agent-reports/29622301/`.

## Detached jobs

The three writers are Agent-tool sub-agents of the old Claude session and die with it. A successor checks each report/`.done`; an unfinished one is re-launched as a new slice in the same worktree after `git -C <wt> status` / `log -3` (finish or discard the partial diff it left; never stash). No Paseo job records.

## Where We're Going

1. Merge PR 649 when green; remove its worktree.
2. Collect router repair → adversary → PR → merge.
3. Collect fable-wait → adversary → PR → merge.
4. tendcf docs: collect → Astra + Fable + adversary → PR (restructure stays blocked on #41/#42 too).
5. Ask djbclark: D-c GitHub-secret default; the pre-existing ruff findings.
6. Operator item carried from 3a99: `sudo-secretspec template-check` drift after `PYPI_API_TOKEN` add.

## Decisions

- [ruling] D-b: "I want people to be able to easily share configurations, but they should be security-scanned before running them, including doing so with the help of AI. We can have a soft requirement that access to AI be present whenever an external import is attempted." + "Do 1, but make a toml config file option (or whatever format we are using) to allow different options/override and doc that." (djbclark, 2026-11-13)
- [ruling] D-c: "3, but we want to leave the unix user as a non-default option in the first real release." (djbclark, 2026-11-13); hardware token optional, never default/required.
- [ruling] Fable short: wait, never degrade (quoted above).
- [decision] D-a option 1; D-d option 1 (promote the PR's own artifacts).

## Relations

- continues [[HANDOFF_standalone-97e8_nix2cf-fold-in-adversary-block_2026-11-13_3a99]]
