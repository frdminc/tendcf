---
schema_version: 1
handoff_id: b6fd
parent_handoff_ids: [0aca]
lineage: deterministic
chain: [standalone-97e8]
repo: tendcf
workspace: main
branch: master
head_sha: a4ea4fc955b75a4f4a7560b07054616f854eb165
created_at: 2026-11-20T15:58:00+00:00
writer: claude-code
---
# Handoff — PR 74 merged; issue64 schema PR plus errata next

## The Goal

Continue as LEAD tendcf, succeeding b6fda1b6-ecba-45c8-b994-43115f8d9090 (which succeeded archived 0aca72cb on 2026-11-20 via C1 native fallback, token 142433e6). Do issue64 as a schema PR plus errata, then renderer issue70.

## Where We Are

1. PR https://github.com/frdminc/tendcf/pull/74 MERGED 2026-11-20T15:52:16Z as merge commit a4ea4fc (all 7 checks green at reviewed head d105fb0; Fable 5.2 high r1+r2). Worktree removed, local branch deleted, claim tendcf-o4-sunset-b6fd released. Remote branch o4-docs-freeze-sunset left (delete_branch_on_merge is off).
2. Issue64: worktree /Users/djbclark/src/tendcf-issue64-design-wt, branch issue64-standing-approval-design fast-forwarded to a4ea4fc, clean, nothing written. Claim tendcf-issue64-design-b6fd (owner b6fda1b6): the successor must take it over (see Peers: release + new claim is the ruled path for a C1 fallback; via `successor-of` only if the helper record exists).
3. Outline to start from: /Users/djbclark/.local/state/agent-reports/b6fda1b6-ecba-45c8-b994-43115f8d9090/first-turn-pr74-issue64-outline.md section II, plus /Users/djbclark/.local/state/agent-reports/0aca72cb-ef64-4eb3-b498-d93de4dc8f60/issue64-next-step.md. Basis: AGENTS.md rule 3 O4 text (now on master): "Issue 64 then proceeds as a schema PR plus errata"; lead reading: a new design section in an existing doc counts as a new design doc, so rationale goes in the PR body and schema descriptions; cite the O4 ruling and Q4/L60 in the PR.
4. Tier: schema_version bump (approval-record const 6, shared family with goal-file/goal-diff) + trust-root = design-ruling tier: two independent frontier reviews (Astra then Fable; Argon stands in once, never twice) plus adversary; fresh `route_agent.py plan --kinds frontier --repo tendcf --json` with aiuse + paseo usage readings before each admission. Validate locally (schema_lint, xref_lint) before the PR.

## Key Decisions

- [ruling] "1. Clarify + sunset (Recommended)" (djbclark, 2026-11-20; O4). Recorded by PR 74 in AGENTS.md rule 3.
- [ruling] djbclark 2026-11-19: all-class standing grants (each class enrolled explicitly); reusable grant with persistent per-device replay state; any explicitly trusted enrolled signer outside dev mode; signed signer/algorithm binding (X-trust-06 adopted).
- [ruling] djbclark 2026-11-20: harness issues go to b0b47ad8; losing Fable work is not acceptable, a boundary hit must pause and ask, never auto-stop. b0b47ad8 is single fix owner for the review-launch exit-77 CF Fable kill.
- [peer ruling] b0b47ad8 2026-11-20: a C1 native-fallback takeover has no claim-rebind path (bind-owner refuses another owner; successor-of needs a handoff-<uuid>.json helper record). Use release + new claim; b0b47ad8 owns the tooling fix.

## Peers and holds

- Custody announced and acked by ADE lead f0012d80, harness owner b0b47ad8, CF owner 70c67088 (waits on b0b47ad8's exit-77 fix, no relaunch). Fork owner a9a65e9f notified, no ack requested.
- Astra f59014da parked/closed, ade.lead=b6fda1b6 (rebind to successor without waking).
- Fable CF-feature-contract gate, root/pin/deploy/storage holds unchanged.

## Quick Start

Read Tier 1 /Users/djbclark/.local/state/handoffs/chains/standalone-97e8/SESSION_LOG.md and this file. Take over claim tendcf-issue64-design-b6fd, then draft the issue64 schema PR in /Users/djbclark/src/tendcf-issue64-design-wt (absolute paths).
