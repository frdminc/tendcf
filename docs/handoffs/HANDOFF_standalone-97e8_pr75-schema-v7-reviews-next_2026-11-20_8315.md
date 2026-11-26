---
schema_version: 1
handoff_id: "8315"
parent_handoff_ids: [b6fd]
lineage: deterministic
chain: [standalone-97e8]
repo: tendcf
workspace: main
branch: master
head_sha: 3fb6418298cf50b160ff4c3c1020bf6f992f887b
created_at: 2026-11-20T16:40:00+00:00
writer: claude-code
---
# Handoff — PR 75 (issue64 schema v7) open; frontier reviews next

## The Goal

Continue as LEAD tendcf, succeeding 831528bb-528a-475a-a27c-0afc87f6ad54 (which succeeded archived b6fda1b6 via acknowledged self-handoff c813c263). Get PR 75 through the design-ruling review tier and merged, then renderer issue70.

## Where We Are

1. PR https://github.com/frdminc/tendcf/pull/75 OPEN at 0e456c2, branch issue64-standing-approval-design, worktree /Users/djbclark/src/tendcf-issue64-design-wt (clean, pushed), claim tendcf-issue64-design-b6fd (owner 831528bb; finish rebinds it to the successor). CI: not yet read.
2. Content: approval-record v7 (record_kind per-change / standing-enrollment / standing-application; signer + sig_alg on every record, X-trust-06; per-grant application_seq high-water persisted before apply; persisted rejects win; most-restrictive mode wins; enrollment accepted only through the owner ceremony of its highest class). Whole goal-file family bumped 6 -> 7 (fixtures, 109 rehashed goal-file hashes, compiler constant/goldens, deploy canary/passthrough; case 13 -> v8). New examples approval-enrollment.json, approval-application.json (schema-only). Negative cases 177-183. Errata: AGENTS.md Android item 5 rewritten; erratum paragraphs after every L5 reading copy and the 14-synthesis agenda; label "(lead decision, PR 62 review)".
3. Local validation run by the lead: tools/schema_lint.py OK (8 schemas, 153 negative, 6 byte, 28 projection), tools/xref_lint.py 0 findings (needs `uv run --with jsonschema --with referencing --with pyyaml --with rfc8785`). Worker ran compiler tests, check_schema_version.py, canary check: pass. Not run: tests/policy/run.sh, Linux legs (CI).
4. PR body lists 7 reviewer questions (family bump vs split, no nonce on enrollment, optional not_after, developer_mode field, terminal revoke, precedence, no per-domain scope) and the deferred enforcement-time negatives.

## Next

1. Read PR 75 CI; fix red legs.
2. Design-ruling tier: two independent frontier reviews, Astra (codex gpt-6-astra high) then Fable (high); Argon stands in once, never twice; plus adversary. Before each admission: `aiuse --available --json`, `paseo usage ls --json`, fresh `~/src/djbclark-ade/bin/route_agent.py plan --kinds frontier --repo tendcf --json`; brief reason `tendcf standing rule: cross-model review`. Parked Astra f59014da has ade.lead=831528bb (rebind to successor without waking). Fable boundary hit: pause and ask, never auto-stop.
3. Quote verdicts in the PR body; disagreements go to djbclark. Merge (pre-authorized) when reviews pass and CI is green; comment on issue 64; release claim, remove worktree.
4. Then renderer issue70.

## Key Decisions

- [ruling] djbclark 2026-11-19: all-class standing grants; reusable grant with per-device replay state; any explicitly trusted enrolled signer outside dev mode; X-trust-06 adopted.
- [ruling] djbclark 2026-11-20 O4 "1. Clarify + sunset": issue 64 proceeds as a schema PR plus errata.
- [lead proposal] family bump together to v7 (Q4 left grouping to the review).

## Peers and holds

- Custody of 831528bb acked by f0012d80 (ADE lead), b0b47ad8 (harness), 70c67088 (CF owner). Fork owner a9a65e9f not messaged.
- Fable CF-feature-contract gate, root/pin/deploy/storage holds unchanged.

## Quick Start

Read Tier 1 /Users/djbclark/.local/state/handoffs/chains/standalone-97e8/SESSION_LOG.md and this file; then PR 75.
