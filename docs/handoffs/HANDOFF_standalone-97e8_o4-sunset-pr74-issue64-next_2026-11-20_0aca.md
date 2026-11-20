---
schema_version: 1
handoff_id: 0aca
parent_handoff_ids: [e985]
lineage: deterministic
chain: [standalone-97e8]
repo: tendcf
workspace: main
branch: master
head_sha: 80397092e48a63eb4f29dc88953971a299caa21b
created_at: 2026-11-20T15:45:00+00:00
writer: claude-code
---
# Handoff — O4 docs-freeze sunset (PR 74) and issue64 next

## The Goal

Continue as LEAD tendcf, succeeding 0aca72cb-ef64-4eb3-b498-d93de4dc8f60 (which succeeded archived d8aa3237 on 2026-11-20 via C1 native fallback, token 7aef6829). Finish PR 74, then issue64 as a schema PR plus errata, then renderer issue70.

## Where We Are

1. PR https://github.com/frdminc/tendcf/pull/74 (branch o4-docs-freeze-sunset, head d105fb0, worktree /Users/djbclark/src/tendcf-o4-sunset-wt, claim tendcf-o4-sunset-0aca). Records operator ruling 2026-11-20 "1. Clarify + sunset" on O4 in AGENTS.md rule 3 plus an erratum at 14-synthesis-and-rulings.md B10. Fable 5.2 high review: round 1 REQUEST-CHANGES (fixed a4ed3b6), round 2 APPROVE-WITH-NITS (N1-N4 fixed d105fb0; reviewer said no round 3 needed if N1 fixed as worded, which it was). Reports: /Users/djbclark/.local/state/agent-reports/0aca72cb-ef64-4eb3-b498-d93de4dc8f60/pr74-o4-fable-review.md and -r2.md. Reviewer 9bc77c03 archived. CI was pending at handoff. NEXT: when all checks green, gh pr merge (pre-authorized once green), then release claim tendcf-o4-sunset-0aca and remove the worktree.
2. Issue64 worktree /Users/djbclark/src/tendcf-issue64-design-wt (branch issue64-standing-approval-design at 8039709, claim tendcf-issue64-design-0aca, owner 0aca72cb; rebind to successor). Nothing written yet. Per the O4 option text, issue64 proceeds as a SCHEMA PR PLUS ERRATA, not a new design doc. Start from /Users/djbclark/.local/state/agent-reports/0aca72cb-ef64-4eb3-b498-d93de4dc8f60/issue64-next-step.md (contrast of issue wording vs the four Nov 19 rulings; approval-record schema_version const 6 shared family with goal-file/goal-diff; required fields include nonce + per-host approval_seq; no signer/sig_alg). Reviews: two frontier (Astra + Fable; Argon once) + adversary; fresh route plan before each.

## Key Decisions

- [ruling] "1. Both, in parallel (Recommended)" (djbclark, 2026-11-20; Fable-use chooser: wake CF owner for its Fable contract review and draft issue64 in parallel).
- [ruling] "1. Clarify + sunset (Recommended)" (djbclark, 2026-11-20; O4 chooser). Option text: "Keep O4, but schema files, fixtures, errata and operator-ordered design reviews (like Q4) are not frozen. The freeze lifts per piece once a spike has run or you order a design review. Issue 64 then proceeds as a schema PR plus errata."
- [ruling] djbclark 2026-11-20: "Report any harness issues like [the review-launch Fable kill] to b0b47ad8-8801-4780-a8e0-08824cd5ce27 -- loosing fable work is not acceptable. At minimum we should not automatically stop it, but ask the user what to do." Saved to memory feedback_tell_ade_lead_about_ade_bugs.md.
- [audit] No past decision was caused by O4 (report /Users/djbclark/.local/state/agent-reports/a3a60366-723d-4e18-85ae-6aed87255f53/audit-past-o4-docs-freeze-impacts-report.md). B5 stock/Termux spike not run: Termux/Android design docs stay frozen.

## Peers and holds

- CF owner 70c67088 ran CF-specific Fable V4 review; review-launch exit 77 killed it (spool Read outside worktree), no verdict. Harness owner b0b47ad8 is SINGLE fix owner (pause-and-ask for frontier boundary hits, spool in allowed reads, preserve resumable sessions); ADE lead f0012d80 stopped its parallel worker and handed patch ~/.local/state/ade/review-spool-handover/spool-wip.patch to b0b47ad8. 70c67088 waits for that fix; no relaunch. All acked.
- Astra f59014da parked, closed, ade.lead=0aca72cb (rebind to successor without waking).
- Fable CF-feature-contract gate, root/pin/deploy/storage holds unchanged.

## Quick Start

Read Tier 1 /Users/djbclark/.local/state/handoffs/chains/standalone-97e8/SESSION_LOG.md and this file. gh pr checks 74 --repo frdminc/tendcf; merge when green. Then issue64 in its claimed worktree (absolute paths).
