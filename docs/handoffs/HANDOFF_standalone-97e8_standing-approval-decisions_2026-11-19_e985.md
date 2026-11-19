---
schema_version: 1
handoff_id: e985
parent_handoff_ids: [e3c0]
lineage: deterministic
chain: [standalone-97e8]
repo: tendcf
workspace: main
branch: master
head_sha: e003445f02937e79d00a956fe86c3606fba5ded0
created_at: 2026-11-19T16:15:10.169142+00:00
writer: codex
---
# Handoff — standing approval decisions and tendcf lead continuity

## The Goal

Continue as LEAD tendcf, succeeding d8aa3237-635e-4198-ae4c-99403dea5cc5. Operator chose issue64 FIRST, then an acknowledged handoff and continuation on 2026-11-19. Preserve these rulings before doing design; do not re-ask settled choices. Issue: https://github.com/frdminc/tendcf/issues/64.

## Where We Are

Main is master at e003445f02937e79d00a956fe86c3606fba5ded0 before this handoff-only commit, clean, remote https://github.com/frdminc/tendcf.git. This file is the only new tracked file; repo AGENTS permits handoff-only commits directly on master. No source/tests/builds/runtime/pin changes by this lead. No claims or dispatched writers. No tests run; this is a documentation/coordination handoff. Check current HEAD and the refreshed Tier1 pointer, whose anchor includes this handoff commit.

Issue64 is OPEN, with zero comments at audit. Its text and AGENTS still carry an interim ordinary-only rule and unruled X-trust-06. The four operator choices below supersede the interim intent; the exact approval-record schema is NOT yet designed, implemented, reviewed or deployed. Record them in the ordinary reviewed design/doc flow, not by silently changing trust enforcement or skipping reviews. This handoff is durable preservation of rulings, not schema approval or a live permission grant.

## Key Decisions

1. Standing approvals may cover ordinary, privileged AND baseline classes, with separate explicit owner enrollment for each. Operator rejected limiting coverage to ordinary or ordinary+privileged.
2. A standing grant is reusable, with persistent per-device replay state for each application. Operator rejected requiring a fresh grant signature for every change. Exact grant generation/application sequence/high-water persistence, atomicity and crash rules still need design; do not interpret reusable as replayable.
3. Outside developer mode an owner may enroll any explicitly trusted signer within the stated scope, including chosen automation/organizational signers. Operator rejected restricting this to owner-held signing keys. Distinguish who grants owner authority from whose updates are covered; define those roles in the schema.
4. Adopt X-trust-06: signer identity and signature algorithm are in signed approval bytes, must match actual verification, and cannot create trust or enable an unapproved algorithm.
5. Revoke/deny, persisted rejects, freshness, device/target binding, validator-derived ceremony checks and other existing checks remain mandatory. Standing approval is explicit owner enrollment, never default. Do not use any of these choices to waive the independent review/CI/consent rules.

## Decisions

- [ruling] "3. Include all classes" (djbclark, 2026-11-19; issue64 change-class chooser, separate explicit enrollment per class).
- [ruling] "1. Reusable grant (Recommended)" (djbclark, 2026-11-19; issue64 replay chooser, persistent per-device application replay state).
- [ruling] "1. Owner-enrolled trusted signers (Recommended)" (djbclark, 2026-11-19; issue64 signer chooser, outside developer mode).
- [ruling] "1. Bind both fields (Recommended)" (djbclark, 2026-11-19; issue64 X-trust-06 signed signer/algorithm chooser).
- [ruling] "1. Prioritize issue 64 (Recommended)" (djbclark, 2026-11-19; loose audit work-priority chooser).
- [ruling] "1. Handoff and continue (Recommended)" (djbclark, 2026-11-19; loose audit session chooser).
- [decision] Preserve the rulings in this append-only handoff first; ordinary rule/schema changes retain the required PR/review process. No source implementation is claimed.

## Relations

- continues [[HANDOFF_standalone-97e8_pr49-50-merged-harness-fixes_2026-11-14_dd79]]
- decided_in [[HANDOFF_standalone-97e8_standing-approval-decisions_2026-11-19_e985]]

Primary continuation is deterministic from native checkpoint /Users/djbclark/.local/state/agent-reports/bfe5e91a/checkpoint-e3c0.md (handoff e3c0, chain standalone-97e8); the linked older repo handoff is historical same-chain recovery context. Do not replay obsolete pauses/tasks from the November6/14 Tier1 snapshots.

## What We Tried

The lead recovered bfe5e91a and failed Pi successor8df34f34, then coordinated custody with additional Codex lead0d23043e before taking ownership. Never infer a running provider from a stale UI spinner: bfe was idle, while8df had an actual managed Go credential-resolution error. Stale manual quota had also been mistaken for usable funds; require fresh provider/pool evidence. An ack alone is not a real successful work turn.

Native MCP archive_agent historically archived the caller when given a different target; https://github.com/getpaseo/paseo/issues/10118 remains OPEN at audit. Cleanup used exact CLI targets and verified identities. No destructive bug reproduction. Predecessors bfe5e91a/8df34f34/0d23043e and completed Argon review2f620764 are archived. Retained Astra f59014da-2296-44d9-a144-50993ee29201 is closed/parked, with no active assignment; do not wake it merely to transfer custody. Its lead label currently names d8aa3237.

Several reads were too large. Extract fields and cap combined output before printing; do not dump the1.38MB feature contract or all live-agent JSON. GitHub queries must use the verified remote owner/repo and separate --repo argv; do not guess an organization. Sandbox may block Electron/Paseo with uv_uptime EPERM: use the required escalation, not daemon restart or an alternative tool to bypass permission.

## Evidence & Data

Private durable lead reports: /Users/djbclark/.local/state/agent-reports/d8aa3237-635e-4198-ae4c-99403dea5cc5/lead-notes.md and sibling review artifacts. They contain summarized findings, not public transcripts. In that folder: harness-investigation.md, tendcf-receipt-adapter-review.md, tendcf-feature-contract-review.json, tendcf-v3-owner-amendments-b848.json, tendcf-v4-targeted-owner-review.json, fork-retention-semantic-review.md, fork-retention-v2-automation-review.md and retention-automatic-frontier-semantic-review.md.

ADE fix owner b0b47ad8-8801-4780-a8e0-08824cd5ce27 acknowledged ownership. Credential diagnostics merged in https://github.com/djbclark/djbclark-ade/pull/790 (77c421d5), real-turn/custody fixes in https://github.com/djbclark/djbclark-ade/pull/791 (00d490be); focused/Linux checks passed. This lead did NOT verify repaired live scenarios or every Carried73 subitem. Queue73 remains; avoid calling it all complete or redoing already merged work.

Fork-maintenance owner a9a65e9f-d2d4-48ba-9d11-778025af9f77; CF owner70c67088-dfb7-469b-aa43-6cf3e747ee6e (closed/nonarchived at latest audit, ownership explicitly confirmed earlier). Inspect continuity before messaging; closed alone does not imply replaced. No successor for70 was verified. Root private reports are under /Users/djbclark/.local/state/agent-reports/a9a65e9f-d2d4-48ba-9d11-778025af9f77/.

Feature contract V4 there: tendcf-feature-contract-proposed-v4.json, SHA25672f548543bd5d2ebfa2a801deeaa3a193ff99faa1176b725f2978d83278669f9,1376679bytes,35 features/186 paper records/25 unmapped obligations; all351 measured-evidence arrays empty, completeness false at review. Fidelity APPROVE means translation only. CF semantics/inventory/API boundaries, exact selectors/fault controls, actual coupled-build evidence and permanent retention remain HOLD.

Independent CF-specific Claude Fable5.2 owner gate remains pending, with no qualifying reviewed-digest/verdict delivered here. Do not claim an active Fable dispatch. The old ADE fable-wait item fw-20261118T155906Z-27e237 was CLOSED after operator clarified Astra is acceptable for the ADE fork-maintenance task. ADE Astra review does not satisfy the separate CF gate. Standing-approval issue64 is a DIFFERENT design review; do not conflate it with the fork feature contract. Fresh quota/admission and existing review tiers apply to both workstreams.

Storage proposals are unselected, not live resources: no approved account, identity, term, budget, scheduler, destination, enrollment or runtime consent. Root reports fork-evidence-retention-proposal-v2.md SHA2564ae4227bac4550baa5b0452db3b6ab9a47ea9d35a106f24dd3ab9d349cbb0175; automation supplement SHA25690607f810695be437ca0966c094eada840f9e9afb326e2fa8c1e069a89814105; latest custody-transition supplement fa2fb25d38dd8f0cd398abcff4457d42adc3c32aa905b1d452013d0ca5e02b04,13514bytes. Root reported our phase-gated acceptance/fixed renewal census concerns resolved there; this lead has NOT independently reviewed that latest supplement. Default-deny ADE source/offline checks are not cloud proof or permission. No storage/CF action or additional paper rewrap is owed unless a real gap or owner request remains.

## Operator Feedback

Work from actual source/config/live evidence. No duplicate writers, no repeated settled questions, no dropping paid work. Heavy builds via CI; focused local validation through current approved bgrun/load gate when required. No macOS runs without ADE go-ahead, no public upstream CF/NorthernTech submissions without operator per-PR consent. Preserve parked /Users/djbclark/src/tendcf-s5-design-wt. Never run a browser/open local files merely to inspect them. Keep reports bounded and honest about unverified live behavior.

## Where We're Going

1. Read this handoff, refreshed Tier1 and issue64; prepare the exact standing-approval schema/replay design from the four settled rulings. Do not re-interview them. Start with grant scope/issuer versus covered signer, application counter persistence and rejected-change/revocation/crash semantics; retain signed identity/algorithm binding. Verify actual schema version before proposing its bump. Use a claimed workspace for ordinary design edits and the required independent review tier (two frontier reviews for design/trust changes, plus adversary where ADE requires it).
2. Verify native handoff identity/ack and complete a first real work turn before claiming successful succession; notify current ADE/fork/CF peers and rebind owned parked reviewer label without waking it. Use the native transaction accept/finish protocol; archive only exact idle predecessor after verified custody. Never archive a workspace holding successor.
3. After issue64 design, inherited launchd-renderer work remains: /Users/djbclark/.local/state/agent-reports/0d23043e-c7ef-4572-9354-e12a611c431e/launchd-renderer.brief.md; https://github.com/frdminc/tendcf/issues/70 OPEN. No renderer worker launched. Fresh quota/router/load admission required, no credit for vanished old admission. Root code requires two frontier reviews and adversary before PR; Linux CI only, dry-run propagation and foreground cf-execd preserved.
4. CF/Fable/retention holds stay independent; collect genuine substantive updates from owners, not new approvals on every routine candidate. Harness repairs are partly merged; live proof/remaining queue items belong to ADE owner, not a new takeover.
5. Audit unrelated changes only read-only. At last sweep tendcf/ADE/site-public clean; paseo/stayturgid/site-private and core submodule contained changes NOT made by this lead. Site-private behind one at audit; do not stash/reset/stage their changes or repair the mismatched core/libntech checkout blindly.

## Detached jobs

None owned by this lead. No agent subtask or renderer dispatch, tests, local server or terminal remains running from this lead. Other leads' workers are not ours to stop. Private report artifacts are intentional continuity material, not disposable test probes.

## Quick Start

Read /Users/djbclark/.local/state/handoffs/tendcf/main/SESSION_LOG.md and this file, then git -C /Users/djbclark/src/tendcf status --short --branch. Fetch issue64 with gh issue view64 using explicit repo frdminc/tendcf (separate argv: gh issue view 64 --repo frdminc/tendcf). Use current ADE routing/claims/self-session docs, not stale shell flags copied from history. No credentials or raw configs are needed to resume.
