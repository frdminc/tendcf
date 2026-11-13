# v6: verification of reports 09 (safety/TUI), 10 (trust), 13 (pre-mortem)

Checker: Opus 5.5, read-only. Repo anchors were read at worktree `eefea3c` (`the review worktree`). Web pages were fetched 2026-11-13 through the shared `mcp__firecrawl__*` tools. arXiv metadata came from export.arxiv.org and the PDFs were scraped. Licences and push dates came from the GitHub API.

Verdicts: confirmed 43, weakened 24, refuted 0, unverifiable 3. Rows marked "ruling" have proposed text that drops part of rulings row 8, or decides something the owner has not decided.

| Item | Verdict | Evidence (one line) | Correction |
|---|---|---|---|
| 09 Summary 1 | confirmed | VAL:869-871 "'Approved' means 'adopted by root on the host'"; map §9.1 at :526 | none |
| 09 Summary 2 | confirmed | Framed as a question (X-safety-10); the "%" vs "/100" choice is left to the owner | none |
| 09 Summary 3 | weakened | Textual pyproject 8.2.8 has `python = "^3.9"`, not 3.11+; the Termux evidence is old Textual Discussion #583 only; Toad's last push was 2026-05-26 | C1 |
| 09 Summary 5 | weakened | 2604.04978 v3: 81.0% is end to end, and 36.8% of actions never reached the classifier; on the actions it evaluated, FNR was 70.3% and FPR 31.9% | C2 |
| 09 Q1 TerraProbe | weakened | 2606.26590: 71.4% are "deceptive fixes that pass automated checks while leaving the underlying vulnerability in place", not "changing behaviour" | C3 |
| 09 Q1 IntelliSA | confirmed | 2601.14595 (MSR 2026): F1 83% | none |
| 09 Q2-1 | confirmed | 2604.04978: 81.0% (CI 73.8–87.4), vendor figure 17%, 36.8% out of scope; the authors call it "a fundamentally different workload" | add the 70.3% figure (C2) |
| 09 Q2-2 | weakened | 2312.12575: the 26%/17% flips come from renaming function or variable names *or adding library functions*; the paper reports them as a robustness failure | C4 |
| 09 Q2-3 | confirmed | 2403.17710 v5 (CCS 2024), 2302.12173, 2608.28411 (code review is one scenario); JudgeDeceiver is gradient-optimised against a pairwise "pick the best response" judge | transfer note (C5) |
| 09 Q2-4 | weakened | 2606.03437 measures six open-weight models on three QA benchmarks: an answer gets higher confidence when framed as the model's own chat turn than as user input; it does not test a fresh scan of a diff the same model wrote | C6 |
| 09 Q2-5 | confirmed | 2006.14779 (CHI'21) "regardless of its correctness"; 2001.02114; 2405.00623 (FAccT'24, N=404, medical questions) | none |
| 09 Q3-1 | weakened | 2306.13063 §B.1: 0.522→0.605 is the gap between black-box and white-box AUROC, averaged over five datasets; it is not a white-box figure for professional knowledge; best ECE reaches 0.028 | C7 |
| 09 Q3-2 | confirmed | 2305.14975 (EMNLP 2023), TriviaQA/SciQ/TruthfulQA | none |
| 09 Q3-3 | weakened | 2207.05221: P(IK) "partially generalize[s] across tasks, though they struggle with calibration of P(IK) on new tasks" | C8 |
| 09 Q3-4 | confirmed | 2305.18404 (multiple-choice QA) states exchangeability; "a hostile author breaks it" is the report's inference, which is sound | none |
| 09 Q5 table | weakened | GitHub API: Textual MIT, Toad AGPL-3.0, textual-diff-view AGPL-3.0, Mosaic Apache-2.0 (confirmed); the Toad README says "runs on Linux and macOS", says nothing of Termux or "permission prompts", and Toad/textual-diff-view have had no push since 2026-05-26/27 | C9 |
| 09 Q5 GPLv3 §13 | unverifiable | Neither the report nor this check fetched gnu.org; the well-known §13 text agrees | fetch https://www.gnu.org/licenses/gpl-3.0.html §13 before the licence ruling |
| X-safety-01 | weakened (ruling) | Anchors confirmed (map:103-125; R6/R8/R9 absent, R14 unused); the proposed R14 says "safety score out of 100", dropping "confidence" and "%" from row 8, yet Merge is "insert after it" with no ruling | C10 |
| X-safety-02 | weakened (ruling) | (d) "never as a percentage, until a calibration corpus exists" is written as settled; Merge does name the score ruling | C11 |
| X-safety-03 | confirmed | VAL:864-876 | none |
| X-safety-04 | confirmed | `schema/approval-record.schema.json`: `briefing_sha256` is "Optional: binds the record to the briefing bytes the person actually saw, when one was shown." | none |
| X-safety-05 | confirmed | map:910 "Verifiable layer authorizes" | none |
| X-safety-06 | weakened | The cited paper does not show what the finding claims (see Q2-4); the apt source is Panickssery et al., arXiv 2404.13076 (self-preference in LLM evaluators); not fetched here | C6 |
| X-safety-07 | confirmed | map:1281-1285 "Countable once real diffs exist." | none |
| X-safety-08 | confirmed | map:1160 (Android deferred), :1167 (Step 9 consent surface) | none |
| X-safety-09 | confirmed | map:576-590 ("Serialization noise is camouflage" at :578); :1281 | none |
| X-safety-10 | confirmed | Correctly a question, needing a ruling | none |
| X-safety-11 | confirmed | Licences confirmed; map §6 "Take (code or a thin wrapper)" at :332; map:120 "GPL-3.0-or-later for code" | add that the AGPL candidates have had no push for about six months (C9) |
| X-safety-12 | confirmed | map:853-876 ("Effects versus declarations" at :863); VAL:489 | none |
| 10 A3 | confirmed | TUF 1.0.37 §1.5.2 "cannot prevent updates from good mirrors"; VAL:466-474 "before parsing anything else" | none |
| 10 A4 | confirmed | map:929 "not tenable once devices belong"; Tailnet Lock page quote (validated 2025-12-02) | none |
| 10 A5 | weakened | G3 itself ends "The architecture is not changed by these words"; row 6b says "I am not trying to change the architecture", and that architecture (map §9.11, §10) already authenticates by content signature and authorises by approval record | C12 |
| 10 B1 (TUF) | confirmed | TUF 1.0.37 (2026-10-08): intermediate-root expiry (5.3.6), freeze limited by expiry, mix-and-match, step-11 deletion of timestamp/snapshot on key rotation | none |
| 10 B (Uptane) | confirmed | Uptane 2.1.0: Director "mostly controlled by automated, online processes"; release counter; hardware id; "ECUs SHALL have a secure source of time" | analogy note (C13) |
| 10 B7 (Tailnet Lock) | confirmed | KB 1226: Android "cannot be used for signing operations"; TOFU; lost disablement secrets mean the tailnet "cannot be recovered" | none |
| 10 C Syncthing row | confirmed | syncthing/syncthing-android archived (last push 2024-12-03, MPL-2.0); Catfriend1 redirects to researchxxl/syncthing-android (Syncthing-Fork, active, push 2026-11-12); package id `com.github.catfriend1.syncthingfork` (from the fork's README) | add a single-maintainer risk note: the fork changed hands in 2025 |
| 10 C Nebula row | weakened | Nebula README: the lighthouse is a discovery node, "(Optional, but you really should..)"; the root of trust is the offline CA (`ca.key`); `static_host_map` exists; CA default 1 year confirmed | C14 |
| 10 C Tailscale row | weakened | KB "What happens if the coordination server is down?" (validated 2025-05-02): the network "mostly continue[s] to function"; the server is needed for join, key refresh, ACL change and revocation | C15 |
| 10 D1 | weakened | Apple's "Protecting keys…" page says "Works only with NIST P-256", but the current CryptoKit `SecureEnclave` docs also list MLKEM768/1024 and MLDSA65/87; Curve25519 is software-only; StrongBox list and Android clock quote confirmed (Keystore page, 2026-10-23) | C16 |
| 10 D2 | confirmed | Ed25519-only pattern confirmed and no other algorithm appears in `schema/`, but the list misses `schema/goal-diff.schema.json:15`; KeyMint v2 Curve25519 is a HAL statement (source.android.com, 2026-09-30) | C17 |
| 10 D3 | weakened | map §10: an `operator`-tier device needs no local yes, so "cannot make the phone apply" holds only for a `consented` phone (or if G4 makes see-and-refuse universal) | C18 |
| X-trust-01 | weakened | Same as A5; the proposed text also narrows G3's "any other device" to holders of "release keys this device enrolled at first run"; Merge is correctly ruling-first | C12 |
| X-trust-02 | confirmed | TUF steps; Keystore clock quote confirmed | none |
| X-trust-03 | weakened (ruling) | map:917 "Push: any host holding `deploy-origin`" also sets push semantics for `operator` hosts; the replacement drops them and makes "Pull is the default", a design change, yet Merge is "replace that paragraph" | C19 |
| X-trust-04 | confirmed | map:935-941 trust table | none |
| X-trust-05 | weakened | Schema facts confirmed; "works only with NIST P-256" is outdated (ML-DSA exists); misses goal-diff:15; KeyMint v2 is a HAL-level statement | C17 |
| X-trust-06 | confirmed | approval-record `signature`: "Exact encoding is residue, not decided here"; no signer or algorithm field | none |
| X-trust-07 | confirmed | map:885 "The 2-of-3 is a **floor**", :893 "None of those is built."; correctly limited to `consented`; ruling-first | analogy note (C13) |
| X-trust-08 | confirmed | guide:1607 Q15 sentence; Keystore "authorizations can't be changed" | none |
| X-trust-09 | confirmed | guide:50-52 "no always-on central server"; TUF freeze checks | none |
| X-trust-10 | weakened | The mesh clause overstates: Nebula lighthouses are discovery, not trust; Tailscale/Headscale traffic survives a coordinator outage (C14, C15) | C20 |
| X-trust-11 | confirmed | VAL:492 (row writer); journald `Seal=` not fetched by me | none |
| X-trust-12 | unverifiable | Recovery table not checked line by line; a key-recovery plan is a design ruling under the repo's standing rule, but Merge is "insert after that sentence" | check, and make Merge ruling-first |
| 13 E1 | weakened | `git rev-list` at eefea3c: 446 commits / 400 non-merge / 242 docs-only / 70,312 docs lines; the report's 444/398/240/70,142 are at 40cf93a; code-touching commits are 123 (131 with `.github`), not 124; "about 19,600" includes `.github` (19,212 without) | C21 |
| 13 E2 | unverifiable | The "quarter upstream" count was not re-derived | needs a commit classifier over history §E |
| 13 E4 | confirmed | `.github/workflows/` holds only check.yml and linux.yml; neither mentions macOS | none |
| 13 E5 | confirmed | `rg` for island/insular/work profile/shizukuplus, handoffs excluded, finds only 00-goal-definition.md; FleetProfileApplier.kt:18-28 has 8 keys | none |
| 13 E7 | confirmed | 42 PRs; 40 merged, median 0.25 h, 33/40 under 1 h; #41 (11-03) and #42 (11-06) open; #24/#29/#38/#43/#44 are rules PRs; VAL is 1,194 lines | none (note: #47 is an issue, not a PR) |
| 13 E8 | confirmed | guide:47-52 "reached through Termux"; Step 8 Pull, Step 9 Consent (guide:1372-1373); guide is 1,676 lines; README:27 | none |
| 13 A(i)-9 | weakened (ruling) | G4 reads "Nothing changes a device except…", with the score, explanation and highlighting; G8.1 sets no exception; moving the score and TUI to "state 1.5" is a scope decision for the owner | C22 |
| 13 B5 | weakened (ruling) | The analysis is sound, but the "Fix" renames the owner's "confidence out of 100%" as if settled; X-pm-03 is correctly a question | C23 |
| 13 B9 | confirmed | Says "Possible conflict", the fair reading given G3's last sentence and row 6b | none |
| 13 D2 stop list | weakened | "The validate proposal" is the macOS/Linux device-side gate (VAL §3) that carries `adopt` and G4's see-and-refuse; 13's own D1 and A(i)-9 need it; 09 builds on it. The G3/G4 schema changes (X-trust-05/06, X-safety-04) are not Linux-specific. `--simulate-json` feeds 09's preview | C24 |
| X-pm-01 | confirmed | guide:47-52; the rg result above | none |
| X-pm-02 | confirmed | guide:1359-1374 | none |
| X-pm-03 | confirmed | Question, ruling-first | none |
| X-pm-04 | confirmed | goal:58-65 (G8 item 3); ruling-first | none |
| X-pm-05 | confirmed | goal:58; ruling-first | none |
| X-pm-06 | confirmed | upstream-overlay.md:50-56 | none |
| X-pm-07 | confirmed | AGENTS.md:62-69 | none |

## Answers to the brief's tests

- **(a) Papers.** The calibration papers measured QA and knowledge benchmarks. The judge-attack papers measured pairwise or QA judges, and 2604.04978 measured a tool-call transcript classifier. None measured configuration diffs, so transfer to goal-file diffs is by analogy only. Three citations overstate their source (2306.13063, 2606.03437, TerraProbe), and two are slightly strong (2207.05221, 2312.12575).
- **(a) TUI.** The licences are as stated. Textual needs Python 3.9 or later, not 3.11. Termux suitability rests on an old discussion. Toad's README claims Linux and macOS only and does not mention permission prompts. Both AGPL candidates have been idle for about six months. SSH is plausible, since these are terminal apps, but untested.
- **(a) Row 8.** X-safety-01, X-safety-02(d), B5 and X-pm-03 drop "confidence" and "%". Only X-safety-10 and X-pm-03 are framed as questions. All keep the explanation and the graded highlighting.
- **(b) Coordinators.** Tailscale's coordinator, and Headscale in its place, is needed for join, key refresh and revocation, but not for ongoing traffic. A Nebula lighthouse is optional discovery and not the trust root; the offline CA is.
- **(b) Hardware keys.** Ed25519 is in neither the Secure Enclave nor StrongBox: confirmed. The Secure Enclave is not P-256-only, since ML-DSA has been added.
- **(b) Schemas.** They are Ed25519-only: confirmed, with one site missed (goal-diff:15).
- **(b) TUF, Uptane, Syncthing.** The TUF and Uptane descriptions are accurate. Uptane's second signer is the OEM's human-run Image repository, so the owner-key mapping is an analogy. Syncthing on Android is as stated: the official app is archived and Syncthing-Fork is active under a new maintainer.
- **(c) G3 reading.** Not fair as a definitive reading. G3's own last sentence and row 6b keep the architecture, which already authenticates content and authorises by approval record. It is a possible misreading to raise with the owner.
- **(d) Pre-mortem.** The commit counts are two commits stale and one figure is off by one. The stop list freezes the validate proposal and the cross-platform schema changes, which G4, G8.1 and 13's own D1 need.

## Corrections

**C1 (09 Summary 3).** Replace "(MIT, Python 3.11+, … runs over SSH and, per a snippet, in Termux)" with:
> (MIT, Python 3.9+, the same language as `tendcf-validate` and the compiler; a terminal app, so it should run over SSH, and an old Textual discussion reports it working in Termux; neither is tested here)

Also add after "and `textual-diff-view`": "(both last pushed in May 2026)".

**C2 (09 Summary 5 and Q2-1).** Replace "One published classifier failed to flag 81% of a stress set end to end (arXiv 2604.04978)." with:
> One stress test of an agent harness's permission classifier found an 81% end-to-end false-negative rate. Part of that came from actions the classifier never saw. On the actions it did evaluate, it missed 70% and wrongly flagged 32% (arXiv 2604.04978).

In Q2 item 1, after "fell outside the classifier's scope altogether", insert:
> ; on in-scope actions the false-negative rate was 70.3% and the false-positive rate 31.9%. The authors call this "a fundamentally different workload" from the vendor's figure, not a contradiction. The classifier gates tool calls from a transcript; it is not a diff reviewer.

**C3 (09 Q1).** Replace "An LLM-written fix can satisfy the scanner while changing behaviour: 71.4% of plan-compared Terraform fixes were "deceptive"" with:
> An LLM-written fix can satisfy the scanner without fixing anything: 71.4% of plan-compared Terraform repairs were "deceptive fixes that pass automated checks while leaving the underlying vulnerability in place"

**C4 (09 Q2-2).** Replace item 2 with:
> 2. **Fragile verdicts.** Renaming function or variable names, or adding library functions, flipped 26% (PaLM2) and 17% (GPT-4) of vulnerability verdicts ([SecLLMHolmes, arXiv 2312.12575](https://arxiv.org/abs/2312.12575), IEEE S&P 2024).

**C5 (09 Q2-3).** Append to item 3:
> JudgeDeceiver optimises its injection with gradients against open models in a pairwise "pick the best response" setting. How far it transfers to a closed model scoring one diff is not measured; plain injection (2302.12173, 2608.28411) needs no such access.

**C6 (09 Q2-4 and X-safety-06).** Q2 item 4: replace with
> 4. **Self-review is biased.** LLM evaluators recognise and favour their own generations (Panickssery et al., [arXiv 2404.13076](https://arxiv.org/abs/2404.13076)). Separately, open-weight models are up to 26% more confident in an answer framed as their own chat turn than in the same answer given as user input ([arXiv 2606.03437](https://arxiv.org/abs/2606.03437), ACL 2026 Findings). The authoring AI (R13) should not score its own change.

The 2404.13076 citation was not fetched here, so fetch it before merging. X-safety-06 Finding: replace "it is biased toward approving it: models are up to 26% more confident in answers framed as their own" with
> it is likely biased toward approving it: LLM evaluators favour their own generations (arXiv 2404.13076), and models grow more confident in answers framed as their own turn (arXiv 2606.03437)

Then add arXiv 2404.13076 to Evidence.

**C7 (09 Q3-1).** Replace "and all methods are weak on professional-knowledge tasks (white-box AUROC 0.522 to 0.605)" with:
> and failure prediction stays weak on professional-knowledge tasks such as law. Across five datasets, white-box methods beat black-box ones only modestly (average AUROC 0.605 against 0.522)

**C8 (09 Q3-3).** Replace "P(IK) generalises poorly to new tasks" with "P(IK) partially generalises across tasks but is poorly calibrated on new ones".

**C9 (09 Q5 table).** Make these changes to the table:
- Textual Termux cell: "reported working in an old Textual discussion (#583); not tested".
- Toad Fit cell: replace "An agent client with permission prompts and" with "An agent client with". Then add: "the README claims Linux and macOS only; last push 2026-05-26".
- textual-diff-view: add "last push 2026-05-27".
- Mosaic: add "active (push 2026-11-12)".

**C10 (X-safety-01).** In the proposed R14, replace "It shows a safety score out of 100," with:
> It shows the safety confidence out of 100% (or a score out of 100, per the ruling on X-safety-10),

Change Merge to: "needs the operator's ruling first (X-safety-10, the number's wording); otherwise insert after it."

**C11 (X-safety-02).** In (d), replace "The score is shown as "NN/100", never as a percentage, until a calibration corpus exists." with:
> The figure is shown as G4 words it, a confidence out of 100%, unless the owner rules for "NN/100" until a calibration corpus exists (X-safety-10).

**C12 (10 A5 and X-trust-01).** A5: replace the heading sentence with
> A5. **The literal G3 wording can be misread as putting trust in the transport layer.** G3 ends "The architecture is not changed by these words", and the owner's ruling (6b) says the same. The architecture already accepts content by TUF signature and approval record (map §9.11, §10). The intended reading is probably that the handshake is those content checks; the owner should confirm.

X-trust-01 Finding: replace the first two sentences with
> Read alone, "completes the correct cryptographic handshake" could mean a transport handshake, which would make every peer holding a transport key root on every device: the full mesh map §10 rejects. G3's last sentence and ruling 6b keep the architecture, under which the handshake is the content check.

Kind: change it to `question`. Proposed item 1: replace "signed by the release keys this device enrolled at first run" with
> signed by keys this device trusts (which keys, and how a device enrols them, is the owner's ruling)

**C13 (Uptane analogy, 10 B and X-trust-07).** Add:
> In Uptane the second, independent signer is the OEM's Image repository, "primarily controlled by human actors". Using the owner's approval key as that second signature is an analogy, not Uptane's design.

**C14 (10 C Nebula row).** Replace the "Both peers rarely online" cell with:
> Needs some reachable node for discovery: a lighthouse ("Optional, but you really should") or a `static_host_map`. The lighthouse is not the trust root; the offline CA is. The CA has a 1-year default lifetime and host certificates expire with it, a hazard for a phone off for months.

**C15 (10 C Tailscale row).** Replace "The control plane is a service: Tailscale's, or Headscale self-hosted, which is the always-on server G3 excludes." with:
> A coordination server (Tailscale's, or Headscale self-hosted) is needed to add nodes, refresh keys, change rules and revoke keys. Existing connections "mostly continue to function" while it is down, until keys expire. It is a control node in G3's sense for membership, not for traffic.

**C16 (10 D1).** Replace "The Secure Enclave "Works only with NIST P-256 elliptic curve keys"" with:
> The Secure Enclave holds no Curve25519/Ed25519 keys. Apple's key-protection page says it "Works only with NIST P-256 elliptic curve keys". The current CryptoKit `SecureEnclave` API also offers ML-KEM and ML-DSA, so P-256 is no longer the only option.

**C17 (10 D2 and X-trust-05).** Add `schema/goal-diff.schema.json:15` to both evidence lists. In X-trust-05 Finding, replace "The Secure Enclave works only with NIST P-256" with "The Secure Enclave has no Ed25519 (it offers P-256 and, in current CryptoKit, ML-DSA)". Replace "The Android TEE supports Curve25519 signing only from Android 13 (KeyMint v2)" with:
> KeyMint HAL v2 (Android 13) adds Curve25519 signing; whether a given device's TEE implements it is per device.

In the proposed text, after "because neither holds Ed25519 keys", add "(ML-DSA in the Secure Enclave is a later option)".

**C18 (10 D3).** Replace "It cannot make the phone apply a change, because" with:
> On a phone at the `consented` tier (map §10; an `operator`-tier device needs no local yes), it cannot make the phone apply a change, because

**C19 (X-trust-03).** Change Merge to:
> needs the operator's ruling first: it removes the `deploy-origin` push semantics for `operator` hosts and makes pull the default, which is map §9.11 design.

**C20 (X-trust-10).** Replace "but are never a trust element: their coordinators or lighthouses are the always-on server this design excludes." with:
> but are never a trust element. A Tailscale/Headscale coordinator controls membership and key refresh (a control node for the network). A Nebula lighthouse only helps peers find each other, while its offline CA controls membership.

**C21 (13 E1).** Replace the sentence with:
> E1. **Effort.** 446 commits at `eefea3c`. Of the 400 non-merge commits, 242 touch only `docs/` and 123 touch a code directory (131 counting `.github/`). Lines added: docs 70,312; code directories about 19,200 (19,600 counting `.github/`).

**C22 (13 A(i)-9).** Replace the Countermeasure with:
> **Countermeasure (an option for the owner, since G4 applies to every change):** state 1's see-and-refuse could start as a CLI diff plus `y/N`, with the score, explanation, graded highlighting and TUI following as state 1.5, if the owner rules that G4's display may lag state 1.

**C23 (13 B5).** Replace "**Fix:** call it" with:
> **Option for the owner (X-pm-03):** call it

**C24 (13 D2 stop list).** Replace "freeze s5, the validate proposal, the D46 restructure, the Guix, Ansible and Salt importers, #47's OpenPGP web of trust, Linux schema bumps and the simulate-json upstream track" with:
> freeze s5, the validate proposal's Linux-only parts (keep `adopt` and the device-side gate state 1 needs on the Mac), the D46 restructure, the Guix, Ansible and Salt importers, issue #47's OpenPGP web of trust, Linux-only schema bumps (not the key-type, signer or `briefing_sha256` changes G3 and G4 need) and the simulate-json *upstream* track (keep `--simulate-json` itself, which the preview uses)

## Not checked

- 09: the Akhawe and Felt (USENIX 2013), Felt et al. (CHI 2015) and no-color.org sources; arXiv 2608.02672 and 2609.28488 (listed but not used in items); the Toad Termux snippet (OpenHCSDev/agent-comms#4339); Toad's "permission prompts" beyond its README; the lazygit/gitui/delta/Rich/Ratatui/Bubble Tea licences and packaging; the GPLv3 §13 text; arXiv 2404.13076 (recommended in C6, not fetched).
- 10: Tailscale client licence (BSD-3); iroh and iroh-ffi on Android; Mobile Nebula; journald `Seal=`; the apt `Check-Valid-Until` page; the X-trust-12 recovery table; Headscale beyond its README line; whether any shipped Android TEE exposes Curve25519 through the app-level Keystore API; map §12 (APK signing).
- 13: E2 (upstream share), E3 (platform-order history), E6 (inventory §H); the developer-verification claim in A(ii)-2; ideas D3-D20 beyond the stop list; the B-section tensions other than B5 and B9.
- No live tests: Textual or Toad were not run in Termux or over SSH.

Sources consulted: arXiv export API and PDFs for 2604.04978, 2306.13063, 2305.14975, 2207.05221, 2306.10193, 2305.18404, 2403.17710, 2302.12173, 2608.28411, 2312.12575, 2606.03437, 2006.14779, 2001.02114, 2405.00623, 2606.26590 and 2601.14595; the GitHub API for Textual, Toad, textual-diff-view, Mosaic, both syncthing-android repos and Nebula; Textual pyproject; the Toad README; Tailscale KB 1226 and the coordination-server-down page; the Headscale and Nebula READMEs; Apple's Secure Enclave page and CryptoKit SecureEnclave docs; developer.android.com Keystore; source.android.com hardware-backed Keystore; TUF spec 1.0.37; Uptane 2.1.0. All fetched 2026-11-13.
Last search run: none run after the checks above; the last fetch was the Uptane standard (Image repository wording), which supports C13.
