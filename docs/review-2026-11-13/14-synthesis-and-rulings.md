# 14. Synthesis and rulings: the goal review of 2026-11-13

Base commit `eefea3c`. Inputs: the goal definition (G1 to G9, rulings rows 1 to 8, differences 1 to 9), thirteen reports (01 to 13) and six refutation checks (v1 to v6). Where a check weakened or refuted a claim, this file uses only the corrected form. Item IDs point at the report that carries the detail. "vN Cn" points at a correction in check file vN. Nothing here is a new finding; it connects what the reports and checks found.

Scale: 355 items across thirteen reports. The six checks tested about 340 rows. Roughly 240 were confirmed, about 105 weakened, 3 refuted, and about 10 left unverifiable or inferred (counts summed from v1 to v6). The three refutations: 04 Idea 1 (with L-§5-09's remedy), 07's Insular licence, and 07's work-profile install timeout.

## A. What the review found, in one page

1. **No code path reaches G8 state 1 today, and the Mac and phone ends are nearly empty.** The shared contract machinery is about 10,900 lines. Linux-only code is about 5,200 lines. macOS-specific code is about 60 lines, plus a compiler that renders launchd units only. Android code is zero (05 summary (b)). The eleven-row gap list puts state 1 at a guessed 3 to 5 months. Device identity, see-and-refuse, and the Android client dominate it (05 summary (a); 13 E4 to E6).

2. **The "cryptographic handshake" G3 and G8.1 depend on is undefined, and nothing produces a device key.** The schemas require `ed25519:` keys. CFEngine's keys are RSA. No tendcf code generates a device key (C-schema-01, confirmed in v4). Ed25519 is in neither the Secure Enclave nor StrongBox (X-trust-05, corrected by v6 C16/C17). Read literally, G3 could make any peer with a transport key root on every device. The architecture already authenticates content by signature and approval record, so that reading is probably not meant. The operator should confirm (10 A5 and X-trust-01, both weakened to a question by v6 C12). Q17 asks what the handshake must prove (M-§16-03).

3. **Every document exempts the operator's own devices from G4's see-and-refuse.** The `operator` tier needs no local yes (G-§7-02, M-§10-01, X-CP-02). The first validator build has no diff: "'Approved' means 'adopted by root on the host'" (V-§2-03, X-safety-03; v6 row for 09 Summary 1). States 1 and 2 consist only of operator devices. Without a ruling, G4 does not apply to anything the finish line builds.

4. **The interlock `pre_action` reaches a root shell as a joined string.** The policy joins argv with spaces and runs it with `useshell => "true"`. The schema puts no pattern on the strings, and the projector blocks only `$(`, `${`, `@(` and `@{`. `tendcf-install.sh data` installs a projection without running the projector at all. The code path is live in the deployed policy. Injection is latent, because the only deployed `pre_action` is `/usr/bin/true` (C-policy-01; v4 rows and corrections).

5. **The launchd adapter has never run in any test or CI job, and reading it finds four defects.** It drops `env` (C-policy-02). It never reloads a changed job and cannot see a failed load, because `launchctl load` returns 0 (C-policy-03). A tombstone deletes any plist the goal file names, guarded only by a lint (C-policy-04). No CI job runs on macOS (C-tests-01, C-ci-01, X-OV-01). There is no Mac installer (C-deploy-01). The Mac runs Homebrew upstream CFEngine 3.29.0, not the fork (G-§7-03, X-engine-07).

6. **The Android differentiator has no design, and the documents still defer Android.** "Island", "Insular", "work profile" and "ShizukuPlus" appear nowhere outside the goal file (13 E5, M-§12-04, G-§6-03). D22, the map's Step 2 and the linux-targets header still record the 2026-10-29 deferral (X-android-01 to -03). The schema has no Android vocabulary, and the compiler refuses `android` (C-schema-03, C-compiler-05, X-CO-04). The Site Model needs a user/profile dimension (X-android-05). Shell into an Island profile works unless its owner sets `DISALLOW_DEBUGGING_FEATURES` (v5 row for 07 §4).

7. **Android has hard 2026 constraints that the state-1 plan must budget for.** Developer verification applies from 2026-09-30 in four countries through participating stores and to all certified devices in 2027. ADB installs are exempt (X-android-07, corrected by v5). Android 17 blocks cross-profile loopback by default (X-android-06). The privileged helper dies at every reboot. ShizukuTendCF documents an unattended boot start. The fleet's one open boot failure is on a Fire OS tablet (X-android-08, corrected by v5). The helper is a single point of failure on a one-person fork chain (07 Idea 1, 01 Idea 3).

8. **"Nix first" (G2) has no frontend, and "carry over" is undefined.** `eval-nix` is a bare `nix-instantiate --eval --strict --json`, with no modules, no options and no `lib` (C-compiler-01, corrected by v4). CI has never evaluated the repo's Nix file. The docs disclose this (X-nix-09, weakened to `improves` by v3 C15). No tool was found that evaluates a NixOS or nix-darwin config to data and applies it without Nix (08 Summary 1, v3 C16). NixOS modular services do not solve this: they are refuted as a fit (v3 C4). Three alternative carry-over designs need one ruling (X-nix-02, L-§5-09, X-nix-05; v3 C13).

9. **The G4 score as worded ("confidence out of 100%") has no calibration method behind it.** Every reviewer proposed a rule-capped score that AI can only lower (09 Summary 2, M-§9-03, 13 D12). Several silently rewrote the operator's verbatim wording to "NN/100" or "score" (v6 answer (a) on row 8: X-safety-01, X-safety-02(d), 13 B5, X-pm-03). The evidence that AI scanning is a weak, attackable second opinion holds in corrected form (v6 C2 to C8). The TUI candidates that fit best are AGPL-3.0 and have been idle since May 2026 (X-safety-11, v6 C9).

10. **The build order, the decision register and the in-flight work all point at Linux.** The guide's §18 order predates 2026-10-29 (G-§18-02 as corrected by v2). The map's order defers Android (M-§13-02). The two reviewer-proposed replacements disagree in thirteen places (v2 section A). PRs #41 and #42 are green but lack their frontier and adversary reviews; #42's own body forbids merging before both (v3 C12). The fork pin carries 68 non-merge commits, none of them upstream. Stock CFEngine still has those bugs (11 §2, v4 (g)).

## B. Rulings needed from the operator

The list runs from most to least consequential. "Support" says how well the recommendation survived checking.

At a glance:
1. B1: what the G3 handshake must prove, and the state-1 signing and transport subset.
2. B2: whether operator devices keep "no local yes" against G4.
3. B3: whether CFEngine runs on the phone, and how profiles are modelled.
4. B4: whether to supersede D12, D22 and Linux-first, and which build order to adopt.
5. B5: the CFEngine fork: keep it, shrink it, or change engine.
6. B6: which Mac is state 1's Mac, and whether it runs nix-darwin.
7. B7: what "carry over" means without Nix.
8. B8: percent or "NN/100", the caps, and whether the display may lag state 1.
9. B9: "comprehensive" and the public Android claim.
10. B10: review for exploratory code.
11. B11: PRs #41/#42 and the paused worktrees.
12. B12: AGPL in the TUI.
13. B13: changes to the goal file's wording.

**B1. What must the G3 handshake prove, and what is the smallest signing and transport subset for state 1?**
Why: G3 and G8.1 both depend on it. Without it, R14, the map's §9.11 push rule, D14, the key type and Step 5 of either build order cannot be written. Two reports state an answer as settled that nobody has ruled (M-§2-08, M-§9-07, M-§10-02, all bracketed by v2).
Options:
1. Content checks only. Any device may deliver. The device accepts a release only if it is signed by keys the device trusts, fresh, names this device, and carries the owner's approval. Transport authentication decides only who may talk. This matches the existing architecture (X-trust-01 as corrected by v6 C12, 01 Idea 5, G-§5-01). Consequence: little new transport code, and relay through a phone works.
2. Mutual peer authentication by device keys, plus content signature. Consequence: narrows "any other device" to listed peers (M-§10-02), and needs a peer list per device.
3. A state-1 v0: SSH signatures (`ssh-keygen -Y`) over the goal-file bytes plus a counter, with `allowed_signers` written at enrolment outside the release path. TUF follows later (13 D4, E-3). Consequence: days of work, but it breaks the map's 2-of-3 offline-root floor until TUF arrives (M-§9-04, Q26).
Sub-rulings: whether a device-local trust root is a requirement of G3/G4 or one design among several (P-§1.1-01, P-§9-05; v1 C2). The key type: Ed25519, P-256 for hardware keys, or ML-DSA later (X-trust-05; v6 C16/C17). The root threshold for a one-operator site (Q26, M-§9-04). The milestone-1 transport (X-trust-10). What expiry does to a sleeping device (X-trust-02).
Recommendation: option 1 as the meaning, with option 3 as the first build if the 2-of-3 floor may lag. Support: strong for option 1. v2 section C1 finds the guide's "any device delivers, content is checked" better supported than the map's peer list. v6 confirms the TUF and Uptane descriptions. Option 3 is one reviewer's inference, unverified.

**B2. Does "operator: no local yes" survive G4, and if not, what replaces it?**
Why: G4 says nothing changes a device except as a difference its owner can see and refuse. The guide, the map, change-process and the validator's first build all exempt operator devices. Those are every device in states 1 and 2 (G-§7-02, M-§10-01, M-§2-10, X-CP-02, V-§2-03, X-safety-03).
Options:
1. The owner accepts, from one place, the diff each of his devices computed. Each device checks that the acceptance names its own diff (G-§7-02). Consequence: fits the existing approval record (`proposed_sha256`, `nonce`, `approval_seq`, single use) with no schema change (v2 section B2).
2. A local yes on every tier. Consequence: the most literal reading of G4. It is a per-device prompt on every change.
3. A hold window, or an owner-enrolled standing approval, shown and refusable before apply (M-§10-01 as corrected by v2). Consequence: needs a new approval-record shape without a per-change nonce, which is a schema bump.
4. Keep the exemption and record it as an explicit operator exception to G4. Consequence: G4 then holds only for `consented` devices until state 3.
Related: auto-review lets the owner's AI sign the yes. It is a mode the person chooses, not a default, and whether it satisfies G4 is part of this ruling (M-§2-05, weakened to `misleads` by v2). The `managed` tier lets a non-owner waive see-and-refuse (P-§2.8-01). On a `consented` phone the Mac cannot make the phone apply anything (10 D3 as corrected by v6 C18).
Recommendation: option 1. Support: good. v2 finds it the best fit for the repo's schemas. Options 2 and 3 are closer to G4's literal text.

**B3. Does CFEngine run on the phone for state 1, and how are Island/Insular profiles modelled?**
Why: Android is platform 2, and its client is the largest item on the state-1 path (05 row 8: a guessed 3,000 to 6,000 Kotlin lines over 4 to 8 weeks). The map keeps CFEngine on Android (R4) and makes the Kotlin `tendcf-agent` Android's validator (D45). v1 reads R4 and D45 as consistent, with no conflict (v1 P-§2.4-01, C8). The predecessor fleet already runs CFEngine 3.27.1 in Termux (C-android-01).
Options:
1. As designed: CFEngine in Termux with a runit renderer, plus the Kotlin agent for verification, consent and the record (G-§18-02 step 5, M-§13-01 step 6). Consequence: needs a fork build under Termux/bionic, which nobody has tried (03 Idea 4). On Android, `processes:` promises are unusable because toybox `ps` cannot be parsed (X-android-11).
2. Termux CFEngine fed tendcf projections, with the Kotlin agent holding trust and consent only (05 Idea 4). Consequence: reuses what the fleet runs, and could reach state 1 months earlier (inferred).
3. A Kotlin applier inside ShizukuTendCF, acting as shell UID through `pm`, `cmd appops` and `settings`, with `--user` reaching the profile. CFEngine on Android becomes a later option (13 D5, E-1). Consequence: 2 to 4 weeks (guess). Supersedes R4's CFEngine clause. Gives a second applier to keep in conformance (11 Idea 8).
Sub-rulings: whether a profile is its own host, a domain, or an entry field (Q20, M-§12-04, X-android-05). Whether `tendcf-validate` runs in Termux instead of a Kotlin port (Q21, M-§12-06). Whether tendcf may take the profile-owner slot. The device-owner slot is already "a hard no" (M-§2-03 as corrected by v2; X-android-09). Whether the phone's review is a native screen, with Termux only for operators (X-safety-08, X-android-14).
Recommendation: reviewers split three ways (03 Idea 4 spike first; 05 Idea 4 option 2; 13 D5 option 3). Support: weak for all three, since none was prototyped. The cheapest evidence is a spike that builds the fork in Termux inside an Insular profile on the actual phone (03 Idea 4, 02 Idea 7).

**B4. Supersede D12, D22 and the 2026-10-29 Linux-first order, and adopt one build order.**
Why: the register still says "two equal frontends" (D12) and "Android deferred" (D22). The linux-targets header calls the deferral current. The guide's and the map's build orders disagree with each other and with G5 (X-nix-01, X-android-01 to -03, M-§13-02, G-§18-02, M-§13-01, X-pm-02).
Options:
1. Adopt draft D47 to D50 as corrected (M-§15-01 to -04). D48 carries only the operator's text; "Linux-only design work waits for state 2" is a separate proposal (v2 on M-§15-02). D49 leaves the schema authority open (Q23; v2 on M-§15-03). D50 amends D14 rather than confirming it (v2 on M-§15-04). Consequence: the register matches the goal.
2. Supersede only D22 and the order, and leave D12 until the Nix frontend exists. Consequence: G2 stays unrecorded.
Riders in the same ruling: whether Linux is "paused" or simply fourth and fifth. No ruling says "paused"; v3 C1 says to use order language unless the operator rules a pause. Whether the pastebin canary stays as the standing proof (operator, 2026-10-31; 04 Idea 10). Whether D16's ordering inference is deferred explicitly (G-§10-01; the map dropped it silently, v2 A10). Whether Nix may sit on the release path, against change-process §2 "Nix is an optional builder" and map R5/D6 (PL-§2-02, X-CO-02; v3 C5). Whether the server's `monitor` role is in state 1 (guide) or state 2 (map); G8.1 names only the log archive (v2 A7).
Recommendation: option 1, with the guide's order as the base and the map's Step 0 and explicit macOS CI step folded in (section D). Support: good. v2 resolves most of the thirteen differences in the guide's favour.

**B5. The CFEngine fork: keep it, shrink it to zero for adopters, or change engine?**
Why: the 2026-10-29 ruling makes Linux run the full fork build (X-forks-08). State 1 needs a macOS build that does not exist (X-OV-01). 11 recommends stock packaged CFEngine with the fork "a research branch, not a dependency", at about 60% confidence. v4 could not confirm that figure's premises, and notes that dropping the fork reverses the 2026-10-29 ruling (v4 (g)).
Options:
1. Keep the full fork pin on every platform, and build it for macOS in CI. Consequence: closes the data-path defects on the Mac, which today runs stock 3.29.0 (v2 A1). The pin trails upstream by 67 commits and one release (11 Idea 4).
2. Ship a minimum per-state fork delta: only the commits each finish-line state needs (X-pm-06). Consequence: smaller adopter build. Nobody has drawn up the list.
3. Stock packaged CFEngine, with the load-bearing bugs made unreachable from outside the engine (11 §7). Consequence: the cheapest adopter path if the spike passes. Not prototyped.
4. Replace the engine with a small applier behind an applier contract (X-engine-08, -09). Consequence: about 500 lines for the existing fixtures (guess). A larger G7 change.
Constraint on every option: a binary enters a release only as a digest-bound fetched artifact, so a local build counts only once published (change-process §2 rule 5; v3 C10).
Recommendation: option 1 for state 1. Run 11's 2-to-3-day spike (stock 3.29.0 and Termux 3.28.0 against `tests/policy/run.sh`, plus a timeout check) before deciding options 2 to 4 for adopters. Support: medium. The fail-open that 11 used as a key argument is narrower than stated (v4 F3).

**B6. Which Mac is state 1's Mac, and does it run nix-darwin?**
Why: this decides where Nix evaluates, how the fork is built for macOS, and whether macOS needs a passthrough design or only the launchd renderer (04 Idea 2). The checked Mac has no Nix (L-§5-11). On a nix-darwin Mac, passthrough is the documented path (P-§2.2-03 as corrected by v1 C6). The live Mac is a laptop, and the predecessor's named failure was a control node that sleeps (02 Idea 1).
Options:
1. A Mac without nix-darwin, with launchd rendering by tendcf. Nix is used for authoring only. Consequence: matches X-nix-12, "macOS as server must not depend on Nix".
2. A nix-darwin Mac through passthrough. Consequence: needs a nix-darwin plan, and the map points at one that does not exist (L-§5-11). It reopens R4/R5 (X-engine-10).
3. A spare Mac or a VM, not the daily driver. Consequence: allows enforcement under the minimal-claim rule without risk to the daily driver (M-§12-01, Q18, 13 E-2).
Also: may the daily driver enforce? Is user-level only (no root daemon) acceptable for state 1 (13 E-2)? On a nix-darwin Mac, does tendcf replace it, coexist with it, or only add the handshake and logs (13 E-4)?
Recommendation: reviewers lean to option 1 or 3. Support: inferred. No reviewer checked which Mac is meant (02 not-checked list).

**B7. What does "carry over" mean on a machine without Nix (G2 wording)?**
Why: passthrough already settles carry-over for NixOS and nix-darwin hosts (ruling of 2026-10-29; P-§2.1-02 as corrected by v1 C5). Phones and plain Macs are open. "Carry over" can grow into reimplementing NixOS modules (03 Idea 3; 08 Idea 6).
Options:
1. Passthrough only. Elsewhere, configs are written fresh in tendcf's own option tree. Consequence: cheapest; G2's promise is narrow.
2. A one-shot importer that carries over the pure-data option families (`system.defaults`, `launchd.*.serviceConfig`, `users.users`, `environment.etc`) and lists what it did not carry over (X-nix-02; 08 Summary 2, Idea 2). Consequence: about 1 to 2 weeks more (05 row 6, guess). Store paths and `services.<x>.enable` modules cannot carry over.
3. Tendcf's options named after nix-darwin and NixOS where they mean the same thing, read live on every compile (X-nix-05, 02 Idea 4, L-§5-09 without the modular-services remedy). Consequence: familiar names, but two namespaces to keep apart (08 Idea 10).
Recommendation: v3 C13 asks that the three be presented as one choice. Reviewers favour option 2 with option 3's names. Support: moderate. The carry-over fractions are estimates; no corpus was measured (08 not-checked 3). Rule this before the Nix frontend starts (03 Idea 3).

**B8. Percent or "NN/100", what the caps are, and whether G4's display may lag state 1.**
Why: the operator's row-8 ruling is verbatim: "the user gets to see safety confidence out of 100% as well as an explanation of why that percentage was choosen". Reviewers argue that a percentage reads as a calibrated probability, which no fetched method supports for this task (X-safety-10, X-pm-03). Four items rewrote his wording without flagging it (v6 answer (a)).
Options:
1. Keep "confidence out of 100%" as worded. Consequence: honest only once a calibration corpus exists.
2. "NN/100" with a stated meaning, becoming a percentage after calibration on labelled diffs (X-safety-10). Consequence: changes the goal's wording.
3. "Score from 0 to 100", with mechanical checks setting a ceiling that AI review can lower but never raise (X-pm-03). Consequence: changes the goal's wording more.
Sub-rulings: the cap values and whether 100 may ever be shown (01 Idea 1 says never; 09 Idea 1 says 95 at most; M-§9-03; Q25). Whether an owner-set auto-refuse floor is allowed (v2 on G-§7-01). Whether state 1 may ship a CLI diff and `y/N`, with the score, explanation, highlighting and TUI as "state 1.5". That is a scope decision, since G4 applies to every change (13 A(i)-9 as corrected by v6 C22). Whether the authoring AI may score its own change (X-safety-06; v6 C6).
Recommendation: reviewers favour option 2 or 3 with ceilings. Support: the evidence is real but measured on QA tasks, judges and a tool-call classifier, never on configuration diffs. Transfer is by analogy (v6 answer (a)).

**B9. "Comprehensive" in the Android differentiator (G5), and the public claim.**
Why: at shell UID some surfaces are out of reach (other apps' data, user restrictions, profiles whose owner forbids debugging). AMAPI and Fleet are declarative too, but enterprise-owned (X-android-15).
Options:
1. Keep G5 as is, and word only the public claim carefully. The claim: "we know of no other tool that converges an owner's own unrooted phone, including its Island/Insular work profile, from a signed goal file, without MDM enrollment or root" (X-android-15; v5 differentiator section).
2. Also qualify "comprehensive" in G5 itself.
Recommendation: option 1. Support: good. v5 found no counter-example, which is absence of evidence, not proof.

**B10. How is exploratory code reviewed?**
Why: the standing rule requires a frontier cross-model review for every PR and two for design rulings. Every state-1 piece qualifies (13 C). Docs grew to about 70,300 added lines against about 19,200 in code directories (13 E1 as corrected by v6 C21). PRs #41 and #42 have waited a week or more for review quota (13 C).
Options (13 C, combinable):
1. O1, a spike lane: throwaway `spike/*` branches, never merged, no frontier review. Each spike must run on a real non-production device and leave a one-page note.
2. O2, tiered review: lighter review for docs and spike notes; one frontier review for device code; two for root, trust-root, key or handshake code.
3. O4, a docs freeze: no new design document for a state-1 piece until a spike has run.
4. O6, the status quo plus one metric: lines of code that ran on a device each week.
Recommendation: 13 recommends O1, O2 and O4 now, and O5 (dogfood the gate) once state 1 holds. Support: inferred. Changing the standing rule is the operator's alone (X-pm-07, E-10).

**B11. What happens to PRs #41 and #42 and the paused worktrees?**
Why: both PRs are green and ruled, but they lack the frontier and adversary reviews their bodies require. Merging #41 after #42 makes two of #42's statements stale. #41's body names a stale pin hash (v3 C12). Both touch only platform-neutral files, so together they close the CMDB fail-open on the Mac too (v2 A2).
Options:
1. Review, then merge #42, then rebase #41, fix the two stale statements and the hash, review it, and merge (X-WIP as corrected by v3 C12). Record the two 2026-11-02 rulings with #41 without duplicating #42's paragraph (V-§13-11; v3 C9).
2. Close both and re-cut them later. Consequence: the Mac's fail-open stays open.
Also: park `s5-design`, the report-only systemd/dpkg detector, now 54 commits behind (X-WIP). Decide the in-flight D46 decisions PR's scope: cite G4 at its scanning rule, and word frontends per G2 (X-HO-02).
Recommendation: option 1, and park s5. Support: strong (v2, v3).

**B12. May the review TUI borrow AGPL-3.0 code?**
Why: G4 says the TUI is built on a borrowed scaffold. The best fits (Toad's screens, `textual-diff-view`) are AGPL-3.0. tendcf is GPL-3.0-or-later (X-safety-11).
Options:
1. Borrow the AGPL screens. Consequence: the review TUI becomes AGPL in effect (09 Idea 4). Both projects have been idle since May 2026 (v6 C9).
2. Textual (MIT, Python 3.9+) with MIT-only borrowing (Rich, interaction patterns from lazygit or gitui). Consequence: more code of our own (09 Summary 3, runner-up).
3. Mosaic (Kotlin, Apache-2.0, experimental) if a Kotlin TUI is ever wanted.
Recommendation: reviewers lean to option 2 given the idle AGPL projects. Support: licences confirmed. Fetch the GPLv3 §13 text before ruling; nobody did (v6 row for 09 Q5). Textual on Termux and over SSH is untested.

**B13. Should the goal file's wording change where reviewers found it unsafe or undefined?**
Why: the goal is agreed and verbatim. Every proposal below is marked "needs the operator's ruling" in its item. Each exact replacement:
1. G3 and G8.1, the handshake (X-trust-01 as corrected by v6 C12). Replace "accepts updates from any other device that completes the correct cryptographic handshake" with: "it accepts updates delivered by any other device, and applies one only when the update itself proves, whoever carried it: 1. it is signed by keys this device trusts (which keys, and how a device enrols them, is the owner's ruling); 2. it is no older than anything this device has already seen, and recent enough to rule out a withheld newer release; 3. it names this device; 4. this device's owner approved exactly this change, with a key the owner holds and no release can replace. The connection between two devices is authenticated too, but that only decides who may talk, never what is applied." In G8.1, replace "after the cryptographic handshake" with "after the checks G3 lists". v6 weakened this to a question. The architecture probably already means this, so a confirmation may be enough.
2. G4, the figure, option A (X-safety-10). Replace the sentence beginning "The owner is shown a safety" with: "The owner is shown a safety score out of 100, with what it means, an explanation of why that figure was chosen, and the questionable code highlighted more dramatically the less safe it looks. It becomes a percentage once calibrated against labelled changes."
3. G4, the figure, option B (X-pm-03). The same sentence becomes: "The owner is shown a safety score from 0 to 100, set as a ceiling by mechanical checks that AI review can lower but never raise, with an explanation of each part of it and its measured hit rate once a test corpus exists."
4. G8, the order (X-pm-05). Replace "Three states, in order:" with: "Three states. Each is reached in this order, but work toward state 3 may start once state 1 holds."
5. G8 item 3, a rehearsal (X-pm-04). Append to item 3: "From state 1 on, a clean machine with a fresh AI session that has only the public docs rehearses this in CI."
6. G5, "comprehensive" (X-android-15). No change to the goal is proposed. The item explicitly targets public docs only (B9).
7. G2, "carry over": no replacement text was proposed. B7's ruling would supply it.
Recommendation: confirm B1's reading rather than reword G3, if the operator agrees with v6 C12. Rule B8 before choosing between wordings 2 and 3. Items 4 and 5 are low-risk clarifications. Support: all are inferred proposals.

**Smaller rulings the reports raise (each is blocked without one):**
1. ShizukuTendCF ignores the owner's revoke and deny for the fleet signer. This was an owner decision of 2026-10-03, scoped to the fleet flavour, and conflicts with G1 and G4 for strangers. Keep a separate "operator fleet" flavour (C-android-03 with v4's framing note; 05 Idea 5).
2. The map's maxim that "interesting" beats "minimal and safe" is an operator principle, so rewording it needs his ruling (M-§0-02 as corrected by v2).
3. Whether D47 supersedes D8's "sovereignty is the point". The goal's own framing is close to sovereignty (M-§15-01, v2 note).
4. Whether a person's own fork is a source input in `site.lock`. Change-process rule 5 covers only the project's tool forks (X-forks-05 as corrected by v5).
5. Whether the D46 out-of-tree plugin entry points are cut (G-§4-01) or restructured as decided (map Step 0). One ruling covers both (v2 C3).
6. Whether the fleet-wide SQLite index sits with the log archive. This answers D45 item 7, which is open (M-§8-01 as corrected by v2).
7. Whether to resend `--simulate-json` upstream as one small PR. Upstream has merged four small simulate fixes since 2026-09-02 (X-engine-03 as corrected by v4; 11 Idea 3).

## C. Defects to fix regardless of rulings

"Live" means the code path runs on a deployed host today. "Latent" means nothing deployed reaches it yet. Statuses are v4's unless noted.

1. **C-policy-01: interlock `pre_action` runs through a root shell.** Live path, latent injection (pastebin's `pre_action` is `/usr/bin/true`). Fix, step 1: set `useshell => "noshell"` in `tendcf_interlock_contain`. Require `command[0]` to match `^/`, and every item to match the systemd argv alphabet with no ASCII space; this needs a schema bump. Step 2, only after a test on a real build: an slist per interlock via `getvalues(...)`, passed as `arglist`. The reviewer's "absolute path required by schema" does not exist (v4). The projector's `$(` filter does not stop `;`, `|`, `&&`, backticks or redirection (v4).
2. **C-schema-06: the schema behind C-policy-01 has no pattern on `pre_action` strings.** Latent. The fix is the alphabet in item 1.
3. **C-deploy-02 and C-bin-01: the installer takes a projection, and the only device-side code checks nothing about authenticity.** Live (this is how pastebin's data is installed). Fix: the validator's baseline and diff, plus verification before projection. Meanwhile, state that the projector refuses shapes structurally but does not validate against the schema (v4 C-bin-01).
4. **C-policy-02: `env` is emitted, passed through, and dropped by both templates.** Latent. Fix: render `EnvironmentVariables` and `Environment=`, and test it.
5. **C-policy-03: a changed launchd job is never reloaded, and a failed load is invisible.** Latent. Fix: a classes body on the files promise, `bootout`/`bootstrap` on change, and a loaded-state probe.
6. **C-policy-04: a launchd tombstone deletes any named plist, guarded only by a lint that never runs on a device.** Latent. Fix: an existence and type gate in policy.
7. **C-policy-05: no `edit_defaults` and no `perms` on the launchd plist.** Latent. A `.cf-before-edit` backup is left. A plist the agent creates is 0600 and root-owned, which launchd accepts, but a wrong owner or mode on an existing plist is never corrected (v4 C-policy-05). Fix: `edit_backup => "false"` and an explicit `perms`.
8. **C-policy-06: the policy cannot tell "no data" from "nothing to do".** The shape is live on pastebin; the consequence is latent. cf-agent logs the CMDB rejection at ERR, but tendcf does not surface it (v4). Fix: an `isvariable` guard that reports, plus PR #41.
9. **X-engine-01, -02, -05: the timeout fix is in the fork pin but not in the overlay, the comment overstates fail-closed, and no test covers a timed-out check.** Latent. On stock CFEngine, a check that is killed fails closed. It passes only if the reaped process exits normally with `expect_exit` after the alarm (v4 F3). Fix: add the overlay patch, use v4's replacement comment, and add a run.sh check whose `pre_action` overruns its timeout.
10. **C-compiler-04: `platform: any` without a `launchd` block crashes the renderer outside the caught error type.** Latent (confirmed by reading, not run). Fix: a schema condition, or catch it in the renderer.
11. **C-compiler-02: `eval-nix` evaluates without `restrict-eval` or `pure-eval`, with import-from-derivation on, and with no `--` before the path.** Latent (authoring machine only). Fix: pass the options and `--`.
12. **C-compiler-03: an unvalidated render exits 0 outside a checkout when neither `--tendcf` nor `$TENDCF_DIR` is given.** Latent. Fix: fail instead of warning.
13. **C-tests-02 and C-tests-03: tests that cannot fail on CI.** C-tests-02: `interlock-refused.json` holds only launchd services, which Linux CI never reaches. C-tests-03: the Nix test skips without Nix. Fix: a fixture that reaches the systemd gate, and Nix in one CI job.
14. **C-android-02: the predecessor's server trusts keys from a whole tailnet range on first use.** Live in the predecessor, not in tendcf. Fix: explicit key lists before any of it is reused (M-§9-07).
15. **Document defects, confirmed.** They merge as corrections without rulings (section F).
    - The paper calls the policy "launchd-only" twice (P-§2.2-02, P-§2.6-02).
    - "Every host runs its own `cf-serverd`" is false of both live hosts (P-§2.3-01, G-§5-02 as corrected).
    - The map says 182 broken fixtures; there are 159 (M-§4-01 as corrected).
    - The map names the wrong first NixOS host (M-§12-08) and a stale schema version (M-§12-09).
    - The README says nothing is deployed (X-RM-01).
    - Compiler AGENTS.md says it compiles from Nix (X-CO-03).
    - Change-process misses that the goal file already binds the policy-tree digest (X-CP-03).
    - The guide says nothing has merged upstream; four fixes have (X-engine-03 as corrected).
    - The guide says three defects "crash" a run; they stop it before any promise and drop the host to failsafe (G-§19-02 as corrected).
    - The overlay doc says `overlay.py` is under 600 lines; it is 626 (X-forks-10).
    - linux-targets §5 and the code disagree on the evaluator (X-nix-14).
    - The paper misattributes and miscounts several citations (06 T5, T6, T8, T9, T14, T24, T33, T39, with v1 C15 to C18).
16. **Not confirmed by any checker, but worth acting on:** two Android release keystores sit in working trees, one at mode 0644. The skill index says the release secrets are escrowed in 1Password (05 Idea 10). Fix: remove the loose copies after confirming the escrow.

## D. The thinnest path to G8 state 1

The work list merges the guide's steps (G-§18-02), the map's steps (M-§13-01) and the code gap list (05 summary (a)). v2's thirteen differences were applied: Mac first (A1), keep the map's Step 0 for #41/#42 but bump the schema only for what is ruled (A2, v2 C on M-§13-01 item 4), validator before signing (A3), peer actions in state 1 (A6), and the guide's acceptance test (A13). Sizes are the reports' guesses and are marked as such.

1. **Close the open safety work.** Exists: #41 and #42, green. Missing: their frontier and adversary reviews, a rebase of #41, and C-policy-01 step 1 (section C). Size: days (guess). Waits on: B11, and B10 if review is tiered.
2. **The fork on the Mac.** Exists: the Linux build action and the canary pattern (`tendcf-install.sh`). Missing: a macOS CI job building the pin and running `tests/policy/run.sh` with launchd live; a macOS installer; a LaunchDaemon for `cf-execd`; and the launchd fixes C-policy-02 to -06 with tests. Size: 1 to 3 days for CI, 1 to 2 days for the installer, 3 to 5 days for the adapter (guess, 05 rows 1 to 3). Waits on: B5 (fork) and B6 (which Mac). A macOS CI leg needs the operator's say under the CI policy (02 Idea 6; v2 A11).
3. **Device identity.** Exists: `ed25519:` patterns in the schemas. Missing: a key type that hardware can hold, and generation on the Mac and the phone. Size: part of 400 to 800 lines and 1 to 2 weeks with step 6 (guess, 05 row 4). Waits on: B1 (key type sub-ruling). 05 Idea 9 calls this the small, unblocking first step.
4. **Nix authoring, minimal.** Exists: `eval-nix`, a plain attrset. Missing: `lib.evalModules` from a pinned `nixpkgs.lib` with no `pkgs`, tendcf options for services, interlocks and roles, and output byte-identical to the YAML twin. Size: 1 to 2 weeks, plus 1 to 2 weeks for importers (guess, 05 row 6). Waits on: B7 (carry-over), B4 (Nix on the release path, Q23 schema authority), and the option namespace (X-nix-03, v3 C14). Independent of step 2 (v2 A1).
5. **`tendcf-validate`, first build, with CLI see-and-refuse.** Exists: the projector, `apply_diff`, the goal-diff and approval-record schemas, and the proposal's platform-neutral options. Missing: a stored baseline, a device-computed diff, accept or refuse, projection only after accept, and a bundled interpreter on macOS. The proposal's §6(d) already recommends one (v3 C8). Size: 300 to 600 lines, about 1 week (guess, 05 row 5). Waits on: B2. The `--accept DIGEST` interface needs a ruling (V-§2-03; v3 C6).
6. **Signed releases and the handshake.** Exists: prose only. Missing: release signing, verification before step 5 sees anything, a high-water mark, and relay by any device. Size: 1 to 2 weeks for signing plus 1 to 2 weeks for transport (guess, 05 rows 4 and 9). Waits on: B1. v2 A3 asks the operator whether signing may follow the validator, as here.
7. **Android in the contract.** Exists: the `termux` flavour and the `android-termux-services` fixture. Missing: Android domains (apps per user/profile, appops, settings, grants), the profile model, and a compiler `android` row. Size: about 400 schema and 300 compiler lines, 1 to 2 weeks (guess, 05 row 7). Waits on: B3. Bump the schema only for what is ruled (v2 on M-§13-01).
8. **Android client.** Exists: the predecessor's Kotlin agent, Termux CFEngine and ShizukuTendCF. Missing: receive, verify, diff, an on-device review screen, apply through the helper, report, a reboot-survival gate (X-android-08), and a distribution plan before 2027 (X-android-07, 13 D19). Size: 3,000 to 6,000 Kotlin lines, 4 to 8 weeks; less if Termux CFEngine converges (guess, 05 row 8). Waits on: B3. Run the Termux spike first (03 Idea 4).
9. **Peer actions and the log archive.** Exists: `report-row.schema.json` and the roles schema. Missing: a JSONL writer on both devices, the Mac's `log-archive` service rendered through launchd, the phone buffering while the Mac sleeps, and the Mac starting ShizukuPlus over ADB when the phone cannot. Size: 300 to 500 lines, about 1 week (guess, 05 row 10). Waits on: B1 (transport), and B4 (whether `monitor` is in state 1). Making log export a goal-file entry is an idea, not yet a ruling (01 Idea 6).
10. **The safety scan, then the TUI.** Exists: the privileged-path list and the ceremony classes. Missing: the rule scanners first (they can ship with step 5; 04 Idea 6), then an owner-chosen AI reviewer, the figure, the explanation and graded highlighting, then the TUI. Size: not estimated by any report. Waits on: B8 (including whether this may lag state 1) and B12.

State 1 is reached when the Mac and the phone each converge from a Nix-authored site. Each must refuse both a release that fails the handshake and a diff its owner refused. Both devices' logs must be in the Mac's archive (G-§18-02; v2 A13 prefers this test to the map's). Total: 3 to 5 months of focused work (guess, 05).

Which rulings unblock which steps:
1. Steps 1 and 2 can start after B11, B5 and B6. Section C's fixes need no ruling.
2. Step 3 needs only B1's key-type sub-ruling, not the whole of B1.
3. Step 4 needs B7 and B4's Nix-on-the-release-path rider.
4. Step 5 needs B2. Steps 6 and 9 need B1.
5. Steps 7 and 8 need B3, and the Termux spike can run before it.
6. Step 10 needs B8 and B12.
7. B10 changes the cost of every step, not its order.

**Stop or park until state 1 (13 D2 as corrected by v6 C24, with X-WIP and v3 C1):**
1. Park `s5-design` (systemd/dpkg detector) and keep the branch. Its promise-module pattern is worth reading for a later launchd or Android detector (X-WIP).
2. Freeze the validate proposal's Linux-only parts. Caveat: keep `adopt` and the device-side gate, which state 1 needs on the Mac (v6 C24).
3. Hold Linux-only schema bumps. Caveat: not the key-type, signer or `briefing_sha256` changes that G3 and G4 need (v6 C24; X-trust-05, X-trust-06, X-safety-04).
4. Pause the `--simulate-json` upstream track. Caveat: keep `--simulate-json` itself, which the preview uses (v6 C24).
5. Freeze the D46 restructure, or split it (04 Idea 8). Caveat: the map's Step 0 does it, and one ruling covers both (v2 C3).
6. Freeze the Guix, Ansible and Salt importers, and issue #47's OpenPGP web of trust (#47 is an issue, not a PR; v6 row for 13 E7).
7. Defer the paper's restructure (P-§S-01). Take its factual corrections now (01 Idea 9).
8. Caveat on wording: call Linux "fourth and fifth", not "paused", unless the operator rules a pause (v3 C1). Keep pastebin's canary running as the standing proof and as the regression host for the shared bundle (04 Idea 10).

## E. Where reviewers disagreed, and what was withdrawn

**Contradictions, and how checking resolved them**
1. **The two build orders** (G-§18-02 against M-§13-01). v2 section A lists thirteen differences. It favours the guide on: the Mac first, validator before signing (the map's Step 3 verifies a signature built only at Step 5), peer actions, extra-entry detectors before retirement, the Linux split, explicit deferral of inference, and the acceptance test. It favours the map on: Step 0 for #41/#42, the explicit macOS CI step, the owner key, and monitoring in state 2.
2. **The operator tier** (G-§7-02 against M-§10-01). Both route it to the operator. The guide's design fits the existing approval record; the map's options need a new shape (v2 B).
3. **The handshake's scope** (G-§5-01, G-§14-01 against M-§2-08, M-§9-07, M-§10-02). The guide is better supported: map §9.11 itself says TUF authenticates the release. The map's peer list narrows "any other device" (v2 C1).
4. **D45 against R4.** 01 claimed a conflict (P-§2.4-01). v1 found none: R4 keeps CFEngine on Android and D45 makes only `tendcf-agent` Android-only. v4's optional framing ("D45 chose no CFEngine on Android") does not match R4's text. v1's reading holds.
5. **The fork** (11 §7 against v2 A1, 02 Idea 6 and X-pm-06). 11 would drop the fork for adopters. The others need it on the Mac because stock 3.29.0 carries the data-path defects. v4 notes that dropping it reverses the 2026-10-29 ruling. Unresolved: B5.
6. **Monitoring in state 1** (guide step 6 against map step 9). The map matches G8.1's literal text; G3 lists monitoring as a server service. Unresolved: B4.
7. **The score's ceiling** (01 Idea 1: never show 100; 09 Idea 1: at most 95; 13 D12 and M-§9-03: rule ceilings). All are proposals. None is in G4 (v1 C9, v6 answer (a)). Unresolved: B8.
8. **Carry-over design** (L-§5-09: read NixOS shapes live; X-nix-02: one-shot import; X-nix-05: nix-darwin names). v3 C13 asks for one choice. Unresolved: B7.
9. **The stop list** (13 D2 against 09, 13 D1 and A(i)-9). The freeze would have stopped the validator that state 1 needs. Narrowed by v6 C24.
10. **The paper against the sources check** (01 against 06). Promise Theory is weighted `improves`, not `misleads`. The "report early" advice belongs to the 2008 booklet, not LISA '05. The two §9.5 edits merge into one, and so do the two §6.4 edits. The Bcfg2 idea count must be settled once. P-§3.2-03 is closed by 06 T34 (v1 section C).
11. **New question numbers.** The guide's new questions are 17 to 26. The map's are 17 to 27, with different content. The map must follow the guide's numbering (v2 C2, v2 on M-§16-03).

**Refuted or materially weakened claims (read these over any earlier summary)**
1. **NixOS modular services are not a fit for the Nix frontend.** They target Nix module-system frameworks. nix-darwin support is an unmerged draft (#1765). About eight exist. Their `process.argv` is a store path (04 Idea 1 and L-§5-09's remedy, refuted by v3 C4).
2. **A timed-out interlock does not pass on stock CFEngine.** A check killed by the timeout fails closed. It passes only if the reaped process exits normally with `expect_exit` after the alarm. The deployed Linux pin carries the fix; the Mac dev build and stock packages do not (X-engine-01, -02 and 11 Idea 1, narrowed by v4 F3).
3. **Shizuku restart after reboot is not a general blocker as stated.** Stock Shizuku needs a manual restart without root. ShizukuTendCF documents an unattended start that waits for Wi-Fi. The fleet's one open failure, #188, is on a Fire OS tablet running an older build, recovered by peer start over ADB. A reboot-survival gate is still needed (X-android-08 and 07 §3 constraint 2, corrected by v5).
4. **Work-profile installs were never observed to time out.** The predecessor's code only anticipates a confirmation dialog (07 §3 constraint 1, refuted; X-android-05, weakened; v5).
5. **Shell into a work profile is not "often blocked".** It works unless the profile owner sets `DISALLOW_DEBUGGING_FEATURES`, which is an opt-in in Island (v5 row for 07 §4).
6. **The change-process rule does not forbid a person's own fork.** Rule 5 covers only the project's tool forks (X-forks-05, corrected by v5).
7. **Insular's licence is Apache-2.0, not GPL-family.** Its last release was 6.4.2 (2025-08-07), and commits resumed 2026-09-11. Island has had no public commits since 2021-09 (07 table, refuted by v5).
8. **The 81% figure.** It is an end-to-end false-negative rate for an agent harness's tool-call classifier. 36.8% of actions never reached the classifier. On the actions it saw, it missed 70.3% and wrongly flagged 31.9%. It is not a diff reviewer (09 Summary 5 and Q2-1, corrected by v6 C2).
9. **Android verification and distribution.** From 2026-09-30, verification covers certified devices in four countries through participating stores, and all certified devices in 2027. Limited distribution allows 20 devices per the FAQ but 50 per the guide updated 2026-10-28 (X-android-07, corrected by v5).
10. **G3 does not obviously put trust in the transport layer.** That is one possible reading. G3's last sentence and ruling 6b keep the existing content-signature architecture (10 A5 and X-trust-01, weakened by v6 C12).
11. **Hardware keys.** The Secure Enclave also offers ML-DSA, not only P-256. Curve25519 in KeyMint v2 depends on the device (10 D1, X-trust-05, corrected by v6 C16/C17).
12. **Mesh coordinators.** A Tailscale or Headscale coordinator controls membership and key refresh, but traffic mostly survives an outage. A Nebula lighthouse is optional discovery; its offline CA is the trust root (10 C, X-trust-10, corrected by v6 C14, C15, C20).
13. **TUI facts.** Textual needs Python 3.9+, not 3.11+. Termux support rests on an old discussion. Toad's README claims only Linux and macOS and does not mention permission prompts (09 Summary 3, Q5, corrected by v6 C1, C9).
14. **Paper citations in 09.** TerraProbe's 71.4% are fixes that leave the vulnerability in place, not behaviour changes (v6 C3). SecLLMHolmes's flips include adding library functions (C4). The self-confidence paper does not test diff scanning; cite self-preference work instead, which is not yet fetched (C6). The AUROC figure is a white-box against black-box gap (C7). P(IK) generalises partly (C8).
15. **Merge-conflict figures.** About 55 to 60% of AI resolutions match the developer's, and 55% is a floor. PortGPT's 62 to 89% is for backporting. "4 of 5 did not parse" was a structural check on n=5 (X-forks-02 and 12 §4, corrected by v5).
16. **Prior art for Nix.** "Nobody evaluates…" becomes "no tool found evaluates…". comin covers pull and signature checks on Nix hosts; clan pushes. Neither shows a refusable diff (08 Summary 1 and 4, corrected by v3 C16, C17).
17. **Repo facts.** There are 159 broken fixtures, not 182 (v2 on M-§4-01). There are two live hosts, not one (v2 on G-§5-02). The guide lists Macs first and never says "Linux first" (v2 on G-§1-01). The guide's table never recorded D22's deferral (v2 on G-§18-02). The validate proposal does plan a bundled interpreter (v3 C8). No ruling "pauses" Linux (v3 C1). Nobody decided that the server Mac is the first enforced host (v3 C3). The commit counts are 446/400/242 at `eefea3c` (v6 C21).
18. **Paper response.** A device-local root is not shown to be "required" (v1 C2). The canary went from a dry run on 2026-10-29 to enforcement on 2026-10-31, not "one day" (v1 C12). "We send upstream only what the design cannot do without" is unsupported (v1 C13). The Bcfg2 docs were last built in 2016, but the repository's last push was November 2023 (v1 C15).
19. **Code response details.** NixOS hosts are passthrough by design, which is not "the inverse of carrying over" (v4 C-compiler-01). The `-` argument claim applies only after `--` (C-compiler-02). The perms claim in C-policy-05 was overstated. The agent does log the CMDB rejection (C-policy-06).
20. **The upstream count.** Four small simulate PRs merged, with backports. The guide's "twenty-three fixes" and the proposed "twenty-six" both need the corrected text (X-engine-03, v4).
21. **Proposals that silently decided rulings.** All are now bracketed. The operator's "%" was reworded (X-safety-01, X-safety-02(d), 13 B5; v6 C10, C11, C23). Pull was made the default (X-trust-03; v6 C19). Peer mutual-key admission was settled (M-§2-08, M-§9-07, M-§10-02; v2). D48 and D49 attributed text to the operator that the goal does not contain (v2). Nix on the release path contradicted change-process (PL-§2-02, X-CO-02; v3 C5).

## F. Merge map

Order inside each document: rulings first (items whose Merge says "needs the operator's ruling", and `ruling-drift` items), then corrections of fact (`correct`), then additions (`add`, `question`), then restructures (`reword`, `move`, `cut` of whole sections). "Today" counts items that need no ruling, after the checkers' Merge changes. The ID lists name only the exceptions.

| Response | Merges into | Items by Kind | Mergeable today |
|---|---|---|---|
| 01 paper | `docs/paper/tendcf-architecture-paper.md` | 57: reword 15, correct 13, add 12, ruling-drift 9, question 5, move 3 | about 44. Not today: P-§1.1-01, P-§9-05 (v1 C2), P-§2.5-01, P-§9-07 (C9), P-§1.1-02 (only if P-§1-01 lands, C3), P-§S-01 (defer, 01 Idea 9), and those already ruling-first. P-§2.2-03 becomes mergeable (C6) |
| 02 guide | `docs/paper/tendcf-architecture-guide.md` | 45: add 18, reword 9, correct 8, cut 4, ruling-drift 4, question 2 | 29, all with v2's text fixes (G-§0-02, G-§1-01, G-§16-01, G-§19-02, G-§20-03). G-§18-02, G-§7-02, G-§3-01 and G-§5-01 wait on B4, B2, B4 and B1 |
| 03 map | `docs/architecture/architecture-DEFINITIVE-v3.md` | 48: add 22, ruling-drift 8, reword 8, question 5, correct 4, cut 1 | about 18. v2 moved M-§0-02, M-§8-01 and M-§10-02 to ruling-first, and M-§2-03 in part. M-§16-03 waits for renumbering. M-§9-03 follows M-§9-02 |
| 04 plans (L) | `docs/architecture/linux-targets.md` | 12: add 4, correct 3, ruling-drift 2, reword 2, question 1 | most, with v3 C1's order wording instead of "paused". L-§4-07 needs C3 |
| 04 plans (N) | `docs/architecture/nixos-passthrough-plan.md` | 5: add 2, correct 2, question 1 | 4. N-§3-02 is a question |
| 04 plans (PL) | `docs/architecture/plugin-layout.md` | 6: add 4, ruling-drift 1, question 1 | 3. PL-§2-02 is now ruling-first (v3 C5). Coordinate with the D46 decisions PR (X-HO-02) |
| 04 plans (V) | `docs/architecture/tendcf-validate-proposal-2026-11-03.md` | 11: add 8, correct 1, reword 1, question 1 | about 8. V-§2-03 is ruling-first (v3 C6). V-§13-11 lands with #41 (C9). V-§3-05 is `improves` (C7) |
| 04 plans (X) | change-process, upstream-overlay, README, compiler docs, AGENTS.md, handoffs | 18: add 5, question 5, correct 4, ruling-drift 3, reword 1 | about 10. X-CO-02 is ruling-first (C5). X-RM-02 needs the C11 tense fix. X-WIP and X-HO-01/-02 are rulings (B11) |
| 05 code | `compiler/`, `policy/`, `schema/`, `bin/`, `tests/`, `deploy/`, CI | 45: add 20, correct 16, question 7, ruling-drift 1, move 1 | 23 code fixes need no ruling (section C), each through the normal PR rule. Schema, Android and G4 items wait on B1 to B3 and B8 |
| 06 sources | paper (19), guide (7), cross-cutting (1) | 27: correct 19, reword 6, cut 1, add 1 | 26, with v1 C15 to C18 and the relabels (s14 to §2.7, s19 and s20 to §3.2). Merge s11 with P-§9-02, and s13 with P-§6.4-01 |
| 07 Android | map R4, §12, §13, D22; linux-targets; goal (public claim) | 15: add 10, ruling-drift 3, question 2 | 7, using v5's corrected text (X-android-04, -06, -08). Drift items wait on B4 |
| 08 Nix | map, linux-targets, nixos-plan, plugin-layout, paper | 15: add 8, correct 2, question 2, reword 2, ruling-drift 1 | 9. X-nix-09 is `improves` (v3 C15). X-nix-02 waits on B7 |
| 09 safety and TUI | map §2, §6, §9; validate proposal; goal | 12: add 10, ruling-drift 1, question 1 | 5. X-safety-01 is now ruling-first (v6 C10). X-safety-06 needs the C6 citation fetched first |
| 10 trust | map §9.11, §10; guide; schema; goal | 12: add 8, reword 3, question 1 | 5. X-trust-03 (v6 C19) and X-trust-12 are now ruling-first. X-trust-01 is a question (C12) |
| 11 engine | guide §7, §19; overlay; policy; map | 10: add 4, correct 3, question 2, reword 1 | 6, with v4's replacement texts for X-engine-01, -02 and -03 |
| 12 forks | guide, overlay doc, map, change-process | 10: add 8, question 1, correct 1 | 7, with v5 C9 to C12 |
| 13 pre-mortem | goal, guide, overlay doc, AGENTS.md | 7: question 2, add 3, ruling-drift 2 | 1 (X-pm-06). The rest are rulings (B10, B13) |

Total: 355 items. About 210 can merge today with the checkers' corrections. The rest wait on B1 to B13.

## G. What nobody checked

**Nothing was executed or built**
1. No test, build, lint or compiler run in any report or check. The `platform: any` crash, the cannot-fail tests and the timeout behaviour all rest on reading (05 Not checked 1; v4 Not checked 5).
2. Whether `@(argv_...)` parses as an `arglist`, which C-policy-01's step 2 needs (v4 Not checked 4).
3. Stock 3.29.0 and Termux 3.28.0 against `tests/policy/run.sh`, which is 11's proposed spike (v4 (g)).
4. Textual, Toad or Mosaic in Termux or over SSH (v6 Not checked; 09 Not checked 5).
5. No score weight was measured (09 Not checked 1).

**No device or live host was touched**
6. No SSH to pastebin or the NixOS host. CI was not re-run; PR state was read with `gh` (v2 Not checked 1, 2).
7. No phone: shell into a work profile, quiet or paused profiles, a Shizuku Binder reaching user 10, ShizukuPlus across profiles, CFEngine under Termux, Android Doze limits (v5 Not checked 2; 07, 10 N9).
8. The Mac's launchd PATH for a root `cf-execd`. Whether launchd loads `.cf-before-edit` files (C-macos-03, unverifiable; v4 Not checked 3).
9. Which Mac is meant for state 1. The operator's phone model, StrongBox and Android version (02 Not checked; 10 N1).

**Nothing ran under Nix**
10. No Nix on the review Mac. IFD, `lib.evalModules` without `pkgs`, and whether `cfengine-tendcf.nix` builds on Darwin are all inferred (08 Not checked 1; v3 Not checked 3, 5).
11. The carry-over fractions are estimates, with no corpus (08 Not checked 3).

**Sources unread**
12. Paywalled or failed: the body of [9] (ACM), the balena blog post [24] (three routes failed), the [29] Jira ticket (empty shell) (06 D1; v1 Not checked 2).
13. Read only in part: [5], [7], [8], [14], [28]. The Promise Theory book [6]. Burgess's 2005 autonomy papers. The 2008 booklet's printed section numbers (v1 Not checked 3, 5; 06 D3).
14. Prior work listed but not fetched: Traugott and Brown, Traugott and Huddleston, LCFG and Anderson's survey, Delaet et al., Tortoise, the Seven Sins, the IaC smells papers, Pearce et al., Perry et al., Kadavath et al., Ansible Lightspeed, the TUF CCS 2010 paper, Uptane at escar, in-toto, Reproducible Builds, Darcs/Pijul patch theory, Computer Immunology (06 C).
15. The GPLv3 §13 text, needed for B12 (v6). Self-preference in LLM evaluators, arXiv 2404.13076, needed for X-safety-06 (v6 C6). The TUF delegation semantics (v3 Not checked 6).
16. Android: Sui, Flyve, Obtainium, Canta, the GrapheneOS tools, the AOSP Shell permission list, Fleet's Android GitOps, the Termux Play build, the phantom-process source, the stayturgid #188 page itself, the ShizukuPlus Dhizuku licence question, "AMAPI/Fleet would own the work profile" (07; v5 Not checked).
17. Trust and transport: Tailscale Android mechanics, iroh on Android, Mobile Nebula, SSB, Briar, Yggdrasil, Radicle, Sigstore, OSTree, journald `Seal=`, Mac log tools, the CHAINIAC body (10 N3 to N8; v6).
18. Nix: licences of clan, home-manager and nix-darwin; garnix; deploy-rs and colmena; system-manager's Nix version; comin's per-remote key pinning (08 Not checked; v3 Not checked 4).
19. Forks: gbp-pq, quilt, stgit, git-branchless, Homebrew taps, Renovate, Radicle, the jdguillot dotfiles PR, PortGPT's body for "of 18" (12 Not checked; v5 Not checked 7, 8).
20. Engine: libntech upstream since 2026-08-20; the 3.28.0 release date; what backports #6499/#6500 carry; the † claims about Salt, Ansible, chezmoi, OpenVox and mgmt (11 Not checked; v4 Not checked 2).

**Samples not fully checked**
21. v1 did not test 12 of 01's 22 `improves` items. v2 did not spot-check ten guide items and five map items. v3 checked `improves` and `nit` items only at their anchors. v4 skipped 05's items below `blocks-goal` (C-compiler-09, C-schema-05, C-bin-02 to -04, C-tests-04, C-ci-02, C-android-04/-05, C-macos-01, C-g4-02 to -04). v6 skipped 13 E2, E3, E6, ideas D3 to D20 beyond the stop list, and 10's recovery table (X-trust-12). The Nits tables of 02 and 03 were not checked beyond one number.
22. 13 read the paper, map and plans only through digests, and none of the other reports (13 Not read).

## H. Ideas worth keeping

1. **A ceiling that AI can only lower.** Mechanical rules set the cap per hunk. AI reviewers can only subtract. Show the reasons and the flagged hunks before the number. Offer no threshold-accept (01 Idea 1, 02 Idea 3, 03 Ideas 1-2, 04 Ideas 5-6, 13 D12). The wording waits on B8.
2. **One review document, many renderers.** Hunks, findings, figure and band are produced once, hashed into `briefing_sha256`, and rendered identically by the CLI, the TUI and the phone (09 Summary 4, 04 Idea 4, X-safety-04).
3. **Score on the device, with a different model family from the author.** This applies the project's own cross-model rule to owners' devices (01 Idea 2, 02 Idea 2, 05 Idea 8, X-safety-06).
4. **A red-team corpus of hostile diffs.** For example, interlock removal hidden among 200 hunks, injected text, or `run_as` root via a renamed id. Use it both as golden fixtures and as the start of calibration (09 Idea 5, 03 Idea 2).
5. **A property test that every goal-file field changes the actuated artefact.** It would have caught C-policy-01, -02 and -03 (05 Idea 3).
6. **Identity first.** Pick and generate the device key on the Mac and the phone before anything else in G3 or G4 (05 Idea 9). An SSH-signature handshake v0 is the cheap first build if B1 allows it (13 D4).
7. **Spike before spec.** Build the fork in Termux inside an Insular profile on the real phone before the Android schema bump (03 Idea 4, 02 Idea 7). Run the stock-CFEngine spike before the fork ruling (11 §7). Each build step closes with a runnable demonstration on a device (03 Idea 5).
8. **The overlay as G9's seed.** Require a plain-language `intent` per patch, and dogfood it on the CFEngine fork and ShizukuTendCF before any non-technical user exists (X-forks-04, 03 Idea 9, 04 Idea 7, 13 D15).
9. **Make carry-over measurable.** Compile a corpus of public nix-darwin and NixOS configs and report the share that carries over. Give the AI the "not carried over" list to explain. Refuse `/nix/store/` in any goal-file string (01 Idea 4, 08 Ideas 2-3).
10. **Use nix-darwin #1860 as G4's motivating example.** There, a declarative cleanup flag silently uninstalled unmanaged Mac App Store apps; tendcf would have shown a tombstone diff (08 Idea 4, X-nix-06).
11. **Ship an MCP server and an agent skill, and rehearse the stranger in CI.** A stranger's AI should call the tool rather than recall it. A clean runner given only the public docs rehearses state 3 from state 1 onward (13 D9, D11, X-pm-04).
12. **Treat the log archive as both a privacy feature and a test.** Make log export a goal-file entry the owner sees. Encrypt it to an archive key held off the Mac. Use it as the first peer protocol, since it carries no actuation risk (01 Idea 6, 10 Idea 10, 04 Idea 9). Syncthing is the cheapest carrier, but it is peer-to-peer, not store-and-forward, and its Android fork has a single maintainer (13 D6, 10 Idea 2, v6 row for 10 C).
