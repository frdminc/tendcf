# 13. Pre-mortem against the new goal, tensions, process, ideas

Base commit: eefea3c

How this was produced: one researching agent (Claude Opus), then an independent checking agent that fetched the cited sources and tried to refute each claim; nothing was executed.

Items by Weight after corrections: blocks-goal 1, misleads 1, improves 5, nit 0 (7 response items; none withdrawn).

Reviewer: Opus 5.5 `high`, read-only. The tendcf goal-review worktree (head c3ae530 = eefea3c plus the goal files). Anchors are at eefea3c.

Sources consulted: shared firecrawl. (1) Android developer verification, scraped from https://developer.android.com/developer-verification: enforcement starts 2026-09-30 for participating stores in some regions, and rolls out globally in 2027. There is an open-source registry, a "limited distribution" account (up to 20 devices per Google's overview page and FAQ, 50 per its 2026-10-28 guide; no ID, no fee) and an "advanced flow" that lets power users sideload. (2) numtide system-manager (Nix modules on non-NixOS Linux) has real users, for example https://github.com/jawuku/dotfiles/blob/67c460e16efefe7f005035ec21bfbdf593a1964f/os_setups/debian-nix-system-manager.md. (3) Generic searches for Shizuku declarative config and for TUI diff scaffolds returned noise. Firecrawl's general web ranking was poor today (unrelated results on two queries). The developer category worked.

## Evidence this review leans on (at eefea3c)

E1. **Effort.** 446 commits at `eefea3c`. Of the 400 non-merge commits, 242 touch only `docs/` and 123 touch a code directory (131 counting `.github/`). Lines added: docs 70,312; code directories about 19,200 (19,600 counting `.github/`) (inventory §B; independently checked 2026-11-13: weakened, corrected).
E2. **Upstream.** About a quarter of all commits went to the CFEngine upstream episode, which ended in "the fork is the destination" (history §E). Not checked: the independent checker did not re-derive the "quarter upstream" count; that needs a commit classifier over history §E.
E3. **Platform order has changed three times.** 08-13: macOS, then Android, then Linux. 10-29: Linux first, Android deferred. 11-13: macOS and Android first, Linux fourth. Each change was followed by about two weeks of intense work.
E4. **Nothing tendcf runs on a Mac or an Android device.** There is no macOS CI. On a Mac the launchd branch runs only under the dev build in tests (inventory §G4, §F; independently checked 2026-11-13: confirmed).
E5. **The Android differentiator has no design.** "Island", "Insular", "work profile" and "ShizukuPlus" occur nowhere in docs/, code or schema outside `00-goal-definition.md` (`rg` over the repo, handoffs excluded). The Android design in the map is Termux, a Kotlin tendcf-agent and a "Shizuku-class helper" (`architecture-DEFINITIVE-v3.md` R4, "Android keeps Termux"). ShizukuTendCF's fleet applier writes only Shizuku's own 8 preference keys (ShizukuTendCF repository, `manager/src/main/java/af/shizuku/manager/fleet/FleetProfileApplier.kt:18-28`) (independently checked 2026-11-13: confirmed).
E6. **State 1 needs four pieces, all unbuilt.** The handshake, the log archive, the Nix module frontend and any peer update path have no code (inventory §H: "Signed release / TUF: prose only"; "Pull / self-update: nothing"; the Nix frontend is an `eval-nix` wrapper only).
E7. **Process.** 42 PRs. Merge latency is short: most merged within an hour. Five PRs (#24, #29, #38, #43, #44) changed review and routing rules, and 11-06 to 11-10 saw AGENTS.md edits only. #41 and #42 have been open for 10 and 7 days. The validate proposal is 1,200 lines and "decides nothing" (independently checked 2026-11-13: confirmed; #47 is an issue, not a PR).
E8. **The guide still states the old aim.** §1 says Android is "reached through Termux", and §18 puts consent at Step 9 and pull at Step 8 (guide:47-52, :1362-1374). The README sends a newcomer to a 1,676-line architecture guide, and its second sentence of status is "Nothing described here is deployed" (independently checked 2026-11-13: confirmed).

---

## A. Pre-mortem: November 2027

### A(i). State 1 never happened

Ranked by my estimate of likelihood. Each story gives the early sign that would show in the repo within a month, and the cheapest countermeasure.

1. **Spec-first habits absorbed the time.** Each state-1 piece got a 1,000-line proposal and two frontier reviews before any code ran: the handshake, the score, the TUI, the log archive and the Android applier. That is the pattern from v5, s5 and validate (E1, E7).
   - **Early sign:** in the next 30 days, more lines added under `docs/` than under code directories, or any new state-1 design doc over 300 lines with no spike beside it.
   - **Countermeasure:** a spike lane (C, option 1) plus a rule that no state-1 design doc exceeds one page until a spike has run on a real device.

2. **Android stalled on the substrate question.** The map's design (CFEngine under Termux, Kotlin agent, Shizuku helper) cannot reach Island or Insular profiles: those are a separate Android user, and Termux runs in the main user. Nobody decided whether CFEngine runs on the phone at all, and G7 forbids changing it without a ruling. So both "Android first" and "nothing changes without a ruling" held, and nothing moved.
   - **Early sign:** by mid-December, no tendcf-produced action has run on the phone, and the profile question has no answer in any doc.
   - **Countermeasure:** a two-day spike. The Mac renders a JSON goal file. A ShizukuTendCF build applies one item as shell UID (for example `pm disable-user --user <island-id> <pkg>`) and writes one JSONL line. Then ask the owner the CFEngine-on-Android question with that evidence in hand (E-1).
   - **Ruled (B3):** "3. Termux CFEngine + thin Kotlin" (operator ruling, 2026-11-14, B3): state 1 on Android is Termux CFEngine fed tendcf projections; the Kotlin agent holds trust and consent only (05 Idea 4). Sub-rulings: "1. Field on entries" (one host per phone; each Android promise names its target user and the work profile's owner app; unreachable profile reports `not_kept`), "1. Termux + Kotlin trust check", "1. Never" (tendcf never holds a DPC slot), "1. Native screen + Termux" (see 07 and 09).

3. **The Mac in state 1 was the daily driver, and enforcing on it felt too risky.** The guide makes dry-run "the standing posture" on the primary workstation (guide:1376-1378). A root `cf-execd` built from a fork on the machine that "cannot easily be reimaged" stayed in dry-run for good.
   - **Early sign:** no launchd item enforced on any Mac within a month, and no macOS CI leg.
   - **Countermeasure:** use a spare Mac or a macOS VM (UTM or tart) for state 1. Start with user-level LaunchAgents, which need no root. Ask for a GitHub macOS CI leg by name: global rule 37 requires the request to be explicit.
   - **Ruled (B6):** "1. Plain Mac, launchd by tendcf" (operator ruling, 2026-11-14, B6): state 1's Mac has no nix-darwin; tendcf renders launchd; Nix for authoring and building only. "1. macOS VM on bigmac" (B6 sub 1, E-2): state 1's Mac is an Apple Silicon macOS VM (tart / Virtualization.framework) on bigmac (MacBookPro18,1), with snapshot and rollback; CI can run the same image; it is a client, not an always-on server. "1. Dry-run only" (B6 sub 2, M-§12-01 / Q18): bigmac may run tendcf in dry-run only (compute and report the diff, log drift, apply nothing); the VM is the only enforcing Mac in state 1; the VM is also the G8 log-archive server, reachable only while bigmac is awake, and devices buffer JSONL. "1. Root in VM, user on bigmac" (B6 sub 3): the enforcing VM runs tendcf as a root LaunchDaemon; bigmac's dry-run runs as a user LaunchAgent, no root; state 1 must verify the root launchd render path (skipped by the WarpBuild spike). Ruled exception (operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"): the VM may enforce early as an explicit, ruled exception like pastebin's: canary only, operator-authored data (it runs a root `cf-execd` before `tendcf-validate` exists, and D45's "before any further host is enforced" does not apply to it). The order is not changed. Rider: "Try to cut down the MacOS VM image so be smaller, remove stuff we don't need." (B6 sub 1 rider): the VM image is minimised, starting from the smallest base (vanilla, not a dev-tools image) and stripping what state 1 does not need; queued as build work (research the floor).

4. **The handshake was built to the map's TUF-subset floor.** That means an offline 2-of-3 root, targets and snapshot roles, and a key ceremony (map:880-886). It needed hardware and a ceremony nobody scheduled.
   - **Early sign:** a handshake doc names TUF roles or thresholds before a single signed byte has been verified on the phone.
   - **Countermeasure:** handshake v0 is `ssh-keygen -Y sign/verify` over the goal-file bytes plus a monotonic release counter, with an `allowed_signers` file written at enrolment that no release can modify. That is also the cheap form of guide §17's "device-local trust root". It needs a ruling, because the map calls 2-of-3 a floor.
   - **Ruled (B1):** "1. Content checks; v0 first" (operator ruling, 2026-11-14, B1): G3's handshake means content checks (signed by trusted keys, fresh, names this device, owner approval); transport auth decides only who may talk. First build: SSH-signature v0 (`ssh-keygen -Y` over goal-file bytes plus a counter); the map's 2-of-3 offline-root floor may lag until TUF. Also "3 but also the existance of standing wait for user and standing refusal" (B2): a hold window or owner-enrolled standing approval, shown and refusable before apply, with a new approval-record shape without a per-change nonce (a schema bump), plus a standing "wait for user" and a standing refusal.

5. **The Nix frontend became "carry over NixOS configs".** G2's promise that existing configs carry over pulled the compiler into NixOS option semantics and nixpkgs imports. Android has no matching options anyway, so this was work for state 3 done before state 1.
   - **Early sign:** compiler commits about `mkOption`/`mkMerge` compatibility or nixpkgs pinning before any Android option exists.
   - **Countermeasure:** use `lib.evalModules` with tendcf's own small option tree (three Mac options, three Android options). Defer carry-over until after state 1.

6. **The goal moved again** (E3). Live Linux work kept pulling attention because it is the only thing that runs: #41, #42, s5, pastebin.
   - **Early sign:** a new ruling reorders platforms, or more than 20% of commits touch Linux-only paths, before state 1.
   - **Countermeasure:** one dated, one-page "state 1 checklist" as the only milestone. Park the Linux items explicitly; parked is not dead (D3).

7. **Fork upkeep came back.** The CFEngine fork has never been built in CI for macOS arm64, let alone Android, and ShizukuTendCF has its own rebase plan (`docs/SHIZUKUPLUS-REBASE-PLAN.md` in the ShizukuTendCF repository). Two forks, both under one maintainer and his AIs, ate the time the way the upstream episode did (E2).
   - **Early sign:** commits touching `overlay/` or the fork pin to fix macOS build failures, or ShizukuTendCF commits with no state-1 purpose.
   - **Countermeasure:** list which fork commits state 1 actually needs (is `--simulate-json` needed for state 1?). Build state 1 against the smallest delta.

8. **The review gate became the bottleneck.** Every state-1 piece counts as a "design ruling" under AGENTS.md rule 3: a deploy plan, the privilege scope on a host, the consent diff. Each therefore needs two frontier reviews, and the quota windows were short.
   - **Early sign:** a PR waits more than three days for a reviewer, or more AGENTS.md routing edits appear.
   - **Countermeasure:** section C.

9. **The score and the TUI were built before there was a diff to show.** G4's visible, novel parts are fun to build, and the "see and refuse" wording was read as "no state 1 without the TUI".
   - **Early sign:** TUI scaffold research or a scoring prototype before two real goal files have ever been diffed on the Mac.
   - **Countermeasure (an option for the owner, since G4 applies to every change):** state 1's see-and-refuse could start as a CLI diff plus `y/N`, with the score, explanation, graded highlighting and TUI following as state 1.5, if the owner rules that G4's display may lag state 1. Needs the operator's ruling first (independently checked 2026-11-13: weakened (ruling), corrected).
   - **Ruled:** "1. Build order, not scope" (operator ruling, 2026-11-14, B8 sub 3, 13 A(i)-9 / v6 C22). G4 stays whole in state 1, so the "state 1.5" in the countermeasure above is not adopted: there is no "state 1.5". The CLI diff plus y/N is built first and used on the VM and dev devices before any TUI or score work; state 1 is declared only once score, explanation, highlighting and TUI land. This is a build order, not a lag in G4's display.

10. **The phone could not reach the Mac's log archive.** The Mac sleeps (the predecessor's named pain, final-v1:57-58), and Android kills background work. A log "server" got designed instead of moving files.
    - **Early sign:** no transport chosen within a month.
    - **Countermeasure:** keep append-only JSONL per device and sync the directory. Borrow Syncthing whole, or have the Mac pull over adb or Tailscale when both are awake. Write no server code.

### A(ii). State 1 happened; state 3 never did

1. **Nobody outside knew it existed, and the obvious channels were cold.** The CFEngine community closed 26 PRs with "we expect @djbclark, the human, not the LLM" (history §E). The named first adopters, Nix sysadmins, see "compile Nix to CFEngine" as an odd detour. No adopter was ever named (ruling 2).
   - **Early sign:** no public post, no outside issue or star traffic, and the README still opens with "Nothing described here is deployed".
   - **Countermeasure:** name three candidate people now (SIPB is the nearest community). Post a five-minute state-1 demo to NixOS Discourse the week it works.

2. **Installing meant building a forked root daemon from source.** That is the CFEngine fork plus the libntech fork on a Mac, and on Android a sideloaded Shizuku fork plus Island. On certified devices, sideloading now needs developer verification (from 2026-09-30 in some regions, globally in 2027; https://developer.android.com/developer-verification).
   - **Early sign:** install steps take more than a page or need root more than once; no signed artifacts; ShizukuTendCF not registered with any verification route.
   - **Countermeasure:** signed binary artifacts (a Homebrew tap or a flake output; for the APK, F-Droid or Obtainium plus registration through the open-source registry). A CI job that measures time-to-first-converge on a clean VM.

3. **The docs were design essays, not user docs** (E8).
   - **Early sign:** no `docs/start/` or quickstart exists, and "Start here" still points at the architecture guide.
   - **Countermeasure:** a quickstart that a fresh AI session follows in CI on a clean VM (D11).

4. **The stranger's AI could not author it.** The vocabulary is tendcf-specific (writer prefixes, supervision records, ceremony classes), the errors are lint-shaped, and there is no option reference, no MCP server and no skill. The stranger's AI invented options, which is a risk that follows from G6.
   - **Early sign:** errors with no fix hint, and no generated option docs.
   - **Countermeasure:** D8, D9 and D10.

5. **The Mac half had no reason to exist next to nix-darwin.** A Nix sysadmin's Mac already converges with nix-darwin plus Home Manager, so the pitch had to rest on Android alone, and Android needs Shizuku and Island, which is a niche within a niche.
   - **Early sign:** nobody can state in one sentence why a nix-darwin user would install tendcf on a Mac.
   - **Countermeasure:** lead with Android. On the Mac, interoperate (read nix-darwin and coexist) rather than compete. This is an operator question (E-4).

6. **Approval fatigue.** Every change needed an exact-diff approval (R5, R15 in the residue register). The owner himself began rubber-stamping, so "keeps using it" failed for the stranger in week two.
   - **Early sign:** in the owner's own state-1 use, approval time drops toward zero, or he disables approval.
   - **Countermeasure:** log approvals per week and seconds-to-approve from day one. Add owner-set auto-approve classes (for example "version bumps of already-approved apps").

7. **Operator-specific assumptions leaked into the tool:** the operator's ops tree, sudo-secretspec, Tailscale, Hyades, frdminc and djbclark fork names, fixture keys.
   - **Early sign:** `rg 'djbclark|frdminc|~/ops|Hyades'` outside docs/ returns hits in shipped code or defaults.
   - **Countermeasure:** a CI job with a fresh identity and no operator infrastructure, plus that `rg` as a lint.

8. **The bus factor of a forked root daemon put strangers off.** Their question was "who ships the CVE fix for your CFEngine fork?"
   - **Early sign:** the fork pin lags upstream security releases, and no policy is written down.
   - **Countermeasure:** a one-paragraph security-update policy, an automated upstream-release watch (the overlay drift job is close), and the smallest possible delta.

9. **State 2 swallowed state 3.** Retiring all of the operator's ops suite has no bounded list, so state 3 never started, although nothing in it depends on state 2.
   - **Early sign:** state 2 is written as "everything".
   - **Countermeasure:** allow state 3 work to start as soon as state 1 holds, in parallel with state 2 (X-pm-05).

10. **A freedom tool that needed a proprietary AI.** The long-run user's only interface was a vendor model, and the explainer behaved differently across vendors. Free-software users declined.
    - **Early sign:** no test of explain or score with an open-weights model.
    - **Countermeasure:** D18.

---

## B. Tensions inside the goal

Each tension says whether the conflict is real and gives the smallest fix.

B1. **"Other people adopt it" against "no adopter named"** (G1, ruling 2). **Real.** There is no feedback loop until state 3, a year or more away.
   - **Fix:** make the stranger operational now: a CI "stranger" (a clean VM and a fresh AI session given only the public docs) plus one named human candidate. In G8 state 3, add "rehearsed in CI from state 1 on" (X-pm-04).

B2. **"No control node" against "servers"** (G3). **Not a wording conflict**, since G3 defines "server". The design tension is real: a log archive on a Mac that sleeps is a de facto hub, and a phone that blocks on it breaks self-sufficiency.
   - **Fix:** add to G3: "No device's convergence waits on reaching a server; a server is an optional sink, and clients buffer."

B3. **A non-expert approving exact diffs** (G1 long-run user against G4). **Real.** An exact JSON diff is not readable without skill, and G2 says what is shown "reads clearly without manuals".
   - **Fix:** split what is checked from what is shown. The device binds and verifies the exact diff mechanically. The owner is shown a plain-language rendering generated from it, plus the exact diff on demand, and approves by class where he has set a policy. G4 already says "can see"; add "and is shown it in plain words, with the exact form one step away".

B4. **A safety figure produced partly by the same class of system that wrote the change** (G4, G6). **Real.** Failures are correlated, and a prompt-injected author can write text aimed at the scorer.
   - **Fix:** deterministic checks set a ceiling. The AI can only lower the score, never raise it. The scorer runs on a different vendor from the author, never sees the author's rationale text, and the display names each contributor.
   - **Ruled:** "2. Should not (as written)" (operator ruling, 2026-11-14, B8 sub 4, X-safety-06 / v6 C6): the scanning AI SHOULD NOT be the authoring model; it sees only the canonical diff as quoted data, never the author's prose; the diff is hostile input; two model families where the owner has them, and their disagreement caps the score (70). The same model is allowed with no extra cap. The citation for self-preference bias, arXiv:2404.13076 (Panickssery, Bowman and Feng, 15 Apr 2024), was fetched and verified on 2026-11-14, so no fetch is outstanding for v6 C6. The "different vendor" fix above is the stronger form; the ruling is "should not".

B5. **"Confidence out of 100%"** (G4). **Real, and nobody has flagged it.** A percentage reads as a calibrated probability, and there is no labelled corpus to calibrate against.
   - **Option for the owner (X-pm-03):** call it a "safety score (0-100)" until it is calibrated against a seeded corpus of known-bad diffs. Then report its measured hit rate next to it. Needs the operator's ruling first (independently checked 2026-11-13: weakened (ruling), corrected).
   - **Ruled:** "1. Capped 0-100 score" (operator ruling, 2026-11-14, B8): "score from 0 to 100", mechanical checks set a ceiling that AI review can lower but never raise, an explanation of each part, a measured hit rate once a corpus exists (B13 wording 3 / X-pm-03). Values: "1. 09's table, top 95" (B8 sub 1): base 95, never 100 (09 Q3). Owner-set auto-refuse floor: "1. Allowed, off by default" (B8 sub 2).

B6. **Nix-first authoring for devices that will not run Nix** (G2, G5). **Mostly not a conflict:** evaluation happens on any device with Nix, and the phone receives JSON. Two real residues:
   - "Existing NixOS configs carry over" means nothing for Android options.
   - The long-run user may own only a phone. Nix exists on Android (nix-on-droid), which contradicts the predecessor's original "no Nix on Android" constraint (history §D).
   - **Fix:** in G2, "carry over" applies to options that exist on the target. State whether a phone may evaluate Nix itself (E-6). **Ruled (partly):** "2. Allow on release path" with scope "1. Build-time only" (operator ruling, 2026-11-14, B4 rider): Nix may be required to build a release; devices never need Nix at run time. And "1. Importer + matching names" (B7): a one-shot importer for pure-data option families, with tendcf option names matching nix-darwin and NixOS where the meaning is the same.

B7. **Android first while every live host is Linux** (G5). **Real for effort, not for design.** The only enforced adapter (systemd) and the only CI are Linux.
   - **Fix:** one sentence in the plan: "Linux remains the CI and regression substrate; it is not a target before step 4." Keep pastebin running as the regression canary and stop extending it.

B8. **A forked root daemon in a tool meant for strangers** (G1, G7). **Real.**
   - **Fix:** a state-1 design that minimises root. On Android there is none: Shizuku runs as shell UID. On macOS, use user-level LaunchAgents where possible. Define a "minimum fork delta for state 1" (X-pm-06).

B9. **"Accepts updates from any device that completes the handshake"** (G3) **against "the owner can see and refuse"** (G4). **Possible conflict.** Read literally, compromising one peer's key means compromising the fleet (independently checked 2026-11-13: confirmed).
   - **Fix:** in G3, "accepts" should mean "accepts for review". The handshake authenticates a proposer, and applying still needs the owner's yes or an owner-set class.

B10. **G7 against speed.** "Nothing about them changes without the operator's ruling" puts every Android-substrate and handshake choice in the owner's queue.
   - **Fix:** a standing ruling that a spike may bypass any instrument, and that no merged design may depend on a bypass without a ruling.

B11. **G9 against the project's own record.** The project is already failing at fork management: the CFEngine fork with two coexisting mechanisms (`overlay/` and the full-fork pin) and the ShizukuPlus rebase.
   - **Fix:** make the project's own forks G9's first user (D15).

B12. **"Free software" and "used through an AI"** (G1). **Real, and nobody has raised it.** If the only working AI is proprietary, the long-run user's freedom depends on a vendor.
   - **Fix:** add to G1: "The AI path works with at least one open-weights model."

B13. **"Directly at the code level" with Nix and hand-written YAML both allowed** (G1, G2). **A mild conflict:** two sources can drift, and the owner sees a goal-file diff, not his own source.
   - **Fix:** use source maps (D14), and pick one canonical source per host.

---

## C. The process

**What helps under G8.**
1. Pedantry and cross-model review fit code that writes to the owner's devices as root: wrong counts and illustrative text promoted to spec were caught by review (guide:1617-1628).
2. CI on real CFEngine builds.
3. Byte-level fixtures.
4. The handoff discipline lets the work survive many sessions.

**What slows it.**
1. The cost is not merge latency: the median is under an hour (E7). It is incentives. Writing a spec is the reviewable unit, so specs get written instead of spikes.
2. Every docs PR spends frontier quota.
3. "Design rulings" need two frontier reviews, and every state-1 piece qualifies.
4. Quota shortness stops PRs outright (#41 and #42 have sat for a week or more).
5. The process itself churns: five PRs and a week of routing edits.
6. Nothing in the process requires a device to run anything.

**Options** (the owner decides; they can be combined):

- **O1. Spike lane.**
  - Spikes live in a `spikes/` directory on throwaway `spike/*` branches and are never merged. They get no frontier review.
  - Each must run on a real device and leave a note of one page or less, with a log excerpt, in `docs/spikes/` (that is a docs-only PR, see O2).
  - Code moves to master only by a fresh PR under the normal rule.
  - Safety rails: a spike never runs as root on the daily-driver Mac and never on pastebin. It runs only on a test phone, a spare Mac or VM, or as an unprivileged user. It touches no real secrets and no keys used elsewhere.
- **O2. Tiered review.**
  - Docs-only PRs and spike notes: one non-frontier, cross-family review, or a post-merge review within 48 hours with a revert window.
  - Code that runs on a device: one frontier review.
  - Root, trust-root, key-material or handshake code: two frontier reviews.
  - "Design ruling" is narrowed to schema bumps and trust changes.
- **O3. A weekly review budget.** A fixed number of frontier reviews per week. Docs PRs are batched into one weekly review, and code is reviewed first.
- **O4. A docs freeze for state 1.** No new design document for a state-1 piece until a spike for it has run. Existing docs get errata items only.
- **O5. Dogfood the gate.** Once state 1 exists, a config change to the owner's own devices is reviewed by tendcf's own diff, score and approval, not by a PR review. The process becomes the product test.
- **O6. Status quo plus one metric.** Keep every rule, and report "lines of code that ran on a device this week" in each handoff. The number makes the drift visible without changing any rule.

My recommendation (inferred): O1 + O2 + O4 now, O5 once state 1 holds.

**Ruled:** "1. Spike lane, 2. Tiered review, 3. Docs freeze" (operator ruling, 2026-11-14, B10): O1, O2 and O4 are chosen (details at X-pm-07). O6 was not chosen; O5 was not asked.

---

## D. Twenty improvement ideas, ranked by value over cost

Novel ones (not found in any document or digest I read) are marked **[new]**.

1. **State-1 thinnest slice, written as a one-page checklist** (G8.1; about 2-3 weeks of code).
   - Mac: one user LaunchAgent plus one managed file.
   - Phone: one app disabled in the Island profile plus one `settings put`.
   - Handshake: an ssh signature (D4). Logs: JSONL synced to the Mac (D6).
   - Every other piece of the architecture waits. Each line of the checklist must be demonstrable with a log.
2. **Stop list** (G8; zero cost, frees most of the time). Until state 1: freeze s5, the validate proposal's Linux-only parts (keep `adopt` and the device-side gate state 1 needs on the Mac), the D46 restructure, the Guix, Ansible and Salt importers, issue #47's OpenPGP web of trust, Linux-only schema bumps (not the key-type, signer or `briefing_sha256` changes G3 and G4 need) and the simulate-json *upstream* track (keep `--simulate-json` itself, which the preview uses). Merge or close #41 and #42 so they stop costing attention (independently checked 2026-11-13: weakened, corrected: the original list also froze the validate proposal's device-side gate, which carries `adopt` and G4's see-and-refuse and which D1 and A(i)-9 need, and schema changes G3 and G4 need that are not Linux-specific). Status, 2026-11-14: this stop list is a premortem proposal and is not ruled as a whole. Two parts are ruled and stay as ruled: "park s5-design" (B11) and Linux "later in the order, not paused" (B4 rider, "1. Order language"); so "freeze" here is read as that order language, never as a pause on Linux work. #41 and #42 were reviewed and merged on 2026-11-14 (acec5b5, daa4530).
3. **Spike lane plus tiered review** (C, O1 and O2; G8; one AGENTS.md PR). Lets code meet devices without spending frontier quota on throwaway work.
4. **Handshake v0 with SSH signatures** (G3, G4; a few days) **[new]**. `ssh-keygen -Y sign/verify` over the goal-file bytes plus a counter, with `allowed_signers` written at enrolment into storage no release writes. On Android that is app-private storage; on macOS a root-owned file outside the policy tree. It is the cheap realisation of guide §17's device-local trust root. TUF comes later; needs a ruling against the map's floor. **Ruled:** "1. Content checks; v0 first" (operator ruling, 2026-11-14, B1): the first build is SSH-signature v0; the map's 2-of-3 offline-root floor may lag until TUF.
5. **Android applier inside ShizukuTendCF for state 1** (G5; 2-4 weeks; needs a G7 ruling). A Kotlin applier reads the goal file and acts as shell UID through `pm`, `cmd appops`, `settings` and `dumpsys`, with `--user` reaching the Island or Insular profile. It reports JSONL. CFEngine on Android becomes a later choice, not a prerequisite. **Ruled otherwise:** "3. Termux CFEngine + thin Kotlin" (operator ruling, 2026-11-14, B3): state 1 on Android is Termux CFEngine fed tendcf projections; the Kotlin agent holds trust and consent only. So the Kotlin applier here is not state 1's path.
6. **Borrow Syncthing whole for the log archive** (G3, G8.1; days) **[new]**. Each device appends to its own JSONL file and Syncthing syncs the directory to the Mac. There is no server code, sleeping is tolerated, and "server" is just the peer that keeps everything.
7. **Borrow `lib.evalModules` from nixpkgs for the Nix frontend** (G2; 1-2 weeks). Typed options, `mkIf` and `mkDefault`, and generated option docs come with it. Keep tendcf's own small option tree, so no NixOS option compatibility is needed for state 1. numtide's system-manager is prior art for Nix modules on non-NixOS hosts.
8. **Risk annotations in the option schema** (G4, G1; small per option) **[new]**. Every option carries `risk: {class, why, reversible}` and an example. The safety score's deterministic part, the plain-language rendering and the AI's warnings all read this one source, so the explanation is written once, by a human-reviewed PR.
9. **Ship an MCP server and an agent skill with the tool** (G1, G8.3; 1-2 weeks) **[new]**. Tools: `options.search`, `options.explain`, `compile`, `diff --explain`, `score`, `check`. The stranger's AI calls the tool instead of recalling a tendcf it has never seen, which answers the main risk G6 creates.
10. **Error messages as repair prompts, tested on the existing 159 broken fixtures** (G1; small) **[new]**. Every error carries a code, the offending path, a fix hint and a doc link. CI checks that each broken fixture's message names the field to change. This tests the messages, not G6.
11. **Stranger rehearsal in CI** (G8.3; medium). A clean macOS runner and a fresh AI session given only the README quickstart and the MCP server, with time-to-first-converge recorded. The job runs from state 1 onward, so state 3 is rehearsed for a year before a human tries it.
12. **A safety score with a deterministic ceiling** (G4; medium). Rule checks set the ceiling, AI reviewers from another vendor can only lower it, and each component is shown. Calibrate on a seeded corpus of bad diffs (from broken fixtures and red-team cases) and show the measured hit rate. **Ruled:** "1. Capped 0-100 score" (operator ruling, 2026-11-14, B8), with "1. 09's table, top 95" (B8 sub 1).
13. **Borrow Textual for the TUI** (G4; medium). It is Python like the compiler, has a diff and highlight widget pattern, and runs in a terminal or browser. Severity grading maps onto colour, weight and blink tiers. The CLI mode is the same renderer without the TUI. **Ruled:** "2. Borrow both freely; raise Python" (operator ruling, 2026-11-14, B12): Textual, with Toad and textual-diff-view (AGPL-3.0) borrowed as needed; the review TUI is AGPL-3.0-only and needs Python >=3.14 (see 09 X-safety-11).
14. **Source maps from goal-file entries back to Nix lines** (G2, G4; medium) **[new]**. The owner sees "line 12 of phone.nix: disable com.example in Work", not a JSON path. This is what makes "reads clearly without manuals" possible for an exact diff.
15. **Use tendcf on itself** (G9, G8; small to start) **[new]**. Manage the dev Mac's agent tooling and the CI runner configuration with tendcf. Track the two forks (CFEngine, ShizukuPlus) as G9's first users: their drift checks become "your fork is N patches ahead; upstream changed these files".
16. **Replace the stranger's first meeting** (G8.3; small). README: ten lines of what it does today, a 90-second terminal recording of the state-1 pair, and a quickstart. The architecture guide moves behind "How it works".
17. **Approval telemetry from day one** (G4; small) **[new]**. Log approvals per week, seconds-to-approve and refusals on the owner's own devices. That turns guide §20 Q10 and R5 (diff fatigue) into numbers during state 1, not after strangers arrive.
18. **An open-weights path** (G1; small to test) **[new]**. Run explain and score with one local open model, and record where it fails. A freedom tool should not need a vendor.
19. **Android distribution plan now** (G5, G8.3; small). Register ShizukuTendCF through the open-source registry or a limited-distribution account. Document the "advanced flow" sideload; it has a one-day wait before it can be turned on. Track the 2027 global enforcement date. Source: https://developer.android.com/developer-verification.
20. **A weekly "what converged" page generated from device JSONL** (G8; small) **[new]**. It replaces prose status with a table of device, last converge, items managed and refusals. Progress is measured in what ran, and the table doubles as the state-1 acceptance evidence.

---

## E. Questions nobody has asked

E-1. **Does CFEngine have to run on the phone for state 1?** Or may a Kotlin applier in ShizukuTendCF apply goal files directly, with CFEngine on Android as a later option? **Ruled:** "3. Termux CFEngine + thin Kotlin" (operator ruling, 2026-11-14, B3): yes, Termux CFEngine fed tendcf projections; the Kotlin agent holds trust and consent only.
E-2. **Which Mac is state 1's Mac?** The daily driver, a spare or a VM? And is user-level only (no root daemon) acceptable for state 1? **Ruled:** "1. macOS VM on bigmac" (operator ruling, 2026-11-14, B6 sub 1): an Apple Silicon macOS VM (tart / Virtualization.framework) on bigmac (MacBookPro18,1), a client and not an always-on server. "1. Dry-run only" (B6 sub 2): bigmac may run tendcf in dry-run only; the VM is the only enforcing Mac in state 1. "1. Root in VM, user on bigmac" (B6 sub 3): the enforcing VM runs tendcf as a root LaunchDaemon; bigmac's dry-run runs as a user LaunchAgent, no root; state 1 must verify the root launchd render path. Ruled exception (operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"): the VM may enforce early as an explicit, ruled exception like pastebin's: canary only, operator-authored data (it runs a root `cf-execd` before `tendcf-validate` exists, and D45's "before any further host is enforced" does not apply to it). The order is not changed. Image rider (B6 sub 1): minimise the VM image, smallest base, strip what state 1 does not need; queued as build work.
E-3. **Is a single-key ssh signature with a device-pinned allowed-signers file enough for state 1's handshake?** Or does the map's 2-of-3 offline-root floor apply from the first byte? **Ruled:** "1. Content checks; v0 first" (operator ruling, 2026-11-14, B1): the first build is SSH-signature v0 (`ssh-keygen -Y` over goal-file bytes plus a counter); the map's 2-of-3 offline-root floor may lag until TUF.
E-4. **On a Mac that already runs nix-darwin, what is tendcf's job:** replace it, coexist, or only add the handshake and logs? (For state 1's own Mac: "1. Plain Mac, launchd by tendcf", operator ruling, 2026-11-14, B6; no nix-darwin there. The question for other people's Macs is not ruled.)
E-5. **What are the first ten things you actually want managed on the phone?** Which apps, which profile, which settings. The Android design should come from that list.
E-6. **May a phone-only person evaluate Nix on the phone** (nix-on-droid)? Or must authoring always happen on a device with Nix?
E-7. **What date makes state 1 late, and what do you do then?** A rethink, a cut, or switching instruments?
E-8. **Must the AI path work with an open-weights model,** given the free-software aim?
E-9. **Is there one real person (SIPB, a Nix friend) you would ask to try state 1 next spring?**
E-10. **Do spikes fall under the cross-model review rule?** If they do, what is the lightest form you would accept?

---

## Response items

### X-pm-01: Guide §1 still describes Android as Termux-reached

**Target:** `docs/paper/tendcf-architecture-guide.md` §1 "What this is", at the sentence beginning "`tendcf` is a design for keeping"
**Kind:** ruling-drift
**Goal:** G5, G1
**Weight:** misleads
**Finding:** §1 frames the project as fleet configuration for "Android devices reached through Termux". G5 makes Android, with Island/Insular profiles and user-space ShizukuPlus, the differentiator. The repository never mentions either (E5). A first reader learns the wrong aim and the wrong Android mechanism.
**Evidence:** `docs/paper/tendcf-architecture-guide.md:47-52`. `rg -i 'Island|Insular|work profile|ShizukuPlus'` over docs/, schema/, compiler/, bin/ and policy/ finds them only in the goal file.
**Proposed text:**

> `tendcf` is free software for keeping a person's own devices in the state they choose: Android phones first (including work profiles managed by Island or Insular, reached through a user-space Shizuku helper), then Macs, then Linux machines. Every device converges on its own; there is no control node, and some devices also serve others, for example by archiving their logs.

**Merge:** needs the operator's ruling first (whether the Termux path stays for state 1; question E-1)
**Checked:** verified (`rg` run at c3ae530); independently checked 2026-11-13: confirmed

### X-pm-02: Guide §18 build order predates G8

**Target:** `docs/paper/tendcf-architecture-guide.md` §18 "What is built, and what is next", at the sentence beginning "**Build order from here**"
**Kind:** ruling-drift
**Goal:** G8, G5
**Weight:** blocks-goal
**Finding:** The table has Android at Step 2 with no mechanism, Linux at Steps 4-5, signing at 6, pull at 8 and consent at 9. G8 state 1 needs a handshake, see-and-refuse, a log archive and Android before any Linux step. Readers and agents plan from this table.
**Evidence:** `docs/paper/tendcf-architecture-guide.md:1359-1374`.
**Proposed text:**

> **Finish line first.** The next milestone is state 1 of the goal: one Mac and one Android phone converge from Nix-authored config, accept updates only after the handshake, and archive logs on the Mac. Each step below is ordered by what that milestone needs; Linux remains the CI substrate and is not a target before state 1.

**Merge:** insert before the table. The table's reordering needs the operator's ruling first.
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### X-pm-03: G4's "confidence out of 100%" implies calibration

**Target:** `docs/review-2026-11-13/00-goal-definition.md` G4 "Safety", at the sentence beginning "The owner is shown a safety confidence"
**Kind:** question
**Goal:** G4
**Weight:** improves
**Finding:** A percentage reads as a probability that the change is safe. With no labelled corpus behind it, it is an uncalibrated score, and a non-expert will read 95% as "safe". Part of it comes from an AI of the same class as the author, so its errors are correlated with the author's (B4).
**Evidence:** inferred.
**Proposed text:**

> The owner is shown a safety score from 0 to 100, set as a ceiling by mechanical checks that AI review can lower but never raise, with an explanation of each part of it and its measured hit rate once a test corpus exists.

**Ruled:** "1. Capped 0-100 score" (operator ruling, 2026-11-14, B8; B13 items 2/3 are settled by it, wording 3): "score from 0 to 100", mechanical checks set a ceiling AI review can lower but never raise, an explanation of each part, a measured hit rate once a corpus exists. The proposed text above is the ruled wording. Ruled; the sentence is in `00-goal-definition.md` G4 as of the rulings commit of this PR (2026-11-14), with the original highlighting clause kept (that sentence, wording 3 plus the highlighting clause, is the ruled wording: "1. Yes, keep it", operator ruling, 2026-11-14, PR 62 review Q5, record line L61; see 14-synthesis-and-rulings.md "PR 62 review rulings (2026-11-14)"). Implementation of the score itself is pending.

**Merge:** ruled (G4 wording)
**Checked:** inferred; independently checked 2026-11-13: confirmed

### X-pm-04: G8 state 3 has no rehearsal

**Target:** `00-goal-definition.md` G8 "Finish line", item 3
**Kind:** add
**Goal:** G8, G1
**Weight:** improves
**Finding:** State 3 is tested only once a real stranger exists, and no adopter is named (ruling 2). A CI stranger (a clean VM and a fresh AI session given only the public docs) can rehearse it from state 1 onward.
**Evidence:** `00-goal-definition.md:58-65`, :82.
**Proposed text:**

> 3. … and keeps using it. From state 1 on, a clean machine with a fresh AI session that has only the public docs rehearses this in CI.

**Ruled:** "1. Add the rehearsal sentence" (operator ruling, 2026-11-14, B13 item 5, G8 item 3 rehearsal): append "From state 1 on, a clean machine with a fresh AI session that has only the public docs rehearses this in CI." Ruled; the sentence is in `00-goal-definition.md` G8 item 3 as of the rulings commit of this PR (2026-11-14). The CI rehearsal itself is not built (pending).

**Merge:** ruled
**Checked:** inferred; independently checked 2026-11-13: confirmed

### X-pm-05: State 3 need not wait for state 2

**Target:** `00-goal-definition.md` G8, at "Three states, in order:"
**Kind:** question
**Goal:** G8
**Weight:** improves
**Finding:** "In order" can be read as forbidding any state-3 work until all of the operator's ops suite is retired. State 2 is unbounded, and nothing in state 3 depends on it.
**Evidence:** `00-goal-definition.md:58`.
**Proposed text:**

> Three states. Each is reached in this order, but work toward state 3 may start once state 1 holds.

**Ruled:** "1. Adopt the clarification" (operator ruling, 2026-11-14, B13 item 4, G8 order): replace "Three states, in order:" with "Three states. Each is reached in this order, but work toward state 3 may start once state 1 holds." Ruled; the sentence is in `00-goal-definition.md` G8 as of the rulings commit of this PR (2026-11-14).

**Merge:** ruled
**Checked:** inferred; independently checked 2026-11-13: confirmed

### X-pm-06: Minimum fork delta for state 1

**Target:** `docs/architecture/upstream-overlay.md`, at the sentence beginning "no longer bounds the tested artifact"
**Kind:** add
**Goal:** G7, G1
**Weight:** improves
**Finding:** CI builds the full integration branch: fork master plus every fix branch plus simulate-json. No document lists which fork commits state 1 needs on macOS or Android, so the stranger-facing build is the largest possible delta.
**Evidence:** `docs/architecture/upstream-overlay.md:50-56`; inventory §E.
**Proposed text:**

> For each finish-line state, this file lists the fork commits that state needs and why; the build shipped to people other than the operator carries only those.

**Merge:** insert after that paragraph
**Checked:** not checked (the list itself); independently checked 2026-11-13: confirmed (anchor and finding)

### X-pm-07: AGENTS.md spike lane

**Target:** `AGENTS.md` "Standing rule", item 3, at "Every PR, docs-only included"
**Kind:** add
**Goal:** G8
**Weight:** improves
**Finding:** The rule has no form for throwaway code that must run on a device before it is designed. As a result, design documents are the cheapest reviewable unit, which matches the 242-of-400 docs-only commit record (E1, at `eefea3c`).
**Evidence:** `AGENTS.md:62-69`; inventory §B.
**Proposed text:**

> Spikes are the exception: code on a `spike/*` branch under `spikes/` is never merged, needs no review, runs only on a test device, a spare machine or as an unprivileged user, and leaves a one-page note in `docs/spikes/`. Anything from a spike reaches master only by a new PR under this rule.

**Ruled:** "1. Spike lane, 2. Tiered review, 3. Docs freeze" (operator ruling, 2026-11-14, B10): O1 spike/* branches are never merged, get no frontier review, each runs on a real non-production device and leaves a one-page note; O2 tiered review (light for docs and spike notes, one frontier review for device code, two for root, trust-root, key and handshake code); O4 no new design doc for a state-1 piece until a spike for it has run. O6 was not chosen; O5 (dogfood the gate) was not asked. The change to tendcf AGENTS.md standing rule 3 is written there in the rulings PR. The proposed text above is the O1 form; the final wording of the rule is the rulings PR's. Ruled. Reading of "light", added in fix round 1 and not part of the ruling: it changes review depth and scope only; it does not waive model-routing, quota, reservation or admission rules, and the cross-model rule still decides who may review. Who may do a light review is ruled: "2. Cheaper reviewer allowed" (operator ruling, 2026-11-14, PR 62 review Q2): any model outside the author's family that is not on the weaker-tier ban list may do a light review; if it is a frontier model, the frontier checks still apply (see AGENTS.md standing rule 3).

**Merge:** ruled (section C options O1, O2, O4)
**Checked:** verified (read); independently checked 2026-11-13: confirmed

---

## Not read

1. The paper (`tendcf-architecture-paper.md`) apart from what the digests cite.
2. The map, apart from grep hits (R4, D8, the 2-of-3 floor).
3. change-process, v4, v5, s5 and the validate proposal, except through the digests.
4. The handoffs.
5. The other twelve phase-2 reports (none had landed when I read the directory).
6. ShizukuTendCF, apart from the fleet applier header and its commit log.

Nothing was run on any host, and no tests were run.

Last search run: firecrawl scrape of https://developer.android.com/developer-verification (verification enforcement dates and the hobbyist and open-source routes, which back A(ii)-2 and D19). The general searches returned noise. No other claims were searched.

## Withdrawn after checking

None. The independent checker refuted no claim in this report.
