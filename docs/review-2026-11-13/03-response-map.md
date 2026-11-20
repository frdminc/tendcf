# Response: implementer map against the 2026-11-13 goal

Target: `docs/architecture/architecture-DEFINITIVE-v3.md` (1,346 lines, read in full)

Base commit: eefea3c

How this was produced: one reviewing agent (Claude Opus), then an independent checking agent that tried to refute each finding; nothing was executed unless an item says so.

Item counts by Weight after corrections: 48 full items and 10 table nits; blocks-goal 21, misleads 13, improves 13, nit 11 (1 full, 10 in the table). One change from checking: M-§2-05 moved from blocks-goal to misleads. Checking: 42 items checked (24 confirmed, 18 weakened and corrected, 0 withdrawn); the other 6 full items and the nit table were not sampled and stand as written.

**Goal:** `docs/review-2026-11-13/00-goal-definition.md` G1–G9
**Reviewer:** Opus 5.5 high, read-only. Line numbers below are at `eefea3c` and are evidence only; anchors are quoted phrases.

Sources consulted: firecrawl search "Textual Python TUI framework" (found Textualize/textual, a Python TUI framework that also runs in a browser); firecrawl search "Insular Island work profile Shizuku device owner" (F-Droid: Insular needs device-admin to create its work profile); Basic Memory `books` + `book-kb query 'trustkeysfrom|ppkeys'` (Learning CFEngine ch. 33: cf-serverd trusts keys by address via `trustkeysfrom`).

---

## §0 Orientation

### M-§0-01: "The trust/consent layer is the point" no longer states the aim

**Target:** `architecture-DEFINITIVE-v3.md` §0 "Orientation for the AI that implements this", item 3, at "The trust/consent layer is the point."
**Kind:** ruling-drift
**Goal:** G1, G4, G8
**Weight:** misleads
**Finding:** The aim is now an adoptable tool that gives people control of their own devices, used through an AI or directly (G1). See-and-refuse is the safety mechanism (G4), not the point. An implementer who reads item 3 first will keep ranking consent work above convergence. G8 gives the implementer a measurable target, and the map has none.
**Evidence:** map:37-39; goal-definition:96-102 (difference 3, difference 7).
**Proposed text:**

> 3. **The aim is an adoptable tool that gives people control of their own devices** (goal G1, [`../review-2026-11-13/00-goal-definition.md`](../review-2026-11-13/00-goal-definition.md)). A person works through their own AI or directly in code, whichever they prefer at the moment. The safety mechanism is see-and-refuse (G4): nothing changes a device except as an exact, mechanically checked difference that its owner can see and refuse. Measure every step against the finish line (G8). State 1 comes first: one Mac and one Android device converge from Nix-authored config, accept updates only after the handshake, and archive logs on the Mac.

**Ruled:** D47 is ruled: "1. Yes, supersede D8's wording" (`operator ruling, 2026-11-14, Smaller 3, M-§15-01`). Adoption is the aim, and G4 see-and-refuse is its safety mechanism; D47 supersedes D8 "Sovereignty is the point" and §0 items 1 and 3.

**Merge:** replace that item. Ruled (operator ruling, 2026-11-14, Smaller 3, M-§15-01).
**Checked:** verified (read map §0 and the goal file); independently checked 2026-11-13: weakened, corrected

### M-§0-02: "Interesting and correct beats minimal and safe" conflicts with G1 and G4

**Target:** §0 item 1, at "This is a freedom project. Interesting and correct beats minimal and safe"
**Kind:** reword
**Goal:** G1, G4
**Weight:** misleads
**Finding:** Read literally, "minimal and safe" losing to "interesting" sits badly with G4 for a tool strangers adopt, though the maxim was about design ambition, not device safety. "Token spend is the cost that matters (§13)" points to a section that never mentions tokens. The pointer "(§13)" has no token text; §14 "Premium-token residue" is probably what was meant. It also contradicts the 2026-10-31 standing rule that getting tendcf right outranks cost.
**Evidence:** map:28-30; map:1152-1176 (no token text); `CLAUDE.md` "Standing rule: most important work" (2026-10-31).
**Proposed text:**

> 1. **This is free software for people who want control of their own devices.** Correct beats interesting; when correct and safe conflict, stop and ask (item 5). Development cost is secondary to getting it right (operator, 2026-10-31). A user's own AI token cost at run time is a design constraint (R12).

**Ruled:** "1. Adopt the proposed text" (`operator ruling, 2026-11-14, Smaller 2, M-§0-02`). The proposed text above replaces §0 item 1 as written; it is no longer a proposal. Ruled; merged into the map's §0 item 1 on 2026-11-14 (the rulings commit of this PR).

**Merge:** replace §0 item 1 with the proposed text. Ruled (operator ruling, 2026-11-14, Smaller 2); it rewrites an operator principle and the operator has approved the rewrite.
**Checked:** verified (grep of §13 for "token": no hit); independently checked 2026-11-13: weakened, corrected

### M-§0-03: The reference target is now macOS, and the distro is de facto Debian

**Target:** §0 item 2, at "The reference target is a stock Linux distro on bare metal"
**Kind:** ruling-drift
**Goal:** G5, G2
**Weight:** misleads
**Finding:** G5 puts macOS first, Android second and Linux fourth and fifth. "Ubuntu Server LTS is the working default; the distro name is open until Step 4" is also stale. The first live Linux host is Debian 13, and schema v5 is dpkg-specific. "One of two equal Site Model authoring languages" contradicts G2's Nix-first rule.
**Evidence:** map:31-36; digest-current-plan C1, D2; goal-definition:39-45.
**Proposed text:**

> 2. **Platforms come in the order of goal G5:** macOS as server, Android as client, macOS as client, Linux as server, Linux as client. Nix is the authoring language (real Nix, NixOS-style options; G2), with plain YAML/JSON beneath it as the data form Nix evaluates to. Nix is used verbatim on hosts that already run NixOS or nix-darwin, and is never the installed OS a stranger must adopt. The first Linux host is Debian 13 (pastebin); a Linux distro default is chosen when Linux becomes the current platform.

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4`): D48 and D49 are adopted as corrected (M-§15-02, M-§15-03). Linux is later in the order, not paused: "1. Order language" (`operator ruling, 2026-11-14, B4 rider, Linux`).

**Merge:** replace that item. Ruled (operator ruling, 2026-11-14, B4).
**Checked:** verified (map and digest); independently checked 2026-11-13: confirmed

---

## §1 The architecture in one screen

### M-§1-01: The diagram lacks peer delivery, service roles and the owner's review surface

**Target:** §1, the diagram from "Signed release" to "JSONL log (capture)"
**Kind:** add
**Goal:** G3, G4, G8
**Weight:** improves
**Finding:** The diagram runs one way, from compile to device. G3's "accepts updates from any other device" and G8's "logs archived on the Mac" have no box. Neither does G4's owner-facing scan and CLI/TUI, so the parts the owner actually touches are invisible.
**Evidence:** map:55-96.
**Proposed text** (insert between "Signed release" and "CFEngine +"):

> ```
>           ▼  delivered by any peer that completes the handshake (G3;
>           │  what it covers is open, §16 Q17); delivery never authorizes
>   Owner review           device-computed diff, scanned (rules + AI):
>   (CLI or TUI)           confidence /100, explanation, graded
>                          highlighting; owner signs accept or refuses
> ```
>
> and after "SQLite (index)":
>
> ```
>           ▼  shipped to a peer that provides the service
>   Service roles          log archive, monitoring (a "server" is any
>   ("servers", G3)        device holding such a role; not a control node)
> ```

**Merge:** insert after it. The handshake is ruled (operator ruling, 2026-11-14, B1: content checks; "1. Content checks; v0 first").
**Checked:** verified (read the diagram)

---

## §2 Requirements

### M-§2-01: R2, R3, R11 and the license clause of R10 are confirmed

**Target:** §2, R2 "No permanent control node", R3 "Resource efficiency", R11 "Preserve", and R7/R10 "Generic layer publishable (GPL-3.0-or-later for code)"
**Kind:** question
**Goal:** G3, G1
**Weight:** nit
**Finding:** G3 restates R2 more strongly, and R3 is untouched. R11 holds, except that its "observability stack as optional sink" is extended by R15 (M-§2-11). GPL-3.0-or-later satisfies G1 and G9's "stays free software". There is no text change except a pointer.
**Evidence:** map:109-112, 118-122.
**Proposed text:**

> **R2** No permanent control node; every device converges on its own (G3). Feature roles `{main, backups[], peers[]}` are data.

**Merge:** replace R2's first sentence
**Checked:** verified

### M-§2-02: R1 targets: reorder for G5 and add work profiles

**Target:** §2, R1, at "Targets: macOS/Apple Silicon, Linux x86_64, Linux aarch64, Android"
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** The list order reads as priority and puts Android last. G5 makes Android the differentiator and requires it to work with Island/Insular work profiles. R1 says nothing about profiles.
**Evidence:** map:105-108; goal-definition:47-49.
**Proposed text:**

> - **R1** Targets, in build order (G5): macOS/Apple Silicon as server, Android as client (every user profile, including Island/Insular work profiles), macOS as client, Linux x86_64 and aarch64 as server, then as client. Intel Mac mini out of scope. tendcf-agent is Android-only; macOS and Linux run CFEngine plus the `tendcf-validate` command, with no daemon (D45).

**Merge:** replace R1. Ruled (operator ruling, 2026-11-14, B4, "1. Adopt D47-D50": D48 adopted).
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§2-03: R4 Android: user-space ShizukuPlus, no device-owner

**Target:** §2, R4, at "Android keeps Termux (+api, +x11), the built-in Terminal app, a Shizuku-class helper"
**Kind:** add
**Goal:** G5
**Weight:** blocks-goal
**Finding:** G5's differentiator is user-space ShizukuPlus working with Island/Insular. Insular needs the device-admin/profile-owner slot to create its work profile. So tendcf must never take the device-owner slot, a rule the 2026-08-13 session recorded ("`dpm set-device-owner` is a hard no") that never reached the map. The helper is now a known fork, `frdminc/ShizukuTendCF`, a ShizukuPlus fork.
**Evidence:** map:113-115; `docs/handoffs/HANDOFF_standalone-3fd9_nix2cf-split-communal-orchestration_2026-08-13_601f.md:218-219, :350`; https://f-droid.org/en/packages/com.oasisfeng.island.fdroid/ ("Device administrator privilege is required to create the Insular space (work profile)"); inventory C (ShizukuTendCF).
**Proposed text:**

> - **R4** Android keeps Termux (+api, +x11), the built-in Terminal app, user-space ShizukuPlus (our fork `frdminc/ShizukuTendCF`), tendcf-agent (Kotlin, D45) and CFEngine. tendcf never takes the device-owner slot, which Island/Insular need (operator, 2026-08-13: "`dpm set-device-owner` is a hard no"); [whether this extends to the profile-owner slot: operator's ruling]; it works in every user profile as an ordinary app plus Shizuku. No nix-on-droid. Nix may build zero-on-device-footprint artifacts only.

**Merge:** replace R4. The profile-owner extension is ruled: "1. Never" (operator ruling, 2026-11-14, B3 sub 3): tendcf never holds a DPC slot (profile owner or device owner), and never requires MDM enrolment.
**Checked:** verified (handoff lines and F-Droid page excerpt); not checked: whether ShizukuPlus can act on a work profile's packages without root; independently checked 2026-11-13: weakened, corrected

### M-§2-04: R5 "No bare-metal Nix ... stock distro is the reference" needs rescoping

**Target:** §2, R5, at "No bare-metal Nix. A mainstream stock distro is the reference."
**Kind:** reword
**Goal:** G2, G5
**Weight:** misleads
**Finding:** With macOS first, "the reference" is no longer a Linux distro. "No bare-metal Nix" coexists with two NixOS target hosts (passthrough) and with Nix-first authoring, so it needs to say what it forbids: requiring a stranger to install NixOS.
**Evidence:** map:116-117; digest-current-plan D3.
**Proposed text:**

> - **R5** tendcf never requires NixOS as the installed OS. Hosts already on NixOS or nix-darwin keep that configuration verbatim (passthrough, D12). On Linux, a mainstream stock distro is the target; Debian 13 is the first live host. Nix may be required to build a release (build time only): a device never needs Nix at run time.

**Ruled:** "2. Allow on release path" (`operator ruling, 2026-11-14, B4 rider, Nix on release path`): Nix may be required to build a release. Scope: "1. Build-time only" (same rider, 2026-11-14): devices never need Nix at run time. This amends R5 and D6 here, and change-process §2 "Nix is an optional builder" (see `04-response-plans.md` PL-§2-02 and X-CO-02). The last sentence of the proposed R5 text above is the amendment; D6 ("Nix on bare metal: No. Builds / dev shells / authoring language / passthrough ...") is amended the same way: the build and authoring uses may be a requirement of building a release, and Nix is still never needed on a device at run time. Ruled; merged on 2026-11-14 (the rulings commit of this PR): the map's R5 and D6 and change-process §2 carry the amendment. The rest of this item's older wording is not otherwise rewritten.

**Merge:** replace R5; amend D6 and change-process §2 to match. Ruled (operator ruling, 2026-11-14, B4 rider, Nix on release path).
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§2-05: R7/R10 "auto-review" lets an AI accept without the owner seeing

**Target:** §2, R7/R10, at "Pull becomes user sovereignty: the person's own AI, suggested default prompt plus their extras, auto-review or a conversation."
**Kind:** ruling-drift
**Goal:** G4, G3
**Weight:** misleads
**Finding:** G4 says the owner can see and refuse every difference. Auto-review is a mode the person chooses, not a default. In it the person's AI signs the yes, so a change can apply that the owner never saw; whether an owner-chosen delegation satisfies G4 is the ruling. G3 also makes delivery peer-to-peer ("from any other device"), not just push or pull.
**Evidence:** map:118-120, 963; goal-definition:31-37.
**Proposed text:**

> - **R7 / R10** Push, pull and peer delivery: a device accepts a release from any device that completes the handshake (G3, R14). The owner sees every difference and may refuse it (R16). The owner's own AI explains and warns, but does not accept on the owner's behalf unless the owner has chosen that explicitly, per device, and can revoke it. Generic layer publishable (GPL-3.0-or-later for code).

**Merge:** replace R7/R10. Needs the operator's ruling first: whether any AI-only accept mode survives G4.
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### M-§2-06: R12 "Token budget is real" should mean the user's run-time cost

**Target:** §2, R12, at "Token budget is real. Design so routine work is cheap."
**Kind:** reword
**Goal:** G1, G4
**Weight:** improves
**Finding:** For development, the 2026-10-31 ruling lifted cost. For adoption (G1), though, every change is scanned by AI (G4), and a person with no admin skill pays for that. R12 is more important than before, but it now concerns run time.
**Evidence:** map:123; `CLAUDE.md` standing rule 2026-10-31.
**Proposed text:**

> - **R12** A user's AI cost per change is a design constraint: authoring and the G4 safety scan must be cheap enough for routine changes on a personal budget. Mechanical scanners run first, and AI scanning sees only the device-computed diff and what it cites, not whole files. (Development cost is governed by the 2026-10-31 standing rule, not by R12.)

**Merge:** replace R12
**Checked:** verified

### M-§2-07: R13 becomes the premise and covers direct code-level use

**Target:** §2, R13, at "AI agents are the primary authors."
**Kind:** reword
**Goal:** G6, G1
**Weight:** improves
**Finding:** G6 makes AI authorship the premise, not a hypothesis. G1 also requires direct code-level use "whichever the user prefers at any moment", so nothing may be reachable only through an AI. G1 additionally gives the AI an authoring-side duty: explain, and warn when a request looks unwise. Nothing in the map ships for that duty (§11 covers only the consent-side advisor).
**Evidence:** map:124-125, 953-980; goal-definition:11-17, 51-52.
**Proposed text:**

> - **R13** AI agents write the configuration; that is the premise (G6), not a hypothesis. Every action an AI can take is equally available at the code level (G1). tendcf ships an authoring guide for the user's AI, a replaceable public file beside the default advisor prompt, covering how to turn a wish into Site Model config, when to warn, and how to explain. Local knowledge; machine-checkable conventions.

**Merge:** replace R13
**Checked:** verified

### M-§2-08: New R14, peer updates by handshake (G3)

**Target:** §2, after R13
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** G3 is firmer than any map text. A device accepts updates from any other device that completes the correct cryptographic handshake. The map has delivery only as push from a `deploy-origin` host or pull on schedule (§9.11). The word "handshake" does not say whether it authenticates the peer (transport) or the content (signature); see M-§16-03 Q17.
**Evidence:** map:917-920; goal-definition:24-29, 104-106.
**Proposed text:**

> - **R14** Peer updates (G3). Any device may hand a release to any other. The receiving device accepts a release only after the handshake [what it covers, release signature, peer authentication or both, is §16 Q17, operator's ruling]. It then authenticates the release itself by signature (§9.11) and authorizes it only through its own diff and the owner's decision (§9, R16). Delivery never authorizes; a compromised peer can withhold or replay, never change a device.

**Ruled:** B1: "1. Content checks; v0 first" (`operator ruling, 2026-11-14, B1`): G3's handshake means content checks (signed by trusted keys, fresh, names this device, owner approval); transport auth decides only who may talk. First build: SSH-signature v0 (`ssh-keygen -Y` over goal-file bytes plus a counter); the 2-of-3 offline-root floor may lag until TUF. This settles §16 Q17 and the bracketed M-§2-08, M-§9-07, M-§10-02 claims: any device may deliver, and the content is checked. Ruled; the ruling is merged into the map's §9.11 ("The handshake is content checks (D50)") and D50 (2026-11-14, the rulings commit of this PR). The R14 requirement text itself is not yet inserted into §2.

**Merge:** insert after R13, with the bracket resolved to B1's content checks. Ruled (operator ruling, 2026-11-14, B1).
**Checked:** inferred (the design reading); map text verified; independently checked 2026-11-13: weakened, corrected

### M-§2-09: New R15, service roles ("servers")

**Target:** §2, after R14
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** G3 defines a "server" as a device that provides services such as log archiving and monitoring, and G8 state 1 needs logs archived on the Mac. The map treats any central log copy as "optional best-effort" (§8) and has no service role in the build order.
**Evidence:** map:460-462, 1156-1168; goal-definition:26-29, 108-109.
**Proposed text:**

> - **R15** Service roles (G3). A "server" is any device holding a role that serves others: first the **log archive** (receives and keeps other devices' JSONL), later **monitoring** (watches other devices' reports and convergence). Roles are data in `roles` (§4.1), are rendered as ordinary tendcf service records, and change no architecture: each device's own JSONL stays its authoritative record (§8). The archive holds an authenticated copy, never a source of truth or a control point.

**Merge:** insert after R14
**Checked:** verified (map §8, §13); independently checked 2026-11-13: confirmed

### M-§2-10: New R16, see-and-refuse on every device, every tier

**Target:** §2, after R15
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 covers every device: "Nothing changes a device except as an exact, mechanically checked difference that the device's owner can see and refuse." The map's §10 default is `operator`: no local yes, so on operator hosts (the whole of G8 state 1) nothing shows the owner a diff before apply. The map also has no requirement that what is shown "reads clearly without manuals" (G2).
**Evidence:** map:938; guide:846 (same default); goal-definition:21-22, 31-33.
**Proposed text:**

> - **R16** See and refuse (G4). On every device, whatever its `trust_tier`, a change applies only as the device-computed diff of §9.1, shown to the owner before apply in words that need no manual, with a refuse that wins. Standing approvals are the owner's own choice, per device, revocable, and logged; none is a default.

**Ruled:** B2: "3 but also the existance of standing wait for user and standing refusal" (`operator ruling, 2026-11-14, B2`). Option 3 (a hold window, or an owner-enrolled standing approval, shown and refusable before apply; a new approval-record shape without a per-change nonce, which is a schema bump), plus two further standing modes: a standing "wait for user" (hold until the owner answers) and a standing refusal. Smaller 1: every build gets a developer mode open to any owner, using an owner-enrolled standing approval for a signer of their choice (the B2 mechanism), with revoke and deny always honoured and a persistent indicator; the separate developer build is `05-response-code.md` C-android-03. Ruled; schema bump pending (SCHEMA-TOUCHING).

**Merge:** insert after R15. Ruled (operator ruling, 2026-11-14, B2: "3 but also the existance of standing wait for user and standing refusal"; it changes the §10 `operator` default, M-§10-01).
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§2-11: New R17, safety scan with confidence, explanation and graded highlighting

**Target:** §2, after R16
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The 0–100 confidence, its explanation and highlighting graded by risk are in no document. They need a requirement so that §9 and the build order have something to implement against.
**Evidence:** goal-definition:33-36, 103-104 (difference 4); `rg -n -i '\bTUI\b' docs` (hits only in deprecated tooling reviews).
**Proposed text:**

> - **R17** Safety scan (G4). Every diff is scanned in several ways: mechanical rules derived from §9 (privilege, ceremony class, coverage transitions, removals, integrity flags) and at least one AI reviewer. The owner sees a safety confidence from 0 to 100%, an explanation of why that figure was chosen that cites the hunks behind it, and each questionable hunk highlighted more dramatically the lower its score. The scan advises and never authorizes (§9.12).

**Ruled:** B8: "1. Capped 0-100 score" (`operator ruling, 2026-11-14, B8`): "score from 0 to 100", mechanical checks set a ceiling that AI review can lower but never raise, an explanation of each part, and a measured hit rate once a corpus exists (B13 wording 3, X-pm-03). The cap values are in M-§9-03. B8 sub 4: "2. Should not (as written)" (`operator ruling, 2026-11-14, B8 sub 4`), adopting X-safety-06's text (`09-safety-score-and-tui.md`). Ruled; the score and the authoring-model rule are merged into the map's §9.12 and §11 (2026-11-14, the rulings commit of this PR). The R17 requirement text itself is not yet inserted into §2.

**Merge:** insert after R16
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§2-12: New R18, command-line and TUI modes on a borrowed scaffold

**Target:** §2, after R17
**Kind:** add
**Goal:** G4, G1
**Weight:** improves
**Finding:** G4 asks for both modes and a TUI scaffold borrowed from another project. Since the compiler and validator are Python, a Python TUI framework keeps one language; Textual is an obvious candidate and also serves a browser. Choosing the scaffold is the operator's call (G7 does not cover it, but G4 says "borrowed").
**Evidence:** goal-definition:36-37; https://github.com/Textualize/textual (search excerpt: "lean application framework for Python").
**Proposed text:**

> - **R18** Two review modes over the same scan output (G4): a command-line mode (plain text, scriptable, every screen reproducible as text) and a TUI mode built on a scaffold borrowed from an existing project, not written from scratch. Both show the same figures and highlighting; neither has an action the other lacks. The scaffold is chosen by the operator (§16).

**Ruled:** B12: "2. Borrow both freely; raise Python" (`operator ruling, 2026-11-14, B12`): borrow Toad and textual-diff-view (AGPL-3.0) as needed; the review TUI becomes AGPL-3.0-only and moves to Python >=3.14 (Toad's floor; Toad pins `textual==8.2.7`). Follow-ups: Termux and Mac Python >=3.14 availability; keep incompatible licences out of the TUI module. §16 Q22 is answered. Ruled; the B12 ruling is merged into the map's §6 ("Review TUI borrows (B12)") (2026-11-14, the rulings commit of this PR). The R18 requirement text itself is not yet inserted into §2.

**Merge:** insert after R17
**Checked:** verified (search only; no scaffold was evaluated); independently checked 2026-11-13: confirmed

### M-§2-13: New R19, Nix-first authoring with YAML beneath

**Target:** §2, after R18
**Kind:** add
**Goal:** G2
**Weight:** blocks-goal
**Finding:** No requirement covers the authoring language; it lives only in D12, which says "two equal frontends". G2 is a requirement on the user's experience. G8 state 1 requires "Nix-authored config", yet today the Nix side is only an `eval-nix` wrapper over a plain attribute set.
**Evidence:** map:1211; inventory A "Compiler" (cli.py:150-171, `site.nix` a plain attribute set); goal-definition:19-22.
**Proposed text:**

> - **R19** Authoring (G2). Config is written in the real Nix language with NixOS-style options (`mkOption`, `mkIf`, `mkDefault`, module imports), so existing NixOS and nix-darwin configs carry over. Plain YAML/JSON is the data form Nix evaluates to; it can be written by hand and is what the compiler validates. A Nix-authored site runs on hosts without Nix. "Carry over" means a one-shot importer for the pure-data option families (it lists what it did not carry over), plus tendcf option names that match nix-darwin and NixOS where the meaning is the same.

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4`) adopts D49. The meaning of "carry over" in the last sentence is ruled by B7: "1. Importer + matching names" (`operator ruling, 2026-11-14, B7`), a one-shot importer for pure-data option families (it lists what it did not carry), plus tendcf option names matching nix-darwin/NixOS where the meaning is the same. Ruled; D49 and the importer ruling are merged into the map's §5 and decision register (2026-11-14, the rulings commit of this PR). The R19 requirement text itself is not yet inserted into §2.

**Merge:** insert after R18. Ruled (operator ruling, 2026-11-14, B4: "1. Adopt D47-D50", D49 adopted).
**Checked:** verified (inventory digest; I did not open cli.py); independently checked 2026-11-13: confirmed

### M-§2-14: New R20, branch management later (G9)

**Target:** §2, after R19
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** G9 is new and is "built as an extension of the platform's existing patch patterns": the `overlay/` manifest, drift check and retirement check, and §11's "personal branch". Recording it now as an extension point stops near-term designs closing it off, for example by hard-coding the fork's integration-branch workflow as agent-only process.
**Evidence:** goal-definition:67-70; map:978-980; inventory E (overlay.json, 6 patches, weekly drift check).
**Proposed text:**

> - **R20** Later (G9): free-software branch management for people who cannot merge, rebase or compile, built as an extension of the `overlay/` patch pattern (manifest, pin, drift and retirement checks) and of §11's personal branch. Extension point only before G8 state 3; designs in the meantime must not preclude it.

**Merge:** insert after R19
**Checked:** verified

---

## §4 The Site Model

### M-§4-01: "Optional Nix module frontend ... Strangers need not know Nix" contradicts D12 and G2, and inverts schema authority

**Target:** §4.1, paragraph beginning "Optional Nix module frontend (`mkOption` / `mkIf` / `mkDefault`)", and the bullet "YAML fallback gets a parse/re-serialize/diff check (D23) until the Nix authoring frontend exists"
**Kind:** ruling-drift
**Goal:** G2, G7
**Weight:** misleads
**Finding:** The paragraph calls Nix "optional" and YAML a "fallback", contradicting both D12 (equal) and G2 (Nix first). It also says "JSON Schema is generated from the module options; never hand-maintain both". That would make the Nix module the schema authority and demote the hand-written `schema/` of eight schemas and 159 broken fixtures (125 schema-level, 6 byte-level, 28 projection-level). Under G2 (YAML/JSON beneath, which Nix evaluates to), the natural direction is the reverse: options generated from, or checked against, `schema/`. That direction is an instrument choice (G7) and needs a ruling.
**Evidence:** map:216-218, 248-250; inventory A (schema/ 8 files, 1,555 lines).
**Proposed text:**

> The Nix module frontend (`mkOption` / `mkIf` / `mkDefault`; `nix2cf`, D12, D49) is the primary authoring surface (G2). It evaluates to the same YAML/JSON data form a person may also write by hand. `schema/` stays the single authority: the module options are generated from it, or checked against it in CI, never maintained as a second source. A person who does not know Nix can write the YAML/JSON form directly.

**Merge:** replace that paragraph. Needs the operator's ruling first on which side is generated (§16 Q23).
**Checked:** verified (map text); not checked: the feasibility of generating NixOS-style options from JSON Schema; independently checked 2026-11-13: weakened, corrected

---

## §8 Local record

### M-§8-01: The log archive needs a JSONL writer that exists nowhere, and the index question changes

**Target:** §8, at "Optional best-effort push of a subset into Vector / OpenObserve / Grafana is never the record of truth." and "It is not built yet on any host — nothing writes report rows"
**Kind:** add
**Goal:** G8, G3
**Weight:** blocks-goal
**Finding:** G8 state 1 requires logs archived on the Mac. Nothing writes JSONL on any platform yet, so the capture writer on macOS and on Android, plus authenticated shipping to the archive, sit on the critical path. They are no longer optional. The device's own copy stays authoritative, and §8's reasoning holds. D45 item 7 (who owns the SQLite index on Linux and macOS) is ruled: both. The archive service keeps a fleet-wide SQLite index over every device, and each device keeps its own index over its own JSONL (see **Ruled** below).
**Evidence:** map:436-444, 460-462, 1130-1132; inventory A ("No hits at all: ... jsonl, sqlite").
**Proposed text** (insert after "Optional best-effort push ..."):

> **Log archive (R15, G8 state 1).** A device holding the `log-archive` role receives other devices' JSONL rows over the R14 handshake and appends them, keyed by device public key and release stamp. Shipping is retried, idempotent by row identity, and never blocks convergence. The sender's JSONL stays the record; the archive is an authenticated copy. **Indexes (D45 item 7):** the log archive keeps a fleet-wide SQLite index over every device's rows, and each device also keeps its own SQLite index over its own JSONL. The device's JSONL stays authoritative. The JSONL writer on macOS and on Android is therefore on the path to G8 state 1.

**Ruled:** "make that both" (`operator ruling, 2026-11-14, Smaller 6, M-§8-01`, given after first answering "2. Per-device indexes"): option 3 "Both". The log archive keeps a fleet-wide SQLite index over every device, AND each device keeps its own index; device JSONL stays authoritative. This supersedes the earlier "2. Per-device indexes" answer (every device keeps its own SQLite index; the archive stores JSONL only; no fleet-wide index) and supersedes this item's earlier recommendation (a fleet-wide index at the archive only, with per-device indexes off Android waiting), which is why the proposed text above was rewritten. D45 item 7 is answered; ruled; merged on 2026-11-14 (the rulings commit of this PR) into the map's §8, §12 item 7 and D45/D18. The new log-archive paragraph in the proposed text above (rows "authenticated by device public key", "idempotent by row identity") is reviewer-proposed wording that was merged with it; kept by the operator ("1. Keep both", `operator ruling, 2026-11-14, PR 62 review Q6`, record line L62; see 14 "PR 62 review rulings (2026-11-14)").

**Merge:** insert after it. Ruled (operator ruling, 2026-11-14, Smaller 6); the index clause answers D45 item 7.
**Checked:** verified (map; inventory search results); independently checked 2026-11-13: weakened, corrected

---

## §9 Releases, ChangePlan, TUF (Model B)

### M-§9-01: What still holds: Model B is G4's "exact, mechanically checked difference"

**Target:** §9 intro, at "The **ChangePlan is the diff** between the goal file the device has already approved and the one the release proposes"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** G4's first sentence describes what Model B already specifies: the device-computed diff (§9.1), canonical bytes and refuse-never-normalize (§9.2), entry-granular structural hunks (§9.2), all-or-nothing accept (§9.3), fail-closed versions (§9.6) and coverage in the file (§9.7). Saying so in one sentence protects these sub-decisions from being cut as "larger than needed". They are the mechanism G4 names, and the hunk key-paths are exactly what graded highlighting needs to anchor on.
**Evidence:** map:471-478, 526-616, 688-700, 736-770.
**Proposed text:**

> This is the mechanism of goal G4: the device-computed diff is the "exact, mechanically checked difference" the owner sees and may refuse, and its `(domain, kind, id)` hunks are the units the safety scan scores and highlights (§9.12). §9.1–§9.3, §9.6 and §9.7 are therefore not candidates for simplification.

**Merge:** insert after that paragraph
**Checked:** verified

### M-§9-02: Add §9.12, "Safety scan", what G4 adds to Model B

**Target:** §9, new subsection after §9.11 "Signing and delivery"
**Kind:** add
**Goal:** G4, G1
**Weight:** blocks-goal
**Finding:** Nothing in §9 scores or highlights a diff. The design constraints follow from existing rules. The scan is semantic-layer output (D29, DC-3), so it never authorizes. It must run over the device-computed diff (§9.1), because a release-time scan is only a preview. Its bytes should be bound in the approval record, and `briefing_sha256` already exists for this. Score and explanation must cite hunk key-paths, so a reader can check them.
**Evidence:** map:910-915, 1228; `schema/approval-record.schema.json:35` (`briefing_sha256`).
**Proposed text:**

> ### 9.12 Safety scan (goal G4, R17)
>
> - The scan runs over the **device-computed** diff (§9.1). A scan of the compiler's preview is itself a preview.
> - Scanners are of two kinds. **Mechanical** scanners are deterministic and derived from this section: validator-held privilege (§9.8), derived ceremony class (§9.4, §9.8), coverage transitions (§9.7), tombstone versus bare deletion (§9.8), predicted-versus-device diff inequality (§9.1), unbound fetched content (§9.8). **AI** scanners are one or more models the owner chooses, given the diff, the hunks' full old and new entries, and nothing they cannot cite.
> - Output is one **scan report**: a score from 0 to 100 (capped; ruled, B8, M-§9-03), an explanation that cites hunk key-paths, and a per-hunk score that drives highlighting. CLI and TUI render the same report (R18).
> - The scan **advises and never authorizes** (D29). No score accepts a change. The owner's accept or refusal is the approval record of §9.1, and the scan report's hash is carried as its `briefing_sha256`, so the record shows what the owner was shown.
> - The scan report is DC-3-labelled untrusted text: a diff can carry a prompt injection aimed at the AI scanner (§14.3).

**Merge:** insert after §9.11
**Checked:** verified (map rules and schema field); inferred: reusing `briefing_sha256` needs no schema bump (the field exists, but its description was not read); independently checked 2026-11-13: confirmed

### M-§9-03: Mechanical findings set a ceiling that the AI score cannot raise

**Target:** the proposed §9.12 (M-§9-02), "Output is one scan report"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** A single 0–100 figure that blends rules with an AI's opinion lets a persuasive AI, or a prompt-injected one, talk a privileged hunk up to "97% safe". The validator already derives privilege and ceremony class deterministically. These should cap the score, and the explanation should say which rule set the cap. This also gives the "graded highlighting" a stable floor that does not move between AI runs.
**Evidence:** map:772-797 (privilege derivation, transition table).
**Proposed text:**

> - The score is a **capped 0-100 score**. The base is 95; it never shows 100. Mechanical findings subtract penalties and set caps; an AI reviewer can lower the figure (by up to 30; whether per reviewer or in total is open: deferred to the schema design review (operator ruling, 2026-11-14, PR 62 review Q7)) and never raise it, and the figure is never above any cap that applies. The explanation names every penalty and cap applied. Values are fixed in the schema, not by the scanner, and change only by an operator ruling, later backed by a labelled corpus:
>
>   | Part | Value |
>   |---|---|
>   | Base | 95; never 100 |
>   | Penalty, lockout | 60 |
>   | Penalty, privilege | 50 |
>   | Penalty, management | 45 |
>   | Penalty, data-loss | 40 |
>   | Penalty, reversible | 10 |
>   | Penalty, notice | 3 |
>   | AI reviewer | subtracts up to 30, from findings that cite a key path only (whether per reviewer or in total: open: deferred to the schema design review (operator ruling, 2026-11-14, PR 62 review Q7)) |
>   | Cap 40 | a lockout, privilege or management finding |
>   | Cap 60 | a check not run or failed, including an AI reviewer that is unavailable |
>   | Cap 70 | an uncovered hunk kind; or AI model families that disagree on a tier |
>   | Cap 80 | a touched domain that is not comprehensive |
>   | Cap 0 | an integrity flag |
>
>   Bands: 0-39 danger, 40-69 caution, 70-89 notice, 90-95 plain. The table's source is `09-safety-score-and-tui.md`, "Recommended design: capped checklist score" (the formula `base - penalty - ai_sub`, then `min` with the caps that apply).

**Ruled:** "1. 09's table, top 95" (`operator ruling, 2026-11-14, B8 sub 1, M-§9-03 / Q25 / 01 Idea 1 / 09 Idea 1`). The values in the proposed text above are the ruling's values, copied in full; 09's "capped checklist score" table is the source. The auto-refuse floor (B8 sub 2, "1. Allowed, off by default") is in the guide response, G-§7-01; the scan's authoring-model rule (B8 sub 4, "2. Should not (as written)") is `09-safety-score-and-tui.md` X-safety-06. Q25 is answered. Ruled; merged into the map's §9.12 and §11 (2026-11-14, the rulings commit of this PR).

**Merge:** insert after the "Output is one scan report" bullet of §9.12 once M-§9-02 is merged. Ruled (operator ruling, 2026-11-14, B8 sub 1).
**Checked:** inferred (design proposal); independently checked 2026-11-13: weakened, corrected

### M-§9-04: TUF subset: defer emergency/pre-grant and rule on the root threshold for state 1

**Target:** §9.11, at "TUF subset sized for one operator (offline root 2-of-3, targets, snapshot, emergency)" and the D42 paragraph "An optional enrolled policy “I pre-grant emergency security patches from role E” may exist"
**Kind:** question
**Goal:** G8, G4
**Weight:** improves
**Finding:** G8 state 1 is two of the operator's own devices. The 2-of-3 offline root, the emergency role and the out-of-band runbook are bigger than state 1 needs. §9.11 itself doubts that a one-operator 2-of-3 means anything when all keys sit on one machine. The guide makes the 2-of-3 a floor that its silence cannot relax, so only the operator can stage it. Separately, D42's "pre-grant emergency patches" is an install without the owner seeing it, which conflicts with G4 even as an opt-in.
**Evidence:** map:879-893, 904-908; guide:9-12.
**Proposed text:**

> For G8 state 1 the release is TUF-shaped (root, targets, timestamp, high-water mark) with a root threshold the operator sets at the first-run ceremony (§16 Q26). The emergency role and DC-20's runbook land before the first non-operator device enrolls. D42's pre-grant is withdrawn under G4: revocation and freezes still need no local yes, but every install is shown.

**Ruled:** B1: "1. Content checks; v0 first" (`operator ruling, 2026-11-14, B1`): "the map's 2-of-3 offline-root floor may lag until TUF" for the first SSH-signature v0 build. The emergency role, D42's pre-grant and the root threshold beyond v0 are not ruled by the 2026-11-14 rulings. Ruled in part; the rest stays open.

**Merge:** needs the operator's ruling first (the 2-of-3 floor and D42's pre-grant)
**Checked:** verified (map and guide text); independently checked 2026-11-13: confirmed

### M-§9-05: The advisor-key signature and auto-review are larger than G4 needs; the owner key comes first

**Target:** §9.1, at "`signature`, valid for exactly one target key", and §11, at "At install they enroll an **advisor key**"
**Kind:** cut
**Goal:** G4, G8
**Weight:** misleads
**Finding:** In G4 the owner sees and refuses; the AI scans and explains. §11 has the person's AI hold the signing key, including in an auto-review mode, which removes the owner from the loop. For G8 state 1, the approval record should be signed by an owner key enrolled on the device and used from the CLI or TUI. An advisor-key signature can stay as an explicit owner-delegated option later. The approval-record shape does not change, only whose key is enrolled.
**Evidence:** map:552-571, 959-967.
**Proposed text** (§11 first bullet):

> - At install the owner enrolls an **owner key** on the device; the CLI and TUI sign the approval record with it. An **advisor key** may be enrolled later as an owner-chosen, revocable delegation (R7/R10, R16); it is not the default and is not built before the first non-operator device enrolls.

**Merge:** replace that bullet. Needs the operator's ruling first; it supersedes D39 ("Their AI, their key").
**Checked:** verified (map text); independently checked 2026-11-13: confirmed

### M-§9-06: `explain-hunk` is not needed for state 1; G4's explanation is a different thing

**Target:** §9.5, at "The tool is due before the consent surface (Step 9)."
**Kind:** reword
**Goal:** G4, G8
**Weight:** improves
**Finding:** `explain-hunk` attributes a hunk to a source layer by re-rendering. That matters once a site has several layers (site-shared, foreign inputs). G4's "explanation" explains a safety figure, and comes from the scan. In state 1 there is one private site and one author, so attribution is trivial. Tying `explain-hunk` to "Step 9" invites it into the critical path for the wrong reason.
**Evidence:** map:678-686.
**Proposed text:**

> The tool is due before a site composes more than one input layer (site-shared or foreign), which is after G8 state 1. It is not the explanation of goal G4, which comes from the safety scan (§9.12); a scan MAY call it once it exists.

**Merge:** replace that sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§9-07: §9.11 "Push: any host holding `deploy-origin`" must become peer delivery

**Target:** §9.11, paragraph beginning "Push: any host holding `deploy-origin`, to **operator** (and operator-chosen `managed`) hosts."
**Kind:** ruling-drift
**Goal:** G3
**Weight:** blocks-goal
**Finding:** G3 allows any device to deliver, after the handshake. TUF already separates content authenticity from transport (any mirror can serve), so G3 fits Model B with no architectural change. The text should say this, and name the transport. CFEngine's own `cf-serverd` already does key-based peer authentication (`trustkeysfrom`, `ppkeys`), and §6/D14 says every host runs one. The live install runs none, though, and CFEngine's default trust is by address, which must be replaced by an explicit key list.
**Evidence:** map:372-376, 917-920, 1214; `rg -n 'cf-serverd|serverd' deploy/linux/tendcf-install.sh` (no hits); Learning CFEngine ch. 33 (`trustkeysfrom => { "127.0.0.1", ... @(def.acl) }`, via `book-kb query`).
**Proposed text:**

> Delivery (G3, R14): any device may offer a release to any other. The receiver completes the handshake [scope: §16 Q17, operator's ruling; if it includes peer authentication, by explicit key lists rather than CFEngine's address-based trust], then verifies the release signature and high-water mark. Delivery authorizes nothing: push, pull and peer relay are one transport, and every install still passes the device-computed diff and the owner's decision (R16). Transport candidate: each device's own `cf-serverd` with key-pinned access (D14), to be confirmed at the step that builds it.

**Ruled:** B1: "1. Content checks; v0 first" (`operator ruling, 2026-11-14, B1`): content checks; transport auth decides only who may talk, so any device may deliver. Ruled; the map's §9.11 now carries "The handshake is content checks (D50)" (2026-11-14, the rulings commit of this PR); the paragraph replacement proposed above is not otherwise made.

**Merge:** replace that paragraph, with the bracket resolved to B1's content checks. Ruled (operator ruling, 2026-11-14, B1).
**Checked:** verified (installer grep, book chapter); not checked: whether the fork's cf-serverd works on Termux; independently checked 2026-11-13: weakened, corrected

---

## §10 Per-device trust

### M-§10-01: The Consent default `operator`: no contradicts G4

**Target:** §10 table, row "**Consent** | Do I also need a local yes? | `operator`: no."
**Kind:** ruling-drift
**Goal:** G4, G8
**Weight:** blocks-goal
**Finding:** Under this default, G8 state 1's devices, all of them the operator's, would apply changes without the owner seeing a diff. That fails G4's "nothing changes a device except as ... the owner can see and refuse". The guide carries the same row. Options: (a) a local yes on every tier; (b) operator tier gets a hold window, with the diff and scan shown and a refuse that wins before apply; (c) a standing yes the owner enrolls explicitly. Each is a ruling.
**Evidence:** map:938; guide:846.
**Proposed text:**

> | **Consent** | Do I also need a local yes? | Every tier: the owner sees the device-computed diff and its scan and may refuse it (G4, R16). `operator`: [per-change yes, a hold window, or an owner-enrolled standing approval: §16 Q19, operator's ruling; a standing approval needs an approval-record shape without a per-change nonce, which is a schema change]. `consented`: an explicit yes per change. `managed`: operator-chosen within that floor |

**Ruled:** B2: "3 but also the existance of standing wait for user and standing refusal" (`operator ruling, 2026-11-14, B2`): option 3 (a hold window, or an owner-enrolled standing approval, shown and refusable before apply; a new approval-record shape without a per-change nonce, i.e. a schema bump), plus a standing "wait for user" (hold until the owner answers) and a standing refusal. §16 Q19 is answered. Ruled; schema bump pending (SCHEMA-TOUCHING). Which schema version carries the new approval-record shape, and whether it is one bump with the Android profile field and the agent id, is ruled this way (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"): the next unused version (v7 or later); grouping not ruled; the schema design review (two frontier reviews) decides (shipped v6 is already taken by C-policy-01, PR 52, 83d7280).

A reading of the ruling (L5, B2), not part of it (lead decision, PR 62 review): a standing approval drops only the per-change nonce (DC-2's device nonce); it is signed by an owner-held trusted key and keeps B1's other content checks (signed by trusted keys, fresh, names this device) and the rest of DC-2 (per-target validity, monotonic-counter single use or high-water mark, persisted rejects); its ceremony class is still checked against the validator's derived requirement (§9.8); until the operator rules, a standing approval covers `ordinary` changes only; whether one may cover `privileged` or `baseline` changes is for the schema design review to propose and the operator to rule; it names its signer and algorithm only if X-trust-06 is adopted (proposed, not ruled); every standing mode (hold window, standing approval, standing "wait for user", standing refusal) is owner-enrolled and refusable, and none is a default; dropping any other check needs an operator ruling; the schema design review confirms the approval-record shape.

**Erratum (2026-11-20, issue 64):** the operator ruled the questions this reading left open (operator rulings, 2026-11-19, issue 64 choosers): "3. Include all classes" (a standing mode may cover `ordinary`, `privileged` and `baseline` changes, each class enrolled separately and explicitly); "1. Reusable grant (Recommended)" (one grant covers many changes, with persistent per-device replay state for each application: reusable, never replayable); "1. Owner-enrolled trusted signers (Recommended)" (outside developer mode the owner may enroll any explicitly trusted signer within a stated scope, automation and organisational signers included); "1. Bind both fields (Recommended)" (X-trust-06 adopted: `signer` and `sig_alg` are in the signed bytes, must match the actual verification, and cannot create trust or enable an unapproved algorithm). So "covers `ordinary` changes only" and "only if X-trust-06 is adopted (proposed, not ruled)" are superseded, and "signed by an owner-held trusted key" now means the enrollment; the changes it covers are signed by a signer the enrollment names. The rest of the reading stands. The shape is approval-record schema v7 (`schema/approval-record.schema.json`: `per-change`, `standing-enrollment` and `standing-application` records; the goal-file family moves to v7 together, PR 62 review Q4). Current wording: `AGENTS.md`, Android item 5.

**Merge:** replace that row. Ruled (operator ruling, 2026-11-14, B2). Names its twin in the guide §14 (the guide reviewer's item).
**Checked:** verified (both tables); independently checked 2026-11-13: weakened, corrected

### M-§10-02: Add a Delivery axis for G3's handshake

**Target:** §10 table, after the "**Release**" row
**Kind:** add
**Goal:** G3
**Weight:** improves
**Finding:** "Whose signatures may change me" (Release) and "who may act on me" (Peer) both differ from "whom do I accept a delivery from". G3 makes the third explicit, and separating it keeps delivery from being mistaken for authority.
**Evidence:** map:935-941.
**Proposed text:**

> | **Delivery** | Which peers may hand me a release (the G3 handshake)? | [Any device (G3's 'any other device'), or only devices my trust policy lists: §16 Q17, operator's ruling]; delivery grants no authority |

**Ruled:** B1: "1. Content checks; v0 first" (`operator ruling, 2026-11-14, B1`): the Delivery axis's bracketed choice resolves to any device may deliver (content checks), and transport authentication decides only who may talk. Ruled; the ruling is merged into the map's §9.11 and D50 (2026-11-14, the rulings commit of this PR). The Delivery row itself is not yet inserted into the §10 table.

**Merge:** insert after the Release row. Ruled (operator ruling, 2026-11-14, B1).
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

---

## §12 Platforms and D45

### M-§12-01: The Mac must converge, not dry-run: which Mac, and what is enforced

**Target:** §12, "**macOS (adapter #1).** ... Dry-run default." and §13, "Dry-run is the standing posture on the first platform (the machine that cannot easily be reimaged)."
**Kind:** question
**Goal:** G8, G5
**Weight:** blocks-goal
**Finding:** G8 state 1 says the Mac "converge[s]", and as the log-archive server it must run a service tendcf enforces. The map's macOS posture is dry-run because the first Mac is the daily driver. Either a second Mac is the state-1 server, or the daily driver enforces under §9.4's minimal-claim rule: only the domains the owner enumerates, beginning with the archive service and a canary. R1 excludes the Intel Mac mini, which narrows the candidates.
**Evidence:** map:986-991, 1170-1171, 644-651, 106.
**Proposed text:**

> **macOS (adapter #1, server first, G5).** The G8 state-1 Mac is an Apple Silicon macOS VM (tart / Virtualization.framework) on bigmac (MacBookPro18,1): current macOS, snapshot and rollback, and CI can run the same image. It is a client, not an always-on server. The VM is the only enforcing Mac in state 1. It runs tendcf as a root LaunchDaemon, and under §9.4's minimal-claim rule its first goal file manages only the domains the owner names at first adoption: a canary and the log-archive service (R15). Every other domain is `not-yet-migrated`. The VM is also the G8 log-archive server, reachable only while bigmac is awake; devices buffer JSONL meanwhile. bigmac itself may run tendcf in dry-run only (compute and report the diff, log drift, apply nothing), as a user LaunchAgent with no root. The state-1 VM image is minimised: start from the smallest base (vanilla, not a dev-tools image) and strip what state 1 does not need. State 1 must verify the root launchd render path (the WarpBuild spike skipped it). §16 Q18 is answered. Ruled exception (operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"): the VM may enforce early as an explicit, ruled exception like pastebin's: canary only, operator-authored data (its root `cf-execd` enforcement at the stage 1 / guide Step 1 VM stands as an exception to D45's "`tendcf-validate` before any further host is enforced"). The order is not changed.

**Ruled:** B6 and its sub-rulings, all dated 2026-11-14. B6: "1. Plain Mac, launchd by tendcf" (state 1's Mac has no nix-darwin; tendcf renders launchd; Nix for authoring and building only). B6 sub 1: "1. macOS VM on bigmac". B6 sub 2 (Q18): "1. Dry-run only". B6 sub 1 rider: "Try to cut down the MacOS VM image so be smaller, remove stuff we don't need." (queued as build work: research the floor, what macOS can drop in a guest, for example tart vanilla against base images). B6 sub 3: "1. Root in VM, user on bigmac". (`operator ruling, 2026-11-14, B6, B6 sub 1, B6 sub 2, B6 sub 3, M-§12-01 / Q18`.) The proposed text above was rewritten to match; the earlier "daily driver enforces" alternative is closed. Ruled; the image minimisation is build work, queued.

**Merge:** replace the first two sentences of the macOS paragraph. Ruled (operator ruling, 2026-11-14, B6 sub 1, sub 2, sub 3).
**Checked:** verified (map text); independently checked 2026-11-13: confirmed

### M-§12-02: macOS server needs an installer, a launchd `cf-execd`, a renderer path and CI, and none exist

**Target:** §12 macOS paragraph, at "Runtime: CFEngine + `tendcf-validate` (D45, below)."
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** Everything deployable is Linux: `deploy/` contains only `linux/`, the root install and `tendcf-execd.service` are systemd, and there is no macOS CI. The Mac has only a dev build used for tests. Platform 1 needs the macOS analogue of `tendcf-install.sh`: a root-owned prefix and a launchd daemon for `cf-execd`. The compiler's launchd renderer exists. What is missing is a fork build checked on macOS in CI; given the operator's macOS-CI policy, this needs his say.
**Evidence:** `ls deploy` (prints `linux/`); inventory F ("There is no macOS CI"); inventory G4.
**Proposed text:**

> Not built for macOS: a root-owned install of the fork (prefix open, §12 item 6), a launchd daemon running `cf-execd`, a macOS installer beside `deploy/linux/`, and a CI job that builds the pinned fork and runs `tests/policy/run.sh` on macOS. These are the first work of G5's platform 1.

**Ruled:** the explicit macOS CI step is part of the adopted build order: "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4`: "guide's build order as base with the map's Step 0 and an explicit macOS CI step folded in"). B5: "1. Keep fork; spike stock" (`operator ruling, 2026-11-14, B5`): the full fork pin on every platform, with the macOS fork build in CI; run report 11's 2-3 day stock/Termux spike before deciding the adopter path (options 2-4). On PR 52's macOS check 8 the operator ruled "let's finish the codewarp setup and then try running on their fastest mac setup" (`operator ruling, 2026-11-14, PR 52 gate 2`): WarpBuild, with `frdminc/tendcf` in runner group 1, spike branch `spike/macos-check8-warp` building the fork pin on `warp-macos-26-arm64-12x` and running `tests/policy/run.sh` (worker 68cf038a); the merge of PR 52 waited on that run (historical: the run "macOS check 8 spike (WarpBuild)", https://github.com/frdminc/tendcf/actions/runs/43602684071, completed with conclusion success, and PR 52 merged on 2026-11-14 at 2c78680). The root launchd render path was skipped by that spike and state 1 must verify it (B6 sub 3, M-§12-01).

**Merge:** insert after that sentence. Ruled (operator ruling, 2026-11-14, B4, B5); the macOS CI policy question is answered by the ruling above.
**Checked:** verified (ls, inventory); independently checked 2026-11-13: confirmed

### M-§12-03: Android (platform 2): the list of missing pieces is long, and the map lists none

**Target:** §12, "**Android (adapter #2).** Same Site Model vocabulary. Runtime: Termux + tendcf-agent (Kotlin, D45) + Shizuku-class helper + CFEngine."
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** Missing, on the path to state 1:
1. A fork build for Termux (bionic, aarch64).
2. A runit/termux-services renderer. The bundle refuses runit by name, and the compiler refuses `android` outright.
3. The agent, which is unbuilt; `ShizukuTendCF` is only a helper.
4. A JSONL writer under the UID split of §8.
5. A protected baseline (§16 Q13, "Android under Termux is the awkward case").
6. APK build and signing. R6, "Gradle stays for APKs", was dropped from v3 without a decision.

The map lists none of these.
**Evidence:** map:993-995, 446-458, 1292-1294; `compiler/nix2cf/compile.py:82-83` (Android refused, "TODO(operator)"); `policy/tendcf_services.cf:125, :251` (runit names fall through); `docs/architecture/deprecated/architecture-DEFINITIVE-v2.md:183` (R6); inventory C (ShizukuTendCF "contains no goal-file, host_specific or cf-agent code").
**Proposed text:**

> **Android (adapter #2, client, G5).** Same Site Model vocabulary. Runtime: Termux + tendcf-agent (Kotlin, D45) + user-space ShizukuPlus (`frdminc/ShizukuTendCF`) + CFEngine. To build, in order: the fork for Termux; the runit renderer (compiler and bundle); the compiler's `android` platform row; the agent's validator, JSONL writer and protected baseline (§8, §16 Q13); APK build and signing (Gradle). Peer actions cover devices that need external ADB help.

**Ruled:** B3: "3. Termux CFEngine + thin Kotlin" (`operator ruling, 2026-11-14, B3`): state 1 on Android is Termux CFEngine fed tendcf projections, and the Kotlin agent holds trust and consent only (05 Idea 4). The paragraph above is the shape; the agent's validator row is settled by B3 sub 2 (M-§12-06: the single Python `tendcf-validate` runs in Termux, the Kotlin agent re-checks and shows consent). B3 sub 3: "1. Never" (`operator ruling, 2026-11-14, B3 sub 3, X-android-09`): tendcf never holds a DPC slot (profile owner or device owner); it works with Island/Insular through shell (`--user N`) and the owner app's API; an unreachable profile reports `not_kept`; tendcf never requires MDM enrolment. Ruled; implementation pending. Whether the fork builds on Termux stays unchecked, and 11's 2-3 day stock/Termux spike (B5) runs before the adopter path is decided.

The B3 ruling above is the trust, consent and Termux decision. Its consequence for the Android log and index is ruled (operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role"): "only" is about decisions; the thin Kotlin agent still writes the device JSONL and index as a support role; map and D18 stand. The proposed text above ("the agent's validator, JSONL writer and protected baseline") and the map's §8 and D18 (which place the Android index in tendcf-agent) stand for the log and index role; the validator is not in the agent (B3 sub 2).

**Merge:** replace that paragraph. Ruled (operator ruling, 2026-11-14, B3, B3 sub 3).
**Checked:** verified (files cited); not checked: whether the fork builds on Termux at all; independently checked 2026-11-13: confirmed

### M-§12-04: Island/Insular profiles need a model: is a profile a host, a domain or a scope?

**Target:** §12 Android paragraph (as replaced by M-§12-03)
**Kind:** question
**Goal:** G5
**Weight:** blocks-goal
**Finding:** Each Android user profile (main, Island/Insular work profile, secondary users) is a separate Android user with its own app data. Termux in one profile cannot see another, and Shizuku acts with `--user N`. The Site Model has no notion of a profile, so per-profile app lists and policy cannot even be stated. Three options: one host per profile, each with its own key and baseline; one host with a profile-keyed domain; or a `profile` field on entries. The choice touches the goal-file schema (a `schema_version` bump), so it is a design ruling with two frontier reviews under the repo's standing rule.
**Evidence:** `rg -il 'insular|island' docs schema compiler policy` (hits only in the goal file and handoff 601f); https://f-droid.org/en/packages/com.oasisfeng.island.fdroid/.
**Proposed text:**

> **Profiles.** Each Android user profile, including an Island/Insular work profile, is managed. There is one host per phone: one key, one baseline, one review. Each Android promise names its target user (`owner`, `work` or `private`) and the work profile's owner app (`island`, `insular` or `none`), per X-android-05's text. A profile tendcf cannot reach reports `not_kept`. tendcf never holds a device-policy-controller slot (profile owner or device owner); it works with Island/Insular through shell (`--user N`) and the owner app's API, and never requires MDM enrolment. The field is a `schema_version` bump, and it rides the same bump as the agent id (§12 item 4).

**Ruled:** B3 sub 1: "1. Field on entries" (`operator ruling, 2026-11-14, B3 sub 1, Q20 / M-§12-04 / X-android-05`). One host per phone; the profile target and owner app are fields on entries; an unreachable profile reports `not_kept`. The schema bump is a design ruling and takes two frontier reviews, and it rides the same bump as the agent id (M-§12-05 item 4). B3 sub 3: "1. Never" (`operator ruling, 2026-11-14, B3 sub 3, X-android-09`). §16 Q20 is answered. Ruled; schema bump pending (SCHEMA-TOUCHING).

**Merge:** insert after the Android paragraph. Ruled (operator ruling, 2026-11-14, B3 sub 1, B3 sub 3).
**Checked:** verified (grep); inferred: per-profile Termux isolation (standard Android multi-user behaviour, not tested here); independently checked 2026-11-13: confirmed

### M-§12-05: D45's open items, re-read under G5 and G8

**Target:** §12, "**Open, for the operator (D45 leaves these undecided ...)**", items 1–8
**Kind:** reword
**Goal:** G5, G8, G4
**Weight:** blocks-goal
**Finding:** The items were written for Linux-next. Under G5 and G8 state 1, macOS is the first host, and the first build must carry the whole gate, because state 1 needs "updates accepted only after the cryptographic handshake" and G4's see-and-refuse. Item 2's "schema-only" first build therefore does not reach the goal. Item 4's timing is stale: at the base this review read (`eefea3c`) v5 had landed (`"const": 5`), so an id change then cost v6; since then v6 itself has shipped (C-policy-01, PR 52, 83d7280), so an id change now costs the next unused schema version (v7 or later). On item 6, the review machine's `/usr/bin/python3` is 3.9.6, below the projector's `>=3.11`. The map notes this does not establish what a CLT-only install supplies, so a bundled interpreter is the likely, not the forced, answer.
**Evidence:** map:1070-1075, 1103-1106, 1117-1129; `schema/goal-file.schema.json:11` (`"const": 5`); `bin/projector.py:3-4` (`requires-python >=3.11`, `rfc8785`).
**Proposed text** (insert before item 1):

> **Under goal G5/G8 (2026-11-13).** macOS is the first host these items apply to, then Android (agent), then Linux. G8 state 1 needs the whole §9 gate, so item 2's first build is the full validator: signature and high-water mark, baseline integrity, device-computed diff, approval record and DC-2, projection. Item 3 assigns all of these, plus the JSONL writer and the `device_convergence` row, to `tendcf-validate` or a sibling command run under launchd. Item 4: the schema is at v6 (C-policy-01, PR 52, 83d7280), so changing the `agent` id now costs the next unused schema version (v7 or later) and a baseline ceremony per device; the Android profile ruling is made ("1. Field on entries", §16 Q20, M-§12-04), so the agent-id change shares that bump with the profile field (ruled, B3 sub 1). Whether the standing-modes approval-record shape (§9.1) also shares it is ruled this way (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"): the next unused version (v7 or later); grouping not ruled; the schema design review (two frontier reviews) decides. Items 5–6: on macOS, likely a bundled interpreter of at least 3.11 with `rfc8785` vendored, invoked by absolute path with `-I`; on Android the single Python `tendcf-validate` runs in Termux (M-§12-06). Item 7: ruled both: the log archive keeps a fleet-wide SQLite index and each device keeps its own (§8, M-§8-01). Item 8: Linux only, later in the order (not paused, D48).

**Ruled:** B3 sub 1 shares its schema bump with item 4 (`operator ruling, 2026-11-14, B3 sub 1, M-§12-05 item 4`: "Schema bump = design ruling (two frontier reviews); ride the same bump as the agent id"). Item 7: "make that both" (`operator ruling, 2026-11-14, Smaller 6`). Items 5-6 on Android: B3 sub 2 (M-§12-06). Items 2, 3 and 8 are not ruled by the 2026-11-14 rulings except as the build order's "CLI diff + y/N first" (B8 sub 3, M-§13-01); the rest of the text stays proposed.

**Merge:** insert before item 1. Items 4 and 7 are ruled as above; the other items remain the operator's open items (2 and 3).
**Checked:** verified (schema const, projector header); not checked: CLT Python version on a current macOS; independently checked 2026-11-13: weakened, corrected

### M-§12-06: The Kotlin port arrives at platform 2: reconsider one Python implementation inside Termux

**Target:** §12, at "On Android the Kotlin agent runs the same validation and projection logic as a port, held byte-for-byte to the same checked-in goldens in CI"
**Kind:** question
**Goal:** G5, G7
**Weight:** improves
**Finding:** D45 chose Kotlin on Android when Android was deferred. With Android second, a second implementation of the whole §9 validator (not just the projector) becomes early, critical-path work, and a drift risk on the one platform that differentiates the project. Termux ships Python, so `tendcf-validate` could run there unchanged. The agent would keep what only an APK can do: Shizuku bridging, Room index and app-private storage, notifications and the TUI's Android counterpart. The cost is that the baseline and the JSONL live in Termux's app-private storage rather than the agent's. That is a ruling on an instrument (G7).
**Evidence:** map:1033-1037, 1243 (D45 (1)-(2)); map:446-458 (UID split).
**Proposed text:**

> Under G5 (§16 Q21, ruled): Android runs the single Python `tendcf-validate` in Termux. The Kotlin `tendcf-agent` independently re-checks the signature and high-water mark, keeps the trust anchor and the approval record in its own app-private storage, and shows consent. There is no full Kotlin port of the validator.

**Ruled:** B3 sub 2: "1. Termux + Kotlin trust check" (`operator ruling, 2026-11-14, B3 sub 2, Q21 / M-§12-06`). This amends D45 (1)-(2): no full Kotlin port of the validator. §16 Q21 is answered. Ruled; merged on 2026-11-14 (the rulings commit of this PR) as the map's D45 (1)-(2) amendment and §12 text. The earlier question form above ("whether Android runs `tendcf-validate` itself inside Termux's Python, leaving tendcf-agent the privileged-helper, index and notification roles") is closed.

**Merge:** replace D45 (1)-(2)'s Kotlin-port clause with the proposed text. Ruled (operator ruling, 2026-11-14, B3 sub 2).
**Checked:** inferred (Termux providing Python is common knowledge, not checked here); independently checked 2026-11-13: confirmed

### M-§12-07: Linux becomes platforms 4 and 5; keep pastebin; Linux-only design work is later in the order, not paused

**Target:** §12, "**Linux (adapter #3, adoptability keystone).**"
**Kind:** ruling-drift
**Goal:** G5
**Weight:** misleads
**Finding:** "Adoptability keystone" and "#3" are stale under G5. Every live host is Linux, though, and pastebin enforces a canary that the operator ruled stays "as the standing proof". The consequence the reviewer drew was that Linux-only work waits behind state 2 (the s5 detector design (873 lines), the Linux validate build and the systemd renderer in the compiler). The operator ruled otherwise (see Ruled below): Linux is later in the order, not paused; only the s5 design is parked (B11, "park s5"). Merging the green PRs #41 and #42 is cheap and unblocks D46.
**Evidence:** map:997-999; inventory C, D (#41, #42 green); digest-history B2.7.
**Proposed text:**

> **Linux (adapters #4 server and #5 client, G5).** Stock distro; mise toolchains + CFEngine everything else, plus `tendcf-validate`. pastebin (Debian 13) keeps its enforced canary as the standing proof. Linux-only design work (the unit-writer detector, the systemd renderer in the compiler) comes later in the order, not paused (D48).

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4`) adopts D48. B4 rider, Linux: "1. Order language" (`operator ruling, 2026-11-14, B4 rider, Linux`): Linux is later in the order, not paused. B4 rider, canary: "1. Keep it" (`operator ruling, 2026-11-14, B4 rider, canary`): the pastebin canary stays the standing end-to-end proof. The proposed text above carries only that order language ("later in the order, not paused"); it no longer carries the earlier "freeze" title or the "waits for G8 state 2" restriction, which the ruling does not contain. The separate B11 ruling "park s5-design" stays as ruled.

**Merge:** replace that paragraph. Ruled (operator ruling, 2026-11-14, B4 and its Linux and canary riders).
**Checked:** verified (inventory; did not check PR state live); independently checked 2026-11-13: confirmed

---

## §13 Build order

### M-§13-01: A replacement build order that reaches G8 state 1 first

**Target:** §13 "Build order", the whole table and the two paragraphs after it
**Kind:** correct
**Goal:** G8, G5, G2, G3, G4
**Weight:** blocks-goal
**Finding:** The current order (macOS dry-run, Android deferred, Linux steps 4–5, consent at Step 9, Nix nowhere) cannot reach G8 state 1. That state needs a Nix frontend, an enforcing Mac, Android, the full device gate, peer delivery and a log archive. The guide's §18 table differs from the map again: it shows Android as Step 2 without the deferral. The replacement below is ordered by state 1's dependencies. Every step leaves something runnable and is measured against a G8 state. It assumes rulings D47–D50; where one goes the other way, the affected rows move. This order defers ordering inference (D16) to "13+ Demand": it is on the path to no G8 state. That amends D16 and needs the operator's ruling (the guide response's G-§10-01 proposes the same deferral).
**Evidence:** map:1152-1176; guide:1362-1374; goal-definition:58-65.
**Proposed text:**

> ## 13. Build order
>
> Each step leaves a coherent system and names the G8 state it serves. Not a schedule. Done before 2026-11-13: schemas through v5 (v6 followed on 2026-11-14: C-policy-01, PR 52, 83d7280), the launchd and systemd bundle branches, `buildfile`, the reference projector, the pastebin canary, NixOS passthrough stages A–C on get.
>
> | Step | What | G8 |
> | --- | --- | --- |
> | 0 | Merge #41 and #42 (historical: both merged 2026-11-14, #42 at acec5b5 and #41 at daa4530); the D46 restructure (`tendcf compile`, `plugins/`), amended: all plugins in tree, compile-time only, never on a device; Python entry-point discovery is deferred until a user needs one and out-of-tree plugins can be pinned (ruled, Smaller 5). Schema additions, each at the next unused schema version (v7 or later; shipped v6 is C-policy-01, PR 52): owner key in device trust, the `log-archive` and `monitor` roles, and whatever of these has been ruled by then: the operator-tier consent shape (§16 Q19), the Android profile model (§16 Q20), the `agent` id (§12 item 4), the scan-report shape. The Android profile model and the `agent` id share one bump (ruled, B3 sub 1); how the other additions group is ruled this way (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"): the next unused version (v7 or later); grouping not ruled; the schema design review (two frontier reviews) decides. Unruled items ride a later bump. | 1 |
> | 1 | **Nix frontend.** `plugins/frontends/nix` with NixOS-style options (module system), rendering byte-identical to its YAML twin; the state-1 Mac and Android device are authored in Nix. | 1 |
> | 2 | **Mac enforces.** Root install of the fork on the state-1 Mac (launchd `cf-execd`), `deploy/macos/`, a macOS CI job (ruled, B4), a launchd canary enforced under the minimal-claim rule. | 1 |
> | 3 | **`tendcf-validate` on macOS.** Baseline integrity, device-computed diff, approval record and DC-2, projection, `device_convergence` row, JSONL writer. Bundled interpreter. Release-signature and high-water verification arrive with signed releases (Step 5). | 1 |
> | 4 | **Owner review, CLI.** Built first, as a CLI diff with `y/N`, and used on the state-1 VM and dev devices before any TUI or score work (B8 sub 3). Shows the device-computed diff; mechanical scanners, confidence with ceilings, explanation, graded highlighting; the owner key signs accept or refuse. | 1 |
> | 5 | **Signed release and peer delivery.** TUF-shaped release (root threshold per ruling); `tendcf-validate` verifies the release signature and high-water mark; the R14 handshake (what it covers: §16 Q17, operator's ruling); any device may relay. | 1 |
> | 6 | **Android client.** Fork on Termux, runit renderer, compiler `android` row, validator (the single Python `tendcf-validate` in Termux, with the Kotlin agent re-checking trust; ruled, B3 sub 2), ShizukuTendCF, profiles (a field on entries; ruled, B3 sub 1), APK build; owner review on the device as the native screen opened from the agent notification, with Termux CLI/TUI as the operator's path (ruled, B3 sub 4). | 1 |
> | 7 | **Log archive on the Mac.** A tendcf-rendered service; Mac and Android ship JSONL over R14; the archive indexes. **G8 state 1 is reached when** one Mac and one Android device converge from Nix-authored config, refuse an unsigned or unhandshaken update in a test, and the Mac holds both devices' logs; and Step 8 has landed (B8 sub 3: state 1 is declared only once score, explanation, highlighting and TUI land). | 1 |
> | 8 | **AI scanner and TUI.** AI scanners under §9.12's ceilings; the TUI on the borrowed scaffold (Toad and textual-diff-view, ruled, B12); both modes complete. G4 stays whole in state 1; there is no "state 1.5". | 1 |
> | 9 | **macOS as client.** Further Macs; nix-darwin passthrough (§14.1 for the workstation); pull and self-update; the `monitor` role (state 2; ruled, B4 rider). | 2 |
> | 10 | **Linux as server.** pastebin through the full gate; the systemd renderer in the compiler; the unit-writer detector. | 2 |
> | 10b | **Linux as client.** NixOS passthrough beyond reporting; distro default. | 2 |
> | 11 | **Retire `~/ops`.** Every operator device on tendcf; the release-train replacement (#2) proved. **G8 state 2.** | 2 |
> | 12 | **Strangers.** Public install docs, the authoring guide for the user's AI (R13), first non-operator enrolment (multi-version render returns, §9.6), trust tiers, TUF emergency role and runbook, optional advisor delegation. **G8 state 3** when someone the operator has not helped installs and keeps using it. | 3 |
> | 13+ | Demand: ordering inference (D16; deferred explicitly, ruled, B4 rider), builder/cache, APK provenance, WoT as advisor tools, composition with site-shared and foreign inputs (`explain-hunk`), branch management (G9). | later |
>
> Reporting ("what changed, what is dirty, what release am I on") is an adoption requirement, not an observability extra. The §9.9 schema family and its §14.2 review gate Step 3, as before.

**Differences from the other proposal** (the guide response's build order, G-§18-02, as corrected after checking; from the independent checker's comparison; the two proposals are kept separate so the owner can choose):
1. **First step.** Here the Nix frontend comes first (1) and the Mac second (2); the guide has the fork on the Mac first and Nix authoring second. The checker notes the Mac today runs Homebrew upstream CFEngine 3.29.0 with the guide §19 data-path defects, which slightly favours the fork first; the two steps are otherwise independent.
2. **Step 0.** Only this proposal has a Step 0 (merge #41 and #42, the D46 restructure, the ruled schema additions). The checker finds it better supported on #41 and #42, which touch only platform-neutral files and so close the interlock fail-open on the Mac too; on the schema additions, it argues against bumping before Q19 and Q20 are ruled, which the corrected Step 0 now respects. (Both PRs merged 2026-11-14; which schema version the additions take is the next unused version (v7 or later) and how they group is ruled (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"): the next unused version (v7 or later); grouping not ruled; the schema design review (two frontier reviews) decides.)
3. **Validator and signing.** Both now put the validator first and signature verification with signed releases after it: here validator (3), owner review (4), signed release (5); the guide validator (3), then signing and the handshake (4), flagged for a ruling.
4. **Safety scan and TUI.** Here mechanical scanning and the CLI are at Step 4 and the AI scanner and TUI at Step 8; the guide puts all scanning, AI included, and the TUI at its Step 7 inside state 1. G4 names AI among the scanners, so a state 1 without them ships a partial G4. Ruled (B8 sub 3, "1. Build order, not scope"): G4 stays whole in state 1; the CLI diff and `y/N` is built first, and state 1 is declared only once score, explanation, highlighting and TUI land; the table's Step 8 is state 1 and there is no "state 1.5".
5. **Owner signature.** Here an owner key signs at Step 4 (supersedes D39, needs that ruling); the guide's Step 3 takes accept or refuse with no key specified.
6. **Peer actions.** The guide schedules ShizukuPlus start-over-ADB as a state-1 step (its 6); this proposal has no peer-action step. The checker finds the guide better supported here.
7. **Monitoring.** Here the `monitor` role is at Step 9, state 2, matching G8.1's literal text; the guide puts it in state 1 (its Step 6). Ruled: "1. State 2" (`operator ruling, 2026-11-14, B4 rider, monitor role`): state 1 needs only the log archive (G8.1).
8. **Extra-entry reporting.** Here only the Linux unit-writer detector comes before retiring `~/ops`; the guide has a separate step with launchd and Android detectors before migration. The checker finds the guide better: retirement needs `not-yet-migrated` counts on macOS and Android too.
9. **Linux.** Both now keep G5's order 4 then 5 (here 10 and 10b, as corrected; the guide 12 and 13). This proposal moves nix-darwin passthrough to Step 9.
10. **Inference.** Both defer it with a ruling flagged: here to "13+ Demand" (added after checking), the guide to "Later" (G-§10-01). Ruled: "1. Defer explicitly" (`operator ruling, 2026-11-14, B4 rider, D16`): D16's ordering inference is recorded as deferred.
11. **macOS CI.** Here Step 2 names a macOS CI job (ruled); the guide's Step 1 says only "the CI build action". Ruled: the explicit macOS CI step is folded into the guide's order (B4).
12. **State 3.** Here public docs, the authoring guide, first non-operator enrolment, the TUF emergency role and advisor delegation (12); the guide has the publishable layer and a root ceremony a novice can complete, then the `consented` tier. Complementary; the emergency-role deferral (M-§9-04) is a ruling the guide does not propose.
13. **When state 1 is reached.** Here refusing an unsigned or unhandshaken update in a test; the guide requires each device to refuse both a release failing the handshake and a diff its owner refused. The checker finds the guide's test closer to G4.
14. **Plugins.** Step 0 here does the D46 restructure as decided; the guide's G-§4-01 cuts out-of-tree entry points (amends D46). One ruling covers both: "1. Defer out-of-tree discovery" (`operator ruling, 2026-11-14, Smaller 5`): D46 is amended with G-§4-01's text (all plugins in tree, compile-time only, never on a device; Python entry-point discovery deferred until a user needs one and out-of-tree plugins can be pinned).

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4`): adopt draft D47-D50 as corrected (M-§15-01..04), "guide's build order as base with the map's Step 0 and an explicit macOS CI step folded in". The base is therefore the guide's order (G-§18-02 in `02-response-guide.md`, which carries the ruled text); the table above is this response's proposal, kept as the source of Step 0 and the macOS CI step, and rows that differ from the guide's order are not adopted unless a difference item above says "Ruled". D16 is deferred explicitly ("1. Defer explicitly", B4 rider); the `monitor` role is state 2 ("1. State 2", B4 rider); Linux is "later in the order, not paused" ("1. Order language"); the pastebin canary stays ("1. Keep it"). Smaller 5 (D46 plugin entry points, "1. Defer out-of-tree discovery") is applied in Step 0. B8 sub 3 ("1. Build order, not scope") is applied in Steps 4, 7 and 8. B3's phone review surface (X-safety-08, "1. Native screen + Termux", `operator ruling, 2026-11-14, B3 sub 4`) replaces the original map's Step 9 "consent surface" row: one review document (R14) is rendered three ways (CLI `--plain`/`--json`, the Textual TUI including Termux and SSH, and a native screen in `tendcf-agent`); the goldens hold all three and the renderers compute nothing; the agent notification opens the native screen with Accept and Refuse; the Termux CLI/TUI is the operator's path; no answer means held, and a refusal is logged. Ruled; the map's §13 carries the adopted order as its stage table (2026-11-14, the rulings commit of this PR). Numbering: this response's "Step N" is its own proposal; the adopted order's two numberings are the guide's Steps 0-15 and the map's Stages 0-16, which are the same order with the macOS CI job split out of guide Step 1 as map Stage 2, so guide Steps 2-15 are map Stages 3-16 (Step N is Stage N+1); "Step 8" and "Steps 3 and 7" cited elsewhere in the review documents are guide numbering unless they say "Stage". Ruled exception (operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"): the VM may enforce early as an explicit, ruled exception like pastebin's: canary only, operator-authored data (its root `cf-execd` enforcement at the stage 1 / guide Step 1 VM stands as an exception to D45's "`tendcf-validate` before any further host is enforced"). The order is not changed.

**Merge:** replace the section with the guide's ruled order carrying Step 0 and the macOS CI step. Ruled (operator ruling, 2026-11-14, B4); amends D16 (deferred), D22 and D46.
**Checked:** inferred (the ordering is a proposal); the inputs it rests on were verified as cited in the items above; independently checked 2026-11-13: weakened, corrected

---

## §15 Decision register

### M-§15-01: Draft D47, the goal (supersedes D8's wording and §0 items 1 and 3)

**Target:** §15, after D46
**Kind:** add
**Goal:** G1, G4, G8
**Weight:** blocks-goal
**Finding:** The 2026-11-13 goal is the operator's ruling but has no register entry. Whether D8 "Sovereignty is the point" is superseded in emphasis is this response's reading, not a ruling.
**Evidence:** map:1209; goal-definition:3-5, 75-89.
**Proposed text:**

> | D47 | Goal | **Operator, 2026-11-13.** The goal is G1–G9 of [`../review-2026-11-13/00-goal-definition.md`](../review-2026-11-13/00-goal-definition.md), as its rulings table records: primary aim "Adoptable tool" (row 1); first adopter "Nobody named yet." (row 2); finish line "The ladder of three states in G8" (row 7); wording "Agreed, with two changes to the draft", framing "focus on the user's freedom to control their own computing devices as they see fit", and "G9 added" (row 8). **Operator, 2026-11-14** ("1. Yes, supersede D8's wording"): adoption is the aim and see-and-refuse (G4) is its safety mechanism; this supersedes D8's "Sovereignty is the point" (the trust layer stays, as G4's mechanism) and §0 items 1 and 3. |

**Ruled:** "1. Yes, supersede D8's wording" (`operator ruling, 2026-11-14, Smaller 3, M-§15-01`) and "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4`). D47's clause is ruled: adoption is the aim, G4 see-and-refuse is its safety mechanism; it supersedes D8 "Sovereignty is the point" (the trust layer stays as G4's mechanism) and §0 items 1 and 3. The "Proposed, not ruled" label is dropped. Ruled; merged as D47 into the map's decision register on 2026-11-14 (the rulings commit of this PR).

**Merge:** insert after D46. Ruled (operator ruling, 2026-11-14, Smaller 3 and B4).
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§15-02: Draft D48, the platform order (supersedes D22 and the 2026-10-29 Linux-first ruling)

**Target:** §15, after D47
**Kind:** add
**Goal:** G5
**Weight:** blocks-goal
**Finding:** D22 reads "macOS, Linux. Android deferred". G5 reverses the deferral and puts Linux fourth and fifth.
**Evidence:** map:1221; `docs/architecture/linux-targets.md:3-4` (per digest B1).
**Proposed text:**

> | D48 | Platform sequence | **Operator, 2026-11-13** (rulings row 6): "The first platforms should be MacOS as server and Android as client, followed by MacOS as client, followed by linux server, followed by linux client. Android is one of the most important pieces as it will be the major marketplace differentiator". Goal G5 (wording agreed, row 8) adds that Android management "works with Island/Insular profiles and with user-space ShizukuPlus". **Operator, 2026-11-14** ("1. Adopt D47-D50"): this supersedes D22 and the 2026-10-29 Linux-first ruling and Android deferral ([`linux-targets.md`](../architecture/linux-targets.md)). Linux is later in the order, not paused ("1. Order language"). Linux work already done stays: pastebin's canary keeps running as the standing proof ("1. Keep it"; operator, 2026-10-31). |

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4, M-§15-02`), D48 as corrected: it carries only the operator's text, with the Linux order wording of B4 rider "1. Order language" and the canary of B4 rider "1. Keep it". D48 supersedes D22 and the 2026-10-29 Linux-first ruling. The "Proposed, not ruled" label is dropped. Ruled; merged as D48 into the map's decision register on 2026-11-14 (the rulings commit of this PR). The merged D48 row carries only the operator's text and the two riders (order language, canary).

**Merge:** insert after D47. Ruled (operator ruling, 2026-11-14, B4).
**Checked:** verified (map; linux-targets via digest); independently checked 2026-11-13: weakened, corrected

### M-§15-03: Draft D49, Nix first (amends D12's equal frontends)

**Target:** §15, after D48
**Kind:** add
**Goal:** G2
**Weight:** blocks-goal
**Finding:** D12 says "Two equal frontends". G2 says real Nix first, with YAML/JSON beneath as the data form Nix evaluates to. Whether byte-identical twins survive as a test is open.
**Evidence:** map:1211.
**Proposed text:**

> | D49 | Authoring | **Operator, 2026-11-13** (rulings row 4): "Real Nix first, YAML beneath." Goal G2 (wording agreed, row 8): config is written in the real Nix language with NixOS-style options, so existing NixOS and nix-darwin configs carry over; plain YAML/JSON sits beneath it as the data form Nix evaluates to and can be written by hand; what a person is shown reads clearly without manuals. **Operator, 2026-11-14** ("1. Adopt D47-D50"): this amends D12 (Nix is first, not one of two equals). Nix may be required to build a release, at build time only ("2. Allow on release path", "1. Build-time only"; amends R5 and D6, M-§2-04). Still open, needs the operator's ruling: whether `schema/` or the Nix module options is the schema authority (map §4.1 currently says JSON Schema is generated from the module options; §16 Q23), and whether a byte-identical YAML twin stays as the frontend's test. |

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4, M-§15-03`), D49 as corrected: it amends D12. D49 leaves the schema authority open (§16 Q23); that and the byte-identical YAML twin are not ruled. B7 ("1. Importer + matching names", `operator ruling, 2026-11-14, B7`) supplies the meaning of "carry over" in G2: a one-shot importer for pure-data option families (it lists what it did not carry), plus tendcf option names matching nix-darwin and NixOS where the meaning is the same. The "Proposed, not ruled" label is dropped. Ruled; merged as D49 into the map's decision register on 2026-11-14 (the rulings commit of this PR), with Q23 still open.

**Merge:** insert after D48. Ruled (operator ruling, 2026-11-14, B4); the Q23 clause stays open.
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### M-§15-04: Draft D50, device shape, peer updates and server/client

**Target:** §15, after D49
**Kind:** add
**Goal:** G3
**Weight:** blocks-goal
**Finding:** G3 confirms D33 (no control node), amends D14's git-synced policy, and adds peer delivery and the vocabulary of service roles. It amends §9.11's push rule, and the handshake is undefined.
**Evidence:** map:917-920, 1214, 1232.
**Proposed text:**

> | D50 | Device shape | **Operator, 2026-11-13** (rulings row 6b): "I am not trying to change the architecture; client and server are not entirely meaningful here as each device will be self-sufficient and able to take updates from any other device that uses the correct crytoographic handshake. So when I say server I am refering only to the machines that are a server for services like recieving and archiving logs and doing monitoring of other machines." Goal G3 (wording agreed, row 8): every device converges on its own and there is no control node. **Operator, 2026-11-14** ("1. Adopt D47-D50"): this confirms D33, amends D14's git-synced policy, and amends §9.11's push rule (peer delivery, R14). "The correct cryptographic handshake" means content checks ("1. Content checks; v0 first", B1): the update is signed by keys the device trusts, fresh, names this device, and carries the owner's approval; transport authentication decides only who may talk (§16 Q17 answered). |

**Ruled:** "1. Adopt D47-D50" (`operator ruling, 2026-11-14, B4, M-§15-04`), D50 as corrected: it amends D14 rather than confirming it. The handshake: "1. Content checks; v0 first" (`operator ruling, 2026-11-14, B1`): G3's handshake means content checks (signed by trusted keys, fresh, names this device, owner approval); transport auth decides only who may talk. The first build is the SSH-signature v0 (`ssh-keygen -Y` over goal-file bytes plus a counter); the map's 2-of-3 offline-root floor may lag until TUF. §16 Q17 is answered; the state-1 root threshold (Q26) follows the "may lag" clause. The "Proposed, not ruled" label is dropped. Ruled; merged as D50 into the map's decision register on 2026-11-14 (the rulings commit of this PR).

**Merge:** insert after D49. Ruled (operator ruling, 2026-11-14, B4 and B1).
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### M-§15-05: Draft D51–D57, the remaining 2026-11-13 rulings (none supersedes an entry; the clauses beyond the rulings are proposals)

**Target:** §15, after D50
**Kind:** add
**Goal:** G4, G6, G7, G8, G9
**Weight:** improves
**Finding:** The remaining rulings add to the register without reversing an entry. D51 is consistent with D29, D53 settles §16 Q2's framing, and D54 states the status of what the fork ruling ("the fork is the destination") and D13 chose.
**Evidence:** map:1212, 1228; goal-definition:31-37, 51-70.
**Proposed text:**

> | D51 | Safety scan | **Operator, 2026-11-13** (rulings row 8, G4 wording): "the diffs are also scanned in various ways including using AI for likely safety, and the user gets to see safety confidence out of 100% as well as an explanation of why that percentage was choosen and the code that is questionable should be hilighted in increasingly dramatic ways depending on safety". **Proposed, not ruled** (consistent with D29): the scan advises and never authorizes (§9.12). |
> | D52 | Review modes | **Operator, 2026-11-13** (rulings row 8): "we should borrow a TUI scaffold from another project, and have both command-line and TUI modes". Scaffold not yet chosen (§16 Q22). |
> | D53 | AI authorship | **Operator, 2026-11-13** (rulings row 5): "Taken as given; no experiment asked for." Goal G6 (wording agreed, row 8): that AIs write the configuration is the premise of the project, not a hypothesis it sets out to test. **Proposed, not ruled:** R13 and §9's writing rule rest on it; §16 questions 2 and 9 are re-posed accordingly. |
> | D54 | Instruments | **Operator, 2026-11-13** (rulings row 3): "Instrument, open to challenge." Goal G7 (wording agreed, row 8): CFEngine, the CFEngine fork, the Site Model and the compiler are instruments, and nothing about them changes without the operator's ruling. **Proposed, not ruled:** D13, D15 and the 2026-08-22 fork ruling hold as instrument choices. |
> | D55 | Finish line | **Operator, 2026-11-13** (rulings row 7): "The ladder of three states in G8": (1) one of the operator's Macs and one of his Android devices converge from Nix-authored config, with updates accepted only after the handshake and logs archived on the Mac; (2) his whole fleet runs on tendcf and `~/ops` is retired; (3) a person he has not helped installs it from the public docs with their own AI and keeps using it. (Ordering §13 against them is proposed in M-§13-01 and needs the ruling.) |
> | D56 | Branch management | **Operator, 2026-11-13** (rulings row 8): "G9 added." Goal G9: later, free-software branch management, built as an extension of the platform's existing patch patterns, so non-technical users can maintain forks of projects or plugins without knowing about merging, rebasing or compiling. **Proposed, not ruled:** those patch patterns are `overlay/`'s; extension point only before D55 state 3 (R20). |
> | D57 | First adopter | **Operator, 2026-11-13** (rulings row 2): "Nobody named yet." Goal G1 (wording agreed, row 8): the first adopters are sysadmins who already share configs in Nix. |

**Merge:** needs the operator's ruling first (the clauses still marked "Proposed, not ruled"; D52's scaffold is ruled in part by B12 "2. Borrow both freely; raise Python", and D51's figure by B8 "1. Capped 0-100 score"); then insert after D50
**Checked:** verified (each row against the goal file); independently checked 2026-11-13: weakened, corrected

---

## §16 Open questions

### M-§16-01: Answered or re-posed by the goal: Q2, Q9, and partly Q5 and Q6

**Target:** §16, items 2, 5, 6 and 9
**Kind:** reword
**Goal:** G6, G3, G4
**Weight:** improves
**Finding:**
1. Q2 asks whether the writing rule is an argument or a hypothesis. Under G6, AI authorship is the premise. What remains open is whether the local-knowledge rule is the right way to make that premise safe.
2. Q9 asks whether the project is hardening the wrong surface. G4's AI scan targets plausible-looking output, which is the failure Q9 names.
3. Q5 and Q6 (local-first, fleet-wide answers) are partly answered by R15's log archive, which gives a fleet view without becoming a source of truth.

None of these calls for an experiment.
**Evidence:** map:1263, 1266-1269, 1279-1280.
**Proposed text:**

> 2. ~~Is the writing rule an argument or a hypothesis?~~ **Re-posed 2026-11-13 (D53):** AI authorship is the premise. Open: is "prefer local knowledge, prefer machine-checkable" the right discipline to make AI-written config safe, and what does the G4 scan need from it?
> 5–6. **Partly answered 2026-11-13 (R15):** the log archive gives a fleet-wide view; each device's JSONL stays the record. Open: what monitoring asks of it.
> 9. **Re-posed 2026-11-13 (D51):** the G4 scan, AI among its scanners, is aimed at plausible-looking output types do not catch. Open: whether it catches it.

**Merge:** replace items 2, 5, 6 and 9
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§16-02: Standing, re-prioritized: Q13, Q15 and Q10 are now on the state-1 path

**Target:** §16, items 10, 13 and 15
**Kind:** reword
**Goal:** G5, G4, G1
**Weight:** misleads
**Finding:**
1. Q13 (what protects the stored baseline; "Android under Termux is the awkward case") is no longer deferred work: it is platform 2.
2. Q15 (a device-local trust root buildable across three platforms by one person) now has an order: macOS, then Android.
3. Q10 (can a person consent to a diff) is what G1's long-run user turns on. It is a test of a display with people, not of AI authorship, so G6 does not exclude it.

Q1, Q3, Q4, Q7, Q8, Q11, Q12, Q14 and Q16 stand unchanged.
**Evidence:** map:1281-1285, 1292-1301.
**Proposed text** (insert after the list):

> **Priority under the 2026-11-13 goal.** Q13 and Q15 are on the path to G8 state 1 (macOS, then Android); Q10 is on the path to state 3 and is answered by putting the G4 review screens in front of a person without admin skill. The rest stand as written.

**Merge:** insert after item 16
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§16-03: New open questions from the goal

**Target:** §16, after item 16
**Kind:** add
**Goal:** G2, G3, G4, G5, G8, G9
**Weight:** blocks-goal
**Finding:** Each of these blocks a step of the M-§13-01 order or a schema bump. Each is the operator's to answer.
**Evidence:** the items cited in each line.
**Proposed text:**

> 17. **What is "the correct cryptographic handshake"** (G3, R14)? Peer authentication by device keys, release signature verification, or both, and is the owner's approval part of it? (M-§9-07) **Ruled 2026-11-14 (B1, "1. Content checks; v0 first"):** content checks (signed by trusted keys, fresh, names this device, owner approval); transport auth decides only who may talk.
> 18. **Which Mac is the G8 state-1 server**, and may the daily driver enforce under the minimal-claim rule? (M-§12-01) **Ruled 2026-11-14 (B6 sub 1, "1. macOS VM on bigmac"; B6 sub 2, "1. Dry-run only"):** an Apple Silicon macOS VM on bigmac enforces; bigmac itself runs dry-run only.
> 19. **What does "can refuse" mean on an operator-tier device:** a local yes per change, a hold window, or an enrolled standing approval? (M-§10-01) **Ruled 2026-11-14 (B2, "3 but also the existance of standing wait for user and standing refusal").**
> 20. **How are Android profiles modelled** (Island/Insular): own host, domain, or entry field? A schema bump. (M-§12-04) **Ruled 2026-11-14 (B3 sub 1, "1. Field on entries").**
> 21. **Does Android run `tendcf-validate` in Termux** instead of a Kotlin port? (M-§12-06) **Ruled 2026-11-14 (B3 sub 2, "1. Termux + Kotlin trust check").**
> 22. **Which TUI scaffold** is borrowed? (R18) **Ruled 2026-11-14 (B12, "2. Borrow both freely; raise Python"):** Toad and textual-diff-view.
> 23. **Which side is generated:** Nix options from `schema/`, or JSON Schema from Nix options? (M-§4-01)
> 24. **What does the `monitor` role watch,** and what does it do on a finding, given that it may not change another device?
> 25. **What are the scan's ceiling values,** and how is a confidence figure calibrated so that 90% means something? (M-§9-03) **Ruled 2026-11-14 (B8 sub 1, "1. 09's table, top 95"):** the cap values are in M-§9-03; calibration against a labelled corpus is later.
> 26. **What root threshold does a one-operator G8 state 1 use?** (M-§9-04) **Partly ruled 2026-11-14 (B1):** the 2-of-3 offline-root floor may lag until TUF; the first build is the SSH-signature v0.
> 27. **What does "carry over" mean** for an existing NixOS or nix-darwin config on a host that does not run Nix? Evaluated through tendcf's own option set (a reimplementation of NixOS modules), or only as passthrough? (G2) **Ruled 2026-11-14 (B7, "1. Importer + matching names"):** a one-shot importer for pure-data option families, plus matching option names.

**Merge:** insert after item 16; renumber to the guide's §20 numbering once both lists are ruled; map:1252 says §16 keeps the guide's order and numbering, and the guide response's new questions 17-26 differ in content
**Checked:** verified (each cross-reference exists in this file); independently checked 2026-11-13: weakened, corrected

---

## Drift (§ various, against the guide and repo)

### M-§12-08: "First host: vps-primary" contradicts linux-targets and the record

**Target:** §12, "**NixOS / nix-darwin (passthrough).**", at "First host: vps-primary."
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** vps-primary is "not in the first milestone (operator)", and stage C ran on get.sipb.cloud first. vps-primary has the module imported but not enabled.
**Evidence:** map:1004; digest-current-plan D1 (linux-targets:13-14; nixos-passthrough:128-133).
**Proposed text:**

> First host: get.sipb.cloud (stage C, report only, `cf-execd` off); vps-primary is not in the first milestone.

**Merge:** replace that sentence
**Checked:** verified (via the phase-1 digest; linux-targets itself not re-opened); independently checked 2026-11-13: confirmed

### M-§12-09: §12 item 4's "the schema is at v4 and v5 is in flight" is stale

**Target:** §12 open item 4, at "Timing: the schema is at v4 and v5 is in flight"
**Kind:** correct
**Goal:** G7
**Weight:** misleads
**Finding:** v5 landed on 2026-11-02 (and v6 on 2026-11-14), so the "rides that bump" window has closed. An implementer reading this could believe an `agent` id change is still free.
**Evidence:** map:1103-1106; `schema/goal-file.schema.json:11` (`"const": 5`).
**Proposed text:**

> Timing: v5 landed on 2026-11-02 and v6 on 2026-11-14 (C-policy-01, PR 52, 83d7280), so an id change now costs the next unused schema version (v7 or later) and a baseline ceremony per device; it rides the same bump as the Android profile model (§16 Q20; ruled, B3 sub 1). Whether the standing-modes approval record shares that bump is ruled this way (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"): the next unused version (v7 or later); grouping not ruled; the schema design review (two frontier reviews) decides.

**Merge:** replace those sentences. The text as first proposed ("an id change now costs v6") is superseded: v6 shipped for a different change, so it cannot carry these
**Checked:** verified; independently checked 2026-11-13: confirmed

### M-§13-02: Guide §18 still lists Android as Step 2 with no deferral, and the map and guide disagree

**Target:** §13 Step 2 "Deferred (operator, 2026-10-29)" against guide §18 Step 2 "Android under the Site Model | Same vocabulary."
**Kind:** ruling-drift
**Goal:** G5
**Weight:** misleads
**Finding:** The map says "where this file and that guide disagree on the current design, the guide wins", and the guide does not record the 2026-10-29 deferral. The irony is that the guide's stale text is now closer to G5 than the map's. Whatever order is ruled, both tables must change in one commit, and the map should stop carrying its own copy of the order, pointing at one table instead.
**Evidence:** map:10-11, 1160; guide:1366.
**Proposed text:**

> (Map §13 header) The build order is kept in one place, this table; the guide's §18 summarizes it and links here.

**Merge:** the build order is ruled (operator ruling, 2026-11-14, B4: "1. Adopt D47-D50", the guide's order as base); the guide-wins rule on which document owns the build order still needs the operator's ruling
**Checked:** verified (both tables); independently checked 2026-11-13: confirmed

---

## Nits

| ID | Target (quoted phrase) | Finding | Proposed fix |
| --- | --- | --- | --- |
| M-nit-01 | Header "**Date:** 2026-08-15 (§9 rewritten for Model B; D43/D44 added)" | Amended through 2026-11-13 (D45, D46) | "Last amended 2026-11-13 (D46)" |
| M-nit-02 | §16 "Compressed from guide §19, in its order and numbering" | The guide's open questions are §20; §19 is "What we found underneath" (guide:1383, 1529) | "guide §20" |
| M-nit-03 | §9.1 "File the upstream `--simulate-output=json` issue before Step 3 code." | Step 3 code exists; the fork carries `--simulate-json`; upstream contact is cut except simulate-json (digest-history E) | Delete, or "The fork carries `--simulate-json` (upstream-overlay §2)." |
| M-nit-04 | §2 jumps R5 → R7/R10 → R11 | R6 (Gradle for APKs), R8 (trust layer minimal safe implementations) and R9 (literate programming) were dropped from v2 without a register line (deprecated v2:183-196). R6 matters again under G5 | Add "R6, R8, R9 dropped 2026-08-15" or restore R6 |
| M-nit-05 | §3 "A host identity in trust and ChangePlans is the **device public key**" | "ChangePlans" is Model A vocabulary; under D43 it is goal files and approval records | "in trust policy, goal files and approval records" |
| M-nit-06 | §6 "Deployment: every host runs its own `cf-serverd`, policy from the signed release via git" | No host runs `cf-serverd` (installer grep: no hits); "via git" predates the TUF release | Mark "planned (R14 transport)" |
| M-nit-07 | §13 Step 1 "Dry-run default" vs pastebin enforcing | The only enforcing host is Linux; Step 1's dry-run reads as the project's posture | Fold into M-§13-01 |
| M-nit-08 | §12 "Distro choice open until this step." | Debian 13 is the live host and v5 is dpkg-specific | "Debian 13 first (pastebin); rpm needs a schema bump" |
| M-nit-09 | §17 "`frdminc/nix2cf` — compiler tool (Step 3) until 2026-11-13" | Fine, but `tendcf-validate-proposal` "deciding nothing" is stale for Q10/Q12 (digest D8a) | Add "(Q10 and Q12 decided 2026-11-02)" |
| M-nit-10 | §4.1 "Lookup CLI (D24, D40)" | Unbuilt (compile.py:118, :322 per inventory) | Add "not built" |

---

## Ideas and risks

1. **The score becomes the decision.** A figure out of 100 invites "accept if ≥ 90" scripts, and then the AI's opinion authorizes in practice even though §9.12 says it never does. Rendering the explanation and the highlighted hunks before the number, and never offering a threshold-accept option in the tool, keeps G4's "owner sees and refuses" real.
2. **Prompt injection through the diff.** Service names, argv and file contents in a hunk are attacker-reachable text that the AI scanner reads. The mechanical ceilings (M-§9-03) are the defence: a scanner talked into "safe" still cannot lift a privileged hunk above its cap. Add a §14.3 red-team on exactly this path before Step 8.
3. **The Nix frontend is the largest unestimated item on the state-1 path.** "Existing NixOS configs carry over" can silently grow into reimplementing NixOS modules (`services.*`) for non-Nix hosts. Question 27 should be ruled before Step 1 starts, and the first cut kept to tendcf's own option tree.
4. **Two big unknowns land on Android at once:** the fork building under Termux/bionic and the profile model. A one-day spike that builds the fork in Termux on the actual device, before Step 0's schema bump, de-risks the most important platform cheaply.
5. **Documentation gravity.** The digests show docs at about 70k added lines against about 5k in the compiler, and the largest recent specs are Linux report-only detection, which G5 now places in state 2. A rule that each §13 step closes with a runnable demonstration on a real device would keep the new order from being written rather than built.
6. **Dogfood the server role.** Rendering the log-archive receiver as an ordinary tendcf service record on the Mac makes the first "server" prove the launchd adapter, the gate and the review screen at once, with no special-case install path.
7. **Use CFEngine's own key handshake for R14.** cf-serverd/cf-agent already authenticate by RSA keys (`ppkeys`). Pinning them explicitly, rather than through address-based `trustkeysfrom`, may give G3's handshake almost for free, with TUF signatures on top for content. Worth checking whether the fork's protocol builds on Termux.
8. **Owner key loss.** Moving the signature from an advisor key to an owner key (M-§9-05) makes the owner key's loss a lockout of that device. The recovery story belongs with Q26's root threshold, not after it.
9. **G9 can shape today's overlay tooling cheaply.** `bin/overlay.py` already has manifest, drift and retirement checks. Keeping its data model user-facing (one patch = one named intent with a plain-language reason) costs little now and is the seed of G9.
10. **The map and the guide each carry a build order and requirement prose, and they drift** (M-§13-02, Android). With the goal now explicit, one owner per fact (the goal file for aims, the map for order and decisions, the guide for explanation) would stop a fourth copy appearing.

Not checked: live hosts; PR #41 and #42 state today; CI; whether the fork builds on macOS outside the dev build or on Termux at all; ShizukuPlus behaviour across work profiles; the guide outside §1, §18 and §20 headings; linux-targets.md and nixos-passthrough-plan.md themselves (relied on the phase-1 digest); `compiler/` source beyond the two grep hits.

Last search run: Learning CFEngine (Basic Memory `books`, then `book-kb query 'trustkeysfrom|ppkeys'`) confirmed cf-serverd's key-trust mechanism cited in M-§9-07 and Idea 7. The firecrawl search for CFEngine key exchange returned only irrelevant hits.

## Withdrawn after checking

None. The independent checker refuted no item in this document.
