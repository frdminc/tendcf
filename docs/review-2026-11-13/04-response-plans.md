# Response: the platform and implementation plans, measured against the 2026-11-13 goal

**Targets:** `docs/architecture/linux-targets.md` (L), `docs/architecture/nixos-passthrough-plan.md` (N),
`docs/architecture/plugin-layout.md` (PL), `docs/architecture/tendcf-validate-proposal-2026-11-03.md` (V),
and cross-cutting (X): `change-process.md`, `upstream-overlay.md`, `README.md`, `docs/architecture/README.md`,
`AGENTS.md`, `compiler/**/*.md`, handoffs `3a99` and `7c41`.

**Base commit:** eefea3c

**How this was produced:** one reviewing agent (Claude Opus), then an independent checking agent that tried to
refute each finding; nothing was executed, and nothing was run under Nix. Each item's **Checked:** line records
the independent check's verdict (2026-11-13) where it ruled on the item. Refuted claims are listed under
"Withdrawn after checking" at the end.

**Item counts by Weight, after corrections:** blocks-goal 14, misleads 18, improves 19, nit 1 (52 items), plus 9 nits in the
Nits table. Independent check: 20 items confirmed, 15 weakened and corrected, X-AR-01 corrected under C1; one idea
withdrawn (and L-§5-09's original remedy).

Reviewer: Claude Opus 5.5 (p2-plans slice), read-only, 2026-11-13. Base `eefea3c`.
Targets: `linux-targets.md` (L), `nixos-passthrough-plan.md` (N), `plugin-layout.md` (PL),
`tendcf-validate-proposal-2026-11-03.md` (V), and cross-cutting (X): `change-process.md`,
`upstream-overlay.md`, `README.md`, `docs/architecture/README.md`, `AGENTS.md`, `compiler/**/*.md`,
handoffs `3a99` and `7c41`. Items are in section order within each target. A short status table
for the work in flight is in X-WIP. Nits are in one table at the end.

Sources consulted: firecrawl search + scrape of the NixOS manual's modular-services section
(`system.services.<name>`, `_class = "service"`, `process.argv`) through an unofficial mirror; the section says
"new in NixOS 25.11" and links https://github.com/NixOS/nixpkgs/pull/372170. The independent check read the
canonical page (https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/modular-services.md)
and nix-darwin/nix-darwin#1765; see L-§5-09. Nothing else was searched.

Local checks run: read every target in full (the validator proposal in four spans, all of it); `git worktree list`;
`gh pr view 41/42`; `rg` over `docs/architecture`, `schema/`, `.github/workflows/`; `ls deploy policy/templates`;
`command -v nix nix-instantiate darwin-rebuild` printed nothing on this Mac, and neither `/nix/var/nix/profiles/default/bin/nix` nor
`/run/current-system/sw/bin/darwin-rebuild` exists (`/etc/nix` has only `macos-keychain.crt`, `sentry-endpoint`).

Other `docs/architecture/` files: **opened** `architecture-DEFINITIVE-v3.md` (§13 build order, §14,
D6/D12 rows, the nix-darwin lines only) and `site-pika-requirement-change-2026-08-13.md` (header only). I also searched the whole directory for Android,
Island/Insular, Shizuku, macOS, logs, monitoring, peer and signing. **No file mentions Island or Insular. No file
plans a log archive or monitoring service, macOS install, Android install or peer transport.** Left unopened: all
`upstream-*`, `UPSTREAM-*`, `*-BRIEF.md`, opinions, reconciliations other than as cited, `GLOSSARY.md`,
`upstream-register.md`, `deprecated/`, `fork-integration-2026-10-29/`. Also read, outside the targets:
`tendcf-s5-design-wt/docs/architecture/s5-unit-detector.md` §11.

---

## L: `docs/architecture/linux-targets.md`

### L-hdr-01: header still says Linux first and Android deferred

**Target:** `docs/architecture/linux-targets.md` header blockquote, at "Android/Termux is deferred;" / "Linux is the platform" (two lines of the blockquote)
**Kind:** ruling-drift
**Goal:** G5
**Weight:** misleads
**Finding:** The header states the 2026-10-29 order as current. G5 reverses it: macOS server, then Android client, then macOS client, then Linux server, then Linux client. The header also says Linux is the platform for "build-order Steps 1 and 3", but map §13 Step 1 is "macOS services adapter", so the sentence contradicted the map even before G5.
**Evidence:** `linux-targets.md:3-4`; `architecture-DEFINITIVE-v3.md` §13 row 1 ("macOS services adapter. Dry-run default. No nix-darwin."); goal G5.
**Proposed text:**

> Operator ruling, 2026-10-29, **superseded in its ordering by the goal of 2026-11-13** (G5: macOS server, Android client, macOS client, Linux server, Linux client). Status: superseded in its ordering by the goal of 2026-11-13 (G5). Linux is fourth and fifth in line; finished pieces stay as standing proofs. Nothing here is deleted.

**Merge:** replace the blockquote; needs the operator's ruling first if "paused" is to be kept (G5 orders the platforms; no ruling pauses Linux work)
**Checked:** verified (read both files); independently checked 2026-11-13: weakened, corrected

### L-§1-02: the target table has no macOS or Android device

**Target:** §1 "Targets", the table beginning "| T1 | GitHub CI"
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** G8 state 1 names "one of the operator's Macs and one of his Android devices". No document names either one, records its OS version, or says which Mac is the server (log archive) Mac. Every row in the table is Linux or a Linux container. The Mac rows need macOS version, architecture and whether it runs nix-darwin. The Android row needs Android version, profile layout (Island/Insular), and whether ShizukuPlus/ShizukuTendCF is installed.
**Evidence:** `linux-targets.md:8-16`; `rg -il 'insular|island' docs/architecture` returns nothing.
**Proposed text:**

> Targets for the first milestone (G8 state 1) live in a separate file, `docs/architecture/first-milestone-targets.md` (to be written): M1, the operator's server Mac (receives and archives logs); A1, one Android device (Island/Insular profiles, ShizukuPlus). The rows below are the Linux targets. Their work is paused (G5 places Linux fourth and fifth).

**Merge:** needs the operator's ruling first (which Mac, which Android device)
**Checked:** verified (table read; grep); independently checked 2026-11-13: confirmed

### L-§3-03: say what each Linux step is worth to the macOS-plus-Android milestone

**Target:** §3 "Order", after the table
**Kind:** add
**Goal:** G5, G8
**Weight:** improves
**Finding:** Much of the Linux work is platform-neutral or has a direct macOS counterpart. The plan does not say which. Without that list, pausing Linux may be read as discarding it. Several pieces carry straight over: the fail-closed flavour guard (step 3) already lets launchd act only on `darwin`; schemas v2–v5 carry the `supervisor` fact and the `launchd` writer vocabulary; the root-owned prefix and root `cf-execd` install shape (step 7) is the shape a macOS LaunchDaemon install needs; and the policy harness runs on the Mac. Other pieces are Linux-only and should pause: the systemd renderer (step 6), dpkg claims (v5), and the NixOS passthrough (step 8).
**Evidence:** `linux-targets.md:35-40`; `policy/templates/launchd.plist.mustache` exists; `deploy/` holds only `linux/`; the compiler renders launchd only (`compiler/README.md` "Units for any supervisor but launchd").
**Proposed text:**

> **Under the 2026-11-13 goal (G5).** Finished, kept as standing proofs: steps 2, 3, 5, 7 (pastebin's canary, under its root `cf-execd`) and 8 stage C (get.sipb.cloud). Carried to macOS unchanged: step 3's guard; the schema v2-v5 vocabulary; `tests/policy/run.sh`. Carried to macOS as a pattern, to be rewritten: step 7's root-owned prefix and install (`deploy/linux/tendcf-install.sh` has no macOS twin; a LaunchDaemon replaces `tendcf-execd.service`); step 2's CI fork build (Linux runners only). Paused: step 6's systemd renderer, the v5 dpkg claims and detector, and step 8 beyond stage C. The macOS adapter (map Step 1) and the compiler's launchd renderer are already the most advanced pieces in the repository.

**Merge:** insert after the table; needs the operator's ruling first ("Paused": G5 orders the platforms, and no ruling pauses Linux work)
**Checked:** verified (files listed; compiler README read); the macOS run of `run.sh` comes from AGENTS.md and was not rerun

### L-§3-04: step 6 should say it comes after macOS and Android, and name the compiler work G8 needs

**Target:** §3 row 6, at "Compiler (`tendcf compile`, was nix2cf; map D46): systemd renderer"
**Kind:** reword
**Goal:** G2, G5
**Weight:** misleads
**Finding:** Step 6 says the next compiler work is the systemd renderer. For G8 state 1, the compiler needs three other things: a Nix frontend (G2), an Android platform and supervisor (G5 #2), and nothing new for launchd, because that renderer exists. As written, the row sends the next compiler slice to Linux.
**Evidence:** `linux-targets.md:38`; `compiler/docs/DESIGN.md` platform↔supervisor row ("`android`, is refused").
**Proposed text:**

> | 6 | Compiler (`tendcf compile`; map D46). **After macOS and Android in the goal's order (G5, 2026-11-13):** the systemd renderer and the Linux `TODO(operator)` markers. The compiler work for the first milestone is the Nix frontend (G2) and an Android platform and supervisor, neither in this file. The compiler emits only the goal file; Augments stay on the device (`projector.py`). |

**Merge:** replace the row; needs the operator's ruling first if "paused" is to be kept
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### L-§4-05: the "Consequences of deferring Android" section is obsolete, and its Termux premise is open

**Target:** §4 "Consequences of deferring Android", item 1, at "The `termux` Site Model block, the `runit` goal-file flavour"
**Kind:** question
**Goal:** G5
**Weight:** blocks-goal
**Finding:** Android is no longer deferred. Item 1 and map §12 assume Android runs Termux with runit services, alongside tendcf-agent and a 'Shizuku-class helper'. G5 adds Island/Insular profiles, which no document or schema models (no work-profile versus personal-profile split), and names ShizukuPlus specifically. Neither profiles nor ShizukuPlus is a service supervisor. Item 2 already allows that "Android may still change the adapter shape later". That cost is now due. It is cheapest before any device holds a baseline, and the validator proposal confirms none does (fact 12).
**Evidence:** `linux-targets.md:44-48`; `schema/services.schema.json:64` (`platform` enum includes `android`), `:114` (`termux`); `tendcf-validate-proposal-2026-11-03.md` §0 fact 12.
**Proposed text:**

> ## 4. Android (no longer deferred; G5 places it second)
>
> The `termux` block, the `runit` flavour and the `android-termux-services` fixture stay until the Android adapter is designed. Open, for the operator: whether Android devices are configured through Termux services at all, or through the profile (Island/Insular) and ShizukuPlus surfaces G5 names; the answer decides whether `runit` is an Android supervisor or only a Linux one. A schema change for it costs no baseline ceremony while no device holds a baseline.

**Merge:** replace §4's heading and item 1–2; needs the operator's ruling first (Android shape)
**Checked:** verified (schema grep, docs grep); independently checked 2026-11-13: weakened, corrected

### L-§4-06: report rows now have a destination, the Mac log archive

**Target:** §4 item 3, at "D18's report rows need a Linux writer. Open."
**Kind:** reword
**Goal:** G3, G8
**Weight:** improves
**Finding:** G3 defines a server as a machine that receives and archives logs. G8 state 1 requires "logs archived on the Mac". So the open point is no longer "who writes rows on Linux". It is two questions: what writes rows on macOS and Android, and what service on the server Mac receives them. No document plans that receiving service. Validator picklist 11 is the closest, and it assumes a pusher collects rows over SSH (see V-§10-10).
**Evidence:** `linux-targets.md:49-51`; goal G3, G8; `tendcf-validate-proposal-2026-11-03.md` §10 item 11.
**Proposed text:**

> 3. Report rows (D18) go to the log-archive service on a server device (G3; on the first milestone, the operator's Mac). On macOS `tendcf-validate run` writes them; on Android tendcf-agent does. The receiving service, its transport and its authentication are not designed.

**Merge:** replace item 3
**Checked:** verified (docs grep: no log-archive design)

### L-§4-07: `tendcf-validate` is described as Linux-only

**Target:** §4 item 5, at "the Linux device-side component"
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** Map D45 and the validator proposal both scope `tendcf-validate` to every host other than Android ("on Linux and macOS"). With macOS first, calling it the Linux component misplaces the first build. The item also says it is "built ... before any further host is enforced". The first further host is now a Mac.
**Evidence:** `linux-targets.md:54-61`; `tendcf-validate-proposal-2026-11-03.md` title and §3 ("on Linux and macOS"); map line 108 ("CFEngine plus the `tendcf-validate` command, with no daemon (D45)").
**Proposed text:**

> 5. **`tendcf-validate`** (map D45): the device-side component on macOS and Linux (Android has tendcf-agent), a Python command (`bin/projector.py` promoted) that validates the approved goal file and writes `host_specific.json` before cf-agent reads it; no daemon. Which host it is first enforced on is for the operator (G5 puts the server Mac first).

**Merge:** replace the first sentence of item 5
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### L-§5-08: "equal frontends" contradicts G2

**Target:** §5 "Nix", at "YAML and Nix are equal frontends"
**Kind:** ruling-drift
**Goal:** G2
**Weight:** misleads
**Finding:** G2 and ruling 4 say "Real Nix first, YAML beneath": YAML/JSON is the data form that Nix evaluates to, and it can be written by hand. "Equal frontends ... Nobody has to learn Nix" puts the two at the same level. It also requires a YAML twin for every Nix fixture, which doubles the fixture work and keeps YAML in the first position. The byte-identical check is still worth keeping. It only needs restating.
**Evidence:** `linux-targets.md:92-94`; goal G2 and ruling 4.
**Proposed text:**

> Nix is the authoring language (G2, 2026-11-13). YAML/JSON is the Site Model data a Nix configuration evaluates to; a person may also write it by hand. Every Nix fixture is checked by evaluating it and comparing the result with its committed YAML/JSON form, byte for byte after canonicalization. Nobody has to learn Nix to edit the data form; a person who knows Nix never has to leave it.

**Merge:** replace the paragraph
**Checked:** verified; independently checked 2026-11-13: confirmed

### L-§5-09: path 2 invents a tendcf option set, so existing NixOS and nix-darwin configs do not carry over

**Target:** §5 path 2, at "The Site Model's types are also Nix module options (`mkOption`, `mkIf`, `mkDefault`)"
**Kind:** add
**Goal:** G2
**Weight:** blocks-goal
**Finding:** G2 says "NixOS-style options, so existing NixOS and nix-darwin configs carry over". Path 2 gives the Site Model its own options. A person's `services.foo.enable` or `launchd.daemons.<name>` would therefore not carry over to a non-Nix target. Only passthrough carries anything over, and passthrough applies only on a Nix host. NixOS 25.11 added *modular services* (`system.services.<name>`, a module with `_class = "service"` setting `process.argv`). The manual marks them "in development … significant changes should be expected". Their portability is between Nix module-system frameworks: "a configuration management framework is an application of `evalModules`" (NixOS, Home Manager, nix-darwin). nix-darwin has no merged support; nix-darwin/nix-darwin#1765, "add modular service interface for launchd", is an open draft (2026-05). nixpkgs ships about eight such services, mostly Linux network daemons (`modular-services.nix`). The canonical `process.argv` is `lib.getExe` of a package, a `/nix/store` path that a Mac without Nix lacks. A tendcf Nix frontend could be one more such framework, but only for services whose argv it can map to a non-store path. That conflicts with X-nix-04's no-`pkgs`, no-store-path envelope, and it does not carry over the conventional `services.<x>.enable` modules that existing configs use. For a machine without Nix, "carry over" can mean only that evaluated pure-data option values are translated into the Site Model off the device; store paths, the packages themselves and high-level `services.<x>.enable` modules do not carry over (08 Summary 2). No existing tool was found that does this for a whole OS configuration (08 §2, searches 2026-11-13).
**Evidence:** `linux-targets.md:80-91`; NixOS manual, "Modular Services": https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/modular-services.md ("new in NixOS 25.11", "in development"); nixpkgs PR https://github.com/NixOS/nixpkgs/pull/372170; nix-darwin draft https://github.com/nix-darwin/nix-darwin/pull/1765.
**Proposed text:**

> Open, for the operator: whether the Nix frontend accepts NixOS modular services (`system.services.<name>`, NixOS 25.11, in development) as one input shape, given that their `process.argv` normally names a store path. Options tendcf cannot honour on the target refuse the compile by name.

**Merge:** insert after the path 2 paragraph; needs the operator's ruling first (whether the Nix frontend accepts modular services as one input shape; one choice with 08's X-nix-02, a one-shot carry-over import, and X-nix-05, nix-darwin option names)
**Checked:** verified against an unofficial mirror of the manual (no modular service evaluated); independently checked 2026-11-13: weakened, corrected (the original remedy, modular services as a ready carry-over route, was refuted and is withdrawn below)

### L-§5-10: path 1 promises distribution and a consent diff on Nix hosts that the NixOS plan withdrew

**Target:** §5 path 1, at "tendcf adds only the thin layer Nix does not do: distribution (lockfile, signed release, consent diff, pull)"
**Kind:** correct
**Goal:** G2, G4
**Weight:** misleads
**Finding:** The NixOS plan's stage D ruling says tendcf "enforces nothing on a Nix host for now. It only reports and refuses". The settled consent diff for the host flake is the GitHub PR's diff, which djbclark approves. That is not a tendcf release and not a device-side diff. Path 1 still claims tendcf distributes to Nix hosts. As written, a reader expects G4's see-and-refuse on NixOS. The plans do not provide it (see N-§3-02).
**Evidence:** `linux-targets.md:73-79`; `nixos-passthrough-plan.md:89-93`, `:105-111`.
**Proposed text:**

> 1. **Passthrough.** On a host that already runs NixOS or nix-darwin, the host's Nix configuration is left to Nix unchanged; services, packages and files stay Nix's (`supervisor: nixos`, schema v4). Ruled 2026-10-31 for NixOS: tendcf there only refuses and reports, and changes arrive through the host flake's own review (nixos-passthrough-plan.md §3 D, §4). Whether tendcf ever distributes to a Nix host is open. No rewrite of a working configuration is ever required.

**Merge:** replace path 1
**Checked:** verified; independently checked 2026-11-13: confirmed

### L-§5-11: nix-darwin has no plan, and the map points at one that is not there

**Target:** §5 Consequences item 2, at "The nix-darwin passthrough adapter is required either way and shares the Step 8 design"
**Kind:** add
**Goal:** G2, G5
**Weight:** blocks-goal
**Finding:** Map §13 Step 7 defers the nix-darwin passthrough adapter to "linux-targets.md Step 8". Step 8 and the whole NixOS plan cover NixOS only: vps-primary and get.sipb.cloud, a read-only `/etc/systemd/system`, and systemd refusal. Neither file covers launchd on nix-darwin, which writes plists into `/Library/LaunchDaemons`, or how the bundle refuses there. macOS is now first, and G2 names nix-darwin. Map §14.1 (nix-darwin on the Mac, yes or no) is still open. This Mac has no Nix installed (checked). So which way G8 state 1 goes on the Mac is undecided: nix-darwin passthrough, or a Nix frontend compiled to launchd for a Mac without Nix.
**Evidence:** `linux-targets.md:99-101`; `architecture-DEFINITIVE-v3.md` §13 row 7 and §14.1; `nixos-passthrough-plan.md` (no "darwin" except via cross-reference); `command -v nix darwin-rebuild` empty.
**Proposed text:**

> 2. nix-darwin has no adapter design yet; Step 8 covers NixOS only. Before the first macOS milestone the operator rules map §14.1 for the server Mac: (a) the Mac runs nix-darwin, and tendcf passes its configuration through (a nix-darwin analogue of nixos-passthrough-plan.md, including how the launchd bundle refuses a label nix-darwin owns); or (b) the Mac has no Nix runtime, and its Nix configuration is compiled by the Nix frontend to a launchd goal file (path 2). G8 state 1 is reachable either way; the two differ in where Nix must be installed.

**Merge:** replace item 2; needs the operator's ruling first (map §14.1)
**Checked:** verified (files read; this Mac checked for Nix); independently checked 2026-11-13: confirmed

### L-§5-12: consequence 3 restates a writer vocabulary that v4 retired

**Target:** §5 Consequences item 3, at "The Step 4 schema bump adds `nix-darwin` to the writer vocabulary next to `nixos`"
**Kind:** correct
**Goal:** G2
**Weight:** misleads
**Finding:** `nixos` left the writer vocabulary in v4 and became the `supervisor: nixos` fact, as §3 step 4 of this same file records. `nix-darwin` is still a writer value. Consequence 4's "how a passthrough host's goal file carries the Nix side" was settled for NixOS by the v4 reconciliation. It is open only for nix-darwin.
**Evidence:** `linux-targets.md:36` (v4: "`nixos` left the writer vocabulary"), `:102-108`.
**Proposed text:**

> 3. `nix-darwin` is a `launchd-writers` writer value (since before v3); `nixos` is no longer a writer but the host-level `supervisor: nixos` fact (v4). 4. For NixOS, how the goal file carries the Nix side was settled by schema v4 (`supervision` is `deliberately-unmanaged`; the consent object is the host flake's PR diff). For nix-darwin it is open (item 2).

**Merge:** replace items 3 and 4
**Checked:** verified; independently checked 2026-11-13: confirmed

---

## N: `docs/architecture/nixos-passthrough-plan.md`

### N-hdr-01: status says "awaiting sign-off" although every decision was taken

**Target:** header, at "Status: proposed 2026-10-31, awaiting operator sign-off"
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** §6 records all four decisions as taken on 2026-10-31. Stages A–C are done and D is ruled. The header still reads as an open proposal. Under G5 the plan also comes after macOS and Android.
**Evidence:** `nixos-passthrough-plan.md:3-5`, `:125-139`.
**Proposed text:**

> Status: decided and executed through stage C (2026-10-31); stage D ruled (enforce nothing on a Nix host). Under the goal's platform order (G5) Linux and NixOS work comes fourth and fifth. get.sipb.cloud keeps the module as a standing proof; vps-primary stays imported, not enabled.

**Merge:** replace the status paragraph; needs the operator's ruling first if "paused" is to be kept
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### N-§3-02: on a passthrough host nothing satisfies G4's device-side see-and-refuse

**Target:** §4 "The passthrough goal file for this host", at "djbclark approves it on the host-flake PR, behind a required CI job"
**Kind:** question
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 says "Nothing changes a device except as an exact, mechanically checked difference that the device's owner can see and refuse." On a NixOS host every change comes through `nixos-rebuild` or `deploy-vps-primary`. The only check is a GitHub PR review, and nothing on the device verifies that what activated is what was reviewed. That is acceptable for the operator's own host today. It does not meet G4 as stated, and G2 invites other NixOS users to bring their configurations. Either G4 has a stated exception for passthrough hosts, or tendcf must gate activation, for example by checking the activated system's toplevel store path against the reviewed `diff-closures`.
**Evidence:** `nixos-passthrough-plan.md:105-111`, `:89-93`; goal G4.
**Proposed text:**

> **Against G4 (2026-11-13):** a passthrough host's changes are not yet a device-checked difference. Open, for the operator: (a) passthrough hosts are outside G4 until stated otherwise; or (b) tendcf records the reviewed toplevel store path and refuses to report the host converged when the activated system differs, a report-only first step toward gating activation.

**Merge:** insert after the consent-diff list; needs the operator's ruling first
**Checked:** verified (text read); option (b) is a design idea, not checked; independently checked 2026-11-13: confirmed

### N-§4-03: "verbatim" is delivered only in the sense that tendcf does nothing

**Target:** §4, at "So the passthrough host is described by a required host-level `supervisor: nixos` fact"
**Kind:** add
**Goal:** G2
**Weight:** improves
**Finding:** G2's "existing NixOS ... configs carry over" is met on NixOS hosts only trivially: the configuration is untouched because tendcf manages nothing there. The goal's adopters are "sysadmins who already share configs in Nix" (G1), and what they would value is carrying a NixOS service definition to a Mac or an Android device. This plan cannot give that, and it should say so, so that passthrough is not mistaken for G2 delivered. How anything carries over to a host without Nix is the open choice of L-§5-09 (with 08's X-nix-02 and X-nix-05).
**Evidence:** `nixos-passthrough-plan.md:97-114`; goal G1, G2.
**Proposed text:**

> Passthrough keeps an existing NixOS configuration working; it does not carry any of it to a host that is not NixOS. That is the Nix frontend's job (linux-targets.md §5, path 2).

**Merge:** insert at the end of §4's first paragraph
**Checked:** verified

### N-§5-04: "Work this unlocks" lists finished work as pending

**Target:** §5 "Work this unlocks, in order", item 1, at "Bundle guard from §2 plus negative test"
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** All three items are done: the guard (§2, check 7), slices B and S1 (schemas v3, v4), and stages A–D. The section reads like a to-do list. Under G5 the next NixOS item is vps-primary's stage C, and it should be marked as coming after macOS and Android in the goal's order, not next.
**Evidence:** `nixos-passthrough-plan.md:28-34` (guard done), `:116-123`.
**Proposed text:**

> ## 5. Work this unlocked (all done 2026-10-31)
>
> 1. Bundle guard and negative test: done (`tendcf_systemd_units_writable`, check 7). 2. Writer vocabulary (v3) and `supervisor` fact (v4): done. 3. Stages A–C: done (C on get.sipb.cloud); D ruled. Next, **after macOS and Android in the goal's order (G5):** stage C on vps-primary.

**Merge:** replace §5; needs the operator's ruling first if "paused" is to be kept
**Checked:** verified; independently checked 2026-11-13: confirmed

### N-§3A-05: what the NixOS derivation and module are worth to the Mac

**Target:** §3 stage A, at "`nixos/pkgs/cfengine-tendcf.nix` (fork `b8abf2840`"
**Kind:** add
**Goal:** G2, G5, G8
**Weight:** improves
**Finding:** Stage A built a Nix derivation of the pinned fork and a `services.cfengine-tendcf` module. If the server Mac takes nix-darwin (L-§5-11 (a)), that derivation is the obvious way to put a pinned, store-owned fork build on the Mac, and nix-darwin's `launchd.daemons` gives the `execd.enable` analogue. That would also solve the missing macOS fork build (X-OV-01). Whether the derivation builds on `aarch64-darwin` was not checked. Its two build patches (perl shebang, `USERMOD` guard) suggest Linux assumptions.
**Evidence:** `nixos-passthrough-plan.md:43-59`; the derivation lives in `site-public-djbclark`, not read here.
**Proposed text:**

> **For macOS (2026-11-13):** the same derivation, built for `aarch64-darwin`, plus a nix-darwin module using `launchd.daemons`, is one candidate for the server Mac's CFEngine install if map §14.1 rules for nix-darwin. Untested on Darwin.

**Merge:** insert after stage A's paragraph
**Checked:** not checked (Darwin build)

---

## PL: `docs/architecture/plugin-layout.md`

### PL-§3-01: "the two equal frontends" contradicts G2

**Target:** §3 table, Frontend row, at "YAML and Nix are the two equal frontends of map D12"
**Kind:** ruling-drift
**Goal:** G2
**Weight:** misleads
**Finding:** Under G2, Nix is the authoring language and YAML/JSON is the Site Model's data form beneath it. The `yaml` plugin is then not a peer frontend. It is the loader for the data form every frontend produces, and a person may also edit that data by hand. The layout can stay. The description has to change, or the restructure will build the wrong priority into the plugin interface (for example, a frontend API shaped around YAML's line-number provenance).
**Evidence:** `plugin-layout.md:104`, `:64-65`; goal G2.
**Proposed text:**

> | Frontend | `tendcf.frontends` (public) | A language a site authors in. It turns its source into Site Model data (YAML/JSON), which the compiler merges, checks and renders. Nix is the primary authoring language (G2, 2026-11-13); the built-in `yaml` frontend loads the data form itself, hand-written or committed beside its Nix source. Guix may follow as an authoring frontend. |

**Merge:** replace the row
**Checked:** verified; independently checked 2026-11-13: confirmed

### PL-§2-02: the Nix frontend needs a Nix evaluator on the compile host, and none is planned

**Target:** §2 table, row `plugins/frontends/nix/`, at "only the hook: `nix2cf eval-nix FILE`"
**Kind:** add
**Goal:** G2, G8
**Weight:** blocks-goal
**Finding:** Nix-first authoring means every compile evaluates Nix. Map D6 keeps Nix off devices, which is fine, but the compile host needs an evaluator. The operator's Mac has none installed (checked), and `compiler/docs/DESIGN.md` records the same absence when nix2cf was built. Today's hook test is skipped without Nix. Before G8 state 1, the plan must name where evaluation runs (the Mac, CI or another device) and how the evaluator is pinned. The evaluator becomes release-path code, so it belongs in §7's "toolchain closure" question. This contradicts `change-process.md` §2 ('Nix is an optional builder, never a dependency of the path', and alternative 5, 'R5/D6 keep Nix optional') and map R5. G2 may override them, but only by the operator's ruling.
**Evidence:** `plugin-layout.md:83`, `:341-346`; `compiler/README.md` ("the test for it is skipped without a Nix install"); `command -v nix` empty on this Mac.
**Proposed text:**

> Open (G2): where the Nix frontend's evaluator runs for a release build, and how its version is pinned. A Nix evaluator is release-path code once Nix is the primary authoring language; until it is pinned, a Nix-authored release is not reproducible from `site.lock` alone.

**Merge:** needs the operator's ruling first (Nix on the release path vs change-process §2 and map R5/D6); then insert as a bullet in §7
**Checked:** verified (this Mac); CI images not checked; independently checked 2026-11-13: weakened, corrected

### PL-§2-03: no Android supervisor or platform in the planned tree

**Target:** §2 tree, at "supervisors/launchd/     unit renderers, one per supervisor; in tree only"
**Kind:** add
**Goal:** G5
**Weight:** blocks-goal
**Finding:** The planned supervisors are launchd, systemd and runit. The second platform in G5 is Android. Its configuration surface (profiles, ShizukuPlus-mediated settings, app state) is not a unit supervisor, and the compiler refuses `android` as a platform. A renderer kind for "Android device state" may be needed beside supervisors. Since §3 already says supervisors need a schema bump, that bump should be designed with Android in view, not after the restructure fixes the tree.
**Evidence:** `plugin-layout.md:67-69`, `:113-124`; `compiler/docs/DESIGN.md` platform↔supervisor row.
**Proposed text:**

> `plugins/renderers/android/` (planned, G5): renders Site Model records for an Android device into goal-file entries tendcf-agent actuates. Whether this is a supervisor or a new renderer kind waits on the Android adapter design (linux-targets.md §4).

**Merge:** insert in the §2 tree and table; needs the operator's ruling first (Android adapter shape)
**Checked:** verified; independently checked 2026-11-13: confirmed

### PL-§4-04: "valid is not faithful" is the gap G4's safety scan fills, so say so

**Target:** §4 "Plugins are trusted build-time code", item 3, at "A plugin **can** make the goal file say something other than what the Site Model says"
**Kind:** add
**Goal:** G4, G6
**Weight:** improves
**Finding:** The layout says a plugin can emit valid but unfaithful output, and that on operator hosts the only human check is the PR preview diff. G6 makes AIs the authors of the configuration. A plugin may also be AI-written. G4 adds a scan of each difference for likely safety. That scan is exactly the second check item 3 lacks. A scanner that compares the rendered hunk with the Site Model change that caused it (`explain-hunk`, D44) flags an unexplained argv or `run_as`. The scan must run in the gates' plugin-free environment, or it inherits the plugins' trust like everything on the compile side.
**Evidence:** `plugin-layout.md:171-187`; handoff `7c41` D-b ruling ("they should be security-scanned before running them, including doing so with the help of AI").
**Proposed text:**

> Under the goal of 2026-11-13 (G4), every difference is also scanned for likely safety, AI among the scanners. A scanner that runs in the gates' plugin-free environment and compares each rendered hunk with the Site Model change it came from is the check item 3 lacks; it scores, it does not authorize.

**Merge:** insert after item 3; coordinate with the in-flight D-a–D-d docs PR (X-HO-02)
**Checked:** verified (text); the handoff ruling is quoted from handoff `7c41`

### PL-§4-05: G9 has no foothold: users cannot fork a plugin without a tendcf PR

**Target:** §4 "Where a plugin lives", and activation item 4, at "a release build loads in-tree plugins only"
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** G9 asks for fork and branch management "as an extension of the platform's existing patch patterns", so that a non-technical user can maintain a fork of a plugin. The layout offers three homes: `plugins/`, `contrib/` (a PR to tendcf) and out-of-tree (not loadable until #47). None lets a user carry a local change to a plugin. The existing patch pattern is the upstream overlay: patch files plus a manifest, `check` for drift, `retired` for upstream catch-up, never a long-lived branch. A site-private overlay over a pinned plugin source, applied at compile time and held to `overlay.py lint/check/retired`, is G9 in its smallest form. The AI turns a user's request into the patch, and a `DRIFT` report is what it re-derives the patch against.
**Evidence:** `plugin-layout.md:198-205`, `:221-239`; `upstream-overlay.md` §3, §5, §6, §8 item 2.
**Proposed text:**

> **Local changes to a plugin (G9, later).** A site may carry patches against an in-tree plugin in site-private, in the upstream overlay's format (patch files and a manifest; `bin/overlay.py` lint, `check`, `retired`). The release build applies them to the plugin source at the pinned tendcf rev and records the patched plugin's hash in `targets.json` `custom`. A drift is reported, never silently rebased. Not designed.

**Merge:** insert at the end of "Where a plugin lives"
**Checked:** verified (both files read)

### PL-§5-06: the restructure is churn against the first milestone

**Target:** §5 row 4 and the paragraph after it, at "Step 4 rewrites every path reference in every file, dated records included"
**Kind:** question
**Goal:** G5, G8
**Weight:** improves
**Finding:** Step 4 renames `bin/` to `tools/`, renames the package, splits the compiler, removes older-version rendering and rewrites paths in every dated record. It waits on #41, #42 and #48. None of it moves G8 state 1 forward, except perhaps the frontend interface the Nix frontend will plug into. It is also the largest diff in the queue, and one cross-model review cycle each. One option is to do only the interface split now (`plugins/frontends/{yaml,nix}`, entry points) and defer the rename and the record rewrite. The rewrite of every dated record was djbclark's ruling, so this is his call.
**Evidence:** `plugin-layout.md:248-260`; handoff `3a99` "Where We're Going" item 3.
**Proposed text:**

> **Under the goal of 2026-11-13:** Open, for the operator: whether step 4 goes in whole before the macOS-and-Android milestone, or only its frontend split (the part the Nix frontend needs), with the renames and the path rewrite after it.

**Merge:** insert after the table; needs the operator's ruling first
**Checked:** verified

---

## V: `docs/architecture/tendcf-validate-proposal-2026-11-03.md`

### V-hdr-01: the proposal covers the launch gate only, and G4's scanned diff has no home in it

**Target:** title block, after "Status: a proposal. It decides nothing."
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 names four device-facing parts: an exact, mechanically checked difference the owner can see and refuse; scans of that difference, AI among them; a 0–100% safety confidence with its reasons; and highlighting graded by risk, in CLI and TUI modes. The proposal is about launch handoff, state, privilege and the interlock fail-open. It mentions the human-facing side only as `propose`, "renders the briefing", in Step 9. Survives intact: the generation store, lock, atomic publication, launch wrapper, launch guard, §13, and the subcommand frame. Must be added: a device-computed diff in the first build (V-§2-03), a `scan`/`show` surface (V-§3-04), the score's semantics (V-§3-05), and where the AI runs (V-§3-06).
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:450-492` (subcommands; `propose` at Step 9), §9 "It does guarantee three things" (no owner-visibility item).
**Proposed text:**

> **Against the goal of 2026-11-13.** This proposal designs the gate between an adopted goal file and cf-agent. G4 also requires, on every device, the difference shown to its owner, scanned for safety, with a 0–100% confidence, its explanation, and graded highlighting, in CLI and TUI modes. Items 2, 3 and 9 below are amended for that (diff in the first build; a `show` subcommand); the scanning and scoring design is not in this proposal.

**Merge:** insert after the status paragraph
**Checked:** verified (all of it read); independently checked 2026-11-13: confirmed

### V-§2-03: option 3's `adopt` lets root change a host with no diff shown

**Target:** §2 option 3, at "The only way to promote is `tendcf-validate adopt FILE`, run as root on the host"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 has no operator exception: nothing changes a device except as a difference its owner can see and refuse. `adopt` checks structure and promotes. It computes no diff against `current`, and §9 lists "the device-computed diff" among what the first build does not guarantee. The diff is cheap. Both files are canonical JSON, and `schema_lint.py` already holds a reference `apply_diff`. Showing it, and requiring the diff's digest on the command line or an interactive yes, makes the first build meet G4 for operator hosts. It needs no approval record or advisor.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:382-391`, §9 "It does not yet guarantee" item 5; inventory report §A (`schema_lint.py` `apply_diff`, L1791-1821).
**Proposed text:**

> `adopt FILE` computes the goal diff from `current` (empty baseline on first adoption) on the device, prints it, and promotes only on an interactive yes or `--accept DIGEST`, where `DIGEST` is the SHA-256 of the printed diff. A mismatch refuses. This is the owner's see-and-refuse (G4) for operator-tier hosts; it is not an approval record and claims none.

**Merge:** insert after option 3's first paragraph as a proposal; needs the operator's ruling first (the `--accept DIGEST` interface). Amend §9 'does not yet guarantee' item 5 only when the first build implements it.
**Checked:** verified (text); `apply_diff` location from the inventory digest, not reopened; independently checked 2026-11-13: weakened, corrected

### V-§3-04: add the `show` duty and the safety assessment to the duties table

**Target:** §3 table, after the row "`--simulate-json` | `propose` only"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The table assigns every device-side duty except the one G4 makes central: presenting the scanned difference. The `--simulate-json` row is the nearest. It already says the simulation is a "human-facing confirmation", never the gate. That is the right status for the safety scan too. CLI and TUI should be two views of one machine-readable assessment, so the TUI adds no logic of its own.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:483-492`.
**Proposed text:**

> | Safety assessment and display (G4) | `show` renders the device-computed diff with the scan results bound to it: per-hunk findings, an overall confidence 0–100%, the reasons, and highlighting graded by each hunk's score; `--format text` (CLI) and a TUI (on a borrowed scaffold, operator to name) read the same JSON assessment. Display only; never the gate. | first build for the mechanical diff; scanners as they land |

**Merge:** insert the row
**Checked:** verified; independently checked 2026-11-13: confirmed

### V-§3-05: the confidence figure needs defined semantics before anyone builds it

**Target:** §3 (b) option 2, after the duties table
**Kind:** add
**Goal:** G4, G6
**Weight:** improves
**Finding:** A 0–100% number invites three errors: treating it as a gate, averaging away one bad hunk, and showing a confident figure when a scanner did not run. G4 says the figure must come with "an explanation of why that percentage was chosen". So the assessment must list which scanners ran, which failed and which were missing. D-b's ruling makes AI a soft requirement for external imports, so a missing AI must lower the figure, visibly. Whether a low score may block a change is a ruling. G4 leaves the refusal to the owner.
**Evidence:** goal G4; handoff `7c41` D-b ruling; `tendcf-validate-proposal-2026-11-03.md:488-489` (the advisor timeout rule, "a timeout means no `accept`").
**Proposed text:**

> Semantics of the confidence (proposal): the overall figure is the minimum of the per-hunk figures, never an average; each figure states the scanners that produced it (rule scanners: privileged region, `run_as` root, new listener, tombstone of a running unit, interlock removed; `--simulate-json`; the owner's AI); a scanner that did not run caps the figure at a stated value and is named in the explanation. The score never authorizes and never refuses; the owner does. Whether a figure below a threshold requires an extra confirmation is for the operator.

**Merge:** insert after the table; needs the operator's ruling first (threshold behaviour, caps)
**Checked:** inferred (design proposal); independently checked 2026-11-13: weakened, corrected (nothing existing misleads; it proposes new semantics, so Weight is now improves)

### V-§3-06: where the AI scan runs, and what binds it to the diff

**Target:** §3 table row "Local-yes exchange", at "`propose` (nonce, briefing) and `accept` (record)"
**Kind:** add
**Goal:** G1, G4
**Weight:** improves
**Finding:** The README says the person reads a change "using **their** AI, not ours". Devices cannot be assumed to have an AI: an Android phone may be offline, and a Mac LaunchDaemon runs as root without one. So the AI scan runs where the owner's AI is, probably the advisor slot. Its output must be bound to the exact diff the device computed, by digest, or a scan of one diff can be displayed over another. The device's own mechanical diff stays the authority, and the scan is a signed or digest-bound annotation of it.
**Evidence:** `README.md:7-10`; `tendcf-validate-proposal-2026-11-03.md:488`.
**Proposed text:**

> An AI scan's result names the SHA-256 of the device-computed diff it scanned; `show` displays it only over that diff and otherwise reports the scan as stale. The scan may run anywhere the owner's AI is (the advisor slot); the device never trusts it for anything but display.

**Merge:** insert after the table
**Checked:** inferred

### V-§1-07: every threat here is sized against root or accidents, none against plausible AI-written changes

**Target:** §1 (b), at "**This guards against accidents and is not a boundary.**"
**Kind:** add
**Goal:** G4, G6
**Weight:** improves
**Finding:** The launch guard is "against accidents", the detector is "threat-modelled for accidents only (R3b)", and every forgery path "needs root". Under G6 every change is AI-written. The realistic hazard is then neither root nor a slip. It is a schema-valid, well-formed change that does something the owner did not ask for: a hallucinated argv, a widened `run_as`, a tombstone of a needed unit, or an imported config with injected content (D-b). The mechanical gate passes all of these by design. That is fine, because G4's scan is what catches them. But the proposal should state this third threat class and point to where it is handled, or readers will assume the gate handles it.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:235`, `:806-807`, `:246-247`; goal G6.
**Proposed text:**

> A third class is out of this gate's scope and must be named: a well-formed, schema-valid change that is wrong or unwanted, the expected failure when AIs author configuration (G6). The gate passes it by design; G4's safety scan and the owner's refusal are its only checks.

**Merge:** insert after the paragraph ending "and so a change to the policy-tree digest."
**Checked:** verified (quotes)

### V-§6-08: macOS is now first, so re-cost item 1 option 3 (launchd job) for macOS

**Target:** §6 (d), at "Recommendation: option 3, prefix `/opt/tendcf/libexec/tendcf-validate/`"; and §1 (d)
**Kind:** question
**Goal:** G5
**Weight:** improves
**Finding:** The recommendations were costed on Linux: cf-execd kept, `tendcf-install.sh`, Debian's `python3`. The proposal recommends item 1 option 3 (replace cf-execd with a timer or launchd job) only "if djbclark prefers" it and "on NixOS". On macOS cf-execd would itself run as a LaunchDaemon, so a LaunchDaemon that starts `tendcf-validate run` directly removes one process layer. It also removes the whole fact-5 process-group problem (cf-execd's single-child kill, the live `assert`). The macOS measurement (no root-owned Python 3.11+) already forces a bundled interpreter there. The first build is now a macOS build. Both platform choices should be re-ruled together.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:204-209`, `:316-322`, `:667-679`, `:724-728`.
**Proposed text:**

> **macOS first (2026-11-13):** on macOS the recommended trigger is option 3, a LaunchDaemon that runs `tendcf-validate run -- cf-agent …` on a `StartInterval`, with cf-execd not installed, because cf-execd would itself be a LaunchDaemon and fact 5's kill path then never arises. Linux keeps option 1 when its work resumes.

**Merge:** insert at the end of §1 (d); needs the operator's ruling first
**Checked:** inferred (launchd behaviour not tested here)

### V-§9-09: the first build's install steps are Linux-only, and no macOS installer exists

**Target:** §9 item 4 "Install changes", at "`tendcf-install.sh` installs the tree"
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** Every install step names `tendcf-install.sh` or `promises.cf` as the Linux installer writes it. `deploy/` has only `linux/`. The first enforced host under G5 is a Mac, so the first build needs a macOS installer: a root-owned `/opt/tendcf` (or other) prefix, a LaunchDaemon, the bundled interpreter, and a pinned macOS fork build (X-OV-01). §6(d) already recommends the bundled interpreter under `/opt/tendcf/libexec/tendcf-validate/` on macOS. The macOS installer, the LaunchDaemon and a pinned macOS fork build are not planned.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:858-865`; `ls deploy` → `linux` only.
**Proposed text:**

> On macOS (first, G5) the same changes need a macOS installer that does not exist yet: a root-owned prefix with the pinned fork build, the bundled interpreter §6(d) recommends, the LaunchDaemon of item 1, and `adopt` in place of `data`.

**Merge:** insert after item 4's list
**Checked:** verified (`ls deploy`); independently checked 2026-11-13: weakened, corrected

### V-§10-10: picklist 11 assumes a central pusher; G3 makes the log archive a service on a server device

**Target:** §10 item 11, at "(1) the pusher collects the JSONL over SSH at each push ... [recommended]"
**Kind:** reword
**Goal:** G3, G8
**Weight:** misleads
**Finding:** The recommendation has the pusher collect rows, which presumes a single host that pushes to everyone. G3 says there is no control node. A "server" is a device offering a service such as receiving and archiving logs, and G8 state 1 puts that archive on the Mac. Option 2 (the device sends rows to an endpoint) matches the goal. The credential it needs is the same peer handshake G3 already requires.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:939-944`; goal G3, G8.
**Proposed text:**

> 11. How report rows leave a device: (1) the pusher collects the JSONL over SSH; (2) the device sends rows to the log-archive service of a server device, authenticated by the same peer handshake updates use (G3) [recommended under the 2026-11-13 goal; the first archive is the operator's Mac, G8]; (3) nothing leaves the device before Step 8.

**Merge:** replace item 11
**Checked:** verified; independently checked 2026-11-13: confirmed

### V-§13-11: the interlock fail-open was ruled, twice, and the proposal still says "not decided"

**Target:** §13, at "It is flagged for djbclark, not decided here."
**Kind:** correct
**Goal:** G4, G7
**Weight:** misleads
**Finding:** Two open PRs record operator rulings: Q10, 2026-11-02, takes option 3 (policy cross-check, PR #42), and R13 (Q49) takes option 5 (a fail-closed fork loader, PR #41). Option 5 reverses the fork's own B-5b, `8f0076b81`. Neither ruling is recorded on master. Map, overlay and register docs still describe the skip-one-entry loader as current. Under G7 an instrument change needs the operator's ruling, and here the ruling exists only in PR bodies.
**Evidence:** `gh pr view 41` ("Operator ruling R13 (Q49)"); `gh pr view 42` ("djbclark's ruling Q10, 2026-11-02, option 3"); `rg 'Q10|Q49|cmdb-fail-closed' docs` finds nothing on master outside this proposal's options.
**Proposed text:**

> **Ruled 2026-11-02:** option 3 (Q10), implemented in PR #42, which records it below; and option 5 (R13, Q49), the fork's all-or-nothing loader pinned by PR #41 (upstream-register B-5b note). Each holds without the other.

**Merge:** needs the operator's ruling first (how #41 and #42 land: both still lack their required frontier cross-model review and adversary verdict, and #41 needs a rebase on #42); then land with #41, after #42; do not duplicate #42's 'Implemented 2026-11-06' paragraph
**Checked:** verified (PR bodies read; grep); independently checked 2026-11-13: weakened, corrected (PR #42 itself adds the Q10 record to §13, and PR #41 records R13 in upstream-register)

### V-§4-12: Android needs the same validator and diff, and the Kotlin port is now critical path

**Target:** §4 (a), at "On Linux and macOS, does the id `tendcf-agent` change"
**Kind:** add
**Goal:** G5, G4
**Weight:** improves
**Finding:** D45 makes tendcf-agent (Kotlin) the Android device component. The proposal's checks (version dispatch, canonical bytes, schema, projection, diff, display) must therefore exist twice, in Python and Kotlin (R22). With Android second in G5, the shared conformance corpus becomes a G8 state 1 dependency, not a later nicety. That corpus is today's goldens and broken fixtures, run by both implementations. G4's display also needs a native Android surface. The CLI and TUI modes do not reach a phone.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:1056-1058` (Kotlin port R22); `change-process.md:276-277` ("The Android agent's Kotlin port must agree with it on the same golden bytes").
**Proposed text:**

> Android (second in G5) runs these checks in tendcf-agent's Kotlin port (R22). The fixture corpus (`examples/`, `examples/broken*`) is the conformance suite both implementations must pass byte for byte; on Android the G4 display is a native screen, not the CLI or TUI.

**Merge:** insert at the end of §4 (a)
**Checked:** verified (quotes); no Android code exists (inventory §H)

---

## X: cross-cutting

### X-CP-01: one signing builder sits uneasily with "no control node" and peer updates

**Target:** `docs/architecture/change-process.md` §6, at "The signing key for `targets` lives on the builder, which is an operator host"
**Kind:** question
**Goal:** G3
**Weight:** blocks-goal
**Finding:** G3: each device "accepts updates from any other device that completes the correct cryptographic handshake", with no control node. The change process has one pipeline (site-private CI) that compiles every host and one builder holding the `targets` key. In practice that builder is a control node for releases. TUF can express G3: per-device delegated targets roles under one offline root, so any enrolled device may sign a release for the hosts it is delegated. But the document picks a single builder, and G8 state 1 requires the handshake. The choice decides the Mac's role: release builder, or one peer among others.
**Evidence:** `change-process.md:186-194`, `:291-294`; goal G3, G8.
**Proposed text:**

> **Against G3 (2026-11-13):** a device accepts a release from any device that completes the handshake. Open, for the operator: (a) one builder signs every release, and peers only relay it; or (b) each enrolled device holds a delegated `targets` key (TUF delegations under the offline root) and may sign releases for the hosts delegated to it.

**Merge:** insert after the paragraph; needs the operator's ruling first
**Checked:** verified (text); TUF delegation semantics from general knowledge, not fetched; independently checked 2026-11-13: confirmed

### X-CP-02: "an operator host applies" without a local yes conflicts with G4

**Target:** `change-process.md` §8 item 1, at "A consented device consents again; an operator host applies."
**Kind:** question
**Goal:** G4
**Weight:** misleads
**Finding:** Here and in map §10, operator-tier hosts apply without a local yes. G4 gives the owner the power to see and refuse every change, on every device. For operator hosts, the refusal could be the PR review (as N-§3-02 discusses), the device-side `adopt` confirmation (V-§2-03), or an explicit standing "auto-accept above N% confidence" that the owner sets. That last option uses G4's score as a policy the owner sets, not as a gate the project sets.
**Evidence:** `change-process.md:326-330`; `plugin-layout.md:175-177`.
**Proposed text:**

> An operator host applies under its owner's standing choice: confirm each diff on the device, or accept automatically the diffs the owner's policy allows (for example, a safety confidence at or above a threshold the owner set). Either way the diff is computed and kept on the device, so the owner can see it and refuse the next one (G4).

**Merge:** replace the sentence; needs the operator's ruling first
**Checked:** verified (text); independently checked 2026-11-13: confirmed

### X-CP-03: stale: the goal file already binds the policy-tree digest

**Target:** `change-process.md` §3 property 3, at "the tarball whose digest the goal file will carry once map §9.8's obligation is discharged. Until then the digest is recorded in `targets.json`"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** The validator proposal records that `goal-file.schema.json` has required `device-trust.entries.policy-tree.tree.sha256` since `9fdf437` (2026-08-15). What is unpaid is R23 (the tree's byte serialization) and a device-side verifier.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:962-969` (stale fact 2).
**Proposed text:**

> what arrives on a device is the tarball whose digest the goal file carries (`device-trust.entries.policy-tree.tree.sha256`, required since the schema family landed). Unpaid: the tree's byte serialization (R23) and the device-side check, by tendcf-agent on Android and `tendcf-validate` on macOS and Linux (map D45).

**Merge:** replace the sentence
**Checked:** inferred from the proposal's cited evidence; schema not reopened; independently checked 2026-11-13: confirmed

### X-CP-04: add the safety scan to the release gates

**Target:** `change-process.md` §6 release gate 5, after "a host's `schema_version` exceeds the ceiling that host last reported"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** Gate 5 computes the per-host preview diff and attaches it to the PR. G4's scan belongs next to it, so that the PR reviewer and later the device owner see the same assessment for the same diff. It runs in the gates' plugin-free environment (§6, "Gates 3 to 6 run apart from plugin code") and never refuses on its own.
**Evidence:** `change-process.md:278-289`, `:296-304`.
**Proposed text:**

> 5b. Scan each host's preview diff for likely safety (G4) and attach the assessment (per-hunk findings, confidence 0–100%, reasons) to the review artifact, bound to the diff's digest. The scan informs; it does not refuse.

**Merge:** insert after gate 5
**Checked:** verified

### X-OV-01: no macOS (or Android) build of the pinned fork exists

**Target:** `docs/architecture/upstream-overlay.md` §2 ruling paragraph, at "the Linux CI and hosts ... run the full fork build"
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** Only Linux CI builds the fork at `overlay/fork.json`'s pin. The Mac runs a dev build (installed in the operator's home directory), which PR #42 reports as `3.29.0a.086d27749`, lacking `8f0076b81`. So the Mac's CFEngine is not the pinned fork, and "every Linux result must name the fork revision" has no macOS counterpart. G8 state 1 needs a pinned, root-owned macOS build, and probably an Android CFEngine build too (map §12 keeps CFEngine on Android beside tendcf-agent, per the s5 note). The operator's global rule keeps macOS legs out of PR checks unless he names them, so this needs his ruling: a scheduled macOS build workflow, a nix-darwin derivation (N-§3A-05), or a local `bg` build.
**Evidence:** `upstream-overlay.md:50-65`; `.github/workflows/*.yml` have no macOS runner (`rg -i 'macos|darwin'` hits a comment only, `check.yml:33`); PR #42 body; the operator's global agent instructions, item 37; `s5-unit-detector.md` §11 (Android bullet).
**Proposed text:**

> **macOS and Android (2026-11-13, G5):** the first milestone runs on a Mac and an Android device, and neither has a pinned build of the fork today (the Mac's dev build is at another revision). Open, for the operator: how the macOS build is produced and pinned (a named macOS CI job, a nix-darwin derivation, or a `bg` build recorded against `overlay/fork.json`), and whether Android runs CFEngine at all. Whichever is chosen, the binary enters a release only as a digest-bound fetched artifact (change-process.md §2 rule 5, 'A tool fork is never an input of its own'; the rule covers the project's own tool forks, which this is, and says nothing about a person's fork), so a local `bg` build counts only once it is published and its digest recorded.

**Merge:** insert after the ruling paragraph; needs the operator's ruling first
**Checked:** verified (workflows grep; PR body); the Mac build's version was not rerun; independently checked 2026-11-13: confirmed (clause on rule 5 added)

### X-OV-02: the overlay is the "existing patch pattern" G9 should extend

**Target:** `upstream-overlay.md` §8 item 2, at "A long-lived merged branch ... is a full parallel fork in all but name"
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** G9 wants non-technical users to keep forks "without knowing about merging, rebasing or compiling". This document has already solved the hard part for one fork. A change is a named patch with a reason (`load_bearing_for`) and an exit condition (`retire_when`). Drift is detected without touching the checkout. Upstream catch-up is detected by patch-id. The rejected alternative is exactly the branch model G9 wants to hide. Recording that this mechanism is the intended base for G9 keeps a later design from starting over with branches.
**Evidence:** `upstream-overlay.md:79-87`, `:141-170`, `:185-208`, `:229-238`; goal G9.
**Proposed text:**

> **G9 (2026-11-13).** This mechanism is the base for later user-facing fork management: a user's fork of a project or a plugin is a manifest of named patches with a reason and a retire condition, applied in order to a pinned base; drift and retirement are reported by `check` and `retired`, and an AI re-derives a drifted patch. No user-visible branch, merge or rebase.

**Merge:** insert as a new §10
**Checked:** verified

### X-OV-03: stale: the `--simulate-json` caller is assigned

**Target:** `upstream-overlay.md` §2, at "on Linux and macOS the caller is an open point of map D45"
**Kind:** correct
**Goal:** G4
**Weight:** nit
**Finding:** The validator proposal assigns it to `propose` (Step 9), and as a G4 scanner it is a natural input: what cf-agent would actually do. The proposal is unruled, so "proposed" is the honest word.
**Evidence:** `tendcf-validate-proposal-2026-11-03.md:489`.
**Proposed text:**

> on Linux and macOS the proposed caller is `tendcf-validate propose` ([`tendcf-validate-proposal-2026-11-03.md`](tendcf-validate-proposal-2026-11-03.md) §3), as a human-facing confirmation and one input to the G4 safety scan.

**Merge:** replace the clause
**Checked:** verified

### X-RM-01: README says nothing is deployed

**Target:** `README.md`, at "Nothing described here is deployed."
**Kind:** correct
**Goal:** G8
**Weight:** misleads
**Finding:** pastebin runs a root-owned fork build with root `cf-execd`, enforcing one canary service, and get.sipb.cloud carries the module. AGENTS.md says so.
**Evidence:** `README.md:27`; `AGENTS.md:267-268`; `linux-targets.md:39`.
**Proposed text:**

> One Linux host (pastebin) enforces one canary service under a root `cf-execd`, as a standing proof; one NixOS host carries the CFEngine module with nothing scheduled. Nothing runs on a Mac or an Android device yet, which is where the first milestone is (G8).

**Merge:** replace the sentence
**Checked:** verified (docs); live hosts not contacted; independently checked 2026-11-13: confirmed

### X-RM-02: README's opening does not state the goal

**Target:** `README.md`, first paragraph, at "Configuration management for a mixed, intermittently-connected fleet"
**Kind:** reword
**Goal:** G1, G5
**Weight:** misleads
**Finding:** The opening describes an operator fleet with "Android devices reached through Termux". G1 frames the project as the user's control of their own devices, used through an AI or at the code level. G5 names Android with Island/Insular profiles and ShizukuPlus as the differentiator. A first-time reader, who is G8 state 3's adopter, meets the old frame.
**Evidence:** `README.md:3-10`; goal G1, G5.
**Proposed text:**

> Free software that gives people control of their own computing devices: a configuration management system you use through your own AI or directly in code. Configuration is to be written in Nix, with plain YAML/JSON beneath it; today the compiler reads the YAML/JSON form only. Nothing changes a device except as a checked difference its owner can see, with a safety score and the reasons, and refuse. First platforms: macOS, and Android with Island/Insular profiles and ShizukuPlus; then Linux. Goal: [`docs/review-2026-11-13/00-goal-definition.md`](docs/review-2026-11-13/00-goal-definition.md) (to move to a permanent home).

**Merge:** replace the first two paragraphs; needs the operator's ruling first (wording, and where the goal file lives)
**Checked:** verified; independently checked 2026-11-13: weakened, corrected (the Nix frontend is not built, so the present tense was wrong)

### X-AR-01: the architecture index omits the three plans that set current work

**Target:** `docs/architecture/README.md`, at "Two living design notes that the map and the guide point at"
**Kind:** add
**Goal:** G5
**Weight:** improves
**Finding:** The index lists change-process, upstream-overlay, upstream-register and plugin-layout. It does not list `linux-targets.md`, `nixos-passthrough-plan.md` or the validator proposal, and nothing on the page tells a reader the Linux plans come after macOS and Android in the goal's order.
**Evidence:** `docs/architecture/README.md:20-28`.
**Proposed text:**

> Platform plans: [`linux-targets.md`](linux-targets.md) and [`nixos-passthrough-plan.md`](nixos-passthrough-plan.md) (Linux and NixOS; Linux is fourth and fifth in the goal's order, G5, 2026-11-13); the device-side gate: [`tendcf-validate-proposal-2026-11-03.md`](tendcf-validate-proposal-2026-11-03.md) (a proposal, unruled). There is no macOS or Android plan yet.

**Merge:** insert after the paragraph; needs the operator's ruling first if "paused" is to be kept
**Checked:** verified; independently checked 2026-11-13: not in the verdict table, but correction C1 applies to it ("paused" replaced by order language)

### X-AG-01: AGENTS.md's verification section has no macOS or Android path

**Target:** `AGENTS.md` "Verifying policy and the CFEngine build", at "Live hosts: pastebin (root install, canary enforced), get.sipb.cloud"
**Kind:** add
**Goal:** G5, G8
**Weight:** improves
**Finding:** Every check named is Linux CI, a Linux VM or a container. The Mac appears only as a dev build for `run.sh`. The section does not warn that this build is not the pinned fork (X-OV-01). There is no Android build check: ShizukuTendCF, its signing keystore in 1Password, nothing. Agents following AGENTS.md will keep doing Linux work.
**Evidence:** `AGENTS.md:241-268`.
**Proposed text:**

> Under the 2026-11-13 goal the first platforms are macOS and Android. The Mac dev build (the one named above) is not the pinned fork; a result from it names its own `cf-agent --version`. No macOS install, macOS CI job or Android build of tendcf exists yet. Linux checks above stay as they are, for the paused Linux work.

**Merge:** insert after "Live hosts …"; needs the operator's ruling first ("paused": G5 orders the platforms, and no ruling pauses Linux work)
**Checked:** verified

### X-CO-01: compiler README calls Nix optional and later

**Target:** `compiler/README.md`, at "The name is historical. YAML and JSON are the inputs. An optional Nix module frontend may author the same JSON later"
**Kind:** ruling-drift
**Goal:** G2
**Weight:** misleads
**Finding:** G2 makes Nix the authoring language. "The name is historical" was also overtaken by D46, under which `nix2cf` names the Nix frontend.
**Evidence:** `compiler/README.md:8-10`; `plugin-layout.md` §6 item 2.
**Proposed text:**

> Today the inputs are YAML and JSON, the Site Model's data form. Nix is the authoring language the project is built around (goal G2); its module frontend, which will carry the name `nix2cf` (map D46), is not built. `nix2cf eval-nix` is the hook it will land behind.

**Merge:** replace the paragraph
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-CO-02: DESIGN.md's case against Nix at build time inverts under G2

**Target:** `compiler/docs/DESIGN.md` "Language and tooling" item 3, at "Making Nix a toolchain requirement of the compiler would invert that."
**Kind:** ruling-drift
**Goal:** G2
**Weight:** misleads
**Finding:** The reason given is that the guide says "nobody adopting the project has to know Nix and YAML/JSON is the stranger path". G2 reverses the priority. A Nix toolchain on the compile host (not on devices, D6) is now expected. "Nix is also not installed on the machine this was built on" is still true of this Mac (checked), and that is now a gap to close (PL-§2-02). This contradicts `change-process.md` §2 ('Nix is an optional builder, never a dependency of the path', and alternative 5, 'R5/D6 keep Nix optional') and map R5. G2 may override them, but only by the operator's ruling.
**Evidence:** `compiler/docs/DESIGN.md:60-69`; `command -v nix` empty.
**Proposed text:**

> 3. **Nix at compile time, never on the device.** Under the goal of 2026-11-13 (G2) Nix is the authoring language, so the compile host evaluates Nix; devices never need it (D6); this amends change-process.md §2's 'Nix is an optional builder', pending the operator's ruling. The evaluator's pinning is open (plugin-layout.md §7). Until the module frontend exists the hook is `nix2cf eval-nix FILE` (`nix-instantiate --eval --strict --json`). YAML/JSON stays the data form, written by hand or produced by Nix.

**Merge:** needs the operator's ruling first (Nix on the release path vs change-process §2 and map R5/D6); then replace item 3
**Checked:** verified; independently checked 2026-11-13: weakened, corrected

### X-CO-03: compiler AGENTS.md says it compiles from Nix expressions

**Target:** `compiler/AGENTS.md`, at "It generates tendcf goal files from Nix expressions"
**Kind:** correct
**Goal:** G2
**Weight:** misleads
**Finding:** The compiler reads YAML/JSON through `sitemodel.py`. `eval-nix` evaluates a plain expression and does not compile. An agent trusting this line would assume the Nix frontend exists.
**Evidence:** `compiler/AGENTS.md:16-18`; `compiler/README.md:95-97`; inventory §A.
**Proposed text:**

> - It generates tendcf goal files from Site Model YAML/JSON (Nix authoring is the goal, G2, and is not built), so CFEngine and goal-file semantics are load-bearing.

**Merge:** replace the bullet's first sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-CO-04: the compiler refuses Android, now the second platform

**Target:** `compiler/docs/DESIGN.md` "Not implemented" bullet, at "*Android/Termux* (Step 2) — deferred (linux-targets ruling 2026-10-29)"
**Kind:** ruling-drift
**Goal:** G5
**Weight:** blocks-goal
**Finding:** `android` is refused as a platform and the `runit` flavour has no renderer. Under G5 that refusal stands between the compiler and G8 state 1. The fix waits on the Android adapter ruling (L-§4-05). Until then the bullet should say "not designed", not "deferred".
**Evidence:** `compiler/docs/DESIGN.md:41-43`, `:101`; `compiler/README.md:89`.
**Proposed text:**

> - *Android* — second in the goal's order (G5, 2026-11-13) and not designed: whether its configuration is Termux/runit services or profile and ShizukuPlus state is open (linux-targets.md §4). Until then `android` is refused as a `--platform`.

**Merge:** replace the bullet (and the matching table row); needs the operator's ruling first for anything beyond the wording
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-HO-01: current sessions are spending on harness and restructure work, none of it on G8 state 1

**Target:** `docs/handoffs/HANDOFF_standalone-97e8_issue48-decided-harness-fixes_2026-11-13_7c41.md`, "Where We're Going"
**Kind:** question
**Goal:** G8
**Weight:** improves
**Finding:** The live queue has three djbclark-ade harness fixes, the D46 decisions docs PR, and then the restructure. Each docs PR costs two frontier reviews plus an adversary review under the standing rule. Nothing in the queue touches a Mac install, Android, the Nix frontend or G4's display. This is not an error, since the queue predates the goal. But the next lead will follow it unless it is re-ordered.
**Evidence:** handoff `7c41` "Where We Are" 1–5, "Where We're Going" 1–6; handoff `3a99` "Where We're Going" 3.
**Proposed text:**

> (For the next handoff, not a merge into the dated one.) Re-order under the 2026-11-13 goal: review (frontier + adversary) and merge #42, then #41; finish the D46 decisions PR; then ask the operator for the first-milestone rulings (server Mac and map §14.1, Android shape, macOS fork build, Nix evaluator) before the restructure.

**Merge:** needs the operator's ruling first (queue order, and what happens to the open PRs: #41 and #42 both still lack their required frontier cross-model review and adversary verdict, and #41 needs a rebase on #42); dated handoffs are not edited
**Checked:** verified (both handoffs read); independently checked 2026-11-13: weakened, corrected

### X-HO-02: the in-flight D46 decisions PR touches the same sections as PL items

**Target:** handoff `7c41` "Where We Are" item 5, at "amends D46 + plugin-layout.md §4/§7 with D-a..D-d"
**Kind:** question
**Goal:** G4, G2
**Weight:** improves
**Finding:** Worktree `tendcf-d46-decisions-wt` (branch `docs/d46-issue48-decisions`, head `7b93a64`) is rewriting `plugin-layout.md` §4 and §7, where PL-§4-04, PL-§4-05 and PL-§2-02 would land. Its D-b ruling ("security-scanned before running them, including ... with the help of AI") is the first concrete instance of G4. If that PR cites G4 and words "equal frontends" per G2, it saves a second review cycle. I did not read its diff.
**Evidence:** `git worktree list`; handoff `7c41`.
**Proposed text:**

> (For the D46 decisions PR's brief.) Cite goal G4 at D-b's scanning rule and word frontends per G2 (Nix primary, YAML/JSON the data form beneath it) in any §3/§4 text the PR touches.

**Merge:** needs the operator's ruling first (scope of an in-flight PR)
**Checked:** verified (worktree exists); its diff not checked

### X-WIP: the three paused worktrees and PRs #41/#42, under the goal

**Target:** worktrees `tendcf-fork-pin-wt` (PR #41), `tendcf-cmdb-xcheck-wt` (PR #42), `tendcf-s5-design-wt` (branch `s5-design`, no PR)
**Kind:** question
**Goal:** G4, G5, G7
**Weight:** improves
**Finding:** The three are summarised in the table below. The owner decides.
**Evidence:** `git worktree list`; `gh pr view 41/42`; `s5-unit-detector.md` §11 (in its worktree).
**Proposed text:**

> | Work | Recommendation | Reasoning |
> | --- | --- | --- |
> | **#42** policy CMDB cross-check (Q10, option 3) | **Finish: merge first.** | Platform-independent: the same `tendcf_services.cf` gates launchd on the Mac, so the fail-open closes on the first-milestone Mac too. Works without #41. Green and ruled; still needs its frontier cross-model review and adversary verdict (its body: 'Do not merge before both'). Merging it unblocks the restructure. Its proof (check 9) uses a simulated loader because the Mac dev build cannot skip one container; check 6b covers Linux systemd. |
> | **#41** fork pin to the fail-closed loader (R13) | **Finish, after #42.** | Ruled; green; moves the pin every later build (including the missing macOS build, X-OV-01) should start from. It reverses the fork's own B-5b and leaves the overlay's B-5b patch text describing the old commit (per its body). That inconsistency should be closed in the same PR or noted in the register. Also needs its frontier and adversary reviews. Rebase it on #42 and re-run CI. In the same PR, correct #42's check-8 comment in `tests/policy/run.sh` ('the fork's loader skips a bad entry') and the §13 sentence 'The Linux CI legs … exercise the real per-entry skip': after #41 neither is true. #41's body names pin `c3afaac26`; the diff pins `d32cade13`. |
> | **s5-design** report-only unit detector as a custom promise (873-line note, no PR, 54 commits behind master) | **Park.** | Its own §11 scopes it to systemd plus dpkg and puts macOS and Android out of scope. Under G5 it serves the fourth and fifth platforms. Keep the branch. The reusable part is the promise-module pattern and the row assembly (§6), worth reading when a launchd or Android extra-entry detector is designed. Do not spend two frontier reviews on it now. |

**Merge:** needs the operator's ruling first (what to do with PRs #41 and #42 and the paused worktrees; both PRs still lack their required frontier cross-model review and adversary verdict, and #41 needs a rebase on #42)
**Checked:** verified (PR bodies, worktree list, s5 §11); PR diffs not read, CI state taken from the inventory digest; independently checked 2026-11-13: weakened, corrected

---

## Nits

| ID | Target, quoted phrase | Fix |
| --- | --- | --- |
| PL-§7-n1 | `plugin-layout.md` §7 "Whether the PyPI names `tendcf` and `nix2cf` are free; unchecked." | Stale: both reserved as 0.0.0 placeholders on 2026-11-13 (handoff `3a99` item 6; https://pypi.org/project/tendcf/, https://pypi.org/project/nix2cf/; URLs not fetched). Replace with "Reserved on PyPI as placeholders, 2026-11-13." |
| N-§3-n2 | `nixos-passthrough-plan.md` §3 A "Written by omp Sonnet 5.5 as a bigteam slice" | omp is retired (ADE); keep as history, add "(omp, since retired)". |
| L-§3-n3 | `linux-targets.md` §3 row 4, one table cell of ~400 words | Move the v2–v5 history into a sub-list under the table; the cell is unreadable rendered. |
| X-AG-n4 | `AGENTS.md` "tendcf and nix2cf are the most important work" | Already in plugin-layout §5 step 4's list; until then add "(nix2cf is now `compiler/`)". |
| X-CP-n5 | `change-process.md` §2 table, the site-private row, at "(today: ops repo" | The ops checkout in use is named `site-private-djbclark` (per the operator's global agent instructions), not `site-private`; check which name the docs standardise on. |
| X-OV-n6 | `upstream-overlay.md` §7 "State verified on 2026-10-09" | Add a line that the tested artifact is the fork pin in `overlay/fork.json` (§2 ruling), not this overlay state. |
| X-CO-n7 | `compiler/README.md` "Units for any supervisor but launchd** (Steps 1–2, 4, 6)" | Step numbers mix map steps and linux-targets steps; name the document for each. |
| V-§0-n8 | `tendcf-validate-proposal-2026-11-03.md` §0 fact 9 "`site-public-djbclark/nixos/modules/cfengine-tendcf.nix`" | Name the repo by its GitHub path, since the doc otherwise links site-djbclark PRs. |
| L-§1-n9 | `linux-targets.md` §1 T7 "prefer CI over Mac resources" | Under G5 the Mac is a target, not only a resource; reword when M1 is named. |

## Ideas and risks

Idea 1 was withdrawn after checking (see the last section); the remaining ideas keep their numbers.

2. **Decide map §14.1 first.** Whether the server Mac runs nix-darwin decides everything else: where Nix evaluates, how the fork is built for macOS (a Nix derivation solves both), and whether macOS needs a passthrough design or only the launchd renderer that already exists. It is a single ruling, and it unblocks most of the first-milestone plan.
3. **Risk: the Android model is unknown and the schema assumes Termux.** No document mentions Island/Insular. If Android configuration is profile and app state through ShizukuPlus rather than services, the goal file needs a new domain, not a supervisor. That is cheapest before any device holds a baseline, which is true today.
4. **One assessment, three views.** Make the G4 safety assessment a schema'd JSON artifact (`safety-assessment.schema.json`, digest-bound to the goal diff). CLI, TUI and the Android screen then become renderers of it. The same artifact goes on the PR (X-CP-04) and the device, so reviewer and owner see identical scores.
5. **Risk: the score becomes the gate by habit.** If owners learn to accept anything at 90% or above, a scanner blind spot becomes a policy hole. Keep the minimum-over-hunks rule, show which scanners did not run, and make any automatic acceptance an explicit owner setting that the device records, never a project default.
6. **Rule scanners before AI scanners.** The privileged-region, `run_as`, tombstone, listener and interlock-removal checks are deterministic. They can ship with the first `adopt`, and they give the AI scanner a floor to explain. They also make the figure meaningful when no AI is reachable.
7. **G9 grows from the overlay, not from git.** `bin/overlay.py` already gives named patches, drift detection without touching a checkout, and patch-id retirement. Generalised to plugins and to forks such as ShizukuTendCF, it hides merge and rebase, as G9 asks, and the AI's job becomes re-deriving one drifted patch.
8. **Risk: review cost against the milestone.** Each docs PR costs two frontier reviews plus an adversary review, and the restructure rewrites every dated record. At the current queue, budget can run out on renames before a Mac converges. Split the restructure, as in PL-§5-06.
9. **The log archive is the first "server" service, and a good first peer protocol.** Rows flowing from Android to the Mac, under the handshake G3 requires, exercise peer authentication with no actuation risk. Building that before signed releases flow peer to peer would test the handshake cheaply.
10. **Keep pastebin as a regression host for the shared bundle.** Linux is paused, but `tendcf_services.cf` is one file for launchd and systemd. pastebin's canary under root `cf-execd` is the only enforced proof of the bundle. Re-installing it after each policy change, #41/#42 included, keeps a Mac-first edit from silently breaking it.

Last search run: firecrawl search and scrape of the NixOS manual's modular-services section (an unofficial mirror), run after drafting L-§5-09; it confirmed `system.services.<name>`, `_class = "service"`, `process.argv`, and that the feature is "new in NixOS 25.11 ... in development". The independent check read the canonical manual page and nix-darwin/nix-darwin#1765 and corrected L-§5-09 accordingly. No search on TUF delegations, nix-darwin's current launchd options, or Android profiles; those statements are marked as unfetched.

Not checked: live hosts; any PR diff (#41, #42, the D46 decisions branch); whether `cfengine-tendcf.nix` builds on Darwin; CI images for Nix; the Mac dev build's version (taken from PR #42's body); the map, guide and paper beyond the cited lines; ShizukuTendCF.

## Withdrawn after checking

| ID | Claim | Refuting evidence |
| --- | --- | --- |
| 04 Ideas 1 | Adopting NixOS modular services as the Nix frontend's input is the cheapest literal delivery of G2, with nix-darwin's launchd named as the second process manager. | Modular services are portable only between Nix module-system (`evalModules`) frameworks; nix-darwin support is an unmerged draft (https://github.com/nix-darwin/nix-darwin/pull/1765); their `process.argv` is normally a `/nix/store` path (https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/modular-services.md). |
| L-§5-09 (original remedy) | A Nix frontend accepting modular-service options and mapping `process.argv` to a launchd `unit` would carry existing services to a Mac without Nix; the evidence was an unofficial manual mirror. | Same evidence as above; the item stays, with its finding and proposed text corrected to an open question for the operator. |

Modular services, accurately: NixOS 25.11 added them (`system.services.<name>`, nixpkgs#372170); the manual marks them in development, about eight exist in nixpkgs, nix-darwin has only a draft, and they do not by themselves carry configuration to a machine without Nix.
