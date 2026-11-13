# Response: the research paper against the 2026-11-13 goal

**Target:** `docs/paper/tendcf-architecture-paper.md` (2,056 lines, all read).
**Base commit:** eefea3c
**How this was produced:** one reviewing agent (Claude Opus), then an
independent checking agent that tried to refute each finding; nothing was
executed unless an item says so.
**Item counts by Weight, after corrections:** 57 items: blocks-goal 16,
misleads 17, improves 24; plus 12 nits in the table. None was withdrawn.
P-§1.1-02 and P-§2.3-02 moved from misleads to improves on checking.

**Reviewer:** Opus 5.5, high effort, read-only, on a worktree of this
repository at `eefea3c`. No repository file changed.

Sources consulted: firecrawl search for ShizukuPlus
(https://github.com/thejaustin/ShizukuPlus: an "enhanced version of Shizuku";
privileged process started "with adb or root"), and for Island/Insular
(https://github.com/proletarius101/Insular; a work profile is a secondary
Android user, "usually user 10",
https://filepathgeek.com/posts/insular-data-location/). A search for the Bcfg2
Actions semantics returned nothing useful, so that is left to the
sources reviewer.

There are 57 items, more than the 25-45 asked for, because one change per
item splits the §9 additions. Where this response and the sources check
(`06-sources-check.md`) treat the same passage, this one follows the
sources check's verdict and names its item.

---

## Front matter and abstract

### P-§0-01: Title and header describe the August paper, not the goal

**Target:** `docs/paper/tendcf-architecture-paper.md` title and header, at "A Configuration Management Architecture for AI-Authored Configuration" and "facts re-checked against the vetted current-state guide and against the repository on 2026-08-18"
**Kind:** reword
**Goal:** G1, G6
**Weight:** improves
**Finding:** The title puts AI authorship first. Under G1 the aim is owner control and adoption, and under G6 AI authorship is the premise, not the subject. The header says facts were re-checked on 2026-08-18. Eight commits touched the paper on 2026-11-13 alone, so readers cannot tell which facts are current.
**Evidence:** `git log -- docs/paper/tendcf-architecture-paper.md` shows a13e892, fd43679, b315772, 74967fc, b47960b, e99db28 and 1ce21a8, all on 2026-11-13.
**Proposed text:**

> # tendcf: Owner-Controlled Configuration Management, Written in Nix by the Owner's AI
>
> Drafted 2026-08-13; restructured against the goal agreed 2026-11-13
> (`docs/review-2026-11-13/00-goal-definition.md`). Facts re-checked against
> the repository at commit `<sha>` on `<date>`.

**Merge:** replace the title and the header's second sentence
**Checked:** verified (git log); independently checked 2026-11-13: confirmed

### P-Abs-01: The abstract says the defect fixes are open upstream

**Target:** Abstract, at "Twenty-three defect fixes are now open as pull requests against `cfengine/core`"
**Kind:** correct
**Goal:** G7
**Weight:** misleads
**Finding:** §7.1 of the same paper says upstream closed all twenty-six PRs on 2026-08-19 and that "the open count upstream is zero". The abstract still says they are open. It is the first factual claim a reader checks.
**Evidence:** paper lines 49-50 against 1544-1554; inventory §E (closed 08-19; "the fork is the destination", 08-22).
**Proposed text:** see P-Abs-03, which replaces the whole abstract. As a stand-alone fix:

> Building on that layer surfaced twenty-three defects, ten of them in that
> data layer, three of which stop the run before a single promise is
> evaluated (§7). Upstream closed the submissions on volume grounds; the
> fixes now live on our CFEngine fork.

**Merge:** replace that sentence (or take P-Abs-03)
**Checked:** verified (read both passages; inventory); independently checked 2026-11-13: confirmed

### P-Abs-02: The abstract describes the withdrawn "typed operation plan"

**Target:** Abstract, at "signed release carrying a typed operation plan that the on-device executor mechanically refuses to exceed"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** §2.5 withdraws exactly this design ("It is withdrawn") and replaces it with a goal-file diff checked by a validator. The abstract and §10 ("a signed plan the executor may not exceed") still describe the old design.
**Evidence:** paper lines 36-38 and 1916-1917 against 461-468.
**Proposed text:** see P-Abs-03. As a stand-alone fix:

> a signed release carrying each host's complete goal file, of which the
> device applies only the difference its owner approved

**Merge:** replace that phrase (or take P-Abs-03)
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### P-Abs-03: Full replacement abstract

**Target:** Abstract, all three paragraphs, from "We describe the architecture of `tendcf`" to "a list of the places we think it is weakest."
**Kind:** reword
**Goal:** G1, G2, G3, G4, G5, G6, G7, G8
**Weight:** blocks-goal
**Finding:** The abstract leaves out the aim (G1), Nix authoring (G2), the peer handshake (G3), see-and-refuse with safety scoring (G4) and the platform order with Android as the differentiator (G5). It frames CFEngine as the design's bet rather than an instrument (G7), and it says nothing about the finish line (G8). It also carries the two errors above. The replacement keeps the paper's habit of saying first what is not built.
**Evidence:** paper lines 20-56; goal G1-G8.
**Proposed text:**

> We describe `tendcf`, free software for configuration management whose aim
> is that people control their own computing devices as they see fit. A
> person uses it through an AI or directly at the code level, whichever they
> prefer at the moment. Through an AI, they say what they want; the AI writes
> it as configuration, and explains or warns when a request looks unwise.
> Configuration is written in the Nix language with NixOS-style options, so
> existing NixOS and nix-darwin configurations carry over. It evaluates to
> plain JSON, which is what gets schema-checked and compiled. We take it as a
> premise, not a hypothesis, that AI agents write most of this configuration.
> From that we derive a design rule: prefer designs whose correctness follows
> from information *local* to the file being edited over designs that need
> *global* knowledge of what everyone else declared.
>
> Every device converges on its own. There is no control node. A device
> accepts an update from any other device that completes the correct
> cryptographic handshake, and a "server" is only a device that provides
> services, such as log archiving and monitoring, to others. Nothing changes a
> device except as an exact, mechanically checked difference between the goal
> file it has approved and the one proposed, and the device's owner can see
> that difference and refuse it. Each difference is also scanned for likely
> safety in several ways, AI among them. The owner sees a confidence figure
> out of 100%, the reasons for it, and the questionable entries highlighted
> more strongly the less safe they look, in a command-line mode or a TUI. The
> first platforms are macOS as a server and Android as a client. We know of
> no comparable tool for Android that works across Island and Insular work
> profiles and with ShizukuPlus's user-space privilege. Today the substrate
> is a fork of CFEngine, driven through its JSON data layer. Bcfg2 supplies
> `<N>` load-bearing ideas (§6).
>
> Little of this is built. A compiler renders per-host goal files, with
> service units for launchd only, and a reference projector and a generic
> CFEngine bundle exist. One canary service has been enforced on one Linux
> operator host since 2026-10-31. No Mac or Android device runs tendcf. The review surface,
> the handshake and the Android agent are designs. Our one empirical result
> is about the substrate: putting real weight on CFEngine's data layer
> surfaced twenty-three defects, ten of them in that layer (§7). The paper is
> written for an expert reader who will find the holes; §9 lists where we
> think it is weakest.

**Merge:** replace the abstract; `<N>` takes the Bcfg2 idea count settled under 06 P-refs-s16 (four in the paper, six in the guide; the same count in both documents)
**Checked:** verified, for the status claims: compiler launchd-only (inventory §A, `RENDERED_SUPERVISORS`); canary since 2026-10-31 (`docs/architecture/linux-targets.md:39`); no Mac or Android deployment (inventory §G4); independently checked 2026-11-13: weakened, corrected (the Android sentence reworded; the compiler limit narrowed to service units, `compiler/nix2cf/compile.py:95`; the idea count deferred to 06 P-refs-s16)

---

## §1 Motivation

### P-§1-01: The motivation predates the aim

**Target:** §1 "Motivation", first paragraph, from "The site is heterogeneous rather than uniform" to "or see the conversation."
**Kind:** ruling-drift
**Goal:** G1, G5
**Weight:** blocks-goal
**Finding:** §1 motivates the design from one heterogeneous site "held by more than one trusted operator". G1 motivates it from people who should control their own devices, with named first adopters (sysadmins who share configs in Nix) and a long-run user with no admin skill. The paragraph never mentions adoption, the platform order or Android's role. It does keep the right point about the user's own AI.
**Evidence:** paper lines 62-71; goal G1, G5; ruling 1 ("non-sysadmin users, even clueless people, could use the tool via only via AI").
**Proposed text:**

> The aim is that people control their own computing devices as they see
> fit, and that they can do so without becoming administrators. tendcf is a
> configuration management system meant to be adopted by others. A person
> uses it through an AI or directly at the code level, whichever they prefer
> at the moment. Through an AI, they say what they want; the AI writes it as
> configuration, and explains or warns when a request looks unwise. That AI
> is **theirs**, not ours: we never run their model, see their prompt, or see
> the conversation. We expect the first adopters to be sysadmins who already
> share configurations in Nix. The user we are building toward has no admin
> skill at all.
>
> The platforms come in a fixed order: macOS as a server, Android as a
> client, macOS as a client, Linux as a server, then Linux as a client.
> Android is the one we think nobody else serves. Comprehensive configuration
> management that works across Island/Insular work profiles and with the
> user-space privilege of ShizukuPlus is, as far as we know, not offered
> anywhere else (§2.8).

**Merge:** replace the paragraph
**Checked:** verified (read §1 against G1/G5); independently checked 2026-11-13: confirmed

### P-§1-02: "The unusual requirement" omits the two ways of use

**Target:** §1, paragraph beginning "**The unusual requirement is who writes the configuration.**"
**Kind:** add
**Goal:** G1, G2, G6
**Weight:** improves
**Finding:** The paragraph states the premise in a way consistent with G6 ("not a prediction... the operating assumption"). It leaves out G1's other half: the same person may edit the code directly at any moment. That makes human readability of the Nix source and of the diff a requirement too (G2: "reads clearly without manuals"). Without it, the local-knowledge rule could be read as licence to optimise only for machine authors.
**Evidence:** paper lines 76-82; goal G1, G2.
**Proposed text:**

> The same person may also stop using the AI at any moment and edit the
> configuration directly. So whatever the AI writes must remain ordinary
> Nix that a person can read and change, and whatever a person is shown, the
> diff above all, must read clearly without a manual. Machine authorship
> sets the cost structure; human legibility is a constraint on it, not a
> casualty of it.

**Merge:** insert after the paragraph
**Checked:** verified (read)

### P-§1.1-01: The device-local trust root is now required, not a fix "until"

**Target:** §1.1 "Scope, and where it stops applying", bullet beginning "**The consent gate does not yet mean what §2.5 says it means.**", at "Until that exists, a site that needs the property §2.5 describes needs a different trust architecture"
**Kind:** ruling-drift
**Goal:** G3, G4
**Weight:** blocks-goal
**Finding:** The bullet treats a device-local trust root as an optional remedy for sites that need real consent. G3 requires that every device accept updates from *any* other device that completes the correct handshake. That works only if the device holds, locally, what a correct handshake is, beyond the reach of the release path. G8 state 1 requires it on the first Mac and Android device. The limit has become a requirement on the first milestone. That "required" is an inference: a TUF root is already enrolled out of band (paper lines 475-477), and G3/G4 imply only that the handshake's anchors and the consent policy sit beyond the release path's reach.
**Evidence:** paper lines 126-138; goal G3, G8.1; inventory §H ("Device-local trust root | schema only").
**Proposed text:**

> Until that exists the gate is an audit trail, not a boundary. Because
> every device must accept updates from any peer that completes the
> handshake (§2.3), what that handshake trusts, and the consent policy, must
> sit beyond the release path's reach; whether that takes a separate
> device-local root is open (§9.15).

**Merge:** needs the operator's ruling first (whether a device-local trust root is a requirement of G3/G4 or one design among several); then replace the final sentence of the bullet
**Checked:** verified (read; inventory); independently checked 2026-11-13: weakened, corrected

### P-§1.1-02: "§1 promises more than one" operator: adoption is many sites, not one shared root

**Target:** §1.1, bullet beginning "**The signing model is sized for one operator, and §1 promises more than one.**"
**Kind:** reword
**Goal:** G1, G3
**Weight:** improves
**Finding:** Under G1, adoption means many independent owners, each with their own site, sharing configuration as inputs (Nix-style). That is many single-root sites, not one multi-operator site, and it needs no threshold signing. The multi-operator limit still applies inside one household or lab that shares a root. That is a narrower case, and the bullet should say so rather than imply the product needs threshold signing to be adopted.
**Evidence:** paper lines 145-149; §2.1 layers at lines 189-212; goal G1.
**Proposed text:**

> - **The signing model is sized for one owner per site.** Adoption does not
>   strain it: each adopter is the owner of their own site and takes other
>   people's configuration as pinned, namespaced inputs (§2.1), not as a
>   shared signing key. The limit is a site with several co-equal owners, a
>   household or a lab, where a second owner must author a release without
>   the first's key. Threshold signing, delegation, per-role scoping and
>   co-owner revocation are a different trust architecture, and we do not
>   have one.

**Merge:** only if P-§1-01 removes "more than one trusted operator"; otherwise no change (the bullet ties threshold signing to §1's multi-operator site, not to adoption)
**Checked:** inferred (reading of G1 against §2.1); independently checked 2026-11-13: weakened, corrected

### P-§1.1-03: The "refusal is offered, not exercised" limit now has a planned answer, G9

**Target:** §1.1, bullet beginning "**Refusal is offered, not exercised.**"
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** The bullet says there is no path for a person's divergence to persist. G9 names the path, later: branch management built on the platform's existing patch patterns, so that non-technical users can keep forks without merging or rebasing. The repo already runs that pattern for CFEngine (`overlay/`: six patches checked weekly for drift). Saying so turns a dead-end limit into a stated direction.
**Evidence:** paper lines 139-144; inventory §E (overlay.json, 6 patches, weekly drift job); goal G9.
**Proposed text:**

> The direction we intend, later, is to make a refusal the start of a branch
> rather than the end of a conversation. A person who keeps a change of
> their own carries it as a patch over the shared configuration. The device
> checks that patch against each new release the way this project already
> checks its own patches against upstream CFEngine (§11). The person never
> has to know about merging, rebasing or compiling.

**Merge:** insert at the end of the bullet
**Checked:** verified (overlay/ per inventory §E; §11 is the new section in P-§S-01); independently checked 2026-11-13: confirmed

### P-§1.1-04: The "much smaller system" boundary should be argued from G4

**Target:** §1.1, bullet beginning "**Below some engineering budget, a much smaller system delivers most of this.**"
**Kind:** reword
**Goal:** G4
**Weight:** improves
**Finding:** The bullet concedes that a signed tarball plus a convergent applier delivers most of the value. Under G4 it does not: it has no exact difference an owner can see and refuse, and nothing to scan. Stating that turns a vague budget concession into a concrete line, which is what an adopter deciding between the two needs.
**Evidence:** paper lines 163-168; goal G4.
**Proposed text:**

> - **Below some engineering budget, a much smaller system delivers most of
>   this, for a fleet whose owner is its only author.** A signed tarball of
>   rendered per-host state plus a convergent applier keeps devices
>   converged at a fraction of the cost. What it cannot give is the one thing
>   this design exists for: an exact difference the device's owner sees,
>   gets a reasoned safety reading on, and can refuse. A reader who does not
>   need that should take the tarball.

**Merge:** replace the bullet
**Checked:** inferred

---

## §2 Architecture

### P-§2.1-01: Nix is "may", G2 makes it the authoring language

**Target:** §2.1 "The Site Model: facts in layers, behavior in tendcf", paragraph beginning "The Site Model *may* be authored in the Nix module system"
**Kind:** ruling-drift
**Goal:** G2
**Weight:** blocks-goal
**Finding:** The paragraph makes Nix optional and promises that an adopter "is never required to know Nix". G2 puts real Nix with NixOS-style options first, with YAML/JSON beneath it as the data form it evaluates to, still writable by hand. The paragraph also omits the reason G2 gives: existing NixOS and nix-darwin configs carry over. The fact that the JSON, not the Nix, is what is validated and signed survives, and should stay.
**Evidence:** paper lines 243-251; goal G2, difference 2; `compiler/nix2cf/cli.py:203` (`eval-nix` exists, thin); inventory §A ("the Nix module frontend of D12 ... is not built").
**Proposed text:**

> The Site Model is written in the Nix language, using the module system as
> NixOS does: `mkOption`, `types.*`, `mkIf`/`mkDefault`/`mkMerge`, and
> option names in NixOS's style. The point is that configuration people
> already have carries over: a host already running NixOS or nix-darwin
> keeps its configuration unchanged through passthrough (linux-targets §5),
> and elsewhere a person who knows Nix writes the configuration for a Mac or
> an Android phone the way they would write it for NixOS. Beneath the Nix sits plain JSON/YAML, the data form the
> evaluation produces. That data is what is schema-validated, compiled,
> signed and diffed, and a person may write it by hand. We use the Nix
> *language* and module system, not the Nix *build system* (but see §9 on
> `pkgs`). Today only a thin evaluator exists (`nix2cf eval-nix`, a wrapper
> around `nix-instantiate --eval --strict --json`); the module frontend
> that will carry the name `nix2cf` is not built (§8).

**Merge:** replace the paragraph
**Checked:** verified (cli.py:203; inventory §A); independently checked 2026-11-13: confirmed (proposed text corrected for passthrough on NixOS/nix-darwin hosts)

### P-§2.1-02: "Carry over" collides with "not the Nix build system"

**Target:** §2.1, sentence beginning "We use the Nix *language* and not the Nix *build system*"
**Kind:** question
**Goal:** G2
**Weight:** blocks-goal
**Finding:** Real NixOS and nix-darwin configs are mostly settings of option trees that nixpkgs and nix-darwin declare (`services.caddy.enable`, `launchd.daemons.*`), and they name packages as derivations (`pkgs.caddy`). Carrying them over means one of three things: evaluate nixpkgs/nix-darwin's own modules and translate their result, which needs nixpkgs at authoring time; re-declare a compatible subset of their option names in tendcf's own modules; or carry only the module *style*, not the configs. The three differ in cost by an order of magnitude, and each needs an answer for what `pkgs.x` means on macOS and Android. The paper should not claim carry-over until one is chosen. On NixOS and nix-darwin hosts the ruling of 2026-10-29 already settles it (passthrough, `docs/architecture/linux-targets.md:63-99`); what is open is a host without Nix.
**Evidence:** paper lines 248-251; goal G2; `docs/architecture/linux-targets.md:65-94` (the 2026-10-29 "verbatim" wording, per digest-current-plan B4).
**Proposed text:**

> Part of "carries over" is settled: on NixOS and nix-darwin hosts the
> existing configuration is used unchanged through passthrough (ruling of
> 2026-10-29, linux-targets §5). What is open is what carries over to a
> host without Nix: a Mac without nix-darwin, or an Android phone. Evaluating nixpkgs' and
> nix-darwin's own modules gives the most faithful carry-over but brings
> nixpkgs onto every authoring machine. Re-declaring a compatible subset of
> their option names in tendcf's modules is cheaper and covers only what we
> declare. Carrying the module style without the configs is cheapest and
> carries nothing. In each case a package reference (`pkgs.caddy`) needs a
> meaning on hosts where nothing is built by Nix. §9.19 asks the question.

**Merge:** needs the operator's ruling first (what G2's carry-over means on non-Nix hosts); insert after the sentence once ruled
**Checked:** inferred (standard NixOS module structure; not checked against a real carry-over attempt); independently checked 2026-11-13: weakened, corrected

### P-§2.1-03: Foreign inputs should be named as what Nix sharers already use

**Target:** §2.1, paragraph beginning "Site-private holds a lockfile (flake-style inputs)"
**Kind:** add
**Goal:** G1, G2
**Weight:** improves
**Finding:** G1's first adopters already share configs in Nix, which today usually means flakes and their `flake.lock`. The layer model (site-shared, foreign site-shared, lockfile) is the right shape. The paper says "flake-style" without saying whether a foreign site-shared input *is* a flake. If it is, an adopter's existing sharing works unchanged and that is a selling point. If it is not, the paper should say why.
**Evidence:** paper lines 193-212; change-process `site.lock` (digest-current-plan A4).
**Proposed text:**

> For the adopters we expect first, who already share configuration as Nix
> flakes, the intent is that a site-shared input is a flake and the lockfile
> pins it the way `flake.lock` does, so what they already publish is
> already a tendcf input. Whether the lockfile is `flake.lock` itself or a
> `site.lock` beside it is open.

**Merge:** insert after the paragraph; needs the operator's ruling on flake-as-input
**Checked:** inferred; independently checked 2026-11-13: confirmed

### P-§2.2-01: `tendcf compile` is presented as the command that exists

**Target:** §2.2 "The compiler: a pure function into CFEngine's own data layer", at "A compiler, `tendcf compile`, reads the Site Model and renders a per-host goal file"
**Kind:** correct
**Goal:** G2
**Weight:** misleads
**Finding:** The command today is `nix2cf buildfile`, with `eval-nix` beside it. `tendcf compile` is the name D46 plans for a later restructure. The second paragraph of §2.2 says so, but the section opens in the present tense with the planned name, and §2.1 does the same ("The compiler (`tendcf compile`, §2.2) is a tool").
**Evidence:** `compiler/pyproject.toml:18` (`nix2cf = "nix2cf.cli:main"`); `compiler/nix2cf/cli.py:179,203`; paper lines 255, 238.
**Proposed text:**

> A compiler reads the Site Model and renders a per-host goal file. Today
> it is invoked as `nix2cf buildfile`; it becomes `tendcf compile` in the
> planned restructure.

**Merge:** replace that sentence (and the parenthesis in §2.1 at "The compiler (`tendcf compile`, §2.2) is a tool")
**Checked:** verified (pyproject.toml, cli.py); independently checked 2026-11-13: confirmed

### P-§2.2-02: The bundle is no longer launchd-only

**Target:** §2.2, at "A first version of that bundle now exists and runs (§8); it is launchd-only, which is a real limit and not a placeholder."
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** §8 of the same paper says the bundle gained a systemd branch on 2026-10-31, and that branch is enforced on pastebin. Only the *compiler* is launchd-only. The two have been conflated, here and again in §2.6 (P-§2.6-02).
**Evidence:** paper line 314 against 1727-1728; inventory §A ("systemd: unit rendered ... enforced on pastebin"; compiler `RENDERED_SUPERVISORS` launchd only).
**Proposed text:**

> A first version of that bundle now exists and runs (§8), with a launchd
> branch and a systemd branch. The compiler renders services for launchd
> hosts only, so a systemd host's goal file is today written outside it.

**Merge:** replace that sentence
**Checked:** verified (read; inventory); independently checked 2026-11-13: confirmed

### P-§2.2-03: nix-darwin is a source of configuration, not just optional "substrate"

**Target:** §2.2, at "NixOS / nix-darwin remain optional Mac *substrate*, Step 7, not a runtime dependency of the compiler."
**Kind:** ruling-drift
**Goal:** G2, G5
**Weight:** misleads
**Finding:** Under G2, nix-darwin configs are an input that should carry over, and under G5 macOS is the first platform. Calling nix-darwin "optional Mac substrate, Step 7" puts it late and on the wrong side of the compiler. Whether a nix-darwin Mac is managed through nix-darwin (as NixOS hosts pass through today) or through CFEngine with the config carried over is a real choice. The paper should state it as such.
**Evidence:** paper lines 352-353; goal G2, G5.1; `docs/architecture/nixos-passthrough-plan.md` (Nix hosts report and refuse; digest-current-plan B6).
**Proposed text:**

> nix-darwin matters twice. Its configurations are input that should carry
> over (§2.1), and on a Mac that already runs it, it could instead be the
> enforcing layer, as NixOS is on NixOS hosts today. On a Mac that runs
> nix-darwin, passthrough is the path (linux-targets §5: the adapter "is
> required either way"); whether the first Mac runs nix-darwin is open
> (§9.19). Neither is a runtime dependency of the compiler.

**Merge:** replace that sentence
**Checked:** inferred; independently checked 2026-11-13: weakened, corrected (`docs/architecture/linux-targets.md:99`: "The nix-darwin passthrough adapter is required either way")

### P-§2.2-04: "because of Promise Theory" treats CFEngine as the design rather than an instrument

**Target:** §2.2, at "The pairing here is Site Model (YAML/JSON, or an optional Nix frontend) into CFEngine Augments, because of Promise Theory and disconnected multi-owner operation (§2.3)"
**Kind:** reword
**Goal:** G2, G7
**Weight:** improves
**Finding:** G7 makes CFEngine, the fork, the Site Model and the compiler instruments, open to challenge. The sentence makes CFEngine Augments part of the design's identity and keeps Nix as "optional". The stable contract the design actually depends on is the goal file and the device's diff, not augments.
**Evidence:** paper lines 349-353; goal G7.
**Proposed text:**

> The pairing here is Nix-authored Site Model into a per-host goal file,
> applied today through CFEngine's augments. CFEngine is the current engine
> because it already runs autonomous agents with no control node (§2.3). It
> is an instrument, not the design: the contract is the goal file and the
> difference a device computes from it, and another engine that can apply
> that difference could replace CFEngine without changing it.

**Merge:** replace that sentence
**Checked:** verified (read against G7)

### P-§2.3-01: "Every host runs its own `cf-serverd`" is not what deployed hosts do, and G3 is firmer

**Target:** §2.3 "Deployment shape: no policy server, push and pull as one mechanism", first paragraph, from "Every host runs its own `cf-serverd` and reads policy synced via git" to "Push and pull are two modes of the same mechanism."
**Kind:** correct
**Goal:** G3
**Weight:** blocks-goal
**Finding:** The one enforced host runs a root `cf-execd` and an installer-copied policy. Neither the deploy tree nor linux-targets mentions `cf-serverd` at all, and nothing is synced via git. G3 states the shape firmly: every device is self-sufficient, there is no control node, and it accepts updates from any device that completes the correct handshake. The paragraph should state that as the requirement and say what exists. Which handshake is unsettled (P-§2.5-03).
**Evidence:** `rg -c cf-serverd deploy/ docs/architecture/linux-targets.md` gave no hits; `docs/architecture/linux-targets.md:39` ("No masterfiles framework: the installer copies the policy in as root"); goal G3, difference 5.
**Proposed text:**

> Every device is self-sufficient: it converges on its own schedule from the
> last release it approved, and there is no control node. A device accepts
> an update from *any* other device that completes the correct cryptographic
> handshake. A peer may carry a release; only the handshake makes it
> acceptable. A device that holds a deploy role may also ask another to
> converge now rather than at its next cycle; that is a request, and the
> target still applies only what it would have accepted anyway. "Server" in
> this paper means only a device that provides services to others, such as
> receiving and archiving logs or monitoring (§2.5). "Client" means a device
> that uses them. Neither word changes the architecture. Today the one
> enforced host runs a root `cf-execd` with an installer-copied policy; no
> `cf-serverd`, git sync or peer transport is built.

**Merge:** replace the paragraph
**Checked:** verified (rg; linux-targets:39); independently checked 2026-11-13: confirmed

### P-§2.3-02: The Promise Theory claim is overstated

**Target:** §2.3, at "Promise Theory was formalized as a model of autonomous agents specifically to rule out client-server protocols that push data to a controller [6]; nothing about "no control node" is this paper's invention, and it is the actual reason §2 chooses CFEngine over the alternatives."
**Kind:** correct
**Goal:** G7
**Weight:** improves
**Finding:** (c) Promise Theory models autonomous agents that can only promise their own behaviour, so cooperation is voluntary. That makes push-imposed obligations inexpressible. It was not formalised "specifically to rule out client-server protocols that push data to a controller": that purpose claim is refuted by the book and by Burgess 2005 (see 06 T27 and R2c in `checks/v7-refetch.md`). Burgess's 2005 DSOM paper introduced the promise as a measure of voluntary cooperation, and the book says Promise Theory "is not about protocol modeling" (checked against the book and the 2005 paper, 2026-11-13). Burgess 2005 even builds client-server interactions from promises, so the theory does not rule them out. The 2014 book [6] is the later full formalisation of that 2005 motivation. The sources check treats the same sentence as 06 P-§2.3-s21 (weight `improves`); this item follows it, and the two now agree and merge as one text.
**Evidence:** paper lines 379-383; reference [6] at line 1969. Checked against the book (Burgess and Bergstra, *Promise Theory: Principles and Applications*, 2014, ch. 1 and 17: "originally invented to discuss the issues surrounding this autonomous operation, and voluntary cooperation"; "It is not about protocol modeling") and against Burgess, DSOM 2005, LNCS 3775 (no external agent can tell an agent what to do "without its consent"; promises rebuild "client-server interactions, dependencies and access control"), both read 2026-11-13. The book and the paper support "no other agent can impose a promise on it", not "cannot be obliged". The markburgess.org FAQ says Promise Theory "emerged from the software CFEngine"; the promises page states no "specifically to rule out" purpose (06 T27).
**Proposed text:**

> In Promise Theory, which was developed to describe CFEngine's
> decentralised mode of operation, an agent can promise only its own
> behaviour and no other agent can impose a promise on it [6]. A design with no
> control node is the natural reading of that model, not this paper's
> invention, and it is one reason CFEngine is the current engine (§2.2).

**Merge:** replace that sentence, as one merged edit with 06 P-§2.3-s21; [6] and Burgess 2005 are now checked (see Finding); consider citing Burgess 2005
**Checked:** verified (the book, ch. 1 and 17, and Burgess 2005 read 2026-11-13); independently checked 2026-11-13: weakened, corrected; sources re-fetched 2026-11-13: corrected

### P-§2.3-03: "No equivalent to phone home to" is false once logs are archived

**Target:** §2.3, at "it is centralized, and devices phone home to it; this design has no equivalent to phone home to at all."
**Kind:** ruling-drift
**Goal:** G3, G8
**Weight:** misleads
**Finding:** G8 state 1 needs logs archived on the Mac, and G3 names log archiving and monitoring as services other devices use. Devices will send something to a server. The real difference from balenaCloud is that nothing a device *needs* in order to converge or accept an update lives on that server.
**Evidence:** paper lines 396-400; goal G3, G8.1, difference 6.
**Proposed text:**

> it is centralized, and devices depend on it. Devices here also send their
> logs to a server, but only as a service: nothing a device needs in order
> to converge, or to accept an update, lives there, and a device that
> cannot reach it keeps working and keeps its own record.

**Merge:** replace that clause
**Checked:** verified (read against G3/G8); independently checked 2026-11-13: confirmed

### P-§2.4-01: The Android paragraph is about Termux; G5 is about profiles and ShizukuPlus

**Target:** §2.4 "The record of truth is local", paragraph beginning "On Android, Termux and tendcf-agent are different UIDs"
**Kind:** ruling-drift
**Goal:** G5
**Weight:** blocks-goal
**Finding:** The only Android-specific architecture in the paper is a storage note about Termux UIDs. G5 makes Android the main differentiator and names what it must handle: Island/Insular work profiles (secondary Android users, typically user 10) and user-space ShizukuPlus. Neither appears anywhere in the paper. How CFEngine's agent runs on Android is also unsettled: the map keeps CFEngine there (R4), D45 makes only tendcf-agent Android-only, and the compiler does not yet offer an `android` platform. This needs a section, not a paragraph (P-§S-01, new §2.8).
**Evidence:** paper lines 423-427; `rg -n -i 'island|insular|shizukuplus'` over the paper gave no hits (Shizuku appears only as "a forked Shizuku" and "Shizuku"); digest-current-plan D6; Insular README, https://github.com/proletarius101/Insular.
**Proposed text:**

> On Android the agent is tendcf-agent, and it owns the JSONL capture and
> the SQLite index in its app-private storage. A device with a work profile
> (Island, Insular) is several Android users, each with its own apps and
> private storage. The agent records every profile's outcomes in one
> capture, and reaches the other profiles through ShizukuPlus's privileged
> process rather than by reading their files (§2.8). How CFEngine's agent
> runs on Android, as a native helper or behind a Termux reporter, is open
> (§2.4; the compiler does not yet offer an `android` platform).

**Merge:** replace the paragraph; needs the operator's ruling on how cf-agent runs on Android (map R4; `compiler/nix2cf/cli.py` --platform)
**Checked:** verified (rg over paper); not checked: ShizukuPlus's cross-user behaviour on a real device, and the clause "reaches the other profiles through ShizukuPlus's privileged process" (the ShizukuPlus README, https://github.com/thejaustin/ShizukuPlus, describes "a privileged process started with adb or root" and says nothing about work profiles); independently checked 2026-11-13: weakened, corrected (no D45/R4 conflict: `docs/architecture/architecture-DEFINITIVE-v3.md:105-115`)

### P-§2.4-02: "Any central or shared view is optional" against a required archive

**Target:** §2.4, at "Any central or shared view is optional and eventually consistent."
**Kind:** reword
**Goal:** G3, G8
**Weight:** improves
**Finding:** The archive on the Mac is part of G8 state 1, so it is not optional for the first milestone. It can still be non-authoritative and eventually consistent, which keeps the local-first argument intact.
**Evidence:** paper line 411-412; goal G8.1.
**Proposed text:**

> A log archive on a server device is part of the design (§2.5); it is
> eventually consistent and never authoritative. The device's own capture
> is the record.

**Merge:** replace that sentence
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### P-§2.5-01: The safety review G4 asks for is missing

**Target:** §2.5 "Releases carry a goal file; the device applies only an approved diff", paragraph beginning "Layered on the verifiable plan is a *semantic* layer"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The paper has a semantic briefing and an `accept | reject` slot. G4 adds a scan of each difference in several ways, AI among them, a confidence figure out of 100% with an explanation, graded highlighting of questionable entries, and CLI and TUI modes. None of this is in any document (difference 4). The paper's own §3.2 item 5 names the risk: a generated summary that cannot authorize can still mislead. The score is the strongest such summary. The design must keep it from becoming the authority by persuasion.
**Evidence:** paper lines 485-491, 1101-1121; goal G4; inventory §H (nothing for scoring).
**Proposed text:**

> Beside the briefing sits a **safety reading**. Each difference is scanned
> in several ways. Mechanical scanners check what the schema already knows:
> a privileged region touched, a domain's coverage withdrawn, a new
> listening port, a secret newly referenced, a removal, an interlock
> changed. Provenance counts who signed the release and how many trusted
> devices already applied it. An AI reviewer, the owner's choice of model,
> reads the difference with the Site Model behind it. The owner is shown
> one figure out of 100%, the reasons for it, each pointing at the entries
> that produced it, and the questionable entries highlighted more
> dramatically the less safe they look. Mechanical findings set a ceiling
> the AI reading can lower but never raise. The reading is offered on the
> command line and in a TUI. Like the briefing, it never authorizes: the
> owner's yes does, against the exact difference, and refusing is always
> one keystroke (§2.7).

**Merge:** needs the operator's ruling first (how the score is computed: the mechanical ceiling, provenance counting and never showing 100% in the proposed text are not in G4); then insert after the paragraph (and see P-§S-01 for the full section)
**Checked:** verified (no scoring in docs per goal difference 4; the ceiling rule is a proposal); independently checked 2026-11-13: confirmed

### P-§2.5-02: The owner's AI may be both author and advisor

**Target:** §2.5, at "The proposing side and the consenting side are different programs."
**Kind:** question
**Goal:** G1, G4, G6
**Weight:** blocks-goal
**Finding:** Under G1 the owner's AI writes the configuration and also warns when a request looks unwise. Under G4 an AI scans the difference. If one AI does both, the "different programs" separation and §1.1's compromised-authoring-agent limit collapse into one model checking its own output. The project's own review rule already forbids that for code ("No PR merges on a review by the model family that wrote the change"). The paper should say whether the scanning AI must differ from the authoring AI, and who enforces that.
**Evidence:** paper lines 505-506, 156-162; `AGENTS.md` standing rule 3 (cross-model review); goal G1, G4.
**Proposed text:**

> The owner's AI may well be the author of the change it is asked to
> review. We therefore require the AI reading of §2.5's safety review to
> come from a different model, or at least a fresh context with no memory
> of authoring it, and say which on the screen. A reading from the author's
> own model is shown as such and cannot lift the figure above the
> mechanical ceiling.

**Merge:** needs the operator's ruling first (whether a different-model reviewer is required, preferred or only disclosed); insert after that sentence once ruled
**Checked:** inferred; independently checked 2026-11-13: confirmed

### P-§2.5-03: "The correct cryptographic handshake" is undefined against the TUF text

**Target:** §2.5, paragraph beginning "The distinction we are drawing is between", at "Signing itself is an unremarkable TUF [26] subset sized for one operator"
**Kind:** question
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** The paper's model is a TUF-signed release from one site root, which says nothing about how a release travels. G3 says "updates from any other device that completes the correct cryptographic handshake". That could mean (a) any device may relay a release and the release's signature is the handshake, (b) a mutual device-key handshake on the channel, as CFEngine's own `cf-serverd` key trust does, or (c) both. Under (a), TUF's mirror model already fits: any peer is a mirror. (b) alone would make a device's key, not the site root, the authority. G8 state 1 needs the choice made.
**Evidence:** paper lines 473-483; goal G3, difference 5; inventory §H ("Pull / self-update | nothing"; "Signed release / TUF | prose only").
**Proposed text (for reading (c), pending ruling):**

> Signing is an unremarkable TUF [26] subset sized for one owner. TUF
> separates who signs from who serves, so any device may serve a release
> to any other, as a mirror. The handshake a device requires is two checks.
> The release verifies against the root this device enrolled. The peer
> carrying it authenticates with a device key this device lists. The first
> decides whether a change is acceptable; the second only decides who may
> talk to it.

**Merge:** needs the operator's ruling first (which of (a), (b), (c) "the correct cryptographic handshake" means)
**Checked:** inferred (TUF mirrors: general knowledge, not re-fetched); independently checked 2026-11-13: confirmed

### P-§2.6-01: The Nix illustration is not NixOS style

**Target:** §2.6 "Three worked examples", the `nix` block beginning "# site/services/edge-http.nix — the same caddy record via the Nix authoring"
**Kind:** correct
**Goal:** G2
**Weight:** misleads
**Finding:** The example *declares options* (`options.siteModel.services.caddy.description = mkOption {... default = ...}`) and puts the record's values in their defaults. NixOS users do not write configuration that way: tendcf would declare the options once, and a user's module *sets* them (`tendcf.services.caddy = {...};`). As shown, a Nix user would conclude that every service needs its own option declarations, the opposite of "existing configs carry over". It is the only Nix in the paper, so it sets the reader's picture of G2.
**Evidence:** paper lines 598-640; goal G2.
**Proposed text:**

> ```nix
> # site/services/edge-http.nix — the same caddy record as a NixOS-style
> # module. tendcf declares the options once (types, defaults, docs); a site
> # only sets them. ILLUSTRATIVE — the module frontend is unbuilt (§8).
> { ... }:
> {
>   tendcf.services.caddy = {
>     description = "Site reverse proxy and HTTPS terminator";
>     domain = "macos-launchd-services";
>     bundle = "edge-http";
>     platform = "macos";
>     runsAs = "djbclark";
>     command = [ "/opt/homebrew/bin/caddy" "run" "--config" "/etc/caddy/Caddyfile" ];
>     launchd = { label = "com.djbclark.caddy"; runAtLoad = true; keepAlive = true; };
>     # provides/requires are typed the same way regardless of frontend:
>     # local knowledge lives in the option, not in which language declared it.
>     provides = [ "service:caddy" "port:443" "port:80" ];
>     requires = [ "path:/etc/caddy/Caddyfile" "service:tailscaled" ];
>   };
> }
> ```
>
> The option declarations behind `tendcf.services.<name>` live once, in
> tendcf, where `mkOption`/`types.*` give each field its type and
> documentation. That is also where a NixOS-compatible name such as
> `services.caddy.enable` would be mapped, if §2.1's carry-over is taken
> that far.

**Merge:** replace the code block and the sentence before it ("but it shows what `caddy`'s record above would look like as typed options")
**Checked:** verified (read the block); option naming `tendcf.services` is a proposal; independently checked 2026-11-13: confirmed

### P-§2.6-02: Example C's "launchd-only" limit is stale

**Target:** §2.6, Example C, at "It is **launchd-only**: systemd, runit and Jobber are unwritten, so "supervisors are adapters" (§2.3) remains a claim about a design and not about running code."
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** The bundle has had a systemd branch since 2026-10-31, enforced on pastebin and run as root in CI on three Ubuntu VMs. runit is refused by name. "Supervisors are adapters" is now true of two adapters in the bundle, and of one in the compiler.
**Evidence:** inventory §A (policy: systemd branch, runit refused), §F (linux.yml VM matrix); paper line 1727-1728.
**Proposed text:**

> It covers **launchd and systemd**. runit is refused by name and Jobber is
> unwritten, and the compiler renders launchd services only, so "supervisors
> are adapters" (§2.3) holds for two adapters in the bundle and one in the
> compiler.

**Merge:** replace that sentence
**Checked:** verified (inventory; paper §8); independently checked 2026-11-13: confirmed

### P-§2.6-03: "The only place in this paper where a mechanism is demonstrated" is stale

**Target:** §2.6, at "That is a small result, and it is the only place in this paper where a mechanism is demonstrated rather than argued." (and §6.1, at "It is the only claim in this paper that has been demonstrated rather than argued.")
**Kind:** correct
**Goal:** G8
**Weight:** misleads
**Finding:** A root `cf-execd` on pastebin restored the enforced canary within three minutes of a manual stop on 2026-10-31. CI runs the systemd lifecycle as root on every push. Those are demonstrated mechanisms (convergence, tombstone-guarded teardown) and the paper does not report them. A Bcfg2 author will value an enforcement result more than an interlock skip.
**Evidence:** `docs/architecture/linux-targets.md:39` ("a root `cf-execd` (`tendcf-execd.service`) restored the canary within 3 minutes of a manual stop"); inventory §F.
**Proposed text:**

> That is a small result. It has one companion: on one Linux operator host,
> a root `cf-execd` running this bundle has enforced a canary service since
> 2026-10-31, and restored it within three minutes of a manual stop (§8).
> Everything else in this paper is argued, not demonstrated.

**Merge:** replace that sentence; make the matching change in §6.1
**Checked:** verified (linux-targets:39); independently checked 2026-11-13: confirmed

### P-§2.7-01: The peer-action example is ShizukuPlus; say so

**Target:** §2.7 "Peer actions: help without a global lock", at "Example from our last system: a device that cannot start its privileged helper itself; any healthy peer in its allowlist may do it over ADB"
**Kind:** reword
**Goal:** G3, G5
**Weight:** improves
**Finding:** The example is a Shizuku-family helper, which on a non-rooted phone must be restarted over ADB after reboot. Under G5 this is the central Android mechanism, not an anecdote from "our last system". Naming it also separates a peer *action* (help) from a peer *update* (G3's handshake). A reader could easily conflate the two.
**Evidence:** paper lines 890-893; ShizukuPlus README ("privileged process started with adb or root"), https://github.com/thejaustin/ShizukuPlus.
**Proposed text:**

> The example that matters most is Android's. Without root, ShizukuPlus's
> privileged process must be started over ADB, and a reboot stops it, which
> leaves the phone unable to converge anything that needs it. Any healthy
> peer in that phone's allowlist may restart it over wireless ADB. If every
> helper is down, **only that phone waits**. A peer action is help with an
> operation; it is not a peer update (§2.3), and it carries no
> configuration.

**Merge:** replace those sentences
**Checked:** not checked: the item rests on the ShizukuPlus README (via search snippet); it needs a test on a real device that a peer can restart ShizukuPlus's privileged process over wireless ADB after a reboot, and whether that needs on-device confirmation on current Android

### P-§2.8-01: The `managed` tier lets someone other than the owner waive see-and-refuse

**Target:** §2.8 "Per-device trust", table row "**Consent** | Do I also need a local yes? | `operator`: no. `consented`: yes (advisor key). `managed`: operator-chosen"
**Kind:** ruling-drift
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4: "Nothing changes a device except as an exact, mechanically checked difference that the device's owner can see and refuse." A `managed` device whose consent rule is "operator-chosen" lets a non-owner decide that the owner is not asked. Even `operator: no` means there is no per-change yes. That is fine if the owner chose a standing accept and can still see every difference and withdraw that choice. The table should say that, and say who may set it.
**Evidence:** paper lines 917-923; goal G4.
**Proposed text:**

> | **Consent** | Do I also need a local yes? | Every change is an exact difference the owner can see and refuse. `consented`: a yes per change (advisor key). `operator` and `managed`: the owner may set a standing accept, which only the owner can set or withdraw, and every applied difference stays visible |

**Merge:** needs the operator's ruling first (whether a standing accept satisfies G4's "can see and refuse"); replace the row once ruled
**Checked:** verified (read against G4); independently checked 2026-11-13: confirmed

### P-§2.8-02: The release axis should name the handshake, not only the TUF root

**Target:** §2.8, table row "**Release** | Whose signatures may change me? | Site TUF root enrolled at the first-run ceremony"
**Kind:** reword
**Goal:** G3
**Weight:** improves
**Finding:** This is the row G3 changes. It should point at the handshake decided in P-§2.5-03, and say that the carrier of a release is irrelevant to whether it is accepted.
**Evidence:** paper line 919; goal G3.
**Proposed text:**

> | **Release** | What may change me, and who may hand it to me? | A release that verifies against the root enrolled at first run, from any peer that completes the handshake (§2.5) |

**Merge:** replace the row after P-§2.5-03 is ruled
**Checked:** inferred

---

## §3 The design rule

### P-§3-01: "Adopting and testing" should separate the premise from the rule

**Target:** §3 "The design rule", at "a rule we are adopting and testing, not one we consider settled"
**Kind:** reword
**Goal:** G6
**Weight:** improves
**Finding:** The sentence is consistent with G6 only if the reader sees that the *rule* is under test and the *premise* is not. As written, a reader could take "testing" to cover machine authorship itself, which §9.2 and §9.9 then seem to confirm. One clause fixes it.
**Evidence:** paper lines 953-955; goal G6, difference 9.
**Proposed text:**

> The premise is fixed: most configuration here is machine-authored, and we
> do not set out to test that. The rule we derive from it is not fixed; it
> is one we are adopting and testing:

**Merge:** replace the paragraph's first two sentences
**Checked:** verified (read)

### P-§3.2-01: Item 3 critiques a warning the map no longer carries

**Target:** §3.2 "Nine concrete instances", item 3, at "carries, at its own top, an instruction telling any AI agent reading it not to modify the document without a human's explicit approval"
**Kind:** correct
**Goal:** —
**Weight:** misleads
**Finding:** The map's header now reads "It is freely editable: keep it current rather than proposing changes elsewhere." The protection was lifted on 2026-08-15. The item's central irony ("the rule caught a document failing to apply the rule to itself") no longer has an object.
**Evidence:** `docs/architecture/architecture-DEFINITIVE-v3.md:3-4`; digest-project-history C7 ("Protected documents. All made mutable 08-15").
**Proposed text:**

> **3. A document's warning about itself should be a check, not prose.**
> The architecture document once carried, at its own top, an instruction
> telling any AI agent not to modify it without a human's explicit
> approval, with nothing enforcing it. The project resolved that by lifting
> the protection rather than mechanising it. The general point stands: an
> instruction a reader must remember, with nothing checking it, is the
> shape §3's second clause warns about.

**Merge:** replace item 3 (or cut it with the rest of §3.2, P-§S-03)
**Checked:** verified (map:3-4); independently checked 2026-11-13: confirmed

### P-§3.2-02: Item 5 makes a literature claim with no citation

**Target:** §3.2, item 5, at "a broader body of work on grounding generated text in retrieved or cited source material, which finds that requiring a generated claim to point at the specific fact it summarizes measurably reduces unsupported claims"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** (c) Every other item that reports an outside finding carries a numbered reference; this one asserts a measured finding ("measurably reduces") with none. Under G4 it becomes the main justification for how the safety explanation is built, so it needs a source or a softer verb.
**Evidence:** paper lines 1112-1116.
**Proposed text:**

> which reports that requiring a generated claim to point at the specific
> fact it summarizes reduces unsupported claims relative to generating
> freely from the same facts [N].

**Merge:** replace that clause and add reference [N]; the sources reviewer should supply it
**Checked:** verified (no citation present); source not checked; independently checked 2026-11-13: weakened, corrected (item 3 has no citation either)

### P-§3.2-03: Item 4's percentages need checking against [13]

**Target:** §3.2, item 4, at "at roughly two-thirds of all technical errors; errors of simple omission are the second-largest, at roughly a quarter; syntax and structural errors ... are the smallest, at under two percent"
**Kind:** question
**Goal:** —
**Weight:** improves
**Finding:** (c) These three figures carry a design conclusion (invest in reference checks, not structure). They are attributed to [13] without a table or section number. A paper aimed at an expert reader should cite the table. The sources check has confirmed them (06 T34: [13] Table 6 gives 65.0%, 26.5% and 1.5%), so the item closes with the locator.
**Evidence:** paper lines 1083-1087; reference [13] arXiv:2512.14792, Table 6 (https://arxiv.org/html/2512.14792).
**Proposed text:**

> (... [13, Table 6])

**Merge:** insert the table locator after the figures; the check is done (06 T34)
**Checked:** verified by the sources check (06 T34, [13] Table 6: 65.0 / 26.5 / 1.5%); independently checked 2026-11-13: confirmed, resolved

---

## §4 Two places the rule shows up

### P-§4.2-01: Comprehensiveness on an owner's device: the owner's own change is not drift

**Target:** §4.2 "Comprehensiveness, default-on with a reasoned opt-out", at "AI-authored drift is exactly what extra-entry detection catches, so the safe default belongs on the detecting side."
**Kind:** add
**Goal:** G1, G5
**Weight:** improves
**Finding:** On a phone (G5's client) the owner installs apps and changes settings by hand all the time. Default-on comprehensiveness reports every such change as an extra entry. G1's freedom to control one's device as one sees fit means the owner's own change must have a first-class path: adopt it into the configuration (through their AI) or mark it theirs. Otherwise the tool punishes direct use, and the `not-yet-migrated` count never falls (§9.3).
**Evidence:** paper lines 1268-1273, 1798-1803; goal G1, G5.
**Proposed text:**

> On a device its owner uses by hand, most extra entries are not drift but
> the owner's own choices. For those the report is an offer: the owner, or
> their AI, can adopt the entry into the configuration as written, or mark
> the domain theirs. Either is one exact difference, seen and approved like
> any other. Extra-entry detection exists to catch what nobody chose, not to
> argue with what the owner did.

**Merge:** insert after that paragraph
**Checked:** inferred

---

## §5 Where this departs from Bcfg2

### P-§5.3-01: "No consumer for a central copy" is no longer true

**Target:** §5.3 "Local-first record, where the papers centralized statistics", at "the honest summary is that we currently have *no consumer* for a central copy"
**Kind:** ruling-drift
**Goal:** G3, G8
**Weight:** misleads
**Finding:** G8 state 1 requires logs archived on the Mac, and G3 names monitoring as a server service. Both consume a central copy. The paper's local-first argument survives (the archive is a service, not the record), but its admission that the Bcfg2 advice to build reporting early might be right is now partly answered in Bcfg2's favour: reporting arrives early. That advice is the 2008 booklet's deployment tip [4, §8.1], not LISA '05's; this item follows the sources check on that (06 P-§5.3-s10, T14). Desai will notice.
**Evidence:** paper lines 1371-1384; goal G3, G8.1; 06 T14 (booklet §8.1 "Set up the reporting system early").
**Proposed text:**

> We now have a consumer: the first milestone archives every device's logs
> on the Mac (G8.1), and the server role includes monitoring other devices
> (G3). That moves us toward the booklet's advice to set up reporting early
> [4, §8.1]. What we keep is the other
> half: the archive is fed from each device's own capture, is eventually
> consistent, and is never the record of truth.

**Merge:** replace from "the honest summary" to "not that one is unbuildable."; coordinate with 06 P-§5.3-s10, which corrects the attribution in the next sentence of §5.3
**Checked:** verified (read against G8); independently checked 2026-11-13: weakened, corrected

---

## §6 What we took from Bcfg2

### P-§6.4-01: "Dry-run the standing posture for ... the primary workstation" is neither what happened nor what G5 orders

**Target:** §6.4 "Deploy reporting early, and dry-run as the default posture", at "we make dry-run the standing posture for the first platform class brought under management: the primary workstation"
**Kind:** correct
**Goal:** G5, G8
**Weight:** misleads
**Finding:** The first platform actually brought under management was a Linux server, enforced, not dry-run. G5 puts macOS as a server first and Android as a client second. A Mac that serves logs is still the machine that is hard to reimage, so the LISA '05 practice applies to it. The paper should say where it applies now, and admit the Linux canary went to enforce after a two-day dry run.
**Evidence:** paper lines 1488-1493; `docs/architecture/linux-targets.md:39` (dry-run 10-29, enforced 10-31); goal G5.
**Proposed text:**

> we make dry-run the standing posture for the first Mac, which is both the
> first server and a machine that cannot easily be reimaged, and for the
> first phone. The one Linux host enforced so far went from a dry run on
> 2026-10-29 to enforcement on 2026-10-31 of a single canary service, which
> is the narrowest form of this practice.

**Merge:** replace that clause; merge with 06 P-§6.4-s13 into one edit of that sentence
**Checked:** verified (linux-targets:39); independently checked 2026-11-13: weakened, corrected

---

## §7 Building on CFEngine

### P-§7.3-01: The fork bullet and the channel bullet are stale

**Target:** §7.3 "What this does to the argument", bullets beginning "**The design currently depends on a fork.**" and "**The channel is open but slow.**"
**Kind:** correct
**Goal:** G7
**Weight:** misleads
**Finding:** "If none of them merge ... permanently rather than temporarily" and "Neither has merged anything yet" were written on 2026-08-18. Since then: upstream closed all twenty-six on 08-19 (as §7.1 says), the operator ruled on 08-22 that the fork is the destination, and core#6332 (CFE-4742) merged on 09-02. The section contradicts §7.1 and the project's own decision.
**Evidence:** paper lines 1638-1646 against 1544-1554; `docs/architecture/upstream-register.md:15-18` ("PR1 MERGED 2026-09-02 ... cfengine/core#6332"); inventory §E.
**Proposed text:**

> - **The design depends on a fork, by decision.** Our builds come from a
>   fork branch that merges every fix and the `--simulate-json` series. We
>   chose on 2026-08-22 to maintain that fork rather than wait on upstream,
>   which makes it a permanent maintenance liability, and one more reason
>   (G7) to keep CFEngine replaceable behind the goal file.
> - **The channel is narrow but not closed.** After the August closures, one
>   small pull request (core#6332, CFE-4742) was merged on 2026-09-02, and
>   on 2026-09-23 a maintainer invited `--simulate-json` back if split into
>   logical parts.

**Merge:** replace both bullets
**Checked:** verified (upstream-register:15-18; inventory; the 2026-09-23 invitation: `docs/handoffs/HANDOFF_standalone-3fd9_simulate-json-three-prs_2026-10-08_fab1.md:18-20`, larsewi on core#6332); independently checked 2026-11-13: weakened, corrected (dropped the unsupported "We send upstream only what the design cannot do without")

### P-§7-01: §7 is the paper's best-evidenced section but the wrong centre of gravity

**Target:** §7 "Building on CFEngine: what the substrate cost", whole section
**Kind:** move
**Goal:** G7
**Weight:** improves
**Finding:** At 185 lines, §7 is the paper's only measured result, and the conclusion calls it the transferable finding. Under G7 the substrate is an instrument. A paper about an adoptable, owner-controlled tool should not have a CFEngine bug report as its main result. Keep §7.2 (the self-inverse codec lesson) and §7.4 (who wrote the fixes, relevant under G6) in a condensed appendix, and leave a five-line summary in the body.
**Evidence:** paper lines 1524-1705, 1923-1931.
**Proposed text (body summary):**

> ### 7. The substrate, briefly
>
> Putting real weight on CFEngine's JSON data layer surfaced twenty-three
> defects, ten in that layer and three fatal before any promise runs. We
> now carry the fixes on a fork. The lesson that transfers is in Appendix
> B: a codec tested only against itself cannot see a fault its two halves
> share, and a design that routes traffic differently from the tool's own
> deployment is in effect a new test suite.

**Merge:** move §7.1-§7.5 to Appendix B and insert the summary in their place
**Checked:** verified (line counts by reading); independently checked 2026-11-13: weakened, corrected (185 lines, not 180)

---

## §8 Status and validation

### P-§8-01: Add status against the finish line

**Target:** §8 "Status and validation", new opening paragraph before "**Implemented.**"
**Kind:** add
**Goal:** G8
**Weight:** blocks-goal
**Finding:** No document states a finish line (difference 7), and §8 measures progress against Bcfg2's deployment numbers rather than against the project's own target. G8 gives a three-state ladder. Measured against state 1, almost nothing exists: no Mac or Android device runs tendcf, no handshake, no archive service, and no Nix module frontend.
**Evidence:** goal G8; inventory §G4 ("Android and Mac: nothing tendcf runs there"), §H (Pull, Push, Peer, Android agent: nothing).
**Proposed text:**

> **The finish line.** We will call this working in three steps. First, one
> of the operator's Macs and one of his Android devices converge from
> Nix-authored configuration, accept updates only after the handshake, and
> archive their logs on the Mac. Second, the operator's whole fleet runs on
> tendcf and the system it replaces is retired. Third, a person we have not
> helped installs it from the public documents with their own AI and keeps
> using it. Against the first step today: neither device runs tendcf; the
> compiler renders launchd services but has no Nix module frontend; the
> handshake, the update path, the archive service, the safety review and
> the Android agent are designs only.

**Merge:** insert at the start of §8
**Checked:** verified (inventory §G, §H); independently checked 2026-11-13: confirmed

### P-§8-02: "Nothing is deployed beyond that one operator-host canary" should say what that canary lacks

**Target:** §8, at "**Nothing is deployed** beyond that one operator-host canary."
**Kind:** reword
**Goal:** G4, G5
**Weight:** misleads
**Finding:** The canary is on Linux, G5's fourth platform. It was brought up with CMDB data "installed by hand", carrying fixture trust content, and no approved goal file is stored on any host. It therefore changes a device without the exact, owner-visible, refusable difference G4 requires. That is acceptable for an operator canary, and the paper should state it plainly. The sentence also omits that the fork is installed, unscheduled, on a NixOS host.
**Evidence:** digest-current-plan C1c, C2; inventory §G ("No approved goal file is stored on any host").
**Proposed text:**

> **Little is deployed.** On one Linux operator host a root `cf-execd`
> enforces one canary service. Its data was installed by hand from a
> schema-valid goal file with fixture trust keys, so it runs without the
> see-and-refuse difference this paper is about. On one NixOS host the
> CFEngine fork is installed and nothing is scheduled.

**Merge:** replace that sentence
**Checked:** verified (digests; not checked live); independently checked 2026-11-13: confirmed

### P-§8-03: The "not implemented" list omits what the goal added

**Target:** §8, paragraph beginning "**Not implemented, and this is still most of it:**"
**Kind:** add
**Goal:** G3, G4, G5
**Weight:** improves
**Finding:** The list predates G3-G5. It should name the safety review and its CLI/TUI, the handshake and peer update path, the log archive and monitoring services, and the Android agent's profile handling. The "Remaining Step 0 work" list refers to the August build order and should be checked against tracker #1 or dropped.
**Evidence:** paper lines 1755-1763; inventory §D (#1 last updated 10-09).
**Proposed text:**

> ... the peer-action runtime; the handshake and the peer update path; the
> log archive and monitoring services; the safety review, its scanners, and
> its command-line and TUI modes; and tendcf-agent on Android, including
> work-profile handling through ShizukuPlus.

**Merge:** insert into the list; delete "Remaining Step 0 work: ..." unless re-checked against tracker #1
**Checked:** verified (inventory)

---

## §9 Open questions

Disposition of the existing sixteen, under the goal:

| Q | Status under the goal | Action |
|---|---|---|
| 9.1 inference vs fixpoint | remains | keep |
| 9.2 argument or hypothesis | premise answered by G6; rule remains | reword (P-§9-01) |
| 9.3 `not-yet-migrated` grind | remains, sharper for a non-admin owner | keep; link P-§4.2-01 |
| 9.4 per-domain granularity | remains; Android profiles are natural domains | keep |
| 9.5 local-first | partly answered by G3/G8 (archive is a consumer) | reword (P-§9-02) |
| 9.6 global question | remains; monitoring service narrows it | keep, cite §2.5 |
| 9.7 spurious-edge provenance | remains | keep |
| 9.8 schema keeps up | remains | fix "8.3" to "9.3" |
| 9.9 premise wrong shape | premise answered by G6; "wrong surface" remains | reword (P-§9-01) |
| 9.10 is a diff consentable | G4 commits to a mechanism; whether it works remains | reword (P-§9-03) |
| 9.11 total-diff events | remains | keep |
| 9.12 refusal cost | remains; G9 gives refusal a future | keep, cite §11 |
| 9.13 baseline protection | remains; "Termux" is the wrong awkward case | reword (P-§9-04) |
| 9.14 policy tree in reviewed state | remains | keep |
| 9.15 device-local trust root | now a requirement (G3); buildability remains | reword (P-§9-05) |
| 9.16 confirming effect | remains | keep |

### P-§9-01: 9.2 and 9.9 question the premise G6 fixes

**Target:** §9 "Open questions", items "**9.2 Is the writing rule an argument or a hypothesis?**" and "**9.9 Is the whole premise the wrong shape?**"
**Kind:** reword
**Goal:** G6
**Weight:** misleads
**Finding:** 9.9's title and first sentence ("on the assumption that they are the primary authors") put the premise itself up for attack, which G6 rules out. Its real question, whether bounded context is the weakness worth hardening against, is legitimate and should stay. 9.2 is already about the rule; it needs only a clause. The sentence G6 directs (difference 9) is this one.
**Evidence:** paper lines 1791-1796, 1834-1841; goal G6.
**Proposed text (9.9):**

> **9.9 Have we hardened the right surface?** That AI agents write most of
> this configuration is the project's premise, not a question here. What is
> open is our account of their weakness. We assume it is bounded context.
> If it is instead plausible-looking output that type systems do not catch,
> the schemas guard the wrong place. §7.4 is one reason to take this
> seriously: none of the ten data-layer defects would have been caught by
> any schema at our layer. The safety review (§2.5) is our second line
> there.

**Merge:** replace 9.9; in 9.2, insert "The premise is fixed; the rule is not." after the title
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### P-§9-02: 9.5 is partly answered

**Target:** §9, item "**9.5 Is local-first the wrong call?**"
**Kind:** reword
**Goal:** G3, G8
**Weight:** improves
**Finding:** With a log archive in the first milestone, the question is no longer whether to have a central copy. It is whether the device or the archive is authoritative when they disagree, and whether an owner can refuse to export logs at all.
**Evidence:** paper lines 1810-1812; goal G8.1.
**Proposed text:**

> **9.5 Which copy wins?** The first milestone archives logs on a server
> device, so a central copy exists. We hold that the device's own capture
> is the record and the archive a service fed from it. Is that right when
> they disagree, and is exporting a device's logs itself a difference its
> owner must approve?

**Merge:** replace 9.5, as one edit with 06 P-§6.4-s11, which corrects the same item's "precisely the reasoning LISA '05 warns against" to the booklet [4, §8.1]; if the replacement names where the "report early" advice comes from, it carries that booklet attribution
**Checked:** inferred

### P-§9-03: 9.10 now has a proposed mechanism

**Target:** §9, item "**9.10 Is a diff something a person can actually consent to?**"
**Kind:** reword
**Goal:** G4
**Weight:** improves
**Finding:** G4 commits to a mechanism for making a large diff holdable: a scored reading with reasons and graded highlighting. The open question becomes whether that mechanism works, and whether a high score trains people to stop reading. That is 9.11's rubber-stamp worry moved one level up.
**Evidence:** paper lines 1843-1851; goal G4.
**Proposed text:**

> **9.10 Does the safety reading make a diff consentable, or replace
> reading it?** Our answer to "forty-one entries changed" is the safety
> review: a figure, its reasons, and the questionable entries highlighted
> (§2.5). If it works, a person reads the few entries that matter. If it
> works too well, a person reads the figure and nothing else, and a
> high-scoring malicious change is the cheapest attack left. The test is
> countable once real diffs exist: how often an owner opens an entry the
> reading did not highlight.

**Merge:** replace 9.10
**Checked:** inferred

### P-§9-04: 9.13's awkward case is Android profiles, not Termux

**Target:** §9, item 9.13, at "and Android under Termux is the awkward case."
**Kind:** reword
**Goal:** G5
**Weight:** improves
**Finding:** With tendcf-agent as the Android component and work profiles in scope, the baseline lives in app-private storage. The awkward case is protecting it from a process holding ShizukuPlus's shell-level privilege, which is the same process tendcf needs in order to act.
**Evidence:** paper lines 1871-1873; digest-current-plan B10 (D45).
**Proposed text:**

> and Android is the awkward case: the baseline sits in tendcf-agent's
> private storage, on a device where ShizukuPlus's privileged process, which
> tendcf itself relies on, can reach more than any one app should.

**Merge:** replace that clause
**Checked:** not checked: reasoning from G5 with no source; it needs a device test of what ShizukuPlus's privileged process can reach in another app's private storage (Shizuku's shell-uid scope is general knowledge, not tested)

### P-§9-05: 9.15 is a requirement now

**Target:** §9, item "**9.15 Can the consent gate be made to mean what it says?**"
**Kind:** ruling-drift
**Goal:** G3
**Weight:** misleads
**Finding:** G3's peer updates make a device-local trust root mandatory (P-§1.1-01). What remains open is how to build it on macOS and Android first, not whether to. As in P-§1.1-01, "mandatory" is an inference: G3/G4 imply only that the handshake's anchors and the consent policy sit beyond the release path's reach.
**Evidence:** paper lines 1883-1886; goal G3, G5.
**Proposed text:**

> **9.15 How is the device-local trust root built?** Every device must hold,
> out of the release path's reach, what a correct handshake is (§1.1,
> §2.5). How that is stored on a Mac (Keychain, a root-owned file, the
> Secure Enclave) and on a phone (Android Keystore inside tendcf-agent) is
> open, and the rest of the gate rests on it.

**Merge:** needs the operator's ruling first (whether a device-local trust root is a requirement of G3/G4 or one design among several); replace 9.15 once ruled
**Checked:** inferred (storage options are suggestions); independently checked 2026-11-13: weakened, corrected

### P-§9-06: New question from G3: what is the handshake, and who may originate an update?

**Target:** §9, new item after 9.16
**Kind:** add
**Goal:** G3
**Weight:** blocks-goal
**Finding:** "Any other device that completes the correct cryptographic handshake" leaves open whether any device may *originate* an update or only relay one, and what happens when a phone holding a deploy key is lost. These are the first design decisions G8 state 1 needs.
**Evidence:** goal G3, difference 5.
**Proposed text:**

> **9.17 What does a peer's handshake authorize?** If any device may carry a
> release, the signature decides and the carrier is irrelevant. If a device
> may also *originate* one, every device that can is a signer, and losing a
> phone is a key compromise. Which devices may originate, how a lost one is
> revoked by peers that never meet the owner's root, and whether a device
> may refuse a valid update from a peer it has never seen are open.

**Merge:** insert after 9.16
**Checked:** inferred; independently checked 2026-11-13: confirmed

### P-§9-07: New question from G4: what does "safety confidence out of 100%" mean?

**Target:** §9, new item
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** A percentage invites a probability reading ("97% safe"). Nothing is calibrated against, the scanners disagree in kind, and the AI component is non-deterministic. The paper needs to say what the number is, how it is combined, whether the same difference always gets the same figure, and what it may never be (100%).
**Evidence:** goal G4, difference 4.
**Proposed text:**

> **9.18 What is the confidence figure a measure of?** It is shown as a
> percentage, but nothing yet calibrates it. Which scanners contribute and
> how, whether one difference always gets the same figure when an AI is
> among them, and how an owner is kept from reading 95% as "safe" are
> open. Our provisional answers: mechanical findings cap it, it never
> shows 100%, and the reasons are shown before the figure.

**Merge:** needs the operator's ruling first (how the score is computed: the cap by mechanical findings and never showing 100% are not in G4); then insert as a new item
**Checked:** inferred; independently checked 2026-11-13: confirmed

### P-§9-08: New question from G2: what carries over?

**Target:** §9, new item
**Kind:** add
**Goal:** G2
**Weight:** improves
**Finding:** The question P-§2.1-02 and P-§2.2-03 defer to. Without a test corpus, "carries over" cannot be checked.
**Evidence:** goal G2.
**Proposed text:**

> **9.19 Which NixOS and nix-darwin configurations carry over, and how
> would we know?** The honest test is a corpus: real, public NixOS and
> nix-darwin configurations, compiled for a Mac and a phone, counting what
> carries over unchanged, what needs a rename, and what has no meaning off
> NixOS. We have not built the corpus or chosen how faithful carry-over must
> be (§2.1).

**Merge:** insert as a new item
**Checked:** inferred

### P-§9-09: New question from G5: one agent per phone, or one per profile?

**Target:** §9, new item
**Kind:** add
**Goal:** G5
**Weight:** improves
**Finding:** A phone with a work profile is several Android users. The agent could be one install in the main profile acting on others through ShizukuPlus, or one per profile, each with its own baseline and its own owner yes. The second matches G4 better if a profile can have a different owner (an employer). The first is simpler.
**Evidence:** Insular: work profile as secondary user (https://filepathgeek.com/posts/insular-data-location/); goal G5.
**Proposed text:**

> **9.20 Is a work profile a device?** An Island or Insular profile is a
> separate Android user with its own apps and storage. tendcf can manage it
> from one agent in the main profile, through ShizukuPlus, or treat each
> profile as its own device with its own goal file, baseline and approval.
> The first is simpler. The second is right if a profile's owner can
> differ from the phone's. We have not decided.

**Merge:** insert as a new item
**Checked:** not checked: reasoning from G5 with no source to check (the Android multi-user model comes from a search snippet); it needs a device test of Island/Insular profiles with ShizukuPlus

### P-§9-10: New question from G9: can a non-technical person keep a fork?

**Target:** §9, new item
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** G9 is "later", but it constrains choices made now: patch formats, how a conflict is presented, and whether a refused change can become a kept patch (P-§1.1-03). Stating the question now stops early decisions from closing it off.
**Evidence:** goal G9; `overlay/` (6 patches, weekly drift check; inventory §E).
**Proposed text:**

> **9.21 Can someone who has never merged anything keep a fork?** We
> intend, later, to let a person maintain their own changes to a project,
> or to a plugin of one, as patches over its releases, extending the
> pattern this project already uses for its CFEngine fork (§11). What a
> conflict looks like to such a person, whether their AI may resolve it,
> and whether each resolution is itself a difference they approve are
> open.

**Merge:** insert as a new item
**Checked:** inferred

---

## §10 Conclusion

### P-§10-01: Full replacement conclusion

**Target:** §10 "Conclusion", all three paragraphs, from "We have described a configuration management architecture" to "than after a fleet is running on it."
**Kind:** reword
**Goal:** G1, G2, G3, G4, G6, G7, G8
**Weight:** blocks-goal
**Finding:** The conclusion repeats the withdrawn "signed plan the executor may not exceed". It calls the CFEngine defect count the paper's transferable finding, which G7 makes a side result. It says "the schemas are days old and nothing is deployed": they date from 2026-08-15 and are at version 5, and a canary is enforced. And it does not state the aim or the finish line.
**Evidence:** paper lines 1903-1935; inventory §A (schema_version 5); goal G1-G8.
**Proposed text:**

> We have described a configuration management system whose aim is that
> people control their own devices, on the premise that an AI, usually the
> owner's own, writes most of the configuration. Three commitments carry
> the design. Configuration is written in Nix with NixOS-style options and
> evaluates to plain data, so the people likely to adopt it first bring
> the language and module style they already use. Every device is self-sufficient and accepts only
> updates that complete its handshake, so there is no control node to fail
> or to trust. And nothing changes a device except as an exact difference
> its owner can see and refuse, with a safety reading that shows its
> reasons, so the owner decides with the evidence in front of them rather
> than on trust in whoever proposed the change.
>
> The local-knowledge rule of §3 is not new. It is a
> configuration-management instance of local reasoning about global
> properties [9], argued independently for AI-generated code by Tratt
> [10]. What we claim is the composition, and one uncommon choice inside
> it: compiling into an existing engine's native data layer rather than
> shipping a new client, with that engine treated as an instrument we can
> replace. The one measured result so far concerns that choice: routing
> heavy traffic through a path the engine's own deployment uses lightly
> found twenty-three defects in the engine, ten of them in that path
> (Appendix B).
>
> The first test is concrete: one Mac and one Android phone converging
> from Nix-authored configuration, accepting updates only after the
> handshake, with their logs archived on the Mac. The last is that someone
> we have not helped installs tendcf from the public documents with their
> own AI and keeps using it. Neither has happened. We would rather be told
> where the design is wrong now, while it is mostly on paper, than after a
> fleet depends on it.

**Merge:** replace §10
**Checked:** verified (stale claims against inventory); independently checked 2026-11-13: confirmed (proposed text corrected: the defect count matches paper lines 49-50 and 1924-1925)

---

## Whole-paper structure

### P-§S-01: Proposed outline for the paper under the goal

**Target:** the whole paper, section order §1-§10
**Kind:** move
**Goal:** G1, G2, G3, G4, G5, G9
**Weight:** blocks-goal
**Finding:** The paper is organised as a dialogue with Bcfg2 about an AI-authorship design rule, with a CFEngine experience report as its result. The goal's distinctive parts have no home: Nix authoring (G2), peer updates (G3), the safety review (G4), Android (G5) and branch management (G9). Keep the Bcfg2 dialogue: it is what the first reader, Desai, can judge best. Add the five sections, move process advice and the substrate report to appendices, and put status against the finish line.
**Evidence:** paper section list (lines 60-1901); goal G1-G9.
**Proposed text (outline):**

> 0. Abstract (P-Abs-03)
> 1. Motivation: owner control, who adopts, AI or code, platform order (P-§1-01, P-§1-02)
>    1.1 Scope and limits (P-§1.1-01 to -04)
> 2. Architecture
>    2.1 The Site Model and its layers (old 2.1, minus the Nix paragraph)
>    2.2 **Authoring in Nix** (new). NixOS-style options declared once by
>        tendcf, set by sites; JSON/YAML beneath and writable by hand; what
>        carries over (P-§2.1-02); flakes as shared inputs (P-§2.1-03); the
>        evaluation boundary: where Nix runs, and that no device evaluates.
>    2.3 The compiler (old 2.2)
>    2.4 **Every device self-sufficient** (old 2.3 rewritten, P-§2.3-01).
>        The handshake (P-§2.5-03), relay and origination, push as request.
>    2.5 **Servers are services** (new). Log archive and monitoring on the
>        first Mac; fed from device capture; never authoritative; owner
>        approves log export.
>    2.6 Releases, goal files and the difference the owner sees (old 2.5)
>    2.7 **The safety review** (new, P-§2.5-01). Scanners (mechanical,
>        provenance, AI from a different model), the figure and its
>        ceiling, reasons citing entries, graded highlighting, CLI for
>        scripts and AIs, TUI on a borrowed scaffold, refusal always one
>        step.
>    2.8 **Android** (new). What is managed per profile (apps, enabled
>        state, permissions and app ops, settings, default apps, always-on
>        VPN); ShizukuPlus as the user-space privilege, and its loss on
>        reboot; Island/Insular profiles (P-§9-09); tendcf-agent's capture
>        and baseline; where, if anywhere, CFEngine runs; the owner's
>        review on the phone itself.
>    2.9 Worked examples (old 2.6, Nix block fixed per P-§2.6-01, plus an
>        Example D: one app installed in a work profile, from Nix to the
>        difference the owner sees, scored)
>    2.10 Peer actions (old 2.7, P-§2.7-01); 2.11 Per-device trust (old
>        2.8); 2.12 Token discovery (old 2.9)
> 3. The design rule (old 3 and 3.1; premise fixed, P-§3-01)
> 4. Two places the rule shows up (old 4, plus P-§4.2-01)
> 5. Where this departs from Bcfg2 (old 5)
> 6. What we took from Bcfg2 (old 6)
> 7. The substrate, briefly (P-§7-01)
> 8. Status against the finish line (old 8, P-§8-01 to -03)
> 9. Open questions (old 9 reworded, plus 9.17-9.21)
> 10. Conclusion (P-§10-01)
> 11. **Later: branch management for everyone** (new, G9). Refusal becomes a
>     kept patch; the overlay pattern (`overlay/`, drift checked weekly)
>     generalised to any project or plugin; the person's AI presents
>     conflicts as differences to approve; no merging, rebasing or
>     compiling asked of them.
> Appendix A. Nine instances of the rule (old 3.2)
> Appendix B. Building on CFEngine (old 7.1-7.5)

**Merge:** needs the operator's ruling first (accept the outline, or name sections to keep as they are)
**Checked:** inferred; independently checked 2026-11-13: confirmed

### P-§S-02: Two documents, not one

**Target:** the whole paper, header paragraph "The vetted current-state description is ... Where this paper and the guide disagree on the current design, the guide wins."
**Kind:** question
**Goal:** G1, G8
**Weight:** improves
**Finding:** The paper serves two audiences: Desai, who will judge the Bcfg2 dialogue and the consent design, and "the public". G8 state 3 adds a third: a person installing from the public docs with their own AI. That person needs a short "what it does for you" document, not a 2,000-line paper. Naming the paper's audience as Desai and expert readers, and pointing the public at an adopter's introduction, stops the paper being bent to serve both.
**Evidence:** paper lines 11-16, 53-56; digest-project-history B1.7 ("he is the primary target"); goal G8.3.
**Proposed text:**

> This paper is written for readers who build configuration management
> systems, and first for the author of Bcfg2. A person deciding whether to
> use tendcf should start with `<adopter introduction>`, which this paper
> does not replace.

**Merge:** needs the operator's ruling first (whether an adopter introduction is wanted, and where it lives)
**Checked:** inferred

### P-§S-03: Move §3.2 to an appendix

**Target:** §3.2 "Nine concrete instances", whole subsection
**Kind:** move
**Goal:** G1
**Weight:** improves
**Finding:** §3.2 is 180 lines of repository practice: lookup CLIs, schema-example pairing, a document's self-warning, YAML round-trips, AGENTS.md files. It reads as an internal memo inside the paper's argument and delays the architecture for the reader. Items 5 (grounded explanations) and 6 (constrained decoding) bear on the safety review and should be cited from §2.7. The rest belongs in Appendix A.
**Evidence:** paper lines 1023-1201.
**Proposed text:**

> §3.1's rule has concrete consequences for the repository as well as the
> design; Appendix A lists nine, each checked against its source. Two bear
> on the safety review (§2.7): an explanation must cite the entries it
> summarises, and where a grammar can constrain what an AI writes, it
> should.

**Merge:** move §3.2 to Appendix A and insert this paragraph in its place
**Checked:** verified (read); independently checked 2026-11-13: confirmed

---

## Nits

| ID | Where (quoted) | Fix |
|---|---|---|
| P-N-01 | §2.2 "That is the §3.2-item-1 problem in its natural habitat" | §3.2 item 1 is the targeted lookup; the silent-scope bug matches §3's "violate confidently and plausibly". Cite §3. |
| P-N-02 | §2.6 "do not exist yet (§6.5, §8)" and the Nix block's "the frontend is unbuilt (§6.5)" | §6.5 is "What did not transfer". Cite §8. |
| P-N-03 | §9.8 "That is question 8.3 wearing a different hat." | Should be 9.3. |
| P-N-04 | References [2], [3], [5], [7], [8], [29] | Never cited by number in the body (LISA '05/'06 are named only). Cite them where named, or drop [5], [7], [8]. Verified by `rg -F "[n]"` over lines < 1940. |
| P-N-05 | §2.1 "tool forks (optional) — sudo-secretspec, Shizuku" | "ShizukuPlus (our fork, ShizukuTendCF)". |
| P-N-06 | §1 "Android devices reached through Termux, a forked Shizuku, and a local agent" | Superseded by P-§1-01; if kept, "ShizukuPlus". |
| P-N-07 | §4.1 "The site's existing Android deploy chain hand-orders" | "Our predecessor system's Android deploy chain"; Ansible was removed 2026-08-13. |
| P-N-08 | §5.4 "all fourteen service-owning roles across the site ... single-role plays" | Say these were the predecessor's Ansible roles. |
| P-N-09 | §6.5 "Termux's `$PREFIX`-relative layout against Linux and macOS absolutes" | Add Android's per-user paths (`/data/user/<n>/`) as the same `altsrc` problem. |
| P-N-10 | §7.5 "who responds to every defect by fixing it upstream" | "by fixing it in the substrate". |
| P-N-11 | §2.6 "**Three worked examples**" then "on two concrete Site Model records" | Fine as written; if Example D (P-§S-01) is added, make it "Four". |
| P-N-12 | §8 Bcfg2 figures "four months, one person, roughly three FTE ... a third and a half of an FTE ... about two hundred people", and §6.4 "about four months" | (c) For the sources reviewer: give the LISA '05 section for each figure. |

Also for the sources reviewer, not itemised: §2.2 "3.7.3 back-ported `def.json` parsing into the core agent"; §2.2 cdktf "deprecated ... December 2025 [21]"; §3.1 Tratt [10] "July 2026"; §3.2 item 9 "[17] ... inference cost rose by more than a fifth"; §6.1's quoted Bcfg2 Actions sentence [4, §A.2.1]. I did not check any of them.

---

## Ideas and risks

1. **The figure becomes the authority.** A well-calibrated 96% will be read as "safe", and the cheapest attack left on G4 is a malicious change that scores high. Show the reasons before the figure, never show 100%, and let mechanical findings cap what the AI can award. Measure how often owners open un-highlighted entries.

2. **Use the project's own review rule on owners' devices.** The repo already forbids a model family from reviewing its own work. Applying the same rule to the safety reading (a different model from the author's, or a disclosed fallback) is a real differentiator, and it costs a configuration option, not a new system.

3. **Android rests on a third-party fork.** ShizukuPlus is one person's fork of a fork (thejaustin over thedjchi over RikkaApps), and ShizukuTendCF forks it again, last touched 2026-10-22. Android releases have repeatedly narrowed wireless debugging. The paper should name this dependency as the platform's largest risk, and the Android section should say what degrades when the privileged process cannot be started.

4. **"Carries over" needs a number.** A corpus of public NixOS and nix-darwin configs compiled for a Mac target, with the share that carries over unchanged, would turn G2 from a slogan into a measurement. It is also the cheapest result to show Nix-sharing sysadmins, G1's first adopters.

5. **TUF already permits relay.** TUF separates signers from mirrors, so "any device may carry an update" costs little if the handshake is the release signature. A phone can carry a release to a sleeping Mac. Much of G3 may be cheaper than the documents' open transport questions suggest.

6. **The log archive is the first thing that leaves a device.** On a household fleet, an owner's phone logs arriving on someone else's Mac is the very kind of change G4 is about. Make log export an entry in the goal file, seen and refused like any other.

7. **Profiles may be the cleanest unit of ownership.** If an Island/Insular profile is a device in the goal-file sense, one phone can host a personal profile under its owner and a work profile under someone else, each with its own see-and-refuse. That would be a strong, demonstrable Android story, and it fits the existing per-device trust table without new concepts.

8. **Refusal and G9 are one feature.** A refused change that the owner wants to keep their own version of is a branch. Designing the refusal record now so it can later become a kept patch costs little and avoids a second mechanism.

9. **The paper can absorb effort the milestone needs.** Docs hold 70,142 added lines against 5,301 for the compiler (inventory §B), and two prior reviews warned of "a paper that had a repo". Rewriting this paper before G8 state 1 exists repeats that pattern. Take the factual corrections now and defer the restructure (P-§S-01) until the Mac and the phone converge.

10. **Desai is a test reader for G4, not only for Bcfg2.** He spent LISA '05 learning that administrator trust is about information presentation. A one-page mock of the CLI review screen for a real difference, with score and highlighting, would draw sharper comment from him than any further prose about consent.

Last search run: exempt: a document review; the two searches above (ShizukuPlus, Insular) were the only facts where current web state could change an item, and they were run before writing.

---

## Withdrawn after checking

None. The independent check refuted no item in this response.
