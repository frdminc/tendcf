# Response: `docs/paper/tendcf-architecture-guide.md` against the goal of 2026-11-13

Target: `docs/paper/tendcf-architecture-guide.md` (1,676 lines, read in full)

Base commit: eefea3c

How this was produced: one reviewing agent (Claude Opus), then an independent checking agent that tried to refute each finding; nothing was executed unless an item says so.

Item counts by Weight after corrections: 45 full items and 10 table nits; blocks-goal 12, misleads 9, improves 21, nit 13 (3 full, 10 in the table). Checking: 32 items checked (25 confirmed, 7 weakened and corrected, 0 withdrawn); the other 13 full items and the nit table were not sampled and stand as written.

Measured against `docs/review-2026-11-13/00-goal-definition.md` G1–G9 and its nine differences (cited as "diff N"). Item format per `docs/review-2026-11-13/README.md`. All anchors are guide `file:line` at `eefea3c` unless named.

Sources consulted: firecrawl_search for ShizukuPlus (found https://github.com/thejaustin/ShizukuPlus), Insular/Island (https://f-droid.org/packages/com.oasisfeng.island.fdroid/, https://github.com/proletarius101/Insular), nix-darwin launchd options (https://nix-darwin.github.io/nix-darwin/manual/, https://mynixos.com/nix-darwin/option/launchd.agents.%3Cname%3E.serviceConfig), Python TUI frameworks (https://www.michaelblaess.de/en/blog/tui-vergleich/).

---

## Front matter

### G-§0-01: The goal, not the guide, says what the design is for

**Target:** front matter, at the sentence beginning "Where any other living document disagrees"
**Kind:** add
**Goal:** G1–G9
**Weight:** blocks-goal
**Finding:** The guide makes itself the winner on every conflict over the current design. It has no higher reference that says what the design is *for*, so a design choice can only be checked against other design choices. The agreed goal should sit above it: the guide wins over other design documents, and the goal wins over the guide.
**Evidence:** guide:8-16; `docs/review-2026-11-13/00-goal-definition.md:1-7`.
**Proposed text:**

> What the system is for is fixed by the goal definition
> ([`00-goal-definition.md`](../review-2026-11-13/00-goal-definition.md),
> agreed 2026-11-13, G1–G9). Where this guide's design conflicts with that
> goal, the guide is wrong and is amended. Below the goal, the order is as
> follows.

**Merge:** insert before "Where any other living document disagrees" (and move the goal file to a permanent path, e.g. `docs/GOAL.md`, first: needs the operator's ruling on where it lives)
**Checked:** verified (read both files); independently checked 2026-11-13: confirmed

### G-§0-02: "Nothing described here is deployed" undercounts the live state

**Target:** front matter, at "**Nothing described here is deployed**, apart from a canary service on one operator host (§4)"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** The sentence names the canary but not what runs it, and leaves two things out. pastebin runs a scheduled root `cf-execd` over a projection installed with `tendcf-install.sh install --data`, and the interlock path there has a documented fail-open. get.sipb.cloud has the fork installed as a NixOS module, with nothing scheduled. The operator's NixOS host repos have consent CI. Under G4 a reader needs to know that a root agent changes a host today with no device-side diff.
**Evidence:** `docs/architecture/tendcf-validate-proposal-2026-11-03.md:1017-1026` ("fail-open in the live design ... applies to pastebin today"); `CLAUDE.md` ("pastebin (root install, canary enforced), get.sipb.cloud (module installed, nothing scheduled)"); inventory report §G.
**Proposed text:**

> **Almost nothing described here is deployed.** One operator Linux host
> (pastebin) runs the fork as root under a scheduled `cf-execd` and enforces
> one canary service, from a projection installed by hand: no device there
> computes a diff or holds an approved baseline, and the interlock path has a
> known fail-open (§16.C). A second host (get.sipb.cloud) has the fork
> installed and nothing scheduled. No Mac or Android device runs any of it.

**Merge:** replace that sentence
**Checked:** verified (read validate proposal §13 and CLAUDE.md); live hosts not contacted; independently checked 2026-11-13: weakened, corrected

---

## §1 What this is

### G-§1-01: Replace §1 with the agreed goal

**Target:** §1 "What this is", whole section
**Kind:** correct
**Goal:** G1, G2, G3, G4, G5, G6, G8, G9
**Weight:** blocks-goal
**Finding:** §1 describes a fleet-keeping design for the operator's mixed fleet. It has no adoption aim, names an ordinary Linux distribution as a goal and reaches Android only through Termux (no ShizukuPlus, no Island/Insular), makes Nix one of two equal languages (diff 2), and has no finish line (diff 7). Its "more than one trusted person can act" is the claim §17 says the signing model cannot meet (guide:1257-1261; also the 2026-08-15 skeptical review, per the review-record digest A8). Below is a full replacement in the guide's voice. It drops the multi-operator claim and narrows "no central server" to what G3 says.
**Evidence:** guide:45-67; goal G1–G9.
**Proposed text:**

> ## 1. What this is
>
> `tendcf` is free software that gives people control of their own
> computers, phones and tablets, as they see fit. It is a configuration
> management system meant to be adopted by people other than its author.
>
> A person uses it through an AI or directly at the code level, and can
> switch between the two at any moment. Through an AI, they say what they
> want; the AI writes it as configuration, and explains or warns when a
> request looks unwise. The first adopters are expected to be sysadmins who
> already share configurations in [Nix](https://nixos.org/). The long-run
> user has no admin skill at all.
>
> That AI agents write the configuration is the premise, not a hypothesis
> this project tests. The design's job is to make that safe.
>
> - **Authoring.** Configuration is written in the real Nix language with
>   NixOS-style options, so existing NixOS and nix-darwin configuration
>   carries over (§3). Plain YAML/JSON sits beneath it as the data Nix
>   evaluates to, and can be written by hand. Nix runs where configuration
>   is written; on a managed device it runs only where it is already that
>   host's configuration system (NixOS, nix-darwin), or as the owner's
>   authoring tool (§4).
> - **Shape.** Every device converges on its own. There is no control node.
>   A device accepts an update from any other device that completes the
>   correct cryptographic handshake (§5, §7). A "server" is only a device
>   that provides services to others, such as receiving and archiving logs
>   or monitoring; a "client" is a device that uses them. Neither word
>   changes the architecture.
> - **Safety.** Nothing changes a device except as an exact, mechanically
>   checked difference its owner can see and refuse (§7). Each difference is
>   also scanned for likely safety in several ways, AI among them, and the
>   owner is shown a confidence out of 100%, why that figure was chosen, and
>   the questionable parts highlighted more dramatically the less safe they
>   look, at the command line or in a TUI (§8).
> - **Platforms, in order:** macOS as server, Android as client, macOS as
>   client, Linux as server, Linux as client. Android is the differentiator:
>   comprehensive configuration management that works with Island/Insular
>   work profiles and with user-space ShizukuPlus (§6, §13).
>
> **Finish line.** Three states, in order. (1) One Mac and one Android device
> converge from Nix-authored configuration, accept updates only after the
> handshake, and archive their logs on the Mac. (2) The author's whole fleet
> runs on tendcf and the configuration stack it replaces is retired. (3)
> Someone the author has not helped installs it from the public
> documentation with their own AI, and keeps using it. §18 is ordered by
> these states.
>
> **Later.** Free-software branch management built on the same patch
> patterns (§18, `overlay/`), so that a person with no technical skill can
> keep a fork of a project, or of a plugin to one, without knowing about
> merging, rebasing or compiling.
>
> CFEngine, the CFEngine fork, the Site Model and the compiler are the
> instruments chosen to reach this. They are open to challenge, and none of
> them changes without the operator's ruling.

**Merge:** replace §1 (the "previous configuration stack" paragraph at guide:39-41 stays in the front matter; G8 state 2 names `~/ops` in private docs only, so the public text says "the configuration stack it replaces")
**Checked:** verified (read §1 and the goal); independently checked 2026-11-13: weakened, corrected

---

## §2 The picture

### G-§2-01: The picture has no server services and no review surface

**Target:** §2 "The picture", the diagram
**Kind:** add
**Goal:** G2, G3, G4
**Weight:** improves
**Finding:** The diagram ends at "JSONL log / SQLite index". It shows no log archive or monitoring service (G3, diff 6) and no place where the owner sees, scores and refuses a diff (G4, diff 4). It lists the frontend as "YAML, or Nix", the opposite of G2's order.
**Evidence:** guide:73-113.
**Proposed text:**

> ```
>   tendcf compile         compiler, in tendcf: frontend (Nix modules via
>   (tool)                 the nix2cf plugin; or YAML/JSON, the data Nix
>                          evaluates to) → merge → conflict check →
>                          per-host goal file.
>   ...
>           ▼
>   Device-side review     the device computes the diff from its approved
>   (CLI or TUI)           baseline; scanners score it 0–100 with reasons;
>                          the owner sees it, highlighted, and accepts or
>                          refuses (§7, §8)
>   ...
>           ▼
>   JSONL log (capture)    append-only; the durable record, on the device
>   SQLite (index)         rebuildable from JSONL
>           ┆ best-effort copy
>           ▼
>   Server services        any device holding the role: log archive,
>   (a role, not a tier)   monitoring. Never the record of truth (§6).
> ```

**Merge:** replace the frontend box, and insert the two new boxes in place
**Checked:** verified (read diagram)

---

## §3 Facts live in layers

### G-§3-01: Nix first, YAML beneath, not "two equal authoring frontends"

**Target:** §3, at "The Site Model has two equal authoring frontends"
**Kind:** ruling-drift
**Goal:** G2
**Weight:** blocks-goal
**Finding:** The paragraph states D12 as amended 2026-10-29: two equal frontends, and "Nobody adopting the project has to know Nix". G2 makes Nix the authoring language and YAML/JSON the data layer beneath it, which can still be written by hand. The compiler today has only an `eval-nix` wrapper over `nix-instantiate`, and `site.nix` is a plain attribute set, not a module system. So the guide's "not built yet" stands, but the frontend it should promise first is the Nix one.
**Evidence:** guide:189-198; `compiler/nix2cf/cli.py:150-171,203`; `compiler/examples/site/site.nix`; inventory report §A ("the Nix module frontend of D12 ... is not built").
**Proposed text:**

> Site Model configuration is written in Nix, with the module system
> (`mkOption`, `mkIf`, `mkDefault`) and NixOS-style option names. It
> evaluates to plain YAML/JSON, the data everything else consumes and the
> form the schemas check. That data form is public and stable, so it can
> also be written by hand, by a person or a tool that does not use Nix.
> A Nix-authored site renders for a Mac or a Debian box that has no Nix at
> all; and a host that already runs NixOS or nix-darwin keeps its
> configuration verbatim, tendcf adding only distribution, consent and
> reporting around it. The Nix module frontend, which will carry the name
> `nix2cf` (§4), is not built yet: today `nix2cf eval-nix` evaluates a
> plain Nix attribute set to the same JSON, and the fixtures are YAML.

**Merge:** replace the paragraph; needs the operator's ruling to amend D12 in the map at the same time (the map's §0.2 and D12 say "equal")
**Checked:** verified (read cli.py and the guide); independently checked 2026-11-13: confirmed

### G-§3-02: "Configs carry over": say which options, and borrow nix-darwin's names

**Target:** §3, same paragraph (follows G-§3-01)
**Kind:** question
**Goal:** G2
**Weight:** improves
**Finding:** G2 says existing NixOS and nix-darwin configuration "carries over". For a host that keeps NixOS or nix-darwin this is passthrough. For a non-Nix host it is open how much carries: a NixOS option such as `services.caddy.enable` means whatever the NixOS module implements, and tendcf would have to reimplement it. A cheap, honest first scope is the supervisor-level options, which map almost one to one onto the service record: nix-darwin's `launchd.daemons.<name>.serviceConfig` and NixOS's `systemd.services.<name>`. Higher-level `services.*` modules would need a ruling.
**Evidence:** guide:189-198; https://nix-darwin.github.io/nix-darwin/manual/ and https://mynixos.com/nix-darwin/option/launchd.agents.%3Cname%3E.serviceConfig ("Each attribute in this set specifies an option for a key in the plist").
**Proposed text:**

> What carries over from an existing NixOS or nix-darwin configuration to a
> host without Nix is, first, its supervisor-level service declarations:
> tendcf's Nix options for services use the names nix-darwin
> (`launchd.daemons.<name>`) and NixOS (`systemd.services.<name>`) already
> use, so those blocks move with no rewrite. Higher-level modules
> (`services.<name>.enable`) carry over only where tendcf supplies an
> implementation; an option it does not implement is a compile error that
> names it, never a silent no-op.

**Merge:** needs the operator's ruling first (scope of "carry over")
**Checked:** verified (nix-darwin option via search results); NixOS option set not checked

---

## §4 A compiler turns facts into CFEngine data

### G-§4-01: Cut the third-party plugin entry points until someone asks

**Target:** §4 "Name and home", at "Frontends and importers are found through Python entry points, so a third party can ship one as an ordinary package"
**Kind:** cut
**Goal:** G2, G8
**Weight:** improves
**Finding:** Entry-point discovery, out-of-tree plugins, and importers from other tools (Ansible, Salt per plugin-layout) serve an ecosystem that does not exist. G2 names one frontend (Nix) with data beneath it. None of G8's three states needs a third-party frontend. The guide's own next paragraph says out-of-tree plugins cannot be pinned yet, so the release loads only in-tree ones anyway.
**Evidence:** guide:234-253; `docs/architecture/plugin-layout.md` (D46), via the plan-docs digest A3, E2; issue #47 (inventory D).
**Proposed text:**

> Frontends, supervisor renderers and one-shot importers are plugins, and
> all of them live in tree. Plugins run only at compile time, never on a
> device. Discovery of out-of-tree plugins (Python entry points) is deferred
> until a user needs one and out-of-tree plugins can be pinned.

**Merge:** replace "Frontends, supervisor renderers and one-shot importers ... never on a device."; needs the operator's ruling (amends D46)
**Checked:** verified (read §4); plugin-layout.md not re-read; independently checked 2026-11-13: confirmed

### G-§4-02: The Mac is both the authoring machine and a managed device

**Target:** §4, at "**Where it runs:** operator machine or CI."
**Kind:** add
**Goal:** G2, G5, G8
**Weight:** improves
**Finding:** At G8 state 1 one Mac holds server roles, is managed, and is very likely where configuration is written. So it is both an authoring machine (Nix installed to evaluate) and a managed device (where §4 says Nix runs only as the host's configuration system). The text should say that Nix-as-authoring-tool on a managed Mac is allowed and is not passthrough. It should also say that the compile step on that Mac must not hold the release signing key. Checked on one of the operator's Macs: no `nix`, no nix-darwin, and Homebrew's upstream CFEngine 3.29.0, not the fork.
**Evidence:** guide:321-324, 248-252; `command -v nix` printed nothing; `/run/current-system` absent; `/opt/homebrew/bin/cf-agent --version` → `CFEngine Core 3.29.0`.
**Proposed text:**

> A device may also be where configuration is written: the Mac that holds
> server roles is usually the author's own machine. Nix installed there to
> evaluate configuration is an authoring tool. It is not that Mac's
> configuration system, so the Mac is a managed, non-Nix host, not a
> passthrough one. The compile step on such a machine still holds no
> signing key (above).

**Merge:** insert after "...(NixOS, nix-darwin)."
**Checked:** verified on this Mac (commands above); whether this is the Mac the operator means for state 1 is not checked; independently checked 2026-11-13: confirmed

---

## §5 Every device runs its own agent

### G-§5-01: Updates come from any peer that completes the handshake, not "synced via git"

**Target:** §5, at "reads policy that arrived as part of the ordinary signed-release path, synced via git"
**Kind:** ruling-drift
**Goal:** G3
**Weight:** blocks-goal
**Finding:** G3 says a device accepts updates from *any other device* that completes the correct cryptographic handshake (diff 5). The guide names git as the sync channel and keeps push for "a host that currently holds a deploy role". TUF-style signing already makes the carrier irrelevant to authenticity, so any peer can relay. That is what G3 needs, but the guide never says it. "Handshake" is ambiguous: it could mean release-signature verification, peer mutual authentication, or both. That decides whether a stranger's device can relay, so it needs a ruling.
**Evidence:** guide:330-338; goal G3 and ruling 6b.
**Proposed text:**

> Each computer runs CFEngine and converges on the last release it
> approved. A release reaches it from any other device: whichever peer has
> it can hand it over, and the device accepts it only after the
> cryptographic handshake [what the handshake covers is open: checking the
> release's signatures against the device's enrolled root (§7),
> authenticating the sending device against its peer allowlist (§14), or
> both — operator's ruling]. The carrier, whether a
> peer, a git remote or a file on a USB stick, adds no trust. There is no
> dedicated central policy host, no SSH requirement, and no requirement to
> push.

**Merge:** replace the first paragraph of §5; needs the operator's ruling first: what the handshake authenticates (the release, the sender, or both)
**Checked:** verified (read §5, §7, §14); independently checked 2026-11-13: confirmed

### G-§5-02: "Its own `cf-serverd`" is true of neither live host, and may be the handshake

**Target:** §5, at "Each computer runs CFEngine, including its own `cf-serverd`"
**Kind:** question
**Goal:** G3, G7
**Weight:** misleads
**Finding:** The installer on pastebin installs and schedules `cf-execd` only. It does not mention `cf-serverd`. If cf-serverd stays in the design, it is the natural peer-to-peer carrier for G3: CFEngine's own protocol already does a key-based mutual-authentication handshake, through `cf-key` and `ppkeys`. That would cover the transport half of the handshake, with TUF signatures as the content half. Whether to use it is a G7 instrument ruling.
**Evidence:** `rg -n "serverd" deploy/linux/tendcf-install.sh` → no hits; guide:330.
**Proposed text:**

> Each computer runs CFEngine. A device that relays releases to peers runs
> `cf-serverd` [whether the handshake includes peer authentication is open,
> operator's ruling; if it does, `cf-serverd`'s key-authenticated
> connection would be its transport half and the release's signatures (§7)
> its content half, neither substituting for the other]. (Today pastebin
> runs `cf-execd` only, and get.sipb.cloud schedules nothing.)

**Merge:** needs the operator's ruling first (G7: is cf-serverd the peer transport; and what the handshake covers, G-§5-01)
**Checked:** verified (grep of the installer); independently checked 2026-11-13: weakened, corrected

### G-§5-03: Trim the supervisor list to what the platform order needs

**Target:** §5, at "[Jobber](https://dshearer.github.io/jobber/), OpenRC / s6 / dinit when a real host needs one"
**Kind:** cut
**Goal:** G5
**Weight:** nit
**Finding:** G5 needs launchd (macOS), runit through termux-services (Android), and systemd (Linux, which already exists). Jobber, OpenRC, s6 and dinit have no host in any G8 state. The guide already hedges them with "when a real host needs one". Dropping them from §2, §3 and §5 shrinks the claims that §4 has to label "still a design claim".
**Evidence:** guide:106, 170-172, 355-358, 276-280.
**Proposed text:**

> [systemd](https://systemd.io/), launchd, and
> [runit](http://smarden.org/runit/) via
> [termux-services](https://github.com/termux/termux-services) on Android.
> Another supervisor is added when a real host needs one.

**Merge:** replace the list in §5, and the same list in §2 and §3 "Services"/"Unit writers"
**Checked:** verified (read)

---

## §6 Each device keeps its own record

### G-§6-01: The log archive is a server service; the device stays the record

**Target:** §6, at "A path to a fleet-wide view already exists and costs nothing new to stand up"
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** G8 state 1 requires logs archived on the Mac, and G3 names log archiving as the defining server service (diff 6). The guide has only a best-effort push into an observability stack and no archive role. Nothing in the guide conflicts with an archive, as long as it stays a copy. The guide should say that, name the role, and say how a mostly offline Android device feeds it.
**Evidence:** guide:409-417; goal G3, G8.1.
**Proposed text:**

> **Log archive is a server service.** A device holding the `log-archive`
> role receives other devices' JSONL capture and keeps it. Each device ships
> its own lines when it can reach a holder, resumes from the last line the
> archive acknowledged, and keeps its local capture until then, so an
> archive that is asleep or unreachable costs delay, never history. The
> archive is a copy: the device's own capture stays the record of truth,
> and a question that needs a real yes or no is still asked of the device.
> Who may write into an archive is the archive host's peer allowlist (§14),
> and each line carries the release and the device key that produced it.

**Merge:** insert before "A path to a fleet-wide view"
**Checked:** inferred (design text; nothing in the repo ships logs: inventory §A, no "jsonl" hits in code); independently checked 2026-11-13: confirmed

### G-§6-02: Monitoring is a server service that reports "unknown", not "down"

**Target:** §6, after G-§6-01
**Kind:** add
**Goal:** G3
**Weight:** improves
**Finding:** G3 names monitoring of other machines as the second server service. The guide's rule that unreachable devices are "unknown, not a stale aggregate" already fits a monitor, but it is written only for one-off fleet queries. For phones, which are routinely offline, a monitor that reports "down" would be wrong most of the time.
**Evidence:** guide:409-414; goal G3.
**Proposed text:**

> **Monitoring is the other server service.** A device holding the
> `monitor` role shows, per device: last contact, the release it last
> reported converged, its extra-entry and `not-yet-migrated` counts, and
> any refusal outstanding. A device not heard from is shown as unknown since
> a time, never as down or as converged.

**Merge:** insert after G-§6-01's paragraph
**Checked:** inferred

### G-§6-03: Android section omits Island/Insular and ShizukuPlus, the differentiator

**Target:** §6, at "**Android:** Termux (`com.termux`) and tendcf-agent are different UIDs."
**Kind:** add
**Goal:** G5
**Weight:** blocks-goal
**Finding:** G5 calls Android with Island/Insular work profiles and user-space ShizukuPlus the main differentiator. The guide and the architecture docs never mention Island, Insular or work profiles (searched). A work profile is a separate Android user, so the guide's UID reasoning applies once per profile: Termux, CFEngine and the agent may exist twice, and "the app list on this device" is two domains. The tool fork the repo has (`frdminc/ShizukuTendCF`) is a fork of ShizukuPlus. The guide still says "Shizuku".
**Evidence:** `rg -n "Island|Insular|work profile" docs/architecture/*.md` → no hits; guide:88-89, 396-402; https://github.com/thejaustin/ShizukuPlus; https://f-droid.org/packages/com.oasisfeng.island.fdroid/ ("Insular is a FLOSS fork of Island"); inventory §C (ShizukuTendCF "a fork of ShizukuPlus").
**Proposed text:**

> **Work profiles.** Android with [Island](https://island.oasisfeng.com/)
> or its free fork [Insular](https://github.com/proletarius101/Insular)
> runs a second Android user, the work profile, beside the personal one.
> Each profile is its own set of UIDs and its own app list, so each is its
> own set of domains in the Site Model (`android-apps@personal`,
> `android-apps@work`), and anything the agent does across the boundary goes
> through the profile owner's APIs, never by reading the other profile's
> storage. Privileged operations go through
> [ShizukuPlus](https://github.com/thejaustin/ShizukuPlus) running in user
> space (our fork, `frdminc/ShizukuTendCF`); where it cannot start itself,
> a peer starts it (§13).

**Merge:** insert after the Android paragraph; the profile-and-domain naming needs the operator's ruling
**Checked:** verified (grep; URLs from search; island.oasisfeng.com URL not fetched); independently checked 2026-11-13: confirmed

---

## §7 Changes arrive as signed plans

### G-§7-01: Add the safety-scoring layer, advisory and owner-side

**Target:** §7, after the paragraph beginning "On top of the verifiable diff sits a *semantic* layer"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4's confidence out of 100, the explanation, and the graded highlighting are absent from every document (diff 4). The guide already has the right slot: an advisory layer above the diff that "never authorizes". The new layer should follow the same rules. It should also be computed on the owner's side, against the diff the device computed. A score computed by the proposer is the same-party problem §17 names for the briefing. One consequence follows from §7's own "Emergency vs consent" rule: a score may tighten (refuse automatically below an owner-set floor) but may never loosen (100% never skips the owner's look).
**Evidence:** guide:562-573, 568-582, 1231-1246; goal G4.
**Proposed text:**

> **Every diff is scanned for likely safety, and the owner sees the
> result.** Several scanners read the device-computed diff: fixed rules
> (a privileged region touched, a removal, a new command or listening
> port, a secret name newly bound, a `--simulate-json` effect outside the
> diff), and one or more AI reviewers chosen by the owner. They produce one
> **safety confidence out of 100%**, an explanation of why that figure and
> not another, and a weight per entry that sets how dramatically it is
> highlighted. Like the briefing, the score **never authorizes**. It can
> only tighten: an owner may set a floor below which a diff is refused
> without asking, but no score, however high, applies a diff the owner has
> not been shown. A fixed rule's finding caps the score; an AI reviewer can
> lower the score, never raise it past a rule. The scan runs on the owner's
> side, against the diff the device computed, because a score the proposer
> computes is a claim the device cannot check.

**Merge:** insert after the semantic-layer paragraph; the cap/lower-only rule and the owner-set auto-refuse floor need the operator's ruling
**Checked:** inferred (design); verified that no document describes scoring (goal diff 4; grep for "TUI" in docs found only the goal file and deprecated tooling notes); independently checked 2026-11-13: confirmed

### G-§7-02: "Operator: no local yes" conflicts with "the owner can see and refuse"

**Target:** §7, at "where the device's tier requires a local yes (§14)"; also §4 "(An operator host applies without a local yes, so there the pull request's preview diff is the only human check.)" and the §14 table row "Consent"
**Kind:** ruling-drift
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 says *nothing* changes a device except as a difference its owner can see and refuse. The guide exempts operator-tier hosts, which are every device in G8 states 1 and 2, and lets the proposer's PR preview stand in for the device-computed diff. That preview is computed from the proposer's idea of the baseline, not the device's (§7's own seven-releases-behind argument). Either the operator tier also sees the device-computed diff (possibly once, on the Mac, for all his devices), or G4 has an operator exception. That is a ruling.
**Evidence:** guide:245-246, 444-450, 846; goal G4.
**Proposed text:**

> Every device shows its owner the difference it computed itself, and
> applies nothing the owner refused. Tiers differ only in *where* and *how*
> that is done: on an `operator` device the owner may accept, from one
> place, the diffs every one of his devices computed, and the device checks
> that the acceptance names its own diff; on a `consented` device the yes is
> local, signed by the enrolled advisor key and bound to a nonce the device
> issued.

**Merge:** needs the operator's ruling first (does G4 admit an operator-tier exception); then replace the §7 clause, the §4 parenthesis, and the §14 "Consent" row
**Checked:** verified (read the three places); independently checked 2026-11-13: confirmed

### G-§7-03: `--simulate-json` is on the fork today, and is a scanner input

**Target:** §7, at "Both are offered and neither has merged, so today this remains a manual check."
**Kind:** correct
**Goal:** G4, G7
**Weight:** misleads
**Finding:** "Offered and not merged" describes upstream. The operator ruled on 2026-08-22 that the fork is the destination, and Linux CI builds the full fork, `--simulate-json` series included. So the feature is available in the build tendcf uses. Under G4 it becomes one of the "several ways" a diff is scanned: effects the run would make that the diff does not describe.
**Evidence:** guide:584-592; plan-docs digest B3 (`upstream-overlay.md:50-56`; `linux-targets.md:23-27`); inventory §E ("`tendcf-integration` is fork master plus every fix branch plus the `--simulate-json` series").
**Proposed text:**

> Both are in the fork tendcf builds (§19) and neither is upstream. Nothing
> calls them yet; when something does, a simulated change set that reaches
> beyond the approved diff is one of the safety scanners' findings (below).

**Merge:** replace that sentence
**Checked:** verified from the digests' citations; fork branch not inspected; independently checked 2026-11-13: confirmed

---

## §8 The person's own AI

### G-§8-01: The owner is usually also the proposer

**Target:** §8, at "We never run their model, see their prompt, or see the conversation. We offer a change and accept a signed yes/no."
**Kind:** reword
**Goal:** G1, G4
**Weight:** misleads
**Finding:** §8 assumes two parties: "we" propose, "they" consent. G1 puts the person in charge of their own devices, working through their own AI or the code. In G8 states 1 and 3 the owner proposes changes to their own devices. In that case the AI that writes the change and the AI that warns are both the owner's, and the person to protect against is mostly the owner's own mistaken or manipulated agent. The two-party case (a household member's device) still exists, as the `consented` tier.
**Evidence:** guide:596-624, 835-849; goal G1, ruling 1.
**Proposed text:**

> Usually the person who owns a device is also the person changing it.
> They say what they want, to their AI or in the code; their AI writes the
> configuration, and explains or warns when a request looks unwise. The
> device then shows them the exact difference, scored (§7), and applies it
> only if they accept. When someone else proposes the change, to a device
> on the `consented` tier, the shape is the same, and we still never run
> their model, see their prompt, or see the conversation: we offer a change
> and accept a signed yes/no, the same shape as a Kubernetes admission
> webhook.

**Merge:** replace the first paragraph of §8
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### G-§8-02: The review surface: command line and TUI

**Target:** §8, at "None of this surface is built yet (§18)."
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 requires both a command-line mode and a TUI mode, with the TUI built on a scaffold borrowed from another project. The guide describes no surface at all. Since the compiler and the projector are Python, a Python TUI framework would keep one language. [Textual](https://textual.textualize.io/) is the obvious Python candidate and Ratatui the Rust one. Which project to borrow from is the operator's call. Highlighting "more dramatically" must not rely on colour alone.
**Evidence:** guide:624; goal G4; https://www.michaelblaess.de/en/blog/tui-vergleich/ (Ratatui, Textual, Terminal.Gui compared).
**Proposed text:**

> The owner reviews a diff in one of two modes, which show the same thing:
> a command-line mode that prints the scored diff and takes `accept` or
> `refuse`, for scripts, SSH and an AI driving it; and a TUI, built on a
> scaffold borrowed from [named project], for reading a large diff with
> the questionable entries highlighted. Highlighting escalates in more than
> colour (weight, markers, ordering the least safe entries first, and
> requiring a keypress per entry below a threshold), so it survives a
> monochrome terminal and colour-blindness. None of this surface is built
> yet (§18).

**Merge:** replace "None of this surface is built yet (§18)."; the scaffold needs the operator's ruling
**Checked:** not checked (which scaffold); Textual URL not fetched; independently checked 2026-11-13: confirmed

### G-§8-03: Personal branches are where G9 starts

**Target:** §8, at "Personal branch: theirs, applied under their consent; never auto-merges into anyone else's trust domain. Upstream-heal is a suggestion their agent evaluates."
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** G9 (diff 8) asks for branch management built on the platform's existing patch patterns. The repo already has one: `overlay/` with `bin/overlay.py`, which keeps patches against a pinned upstream with lint, drift and retirement checks. That is "keep a fork without merging" in mechanical form, and the CFEngine fork is its first user. The guide never connects personal branches to it.
**Evidence:** guide:620-622, 1333-1338; inventory §E (overlay: 6 patches, weekly drift check).
**Proposed text:**

> A personal branch is kept the way this project keeps its own CFEngine
> changes (`overlay/`, §18): as a set of named patches against a pinned
> upstream, each checked for drift when upstream moves and retired when
> upstream absorbs it. Later (§18, after the finish line) the same pattern
> becomes a tool a person with no technical skill can use, through their
> AI, to keep a fork of a project or of a plugin to one.

**Merge:** insert after "Upstream-heal is a suggestion their agent evaluates."
**Checked:** verified (read §18 bullet and inventory); independently checked 2026-11-13: confirmed

---

## §9 The writing rule

### G-§9-01: The premise is fixed; the writing rule is a hypothesis about serving it

**Target:** §9, at "The rule is a working hypothesis, not a law. §20 asks what would count against it."
**Kind:** reword
**Goal:** G6
**Weight:** improves
**Finding:** Under G6 AI authorship is the premise, and §9 should say so before it says what remains open. What stays a hypothesis is the *rule*: that local-knowledge designs are how to make AI authorship safe. That distinction is consistent with G6 and keeps §20 Q1 and Q2 legitimate.
**Evidence:** guide:630, 671-672; goal G6.
**Proposed text:**

> That AI agents write the configuration is the premise of the project, not
> something it sets out to test. The writing rule is a working hypothesis
> about how to make that premise safe, not a law; §20 asks what would count
> against it, and a counter-example changes the rule, not the premise.

**Merge:** replace those two sentences
**Checked:** verified (read)

---

## §10 Ordering without a shared to-do list

### G-§10-01: Take inference off the path to the finish line

**Target:** §10, at "The primary authoring mechanism is `provides` / `requires`"
**Kind:** cut
**Goal:** G8
**Weight:** improves
**Finding:** The guide itself doubts inference (§10's three ways it may fail; §20 Q1 and Q7), and the compiler marks it "NOT implemented". State 1 has a handful of services on two devices. Retry-until-stable plus explicit `depends_on` is enough, and `provides`/`requires` can stay as data that the conflict check and lookup use. Deferring inference removes a stage, the two-platform gate and its edge-origin machinery from every G8 state.
**Evidence:** guide:689-693, 701-723, 1533-1536, 1553-1554; `compiler/nix2cf/compile.py:11-22` (inventory §A: inference "NOT implemented").
**Proposed text:**

> Retry-until-stable is the substrate, and explicit `depends_on` wins
> where it exists. Records still state what they `provide` and `require`,
> because the conflict check and the lookup (§15) read them, but the
> compiler does not derive ordering edges from them until a real site shows
> retry-until-stable is not enough. Inference is demand-driven (§18).

**Merge:** replace "This design uses all three ... seen the rest of the system."; needs the operator's ruling (G7: compiler scope)
**Checked:** verified (read §10, inventory); independently checked 2026-11-13: confirmed

---

## §13 Peer actions

### G-§13-01: Starting ShizukuPlus over ADB is on the path to state 1

**Target:** §13, at "a device that cannot start its privileged helper itself; any healthy peer in its allowlist may do it over ADB"
**Kind:** add
**Goal:** G5, G8
**Weight:** improves
**Finding:** The guide's own example is the Android client's helper. Under G5 and G8 state 1 that example stops being an illustration and becomes a requirement: the Mac is the healthy peer, and ShizukuPlus is the helper. Non-root Shizuku-family helpers have to be started over ADB or wireless debugging after a reboot. The fork adds headless start/stop/status broadcasts and boot retry, which narrows the cases a peer must cover. The peer-action runtime is "nothing" in code today, so it belongs in the state-1 build order, not in "10+".
**Evidence:** guide:809-821; inventory §C (ShizukuTendCF features), §H ("Peer actions | nothing"); Shizuku's need for ADB after reboot is inferred from https://github.com/thejaustin/ShizukuPlus ("a privileged process started with adb or root"), not fetched in full.
**Proposed text:**

> This is the first peer action tendcf will run. On an Android device
> without root, the privileged helper (ShizukuPlus, our fork) is started
> over ADB or wireless debugging, and after a reboot it may not be able to
> start itself; the device declares `start-helper` as a peer action, and the
> Mac holding the `helper` role does it. If no peer is reachable, only that
> device waits, and it reports why.

**Merge:** insert after the first paragraph of §13
**Checked:** inferred (Shizuku start mechanics not verified against its docs); independently checked 2026-11-13: confirmed

---

## §14 Per-device trust

### G-§14-01: Separate "who may relay" from "who may sign"

**Target:** §14, the table, after the "Release" row
**Kind:** add
**Goal:** G3
**Weight:** improves
**Finding:** G3's "any other device" makes the carrier of a release a separate question from its author. The table has "Release: whose signatures may change me" and "Peer: who may act on me" but no row for who may hand over a release or receive logs. Without one, a reader can take "Peer: nobody unless listed" to mean that only listed peers may relay, which contradicts G3. Follows G-§5-01.
**Evidence:** guide:843-849.
**Proposed text:**

> | **Relay** | Who may hand me a release, or take my logs? | Release: [any device, if the handshake checks the release and not the carrier; only listed devices, if it also authenticates the sender: open, operator's ruling (G-§5-01)]. Logs: holders of the `log-archive` role on my allowlist |

**Merge:** needs the operator's ruling first (what the handshake covers, G-§5-01); then insert after the "Release" row
**Checked:** verified (read); independently checked 2026-11-13: confirmed

---

## §16 Three walkthroughs

### G-§16-01: "The compiler's render stage does not exist yet" is false since `buildfile`

**Target:** §16 intro, at "the compiler's render stage does not exist yet, so nothing in those two except the YAML was produced mechanically"
**Kind:** correct
**Goal:** G2
**Weight:** misleads
**Finding:** §4 and §18 say `buildfile` renders a goal file (launchd services, JCS bytes), and the projector produces `host_specific.json` from it. So the guide contradicts itself. What is still hand-authored in A is the edge list (no inference) and the `preview_*` nesting. In B, the CFEngine sketch is hand-authored, since the real bundle is generic.
**Evidence:** guide:891-895 vs guide:303-305, 1342-1347; inventory §A (`render_goal_file` compile.py L463).
**Proposed text:**

> In **A** and **B** the outputs are hand-authored. Some of their shapes are
> now emitted by code: the compiler renders the goal file,
> `bin/projector.py` its projection, and the generic bundle the launchd
> plist. But nothing derives ordering edges (§10), and B's per-bundle
> promise sketch is illustrative: the generic bundle, not per-bundle
> CFEngine text, enforces interlocks (§16.C).

**Merge:** replace that sentence
**Checked:** verified (read guide and inventory); independently checked 2026-11-13: weakened, corrected

### G-§16-02: §16.C says "launchd-only"; the bundle has had systemd since 2026-10-31

**Target:** §16.C, at "It is **launchd-only**, and since 2026-10-29 it says so instead of pretending otherwise"
**Kind:** correct
**Goal:** G5
**Weight:** misleads
**Finding:** §4 and §18 report the systemd branch (2026-10-31), and the bundle's first line reads "launchd on darwin, systemd on Linux". §16.C still calls the bundle launchd-only. The flavour guard now refuses runit and NixOS-shaped hosts.
**Evidence:** guide:1163-1167 vs guide:273-280, 1329-1332; `policy/tendcf_services.cf:1,48-50`.
**Proposed text:**

> It actuates **launchd on darwin and systemd on Linux only**, and says so
> instead of pretending otherwise: an entry of any other flavour (runit
> today), or a host whose `/etc/systemd/system` is a Nix store symlink, is
> refused and reported by name (the flavour guard).

**Merge:** replace that sentence
**Checked:** verified (grep of the bundle); independently checked 2026-11-13: confirmed

### G-§16-03: The interlock section omits the known container-drop fail-open

**Target:** §16.C, at "dry-run stays fail-closed because a check that never ran defines nothing"
**Kind:** add
**Goal:** G4
**Weight:** misleads
**Finding:** §16.C presents the interlock as fail-closed. The validate proposal records a fail-open that applies to pastebin today: if the CMDB loader installs `tendcf_service` but drops `tendcf_interlock`, every service runs ungated. Two open PRs address it (#41, the fail-closed loader on the fork; #42, a policy cross-check). Under G4 this belongs in the one section that claims a demonstrated safety mechanism.
**Evidence:** `docs/architecture/tendcf-validate-proposal-2026-11-03.md:1017-1030`; inventory §D (#41, #42 open).
**Proposed text:**

> One path is still open, and it fails open: if CFEngine's loader installs
> the services container but drops the interlock container, the bundle sees
> no interlock and runs every service ungated. No known input does this
> today. Two fixes are open: a fail-closed loader in the fork
> ([#41](https://github.com/frdminc/tendcf/pull/41)) and a policy check
> that refuses to act when the loaded data differs from the file
> ([#42](https://github.com/frdminc/tendcf/pull/42)).

**Merge:** insert after "...defines nothing."
**Checked:** verified (read proposal §13); PR state from the inventory, not re-queried; independently checked 2026-11-13: confirmed

### G-§16-04: Show walkthrough A's input in Nix

**Target:** §16.A, the YAML block beginning "- name: caddy"
**Kind:** add
**Goal:** G2
**Weight:** improves
**Finding:** Under G2 the reader should see the authoring language first and the YAML as what it evaluates to. A short Nix module for `caddy`, shown beside the existing YAML as its evaluation, makes the G2 claim concrete. Here it is a target shape, labelled as such, because the module frontend is unbuilt.
**Evidence:** guide:905-941.
**Proposed text:**

> ```nix
> # ILLUSTRATIVE — the Nix module frontend is not built (§3)
> { ... }: {
>   tendcf.services.caddy = {
>     bundle = "edge-http";
>     runsAs = "djbclark";
>     command = [ "/opt/homebrew/bin/caddy" "run" "--config" "/etc/caddy/Caddyfile" ];
>     launchd = { label = "com.djbclark.caddy"; runAtLoad = true; keepAlive = true; };
>     provides = [ "port:443" "port:80" ];
>     requires = [ "path:/etc/caddy/Caddyfile" "service:tailscaled" ];
>   };
> }
> ```
>
> It evaluates to the YAML below, which is also what a person writes who
> does not use Nix.

**Merge:** insert before the YAML block; the option names depend on G-§3-02
**Checked:** not checked (not evaluated; illustrative)

---

## §17 Where a different design is a better fit

### G-§17-01: "The part the implementer map's §0 calls the point"

**Target:** §17 intro, at "the part the implementer map's §0 calls the point"
**Kind:** ruling-drift
**Goal:** G1, G4
**Weight:** misleads
**Finding:** Diff 3: the map's §0.3 says "The trust/consent layer is the point". G1 makes adoption the aim, and G4 makes see-and-refuse the safety mechanism serving it. The sentence should point at the goal, and the map's §0.3 should change too (see the M-series response).
**Evidence:** guide:1189-1195; map:37-39.
**Proposed text:**

> The rest bound the see-and-refuse layer — the part with no prior art,
> the safety mechanism the goal (G4) rests adoption on, and the part with
> the most to lose.

**Merge:** replace that clause; the map §0.3 change needs the operator's ruling
**Checked:** verified (read both); independently checked 2026-11-13: confirmed

### G-§17-02: The consent-gate limit mostly dissolves when the owner is the proposer

**Target:** §17, bullet beginning "**The consent gate does not yet mean what §8 says it means"
**Kind:** reword
**Goal:** G1, G4
**Weight:** improves
**Finding:** The limit is that every control is authored by the party it constrains. On a device whose owner is also the proposer (G1, G8 states 1 and 3), that party *is* the owner. The control's job is then to protect the owner from their own agent, and an owner-authored trust policy is correct. The limit still holds in full for the `consented` tier. Say which case it binds, so the limit is not read as fatal to the main use.
**Evidence:** guide:1231-1246; goal G1.
**Proposed text:**

> **On a device the proposer does not own, the consent gate does not yet
> mean what §8 says it means.** (On a device whose owner writes its
> configuration, the usual case, the party the controls constrain is the
> owner's own agent, and owner-authored controls are what is wanted; the
> limit there is the next-but-two, the compromised authoring agent.) ...

**Merge:** replace the bullet's first sentence; the rest of the bullet stands
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### G-§17-03: The one-operator signing limit is answered by "one owner per site"

**Target:** §17, bullet beginning "**The signing model is sized for one operator and §1 promises more than one.**"
**Kind:** reword
**Goal:** G1, G3
**Weight:** improves
**Finding:** With §1 replaced (G-§1-01), §1 no longer promises several operators. Each adopter is the one owner of their own site, which is the shape the signing model fits. The limit remains for a household where two people sign for one site.
**Evidence:** guide:1257-1261, 47-52.
**Proposed text:**

> - **The signing model is sized for one owner per site.** That fits the
>   goal: each adopter runs their own site. The limit is the second person
>   who must sign releases for the *same* site without the first's key —
>   a household sharing devices — which needs threshold signing,
>   delegation, per-role scoping and co-signer revocation. That is a
>   different trust architecture, not triggered by anything §1 promises.

**Merge:** replace the bullet
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### G-§17-04: The compromised authoring agent is now the main threat, and G4 is a partial answer

**Target:** §17, bullet beginning "**The threat model outgrows this design at the compromised authoring agent.**"
**Kind:** reword
**Goal:** G4, G6
**Weight:** improves
**Finding:** Under G6, AI authorship is certain, so a manipulated authoring agent is the ordinary threat, not an outer limit. G4's independent scanners (fixed rules plus an AI the owner chose, different from the one that wrote the change) are a step toward the "two-party authoring review" this bullet says the design lacks. The bullet should credit that and keep what still stands: a scanner shares the reviewer's blind spots, and a score is not a proof.
**Evidence:** guide:1269-1276.
**Proposed text:**

> ... is inside every control described here. The safety scan (§7) is the
> design's partial answer: rules that do not read prose, and an AI reviewer
> the owner chose, separate from the one that wrote the change. It narrows
> the gap and does not close it — two models can share a blind spot, and a
> crafted diff can be written to read as safe. Past that point the answer is
> an independent party reproducing the release from the Site Model, or
> n-of-m sign-off — neither of which is this design.

**Merge:** replace from "is inside every control described here." to the end of the bullet
**Checked:** verified (read)

### G-§17-05: The "AI-authorship premise" bullet: keep one side

**Target:** §17, bullet beginning "**The AI-authorship premise bounds the design from both sides.**"
**Kind:** reword
**Goal:** G6
**Weight:** improves
**Finding:** Consistent with G6 in substance, because the bullet bounds the *scaffolding*, not the premise. But "§20 asks this as a question" points at Q9, which as written asks whether "the whole premise" is the wrong shape. Reword both so that the premise is fixed and the defence is in question. The "worse than assumed" half is the live one, and G4's scanners and differential runs are its answer.
**Evidence:** guide:1283-1290, 1562-1565.
**Proposed text:**

> - **AI authorship is the premise; what it bounds is the defence.** If
>   agents become reliable over long contexts, the local-knowledge
>   scaffolding is unnecessary and an ordinary catalog compiler wins. If
>   they are worse than assumed — fluent, schema-conformant and
>   semantically wrong — types are the wrong defence, and what is needed is
>   the review-and-test loop: the safety scan (§7), property tests over
>   rendered output, differential runs against the previous release.

**Merge:** replace the bullet
**Checked:** verified (read)

### G-§17-06: New limit: a score invites the rubber stamp it exists to prevent

**Target:** §17, append to "The trust and consent layer"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** A visible "97%" on every routine release trains an owner to stop reading, which is the failure §20 Q10–Q11 describe, now with a number attached. The limit should be stated with something measurable, in the section's own style.
**Evidence:** guide:1566-1581; goal G4.
**Proposed text:**

> - **A confidence figure can become the thing that is approved.** Once
>   most diffs score high, a person reads the number and not the diff, and
>   the scan becomes the authority it was designed never to be. The
>   mitigation is structural — privileged regions and removals always need
>   their own keypress, whatever the score — but whether people read past a
>   high score is an observation, not a design. Measure time spent per
>   accepted diff against its score, and how often a diff later reverted had
>   scored above 90%.

**Merge:** insert as the last bullet of "The trust and consent layer"
**Checked:** inferred

### G-§17-07: Local-first reporting: G3's archive is the middle path

**Target:** §17, bullet beginning "**Local-first reporting stops paying for itself"
**Kind:** reword
**Goal:** G3
**Weight:** nit
**Finding:** The bullet offers only two shapes: per-device records, or a central statistics spine. G3's archive server (G-§6-01) is a third: a central copy fed by devices, never the record. The bullet should name it as the step before the spine.
**Evidence:** guide:1199-1208.
**Proposed text:**

> ... the honest fix is a central statistics spine (the shape Bcfg2 already
> builds). The log archive (§6) is the step before it: it answers "what did
> device X report" without asking device X, but not "did the rollout land",
> which still needs the device.

**Merge:** replace "the honest fix is a central statistics spine (the shape Bcfg2 already builds), not a federation layer retrofitted onto a local-first design."
**Checked:** verified (read)

---

## §18 What is built, and what is next

### G-§18-01: "Built today" omits the Linux work and the prototypes

**Target:** §18 "Built today"
**Kind:** correct
**Goal:** G5, G8
**Weight:** misleads
**Finding:** The list leaves out the pieces the new build order reuses most. These are: Linux CI building the pinned fork and running the bundle as root on three Ubuntu VMs and a `debian:13` container; the root installer and runbook (`deploy/linux/`); the enforced canary and its schema check; the read-only unit-namespace classifier (186 tests, not wired); the compiler's `eval-nix` and its NixOS service-free render; and the fact that macOS has no CI.
**Evidence:** inventory §A, §F; `CLAUDE.md` "Verifying policy and the CFEngine build"; guide:1296-1347.
**Proposed text:**

> - **A root-owned Linux install** (`deploy/linux/tendcf-install.sh`, a
>   runbook, and a canary goal file whose projection CI keeps
>   byte-identical): the fork at `/opt/tendcf`, a root `cf-execd`, one
>   canary service enforced on one operator host.
> - **CI that builds the pinned fork** and runs the bundle against it as
>   root on ubuntu-24.04, 26.04 and 24.04-arm and a `debian:13` container,
>   including the systemd lifecycle and the refusal on a NixOS-shaped host.
>   There is no macOS CI: the launchd branch is tested on a Mac development
>   build only.
> - **A read-only unit-namespace classifier** (`bin/unit_classifier.py`),
>   the prototype of the extra-entry detector for Debian units; not wired
>   into the bundle.
> - In the compiler, `nix2cf eval-nix`, which evaluates a plain Nix
>   attribute set to Site Model JSON (not the module frontend), and a
>   NixOS host rendered with no services.

**Merge:** insert after the overlay bullet
**Checked:** verified (inventory with file references; CI not re-run); independently checked 2026-11-13: confirmed

### G-§18-02: Replace the build order with one ordered by G8's states

**Target:** §18 "Build order from here", the table and the two paragraphs after it
**Kind:** correct
**Goal:** G5, G8 (also G2, G3, G4)
**Weight:** blocks-goal
**Finding:** The table is the order from before 2026-10-29: macOS adapter, then Android, compiler, Linux, signing at Step 6 and consent at Step 9. It does not record D22's Android deferral, which the map's table does. G8 state 1 needs four things the table puts late or nowhere: signing with the handshake (Step 6), the device-side validator with see-and-refuse (Steps 6 and 9), the log archive (absent), and safety scoring (absent). It also needs two the table never schedules: the Nix module frontend and Android profiles. Below is a replacement ordered by state, with the reuse named per step. What the Linux work is worth: the root-install pattern, fork CI, the run.sh harness, the projector, the canary and the validate proposal all carry to macOS and Android almost unchanged. The systemd branch, schema v4/v5's dpkg claims, the unit classifier and the NixOS passthrough are parked until state 2 (Steps 12–13), where they are needed as built. Nothing is thrown away.
**Evidence:** guide:1359-1379; inventory §A, §C, §F, §H; goal G5, G8; `docs/architecture/PREMORTEM-BRIEF.md:20` (the Mac is a laptop that sleeps).
**Proposed text:**

> **Build order from here**, by the three states of the finish line (§1).
> Each step leaves a coherent, describable system.
>
> *State 1: one Mac (server) and one Android device (client).*
>
> | Step | What | Reuses |
> | --- | --- | --- |
> | 1 | **The fork on the Mac.** Build the pinned fork for macOS arm64 into `/opt/tendcf`; a root `cf-execd` under launchd; one canary launchd service enforced, dry-run for everything else (the Mac is the daily driver). | `overlay/fork.json` and the CI build action; `tendcf-install.sh` and the canary pattern, ported from systemd to launchd; the launchd branch of `policy/tendcf_services.cf`; `tests/policy/run.sh`. |
> | 2 | **Nix authoring, minimal.** A module system (`lib.evalModules`) with tendcf options for services, interlocks and roles, named after nix-darwin where one exists, evaluating to today's Site Model JSON; YAML twins stay as fixtures and must be byte-identical. | `nix2cf eval-nix`; `buildfile` (renamed `tendcf compile`); the schemas and lint unchanged. |
> | 3 | **`tendcf-validate`, first build.** Stored, integrity-checked baseline; the device computes the diff; the command-line review mode shows it and takes accept or refuse; projection only after accept. Operator tier. | `bin/projector.py` (promoted, D45); `apply_diff` and `derive_ceremony_class` from `bin/schema_lint.py`; goal-diff and approval-record schemas; the validate proposal's options for trigger and atomic publication, which are platform-neutral. |
> | 4 | **Signed releases and the handshake.** The TUF subset of §7; any device may relay a release; the device verifies it before step 3 sees it. | `change-process.md` (lockfile, release, rollback, gates); `bin/overlay.py`'s pinning discipline. |
> | 5 | **Android client.** CFEngine in Termux; runit services via termux-services (a third bundle branch); the agent's validator and record in app-private storage; Island/Insular work profiles as separate domains; ShizukuPlus as the helper. | The `termux` flavour already in `services.schema.json` and the `android-termux-services` fixture; `frdminc/ShizukuTendCF`; the golden projections, which the Kotlin port must match (D45). |
> | 6 | **Peer actions and the archive.** The Mac starts ShizukuPlus over ADB when the phone cannot (§13); JSONL capture on both devices; the Mac's `log-archive` and `monitor` roles, each a service record rendered through launchd; the phone buffers while the Mac sleeps. | `report-row.schema.json`; the roles schema (`{main, backups[], peers[]}`). |
> | 7 | **Safety scan, then the TUI.** Fixed-rule scanners and an owner-chosen AI reviewer over the device-computed diff; the score, its explanation, graded highlighting; then the TUI on the borrowed scaffold. | The privileged-path list and ceremony classes already in the schemas; the fork's `--simulate-json`. |
>
> **State 1 is reached** when the Mac and the phone each converge from a
> Nix-authored site, each refuses a release that fails the handshake and a
> diff its owner refused, and both devices' logs are in the Mac's archive.
>
> *State 2: the whole fleet, and the old stack retired.*
>
> | Step | What | Reuses |
> | --- | --- | --- |
> | 8 | Pull: every device self-updates from any peer; roles move by editing data. | Steps 3–4. |
> | 9 | macOS as client: the other Macs. | Steps 1–3. |
> | 10 | Extra-entry reporting per domain, so the `not-yet-migrated` count measures what is left. | `bin/unit_classifier.py` and the s5 detector design (Debian units); new detectors for launchd and the Android app list. |
> | 11 | Migrate the old stack's services one domain at a time, then retire it. | Everything above. |
> | 12 | Linux as server: the existing Debian host, from canary to full. | The systemd branch, schema v5 package claims, the root installer, Linux CI. |
> | 13 | Linux as client, and NixOS/nix-darwin hosts as passthrough. | The NixOS refusal and passthrough stages already run on get.sipb.cloud. |
>
> *State 3: a stranger installs it from the public docs with their own AI.*
>
> | Step | What |
> | --- | --- |
> | 14 | The publishable layer extracted; install and first-run root ceremony a person with no admin skill can complete; the default advisor prompt; public documentation written for that person and their AI. |
> | 15 | The `consented` tier, for a device someone else proposes changes to. |
>
> *Later, demand-driven:* free-software branch management built on
> `overlay/` (§8, G9); ordering inference (§10); the builder/cache;
> reproducible APK provenance; web-of-trust as advisor tools;
> out-of-tree plugins.
>
> On the daily-driver Mac, which cannot easily be reimaged, dry-run is the
> standing posture for everything but the canary and the server services
> it holds. Reporting ("what changed, what is dirty, what release am I
> on") is an adoption requirement, not an observability extra.

**Differences from the other proposal** (the map response's build order, M-§13-01, as corrected after checking; from the independent checker's comparison; the two proposals are kept separate so the owner can choose):
1. **First step.** Here the fork on the Mac comes first (1) and Nix authoring second (2); the map has the Nix frontend first and the Mac second. The checker notes the Mac today runs Homebrew upstream CFEngine 3.29.0 with the §19 data-path defects, which slightly favours the fork first; the two steps are otherwise independent.
2. **Step 0.** The map adds a Step 0: merge #41 and #42, the D46 restructure, and one schema bump carrying whatever has been ruled by then. This proposal has no schema step. The checker notes #41 and #42 touch only platform-neutral files, so they close the interlock fail-open on the Mac too.
3. **Validator and signing.** Here the validator (3) precedes signing and the handshake (4), flagged for a ruling. The map, as corrected, has the validator (3), owner review (4), then signed releases with signature and high-water verification (5).
4. **Safety scan and TUI.** Here all scanning, rules and AI, plus the TUI, is Step 7 inside state 1. The map has mechanical scanning and the CLI at Step 4 and the AI scanner and TUI at Step 8 ("1→2"), so its state 1 ships a partial G4.
5. **Owner signature.** The map has an owner key sign at Step 4 (supersedes D39, needs that ruling); this Step 3 takes accept or refuse with no key specified.
6. **Peer actions.** Here ShizukuPlus start-over-ADB is a state-1 step (6); the map has no peer-action step.
7. **Monitoring.** Here the `monitor` role is in state 1 (Step 6); the map has it at Step 9, in state 2, which matches G8.1's literal text (log archive only).
8. **Extra-entry reporting.** Here a separate step (10) with launchd and Android detectors precedes migration (11); the map has only the Linux unit-writer detector before retiring the old stack.
9. **Linux.** Both now keep G5's order 4 then 5 (here Steps 12 and 13; the map, as corrected, 10 and 10b). The map moves nix-darwin passthrough to its Step 9.
10. **Inference.** Both defer it with a ruling flagged: here to "Later" (G-§10-01), in the map, as corrected, to "13+ Demand".
11. **macOS CI.** The map names a macOS CI job (ruling) in Step 2; this Step 1 says only "the CI build action" and leaves CI to Idea 6.
12. **State 3.** Here the publishable layer and a root ceremony a novice can complete (14), then the `consented` tier (15); the map has public docs, the authoring guide, first non-operator enrolment, the TUF emergency role and advisor delegation. Complementary; the map's emergency-role deferral is a ruling this proposal does not make.
13. **When state 1 is reached.** Here each device must refuse both a release failing the handshake and a diff its owner refused; the map requires refusing an unsigned or unhandshaken update in a test. The checker finds this test closer to G4.
14. **Plugins.** The map's Step 0 does the D46 restructure as decided; G-§4-01 here cuts out-of-tree entry points (amends D46). One ruling covers both.

**Merge:** needs the operator's ruling first. It supersedes D22 and the 2026-10-29 Linux-first ruling (`linux-targets.md`), defers D16's inference, and may amend D45 (the Android validator). Within it, rule on step order 3-7, in particular whether signing (step 4) may follow the validator (step 3). The map's §13 changes in the same commit.
**Checked:** reuse claims verified against the inventory; feasibility of a macOS fork build and of CFEngine under Termux in a work profile not checked; independently checked 2026-11-13: weakened, corrected

### G-§18-03: Step 4's distro default is Ubuntu; the first live host is Debian

**Target:** §18 table, Step 4, "Ubuntu Server is the working default."
**Kind:** correct
**Goal:** G5
**Weight:** nit
**Finding:** The only live Linux host is Debian 13, schema v5's package claims are dpkg-specific, and CI's root install runs on Ubuntu and Debian. Under the replacement (G-§18-02) the question moves to Step 12. If the old table stays, correct it.
**Evidence:** guide:1368; `docs/architecture/linux-targets.md:11-12`.
**Proposed text:**

> | 4 | Linux reference path | A stock distro, not NixOS. The first live host is Debian 13 and the package claims are dpkg's; another family needs a schema bump. |

**Merge:** replace the row (moot if G-§18-02 is merged)
**Checked:** verified (read)

---

## §19 What we found underneath

### G-§19-01: "This design bets everything on one thing": the instrument is open to challenge

**Target:** §19, at "This design bets everything on one thing"
**Kind:** reword
**Goal:** G7
**Weight:** improves
**Finding:** G7 makes CFEngine, the fork and the compile-to-Augments shape instruments, open to challenge. "Bets everything" frames the instrument as the project. The same section's costs (a permanent fork, time not spent building) are exactly the evidence an instrument challenge would weigh, so the opening should invite that challenge, not foreclose it.
**Evidence:** guide:1385-1390, 1469-1482; goal G7.
**Proposed text:**

> The current instruments rest on one choice: that the right place to put
> a compiler's output is CFEngine's own JSON data layer, so the policy text
> stays generic and every site-specific fact arrives as data (§4). That
> choice is open to challenge, and changes only by the operator's ruling;
> what follows is the evidence any challenge would start from.

**Merge:** replace the first paragraph's first sentence
**Checked:** verified (read)

### G-§19-02: Move the upstream narrative out of the current-state guide

**Target:** §19, subsections "Who wrote the fixes" and the upstream-history paragraphs
**Kind:** cut
**Goal:** G8
**Weight:** improves
**Finding:** The front matter says the guide "does not recount how the design was reached", yet §19 runs about 140 lines of the August upstream episode. That story already lives in `upstream-register.md`. For a G8 state-3 reader, what matters is that tendcf ships against a patched fork, why, and what it costs. A 20-line §19 with a link keeps that and shrinks the guide by about 8%.
**Evidence:** guide:3-6, 1383-1525.
**Proposed text:**

> tendcf runs on a fork of CFEngine (§18, `overlay/`). Pushing a whole
> site's facts through `def.json` and `host_specific.json` found ten
> defects in that data path — three of them stop a run before any promise
> is evaluated, dropping the host to failsafe, on input a correct compiler produces — and the fixes, each
> with a test shown to fail without it, live on the fork. Upstream declined
> the batch on review volume, not on substance. The cost is a fork to
> maintain; the record is [`upstream-register.md`](../architecture/upstream-register.md).

**Merge:** replace §19 except "One last thing, and it cuts against §9", which stays; needs the operator's ruling (the paper keeps the long form)
**Checked:** verified (read); independently checked 2026-11-13: weakened, corrected

---

## §20 Open questions

### G-§20-01: Q9 asks about "the whole premise"; under G6 it asks about the defence

**Target:** §20 Q9, "**Is the whole premise the wrong shape?**"
**Kind:** reword
**Goal:** G6
**Weight:** improves
**Finding:** Diff 9. The question's substance, whether schemas defend the right wall, is legitimate under G6. Its title puts the premise in doubt. Q2 stands as written (it is about the rule).
**Evidence:** guide:1562-1565.
**Proposed text:**

> 9. **Are the schemas defending the wrong wall?** The design hardens the
>    surface where a machine author lacks global context. If the real
>    weakness is plausible-looking output that type systems do not catch,
>    the weight belongs on the safety scan and on testing rendered output
>    (§7, §17), and the schemas are defending the wrong wall.

**Merge:** replace Q9
**Checked:** verified (read)

### G-§20-02: Which questions the goal answers, which stand

**Target:** §20, the list as a whole
**Kind:** add
**Goal:** G1–G9
**Weight:** improves
**Finding:** Status of the existing 16 against the goal:
1. Q5 and Q6 (local-first) are **partly answered** by G3: the archive and monitor roles give a central copy that is not the record.
2. Q12 (does refusing cost the proposer) and Q15 (can the consent gate mean what it says) **narrow** to the `consented` tier once the owner is the usual proposer (G-§8-01, G-§17-02).
3. Q1 and Q7 (inference) **leave the critical path** if G-§10-01 is ruled.
4. Q2, Q3, Q4, Q8, Q10, Q11, Q13, Q14 and Q16 **stand**. Q10 and Q11 become sharper under G4, because a score now sits on top of the diff. Q13 (the baseline) is a state-1 blocker for Android.
5. Q9 is reworded (G-§20-01).
**Evidence:** guide:1533-1615.
**Proposed text:**

> After the goal of 2026-11-13: questions 5 and 6 are partly answered by the
> archive and monitoring roles (§6); 12 and 15 bind only the `consented`
> tier, since an owner usually proposes their own changes (§8); 1 and 7
> are off the path to the finish line while inference is deferred (§10).
> The rest stand, and 13 must be answered for Android before the first
> state of the finish line is reached.

**Merge:** insert before question 1
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### G-§20-03: New questions from G3 (peer updates, servers)

**Target:** §20, append
**Kind:** add
**Goal:** G3
**Weight:** blocks-goal
**Finding:** G3 raises at least four open design questions that the guide does not ask: what the handshake authenticates; how an offline phone and a sleeping Mac meet; what happens to the archive when its only holder is lost; and whether a relaying peer can withhold releases (freeze) even though it cannot forge them. Mark them open; they gate state 1.
**Evidence:** goal G3, G8.1; (guide:550-552: the high-water mark rejects replay, freeze and downgrade; whether freeze detection works for a device that hears from one intermittent relay is the open part); `docs/architecture/PREMORTEM-BRIEF.md:20`.
**Proposed text:**

> 17. **What does the handshake authenticate?** The release's signatures,
>     the sending device, or both — and so whether a device outside the
>     site may carry a release at all.
> 18. **How do a phone that is mostly offline and a laptop that sleeps
>     meet?** The server is a role on a machine that is often unreachable;
>     the archive and the relay have to work in the windows both are awake,
>     and a client has to say how long it has gone unheard from.
> 19. **What survives losing the only server?** If the one Mac holding
>     `log-archive` is lost, the devices still hold their own records; what
>     has to be true for a second holder to take the role from data alone?
> 20. **Can a relay freeze a device by withholding?** A peer cannot forge a
>     release, but if it is the only one a device hears from, it can stop
>     passing them on. Freeze detection (§7) needs a clock or a second path.

**Merge:** insert after question 16
**Checked:** inferred; independently checked 2026-11-13: weakened, corrected

### G-§20-04: New questions from G4 (score, highlighting, CLI and TUI)

**Target:** §20, append
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The score needs calibration and a defence against a diff written to manipulate the AI scanner. Configuration carries free text (descriptions, comments, command strings) that an AI reads as instructions. The explanation must not be AI-only either. Mark these open.
**Evidence:** goal G4; guide:1049-1062 (interlock `description` is free text inside the Site Model).
**Proposed text:**

> 21. **What does 80% mean?** A confidence figure is only useful if it is
>     calibrated: of diffs scored 80%, roughly how many turn out unsafe.
>     Until there is a record to calibrate against, the figure is a ranking,
>     and should say so.
> 22. **Can the diff talk the scanner round?** Descriptions, comments and
>     command strings are text an AI scanner reads; a change can carry
>     "this is a routine, safe update" inside itself. The AI scanner must
>     read the diff as data, and its verdict can only lower the score a
>     fixed rule allows (§7) — whether that is enough is untested.
> 23. **Does the explanation hold without AI?** If the owner's AI is
>     unavailable, the fixed rules alone must still produce a score and a
>     reason; how much lower that score is, and whether the owner can
>     still accept, is open.
> 24. **Do the command-line and TUI modes stay equal?** An AI driving the
>     command line must get everything the TUI shows a person, or the two
>     modes are two different consent experiences.

**Merge:** insert after question 20
**Checked:** inferred; independently checked 2026-11-13: confirmed

### G-§20-05: New questions from G1, G8.3 and G9

**Target:** §20, append
**Kind:** add
**Goal:** G1, G8, G9
**Weight:** improves
**Finding:** The 2-of-3 offline root (§7), which the front matter makes a floor, is a key ceremony no person without admin skill will complete unaided. That collides with G1's long-run user and G8 state 3. G9 raises its own question: what a non-technical user does when an overlay patch stops applying.
**Evidence:** guide:9-12, 547-560; goal G1, G8.3, G9.
**Proposed text:**

> 25. **Can a person with no admin skill hold the root?** The release root
>     is offline and 2-of-3. For one owner of one site, what form of that
>     ceremony can someone complete with only their AI's help, without
>     relaxing the floor — or does the floor change for single-owner sites?
> 26. **What does a non-technical person do when their patch stops
>     applying?** Branch management (§18, later) keeps a fork as patches
>     against upstream. When upstream moves and a patch conflicts, the
>     person's AI has to explain it and propose a fix they can refuse —
>     the same see-and-refuse loop, applied to source rather than state.

**Merge:** insert after question 24; question 25 needs the operator's ruling on whether the map's floor applies to single-owner sites
**Checked:** verified (read the floor statement); independently checked 2026-11-13: confirmed

---

## Nits

| ID | Where | Finding | Proposed fix |
|---|---|---|---|
| G-§0-03 | front matter "Prepared 2026-08-14; re-checked against the repository 2026-08-18." | Text carries 2026-11-13 edits; the date line is three months stale. | "Prepared 2026-08-14; last re-checked against the repository 2026-11-13." |
| G-§1-02 | §1 "Android devices reached through [Termux]" | Termux is one of three Android parts; G5 names ShizukuPlus and Island/Insular. | Covered by G-§1-01. |
| G-§2-02 | §2 "tool forks (optional) sudo-secretspec, Shizuku, …" | The fork is of ShizukuPlus (`frdminc/ShizukuTendCF`), and under G5 it is not optional for Android. | "ShizukuPlus (our fork, required on Android), sudo-secretspec, …" |
| G-§12-01 | §12 "This is the one mechanism in this guide that has been demonstrated" | The systemd lifecycle and tombstone teardown are also demonstrated (CI, pastebin). | "This is the one Site Model mechanism shown refusing for real;" |
| G-§18-04 | §18 Step 2, no "Deferred" | Map §13 Step 2 says Deferred (2026-10-29); the guide does not. Under G5 the guide is accidentally right and the map is wrong. | Fix the map, not the guide (M-series). |
| G-§18-05 | §18 Step 3 "Inference waits until types exist on two platforms." | Map Step 3 says "needs step 1 and a Linux systemd adapter"; both exist now, so the gate reads as open. | Moot under G-§10-01; otherwise "Types now exist for launchd and systemd." |
| G-§18-06 | §18 Step 6 note | Omits the map's "tendcf-validate built after schema v5 lands and before any further host is enforced" (map:1164); v5 landed 2026-11-02, validate is unbuilt. | Add the sentence, with "not yet built (2026-11-13)". |
| G-§map-01 | map §12 "First host: vps-primary." | linux-targets says vps-primary is not in the first milestone, and stage C ran on get.sipb.cloud. | M-series. |
| G-§map-02 | map §0.2 "reference target is a stock Linux distro" | Contradicts G5 (macOS first) as well as G2. | M-series. |
| G-§FR-01 | Further reading | No entry for Island/Insular, Shizuku/ShizukuPlus or nix-darwin, which the new §1, §3 and §6 lean on. | Add the three URLs from the items above. |

## Ideas and risks

1. **The server is a laptop.** The predecessor's named failure was "the control node was a Mac that sleeps", and the live Mac is a MacBook Air (`PREMORTEM-BRIEF.md:20`). G3's wording protects convergence. But the archive, relay and ShizukuPlus restart in state 1 all depend on the Mac being awake, so every server service must be designed around missed windows from day one, not retrofitted.
2. **Compute the score where the owner is.** A safety score computed by the proposer's pipeline repeats the §17 same-party problem with a number attached. Running the scanners against the device-computed diff, with an AI the owner chose, is what makes G4 more than display.
3. **Prompt injection through config text.** Free-text fields (descriptions, commands, comments in Nix) reach the AI scanner. The rule "AI may only lower the score below what fixed rules allow" is cheap and should be in the first scoring build, not added after an incident.
4. **Borrow nix-darwin's option names.** Using `launchd.daemons.<name>` and `systemd.services.<name>` as tendcf's service options would make "existing configs carry over" (G2) literally true for the supervisor layer at almost no cost. It also gives the first adopters (Nix sysadmins) something familiar on day one.
5. **CFEngine's own handshake may be most of G3.** cf-serverd already does key-authenticated peer connections. Pairing it with TUF signatures (transport plus content) could deliver "updates from any device with the handshake" without writing a transport. This is a G7 ruling, but cheap to evaluate.
6. **The Mac runs upstream CFEngine, not the fork.** The checked Mac has Homebrew CFEngine 3.29.0, which still carries the data-path crashes §19 lists (null in `host_specific.json` and the rest, per the guide). There is no macOS CI. State 1 Step 1 needs a macOS fork build and some macOS test leg, which the CI policy reserves for explicit request, so the operator should rule on it early.
7. **Android in a work profile doubles everything.** Termux, CFEngine, the agent and the record may be needed once per profile, with cross-profile actions only through the profile owner. Prototyping CFEngine under Termux inside an Insular profile before writing the Android adapter would surface the hard limits cheaply.
8. **Let the overlay be G9's first customer.** `bin/overlay.py` already does pinned patches, drift checks and retirement for the CFEngine fork. Generalising it for the operator's own forks (ShizukuTendCF, the CFEngine fork) before any non-technical user exists tests G9's core on real forks at no product cost.
9. **The guide is written for reviewers, not adopters.** Its voice, length and Bcfg2 lineage serve a reviewer like Desai, while G8 state 3 needs public docs a stranger's AI can follow. Plan a separate, short adopter document instead of growing the guide. Measure the guide's line count, because the docs-to-code ratio (240 of 398 non-merge commits docs-only) is the risk the 2026-08 pre-mortem named.
10. **Re-sequence before more Linux depth.** Open work today (PRs #41 and #42, the s5 detector, the validate picklist) is mostly Linux-specific. Without a ruling on G-§18-02, the next weeks will likely keep deepening platform 4 while platforms 1 and 2 have no code. Parking the Debian-only items explicitly would make the reorder real.

Last search run: exempt: review of a given document; searches run at the start are listed under "Prior art / docs checked".

Not checked: live hosts (no SSH); CI not re-run; no test or build run; PR #41/#42 state taken from the inventory; the fork branch contents; the Shizuku reboot/ADB behaviour against its docs; whether the Mac checked here is the one meant for state 1; CFEngine under Termux in a work profile; the map beyond §0–§2 and §12–§13; plugin-layout.md, change-process.md and linux-targets.md beyond cited lines.

Counts: 45 full items plus 10 table nits; see the header for counts after checking.

## Withdrawn after checking

None. The independent checker refuted no item in this document.
