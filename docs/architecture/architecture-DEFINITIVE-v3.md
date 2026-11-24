# tendcf — Architecture (v3, definitive)

> This file is the map, not the worksheet — it records decisions and
> build order rather than working notes. It is freely editable: keep it
> current rather than proposing changes elsewhere. Read §0 first.

- **Status:** Implementer map (decisions, build order, protection).
  Supersedes `deprecated/architecture-DEFINITIVE-v2.md` where they
  conflict. The vetted current-state description is
  `docs/paper/tendcf-architecture-guide.md`; where this file and that
  guide disagree on the current design, **the guide wins**. Numbered
  v1/v2 files, panel drafts, and the v2 trust spec are archival — see
  `deprecated/README.md`.
- **Date:** 2026-08-15 (§9 rewritten for Model B; D43/D44 added);
  amended 2026-11-14 (operator rulings of the goal review written in:
  D47–D50 added; §0, §1, §2 (R4, R5), §5, §6, §8, §9.1, §9.6, §9.11, §11,
  §12, §13, §17, D6, D8, D12, D14, D16, D18, D22, D45 and D46 amended; new
  §9.12, the safety score). Rulings are quoted as
  `operator ruling, 2026-11-14, <item id>`; the full proposals are in
  [`../review-2026-11-13/`](../review-2026-11-13/README.md) and the
  rulings record is
  [`../review-2026-11-13/rulings-record-2026-11-14.md`](../review-2026-11-13/rulings-record-2026-11-14.md).
  Corrected the same day to the merged state (schema v6, PRs 52, 42 and
  41 merged); items not decided are marked "open" (only the AI reviewer
  "up to 30" count still is, marked "open: deferred to the schema design
  review (operator ruling, 2026-11-14, PR 62 review Q7)"; Q1-Q6 of PR 62 are
  ruled, including the G4 sentence, Q5, and the reviewer-proposed map text,
  Q6).
- **Tracker:** frdminc/tendcf#1.

This document describes the **current design and what is planned next**.
It does not recount how the design was reached. A previous configuration
stack on this fleet is **legacy reference only** — not a dependency, not
an upstream, not a name in this architecture. Patterns taken from it are
described in generic terms (for example “peer ADB help for a device that
cannot start its own privileged helper”).

---

## 0. Orientation for the AI that implements this

1. **This is free software for people who want control of their own
   devices.** Correct beats interesting; when correct and safe conflict,
   stop and ask (item 5). Development cost is secondary to getting it
   right (operator, 2026-10-31). A user's own AI token cost at run time
   is a design constraint (R12). (Replaces "This is a freedom project.
   Interesting and correct beats minimal and safe …"; operator ruling,
   2026-11-14, Smaller 2 (M-§0-02), "1. Adopt the proposed text".)
2. **The reference target is a stock Linux distro on bare metal**, not
   NixOS. Nix is used for builds, as one of two equal Site Model authoring
   languages, and verbatim on hosts that already run NixOS or nix-darwin
   (D12, [`linux-targets.md`](linux-targets.md) §5) — never as the
   installed OS a stranger must adopt. Ubuntu Server LTS is the working
   default; the distro name is open until Step 4. (Platform order is
   D48, not this item: macOS first, Linux fourth and fifth; Nix is first
   among authoring languages, D49. This item's Linux statement holds for
   Linux hosts; operator ruling, 2026-11-14, B4, "1. Adopt D47-D50".)
3. **The aim is an adoptable tool that gives people control of their own
   devices** (goal G1,
   [`00-goal-definition.md`](../review-2026-11-13/00-goal-definition.md)).
   A person works through their own AI or directly in code, whichever
   they prefer at the moment. The safety mechanism is see-and-refuse
   (G4): nothing changes a device except as an exact, mechanically
   checked difference that its owner can see and refuse. Measure every
   step against the finish line (G8). State 1 comes first: one Mac and
   one Android device converge from Nix-authored config, accept updates
   only after the handshake, and archive logs on the Mac. (Replaces "The
   trust/consent layer is the point."; D47 supersedes it and item 1's old
   wording: operator ruling, 2026-11-14, Smaller 3 (M-§15-01), "1. Yes,
   supersede D8's wording"; text from M-§0-01. The trust layer stays, as
   G4's mechanism; a person still keeps a personal branch using **their**
   AI, not ours, §11.)
4. **Facts live in site data; behavior lives in tendcf.** Every tool
   (CFEngine, mise, Nix-for-builds, `tendcf-validate`, tendcf-agent) is a
   replaceable consumer.
5. **When unsure, stop.** Items in §14 are not for a cheap model to
   improvise.
6. **Prefer local knowledge over global knowledge; prefer
   machine-checkable to conventional.** If a comment says “remember
   to…”, it belongs in a schema.
7. **Put what matters at the front or the back** of anything another
   agent will read.

---

## 1. The architecture in one screen

```
  tendcf                 engine: schemas/types, generic adapters,
  (public)               default advisor prompt, and the compiler
                         with its plugins (one repository, D46)

  site-shared            reusable recipes (a Caddy role, an apt pattern).
  (optional, public)     Not live inventory.

  foreign site-shared    other people's recipes, listed as inputs.
  (read-only)

  site-private           THIS site's facts: inventory, allocations,
  (never an input)       secret names, trust policy, extra advisor prompt.
                         Holds the lockfile that pins everything else.

  tool forks (optional)  sudo-secretspec, Shizuku, … only if
                         patching them.

          │  Site Model instances (private) + recipes (shared)
          ▼
  tendcf compile         compiler, in tendcf: frontend (YAML, or Nix
  (tool)                 via the nix2cf plugin) → merge → conflict
                         check → infer ordering → per-host goal file.
                         Schemas stay in `schema/`; holds no facts.

          ▼
  Signed release         manifest + per-host canonical goal file
                         (TUF-subset; the device diffs it against its
                         approved baseline and the validator refuses
                         anything outside the approved diff — §9)

          ▼
  CFEngine +             each device is its own policy hub.
  tendcf-validate        Supervisors are adapters: systemd, launchd,
  (Linux, macOS), or     runit, Jobber, … from one service record.
  tendcf-agent (Android) No daemon beside CFEngine off Android (D45).

          ▼
  JSONL log (capture)    append-only; the durable record
  SQLite (index)         rebuildable from JSONL; one per device,
                         plus a fleet-wide one on the log archive
                         (§8); owner: tendcf-agent on Android, open
                         elsewhere (§12)
```

Collision of the same identity from two peer inputs is a **compile
error**. Only site-private may bind a winner or a short name.

---

## 2. Requirements (normative)

- **R1** Targets: macOS/Apple Silicon, Linux x86_64, Linux aarch64,
  Android (Termux + tendcf-agent + a Shizuku-class helper). Intel Mac
  mini out of scope. tendcf-agent is Android-only; Linux and macOS run
  CFEngine plus the `tendcf-validate` command, with no daemon (D45).
  Platform order: D48 (macOS as server, Android as client, macOS as
  client, Linux as server, Linux as client).
- **R2** No permanent control node. Feature roles
  `{main, backups[], peers[]}` are data.
- **R3** Resource efficiency; no fat containers; no VMs as the build
  substrate.
- **R4** Android keeps Termux (+api, +x11), the built-in Terminal app, a
  Shizuku-class helper, tendcf-agent (Kotlin, D45), CFEngine. No
  nix-on-droid. Nix may build zero-on-device-footprint artifacts only.
  tendcf never holds a DPC slot (profile owner or device owner) and never
  requires MDM enrolment; it works with Island/Insular through shell
  (`--user N`) and the owner app's API (operator ruling, 2026-11-14, B3
  sub 3 (X-android-09), "1. Never").
- **R5** No bare-metal Nix. A mainstream stock distro is the reference.
  Ubuntu Server is the default answer, not the requirement. **Amended
  2026-11-14:** Nix may be required to build a release (operator ruling,
  2026-11-14, B4 rider, Nix on release path, "2. Allow on release path"),
  scope "1. Build-time only": devices never need Nix at run time. What
  R5 forbids is Nix or NixOS as something a device or a stranger must
  install; the change-process §2 amendment is in that file.
- **R7 / R10** Push and pull. Pull becomes user sovereignty: the person’s
  own AI, suggested default prompt plus their extras, auto-review or a
  conversation. Generic layer publishable (GPL-3.0-or-later for code).
- **R11** Preserve: worktrees for development; secretspec as sole secret
  authority; CFEngine; observability stack as optional sink.
- **R12** Token budget is real. Design so routine work is cheap.
- **R13** AI agents are the primary authors. Local knowledge; machine-
  checkable conventions.

---

## 3. On-disk and repo layout (D34, D35, D21)

Git-repo count is not the composition mechanism. Layers are **roles**.
Site-private holds a **lockfile** (flake-style inputs) that pins tendcf,
site-shared, foreign shared sites, and optional tool forks. **Amended
2026-11-13 (D46):** the compiler is part of tendcf, so one tendcf pin
covers schemas and compiler together (~~pins tendcf, nix2cf,
site-shared, …~~); the compiler is under `compiler/` since #45
(2026-11-13), and the separate `frdminc/nix2cf` repository is archived.
The repository's plugin-type layout is
[`plugin-layout.md`](plugin-layout.md). The signed release is the
deploy artifact. There is no lockstep of sibling
checkouts that must share one tag.

| Layer | Holds | Local repo convention (issue #98) | Visibility |
| --- | --- | --- | --- |
| **tendcf** | Engine, **schemas/types**, generic adapters, default advisor prompt, the compiler (`compiler/`) and its plugins (`plugins/`, D46) | `tendcf/` (optional local checkout; informational/dev-only, never auto-loaded as schema or projector authority during builds) | Public product |
| ~~**nix2cf**~~ | ~~Compiler tool only (Site Model → CFEngine JSON)~~ Folded into tendcf (D46). `nix2cf` now names the Nix frontend plugin | — | Repository archived 2026-11-13, right after the import ([#45](https://github.com/frdminc/tendcf/pull/45)) merged |
| **site-shared** | Reusable recipes | `tendcf-public-<site>/` (optional) | Public or shared |
| **site-private** | Inventory, allocations, secret *names*, trust policy, extra prompt, lockfile | `tendcf-private-<site>/` (required primary site root) | Private |
| **foreign shared** | Other sites' recipes | `tendcf-public-<other>/` (optional read-only clone; builds take only what `site.lock` pins) | Read-only inputs |
| **tool forks** | sudo-secretspec, Shizuku, … | Optional | Optional |

**Schemas live in tendcf**, in `schema/`, not in the compiler's code
(~~not in nix2cf~~; amended 2026-11-13, D46: the compiler moved into
this repository, `compiler/`, so schema and compiler change in the same
commit). A
schema change is a tendcf interface change. An instance change is site
data. The JSON Schema files, fixtures, and lint are `schema/`,
`examples/`, and `bin/schema_lint.py` in this repository (`bin/` becomes
`tools/` in a later change, [`plugin-layout.md`](plugin-layout.md) §5).

**Inventory is private by default (D35).** Site-shared ships:

- device *kinds* (for example “tablet that cannot do local ADB and needs
  a peer helper”)
- example / template inventories
- **explicit exports**: public endpoints and role advertisements, only
  for fields the private site marked exportable

USB serials, RFC1918 addresses, and the full host list do not go in
site-shared. Two foreign sites both shipping a host named `mac` is a
compile error unless private binds.

A host identity in trust and ChangePlans is the **device public key**,
not the hostname.

**Lockfile composition (who wins):** same identity, same priority →
evaluation error (NixOS module-system rule). Private site may bind
`caddy: from: alice` or rename. Foreign inputs are namespaced
(`alice.caddy`) so auto-provided `service:caddy` tokens do not collide;
private may alias a short name. tendcf defaults lose to an explicit
private bind.

Development happens in task worktrees, not in a deploy checkout.

**Local multi-site workspace convention (amended 2026-11-24; operator ruling,
2026-11-24, `Ref: ANTIGRAVITY-we`, `Ref: ANTIGRAVITY-wf`, `Ref: ANTIGRAVITY-wg`
— narrow O4 docs lift for
[frdminc/tendcf#98](https://github.com/frdminc/tendcf/issues/98)):**

- **Workspace root:** `~/tendcf-ops` (overridable via `--ops-root` or
  `TENDCF_OPS_ROOT`), separate from legacy ops layouts. It holds an optional
  `tendcf/` checkout (strictly informational/development-only — never
  auto-loaded as schema or projector authority during builds, aligning with
  D46(9a)), matched site pairs `tendcf-private-<site>/` (required primary site
  root, corresponding to logical role `site-private`) and optional
  `tendcf-public-<site>/` (corresponding to `site-shared`), plus optional
  read-only clones of other operators' public sites (`tendcf-public-<other>/`).
- **Site slug and worktree hygiene:** `<site>` allows `<operator>` or
  `<operator>-<name>` (lowercase ASCII `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z`, no
  trailing newline, max 64 chars, never ending in `-wt`). Development worktrees
  MUST live outside the site scan namespace (`~/src/` or
  `~/tendcf-ops/.worktrees/`). Zero legacy aliases (`tendcf-private`,
  `site-private`, `.mysite`) are accepted.
- **Pair-bound, fail-closed selection:** one selector (`--site-name` >
  `TENDCF_SITE` > XDG active-site file `$XDG_CONFIG_HOME/tendcf/active-site`
  when absolute, else `~/.config/tendcf/active-site`, plain single-line
  non-symlink regular file) resolves `(tendcf-private-<site>,
  tendcf-public-<site>)` together and fails closed when unset or missing (on
  `nix2cf buildfile`, reading XDG `active-site` requires explicit workspace
  opt-in via `--workspace`, `--ops-root`, or `TENDCF_SITE`). There is no silent
  sole-directory glob and no uncoupled public/private selector.
- **Lockfile isolation preserved (D21/D34/D35/D46):** local sibling clones
  exist for human/agent reading, diffing, and development; no device and no
  release build ever reads a sibling checkout — builds take only what
  `site.lock` pins. Preview/test builds may pass an explicit dev-only
  `--override-input <ns>=<path>`: today it validates paths, warns loudly,
  records taint on `CompileResult`/`WorkspaceResolution`, blocks `-o` artifact
  writes without `--allow-tainted`, and fails `--check-releasable` /
  `assert_releasable()`, while foreign-input substitution awaits `site.lock`
  composition. Future release/signing pipelines (§9.11) MUST call the release
  gate and MUST NOT accept artifacts from an override build (dev overrides are
  also refused in release/CI builds per D46(9b)).
- **XDG runtime state:** mutable runtime state lives under XDG
  (`$XDG_STATE_HOME/tendcf`, `$XDG_CACHE_HOME/tendcf`, exposed by
  `state_dir()` / `cache_dir()` in `compiler/nix2cf/workspace.py`), never
  inside git checkouts.

---

## 4. The Site Model

Facts and intent in data; behavior in generic code; adapters translate.

### 4.1 Contents

- **inventory** — hosts + taxonomy: `arch`, `platform`, `adapter`,
  `trust_tier` (`operator` | `managed` | `consented`). `trust_tier` is a
  **class** (which consent gate applies). Who trusts whom is §10.
- **ports / paths** — allocation authorities; existence-checked at
  compile time.
- **services** — one record per service: name, run-as, command, `env`
  (secret *names* only), platform notes, role binding, `managed_by`,
  `supervisor` (see §6). Rendered to whatever unit that OS uses.
- **roles** — `role → {main, backups[], peers[]}`. This file dissolves
  “the control node.”
- **unit-writers** — one writer per unit name in the goal file's name
  claims (an exact name, a template key, or a prefix), for every
  supervisor (launchd label, systemd instance, runit service, Jobber
  job, …); on Debian a `unit-package` claim covers what a package ships;
  and a local drop-in or mask on a vendor unit is admitted only under an
  exact non-cfengine claim on that unit (schema v5, amended 2026-11-02,
  [schema-v5-dpkg-reconciliation-2026-11-02.md](schema-v5-dpkg-reconciliation-2026-11-02.md)
  §4(10); ~~exactly one writer per unit-name prefix; two writers on one
  unit is a lint failure~~). Lint proves uniqueness among name claims
  and package ids only; the device detects the layered rest
  (`two_writers`).
- **trust policy** — per-device, §10. Lives in site-private; compiled
  into that host’s signed release.
- Schema + lint in tendcf; example fixture paired with every schema
  (D25). YAML fallback gets a parse/re-serialize/diff check (D23) until
  the Nix authoring frontend exists.
- Lookup CLI (D24, D40): `who-provides port:443`, `does-role exist`,
  `tokens kind=service` — a tool call, not a whole-file read.

**Fields that are schema, so they land at Step 0:**

- **`provides` / `requires`** per type. A service named `caddy`
  **auto-provides** `service:caddy` unless it opts out (D40). Explicit
  `depends_on` remains available and wins. Origin-bearing edges
  (authored with location, or inferred with the rule) are **preview-channel
  only** — compiler output the person and the advisor see, never the goal
  file (corrected from this section's earlier text, which said edges in
  compiled output carry origin without scoping which compiled output:
  that collides with §9.5's no-attribution rule once the goal file is the
  compiled output the device consumes. Resolution: the goal file carries
  no edges in v1, and origin-stripped edges at most if edges are ever
  added to it; C-8, reconciliation §8).
- **`interlocks`** per bundle — precondition → CFEngine guard +
  bundle-scoped refusal. Blast radius and reporting are schema
  constants.
- **`peer_actions`** per host/type (D37) — an operation this host cannot
  perform locally, plus the capability a helper must hold, plus the
  target’s peer allowlist (§10). Helpers are fungible within the
  allowlist (preferably a **group**, not only individual keys). Stall is
  local. Idempotent. Not a distributed lock.
- **`comprehensive` + `opt_out_reason`** per domain — default on.
  Reasons: `not-yet-migrated` (backlog, countable) or
  `deliberately-unmanaged` (permanent, rare). Extra entries are the
  only detector of two writers drifting.

Optional Nix module frontend (`mkOption` / `mkIf` / `mkDefault`):
renders to the same JSON. JSON Schema is generated from the module
options; never hand-maintain both. Strangers need not know Nix.

### 4.2 Token discovery (D40)

Inference removes “you must already know the *edge*.” Naming the *thing*
is a catalog, not a graph.

1. Auto-provide `service:<name>`.
2. Lookup CLI against registries and compiled provides.
3. Unknown token, unmatched `requires`, or two providers of the same
   token → compile error listing near-misses and the catalog.

Token *kinds* are a closed enum in the schema (`service`, `port`,
`path`, `secret`, `class`, `network`, …). Token *values* are instance
data, checked at compile time — not a schema enum that changes with
every new service.

If an author has never heard of the thing they need, lookup and the
error are the discovery path. The writing rule is “don’t require the
graph,” not “don’t require names.”

---

## 5. The compiler (`tendcf compile`)

A **tool**: Site Model (YAML/JSON, or Nix frontend → JSON) → merge →
conflict check → inference → render of the per-host goal file (§9),
which the device projects to [CFEngine Augments](https://docs.cfengine.com/docs/3.21/reference-language-concepts-augments.html)
(`host_specific.json`) after approval. (~~… → inference → CFEngine
Augments (`def.json` / `host_specific.json`)~~: superseded by §9's
render-stage decision; corrected here on 2026-11-13.)

**Amended 2026-11-13 (D46).** The compiler was built as the separate
repository `frdminc/nix2cf` (`nix2cf buildfile`, Step 3). It moved into
tendcf with its history under `compiler/` (#45, 2026-11-13; the old
repository is archived), and in the restructure its command becomes
`tendcf compile`, which replaces `nix2cf buildfile` with no
alias. The name `nix2cf` moves to the Nix module frontend (D12).
Frontends, supervisor renderers and importers are plugins, all compile
time only. ~~Third-party frontends and importers are to be found through
the public Python entry-point groups `tendcf.frontends` and
`tendcf.importers`~~ (**amended 2026-11-14, D46:** all plugins live in
tree and run only at compile time, never on a device; Python
entry-point discovery of out-of-tree plugins is deferred until a user
needs one and out-of-tree plugins can be pinned); plugins in this
repository are to be found through a static import table, never through
entry points (planned, restructure step 4; no loader exists today);
supervisor renderers are in tree only. Plugins are trusted build-time code the
operator explicitly allows, not sandboxed: a plugin cannot make a device
accept anything that device's own diff does not show (on Linux and
macOS that is `tendcf-validate`, planned, D45), and cannot emit a shape the schema forbids,
but it can make the goal file say something
other than what the Site Model says. Release gates and signing are
therefore to run apart from plugin code (**planned, Step 6**: nothing
enforces it today; what "apart" means, how what is signed is tied to what
was reviewed, and that frontend recipes are code is in D46 (9) and
[`plugin-layout.md`](plugin-layout.md) §4). Layout, plugin kinds, the trust and
activation rules and the order of the move:
[`plugin-layout.md`](plugin-layout.md).

CFEngine’s [Masterfiles Policy Framework](https://github.com/cfengine/masterfiles)
already consumes that data layer. Common case: emit data, not `.cf`
text. Merge once in the compiler; do not also use `mergedata()`.

**Carry-over from other tools (B7).** Operator ruling, 2026-11-14, B7,
"1. Importer + matching names": a one-shot importer for pure-data option
families (it lists what it did not carry), plus tendcf option names that
match nix-darwin and NixOS where the meaning is the same. Ruled;
implementation pending (full text: X-nix-02 and X-nix-05 in
[`08-nix-ecosystem.md`](../review-2026-11-13/08-nix-ecosystem.md)).

Build **first** inside this pipeline: “exactly what device X would
receive, without touching X” ([Bcfg2 `buildfile`](https://docs.bcfg2.org/)
shape). Then conflict check, extra-entry reporting, then inference.
Inference waits until real types exist on **two** platforms.

Conflict errors name the resource, every writer and location, the
values, and what a resolution looks like.

Compile-to-native-format is an established pattern
([NixOS](https://nixos.org/) → systemd, [nix-darwin](https://github.com/nix-darwin/nix-darwin)
→ launchd, [cdk8s](https://cdk8s.io/) → Kubernetes YAML). The pairing
here is Site Model → CFEngine, because of
[Promise Theory](https://markburgess.org/promises.html) and disconnected
multi-owner operation — not because the compiler mechanism is new.

**Where it runs:** operator machine or CI. Consented devices receive a
signed artifact. They do not run the compiler, any of its plugins, or
Nix (except where Nix already is the host's configuration system: D12,
passthrough).

---

## 6. Supervisors, packages, and what we borrow (D36)

A service record is one fact. The host’s `supervisor` field (or a
platform default) selects the adapter. launchd is an example, not the
model.

**Take (code or a thin wrapper)**

| Need | Source |
| --- | --- |
| apt / yum / dnf / pkg | [CFEngine package modules](https://docs.cfengine.com/docs/3.21/reference-promise-types-packages.html) |
| systemd units / timers | [NixOS systemd modules](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/system/boot/systemd.nix) for shape; CFEngine `services:` to keep them loaded |
| File / package / service idioms | [ncf / Rudder generic methods](https://github.com/Normation/rudder/tree/master/policies/lib) — vendor, strip Rudder reporting |
| launchd plist fields | [nix-darwin launchd](https://github.com/nix-darwin/nix-darwin/blob/master/modules/launchd/default.nix) — pattern, not a runtime dependency |
| Termux daemons | [termux-services](https://github.com/termux/termux-services) ([runit](http://smarden.org/runit/)) |
| Termux at boot | [Termux:Boot](https://github.com/termux/termux-boot) |
| Signed updates | [TUF](https://theupdateframework.io/) (`python-tuf` / `go-tuf`) |
| Secret names vs values | [sudo-secretspec](https://github.com/djbclark/sudo-secretspec) |
| Android privilege / peer ADB | tendcf-agent + [Shizuku](https://github.com/RikkaApps/Shizuku) (our fork if we patch) |
| Toolchains | [mise](https://mise.jdx.dev/) |

**Pattern only**

| Need | Guidance |
| --- | --- |
| [Jobber](https://dshearer.github.io/jobber/) / other cron replacements | YAML jobfile we render. On systemd hosts, prefer timers. |
| Homebrew | nix-darwin Homebrew module if Mac substrate goes that way; else CFEngine around `brew bundle` |
| OpenRC / s6 / dinit / sysv | Same record, small renderer; only when a real host needs one |
| Extra entries, interlocks, `buildfile` | [Bcfg2](https://www.usenix.org/legacy/publications/library/proceedings/lisa05/tech/full_papers/desai/desai.pdf) ideas; reimplement |
| Git-synced policy, no hub | [Flux](https://fluxcd.io/) / GitOps shape on CFEngine |

**Ours**

- Multi-input merge + conflict-as-error
- `provides` / `requires` inference and origin
- Goal-file render, canonicalization, and the ChangePlan validator (§9)
- Consent slot + default prompt (the advisor is theirs)
- JSONL capture + SQLite index (§8; tendcf-agent's on Android per D45, a support role; operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role")
- Generic bundle that picks a supervisor
- Peer actions as typed cross-machine help

**Review TUI borrows (B12).** Borrow Toad and textual-diff-view
(AGPL-3.0) as needed. The review TUI becomes AGPL-3.0-only and moves to
Python >=3.14 (Toad's floor; Toad pins `textual==8.2.7`). The rest of the
repository's licence is unchanged (R7 / R10). AGPL blocks GPL-2.0-only,
CDDL, EPL-2.0 without a secondary designation and proprietary code in
that module, so keep incompatible licences out of the TUI module; nothing
tendcf uses today is affected. Follow-ups: Termux and Mac availability of
Python >=3.14. Operator ruling, 2026-11-14, B12, "2. Borrow both freely;
raise Python"; the licence question is X-safety-11 in
[`09-safety-score-and-tui.md`](../review-2026-11-13/09-safety-score-and-tui.md).

ncf/Rudder has no macOS or Android. CFEngine `services:` talks
systemd/Windows/sysv, not launchd. Linux packages and systemd are mostly
assembly; launchd, Termux/runit, Jobber, and the supervisor switch are
original work with those projects as templates.

Deployment: every host runs its own `cf-serverd`, policy from the signed
release via git. [CFEngine’s documented default](https://docs.cfengine.com)
is hub-and-spoke; self-bootstrap when the declared server is itself is a
documented primitive, used here fleet-wide. Push (`cf-runagent`) is the
same mechanism, not a second system.

---

## 7. Ordering, interlocks, peer actions (D16, D37)

Retry-until-stable (CFEngine) is the substrate. Explicit `depends_on`
wins where present. Inference from `provides`/`requires` is the primary
authoring mechanism.

Do **not** compile everything into a Puppet-style catalog. Roles examined
so far are largely independent. A site whose roles interleave into a
real DAG would want a different design.

**Interlocks** are not edges: “do not enable always-on VPN lockdown until
the VPN is authenticated.” Bundle-scoped refusal; author cannot narrow
blast radius or silence the report.

**Peer actions (D37)** are the cross-machine shape that actually fits an
often-offline fleet. Example from our last system: a device that cannot
start its privileged helper locally; any healthy peer in its allowlist
may do it over ADB; if every helper is down, **only that device waits**.

This is not a [distributed lock](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html)
and not Bcfg2’s [LISA ’06 FSM](https://www.usenix.org/conference/lisa-06/directing-change-using-bcfg2)
over releases. Those stall the *fleet* when one box is unreachable.

Cross-machine “wait until the server is serving the new export” is a
**local probe** (or a wait for a signed apply-attestation from the host
that holds that role). Bcfg2’s FSM is a **view** reconstructed from JSONL
+ optional attestations, never a coordinator.

[Bcfg2 `altsrc`](http://docs.bcfg2.org/) still transfers: Termux
`$PREFIX` vs Linux/macOS absolute paths sharing one source.

---

## 8. Local record (D18)

The local capture must exist on CFEngine Community anyway. The device’s
record is authoritative because devices go unreachable; a central copy
is incomplete in exactly those windows.

**Capture and index are different files:**

1. **Capture:** append-only JSONL. One `write()`. If logging fails, a
   line is lost, not the history. This is what
   [CFEngine Enterprise](https://docs.cfengine.com) already does locally
   (`promise_log.jsonl`) before a hub copies it into SQL. Community needs
   the same glue. [osquery](https://osquery.readthedocs.io/en/latest/deployment/logging/)
   likewise logs results as JSON lines.
2. **Index:** SQLite, for queries, extra-entry counts, “what release am
   I on.” Rebuildable from JSONL. If the DB is corrupt, history still
   exists. Every device keeps its own index over its own JSONL, and the
   log archive keeps a fleet-wide one as well (ruled 2026-11-14, below).
   On Android a device's index lives inside **tendcf-agent** per D45
   (2026-11-02), and the B3 ruling ("trust and consent only", §12) does not
   remove that role from the thin agent: "only" is about decisions, and the
   thin Kotlin agent still writes the device JSONL and index as a support
   role (operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role"). On Linux
   and macOS its owning command is not yet named (below).

CFEngine never opens SQLite. Single writer to JSONL (engine or its
wrapper); single writer to SQLite (on Android the agent, which tails or
receives the log, as D45 stands; the B3 ruling does not change that: operator ruling,
2026-11-14, PR 62 review Q3, "1. Agent keeps log role", see above).

**Linux and macOS (D45, 2026-11-02).** No daemon runs beside CFEngine:
`tendcf-validate` (§12) is a command that runs and exits, not a process
that tails the log. What holds there is the capture: JSONL, written by
the engine or its wrapper. It is not built yet on any host — nothing
writes report rows (`report-row.schema.json`), and the Linux writer is
open in [`linux-targets.md`](linux-targets.md) §4. D45 gives the SQLite
index no owner on these platforms; the operator has ruled that every
device keeps one (below, and §12 item 7), and nothing above depends on
it, because the index is rebuildable and the JSONL is the record. Which
command owns a device's index on Linux and macOS is implementation work
and is not named yet.

**Android UID isolation (looked up, 2026-08-14).** Termux (`com.termux`)
and tendcf-agent are different UIDs. The APK **cannot** read
`$PREFIX/...` as files. [RUN_COMMAND](https://github.com/termux/termux-app/wiki/RUN_COMMAND-Intent)
is a user-granted bridge with stdout via `PendingIntent`, not a log
directory. Therefore:

- tendcf-agent owns **both** JSONL and SQLite in **app-private storage**
  (D45, 2026-11-02, unchanged by any ruling; the B3 ruling "trust and
  consent only" is about decisions, so the thin Kotlin agent still writes
  the device JSONL and index as a support role: operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role"; map and D18
  stand).
- Either cf-agent runs as a native helper of the agent (same UID), or a
  Termux-side reporter **pushes** lines to the agent (localhost /
  ContentProvider). Never “agent opens Termux’s files.”
- [Room](https://developer.android.com/training/data-storage/room) /
  Android’s SQLite is the index path, not Termux `sqlite3`. Use
  `synchronous=FULL` if WAL is on; OEM freezers OOM-kill mid-commit.

Optional best-effort push of a subset into Vector / OpenObserve /
Grafana is never the record of truth. Fleet-wide yes/no questions query
reachable devices and treat the rest as unknown.

**Log archive (G8 state 1).** A device holding the `log-archive` role
receives other devices' JSONL rows, authenticated by device public key,
and appends them keyed by device public key and release stamp. Shipping
is retried, idempotent by row identity, and never blocks convergence.
The sending device's JSONL stays authoritative; the archive is an
authenticated copy. **SQLite index (D45 item 7), ruled:** the log archive
keeps a fleet-wide SQLite index over every device, **and** each device
keeps its own index; device JSONL stays authoritative (operator ruling,
2026-11-14, Smaller 6 REVISED, "make that both", option 3 "Both"; M-§8-01).
The earlier answer the same day, "2. Per-device indexes" (every device
its own index, the archive storing JSONL only), is superseded; it was
also not the reviewers' recommendation. The JSONL writer on macOS and on
Android is on the path to G8 state 1 (nothing writes report rows yet).
In state 1 the archive server is the macOS VM on bigmac (§12); it is
reachable only while bigmac is awake, so devices buffer JSONL until it is.
The `monitor` role (monitoring of other machines) is G8 state 2: state 1
needs only the log archive (operator ruling, 2026-11-14, B4 rider,
monitor role, "1. State 2"; G8.1).

Every row carries the release stamp. Each device records which release
it is converged to.

---

## 9. Releases, ChangePlan, TUF (D41, D42, D43, D44)

Configuration reaches devices only as a versioned, signed release. The
per-host payload of that release is the host’s **complete canonical goal
file**: one fully resolved JSON document describing the whole managed
state of that device. The **ChangePlan is the diff** between the goal
file the device has already approved and the one the release proposes,
and the on-device executor is a **validator** over that diff — it
compares two canonical documents against an approved diff and performs
no policy interpretation (**D43**).

**Model A is superseded.** The former text of this section — a closed
`capability` vocabulary, per-operation `resources`, and an executor that
“refuses any effect outside that set” — is withdrawn, together with the
vocabulary’s versioning and skew policy. CFEngine has no runtime
capability confinement, so that executor could only exist as a pre-flight
*interpreter* of the vocabulary plus a proof that the vocabulary
describes what the rendered policy actually does; neither artifact exists
nor is in budget. Authority: `e1-adjudication-xhigh-2026-08-15.md`, which
is final and supersedes `e1-adjudication-2026-08-15.md`. Section
references below of the form **E1 §5.x** are to that note.

The compiler (§5) therefore gains a **render** stage: merge → conflict
check → render of the complete per-host goal file. **Decided** (this
paragraph left open until the schema family landed; closed by
`goal-file-schema-reconciliation-2026-08-15.md` §9): the goal file and
the CFEngine Augments JSON (`def.json` / `host_specific.json`) are not
one document. The goal file is the signed wire artifact and the object
consent binds to; Augments JSON is produced from it by a **device-side
projection**, run after approval and before the cf-agent run that reads
it — by `tendcf-validate` on Linux and macOS, inside tendcf-agent on
Android (D45, §12) — and never appears on the wire. The projector's
target is `$(sys.workdir)/data/host_specific.json` and nothing else; its
output is
`{"vars": {…}}` with no sibling keys — no `variables`, no `classes`, no
`inputs`, no top-level `data`. `def.json` remains MPF glue under the
policy-tree digest (§9.8) and is never a per-host slot: 3.27.1 drops its
unknown keys silently, the worst of the candidate targets. A
compiler-shipped projection sibling, hash-bound on the approval record,
was considered and rejected — it reopens the approved-equals-applied gap
Model B exists to close, since no one *reviews* a hash-bound sibling the
way the goal-file diff is reviewed, and the projector must exist under
either option, so putting it device-side costs one implementation with
two call sites (`tendcf-validate`, invoked on the device and by CI for
golden tests; D45) rather than a second wire artifact, a per-host TUF
sibling target, and an approval-record hash extension. The Android
agent's Kotlin projector is a port held to the same golden bytes in CI
(residue R22), not a second normative source. The projector **MUST be
policy-free** — a structural re-keying only (entries → the generic
bundle's containers, tombstones → the negative-promise lists, trust
entries → the validator's own config, which is `device-trust` itself,
`projector-reconciliation-2026-08-16.md` C-3) — carried as residue R21;
any change that inspects entry *values* to decide output *structure* is
the interpreter returning and is a named §14.2 review target. `def.json`'s
own digest binding is unmoved (§9.8); `augments_digest` inside the goal
file stays rejected as circular.

### 9.1 Where the diff is computed (E1 §5.1)

- The **full canonical goal file MUST be the signed wire artifact.** The
  diff MUST NOT be shipped as the artifact: reconstructing
  `new = old + patch` on the device would make patch application a second
  interpreter, and would make the applied state derived rather than
  directly signed.
- The **authorizing diff MUST be computed device-side**, between the
  device’s currently-approved goal file and the received one. This is
  what makes the approved object equal the applied object at *any*
  staleness: a device seven releases behind briefs and approves the one
  true diff from its own signed baseline.
- The **compiler-side diff is a preview** — author review, CI regression
  artifact, cross-check. It MUST NOT be the object consent binds to.
- When the device’s baseline equals the release’s expected baseline, the
  device-computed diff MUST equal the compiler’s predicted diff.
  Inequality is a **reportable integrity flag**, never a silent
  condition.
- Consequence, accepted: the advisor round trip happens **after** device
  contact, and pre-generated briefings are previews rather than the
  consent object.
- **Baseline integrity is the root of the gate.** The stored approved
  goal file MUST be integrity-protected and its verification MUST be a
  validator precondition, ordered before the diff is computed. Corrupting
  or swapping it either denies service or launders arbitrary state
  through the baseline ceremony of §9.4.
- The accept binds per DC-2, instantiated for the goal file as an
  **approval record**, not a hash concatenation (corrected from this
  section's earlier formula
  `Sig_advisor( H(old_canonical) ‖ H(new_canonical) ‖ device_nonce [‖ H(briefing_bytes)] )`,
  whose optional briefing member was an encoding-ambiguity hazard — a
  variable-arity concatenation does not fix which bytes were signed when
  the optional member is absent; C-5, reconciliation §11). The signed
  object is the **JCS bytes of the approval record with the `signature`
  member removed**. The record carries: `schema_version`, `host` (the
  target key), `baseline_sha256` (absent only at first adoption, a named
  §14.2 review target), `proposed_sha256`, `nonce` (device-issued),
  `approval_seq` (monotonic, DC-2 single-use), optional
  `briefing_sha256`, `verdict` (`accept` | `reject` | `withdraw`),
  `refused` (hunk key-paths, present iff reject, annotation only),
  `ceremony_class` (`ordinary` | `privileged` | `baseline`, asserted by
  the approver and checked against the validator's own derived
  requirement, §9.8), and `signature`, valid for exactly one target key.
  The validator MUST recompute every hash. DC-2 applies in full:
  per-target validity, device nonce, monotonic-counter single use,
  persisted rejects.
- **Standing modes (ruled; implementation pending; a schema bump).**
  Operator ruling, 2026-11-14, B2, "3 but also the existance of standing
  wait for user and standing refusal": option 3 (a hold window, or an
  owner-enrolled standing approval, shown and refusable before apply; new
  approval-record shape without a per-change nonce, i.e. a schema bump),
  PLUS two further standing modes: a standing "wait for user" (hold until
  the owner answers) and a standing refusal. The record fields above
  describe the per-change shape, which stands until that bump lands. How
  the new shape sits with DC-2 is for the design review the schema bump
  requires (two frontier reviews), within the reading below (dropping any
  check other than the per-change nonce needs an operator ruling). **A reading of the ruling (L5, B2), not
  part of it (lead decision, PR 62 review):** a standing approval drops
  only the per-change nonce (DC-2's device nonce); it is signed by an
  owner-held trusted key and keeps B1's other content checks (signed by trusted
  keys, fresh, names this device) and the rest of DC-2 (per-target validity,
  monotonic-counter single use or high-water mark, persisted rejects); its
  ceremony class is still checked against the validator's derived requirement
  (§9.8); until the operator rules, a standing approval covers `ordinary`
  changes only; whether one may cover `privileged` or `baseline` changes is for
  the schema design review to propose and the operator to rule; it names its
  signer and algorithm only if X-trust-06 is adopted (proposed, not ruled);
  every standing mode (hold window, standing approval, standing "wait for
  user", standing refusal) is owner-enrolled and refusable, and none is a
  default; dropping any other check needs an operator ruling; the schema design
  review confirms the approval-record shape (AGENTS.md, Android item 5).

  **Erratum (2026-11-20, issue 64):** the operator ruled the questions this reading left open (operator rulings, 2026-11-19, issue 64 choosers): "3. Include all classes" (a standing mode may cover `ordinary`, `privileged` and `baseline` changes, each class enrolled separately and explicitly); "1. Reusable grant (Recommended)" (one grant covers many changes, with persistent per-device replay state for each application: reusable, never replayable); "1. Owner-enrolled trusted signers (Recommended)" (outside developer mode the owner may enroll any explicitly trusted signer within a stated scope, automation and organisational signers included); "1. Bind both fields (Recommended)" (X-trust-06 adopted: `signer` and `sig_alg` are in the signed bytes, must match the actual verification, and cannot create trust or enable an unapproved algorithm). So "covers `ordinary` changes only" and "only if X-trust-06 is adopted (proposed, not ruled)" are superseded, and "signed by an owner-held trusted key" now means the enrollment (signed by an `owner`-role key, R5); the changes it covers are signed by a signer the enrollment names. The rest of the reading stands. The shape is approval-record schema v7 (`schema/approval-record.schema.json`: `per-change`, `standing-enrollment` and `standing-application` records; the goal-file family moves to v7 together, the grouping decided at the schema design review, PR 62 review Q4 "1. Decide at design review"). Operator rulings, 2026-11-20, PR 75 review (the issue 64 schema review), recorded as "(operator ruling, 2026-11-20, PR 75 review)": R1 "1. Carve-out (Recommended)", R2 "1. One class per grant (Recommended)", R3 "1. Device nonce (Recommended)", R4 "1. Apply-without-yes modes (Recommended)", R5 "1. Role in goal file now (Recommended)", R6 "1. Ordinary only (Recommended)": standing grants never cover changes to the trust root, owner/advisor keys, covered-signer trust, the validator binary/version or grant replay state, and (R7 "1. Add to carve-out (Recommended)", operator ruling, 2026-11-20, PR 75 review) `policy-tree` changes (the carve-out covers goal-diff hunks, so it stays an enforcement-PR negative-list item, [frdminc/tendcf#76](https://github.com/frdminc/tendcf/issues/76)); one class per grant; an active enrollment carries a device-issued nonce (a revocation does not) and the replay store is rollback-protected, its loss voiding every grant on the host; `not_after` is required for standing approval and hold window; the key entries of the goal file carry a role (owner or covered-signer); developer mode is ordinary-only, needs at least the privileged ceremony and `not_after`. R8 "1. Separate PR after 75 (Recommended)" (operator ruling, 2026-11-20, PR 75 review): the issue 55 goal-file pattern fixes are out of PR 75, a separate small PR after it, "in the same v7 window (no extra bump)" (lead reading, not part of the ruling: sound only before any device adopts a v7 baseline, since one version means one acceptance set). R9 "1. Accept, disclose (Recommended)" (operator ruling, 2026-11-20, PR 75 review): a standing grant knowingly delegates root-equivalent authority to its covered signers, because a covered change may add or alter a service or interlock that runs as root; revocation and expiry stop only later applications and a pending hold, never what an earlier application installed; and because that authority is root-equivalent, a covered signer can also, through the code it installs, alter the trust root, the replay store, the validator and the clock, so the R1 carve-out and revocation bind the approval path and not such code, and a grant should be given only to a signer the owner would trust with root. So "revoke and deny always honoured" in the Smaller 1 text above means honoured as a record, not undone installs. R10 "1. Bind to enrollment (Recommended)" (operator ruling, 2026-11-20, PR 75 review): each application carries a required `enrollment_nonce` naming its enrollment instance, checked against the stored grant. Wording follow-up (issue 64): "a standing approval drops only the per-change nonce" reads "every standing mode that applies a change without a per-change yes (hold window, standing approval) drops only the per-change nonce", and an active enrollment carries its own device nonce (R3). Current wording: `AGENTS.md`, Android item 5.

- `cf-agent --simulate` remains an **optional human-facing confirmation**
  of actual-state delta, never a mechanism of the gate. File the upstream
  `--simulate-output=json` issue before Step 3 code.

### 9.2 Canonicalization and the shape of the diff (E1 §5.2)

Serialization noise is camouflage, so canonicalization is a consent
property, not a testing nicety.

- **Wire format is JSON.** YAML stays an authoring format for Site Model
  sources and never appears on the wire (D23’s parse/re-serialize/diff
  check was the symptom of why).
- **Canonical form is RFC 8785 (JCS)** plus the structural rules JCS does
  not give: every set-semantics collection is a **map keyed by identity**
  — entries addressed by the `(domain, kind, id)` key path, nested
  `domains → <domain> → <kind> → <id>` — rather than an array sorted by a
  schema-declared key (corrected from this section's earlier text:
  RFC 8785 orders object members by UTF-16 code units, so a
  `(domain, kind, id)`-sorted array needs its own comparator definition, a
  second ordering rule alongside JCS's that the corpus's own review caught
  disagreeing with it at a non-BMP boundary; a map has no second
  definition to get wrong, and duplicate-key rejection gives uniqueness
  from the parse itself instead of a separate lint rule — reconciliation
  §2.2, C-2). Two positional arrays survive where order is meaning
  (`command` argv, `pre_action.command`); one sorted string-set array
  (`verbs`, ascending code-point order) survives for when the peer-grant
  kind lands. Strings are NFC normalized; no floats anywhere in the goal
  file; **booleans are legal** — JCS gives them one canonical spelling,
  and forbidding them would only force a second spelling as `"true"` /
  `"false"` strings (C-3); signatures detached; and no nonces, timestamps,
  or other run-varying fields inside the diffed object.
- **The goal file is fully resolved and the schema defines no defaults.**
  Every meaningful field is present with its explicit value; authoring
  defaults are resolved by the compiler before render; empty collections
  are invalid, so omission is the only representation of “none.” One
  meaning therefore has exactly one byte representation, and a later
  change to an authoring default can never reinterpret an already-signed
  file.
- **Refuse, never normalize.** Validator and lint MUST reject any goal
  file that is not byte-identical to the canonicalization of itself.
- **The diff is structural, not textual.** Hunks are at **entry**
  granularity, addressed by the `(domain, kind, id)` key path, each
  carrying the full old and/or new entry. Field-level diffs are derived
  for display. A text diff of canonical bytes is a permitted rendering
  and never the authoritative object.

### 9.3 Accept is all-or-nothing (E1 §5.3)

- A **partial accept MUST NOT be applied.** The accept verb is
  all-or-nothing per proposal. No device applies a state the compiler did
  not render and conflict-check.
- The advisor MAY return a **refusal annotated with the hunks that drove
  it**. The proposer then withdraws the corresponding source-level
  changes, re-renders the complete goal file, re-runs the conflict check,
  and offers a new diff.
- **Dependency-grouped hunks are rejected** and MUST NOT carry apply
  semantics. A correct dependency relation over hunks needs exactly the
  global `provides`/`requires` knowledge the inference cut removed, and a
  wrong grouping silently produces an unchecked applied state. Grouping
  MAY exist later as a *display* aid in the preview layer only.
- Bundling is defeated by cheap counter-proposal, not by partial apply:
  refusal costs the proposer a re-render, not the person their patch. A
  proposer who re-offers an annotated-refused bundle creates exactly the
  record TC-19’s persistence rule exists to surface. The counter-proposal
  loop is itself a fatigue channel to watch.

### 9.4 The two total-diff events are baseline ceremonies (E1 §5.4)

First adoption and schema migration present a total diff. They are a
distinct consent class with their own rules, and what each may claim is
bounded rather than pretended-reviewed.

- **First adoption is governed by a minimal-claim rule.** The initial
  goal file, accepted at D41’s first-run fingerprint ceremony, MAY manage
  only the domains the operator explicitly enumerates at that ceremony.
  Every other domain enters as `not-yet-migrated`. Each later domain
  migration then arrives as an ordinary reviewable hunk set, and the
  `not-yet-migrated` backlog counter (§4.1; guide §11) doubles as the
  consent metric. The honest day-one goal file is small in **managed
  surface**, which is already the correct day-one state.
- **Schema migration MUST be semantics-preserving and mechanically
  checked.** A migration release is valid iff `diff(migrate(old), new)`
  is **empty** apart from the schema-version bump — a pure migration
  presents as a one-line reviewable change. Mixing migration and semantic
  change in one release is **forbidden**; split into two releases. The
  migration function ships in the validator update, which itself arrives
  as an ordinary diff under the old schema (§9.6).
- The approval record MUST carry a **ceremony class** — ordinary,
  privileged, or baseline — adequate to what is being approved.

### 9.5 Hunk attribution is a query, not a field (E1 §5.5)

Attribution (“which source layer produced this hunk”) **MUST NOT appear
in the authoritative format** — not day one, not later. Three independent
reasons, any one sufficient:

1. It is **impossible** where the authoritative diff is computed: under
   §9.1 the device computes it and the device has no source layers. In
   the compiler’s preview it is proposer-asserted provenance the device
   cannot verify — TC-07’s forgeable citation at the hunk level.
2. Provenance plumbed through merge and render is the origin-tracking
   machinery CUT-3 cut, returning at the value level.
3. Attribution stored in the canonical artifact makes semantically
   identical states byte-different when sources are refactored, breaking
   §9.2’s one-meaning-one-representation property.

What replaces it: render purity makes attribution **reconstructible on
demand**. A compiler-side `explain-hunk` tool re-renders with a candidate
source change reverted, diffs the renders, and subtracts; CI can
attribute a whole preview diff mechanically and checkably, against actual
renders rather than an assertion. Its output travels in the
preview/briefing channel as DC-3-labelled untrusted context. The tool is
due before the consent surface (Step 9). Fan-out fatigue is real and is
mitigated here plus by §9.3’s counter-proposal loop — not by a signed
field.

### 9.6 Schema version and unknown entry kinds: fail closed (E1 §5.6)

- The goal file carries a `schema_version`. Its contract is **stricter
  than** `common.schema.json`’s `contract_version` rule: *any* change to
  the entry-kind set, additive included, MUST bump the version, so that
  an old validator can tell from the version alone whether it can fully
  interpret the file.
- A validator that sees a version above its ceiling, or an entry kind it
  does not recognize, **MUST refuse the entire goal file** with a
  distinct reported reason; the device keeps converging on its last
  approved state. Refusal is a visible, reportable stall, not a brick.
- **Ignore-unknown is rejected outright.** An ignored unknown entry is an
  unreviewed change riding a reviewed diff — fail-open in exactly the
  sense the validator exists to prevent.
- Strandedness is prevented at the compiler, not the device: goal files
  are per-host, so the compiler MUST render each host’s file at the
  highest schema version that host’s **last-reported** validator supports.
  A long-dark device is rendered at its old version until it reports back.
  *Correction to E1 §5.6, which says the report rows already carry this:*
  they did not. `report-row.schema.json` carried `release` and
  `converged_release` but no validator version column, so the reported
  field was a **schema addition D44 requires**, not an existing property
  to read. It has since landed (checked 2026-11-02) as
  `device_convergence.schema_ceiling`, with an optional
  `validator_version`.
- A schema bump ships in **two phases**: first the validator update
  (`tendcf-validate` on Linux and macOS, tendcf-agent on Android; D45)
  as an ordinary diff under version N−1 — a privileged-region hunk, TC-25
  class — then the migration release under §9.4’s empty-diff rule. There
  is no separate release-lint phase-order check (cut from this section’s
  earlier text, C-6, reconciliation §5): "the compiler refuses to render
  version N for a host whose reported ceiling is < N" *is* the two-phase
  enforcement, in the one place the per-host knowledge already lives — a
  release-lint restatement would need the same report data and duplicate
  the same rule.

Cost, accepted: the compiler carries multi-version render ability for a
window and tracks per-host versions. The price is paid in one place
rather than as device-side leniency on every device.

**Ruled 2026-11-14 (schema).** (a) C-policy-01: "1. Bump to 6": a strict
narrowing of `pre_action.command` still bumps `schema_version`; same
version = same acceptance set (operator ruling, 2026-11-14,
C-policy-01 schema version). (b) C-policy-01 `contract_version`:
"1. Confirm `const: 2`": an exact pin, not a floor (operator ruling,
2026-11-14, C-policy-01 contract_version form). (a) and (b) are
**implemented**: the schema is at v6 (`"const": 6`, commit 83d7280) with
`contract_version` const 2, merged by PR 52 (merge 2c78680, 2026-11-14).
(c) The Android profile field (§12) rides the same bump as the `agent` id
change (§12 item 4; M-§12-05 item 4); the standing-modes record (§9.1) is
a schema bump too. Both are still pending and take **the next unused
schema version (v7 or later)**, never v6, which has shipped. Ruled: "the next unused version (v7 or later); grouping not
ruled; the schema design review (two frontier reviews) decides" (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"). Whether the profile/agent-id change and the
standing-modes record are one version, and which number each takes, is
that review's call.

**Erratum (2026-11-20, PR 75):** the schema design review decided it. v7 is the standing-modes record (§9.1: `record_kind`, the two standing kinds, and `signer`/`sig_alg` on every record, X-trust-06) plus the `role` on the goal file's `advisor-key` entries (operator ruling R5, 2026-11-20, PR 75 review, "1. Role in goal file now (Recommended)"). The goal-file family moved to v7 together, and v7 is **current**: the schema is at v7, not v6. The Android `profile` field and the agent-id change did not ride it and take **v8 or later**, never v7. Current wording: `AGENTS.md`, Android item 5, and `schema/approval-record.schema.json`.

**Amended 2026-11-13 (D46).** There is no device outside the operator's
own hosts to strand yet, so the
compiler renders only the current `schema_version`, and its older-version
rendering is removed when the compiler is restructured
([`plugin-layout.md`](plugin-layout.md) §4, §5). This section's design
stands and applies once the first device that is not an operator host
enrolls; the multi-version render returns with it.

### 9.7 Coverage travels in the goal file (E1 §5.7)

The goal-file schema **MUST include the per-domain coverage
declaration**, restated as a **single enum** —
`comprehensive` / `not-yet-migrated` / `deliberately-unmanaged` — never a
verbatim `$ref` of `common.schema.json#/$defs/domain_coverage` (§4.1):
that def carries a `default`, an optional boolean where
absent-vs-present-true is two spellings of one meaning, required free
prose, and if/then contradiction guards a single field does not need.
Same three meanings; the Site Model keeps its authoring shape; the
compiler resolves to the enum (corrected from this section’s earlier
text, which named the `$ref`; C-1, reconciliation §4.1). Entries nest
**inside** the domain envelope
(`domains → <domain> → {coverage, entries}`), so an entry without stated
coverage is unrepresentable and `deliberately-unmanaged`-with-entries is
a schema violation, not a lint finding.

The diff’s meaning depends on coverage, and there are **three** silence
classes, not two: silence in a `comprehensive` domain means “no change”;
silence in a `not-yet-migrated` domain means “not described”; and a
**domain absent from the map entirely is `undeclared`** — a third class
E1 §5.7 does not name, because the unbounded unknown cannot be
enumerated and declaring a domain is precisely the act of naming a
backlog item so it becomes countable (C-10, reconciliation §4.1).
Site-Model-declared domains all appear in every goal file, at minimum as
`not-yet-migrated`; a domain’s first appearance is itself a reviewable
`coverage_changes` item with `"old": "undeclared"`. Validator and
briefing MUST NOT let any two of the three read alike. A coverage
transition is itself a hunk, and reclassification to
`deliberately-unmanaged` (DC-37) is a distinct review class; the full
transition-to-ceremony derivation is §9.8.

Goal-file completeness is a **contract, not a given**: a diff over a
non-comprehensive domain proves nothing about what else changed on the
device.

### 9.8 Privileged regions, removals, fetched content

- **Privilege is validator-held, never proposer-set.** The diff format
  carries no privilege flags — those would be forgeable. The validator
  derives privilege from its own local list, whose floor is: trust
  policy, advisor keys, peer allowlist, policy-tree digest,
  validator binary and version (the `device-trust` `agent` entry; what it
  binds on Linux and macOS is open, §12 / D45), device resource policy,
  and `schema_version` itself. The approval record MUST carry a ceremony
  class adequate to the derived privilege (§9.4). Coverage transitions
  (§9.7) derive their ceremony class the same way — retreat is
  privileged, not forbidden, because forcing a stall or a lie is worse
  than a loud, reviewable step backward:

  | Coverage transition | Ceremony class |
  | --- | --- |
  | `undeclared` → `not-yet-migrated` or → `comprehensive` | ordinary (declaring / tightening) |
  | `not-yet-migrated` → `comprehensive` | ordinary (tightening) |
  | any transition **into** `deliberately-unmanaged` | privileged (DC-37 class) |
  | any transition **out of** `comprehensive` (incl. → `undeclared`) | privileged (retreat) |
  | any transition **out of** `deliberately-unmanaged` | privileged (reversing a deliberate decision) |

  One uniform rule the validator holds: a coverage transition is
  privileged iff it touches `deliberately-unmanaged` or leaves
  `comprehensive`. Retreats are counted next to Q11’s migration counter
  (reconciliation §4.3).
- **Removal is a state, not a diff-compiled actuation** (corrected from
  this section’s earlier text, which had the negative promise compile
  from the diff itself — read literally, that breaks convergence: the
  applied configuration becomes a function of the diff as well as the
  goal file, the diff has acquired apply semantics on the exact ground
  §9.1 refused to ship diffs on, and a one-shot imperative is lost by a
  crash, a re-run, or a stale device’s N−7 → N catch-up; C-4,
  reconciliation §6). Actuated entries carry `state: "present" |
  "absent"`. A removal is a **replace hunk** (`present → absent`) whose
  tombstone persists in the goal file, and the negative promise (file
  delete, package absent, `service_policy => "stop"`) renders from the
  **file**, not the diff — idempotent, crash-safe, re-release-safe,
  stale-catch-up-safe. A removal correctly *is* a modify of `state`; the
  real smuggling hazard is the **bare entry deletion**, which means “stop
  managing,” not “remove from device” — the briefing MUST render the two
  distinctly (“stops being managed; the thing REMAINS” vs “will be
  stopped and unloaded”). Tombstones are legal in `comprehensive`
  domains: there is no sweeper, only extra-entry *reporting*, so
  forbidding the tombstone there would leave a finished domain with no
  actuated removal path at all. Tombstone kinds are present-state kinds
  only (`service` in v1, plus `file`/`package` when they land);
  `interlock` and `unit-writer` are present-only, with no device-state
  footprint to tombstone — deleting one is an ordinary remove hunk the
  briefing renders as “guard removed” / “writer declaration dropped.” A
  dropped tombstone is itself a change (“stop enforcing absence”), silent
  in non-comprehensive domains; per-file tombstone count is a residue
  counter to watch beside diff-size (R19). Tombstone GC is a policy note,
  not a v1 feature.
- **Fetched content binds bytes, not names.** Digest fields on fetched
  artifacts (DC-11) are a schema obligation, covered by the accept and
  re-verified immediately before apply. The policy tree / generic bundle
  is code outside the goal file until the schema binds its digest as a
  privileged region; that is an obligation this design takes on, not a
  property it already has.

### 9.9 The schema family, and the gate on it

Three schemas, following the existing contract conventions (`$id`, draft
2020-12, schema/example pairing, negative fixtures, cross-file lint):
`schema/goal-file.schema.json`, `schema/goal-diff.schema.json`,
`schema/approval-record.schema.json`, with `.json` fixtures **in
canonical bytes** (the fixture is itself a canonicalization test). The
goal-diff schema carries no attribution fields, no group fields, and no
privilege flags — all three are derived. Lint gains `.json` example
pairing and a canonicalization-idempotence check.

**§14.2’s gate applies to this family with full force.** That clause
originally named the artifact by its Model A description and has been
restated; its function is unchanged and is what carries over — *the
artifact the executor enforces and the person consents over gets
independent adversarial review before build*. Write the schemas and
fixtures first, then run that review **on the contract, before the
validator is coded**, with a reviewer outside the lineage that wrote the
schemas.

### 9.10 What this does not fix

Model B improves what the person is shown; it does not change who authors
the machinery. These MUST NOT be presented as closed — the residue
register R1–R18 of `e1-adjudication-xhigh-2026-08-15.md` §7 is the
authority:

- Every control is still operator-authored, -delivered, and -evaluated.
  DC-1’s device-local trust root is untouched by this decision and is
  still required.
- **Effects versus declarations** (TC-23) is unsolved at this layer in
  either model; enclosure needs OS confinement and is out of scope.
- **The activation gap:** `--simulate` covers files and packages only.
  The “loaded and running” half of a service change is
  device-unconfirmable. This is a permanent honesty clause on
  device-computed confirmations.
- **Rollback** to a prior signed state fixes the *specification* problem,
  not the *reversibility* problem: a prior state is always well-defined
  as a target and not always achievable as a transition (package
  downgrades, data migrations).
- Per-host diffs hide fleet-level intent, and cross-entry transitions
  (a port moving between services) ride retry-until-stable and can
  transit conflicting intermediate states.

### 9.11 Signing and delivery (D41, D42)

Signing: [TUF](https://theupdateframework.io/) subset sized for one
operator (offline root 2-of-3, targets, snapshot, emergency). High-water
mark on every applying client. This layer authenticates the release; the
goal file, its diff, and the approval record are what authorize a change
to the device.

The 2-of-3 is a **floor**, and it is a parameter, not a runbook. Two
questions under it are open and belong to §14.4: whether a 2-of-3
ceremony held by one operator means anything if all three keys live on
the machine that also compiles and signs, and what the recovery path is
when a genuinely offline root is lost and every `consented` device
becomes unupdatable. DC-20 also asks for every root version to be
retained and served, a written out-of-band runbook, and a
machine-assisted fingerprint compare rather than an eyeball-hex one.
None of those is built. **Ruled first build (operator ruling, 2026-11-14,
B1, "1. Content checks; v0 first"):** SSH-signature v0, that is
`ssh-keygen -Y` over the goal-file bytes plus a counter; the 2-of-3
offline-root floor above may lag until TUF.

**First-run root (D41).** The [TUF spec](https://theupdateframework.github.io/specification/latest/)
assumes a good trusted `root.json` shipped with the updater, out of
band. TOFU is documented as an example in some clients; we do **not**
use it for consented devices. Install shows the root key IDs /
fingerprint; the person compares that to a channel they already trust
(operator, printed card, published fingerprint in site-shared). Later
root rotation is in-band (threshold of old **and** new keys). Threshold
compromise of root is again out of band.

**Emergency vs consent (D42).** Revocation, “do not apply releases signed
by K,” freeze detection, and high-water rejection **tighten** what may
run. They do not need a local yes. Installing new targets still does, on
`consented` devices. An optional enrolled policy “I pre-grant emergency
security patches from role E” may exist; **default off**.

Verifiable layer authorizes. Semantic layer (template-filled from the
goal file and diff fields; free prose must cite those fields, and travels
as DC-3-labelled untrusted text) briefs the advisor; never authorizes.
Under §9.1 the briefing is generated over the **device-computed** diff,
so a briefing produced at release time is a preview, not the object the
accept binds to.

Push: any host holding `deploy-origin`, to **operator** (and
operator-chosen `managed`) hosts. Push to a `consented` device still
requires that device’s consent grant. Pull: each host’s own schedule,
gated on timestamp role + quotas before it is autonomous.

**The handshake is content checks (D50).** G3's "correct cryptographic
handshake" means content checks: the goal file is signed by trusted keys,
is fresh, names this device, and carries the owner's approval. Transport
authentication decides only who may talk (operator ruling, 2026-11-14,
B1, "1. Content checks; v0 first"; B13 item 1, "1. Keep text; B1 is the
reading": goal text unchanged). Any device may relay a release; delivery
never authorizes.

### 9.12 The safety score (G4; operator rulings, 2026-11-14, B8)

What G4 adds to Model B. The scan **advises**: it never authorizes (the
device-computed diff, the approval record and the validator do). Ruled
(implementation pending; the full text is in
[`09-safety-score-and-tui.md`](../review-2026-11-13/09-safety-score-and-tui.md)
and M-§9-03):

- **A capped 0-100 score.** Operator ruling, 2026-11-14, B8, "1. Capped
  0-100 score": "score from 0 to 100"; mechanical checks set a ceiling
  that AI review can lower but never raise; an explanation of each part;
  a measured hit rate once a corpus exists (B13 wording 3, X-pm-03).
  This settles B13 items 2 and 3 (the G4 figure).
- **Values.** B8 sub 1, "1. 09's table, top 95": base 95, never 100;
  penalties, caps and bands are 09's table, fixed in the schema and
  changed only by a ruling (later backed by a labelled corpus). The table
  is in M-§9-03 and 09 (01 Idea 1, 09 Idea 1); it is not copied here.
  **One part is undecided:** the table's AI-reviewer deduction ("up to
  30") does not say whether 30 is the maximum per AI reviewer or the
  maximum in total across reviewers; this aggregation is "open: deferred
  to the schema design review (operator ruling, 2026-11-14, PR 62 review
  Q7)". Nothing here chooses either reading.
- **Owner-set auto-refuse floor.** B8 sub 2, "1. Allowed, off by
  default": an owner may set a floor; a bundle below it is refused
  automatically, logged, and the owner notified with the diff; no default
  floor; tighten-only (no score ever auto-accepts); the owner can
  re-request and accept a refused bundle (G-§7-01).
- **Build order, not scope.** B8 sub 3, "1. Build order, not scope": G4
  stays whole in state 1. The CLI diff and y/N is built first and used on
  the VM and dev devices before any TUI or score work; state 1 is
  declared only once score, explanation, highlighting and TUI land. No
  "state 1.5".
- **The authoring AI.** B8 sub 4, "2. Should not (as written)" (X-safety-06,
  also placed in §11): the scanning AI SHOULD NOT be the authoring model;
  it sees only the canonical diff as quoted data, never the author's
  prose; the diff is hostile input; two model families where the owner
  has them, and their disagreement caps the score (70). The same model is
  allowed with no extra cap.

---

## 10. Per-device trust (D38)

`trust_tier` is not the trust model. Full-mesh “every device has operator
root to every sibling” is **not** the product default. It is a
site-private policy some operator-tier labs may still choose. Our last
system did that; it is not tenable once devices belong to more than one
person.

Each device carries a **local trust policy** in its signed release
(authored in site-private). It does not phone home to ask.

| Axis | Question | Default |
| --- | --- | --- |
| **Release** | Whose signatures may change me? | Site TUF root enrolled at the first-run ceremony |
| **Consent** | Do I also need a local yes? | `operator`: no. `consented`: yes (advisor key). `managed`: operator-chosen |
| **Peer** | Who may act *on* me (ADB, SSH, peer-help)? | Nobody, unless listed. Prefer **groups** (“household helpers”) plus allowed verbs |
| **Attestation** | Whose “I applied this” counts for my advisor tools? | Only sets that person configured |
| **Secrets / cache** | Who may receive this secret or substitute this store path? | secretspec resolver; cache keys `operator` only |

Peer actions (§7) check the **target’s** peer allowlist, not only “the
helper has a capability.” Identity is the device public key.

A label in inventory does not enforce this. The executor does.

Web-of-trust thresholds (“50% of people I trust have installed this”)
live in the **advisor plug-in**, not in the executor.

---

## 11. The person’s own AI (D39)

We never run their model, see their prompt, or see the conversation. We
offer a change and accept a signed yes/no. Same shape as a
[Kubernetes admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/).

- At install they enroll an **advisor key** (or a local app/socket) in
  site-private.
- tendcf ships a **suggested default prompt** as a replaceable public
  file. They may append or replace it.
- Modes: auto-review, or a conversation with them first.
- Return path: `accept | reject | withdraw` (DC-5), signed by the
  enrolled key, bound to the baseline and proposed goal-file hashes and
  the device nonce (§9.1). A reject MAY carry the hunks that drove it;
  accept is all-or-nothing (§9.3). Timeout is deny. Advisor down → fail
  closed for *installs* (revocation still applies, §9). The owner's own
  enrolled alternatives to this default are the standing modes of §9.1
  (hold window or standing approval, standing "wait for user", standing
  refusal; operator ruling, 2026-11-14, B2).
- Custom tools (OpenPGP WoT, a transparency log, a chain, gossip of
  signed apply-attestations) are theirs. Deadlock among “everyone
  waiting for everyone else” is a separate project that consumes
  attestations. tendcf owes: the goal file and its diff (§9), optional
  exportable apply-attestations, the `accept | reject` slot.

Proposing side and consenting side are different programs. The advisor
never authorizes; the executor does, against the signed grant.

**The scanning AI is not the authoring AI** (operator ruling, 2026-11-14,
B8 sub 4, "2. Should not (as written)"; X-safety-06). The AI that scans a
change SHOULD NOT be the model that authored it, and sees only the
canonical diff as quoted data, never the author's prose. The diff is
hostile input to it. Two model families, where the owner has them, are
better than one; their disagreement caps the score (70). The same model is
allowed with no extra cap. (Self-preference bias: [arXiv
2404.13076](https://arxiv.org/abs/2404.13076), fetched and verified
2026-11-14; cited for self-preference bias only, not for anything about
code review.)

Personal branch: theirs, applied under their consent; never auto-merges
into anyone else’s trust domain. Upstream-heal is a suggestion their
agent evaluates.

---

## 12. Platforms

**macOS (adapter #1).** Services as CFEngine promises from `services.yml`
via the launchd adapter. Dry-run default. A Mac that already runs
nix-darwin keeps that configuration verbatim (passthrough, D12); whether
the primary workstation adopts nix-darwin is Step 7, gated on §14.1.
Unit-writers lint is the safety rail on a live daily driver. Runtime:
CFEngine + `tendcf-validate` (D45, below).

*Ruled 2026-11-14: state 1's Mac.* macOS is platform 1, as a server (D48).

- **Plain Mac, launchd by tendcf.** State 1's Mac has no nix-darwin;
  tendcf renders launchd; Nix is for authoring and building only
  (operator ruling, 2026-11-14, B6, "1. Plain Mac, launchd by tendcf").
- **Which Mac.** An Apple Silicon macOS VM (tart / Virtualization.framework)
  on bigmac (MacBookPro18,1): current macOS, snapshot/rollback, and CI can
  run the same image; it is a client, not an always-on server (operator
  ruling, 2026-11-14, B6 sub 1, "1. macOS VM on bigmac"; 13 E-2).
- **Image size.** The state-1 macOS VM image is minimised: start from the
  smallest base (vanilla, not a dev-tools image) and strip what tendcf's
  state 1 does not need (operator ruling, 2026-11-14, B6 sub 1 rider,
  "Try to cut down the MacOS VM image so be smaller, remove stuff we don't
  need."). Queued as build work: research the floor (what macOS can drop
  in a guest, e.g. tart vanilla vs base images).
- **May the daily driver enforce.** "1. Dry-run only": bigmac may run
  tendcf in dry-run (compute and report the diff, log drift, apply
  nothing); the VM is the only enforcing Mac in state 1 (operator ruling,
  2026-11-14, B6 sub 2, M-§12-01 / Q18). The VM is also the G8 log-archive
  server, reachable only while bigmac is awake; devices buffer JSONL (§8).
- **Root or user.** "1. Root in VM, user on bigmac": the enforcing VM runs
  tendcf as a root LaunchDaemon; bigmac's dry-run runs as a user
  LaunchAgent, no root (operator ruling, 2026-11-14, B6 sub 3, 13 E-2).
  State 1 must verify the root launchd render path, which the WarpBuild
  spike skipped.

**Android (adapter #2).** Same Site Model vocabulary. Runtime: Termux +
tendcf-agent (Kotlin, D45) + Shizuku-class helper + CFEngine. Agent owns
logs as a support role (§8, as D45 stands; operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role", see below). Peer actions cover devices that need external ADB help.

*Ruled 2026-11-14: Android (platform 2, client, D48).*

- **State 1 on Android:** "3. Termux CFEngine + thin Kotlin": Termux
  CFEngine fed tendcf projections; the Kotlin agent holds trust and
  consent only (operator ruling, 2026-11-14, B3; 05 Idea 4). That ruling
  decides the trust, consent and Termux split. It does not name who owns
  the Android JSONL log and SQLite index (§8, D18); operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role":
  "only" is about decisions; the thin Kotlin agent still writes the device
  JSONL and index as a support role; map and D18 stand.
- **Profile model.** "1. Field on entries": one host per phone (one key,
  baseline, review); each Android promise names its target user (`owner`,
  `work`, `private`) and the work profile's owner app (`island`,
  `insular`, `none`), per X-android-05's text; an unreachable profile
  reports `not_kept`. A `profile` field on entries is a schema bump, a
  design ruling with two frontier reviews; it rides the same bump as the
  `agent` id (§12 item 4; M-§12-05 item 4) (operator ruling, 2026-11-14,
  B3 sub 1, M-§12-04).
- **Validator on Android.** The single Python `tendcf-validate` runs in
  Termux; the Kotlin agent independently re-checks signature and
  high-water mark, keeps the trust anchor and the approval record in its
  own app-private storage, and shows consent; no full Kotlin port
  ("1. Termux + Kotlin trust check", B3 sub 2, M-§12-06; amends D45
  (1)-(2)).
- **Never a DPC slot.** tendcf never holds a DPC slot (profile owner or
  device owner); it works with Island/Insular through shell (`--user N`)
  and the owner app's API; an unreachable profile reports `not_kept`;
  tendcf never requires MDM enrolment ("1. Never", B3 sub 3,
  X-android-09).
- **Phone review surface.** "1. Native screen + Termux": one review
  document rendered three ways (CLI `--plain`/`--json`, Textual TUI
  including Termux/SSH, native screen in tendcf-agent); goldens hold all
  three; renderers compute nothing. The agent notification opens the
  native screen with Accept/Refuse; the Termux CLI/TUI is the operator's
  path. No answer = held; a refusal is logged ("1. Native screen +
  Termux", B3 sub 4, X-safety-08 / X-android-14; replaces the former
  Step 9 row, §13).
- **The public claim (G5).** "1. Keep G5; word public claim": G5 is
  unchanged; public docs use "we know of no other tool that converges an
  owner's own unrooted phone, including its Island/Insular work profile,
  from a signed goal file, without MDM enrollment or root" and state the
  developer-verification terms (ADB exempt; advanced flow one-day wait;
  limited distribution 20 vs 50 devices discrepancy) (operator ruling,
  2026-11-14, B9).

**Linux (adapter #3, adoptability keystone).** Stock distro; mise
toolchains + CFEngine everything else, plus `tendcf-validate` (D45,
below). Distro choice open until this step. *Ruled 2026-11-14:* under D48
Linux is platforms 4 and 5 (server, then client): "1. Order language":
Linux is later in the order, not paused (operator ruling, 2026-11-14, B4
rider, Linux). The pastebin canary stays the standing end-to-end proof:
"1. Keep it" (operator ruling, 2026-11-14, B4 rider, canary).

**NixOS / nix-darwin (passthrough).** The host's existing Nix
configuration, unchanged; tendcf supplies distribution, consent and
reporting around it ([`linux-targets.md`](linux-targets.md) §5, Step 8
there). First host: vps-primary.

**`tendcf-validate`: the device-side component off Android (D45,
operator ruling 2026-11-02; the name was chosen by the amending
session).** tendcf-agent exists only on Android. A Linux or
macOS host runs CFEngine plus `tendcf-validate`, a command and not a
daemon: it validates the approved goal file, writes the projection to
`$(sys.workdir)/data/host_specific.json` (§9), and exits. It runs to
completion before the cf-agent run that is to read that file. It cannot
run from inside a bundle, because CFEngine loads the file at start-up,
before any bundle runs (`LoadCMDBData`, called from
`GenericAgentDiscoverContext` in `libpromises/generic_agent.c`, the
start-up path cf-agent and cf-execd share). cf-execd reads the same file
for itself at start and at policy reload (`cf-execd.c`), so a projection
written inside `exec_command` reaches cf-agent at once and cf-execd one
reload later; harmless while the projection carries supervision vars
only (P-1). CFEngine caps the file at 5 MiB (`cmdb.c`
`HOST_SPECIFIC_DATA_MAX_SIZE`). The current Linux deployment runs
cf-execd and cf-agent as root and installs the projection as root-owned
mode 0600 in a root-owned work directory
(`deploy/linux/tendcf-install.sh`). Updating that destination requires
suitable privilege. D45 does not decide whether validation and
publication share one privileged process or where their privilege
boundary lies on each platform. The install location is also open; the
working assumption on Linux is the CFEngine tree (`/opt/tendcf`).
It is Python, `bin/projector.py` promoted, so the code CI's golden gate
runs is the code the host runs: one implementation on these platforms,
with nothing to drift. Each host needs `python3`; per the ruling, Debian
has it, NixOS gets it through the derivation, and macOS from a bundled
interpreter or the Command Line Tools. ~~On Android the Kotlin agent runs
the same validation and projection logic as a port, held byte-for-byte
to the same checked-in goldens in CI (residue R22 of
`projector-reconciliation-2026-08-16.md`, whose §9 placed the code)~~.
**Amended 2026-11-14 (D45 (1)-(2)):** on Android the single Python
`tendcf-validate` runs in Termux, and the Kotlin agent independently
re-checks signature and high-water mark, keeps the trust anchor and
approval record in app-private storage and shows consent; there is no
full Kotlin port of the validator (operator ruling, 2026-11-14, B3
sub 2, "1. Termux + Kotlin trust check"). The Python implementation is
the one normative source on every platform. It is
built after schema v5 lands (it has; the schema was at v6 and since 2026-11-20 is at v7, see the erratum at §9.6) and before any
further host is enforced (§13). Ruled exception (operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"): the §13 stage 1 macOS VM
may enforce a root `cf-execd` early, before `tendcf-validate` exists at
stage 4, as an explicit exception like pastebin's: canary only,
operator-authored data. The stage order is not changed. Nothing device-side runs today: pastebin's canary data is a
projection made in this repository by `bin/projector.py`, checked by
`deploy/linux/canary/check.py` and installed by
`tendcf-install.sh install --data`.

**Open, for the operator (D45 leaves these undecided; nothing in this
document decides them). Options and a recommendation per item, deciding
nothing:
[`tendcf-validate-proposal-2026-11-03.md`](tendcf-validate-proposal-2026-11-03.md).**

1. **Trigger.** What starts `tendcf-validate` ahead of cf-agent:
   cf-execd's `exec_command` (today `$(sys.cf_agent) -f
   $(sys.inputdir)/promises.cf`, written by `tendcf-install.sh`) running
   it first, or a step of its own; and whether it runs before every
   scheduled run or once per newly approved goal file. Neither scheduling
   choice by itself establishes §9's approved-equals-applied guarantee. A
   projection retained between runs needs an integrity check before use;
   running the command before every run also needs a defined handoff that
   ensures CFEngine consumes the projection that passed validation. Open
   are failure propagation, atomic publication, concurrent update/run
   ordering, and recovery if interrupted between approval-state
   persistence, projection publication and CFEngine launch. Timeout must
   not authorize the proposed change (§11). Whether an independently
   verified previous approved state continues to converge is a separate
   question. The scheduling and handoff design must preserve DC-2 without
   treating each convergence run as a new acceptance of the same
   single-use approval. CFEngine supplies no gate here: `LoadCMDBData`
   (`libpromises/cmdb.c`) checks only that the file is readable JSON, and
   a load failure is logged and the run continues
   (`libpromises/generic_agent.c`), so deleting or withholding the
   projection is not a demonstrated fail-closed launch protocol.
2. **What "validate" covers in the first build.** The goal file's schema,
   canonical bytes and version ceiling plus the projection's own checks,
   or the whole §9 validator (baseline integrity, device-computed diff,
   approval record and DC-2, ceremony class). Step 6 needs the latter;
   D45's timing (after schema v5, before any further host is enforced)
   does not say which the first build is.
3. **The rest of the device-side gate on Linux and macOS.** §9 and §11
   put the TUF fetch and high-water mark (§9.11), the local-yes exchange
   (§11), the stored baseline (§16 question 13) and device-authored state
   (residue R24) on the device without naming a component for Linux or
   macOS; D45 assigns none of them. Likewise who calls `--simulate-json`
   ([`upstream-overlay.md`](upstream-overlay.md) §2) and who checks the
   policy-tree digest before CFEngine is pointed at the tree
   ([`change-process.md`](change-process.md) §3), and who writes the
   `device_convergence` row whose required `schema_ceiling` the §9.6
   render rule reads; without a writer the two-phase rule has no per-host
   input on these platforms. "No daemon" does not preclude any of these
   being steps of `tendcf-validate` or a sibling command run by cf-execd
   or a timer: the question is assignment, not feasibility.
4. **The `device-trust` `agent` entry.** `goal-file.schema.json`
   (`agent_map`) fixes its id to `tendcf-agent` and calls it "the
   comparator/projector binary". On Linux and macOS: does the id change
   (a `schema_version` bump), and what does its `sha256` bind: the
   script, its installed tree, the `python3` it runs on (DC-11, §9.8)?
   The schema descriptions (`agent_map`, and `report-row.schema.json`'s
   header and `validator_version`) were amended to D45 on 2026-11-02;
   the wire identifier, enums and structure are unchanged.
   The existing TUF-target wording does not yet specify how it applies to
   the Python runtime. The operator must define which interpreter,
   standard-library and dependency bytes are covered by the accepted
   artifact and verified before apply, and which, if any, belong to an
   explicitly trusted host runtime outside that artifact. Pinning a
   version alone does not satisfy DC-11. R-S3-4's accidents-only model
   applies to the passthrough hard checks, not this consent gate. Timing:
   the schema is already at v6 (`"const": 6`, PR 52; v5 was the earlier
   state), so an id change costs the next unused schema version (v7
   or later; since 2026-11-20 v7 is taken, see the erratum at §9.6, so v8 or later) and a baseline ceremony per device. Ruled 2026-11-14 (B3 sub
   1, "1. Field on entries"): the schema bump for the Android `profile`
   field rides this agent-id bump (M-§12-05 item 4). Ruled (operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review"): the next unused version (v7 or later); grouping not ruled (whether the standing-modes record, §9.1, shares that
   version included); the schema design review (two frontier reviews) decides.
5. **The `rfc8785` dependency.** `bin/projector.py` declares the PyPI
   package `rfc8785` and runs under `uv run --script`; D45 names only
   `python3`. Vendor it, package it, or implement JCS in the command.
   Recommended for the implementation review, not settled by D45: invoke
   a trusted interpreter by absolute path in isolated mode (`-I`), with
   dependencies supplied from trusted installed locations. Define
   executable selection, import paths and dependency installation
   together; the privileged apply path must not resolve or download
   dependencies through `uv` at runtime. The complete arrangement must
   satisfy item 4's runtime trust boundary.
6. **Interpreter and prefix.** On macOS a bundled `python3` or the
   Command Line Tools' interpreter (D45 names both); the install prefix
   on every platform (`/opt/tendcf` is assumed on Linux, not ruled).
   Debian's standard task ships `python3`; a minimal or container image
   does not (CI's `debian:13` job installs it), so the install must
   declare the dependency. On the review machine,
   `/usr/bin/python3 --version` reports 3.9.6 (checked 2026-11-02), below
   `bin/projector.py`'s declared `requires-python = ">=3.11"`. This does
   not establish the version supplied by a CLT-only installation. Before
   choosing that deployment route, verify its interpreter and dependency
   compatibility; otherwise use a compatible bundled interpreter. Also
   open: the execution identity and privilege boundary for validation and
   projection publication on each platform.
7. **The SQLite index on Linux and macOS (§8, D18).** **Ruled
   2026-11-14** (Smaller 6 REVISED, "make that both", option 3 "Both";
   it supersedes the same day's "2. Per-device indexes"): the log archive
   keeps a fleet-wide SQLite index over every device, **and** each device
   keeps its own; device JSONL stays authoritative. What stays open is
   the owning command on a Linux or macOS device: `tendcf-validate` is
   not a daemon and CFEngine never opens SQLite.
8. **The v5 detector.** `schema-v5-dpkg-reconciliation-2026-11-02.md` R4
   left open whether tendcf-agent later takes over the Linux unit
   detector. D45 (1) closes that as posed: no tendcf-agent exists on
   Linux. Open is only whether any other component (`tendcf-validate` or
   a further command) ever takes it over from the policy bundle.

**Engine pin (B5).** "1. Keep fork; spike stock" (operator ruling,
2026-11-14, B5): the full fork pin on every platform, with the macOS fork
build in CI; run report 11's 2-3 day stock/Termux spike before deciding
the adopter path (options 2-4 of
[`11-engine-alternatives.md`](../review-2026-11-13/11-engine-alternatives.md)).
The spike is a spike-lane branch (never merged, §13).

Future classes (extension points, no build-out): OpenWrt; consented
iPhone/wearables that consume artifacts; firmware as Nix-built
artifacts; image-based appliances (RAUC / OSTree family).

Nix store: never a multi-host `NIX_STORE_DIR` (D20). Cache role is
`operator` only; NAR digests in the manifest (RT-05) — a floor for the
builder/cache when it lands at Step 10+, not a control that exists today.
The live, general form of that requirement is DC-11/§9.8: **every**
fetched artifact binds a digest, covered by the accept and re-verified
before apply.

---

## 13. Build order

**Order, ruled 2026-11-14.** Operator ruling, 2026-11-14, B4, "1. Adopt
D47-D50": the guide's build order
([`02-response-guide.md`](../review-2026-11-13/02-response-guide.md)
G-§18-02, "Build order from here") is the base, with this map's Step 0
(M-§13-01: merge, the D46 restructure, the ruled schema changes) and an
explicit macOS CI step folded in. Each stage leaves a coherent system and names
the G8 state it serves ([`00-goal-definition.md`](../review-2026-11-13/00-goal-definition.md)
G8). Not a schedule. Each state is reached in this order, but work toward
state 3 may start once state 1 holds (operator ruling, 2026-11-14, B13
item 4, "1. Adopt the clarification"). Linux is later in the order, not
paused ("1. Order language", B4 rider); the pastebin canary stays the
standing end-to-end proof ("1. Keep it", B4 rider); ordering inference
(D16) is deferred explicitly ("1. Defer explicitly", B4 rider).

| Stage | What | G8 |
| --- | --- | --- |
| 0 | Merge #42, then #41 (operator ruling, 2026-11-14, B11; historical: both merged 2026-11-14, #42 at acec5b5 and #41 at daa4530); the D46 restructure (`tendcf compile`, in-tree `plugins/`). The ruled schema changes: C-policy-01 (schema v6 with `contract_version` const 2) is done, merged by PR 52 (2c78680); the Android `profile` field with the `agent` id (§12 item 4) and the standing-modes approval record (§9.1) are still pending and take the next unused schema version (v7 or later); how they group is not ruled (§9.6; operator ruling, 2026-11-14, PR 62 review Q4, "1. Decide at design review": the next unused version (v7 or later), the schema design review of two frontier reviews decides). | 1 |
| 1 | **The fork on the Mac.** Build the pinned fork for macOS arm64 into `/opt/tendcf` in the state-1 macOS VM on bigmac (§12; minimised image); root LaunchDaemon `cf-execd`; one canary launchd service enforced; bigmac itself dry-run only, as a user LaunchAgent. Verify the root launchd render path. Ruled exception (operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"): this stage enforces a root `cf-execd` in the VM before `tendcf-validate` exists at stage 4 and the handshake at stage 5; D45 says the validator is built "before any further host is enforced", and the VM is an explicit, ruled exception like pastebin's canary: it may enforce early, canary only, operator-authored data. The order is not changed. | 1 |
| 2 | **macOS CI (explicit step).** A CI job builds the pinned fork on macOS and runs `tests/policy/run.sh`; the VM image is one CI can run. The WarpBuild spike (`spike/macos-check8-warp`, `warp-macos-26-arm64-12x`) is the first run. Historical: PR 52's merge waited on it (operator ruling, 2026-11-14, PR 52 gate 2); the run ("macOS check 8 spike (WarpBuild)", [run 43602684071](https://github.com/frdminc/tendcf/actions/runs/43602684071)) completed with conclusion success and PR 52 merged 2026-11-14 (2c78680). | 1 |
| 3 | **Nix authoring, minimal.** A module system with tendcf options for services, interlocks and roles, named after nix-darwin and NixOS where the meaning is the same (B7), evaluating to today's Site Model JSON; YAML twins stay as fixtures. | 1 |
| 4 | **`tendcf-validate`, first build, with the CLI review.** Stored, integrity-checked baseline; the device computes the diff; the CLI shows it and takes y/N; projection only after accept. Built first, and used on the VM and on dev devices before any TUI or score work (operator ruling, 2026-11-14, B8 sub 3, "1. Build order, not scope"). | 1 |
| 5 | **Signed releases and the handshake.** Content checks (§9.11); SSH-signature v0 first (B1), TUF later; any device may relay. | 1 |
| 6 | **Android client.** Termux CFEngine fed tendcf projections; the thin Kotlin agent (trust and consent only; it keeps the log and index as a support role: operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role", §8); `tendcf-validate` in Termux; runit services via termux-services; the `profile` field on entries; ShizukuPlus helper; the native review screen (§12). | 1 |
| 7 | **Peer actions and the archive.** The Mac starts ShizukuPlus over ADB when the phone cannot; JSONL capture on both devices (on Android the thin agent writes it as a support role: operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role", §8); the `log-archive` role on the VM, fleet-wide index (§8); the phone buffers while the VM sleeps. The `monitor` role is not here: state 2. | 1 |
| 8 | **Safety score, explanation, highlighting; then the TUI** (§9.12). State 1 is declared only once these land; G4 stays whole in state 1, and there is no "state 1.5". | 1 |
| 9 | Pull: every device self-updates from any peer; roles move by editing data; the `monitor` role (operator ruling, 2026-11-14, B4 rider, "1. State 2"). | 2 |
| 10 | macOS as client: the other Macs; nix-darwin passthrough (§14.1 for a workstation). | 2 |
| 11 | Extra-entry reporting per domain, so the `not-yet-migrated` count measures what is left. | 2 |
| 12 | Migrate the old stack's services one domain at a time, then retire it (`~/ops`). | 2 |
| 13 | Linux as server: the existing Debian host, canary to full. | 2 |
| 14 | Linux as client; NixOS and nix-darwin hosts as passthrough. | 2 |
| 15-16 | State 3: the publishable layer, install and first-run root ceremony a person with no admin skill can complete, the default advisor prompt, public docs; then the `consented` tier. From state 1 on, a clean machine with a fresh AI session that has only the public docs rehearses this in CI (operator ruling, 2026-11-14, B13 item 5, "1. Add the rehearsal sentence"). | 3 |
| later | Demand-driven: branch management (G9); ordering inference (D16, deferred explicitly); the builder/cache; APK provenance; web of trust as advisor tools; out-of-tree plugin discovery (D46, deferred). | later |

State 1 is reached when the Mac and the phone each converge from a
Nix-authored site, each refuses a release that fails the handshake and a
diff its owner refused, and both devices' logs are in the Mac's archive,
with stage 8 landed. Spike lane, tiered review and the docs freeze:
`AGENTS.md` standing rule 3 (operator ruling, 2026-11-14, B10).

**The earlier numbered steps** below are the names of pieces of work, kept
for their status notes and for the references to them elsewhere (this map,
`change-process.md`, `linux-targets.md`); the order is the stage table
above. The guide's own Steps 0-15
([`02-response-guide.md`](../review-2026-11-13/02-response-guide.md)
G-§18-02) keep macOS CI inside their Step 1, so guide Step 0 = stage 0,
guide Step 1 = stages 1-2, and guide Step n for n = 2 to 15 = stage n+1
(stages 3 to 16). Rough correspondence of the former steps: Step 1 = stages 1-2, Step 2 = stage 6, Step 3
(compiler) = built, stage 0, Steps 4-5 = stages 13-14, Step 6 = stages 4-5,
Step 7 = stage 10, Step 8 = stage 9, Step 9 = stage 8.

| Former step | What |
| --- | --- |
| 0 | Schemas in **tendcf** (`schema/`, `examples/`, `bin/schema_lint.py` — provides/requires, interlocks, comprehensive, report-row). Remaining: peer_actions, trust-policy shape, generic unit-writers, lookup stub, YAML canonicalize. Transcribe reality (`not-yet-migrated` is the correct day-one state). |
| 1 | macOS services adapter. Dry-run default. No nix-darwin. **Started** (`policy/tendcf_services.cf`, `222da45`: launchd present/absent and interlock refusal, verified against a real `cf-agent`; package/file promises, environment rendering, the unit-writer detector still open). 2026-10-29: the satisfied-interlock path had never opened (verdict class fixed in pass 1 before the check ran); the check moved to `tendcf_interlocks`, sequenced before `tendcf_services`, and `tests/policy/run.sh` proves both paths on Linux CI and the Mac. The CFEngine it was verified against is upstream plus the patch overlay (`overlay/`, [`upstream-overlay.md`](upstream-overlay.md)); Linux CI builds the full fork ([`linux-targets.md`](linux-targets.md)). **Ruled 2026-11-14:** the enforcing Mac in state 1 is the macOS VM on bigmac, not the daily driver (§12). |
| 2 | Android under the Site Model; Termux types; agent writes JSONL+SQLite as a support role (operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role", §8). ~~**Deferred** (operator, 2026-10-29): Linux comes first, see [`linux-targets.md`](linux-targets.md).~~ **Reversed 2026-11-13 (D48):** Android is platform 2; Linux is later in the order, not paused. Not started as code: the schema already carries a `termux` supervisor flavour (`services.schema.json`) and the `android-termux-services` domain fixture, but no adapter bundle, no agent, no JSONL/SQLite ownership. `frdminc/ShizukuTendCF` is the R4 helper (a tool fork), not this step. |
| 3 | Compiler (`tendcf compile`; ~~nix2cf~~): `buildfile` first, conflict, extra-entry, then inference (needs step 1 and a Linux systemd adapter; Android is deferred). **Unblocked** on 2026-10-29 by the operator's decision recorded on [#4](https://github.com/frdminc/tendcf/issues/4); `frdminc/nix2cf` had one compilation command, `buildfile`, plus the `eval-nix` evaluation hook. **Amended 2026-11-13 (D46):** the compiler moved into tendcf under `compiler/` (#45; `frdminc/nix2cf` archived) and the restructure splits it into plugins ([`plugin-layout.md`](plugin-layout.md)); ~~its `tendcf.lock` is specified in [`change-process.md`](change-process.md) §2~~ with schema and compiler in one repository there is no `tendcf.lock` (it was specified, never built). |
| 4 | Linux reference path on a stock distro. (Later in the order, not paused: D48.) |
| 5 | First real Linux host; prove roles are data. (Later in the order, not paused: D48.) |
| 6 | Signed releases, push-only; goal-file render + diff + on-device validator (§9). Operator hosts. The lockfile, release, rollback and CI-gate design is [`change-process.md`](change-process.md) (#2); the code is not written. On Linux and macOS the on-device validator is `tendcf-validate`, built after schema v5 lands and before any further host is enforced; how much of this step's validator its first build carries is open (D45, §12). |
| 7 | Mac substrate on the primary workstation (nix-darwin) if §14.1 says yes. The nix-darwin passthrough adapter itself is [`linux-targets.md`](linux-targets.md) Step 8 and does not wait on §14.1. |
| 8 | Pull / self-update. |
| 9 | Consent surface + default prompt + advisor slot. One review document rendered three ways: command line (`--plain`, `--json`), TUI (Textual; also under Termux and SSH), and a native screen in tendcf-agent. Renderers compute nothing; golden fixtures hold all three (operator ruling, 2026-11-14, B3 sub 4, "1. Native screen + Termux"; X-safety-08, which replaces this row's former text). |
| 10+ | Demand: builder/cache, APK provenance, WoT-as-advisor-tools, extracting the publishable layer when a second person runs it. |

Dry-run is the standing posture on the daily driver (the machine that
cannot easily be reimaged), bigmac; the state-1 VM is the only enforcing
Mac (§12). Reporting is an adoption requirement.

The §9.9 schema family and the §14.2 review of it **MUST** land before the
Step 6 validator (stage 4) is coded. Nothing else gates them — no fleet, no
compiler — so they may be written as soon as someone is free to write
them.

---

## 14. Premium-token residue

Cheap models execute this document everywhere except:

- **§14.1** nix-darwin on the Mac, yes or no (gates Step 7 only).
- **§14.2** The artifact the executor enforces and the person consents
  over. Under D43 that is the §9.9 schema family — goal file, goal diff,
  approval record — not the withdrawn capability vocabulary this clause
  originally named. Do not improvise. Independent adversarial review on
  the contract, before the validator is coded.
- **§14.3** Advisor/personal-branch loop + AI-in-the-loop red-team
  (prompt injection, poisoned model, semantic layer as injection).
- **§14.4** TUF-subset ceremony + recovery runbook, including the
  first-run fingerprint check.

If a cheap model hits one of these unresolved, it writes a question doc
and stops.

---

## 15. Decision register (current)

Older “superseded by” archaeology lives in
`deprecated/architecture-DEFINITIVE-v2.md`. This table is what holds now.

| # | Decision | Resolution |
| --- | --- | --- |
| D2 | Site Model formality | Schemas at Step 0; writer-lint immediate. |
| D6 | Nix on bare metal | No. Builds / dev shells / authoring language / passthrough where a host already runs NixOS or nix-darwin. Never the OS a stranger must install. **Amended 2026-11-14:** Nix may be required to build a release (operator ruling, 2026-11-14, B4 rider, Nix on release path, "2. Allow on release path"), scope "1. Build-time only": devices never need Nix at run time. |
| D8 | Trust layer | Build it, gated. ~~Sovereignty is the point.~~ **Superseded in wording 2026-11-14 by D47:** adoption is the aim and see-and-refuse (G4) is its safety mechanism; the trust layer stays, as G4's mechanism (operator ruling, 2026-11-14, Smaller 3 (M-§15-01), "1. Yes, supersede D8's wording"). |
| D10 | Task runner | `just` for humans; mise for toolchains. |
| D12 | Authoring frontend | **Amended 2026-10-29.** Two equal frontends, Nix modules and YAML, rendering to byte-identical goal files; a Nix-authored site runs on hosts without Nix. Existing NixOS/nix-darwin configurations are used verbatim (passthrough). JSON remains the wire format. [`linux-targets.md`](linux-targets.md) §5. **Amended 2026-11-13 (D46):** the Nix frontend is the compiler plugin `plugins/frontends/nix/` and carries the name `nix2cf`; the YAML frontend is `plugins/frontends/yaml/` (built in); a Guix frontend may follow. Not built yet ([`plugin-layout.md`](plugin-layout.md)). **Amended 2026-11-13 (D46 (9), issue #48):** every Nix evaluation runs under restricted evaluation with no import-from-derivation, an empty `allowed-uris` and no network, and recipes from other sites are imported, pinned and scanned before compile; a Guix frontend waits for a sandbox design of its own (all planned). **Amended 2026-11-14 (D49):** Nix is first, not one of two equals: "Real Nix first, YAML beneath."; whether the byte-identical YAML twin stays as the frontend's test is open (D49). |
| D13 | Service owner | CFEngine promises everywhere; mise toolchains only. |
| D14 | Deployment shape | Git-synced policy; `cf-serverd` on every host; push and pull are one mechanism. **Amended 2026-11-14 (D50):** a device takes updates from any peer that completes the content-check handshake (§9.11); delivery never authorizes. |
| D15 | Compile target | CFEngine Augments, not freehand `.cf`. (By way of the per-host goal file, which the device projects to Augments after approval: D43, D44, §5, §9.) |
| D16 | Ordering | No Puppet catalog. Inference + fixpoint + authored `depends_on`. Interlocks. Default-on comprehensiveness. **Ordering inference deferred explicitly, 2026-11-14:** operator ruling, 2026-11-14, B4 rider, D16, "1. Defer explicitly"; it is demand-driven (§13, "later"; G-§10-01), and the rest of D16 stands. |
| D17 | ncf | Vendor generic methods as a reference corpus; strip Rudder reporting. |
| D18 | Local record | ~~JSONL is the durable capture; SQLite in tendcf-agent is the index. On Android the agent owns both in app-private storage.~~ **Amended 2026-11-02 by D45:** JSONL is the durable capture; SQLite is the index, rebuildable from it. On Android tendcf-agent owns both in app-private storage. On Linux and macOS there is no agent, and the index's owner there is open (§8, §12). **Amended 2026-11-14 (Smaller 6 REVISED, "make that both"):** every device keeps its own SQLite index over its own JSONL, **and** the log archive keeps a fleet-wide SQLite index over every device; device JSONL stays authoritative (§8, §12 item 7). The owning command on a Linux or macOS device is not yet named. **Android ownership of the log and index:** operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role": "only" is about decisions; the thin Kotlin agent still writes the device JSONL and index as a support role; map and D18 stand. The B3 ruling decides only trust, consent and Termux CFEngine (§12). |
| D19 | Composition | Private-site lockfile pins inputs (DAG). Signed release is the deploy artifact. No sibling-repo tag lockstep. |
| D20 | Nix store locality | Single writer per host. |
| D21 | Schema home | **tendcf** owns schemas/types. ~~nix2cf is the compiler.~~ **Amended 2026-11-13 (D46):** the compiler also lives in tendcf (`compiler/`, command `tendcf compile`); schemas stay in `schema/`, outside the compiler's code, and the two live under one pin and change in separate commits whenever a change touches `tools/`, `schema/` or the projector (D46 (9d), operator rulings 20 and 21). `nix2cf` names the Nix frontend plugin. |
| D22 | Platform sequence | ~~macOS, Linux. Android deferred by the operator on 2026-10-29 ([`linux-targets.md`](linux-targets.md)).~~ **Superseded 2026-11-13 by D48** (ruled 2026-11-14, B4, "1. Adopt D47-D50"). |
| D23 | YAML canonicalize | Parse, re-serialize, diff on the YAML path. |
| D24 / D40 | Lookup + auto-provide | Registry/token CLI; default `service:<name>`; compile errors teach names. |
| D25 | Schema/example pairing | Lint fails if unpaired. |
| D26 | Root AGENTS.md | Not on a performance rationale. Discoverability-only if ever added, hand-written. |
| D27 | This file | ~~Edit protection via `Approved-change:` trailer.~~ **Reversed 2026-08-15:** every document here is mutable; no approval ceremony. Rationale: pre-mortem N9 / synthesis DC-44 — a trailer gate whose approver is the author makes changing your mind expensive, which is wrong for a design carrying open questions. |
| D28 | Guardrail weight | Existence checks for the large IaC error class; extra entries for omission; schema for the tiny syntax class. |
| D29 | Semantic layer | Template-fill from the goal file and diff fields; free prose cites those fields and travels as DC-3-labelled untrusted text. Briefs; never authorizes. |
| D30 | `.cf` escape hatch | Prefer a grammar before lint-only, when that surface is exercised. Re-scoped by D43: goal-file coverage is closed by construction, so the *escape-hatch pressure* the capability vocabulary created is gone; what remains is the policy tree as code outside the goal file until the schema binds its digest as a privileged region (§9.8). |
| D31 | Front or back | Critical fields at start or end of agent-facing artifacts. |
| D32 | Compiler prior art | Mechanism common; Site Model → CFEngine is the pairing, not a novel compiler mechanism. |
| D33 | No control node | Promise Theory’s; GitOps is the closest shape. |
| D34 | Repo layers | tendcf / site-shared / site-private / foreign / optional tool forks. Conflict-as-error; private binds. |
| D35 | Inventory | Private by default; kinds, templates, explicit exports may be shared. |
| D36 | Supervisors | Generic; launchd is one adapter. See §6. |
| D37 | Peer actions | Typed cross-machine help; local stall; no distributed lock; FSM is a view. |
| D38 | Trust | Per-device policy, several axes. Full mesh is a site choice. Executor enforces. |
| D39 | Advisor | Their AI, their key, our slot. Default prompt replaceable. |
| D41 | TUF bootstrap | Ceremony + fingerprint; not TOFU on consented devices. |
| D42 | Emergency | Restrictive metadata without consent; new installs still gated. |
| D43 | ChangePlan model | ~~Model A: a closed `capability` vocabulary per operation, executor refuses effects outside the declared set.~~ **Superseded 2026-08-15 by Model B** (synthesis finding E1, adjudicated in `e1-adjudication-xhigh-2026-08-15.md`, which is final and supersedes `e1-adjudication-2026-08-15.md`): the wire artifact is the complete canonical per-host **goal file**; the ChangePlan is the **diff** against the device’s approved baseline; the executor is a **validator** over that diff, not an interpreter. Rationale: CFEngine has no runtime capability confinement, so Model A’s executor requires an interpreter plus a vocabulary-to-policy correspondence proof that does not exist and is not in budget; and coverage closes by construction when compiler and validator share one schema. The vocabulary, its versioning, and its skew policy are dropped. See §9. |
| D44 | Goal-file schema family | The consent artifact is three paired schemas (goal file, goal diff, approval record) with canonical-byte fixtures. Binding sub-decisions, all from E1 §5 and normative in §9: diff computed **device-side**, full file on the wire, compiler diff is preview (§9.1 / E1 §5.1); RFC 8785 canonical JSON, no defaults, no empty collections, refuse-never-normalize, entry-granular structural hunks (§9.2 / E1 §5.2); accept is all-or-nothing, refusal annotated, no dependency groups (§9.3 / E1 §5.3); first adoption and schema migration are bounded **baseline ceremonies**, migration must diff to empty (§9.4 / E1 §5.4); hunk attribution is **excluded from the format** — impossible device-side — and replaced by an `explain-hunk` query (§9.5 / E1 §5.5); `schema_version` fails closed on unknown kinds, strandedness prevented at the compiler, two-phase bumps (§9.6 / E1 §5.6); per-domain coverage travels **in** the goal file (§9.7 / E1 §5.7). §14.2’s pre-build review applies to this family. |
| D45 | Device-side component per platform | **Operator, 2026-11-02.** (1) tendcf-agent is **Android-only**, written in Kotlin. A Linux or macOS host runs CFEngine plus "a small validate-and-project command" (the ruling's words; the name **`tendcf-validate`** was chosen by the amending session on 2026-11-02 and may change without reopening the ruling), run before cf-agent reads `host_specific.json`; no daemon. (2) `tendcf-validate` is Python, the promotion of `bin/projector.py`: one implementation, so no byte-identity drift on those platforms. It needs `python3` on each host (Debian ships it, NixOS through the derivation, macOS bundled or the Command Line Tools). ~~The Android agent's Kotlin projector is a port held to the same golden bytes in CI (residue R22), not a second normative source.~~ (3) Built after schema v5 lands, before any further host is enforced (exception: the stage 1 macOS VM may enforce early, canary only, operator-authored data, like pastebin's; operator ruling, 2026-11-14, PR 62 review Q1, "2. Exception for the VM"; §12, §13). **Supersedes** every reading that ran the validator, the projector or the SQLite index inside tendcf-agent on every host: the §1 diagram's "CFEngine + tendcf-agent" per device, §8's index owner and D18 as written, §9's "run inside tendcf-agent" and "the agent binary" as the projector's call site, `goal-file-schema-reconciliation-2026-08-15.md` §0 item 7, §9 and §13 ("CI invokes the agent's own projector"), and `projector-reconciliation-2026-08-16.md` §9 and R22 ("tendcf-agent must reproduce" the reference). Not decided by it, and open for the operator: §12's list. **Amended 2026-11-14 ((1)-(2) and item 7):** (1)-(2) on Android the single Python `tendcf-validate` runs in Termux; the Kotlin agent independently re-checks the signature and the high-water mark, keeps the trust anchor and the approval record in its own app-private storage, and shows consent; there is no full Kotlin port of the validator (operator ruling, 2026-11-14, B3 sub 2 (Q21 / M-§12-06), "1. Termux + Kotlin trust check"). Item 7 (the SQLite index): every device keeps its own index **and** the log archive keeps a fleet-wide one; device JSONL stays authoritative; this was revised the same day from "2. Per-device indexes" to option 3 "Both" ("make that both") (operator ruling, 2026-11-14, Smaller 6 / M-§8-01; §8, §12 item 7). |
| D46 | Repository layout and compiler plugins | **Operator, 2026-11-13.** (1) `frdminc/nix2cf` folds into tendcf with full history, first under `compiler/` ([#45](https://github.com/frdminc/tendcf/pull/45)), and is archived as soon as that import merges. Both done 2026-11-13 (merge commit `ca4fa90`; the repository archived the same day). (2) The repository takes the plugin-type layout of [`plugin-layout.md`](plugin-layout.md): `schema/`, `examples/`, `policy/`, `overlay/`, `deploy/` unchanged; `tools/` (was `bin/`); `compiler/` (merge, conflict check, render); `plugins/frontends/` (`yaml`, `nix`, later `guix`, an authoring frontend), `plugins/supervisors/` (`launchd`, `systemd`, `runit`), `plugins/importers/` (`ansible`, `salt`); `contrib/` for in-tree third-party frontends and importers. It becomes one Python package, import name `tendcf`. (3) ~~Third-party frontends and importers are found through the public entry-point groups `tendcf.frontends` and `tendcf.importers`, so they can live out of tree as a pip package;~~ (deferred, see the amendment at the end of this row) plugins in this repository are found through a static import table, never entry points (9a). Supervisor renderers are in tree only; there is no public `tendcf.supervisors` group, because the goal file's `unit` is a closed `oneOf` and an out-of-tree renderer could only shadow a built-in. (4) Plugins are compile-time only: none runs on a device. The device artifact (`tendcf-validate`, D45) is built from the validator's own source alone, never imports `compiler/`, `plugins/` or `contrib/` and never calls entry-point discovery; the schema lint and the projector never import the compiler; a CI import check is to enforce both (planned). Plugins are trusted build-time code that the operator explicitly allows, not sandboxed: a plugin cannot make a device accept anything that device's own diff does not show (on Linux and macOS that validation is `tendcf-validate`, planned, D45, and does not exist yet; the Android agent was not checked), and cannot emit a shape the schema forbids, but it can make the goal file say something other than what the Site Model says, and it sees the site's private data. Release gates (schema lint, projector, preview diff) and signing are to run in a separate environment with no plugin installed, and the compile step is to hold no signing key (planned, Step 6; nothing enforces this today, and amendment (9) says what the environment is). A compile-side preview diff or `explain-hunk` (D44) is compiler output and inherits the plugins' trust. `contrib/`'s lower bar waives support and maintenance promises, never the standing review rule. Out-of-tree trust establishment and plugin management: [#47](https://github.com/frdminc/tendcf/issues/47). (5) Activation (the loader is planned, restructure step 4): a plugin is selected only if site-private names it (name → distribution, version, hash); an installed but unnamed plugin is not selected (installing a package can still run code, amendment (9)); a duplicate name in a group is a compile error; built-in names are reserved; until out-of-tree pinning exists (#47) a release build loads in-tree plugins only; the release's `targets.json` `custom` records the plugin set. (6) No users and no backward compatibility yet, so no shims: the compiler's command becomes `tendcf compile`, which replaces `nix2cf buildfile` with no alias (it compiles every host; `--host` renders one); `eval-nix` moves to the Nix frontend; `bin/` → `tools/` leaves no symlink or wrapper and rewrites every path reference in every file, dated records included (djbclark, 2026-11-13, a one-time exception to their append-only convention; only paths change, and prose naming nix2cf as the old repository stays as history); `nix2cf` names the Nix frontend (D12). The compiler renders only the current `schema_version`; older-version rendering is removed in the restructure, and §9.6's ceiling design applies once the first device that is not an operator host enrolls. (7) The keys `nix2cf_services` and `nix2cf_edges` were only ever illustrative: they occurred in guide §16.A's preview-channel example and its copy in the paper, and no schema, fixture, projector or bundle carried them (the projection's keys are `tendcf_service` and `tendcf_interlock`). In the same change that recorded this decision they were renamed `preview_services` and `preview_edges` (illustrative only, chosen so they cannot be mistaken for the `tendcf_services` bundle or the real projected keys `tendcf_service`/`tendcf_interlock`). No schema change is involved ([`plugin-layout.md`](plugin-layout.md) §6). (8) Consequence for [`change-process.md`](change-process.md): the compiler is no longer a separately pinned input, the two-repository bump order and the compiler's `tendcf.lock` go away; `site.lock` loses only its `nix2cf` entry. One tendcf rev is the unit a site pins, so a compiler fix brings the `schema/` and `policy/` commits before it; accepted, with no maintenance-branch machinery, revisited when the first device that is not an operator host enrolls. Moving `bin/` to `tools/` and the plugin split wait until open PRs #41 and #42 merge (historical: both merged 2026-11-14, #42 at acec5b5 and #41 at daa4530). (9) **Amended 2026-11-13 ([issue #48](https://github.com/frdminc/tendcf/issues/48), the adversary review of this decision; operator decisions D-a to D-d recorded in [its comment](https://github.com/frdminc/tendcf/issues/48#issuecomment-6857866487); full text in [`plugin-layout.md`](plugin-layout.md) §4). Nothing below is built; each part is tagged with its step.** (a) **In-tree proof (D-a), planned with the loader:** a plugin is in-tree when its module's realpath sits under the gate-1-verified tendcf tree, checked before the module's code runs (a release build runs the compiler from that tree without installing it); every in-tree plugin (frontends, supervisors, importers) is found through a static import table, never through entry points, which are read only for third-party plugins after #47: list every one without deduplication by name, refuse duplicate names and every entry point that claims a reserved name, whatever its distribution name, load only the named ones; release builds never resolve `tendcf` from a package index; a release build pins or refuses `TENDCF_DIR`. This replaces the first sentence of (3) for in-tree plugins: only third-party plugins use the public groups. (b) **Frontend inputs are code (D-b), planned, Step 6:** external (site-shared or foreign) recipes are imported, never fetched at compile time; the import pins by content digest, runs a static scan and an AI review, and records the verdict with the pin; compile evaluates only pinned recipes with an accepting verdict bound to the digest and fails closed on a failed scan, a rejecting review or a missing or mismatched verdict (the no-AI setting never overrides a negative result; only the gate-5 ceremony marker does, recorded with the pin and shown in every later gate-5 review; the recorded verdict is advisory, because job B′ re-runs the static scan and the AI review on the pinned digest and fails on a negative result), and a site-shared or foreign `site.lock` input is not an import by being pinned; every Nix evaluation, the site's own included, runs under `restrict-eval` with import-from-derivation off, an empty `allowed-uris`, no unsafe native code and no network, with the whole directory tree that the import digested and scanned passed to `-I` and nothing wider (the import refuses a symlink that resolves outside it); `pure-eval` is not used because it cannot evaluate a file named on the command line (tested 2026-11-13 on Nix 2.35.6 in CI, [run 43483740436](https://github.com/frdminc/tendcf/actions/runs/43483740436): the positive recipe evaluates, and file reads outside the recipe (a symlink escape, `readDir` and `builtins.path` included), `fetchurl`, `fetchTarball`, a local `fetchGit`, a `<nixpkgs>` lookup and `builtins.exec` are each refused, each flag shown by relaxing it alone, while `getEnv` returns the empty string; the import-from-derivation flag is the layer that refuses it (on a fresh store the read-only `--eval` stops it first, with a store-state-specific message) and was proven with `--read-write-mode`; the exact command and what stays untested are in `plugin-layout.md` §4); no Guix frontend until it has a sandbox design of its own; with no AI reachable at import the static scan still runs and `external_import.without_ai` (`require-human-ack` by default, or `warn`, or `refuse`) decides, for the import step only (job B′ still requires an AI review, or the ceremony override, before anything is signed), set in the site-private file that names plugins. (c) **Separate environment (D-c), planned, Step 6:** interim, a separate Unix user on the builder holds the key and the gate tools; the default before the first real release is a two-job split (job A on a throwaway runner with no secrets compiles, runs gate 2 and uploads goal-file bytes plus a digest manifest; job B in a protected signing environment builds the gate tools from the previous release's tendcf pin, never the pin under test (the first release uses the tip of the protected branch the trust root declares, resolved once by job B′ and bound to the approval), with hash-locked dependencies, installs no `tendcf`, runs gates 3 to 5 and signs exactly the digests it checked; job B′ is job B without the key, runs gates 3 to 5 for pull requests so that the reviewed preview is computed outside the plugins); signers in the first real release are one of n (operator rulings, 2026-11-13): the CI key held as a GitHub environment secret, which alone suffices; hardware tokens, optional, at least two if any is enrolled; and the separate Unix user, opt-in and non-default, whose enrolment lowers every release to its level; each enrolled signer signs alone (`vps-hub` and the Hyades podman runner are not signers); both token paths normally sign only the approved pull request's job A digests (merged tree equal to the approved head), path 1 after verifying a passing job B′ run and path 2 after re-running gates 3 to 5 itself with the previous release's gate tools, hash-locked, and `targets.json` `custom` records which; a break-glass route with no merged pull request is allowed, privileged and recorded there too, and is one person's act, bounded only by the threshold-one trust in that signer (ruling 19); job A's egress is unrestricted for now, a stated exfiltration risk left open in `plugin-layout.md` §7. (d) **Signed is what was reviewed (D-d), planned, Step 6:** the pull request's own job A artifacts, previewed by job B′, are what reviewers approve (the approval is bound to head commit, job A run, manifest, preview and baseline release) and what merge signs when the merged tree equals the approved head tree and nothing bound changed (otherwise the gates run and are reviewed again); branch protection on site-private; a changed pin `url`, a pin that does not descend from the previous one and a changed plugin set (the operator's list), and a tendcf bump that changes `tools/`, `schema/` or the projector (issue #48's fixes; such a bump ships as its own release with unchanged data, because the gate tools come from the previous release's pin, ruling 18; a planned tendcf CI check fails a commit that changes `tools/`, `schema/` or the projector together with the compiler goldens or with `policy/`, rulings 20 and 21) need the gate-5 ceremony marker, and so do (operator rulings) a new `site.lock` input, the files the gate jobs run, CI workflow and signer configuration, a signer backend change and a lowered `external_import.without_ai`; the tendcf pin's `url` and `ref` must be what the site's trust root declares (default `frdminc/tendcf` and `master`, or a listed release-branch set, each with required review, no force-push, no deletion and no administrator bypass), any other ref is refused, and a site may declare its own tendcf repository and branch set in its trust root, a privileged change that no per-pull-request marker substitutes for, and gate 1 reads the trust root from the protected base, never from the pull request, so one pull request cannot both change it and move the pin; a backward pin move across a `schema_version` bump is forbidden (roll forward) and within one version is privileged; for a pull request that changes a pin `url` or the plugin set, adds a `site.lock` input or changes the trust-root declaration, job A does not run until the marker is present; the marker must be an attestation the author cannot produce, bound to one head and the named changes, and verified by jobs B′ and B from definitions outside the pull request, and the approval record is produced by job B′ and verified by job B (mechanisms open, `plugin-layout.md` §7); a break-glass route and a change of the trust-root declaration are also privileged; until built the preview diff is advisory. (e) **Statements corrected:** the claim that installing a package activates nothing was false (`.pth` files run when the interpreter starts and sdist build backends run at install time), so rule (5) says an unnamed plugin is "not selected"; hashes are to be checked at install time from a hash-locked, wheels-only resolution, plugin dependency closures pinned and the gate tools' dependencies locked; a plugin or recipe can copy one host's private data into another host's goal file and nothing in gates 3 to 5 checks that yet (planned: the projection lint checks for values from other hosts' slices; each host reads only its own goal files from the release store, by a per-host path and credential, while the operator and the signing job read all); folding the compiler in removed the producer/checker independence, listed as a cost in [`change-process.md`](change-process.md) §9; importers follow the naming and pinning rules of frontends, and gate 5 compares the plugin set with the previous release's. Amends D12, D15 (a pointer), D21, §1, §3, §5, §9.6 (when it applies) and Step 3. **Amended 2026-11-14 (operator ruling, 2026-11-14, Smaller 5 (D46 out-of-tree plugin entry points, G-§4-01 / map Step 0, v2 C3), "1. Defer out-of-tree discovery"):** all plugins live in tree, compile-time only, never on a device; Python entry-point discovery of out-of-tree plugins is deferred until a user needs one and out-of-tree plugins can be pinned. The public entry-point groups of (3) are not built until then. |
| D47 | Goal | **Operator, 2026-11-13.** The goal is G1–G9 of [`../review-2026-11-13/00-goal-definition.md`](../review-2026-11-13/00-goal-definition.md), as its rulings table records: primary aim "Adoptable tool" (row 1); first adopter "Nobody named yet." (row 2); finish line "The ladder of three states in G8" (row 7); wording "Agreed, with two changes to the draft", framing "focus on the user's freedom to control their own computing devices as they see fit", and "G9 added" (row 8). Adoption is the aim and see-and-refuse (G4) is its safety mechanism; this supersedes D8's "Sovereignty is the point" (the trust layer stays, as G4's mechanism) and §0 items 1 and 3. **Ruled 2026-11-14:** operator ruling, 2026-11-14, Smaller 3 (M-§15-01), "1. Yes, supersede D8's wording"; adopted with D48-D50, B4, "1. Adopt D47-D50". |
| D48 | Platform sequence | **Operator, 2026-11-13** (rulings row 6): "The first platforms should be MacOS as server and Android as client, followed by MacOS as client, followed by linux server, followed by linux client. Android is one of the most important pieces as it will be the major marketplace differentiator". Goal G5 (wording agreed, row 8) adds that Android management "works with Island/Insular profiles and with user-space ShizukuPlus". This supersedes D22 and the 2026-10-29 Linux-first ruling and Android deferral ([`linux-targets.md`](linux-targets.md)). Linux work already done stays: pastebin's canary keeps running as the standing proof (operator, 2026-10-31; "1. Keep it", B4 rider, canary), and Linux is later in the order, not paused ("1. Order language", B4 rider, Linux). **Ruled 2026-11-14** (B4, "1. Adopt D47-D50"; M-§15-02). |
| D49 | Authoring | **Operator, 2026-11-13** (rulings row 4): "Real Nix first, YAML beneath." Goal G2 (wording agreed, row 8): config is written in the real Nix language with NixOS-style options, so existing NixOS and nix-darwin configs carry over; plain YAML/JSON sits beneath it as the data form Nix evaluates to and can be written by hand; what a person is shown reads clearly without manuals. This amends D12 (Nix is first, not one of two equals). Carry-over: a one-shot importer for pure-data option families (it lists what it did not carry), plus tendcf option names matching nix-darwin and NixOS where the meaning is the same (operator ruling, 2026-11-14, B7, "1. Importer + matching names"). Nix may be required to build a release, build-time only (R5, D6). **Ruled 2026-11-14** (B4, "1. Adopt D47-D50"; M-§15-03). Still open, not decided by that ruling: whether `schema/` or the Nix module options is the schema authority (§4.1 says JSON Schema is generated from the module options), and whether a byte-identical YAML twin stays as the frontend's test. |
| D50 | Device shape | **Operator, 2026-11-13** (rulings row 6b): "I am not trying to change the architecture; client and server are not entirely meaningful here as each device will be self-sufficient and able to take updates from any other device that uses the correct crytoographic handshake. So when I say server I am refering only to the machines that are a server for services like recieving and archiving logs and doing monitoring of other machines." Goal G3 (wording agreed, row 8): every device converges on its own and there is no control node. This confirms D33, amends D14's git-synced policy, and amends §9.11's push rule (peer delivery). The handshake: "the correct cryptographic handshake" means content checks (signed by trusted keys, fresh, names this device, owner approval); transport authentication decides only who may talk; first build SSH-signature v0; the 2-of-3 offline-root floor may lag until TUF (operator ruling, 2026-11-14, B1, "1. Content checks; v0 first"; B13 item 1, "1. Keep text; B1 is the reading"; §9.11). Owners may also enrol standing modes (§9.1, B2). **Ruled 2026-11-14** (B4, "1. Adopt D47-D50"; M-§15-04). |

Silence = proceed from Step 0. Objections amend this register.

---

## 16. Open questions (remaining)

Compressed from guide §19, in its order and numbering; the guide’s text
governs. It ran to nine while §9 was Model A; D43 dissolved question 8
**as posed** and added seven more, drawn from the residue register of
`e1-adjudication-xhigh-2026-08-15.md` §7. None of those seven is closed
by D43 — they are what Model B carries, and stating them as resolved
would misrepresent the adjudication.

1. Is inference justified, or is retry-until-stable already the local
   answer? (E1 endorses the inference *cut* as severable — the fields
   stay, D43 does not depend on the cut, and DC-41’s experiment can
   revive the engine. The question itself is still open.)
2. Is the writing rule an argument or a hypothesis?
3. Do `not-yet-migrated` counts get ground down without a dedicated role?
4. Is per-domain the right granularity for comprehensiveness?
5. Is local-first the wrong call? Network-wide reports are what bought
   administrator trust in the Bcfg2 deployment.
6. When a global yes/no arrives, is querying reachable devices and
   treating the rest as unknown enough?
7. Does edge origin information actually turn “why is this waiting?”
   into a query?
8. ~~Does the ChangePlan capability list survive real operations without
   an escape hatch?~~ **Re-posed 2026-08-15 by D43:** does the *goal-file
   schema* keep up with real operations? There is no capability list, and
   coverage closes by construction — compiler and validator share one
   schema and fail together — so the escape-hatch pressure relocates to
   declaring a domain `not-yet-migrated` to get a change out. That is
   question 3 wearing a different hat.
9. If the real AI failure mode is plausible-looking output that types
   do not catch, are we hardening the wrong surface?
10. Is a diff something a person can actually consent to? Everything that
    makes a large diff holdable (`explain-hunk`, display grouping, the
    briefing) is advisory machinery that never widens what the validator
    accepts — which is what keeps it safe and what makes it the first
    thing dropped under pressure. Countable once real diffs exist.
11. Do the total-diff events stay rare? Count migration releases per year;
    a project with high schema churn hands its reviewer a recurring
    “everything moved, this one is fine” event (§9.4).
12. Does refusing actually cost the proposer anything? Nothing stops the
    same bundle being re-offered; the answer is that persistent re-offers
    are visible in the record (§9.3, TC-19).
13. What protects the stored baseline (§9.1)? Integrity-protected storage
    is platform-specific to build, and Android under Termux is the awkward
    case — the same ownership problem §8 already has.
14. The policy tree is still code arriving outside the reviewed state,
    until the goal file carries its digest as a privileged region (§9.8,
    D30). An obligation on an unwritten schema, not a property.
15. Nothing here changes who authors the machinery (§9.10). Whether a
    device-local trust root the release path cannot write is buildable
    across macOS, Linux, and Android by one person is open, and the rest
    of the consent layer rests on the answer.
16. What confirms that a change took effect? `--simulate` covers files and
    packages; “loaded and running” is device-unconfirmable, permanently at
    this layer (§9.10).

Token discovery is **D40**, not open. Trust-tier-as-label (confusion
with full mesh) is **D38**.

---

## 17. Document map

- `docs/paper/tendcf-architecture-guide.md` — vetted current-state
  description. Wins on conflict about the current design.
- **This file** — implementer map (decisions, build order, protection).
  Must agree with the guide.
- `README.md` — pointer.
- `deprecated/` — v1/v2 and panel drafts. Do not update them.
- `e1-adjudication-xhigh-2026-08-15.md` — the binding adjudication of
  E1 (Model B) and of the schema-family decisions recorded as D43/D44.
  Final; supersedes `e1-adjudication-2026-08-15.md`, which is kept for
  delta context only. Its §7 residue register is the authority on what
  Model B does **not** fix.
- `cfengine-feasibility-of-diff-plan-2026-08-15.md` — the feasibility
  evidence D43 rests on; its addendum controls over its body.
- `change-process.md` — the lockfile / release / rollback / CI-gate design
  for requirement #2 (D19 made concrete); binding on Step 6.
- `upstream-overlay.md` — the patch overlay on libntech and cfengine/core
  (`overlay/`, `bin/overlay.py`) for issue #3; `upstream-register.md`
  stays the record of the defects behind it.
- Dated `*-2026-08-13.md` research notes in this directory — evidence
  trail; the guide wins on conflict.
- `docs/paper/tendcf-architecture-paper.md` — technical paper; the guide
  wins on conflict.
- `schema/`, `examples/`, `bin/schema_lint.py` — Site Model contract.
- `frdminc/nix2cf` — compiler tool (Step 3) until 2026-11-13, when it
  was folded into this repository as `compiler/` (D46, #45) and archived.
- `compiler/` — the compiler; consumes this contract.
- `plugin-layout.md` — the repository's plugin-type layout, the plugin
  kinds and their two public entry-point groups, the plugin trust and
  activation rules, and the order of the move (D46).
- `../review-2026-11-13/` — the 2026-11-13 goal review: the goal
  (`00-goal-definition.md`, G1-G9), the proposals behind D47-D50 and the
  2026-11-14 rulings written into this file, and the checks;
  `../review-2026-11-13/rulings-record-2026-11-14.md` is the operator's
  rulings record (the L-numbers cited in `14-synthesis-and-rulings.md`),
  and 14 lists the one item still open: the AI reviewer "up to 30" count
  (per reviewer or total), "open: deferred to the schema design review
  (operator ruling, 2026-11-14, PR 62 review Q7)".
- `tendcf-validate-proposal-2026-11-03.md` — a proposal, deciding
  nothing: options and a recommendation for each of §12's open D45
  items, a minimal first build, and an operator picklist.

Local prior-art clones (not dependencies): `~/src/config-mgmt-prior-art/`.
