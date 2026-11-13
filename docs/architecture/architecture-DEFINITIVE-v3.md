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
- **Date:** 2026-08-15 (§9 rewritten for Model B; D43/D44 added)
- **Tracker:** frdminc/tendcf#1.

This document describes the **current design and what is planned next**.
It does not recount how the design was reached. A previous configuration
stack on this fleet is **legacy reference only** — not a dependency, not
an upstream, not a name in this architecture. Patterns taken from it are
described in generic terms (for example “peer ADB help for a device that
cannot start its own privileged helper”).

---

## 0. Orientation for the AI that implements this

1. **This is a freedom project.** Interesting and correct beats minimal
   and safe when they conflict. Token spend is the cost that matters
   (§13).
2. **The reference target is a stock Linux distro on bare metal**, not
   NixOS. Nix is used for builds, as one of two equal Site Model authoring
   languages, and verbatim on hosts that already run NixOS or nix-darwin
   (D12, [`linux-targets.md`](linux-targets.md) §5) — never as the
   installed OS a stranger must adopt. Ubuntu Server LTS is the working
   default; the distro name is open until Step 4.
3. **The trust/consent layer is the point.** A person should understand a
   proposed change in ordinary language, refuse it, and keep a personal
   branch — using **their** AI, not ours.
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
  SQLite (index)         rebuildable from JSONL; tendcf-agent on
                         Android, owner open elsewhere (§12)
```

Collision of the same identity from two peer inputs is a **compile
error**. Only site-private may bind a winner or a short name.

---

## 2. Requirements (normative)

- **R1** Targets: macOS/Apple Silicon, Linux x86_64, Linux aarch64,
  Android (Termux + tendcf-agent + a Shizuku-class helper). Intel Mac
  mini out of scope. tendcf-agent is Android-only; Linux and macOS run
  CFEngine plus the `tendcf-validate` command, with no daemon (D45).
- **R2** No permanent control node. Feature roles
  `{main, backups[], peers[]}` are data.
- **R3** Resource efficiency; no fat containers; no VMs as the build
  substrate.
- **R4** Android keeps Termux (+api, +x11), the built-in Terminal app, a
  Shizuku-class helper, tendcf-agent (Kotlin, D45), CFEngine. No
  nix-on-droid. Nix may build zero-on-device-footprint artifacts only.
- **R5** No bare-metal Nix. A mainstream stock distro is the reference.
  Ubuntu Server is the default answer, not the requirement.
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

| Layer | Holds | Visibility |
| --- | --- | --- |
| **tendcf** | Engine, **schemas/types**, generic adapters, default advisor prompt, the compiler (`compiler/`) and its plugins (`plugins/`, D46) | Public product |
| ~~**nix2cf**~~ | ~~Compiler tool only (Site Model → CFEngine JSON)~~ Folded into tendcf (D46). `nix2cf` now names the Nix frontend plugin | Repository archived 2026-11-13, right after the import ([#45](https://github.com/frdminc/tendcf/pull/45)) merged |
| **site-shared** | Reusable recipes | Public or shared |
| **site-private** | Inventory, allocations, secret *names*, trust policy, extra prompt, lockfile | Private |
| **foreign shared** | Other sites' recipes | Read-only inputs |
| **tool forks** | sudo-secretspec, Shizuku, … | Optional |

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
time only. Third-party frontends and importers are to be found through
the public Python entry-point groups `tendcf.frontends` and
`tendcf.importers`; plugins in this repository are to be found through a
static import table, never through entry points (planned, restructure
step 4; no loader exists today); supervisor renderers are in tree only. Plugins are trusted build-time code the
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
- JSONL capture + SQLite index (§8; tendcf-agent's on Android)
- Generic bundle that picks a supervisor
- Peer actions as typed cross-machine help

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
   exists. On Android it lives inside **tendcf-agent**; on Linux and
   macOS its owner is open (below).

CFEngine never opens SQLite. Single writer to JSONL (engine or its
wrapper); single writer to SQLite (on Android the agent, which tails or
receives the log).

**Linux and macOS (D45, 2026-11-02).** No daemon runs beside CFEngine:
`tendcf-validate` (§12) is a command that runs and exits, not a process
that tails the log. What holds there is the capture: JSONL, written by
the engine or its wrapper. It is not built yet on any host — nothing
writes report rows (`report-row.schema.json`), and the Linux writer is
open in [`linux-targets.md`](linux-targets.md) §4. D45 gives the SQLite
index no owner on these platforms; that is an operator question (§12),
and nothing above depends on it, because the index is rebuildable and
the JSONL is the record.

**Android UID isolation (looked up, 2026-08-14).** Termux (`com.termux`)
and tendcf-agent are different UIDs. The APK **cannot** read
`$PREFIX/...` as files. [RUN_COMMAND](https://github.com/termux/termux-app/wiki/RUN_COMMAND-Intent)
is a user-granted bridge with stdout via `PendingIntent`, not a log
directory. Therefore:

- tendcf-agent owns **both** JSONL and SQLite in **app-private storage**.
- Either cf-agent runs as a native helper of the agent (same UID), or a
  Termux-side reporter **pushes** lines to the agent (localhost /
  ContentProvider). Never “agent opens Termux’s files.”
- [Room](https://developer.android.com/training/data-storage/room) /
  Android’s SQLite is the index path, not Termux `sqlite3`. Use
  `synchronous=FULL` if WAL is on; OEM freezers OOM-kill mid-commit.

Optional best-effort push of a subset into Vector / OpenObserve /
Grafana is never the record of truth. Fleet-wide yes/no questions query
reachable devices and treat the rest as unknown.

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
None of those is built.

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
  closed for *installs* (revocation still applies, §9).
- Custom tools (OpenPGP WoT, a transparency log, a chain, gossip of
  signed apply-attestations) are theirs. Deadlock among “everyone
  waiting for everyone else” is a separate project that consumes
  attestations. tendcf owes: the goal file and its diff (§9), optional
  exportable apply-attestations, the `accept | reject` slot.

Proposing side and consenting side are different programs. The advisor
never authorizes; the executor does, against the signed grant.

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

**Android (adapter #2).** Same Site Model vocabulary. Runtime: Termux +
tendcf-agent (Kotlin, D45) + Shizuku-class helper + CFEngine. Agent owns
logs (§8). Peer actions cover devices that need external ADB help.

**Linux (adapter #3, adoptability keystone).** Stock distro; mise
toolchains + CFEngine everything else, plus `tendcf-validate` (D45,
below). Distro choice open until this step.

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
interpreter or the Command Line Tools. On Android the Kotlin agent runs
the same validation and projection logic as a port, held byte-for-byte
to the same checked-in goldens in CI (residue R22 of
`projector-reconciliation-2026-08-16.md`, whose §9 placed the code); the
Python implementation stays the one normative source. It is
built after schema v5 lands and before any further host is enforced
(§13). Nothing device-side runs today: pastebin's canary data is a
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
   the schema is at v4 and v5 is in flight; an id change decided before
   v5 lands rides that bump, afterwards it costs v6 and a baseline
   ceremony per device.
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
7. **The SQLite index on Linux and macOS (§8, D18).** No owner:
   `tendcf-validate` is not a daemon and CFEngine never opens SQLite.
   Deferred, owned by another command, or not built on these platforms.
8. **The v5 detector.** `schema-v5-dpkg-reconciliation-2026-11-02.md` R4
   left open whether tendcf-agent later takes over the Linux unit
   detector. D45 (1) closes that as posed: no tendcf-agent exists on
   Linux. Open is only whether any other component (`tendcf-validate` or
   a further command) ever takes it over from the policy bundle.

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

Each step leaves a coherent system. Not a schedule.

| Step | What |
| --- | --- |
| 0 | Schemas in **tendcf** (`schema/`, `examples/`, `bin/schema_lint.py` — provides/requires, interlocks, comprehensive, report-row). Remaining: peer_actions, trust-policy shape, generic unit-writers, lookup stub, YAML canonicalize. Transcribe reality (`not-yet-migrated` is the correct day-one state). |
| 1 | macOS services adapter. Dry-run default. No nix-darwin. **Started** (`policy/tendcf_services.cf`, `222da45`: launchd present/absent and interlock refusal, verified against a real `cf-agent`; package/file promises, environment rendering, the unit-writer detector still open). 2026-10-29: the satisfied-interlock path had never opened (verdict class fixed in pass 1 before the check ran); the check moved to `tendcf_interlocks`, sequenced before `tendcf_services`, and `tests/policy/run.sh` proves both paths on Linux CI and the Mac. The CFEngine it was verified against is upstream plus the patch overlay (`overlay/`, [`upstream-overlay.md`](upstream-overlay.md)); Linux CI builds the full fork ([`linux-targets.md`](linux-targets.md)). |
| 2 | Android under the Site Model; Termux types; agent owns JSONL+SQLite. **Deferred** (operator, 2026-10-29): Linux comes first, see [`linux-targets.md`](linux-targets.md). Not started as code: the schema already carries a `termux` supervisor flavour (`services.schema.json`) and the `android-termux-services` domain fixture, but no adapter bundle, no agent, no JSONL/SQLite ownership. `frdminc/ShizukuTendCF` is the R4 helper (a tool fork), not this step. |
| 3 | Compiler (`tendcf compile`; ~~nix2cf~~): `buildfile` first, conflict, extra-entry, then inference (needs step 1 and a Linux systemd adapter; Android is deferred). **Unblocked** on 2026-10-29 by the operator's decision recorded on [#4](https://github.com/frdminc/tendcf/issues/4); `frdminc/nix2cf` had one compilation command, `buildfile`, plus the `eval-nix` evaluation hook. **Amended 2026-11-13 (D46):** the compiler moved into tendcf under `compiler/` (#45; `frdminc/nix2cf` archived) and the restructure splits it into plugins ([`plugin-layout.md`](plugin-layout.md)); ~~its `tendcf.lock` is specified in [`change-process.md`](change-process.md) §2~~ with schema and compiler in one repository there is no `tendcf.lock` (it was specified, never built). |
| 4 | Linux reference path on a stock distro. |
| 5 | First real Linux host; prove roles are data. |
| 6 | Signed releases, push-only; goal-file render + diff + on-device validator (§9). Operator hosts. The lockfile, release, rollback and CI-gate design is [`change-process.md`](change-process.md) (#2); the code is not written. On Linux and macOS the on-device validator is `tendcf-validate`, built after schema v5 lands and before any further host is enforced; how much of this step's validator its first build carries is open (D45, §12). |
| 7 | Mac substrate on the primary workstation (nix-darwin) if §14.1 says yes. The nix-darwin passthrough adapter itself is [`linux-targets.md`](linux-targets.md) Step 8 and does not wait on §14.1. |
| 8 | Pull / self-update. |
| 9 | Consent surface + default prompt + advisor slot. |
| 10+ | Demand: builder/cache, APK provenance, WoT-as-advisor-tools, extracting the publishable layer when a second person runs it. |

Dry-run is the standing posture on the first platform (the machine that
cannot easily be reimaged). Reporting is an adoption requirement.

The §9.9 schema family and the §14.2 review of it **MUST** land before the
Step 6 validator is coded. Nothing else gates them — no fleet, no
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
| D6 | Nix on bare metal | No. Builds / dev shells / authoring language / passthrough where a host already runs NixOS or nix-darwin. Never the OS a stranger must install. |
| D8 | Trust layer | Build it, gated. Sovereignty is the point. |
| D10 | Task runner | `just` for humans; mise for toolchains. |
| D12 | Authoring frontend | **Amended 2026-10-29.** Two equal frontends, Nix modules and YAML, rendering to byte-identical goal files; a Nix-authored site runs on hosts without Nix. Existing NixOS/nix-darwin configurations are used verbatim (passthrough). JSON remains the wire format. [`linux-targets.md`](linux-targets.md) §5. **Amended 2026-11-13 (D46):** the Nix frontend is the compiler plugin `plugins/frontends/nix/` and carries the name `nix2cf`; the YAML frontend is `plugins/frontends/yaml/` (built in); a Guix frontend may follow. Not built yet ([`plugin-layout.md`](plugin-layout.md)). **Amended 2026-11-13 (D46 (9), issue #48):** every Nix evaluation runs under restricted evaluation with no import-from-derivation, an empty `allowed-uris` and no network, and recipes from other sites are imported, pinned and scanned before compile; a Guix frontend waits for a sandbox design of its own (all planned). |
| D13 | Service owner | CFEngine promises everywhere; mise toolchains only. |
| D14 | Deployment shape | Git-synced policy; `cf-serverd` on every host; push and pull are one mechanism. |
| D15 | Compile target | CFEngine Augments, not freehand `.cf`. (By way of the per-host goal file, which the device projects to Augments after approval: D43, D44, §5, §9.) |
| D16 | Ordering | No Puppet catalog. Inference + fixpoint + authored `depends_on`. Interlocks. Default-on comprehensiveness. |
| D17 | ncf | Vendor generic methods as a reference corpus; strip Rudder reporting. |
| D18 | Local record | ~~JSONL is the durable capture; SQLite in tendcf-agent is the index. On Android the agent owns both in app-private storage.~~ **Amended 2026-11-02 by D45:** JSONL is the durable capture; SQLite is the index, rebuildable from it. On Android tendcf-agent owns both in app-private storage. On Linux and macOS there is no agent, and the index's owner there is open (§8, §12). |
| D19 | Composition | Private-site lockfile pins inputs (DAG). Signed release is the deploy artifact. No sibling-repo tag lockstep. |
| D20 | Nix store locality | Single writer per host. |
| D21 | Schema home | **tendcf** owns schemas/types. ~~nix2cf is the compiler.~~ **Amended 2026-11-13 (D46):** the compiler also lives in tendcf (`compiler/`, command `tendcf compile`); schemas stay in `schema/`, outside the compiler's code, and the two change in the same commit. `nix2cf` names the Nix frontend plugin. |
| D22 | Platform sequence | macOS, Linux. Android deferred by the operator on 2026-10-29 ([`linux-targets.md`](linux-targets.md)). |
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
| D45 | Device-side component per platform | **Operator, 2026-11-02.** (1) tendcf-agent is **Android-only**, written in Kotlin. A Linux or macOS host runs CFEngine plus "a small validate-and-project command" (the ruling's words; the name **`tendcf-validate`** was chosen by the amending session on 2026-11-02 and may change without reopening the ruling), run before cf-agent reads `host_specific.json`; no daemon. (2) `tendcf-validate` is Python, the promotion of `bin/projector.py`: one implementation, so no byte-identity drift on those platforms. It needs `python3` on each host (Debian ships it, NixOS through the derivation, macOS bundled or the Command Line Tools). The Android agent's Kotlin projector is a port held to the same golden bytes in CI (residue R22), not a second normative source. (3) Built after schema v5 lands, before any further host is enforced. **Supersedes** every reading that ran the validator, the projector or the SQLite index inside tendcf-agent on every host: the §1 diagram's "CFEngine + tendcf-agent" per device, §8's index owner and D18 as written, §9's "run inside tendcf-agent" and "the agent binary" as the projector's call site, `goal-file-schema-reconciliation-2026-08-15.md` §0 item 7, §9 and §13 ("CI invokes the agent's own projector"), and `projector-reconciliation-2026-08-16.md` §9 and R22 ("tendcf-agent must reproduce" the reference). Not decided by it, and open for the operator: §12's list. |
| D46 | Repository layout and compiler plugins | **Operator, 2026-11-13.** (1) `frdminc/nix2cf` folds into tendcf with full history, first under `compiler/` ([#45](https://github.com/frdminc/tendcf/pull/45)), and is archived as soon as that import merges. Both done 2026-11-13 (merge commit `ca4fa90`; the repository archived the same day). (2) The repository takes the plugin-type layout of [`plugin-layout.md`](plugin-layout.md): `schema/`, `examples/`, `policy/`, `overlay/`, `deploy/` unchanged; `tools/` (was `bin/`); `compiler/` (merge, conflict check, render); `plugins/frontends/` (`yaml`, `nix`, later `guix`, an authoring frontend), `plugins/supervisors/` (`launchd`, `systemd`, `runit`), `plugins/importers/` (`ansible`, `salt`); `contrib/` for in-tree third-party frontends and importers. It becomes one Python package, import name `tendcf`. (3) Third-party frontends and importers are found through the public entry-point groups `tendcf.frontends` and `tendcf.importers`, so they can live out of tree as a pip package; plugins in this repository are found through a static import table, never entry points (9a). Supervisor renderers are in tree only; there is no public `tendcf.supervisors` group, because the goal file's `unit` is a closed `oneOf` and an out-of-tree renderer could only shadow a built-in. (4) Plugins are compile-time only: none runs on a device. The device artifact (`tendcf-validate`, D45) is built from the validator's own source alone, never imports `compiler/`, `plugins/` or `contrib/` and never calls entry-point discovery; the schema lint and the projector never import the compiler; a CI import check is to enforce both (planned). Plugins are trusted build-time code that the operator explicitly allows, not sandboxed: a plugin cannot make a device accept anything that device's own diff does not show (on Linux and macOS that validation is `tendcf-validate`, planned, D45, and does not exist yet; the Android agent was not checked), and cannot emit a shape the schema forbids, but it can make the goal file say something other than what the Site Model says, and it sees the site's private data. Release gates (schema lint, projector, preview diff) and signing are to run in a separate environment with no plugin installed, and the compile step is to hold no signing key (planned, Step 6; nothing enforces this today, and amendment (9) says what the environment is). A compile-side preview diff or `explain-hunk` (D44) is compiler output and inherits the plugins' trust. `contrib/`'s lower bar waives support and maintenance promises, never the standing review rule. Out-of-tree trust establishment and plugin management: [#47](https://github.com/frdminc/tendcf/issues/47). (5) Activation (the loader is planned, restructure step 4): a plugin is selected only if site-private names it (name → distribution, version, hash); an installed but unnamed plugin is not selected (installing a package can still run code, amendment (9)); a duplicate name in a group is a compile error; built-in names are reserved; until out-of-tree pinning exists (#47) a release build loads in-tree plugins only; the release's `targets.json` `custom` records the plugin set. (6) No users and no backward compatibility yet, so no shims: the compiler's command becomes `tendcf compile`, which replaces `nix2cf buildfile` with no alias (it compiles every host; `--host` renders one); `eval-nix` moves to the Nix frontend; `bin/` → `tools/` leaves no symlink or wrapper and rewrites every path reference in every file, dated records included (djbclark, 2026-11-13, a one-time exception to their append-only convention; only paths change, and prose naming nix2cf as the old repository stays as history); `nix2cf` names the Nix frontend (D12). The compiler renders only the current `schema_version`; older-version rendering is removed in the restructure, and §9.6's ceiling design applies once the first device that is not an operator host enrolls. (7) The keys `nix2cf_services` and `nix2cf_edges` were only ever illustrative: they occurred in guide §16.A's preview-channel example and its copy in the paper, and no schema, fixture, projector or bundle carried them (the projection's keys are `tendcf_service` and `tendcf_interlock`). In the same change that recorded this decision they were renamed `preview_services` and `preview_edges` (illustrative only, chosen so they cannot be mistaken for the `tendcf_services` bundle or the real projected keys `tendcf_service`/`tendcf_interlock`). No schema change is involved ([`plugin-layout.md`](plugin-layout.md) §6). (8) Consequence for [`change-process.md`](change-process.md): the compiler is no longer a separately pinned input, the two-repository bump order and the compiler's `tendcf.lock` go away; `site.lock` loses only its `nix2cf` entry. One tendcf rev is the unit a site pins, so a compiler fix brings the `schema/` and `policy/` commits before it; accepted, with no maintenance-branch machinery, revisited when the first device that is not an operator host enrolls. Moving `bin/` to `tools/` and the plugin split wait until open PRs #41 and #42 merge. (9) **Amended 2026-11-13 ([issue #48](https://github.com/frdminc/tendcf/issues/48), the adversary review of this decision; operator decisions D-a to D-d recorded in [its comment](https://github.com/frdminc/tendcf/issues/48#issuecomment-6857866487); full text in [`plugin-layout.md`](plugin-layout.md) §4). Nothing below is built; each part is tagged with its step.** (a) **In-tree proof (D-a), planned with the loader:** a plugin is in-tree when its module's realpath sits under the gate-1-verified tendcf tree, checked before the module's code runs (a release build runs the compiler from that tree without installing it); every in-tree plugin (frontends, supervisors, importers) is found through a static import table, never through entry points, which are read only for third-party plugins after #47: list every one without deduplication by name, refuse duplicate names and every entry point that claims a reserved name, whatever its distribution name, load only the named ones; release builds never resolve `tendcf` from a package index; a release build pins or refuses `TENDCF_DIR`. This replaces the first sentence of (3) for in-tree plugins: only third-party plugins use the public groups. (b) **Frontend inputs are code (D-b), planned, Step 6:** external (site-shared or foreign) recipes are imported, never fetched at compile time; the import pins by content digest, runs a static scan and an AI review, and records the verdict with the pin; compile evaluates only pinned recipes with an accepting verdict bound to the digest and fails closed on a failed scan, a rejecting review or a missing or mismatched verdict (the no-AI setting never overrides a negative result; only the gate-5 ceremony marker does, recorded with the pin and shown in every later gate-5 review; the recorded verdict is advisory, because job B′ re-runs the static scan and the AI review on the pinned digest and fails on a negative result), and a site-shared or foreign `site.lock` input is not an import by being pinned; every Nix evaluation, the site's own included, runs under `restrict-eval` with import-from-derivation off, an empty `allowed-uris`, no unsafe native code and no network, with the whole directory tree that the import digested and scanned passed to `-I` and nothing wider (the import refuses a symlink that resolves outside it); `pure-eval` is not used because it cannot evaluate a file named on the command line (tested 2026-11-13 on Nix 2.35.6 in CI, [run 43469616588](https://github.com/frdminc/tendcf/actions/runs/43469616588): the positive recipe evaluates, and file reads outside the recipe (a symlink escape, `readDir` and `builtins.path` included), `fetchurl`, `fetchTarball`, a local `fetchGit`, a `<nixpkgs>` lookup and `builtins.exec` are each refused, each flag shown by relaxing it alone, while `getEnv` returns the empty string; the import-from-derivation flag is the layer that refuses it (on a fresh store the read-only `--eval` stops it first, with a store-state-specific message) and was proven with `--read-write-mode`; the exact command and what stays untested are in `plugin-layout.md` §4); no Guix frontend until it has a sandbox design of its own; with no AI reachable at import the static scan still runs and `external_import.without_ai` (`require-human-ack` by default, or `warn`, or `refuse`) decides, for the import step only (job B′ still requires an AI review, or the ceremony override, before anything is signed), set in the site-private file that names plugins. (c) **Separate environment (D-c), planned, Step 6:** interim, a separate Unix user on the builder holds the key and the gate tools; the default before the first real release is a two-job split (job A on a throwaway runner with no secrets compiles, runs gate 2 and uploads goal-file bytes plus a digest manifest; job B in a protected signing environment builds the gate tools from the previous release's tendcf pin, never the pin under test (the first release uses the tip of the protected branch the trust root declares), with hash-locked dependencies, installs no `tendcf`, runs gates 3 to 5 and signs exactly the digests it checked; job B′ is job B without the key, runs gates 3 to 5 for pull requests so that the reviewed preview is computed outside the plugins); signers in the first real release are one of n (operator rulings, 2026-11-13): the CI key held as a GitHub environment secret, which alone suffices; hardware tokens, optional, at least two if any is enrolled; and the separate Unix user, opt-in and non-default, whose enrolment lowers every release to its level; each enrolled signer signs alone (`vps-hub` and the Hyades podman runner are not signers); both token paths normally sign only the approved pull request's job A digests (merged tree equal to the approved head), path 1 after verifying a passing job B′ run and path 2 after re-running gates 3 to 5 itself with the previous release's gate tools, hash-locked, and `targets.json` `custom` records which; a break-glass route with no merged pull request is allowed, privileged and recorded there too, and is one person's act, bounded only by the threshold-one trust in that signer (ruling 19); job A's egress is unrestricted for now, a stated exfiltration risk left open in `plugin-layout.md` §7. (d) **Signed is what was reviewed (D-d), planned, Step 6:** the pull request's own job A artifacts, previewed by job B′, are what reviewers approve (the approval is bound to head commit, job A run, manifest, preview and baseline release) and what merge signs when the merged tree equals the approved head tree and nothing bound changed (otherwise the gates run and are reviewed again); branch protection on site-private; a changed pin `url`, a pin that does not descend from the previous one and a changed plugin set (the operator's list), and a tendcf bump that changes `tools/`, `schema/` or the projector (issue #48's fixes; such a bump ships as its own release with unchanged data, because the gate tools come from the previous release's pin, ruling 18) need the gate-5 ceremony marker, and so do (operator rulings) a new `site.lock` input, the files the gate jobs run, CI workflow and signer configuration, a signer backend change and a lowered `external_import.without_ai`; the tendcf pin's `url` and `ref` must be what the site's trust root declares (default `frdminc/tendcf` and `master`, or a listed release-branch set, each with required review, no force-push, no deletion and no administrator bypass), any other ref is refused, and a site may declare its own tendcf repository and branch set in its trust root, a privileged change that no per-pull-request marker substitutes for, and gate 1 reads the trust root from the protected base, never from the pull request, so one pull request cannot both change it and move the pin; a backward pin move across a `schema_version` bump is forbidden (roll forward) and within one version is privileged; for a pull request that changes a pin `url` or the plugin set, adds a `site.lock` input or changes the trust-root declaration, job A does not run until the marker is present; the marker must be an attestation the author cannot produce, bound to one head and the named changes, and verified by jobs B′ and B from definitions outside the pull request, and the approval record is produced by job B′ and verified by job B (mechanisms open, `plugin-layout.md` §7); a break-glass route and a change of the trust-root declaration are also privileged; until built the preview diff is advisory. (e) **Statements corrected:** the claim that installing a package activates nothing was false (`.pth` files run when the interpreter starts and sdist build backends run at install time), so rule (5) says an unnamed plugin is "not selected"; hashes are to be checked at install time from a hash-locked, wheels-only resolution, plugin dependency closures pinned and the gate tools' dependencies locked; a plugin or recipe can copy one host's private data into another host's goal file and nothing in gates 3 to 5 checks that yet (planned: the projection lint checks for values from other hosts' slices; each host reads only its own goal files from the release store, by a per-host path and credential, while the operator and the signing job read all); folding the compiler in removed the producer/checker independence, listed as a cost in [`change-process.md`](change-process.md) §9; importers follow the naming and pinning rules of frontends, and gate 5 compares the plugin set with the previous release's. Amends D12, D15 (a pointer), D21, §1, §3, §5, §9.6 (when it applies) and Step 3. |

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
- `tendcf-validate-proposal-2026-11-03.md` — a proposal, deciding
  nothing: options and a recommendation for each of §12's open D45
  items, a minimal first build, and an operator picklist.

Local prior-art clones (not dependencies): `~/src/config-mgmt-prior-art/`.
