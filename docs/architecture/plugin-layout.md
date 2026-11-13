# Repository layout and compiler plugins (decided 2026-11-13)

> Operator ruling, 2026-11-13; recorded as map D46
> ([`architecture-DEFINITIVE-v3.md`](architecture-DEFINITIVE-v3.md)).
> Status: decided, **almost none of it built**. §2 marks each part as
> exists today or planned. Where this file and the guide disagree on the
> current design, the guide wins.
>
> Amended 2026-11-13 after the adversary review recorded in
> [issue #48](https://github.com/frdminc/tendcf/issues/48) (operator
> decisions D-a to D-d, [recorded on the issue](https://github.com/frdminc/tendcf/issues/48#issuecomment-6857866487)):
> §4 now says how the loader proves a plugin is in-tree, that frontend
> inputs are code, what "separate environment" means, and how what is
> signed is tied to what was reviewed. **Every property of §4 that no
> code enforces yet is tagged "planned", with its step.** Today there is
> no plugin loader, no release pipeline, no gate separation, no import
> step and no device-side validation command.

## 1. The decision

1. `frdminc/nix2cf`, the compiler, folds into `frdminc/tendcf` with its
   full git history, first under `compiler/`. A separate pull request
   ([#45](https://github.com/frdminc/tendcf/pull/45)) did the import; it
   merged on 2026-11-13 (merge commit `ca4fa90`). This document moves no
   files.
2. The repository takes the plugin-type layout of §2. It becomes one
   Python package, import name `tendcf` (today's `nix2cf` package is
   renamed; how the directories map onto it is open, §7).
3. A third-party frontend or importer can live outside this repository as
   an ordinary pip package, found through the public Python entry-point
   groups `tendcf.frontends` and `tendcf.importers` (§3). Every plugin in
   this repository (frontends, supervisor renderers and importers) is
   found through a static import table, never through entry points (§4,
   activation). Supervisor renderers are in tree only; there is no public
   `tendcf.supervisors` group (§3).
4. Plugins run at compile time only, and they are trusted build-time code
   that the operator explicitly allows, not sandboxed code (§4).
5. A plugin is selected only if site-private names it (§4, activation;
   the loader is planned, restructure step 4).
6. The compiler's command becomes `tendcf compile`, which replaces
   `nix2cf buildfile` outright: no alias (§6). The name `nix2cf` moves to
   the Nix frontend.
7. The compiler renders only the current `schema_version` (§4).
8. `frdminc/nix2cf` is archived as soon as the import (#45) merges (§5).
   Done 2026-11-13: archived the same day #45 merged, its README pointing
   here.

The consequence for the change process: the compiler is no longer a
separately pinned input. Schema and compiler change in the same commit,
so the two-repository bump order and the compiler's `tendcf.lock` go
away. `site.lock` loses only its `nix2cf` entry: it still pins tendcf,
site-shared and foreign sites, and tool forks stay as its rule 5 has
them, never an input of their own
([`change-process.md`](change-process.md) §2, §4).

The price: one tendcf rev is the unit a site pins. A compiler fix brings
with it every `schema/` and `policy/` commit that landed before it, and a
change to the policy tree is a privileged-region hunk on a consented
device (map §9.8). The coupling is accepted. There is no
maintenance-branch machinery for carrying a compiler fix on its own; the
question is revisited when the first device that is not an operator host
enrolls ([`change-process.md`](change-process.md) §8).

No compatibility layer is kept, because the project has no users yet: no
command alias, no `bin/` symlinks or wrappers, no rendering of older
schema versions (§4, §5, §6).

## 2. The tree

```
tendcf/
  schema/ examples/          the contract; paths unchanged
  policy/ overlay/ deploy/   device side; unchanged
  tools/                     was bin/ (schema_lint, projector, xref_lint, overlay, …)
  compiler/                  was the nix2cf repository: merge, conflict check, render
  plugins/
    frontends/yaml/          the YAML Site Model loader (built in)
    frontends/nix/           the Nix module frontend (map D12); named nix2cf
    frontends/guix/          later: Guile records → Site Model JSON
    supervisors/launchd/     unit renderers, one per supervisor; in tree only
    supervisors/systemd/
    supervisors/runit/
    importers/ansible/       optional one-shot migration into the Site Model
    importers/salt/
  contrib/                   in-tree third-party frontends and importers
  docs/ tests/
```

| Path | Today (2026-11-13) | Planned |
| --- | --- | --- |
| `schema/`, `examples/` | exist in tendcf | unchanged |
| `policy/`, `overlay/`, `deploy/` | exist in tendcf | unchanged |
| `tools/` | is `bin/`: standalone `uv run --script` files; tendcf has no `pyproject.toml` | `bin/` renamed `tools/` after #41 and #42 merge, with no symlink or wrapper left behind and every reference rewritten (§5, step 4) |
| `compiler/` | exists since #45 (2026-11-13), imported from the now archived `frdminc/nix2cf`: package `nix2cf` (`nix2cf/cli.py`, `compile.py`, `sitemodel.py`), its tests run by the `compiler` job of `.github/workflows/check.yml`. Two subcommands: `buildfile`, the implemented compilation command, which renders one host; and `eval-nix`, a plain-expression evaluation hook, not the D12 module frontend | the compiler of the `tendcf` package; command `tendcf compile` (§6) |
| `plugins/frontends/yaml/` | `nix2cf/sitemodel.py` (YAML loading with duplicate-key refusal and line numbers) | split out of the compiler, still built in |
| `plugins/frontends/nix/` | only the hook: `nix2cf eval-nix FILE` evaluates a plain Nix expression with `nix-instantiate --eval --strict --json`; no module frontend | the D12 Nix module frontend, named `nix2cf`; `eval-nix` moves here |
| `plugins/frontends/guix/` | nothing | later, and only after a sandbox design of its own (§4) |
| `plugins/supervisors/launchd/` | inside `nix2cf/compile.py`, the only supervisor whose goal-file `unit` entry is rendered | split out |
| `plugins/supervisors/systemd/`, `runit/` | nothing: a service selected for a systemd or runit host is a compile error (`RENDERED_SUPERVISORS` in `compile.py`) | written in tree ([`linux-targets.md`](linux-targets.md) §3, step 6) |
| `plugins/importers/` | nothing | optional |
| `contrib/` | nothing | as third parties contribute |
| entry-point groups | none; nix2cf's `pyproject.toml` declares only the `nix2cf` script | the two public groups of §3, read for third-party plugins only; in-tree plugins are found through a static import table (§4) |

A supervisor plugin renders a service record into the goal file's `unit`
entry for that supervisor and resolves that supervisor's defaults (for
example `working_dir`). It does not write the unit file on the host; the
generic bundle under `policy/` does that, after approval and projection.

`tendcf-validate`, the device-side command that D45 makes out of the
reference projector, has no directory of its own in this tree yet (§7).
Wherever it lands, the device boundary rules of §4 apply to it.

## 3. Plugin kinds and entry-point groups

| Kind | Entry-point group | What it is |
| --- | --- | --- |
| Frontend | `tendcf.frontends` (public; third-party plugins only, §4) | A language a site keeps authoring in. It turns its source into the Site Model's JSON, which the compiler then merges, checks and renders like any other. YAML and Nix are the two equal frontends of map D12; Guix may follow as an authoring frontend (Guile records → Site Model JSON) once it has a sandbox design of its own (§4). |
| Importer | `tendcf.importers` (public; third-party plugins only, §4) | An optional one-shot migration from another tool's configuration (Ansible, Salt) into Site Model files, which the site then keeps and edits as its own. Not run on every compile. |
| Supervisor renderer | none: in tree only | A unit renderer for one supervisor (launchd, systemd, runit): service record in, goal-file `unit` entry out (§2). |

The difference between a frontend and an importer is what happens next. A
site authored through a frontend keeps its source in that language. A site
migrated by an importer keeps the Site Model files the importer wrote, and
the importer is not needed again.

**Why supervisor renderers are not a public group.** The goal file's
`unit` is a closed `oneOf` over `launchd`, `systemd` and `runit`, each with
`additionalProperties: false` (`schema/goal-file.schema.json`, the `unit`
definition), and the generic bundle refuses any flavour it does not
implement ([`linux-targets.md`](linux-targets.md) §3, step 3). An
out-of-tree plugin therefore cannot add a supervisor: that needs a
`schema_version` bump, a bundle branch and projector support in tendcf
first. All an out-of-tree supervisor plugin could do is replace the
renderer of one of the three existing supervisors, which is exactly the
shadowing of a built-in that §4 forbids. Frontends and importers are
genuinely open, because their output is Site Model data that the compiler
checks like any other.

**Not Guix System.** The Guix frontend is an authoring language for the
Site Model, not a host type. A Guix System host, whose init is Shepherd
(not one of the supervisors above), is a separate question and is not
decided (§7).

Built-in frontends, supervisor renderers and importers are in tree, are
found through a static import table and never through entry points, and
their names are reserved against third-party entry points (§4). The
Python interface a plugin implements, and the table's format, are not
specified yet; they are to be settled when the split is done (§5, step 4).

An **importer** (this section) is a plugin that migrates another tool's
configuration into Site Model files. An **external import** (§4, frontend
inputs) is something else: the step that brings a site-shared or foreign
recipe into a site, pinned and scanned. The glossary keeps the two apart.

## 4. Rules for every plugin

**Compile time only.** No plugin runs on a device. A device receives a
signed release and runs CFEngine with `tendcf-validate` or tendcf-agent
(map D45), never the compiler. (On Linux and macOS the
validation is `tendcf-validate`, which is planned: it does not exist as a
command yet, it has no directory in this tree (§2) and map D45 (3) builds
it after schema v5. Any sentence below that relies on a Linux or macOS
device validating a goal file describes that planned design; the Android
agent's state was not checked for this amendment.)

**The device boundary is structural, not a convention** (planned with the
restructure, §5 step 4):

1. The device artifact (`tendcf-validate`, D45) is built from the
   validator's own source alone. It imports nothing from `compiler/`,
   `plugins/` or `contrib/` and never calls entry-point discovery.
2. Dependency direction: the schema lint and the projector never import
   the compiler. The contract stays outside the compiler's code even
   though both live in one repository.
3. A CI import check enforces both. It does not exist yet.

**Plugins are trusted build-time code.** A plugin is Python that runs in
the compile step with the compiler's own access: the merged Site Model,
including inventory that is private by default (map D35), allocations and
secret names; the build host's files and processes. A pip distribution
can also run code at import time in every Python process of the
environment it is installed in. Nothing sandboxes it. Allowing a plugin
(by naming it, below) is trusting it as much as the compiler itself, with
the site's private data and, on operator hosts, with root. What the
release checks do and do not give, stated exactly:

1. A plugin cannot make a device accept anything that device's own diff
   does not show. A goal file that passes reaches the device as a
   complete signed canonical goal file; the device computes and validates
   the diff against its own approved baseline before approval and
   projection (guide §7; on Linux and macOS this is `tendcf-validate`, planned, map D45).
2. A plugin cannot emit a shape the schema forbids. The schema lint and
   the projector reject it, and a goal file they reject stops the release
   ([`change-process.md`](change-process.md) §6, release gates 3 and 4).
3. A plugin **can** make the goal file say something other than what the
   Site Model says. Valid is not faithful: a buggy or malicious renderer
   or frontend can emit a schema-valid entry with a different argv, a
   different `run_as`, an extra service or a tombstone. On a consented
   device the check is the person's yes over the device-side diff. An
   operator host applies without a local yes (change-process §8), so
   there the only human check is the pull request's preview diff, which
   is advisory until the binding of "Signed is what was reviewed" below
   is built (planned, Step 6).
4. A plugin or recipe **can** carry private data across hosts. It can
   copy host A's private data (inventory, allocations, secret names) into
   a schema-valid string field of host B's goal file. Nothing in release
   gates 3 to 5 looks for that today. Planned requirement: the projection
   lint checks every goal file for values that belong to other hosts'
   slices. Who can read the release store is not specified (§7); one
   release carries every host's goal file ([`change-process.md`](change-process.md)
   §3), so whoever can read the store can read all of them. The release
   gates bound a goal file's shape, not its confidentiality.

**Frontend inputs are code (decision D-b, 2026-11-13).** A recipe that a
frontend evaluates (a Nix expression today, Guile records later) runs
during the compile step with the compiler's own access, so a recipe is
code, not data. The operator's words: "I want people to be able to easily
share configurations, but they should be security-scanned before running
them, including doing so with the help of AI. We can have a soft
requirement that access to AI be present whenever an external import is
attempted." The rules below are all **planned, Step 6**: no import step
exists, and `nix2cf eval-nix` today runs with none of the limits in
item 3.

1. **Import, not fetch.** An external recipe (one from site-shared or
   from a foreign site) is imported, never fetched at compile time. The
   import:
   1. pins the recipe by content digest;
   2. runs a static scan for network access, file reads outside the
      recipe, import-from-derivation, and exec-style escapes;
   3. runs an AI review;
   4. records the verdict with the pin.
2. **Compile evaluates only pinned recipes whose recorded verdict matches
   the recipe's digest.** Any change to a recipe is a new import and a
   new scan. (Where the pin and the verdict are stored, and the command
   that imports, are not specified: §7.)
3. **Nix limits, for every Nix evaluation, the site's own recipes
   included.** Restricted evaluation (`restrict-eval`), and pure
   evaluation (`pure-eval`) where it works; no import-from-derivation;
   an empty `allowed-uris`; no network. The names below are checked
   against the Nix 2.35.6 reference manual on 2026-11-13
   ([`nix.conf`](https://nix.dev/manual/nix/latest/command-ref/conf-file),
   [`nix-instantiate`](https://nix.dev/manual/nix/latest/command-ref/nix-instantiate)):

   | Setting | Value | What the manual says | Default |
   | --- | --- | --- | --- |
   | `restrict-eval` | `true` | the evaluator "doesn't allow access to any files outside of `builtins.nixPath`, or to URIs outside of `allowed-uris`" | `false` |
   | `allowed-uris` | empty | URI prefixes allowed in restricted evaluation | empty |
   | `allow-import-from-derivation` | `false` | with `false`, Nix "throws an error when evaluating an expression that uses" import-from-derivation | `true` |
   | `pure-eval` | `true`, where it works | restricts file system and network access to files specified by cryptographic hash and disables impure constants (`builtins.currentSystem`, `currentTime`, `nixPath`, `storePath`) | `false` |
   | `allow-unsafe-native-code-during-evaluation` | `false`, never changed | enables `builtins.importNative` and `builtins.exec` | `false` |

   The manual documents `--option NAME VALUE` on `nix-instantiate`
   ("Set the Nix configuration option _name_ to _value_. This overrides
   settings in the Nix configuration file"), so the shape of the call is
   `nix-instantiate --eval --strict --json --option restrict-eval true
   --option allow-import-from-derivation false --option allowed-uris ''
   FILE`, with `NIX_PATH` set to the empty string (the manual: "If
   `NIX_PATH` is set to an empty string, resolving search paths will
   always fail") and never `--impure`. **That command line is the shape
   the manual supports; it has not been run.** Nix is not installed on
   the machine that wrote this, so these were not tested: the exact
   spelling the PR that moves the Nix frontend needs, whether the
   evaluated file itself must also be allowed under `restrict-eval`
   (for example through `-I`), whether `pure-eval` works for a plain file
   evaluation, and how a `nix-daemon` treats these options from a client.
   That PR tests them on a real Nix and records the tested command here.
   Today `compiler/nix2cf/cli.py` (`cmd_eval_nix`) passes only
   `--eval --strict --json`: the limits are a code change, planned with
   the Nix frontend move (§5, step 4).
4. **No Guix frontend** until it has a sandbox design of its own.
5. **When no AI is reachable at import**, the static scan still runs and
   the setting `external_import.without_ai` decides the rest:

   | Value | The import |
   | --- | --- |
   | `require-human-ack` (default) | needs an explicit operator acknowledgement, recorded in the pin as "reviewed by hand, no AI"; the next import with AI present scans it again |
   | `warn` | goes ahead without an acknowledgement and with a warning, and the pin records that no AI review took place |
   | `refuse` | is refused |

   The setting lives in the site-private file that names plugins (§7,
   "how site-private names its plugins"). That file's format is still an
   open question; until it is decided the encoding is TOML, so the
   setting reads:

   ```toml
   [external_import]
   without_ai = "require-human-ack"   # or "warn", or "refuse"
   ```

   The operator's instruction: "Do 1, but make a toml config file option
   (or whatever format we are using) to allow different options/override
   and doc that." How the compiler decides that no AI is reachable, and
   what the AI review consists of, are not specified (§7).

**Release gates and signing run apart from plugins** (decision D-c; **planned,
Step 6**: no release pipeline exists, so nothing enforces this today). As
first written the rule said "a separate environment" and nothing made it
true: [`change-process.md`](change-process.md) §6 puts the `targets` key on
the builder, so a plugin running in gate 2 could read the key, tamper with
the gate tools (a `.pth` file, say), rewrite goal files between gates 3 to
5 and signing, or persist on the builder. Every in-tree plugin ships inside
the one `tendcf` distribution, so no environment that installs tendcf is
plugin-free. What it means now:

1. **Interim, until the first real release:** a separate Unix user on the
   builder holds the signing key and the gate tools, and the compile step
   does not run as that user. This leaves persistence and tampering
   before signing open. It costs about half a day and no money.
2. **The default before the first real release: a two-job split.**
   1. **Job A** runs on a throwaway runner with no secrets. It compiles,
      runs gate 2, and uploads the goal-file bytes plus a digest manifest.
      That is its only output, and it flows one way.
   2. **Job B** runs in a protected signing environment. It builds the
      gate tools from the pinned source with hash-locked dependencies,
      without installing the `tendcf` package. It runs gates 3 to 5 on the
      uploaded bytes and signs exactly the digests it checked.
3. **Signer backends in the first real release** (the signer holds the
   `targets` key):
   1. the two-job CI with the key held as a GitHub environment secret:
      the default. *This default is the lead's assumption, pending the
      operator's confirmation: the operator chose the two-job split and
      did not choose the variant with a dedicated signer VM.*
   2. a separate Unix user: a non-default option;
   3. a hardware token on the operator's Mac: a non-default option, never
      required.
4. **Cost shown to the operator when deciding:** the two-job split is
   about 1 to 2 agent-days of work plus about $0.03 per release (Linux
   2-core runner at $0.006 a minute; GitHub's runner-pricing page, read
   2026-11-13). The Unix user is about half a day and $0, but leaves
   persistence and pre-signing tampering open. The operator chose: "3, but
   we want to leave the unix user as a non-default option in the first real
   release." Item 1 is that Unix-user variant as the interim; item 2 is
   the default before the first real release.

What this still does not give. The compiler and the gates share the
dependencies pyyaml, jsonschema and rfc8785 (`compiler/pyproject.toml`,
`bin/schema_lint.py`, `bin/projector.py`). Job B's locked, hash-checked
closure means a changed dependency is a reviewed change, not a resolution
made at run time; it does not protect against a malicious release of a
dependency at a locked hash. The gates' preview diff is computed apart
from the plugins, but it diffs their output, so it shows what they
rendered. A preview diff or an `explain-hunk` attribution produced on the
compile side (D44, map §9.5) is compiler output and inherits the plugins'
trust.

**Signed is what was reviewed** (decision D-d; **planned, Step 6**). As
first written, nothing tied what a merge run signs to what the pull
request showed: the merge run compiled again and signed whatever came out,
a plugin can tell a pull-request run from a merge run, and nothing
required site-private changes to be reviewed at all. Until this is built,
the preview diff is **advisory**. The rule:

1. **Promote the pull request's own artifacts.** The pull-request run is
   job A on a throwaway runner with no secrets. It produces the goal files
   and the digest manifest, and reviewers approve that preview.
2. **At merge**, if the merged tree equals the approved pull-request head
   tree, job B signs exactly those digests. If it does not, the gates run
   again and the result is reviewed again.
3. **Branch protection on site-private**: a change reaches the signing
   branch only through a reviewed pull request.
4. **Privileged changes need the gate-5 ceremony marker**
   ([`change-process.md`](change-process.md) §6): a changed `url` in a
   `site.lock` pin; a pin that is not a descendant of the previous one (so
   any move backwards, which also rolls back gate fixes); a changed plugin
   set; and a tendcf bump that changes `tools/` (today `bin/`), `schema/`
   or the projector. Planned requirement: `CODEOWNERS` for `schema/`,
   `tools/` and `policy/`. Folding the compiler into tendcf cost the
   independence of producer and checker: one tendcf commit can change
   both the compiler and its gates, and rolling the pin back rolls back
   gate fixes too ([`change-process.md`](change-process.md) §9). Whether a
   pin may move backwards across a `schema_version` bump is not decided
   (§7).
5. **A throwaway runner has no secrets but does see site-private data**
   (private by default, map D35). That is why item 4's changes also
   matter for pull-request runs, which compile whatever tree the pinned
   `url` and `rev` name; whether those runs wait for the marker is open
   (§7).

**Activation: a plugin is selected only if site-private names it** (the
loader is **planned**, restructure step 4, and Step 6 for the release
checks; no loader exists today). The steps run in this order:

1. **In-tree plugins come from a static import table.** A plugin is
   in-tree when its module's realpath, with symlinks resolved, sits under
   the gate-1-verified tendcf tree (decision D-a). Every in-tree plugin,
   frontends, supervisor renderers and importers alike, is found through a
   static import table, never through entry points, so distribution name
   and metadata prove nothing and an installed distribution cannot claim
   to be in-tree.
2. **Entry points are read only for third-party plugins**, and only after
   [#47](https://github.com/frdminc/tendcf/issues/47) exists. The loader
   lists every entry point, with no deduplication by distribution name
   (`importlib.metadata.entry_points()` drops a second distribution with
   the same name, so "a duplicate name is a compile error" could never
   fire for a second distribution called `tendcf`); refuses a duplicate
   name within a group; and refuses any non-tendcf entry point that uses a
   reserved name. Built-in names are reserved.
3. **Only named plugins are loaded.** Site-private names every plugin a
   compile uses: name → distribution, version and hash. An installed
   plugin that site-private does not name **is not selected**. This does
   not mean that installing it does nothing: `.pth` files and sdist build
   backends run code at install time, and a hash checked at load time
   against the installed `RECORD` file proves nothing. So, planned:
   1. third-party plugins are installed from a hash-locked resolution,
      wheels only, and the hash is checked at install time;
   2. each plugin's dependency closure is pinned;
   3. the gate tools' dependencies are locked (`uv lock --script`;
      `uv lock --help` lists `--script`) and the tools run offline.
4. **Importers follow the same rules as frontends**: an importer runs
   only if it is named and pinned. Which importers an operator may run is
   exactly the set site-private names.
5. **Until out-of-tree pinning exists**
   ([#47](https://github.com/frdminc/tendcf/issues/47)), a release build
   loads in-tree plugins only (`plugins/` and `contrib/`, at the pinned
   tendcf rev). That way the tendcf pin identifies the source of the
   compiler and of every plugin a release loads. Reproducing a release
   byte for byte also needs a fixed dependency and toolchain closure and
   controlled or recorded external inputs (environment, network); those
   controls are not specified yet (§7).
6. **Release builds never resolve `tendcf` (or `nix2cf`) from a package
   index.** The PyPI names are reserved with `0.0.0` placeholders
   ([tendcf](https://pypi.org/project/tendcf/),
   [nix2cf](https://pypi.org/project/nix2cf/)), which closes squatting
   and does not by itself stop dependency confusion.
7. **The environment does not choose the projector.** `TENDCF_DIR` and
   `--tendcf` (`compiler/nix2cf/cli.py`, `_tendcf_dir`) let the caller
   choose which tendcf checkout's projector is executed. A release build
   pins that to the gate-1-verified tree or refuses the override. This is
   a code change, planned.
8. **The release's `targets.json` `custom` records the plugin set**
   ([`change-process.md`](change-process.md) §3), and gate 5 compares it
   with the previous release's: a changed plugin set is a privileged
   change (above), so a plugin cannot be named now and change behaviour
   later without the ceremony marker. Planned, Step 6.

How an out-of-tree plugin earns trust (an OpenPGP web of trust) and how a
site manages its plugins (a `tendcf plugin` command) is
[#47](https://github.com/frdminc/tendcf/issues/47).

**Current schema version only.** The compiler renders only the current
`schema_version`. Its ability to render older versions (today nix2cf's
`SUPPORTED_SCHEMA_VERSIONS`, 3 to 5) is removed in the restructure (§5,
step 4). Map §9.6's ceiling design, under which the compiler renders each
host at the highest version that host last reported, stays the design;
it applies once the first device that is not an operator host enrolls,
and the multi-version render returns with it.

**Where a plugin lives.**

1. **In tree, `plugins/`.** The YAML frontend, the Nix frontend, every
   supervisor renderer, and any importer the project maintains. Held to
   this repository's full review rule.
2. **In tree, `contrib/`.** Third-party frontends and importers accepted
   into the repository with a lower bar. The lower bar waives support and
   maintenance promises only: the project does not promise to fix, keep
   or port a contrib plugin. It never waives the standing review rule
   (root `AGENTS.md`: every pull request gets a cross-model frontier
   review), because contrib code runs in the release pipeline with the
   same privilege as everything else. A contrib plugin is off unless
   site-private names it, like any other.
3. **Out of tree.** A pip package that registers under `tendcf.frontends`
   or `tendcf.importers`, the way Salt extensions and Ansible collections
   are shipped apart from Salt and Ansible. tendcf does not review it.
   Its output passes the same release gates as any plugin's, which bound
   its shape, not its faithfulness (above). A release build does not load
   one until #47 exists, and then only by the entry-point rules of
   "Activation" above.

## 5. Order of the move

| # | Change | State |
| --- | --- | --- |
| 1 | This documentation: the guide, the paper, the map (D46), the change process, the Linux targets plan, the glossary, this file; and the rename of the illustrative `nix2cf_*` keys (§6). Moves no files and changes no code or schema. | this change |
| 2 | Import `frdminc/nix2cf` with full history under `compiler/`; the root `README.md` follows. | done: [#45](https://github.com/frdminc/tendcf/pull/45), merged 2026-11-13 (`ca4fa90`) |
| 3 | Archive `frdminc/nix2cf`. | done 2026-11-13, right after #45 merged (README points here) |
| 4 | The restructure, one pull request: `bin/` → `tools/`; the Python package renamed `tendcf`; the compiler split into `compiler/` and `plugins/` with the two public entry-point groups; `tendcf compile` replaces `nix2cf buildfile`; older-version rendering removed; the device-boundary import check (§4). No alias, symlink or wrapper. Waits until open PRs #41 and #42 merge. | planned |
| 5 | The release pipeline (Step 6, [`change-process.md`](change-process.md) §10) and the §4 properties that depend on it: the plugin loader's activation steps; the two-job split and its signer backends; promotion of the pull request's artifacts and branch protection on site-private; the privileged-change checks of gate 5; the import step for external recipes with the Nix limits; the projection lint's cross-host check. None is built. | planned |

Step 4 rewrites every path reference in every file, dated records
included (handoffs, reviews, reconciliations, opinions, `deprecated/`):
djbclark, 2026-11-13, a one-time exception to their append-only
convention for this move, so that no path in the repository points at
a location that no longer exists. Prose that names nix2cf as the old
repository stays as history; only paths change. The living files found
on 2026-11-13 are listed below (`rg 'nix2cf'` and
`rg 'bin/(schema_lint|projector|xref_lint|overlay|flag_coverage|unit_classifier)'`
outside dated records). Rerun both over the whole tree before the
change, because the list moves:

1. **The compiler's in-tree check, and the rest of `compiler/`** (from
   #45): `compiler/nix2cf/cli.py` accepts an enclosing tendcf checkout
   only if it has `bin/projector.py` (`_in_tree_tendcf`), loads the
   projector from that path (`load_projector`) and names it in an error
   message; `compiler/nix2cf/__init__.py`, `compile.py` and
   `sitemodel.py` cite `bin/projector.py` or `bin/schema_lint.py` in
   docstrings and comments; so do `compiler/README.md` (links to
   `../bin/…`), `compiler/docs/DESIGN.md`, `compiler/pyproject.toml`,
   `compiler/examples/site/launchd-writers.yml` and
   `compiler/tests/test_compile.py`. The package name `nix2cf` itself
   (`compiler/pyproject.toml`, `compiler/AGENTS.md`,
   `compiler/scripts/check_schema_version.py`, the tests and examples)
   changes with the rename to `tendcf`.
2. **Schema description text**: `schema/common.schema.json` (three
   descriptions say nix2cf infers edges or fills in a field; under the new
   names that is the compiler), `schema/services.schema.json` and
   `schema/launchd-writers.schema.json` (`bin/schema_lint.py`).
3. **Examples**: `examples/services.yml`, `examples/launchd-writers.yml`,
   and the broken fixtures `04-nested-writer-prefix`,
   `107-launchd-writers-nixos-writer` and `123-launchd-writers-dpkg-writer`
   (their `launchd-writers.yml` copies the note) plus
   `examples/broken/README.md`.
4. **Repository files**: `AGENTS.md` (the standing rule names nix2cf as a
   repository, and its description of `check.yml` names the `bin/`
   tools; its rule that `docs/handoffs/` is append-only and never
   rewritten yields to the one-time path exception above, for paths
   only),
   `README.md`, `overlay/overlay.json`, `overlay/README.md`,
   `.github/workflows/check.yml`, `.githooks/pre-commit`,
   `deploy/linux/canary/check.py`, `tests/unit_classifier/test_logic.py`,
   and the tools' own cross-references inside `bin/`.
5. **Documents**: map D45 (`bin/projector.py` as the source of
   `tendcf-validate`), every living document `bin/xref_lint.py` lints,
   and, under the exception above, every dated record (handoffs, reviews,
   reconciliations, opinions, `deprecated/`): their paths are rewritten,
   their prose is not.

## 6. Names

1. **`tendcf compile`** is the compiler. By default it compiles every
   host; `tendcf compile --host NAME` renders one host, which is what
   `nix2cf buildfile` does today. It replaces `nix2cf buildfile` in the
   restructure (§5, step 4) with no alias. The Bcfg2 `buildfile` lineage
   (guide §4) is kept in prose only; no subcommand keeps the name.
2. **`nix2cf`** is the Nix module frontend, `plugins/frontends/nix/`. Up
   to 2026-11-13 the name meant the whole compiler; older documents and
   handoffs use it that way, and that prose is not rewritten (only their
   paths change, §5). Until the restructure the only thing that ships
   under the name is still the old compiler (`frdminc/nix2cf`, since #45
   `compiler/`, command `nix2cf buildfile`).
3. **`guix`** is the planned Guix authoring frontend,
   `plugins/frontends/guix/`.
4. **The illustrative `preview_services` / `preview_edges` keys.** The
   example's keys were `nix2cf_services` and `nix2cf_edges`. Checked on
   2026-11-13: they occurred only in the illustrative, preview-channel
   `host_specific.json` of guide §16.A, its copy in the paper, and review
   notes about it; the guide itself says that file does not load as
   Augments. No schema, fixture, projector or bundle carried them. On
   2026-11-13 they were renamed `preview_services` and `preview_edges`, in
   the same change as this file: illustrative only, chosen so they cannot
   be mistaken for the `tendcf_services` bundle or the real projected
   keys `tendcf_service` and `tendcf_interlock`. No schema change is
   involved (the goal file stays at `schema_version` 5). Dated review and
   reconciliation notes keep the old spelling.

## 7. Not decided here

- The Python interface each plugin kind implements (§3), and the format of
  the static import table through which the compiler finds every in-tree
  plugin (decided in §4: a table, never entry points).
- How the directories (`compiler/`, `plugins/`, `tools/`, `contrib/`) map
  onto the `tendcf` import package, and whether `schema/` ships as package
  data (an out-of-tree plugin that depends on tendcf needs the contract
  from the installed package).
- Where `tendcf-validate`'s source lives (§2), within the device boundary
  rules of §4.
- How site-private names its plugins: the file and its encoding, and how
  an in-tree plugin is named in it (§4, activation). The setting
  `external_import.without_ai` (§4, frontend inputs) lives in this file,
  so the file's format decides how that setting is written; TOML unless
  decided otherwise.
- Out-of-tree pinning and trust establishment, after which a release
  build may load an out-of-tree plugin
  ([#47](https://github.com/frdminc/tendcf/issues/47)).
- Whether the compile step has network access, the dependency and
  toolchain closure a release build runs in, and how external inputs are
  controlled or recorded. The guide calls the render a pure function of
  the Site Model (guide §4); until these are specified, a pinned
  site-private commit identifies a release's sources but does not by
  itself reproduce its bytes.
- The external-import step (§4, frontend inputs): the command, where the
  pin and the verdict are stored, what the AI review consists of, how the
  compiler decides that no AI is reachable, and whether a change to
  `external_import.without_ai` is itself a privileged change (it lowers a
  control, but it is not a change of the plugin set).
- Whether a pull request whose pin `url` or plugin set changed may run
  gate 2 before the ceremony marker is present (§4: the throwaway runner
  has no secrets but sees site-private data), and whether the tendcf URL
  is allowlisted (issue #48, F3, optional).
- Whether a pin may move backwards across a `schema_version` bump:
  define the rollback or forbid it (issue #48, F7). A backward move is
  privileged either way (§4).
- Who can read the release store (§4, confidentiality).
- Which importers, if any, get built.
- Guix System hosts with Shepherd as their supervisor (§3).

Settled by the 2026-11-13 decisions on issue #48 and no longer open: how
the loader proves a plugin is in-tree and how in-tree supervisor renderers
are found without a public group (D-a); whether recipes from other sites
may be evaluated unchecked (D-b); what a separate signing environment is
(D-c); how what is signed is tied to what was reviewed (D-d); and whether
the PyPI names `tendcf` and `nix2cf` are free (reserved on 2026-11-13 with
`0.0.0` placeholders, see issue #48's comment).
