# Repository layout and compiler plugins (decided 2026-11-13)

> Operator ruling, 2026-11-13; recorded as map D46
> ([`architecture-DEFINITIVE-v3.md`](architecture-DEFINITIVE-v3.md)).
> Status: decided, **almost none of it built**. §2 marks each part as
> exists today or planned. Where this file and the guide disagree on the
> current design, the guide wins.

## 1. The decision

1. `frdminc/nix2cf`, the compiler, folds into `frdminc/tendcf` with its
   full git history, first under `compiler/`. A separate pull request
   ([#45](https://github.com/frdminc/tendcf/pull/45)) did the import; it
   merged on 2026-11-13 (merge commit `ca4fa90`). This document moves no
   files.
2. The repository takes the plugin-type layout of §2. It becomes one
   Python package, import name `tendcf` (today's `nix2cf` package is
   renamed; how the directories map onto it is open, §7).
3. Frontends and importers are found through the public Python
   entry-point groups `tendcf.frontends` and `tendcf.importers` (§3), so a
   third-party frontend or importer can live outside this repository as
   an ordinary pip package. Supervisor renderers are in tree only; there
   is no public `tendcf.supervisors` group (§3).
4. Plugins run at compile time only, and they are trusted build-time code
   that the operator explicitly allows, not sandboxed code (§4).
5. A plugin loads only if site-private names it (§4, activation).
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
| `plugins/frontends/guix/` | nothing | later |
| `plugins/supervisors/launchd/` | inside `nix2cf/compile.py`, the only supervisor whose goal-file `unit` entry is rendered | split out |
| `plugins/supervisors/systemd/`, `runit/` | nothing: a service selected for a systemd or runit host is a compile error (`RENDERED_SUPERVISORS` in `compile.py`) | written in tree ([`linux-targets.md`](linux-targets.md) §3, step 6) |
| `plugins/importers/` | nothing | optional |
| `contrib/` | nothing | as third parties contribute |
| entry-point groups | none; nix2cf's `pyproject.toml` declares only the `nix2cf` script | the two public groups of §3 |

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
| Frontend | `tendcf.frontends` (public) | A language a site keeps authoring in. It turns its source into the Site Model's JSON, which the compiler then merges, checks and renders like any other. YAML and Nix are the two equal frontends of map D12; Guix may follow as an authoring frontend (Guile records → Site Model JSON). |
| Importer | `tendcf.importers` (public) | An optional one-shot migration from another tool's configuration (Ansible, Salt) into Site Model files, which the site then keeps and edits as its own. Not run on every compile. |
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

Built-in frontends and importers register under the same groups as
third-party ones, and their names are reserved (§4). The Python interface
a plugin implements is not specified yet; it is to be settled when the
split is done (§5, step 4).

## 4. Rules for every plugin

**Compile time only.** No plugin runs on a device. A device receives a
signed release and runs CFEngine with `tendcf-validate` or tendcf-agent
(map D45), never the compiler.

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
   projection (guide §7).
2. A plugin cannot emit a shape the schema forbids. The schema lint and
   the projector reject it, and a goal file they reject stops the release
   ([`change-process.md`](change-process.md) §6, release gates 3 and 4).
3. A plugin **can** make the goal file say something other than what the
   Site Model says. Valid is not faithful: a buggy or malicious renderer
   or frontend can emit a schema-valid entry with a different argv, a
   different `run_as`, an extra service or a tombstone. On a consented
   device the check is the person's yes over the device-side diff. An
   operator host applies without a local yes (change-process §8), so
   there the only human check is the pull request's preview diff.

**Release gates and signing run apart from plugins.** Release gates 3 to 5
(schema lint, projector, preview diff) and signing (gate 6) run in a
separate environment in which no plugin distribution is installed, and
the compile step holds no signing key
([`change-process.md`](change-process.md) §6). The gates' preview diff is
computed apart from the plugins, but it diffs their output, so it shows
what they rendered. A preview diff or an `explain-hunk` attribution
produced on the compile side (D44, map §9.5) is compiler output and
inherits the plugins' trust.

**Activation: a plugin loads only if site-private names it.**

1. Site-private names every plugin a compile uses: name → distribution,
   version and hash. An installed plugin that site-private does not name
   is ignored; installing a package activates nothing.
2. A duplicate name within a group is a compile error, never a silent
   winner (the same rule map §3 applies to identities from two peer
   inputs).
3. Built-in names are reserved: no other distribution may register them.
4. Until out-of-tree pinning exists
   ([#47](https://github.com/frdminc/tendcf/issues/47)), a release build
   loads in-tree plugins only (`plugins/` and `contrib/`, at the pinned
   tendcf rev). That way the tendcf pin identifies the source of the
   compiler and of every plugin a release loads. Reproducing a release
   byte for byte also needs a fixed dependency and toolchain closure and
   controlled or recorded external inputs (environment, network); those
   controls are not specified yet (§7).
5. The release's `targets.json` `custom` records the plugin set
   ([`change-process.md`](change-process.md) §3).

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
   one until #47 exists.

## 5. Order of the move

| # | Change | State |
| --- | --- | --- |
| 1 | This documentation: the guide, the paper, the map (D46), the change process, the Linux targets plan, the glossary, this file; and the rename of the illustrative `nix2cf_*` keys (§6). Moves no files and changes no code or schema. | this change |
| 2 | Import `frdminc/nix2cf` with full history under `compiler/`; the root `README.md` follows. | done: [#45](https://github.com/frdminc/tendcf/pull/45), merged 2026-11-13 (`ca4fa90`) |
| 3 | Archive `frdminc/nix2cf`. | done 2026-11-13, right after #45 merged (README points here) |
| 4 | The restructure, one pull request: `bin/` → `tools/`; the Python package renamed `tendcf`; the compiler split into `compiler/` and `plugins/` with the two public entry-point groups; `tendcf compile` replaces `nix2cf buildfile`; older-version rendering removed; the device-boundary import check (§4). No alias, symlink or wrapper. Waits until open PRs #41 and #42 merge. | planned |

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

- The Python interface each plugin kind implements (§3), and how the
  compiler finds its in-tree supervisor renderers without a public group.
- How the directories (`compiler/`, `plugins/`, `tools/`, `contrib/`) map
  onto the `tendcf` import package, and whether `schema/` ships as package
  data (an out-of-tree plugin that depends on tendcf needs the contract
  from the installed package).
- Where `tendcf-validate`'s source lives (§2), within the device boundary
  rules of §4.
- How site-private names its plugins: the file and its encoding, and how
  an in-tree plugin is named in it (§4, activation).
- Out-of-tree pinning and trust establishment, after which a release
  build may load an out-of-tree plugin
  ([#47](https://github.com/frdminc/tendcf/issues/47)).
- Whether the compile step has network access, the dependency and
  toolchain closure a release build runs in, and how external inputs are
  controlled or recorded. The guide calls the render a pure function of
  the Site Model (guide §4); until these are specified, a pinned
  site-private commit identifies a release's sources but does not by
  itself reproduce its bytes.
- Which importers, if any, get built.
- Guix System hosts with Shepherd as their supervisor (§3).
- Whether the PyPI names `tendcf` and `nix2cf` are free; unchecked.
