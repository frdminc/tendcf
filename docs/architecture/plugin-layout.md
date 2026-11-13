# Repository layout and compiler plugins (decided 2026-11-13)

> Operator ruling, 2026-11-13; recorded as map D46
> ([`architecture-DEFINITIVE-v3.md`](architecture-DEFINITIVE-v3.md)).
> Status: decided, **almost none of it built**. §2 marks each part as
> exists today or planned. Where this file and the guide disagree on the
> current design, the guide wins.

## 1. The decision

1. `frdminc/nix2cf`, the compiler, folds into `frdminc/tendcf` with its
   full git history, first under `compiler/`. A separate pull request does
   the import; this document moves no files.
2. The repository takes the plugin-type layout of §2. It stays one Python
   package.
3. Plugins are found through Python entry-point groups (§3), so a
   third-party plugin can live outside this repository as an ordinary
   pip package.
4. Plugins run at compile time only (§4).
5. The compiler's command becomes `tendcf compile`. The name `nix2cf`
   moves to the Nix frontend (§6).
6. `frdminc/nix2cf` is archived once the move is done.

The consequence for the change process: the compiler is no longer a
separately pinned input. Schema and compiler change in the same commit,
so the two-repository bump order and the compiler's `tendcf.lock` go
away. Site inputs (site-shared, foreign sites, tool forks) keep
`site.lock` ([`change-process.md`](change-process.md) §2, §4).

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
    frontends/guix/          later: Guix System, Guile configuration → JSON via `guix repl`
    supervisors/launchd/     unit renderers, one per supervisor
    supervisors/systemd/
    supervisors/runit/
    importers/ansible/       optional one-shot migration into the Site Model
    importers/salt/
  contrib/                   in-tree third-party plugins, lower bar
  docs/ tests/
```

| Path | Today (2026-11-13) | Planned |
| --- | --- | --- |
| `schema/`, `examples/` | exist in tendcf | unchanged |
| `policy/`, `overlay/`, `deploy/` | exist in tendcf | unchanged |
| `tools/` | is `bin/`: standalone `uv run --script` files; tendcf has no `pyproject.toml` | `bin/` renamed `tools/`, after #41 and #42 merge |
| `compiler/` | `frdminc/nix2cf`: `nix2cf/cli.py`, `compile.py`, `sitemodel.py`; one command, `nix2cf buildfile` | imported with history, then `tendcf compile` |
| `plugins/frontends/yaml/` | `nix2cf/sitemodel.py` (YAML loading with duplicate-key refusal and line numbers) | split out of the compiler, still built in |
| `plugins/frontends/nix/` | only the hook: `nix2cf eval-nix FILE` evaluates a plain Nix expression with `nix-instantiate --eval --strict --json`; no module frontend | the D12 Nix module frontend, named `nix2cf` |
| `plugins/frontends/guix/` | nothing | later |
| `plugins/supervisors/launchd/` | inside `nix2cf/compile.py`, the only supervisor whose goal-file `unit` entry is rendered | split out |
| `plugins/supervisors/systemd/`, `runit/` | nothing: a service selected for a systemd or runit host is a compile error (`RENDERED_SUPERVISORS` in `compile.py`) | written as plugins ([`linux-targets.md`](linux-targets.md) §3, step 6) |
| `plugins/importers/` | nothing | optional |
| `contrib/` | nothing | as third parties contribute |
| entry-point groups | none; nix2cf's `pyproject.toml` declares only the `nix2cf` script | the three groups of §3 |

A supervisor plugin renders a service record into the goal file's `unit`
entry for that supervisor and resolves that supervisor's defaults (for
example `working_dir`). It does not write the unit file on the host; the
generic bundle under `policy/` does that, after approval and projection.

## 3. Plugin kinds and entry-point groups

| Kind | Entry-point group | What it is |
| --- | --- | --- |
| Frontend | `tendcf.frontends` | A language a site keeps authoring in. It turns its source into the Site Model's JSON, which the compiler then merges, checks and renders like any other. YAML and Nix are the two equal frontends of map D12; Guix may follow. |
| Supervisor | `tendcf.supervisors` | A unit renderer for one supervisor (launchd, systemd, runit, …): service record in, goal-file `unit` entry out (§2). |
| Importer | `tendcf.importers` | An optional one-shot migration from another tool's configuration (Ansible, Salt) into Site Model files, which the site then keeps and edits as its own. Not run on every compile. |

The difference between a frontend and an importer is what happens next. A
site authored through a frontend keeps its source in that language. A site
migrated by an importer keeps the Site Model files the importer wrote, and
the importer is not needed again.

Built-in plugins are found through the same groups as third-party ones.
The Python interface a plugin implements is not specified yet; it is to
be settled when the split is done (§5, step 3).

## 4. Rules for every plugin

**Compile time only.** No plugin runs on a device. A device receives a
signed release and runs CFEngine with `tendcf-validate` or tendcf-agent
(map D45), never the compiler.

**No way around consent.** Everything a plugin produces passes through the
same checks as the rest of the compiler's output: the Site Model and the
goal file are validated against `schema/`, and the goal file is projected
by the reference projector. A goal file the schema lint or the projector
rejects stops the release ([`change-process.md`](change-process.md) §6,
release gates 3 and 4). One that passes still reaches a device only as a
diff the device validates against its approved baseline (guide §7). A
plugin has no other path to a device.

**Where a plugin lives.**

1. **In tree, `plugins/`.** The YAML frontend, the Nix frontend, the
   supervisor renderers the project supports, and any importer the
   project maintains. Held to this repository's full review rule.
2. **In tree, `contrib/`.** Third-party plugins accepted into the
   repository with a lower bar. They pass the same schema lint and
   projector as everything else (the rule above does not relax).
3. **Out of tree.** A pip package that registers under one of the three
   entry-point groups, the way Salt extensions and Ansible collections are
   shipped apart from Salt and Ansible. tendcf does not review it; its
   output is checked like any other plugin's.

## 5. Order of the move

| # | Change | State |
| --- | --- | --- |
| 1 | This documentation: the guide, the paper, the map (D46), the change process, the Linux targets plan, the glossary, this file; and the rename of the illustrative `nix2cf_*` keys (§6). Moves no files and changes no code or schema. | this change |
| 2 | Import `frdminc/nix2cf` with full history under `compiler/`; the root `README.md` follows. | separate pull request |
| 3 | `bin/` → `tools/`; split the compiler into `compiler/` and `plugins/` with the three entry-point groups; the command becomes `tendcf compile`, `nix2cf buildfile` kept as a short-lived alias. Waits until open PRs #41 and #42 merge. | planned |
| 4 | Archive `frdminc/nix2cf`. | planned, once the move is done |

## 6. Names

1. **`tendcf compile`** is the compiler. Today the same code is
   `nix2cf buildfile`; that spelling stays as a short-lived alias.
2. **`nix2cf`** is the Nix module frontend, `plugins/frontends/nix/`. Up
   to 2026-11-13 the name meant the whole compiler; older documents and
   handoffs use it that way and are not rewritten.
3. **`guix`** is the planned Guix frontend, `plugins/frontends/guix/`.
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

- The Python interface each plugin kind implements (§3).
- The review bar for `contrib/` beyond the schema lint and the projector.
- Which importers, if any, get built.
- How out-of-tree plugins are pinned for a release. `site.lock` pins
  sources ([`change-process.md`](change-process.md) §2, rule 5); a plugin
  installed from pip is not yet covered by it.
