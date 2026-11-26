# tendcf compiler

The **compiler tool** for the [tendcf](..) architecture, living in `compiler/`
of the tendcf repository (imported from the archived `frdminc/nix2cf` repository
with full history on 2026-11-13 and renamed `tendcf` in D46 Step 4): **Site Model → merge → conflict check → (inference, later) →
per-host canonical goal file**.

YAML and JSON are the primary inputs (`plugins/frontends/yaml/loader.py`). An
optional Nix frontend (`plugins/frontends/nix/eval.py`, named `nix2cf`)
evaluates Nix expressions under restricted D-b limits via `tendcf eval-nix`.
In-tree plugins (frontends and supervisor renderers under `../plugins/`) are
loaded strictly through `compiler/tendcf/plugins.py`'s static import table
(never Python entry points). This directory does not hold site facts,
inventory, schemas, or the product engine.

**Schemas and types live in tendcf** (D21):
[`schema/`](../schema/),
[`examples/`](../examples/),
[`tools/schema_lint.py`](../tools/schema_lint.py),
[`tools/projector.py`](../tools/projector.py).
A schema change is a tendcf interface change. This tool consumes that
contract from the enclosing tendcf checkout; it does not own or copy it.

> Authority: `tendcf/docs/paper/tendcf-architecture-guide.md` (vetted
> current-state). If this README and that guide disagree, the guide wins.
> `architecture-DEFINITIVE-v3.md` is the implementer map and must agree
> with the guide. The compiler's own choices are in [`docs/DESIGN.md`](docs/DESIGN.md).

## What it does today

The primary compiler command: **`tendcf compile`** (replacing `nix2cf buildfile`
outright with no alias, per D46 §6) — render exactly what one host would
receive, without touching the host.

```sh
# Run from compiler/. The schemas and reference projector are found in the
# enclosing tendcf checkout; TENDCF_DIR (or --tendcf) is optional in dev mode
# and refused under --check-releasable.
uv run tendcf compile \
    --host mac --platform macos --supervisor launchd \
    --host-key ed25519:a1a1…a1 \
    --device-trust examples/site/device-trust.json \
    --site examples/site                  # services.yml, roles.yml, launchd-writers.yml
```

`--platform` (`macos` or `linux`) and `--supervisor` (`launchd`, `systemd`,
`runit` or `nixos`) are both required and have no default. It is written into the goal file's `device-trust.entries.supervisor`;
a `--device-trust` document that already carries a different `supervisor` is
refused. The output is **schema_version 9** only (tendcf's `goal-file.schema.json`;
older-version rendering was removed in D46 Step 4); CI fails when
`GOAL_FILE_SCHEMA_VERSION` and tendcf's schema const differ.

That prints the host's **goal file**: the canonical (RFC 8785, no trailing
newline) JSON document of guide §7 that a release carries, that consent binds
to, and that `tendcf/schema/goal-file.schema.json` checks. Add `--project` to
print instead the `host_specific.json` that tendcf's *device-side* projector
derives from it — the only shape `cf-agent` reads. The compiler does not emit
CFEngine Augments itself; see `docs/DESIGN.md` for why.

What the compile does, in order:

1. **Merge** — select the services that apply to the host (`hosts:` or the
   role's `main`), resolve every default the goal file refuses to leave
   implicit (`working_dir`, launchd booleans, interlock exit/timeout), map the
   Site Model's coverage pair onto the goal file's single enum, carry the
   unit-writer registry.
2. **Conflict check** — over the merged per-host picture: two services with
   one launchd label, two providers of one token, an id outside every declared
   writer prefix, a bundle in the wrong domain. A refusal names the resource,
   every writer with its `file:line`, the values, and a resolution. Never
   last-wins, and duplicate keys are refused at parse time.
3. **Render** — JCS bytes, validated against `goal-file.schema.json`, NFC
   checked, and (in the tests) projected through tendcf's reference projector
   with zero findings.

A `nixos` host gets no services: selecting any is refused ("host is
nixos-supervised; its units are the Nix configuration's"), and the goal file
carries `supervision: {"coverage": "deliberately-unmanaged"}` with the
`supervisor` entry, which tendcf's projector reads as `{"vars":{}}`.

`examples/site/` is tendcf's own fixtures with one edit, so an interlock
renders. Fixture, not site data.

### Multi-site workspace (`tendcf workspace` and `--site-name`)

For multi-site local ops workspaces under `~/tendcf-ops` (override:
`--ops-root` or `TENDCF_OPS_ROOT`), a single validated site slug pairs
`tendcf-private-<site>` (required primary site root) with optional
`tendcf-public-<site>` (publishable recipes/exports):

```sh
# Inspect the resolved workspace (human-readable or --json)
uv run tendcf workspace --site-name djbclark --json
uv run tendcf workspace --list

# Compile from a workspace site (prints selected site + source to stderr)
uv run tendcf compile \
    --host mac --platform macos --supervisor launchd \
    --host-key ed25519:a1a1…a1 \
    --device-trust ~/tendcf-ops/tendcf-private-djbclark/device-trust.json \
    --site-name djbclark
```

- **Selector precedence:** `--site-name` > `TENDCF_SITE` > XDG `active-site`
  file (`$XDG_CONFIG_HOME/tendcf/active-site` when absolute, else
  `~/.config/tendcf/active-site`), or explicit `--config PATH` on `workspace`
  (mutually exclusive with `--site-name`, honored ahead of ambient
  `TENDCF_SITE`, and failing closed if missing). Fails closed when unset (never
  globs a sole checkout; zero legacy aliases). On `compile`, XDG `active-site`
  is read only when workspace mode is explicitly opted in (`--workspace`,
  `--ops-root`, or ambient `TENDCF_SITE` with no `--site` or explicit file
  flags), keeping omitted-`--site` invocations hermetic.
- **`--site DIR`** and explicit `--services`/`--roles`/`--launchd-writers`
  remain available and are mutually exclusive with `--site-name`, `--ops-root`,
  and `--workspace`.
- **`<ops_root>/tendcf`** is reported by `tendcf workspace` strictly as
  informational metadata; `tendcf compile` never auto-loads schemas or
  `tools/projector.py` from a sibling `<ops_root>/tendcf` checkout.
- **Release guard (`--check-releasable`):** refuses `--override-input`,
  `--tendcf`, and `$TENDCF_DIR` overrides so release builds run strictly from
  the verified in-tree tendcf checkout (D46 §4 Activation step 7 / F9).
- **Dev-only `--override-input NS=PATH`** (repeatable on `compile` and
  `workspace`): today it validates the namespace and target directory, warns
  loudly on stderr, records taint on `WorkspaceResolution` and `CompileResult`,
  refuses `-o`/`--output` writes unless `--allow-tainted` is also passed, and
  fails `--check-releasable` / `assert_releasable()`. Actual `site.lock`
  foreign-input substitution is not yet wired into `compile_host`; future
  release/signing pipelines must call the release gate and refuse override
  builds.
- **XDG runtime state:** `workspace.state_dir()` (`$XDG_STATE_HOME/tendcf` or
  `~/.local/state/tendcf`) and `workspace.cache_dir()` (`$XDG_CACHE_HOME/tendcf`
  or `~/.cache/tendcf`) keep mutable state out of git checkouts.

## Not here yet

- **Inference** (`provides`/`requires` → ordering edges): waits until real
  types exist on two platforms (guide §10, §18 Step 3), and the goal file has no
  edge kind to render into.
- **Units for any supervisor but launchd** (Steps 1–2, 4, 6). A `systemd` or
  `runit` host gets its `supervisor` entry, but a service selected for it is a
  compile error via its in-tree stub renderer (`plugins/supervisors/{systemd,runit}/renderer.py`):
  the systemd renderer (and with it the v2 `restart`/`wanted_by` fields) is
  step 6 proper. `nixos` needs no renderer, as above. Android has no supervisor
  decided: it is not a `--platform` choice.
- **Extra-entry reporting** (device-side, tendcf-agent) and `def.json`.
- **Inventory, trust policy, peer actions** as Site Model inputs (Step 0
  remaining): the host key, platform, supervisor and `device-trust` domain are
  passed on the command line until those schemas exist.
- **Tombstones** from the Site Model (it cannot yet say "absent").
- **The Nix module frontend** (D12). `tendcf eval-nix FILE` evaluates a plain
  Nix expression through `plugins/frontends/nix/eval.py` (`nix2cf`) under the
  tested D-b `restrict-eval` limits; the integration test is skipped without a
  Nix install.

Every choice the paper leaves open is marked in `tendcf/compile.py` and
tabulated in `docs/DESIGN.md`.

## Tests

```sh
uv run --locked pytest        # from compiler/; TENDCF_DIR=<dir> overrides in dev mode
```

Goldens under `tests/golden/` are the compiler's own regression test; update
them deliberately with `TENDCF_UPDATE_GOLDEN=1` and read the diff first.
CI runs the same command from the `compiler` job of the root `.github/workflows/check.yml`.

License: [GPL-3.0-or-later](../LICENSE) (the repository's license).
