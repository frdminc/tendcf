# 05 — Response: the code, against the goal (G1–G9)

Targets: the code at `eefea3c`: `compiler/` (nix2cf), `policy/`, `schema/`, `bin/`, `tests/`, `deploy/` and `.github/workflows/`; for the Android items, the sibling repositories stayturgid and ShizukuTendCF.

Base commit: eefea3c

How this was produced: one reviewing agent (Claude Opus), then an independent checking agent that tried to refute each finding; nothing was built or executed, so every defect is established by reading the code.

Items by Weight after corrections: blocks-goal 22, improves 21, nit 2 (45 items).

Reviewer: Opus 5.5 (Claude Code sub-agent), 2026-11-13. Base `eefea3c` (a tendcf worktree at that commit). Read-only: no file changed in any repository, no build, no test suite, no live host. graft was run from the main tendcf checkout (same commit; the worktree has no `graft/` and building one would write to it). Paths are relative to the tendcf repository unless a sibling repository is named.

Sources consulted: firecrawl (scrape) — Nix manual `restrict-eval`/`pure-eval` (https://nix.dev/manual/nix/2.28/command-ref/conf-file.html#conf-restrict-eval: restrict-eval is `false` by default); launchctl(1) (https://ss64.com/mac/launchctl.html: `load`/`unload` "will only return a non-zero exit code due to improper usage. Otherwise, zero is always returned"; `bootstrap`/`bootout` are the current verbs). CFEngine key type taken from the cfengine-core fork's source, `cf-key/cf-key-functions.c:322` (`RSA_generate_key_ex`). Two firecrawl web searches returned only irrelevant results.

## Summary answers to (a)–(g)

**(a) G8 state 1 gap list, in dependency order.** Sizes are guesses.

| # | Gap | Exists today | Missing | Size (guess) | Item |
|---|---|---|---|---|---|
| 1 | Fork build for macOS, packaged, in CI | Linux build only: `.github/actions/build-fork/action.yml`, `linux.yml:25-118`; a hand-made Mac dev build (the one AGENTS.md names) | A macOS job that builds `overlay/fork.json`'s pin and runs `tests/policy/run.sh` with the launchd path live | ~150 lines YAML, 1–3 days | C-ci-01 |
| 2 | Root install and a root `cf-execd` on the Mac | `deploy/linux/tendcf-install.sh` (refuses non-Linux at :47) | A macOS installer and a LaunchDaemon for `cf-execd` | ~200 lines, 1–2 days | C-deploy-01 |
| 3 | A launchd adapter that converges | `policy/tendcf_services.cf:274-317`, `policy/templates/launchd.plist.mustache` | env, reload on change, error visibility, tombstone guard, backup files, a "data loaded" guard, tests | ~150 policy + ~150 test lines, 3–5 days | C-policy-01..06, C-tests-01 |
| 4 | Device identity and a signed update | ed25519 `host` patterns in schemas; approval-record `signature` member (fixtures only) | A device key that exists, a signature over the goal file, verification before projection | 400–800 lines, 1–2 weeks | C-schema-01, C-schema-02, C-bin-01 |
| 5 | See and refuse (G4's minimum) | `goal-diff.schema.json`; lint-only `apply_diff` (`bin/schema_lint.py:1821`) | A diff the owner reads and accepts or refuses on the device | 300–600 lines, ~1 week | C-bin-03, C-deploy-02 |
| 6 | Nix authoring with NixOS-style options | `nix2cf eval-nix` (`compiler/nix2cf/cli.py:150-171`), a plain attrset | A module system with tendcf options, and a whole-site Nix input | 300–600 lines, 1–2 weeks (carry-over importers: +1–2 weeks) | C-compiler-01 |
| 7 | Android in the contract | nothing: the compiler refuses android (`compile.py:85-88`), the schema has no Android supervisor or domain | Android domains (apps per user/profile, appops, settings, grants) in a schema bump, plus compiler rendering | ~400 schema + ~300 compiler lines, 1–2 weeks | C-schema-03, C-compiler-05 |
| 8 | Android client | nothing in tendcf; substrate in stayturgid's Kotlin agent, Termux CFEngine and ShizukuTendCF | Receive, verify, diff/consent UI, apply via Shizuku, report | 3–6k Kotlin lines, 4–8 weeks (less if Termux CFEngine converges: needs a ruling) | C-android-01..05 |
| 9 | Transport and peer handshake | nothing (inventory §H "Push: nothing") | Mac to Android delivery, and acceptance from any peer that completes the handshake | 1–2 weeks | C-schema-02 |
| 10 | Logs archived on the Mac | `schema/report-row.schema.json` (only `bin/unit_classifier.py`, Linux, uses it) | A sender on Android, a receiver and archive on the Mac, and a goal-file shape for both | 300–500 lines, ~1 week | C-macos-02 |
| 11 | Fail-closed CMDB on the Mac build | PR #41 (open) | Merge it, and add a policy-side guard | days | C-policy-06 |

The total is a guess of 3 to 5 months of focused work. Rows 4, 5 and 8 dominate.

**(b) Share of code by platform** (`wc -l` over the tracked files in the target dirs: 16,181 lines).
1. Linux-only: about 5,200 lines (32%). This is `bin/unit_classifier.py` 896 plus `tests/unit_classifier/` 3,135, `deploy/` 405, `tests/deploy/` 162, `run.sh` check 6 (about 194 lines, :163-356), the systemd half of the policy (66 lines naming systemd) and its template (13), `linux.yml` 118 and `build-fork` 81.
2. macOS-specific: about 60 lines, all policy and template, plus the launchd-only renderer inside `compiler/` (1,139 Python lines that render launchd units only).
3. Android: 0.
4. Platform-neutral contract machinery: the rest, about 10,900 lines (schemas, schema_lint 2,260, projector 620, overlay 2,029 plus 626, xref and flag lint). It is neutral in platform but CFEngine-shaped (C-bin-02).
5. Linux-shaped assumptions baked into shared parts: the v5 `unit-package` writer enum `["dpkg"]` (`schema/goal-file.schema.json:544-551`); the unit-writer key language of `.service/.socket/.timer/.path` (:520-524); the `tendcf-install` writer "systemd hosts only" (:535); a supervisor enum with no Android value (:679); `/usr/bin/systemctl` hard-coded (`policy/tendcf_services.cf:321-350`); `ldd` and systemd in the only installer; a `run_as` Unix-user pattern (:380) that has no meaning for Android app UIDs.

**(c) The Nix frontend** is a JSON evaluator: about 20 lines that shell out to `nix-instantiate --eval --strict --json`. It has no options, no `lib`, no modules and no way to read a NixOS or nix-darwin configuration. Its example covers services only. A NixOS host is passthrough by design (`NIXOS_REFUSAL`, `compile.py:96`): tendcf writes none of its units, and nothing imports them into the Site Model. The distance to G2 is the whole frontend (C-compiler-01, C-compiler-02, C-tests-03).

**(d) macOS.** The launchd adapter is about 25 lines of policy and a 32-line plist template, and it has never been executed in any test or CI run (C-tests-01). On reading it:
1. it drops `env`;
2. it never reloads a changed job;
3. it cannot see a failure, because `launchctl load` returns 0;
4. it deletes any named plist on a tombstone, guarded only by a lint that never runs on a device;
5. it leaves an edit backup beside the plist.

Nothing in tendcf installs or schedules it on a Mac, and there is no macOS CI.

**(e) Android.** stayturgid already runs CFEngine 3.27.1 in Termux (`cf-agent` and `cf-serverd`) and has a Kotlin Shizuku agent. Its Ansible `android_common` modules are the resource vocabulary an Android client needs, including `--user N` for Island profiles. Three things in them contradict tendcf's goal and decisions:
1. Key trust over the tailnet is trust-on-first-use, which is not G3's handshake.
2. The Mac pushes with `cf-runagent`, which makes it a control node.
3. ShizukuTendCF's signer allowlist ignores the owner's revoke and deny.

D45 (a Kotlin agent) is consistent with stayturgid's native agent. It is in tension with the CFEngine that already runs on the fleet. Items C-android-01..05.

**(f) Defects.** The strongest:
1. shell injection through interlock `pre_action` (C-policy-01);
2. env silently dropped (C-policy-02);
3. the launchd tombstone (C-policy-04);
4. eval-nix's impure evaluation of untrusted Nix on the authoring machine (C-compiler-02);
5. unvalidated output with exit 0 outside a checkout when neither `--tendcf` nor `$TENDCF_DIR` is given (C-compiler-03);
6. a `platform: any` crash (C-compiler-04);
7. tests that cannot fail (C-tests-02, C-tests-03);
8. schemas that nothing consumes (C-schema-04).

**(g) G4 attach points.** These are in C-g4-01..04.
1. The scan and confidence figure attach between `conflict_check` and `canonical_bytes`, on the diff.
2. Highlighting needs a source map that the YAML loader half-has and the Nix path lacks.
3. The CLI attaches as a new subcommand beside `buildfile`.
4. The TUI attaches device-side over the same diff and report. Nothing for any of these exists.

---

## Compiler

### C-compiler-01: The Nix frontend evaluates JSON; it is not NixOS-style options

**Target:** `compiler/nix2cf/cli.py` `cmd_eval_nix`, at "Evaluates a Nix expression to the JSON the compiler consumes"
**Kind:** add
**Goal:** G2
**Weight:** blocks-goal
**Finding:** `eval-nix` runs `nix-instantiate --eval --strict --json FILE` and pretty-prints the result. That is all there is. The example is a plain attribute set with "No nixpkgs, no `lib`, no module system". It encodes only `services.yml`: roles and launchd-writers have no Nix form. `buildfile` cannot consume `eval-nix` output directly. It needs three separate files (`--services`, `--roles`, `--launchd-writers`), and it parses any non-`.json` suffix as YAML. So "existing NixOS and nix-darwin configs carry over" is entirely unbuilt. A NixOS host is passthrough by design (`NIXOS_REFUSAL`): tendcf writes none of its units, so a NixOS configuration "carries over" only by staying where it is; nothing imports it into the Site Model.
**Evidence:** `compiler/nix2cf/cli.py:150-171`, `:82-90`; `compiler/nix2cf/sitemodel.py:99-112`; `compiler/examples/site/site.nix:1-13`; `compiler/nix2cf/compile.py:96`, `:430-434`.
**Proposed text:**

> Build the Nix frontend as a module evaluation, not a JSON dump: `lib.evalModules` over a `tendcf` option tree (`tendcf.services.<name>`, `tendcf.roles`, `tendcf.writers`, later `tendcf.android.*`), evaluated with `--restrict-eval`, whose `config.tendcf` is the whole Site Model in one document. Add two importers that read an existing configuration's evaluated options: nix-darwin `config.launchd.daemons.<name>.serviceConfig` (ProgramArguments, UserName, WorkingDirectory, EnvironmentVariables, RunAtLoad, KeepAlive) to launchd services, and NixOS `config.systemd.services` to systemd services. `buildfile --site site.nix` takes the result directly.

**Merge:** needs the operator's ruling first (the option namespace and whether "carry over" means import or co-existence)
**Checked:** verified (read cli.py, sitemodel.py, site.nix); independently checked 2026-11-13: weakened, corrected (latent: no Nix frontend in use)

### C-compiler-02: `eval-nix` evaluates untrusted Nix with full file and network access

**Target:** `compiler/nix2cf/cli.py` `cmd_eval_nix`, at `[exe, "--eval", "--strict", "--json", str(args.file)]`
**Kind:** correct
**Goal:** G4, G6
**Weight:** improves
**Finding:** Config is AI-authored (G6), so a `.nix` file is untrusted input. The evaluator is run with defaults. `restrict-eval` is false by default, so `builtins.readFile` of the author's SSH private key or `builtins.fetchurl` works, and the value is printed to stdout and can travel into a goal file. A file named after `--` (`nix2cf eval-nix -- -x`) reaches nix-instantiate as an option, because the argv has no `--` before the path. Import-from-derivation is also on by default, so evaluation can trigger builds. Scope: this runs on the authoring machine, not on a managed device; no device runs `eval-nix`.
**Evidence:** `compiler/nix2cf/cli.py:155-160`; Nix manual: https://nix.dev/manual/nix/2.28/command-ref/conf-file.html#conf-restrict-eval ("Default: false").
**Proposed text:**

> Run the evaluator as `nix-instantiate --eval --strict --json --option restrict-eval true --option allowed-uris '' -I site=<site dir> -- <file>` and refuse a file outside the site directory. A frontend that reads anything else is a compile error.

**Merge:** replace that call
**Checked:** verified (code read; Nix default from manual); not run; independently checked 2026-11-13: weakened, corrected (latent: authoring machine only; no device runs it)

### C-compiler-03: Outside a tendcf checkout the compiler writes an unvalidated goal file and exits 0

**Target:** `compiler/nix2cf/compile.py` `compile_host`, at "no tendcf schema directory found"
**Kind:** correct
**Goal:** G1, G4
**Weight:** improves
**Finding:** When neither `--tendcf` nor `$TENDCF_DIR` is given, `_in_tree_tendcf` deliberately returns None for any installed layout (pip, venv, `--target`). Then:
1. `buildfile` skips Site Model validation (`cli.py:101`);
2. it compiles anyway;
3. it prints only a `note:`;
4. it writes the goal file with exit 0.

The docstring "Raises CompileError; never emits a wrong file" is then false. Unvalidated input also reaches `rec["launchd"]`, `rec["bundle"]` and the like as raw KeyErrors. This is the path every adopter (G8 state 3) takes.
**Evidence:** `compiler/nix2cf/cli.py:40-59`, `:99-113`; `compiler/nix2cf/compile.py:663`, `:707-711`.
**Proposed text:**

> Ship the schemas and the projector as package data of the compiler and validate always; with no schemas available, refuse (exit 2) rather than emit.

**Merge:** replace that branch
**Checked:** verified (read; not run); independently checked 2026-11-13: weakened, corrected (latent)

### C-compiler-04: A `platform: any` service crashes the compiler with a traceback

**Target:** `compiler/nix2cf/compile.py` `conflict_check`, at `entry_id = sel.record["launchd"]["label"]`
**Kind:** correct
**Goal:** G1
**Weight:** improves
**Finding:** `select_services` accepts `platform in (host.platform, "any")`. `services.schema.json` requires `launchd` only `if platform == macos`. So a schema-valid `platform: any` service selected for a launchd host has no `launchd` key, and `conflict_check` raises KeyError. The CLI catches only `CompileError`, so the user gets a Python traceback.
**Evidence:** `compiler/nix2cf/compile.py:238`, `:293`, `:535`; `schema/services.schema.json` top-level `allOf` (macos→launchd, linux→systemd); `compiler/nix2cf/cli.py:121-127`.
**Proposed text:**

> In `select_services`, a selected service that lacks the host supervisor's unit block (`launchd` on a launchd host) is a compile error naming the record and line: "service X is platform any but has no launchd block; add one or set platform".

**Merge:** insert after the platform check
**Checked:** verified by reading (not executed); independently checked 2026-11-13: confirmed by reading, not run (latent: no example uses `platform: any` without a launchd block)

### C-compiler-05: Android is refused at every layer although the Site Model admits it

**Target:** `compiler/nix2cf/compile.py` `PLATFORM_SUPERVISORS`
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** The Site Model's `platform` enum includes `android`, and the example declares an `android-termux-services` domain. But `PLATFORM_SUPERVISORS` has no android row, `--platform` offers only macos and linux, and the goal file has no Android supervisor or domain. G5's platform 2 cannot be compiled for at all.
**Evidence:** `compiler/nix2cf/compile.py:81-88`; `compiler/nix2cf/cli.py:182`; `schema/services.schema.json` (`platform` enum `["macos","android","linux","any"]`); `compiler/examples/site/site.nix:27-32`.
**Proposed text:**

> Add `android` as a platform whose host fact is not a unit supervisor but an agent (`tendcf-agent`), with its own domains (C-schema-03); render those domains, and refuse services (launchd/systemd units) on it.

**Merge:** needs the operator's ruling first (C-android-01 decides what converges on Android)
**Checked:** verified; independently checked 2026-11-13: confirmed

### C-compiler-06: Only one actuated domain exists, so logs, files and packages have nowhere to go

**Target:** `compiler/nix2cf/compile.py` `SUPERVISION_DOMAIN` and `render_goal_file`, at "keep one host's services in one domain"
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** The compiler maps exactly one Site Model domain to `supervision` and refuses a host whose services span two. The "Site-Model-domain → goal-file-domain mapping is not written down anywhere". A Mac that archives logs and an Android device that ships them need state beyond "a daemon runs": a log endpoint, a receiver, retention, a forwarding config, and files. The pipeline has no domain for any of these, and the projector projects only `supervision`.
**Evidence:** `compiler/nix2cf/compile.py:63-74`, `:503-511`; `bin/projector.py:127-128`.
**Proposed text:**

> Write the domain mapping down and add the first two non-service domains the finish line needs: `log-forward` (client: where reports go, signed by whom) and `log-archive` (server: where they land, retention).

**Merge:** needs the operator's ruling first (schema bump)
**Checked:** verified; independently checked 2026-11-13: confirmed

### C-compiler-07: No tombstones, so removing a service changes nothing on the device

**Target:** `compiler/README.md` "Not here yet", at "Tombstones from the Site Model"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The compiler emits only `state: present`. A service deleted from the Site Model simply vanishes from the next goal file. The policy acts only on ids it is given, and extra-entry detection is not wired, so the daemon keeps running and its plist stays. G4's "exact difference" then reports a removal that never happens on the device. The removal hunk exists in the diff schema but not in reality.
**Evidence:** `compiler/README.md:93`; `compiler/nix2cf/compile.py:536-551` (present only); `policy/tendcf_services.cf:104-105` (acts on `getindices` of the given ids only).
**Proposed text:**

> Derive tombstones from the previous accepted goal file (baseline) rather than from the Site Model: an id present in the baseline and absent from the new render becomes `{"state":"absent"}` in a comprehensive domain.

**Merge:** needs the operator's ruling first (where the baseline lives, C-bin-01)
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### C-compiler-08: Invariants the lint enforces are not enforced at compile time

**Target:** `compiler/nix2cf/compile.py` `render_goal_file`, at `owners = [w for w in writers if _prefix_matches(...)]`
**Kind:** correct
**Goal:** G4
**Weight:** improves
**Finding:** Several rules are lint-only (`bin/schema_lint.py`), but the compiler never imports or runs that lint on user input or on its own output:
1. nested writer prefixes are refused (:1421-1429);
2. goal-file unit-writer keys must not overlap;
3. every interlock bundle must be used;
4. a tombstone must fall under a cfengine prefix.

With nested prefixes the compiler takes `owners[0]`, the first declared, not the most specific, so its writer check depends on file order. The tests call the lint's cross-file check (`test_compile.py:70-74`); the CLI does not.
**Evidence:** `compiler/nix2cf/compile.py:599-612`; `bin/schema_lint.py:1408-1431`, `:1611`; `schema/goal-file.schema.json:520` ("Lint: no two keys overlap"); `rg lint compiler/nix2cf` (docstring mentions only).
**Proposed text:**

> Move the cross-file checks into an importable library that `compile_host` runs over the Site Model and the rendered goal file, and that the device validator runs again; the lint calls the same library.

**Merge:** needs a design decision (library location under the D46 layout)
**Checked:** verified (read); independently checked 2026-11-13: confirmed (latent)

### C-compiler-09: Source locations exist for YAML only, so the Nix path cannot point at code

**Target:** `compiler/nix2cf/sitemodel.py` `load_document`, at `return Document(path, data)`
**Kind:** add
**Goal:** G2, G4
**Weight:** improves
**Finding:** Locations are recorded per YAML mapping only (`_LineLoader`). JSON input gets none, and the Nix route goes through JSON, so every error message and any future highlight points at a temporary file, not at the line in the `.nix` file. Entries in the goal file carry no provenance back to the Site Model at all.
**Evidence:** `compiler/nix2cf/sitemodel.py:33-45`, `:99-104`; `compiler/nix2cf/cli.py:169`.
**Proposed text:**

> Carry a source map beside the goal file (`entry pointer -> file:line`, from `builtins.unsafeGetAttrPos` on the Nix side and `_LineLoader` on the YAML side); it is not part of the signed bytes.

**Merge:** insert as a new compiler output
**Checked:** verified (read); `unsafeGetAttrPos` availability not checked

## Policy

### C-policy-01: Interlock `pre_action` argv is joined with spaces and run through a shell as root

**Target:** `policy/tendcf_services.cf` bundle `tendcf_interlocks`, at "acceptable here since pre_action.command comes from our own schema-validated goal file"
**Kind:** correct
**Goal:** G4, G6
**Weight:** blocks-goal
**Finding:** The policy builds the command string with `join(" ", …[pre_action][command])` and runs it with `useshell => "true"`. The goal-file schema puts no alphabet limit on `pre_action.command` items (contrast the systemd argv alphabet). So `["tailscale", "status; curl …|sh"]` runs as root every five minutes. Under G6 the author is an AI, which is exactly the input the comment calls trusted. A mechanical diff shows an argv array, but the device executes a different thing (a shell string), so what the owner sees is not what runs. The only other filter on these strings is the projector's refusal of `$(`, `${`, `@(`, `@{` (`bin/projector.py:145`). It does not stop `;`, `|`, `&&`, backticks or redirection, and `tendcf-install.sh data` installs a projection without running the projector. No other lint restricts them: `bin/schema_lint.py`, `bin/xref_lint.py`, `bin/overlay.py` and the compiler never mention `pre_action`, and the Site Model's `common.schema.json` items are plain strings too. The proposed text first given here (promiser `command[0]` with "absolute path required by schema", `arglist` from a container slice) cited a schema rule that does not exist and is not proven expressible in CFEngine: `getvalues()` can turn the container path into an slist, but whether that slist, split into head and tail, parses as an `arglist` is exactly what the policy comment reports failing, and needs a real `cf-promises` run. It is replaced below by the fallback, restricting the argument alphabet in the schema, as a certain step 1, with the no-shell `arglist` form as step 2 once a test proves it.
**Evidence:** `policy/tendcf_services.cf:72-98`, `:370-374`; `schema/goal-file.schema.json:497-504`; `bin/projector.py:145`; CFEngine `commands` reference (<https://docs.cfengine.com/docs/master/reference/promise-types/commands/>: `arglist` is an slist, `useshell` defaults to `noshell`) and `getvalues()` reference (<https://docs.cfengine.com/docs/master/reference/functions/getvalues/>).
**Proposed text:**

> Step 1, certainly expressible today: set `useshell => "noshell"` (CFEngine's default) in `tendcf_interlock_contain`, so no shell parses the joined string, and require `pre_action.command[0]` to match `^/` and every item to match the systemd argv alphabet plus "no ASCII space" (schema bump), so that the joined string splits back into the same argv. Step 2, once proven against a real build: build an slist per interlock with `getvalues("data:variables.tendcf_interlock[$(id)][pre_action][command]")` under a canonified, non-bracket name, and pass its tail as `arglist` with its head as the promiser. Keep step 1's alphabet until step 2 passes a test.

**Merge:** replace the vars and commands sections of `tendcf_interlocks`
**Checked:** verified (read; not executed); independently checked 2026-11-13: confirmed (live on the deployed path as code: the deployed policy joins and shells every pre_action; the injection itself is latent, since the deployed canary pre_action is `/usr/bin/true`); no lint outside the schema restricts the strings: confirmed; proposed fix expressible as written: weakened, corrected (step 2 not proven; replaced by the fallback as step 1)

### C-policy-02: `env` reaches the device and is silently dropped by both adapters

**Target:** `policy/templates/launchd.plist.mustache` (whole template)
**Kind:** correct
**Goal:** G4, G8
**Weight:** blocks-goal
**Finding:** The compiler emits `env` (litellm's `LITELLM_MASTER_KEY`, `OPENAI_API_KEY`), and the projector carries it into `host_specific.json`. Neither the launchd plist template nor the systemd unit template mentions it. No code resolves a secretspec name to a value. The service starts without its environment and nothing reports it. The goal file and the diff say one thing and the device does another, which G4 rules out.
**Evidence:** `compiler/nix2cf/compile.py:548-550`; `examples/host_specific.json` (`"env":{"CADDY_ADMIN_TOKEN":…}`); `policy/templates/launchd.plist.mustache:1-32`; `policy/templates/systemd.service.mustache:1-13`; `rg secretspec policy bin deploy compiler/nix2cf` (projector name check only).
**Proposed text:**

> Until a device-side secret resolver exists, refuse (report, do not actuate) any service entry carrying `env`; when it exists, render `EnvironmentVariables` from a root-only file the resolver writes, never inline values in the plist.

**Merge:** insert a refusal class beside `_refused`
**Checked:** verified (read); independently checked 2026-11-13: confirmed (latent: no deployed service carries `env`, and no Mac runs the policy)

### C-policy-03: A changed launchd job never takes effect, and a failed load is invisible

**Target:** `policy/tendcf_services.cf` `commands:`, at `"/bin/launchctl" arglist => { "load", "-w", … }`
**Kind:** correct
**Goal:** G4, G8
**Weight:** blocks-goal
**Finding:** `launchctl load -w` runs on every pass with no "already loaded" probe and no unload on change. The systemd branch has `restart … _unit_changed`, but the launchd branch has no equivalent. So an edited plist keeps running the old definition until reboot. `load`/`unload` "only return a non-zero exit code due to improper usage. Otherwise, zero is always returned", so CFEngine records every outcome as repaired and a broken plist is never reported.
**Evidence:** `policy/tendcf_services.cf:274-280`, `:311-317`, contrast `:337-340`; https://ss64.com/mac/launchctl.html (load/unload NOTE).
**Proposed text:**

> Use `launchctl print system/<label>` as the loaded-state probe, `launchctl bootstrap system <plist>` when not loaded, `launchctl bootout system/<label>` then `bootstrap` when the files promise repaired the plist, and classify by their exit codes.

**Merge:** replace the two launchctl promises
**Checked:** verified (read; launchctl semantics from the man page, not run); independently checked 2026-11-13: confirmed (latent: no Mac deployment)

### C-policy-04: A launchd tombstone deletes any plist the goal file names, guarded only by a lint

**Target:** `policy/tendcf_services.cf` `files:`, at "This path has no existence or type gate, by design"
**Kind:** correct
**Goal:** G4
**Weight:** blocks-goal
**Finding:** On darwin, `{"state":"absent"}` for any id unloads and deletes `/Library/LaunchDaemons/<id>.plist`, a directory shared with Homebrew, Docker and vendor daemons. The comment names the only guard: the lint rule that "a tombstone must fall under a cfengine unit-writer prefix". That lint runs over repo fixtures in CI. It does not run in the compiler (C-compiler-08), in the installer, or on a device. The goal file carries the unit-writer map, but the policy does not consult it.
**Evidence:** `policy/tendcf_services.cf:293-301`, `:315-317`; `.github/workflows/check.yml:27-28` (lint over the repo only).
**Proposed text:**

> Gate the launchd tombstone on the projection carrying the entry's cfengine prefix (project `unit-writer` prefixes as a third, non-actuating container, or have the validator refuse a tombstone outside them before projection).

**Merge:** needs a design decision (projecting unit-writer reverses P-1's exclusion)
**Checked:** verified (read); independently checked 2026-11-13: confirmed (latent: no compiler tombstones, no Mac install)

### C-policy-05: The launchd files promise leaves `.cf-before-edit` backups in /Library/LaunchDaemons and states no mode

**Target:** `policy/tendcf_services.cf` `files:` "/Library/LaunchDaemons/$(service_ids).plist"
**Kind:** correct
**Goal:** G4
**Weight:** improves
**Finding:** The systemd promise sets `edit_defaults => tendcf_no_backup` because "The default leaves <unit>.cf-before-edit beside the unit". The launchd promise does not, so every change leaves a backup plist in the daemon directory. It states no `perms`. A plist the agent creates is `0600` and root-owned (CFEngine's create default), which launchd accepts, but an existing plist with the wrong owner or mode is never corrected. I did not check whether launchd loads the backup files.
**Evidence:** `policy/tendcf_services.cf:274-280` versus `:282-286`, `:376-387`.
**Proposed text:**

> Add `edit_defaults => tendcf_no_backup` and `perms => tendcf_plist_perms` (mode 0644, owner root, group wheel) to the launchd files promise.

**Merge:** insert into that promise
**Checked:** verified (read); launchd's handling of the backup not checked; independently checked 2026-11-13: weakened, corrected (latent)

### C-policy-06: The policy cannot tell "no data" from "nothing to do"

**Target:** `policy/tendcf_services.cf` `tendcf_services` vars, at `getindices("data:variables.tendcf_service")`
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** If `host_specific.json` fails to load (the upstream fail-open that PR #41 fixes in the fork), both containers are undefined, `getindices` is empty, and the bundle does nothing and reports nothing. Only cf-agent's own ERR log line about the CMDB data is left, and tendcf does not surface it. To the bundle, that run looks like a host with zero entries. The policy has no `isvariable` check. That makes a device that is not under control look converged.
**Evidence:** `rg isvariable policy/` (no hits); `policy/tendcf_services.cf:104-108`; digest-current-plan-docs C1d and B12 (fail-open applies to pastebin; #41 open).
**Proposed text:**

> Require a projection marker (`vars.tendcf_meta.goal_sha256`, per Q12) and report `tendcf: no goal data loaded` and actuate nothing when it is absent.

**Merge:** insert at the top of `tendcf_services`
**Checked:** verified (read); fork behaviour from the docs, not run; independently checked 2026-11-13: weakened, corrected (live in shape on the pastebin canary; the consequence is latent)

## Schema

### C-schema-01: The goal file's `host` key type is one nothing on a device produces

**Target:** `schema/goal-file.schema.json` `host`, at "Device public key — host identity is the key"
**Kind:** question
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** `host` must be `ed25519:<64 hex>`, but CFEngine's own device key is RSA, and no tendcf code generates, stores or reads an ed25519 device key. The canary and every fixture carry `a1a1…`. G3's handshake has no key to start from on either the Mac or Android. An Android keystore key or a Termux key would be a third identity.
**Evidence:** `schema/goal-file.schema.json:13-17`; cfengine-core `cf-key/cf-key-functions.c:322` (`RSA_generate_key_ex`); `compiler/tests/test_compile.py:32`.
**Proposed text:**

> State one device identity per platform and where it lives (Mac: a root-only ed25519 key under the work directory, generated by the installer; Android: an Android Keystore key held by tendcf-agent) and how the CFEngine RSA key relates to it (unused, or bound by a signed statement).

**Merge:** needs the operator's ruling first
**Checked:** verified (schema and core source read); independently checked 2026-11-13: confirmed (latent; the design never says the host key is CFEngine's key, so the gap is "not built", not "wrong key type chosen")

### C-schema-02: No data shape carries a signature or a handshake for an update

**Target:** `schema/goal-file.schema.json` top level; `schema/approval-record.schema.json` `signature`
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** The goal file has no signature or envelope. The approval record has a `signature` member whose "exact encoding is residue", and it is validated only against fixtures. The shapes needed to accept "updates from any other device that completes the correct cryptographic handshake" do not exist:
1. who may sign;
2. the peer allowlist;
3. replay or rollback counters;
4. transport.

`device-trust` has `advisor-key` and `trust-policy`, but no peer keys.
**Evidence:** `schema/approval-record.schema.json:63-77`; `schema/goal-file.schema.json:560-679` (`trust_domain`, no peer member); inventory §H "Peer actions: nothing".
**Proposed text:**

> Add a detached envelope (`goal-file.sig`: signer key id, sequence number, signature over the JCS bytes) and a `device-trust` `peer-key` kind listing the keys this device accepts updates from; the validator refuses an unsigned, unknown-signer or non-increasing-sequence file before any diff.

**Merge:** needs the operator's ruling first (schema bump, design ruling: two frontier reviews per AGENTS.md)
**Checked:** verified; independently checked 2026-11-13: confirmed

### C-schema-03: The schema has no vocabulary for an Android client

**Target:** `schema/goal-file.schema.json` `state_entries`, at "Kinds are a closed set per schema_version"
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** The kinds are service, interlock, unit-writer and unit-package; the supervisors are launchd, systemd, runit and nixos. Nothing describes an app installed for a given Android user or profile, an appops or permission grant, a `settings` key, a Shizuku grant, or an Island/Insular profile. G5 names those profiles as the differentiator. stayturgid's Ansible modules already define this vocabulary (C-android-04).
**Evidence:** `schema/goal-file.schema.json:335-341`, `:679`; stayturgid `ansible_collections/stayturgid/android_common/plugins/modules/` (android_apk, android_appops, android_settings, android_app_privileges, android_a11y_services, shizuku_grant).
**Proposed text:**

> Add an `android` domain family keyed by Android user id: `app` (package, source, sha256, user), `appop`, `permission`, `setting` (namespace, key, value), `a11y-service`, `shizuku-grant`, each present/absent, comprehensive or not-yet-migrated per user.

**Merge:** needs the operator's ruling first (schema bump)
**Checked:** verified (schema read; stayturgid module names listed, bodies not read); independently checked 2026-11-13: confirmed

### C-schema-04: Three schemas validate only fixtures; no code produces or consumes them

**Target:** `schema/goal-diff.schema.json`, `schema/approval-record.schema.json`, `schema/report-row.schema.json`
**Kind:** question
**Goal:** G4
**Weight:** improves
**Finding:** Only `bin/schema_lint.py` references goal-diff and approval-record. report-row is used also by the Linux-only unit classifier. No compiler, projector, installer or policy code reads or writes any of the three. That is the review record's pre-mortem C1 ("validates files that nothing consumes") in concrete form. These are exactly the shapes G4 and the log archive need, so they should get their first consumer before any further bump.
**Evidence:** `rg -l goal-diff|approval-record|report-row bin compiler/nix2cf policy deploy tests .github`, which gives schema_lint.py for all three plus unit_classifier.py for report-row.
**Proposed text:**

> Freeze further shape work on these three until the G4 diff CLI (C-g4-03) produces goal-diff and the Mac log archive (C-macos-02) consumes report-row.

**Merge:** needs the operator's ruling first (ordering)
**Checked:** verified (rg); independently checked 2026-11-13: confirmed

### C-schema-05: Schema v5 bakes Debian and systemd into the shared contract

**Target:** `schema/goal-file.schema.json` `unit_package_map` and `unit_writer_map`
**Kind:** ruling-drift
**Goal:** G5
**Weight:** improves
**Finding:** v5 added a `unit-package` kind whose only writer is `dpkg`. It also widened the unit-writer key language to systemd suffixes, and its `tendcf-install` writer is "systemd hosts only". All three changes were made for the pastebin Debian host, i.e. G5's platform 4. Each costs a `schema_version` bump that macOS and Android files must also carry. Per v5, rpm would need another bump. Note that 5,200 lines (32%) of the target code is Linux-only (summary (b)).
**Evidence:** `schema/goal-file.schema.json:520-555`, `:535`; `compiler/nix2cf/compile.py:47-56`.
**Proposed text:**

> Move platform-specific kinds into per-platform domain schemas that a goal file includes by `supervisor`, so a Linux bump does not version a Mac or Android file.

**Merge:** needs the operator's ruling first
**Checked:** verified (read)

### C-schema-06: The interlock command has no alphabet, while the systemd argv does

**Target:** `schema/goal-file.schema.json` `interlock_entry.pre_action.command`
**Kind:** correct
**Goal:** G4
**Weight:** improves
**Finding:** This is the schema half of C-policy-01. `command.items` is any non-empty string, so a space or a shell metacharacter is schema-valid and changes meaning once the policy joins the argv. The launchd `command` likewise has no limit. That is safe only because Mustache HTML-escapes it into XML, an accident and not a stated rule.
**Evidence:** `schema/goal-file.schema.json:497-504` versus `:400-416`; `policy/templates/launchd.plist.mustache:9-11`.
**Proposed text:**

> `pre_action.command[0]` must be an absolute path (`^/`), and every item is held to the systemd argv alphabet plus "no ASCII space" until C-policy-01 removes the shell.

**Merge:** insert into `interlock_entry` (schema bump)
**Checked:** verified; independently checked 2026-11-13: confirmed (latent)

## bin

### C-bin-01: The only device-side code checks nothing about authenticity or ownership

**Target:** `bin/projector.py` module docstring, at "Neither exists yet and this repo is contract-only"
**Kind:** add
**Goal:** G3, G4, G8
**Weight:** blocks-goal
**Finding:** The projector is pure by design, and nothing wraps it. It does none of the following:
1. check that `host` is this device;
2. validate against goal-file.schema.json (it does refuse non-conforming shapes, duplicate ids, non-name `env` values and CFEngine expansion sequences, but it is not a schema validator);
3. verify a signature;
4. compare with a baseline;
5. show a diff;
6. ask anything.

The installer then bypasses even the projector (C-deploy-02). `tendcf-validate`, which is meant to do all of this on Mac and Linux, is a proposal only. Every G4 step needs it first.
**Evidence:** `bin/projector.py:14-25`, `:251-332`; inventory §H ("Validator (tendcf-validate): prose only").
**Proposed text:**

> Build `tendcf-validate` minimal for the Mac first: verify envelope (C-schema-02), refuse `host != self`, schema-validate, diff against the stored baseline (goal-diff), print the diff, require an explicit yes, then project and atomically replace `host_specific.json` and the baseline.

**Merge:** needs the operator's ruling first (the validate picklist is open, digest B15)
**Checked:** verified; independently checked 2026-11-13: weakened, corrected (live on the deployed path: the installer path)

### C-bin-02: The Android agent must port a CFEngine-shaped contract byte for byte

**Target:** `bin/projector.py` docstring, at "the Android agent's Kotlin port must reproduce it byte-for-byte (R22)"
**Kind:** question
**Goal:** G5, G7
**Weight:** improves
**Finding:** The projection is CFEngine CMDB input. Its rules exist because of `cmdb.c`:
1. the 5 MiB cap;
2. the refusal of `$(` anywhere;
3. containers because dotted keys become scopes.

R22 requires the Kotlin agent to reproduce it byte for byte. If no `cf-agent` reads it on Android (D45), it is a second implementation of a format nobody on that device consumes. If Termux CFEngine does read it (C-android-01), the port is justified.
**Evidence:** `bin/projector.py:20-25`, `:137-145`, `:43-50`.
**Proposed text:**

> Decide per platform what the agent consumes: on Android, either the goal file directly (no projection, no CMDB rules) or the projection fed to Termux cf-agent; R22 applies only in the second case.

**Merge:** needs the operator's ruling first
**Checked:** verified (read)

### C-bin-03: The only diff application and ceremony derivation live inside the lint

**Target:** `bin/schema_lint.py` `apply_diff` and `derive_ceremony_class`
**Kind:** move
**Goal:** G4
**Weight:** improves
**Finding:** `apply_diff` (L1821) and `derive_ceremony_class` (L1791) are the nearest working code to G4's "exact, mechanically checked difference" and to a risk class. They live in a 2,260-line lint script and check fixtures only. A device validator or a CLI would have to copy them, the same second-implementation drift the projector docstring warns about.
**Evidence:** `bin/schema_lint.py:1791-1821`; graft skeleton of schema_lint.py.
**Proposed text:**

> Move `apply_diff`, `derive_ceremony_class` and the cross-file checks into a `tendcf.contract` library module; the lint, the compiler and tendcf-validate import it.

**Merge:** replace (move) under the D46 package layout
**Checked:** verified (skeleton; bodies not read in full)

### C-bin-04: The largest code investment serves platforms 4 and 5 only

**Target:** `bin/unit_classifier.py` and `tests/unit_classifier/`
**Kind:** question
**Goal:** G5
**Weight:** improves
**Finding:** 4,031 lines are a "read-only prototype" that is "not wired":
1. a 896-line classifier with a systemctl/dpkg-query allow-list;
2. 3,135 test and probe lines, including the 312-line `pastebin-claims.json`.

They also run as root in every Linux VM CI row. Under G5 this is platform-4/5 work and should stop until platforms 1 and 2 converge. The code is sound as far as I read; the question is ordering.
**Evidence:** `bin/unit_classifier.py:20-21`, `:54-57`; `.github/workflows/linux.yml:51-67`.
**Proposed text:**

> Park the classifier (keep CI green, add nothing) until G8 state 1; the s5 design waits with it.

**Merge:** needs the operator's ruling first
**Checked:** verified (header and allow-list read; logic not reviewed)

## Tests

### C-tests-01: The launchd render path has never been executed by any test or CI run

**Target:** `tests/policy/run.sh` header, at "nothing here touches launchd or /Library/LaunchDaemons"
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** Check 5 is skipped on Darwin "where the same fixture is the real render path and needs root". On Linux it tests only the refusal. No test renders a plist, compares it with a golden, or runs launchctl. C-policy-02, C-policy-03 and C-policy-05 are bugs no test could catch. The first platform in G5 has the least-tested adapter.
**Evidence:** `tests/policy/run.sh:4-5`, `:148-161`; `tests/policy/fixtures/` (8 files, one launchd).
**Proposed text:**

> Add check 5m on macOS with root: render `launchd-present.json`, compare each plist to a golden byte for byte, `plutil -lint` it, assert `launchctl print system/<label>` shows it loaded, change the entry and assert the running definition changed, tombstone it and assert it is gone.

**Merge:** insert after check 5
**Checked:** verified (read); independently checked 2026-11-13: confirmed

### C-tests-02: Check 2's "nothing actuated" assertions cannot fail on Linux

**Target:** `tests/policy/run.sh` check 2, at "no launchctl invocation"
**Kind:** correct
**Goal:** G4
**Weight:** improves
**Finding:** The fixture has two launchd services under the blocked bundle. Every launchd promise is also gated on `darwin`, so on the Linux CI runners `no launchctl` and `no unit rendered for a blocked service` pass even if the interlock gate were deleted. The header claims "an incorrect one would [render]", which is true only on a Mac, and the Mac is never run in CI. Only the "refusal reported" lines test the interlock.
**Evidence:** `tests/policy/run.sh:11-16`, `:116-124`; `policy/tendcf_services.cf:280`, `:313`.
**Proposed text:**

> Give check 2 a systemd twin (a blocked bundle containing a systemd entry, run under `TENDCF_TEST_SYSTEMD=1`) that asserts no unit file and no systemctl call, so the interlock gate is tested where CI runs.

**Merge:** insert after check 2
**Checked:** verified (read; mutation not run); independently checked 2026-11-13: confirmed by reading; mutation not run

### C-tests-03: The only Nix test is always skipped in CI and covers a third of the Site Model

**Target:** `compiler/tests/test_compile.py` `test_nix_expression_equals_yaml`
**Kind:** correct
**Goal:** G2
**Weight:** improves
**Finding:** The test skips without `nix-instantiate`, and the CI `compiler` job installs only uv on ubuntu-latest. The test compares `site.nix` with `services.yml` only, so roles and writers have no Nix form tested. Nothing tests that a Nix-authored site compiles to the same goal file.
**Evidence:** `compiler/tests/test_compile.py:739-743`; `.github/workflows/check.yml:67-84`.
**Proposed text:**

> Install Nix in the compiler job (`cachix/install-nix-action` or the Determinate installer) and assert `buildfile --site site.nix` equals the YAML golden byte for byte.

**Merge:** replace the test and add a CI step
**Checked:** verified (read); runner image contents inferred; independently checked 2026-11-13: confirmed

### C-tests-04: No end-to-end test runs Site Model to goal file to projection to cf-agent

**Target:** `tests/policy/run.sh` check 1, at "cf-promises parses the bundle with the example projection"
**Kind:** add
**Goal:** G8
**Weight:** improves
**Finding:**
1. The compiler goldens stop at the goal file.
2. The policy tests start from hand-written projections and the oracle `examples/host_specific.json`.
3. Check 1 only parses.

So the compiler and the policy can disagree, and the `env` drop (C-policy-02) is exactly such a disagreement.
**Evidence:** `tests/policy/run.sh:104-107`; `tests/policy/fixtures/`; `compiler/tests/golden/`.
**Proposed text:**

> Add one chain test: `nix2cf buildfile --project` over `compiler/examples/site`, feed the bytes to cf-agent as in run.sh, and assert the rendered unit carries every field of the goal-file entry.

**Merge:** insert as check 8
**Checked:** inferred (fixture and test lists read; no test of this shape found)

## Deploy

### C-deploy-01: There is no Mac installer and no Mac scheduler

**Target:** `deploy/linux/tendcf-install.sh`, at `[ "$(uname)" = Linux ] || die "Linux only"`
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:** The installer is Linux-only throughout: `ldd`, `stat -c`, systemd and `LD_LIBRARY_PATH`. G8 state 1 needs a root-owned tree on the Mac and a `cf-execd` LaunchDaemon. It also needs the macOS equivalent of the library-path guard (`otool -L`, `DYLD_*` stripping). None exists.
**Evidence:** `deploy/linux/tendcf-install.sh:46-51`, `:76-93`, `:183-207`.
**Proposed text:**

> Add `deploy/macos/tendcf-install.sh` with the same subcommands: tree under `/opt/tendcf` (root:wheel), `otool -L` check, `org.tendcf.execd` LaunchDaemon via `launchctl bootstrap system`, and the same data-restore-on-reject rule.

**Merge:** insert as a new file (needs the operator's ruling on the location, AGENTS.md item 23)
**Checked:** verified; independently checked 2026-11-13: confirmed

### C-deploy-02: The installer takes a projection, so the device never sees the goal file

**Target:** `deploy/linux/tendcf-install.sh` `put_data`, at "validated by cf-promises first"
**Kind:** correct
**Goal:** G4
**Weight:** blocks-goal
**Finding:** `data FILE` installs raw `host_specific.json`. The host never holds the goal file, so it cannot show a diff or refuse one, and it cannot check `host`, a signature or a baseline. "Validated by cf-promises" checks policy syntax. While the fork's CMDB loader is fail-open (#41), a bad data file passes it and is silently ignored. So the live canary path is the opposite of G4: the operator hand-copies opaque bytes.
**Evidence:** `deploy/linux/tendcf-install.sh:13-18`, `:144-158`; digest-current-plan-docs C1c and C1d.
**Proposed text:**

> `data` takes a goal file (and later its envelope), runs `projector.py` and `projector.py --check` on the host, shows the projection diff against the installed one, and installs only on an explicit `--yes`.

**Merge:** replace `put_data`'s contract
**Checked:** verified (read); fail-open from docs; independently checked 2026-11-13: confirmed (live on the deployed path: this is how the pastebin canary data is installed)

## CI

### C-ci-01: No macOS job exists for the first G5 platform

**Target:** `.github/workflows/` (check.yml, linux.yml)
**Kind:** add
**Goal:** G5, G8
**Weight:** blocks-goal
**Finding:**
1. Every job is ubuntu or debian.
2. The fork is never built for macOS.
3. The launchd policy never runs.
4. The compiler's macOS output is never applied.

The operator's global rule allows no macOS leg in PR checks unless asked by name, and runs heavy builds in CI first. So the job belongs on push to master, on schedule and on dispatch, not in PR checks.
**Evidence:** `.github/workflows/check.yml:17-18`, `:67-68`; `.github/workflows/linux.yml:25-31`, `:74-76`; the operator's global agent instructions, item 37.
**Proposed text:**

> Add `.github/workflows/macos.yml` (push to master, weekly, workflow_dispatch; not pull_request): build the fork at the `overlay/fork.json` pin to `/opt/tendcf` on `macos-latest`, run `tests/policy/run.sh` with the new root launchd check (C-tests-01), and upload the tree.

**Merge:** needs the operator's ruling first (macOS leg naming, per item 37)
**Checked:** verified (workflows read); independently checked 2026-11-13: confirmed

### C-ci-02: CI time goes to platforms 4 and 5 and nothing goes to platforms 1 and 2

**Target:** `.github/workflows/linux.yml` `vm` matrix
**Kind:** question
**Goal:** G5
**Weight:** nit
**Finding:** Each push builds the fork three times on ubuntu VMs plus once in debian:13 (about 10.5 minutes per the inventory), and runs the classifier as root. Nothing builds Kotlin or Android. That is a fair reflection of the 2026-10-29 order, but not of G5.
**Evidence:** `.github/workflows/linux.yml:25-118`; inventory §F.
**Proposed text:**

> Cut the VM matrix to one row (ubuntu-24.04) on pull requests and keep the full matrix on master; spend the saved minutes on the macOS job.

**Merge:** needs the operator's ruling first
**Checked:** verified

## Android

### C-android-01: The predecessor already runs CFEngine on the Android fleet, which D45 did not weigh

**Target:** stayturgid `device/termux/cfengine/` (README, `policy/stayturgid.cf`, `policy/cf-serverd.cf`)
**Kind:** question
**Goal:** G5, G7, G8
**Weight:** blocks-goal
**Finding:** stayturgid deploys a `cfbs`-built standalone policy to Termux and runs `cf-agent -f` and `cf-serverd -f` there. The README says the fleet is on 3.27.1, the policy is 278 lines, and Ansible handlers start the daemons. So CFEngine converges on G5's platform 2 today. tendcf, however:
1. refuses android in the compiler;
2. makes the agent "Android-only" and Kotlin (D45);
3. requires a byte-identical Kotlin projector port.

D45 chose no CFEngine on Android ("No daemon beside CFEngine off Android", `architecture-DEFINITIVE-v3.md:87-90`) without weighing the Termux CFEngine already deployed. A Termux cf-agent could consume tendcf's projection now, leaving the Kotlin agent to do trust, consent UI and the Shizuku-only actions. That would cut row 8 of the gap list substantially.
**Evidence:** stayturgid `device/termux/cfengine/README.md:1-30`; stayturgid `device/termux/cfengine/policy/` (cf-serverd.cf 96, stayturgid.cf 278 lines); `bin/projector.py:14-23`.
**Proposed text:**

> Ruling requested: on Android, does tendcf converge with Termux cf-agent (fed the projection; Kotlin agent = trust, diff/consent UI, Shizuku actions), or with the Kotlin agent alone (no CFEngine on Android, R22 dropped)?

**Merge:** needs the operator's ruling first (D45 scope)
**Checked:** verified (layout and README read; policy bodies not read; fleet version from README); independently checked 2026-11-13: confirmed (fleet version from the README only)

### C-android-02: stayturgid's trust is trust-on-first-use over the tailnet, pushed from a control node

**Target:** stayturgid `device/termux/cfengine/policy/cf-serverd.cf` `trustkeysfrom`; stayturgid `control/cfengine/cf-runagent.cf.example` `trustkey`
**Kind:** correct
**Goal:** G3
**Weight:** blocks-goal
**Finding:** The predecessor's approach breaks G3 in two ways if it is carried over:
1. Every device trusts any key from `100.64.0.0/10` on first contact, and the Mac's `cf-runagent` sets `trustkey => "true"`.
2. The Mac pushes runs to every device, which makes it a control node.

The cf-serverd and cf-runagent path must not be reused as the update channel.
**Evidence:** stayturgid `device/termux/cfengine/policy/cf-serverd.cf:8`, `:33-34`, `:42`, `:66-71`; stayturgid `control/cfengine/cf-runagent.cf.example:21-31`.
**Proposed text:**

> tendcf does not inherit stayturgid's cf-serverd/cf-runagent channel; an update is a signed goal file any peer may deliver (C-schema-02), and cf-serverd, if kept, admits only keys listed in `device-trust`.

**Merge:** insert into the Android plan as a constraint
**Checked:** verified (read); independently checked 2026-11-13: confirmed (live in stayturgid's fleet, not in tendcf)

### C-android-03: ShizukuTendCF ignores the owner's revoke and deny for the fleet agent's signer

**Target:** ShizukuTendCF `README.md` disclosure, at "revoke and deny are ignored"
**Kind:** question
**Goal:** G1, G4
**Weight:** blocks-goal
**Finding:** Any app signed with the stayturgid-agent certificate is "always allowed Shizuku access" and the manager "shows it locked on". The only way out is to rebuild with the digest removed, uninstall, or stop Shizuku. For a product whose aim is "control of their own computing devices" and owner see-and-refuse, a privileged grant the owner cannot revoke in the UI is the opposite. It also hard-codes one signer (`TrustedSigners`), so a tendcf agent with another certificate gets no such grant without a rebuild. This is a recorded owner decision for the fleet flavour (README: "by owner decision on 2026-10-03 … intended for stayturgid fleet devices"), so it is a conflict between rulings, not an oversight.
**Evidence:** ShizukuTendCF `README.md:14-20`; ShizukuTendCF `server/src/main/java/rikka/shizuku/server/ShizukuService.java:2455-2601` (TrustedSigners outcomes).
**Proposed text:**

> For tendcf, the allowlist is an owner setting, not a build constant: the owner enrolls the agent's signer once, sees it listed, and can revoke it in the manager; the fleet's "locked on" stays a stayturgid-only build flavour.

**Merge:** needs the operator's ruling first
**Checked:** verified (README and call sites read; TrustedSigners body not read); independently checked 2026-11-13: confirmed (live in the ShizukuTendCF build)

### C-android-04: Reusable Android substrate, and what is missing

**Target:** stayturgid `device/native-agent/`, stayturgid `ansible_collections/stayturgid/android_common/`, ShizukuTendCF `manager/src/main/java/af/shizuku/manager/fleet/`
**Kind:** add
**Goal:** G5, G8
**Weight:** improves
**Finding:**
1. Reusable for the Kotlin client:
   1. stayturgid's native agent (50 Kotlin files, 7,068 lines): a foreground service, a Shizuku UserService at UID 2000, boot start, heartbeat, probes, and a CI-builds/Mac-signs release flow.
   2. The `android_common` modules (apk per `--user N`, appops, settings, privileges, a11y, Shizuku grant): the resource semantics and their unit tests, though driven over ADB from the Mac.
   3. ShizukuTendCF's headless broadcasts and `FleetProfileApplier`: a path allowlist, the SHA-256 of the profile bytes, and a per-key report.
2. Missing:
   1. goal-file parsing and verification;
   2. a baseline;
   3. a diff and consent UI;
   4. an on-device apply engine for the resource types (today they run from the Mac via ADB);
   5. report shipping.
**Evidence:** stayturgid `device/native-agent/README.md:108-147`; `ls ansible_collections/stayturgid/android_common/plugins/modules` in stayturgid; ShizukuTendCF `manager/src/main/java/af/shizuku/manager/fleet/FleetProfileApplier.kt:11-93`.
**Proposed text:**

> Seed tendcf-agent from stayturgid's native agent (rename package, drop stayturgid-specific repair loops), and port the android_common module semantics into on-device Kotlin appliers behind the Shizuku UserService, one per C-schema-03 kind, each with the module's existing tests as its specification.

**Merge:** insert into the Android plan
**Checked:** verified (layouts, READMEs, one Kotlin file read); module bodies not read

### C-android-05: ShizukuTendCF's fleet profile is best-effort per key, not an exact difference

**Target:** ShizukuTendCF `manager/src/main/java/af/shizuku/manager/fleet/FleetProfileApplier.kt`, at "Application is best effort per key, not transactional"
**Kind:** correct
**Goal:** G4
**Weight:** improves
**Finding:** The profile covers eight Shizuku preference keys, and a bad value skips that key while the rest apply. Under G4 a partly applied profile is a change the owner did not see as a whole. If tendcf ever drives Shizuku's own settings through this receiver, it must be all-or-nothing.
**Evidence:** ShizukuTendCF `manager/src/main/java/af/shizuku/manager/fleet/FleetProfileApplier.kt:11-28`.
**Proposed text:**

> Add a validate-all-then-apply mode (`APPLY_FLEET_PROFILE --ez atomic true`) that rejects the whole profile on any bad key.

**Merge:** insert as an option in the fork
**Checked:** verified (read)

## macOS

### C-macos-01: The macOS adapter can describe only root LaunchDaemons

**Target:** `policy/tendcf_services.cf` `files:` "/Library/LaunchDaemons/…"; `schema/goal-file.schema.json` `unit.launchd`
**Kind:** add
**Goal:** G5, G8
**Weight:** improves
**Finding:** The adapter writes only system-domain daemons, with two knobs: `run_at_load` and `keep_alive`. It cannot express any of these:
1. a per-user LaunchAgent (GUI login domain);
2. StandardOut/ErrorPath, which a log-archive server needs;
3. a schedule (StartCalendarInterval);
4. sockets;
5. Homebrew packages;
6. `defaults` preferences;
7. files.

A Mac "server" for logs and monitoring (G3) needs at least the log paths, a receiver daemon and a retention job.
**Evidence:** `policy/tendcf_services.cf:274-280`; `schema/goal-file.schema.json:425-433`; `policy/templates/launchd.plist.mustache:1-32`.
**Proposed text:**

> Grow `unit.launchd` with `stdout_path`, `stderr_path` and `start_calendar_interval` (schema bump) as the minimum the Mac log-archive role needs; LaunchAgents and preferences wait until G5 step 3.

**Merge:** needs the operator's ruling first (schema bump)
**Checked:** verified

### C-macos-02: Nothing archives or ships logs, and report-row has no consumer on the Mac

**Target:** `schema/report-row.schema.json` description, at "Durable capture is JSONL; SQLite is a rebuildable index"
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:**
1. G8 state 1 requires logs archived on the Mac.
2. No code writes JSONL report rows on any host (no "jsonl" hit in the code).
3. No code sends them.
4. Nothing receives them on the Mac.
5. The goal file cannot declare either end (C-compiler-06).

cf-agent's own outcomes on a device go only to stdout and the CFEngine workdir.
**Evidence:** `schema/report-row.schema.json:5`; inventory §A ("No hits at all: tuf, jsonl, sqlite").
**Proposed text:**

> Minimal path: tendcf-validate and tendcf-agent append report rows (JSONL) locally; a signed batch is sent to every peer whose goal file grants `log-archive`; the Mac receiver verifies the sender key against device-trust and appends to a per-device file under a root-owned archive directory.

**Merge:** needs the operator's ruling first (transport choice)
**Checked:** verified (rg via the inventory; schema header read); independently checked 2026-11-13: confirmed

### C-macos-03: The example interlock calls `tailscale` by bare name and would block its bundle forever under cf-execd

**Target:** `compiler/examples/site/services.yml` interlock `tailscale-authenticated-before-lockdown`, at `command: ["tailscale", "status", "--json"]`
**Kind:** correct
**Goal:** G8
**Weight:** nit
**Finding:** `useshell` resolves `tailscale` on cf-execd's PATH. On a Mac, Homebrew and the Tailscale app install outside the default launchd PATH, so the check would fail and fail closed, blocking `fleet-vpn` on every run. The example is the template authors copy.
**Evidence:** `compiler/examples/site/services.yml:47`; `compiler/examples/site/site.nix:47`; `policy/tendcf_services.cf:370-374`.
**Proposed text:**

> `command: ["/usr/local/bin/tailscale", "status", "--json"]` (the path `tailscaled` uses in the same file), with the schema rule of C-schema-06 enforcing absolute paths.

**Merge:** replace that line (both files)
**Checked:** not checked: the PATH a root cf-execd under launchd hands to `/bin/sh` is unknown (independently checked 2026-11-13: unverifiable); needs a run under launchd on a Mac, or launchd documentation that states that PATH

## G4 attach points (nothing exists for any of them)

### C-g4-01: The safety scan and the confidence figure attach to the diff, between compile and sign

**Target:** `compiler/nix2cf/compile.py` `compile_host`, between `conflict_check` and `canonical_bytes`; device side in tendcf-validate (C-bin-01)
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The scan has to read what changes, not the whole file. That is goal-diff (schema exists; `apply_diff` in the lint). It runs twice:
1. at the author's side, after `conflict_check`, to inform the AI and the human;
2. on the device, before consent, because the device must not trust the author's score.

`derive_ceremony_class` is the only existing risk signal. Rule-based scanners are the first scanners:
1. privileged region touched;
2. shell in argv;
3. a new root service;
4. removal of a guard;
5. network-facing port.

The AI review is one more scanner with its own weight. The figure out of 100 and the explanation belong in an unsigned report beside the signed bytes, not inside them.
**Evidence:** `compiler/nix2cf/compile.py:681-714`; `bin/schema_lint.py:1791-1821`; `schema/goal-diff.schema.json`.
**Proposed text:**

> Add `tendcf.safety`: input a goal-diff, output `{score: 0-100, reasons: [...], findings: [{pointer, severity, scanner, why}]}`; scanners are plug-ins (rule scanners first, an AI scanner second); the device recomputes and shows its own result.

**Merge:** needs the operator's ruling first (the scoring method is not described anywhere)
**Checked:** verified (absence: no scoring code); independently checked 2026-11-13: confirmed

### C-g4-02: Graded highlighting needs a source map back to the authored line

**Target:** `compiler/nix2cf/sitemodel.py` `Document.where`
**Kind:** add
**Goal:** G4, G2
**Weight:** improves
**Finding:** A finding has a goal-file pointer. To highlight "the questionable code" G4 needs the Nix or YAML span that produced it. `Document.where` gives YAML lines per mapping, JSON gives none, and Nix gives none (C-compiler-09). Severity → intensity is then a renderer concern.
**Evidence:** `compiler/nix2cf/sitemodel.py:77-91`, `:99-104`.
**Proposed text:**

> Each safety finding carries `source: file:line-span` from the C-compiler-09 source map; the CLI and TUI colour that span by severity band.

**Merge:** insert after C-compiler-09
**Checked:** verified

### C-g4-03: The CLI attaches as subcommands beside `buildfile`, with no `tendcf` command yet

**Target:** `compiler/nix2cf/cli.py` `build_parser`
**Kind:** add
**Goal:** G4, G1
**Weight:** improves
**Finding:** The only CLI is `nix2cf` with `buildfile` and `eval-nix`. The D46 layout plans `tendcf compile`. The G4 command-line mode should be `tendcf review <old> <new>` with the diff, score, reasons and highlighted source, and `tendcf accept|refuse`, which signs or discards. It also needs the device-side twin in tendcf-validate.
**Evidence:** `compiler/nix2cf/cli.py:174-206`; digest-current-plan-docs A3 (plugin-layout `tendcf compile`).
**Proposed text:**

> Add `review`, `accept` and `refuse` subcommands to the planned `tendcf` entry point; `review` exits non-zero below a configurable score so an AI caller cannot skip it.

**Merge:** needs the operator's ruling first (command names)
**Checked:** verified

### C-g4-04: The TUI attaches device-side over the same report

**Target:** (no file)
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** The TUI is a second renderer of the C-g4-01 report and the C-g4-02 spans. On the Mac it wraps `tendcf review`. On Android the equivalent is the agent's consent screen, which is not a TUI, so G4's "TUI mode" covers Mac and Linux only. No scaffold has been chosen. Textual (Python, matching the compiler) is the obvious candidate, but not checked.
**Evidence:** absence (no TUI code in the target dirs).
**Proposed text:**

> The TUI reads the same `review --json` output as the CLI and adds per-finding accept/refuse; choose the borrowed scaffold by operator ruling.

**Merge:** needs the operator's ruling first (scaffold)
**Checked:** not checked (scaffold candidates)

## Withdrawn after checking

None. The independent check refuted no item in this file.

## Ideas and risks

1. **Import before inventing.** nix-darwin's `launchd.daemons` and NixOS's `systemd.services` are already typed Nix option trees covering exactly what `services.yml` hand-encodes. An importer that evaluates them and emits the Site Model would make G2's "carry over" real in weeks, and would give the first adopters (G1) a reason to try it.
2. **One contract library, three consumers.** The lint, the compiler and the projector each restate rules (patterns, duplicate-key hooks, cross-file checks). The projector docstring already counts the drift this causes. A single `tendcf.contract` module, imported by all three and later by the Kotlin port's test vectors, would remove a whole class of "lint-only" safety (C-compiler-08, C-policy-04).
3. **What runs can differ from what the owner sees.** Three cases already exist: argv becomes a shell string (C-policy-01), `env` is dropped (C-policy-02), and an edited plist is not reloaded (C-policy-03). G4's promise needs a property test: for each goal-file field, assert it changes the actuated artefact. A field that changes nothing is a bug.
4. **Termux CFEngine is a shortcut worth a ruling.** The fleet already runs cf-agent on Android. Feeding it tendcf projections could reach G8 state 1 months earlier than a full Kotlin converger. The Kotlin agent would hold trust and consent only.
5. **Owner control versus fleet convenience.** ShizukuTendCF's locked-on signer and stayturgid's TOFU key trust are the operator's fleet choices. Shipped to strangers (G8 state 3), they would contradict G1 directly. Keep them as a separate "operator fleet" flavour from day one.
6. **The contract is CFEngine-shaped at its core.** CMDB size caps, `$(` refusals and container naming are CFEngine 3.27 facts frozen into a "neutral" format. If G7's instrument is ever challenged, the goal file should not need a version bump. Keep CMDB rules in the projector and out of the goal-file schema.
7. **The schema-version meter is driven by Linux.** v4 and v5 were both Linux/NixOS bumps. Without per-platform domain schemas (C-schema-05), every Debian detail will version Mac and Android files and their consent diffs, adding noise to exactly what the owner must read.
8. **The safety score is itself an attack surface.** If the author's toolchain computes the score, a compromised AI can make it 100%. The device must recompute it from the diff alone, and the score must never gate anything without the owner's yes.
9. **Identity first.** Every G3/G4 piece (signature, peer list, log sender, replay counter) hangs off a device key that does not exist (C-schema-01). Picking and generating it on the Mac and on Android is a small, unblocking first step.
10. **Release keys live loose on the Mac.** `shizuku-djbclark-release.jks` and stayturgid's `agent-release.jks` sit in the working trees: git-ignored, the former mode 0644. The skill index says the release secrets are escrowed in 1Password. A tendcf signing story should start by removing these loose copies.

## Not checked

1. No test, build, lint or compiler run. Every behavioural claim comes from reading the code, so the C-compiler-04 crash and the C-tests-02 can't-fail claim are not demonstrated by execution.
2. The bodies of: schema_lint beyond its skeleton and the writer-prefix section; unit_classifier's logic; overlay.py; xref_lint; canary/check.py; run.sh lines 175-356.
3. stayturgid's policy bodies, the android_common module bodies, and ShizukuTendCF's TrustedSigners implementation.
4. Whether launchd loads `.cf-before-edit` files; the Mac's launchd PATH; Nix in GitHub runner images.
5. Live hosts, PRs #41 and #42, and the s5 branch.

graft tokens saved this task ≈ 50,439 (compile.py 7,632; projector 1,016; schema_lint 8,345; unit_classifier 23,607; xref_lint 6,858; flag_coverage 2,981).

Last search run: firecrawl scrape of the Nix manual (restrict-eval default false, confirming C-compiler-02) and of launchctl(1) on ss64 (load/unload always return 0, confirming C-policy-03). CFEngine RSA key type confirmed from local core source rather than the web: the docs URL returned 404 and searches were irrelevant.
