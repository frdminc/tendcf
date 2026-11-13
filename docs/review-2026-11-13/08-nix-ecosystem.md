# 08 — The Nix ecosystem against G2 (and G1, G3, G5)

**Targets:** the Nix ecosystem as it bears on goal G2 (and G1, G3, G5); response items against
`docs/architecture/architecture-DEFINITIVE-v3.md`, `docs/architecture/linux-targets.md`,
`docs/architecture/nixos-passthrough-plan.md`, `docs/architecture/plugin-layout.md`,
`docs/paper/tendcf-architecture-paper.md` and `.github/workflows/check.yml`.

**Base commit:** eefea3c

**How this was produced:** one reviewing agent (Claude Opus), then an independent checking agent that tried to
refute each finding; nothing was executed, and nothing was run under Nix. Each item's **Checked:** line records
the independent check's verdict (2026-11-13) where it ruled on the item.

**Item counts by Weight, after corrections:** blocks-goal 1, misleads 3, improves 8, nit 3 (15 items).
Independent check: 4 claims confirmed (X-nix-01, -03, -06, Summary 5), 4 weakened and corrected (X-nix-02, -09,
Summary 1, Summary 4 with §3); nothing withdrawn from this document.

Reviewer: p2-nix (Claude Opus 5.5, high). Base `eefea3c`. Read-only; no repository file changed.

Sources consulted: shared `mcp__firecrawl__*` only (search + scrape), 2026-11-13. Pages fetched are cited inline with the date the page shows. "Snippet only" marks claims seen only in a search result.

## Summary (five findings)

1. **No tool found (searches 2026-11-13) evaluates a NixOS or nix-darwin config to data and applies it without Nix on a stock OS.** The nearest prior art proves the pattern for narrower targets: nixidy (NixOS module system → plain YAML → Argo CD; the cluster needs no Nix), terranix (→ Terraform JSON), and, of the same kind, kubenix and arion, all narrow, non-OS precedents; also nix-darwin's `homebrew` module (→ Brewfile → `brew bundle`). system-manager, home-manager, nix-darwin, clan, comin and nix-on-droid all need Nix on the device. tendcf's G2 is new ground. NixOS 25.11's modular services (`system.services.<name>`) do not change this: they are portable only between Nix module-system frameworks, are marked in development, and have only a draft for nix-darwin (see 04, L-§5-09). (Claim b; independently checked 2026-11-13: weakened, corrected.)
2. **"Carry over" is undefined in the documents, and only part of a shared config can carry over.** Pure-data options (nix-darwin `system.defaults`, `homebrew.*`, `launchd.*.serviceConfig` keys, `users.users` names, `networking.hostName`, `environment.etc.<p>.text`) can. Anything that holds a `pkgs` reference (store paths in `ExecStart`/`ProgramArguments`, `environment.systemPackages`, `shell = pkgs.zsh`), and every high-level NixOS `services.<x>.enable` module, cannot. The docs need a third path beside passthrough and authoring: a carry-over import that reports what it dropped (X-nix-02, -05, -06).
3. **The paper's only Nix example is not NixOS-style.** It writes site values as `mkOption` *defaults* in option *declarations*. A NixOS user sets `config` values against options a module declares (X-nix-03). The frontend should evaluate with `lib.evalModules` from a pinned `nixpkgs.lib` and no `pkgs`, so a store path cannot reach a goal file (X-nix-04).
4. **For NixOS and nix-darwin hosts, comin already covers G3's pull and self-convergence: it polls several Git remotes, checks GPG/SSH commit signatures, refuses force-pushed `main`, and evaluates and builds on the device. clan adds no central controller but pushes over SSH. Neither accepts updates from an arbitrary peer unless that peer is a configured remote, and neither shows the owner a refusable diff.** Neither reaches stock macOS or Android, and nix-darwin issue #1860 (Sep 2026) shows a declarative Nix config silently uninstalling unmanaged Mac App Store apps. That is G4's case exactly (X-nix-07, -08). (Claim c; independently checked 2026-11-13: weakened, corrected.)
5. **The one Nix test never runs in CI.** `test_nix_expression_equals_yaml`, the only test that evaluates Nix, is skipped in CI (no Nix in the `compiler` job; log: `59 passed, 1 skipped`) and this Mac has no Nix. No CI run has ever evaluated the repository's Nix file (X-nix-09). (Claim d; independently checked 2026-11-13: confirmed; wording corrected.)

## 1. Prior art: NixOS-style modules configuring a non-NixOS system

| Tool | Evaluates modules how | Needs on target | Applies how | Licence, activity | Role for tendcf |
|---|---|---|---|---|---|
| nix-darwin | `darwinSystem`, its own module tree on nixpkgs | Nix (Nix or Lix); README recommends the Lix installer because the official one has no automated uninstaller | `sudo darwin-rebuild switch`; activation scripts; manages the Nix install itself | MIT (not re-checked); active, 26.05 branch current. README still says flakes are "an experimental feature in Nix currently" ([README](https://raw.githubusercontent.com/nix-darwin/nix-darwin/master/README.md), fetched 2026-11-13) | passthrough host (already D12); **option-name source** for the frontend (X-nix-05) |
| home-manager | same module system, user scope | Nix | activation script per user | MIT (not checked) | competitor for dotfiles; `programs.*` mostly emit store-path-laden files: low carry-over |
| system-manager (numtide) | "builds on the many modules that already exist in NixOS"; a subset of NixOS-compatible modules | Nix, tested against 2.32 and above (the README says "tested", not required); supported on NixOS, Ubuntu, Debian ([repo](https://github.com/numtide/system-manager)) | own diff engine, "can only modify files in `/etc` and systemd units", local state file "similar to Terraform"; "no central controller or agents", local or over SSH ([1.0 post, 2026-01-08](https://numtide.com/blog/system-manager-1-0/)) | 1.8k stars; 1.0 stable Jan 2026 | **closest competitor on Linux** (G5 items 4-5); its narrow-surface diff engine is the same idea as tendcf's unit-writer domains |
| nix-on-droid | own module set (`environment.packages`, etc.) | the app from F-Droid; "relies on `proot` and other hacks"; "prototype-grade"; aarch64 only ([repo](https://github.com/nix-community/nix-on-droid)) | `nix-on-droid switch` inside the proot userland | MIT; 2.2k stars; last commits 2026-10-26, 2026-08-21, one main maintainer ([commits API](https://api.github.com/repos/nix-community/nix-on-droid/commits?per_page=3)); no GitHub releases | not a frontend or backend: it configures a userland, not Android. No overlap with Island/Insular/Shizuku (G5) |
| NixOS-WSL | NixOS modules | WSL | `nixos-rebuild` | listed in [awesome-nix](https://raw.githubusercontent.com/nix-community/awesome-nix/main/README.md) | out of scope (no Windows target) |
| disko | NixOS module for disk layout | Nix at install | partitions at install (with nixos-anywhere) | used by clan | out of scope |
| Guix System / `guix home` / `guix deploy` | Guile records, services graph | Guix; GNU/Linux or Hurd only; 1.5.0 released 2026-01-23, rootless daemon default on foreign distros ([release](https://guix.gnu.org/en/blog/2026/gnu-guix-1.5.0-released/)) | `guix system reconfigure`, `guix home reconfigure`, `guix deploy` over SSH | GPL; 744 contributors 2022-2026 | no macOS or Android: a Guix frontend serves only G5 items 4-5 (X-nix-15) |
| nixidy | NixOS-style modules (`imports`, `mkDefault`, `mkForce`) over typed Kubernetes options | **nothing on the cluster**: "the output is plain YAML you can `git diff`"; rendered-manifests pattern ([codedbearder, 2026-06-08](https://codedbearder.com/posts/nixidy-part-1-introduction/)) | Argo CD syncs the committed YAML | listed in awesome-nix | **the best precedent for G2's shape**: Nix authoring, data beneath, a non-Nix applier, reviewable diff |
| terranix | module system → Terraform JSON | Terraform, no Nix | `terraform apply` | listed in awesome-nix | same precedent |

## 2. NixOS config → data → a non-Nix applier

No project found that does this for a whole OS configuration on a stock OS (searches: firecrawl web and developer index, three phrasings; closing search found nothing new). Narrow cases exist (table above; kubenix and arion are of the same non-OS kind as nixidy and terranix; plus nix-darwin `homebrew`, which writes a Brewfile and runs `brew bundle --file=… --zap --force-cleanup`). "Nobody does this" is unprovable; the claim is that no tool was found. (Independently checked 2026-11-13: weakened, corrected; no counter-example found.)

What a NixOS/nix-darwin config holds that is not portable data (inferred from Nix semantics; not run, no Nix on this Mac):

1. **Store paths.** Any `"${pkgs.foo}/bin/foo"` interpolation evaluates to `/nix/store/<hash>-foo/bin/foo`. Meaningless on a device without that closure.
2. **Derivations and packages.** `environment.systemPackages`, `*.package` options, `users.users.<u>.shell = pkgs.zsh`.
3. **Functions and lazy structure.** `config` as a whole cannot be `toJSON`'d: functions, `_module`, infinite or throwing attributes. Only chosen option paths can be read.
4. **High-level modules.** `services.nginx.enable = true` is a promise to expand into units, users, tmpfiles and firewall rules. The meaning lives in nixpkgs code, so carrying it over means reimplementing that module.
5. **Activation scripts** (`system.activationScripts`, nix-darwin `system.activationScripts.*`): arbitrary shell.
6. **IFD.** Evaluation may build things ([Nix 2.34 manual, IFD](https://nix.dev/manual/nix/stable/language/import-from-derivation)).

Rough carry-over by category for a typical shared config. These are estimates. I did not measure a corpus.

| Category | Carries over | Does not |
|---|---|---|
| nix-darwin `system.defaults.*` (Dock, Finder, NSGlobalDomain) | nearly all: plain values | none |
| `homebrew.brews/casks/masApps` | names: all | `onActivation.cleanup` semantics must become tendcf tombstones (see #1860) |
| `launchd.user.agents`/`launchd.daemons` `.serviceConfig` | keys map 1:1 to plist ([option list](https://mynixos.com/nix-darwin/options/launchd.user.agents.%3Cname%3E.serviceConfig)) | `ProgramArguments`/`command` that hold store paths |
| `systemd.services.<n>` (raw) | structure, `User`, `Restart`, `wantedBy` | `ExecStart` with store paths; `path = [ pkgs.x ]` |
| `services.<x>.enable` modules | none | the bulk of a NixOS server config |
| `users.users`, `networking.hostName`, `time.timeZone` | names, uid, groups, home, values | `shell = pkgs.*`, `hashedPassword` (secret) |
| `environment.etc.<p>.text` | yes | `.source = ./file` / store paths (needs copying) |
| `environment.systemPackages` | names only, through a per-platform package claim | the packages themselves |
| home-manager `programs.*` | little | generated dotfiles referencing the store |

So a nix-darwin workstation config carries over well. A NixOS server config, which is mostly `services.*.enable`, carries over badly. That fits G5's order, macOS first.

## 3. Fleet tools vs G3 (no control node, each device pulls alone, peer update after a crypto check)

| Tool | Pull/push | Control node | Crypto check | Owner sees and can refuse a diff | Non-NixOS |
|---|---|---|---|---|---|
| comin | pull; polls Git, deploys within ~60 s; "multiple Git remotes to avoid SPOF"; testing branches; refuses force-pushed `main` ([repo](https://github.com/nlewo/comin), [design](https://github.com/nlewo/comin/blob/main/docs/design.md)) | none | "optionally check GPG and SSH Git commit signatures" | no (signature proves *who*, not *what*) | nix-darwin yes |
| bento | pull over SFTP chroot per client, systemd timer ([README](https://raw.githubusercontent.com/rapenne-s/bento/main/README.md)) | yes: "need a machine to be online most of the time" | SSH auth | no; `nvd` diff for the admin | NixOS only |
| clan | push (`clan machines update`, "from any computer that can reach this machine via SSH"); "without a central controller"; vars/sops secrets; inventory ([docs 26.05](https://docs.clan.lol/), [macOS guide](https://clan.lol/docs/26.05/guides/macos)) | none | SSH | no | nix-darwin with Nix installed; no Android |
| deploy-rs, colmena, morph, NixOps, krops, pushnix | push over SSH from an admin machine ([awesome-nix](https://raw.githubusercontent.com/nix-community/awesome-nix/main/README.md)) | the admin machine | SSH | no | no |
| nixos-anywhere | install-time push | n/a | SSH | n/a | installs NixOS over a host |
| FlakeHub `fh apply` | pull of a pre-resolved store path; Nix need not evaluate; paid plan required ([docs, 2026-09-21](https://docs.determinate.systems/flakehub/store-paths/)) | FlakeHub (hosted) | FlakeHub auth + cache signatures | no | NixOS, home-manager, nix-darwin |
| nixos-rebuild + timer / Hydra channel | pull a channel | Hydra | binary-cache signatures | no | no |
| garnix | not fetched | | | | |

Answer to "is any of them already most of G3 for NixOS hosts?": For NixOS and nix-darwin hosts, comin already covers G3's pull and self-convergence: it polls several Git remotes, checks GPG/SSH commit signatures, refuses force-pushed `main`, and evaluates and builds on the device. clan adds no central controller but pushes over SSH. Neither accepts updates from an arbitrary peer unless that peer is a configured remote, and neither shows the owner a refusable diff. (Independently checked 2026-11-13: weakened, corrected; comin and clan together are not G3, since clan adds push, not pull.) What tendcf adds over clan + nix-darwin + nix-on-droid: (a) devices that never install Nix; (b) Android itself (work profile, Shizuku), not a proot userland; (c) an owner-visible, refusable, mechanically checked diff on the device; (d) peer relay of signed releases. Without (a)-(c), tendcf would be a fourth wrapper around `switch`.

## 4. Nix on macOS and Android in 2026

1. macOS: installers are upstream, Lix (recommended by nix-darwin) and Determinate Nix (a downstream distribution with lazy trees and parallel eval, [docs, 2026-10-08](https://docs.determinate.systems/)). Known upgrade breakage: macOS overwrites `/etc/zshrc`/`/etc/bashrc` on updates (a fixer LaunchDaemon exists but the repository is archived, last pushed 2024-04-16: [nix-darwin-fixer](https://github.com/mrhenry/nix-darwin-fixer), read). macOS 15 needed a `_nixbld` UID migration ([NixOS/nix#11075](https://github.com/NixOS/nix/pull/11075), merged 2024-09, snippet only). A third-party 2026-05 design note rejects nix-darwin for "sudo on every apply, four open Tahoe-incompatibility issues" (snippet only, not verified). nix-darwin now needs `sudo darwin-rebuild` and has a `system.primaryUser` option ([README](https://raw.githubusercontent.com/nix-darwin/nix-darwin/master/README.md); [option](https://mynixos.com/nix-darwin/option/system.primaryUser), snippet only).
2. Android: nix-on-droid only (above). Proot, aarch64 only, prototype-grade, low commit rate. It cannot set Android settings, profiles or app state. Nix on the phone is not a viable tendcf dependency, and D6/D46 already keep it off.

## 5. AI and Nix

1. **Tools exist because models invent names.** mcp-nixos is titled "Because Your AI Shouldn't Hallucinate Package Names". It serves NixOS, home-manager, nix-darwin, flakes, Nixvim and NVF options plus NixHub versions, needs no Nix, and is MIT with 885 stars ([repo](https://github.com/utensils/mcp-nixos), fetched 2026-11-13). Static option search engines exist for any module set: NüschtOS Search takes "a list of NixOS modules" ([README](https://github.com/NuschtOS/search/blob/cbdbeef58566d5107808b467832c2203387c2dec/README.md), snippet only). Also optnix, manix, nix-search-tv ([awesome-nix](https://raw.githubusercontent.com/nix-community/awesome-nix/main/README.md)).
2. **Good target.** The module system is a checker. An undeclared option fails evaluation, types are enforced, and `mkOption` carries a `description` that becomes generated docs (`optionsJSON` → `options.json`, as system-manager ships: [docs/options.nix](https://github.com/numtide/system-manager/blob/7dc61e113afa23d51ceb92feb186dc708297efb3/docs/options.nix), snippet only). Merge semantics (`mkDefault`, `mkForce`) are explicit.
3. **Bad target.** Lazy evaluation hides errors until a value is forced. `rec`/`with` cause "hard-to-debug" `infinite recursion` and defeat static analysis ([nix.dev best practices](https://nix.dev/guides/best-practices)). nixpkgs changes option names across releases, and a model trained on several releases mixes them. Flakes are still experimental upstream.
4. **What tendcf should ship** (X-nix-10): `options.json` and a static search page built from tendcf's own module; the same data through an MCP source (mcp-nixos already aggregates several option catalogues, so a contribution is plausible: inferred); and `tendcf compile --check` as the model's loop, printing the module system's error with the option path and a nearest-name suggestion.

## 6. Readable without manuals

The community lessons, all in nix.dev best practices (fetched): quote URLs, avoid `rec`, no top-level `with`, no `<nixpkgs>` lookup paths, pin nixpkgs, set `config = {}; overlays = [];`, and remember that `//` is shallow. Newcomers get lost in flake boilerplate (`inputs`/`outputs`/`follows`) before reaching a single option, so nix-darwin's README spends three steps on it. For G2's "reads clearly": a site file should be a plain module (`{ ... }: { tendcf.… = …; }`) with no flake wrapper. tendcf should own the pinning in its lock, and the person should see the evaluated YAML/JSON beneath. That is the nixidy and terranix lesson: show the rendered data in the diff.

## 7. Honest risks of "real Nix first"

1. Error messages: lazy evaluation, `infinite recursion`, and trace depth. A non-admin user (G1) never sees these only if the AI reads them first.
2. Pinning: module-system code (`lib.evalModules`) lives in nixpkgs `lib`. Every site pins one, and NixOS option compatibility drifts per release.
3. IFD: must be off. `nix-instantiate --eval` without `--read-write-mode` does not build (manual example shows the flag is needed), so today's hook is IFD-safe by accident (inferred, not run).
4. Flakes are experimental upstream. Determinate's downstream differs. The hook's flake-free `nix-instantiate` is the conservative choice. linux-targets §5 contradicts it (X-nix-14).
5. Evaluation cost: full NixOS evaluation imports every module (4.0 s → 1.4 s for `toplevel` when the list is cut, per [nixpkgs#137168](https://github.com/NixOS/nixpkgs/issues/137168), open since 2021; a 2026-10 comment reports "gigabytes of extra memory" for dense import graphs). A carry-over import of a NixOS config pays this on the author machine, never on a phone.
6. The reimplementation trap: each NixOS `services.<x>` carried over is a module rewrite. That is the system-manager road (a curated subset), and it never ends. Refuse it: carry over only pure-data option families and report the rest.
7. Nix on the evaluating machine: G1's long-run user may own only a phone and a Mac. Evaluation then needs Nix on the Mac (G5 item 1) or a pure evaluator (snix is a Tvix fork with "no drop-in binary", snippet only; snix.dev's home page and /docs/ were read 2026-11-13 and the phrase is not there: the page says "Nix-compatible surface" and "Designed to be embedded", so the quoted phrase is still unlocated). Nix is a build-host dependency, not a device one.

## Response items

### X-nix-01: D12 still says two equal frontends; G2 makes Nix first

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §15 decision table, row D12, at the sentence beginning "Two equal frontends, Nix modules and YAML"
**Kind:** ruling-drift
**Goal:** G2
**Weight:** misleads
**Finding:** D12 and linux-targets §5 ("YAML and Nix are equal frontends … Nobody has to learn Nix") make the frontends peers. G2 makes Nix the authoring language and YAML/JSON the data it evaluates to, still writable by hand. The byte-identical twin rule still fits. The ordering and the "stranger path" wording in compiler/docs/DESIGN.md item 3 do not.
**Evidence:** `architecture-DEFINITIVE-v3.md:1211`; `linux-targets.md:92-94`; `compiler/docs/DESIGN.md:60-63`; goal G2.
**Proposed text:**

> **Amended 2026-11-13 (goal G2).** Nix is the authoring language: Site Model options are NixOS-style module options, and a site is a set of modules that set them. The YAML/JSON Site Model is the data a Nix site evaluates to; it is also a complete authoring form by hand, and each Nix fixture keeps a YAML twin that renders to a byte-identical goal file.

**Merge:** needs the operator's ruling first (amends D12; also linux-targets §5 last paragraph and compiler DESIGN.md item 3)
**Checked:** verified (read the three anchors); independently checked 2026-11-13: confirmed

### X-nix-02: add a third Nix path, carry-over import

**Target:** `docs/architecture/linux-targets.md` §5 "Nix (ruling 2026-10-29)", insert after item 2 "Nix as an authoring language"
**Kind:** add
**Goal:** G2, G1
**Weight:** blocks-goal
**Finding:** G2 says existing NixOS and nix-darwin configs "carry over" to devices that need not run Nix. §5 offers only passthrough (the host keeps Nix) and authoring (new files in tendcf's options). Nothing takes a sysadmin's existing nix-darwin config to a stock Mac, and that is the G1 first adopter's first move. No prior art was found that does it (§2 above). It has to be specified, including what is refused. This is an alternative to L-§5-09 (the frontend reads NixOS option shapes on every compile) and to X-nix-05 (the frontend accepts nix-darwin names). Present the three as one choice for the operator.
**Evidence:** `linux-targets.md:70-90`; §2 of this report.
**Proposed text:**

> 3. **Carry-over import.** A person's existing NixOS or nix-darwin configuration is evaluated once, with its own pinned nixpkgs and nix-darwin, on the authoring machine or in CI (never on a device). The importer reads a fixed list of pure-data option families (nix-darwin `system.defaults`, `homebrew`, `launchd.agents`/`launchd.daemons`/`launchd.user.agents` `serviceConfig`, raw `systemd.services`, `users.users`, `networking.hostName`, `time.timeZone`, `environment.etc.<path>.text`) into Site Model files. It then reports every other defined option by path and file as **not carried over**, and refuses any value containing a `/nix/store/` path. High-level `services.<name>.enable` modules are never reimplemented one by one. The import is a plugin of kind importer (plugin-layout §3), not a frontend: after it runs, the site keeps the written files.

**Merge:** needs the operator's ruling first (scope of G2's "carry over"; one choice with 04's L-§5-09 and X-nix-05)
**Checked:** inferred (option families from nix-darwin option lists fetched; no corpus measured); independently checked 2026-11-13: weakened, corrected

### X-nix-03: the paper's Nix example declares options instead of setting them

**Target:** `docs/paper/tendcf-architecture-paper.md` §2.6 "Three worked examples", the block beginning "# site/services/edge-http.nix — the same caddy record"
**Kind:** correct
**Goal:** G2
**Weight:** misleads
**Finding:** The example puts each site value in an option *declaration's* `default` (`options.siteModel.services.caddy.command = mkOption { default = [ … ]; }`). In NixOS style a module shipped by the tool declares the options once, and the site's file sets `config` values. A NixOS sysadmin reading this would not recognise it, and an AI copying it would produce declarations, not configuration.
**Evidence:** `docs/paper/tendcf-architecture-paper.md:598-640`.
**Proposed text:**

> ```nix
> # site/services/edge-http.nix: the same caddy record, set against the
> # options tendcf's module declares (ILLUSTRATIVE, frontend unbuilt §6.5).
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
>     provides = [ "service:caddy" "port:443" "port:80" ];
>     requires = [ "path:/etc/caddy/Caddyfile" "service:tailscaled" ];
>   };
> }
> ```
>
> The option declarations (`mkOption`, `types.*`) live once in tendcf's Nix frontend, not in the site.

**Merge:** replace the code block and its lead-in sentence's "`mkOption`/`types.*` and all"; needs the operator's ruling first for the option namespace (`tendcf.services` here), which waits on the ruling on X-nix-05/L-§5-09; until then label it provisional in the code comment
**Checked:** verified (read the block); proposed snippet not evaluated (no Nix here); independently checked 2026-11-13: confirmed

### X-nix-04: specify the frontend's evaluation envelope

**Target:** `docs/architecture/plugin-layout.md` §2 table, row `plugins/frontends/nix/`, column "Planned"
**Kind:** add
**Goal:** G2, G4
**Weight:** improves
**Finding:** The planned frontend is described only as "the D12 Nix module frontend". Its safety depends on what is in scope during evaluation. If it uses `lib.evalModules` from a pinned nixpkgs `lib` and does **not** pass `pkgs`, a site cannot produce a store path or build anything, and its output is pure data. Without that rule, one `"${pkgs.caddy}/bin/caddy"` puts a Nix-only path in a goal file for a Nix-less Mac.
**Evidence:** `plugin-layout.md:83`; `compiler/nix2cf/cli.py:150-170` (`nix-instantiate --eval --strict --json`); [IFD manual](https://nix.dev/manual/nix/stable/language/import-from-derivation).
**Proposed text:**

> the D12 Nix module frontend, named `nix2cf`; `eval-nix` moves here. It evaluates the site's modules with `lib.evalModules` from a nixpkgs `lib` pinned in the site lock, passes no `pkgs`, runs read-only with import-from-derivation off, and refuses any output string containing `/nix/store/`. Only the Site Model option tree is read; the result is the Site Model JSON the YAML frontend would produce.

**Merge:** replace the "Planned" cell
**Checked:** inferred (Nix semantics; not run)

### X-nix-05: name Site Model options after nix-darwin and NixOS where they mean the same

**Target:** `docs/architecture/plugin-layout.md` §3 "Plugin kinds and entry-point groups", Frontend row
**Kind:** add
**Goal:** G2, G1
**Weight:** improves
**Finding:** Carry-over (and an AI trained on NixOS) works best if a block copied from an existing config evaluates unchanged. nix-darwin's `launchd.user.agents.<name>.serviceConfig` already uses plist keys (`Label`, `ProgramArguments`, `RunAtLoad`, `KeepAlive`, `UserName`, `WorkingDirectory`), the same facts tendcf's launchd `unit` carries. Inventing `tendcf.services.<n>.launchd.runAtLoad` beside it makes users and models translate by hand.
**Evidence:** [nix-darwin serviceConfig options](https://mynixos.com/nix-darwin/options/launchd.user.agents.%3Cname%3E.serviceConfig) (fetched 2026-11-13); `schema/goal-file.schema.json` `unit` (not re-read for this item).
**Proposed text:**

> Where a Site Model fact has a nix-darwin or NixOS option of the same meaning, the Nix frontend accepts that option's name and shape (for example `launchd.user.agents.<name>.serviceConfig.{Label,ProgramArguments,RunAtLoad,KeepAlive,UserName}` and `systemd.services.<name>.serviceConfig.{User,Restart}` with `wantedBy`). It maps them to the Site Model and refuses, by path, any key it does not map.

**Merge:** needs the operator's ruling first (option-tree design; a data-shape choice)
**Checked:** verified (nix-darwin option names fetched); mapping completeness not checked

### X-nix-06: packages are the largest part of a shared config and have no home

**Target:** `docs/architecture/linux-targets.md` §5, "Consequences" list, insert as a new item after item 4
**Kind:** add
**Goal:** G2, G5
**Weight:** misleads
**Finding:** `environment.systemPackages`, `homebrew.brews/casks` and nix-on-droid `environment.packages` are what people share most. The Site Model has services and files, not package claims per platform package manager (Homebrew, apt, F-Droid). Without them, carry-over silently drops the biggest category. Schema v5 has `unit-package` for Debian only.
**Evidence:** `linux-targets.md:36` (v5 `unit-package`); §2 table of this report.
**Proposed text:**

> 5. Package lists (`environment.systemPackages`, nix-darwin `homebrew.*`) carry over only as names. Until the Site Model has a per-platform package claim, a carried-over package list is reported as not carried over, never dropped silently. nix-darwin's `homebrew.onActivation.cleanup` is not imported as a behaviour: removal in tendcf is a tombstone the owner approves (see nix-darwin issue #1860, where cleanup uninstalled unmanaged App Store apps without a prompt).

**Merge:** insert after item 4; the package-claim schema needs the operator's ruling
**Checked:** verified (#1860 fetched, opened 2026-09-03, open); independently checked 2026-11-13: confirmed ("largest part of a shared config" is an estimate)

### X-nix-07: passthrough hosts — compare comin before building a pull agent

**Target:** `docs/architecture/nixos-passthrough-plan.md` §5 "Work this unlocks, in order", insert as item 4
**Kind:** question
**Goal:** G3, G7
**Weight:** improves
**Finding:** linux-targets §5 says tendcf adds "distribution (lockfile, signed release, consent diff, pull)" on Nix hosts. comin already pulls from several Git remotes, converges alone, refuses force-pushed history, supports testing branches and checks commit signatures, on NixOS and nix-darwin. tendcf's unique part there is the owner's refusable diff, which could gate comin (for example a branch comin reads only after approval) rather than replace it.
**Evidence:** [comin README](https://github.com/nlewo/comin), [design](https://github.com/nlewo/comin/blob/main/docs/design.md) (fetched 2026-11-13); `linux-targets.md:76-79`.
**Proposed text:**

> 4. Before any tendcf pull agent is built for Nix hosts: decide whether comin (pull-mode GitOps for NixOS and nix-darwin, multi-remote, commit-signature checks) is the transport there, with tendcf's approved consent diff deciding which commit comin may deploy.

**Merge:** needs the operator's ruling first
**Checked:** verified (comin docs); comin's signature-check details not read

### X-nix-08: say what tendcf adds over clan + nix-darwin + nix-on-droid

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §12 "Platforms", insert before "**macOS (adapter #1).**"
**Kind:** add
**Goal:** G1, G3, G4, G5
**Weight:** improves
**Finding:** A Nix-sharing sysadmin (G1's first adopter) will ask why not clan. The map never answers. Clan has no central controller, drives nix-darwin, and has secrets and inventory, but it pushes over SSH, needs Nix on every machine and has no Android. comin and FlakeHub `fh apply` cover pull. None shows the owner a refusable diff.
**Evidence:** [clan docs](https://docs.clan.lol/), [clan macOS](https://clan.lol/docs/26.05/guides/macos), [nix-on-droid](https://github.com/nix-community/nix-on-droid), [fh apply](https://docs.determinate.systems/flakehub/store-paths/) (all fetched 2026-11-13).
**Proposed text:**

> **Against the Nix fleet tools.** clan, comin, deploy-rs and FlakeHub's `fh apply` all need Nix on the device and apply whatever the signed or reachable head says. tendcf targets devices that never install Nix, configures Android itself rather than a userland on it (nix-on-droid runs under proot), and changes nothing the owner has not seen as an exact diff and could refuse. On a host that already runs NixOS or nix-darwin those tools remain the right appliers (passthrough, D12).

**Merge:** insert before the macOS paragraph
**Checked:** verified (sources above)

### X-nix-09: the Nix test is skipped everywhere

**Target:** `.github/workflows/check.yml`, job `compiler`, before step "Tests"
**Kind:** add
**Goal:** G2
**Weight:** improves
**Finding:** `test_nix_expression_equals_yaml` is `skipif` no `nix-instantiate`. The `compiler` job installs only uv, and the operator's Mac has no Nix (`command -v nix-instantiate` printed nothing). The CI run for `eefea3c` reports `59 passed, 1 skipped`, and the only other skip in that file needs a missing checkout, which CI has. No CI run, in this repository or in the archived frdminc/nix2cf, has evaluated `compiler/examples/site/site.nix`; the docs say so (`compiler/README.md`, `DESIGN.md` item 3).
**Evidence:** `compiler/tests/test_compile.py:739-744`; `.github/workflows/check.yml:67-84`; `gh run view 43457987671 --log` → `compiler Tests … 59 passed, 1 skipped in 2.16s`.
**Proposed text:**

> ```yaml
>       # The Nix frontend hook's only test needs nix-instantiate; without
>       # this step it is skipped and site.nix is never evaluated.
>       - uses: DeterminateSystems/nix-installer-action@main
> ```

**Merge:** insert after `astral-sh/setup-uv@v5`; add `-rs` to pytest so a skip is named
**Checked:** verified (CI log); which test was skipped is inferred (pytest did not print reasons); independently checked 2026-11-13: weakened, corrected (the docs already disclose the skip, so nothing misleads; Weight now improves)

### X-nix-10: ship the option set in the forms models already use

**Target:** `docs/architecture/plugin-layout.md` §3, insert a paragraph after the table
**Kind:** add
**Goal:** G1, G6, G2
**Weight:** improves
**Finding:** G6 makes AI authorship the premise. The Nix world's answer to invented options is option catalogues served to the model (mcp-nixos, 23k+ NixOS options plus home-manager, nix-darwin, Nixvim, NVF) and static option search. tendcf's options exist only as JSON Schema today. Generated option docs and an eval-check loop cost little and make the module system the model's checker.
**Evidence:** [mcp-nixos](https://github.com/utensils/mcp-nixos), [awesome-nix](https://raw.githubusercontent.com/nix-community/awesome-nix/main/README.md) (fetched); system-manager `optionsJSON` (snippet only).
**Proposed text:**

> The Nix frontend publishes its option tree in three generated forms: an `options.json` in the nixpkgs `optionsJSON` format, a static search page, and the same data as an MCP source. `tendcf compile --check` is the authoring loop for a person or a model: it evaluates, and on failure prints the option path, the defining file and line, and the nearest declared option name.

**Merge:** insert after the table
**Checked:** inferred (mcp-nixos accepting a third-party source not checked)

### X-nix-11: the passthrough consent summary cannot be "the evaluated options JSON"

**Target:** `docs/architecture/nixos-passthrough-plan.md` §4, at the sentence beginning "The evaluated options JSON is a readable summary"
**Kind:** reword
**Goal:** G4
**Weight:** nit
**Finding:** A NixOS `config` cannot be serialised whole: functions, derivations and throwing attributes. The summary has to be a named list of option paths, plus `nvd`/`dix` package diffs, or it will fail or be unreadable.
**Evidence:** `nixos-passthrough-plan.md:109`; [awesome-nix](https://raw.githubusercontent.com/nix-community/awesome-nix/main/README.md) (nvd, dix).
**Proposed text:**

> - A readable summary under it: the values of a fixed list of option paths (users, `networking`, `services.*.enable`, `systemd.services` names, `environment.etc` names), before and after, and `nvd` package-version changes.

**Merge:** replace that bullet
**Checked:** inferred

### X-nix-12: macOS as server must not depend on Nix

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §12 "Platforms", macOS paragraph, after "Mac that already runs nix-darwin keeps that configuration verbatim"
**Kind:** add
**Goal:** G5, G8
**Weight:** improves
**Finding:** G5 puts macOS-as-server first and G8 state 1 needs a Mac to converge from Nix-authored config. Nix on macOS breaks on OS updates (`/etc/zshrc` overwrite; the Sequoia `_nixbld` UID migration), and nix-darwin needs root on every apply. Nix belongs on that Mac only as the evaluating toolchain, and the Mac's convergence must not stop when Nix breaks.
**Evidence:** [nix-darwin README](https://raw.githubusercontent.com/nix-darwin/nix-darwin/master/README.md); NixOS/nix#11075 ("add UID migration script for macOS Sequoia 15", closed 2024-07-10) and nix-darwin-fixer (archived, last pushed 2024-04-16), both read 2026-11-13.
**Proposed text:**

> On the Mac that evaluates the site (G5 item 1), Nix is a build-host tool only: a macOS update that breaks the Nix install stops new compiles, never convergence of the approved release already on the device.

**Merge:** insert after that sentence
**Checked:** partly (README verified; the breakage reports read 2026-11-13); sources re-fetched 2026-11-13: corrected

### X-nix-13: say where evaluation runs for a phone-only user

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §5, "**Where it runs:** operator machine or CI."
**Kind:** question
**Goal:** G1, G3
**Weight:** improves
**Finding:** G1's long-run user may own a phone and nothing else that runs Nix, and G3 forbids a control node. The compile step (and so Nix evaluation) has to run somewhere: the user's Mac, a CI runner, or a peer that offers it as a service (a "server" in G3's sense). The map names only the operator machine or CI.
**Evidence:** `architecture-DEFINITIVE-v3.md:319-322`.
**Proposed text:**

> **Where it runs:** any machine the site's owner trusts to compile: their own Mac or Linux box, CI, or a peer offering compilation as a service (a server in the goal's sense, G3). Never on the device being configured. A device accepts only the signed result.

**Merge:** needs the operator's ruling first
**Checked:** verified (read anchor)

### X-nix-14: linux-targets §5 and the code disagree on the evaluator

**Target:** `docs/architecture/linux-targets.md` §5 item 2, at "evaluates (`nix eval --json --store dummy://` in this plan;"
**Kind:** correct
**Goal:** G2
**Weight:** nit
**Finding:** The plan names `nix eval` (needs the experimental `nix-command`, and flakes for a flake ref). The hook uses `nix-instantiate --eval --strict --json`, which DESIGN.md chose as flake-free and stable. nix-darwin's README still calls flakes experimental. Pick one, and say why.
**Evidence:** `linux-targets.md:82-86`; `compiler/nix2cf/cli.py:14-18`; `compiler/docs/DESIGN.md:60-69`.
**Proposed text:**

> evaluates (`nix-instantiate --eval --strict --json`, read-only, the stable flake-free evaluator; no `nix-command` or flakes feature is required)

**Merge:** replace the parenthesis
**Checked:** verified (read the three anchors)

### X-nix-15: the Guix frontend serves only G5's last two platforms

**Target:** `docs/architecture/plugin-layout.md` §2 tree, line "frontends/guix/          later: Guile records → Site Model JSON"
**Kind:** reword
**Goal:** G5, G2
**Weight:** nit
**Finding:** Guix 1.5.0 (2026-01-23) runs on GNU/Linux and the Hurd only. Its users cannot carry configs to macOS or Android. G2 names only Nix. The entry can stay, ranked after G5 item 5.
**Evidence:** [Guix 1.5.0](https://guix.gnu.org/en/blog/2026/gnu-guix-1.5.0-released/).
**Proposed text:**

> frontends/guix/          later, after the Linux targets (G5 items 4-5): Guile records → Site Model JSON

**Merge:** replace that line
**Checked:** verified

## What I did not check

1. Nothing was evaluated with Nix: there is no Nix on this Mac, and I ran no build. All Nix-semantics claims above are inferred, not run.
2. Licences of clan, home-manager and nix-darwin. garnix, NixOps current status, deploy-rs/colmena READMEs (one-line awesome-nix descriptions only), and Hydra setups.
3. The carry-over fractions are estimates, with no corpus measured.
4. Whether mcp-nixos accepts third-party option sources.
5. nix-darwin's open Tahoe issues (snippet only).
6. comin's signature-check semantics, and whether its signature list can pin a key per remote.
7. Paper §6.5 and the guide's Nix passages; other reviewers hold those documents.

## Ideas and risks

1. **Ship a nixidy-style "rendered site" in Git.** Commit the evaluated YAML beside the `.nix` files so every diff shows both. This is the rendered-manifests pattern, and G2's "reads clearly" made concrete.
2. **Carry-over as a report the AI reads.** The importer's "not carried over" list is exactly what G1's AI should explain to the user, one line per option path.
3. **Store-path tripwire everywhere.** The schema lint can refuse `/nix/store/` in any goal-file string, a one-line rule and a second wall behind X-nix-04.
4. **nix-darwin #1860 as a showcase.** Write it up as G4's motivating example: a declarative config with a cleanup flag silently deleted unmanaged apps. tendcf would have shown a tombstone diff.
5. **comin as the NixOS-host transport** (X-nix-07) saves building a pull agent for G5's fourth platform.
6. **Risk: the reimplementation trap.** Requests for "just one more NixOS service" will come. Hold the line at pure-data families, or the project becomes system-manager for macOS.
7. **Risk: nixpkgs `lib` drift.** Pin it in the site lock. Test the frontend against two nixpkgs releases in CI, since a site's carried-over config comes with its own pin.
8. **Risk: evaluation host as an implicit control node.** If only the operator's Mac can compile, G3 breaks in practice. Make "compile" a service any trusted peer can offer (X-nix-13).
9. **Idea: Determinate's lazy trees and parallel eval** could cut import time for large NixOS configs. A pure evaluator (snix) could one day remove the Nix install from the build host. Neither is needed now.
10. **Risk: two option namespaces.** Mirroring nix-darwin names (X-nix-05) and keeping tendcf's own (`tendcf.services`) can confuse authors. Choose one canonical name per fact and accept the other only on import.

Last search run: firecrawl developer index, "NixOS module system compile to Ansible or launchd plist without Nix on target", 2026-11-13: nothing that changes finding 1.

## Withdrawn after checking

Nothing in this document was refuted. The related refuted claim, that NixOS modular services are a ready way to carry configuration to a machine without Nix, was made in 04 (Ideas 1 and L-§5-09's original remedy) and is withdrawn there.
