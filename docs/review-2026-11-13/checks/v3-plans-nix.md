# v3: verification of 04-response-plans.md and 08-nix-ecosystem.md

Checker: independent, read-only, 2026-11-13. Repo: `the review worktree` (HEAD `c3ae530` = `eefea3c` plus the two goal-review files; anchors checked against the working tree, identical to `eefea3c` for every target). Every anchor phrase of both reports was checked by a script (exact or line-wrapped match); all exist except where noted. No repository file was changed.

Prior art / docs checked (shared `mcp__firecrawl__*` and `gh api`, all fetched 2026-11-13): nixpkgs `nixos/doc/manual/development/modular-services.md` on `master` and on `release-25.11`; `nixos/README-modular-services.md`; `nixos/modules/misc/documentation/modular-services.nix`; release notes `rl-2511`, `rl-2605`, `rl-2611`; NixOS/nixpkgs#372170 (merged 2025-07-24) and #428084 (open); nix-darwin/nix-darwin#1765 (draft, open) and #1860; comin README and `docs/design.md`; clan docs 26.05 index and macOS guide; system-manager repo page; frdminc/tendcf PRs #41, #42 (bodies, files, diffs, checks, comments) and CI run 43457987671; frdminc/nix2cf `.github/workflows/check.yml`. Searches (firecrawl web and developer index) for Nix-config-to-non-Nix appliers and nix-darwin modular-services support.

## Verdicts

| Item | Verdict | Evidence (one line) | Correction |
|---|---|---|---|
| L-hdr-01 (misleads) | weakened | Anchor spans a blockquote line break (`deferred;` / `> Linux is the platform`, `linux-targets.md:3-4`); facts right (map §13 row 1 is macOS). "Linux work is paused" is not in G5 or any ruling. | C1 |
| L-§1-02 (blocks-goal) | confirmed | `linux-targets.md:8-16` all Linux; `rg -il 'insular\|island' docs/architecture schema compiler` empty. New file name is a proposal, correctly marked "needs ruling". | none |
| L-§3-04 (misleads) | weakened | Row 6 anchor at `:38` exists; launchd is the only rendered supervisor (`compile.py:95`). "Paused 2026-11-13" is an un-ruled decision. | C1 |
| L-§4-05 (blocks-goal) | weakened | Map §12 (`architecture-DEFINITIVE-v3.md:993-995`) already names "Termux + tendcf-agent + Shizuku-class helper + CFEngine"; the gap is Island/Insular profiles, not Shizuku. | C2 |
| L-§4-07 (misleads) | weakened | D45 scope confirmed (map `:1006-1011`). Proposed "Its first enforced host is the server Mac" is a decision nobody made (pastebin is already enforced, without it). | C3 |
| L-§5-08 (misleads) | confirmed | `linux-targets.md:92-94`; G2. | none |
| L-§5-09 (blocks-goal) | weakened; remedy refuted | Finding (path 2 invents its own options) holds. Remedy rests on misread facts: modular services target Nix module-system frameworks, nix-darwin has none merged (draft PR #1765), about 8 exist in nixpkgs, and their `process.argv` is a store path. Evidence URL is an unofficial mirror. | C4 |
| L-§5-10 (misleads) | confirmed | `linux-targets.md:76-77` vs `nixos-passthrough-plan.md:88-92` (stage D) and `:104-111`. | none |
| L-§5-11 (blocks-goal) | confirmed | Map `:1165` sends nix-darwin passthrough to linux-targets Step 8; the NixOS plan's only "darwin" is a vocabulary note (`:120`); no Nix on this Mac (`command -v nix nix-instantiate darwin-rebuild` empty, no `/nix`). | none |
| L-§5-12 (misleads) | confirmed | `linux-targets.md:36` ("`nixos` left the writer vocabulary"); `goal-file.schema.json:536` enum has `nix-darwin`, no `nixos`. | none |
| N-hdr-01 (misleads) | weakened | `nixos-passthrough-plan.md:3` vs §6 `:125-139` confirmed. "Paused 2026-11-13" is un-ruled. | C1 |
| N-§3-02 (blocks-goal) | confirmed | `:105-111` consent is the host-flake PR; nothing device-side. Phrased as a question, correctly. | none |
| N-§5-04 (misleads) | confirmed | `:116-123` vs `:28-34` and §6. Same "paused" caveat (C1). | C1 (wording only) |
| PL-§2-02 (blocks-goal) | weakened | Facts right. But change-process `:114-115` ("Nix is an optional builder, never a dependency of the path"), `:386-387` and map R5/D6 say the opposite of "a Nix evaluator is release-path code"; the item neither names the conflict nor asks for a ruling. | C5 |
| PL-§2-03 (blocks-goal) | confirmed | `plugin-layout.md:67-69` launchd/systemd/runit only; `compiler/docs/DESIGN.md:41-43` refuses `android`. | none |
| PL-§3-01 (misleads) | confirmed | `plugin-layout.md:104`. | none |
| V-hdr-01 (blocks-goal) | confirmed | Anchor `:5`; §9 "It does guarantee" `:889` has no owner-visibility item. | none |
| V-§2-03 (blocks-goal) | weakened | Anchor and §9 item 5 (`:879`) confirmed. The `--accept DIGEST` design is new and un-ruled, and the merge note deletes §9's "not yet guarantee" text before anything is built. | C6 |
| V-§3-04 (blocks-goal) | confirmed | Anchor `:489`. | none |
| V-§3-05 (misleads) | weakened | Nothing existing is misleading; it proposes new semantics. Weight should be `improves`. Merge already says it needs a ruling. | C7 |
| V-§9-09 (blocks-goal) | weakened | `ls deploy` = `linux/` only, confirmed. But "None of these is planned anywhere" is wrong: §6(d) (`:724-728`) already recommends the bundled interpreter under `/opt/tendcf/libexec/tendcf-validate/` "on Linux and macOS". | C8 |
| V-§10-10 (misleads) | confirmed | Item 11 anchor (wrapped) confirmed; map Step 6 is "push-only". | none |
| V-§13-11 (misleads) | weakened | Master records neither ruling (grep). But PR #42 itself adds "Implemented 2026-11-06: option 3, per djbclark's ruling Q10 (2026-11-02)" to §13, and PR #41 records R13 (2026-11-02) in upstream-register. The proposed text would duplicate #42's paragraph. | C9 |
| X-CP-01 (blocks-goal) | confirmed | `change-process.md:291-292`; phrased as a question. TUF delegated targets roles are a standard spec feature (not fetched by me either). | none |
| X-CP-02 (misleads) | confirmed | `change-process.md:330`. | none |
| X-CP-03 (misleads) | confirmed | `change-process.md:177-178`; `goal-file.schema.json:570,576,603` require `policy-tree`; added in `9fdf437` (2026-08-15). | none |
| X-OV-01 (blocks-goal) | confirmed | Workflows are `check.yml` and `linux.yml`, no macOS runner; PR #42 body gives the Mac build as `3.29.0a.086d27749` without `8f0076b81`. Rule (f) applies to the options (C10). | C10 (add a clause) |
| X-RM-01 (misleads) | confirmed | `README.md:27` vs `AGENTS.md:267-268`. | none |
| X-RM-02 (misleads) | weakened | Anchor `README.md:3` confirmed. The proposed text says "Configuration is written in Nix" in the present tense, but the Nix frontend is not built (`compiler/README.md`, `cli.py:14-18`). | C11 |
| X-CO-01 (misleads) | confirmed | `compiler/README.md:8-10`; plugin-layout `:83` names the Nix frontend `nix2cf`. | none |
| X-CO-02 (misleads) | weakened | `DESIGN.md:60-69` confirmed. The proposed text drops R5/change-process "Nix optional" without naming it (same conflict as PL-§2-02). | C5 |
| X-CO-03 (misleads) | confirmed | `compiler/AGENTS.md:16`. | none |
| X-CO-04 (blocks-goal) | confirmed | `DESIGN.md:41-43`, `:101`. | none |
| X-WIP (#41/#42/s5) | weakened | Ordering and park both hold. But #42's body says "Not yet done: the frontier cross-model review and the adversary security verdict … Do not merge before both". Neither PR records a frontier review. Merging #41 after #42 also makes two #42 statements stale. s5-design is now 54 commits behind master, not 52. | C12 |
| X-HO-01 (improves; carries (e)) | weakened | Same omission: "merge #42 and #41" skips their outstanding frontier and adversary reviews. | C12 |
| 04 Ideas 1 (modular services) | refuted | See C4: designed for Nix module-system frameworks; nix-darwin support is an unmerged draft; argv holds store paths. | C4 |
| X-nix-01 (misleads) | confirmed | Map `:1211`, `linux-targets.md:92-94`, `DESIGN.md:60-63`. | none |
| X-nix-02 (blocks-goal) | weakened | Gap confirmed. It conflicts with L-§5-09 (a one-shot importer here, a live frontend reading NixOS shapes there) and with X-nix-05. "No prior art" holds only as far as anyone searched. | C13 |
| X-nix-03 (misleads) | confirmed | Paper `:598-640` declares `mkOption` defaults. The replacement's `tendcf.services` namespace is an un-ruled data-shape choice (cf. X-nix-05, L-§5-09). | C14 |
| X-nix-06 (misleads) | confirmed | Schemas have no package claim except v5 `unit-package` (systemd hosts, dpkg names; `linux-targets.md:36`). #1860 confirmed (opened 2026-09-03, open; needs `cleanup = "uninstall"/"zap"` plus a `masApps` entry). "Largest part of a shared config" is an estimate. | none |
| X-nix-09 (misleads) | weakened | CI skip confirmed: run 43457987671 (head `eefea3c`), `compiler Tests … 59 passed, 1 skipped`; the `compiler` job installs only uv; frdminc/nix2cf's CI had no Nix either. But the docs already disclose the skip (`compiler/README.md` "skipped without a Nix install"; `DESIGN.md:69`; the `site.nix` header), so nothing misleads; weight `improves`. Path is `compiler/examples/site/site.nix`. "Never evaluated": no CI run or record shows one; a local run elsewhere cannot be excluded. | C15 |
| 08 Summary 1 / §2 (claim b) | weakened | No counter-example found (my searches: Ansible export, defaults-write export, "without Nix" appliers). system-manager is "supported on NixOS, Ubuntu, and Debian" and is Nix-based. Narrow precedents (nixidy, terranix; kubenix and arion are of the same kind) target non-OS appliers. "Nobody" is unprovable. | C16 |
| 08 Summary 4 / §3 (claim c) | weakened | comin confirmed: pull, multiple remotes, GPG/SSH commit-signature checks, refuses force-pushed `main`, nix-darwin. Its builder evaluates and builds on the device. clan confirmed: no central controller, but updates are pushed (`clan machines update` "from any computer that can reach this machine via SSH"), and Nix plus nix-darwin are needed on Macs. Together they are not G3: clan adds push, not pull. | C17 |
| Claim d (CI skips the only Nix test; site.nix never evaluated) | confirmed, wording | Skip confirmed (above). `test_eval_nix_without_nix_is_a_clean_error` runs, but it tests absence. "Only test that evaluates Nix" is exact. | C15 |

Counts: 24 confirmed, 19 weakened, 1 refuted (04 Ideas 1; L-§5-09's remedy likewise), 0 unverifiable.

## Corrections

**C1 (L-hdr-01, L-§3-04, N-hdr-01, N-§5-04, also X-AR-01).** G5 orders the platforms. It does not pause Linux work, and no ruling does. Replace "paused" with order language unless the operator rules a pause. In L-hdr-01's text: "Status: superseded in its ordering by the goal of 2026-11-13 (G5 …). Linux is fourth and fifth in line; finished pieces stay as standing proofs." In L-§3-04: "**After macOS and Android in the goal's order (G5, 2026-11-13):** …". In N-hdr-01: "Under the goal's platform order (G5) Linux and NixOS work comes fourth and fifth." Add to each Merge: "needs the operator's ruling first if 'paused' is to be kept". Quote L-hdr-01's anchor as two lines: "Android/Termux is deferred;" / "Linux is the platform".

**C2 (L-§4-05).** Replace the second sentence of the Finding with: "Item 1 and map §12 assume Android runs Termux with runit services, alongside tendcf-agent and a 'Shizuku-class helper'. G5 adds Island/Insular profiles, which no document or schema models (no work-profile versus personal-profile split), and names ShizukuPlus specifically." Proposed text unchanged.

**C3 (L-§4-07).** Delete "Its first enforced host is the server Mac (G5)." from the proposed text, or end it with "Which host it is first enforced on is for the operator (G5 puts the server Mac first)."

**C4 (L-§5-09 and 04 Ideas 1).** Replace the Finding's last three sentences and the proposed text with:
> NixOS 25.11 added *modular services* (`system.services.<name>`, a module with `_class = "service"` setting `process.argv`). The manual marks them "in development … significant changes should be expected". Their portability is between Nix module-system frameworks: "a configuration management framework is an application of `evalModules`" (NixOS, Home Manager, nix-darwin). nix-darwin has no merged support; nix-darwin/nix-darwin#1765, "add modular service interface for launchd", is an open draft (2026-05). nixpkgs ships about eight such services, mostly Linux network daemons (`modular-services.nix`). The canonical `process.argv` is `lib.getExe` of a package, a `/nix/store` path that a Mac without Nix lacks. A tendcf Nix frontend could be one more such framework, but only for services whose argv it can map to a non-store path. That conflicts with X-nix-04's no-`pkgs`, no-store-path envelope, and it does not carry over the conventional `services.<x>.enable` modules that existing configs use.

Proposed text: "Open, for the operator: whether the Nix frontend accepts NixOS modular services (`system.services.<name>`, NixOS 25.11, in development) as one input shape, given that their `process.argv` normally names a store path. Options tendcf cannot honour on the target refuse the compile by name." Evidence: https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/modular-services.md, https://github.com/nix-darwin/nix-darwin/pull/1765 (in place of the nixos.lv mirror). In 04 Ideas 1 replace "nix-darwin's launchd is named as the second process manager" with "nix-darwin support is an unmerged draft (#1765)", and drop "cheapest literal delivery of G2".

**C5 (PL-§2-02, X-CO-02).** Add to the Finding: "This contradicts `change-process.md` §2 ('Nix is an optional builder, never a dependency of the path', and alternative 5, 'R5/D6 keep Nix optional') and map R5. G2 may override them, but only by the operator's ruling." Set Merge to "needs the operator's ruling first (Nix on the release path vs change-process §2 and map R5/D6)". In X-CO-02's proposed text, after "devices never need it (D6)", insert "; this amends change-process.md §2's 'Nix is an optional builder', pending the operator's ruling".

**C6 (V-§2-03).** Merge: "insert after option 3's first paragraph as a proposal; needs the operator's ruling first (the `--accept DIGEST` interface). Amend §9 'does not yet guarantee' item 5 only when the first build implements it."

**C7 (V-§3-05).** Weight: `improves`.

**C8 (V-§9-09).** Replace "None of these is planned anywhere." with: "§6(d) already recommends the bundled interpreter under `/opt/tendcf/libexec/tendcf-validate/` on macOS. The macOS installer, the LaunchDaemon and a pinned macOS fork build are not planned." In the proposed text replace "the bundled interpreter (item 6)" with "the bundled interpreter §6(d) recommends".

**C9 (V-§13-11).** Replace the proposed text with: "**Ruled 2026-11-02:** option 3 (Q10), implemented in PR #42, which records it below; and option 5 (R13, Q49), the fork's all-or-nothing loader pinned by PR #41 (upstream-register B-5b note). Each holds without the other." Merge: "land with #41, after #42; do not duplicate #42's 'Implemented 2026-11-06' paragraph".

**C10 (X-OV-01).** Append to the proposed text: "Whichever is chosen, the binary enters a release only as a digest-bound fetched artifact (change-process.md §2 rule 5, 'A tool fork is never an input of its own'), so a local `bg` build counts only once it is published and its digest recorded."

**C11 (X-RM-02).** In the proposed text replace "Configuration is written in Nix, with plain YAML/JSON beneath it." with "Configuration is to be written in Nix, with plain YAML/JSON beneath it; today the compiler reads the YAML/JSON form only."

**C12 (X-WIP, X-HO-01).** X-WIP row #42: replace "Green, ruled, and it unblocks the restructure" with "Green and ruled; still needs its frontier cross-model review and adversary verdict (its body: 'Do not merge before both'). Merging it unblocks the restructure." Row #41: add "Also needs its frontier and adversary reviews. Rebase it on #42 and re-run CI. In the same PR, correct #42's check-8 comment in `tests/policy/run.sh` ('the fork's loader skips a bad entry') and the §13 sentence 'The Linux CI legs … exercise the real per-entry skip': after #41 neither is true. #41's body names pin `c3afaac26`; the diff pins `d32cade13`." Row s5: "54 commits behind" (measured `git rev-list --count HEAD..master`). X-HO-01's proposed text: "review (frontier + adversary) and merge #42, then #41".

**C13 (X-nix-02).** Add to the Finding: "This is an alternative to L-§5-09 (the frontend reads NixOS option shapes on every compile) and to X-nix-05 (the frontend accepts nix-darwin names). Present the three as one choice for the operator." Replace "No prior art does it" with "No prior art was found that does it."

**C14 (X-nix-03).** Add to Merge: "the option namespace (`tendcf.services` here) waits on the operator's ruling on X-nix-05/L-§5-09; until then label it provisional in the code comment."

**C15 (X-nix-09).** Weight: `improves`. Replace the Finding's last sentence with: "No CI run, in this repository or in the archived frdminc/nix2cf, has evaluated `compiler/examples/site/site.nix`; the docs say so (`compiler/README.md`, `DESIGN.md` item 3)." In 08 Summary 5 replace "Nothing in the repository has ever been checked to evaluate as Nix" with "No CI run has ever evaluated the repository's Nix file".

**C16 (08 Summary 1).** Replace "Nobody evaluates" with "No tool found (searches 2026-11-13) evaluates", and add kubenix and arion beside nixidy and terranix as narrow, non-OS precedents.

**C17 (08 Summary 4 and §3 answer).** Replace with: "For NixOS and nix-darwin hosts, comin already covers G3's pull and self-convergence: it polls several Git remotes, checks GPG/SSH commit signatures, refuses force-pushed `main`, and evaluates and builds on the device. clan adds no central controller but pushes over SSH. Neither accepts updates from an arbitrary peer unless that peer is a configured remote, and neither shows the owner a refusable diff." X-nix-07 needs no change.

## Answers to (a)–(f)

**(a)** Modular services are real: nixpkgs#372170, merged 2025-07-24. The manual says "new in NixOS 25.11", "Status: in development … significant changes should be expected". They are portable between Nix `evalModules` frameworks (NixOS; Home Manager and nix-darwin are named), not to non-Nix configuration managers. RFC 163's approach is "not yet a widely agreed upon solution" (README-modular-services). About 8 services exist. nix-darwin has only draft PR #1765. The 25.11, 26.05 and 26.11 release notes do not mention them. Fit for tendcf: weak. argv is normally a store path, and adopting them contradicts X-nix-04.

**(b)** No counter-example found. system-manager needs Nix on the target (NixOS, Ubuntu, Debian). nixidy, terranix, kubenix and arion are non-OS precedents. Option-to-JSON exporters (`nix eval --json`, `optionsJSON`) exist but apply nothing.

**(c)** Partly. comin covers pull, self-convergence and signature checks on NixOS and nix-darwin. clan is push. Neither covers peer acceptance from arbitrary devices or G4.

**(d)** True. The skip is confirmed in the CI log, and no CI in either repo ever installed Nix. "Never evaluated" is unprovable beyond CI and records, and the docs already disclose it.

**(e)** The order (#42 then #41) and parking s5 hold under G5. Missing: both PRs still need frontier and adversary reviews (#42's body forbids merging before them), #41 needs a rebase that fixes two stale #42 statements, and #41's body pin hash is stale.

**(f)** change-process.md §2 rule 5 (`:121-125`): "A tool fork is never an input of its own. The CFEngine patch overlay is content inside the tendcf input; a built binary or the Android agent's APK enters a release only as a digest-bound fetched artifact (map §9.8, DC-11). The lockfile pins sources, not binaries." Neither report cites it. It constrains X-OV-01's macOS-build options (C10).

## Not checked

1. Items weighted `improves` or `nit` beyond their anchors (all anchors exist), except where they bear on (a)–(f).
2. Whether #41 and #42 conflict textually: diffs read; their run.sh hunks are in different regions and `interlock-malformed.json` is byte-identical in both. No trial merge was run (read-only).
3. The D46 decisions worktree diff; live hosts; Darwin buildability of `cfengine-tendcf.nix`.
4. 08's unverified table facts: system-manager "Nix ≥ 2.32", FlakeHub's paid plan, nix-on-droid commit dates, mcp-nixos figures, the nix-darwin README flakes wording, Guix 1.5.0. Home Manager's `home.services` is snippet only.
5. Nix semantics (IFD, `lib.evalModules` without `pkgs`): no Nix here, nothing evaluated.
6. TUF delegation semantics (not fetched).

Last search run: firecrawl developer index, "nix-darwin pull request modular services launchd", then `gh search prs` on nix-darwin, run after drafting. It found #1765, an open draft, which changed C4. Nothing else found changes a verdict.

