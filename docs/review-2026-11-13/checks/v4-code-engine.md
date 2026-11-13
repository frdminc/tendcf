# v4: refutation check of 05-response-code.md and 11-engine-alternatives.md

Checker: Opus 5.5 (Agent-tool sub-agent), 2026-11-13. Repo read-only at `eefea3c` (`the review worktree`); fork checkout `the cfengine-core fork checkout` (read-only `git show`/`log`/`merge-base`, no fetch). No build, no test suite, no live host, nothing posted. Only local commands run: `git`, `rg`, `man launchctl`, small Python readers, and `cf-agent --version` on the two installed builds.

Prior art / docs checked (shared firecrawl, scrape): CFEngine `commands` reference (https://docs.cfengine.com/docs/master/reference/promise-types/commands/), `getvalues()` reference (https://docs.cfengine.com/docs/master/reference/functions/getvalues/), Nix 2.28 conf-file manual (https://nix.dev/manual/nix/2.28/command-ref/conf-file.html), cfengine/core merged and unmerged simulate PR lists (https://github.com/cfengine/core/pulls?q=is%3Apr+simulate+is%3Amerged, ...+is%3Aunmerged), Homebrew API (https://formulae.brew.sh/api/formula/cfengine.json), Termux recipe (https://raw.githubusercontent.com/termux/termux-packages/master/packages/cfengine/build.sh), repology (https://repology.org/project/cfengine/versions), NixOS search (https://search.nixos.org/packages?channel=unstable&query=cfengine). Local: `man launchctl`. One firecrawl search returned only irrelevant hits, so I fetched known URLs instead.

Verdict counts: confirmed 33, weakened 10, refuted 0, unverifiable 2 (45 rows). The C-policy-01 row counts as confirmed: its finding holds, and only its proposed text is wrong.

| Item ID | Verdict | Live or latent | Evidence, one line | Correction to apply, if any |
|---|---|---|---|---|
| 05 C-compiler-01 | weakened | latent (no Nix frontend in use) | `cli.py:150-171` is a bare `nix-instantiate --eval --strict --json`; `site.nix:1-13` says "No nixpkgs, no `lib`, no module system" | Drop the NIXOS_REFUSAL sentence (see Corrections) |
| 05 C-compiler-02 | weakened | latent (authoring machine only; no device runs it) | Nix manual: `restrict-eval` and `pure-eval` both "Default: `false`", `allow-import-from-derivation` "Default: `true`"; `cli.py:155-160` passes no options | Fix the `-` argument clause (see Corrections) |
| 05 C-compiler-03 | weakened | latent | `_tendcf_dir` (`cli.py:62-65`) takes `--tendcf`, then `$TENDCF_DIR`, then the checkout; the unvalidated path needs all three to be absent, and the note says "pass --tendcf or set TENDCF_DIR" (`compile.py:707-711`) | Add the condition (see Corrections) |
| 05 C-compiler-04 | confirmed (by reading, not run) | latent (no example uses `platform: any` without a launchd block) | `services.schema.json` `$defs/service` allOf requires `launchd` only `if platform == macos`; `compile.py:238` accepts `"any"`; `:293` reads `sel.record["launchd"]["label"]`; `cli.py:123` catches only CompileError; `test_compile.py:295` sets `any` but keeps the launchd block | none |
| 05 C-compiler-05 | confirmed | n/a | `PLATFORM_SUPERVISORS` has no android row (`compile.py:85-88`); `--platform choices=["macos","linux"]` (`cli.py:182`); `site.nix:27` declares `android-termux-services` | none |
| 05 C-compiler-06 | confirmed | n/a | `SUPERVISION_DOMAIN` TODO "mapping is not written down anywhere" (`compile.py:63-74`); `PROJECTING_DOMAIN = "supervision"` (`projector.py:127`) | none |
| 05 C-compiler-07 | confirmed | n/a | `compiler/README.md:93` "Tombstones from the Site Model (it cannot yet say \"absent\")"; render emits only `"state": "present"` (`compile.py:536`) | none |
| 05 C-compiler-08 | confirmed (read) | latent | `owners[0]` at `compile.py:599-612`; the compiler never imports schema_lint (only docstring mentions) | none |
| 05 C-policy-01 | confirmed (finding); proposed text weakened | code path live in the deployed policy; injection latent (the deployed canary pre_action is `["/usr/bin/true"]`) | `join(" ", …)` + `useshell => "true"` (`tendcf_services.cf:85-98, 370-374`); schema `pre_action.command.items` = `{"type":"string","minLength":1}` with no pattern; site-model `common.schema.json:84-96` items are plain strings | The proposed text says "absolute path required by schema"; no such rule exists (see Corrections) |
| 05 C-policy-01 extension: other lints | confirmed: nothing else restricts it | as above | No `pre_action` hit in `bin/schema_lint.py`, `xref_lint.py`, `overlay.py` or the compiler. The only string filter is the projector's `EXPANSION_SEQUENCES = ("$(", "${", "@(", "@{")` (`projector.py:145`), which blocks `$(…)` substitution but not `;`, `|`, `&&`, backticks or redirection; and `tendcf-install.sh data FILE` installs a projection without running the projector (`put_data`, `:144-158`) | Mention the projector filter and its limit (see Corrections) |
| 05 C-policy-01 extension: fix expressible? | weakened: expressible in principle, not proven, and a smaller certain step exists | n/a | Docs: `arglist` is an slist (3.9.0+), whitespace kept under noshell since 3.24.0; `useshell` default is `noshell`; `getvalues("d[k]")` returns an slist from a container path (documented example). So `"argv_$(canon)" slist => getvalues("data:variables.tendcf_interlock[$(id)][pre_action][command]")` dodges the "container assigned to an indexed variable" error. Splitting head and tail, and whether `@(argv_$(canon))` parses as an arglist, are exactly what the comment reports failing; that is unproven | See Corrections (two-step fix) |
| 05 C-policy-02 | confirmed | latent on the deployed path (no deployed service carries `env`; the Mac runs nothing) | Neither `launchd.plist.mustache` nor `systemd.service.mustache` names `env`; `compile.py:548-550` emits it; `projector.py:484-509` passes it through after a name check | none |
| 05 C-policy-03 | confirmed | latent (no Mac deployment) | `launchctl load -w` gated only on classes, no loaded probe, no unload on change (`:311-317`); the launchd files promise has no `classes` body, unlike systemd's `tendcf_unit_rendered`; local `man launchctl`: load/unload "will only return a non-zero exit code due to improper usage. Otherwise, zero is always returned" | none |
| 05 C-policy-04 | confirmed | latent (no compiler tombstones, no Mac install) | `:293-301` says it in so many words: "no existence or type gate, by design … Its only guard is the lint"; `unload` runs for any non-present id (`:315-317`) | none |
| 05 C-policy-05 | weakened | latent | Backup half confirmed: no `edit_defaults` on the launchd promise; the file's own comment at `:376-381` says the default leaves `.cf-before-edit`. Perms half overstated: CFEngine creates new files at `0600` (`cf-agent/verify_files_utils.c:4515, 4569`), root-owned under a root agent, which launchd accepts | See Corrections |
| 05 C-policy-06 | weakened | live in shape (pastebin canary), consequence latent | No `isvariable` in `policy/` (rg exit 1); `getindices` of an undefined container is empty. But cf-agent logs CMDB rejections at ERR (`libpromises/cmdb.c` at the pin: `LOG_LEVEL_ERR` at :185, :205, :212, :230 …), so the bundle is silent but the agent is not | See Corrections |
| 05 C-schema-01 | confirmed | latent | `host` pattern `^ed25519:[0-9a-f]{64}$` (`goal-file.schema.json:13-17`); `cf-key-functions.c:322` `RSA_generate_key_ex`; `git grep -i ed25519` in cfengine-core: 0 hits; no tendcf code generates a device key (`--host-key` is a required CLI input, `cli.py:181`). The design never says the host key is CFEngine's key (`architecture-DEFINITIVE-v3.md:173`), so the gap is "not built", not "wrong key type chosen" | none (the finding already says no code produces it) |
| 05 C-schema-02 | confirmed | n/a | approval-record `signature` "Exact encoding is residue" (`approval-record.schema.json:64`); the goal file has no signature member | none |
| 05 C-schema-03 | confirmed | n/a | Closed kinds and supervisors (`compile.py:80`; schema `state_entries`); stayturgid modules exist: android_apk, android_appops, android_settings, android_app_privileges, android_a11y_services, shizuku_grant (+ android_intent, shizuku_start, native_agent_config) | none |
| 05 C-schema-04 | confirmed | n/a | `rg -l 'goal-diff|approval-record|report-row'` over bin, compiler/nix2cf, policy, deploy, tests, .github gives only `schema_lint.py` and `unit_classifier.py` | none |
| 05 C-schema-06 | confirmed | latent | Same schema span as C-policy-01 | none |
| 05 C-bin-01 | weakened (one sub-claim) | live (installer path) | No host, signature or baseline check, and no full schema validation (projector imports no jsonschema). But the projector does refuse non-conforming input structurally (P-6.6, P-6.7, env names, expansion sequences; `projector.py:190-200, 145, 484-509`) | See Corrections |
| 05 C-tests-01 | confirmed | n/a | run.sh header: "nothing here touches launchd"; check 5 runs only `!= Darwin` (`:148-161`); only two workflows, all `ubuntu-*`/`debian:13`; no fixture reaches a launchd render on any CI runner | none |
| 05 C-tests-02 | confirmed (read; mutation not run) | n/a | `interlock-refused.json` holds only launchd services; both launchd promises are gated on `darwin` (`:280, :313`) | none |
| 05 C-tests-03 | confirmed | n/a | `skipif(shutil.which("nix-instantiate") is None)` (`test_compile.py:739`); the compiler job is `ubuntu-latest` + `setup-uv` only (`check.yml:68-76`) | none |
| 05 C-deploy-01 | confirmed | n/a | `[ "$(uname)" = Linux ] || die "Linux only"` (`tendcf-install.sh:47`) | none |
| 05 C-deploy-02 | confirmed | live (how the pastebin canary data is installed) | `put_data` copies the file and runs `cf-promises` only (`:144-158`) | none |
| 05 C-ci-01 | confirmed | n/a | Workflows are `check.yml` (ubuntu-latest) and `linux.yml` (ubuntu matrix + `debian:13`) | none |
| 05 C-android-01 | confirmed (facts); framing note | n/a | stayturgid README: `cf-agent -f` / `cf-serverd -f`, "the Termux fleet's 3.27.1". The design states the choice outright: "tendcf-agent (Android) … No daemon beside CFEngine off Android" (`architecture-DEFINITIVE-v3.md:87-90`, R1). Fleet version from the README only | Optional: say "D45 chose no CFEngine on Android without weighing the Termux CFEngine already deployed" rather than "does not account for" |
| 05 C-android-02 | confirmed | live in stayturgid (not in tendcf) | `trustkeysfrom => { "100.64.0.0/10" }` (`cf-serverd.cf:34`); `trustkey => "true"` (`cf-runagent.cf.example:30`) | none |
| 05 C-android-03 | confirmed; framing note | live in the ShizukuTendCF build | README:14-20: "revoke and deny are ignored … by owner decision on 2026-10-03 … intended for stayturgid fleet devices" | Note that it is a recorded owner decision for the fleet flavour: a ruling conflict, not an oversight |
| 05 C-macos-02 | confirmed | n/a | `rg -il jsonl` over bin, compiler/nix2cf, policy, deploy: no hits | none |
| 05 C-macos-03 | unverifiable (PATH) | latent | `services.yml:47` `["tailscale","status","--json"]` against `:105` `/usr/local/bin/tailscaled`. The PATH a root cf-execd under launchd hands to `/bin/sh` was not checked (needs a Mac launchd run, or launchd documentation) | Keep `Checked: inferred` |
| 05 C-g4-01 | confirmed (absence) | n/a | No scoring code; `derive_ceremony_class` in `schema_lint.py` | none |
| 11 §2 drift numbers | confirmed | n/a | `upstream/master..b8abf2840` 68 non-merge; merge-base diff 65 files +4540/−269; `git cherry` 0 equivalent; `b8abf2840..upstream/master` 67 non-merge (95 with merges); upstream tip `270e6c36f` 2026-11-12; 226 non-merge commits since 2026-08-01 | none |
| 11 F3 / X-engine-01 | weakened | latent: the deployed Linux build is the full fork pin `b8abf2840`, which contains `6e522a730` (`merge-base --is-ancestor`: yes) under the 2026-10-29 ruling (`upstream-overlay.md:50-55`); the Mac dev build and stock lack it; the only deployed pre_action is `/usr/bin/true` | Commit text read. Stock `cf_pwait` returns −1 for any `!WIFEXITED` child (pre-fix `pipes_unix.c:801-809`), which is PROMISE_RESULT_FAIL; `GracefulTerminate` escalates SIGINT→SIGTERM→SIGKILL on the pid. So a check that hangs until killed fails closed on stock too. Fail-open needs the reaped process to exit normally with `expect_exit` after the alarm | Narrow the claim (see Corrections) |
| 11 X-engine-01 "not in overlay" | confirmed | n/a | `overlay.json` patches: B-5a, B-5b, B-13, B-14, B-22, B-23 only; upstream master has no `TimeOutHasFired` (`git show upstream/master:cf-agent/verify_exec.c`) | none |
| 11 X-engine-02 | weakened | latent | as F3 | Replace the proposed comment (see Corrections) |
| 11 X-engine-03 | weakened (detail) | n/a | Merged list fetched: #6332 Sep 2, #6389 Oct 13, #6412 Oct 20, #6424 Nov 12 (all by the project's author); backports #6338/#6339 (Sep 3, of #6332) and #6499/#6500 "Simulate mode package fixes" (Nov 13); maintainer PRs #6436, #6438, #6439 (Oct 26-27), backports #6443/#6444. Guide line 1477 says "Nothing has merged." Proposed text says "twenty-six"; guide line 1472 says "twenty-three fixes"; which fixes #6499/#6500 carry was not checked | Fix the count and the backport claim (see Corrections) |
| 11 X-engine-04 | confirmed | n/a | #6293, #6294 "was closed Aug 19, 2026" (unmerged list); guide:591-592 "Both are offered and neither has merged" | none |
| 11 X-engine-05 | confirmed | n/a | Every fixture's pre_action is `/usr/bin/true` or `/usr/bin/false` with `timeout_seconds: 5`; no run.sh check sleeps past a timeout | none |
| 11 X-engine-06 | confirmed | n/a | Homebrew `stable 3.29.0`, bottles arm64_golden_gate/tahoe/sequoia + Linux, `autobump: true`, 182 installs/365d; Termux `1:3.28.0`, revision 2, maintainer `@termux`; repology: MacPorts 3.18.0, no nixpkgs row; NixOS search: only two emacsPackages | none |
| 11 X-engine-07 | confirmed (date detail) | n/a | `the Mac dev build` reports `3.29.0a.086d27749`; `6e522a730` and `8f0076b81` are not ancestors of it. `086d27749` was authored 2026-09-30 and committed 2026-10-15 | none |
| 11 X-engine-08 | unverifiable | n/a | Design proposal, not prototyped; needs the §7 spike | none |
| 11 §3 liveness/releases | confirmed in part | n/a | Package versions as above; tags page not re-fetched | none |

## Corrections

05 C-compiler-01: replace "Worse, a NixOS host's units are refused by design (`NIXOS_REFUSAL`), the inverse of carrying them over." with:
> A NixOS host is passthrough by design (`NIXOS_REFUSAL`): tendcf writes none of its units, so a NixOS configuration "carries over" only by staying where it is; nothing imports it into the Site Model.

05 C-compiler-02: replace "A file argument beginning with `-` is also passed straight to nix-instantiate as an option." with:
> A file named after `--` (`nix2cf eval-nix -- -x`) reaches nix-instantiate as an option, because the argv has no `--` before the path. Import-from-derivation is also on by default, so evaluation can trigger builds.

05 C-compiler-03: replace the first sentence of the Finding with:
> When neither `--tendcf` nor `$TENDCF_DIR` is given, `_in_tree_tendcf` deliberately returns None for any installed layout (pip, venv, `--target`).

05 C-policy-01: replace the Proposed text with:
> Step 1, certainly expressible today: set `useshell => "noshell"` (CFEngine's default) in `tendcf_interlock_contain`, so no shell parses the joined string, and require `pre_action.command[0]` to match `^/` and every item to match the systemd argv alphabet plus "no ASCII space" (schema bump), so that the joined string splits back into the same argv. Step 2, once proven against a real build: build an slist per interlock with `getvalues("data:variables.tendcf_interlock[$(id)][pre_action][command]")` under a canonified, non-bracket name, and pass its tail as `arglist` with its head as the promiser. Keep step 1's alphabet until step 2 passes a test.

Add to its Finding:
> The only other filter on these strings is the projector's refusal of `$(`, `${`, `@(`, `@{` (`bin/projector.py:145`). It does not stop `;`, `|`, `&&`, backticks or redirection, and `tendcf-install.sh data` installs a projection without running the projector.

05 C-policy-05: replace "It also states no `perms`, although launchd refuses daemon plists that are not root-owned or that are group- or world-writable." with:
> It states no `perms`. A plist the agent creates is `0600` and root-owned (CFEngine's create default), which launchd accepts, but an existing plist with the wrong owner or mode is never corrected.

05 C-policy-06: replace "and the bundle does nothing and reports nothing: the same as a host with zero entries" with:
> and the bundle does nothing and reports nothing. Only cf-agent's own ERR log line about the CMDB data is left, and tendcf does not surface it. To the bundle, that run looks like a host with zero entries.

05 C-bin-01: replace item "2. validate the schema;" with:
> 2. validate against goal-file.schema.json (it does refuse non-conforming shapes, duplicate ids, non-name `env` values and CFEngine expansion sequences, but it is not a schema validator);

11 F3 (§2) and X-engine-01: replace "If that commit message is right, then on stock CFEngine a hung interlock check whose shell exits with `expect_exit` (0 is the common case) sets `interlock_ok_*` and the bundle actuates: fail-open." with:
> On stock CFEngine a check that is killed by the timeout fails closed: `cf_pwait` returns −1 for a signalled child, which is a failed promise. It passes only if the process CFEngine reaps exits normally with `expect_exit` after the alarm. That covers a check that turns SIGINT or SIGTERM into that code, a shell whose child finishes inside the SIGINT→SIGTERM→SIGKILL ladder, and a check that closed its output before the alarm (nothing is signalled) and later finishes with that code. The deployed Linux build is the full fork pin, which carries the fix; the Mac dev build and stock packages do not.

In X-engine-01's Proposed text, replace "so a hung check can pass" with:
> so a check that overruns its timeout and then exits with `expect_exit` is judged passed.

11 X-engine-02: replace the Proposed text with:
> # final verdict. Fail-closed is kept: a pre_action that never ran (dry-run
> # `-n`, missing executable) or was killed by its exec_timeout leaves
> # `interlock_ok_*` undefined and the bundle blocked. One that overran its
> # timeout but then exited with expect_exit is refused only on a build
> # carrying the fork's exec_timeout fix (6e522a730); stock CFEngine judges
> # it on that exit status.

11 X-engine-03: replace the Proposed text with:
> None of the original batch merged. Since then the one-small-PR channel the maintainers asked for has worked: four simulate fixes merged between 2026-09-02 and 2026-11-12 (#6332, #6389, #6412, #6424), with maintainer backports to the 3.27.x and 3.24.x lines (#6338/#6339 and #6499/#6500), and a maintainer has extended `--simulate=diff` to report ownership, permission and symlink changes (#6436, #6438, #6439). `--simulate-json` itself has not been resent.

## Answers to the brief's (a)-(g)

(a) Confirmed. The launchd adapter drops `env` (the template has no such key), never reloads (no classes on the files promise, no unload or bootout on change), and cannot see a failed `load` (launchctl(1): "zero is always returned"). No CI job runs it, and no run.sh check renders a plist. On a Mac dev run, check 2 exercises only the launchd interlock gate (a negative).

(b) Confirmed. The schema requires `ed25519:`; cf-key uses `RSA_generate_key_ex` and core has no ed25519 code. The design intends a tendcf device key that does not exist yet, not CFEngine's key.

(c) Confirmed, with framing. `restrict-eval` and `pure-eval` default to false and IFD defaults to true. It runs on the authoring machine, not on a device, and "untrusted" rests on G6 (AI-authored input).

(d) Weakened. The fork commit, its absence from overlay/ and the missing test are all confirmed. But stock fails closed when it kills a check: fail-open needs a normal exit with `expect_exit` after the alarm. The deployed Linux pin carries the fix.

(e) Confirmed: #6332 (Sep 2), #6389 (Oct 13), #6412 (Oct 20), #6424 (Nov 12).

(f) Confirmed: Homebrew 3.29.0 (bottled; Apple Silicon and Linux only), Termux 3.28.0 rev 2, absent from nixpkgs.

(g) The "about 60%" rests on these points I could not confirm:
1. That every load-bearing patch (B-5b, B-14, B-23, the timeout) can be made unreachable from outside the engine. This was not prototyped, and `git cherry` shows none of the 68 is upstream, so stock 3.29 still has those bugs.
2. That stock 3.29.0 and 3.28.0 pass `tests/policy/run.sh` (the proposed spike, not run).
3. The F3 severity, which is narrower than stated.
4. Every † claim about alternatives (Salt, ansible, chezmoi, OpenVox, mgmt platforms, pyinfra on Termux or launchd).
5. Termux CFEngine's behaviour on a phone.
6. libntech drift (local ref stale since 2026-08-20).
7. The adopter-cost argument, which is reasoning, not measurement.

The report also does not weigh the 2026-10-29 operator ruling that Linux runs the full fork build (`upstream-overlay.md:50-55`). Dropping the fork reverses that ruling.

## Not checked

1. 05 items below `blocks-goal` that I did not trace: C-compiler-09, C-schema-05, C-bin-02..04, C-tests-04, C-ci-02, C-android-04, C-android-05, C-macos-01, C-g4-02..04, and the code-share line counts in summary (b).
2. 11: X-engine-09 and X-engine-10 (questions for a ruling), §5 alternatives, the 3.28.0 release date, and whether #6499/#6500 carry all four fixes.
3. Whether launchd loads `.cf-before-edit` files; the launchd PATH (C-macos-03); Nix's macOS sandbox default.
4. Whether `@(argv_$(canon))` parses as an `arglist` (needs a real cf-promises run).
5. No behaviour was demonstrated by execution: the C-compiler-04 crash, C-tests-02 and F3 all rest on reading.
6. stayturgid policy bodies, the ShizukuTendCF `TrustedSigners` body, PR #41, and live devices.

Last search run: exempt: verification of a given set of reports; the external facts were fetched live this session (cfengine/core PR lists with `maxAge: 0`, Homebrew API, Termux recipe, repology, NixOS search, CFEngine and Nix docs), and those fetches serve as the closing check.

