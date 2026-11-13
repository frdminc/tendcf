# G7 review: the engine, the fork, and the alternatives

Targets: `docs/architecture/upstream-overlay.md`, `docs/architecture/architecture-DEFINITIVE-v3.md`, `docs/paper/tendcf-architecture-guide.md` (§7, §19), `policy/tendcf_services.cf` and `tests/policy/run.sh`; CFEngine and the cfengine-core fork as instruments (G7).

Base commit: eefea3c

How this was produced: one reviewing agent (Claude Opus), then an independent checking agent that tried to refute each finding; nothing was built or executed, so every defect is established by reading the code.

Items by Weight after corrections: blocks-goal 2, misleads 4, improves 4 (10 items).

Reviewer: Opus 5.5 (read-only slice p2-engine), 2026-11-13. Base `eefea3c`.
Scope: CFEngine and the CFEngine fork as instruments (G7), costed against G1–G5.
The Site Model and the compiler are touched only where the engine choice moves them.

Sources consulted: shared firecrawl (scrape) on github.com/cfengine/core
(PR search, tags), cfengine.com/supported-versions, formulae.brew.sh, repology,
termux-packages build.sh, search.nixos.org, puppet.com blog, numtide/system-manager,
nix-community/nix-on-droid, nix-darwin, purpleidea/mgmt, Normation/rudder-*,
docs.pyinfra.com. Firecrawl search returned mostly irrelevant hits; direct
scrapes worked, so not `blocked-firecrawl`. Local: the cfengine-core fork checkout and a libntech integration worktree
(read-only `git log`/`cherry`/`merge-base`; no fetch).

## 1. What tendcf uses CFEngine for today

From `policy/tendcf_services.cf` (424 lines at `eefea3c`, not ~470):

1. Promise types: `vars`, `classes`, `files` (mustache `edit_template` into
   launchd plists and systemd units, delete), `commands` (`launchctl`,
   `systemctl`, interlock pre_actions under `exec_timeout`), `reports`. Nothing
   else: no `packages`, `processes`, `services`, `users`, `methods`, `edit_line`.
2. Functions: `getindices`, `canonify`, `join`, `mergedata`, `strcmp`,
   `returnszero`. Two bundles sequenced for the class-ordering reason in the
   header (`tendcf_services.cf:26-37`).
3. Data path: the CMDB loader reading `$(sys.workdir)/data/host_specific.json`
   into `data:variables.*` (`tendcf_services.cf:3-10`). That file is projector
   output; the projector and validator are tendcf's Python (`D45`).
4. Daemons: `cf-agent` (and `cf-promises`); root `cf-execd` on the Linux root
   install (CLAUDE.md, `tests/deploy/linux-install.sh`). The guide's per-device
   `cf-serverd` (`tendcf-architecture-guide.md` §5, line 330) is design, not
   shipped.
5. Simulate: not called by shipped code. `--simulate-json` is wanted by the
   consent path (guide §7, line 584-592); its caller is open (map D45).

So the engine does four things for tendcf: parse a fixed generic bundle,
load a JSON document, render two templates, and run a dozen commands in a
safe order. The product's value (goal file, schema, projector, validator,
consent diff, handshake) sits outside it.

## 2. What the fork carries, and whether the goal needs it

Fork pin `overlay/fork.json`: core `b8abf2840` on `tendcf-integration`
(merge of upstream master `b0f6da2dd`, 2026-10-28). Measured (independently
checked 2026-11-13: confirmed):

| | core | libntech |
|---|---|---|
| non-merge commits not upstream | 68 (`git log upstream/master..b8abf2840`) | 12 (`origin/master..d379dce`; local upstream ref dated 2026-08-20, stale) |
| diff vs merge-base | 65 files, +4540/−269 | 8 files, +1379/−96 |
| patch-id equivalent upstream (`git cherry`) | 0 of 68 | not checked |
| upstream master ahead of the fork's last merge | 67 commits (to `270e6c36f`, 2026-11-12) | not checked |

Groups, with my classification (N = needed for the goal as currently
designed; P = needed only for a proof or test; S = a fix stock users live
without; O = avoidable by doing the work outside the engine):

| Group | Commits (examples) | Class | Note |
|---|---|---|---|
| CMDB loader: one bad entry drops its section (B-5b) + naming the bad entry | `8f0076b81`, `958d13949` | N today, O | `tendcf-validate` rejecting the bad entry before cf-agent reads the file makes the bug unreachable. In overlay. |
| JSON null crash in host_specific.json / def.json | `87490bb8f`, `dd917f09d` | O | Validator can forbid `null`. Not in overlay. |
| JSON numbers (exponent form, > long, reals to 2 dp, `eval`) | `2c8c6d4c7`, `c35bb0474`, `13fff92dc`, `b74e8f4cf`, libntech `f9d461d`, `59d7c03`, `796ca0b`, `eda43f0` | O / S | Schema can confine numbers to safe integers or strings. |
| JSON string codec: backslash decoded twice (B-14), `\uXXXX`, raw UTF-8 | libntech `3c9e457`, `90cf8cc`, `1a3b12f`; core `fba51cbbb` | N today, O | Load-bearing in overlay. Avoidable if strings with `\` never reach CFEngine (systemd argv already forbids `\`, `tendcf_services.cf:53-57`). |
| Mustache: log-truncation format bug and OOB pointer (B-23) + 17 unit tests | libntech `2f584b0`, `1b16ae8` | N today, O | Load-bearing in overlay. Avoidable by rendering units in the projector and having CFEngine only place bytes. |
| Dotted CMDB keys warning | `ee1f9d60c` | S | |
| `exec_timeout` / process-group / poll-loop series (~19 commits) | `6e522a730`, `8f4ebedbd`, `cb2561584`, `ab98a5df4`, `e7fd46c6d`, `453cc264d`, `a14792d42`, ... | **N, and missing from the overlay** | See finding F3. |
| `--simulate-json`, `--simulate-keep-chroot`, simulate package fixes | `94d325e88`/`d5cc2c4e0`, `1b0fb89db`, `e00b8990b`, `19f1ff672`, `f6c06f9e2`, `d5052b786`, `6eb70adaf`, `c5e6a37fb`, `e383c7665`, `2cf0b678d` | P (consent confirmation, guide §7) | Package fixes overlap four that upstream has merged under other ids. `--simulate-json` is a confirmation, not the diff itself (guide §7). |
| macOS process table (`process_darwin.c`) | `68ac0d6f5` | S | Only matters to `processes:` promises, which tendcf does not use. |
| Default route lowest metric | `684043972` | S | |
| getopt short-option strings (12) | `cf69e4bc8` ... `da579e648` | S | |
| Format-gate and test-expectation commits (~9) | `e6cab364d`, `9d7d9848f`, ... | P | |
| libntech digest init failure | `8023f45` | S | |

**F3 (the important one).** The interlock bundle claims "Fail-closed is kept:
a pre_action that never ran (dry-run `-n`, missing executable, timeout)
leaves `interlock_ok_*` undefined" (`tendcf_services.cf:35-37`). Fork commit
`6e522a730` says stock CFEngine judges a timed-out `commands:` promise only
on the child's wait status: "the shell is signalled, its own child keeps
running, the shell reaps it and exits 0, and that 0 is what the promise was
judged on ... a policy keying a later promise off if_ok ... treats 'the check
never finished' as 'the check succeeded'". tendcf's interlock body uses
`useshell => "true"` and classifies by `kept_returncodes => {expect_exit}`
(`tendcf_services.cf:370-374, 416-424`). On stock CFEngine a check that is
killed by the timeout fails closed: `cf_pwait` returns −1 for a signalled
child, which is a failed promise. It passes only if the process CFEngine
reaps exits normally with `expect_exit` after the alarm. That covers a check
that turns SIGINT or SIGTERM into that code, a shell whose child finishes
inside the SIGINT→SIGTERM→SIGKILL ladder, and a check that closed its output
before the alarm (nothing is signalled) and later finishes with that code.
The deployed Linux build is the full fork pin, which carries the fix; the
Mac dev build and stock packages do not. `overlay/overlay.json` lists only B-5b, B-14 and B-23 as
load-bearing, so "upstream plus the overlay" does not reproduce the property
the policy claims. `tests/policy/run.sh` checks 1-6 test no timed-out
pre_action (`run.sh:6-45`). Checked: inferred from the commit message and
policy text; not run on any build; independently checked 2026-11-13: weakened, corrected
(stock `cf_pwait`, pre-fix `pipes_unix.c:801-809`, and `GracefulTerminate`
read; latent: the deployed Linux build is the fork pin `b8abf2840`, which
contains `6e522a730`, under the 2026-10-29 ruling, and the only deployed
pre_action is `/usr/bin/true`).

**F3b.** The Mac dev build AGENTS.md names reports
`CFEngine Core 3.29.0a.086d27749`; `086d27749` is a simulate-fix branch
commit (authored 2026-09-30, committed 2026-10-15) that does **not** contain `6e522a730` (timeout) or
`8f0076b81` (CMDB) (`git merge-base --is-ancestor`, both "no"). Homebrew's
stock `cf-agent` 3.29.0 is also installed at `/opt/homebrew/bin`. macOS comes
first in G5, but the fork-revision rule (`upstream-overlay.md:55`, "Every
Linux result must name the fork revision it ran") covers Linux only.

## 3. Upstream today

Independently checked 2026-11-13: confirmed in part (merged PRs and package
versions re-fetched; the tags page was not).

1. Releases: 3.29.0 tagged 2026-11-06 (non-LTS); 3.27.3 and 3.24.6 tagged
   2026-10-22 (LTS lines); 3.28.0 exists (tag seen by `git ls-remote`; date
   not checked). Sources: <https://github.com/cfengine/core/tags> (fetched
   2026-11-13). Schedule: "LTS releases are scheduled every 18 months and are
   supported and maintained for 3 years ... non-LTS releases which are
   scheduled every 6 months"; timeline image shows 3.27 LTS 2026-2028
   (<https://cfengine.com/supported-versions/>, undated page, fetched
   2026-11-13). Commercial support is for Enterprise LTS only (same page).
2. Machine-readable simulate: not landed, not in review. The PR search
   `is:pr simulate` shows 0 open, 39 closed; `--simulate-json` #6294 and
   `--simulate-keep-chroot` #6293 "closed Aug 19, 2026"
   (<https://github.com/cfengine/core/pulls?q=is%3Apr+simulate>, fetched
   2026-11-13).
3. But upstream has since **merged four of this project's simulate fixes**:
   #6332 (2026-09-02), #6389 (2026-10-13), #6412 (2026-10-20), #6424
   (2026-11-12), with maintainer backports to 3.27.x/3.24.x (#6338/#6339,
   2026-09-03, of #6332; and #6499/#6500, merged 2026-11-13, whose contents
   were not checked); and a maintainer has himself fixed `--simulate=diff` to
   report permission/ownership changes and symlink targets (#6436, #6438,
   #6439, backports #6443/#6444, 2026-10-26 to 2026-11-05) (same URL). Local
   `git log upstream/master` agrees (`ab0408f1f`, `eb6cf5f04`, `a5a6b6b6a`,
   `5ddb6d97b`).
4. Liveness: 226 non-merge commits on upstream master since 2026-08-01
   (local ref to 2026-11-12); signed tags from four Northern.tech staff.
   Alive and responsive to small, focused PRs, which is the channel the
   maintainers asked for on 2026-08-19 (history digest §E).

Packaging (all fetched 2026-11-13):

| Where | Version | State |
|---|---|---|
| Homebrew | 3.29.0, bottles arm64 tahoe/sequoia + Linux, `autobump: true`, 182 installs/yr | maintained (<https://formulae.brew.sh/api/formula/cfengine.json>) |
| Termux | 3.28.0 rev 2, maintainer `@termux`, "Contributor: @craigcomstock" (a CFEngine tag signer) | maintained (<https://raw.githubusercontent.com/termux/termux-packages/master/packages/cfengine/build.sh>) |
| MacPorts | 3.18.0, `nomaintainer@macports.org`, flagged potentially vulnerable | abandoned (<https://repology.org/project/cfengine/versions>) |
| nixpkgs unstable | none; only two Emacs packages match | absent (<https://search.nixos.org/packages?channel=unstable&query=cfengine>) |
| Debian sid / Ubuntu 26.04 / FreeBSD | 3.27.3 / 3.24.2 / 3.29.0 | maintained (repology, above) |

Stock CFEngine is therefore one command away on every G5 platform except a
Nix-only setup. The fork is on none of them.

## 4. What the fork costs

To an adopter (G1, G8.3):

1. Build from source on every device class: autotools, OpenSSL, LMDB, PCRE2,
   librsync, libyaml, libxml2 (dependency list from the Homebrew and Termux
   recipes above). On macOS no bottle; on Android a termux-packages
   cross-build (NDK, `-landroid-glob`, the recipe's own patches) or an
   on-device build. No adopter "installs it from the public docs with their
   own AI" (G8.3) without that.
2. Root trust: a one-maintainer fork of a C daemon that runs as root, 4.5k
   lines over upstream, most patches AI-drafted (guide §19 "Who wrote the
   fixes"), no third-party review since upstream closed the PRs. An adopter
   cannot lean on Northern.tech's security process for the fork.
3. Security updates: every upstream fix arrives only when the fork merges
   upstream. The pin is a master snapshot of 2026-10-28, not a release, and
   upstream has moved 67 commits and cut 3.29.0 since.

To the project:

1. A merge of upstream into `tendcf-integration` per upstream move, CI on
   four Linux targets (`linux.yml`), and the weekly drift job
   (`upstream-overlay.md` §5). Libntech's local upstream ref is three months
   stale, so its drift is unmeasured here.
2. Packaging it for macOS and Termux, which nobody has done.
3. Opportunity cost, which guide §19 already names ("Time spent here is time
   not spent building").

## 5. Alternatives against G1–G5

Legend: **Free** = what it gives; **Build** = what tendcf still builds;
**Android** = without root; **Diff** = dry-run change set as data. Claims
marked † are from my prior knowledge, not fetched today.

1. **Stock CFEngine, missing pieces outside it.** Free: convergence, all G5
   packages (§3), no control node. Build: render units in the projector;
   validator forbids what trips B-5b/B-14/null; run each interlock check
   under tendcf's own timeout wrapper that exits non-`expect_exit` on
   timeout; compute the consent diff from goal file plus probes, and use
   upstream `--simulate=diff` (prose, now improving upstream) only to
   confirm. Android: the Termux package runs as the Termux UID, so it manages
   Termux userland only; Android settings need the Shizuku-class helper
   whatever the engine. Diff: tendcf's own. Licence GPL-3.0 (Homebrew lists
   BSD-3 AND GPL-2+ AND GPL-3 AND LGPL-2+). Lock-in: one 424-line bundle.
2. **Nix-native appliers.** nix-darwin "Nix modules for darwin,
   `/etc/nixos/configuration.nix` for macOS", applied with `sudo darwin-rebuild
   switch` (<https://github.com/nix-darwin/nix-darwin>, fetched 2026-11-13).
   system-manager: "currently supported on NixOS, Ubuntu, and Debian", needs
   Nix ≥ 2.32, builds on NixOS modules
   (<https://github.com/numtide/system-manager>, fetched). nix-on-droid: "does
   not require root ... relies on `proot`", "prototype-grade quality",
   aarch64 only, MIT (<https://github.com/nix-community/nix-on-droid>,
   fetched). Free: G2 exactly (real Nix, NixOS options carry over),
   generations and rollback. Build: interlocks, see-and-refuse, peer
   handshake, and all Android control (proot cannot reach Android settings).
   Diff: closure diff (`nix store diff-closures`†), not an owner-readable
   change set. Conflicts with map R4 "No nix-on-droid" and R5 "No bare-metal
   Nix" (`architecture-DEFINITIVE-v3.md:113-117`). Lock-in: Nix and its store
   on every device.
3. **mgmt.** Go, GPL-3.0, real-time, can "run as a decentralized cluster of
   agents" with etcd; "used in production with a growing number of both
   corporate and individual users" (<https://github.com/purpleidea/mgmt>,
   fetched). macOS/Android support: not checked. Lock-in: `mcl` language, a
   small project led by one author†.
4. **pyinfra.** `@local` executes "on the local machine via subprocess";
   "Pass `--json` ... `--dry` runs ... Show a deploy's proposed changes as JSON
   without touching the host"
   (<https://docs.pyinfra.com/en/3.x/cli.html>, fetched). This is the nearest
   off-the-shelf thing to `--simulate-json`. Not a convergence daemon (run by
   launchd/cron); licence MIT†; Termux: plausible (pure Python†), not checked;
   launchd operations: not checked.
5. **ansible-pull.** Check mode + `--diff`†, JSON via callback†; GPL-3.0†;
   heavy Python dependency set; pull from git means a git remote, not a peer
   handshake. Termux: not checked.
6. **Masterless Salt.** `salt-call --local state.apply test=True`†; Apache-2.0†;
   corporate owner changes since 2023† (not checked today); no Android story.
7. **`puppet apply` / OpenVox.** Perforce: "In early 2025, Puppet will begin
   to ship any new binaries and packages ... to a private, hardened, and
   controlled location", source stays Apache-2.0
   (<https://www.puppet.com/blog/open-source-puppet-updates-2025>, 2024-11-07,
   fetched). OpenVox "is a community-maintained implementation of Puppet",
   OpenVox 9 docs dated 2026-10-03 (snippet only,
   <https://docs.openvoxproject.org/openvox/latest/>). `--noop`† with JSON/YAML
   reports†; Ruby runtime; no Android story.
8. **Rudder agent.** "a package bundling CFEngine Community"; verdict "It
   cannot manage the Mac, cannot manage Android"
   (`docs/architecture/rudder-as-umbrella-evaluation-2026-08-13.md:22-24,
   206-208`, archival). Agent tooling GPL-3.0
   (<https://github.com/Normation/rudder-agent>, fetched). Same engine, plus a
   server: no gain for G3/G5.
9. **chezmoi-class tools.** User-scope files only, `chezmoi diff`†; good fit
   for Termux home and dotfiles, no services or system state.
10. **A purpose-built small applier reading the goal file.** Free: nothing.
    Build: idempotent actions for the two supervisor adapters, file
    placement, interlocks, reporting; but the plan (typed operations with
    before/after digests) is the consent diff by construction, so G4's
    "exact, mechanically checked difference" is the applier's own output,
    not a reconstruction of another engine's. Android: D45's Kotlin agent is
    already this shape; on macOS/Linux, `tendcf-validate` is already Python
    (D45). Licence: the project's. Lock-in: none outside; all maintenance
    inside, including the ordering and fail-closed subtleties CFEngine
    taught the project (`tendcf_services.cf:26-37`).

## 6. Two engines, one goal file

For "strength": the goal file is already the contract (schema, projector,
golden bytes, R22), so two consumers prove it is engine-neutral; CFEngine on
desktops brings decades of convergence semantics for free; Android cannot run
CFEngine against Android itself anyway, so a native agent there is forced, not
chosen; diversity means one engine's bug is not a fleet-wide bug.

For "the goal file plus a small applier is the product": tendcf uses five
promise types and one data loader (§1); the Android agent must already
implement "read goal, decide, act, report" natively; every safety property
the owner sees (G4) has to be stated in goal-file terms, and today the
desktop side's properties hinge on engine internals the project had to fix
(F3, narrower than first stated: see §2); the fork is the largest cost on the adopter path (§4); two engines
means two conformance suites, and the desktop one depends on a fork nobody
else ships.

My reading: the second argument is stronger for G1/G4/G8.3, the first is
stronger for G8.1 (time to a converging Mac). They do not conflict if the
applier contract is written down and CFEngine is held to it as one
implementation.

## 7. Recommendation

An option that has not been tested, not a settled recommendation:

**Keep CFEngine on macOS and Linux for now, drive the fork to zero for the
adopter path, and write the applier contract so the engine is replaceable.**
Concretely: stock packaged CFEngine (Homebrew 3.29, Termux 3.28, distro
3.27/3.24) as the supported build; the three load-bearing bugs plus the
timeout-overrun case (a check that overruns its timeout and then exits with
`expect_exit`) made unreachable from outside (projector renders bytes,
validator forbids trigger inputs, tendcf's own timeout wrapper); the consent
diff produced by tendcf from the goal file, with `--simulate=diff` as a
confirmation; `--simulate-json` resent upstream as one small PR only if the
operator wants it. The fork stays a research branch, not a dependency.

It rests on these points, which the independent check (2026-11-13) could not
confirm:

1. That every load-bearing patch (B-5b, B-14, B-23, the timeout) can be made
   unreachable from outside the engine. This was not prototyped, and
   `git cherry` shows none of the fork's 68 commits is upstream, so stock
   3.29 still has those bugs.
2. That stock 3.29.0 and 3.28.0 pass `tests/policy/run.sh` (the spike below,
   not run).
3. The F3 severity, which is narrower than first stated (§2).
4. Every † claim about the alternatives in §5 (Salt, ansible, chezmoi,
   OpenVox, mgmt, pyinfra on Termux or launchd).
5. Termux CFEngine's behaviour on a phone.
6. libntech drift (the local upstream ref is stale since 2026-08-20).
7. The adopter-cost argument (§4), which is reasoning, not measurement.

It also runs against the owner's 2026-10-29 ruling that Linux runs the full
fork build (`docs/architecture/upstream-overlay.md:50-55`); dropping the fork
reverses that ruling. Every engine-changing item below (X-engine-01,
X-engine-08, X-engine-09, X-engine-10) therefore needs the operator's ruling
first.

Confidence: medium, about 60%, as the reviewer's judgment; untested.

What would change it:

1. The spike below shows stock 3.29/3.28 fails policy checks that cannot be
   closed outside the engine: keep the fork, and budget packaging it.
2. The Android agent (D45) turns out to implement most of the generic
   bundle's semantics anyway: then one small applier on every platform is
   cheaper than two engines, and CFEngine should go.
3. Upstream merges `--simulate-json` or an equivalent: the fork's main
   feature reason disappears.
4. The operator lifts R4/R5: nix-darwin becomes the strongest macOS server
   applier for G2's first adopters, with tendcf's consent layer over it.

Cheapest test (2-3 days, CI or `bg`, not run here): run `tests/policy/run.sh`
unchanged against stock Homebrew 3.29.0 on the Mac (`--bindir
/opt/homebrew/bin`) and Termux 3.28.0 on one phone, plus one new check (a
pre_action that sleeps past its timeout must refuse); record each failure and
prototype its outside-the-engine fix. Optional second spike (3-5 days): a
~500-line Python applier for the same fixtures with `plan --json` / `apply
--plan`, compared on lines, checks passed, and whether its plan is the
byte-exact consent diff.

## 8. Response items

### X-engine-01: overlay omits the timeout fix the interlocks rely on

**Target:** `docs/architecture/upstream-overlay.md` §2 "What may go in it",
at the sentence beginning "Not in the overlay, by that rule"
**Kind:** correct
**Goal:** G4, G7
**Weight:** blocks-goal
**Finding:** The overlay claims to hold every patch "load-bearing for code
this repository has shipped", but the interlock bundle's fail-closed claim on
timeout depends on fork commit `6e522a730` (and its stack), which is not in
`overlay/overlay.json`. A build of upstream plus the overlay judges a check
that overruns its timeout and then exits normally with `expect_exit` as
passed; a check killed by the timeout fails closed on stock too (§2, F3). Either the overlay
grows, or the timeout moves outside the engine (X-engine-08).
**Evidence:** `policy/tendcf_services.cf:35-37, 370-374, 416-424`;
`git log -1 6e522a730` in the cfengine-core fork checkout; stock `cf_pwait`
(pre-fix `pipes_unix.c:801-809`);
`overlay/overlay.json` lists B-5a/B-5b, B-13/B-14, B-22/B-23 only.
**Proposed text:**

> The `exec_timeout` series on the fork (`6e522a730` and the commits it is
> stacked on) is load-bearing for `tendcf_interlocks`: without it a timed-out
> pre_action is judged on its shell's exit status, so a check that overruns
> its timeout and then exits with `expect_exit` is judged passed.
> It belongs in the overlay until the timeout is enforced outside the engine.

**Merge:** needs the operator's ruling first (grow the overlay, or move the
timeout outside CFEngine)
**Checked:** inferred (commit message and policy text read; no build run); independently checked 2026-11-13: weakened, corrected (latent: the deployed Linux build is the full fork pin `b8abf2840`, which contains `6e522a730`; the Mac dev build and stock lack it; the only deployed pre_action is `/usr/bin/true`); "not in the overlay": confirmed

### X-engine-02: the fail-closed claim holds only on the fork build

**Target:** `policy/tendcf_services.cf` header, at the comment beginning
"Fail-closed is kept: a pre_action that never ran"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** The comment lists "timeout" among the cases that leave
`interlock_ok_*` undefined. That is fully true only with the fork's timeout
fix; on stock CFEngine a check killed by its timeout fails closed, but one
that overruns its timeout and then exits normally with `expect_exit` is
judged on that exit status. The comment should say which build it was verified on. Pairs with X-engine-01
and X-engine-05.
**Evidence:** as X-engine-01.
**Proposed text:**

> # final verdict. Fail-closed is kept: a pre_action that never ran (dry-run
> # `-n`, missing executable) or was killed by its exec_timeout leaves
> # `interlock_ok_*` undefined and the bundle blocked. One that overran its
> # timeout but then exited with expect_exit is refused only on a build
> # carrying the fork's exec_timeout fix (6e522a730); stock CFEngine judges
> # it on that exit status.

**Merge:** replace that sentence
**Checked:** inferred; independently checked 2026-11-13: weakened, corrected (latent)

### X-engine-03: guide §19 says nothing has merged; four fixes have

**Target:** `docs/paper/tendcf-architecture-guide.md` §19 "What it costs us",
at the sentence "Nothing has merged."
**Kind:** correct
**Goal:** G7
**Weight:** misleads
**Finding:** Since 2026-09-02 upstream has merged four of this project's
simulate fixes, with maintainer backports to the 3.27.x and 3.24.x lines
(#6338/#6339 and #6499/#6500), and a maintainer has
extended `--simulate=diff` himself. The channel the maintainers asked for
works. The section reads as if it does not.
**Evidence:** <https://github.com/cfengine/core/pulls?q=is%3Apr+simulate>
(fetched 2026-11-13): #6332, #6389, #6412, #6424 merged; #6338/#6339
backports of #6332 merged 2026-09-03; #6499/#6500 backports merged
2026-11-13; #6436-#6444 by a maintainer.
**Proposed text:**

> None of the original batch merged. Since then the one-small-PR channel the
> maintainers asked for has worked: four simulate fixes merged between
> 2026-09-02 and 2026-11-12 (#6332, #6389, #6412, #6424), with maintainer
> backports to the 3.27.x and 3.24.x lines (#6338/#6339 and #6499/#6500), and
> a maintainer has extended `--simulate=diff` to report ownership, permission
> and symlink changes (#6436, #6438, #6439). `--simulate-json` itself has not
> been resent.

**Merge:** replace that sentence
**Checked:** verified (PR list fetched; `git log upstream/master` locally); independently checked 2026-11-13: weakened, corrected (the count and the backport claim; which fixes #6499/#6500 carry was not checked)

### X-engine-04: guide §7 simulate paragraph predates upstream's diff work

**Target:** `docs/paper/tendcf-architecture-guide.md` §7, at the sentence
beginning "Both are offered and neither has merged"
**Kind:** reword
**Goal:** G4
**Weight:** improves
**Finding:** "Offered" is stale: both PRs were closed on 2026-08-19 and not
resent. Meanwhile stock `--simulate=diff` now reports more (ownership,
permissions, symlinks) in 3.27.x/3.24.x backports, which matters if the
confirmation is done against stock CFEngine.
**Evidence:** PR list URL above; #6293, #6294 "closed Aug 19, 2026".
**Proposed text:**

> Both were offered upstream and closed on 2026-08-19 with the rest of that
> batch; neither has been resent. Stock `--simulate=diff` has since gained
> ownership, permission and symlink reporting upstream, so today this
> remains a manual check, against prose output.

**Merge:** replace that sentence
**Checked:** verified (fetched); independently checked 2026-11-13: confirmed

### X-engine-05: no test covers a timed-out interlock check

**Target:** `tests/policy/run.sh` header, after the paragraph beginning
"3. interlock satisfied, enforce mode"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** Checks 1-6 never exercise a pre_action that exceeds
`timeout_seconds`, so the fail-closed-on-timeout claim is untested on any
build, fork or stock. This is the test the spike in §7 needs.
**Evidence:** `tests/policy/run.sh:6-45`.
**Proposed text:**

> #   3b. interlock timed out, enforce mode: a pre_action that sleeps past
> #      its timeout_seconds and whose shell would exit with expect_exit.
> #      Every service tagged with its bundle must be refused. Run against
> #      both the fork and a stock build; the result names the build.

**Merge:** insert after it (and add the check)
**Checked:** verified (read run.sh); the check itself not written or run; independently checked 2026-11-13: confirmed

### X-engine-06: say what an adopter must build, next to what stock ships

**Target:** `docs/paper/tendcf-architecture-guide.md` §19 "What it costs us",
after the bullet beginning "This project currently depends on a fork."
**Kind:** add
**Goal:** G1, G5, G8
**Weight:** misleads
**Finding:** The section costs the fork to the project but not to an
adopter. Stock CFEngine ships on Homebrew (3.29.0, bottled), Termux (3.28.0)
and distros; the fork ships nowhere, so every adopter would build a root C
daemon from source on macOS and cross-build it for Termux. MacPorts is
abandoned at 3.18 and nixpkgs has no package.
**Evidence:** §3 table URLs (fetched 2026-11-13).
**Proposed text:**

> - **An adopter pays more than we do.** Stock CFEngine installs in one
>   command from Homebrew, Termux and the major distributions; our fork is
>   packaged nowhere. Shipping the fork would ask every adopter to build a
>   root-running C daemon from a one-maintainer branch, on macOS and again
>   through the Termux toolchain.

**Merge:** insert after it
**Checked:** verified (package pages fetched); independently checked 2026-11-13: confirmed

### X-engine-07: name the macOS build in every macOS result

**Target:** `docs/architecture/upstream-overlay.md` §2, at the sentence
"Every Linux result must name the fork revision it ran."
**Kind:** add
**Goal:** G5
**Weight:** misleads
**Finding:** macOS is first in G5, but the revision rule covers Linux only.
The Mac dev build named in CLAUDE.md is `3.29.0a.086d27749`, a simulate-fix
branch commit without the CMDB or timeout fixes, so Mac results today come
from neither the pinned fork nor stock.
**Evidence:** `cf-agent --version` of the Mac dev build AGENTS.md names;
`git merge-base --is-ancestor 6e522a730 086d27749` → no; same for
`8f0076b81`.
**Proposed text:**

> Every Linux or macOS result must name the build it ran: the fork revision,
> or "stock" with its version.

**Merge:** replace that sentence
**Checked:** verified (commands run); independently checked 2026-11-13: confirmed (`086d27749` was authored 2026-09-30 and committed 2026-10-15)

### X-engine-08: move rendering and the timeout outside the engine

**Target:** `docs/architecture/upstream-overlay.md` §6 "How a patch
retires", at the sentence beginning "A patch can also retire because the
code it protects stops shipping"
**Kind:** question
**Goal:** G4, G7
**Weight:** improves
**Finding:** Three of the four load-bearing dependencies can be made
unreachable by tendcf's own code: the projector renders unit bytes (retires
B-23, and makes the owner's diff byte-exact rather than data-level); the
validator forbids `null`, backslashes in CFEngine-bound strings and the
entry shapes B-5b drops (retires B-14, B-5b); interlock checks run under a
tendcf wrapper that enforces the timeout and exits non-`expect_exit`
(retires the timeout series). The overlay would then be empty and stock
packages would suffice.
**Evidence:** §2 table; `tendcf_services.cf:273-290` (mustache render).
**Proposed text:**

> The overlay's intended end state is empty: each load-bearing patch retires
> either upstream or by moving the dependency into tendcf's own projector,
> validator or interlock wrapper, so that a packaged stock CFEngine is a
> correct build.

**Merge:** needs the operator's ruling first (engine change: fork-to-zero)
**Checked:** not checked: a design proposal, not prototyped (independently checked 2026-11-13: unverifiable); needs the §7 spike against stock builds, with each outside-the-engine fix prototyped, to show every load-bearing patch can be made unreachable

### X-engine-09: write the applier contract so the engine is one implementation

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §1 diagram
caption, at "each device is its own policy hub."
**Kind:** add
**Goal:** G3, G5, G7
**Weight:** improves
**Finding:** Desktops (CFEngine) and Android (Kotlin agent, D45) already
consume one goal file through two engines, but no document states what an
applier must guarantee (inputs, ordering, fail-closed cases, report rows,
plan output). Without it, engine properties such as F3 live in code
comments. A contract makes CFEngine challengeable under G7 and testable by
one conformance suite.
**Evidence:** `architecture-DEFINITIVE-v3.md:84-90, 1243` (D45).
**Proposed text:**

> Every applier (CFEngine with `tendcf-validate` on Linux and macOS,
> tendcf-agent on Android) implements one written applier contract: what it
> reads, what it may change, which cases refuse, and what it reports. A
> shared conformance suite holds each to it.

**Merge:** needs the operator's ruling first (changes the engine's status)
**Checked:** inferred

### X-engine-10: R4/R5 versus G2's Nix-first adopters

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §2, at "**R5**
No bare-metal Nix."
**Kind:** question
**Goal:** G2, G7
**Weight:** improves
**Finding:** R4 ("No nix-on-droid") and R5 ("No bare-metal Nix") predate G2.
G2 needs Nix only for authoring, so they still fit, but the first adopters
"already share configs in Nix" and will ask why nix-darwin is not the macOS
applier. The documents should say whether R4/R5 stand under G2 and why.
**Evidence:** `architecture-DEFINITIVE-v3.md:113-117`; nix-darwin and
system-manager READMEs (fetched).
**Proposed text:**

> Under G2 (2026-11-13), Nix is the authoring language, not a device
> dependency; R4 and R5 [stand | are reopened] because [operator's reason].

**Merge:** needs the operator's ruling first (R4/R5)
**Checked:** verified (requirements read); ruling not presumed

## Withdrawn after checking

None. The independent check refuted no item in this file.

## Ideas and risks

1. **Risk:** F3 means a device run on stock CFEngine (or on the Mac dev
   build) today could pass an interlock check that overruns its timeout and
   then exits with `expect_exit`; a check killed by the timeout still fails
   closed. Until X-engine-05 exists, do not run the policy on stock
   builds with interlocks enforced.
2. **Idea:** pyinfra's `--dry --json` shows a mainstream tool already ships
   a machine-readable plan; use its JSON shape as prior art for tendcf's own
   plan/diff format rather than designing from CFEngine's simulate output.
3. **Idea:** resend `--simulate-json` upstream as one small PR now that four
   small PRs merged; a maintainer is actively working in the same code.
   Operator's call (standing rule: nothing sent without him).
4. **Risk:** the fork pins a master snapshot, not a release, and is already
   67 commits and one release behind; an adopter-facing build should pin a
   tagged release.
5. **Idea:** ask Homebrew/Termux-style packaging questions before choosing:
   the cheapest adopter path is whatever `brew install` and `pkg install`
   already give.
6. **Risk:** rendering units on-device means the owner approves data, not
   bytes; G4 says "exact". Projector-side rendering closes that gap whatever
   the engine.
7. **Idea:** the generic bundle is 424 lines over five promise types; a
   like-for-like applier is a bounded experiment, not a rewrite of CFEngine.
8. **Risk:** two engines double the conformance work; without the contract
   (X-engine-09) they will drift in refusal semantics.
9. **Risk:** nix-on-droid is "prototype-grade" and proot-based; even if R4 is
   lifted it does not reach Android system state, so it cannot replace the
   Android agent.
10. **Idea:** libntech's local upstream ref is from 2026-08-20; refresh it
   (a fetch, outside this read-only slice) before any decision that depends
   on libntech drift.

## Not checked

1. No build or test run on any CFEngine; F3 is inferred from the fork's
   commit message, not reproduced. The independent check read the stock
   `cf_pwait` code and narrowed F3 (§2); it did not reproduce it either.
2. libntech upstream master after 2026-08-20; whether its fixes landed.
3. 3.28.0 release date; whether `b0f6da2dd` precedes the 3.29.0 tag.
4. Termux runtime behaviour of CFEngine, pyinfra, ansible or chezmoi on a
   phone.
5. Claims marked † (Salt, ansible, chezmoi, OpenVox details, Nix diff
   tools, licences not on a fetched page).
6. mgmt's macOS/Android support.
7. The guide's other sections beyond §5, §7 and §19, and the other
   `cfengine-*` architecture notes beyond their titles.

Last search run: the cfengine/core simulate PR list and tags page, scraped
live (`maxAge: 0`) in this session on 2026-11-13, not re-run after drafting:
0 open simulate PRs, 3.29.0 latest tag, backports #6499/#6500 merged today.
Nothing in them changes the recommendation.
