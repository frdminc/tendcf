# 12 — Fork management (G9) against the 2026-11-13 goal

Base commit: eefea3c

How this was produced: one researching agent (Claude Opus) using web sources, then an independent checking agent that fetched primary sources and tried to refute each claim; no device was touched.

No phone, tablet or other device was touched, by either agent, and no fork was built.

Items by Weight after corrections: blocks-goal 0, misleads 0, improves 7, nit 3 (10 items). None was withdrawn; X-forks-05 was rewritten in place after its premise was refuted (see "Withdrawn after checking").

Reviewer slice: G9 ("free-software branch management ... without knowing about merging, rebasing or compiling"), read against G1 (freedom through an AI) and G4 (checked diff, safety confidence). Base `eefea3c`, read in the review worktree. Read-only; no repo file changed.

Sources consulted: shared `mcp__firecrawl__*` search and scrape. Fetched: Gentoo user patches, NixOS wiki Overlays, Guix transformation options, patch-package README, Jujutsu conflicts doc, wei/pull README, F-Droid reproducible builds, attic README, `nix store sign` manual, GNU GPL FAQ, a foresightmobile Android-verification article, a real Nix dotfiles weekly-update PR, and arXiv PortGPT plus two 2026 merge-conflict papers. Snippet only: Google's Android developer blog posts (the page body did not render), Obtainium, Radicle. `firecrawl_research_search_papers` returned HTTP 404 twice. Core search and scrape worked, so this is not a firecrawl outage. LLM `query` extraction failed on every page (HTTP 400/429) and full markdown came back instead.

## 1. What "the platform's existing patch patterns" are today

| Piece | What it does | Evidence |
|---|---|---|
| `overlay/overlay.json` | Per component: upstream URL, fork URL, pinned `base`. Per patch: `file`, `commit`, `subject`, `register`, `fork_ref`, `upstream_pr` and its state, `role` (load-bearing / carrier), `retire_when`. Some patches add `why`, `load_bearing_for` or `acceptance_test`. | `overlay/overlay.json`; field dump run 2026-11-13 |
| `bin/overlay.py` | `lint`, `status`, `check` (temporary index; the repo is never touched), `retired` (`git patch-id --stable`, RETIRE/VERIFY), `apply` (refuses a wrong base or a dirty tree), `export` (format-patch from a fork branch), `self-test` (13 behaviours on a synthetic upstream). Component names are not hardcoded. | `bin/overlay.py:135`, `:548-575`; `docs/architecture/upstream-overlay.md` §3–§6 |
| weekly `overlay-drift` job | Runs `check` against upstream master and the newest tag, then `retired --strict`. | `upstream-overlay.md` §5 |
| `overlay/fork.json` | Since the 2026-10-29 ruling, Linux runs the **full fork** pinned by commit on `tendcf-integration`. That branch is refreshed by merging, not rebasing. | `upstream-overlay.md` §2 "Ruling, 2026-10-29" |
| change-process rule 5 | "A tool fork is never an input of its own". Binaries enter a release only as digests. | `docs/architecture/change-process.md:121-125` |
| guide/map "fetched content binds bytes" | A fetched artifact's digest is part of the accept and is re-checked before apply. | guide §7 (`tendcf-architecture-guide.md:526-532`); map §9.8 |

Independently checked 2026-11-13: the rule 5 citation is confirmed. Rule 5 is scoped to the project's own tool forks, which the table row at `change-process.md:76` names as `djbclark/core`, `djbclark/libntech` and `frdminc/ShizukuTendCF`; it says a built binary or the Android agent's APK enters a release only as a digest-bound fetched artifact.

The guide's `altsrc` (§13) is about Termux and absolute paths, not patches. It has no bearing on G9.

Two facts shape G9:

1. **The patch-series model already did its job once and then gave way.** The operator carries 23 fixes plus `--simulate-json` as a merged branch pinned by commit, not as overlay patches. G9 therefore has to carry both a patch series and a pinned merged branch. The owner is shown a per-change list in either case.
2. **The project already keeps an Android app fork**, `frdminc/ShizukuTendCF` (`change-process.md:76`). It is the natural first Android G9 case.

## 2. How people keep a personal fork alive today

"Knows" means what the person must understand to keep the fork alive when upstream moves.

| Approach | Person must know | Separates "my change" from "carrying it"? | Source (date) |
|---|---|---|---|
| Long-lived git branch, rebase or merge | git, conflict resolution, building | No. The change *is* commits on a moving branch | background, not fetched |
| `pull` GitHub app | Little. But the default is a **hard reset** to upstream, the README warns "Make a backup if you've made changes", and on a conflict it only labels the PR and assigns a reviewer | No. It syncs and does not carry | https://github.com/wei/pull (README, undated, fetched 2026-11-13) |
| Jujutsu | A VCS. Conflicts are stored in commits, descendants auto-rebase, and resolution can be postponed | Partly. Upkeep never blocks, but the conflict is still the person's to resolve | https://docs.jj-vcs.dev/latest/conflicts/ (undated) |
| quilt, gbp-pq, stgit, git-branchless | Patch-stack tooling | Yes, in form (a series), but expert tools | not fetched; `upstream-overlay.md` §8.4 rejected quilt/stgit/git-series |
| Gentoo `/etc/portage/patches/<cat>/<pkg>[-ver][:slot]/` | Dropping a `.patch` file and re-emerging, which **compiles locally**. Remove the patch once upstream has it or "next time compiling the ebuild might fail". With `userpriv` an unreadable dir means patches are "silently ignored" | Yes. The drop-in dir *is* "the change I want" | https://wiki.gentoo.org/wiki//etc/portage/patches (oldid 1440922; snippet dates it 2026-05-16) |
| Nix overlay `patches = (old.patches or []) ++ [...]`, `fetchpatch` with hash; overriding `src` | The Nix language. The wiki says a src override "will fail if the build system changed or new dependencies are required" | Yes. A declarative list, rebuilt by a builder, substitutable from a cache | https://wiki.nixos.org/wiki/Overlays (oldid 35275) |
| nixpkgs `applyPatches` | Same as above | Yes. It also fails loudly on a stale patch (see §3) | https://github.com/jdguillot/.dotfiles/pull/32 (2026-10-20) |
| Guix `--with-patch=pkg=file`, `--with-source`, `--with-commit`, `--with-latest` | One CLI flag. "Package transformation options are preserved across upgrades". `--with-latest` warns that QA is missing and the result may be non-reproducible | **Yes, best of the distros.** The transformation is recorded in the profile and re-applied on upgrade | https://guix.gnu.org/manual/1.5.0/en/html_node/Package-Transformation-Options.html (Guix 1.5.0) |
| `patch-package` (npm) | Edit `node_modules`, run one command, commit `patches/<pkg>+<ver>.patch`. It is re-applied on install, says "in big red letters when the dependency changed", and `--create-issue` drafts an upstream issue from the diff | Yes. It also has the only built-in path to upstream | https://github.com/ds300/patch-package (README, undated) |
| Homebrew taps / `brew edit`, Arch ABS/PKGBUILD | Formula or PKGBUILD editing, local build | Partly | not fetched |
| F-Droid recipes; Obtainium | F-Droid: a build recipe per app, reproducibility checked by copying the upstream APK signature. Obtainium: installs updates "directly from their release pages", with no build | F-Droid: recipe and build are separate from the source. Obtainium: distribution only | https://f-droid.org/docs/Reproducible_Builds/ (undated); Obtainium snippet only (https://obtainium.imranr.dev/) |
| Renovate; Radicle patches | Renovate bumps pins and does not carry patches (not fetched). Radicle is a local-first forge with patches as repo data | No / partly | Radicle snippet only (https://radicle.xyz/) |

## 3. Which is closest to something a non-technical person could own

Test of the hypothesis "Nix-style declarative patches, rebuilt by a builder, come closest".

**Holds:**

1. A pinned source plus hash, an ordered patch list and a builder separate the *what* (the list) from the *how* (the derivation).
2. A binary cache removes compiling from the device.
3. Guix shows that the transformation can survive upgrades without the person re-stating it.

**Does not hold on its own.** Nix has:

1. no statement of *intent* per patch;
2. no drift warning before the build breaks;
3. no "upstream already has this" detection;
4. no account a non-programmer can read.

`bin/overlay.py` has items 2 and 3 already (`check`, `retired`), so overlay.py plus a Nix-style builder is closer than either alone.

**The upkeep loop already happens in the wild.** In https://github.com/jdguillot/.dotfiles/pull/32 (2026-10-20), a scheduled workflow bumped inputs and `applyPatches` failed. An agent found that upstream had absorbed two of the five patches and deleted them. It checked that the other three still apply and still fix open issues (it cites the issue numbers), rebuilt all 7 hosts, and pushed to attic and cachix. It then wrote a plain account ending "Written by the agent that made the change. Read the diff outside the lock files carefully."

That is G9's loop, run for a sysadmin today. The person still designed the machinery: a workarounds register with "Waiting on" probes and hold rules. The gap G9 has to close is that machinery, not the AI step.

## 4. AI in the loop: what works, what fails

| Work | Result | Source |
|---|---|---|
| PortGPT, LLM agent for backporting with code access, git-history summaries and compiler feedback | 89.15% success on 1,815 prior-dataset cases. 62.33% on 146 complex cases (C, C++, Go). 9 backports contributed to the Linux kernel, all merged (abstract). Exact success definition not checked | https://arxiv.org/html/2510.22396v1 (2025-10-25) |
| LLM solver for real Java merge conflicts with a judge calibrated against human labels | Matches the developer's resolution on about 55% of conflicts (a conservative floor). Its edge over tools comes from coverage: tools abstain on 20–90%. **The LLM judge accepted 4 of 5 structurally invalid resolutions** (n=5; structural check = Java parser plus duplicate-declaration checks): "structural correctness must not be delegated to an LLM" | https://arxiv.org/abs/2607.27674 (2026-07-30) |
| Merge-Bench, 7,938 hunks, 11 languages | "The best models correctly resolve less than 60% of merge conflicts" | https://arxiv.org/abs/2605.25890 (2026-05-25) |
| Also listed, not read | MergirafSemi (2608.11345, 2026-08-24); LLM vs search-based resolution (2605.16646); Rover (2605.17279); CONGRA (2409.14121) | arXiv search listing, fetched 2026-11-13 |

Independently checked 2026-11-13: the PortGPT row weakened, corrected; the 2607.27674 and Merge-Bench rows confirmed.

What follows for the design:

1. **Expect a hard-conflict regeneration to fail or be wrong about 4 times in 10.** So AI regeneration is a proposal. Deterministic gates decide: the patch applies, the build passes, the per-patch acceptance test passes, and upstream's own tests pass. Never an AI judge alone.
2. **Intent must be executable to be preserved.** `overlay.json` already has `acceptance_test` on B-5b. G9's "intent" should be a plain sentence the owner approves *plus* a check the AI writes from it when the patch is created. Then "re-derive from intent" has a pass/fail.
3. **A truthful account for someone who cannot read code** (G4). Per patch, one of four states, in plain words:
   - `carried unchanged`: same patch-id, applied cleanly;
   - `re-made by AI`: show the interdiff of old patch against new, and score it lower;
   - `no longer needed`: upstream carries it, by patch-id RETIRE or a VERIFY that needs reading;
   - `could not carry`: staying on the last good build.

   Add upstream's changelog between the pins, the output digest change, and the G4 safety confidence. The confidence should be computed mostly from the *interdiff*. The new upstream code is upstream's responsibility and should get a separate, coarser score.
4. **G4 has a binary gap.** "Exact, mechanically checked difference" is met by a digest change, but a digest means nothing to an owner. For a fork build, the reviewable difference is the source-level interdiff plus the upstream range. The goal-file hunk is only the digest.

## 5. Building without the user compiling

1. **The Mac server as builder and cache.** attic is a self-hostable Nix binary cache. It is multi-tenant ("a private cache for yourself, and one for friends"), the server signs on fetch so pushers never hold the key, the README says it "works on macOS too", and it calls itself "an early prototype" (https://github.com/zhaofengli/attic, README undated). Plain Nix signs with `nix store sign --key-file` (https://nix.dev/manual/nix/2.35/command-ref/new-cli/nix3-store-sign, Nix 2.35.6). tendcf already requires fetched content to be bound by digest (guide §7). A fork output fits that rule unchanged.
2. **Reproducibility as the check on the builder.** F-Droid rebuilds and verifies by copying the upstream APK signature onto its own unsigned build. That forces byte-identical APKs. NDK builds differ even across macOS and Ubuntu with the same NDK, and `apksigner` from build-tools ≥ 35 makes APKs `apksigcopier` cannot verify (https://f-droid.org/docs/Reproducible_Builds/). For a household the realistic bar is a second builder (CI) reproducing the digest for Nix outputs. For APKs it is best-effort.
3. **Android signing.** A fork must be signed with the household's key. It therefore cannot update an app installed from upstream's signature. Background knowledge, not fetched; p2-android should confirm. The key is identity: losing it strands every installed copy. It belongs in the secret store with an escrow (the project already escrows ShizukuTendCF release signing).
4. **Developer verification.** From 30 September 2026, participating stores (Play, Galaxy Store and OEM stores) install only registered developers' apps on certified devices in Brazil, Indonesia, Singapore and Thailand. It goes global in 2027. ADB and an "advanced flow" with anti-coercion checkpoints remain. "Limited distribution accounts" for a small number of devices launched in August 2026: up to 20 devices per Google's overview page and FAQ (https://developer.android.com/developer-verification/guides/faq), while the limited-distribution guide (https://developer.android.com/developer-verification/guides/limited-distribution, updated 2026-10-28) says 50; plan for 20 until Google reconciles them; the advanced flow has a one-time one-day wait before it can be turned on (all three pages read 2026-11-13; https://foresightmobile.com/blog/android-developer-verification-2026, 2026-09-01, updated 2026-09-28; Google's blogs https://android-developers.googleblog.com/2026/06/android-developer-verification.html and https://android-developers.googleblog.com/2026/03/android-developer-verification-rolling-out-to-all-developers.html are snippet only).

   For G9 a household fork needs one of: a limited-distribution registration of the fork's package name, ADB-class install, or the advanced flow. Whether an install through Shizuku/ShizukuPlus counts as ADB-class under the 2027 rules is **not checked** and is load-bearing for G5's Android differentiator.

## 6. Design sketch

**Claim shape.** A new Site Model kind; illustrative only.

```yaml
forks:
  - id: shizuku-household
    upstream: { url: https://github.com/RikkaApps/Shizuku, follow: releases }
    pin: { rev: <commit>, tree: <tree> }          # as site.lock rule 2
    patches:
      - id: allow-island-profile
        intent: "Shizuku can grant to apps inside an Island work profile."
        file: patches/0001-....patch              # format-patch, as overlay/
        check: tests/island-grant.sh               # executable intent
        made_by: ai | person
        upstream: { url: <issue or PR>, state: open }
        retire_when: "upstream carries it (patch-id) or the check passes without it"
    build: { recipe: nix | gradle, builder_role: builder }   # the Mac server
    sign: { key: secret-name, android_package: <id> }
    install: { hosts: [phone-a], replaces: <package or plugin dir> }
    on_failure: hold                               # stay on last good digest
```

**Upkeep loop.**

1. Upstream moves.
2. `check` runs in a temporary index, then `retired` runs.
3. Patches that drift go to the AI regenerator, which gets the old patch, its intent, the upstream diff in the conflicting region and the check.
4. Gates run: applies, builds, check passes, upstream tests pass.
5. The builder builds, signs and pushes to the cache.
6. The compiler writes a new goal-file digest, which becomes a ChangePlan with the §4 account and safety score.
7. The owner accepts or refuses.

Any failed gate means no ChangePlan is issued. The device stays on the last good digest and the owner sees "held at X, patch P could not be carried, upstream link". Dropping a patch is always the owner's decision, even on RETIRE, because it changes behaviour if upstream's version differs.

**Smallest first version.** No device changes; dogfood on the existing CFEngine overlay:

1. Add `intent` (plain sentence) to every patch in `overlay.json`. Make `lint` require it. Make `acceptance_test` the start of `check`.
2. Make the weekly `overlay-drift` job also write an owner-readable status file (the four states).
3. On DRIFT, an agent opens a PR containing the regenerated patch, the interdiff and the gate results, under the repo's usual frontier review.

**Reuse from `overlay.py`:**

- manifest plus `lint` (provenance discipline);
- `export`;
- `check` (temporary index, never touches a shared checkout);
- `apply` (refuses a wrong base or a dirty tree);
- `retired` (patch-id plus same-subject VERIFY);
- `self-test` (synthetic upstream and fork; extend it with an "AI-regenerated patch must pass its check" case).

**New code needed:** non-git upstreams, build and digest output, a per-patch check runner, the owner report, and a series derived from a pinned merged branch (the `fork.json` case).

## 7. Licence and community

1. **Private use is free.** "The GPL does not require you to release your modified version ... free to make modifications and use them privately". Internal copies within one organisation are not distribution, but "when the organization transfers copies to other organizations or individuals, that is distribution" (https://www.gnu.org/licenses/gpl-faq.html, sections GPLRequireSourcePostedPublic and InternalDistribution; page undated, fetched 2026-11-13).

   Own devices are fine. A build installed on a **friend's** device is distribution and carries source obligations: the upstream pin plus the patch files is the natural corresponding source. Whether a *household* counts as one "organization" is not settled by the FAQ.

   AGPL: a modified network service must offer its source to users (same FAQ, UnreleasedModsAGPL). GPLv3 §6 requires Installation Information only when object code is conveyed "in, or with, or specifically for use in, a User Product" in a transaction that transfers possession of that product (read 2026-11-13); software installed on a phone the household already owns is not that case, but a phone handed over with the software on it is. Permissive licences: keep notices. Each fork needs an SPDX licence read at creation.
2. **Make upstream the easy path:**
   - every patch carries `upstream` (overlay.json already does);
   - the AI drafts a terse issue or PR from the intent and diff, as patch-package's `--create-issue` does;
   - the person sends it, never the AI;
   - `retired` closes the loop automatically when upstream takes it.

   The project's own record cuts the other way: upstream closed all 26 PRs for review volume and two maintainers asked for less verbosity (guide §19 "What it costs us"). Default to one short issue per patch, opt-in, and to the project's own contribution rules.

## Response items

### X-forks-01: guide gets a "Later: forks you can keep" section

**Target:** `docs/paper/tendcf-architecture-guide.md` §18 "What is built, and what is next", after the paragraph beginning "On the first platform brought under management"
**Kind:** add
**Goal:** G9, G1, G4
**Weight:** improves
**Finding:** G9 is new (goal file "Where this differs" item 8) and no document mentions it. The guide is where a reader learns what the design is for. The overlay already contains most of the mechanism, so the section can be short and honest about what exists.
**Evidence:** `00-goal-definition.md:67-70,110`; `upstream-overlay.md` §3–§6; https://github.com/jdguillot/.dotfiles/pull/32 (2026-10-20)
**Proposed text:**

> **Later: forks you can keep.** The patch overlay (§19) is a small instance of something people want generally: a change to someone else's program, or to a plugin of it, that survives the next release. The later aim is that a person says what they want changed. Their AI writes the patch together with a check that proves it. The site pins the upstream and lists the patches, each with its intent. A builder (the Mac server) builds and signs the result. When upstream moves, the same drift and retirement checks the overlay runs today decide what happens to each patch: it is carried unchanged, re-made, dropped because upstream now has it, or held. Anything re-made is re-tested. What reaches a device is a digest, and the person accepts it like any other change. They are shown, in plain words, what each patch now does and what changed since the last build. A fork that cannot be carried stays on its last good build. Nothing here is built beyond the overlay.

**Merge:** insert after it
**Checked:** verified (anchors read at `eefea3c`); independently checked 2026-11-13: confirmed (the jdguillot dotfiles PR was not re-fetched)

### X-forks-02: open question on AI-regenerated patches and the safety gate

**Target:** guide §20 "Open questions", append as the next numbered question after the one beginning "What confirms that a change took effect?"
**Kind:** add
**Goal:** G4, G9
**Weight:** improves
**Finding:** Published results put LLM merge-conflict resolution at about 55–60% matching the developer's resolution (55% a conservative floor), and in one study an LLM judge accepted 4 of the 5 resolutions that failed a deterministic structural check. The guide should say what decides whether a re-made patch ships, and what the owner's "difference" is when the device-side change is only a digest.
**Evidence:** https://arxiv.org/abs/2607.27674 (2026-07-30); https://arxiv.org/abs/2605.25890 (2026-05-25); https://arxiv.org/html/2510.22396v1 (2025-10-25)
**Proposed text:**

> **What may decide that a re-made patch is right?** Published results put AI conflict resolution at about 55 to 60 percent matching the developer's own resolution, and AI backporting of security patches at 62 to 89 percent depending on difficulty. In one study an AI judge accepted 4 of the 5 resolutions that failed a deterministic structural check. The working answer is that only deterministic gates decide: the patch applies, the program builds, the patch's own check passes. The difference the owner reviews is the old patch against the new one, not the binary's digest. Whether that is enough for a person who cannot read code is open.

**Merge:** insert after it (renumber)
**Checked:** verified (sources fetched 2026-11-13); independently checked 2026-11-13: weakened, corrected

### X-forks-03: overlay doc names its G9 role

**Target:** `docs/architecture/upstream-overlay.md` §9 "Open", new bullet at the end
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** G9 says it is to be "built as an extension of the platform's existing patch patterns", and this file is those patterns. It should record that it is the seed and which fields are missing (intent, build, install, output digest, owner report), so nobody re-derives that later.
**Evidence:** `upstream-overlay.md` §3 manifest fields; manifest field dump (no `intent`; `acceptance_test` only on B-5b)
**Proposed text:**

> - **The seed of G9 (goal 2026-11-13).** Per-person forks are to extend this mechanism, not replace it. What carries over unchanged: the manifest with provenance per patch, `export`, `check` in a temporary index, `apply`'s refusal of a wrong base or dirty tree, `retired` by patch-id, and the synthetic self-test. What is missing: a plain-words `intent` and an executable check per patch, a build recipe and output digest, an install target, and an owner-readable status. The first step needs no device: add `intent` here and have `overlay-drift` write the status.

**Merge:** insert after the last bullet
**Checked:** verified (file read at `eefea3c`); independently checked 2026-11-13: confirmed (the label "B-5b" was not checked)

### X-forks-04: require `intent` per patch in the manifest

**Target:** `overlay/overlay.json` (every patch) and `bin/overlay.py` `lint()`
**Kind:** add
**Goal:** G9, G4
**Weight:** improves
**Finding:** The three carriers have `why`, the three load-bearing patches have `load_bearing_for`, one has `acceptance_test`, and none has a uniform statement of what the patch is for. G9's re-derive-from-intent loop needs one plain sentence per patch, linted, and an executable check where one exists.
**Evidence:** field dump of `overlay/overlay.json` run 2026-11-13; `bin/overlay.py:179` (`lint`)
**Proposed text:**

> Each patch entry gains `"intent": "<one plain sentence a non-programmer can approve>"`, and `lint` reports a patch without one. `acceptance_test` becomes `check`: a test path or command, which `self-test` proves fails without the patch and passes with it.

**Merge:** needs the operator's ruling first (manifest shape change)
**Checked:** inferred (lint code not read in full); independently checked 2026-11-13: confirmed (field counts)

### X-forks-05: rule 5 is silent on a person's own fork

**Target:** `docs/architecture/change-process.md` §2, rule 5, at "A tool fork is never an input of its own."
**Kind:** add
**Goal:** G9, G3
**Weight:** improves
**Finding:** Rule 5 covers only the project's own tool forks (the table row at `change-process.md:76`: `djbclark/core`, `djbclark/libntech`, `frdminc/ShizukuTendCF`), and says a fork's built binary or APK enters a release only as a digest-bound fetched artifact. It says nothing about a person's fork, so it does not forbid one, and no ruling is needed to permit one. A G9 fork is the person's input: an upstream pin plus a patch list they own. That fits `site.lock` (pins sources) plus a digest-bound build output (map §9.8), which is the binary rule rule 5 already states. What stays open is only whether a person's fork is recorded as a source input in `site.lock`.
**Evidence:** `change-process.md:76`, `:121-125`
**Proposed text:**

> A person's own fork (G9, later) is not a tool fork in this sense. Its build, like a tool fork's, reaches a device only as a digest-bound artifact; its upstream pin is in `site.lock`, and its patches are site content.

**Merge:** needs the operator's ruling first (whether a person's fork is a source input in `site.lock`); then insert after it
**Checked:** verified (text read); independently checked 2026-11-13: the claim that rule 5 forbids a person's fork was refuted (rule 5 is scoped to the project's tool forks); item rewritten to keep only what holds

### X-forks-06: Step 10+ names fork builds

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §13 build-order row "10+", at "Demand: builder/cache, APK provenance"; and guide §18 table row "10+"
**Kind:** add
**Goal:** G9, G5
**Weight:** nit
**Finding:** The builder/cache step is where G9's builds would run. The row should say so, so the cache design accounts for signing other people's builds of patched upstreams.
**Evidence:** map line 1168; guide line 1375
**Proposed text:**

> Demand: builder/cache (also the builder for per-person forks, G9), APK provenance, ...

**Merge:** replace that sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-forks-07: "plugin" means two things

**Target:** `docs/architecture/plugin-layout.md` §7 "Not decided here", new item
**Kind:** add
**Goal:** G9
**Weight:** nit
**Finding:** G9's "plugins to projects" (a fork of, say, an app's plugin) is unrelated to D46's compiler plugins (frontends and importers). Readers will conflate them.
**Evidence:** `plugin-layout.md` §1, §3; `00-goal-definition.md:67-70`
**Proposed text:**

> - **Not G9's plugins.** The goal's "forks of plugins to projects" means plugins of other people's software, maintained as per-person forks. Those are not compiler plugins and have no entry-point group here.

**Merge:** insert as the last item
**Checked:** inferred (§7 not read in full); independently checked 2026-11-13: confirmed (the risk that readers confuse the two meanings is an inference)

### X-forks-08: a series and a merged branch both have to be carried

**Target:** `docs/architecture/upstream-overlay.md` §2, after the paragraph beginning "**Ruling, 2026-10-29 (operator):**"
**Kind:** add
**Goal:** G9
**Weight:** improves
**Finding:** The operator's own needs outgrew the patch series. Linux runs a merged fork branch pinned by commit. G9 must support both forms, and show the owner the same per-change list for either (derived from the branch against its base).
**Evidence:** `upstream-overlay.md:50-65`; `overlay/fork.json`
**Proposed text:**

> For G9 this is evidence, not an exception: a fork worth keeping may outgrow a short series. A per-person fork should be able to pin either a series on a base or a merged branch by commit, and in both cases list its changes to the owner one by one.

**Merge:** needs the operator's ruling first (the per-person fork shape: a series on a base, or a merged branch by commit); then insert after it
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-forks-09: G4 for a built binary is the source interdiff

**Target:** map §9.8 "Privileged regions, removals, fetched content", after the bullet beginning "**Fetched content binds bytes, not names.**"
**Kind:** add
**Goal:** G4, G9
**Weight:** improves
**Finding:** For a fork build, the goal-file hunk is a digest change. That is mechanically exact but meaningless to an owner. The briefing should carry the patch interdiff and upstream range the digest was built from, and the safety score should be computed on those.
**Evidence:** map §9.8; `00-goal-definition.md:31-37`
**Proposed text:**

> - **A built artifact's briefing is its source change.** Where a digest names something built from a pinned upstream plus patches (G9), the briefing shows the upstream range and each patch's old-against-new interdiff. The safety score is computed on those, not on the digest.

**Merge:** needs the operator's ruling first (scope of G4 for built artifacts)
**Checked:** not checked (design inference; map §9.8 exists; confirming it needs the operator's ruling on G4's scope for built artifacts and a trial briefing for one fork build)

### X-forks-10: line-count claim is stale

**Target:** `docs/architecture/upstream-overlay.md` §8 item 4, at "`bin/overlay.py` is under 600 lines"
**Kind:** correct
**Goal:** G7
**Weight:** nit
**Finding:** The file is 626 lines.
**Evidence:** `wc -l bin/overlay.py` printed `626`
**Proposed text:**

> `bin/overlay.py` is about 600 lines with no dependency but git.

**Merge:** replace that sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

## Withdrawn after checking

No item was withdrawn.

1. **X-forks-05, rewritten in place.** Claim: change-process rule 5 "as worded forbids" a person's own fork, so a ruling is needed to permit one. Evidence: `change-process.md:76` scopes "tool forks" to `djbclark/core`, `djbclark/libntech` and `frdminc/ShizukuTendCF`; rule 5 (`:121-125`) says such a fork's binary enters a release only as a digest-bound fetched artifact and says nothing about a person's fork. The item no longer asks for that ruling.

## Ideas and risks

1. **Shizuku-class install and Android verification.** Is a Shizuku/ShizukuPlus install ADB-class under the 2027 rules? If not, household forks need a limited-distribution account or the advanced flow, which an AI cannot complete on the person's behalf. Hand this to p2-android.
2. **Signing-key loss strands every installed fork copy.** Treat it like the TUF root: escrow plus a rotation plan, at fork creation.
3. **Silent no-op patches.** Gentoo ignores unreadable patch dirs "silently", and patch-package exits 0 locally on failure. Every carried patch needs its check to *run*, or "carried" is unproven. The project's discrimination rule (guide §19) applies.
4. **RETIRE by patch-id is necessary but not sufficient.** Upstream may fix it differently (VERIFY). Run the intent check without the patch before dropping it.
5. **AI-regenerated patches are new authorship.** Licence attribution, any upstream rules on AI contributions (not checked), and G4 scoring should mark them distinctly and permanently.
6. **The dotfiles PR shows a cost trap.** An agent rebuilding all hosts weekly is cheap for one sysadmin. For a household, bound rebuilds to forks whose upstream actually moved.
7. **Hold rules need an expiry.** "Stay on last good build" becomes "stay on a build with known CVEs". Surface age and upstream security releases, and escalate in the briefing after N weeks.
8. **Guix's "preserved across upgrades" is the UX to copy.** The person states the change once, and every upgrade re-applies it or explains why it cannot.
9. **Plugins are the easier first market.** Plugin forks (editor, browser and app plugins) are smaller, often interpreted (no compile), and closer to patch-package than to CFEngine. A good second dogfood after the overlay.
10. **Upstream fatigue.** This project already saw 26 PRs closed for volume. One terse, opt-in issue per patch, sent by the person, or G9 multiplies that experience.

## Not checked

- Debian gbp-pq, quilt, stgit, git-branchless, Homebrew taps and `brew edit`, Arch ABS, Renovate: not fetched.
- Radicle and Obtainium: snippet only.
- Google's developer-verification blog posts: snippet only; the body did not render. Google's official pages were fetched by the independent check: https://developer.android.com/developer-verification, https://developer.android.com/developer-verification/guides/faq and https://developer.android.com/developer-verification/guides/limited-distribution.
- Android same-key update rule: background knowledge only.
- PortGPT's exact success definition: not checked.
- `overlay.py` `lint` internals: not read in full.
- No test or build was run.

Last search run: firecrawl search for 2026 Android developer verification, already run in this slice. It found the 2026-03 and 2026-06 Google posts (snippet only) and the 2026-09-28 update of the foresightmobile article: no newer change to the 30 September 2026 / 2027 dates. No further search run.
