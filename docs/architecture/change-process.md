# The change process: lockfile, release, rollback, gates

**Date:** 2026-10-09. **Author:** Claude Fable 5.1 (ClaudeHelm worker), from
the guide, the implementer map, and the state of the four repositories on
that day. **Status:** design for requirement #2
([frdminc/tendcf#2](https://github.com/frdminc/tendcf/issues/2)), binding
on Step 6 until the guide or the map says otherwise. On conflict about the
*current* design the guide wins; this document fills in what the guide
leaves as "a lockfile (flake-style inputs)" and "the signed release is the
deploy artifact" with a mechanism concrete enough to build.

**Amended 2026-11-13 (map D46).** The compiler, built as the separate
repository `frdminc/nix2cf`, is folded into tendcf with its history
under `compiler/` ([#45](https://github.com/frdminc/tendcf/pull/45),
merged 2026-11-13), and `frdminc/nix2cf` was archived the same day
([`plugin-layout.md`](plugin-layout.md)). The compiler is therefore no
longer a separately pinned input: schema and compiler change in the same
tendcf commit, and the two-repository bump order and the compiler's own
`tendcf.lock` that this document used to specify are gone. `site.lock`
loses only its `nix2cf` entry: it still pins tendcf, site-shared and
foreign sites, and tool forks stay as rule 5 has them. One tendcf rev is
now the unit a site pins (§8 item 5). Compiler plugins are trusted
build-time code; which ones a release loads, and the rule that the gates
and signing run apart from them, are in §3 and §6. Since #45 the
compiler's tests run in tendcf's own CI against the same commit (the
`compiler` job of `.github/workflows/check.yml`); before that, nix2cf's
CI checked out tendcf's default branch beside it and never had the
`tendcf.lock` specified here.

> The requirement, verbatim from #2: the Site Model → signed-release →
> deploy path must be **much faster and much more atomic** than cutting a
> coordinated tag across several sibling repositories. It does not relax
> signing, consent, review gates, or rollback discipline. It shrinks the
> *unit* and the *latency* of a change.

## 1. What "atomic" and "fast" mean here

A tag train is slow for one reason and non-atomic for another, and the two
are usually confused:

- It is **slow** because every repository must reach a releasable state at
  the same time, so the slowest one sets the pace, and because each tag is a
  human ceremony.
- It is **non-atomic** because the consumer reads several moving references.
  Between the first tag and the last, a device that fetches sees a mixture
  that nobody tested.

The fix for both is the same and is already decided (map D19, guide §2):
**no device, and no build, ever reads a repository.** A device reads a
release. A build reads a lockfile. Repositories move freely; a change
becomes visible only when *one* file in *one* repository changes, and that
file names every input by content.

So the definitions this document uses:

- **Atomic** — a release is built from exactly one commit of site-private,
  and that commit names, by hash, every other input. There is no state in
  which a device or a build sees input A at a new version and input B at an
  old one unless the lockfile says so.
- **Fast** — the latency from "a person saves a Site Model edit" to "a
  signed release exists" is bounded by one CI run of site-private, not by
  the readiness of any other repository. §7 proposes the numbers.

Atomic across *devices* is not a goal. There is no distributed lock (map
D37); every host applies its own ChangePlan on its own schedule, and a
device seven releases behind still computes one true diff (guide §7).

## 2. The inputs, and where they are pinned

| Layer (map §3) | Repository today | What a release takes from it |
| --- | --- | --- |
| tendcf | `frdminc/tendcf` | schemas, `bin/projector.py`, generic bundles under `policy/`, the upstream overlay (`overlay/`, see [`upstream-overlay.md`](upstream-overlay.md)), and the compiler with its plugins (Step 3; in `compiler/` since map D46's import (#45); its one compilation command is `buildfile`; `plugins/` after the restructure, [`plugin-layout.md`](plugin-layout.md) §5 step 4) |
| site-shared | not yet created | recipes |
| foreign site-shared | none yet | recipes, namespaced |
| site-private | `~/ops/site-private` (today: ops repo; the tendcf inventory does not exist yet) | inventory, allocations, secret *names*, trust policy, the lockfile |
| tool forks | `djbclark/core`, `djbclark/libntech`, `frdminc/ShizukuTendCF` | reached only through tendcf's overlay or as digests of built artifacts |

**One lockfile, in site-private: `site.lock`.** It is the only place a
version is chosen. Everything else is content.

```json
{
  "inputs": {
    "alice": {
      "$comment": "illustrative foreign input; its hashes are placeholders",
      "namespace": "alice",
      "ref": "main",
      "rev": "9c1f0e4d2b7a6c8e0f3a5b7d9e1c3a5b7d9e1c3a",
      "tree": "5e7a9c1b3d5f7a9c1b3d5f7a9c1b3d5f7a9c1b3d",
      "type": "git",
      "url": "https://github.com/alice/site-shared"
    },
    "tendcf": {
      "ref": "master",
      "rev": "af0e0c5781ba6eb0123a9fe65db37e6a0ea74905",
      "tree": "fdde52257509a9157f270861da1c020297936b41",
      "type": "git",
      "url": "https://github.com/frdminc/tendcf"
    }
  },
  "schema_version": 1
}
```

Rules for the file, each with the reason it is a rule:

1. **Canonical JSON (RFC 8785), the same discipline as the goal file**
   (map §9.2, D44). The lockfile's own SHA-256 is bound into the release
   metadata (§4), so two spellings of one pin must be impossible.
2. **`rev` and `tree` are both recorded.** `rev` is the audit trail (what
   commit, reachable from what branch); `tree` is what the build verifies
   after fetching, because a rewritten branch can move `rev` out from under
   a `ref` while `tree` still proves the content. Both are plain git
   objects: no Nix is needed to compute or check them, which R5 and D6
   require (Nix is an optional builder, never a dependency of the path).
3. **`ref` is informational.** The resolver updates `rev`/`tree` from `ref`
   on request; a build never follows `ref`.
4. **Foreign inputs carry `namespace`**, which is the map §3 composition
   rule (`alice.caddy`), applied at the lockfile rather than invented at
   compile time.
5. **A tool fork is never an input of its own.** The CFEngine patch overlay
   is content inside the tendcf input; a built binary or the Android
   agent's APK enters a release only as a digest-bound fetched artifact
   (map §9.8, DC-11). The lockfile
   pins sources, not binaries.

~~**nix2cf has a one-input lock of the same shape** (`tendcf.lock`)
pinning the tendcf rev its golden tests run against.~~ **Amended
2026-11-13:** there is no compiler lock. The compiler is in tendcf, so its
goldens run against the schemas of the same commit, and a schema change
lands together with the compiler support it needs (§4, §5). This holds
for the current `schema_version`, the only one the compiler renders (map
D46): older-version rendering is removed in the restructure. Map §9.6's
ceiling design, which needs the compiler to render older versions for
hosts below the ceiling, applies once the first device that is not an
operator host enrolls; how that older output is validated when schema and
compiler share a commit is decided then.

A `flake.lock` was considered as *the* format and rejected as the
requirement (§8.5); a converter from `site.lock` to flake inputs is a
one-screen script if Step 7 wants it.

## 3. What a release is

A release is one immutable, numbered artifact set:

| Part | Content | Signed by |
| --- | --- | --- |
| `targets/<host-pubkey>.goal.json` | that host's complete canonical goal file (map §9) | targets role |
| `targets/policy-tree.tar` | the generic bundles and templates at the tendcf rev, whose digest is the privileged region map §9.8 names | targets role |
| `targets.json` | the digest of every target, plus `custom`: release number, `site.lock` SHA-256, the site-private commit, the tendcf rev (compiler and projector; one rev since map D46) and the compiler plugin set the compile loaded (name, distribution, version, hash; map D46) | targets role |
| `snapshot.json`, `timestamp.json` | TUF metadata binding the set and its freshness | snapshot / timestamp roles |

Three properties follow:

1. **Immutable and content-addressed.** The release number is the TUF
   `version`; it only goes up (high-water mark on every client, map
   §9.11). The site-private commit identifies the release's sources, and
   the lockfile hash in `targets.json` is how a reader gets from a release
   back to its inputs without trusting a branch name. That needs every
   compiler plugin to come from a pinned input: until out-of-tree pinning
   exists ([#47](https://github.com/frdminc/tendcf/issues/47)), a release
   build loads only in-tree plugins named by site-private, so the tendcf
   pin covers them, and plugins installed on the builder but not named
   are ignored (map D46). Reproducing the release byte for byte also
   needs a fixed dependency and toolchain closure for the build and
   controlled or recorded external inputs (environment, network); those
   are not specified yet.
2. **Per-host targets, one release.** One release carries every host.
   Hosts that did not change get a byte-identical goal file and compute an
   empty diff; nothing is applied. This is why "a release" and "a change"
   are not the same size: a release is cheap to cut even when it changes one
   line on one host.
3. **The policy tree rides in the release**, not in a git checkout the
   device syncs on its own. Map D14's "git-synced policy" is the transport
   between operator hosts; what arrives on a device is the tarball whose
   digest the goal file will carry once map §9.8's obligation is discharged.
   Until then the digest is recorded in `targets.json` and checked on the
   device before CFEngine is pointed at the tree: by tendcf-agent on
   Android; on Linux and macOS the checking component is not yet assigned
   (map D45 and its open points in §12).

## 4. How a change lands

The ordinary case, one site-private commit:

1. A person or agent edits Site Model data in site-private (or bumps a pin
   in `site.lock`; both are the same kind of commit).
2. Site-private CI runs the **release pipeline** (§6): resolve the lock,
   fetch each input, verify its `tree`, compile every host, lint every goal
   file, render a per-host preview diff, refuse on any gate, sign, publish.
3. The release exists. Operator-tier hosts take it by push (Step 6) and later
   by pull (Step 8); consented devices take it when their advisor and their
   person say yes (Step 9). None of that waits on any other repository.

The cross-repo case — say a new entry kind, which needs a schema,
projector support, a generic bundle promise and compiler support (all
tendcf), and site data (site-private):

1. **tendcf lands first**, as one commit: schema, fixture, projector,
   bundle, compiler support, and the broken fixtures that prove the lint
   catches the new kind's failure modes. tendcf CI, compiler goldens
   included, is green on its own. No device notices.
2. **site-private bumps the tendcf pin and adds the data in one commit.**
   The release pipeline runs once. That release is the first thing any
   device sees, and it contains both changes or neither.

(~~Before 2026-11-13 this was three steps: tendcf, then nix2cf bumping its
`tendcf.lock` and landing compiler support, then site-private bumping
both pins.~~ Map D46 put the compiler in tendcf, so the middle step is
part of the first.)

If step 2 is split (pin first, data later) nothing breaks: a release whose
inputs changed but whose data did not renders the same goal files, and
every host computes an empty diff. That is the test that the pin bump was
pure. Doing it that way on purpose is cheap and is recommended for any
tendcf bump that touches the projector or the compiler.

If the schema change is **not** backward compatible, map §9.6 governs: it
ships as two releases, the validator update first as an ordinary diff, the
migration second, and the migration must diff to empty (map §9.4). The
lockfile does not change that rule; it only makes each of the two releases
one commit.

## 5. Why the other repositories never block

Each repository's CI runs against pinned inputs, never against a sibling's
`master`:

- **tendcf** has no inputs. Its CI is the schema lint, the cross-reference
  lint, the overlay self-test and, since the compiler moved in (map D46,
  #45), the compiler's goldens against the same commit's schemas. A schema
  change that breaks the compiler fails tendcf's own CI, in the commit
  that makes it. That is a statement about the current `schema_version`,
  the only one the compiler renders until map §9.6's ceiling design
  applies (§2).
- ~~**nix2cf** pins tendcf (`tendcf.lock`). A schema change in tendcf
  cannot break nix2cf's CI until nix2cf chooses to bump.~~ Gone with map
  D46.
- **site-private** pins tendcf and the other site inputs. A change in any
  of them cannot reach a release until site-private chooses to bump.

So the only ordering constraint is the one the data imposes (a compiler must
understand a kind before a release uses it), and it is enforced by the
release pipeline refusing, not by anyone cutting tags in sequence. tendcf
and the site inputs can be hours, days, or a month apart; the device sees
one consistent set.

## 6. CI gates, in the order they run

**Component gates** (per repository, on every push and pull request):

| Repo | Gate | Exists today |
| --- | --- | --- |
| tendcf | `bin/schema_lint.py` incl. the 159 broken fixtures (125 schema-level, 6 byte-class, 28 projection; counted 2026-11-13) and projector goldens | yes |
| tendcf | `bin/xref_lint.py` | yes |
| tendcf | `bin/overlay.py self-test` and `lint` (patch overlay applies; drift fails loudly) | yes, this change |
| tendcf | overlay drift against upstream (`check --against upstream/master`) | scheduled / manual job, this change |
| tendcf (compiler) | compile the tendcf fixtures at the same commit; goldens byte-identical | yes: the `compiler` job of `.github/workflows/check.yml`, since #45 (map D46); before that in `frdminc/nix2cf` CI, against tendcf's default branch |

**Release gates** (site-private, every commit; a pull request gets the same
run with signing and publishing skipped, and the per-host diffs attached as
the review artifact):

1. `site.lock` is canonical bytes; every input's `rev` is reachable and its
   fetched `tree` matches. Refuse otherwise: a pin that cannot be verified
   is not a pin.
2. Compile every host, loading only the compiler plugins site-private
   names (in-tree only until #47; map D46). Conflict-as-error (map §3):
   the same identity from two peer inputs without a private bind refuses
   the whole release, and so does a duplicate plugin name within a group.
3. Every goal file passes `bin/schema_lint.py` at the pinned tendcf rev and
   is canonical bytes.
4. Project every goal file with the pinned projector; the projection passes
   the projection lint. (On Linux and macOS this is the device's own code:
   the projector is promoted to `tendcf-validate`, map D45. The Android
   agent's Kotlin port must agree with it on the same golden bytes.)
5. Compute the per-host preview diff against the previous release's goal
   file for that host. Refuse when:
   - a hunk touches a privileged region (map §9.8) and the commit does not
     carry the matching ceremony marker, or
   - the release is marked `migration` and any host's diff is non-empty
     apart from the version bump (map §9.4), or
   - a host's `schema_version` exceeds the ceiling that host last reported
     (guide §7: nobody gets stranded).
6. Sign `targets`, `snapshot`, `timestamp`; publish to the release store;
   record the release number against the site-private commit (a git note or
   a tag on site-private, after the fact, is fine — it is a label, not an
   input).

The signing key for `targets` lives on the builder, which is an operator
host; `root` stays offline (map §9.11, residue §14.4). A pull request can
run every gate but 6, so review happens over the exact diffs a merge would
ship.

**Gates 3 to 6 run apart from plugin code** (map D46). Compiler plugins
are trusted build-time code, not sandboxed, so the schema lint, the
projector, the preview diff and signing run in a separate environment in
which no plugin distribution is installed, and the compile step (gate 2)
holds no signing key. The gates bound the shape of what a plugin renders,
not its faithfulness to the Site Model: gate 5's preview diff shows what
the plugins rendered, and a preview diff or `explain-hunk` attribution
produced on the compile side (map D44) is compiler output that inherits
the plugins' trust ([`plugin-layout.md`](plugin-layout.md) §4).

## 7. Latency target (proposed; needs the operator)

#2 says no number has been picked. Proposal, to be confirmed or replaced:

| Measure | Target | Why this number |
| --- | --- | --- |
| Site Model edit pushed → signed release exists | **≤ 5 minutes p95** | one CI run: fetch a few small inputs, compile a fleet of under fifty hosts, lint, sign. Nothing in the pipeline is heavier than the schema lint, which runs in seconds today. |
| Signed release → converged on every *reachable* operator host | **≤ 10 minutes p95** | push (Step 6) triggers an immediate `cf-agent` run; the default 5-minute schedule bounds the pull path (Step 8). |
| Devices never reached | reported per release, by trust tier | guide §17 names this as the measurement that says when the release-as-artifact model stops being adequate. |

Measured from the release pipeline's own log and the per-host report row
(release stamp, guide §18), so the numbers exist from the first release.

## 8. Rollback

A rollback is **a new release whose content is an old one**. Never
re-serving old metadata, because the high-water mark (map §9.11) correctly
rejects it as a downgrade, and because the device's stored baseline has
moved on since.

1. `release revert N` (site-private tooling, Step 6) creates a commit that
   restores `site.lock` and the Site Model data to the state of release N,
   runs the full pipeline, and produces release M > current. Every host
   computes the reverse diff against its current baseline and applies it the
   ordinary way. A consented device consents again; an operator host applies.
   Removals revert as `absent → present` replace hunks, which is why map
   §9.8 insists removals are states, not events: a rollback is just another
   diff.
2. **Partial rollback is the same mechanism**: move one input's pin back
   (the tendcf pin moves schemas, policy tree and compiler together, item
   5) or revert one host's entries, cut a release. There is no "roll back
   repo X" because no device ever depended on repo X directly.
3. **A device that never took the bad release** computes the diff from its
   own baseline to M and finds it empty or small. Nothing special happens.
4. **A bad release that must be stopped before devices apply it** uses the
   emergency role (map D42): revoke that release's targets without consent,
   then cut M. Tightening never needs a local yes; the rollback content does.
5. **A bad tendcf commit** (schema, projector, bundle or compiler; ~~a bad
   tendcf or nix2cf commit~~ before map D46) is reverted in tendcf on its
   own schedule, or not at all; the fleet is fixed by the site-private
   pin going back, which is step 1. This is the whole point: the input
   repositories' history is never load-bearing for what devices run.
   Since map D46 one tendcf rev is the unit a site pins: taking or
   reverting a compiler fix also takes or reverts every `schema/` and
   `policy/` commit before it, and on a consented device a policy-tree
   change is a privileged-region hunk (map §9.8). That coupling is
   accepted. There is no maintenance-branch machinery for carrying a
   compiler fix alone; revisit when the first device that is not an
   operator host enrolls.

## 9. Rejected alternatives

1. **Coordinated tag train** (the thing #2 forbids). Slow for the reasons in
   §1, non-atomic because consumers read several moving refs, and it puts a
   human ceremony in front of every change, which R12/R13 (cheap routine
   work, agents as authors) cannot afford.
2. **Monorepo.** Would make the change atomic trivially, but map D34/D35
   require the public engine, the optional public recipes, and the private
   inventory to be separable, and foreign sites' recipes are by definition
   other people's repositories. A monorepo also cannot hold the tool forks.
   (Map D46, 2026-11-13, does merge two *public engine* repositories, tendcf
   and the compiler, which share an owner, a licence and reviewers; the
   layers this item keeps apart stay apart. The cost is rollback
   granularity: one tendcf rev pins compiler, schemas and policy tree
   together, accepted in §8 item 5.)
3. **Git submodules in site-private.** A submodule pointer is a lockfile
   with worse properties: it records only `rev` (no `tree`, so a rewritten
   fork is undetectable until the fetch fails), it is bound to a checkout
   layout rather than to a resolver, it fights task worktrees (map §3:
   development happens in worktrees), and it has nothing to say about
   namespacing or private binds, which the composition rules need anyway.
   Everything a submodule gives, `site.lock` gives with one JSON file and
   one script.
4. **Vendoring copies of tendcf (and, before map D46, nix2cf) into
   site-private.** Atomic, but it
   duplicates review (every tendcf change is re-reviewed as a vendored
   diff), loses provenance (`rev`/`tree` of a copy is whatever the copier
   says), and makes the public engine's history irrelevant to its users.
5. **Nix `flake.lock` as the mandatory lock.** The shape is right and the
   resolver is battle-tested, but it needs Nix to compute `narHash`, which
   makes Nix a dependency of the release path on the builder; R5/D6 keep Nix
   optional. `site.lock` keeps the two git hashes Nix does not need and can
   be converted into flake inputs when a Nix builder exists (Step 7/10+).
6. **Devices reading git directly** (a device fetches the policy tree from
   a branch). This is what "git-synced policy" is sometimes taken to mean and
   it is what makes a tag train necessary: the consumer reads a moving ref.
   Map D19 and guide §7 already rule it out; this document makes the
   consequence explicit — git-sync is a transport between operator hosts,
   the release is what devices consume.
7. **One release per host.** Smaller artifacts, but it reintroduces the
   mixture problem across hosts and multiplies the signing ceremony. One
   release, per-host targets, empty diffs for unchanged hosts is cheaper and
   is what TUF's single `snapshot` is for.
8. **Re-serving an old release as the rollback.** Rejected by the high-water
   mark and by the stored baseline; §8.

## 10. What this leaves for later

- **The resolver and the release pipeline are Step 6 code**, not written.
  This document is their specification. The pieces that exist today
  (schema lint, projector goldens, overlay self-test) are the component
  gates in §6.
- **The privileged-region ceremony marker** (§6 gate 5) is a site-private
  commit convention to be chosen with the TUF ceremony (map §14.4).
- **The inventory does not exist yet**, so `site.lock` has nothing to pin
  for a real fleet; the format is fixed now so that the real one (Step 6)
  needs no redesign. (~~so that nix2cf's `tendcf.lock` (Step 3) and the
  real one (Step 6) are the same thing~~: there is no compiler lock since
  map D46.)
- **The latency numbers in §7 are a proposal.** They become the requirement
  when the operator confirms them on #2.
