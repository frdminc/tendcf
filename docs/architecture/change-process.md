# The change process: lockfile, release, rollback, gates

**Date:** 2026-10-09. **Author:** Claude Fable 5.1 (ClaudeHelm worker), from
the guide, the implementer map, and the state of the four repositories on
that day. **Status:** design for requirement #2
([frdminc/tendcf#2](https://github.com/frdminc/tendcf/issues/2)), binding
on Step 6 until the guide or the map says otherwise. On conflict about the
*current* design the guide wins; this document fills in what the guide
leaves as "a lockfile (flake-style inputs)" and "the signed release is the
deploy artifact" with a mechanism concrete enough to build.

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
| tendcf | `frdminc/tendcf` | schemas, `bin/projector.py`, generic bundles under `policy/`, the upstream overlay (`overlay/`, see [`upstream-overlay.md`](upstream-overlay.md)) |
| nix2cf | `frdminc/nix2cf` | the compiler (Step 3; today a README) |
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
    "nix2cf": {
      "ref": "master",
      "rev": "582a66123df2919a21279381f47b2d9c6132ee74",
      "tree": "8ee45f66743fe1549c162bd9921cf0c222871a50",
      "type": "git",
      "url": "https://github.com/frdminc/nix2cf"
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
   is content inside the tendcf input; a built agent or APK enters a release
   only as a digest-bound fetched artifact (map §9.8, DC-11). The lockfile
   pins sources, not binaries.

**nix2cf has a one-input lock of the same shape** (`tendcf.lock`) pinning
the tendcf rev its golden tests run against. That is what lets a schema
change land in tendcf before the compiler supports it without breaking the
compiler's CI (§5).

A `flake.lock` was considered as *the* format and rejected as the
requirement (§8.5); a converter from `site.lock` to flake inputs is a
one-screen script if Step 7 wants it.

## 3. What a release is

A release is one immutable, numbered artifact set:

| Part | Content | Signed by |
| --- | --- | --- |
| `targets/<host-pubkey>.goal.json` | that host's complete canonical goal file (map §9) | targets role |
| `targets/policy-tree.tar` | the generic bundles and templates at the tendcf rev, whose digest is the privileged region map §9.8 names | targets role |
| `targets.json` | the digest of every target, plus `custom`: release number, `site.lock` SHA-256, the site-private commit, the compiler and projector versions | targets role |
| `snapshot.json`, `timestamp.json` | TUF metadata binding the set and its freshness | snapshot / timestamp roles |

Three properties follow:

1. **Immutable and content-addressed.** The release number is the TUF
   `version`; it only goes up (high-water mark on every client, map
   §9.11). The content is reproducible from the site-private commit, and
   the lockfile hash in `targets.json` is how a reader gets from a release
   back to its inputs without trusting a branch name.
2. **Per-host targets, one release.** One release carries every host.
   Hosts that did not change get a byte-identical goal file and compute an
   empty diff; nothing is applied. This is why "a release" and "a change"
   are not the same size: a release is cheap to cut even when it changes one
   line on one host.
3. **The policy tree rides in the release**, not in a git checkout the
   device syncs on its own. Map D14's "git-synced policy" is the transport
   between operator hosts; what arrives on a device is the tarball whose
   digest the goal file will carry once map §9.8's obligation is discharged.
   Until then the digest is recorded in `targets.json` and checked by the
   agent before it points CFEngine at the tree.

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

The cross-repo case — say a new entry kind, which needs a schema (tendcf),
projector support (tendcf), a generic bundle promise (tendcf), compiler
support (nix2cf), and site data (site-private):

1. **tendcf lands first**, as one commit: schema, fixture, projector,
   bundle, and the broken fixtures that prove the lint catches the new
   kind's failure modes. tendcf CI is green on its own. No device notices.
2. **nix2cf bumps `tendcf.lock` to that rev and lands compiler support**, in
   one commit, green against the new fixtures. No device notices.
3. **site-private bumps both pins and adds the data in one commit.** The
   release pipeline runs once. That release is the first thing any device
   sees, and it contains all three changes or none of them.

If step 3 is split (pins first, data later) nothing breaks: a release whose
inputs changed but whose data did not renders the same goal files, and
every host computes an empty diff. That is the test that the pin bump was
pure. Doing it that way on purpose is cheap and is recommended for any
tendcf or nix2cf bump that touches the projector or the compiler.

If the schema change is **not** backward compatible, map §9.6 governs: it
ships as two releases, the validator update first as an ordinary diff, the
migration second, and the migration must diff to empty (map §9.4). The
lockfile does not change that rule; it only makes each of the two releases
one commit.

## 5. Why the other repositories never block

Each repository's CI runs against pinned inputs, never against a sibling's
`master`:

- **tendcf** has no inputs. Its CI is the schema lint, the cross-reference
  lint, and the overlay self-test.
- **nix2cf** pins tendcf (`tendcf.lock`). A schema change in tendcf cannot
  break nix2cf's CI until nix2cf chooses to bump.
- **site-private** pins both. A change in either cannot reach a release
  until site-private chooses to bump.

So the only ordering constraint is the one the data imposes (a compiler must
understand a kind before a release uses it), and it is enforced by the
release pipeline refusing, not by anyone cutting tags in sequence. The
sibling repositories can be hours, days, or a month apart; the device sees
one consistent set.

## 6. CI gates, in the order they run

**Component gates** (per repository, on every push and pull request):

| Repo | Gate | Exists today |
| --- | --- | --- |
| tendcf | `bin/schema_lint.py` incl. the 92 broken fixtures and projector goldens | yes |
| tendcf | `bin/xref_lint.py` | yes |
| tendcf | `bin/overlay.py self-test` and `lint` (patch overlay applies; drift fails loudly) | yes, this change |
| tendcf | overlay drift against upstream (`check --against upstream/master`) | scheduled / manual job, this change |
| nix2cf | compile the tendcf fixtures at the pinned rev; goldens byte-identical | Step 3 |

**Release gates** (site-private, every commit; a pull request gets the same
run with signing and publishing skipped, and the per-host diffs attached as
the review artifact):

1. `site.lock` is canonical bytes; every input's `rev` is reachable and its
   fetched `tree` matches. Refuse otherwise: a pin that cannot be verified
   is not a pin.
2. Compile every host. Conflict-as-error (map §3): the same identity from
   two peer inputs without a private bind refuses the whole release.
3. Every goal file passes `bin/schema_lint.py` at the pinned tendcf rev and
   is canonical bytes.
4. Project every goal file with the pinned projector; the projection passes
   the projection lint. (This is the compiler's regression test against the
   agent's eventual projector: both must agree on golden bytes.)
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

## 7. Latency target (proposed; needs the operator)

#2 says no number has been picked. Proposal, to be confirmed or replaced:

| Measure | Target | Why this number |
| --- | --- | --- |
| Site Model edit pushed → signed release exists | **≤ 5 minutes p95** | one CI run: fetch three small inputs, compile a fleet of under fifty hosts, lint, sign. Nothing in the pipeline is heavier than the schema lint, which runs in seconds today. |
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
2. **Partial rollback is the same mechanism**: revert one input's pin or one
   host's entries, cut a release. There is no "roll back repo X" because no
   device ever depended on repo X directly.
3. **A device that never took the bad release** computes the diff from its
   own baseline to M and finds it empty or small. Nothing special happens.
4. **A bad release that must be stopped before devices apply it** uses the
   emergency role (map D42): revoke that release's targets without consent,
   then cut M. Tightening never needs a local yes; the rollback content does.
5. **A bad tendcf or nix2cf commit** is reverted in its own repository on
   its own schedule, or not at all; the fleet is fixed by the site-private
   pin going back, which is step 1. This is the whole point: the sibling
   repositories' history is never load-bearing for what devices run.

## 9. Rejected alternatives

1. **Coordinated tag train** (the thing #2 forbids). Slow for the reasons in
   §1, non-atomic because consumers read several moving refs, and it puts a
   human ceremony in front of every change, which R12/R13 (cheap routine
   work, agents as authors) cannot afford.
2. **Monorepo.** Would make the change atomic trivially, but map D34/D35
   require the public engine, the optional public recipes, and the private
   inventory to be separable, and foreign sites' recipes are by definition
   other people's repositories. A monorepo also cannot hold the tool forks.
3. **Git submodules in site-private.** A submodule pointer is a lockfile
   with worse properties: it records only `rev` (no `tree`, so a rewritten
   fork is undetectable until the fetch fails), it is bound to a checkout
   layout rather than to a resolver, it fights task worktrees (map §3:
   development happens in worktrees), and it has nothing to say about
   namespacing or private binds, which the composition rules need anyway.
   Everything a submodule gives, `site.lock` gives with one JSON file and
   one script.
4. **Vendoring copies of tendcf/nix2cf into site-private.** Atomic, but it
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
  for a real fleet; the format is fixed now so that nix2cf's `tendcf.lock`
  (Step 3) and the real one (Step 6) are the same thing.
- **The latency numbers in §7 are a proposal.** They become the requirement
  when the operator confirms them on #2.
