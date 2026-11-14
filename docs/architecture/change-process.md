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
and signing run apart from them (planned, Step 6; nothing enforces it
today), are in §3 and §6. Since #45 the
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
3. **A build never follows `ref`, but `ref` is verified.** The resolver
   updates `rev`/`tree` from `ref` on request, and a build never replaces
   the pinned `rev` with the tip of the moving `ref`. Gate 1 does fetch
   `ref` from `url` and requires `rev` to be its ancestor, so `ref` is a
   provenance check and not merely informational; for the tendcf input
   it also has to be a declared branch (gate 1).
4. **Foreign inputs carry `namespace`**, which is the map §3 composition
   rule (`alice.caddy`), applied at the lockfile rather than invented at
   compile time.
5. **A tool fork is never an input of its own.** The CFEngine patch overlay
   is content inside the tendcf input; a built binary or the Android
   agent's APK enters a release only as a digest-bound fetched artifact
   (map §9.8, DC-11). The lockfile
   pins sources, not binaries.
6. **A changed `url` is a privileged change** (decision D-d, issue #48;
   planned, Step 6). Gate 1 below verifies that `rev` belongs to `ref` at
   `url` and that `tree` matches, so a pull request that repoints a pin
   at a fork would make "the pinned tree" whatever the fork contains, and
   gate 2 would run its code. The same holds for a pin that is not a
   descendant of the previous release's pin, for a new input (its `url`
   is new), and for a changed compiler plugin set: each needs the gate-5
   ceremony marker (§6). **The tendcf input is the exception** (operator
   rulings 16 and 17): its `url` and `ref` are fixed by gate 1 against the
   site's trust root (`frdminc/tendcf` and `master` or a listed
   release-branch set by default), and a pull request that points it at
   anything else is refused, not held for a marker. A site declares its
   own tendcf repository and branch set only in its trust root, and that
   declaration is a privileged change; a per-pull-request marker never
   admits a fork. The trust root is a site declaration of the accepted
   tendcf repository and branches, not the TUF `root` role and not DC-1's
   device-local trust root. **Gate 1 reads the trust-root declaration from
   the protected base, never from the pull request under test, so a
   declaration change takes effect only after it merges and a pin that
   relies on it comes in a later pull request.** A pull request that
   changes the declaration may not also move the tendcf pin.
7. **A site-shared or foreign input is not yet an import** (decision D-b,
   issue #48; planned, Step 6). Pinning it here fetches its repository and
   verifies `rev` and `tree`; it does not make its recipes evaluable.
   Gate 2 evaluates a recipe from such an input only if the external
   import of plugin-layout §4 recorded an accepting verdict bound to that
   recipe's content digest, and refuses otherwise. The recorded verdict is
   advisory: job B′ re-runs the static scan and the AI review on the
   pinned digest and fails on a negative result, which only the gate-5
   ceremony marker overrides (operator rulings, plugin-layout §4). Without this rule the
   lockfile would be a second road to the recipes that D-b closes.

~~**nix2cf has a one-input lock of the same shape** (`tendcf.lock`)
pinning the tendcf rev its golden tests run against.~~ **Amended
2026-11-13:** there is no compiler lock. The compiler is in tendcf, so its
goldens run against the schemas of the same commit, and a schema change
is paired with the compiler support it needs, in separate tendcf commits
(§4, §5). This holds
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
| `targets.json` | the digest of every target, plus `custom`: release number, `site.lock` SHA-256, the site-private commit, the tendcf rev (compiler and projector; one rev since map D46) and the compiler plugin set (name, and for a third-party plugin distribution, version and hash; an in-tree plugin is identified by the tendcf rev; map D46), as derived by the plugin-free job and compared by gate 5 with the previous release's (planned), and the signer backend in use (planned) | targets role |
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
   are not selected (map D46; installing one can still run code, plugin-layout §4). Reproducing the release byte for byte also
   needs a fixed dependency and toolchain closure for the build and
   controlled or recorded external inputs (environment, network); those
   are not specified yet.
2. **Per-host targets, one release.** One release carries every host.
   Hosts that did not change get a byte-identical goal file and compute an
   empty diff; nothing is applied. This is why "a release" and "a change"
   are not the same size: a release is cheap to cut even when it changes one
   line on one host. Reading the store (operator ruling, planned, Step 6):
   each host reads only its own goal files, by a per-host path and a
   per-host credential; the operator and the signing job read all.
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
tendcf), and site data (site-private). Two operator rulings shape it.
**The gate tools ship first** (ruling 18; planned, Step 6): the gates that
check a release run from the previous release's tendcf pin (§6). And
**tendcf commits stay separable** (rulings 20 and 21, the authoring rule
below). Because map §9.6 makes every entry-kind change, additive
included, a `schema_version` bump, this example is the schema-bump
sequence, and **staging the gate tools in CI is a different act from
deploying the device validator**: the first is a pin-only release that no
device notices, the second an ordinary goal diff that devices take.

1. **tendcf lands first**, as separate commits, each green on tendcf CI:
   (a) the schema, the projector and any `tools/` change, with the
   validator source that accepts the old and the new version, the
   fixture and the broken fixtures that prove the lint catches the new
   kind's failure modes; it changes no compiler golden and nothing in
   `policy/`; (b) the bundle (`policy/`), alone; (c) the compiler support
   and its goldens, which touches none of `tools/`, `schema/` and the
   projector. No device notices.
2. **Release 1, the gate tools staged: site-private bumps the tendcf pin
   alone**, to the rev after 1(a), as its own release. The
   commit changes the pin and no data. The previous release's tools check
   it, and they pass it because every host's goal file is byte-identical
   to the previous release's: every host computes an empty diff, which is
   also the test that the bump was pure. It needs the ceremony marker (a
   tendcf bump that changes `tools/`, `schema/` or the projector is a
   privileged change, §6 gate 5). This holds only while the compiler at
   the new pin still renders every host's goal file at the previous
   `schema_version`, which is so at the rev after 1(a) because the
   compiler has not changed there. Map §9.6 makes every entry-kind
   change, additive included, a `schema_version` bump, and commit 1(a)
   cannot land in tendcf as it stands, so for this example step 2 waits
   on the open item below.
3. **Release 2, the device validator deployed.** The validator update
   (`tendcf-validate` on Linux and macOS, `tendcf-agent` on Android; map
   D45) is an ordinary privileged-region goal diff under schema N−1 (map
   §9.6, TC-25 class). It is a release of its own: release 1 may change no
   goal file, and gate 5 refuses a release that moves the pin across a
   tools change and also changes bytes, so the two cannot be one release.
   Release 1's tools, which accept both versions, check it. Hosts report
   their `schema_ceiling` (map §9.6), and gate 5's ceiling check (§6)
   refuses release 3 for any host whose reported ceiling is below the new
   version.

   **The bundle commit 1(b) is adopted here or in a release of its own,
   never in release 1 or release 3.** Release 2 may move the pin to the
   rev after 1(b): that move crosses a bundle commit and no
   `tools/`, `schema/` or projector commit, so it may change bytes, and
   once the goal file carries the policy-tree digest (map §9.8) it will
   change every goal file. It is an ordinary privileged-region release
   (the authoring rule below). If the bundle's hunk should be reviewed
   apart from the validator upgrade, it takes a release of its own between
   release 2 and release 3. Release 1 must be byte-identical, so it cannot
   cross 1(b); release 3 must diff to empty apart from the version bump,
   so it cannot either.
4. **Release 3, the migration.** The pin moves to the rev after 1(c), so
   the compiler renders the new version; the bundle commit 1(b) was
   adopted before this release, so the version bump is its only change.
   Map §9.4 governs: the migration must diff to empty apart from the
   version bump and may not be mixed with a semantic change. The new
   tools, now the previous release's pin, check it.
5. **Release 4 or later, the data that uses the new kind**, checked by
   the new tools. This is the first release any device sees that uses the
   new kind.

(~~Before 2026-11-13 this was three steps: tendcf, then nix2cf bumping its
`tendcf.lock` and landing compiler support, then site-private bumping
both pins.~~ Map D46 put the compiler in tendcf, so the middle step is
part of the first.)

**Where the sequence depends on tendcf as it stands, the reconciliation is
open and is not asserted here.** With the authoring rule's commit split
the compiler at each pinned rev still renders one version: the old one at
the rev after 1(a), where the compiler has not changed, and the new one
after 1(c). Releases 1 to 3 therefore need no multi-version compiler; D46
(6) still defers that until the first device that is not an operator host
enrolls. Commit 1(a)
is not possible in tendcf as it stands. `schema/goal-file.schema.json`
states `schema_version` as one `const`, and tendcf CI fails unless the
compiler's `GOAL_FILE_SCHEMA_VERSION` equals it (`check.yml`,
`compiler/scripts/check_schema_version.py`; §5), so today a schema bump,
the compiler bump and every golden land in one commit, which the
authoring rule refuses. The sequence needs `schema/` to carry both
versions for the window and that check to become "the compiler renders a
version the schema accepts". Open. How the device validator update is
delivered as a goal diff (D45) is open as well. What guards that every
host has the validator before release 3 is gate 5's ceiling check (§6),
which refuses a release in which a host's `schema_version` exceeds the
ceiling that host last reported; what is missing beyond it is that the
check is planned Step 6 code like the rest of gate 5, and whether an
operator host reports a ceiling at all while the compiler renders one
version (D46 (6)) is not specified. Both are in
[`plugin-layout.md`](plugin-layout.md) §7. The order above is the
intended one, not a tested one.

A tendcf bump that changes none of `tools/`, `schema/` and the projector
(a compiler-only fix, say) needs no pin-only release: it may go in one
commit with data changes, checked by the previous release's tools.

**The tendcf authoring rule** (operator rulings 20 and 21; planned: a
tendcf CI check, which does not exist today). A tendcf commit that
changes `tools/`, `schema/` or the projector fails tendcf CI if it also
changes the compiler's goldens, and also if it changes `policy/`. The
first half gives every change to the gate tools a pin-only rev whose
output is byte-identical to the rev before it, forwards and backwards
(§8), as far as the goldens cover (an unchanged golden set shows
byte-identity for the golden inputs, not for every site's data), so that
ruling 18's rule can be followed; without it, a commit that changed a
lint and a rendering together could never be adopted by any site. Where
the goldens miss, gate 5 still fails closed at the site: a release whose
bytes differ across a tools change is refused, not signed. The rule
covers any such commit, not only `schema_version` bumps. The second half keeps bundle changes in
their own tendcf commit: once the goal file carries the policy-tree digest
(map §9.8), a bundle change alters every goal file, so a bump across it is
an ordinary privileged-region release, never a pin-only one, and it must
not share a commit with a gate-tools change. How the check names the
goldens and the paths, and how it relates to today's compiler-equals-
schema check, is open.

Map §9.6's two phases are the sequence above: the validator update first
as an ordinary diff under the old schema (release 2, after the gate tools
are staged in release 1), the migration second (release 3), which must
diff to empty (map §9.4). The lockfile does not change that rule; it only
makes each release one commit. For every `schema_version` bump, the
additive case above included, the pin-only release has to keep every goal
file at the old version. With the commit split the compiler at that pin
still renders the old version; what the sequence needs is the two-version
schema window and the relaxed equality check above, which are open
([`plugin-layout.md`](plugin-layout.md) §7).

## 5. Why the other repositories never block

Each repository's CI runs against pinned inputs, never against a sibling's
`master`:

- **tendcf** has no inputs. Its CI is the schema lint, the cross-reference
  lint, the overlay self-test and, since the compiler moved in (map D46,
  #45), the compiler's goldens against the same commit's schemas. A schema
  change that breaks the compiler fails tendcf's own CI, in the commit
  that makes it. That statement changes with the authoring rule (§4): a
  commit that changes `schema/` may no longer also change the compiler's
  goldens, so the compiler-equals-schema check (`check_schema_version`)
  has to accept the two-version window, not one version (open,
  [`plugin-layout.md`](plugin-layout.md) §7). It is a statement about the
  current `schema_version`,
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
| tendcf | `bin/schema_lint.py` incl. the 172 broken fixtures (138 schema-level, 6 byte-class, 28 projection; counted 2026-11-13) and projector goldens | yes |
| tendcf | `bin/xref_lint.py` | yes |
| tendcf | `bin/overlay.py self-test` and `lint` (patch overlay applies; drift fails loudly) | yes, this change |
| tendcf | overlay drift against upstream (`check --against upstream/master`) | scheduled / manual job, this change |
| tendcf (compiler) | compile the tendcf fixtures at the same commit; goldens byte-identical | yes: the `compiler` job of `.github/workflows/check.yml`, since #45 (map D46); before that in `frdminc/nix2cf` CI, against tendcf's default branch |
| tendcf (authoring rule) | a commit that changes `tools/`, `schema/` or the projector fails if it also changes the compiler goldens or `policy/` (operator rulings 20 and 21, §4) | no, planned |

**Release gates** (site-private, every commit; a pull request gets the same
run with signing and publishing skipped, and gates 3 to 5 run in a
plugin-free job without the key (job B′, below), whose per-host diffs are
the review artifact; a diff computed in the compile job never is):

1. `site.lock` is canonical bytes; every input's `rev` is reachable and its
   fetched `tree` matches. "Reachable" means `rev` is an ancestor of the
   pin's `ref` as fetched from the pin's `url`; being fetchable by hash is
   not enough. For the tendcf input `url` and `ref` have to be the
   repository and branch the site's trust root declares: by default
   `frdminc/tendcf` and `master`, or an explicitly listed set of its
   release branches, each with required review, no force-push, no
   deletion and no administrator bypass; any other ref is refused
   (operator rulings 16 and 17; planned, Step 6). Gate 1 reads the trust
   root from the protected base, never from the tree under test, and
   refuses a pull request that both changes it and moves the tendcf pin
   (rule 6). Refuse otherwise: a pin
   that cannot be verified is not a pin. (A changed `url` is also caught
   by gate 5's privileged-change rule below.) Each job fetches and
   verifies the pins itself; jobs B′ and B take nothing from job A but
   goal-file bytes and the digest manifest (plugin-layout §4).
2. Compile every host, loading only the compiler plugins site-private
   names (in-tree only until #47; map D46; the loader is planned,
   [`plugin-layout.md`](plugin-layout.md) §4). Conflict-as-error (map §3):
   the same identity from two peer inputs without a private bind refuses
   the whole release, and so does a duplicate plugin name within a group.
   A recipe from a site-shared or foreign input needs an accepting
   import verdict bound to its content digest (rule 7 above); a missing,
   rejecting or mismatched verdict refuses the release, unless the
   ceremony marker overrides a negative result (it is then recorded with
   the pin and shown in every later gate 5 review). A pull request that
   changes a pin's `url` or the plugin set, adds a `site.lock` input (its
   `url` is new) or changes the trust-root declaration does not get this
   gate run until the marker is present (operator ruling 9 for a changed
   `url` or plugin set; the new input and the trust-root change are held
   on the same reasoning; job B′'s checks that need no job A output may
   run).
3. Every goal file passes `bin/schema_lint.py` as built from the previous
   release's tendcf pin (the gate tools, below) and
   is canonical bytes.
4. Project every goal file with the previous release's projector (the gate
   tools, below); the projection passes
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
     (guide §7: nobody gets stranded), or
   - the tendcf pin moves backwards across a `schema_version` bump
     (forbidden, not merely privileged: roll forward), or
   - the tendcf pin moves, in either direction, across a change to
     `tools/`, `schema/` or the projector and any host's goal file differs
     from the previous release's (a tools bump or a backward move ships
     alone, with unchanged data; see "Which tendcf rev the gate tools come
     from" below and §8 item 2), or
   - the commit makes a **privileged change** and does not carry the
     ceremony marker (decisions D-d and issue #48, planned, Step 6). The
     list (the operator's: a changed `url` in any `site.lock` pin; a pin
     that is not a descendant of the previous release's pin, which includes
     every backward move, though one across a `schema_version` bump is
     forbidden outright, §8 item 5; a compiler plugin set that differs
     from the previous release's. Issue #48's F7 fix: a tendcf bump that
     changes `tools/` (today `bin/`), `schema/` or the projector, which
     ships as its own release with unchanged data. The
     operator-confirmed additions: a new `site.lock` input; any file that
     jobs B′ and B execute or build their environment from; the workflow
     files and signer configuration that define jobs A, B′ and B; a change
     of signer backend, enrolling or removing a hardware token or the Unix
     user included; and a lowering of `external_import.without_ai`.
     Following the rulings on forks and break-glass: a change to the tendcf
     repository or branch set the trust root declares, and a break-glass
     signing route with no merged pull request). The plugin-set rule exists because a
     plugin can be named now and change behaviour later, and the tendcf
     rule because one tendcf commit can change both the compiler and the
     gates that check it. The plugin set compared is the one the
     plugin-free job derives (plugin-layout §4, activation item 8), not the
     compiler's own report.
6. Sign `targets`, `snapshot`, `timestamp`; publish to the release store;
   record the release number against the site-private commit (a git note or
   a tag on site-private, after the fact, is fine — it is a label, not an
   input).

**Which tendcf rev the gate tools come from** (operator ruling 18;
planned, Step 6). Gates 3 to 5 run the schema lint, the projector and the
projection lint built from the **previous release's tendcf pin**, never
from the pin under test, so a tendcf bump is never judged by the tools it
brings. A bump that changes `tools/`, `schema/` or the projector therefore
ships as its own release with unchanged data: every host's goal file is
byte-identical to the previous release's (an empty diff for every host),
the old tools pass it, and it carries the ceremony marker (gate 5,
privileged change). Only a later release may use what the bump added, and
that release is checked by the new tools, which are by then the previous
release's pin (§4). A backward move across such a change is a pin-only
release too (§8 item 2). The first release has no previous release: its
gate tools are built from the tip of the protected branch that the site's
trust root declares, **resolved once, by job B′**; that rev is part of the
approval binding below and, once signed, is recorded in `targets.json`
`custom`. Job B and a token's local re-run build from that recorded rev,
not from the tip as it is by then, and a different rev means the approval
does not carry. Otherwise jobs B′ and B and a token's local re-run use the
same tools (plugin-layout §4, signing rule 5).

The signing key for `targets` lives on the signer, not in the compile
step; `root` stays offline (map §9.11, residue §14.4). Which machine the
signer is, is the subject of the next paragraph. A pull request runs
gates 1 to 5 and not 6, on throwaway runners that hold no key and no
secrets (planned, Step 6; nothing builds those runners today).

**Gates 3 to 6 run apart from plugin code** (map D46, amended 2026-11-13
by decisions D-c and D-d; **planned, Step 6**: no release pipeline
exists, so none of this is enforced today). Compiler plugins are trusted
build-time code, not sandboxed, and in-tree plugins ship inside the one
`tendcf` distribution, so "a separate environment" has to mean something
concrete:

1. **Interim, until the first real release:** a separate Unix user on the
   builder holds the key and the gate tools. It leaves persistence and
   tampering before signing open.
2. **The default before the first real release: two jobs, and a key-less
   copy of the second for pull requests.** Job A, on a throwaway runner
   with no secrets, compiles, runs gate 2, and uploads the goal-file bytes
   plus a digest manifest; it is the only job that runs plugins. Job B, in
   a protected signing environment, builds the gate tools from the
   previous release's tendcf pin (above) with hash-locked dependencies
   and without installing the
   `tendcf` package, runs gates 3 to 5 on the uploaded bytes, and signs
   exactly the digests it checked. Job B′ is job B without the key and
   without secrets: it runs gates 3 to 5 for a pull request, so that the
   preview a human approves is computed outside the plugins' reach.
3. **Signers in the first real release are one of n** (operator
   rulings): the CI key held as a GitHub environment secret (job B signs
   with it), which alone suffices; hardware tokens, optional, and at
   least two if any is enrolled; and a separate Unix user, opt-in and
   non-default, which may be enrolled for real releases (enrolling it
   lowers every release to its level, since compile and signer share one
   machine). Each enrolled signer may sign alone. `vps-hub` and the
   Hyades podman runner are not signers. Both token paths normally sign
   only the approved pull request's job A digests (merged tree equal to
   the approved head, binding unchanged): path 1 verifies a passing job B′
   run and signs its manifest, path 2 re-runs gates 3 to 5 itself in a
   plugin-free environment built from the previous release's pin with
   hash-locked dependencies; the path
   is recorded in `targets.json` `custom`. A break-glass route with no
   merged pull request is a privileged change, recorded in the same
   place, and it is one person's act (operator ruling 19): bounded only
   by the threshold-one trust in that signer. What each keeps and loses, and the rules of the signing
   environment, are in [`plugin-layout.md`](plugin-layout.md) §4.
4. **Signed is what was reviewed.** The pull-request run is job B′'s checks
   that need no job A output, then job A, then the rest of job B′. Reviewers approve job B′'s preview (which carries the import scan and
   AI review results). The approval is bound to the
   head commit, job A's run identity, the digest manifest, that preview and
   the number of the previous release it was diffed against (for the first
   release, which has none, the bootstrap tools' rev that job B′
   resolved). At merge, if
   the merged tree equals the approved head tree and none of those
   changed, job B takes the same artifacts by run identity, re-runs gates 3
   to 5, checks the digests and previews equal what was approved, and signs
   exactly those digests; otherwise the gates run again and the result is
   reviewed again. The approval record that carries this binding is produced
   by job B′ and verified by job B (a GitHub approval binds only a
   commit). Site-private gets branch protection (stale approvals
   dismissed on a new push, approval of the most recent push required, no
   administrator bypass). Until this exists, the pull request's preview
   diff is advisory, not a check.

Reasons and the cost shown to the operator are in
[`plugin-layout.md`](plugin-layout.md) §4. The gates bound the shape of
what a plugin renders, not its faithfulness to the Site Model: a preview
diff or `explain-hunk` attribution produced on the compile side (map D44)
is compiler output that inherits the plugins' trust, which is why only job
B′'s preview is reviewed.

## 7. Latency target (proposed; needs the operator)

#2 says no number has been picked. Proposal, to be confirmed or replaced.
(It was written for one CI run. The three-job split of §6, planned for
Step 6, adds job start-up and artifact transfer; the numbers were not
re-estimated for it.)

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
   diff. **When release N's tendcf pin lies across a change to `tools/`,
   `schema/` or the projector from the current pin, one commit cannot do
   it:** gate 5 refuses a release that moves the pin across such a change
   and also changes goal-file bytes (§6), and a revert changes both. The
   revert is then two releases, each one commit, in the order item 2
   gives. A revert across a `schema_version` bump is not offered (item 5).
2. **Partial rollback is the same mechanism**: move one input's pin back
   (the tendcf pin moves schemas, policy tree and compiler together, item
   5) or revert one host's entries, cut a release. There is no "roll back
   repo X" because no device ever depended on repo X directly. **A move
   of the pin across a change to `tools/`, `schema/` or the projector is a
   pin-only release, and combined with a data revert it is two releases,
   in an order that depends on which tools would refuse what:**
   1. *Data first, then the pin*, when the older tendcf tools would refuse
      the current data (it uses something they lack, a newer entry kind or
      field, say). Release one reverts the data under the current pin,
      checked by the current tools. Release two moves the pin back alone,
      byte-identical, with the ceremony marker.
   2. *Pin first, then the data*, when the current tools would refuse the
      older data (a lint tightened since). Release one moves the pin back
      alone, with unchanged goal files, checked by the current tools and
      carrying the marker. Release two reverts the data, checked by the
      older tools, which are by then the previous release's pin.
   3. *Neither order passes* when each side's tools refuse the other's
      data. That case cannot be split. The fix is to roll forward with a
      new tendcf commit or, as a last resort, break-glass (one person's
      act, §6, operator ruling 19).

   A long range is crossed one step at a time. A step that crosses a
   `tools/`, `schema/` or projector commit is a pin-only release; a step
   that crosses none may change bytes and go with data in one release. The
   tendcf authoring rule (§4) is what makes such a pin-only step exist
   across each such commit, forwards and backwards, as far as the goldens
   cover; where they miss, gate 5 refuses the pin-only release, which
   fails closed.
3. **A device that never took the bad release** computes the diff from its
   own baseline to M and finds it empty or small. Nothing special happens.
4. **A bad release that must be stopped before devices apply it** uses the
   emergency role (map D42): revoke that release's targets without consent,
   then cut M. Tightening never needs a local yes; the rollback content does.
5. **A bad tendcf commit** (schema, projector, bundle or compiler; ~~a bad
   tendcf or nix2cf commit~~ before map D46) is reverted in tendcf on its
   own schedule, or not at all; the fleet is fixed by the site-private
   pin going back, which is item 1 (two releases where item 2 says so).
   This is the whole point: the input
   repositories' history is never load-bearing for what devices run.
   Since map D46 one tendcf rev is the unit a site pins: taking or
   reverting a compiler fix also takes or reverts every `schema/` and
   `policy/` commit before it, and on a consented device a policy-tree
   change is a privileged-region hunk (map §9.8). That coupling is
   accepted. There is no maintenance-branch machinery for carrying a
   compiler fix alone; revisit when the first device that is not an
   operator host enrolls. Moving the pin backwards also rolls back every
   fix to `tools/`, `schema/` and the projector that landed after the
   target rev, so a backward pin move is a privileged change (§6, gate 5; planned, Step 6).
   A rollback across a `schema_version` bump is forbidden (operator
   ruling): the pin does not move backwards over a bump, and the fix is to
   roll forward with a new commit. A backward move within one
   `schema_version` is a privileged change, and across a change to
   `tools/`, `schema/` or the projector it is a pin-only release (item 2).

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
   together, accepted in §8 item 5.) The cost the merge also took: the
   compiler and the gates that check its output (`tools/`, `schema/`, the
   projector) now change in one commit, so the producer/checker
   independence two repositories gave is gone. One commit could change
   both, and rolling the pin back rolls back gate fixes. The mitigations
   are privileged-change rules in gate 5 (§6), the planned tendcf CI check
   that fails one commit changing the gates together with the compiler's
   goldens (§4, operator rulings 20 and 21) and `CODEOWNERS` for
   `schema/`, `tools/` and `policy/`, all planned.
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
- **The privileged-change checks of gate 5, the two-job signing split,
  promotion of the pull request's artifacts and branch protection on
  site-private** (§6; decisions D-c and D-d, issue #48) are Step 6 code
  and configuration, none of it built.
- **The ceremony marker** (§6 gate 5) carries the privileged-region
  hunks, the privileged changes, the override of a negative
  import result and the job A hold, so its mechanism is not a text
  convention in the commit (a pull request's author would write it): it
  is still to be chosen with the TUF ceremony (map §14.4), against these
  invariants. It is an attestation the pull request's author cannot
  produce for themselves; it is bound to one head commit and to the named
  changes it admits; and it is verified by jobs B′ and B, never by job A
  (plugin-layout §4, item 5).
- **The definitions that check a change come from outside it** (planned
  invariant; mechanism open). The hold on job A, the privileged-change
  detector, gate 1 and jobs B′ and B run from the protected ref's
  workflow, the trust-root declaration and the previous release's gate
  tools (§6; operator ruling 18), never from the tree under test; a
  change to them takes effect only after it merges under the old
  definition, with the marker. The approval record is produced by job B′
  and verified by job B. The site's trust root, where it lives and how
  gate 1 reads a branch's protection settings, are open as well, and so
  is who verifies a break-glass marker, since that route is one person's
  act (operator ruling 19; plugin-layout §4 and §7).
- **The inventory does not exist yet**, so `site.lock` has nothing to pin
  for a real fleet; the format is fixed now so that the real one (Step 6)
  needs no redesign. (~~so that nix2cf's `tendcf.lock` (Step 3) and the
  real one (Step 6) are the same thing~~: there is no compiler lock since
  map D46.)
- **The latency numbers in §7 are a proposal.** They become the requirement
  when the operator confirms them on #2.
