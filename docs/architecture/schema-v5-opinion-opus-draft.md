STATUS: recovered by acp-dispatch from the agent's final message (the agent did not write the report file)
Status: the evidence is collected, including Debian's `systemd` and `openssh-server` file lists and the systemd man pages. I'm making two last repo checks, then writing the design.# Q9 design: naming Debian-owned systemd units in the goal file (schema v5)

**Author:** Opus 5.5 (high), read-only design lead. Today's date: 2026-11-01. Next step: critique by astra and Fable.

**Bottom line:** recommend C4. Debian package claims cover units in the vendor directory, and a narrow name grammar covers everything else. This is not blocked, but the recommendation rests on the unverified assumptions in F.3.

**What I did not run.** This run had Read, Grep, Glob and web tools only, with no shell. That has four consequences:
- **The `ssh root@pastebin` probe was NOT run.** No real pastebin unit list backs this report. Unit names come from Debian's published file lists and the repo. The pastebin sketch in C.2 is illustrative.
- **`bm` and `book-kb` were NOT run.** I grepped the book's raw file for `dpkg` once with a bounded result, which gave one irrelevant hit. The design relies on no CFEngine semantics beyond repo code.
- **No regex or lint was executed.** Every regex claim and lint behaviour here comes from reading, not running.
- **The inbox file does not exist,** so there were no lead messages to answer.

**DECIDED (conservative, reversible):** the C.2 sketch uses `third-party` for `tendcf-execd.service` until E3 is answered.

---

## A. Problem and constraints

**The defect.** The key pattern (`goal-file.schema.json:499`) is reverse-DNS with at least two labels, ending `.*`. It cannot name `ssh.service`, `getty@.service`, `systemd-*` or `dbus-org.freedesktop.login1.service`, whose first label contains a hyphen. The `dpkg` writer (`:511`) therefore cannot be used for any real Debian unit.

**Findings the brief does not state:**
1. **It is not only dpkg.** pastebin runs `tendcf-execd.service`, written by the installer (`tendcf-install.sh:38-39`). v4 cannot declare it either: `tendcf-execd.*` fails on the hyphen, and `tendcf.execd.*` does not match that name.
2. **The canary overclaims today.** Its `supervision` domain is `comprehensive` with a single prefix (`deploy/linux/canary/goal-file.json:1`). Nothing notices, because no detector exists.
3. **The two definitions of "extra" disagree.**
   - `launchd-writers.schema.json:12`: a label matching no declared prefix.
   - `common.schema.json:117` (D16(d)): anything absent from the domain's description.
   - Under the first, `tendcf.rogue.service` beneath a cfengine prefix is clean. Under the second it is extra.
   - v5 must pick one; I pick D16(d) (C.3).
4. **Lint checks present services only** (`schema_lint.py:1536`). Once `ssh.service` is declarable, a tombstone on it passes lint. The adapter only looks in `/etc/systemd/system` (`tendcf_services.cf:240-245`), so the tombstone does nothing to a vendor unit.
5. **A name is not evidence.** systemd picks the effective file by load-path order, so `/etc/systemd/system` overrides `/usr/lib/systemd/system` (systemd.unit(5)). A file named `systemd-rogue.service` in `/etc` matches `systemd-*` but dpkg never wrote it.

**Constraints:**

| Constraint | Source |
|---|---|
| One writer per namespace, and nesting is refused whatever the writer | `architecture-DEFINITIVE-v3.md:188-190`, `schema_lint.py:1566-1575` |
| No hidden defaults; omission is the only spelling of none | `goal-file.schema.json:5`, `:295` |
| Fail-closed: closed kinds, unknown is structural failure | `goal-file.schema.json:311` |
| No whole-namespace wildcard unit-writer | D2, reconciliation `:21` |
| Forbidden kinds on nixos are listed per kind | R2, reconciliation `:30` |
| Extra-entry detection reports and never removes | 2026-08 reconciliation `:350-357` |
| The device has no Site Model, so detector data travels in the goal file | 2026-08 reconciliation `:457-462` |
| The bundle does not read writer data; `unit-writer` does not project | `projector.py:23-25`, `:123`; policy grep shows no `unit-writer` use |

---

## B. Candidate designs

### C1. Widened name grammar with `writer: dpkg` on names

- **Schema delta:** the C.1 grammar, with `dpkg` kept in the enum.
- **Overlap lint:** the rule in C.1.
- **Consent diff:** ordinary `unit-writer` hunks. Debian upgrades that rename or add units produce noise.
- **pastebin file:** `systemd-*`, 34 further exact names from the `systemd` package alone (hand count), and `ssh.service`, `ssh.socket`, `sshd-keygen.service`, `sshd@.service`, plus every other package's names.
- **Fail-closed:** weak. `systemd-*` absolves a rogue `/etc/systemd/system/systemd-x.service`. `ssh*` also swallows `sshuttle.service`, while `ssh.*` misses `sshd@.service`.
- **nixos/supervisor:** already forbidden on nixos. Each manager needs its own grammar.
- **Verdict:** rejected. It widens what can be said without saying anything checkable.

### C2. Host-level default writer, unverified

- **Schema delta:** a `default_writer: dpkg` field on `supervisor.host`.
- **Overlap lint:** none needed, since any declared prefix wins.
- **Consent diff:** one privileged hunk once. After that, nothing ever shows.
- **pastebin file:** one field.
- **Fail-closed:** **fails open.** A hand-written `/etc/systemd/system/evil.service` is reported as dpkg's while the domain still says `comprehensive`.
- **nixos/supervisor:** looks like D2 but is not. On nixos the claim is true by construction, because `/etc/systemd/system` is a read-only store symlink (`tendcf_services.cf:165-171`), and coverage is forced to `deliberately-unmanaged` (Q3, reconciliation `:301`). Debian has several writers and a writable `/etc`. This is the rejected whole-namespace wildcard under a new name.
- **Verdict:** rejected.

### C2′. Host-level fact, verified on the device

"Units in the vendor directory whose file a Debian package owns are dpkg's; everything else needs a name claim."

- **Schema delta:** a required `vendor_units` enum (`none`, `dpkg`) on `supervisor.host`, constrained per manager in `allOf`. It adds required content, so v5 needs a re-adoption (`goal-diff.schema.json:26`).
- **Overlap lint:** the tier partition in C.3, so no name-versus-package overlap exists.
- **Consent diff:** one privileged hunk. `apt install nginx` then produces **no signal at all**.
- **pastebin file:** one field, plus name claims for units outside the vendor directory.
- **Fail-closed:** good. An unowned or unverifiable unit is extra.
- **nixos/supervisor:** `const: none` on nixos, launchd and runit.
- **Verdict:** the credible runner-up. Choose it if E1 goes that way.

### C3. Explicit per-host list of exact names

- **Schema delta:** exact-name grammar only.
- **Overlap lint:** equality only.
- **Consent diff:** large and honest. An upgrade produces many ordinary hunks.
- **pastebin file:** 128 code-running entries from the `systemd` package alone (94 `systemd-*` plus 34 others, hand count; 266 paths in total), before any other package.
- **Fail-closed:** catches new names but not who wrote them, unless the detector also checks ownership.
- **nixos/supervisor:** forbidden on nixos.
- **Verdict:** rejected. It records the distro's file list in each signed goal file, with no gain over naming packages.

### C4. Package claims plus a narrow name grammar (RECOMMENDED)

Details are in C.

### C5. Honest coverage, no bump

- **Change:** set Debian's `supervision` to `not-yet-migrated`, which the architecture calls the correct day-one state (`architecture-DEFINITIVE-v3.md:950`).
- **Consent diff:** retreating from `comprehensive` is a privileged change (`schema_lint.py:1638`).
- **Fail-closed:** detection is off, and the file says so.
- **Verdict:** does not answer the ruling, because the unit namespace still can't be described. It is a valid stopgap if v5 slips.

---

## C. Recommendation: C4

### C.1 Schema delta (`goal-file.schema.json`, `schema_version: 5`)

**Widen the name grammar.** Exact names carry a type suffix and may be templates but never instances. Prefixes have a trailing star only, and it must follow a `.` or `-`.

```json
"unit_writer_map": {"propertyNames": {"type": "string", "maxLength": 128, "anyOf": [
  {"pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*@?\\.(service|socket|timer|path)$"},
  {"minLength": 4, "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*[.-]\\*$"}
]}}
```

**Add a kind** to `state_entries`:

```json
"unit-package": {"$ref": "#/$defs/unit_package_map"}

"unit_package_map": {
  "type": "object",
  "propertyNames": {"type": "string", "pattern": "^[a-z0-9][a-z0-9+.-]+$", "maxLength": 128},
  "additionalProperties": {
    "type": "object",
    "properties": {"state": {"const": "present"}, "writer": {"enum": ["dpkg"]}},
    "required": ["state", "writer"],
    "additionalProperties": false
  },
  "minProperties": 1
}
```

`writer` is explicit so the kind has no hidden default package manager. An rpm host would later widen the enum in a counted bump. The package-name pattern is from my memory of Debian Policy §5.6.1 and needs checking (F.3).

**Other schema changes:**
- **Writer enum:** remove `dpkg` from `unit_writer_entry.writer` and from `launchd-writers.schema.json:36`. It has one meaning now, following the Q7 precedent. No `contract_version` bump, per reconciliation `:105`.
- **`allOf` members:**
  - launchd and runit: `unit-writer` keys stay at the v4 pattern, and `unit-package: false`. The v4 pattern is a subset of the new grammar, so these hosts see no widening.
  - nixos: add `unit-package: false` to the per-kind list (`:85-89`, R2). `supervision` already has `entries: false`.
  - systemd: `patternProperties {"\\*$": {"properties": {"writer": {"const": "cfengine"}}}}` on `unit-writer`. A non-cfengine writer may name exact units only, because a blanket claim has no evidence behind it. `patternProperties` is already a recognised applicator (`schema_lint.py:1108`).

### C.2 Overlap rule and pastebin shape

A trailing star only keeps overlap decidable by plain string prefix, which is why mid-string globs are refused.

```python
def covers(key, name):
    return name.startswith(key[:-1]) if key.endswith("*") else name == key

def overlap(a, b):
    a_prefix, b_prefix = a.endswith("*"), b.endswith("*")
    if a_prefix and b_prefix:
        return a[:-1].startswith(b[:-1]) or b[:-1].startswith(a[:-1])
    if a_prefix:
        return covers(a, b)
    if b_prefix:
        return covers(b, a)
    return a == b
```

- This replaces `startswith` at `schema_lint.py:1571` and `:1586`. Reusing the old code would wrongly flag `foo.service` against `foo.service.*`, which do not overlap.
- Overlap stays global across domains and refuses even with the same writer (unchanged).
- Package ids are unique across domains, matching case 65's rule.
- An instance id (`getty@tty1.service`) does not match the exact template key `getty@.service` at lint time, so lint refuses it. Recorded as residue.

**Illustrative pastebin `supervision`.** `systemd` and `openssh-server` own units per Debian's lists. Their presence on pastebin, like the other placeholders, needs the probe:

```json
"unit-package": {
  "openssh-server": {"state": "present", "writer": "dpkg"},
  "systemd":        {"state": "present", "writer": "dpkg"},
  "<each further owning package from the probe>": {"state": "present", "writer": "dpkg"}
},
"unit-writer": {
  "tendcf-execd.service": {"state": "present", "writer": "third-party"},
  "tendcf.canary.*":      {"state": "present", "writer": "cfengine"}
}
```

### C.3 What the detector must do

The detector does not exist yet; this is its contract, stated in schema descriptions. Scope is `supervisor: systemd`, domain `supervision`, coverage `comprehensive`.

1. **Enumerate** system-manager unit files of type service, socket, timer and path (default; see E2).
2. **Resolve** each to its primary name and effective file, so `sshd.service` as an alias counts once as `ssh.service`.
3. **Vendor directory** (`/usr/lib/systemd/system`, including its `/lib` spelling): query dpkg using both spellings, because the database records one path and a query through the alias can fail. The unit is clean only if every owning package is declared in `unit-package`. Otherwise it is extra.
4. **Anywhere else** (`/etc/systemd/system`, `/usr/local/lib/systemd/system`, `/run/...`, generators): match against `unit-writer`.
   - No match is extra.
   - A match with `writer: cfengine` also requires an entry in `service` (the D16(d) reading).
   - A match with another writer is clean.
5. **Name claims never apply to the vendor directory; package claims never apply outside it.**
6. **Any failure** counts as extra, never as clean. That covers `dpkg-query` missing, unparseable output, or an unresolvable file. Reporting a distinct "unverifiable" reason is allowed.

**Why this keeps one writer per unit.** A unit has exactly one effective file, so exactly one claim type applies. Lint makes name claims unique. No overlap check between names and packages is needed, and none is possible at compile time, because the compiler has no dpkg database.

### C.4 Reasons

1. **"Comprehensive" stays true.** Everything present is described, and `apt install nginx` shows as extra until declared. That is the D16(d) skew signal. C2′ loses it.
2. **`writer: dpkg` becomes falsifiable.** "A Debian package's own unit" (`:510`) is something the device can check offline.
3. **The file stays small and stable.** It lists packages rather than files, so unit changes inside a package cause no churn. The count is unverified.
4. **No whole-namespace claim exists,** honouring D2.
5. **It fixes the non-Debian gap too.** `tendcf-execd.service` becomes declarable.
6. **The bump is small.** There is no required content and no device-trust change.

**Consent diff.**
- Hunks use the existing address `(supervision, unit-package, <pkg>)`. `goal-diff.schema.json:68-87` does not constrain kinds, so no diff schema shape changes.
- Ceremony is ordinary (`derive_ceremony_class`), the same as adding a prefix today.
- Rendering: add is "Debian package X may supply its own units; they stop being reported as extras". Remove is "writer declaration dropped; its units are reported as extras; nothing is stopped".

### C.5 Residue

1. A package claim covers **every** present and future unit of that package, including new daemons in an upgrade.
2. **A cfengine exact claim can shadow a vendor unit** (`ssh.service`). A tombstone then removes only the `/etc` file and the vendor unit reappears, disabled (`tendcf_services.cf:275-278`). Lint cannot see this.
3. **`dpkg` ownership is not integrity.** A modified file still counts as owned. Root can forge the database (E4).
4. **Instance ids** under an exact template key are refused by lint.
5. **Ubuntu snap units** (non-package files in `/etc`) can't use a third-party prefix. T1 is CI only, so a real need costs a later bump. Unverified.
6. **Multiple owners and diversions** make `dpkg -S` output awkward to parse. The prototype must cover them.
7. **User managers** (`/usr/lib/systemd/user`) are out of scope.
8. **Service management of an externally written unit** remains deferred (`linux-targets.md:36`). Comprehensive-domain services under non-cfengine writers stay refused (`schema_lint.py:1594`).
9. **The Site Model has no systemd writer registry.** `launchd-writers` is launchd-only, and `services.schema.json:109` has no writer data. nix2cf needs a source for these claims; that is a Step 6 item under Q8.

---

## D. Migration, negative cases, test plan

### D.1 Order

1. **Lead runs the probes** in F.3 and rechecks the falsifiers.
2. **Read-only classifier prototype** of C.3, run on pastebin and a ubuntu VM, before the shape freezes. `linux-targets.md:36` already calls for a bump "from an adapter prototype".
3. **Two frontier reviews** (`AGENTS.md:79-84`), then operator rulings on E.
4. **One schema PR** (below).
5. **nix2cf** follows through its version-sync CI check (reconciliation `:290`).

### D.2 Schema PR (enumerate from disk; these are not counts to trust)

- `const` 4→5 in goal-file, goal-diff and approval-record.
- Regenerate every hash, all goal-family overlays and `broken-bytes`. Case 13 claims 6; re-embed case 75.
- **Case 98 uses `writer: dpkg`.** Change it to `third-party`, or it also fires an enum finding and stops being a single-defect case.
- Replace the lint matchers (C.2). Add a rule that a comprehensive-domain tombstone needs a cfengine claim.
- Update descriptions: `state_entries`, `unit_writer_map`, `unit_writer_entry`, `service_map`, `trust_domain`, `supervisor_map`, and the prefix wording in `launchd-writers`. Update the prose at `projector.py:436`. `PROJECTING_KINDS` is unchanged, so projections stay byte-identical.
- Update counts: `EXPECTED_BROKEN` (`schema_lint.py:87`), the prose "eighty-three" (`:36`), `examples/broken/README.md` and the root README.
- Add a happy fixture `deploy/linux/canary/goal-file-debian.json` with its projection, wired into `check.py` `PAIRS` (`:31-39`).
- **Ceremony:** v5 adds no required content and no live file uses `writer: dpkg`, so a bare `version_bump` is valid (`goal-diff.schema.json:26`), and `derive_ceremony_class` calls it `baseline` (`schema_lint.py:1630-1631`). Declaring pastebin's units is a separate later diff.
- No device baseline exists, because the agent is unbuilt.

### D.3 Negative cases (113–132; series per reconciliation `:149-150`)

| # | Directory | Broken input | Class |
|---|---|---|---|
| 113 | `113-unit-writer-bare-star` | systemd; key `*` | schema (`propertyNames`) |
| 114 | `114-unit-writer-mid-glob` | key `ssh*.service` | schema (`propertyNames`) |
| 115 | `115-unit-writer-instance-key` | key `getty@tty1.service` | schema (`propertyNames`) |
| 116 | `116-unit-writer-no-separator` | key `ssh*` | schema (`propertyNames`) |
| 117 | `117-exact-under-prefix` | `tendcf.canary.service` with `tendcf.canary.*` | goal cross-file |
| 118 | `118-launchd-single-label-key` | launchd; key `ssh.service` | schema (`if/then`) |
| 119 | `119-runit-single-label-key` | runit; key `ssh.service` | schema (`if/then`) |
| 120 | `120-writer-dpkg-on-name` | `ssh.service` with `writer: dpkg` | schema (`enum`) |
| 121 | `121-third-party-prefix` | systemd; `local-*` with `third-party` | schema (`if/then`) |
| 122 | `122-service-exact-non-cfengine` | comprehensive; present `foo.service` under exact `third-party` | goal cross-file |
| 123 | `123-tombstone-no-cfengine-claim` | comprehensive; tombstone `ssh.service`, no cfengine claim | goal cross-file |
| 124 | `124-nixos-unit-package` | nixos; domain `packaging` with `unit-package` | schema (`if/then`) |
| 125 | `125-launchd-unit-package` | launchd with `unit-package` | schema (`if/then`) |
| 126 | `126-runit-unit-package` | runit with `unit-package` | schema (`if/then`) |
| 127 | `127-unit-package-bad-name` | id `Open_SSH` | schema (`propertyNames`) |
| 128 | `128-unit-package-wrong-writer` | `writer: cfengine` | schema (`enum`) |
| 129 | `129-unit-package-empty` | `unit-package: {}` | schema (`minProperties`) |
| 130 | `130-unit-package-tombstone` | `state: absent` | schema (`const`) |
| 131 | `131-unit-package-twice` | one package in two domains | goal cross-file |
| 132 | `broken-projection/132-unit-package-under-vars.json` | `vars/unit_package` | projection |

Take the exact class and location strings from a real lint run, and correct the README rows to match (as in reconciliation `:151-152`).

### D.4 Test plan (all through `~/ops/site-private/bin/bg`)

1. **Lint and canary:** `bin/schema_lint.py`, then `deploy/linux/canary/check.py`.
2. **Discrimination run** (F8, reconciliation `:184`): delete each new rule alone, and exactly its case goes red.
3. **Overlap truth table,** both directions:

   | Pair | Overlap? |
   |---|---|
   | `foo.service` / `foo.service.*` | No |
   | `foo.*` / `foo.bar.*` | Yes |
   | `foo-*` / `foo-bar.service` | Yes |
   | `foo.service` / `foo.socket` | No |

4. **Regression:** v4 keys `com.tendcf.caddy.*` and `tendcf.canary.*` still validate.
5. **Classifier prototype on a ubuntu VM (`TENDCF_TEST_SYSTEMD=1`).** Each row below must come out as stated:

   | Fixture | Expected |
   |---|---|
   | Rogue `/etc/systemd/system/systemd-rogue.service` | Extra |
   | Unowned file in the vendor directory | Extra |
   | Unit of an undeclared package | Extra |
   | Alias `sshd.service` | Counted once |
   | Shadow, mask and drop-in on `ssh.service` | Per E5 ruling |
   | `dpkg-query` removed from `PATH` | All vendor units extra, none clean |

6. **Linux gate:** the same prototype on pastebin, read-only, with results recorded.
7. **Policy:** `tests/policy/run.sh` unchanged, since the bundle does not read this data.

---

## E. Questions for the operator

Recommendations are mine; each needs a ruling.

1. **Should a newly installed Debian daemon surface?** C4 reports it until declared. C2′ never does. *Recommend C4.* Cost: a package-list hunk per new unit-owning package. The hazard is noise from upgrades, and it is report-only.
2. **Which unit types count?** *Recommend service, socket, timer, path.* Targets, mounts and slices don't start a program of their own. Generated and transient units outside the vendor directory would be reported as extra on every host that has them, and the probe will show how noisy that is.
3. **Who writes `tendcf-execd.service` and hand-made local units?** *Recommend a new writer value for the installer*, so `third-party` doesn't hide our own unit. Whether pastebin's application has a hand-written unit is unknown until the probe.
4. **Is the threat model accidents only, as R-S3-4 is for the hard checks?** *Recommend yes:* ownership via `dpkg -S`, with no hash check. `dpkg --verify` would add integrity, but not against root.
5. **Should an `/etc` drop-in or mask on a vendor unit count as a second writer?** *Recommend yes:* extra unless an exact name claim covers it. It adds noise on any host with local overrides.
6. **May cfengine shadow a vendor unit?** *Recommend allowing it through an exact key only* and rendering the consent line accordingly, accepting residue 2.
7. **Does anything ride with this bump?** Distro family stays deferred (Q5), as do `scope` and externally-written units (`linux-targets.md:36`). *Recommend v5 carries Q9 alone.*

---

## F. Evidence

### F.1 Repo claims (read, not executed)

| Claim | Location |
|---|---|
| Key pattern; map definition | `schema/goal-file.schema.json:494-503`, `:499` |
| Writer enum and `dpkg` meaning | `schema/goal-file.schema.json:509-511` |
| nixos member, per-kind ban | `schema/goal-file.schema.json:32-96`, `:85-89` |
| Manager flavour members | `schema/goal-file.schema.json:97-285` |
| Closed kinds | `schema/goal-file.schema.json:310-320` |
| `supervisor_map` | `schema/goal-file.schema.json:630-644` |
| No defaults; omission rule | `schema/goal-file.schema.json:5`, `:295` |
| Site Model writers and label scope | `schema/launchd-writers.schema.json:12`, `:30-36` |
| Site Model systemd unit pattern | `schema/services.schema.json:109` |
| D16(d) definition | `schema/common.schema.json:117` |
| `extra_entries` is a counter | `schema/report-row.schema.json:86-90` |
| Diff hunks and `version_bump` rule | `schema/goal-diff.schema.json:26`, `:68-87` |
| Present-only collection | `bin/schema_lint.py:1536` |
| Duplicate, nesting, cfengine rules | `bin/schema_lint.py:1541-1549`, `:1566-1575`, `:1581-1599` |
| Ceremony derivation | `bin/schema_lint.py:1630-1639` |
| Case count; applicators | `bin/schema_lint.py:87`, `:36`, `:1105-1116` |
| Trust-region property test extends itself | `bin/schema_lint.py:1922-1947` |
| Projection scope | `bin/projector.py:23-25`, `:122-123`, `:431-439` |
| Adapter touches only `/etc/systemd/system` | `policy/tendcf_services.cf:240-245`, `:256`, `:275-278` |
| NixOS read-only guard | `policy/tendcf_services.cf:165-171` |
| Canary goal file, projection pairs | `deploy/linux/canary/goal-file.json:1`, `deploy/linux/canary/check.py:31-39` |
| Passthrough fixture | `deploy/linux/passthrough/goal-file.json:1` |
| Installer's unit | `deploy/linux/tendcf-install.sh:38-39` |
| Unit on pastebin | `docs/handoffs/HANDOFF_tendcf-linux-targets-20261029_linux-milestone-through-nixos-stage-c_2026-10-31_f34c.md:38` |
| Case 98 uses `dpkg` | `examples/broken/98-nixos-unit-writer-elsewhere/goal-file.json:1` |
| Existing writer cases | `examples/broken/README.md:83-84`, `:259-263` |
| Rulings D2, Q7, R2, R3, Q9 | `docs/architecture/schema-v4-reconciliation-2026-10-31.md:21`, `:29-31`, `:33` |
| No-bump precedent; re-adoption rule | same file `:105-106` |
| Case numbering, F8 | same file `:149-152`, `:184` |
| nix2cf version check; residue | same file `:290`, `:300-301` |
| Reports, not removes; registry travels | `docs/architecture/goal-file-schema-reconciliation-2026-08-15.md:350-357`, `:457-462` |
| One writer per prefix; D36; day-one state | `docs/architecture/architecture-DEFINITIVE-v3.md:188-190`, `:1027`, `:950` |
| T3 facts; bump from a prototype | `docs/architecture/linux-targets.md:12`, `:36`, `:39` |
| Earlier flags of this defect | `docs/architecture/schema-v4-opinion-opus-draft.md:267`, `docs/architecture/schema-v4-opinion-fable.md:80` |
| Two frontier reviews | `AGENTS.md:79-84` |

### F.2 External (fetched this run)

| Claim | Source |
|---|---|
| `systemd` on trixie: 266 unit-directory paths, all `/usr/lib`, including aliases and `.d` drop-ins. The 128 count is **my hand count, not machine-checked** | [Debian filelist: systemd](https://packages.debian.org/trixie/amd64/systemd/filelist) |
| `openssh-server` owns `ssh.service`, `ssh.socket`, `sshd-keygen.service`, `sshd@.service`, `rescue-ssh.target` | [Debian filelist: openssh-server](https://packages.debian.org/trixie/amd64/openssh-server/filelist) |
| Name characters, load-path order, aliases, templates, drop-ins | [systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) |
| `list-unit-files` states, including `alias`, `generated`, `transient`, `masked` | [systemctl(1)](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) |
| `dpkg-query -S` fails through a `/lib` alias (reported for libc, not unit files) | [debian-glibc, Aug 2025](https://lists.debian.org/debian-glibc/2025/08/msg00036.html), [debian-user, Apr 2024](https://lists.debian.org/debian-user/2024/04/msg00167.html) |

### F.3 Unverified, and what would change the design

| Unverified | Check | If false |
|---|---|---|
| pastebin's real unit list and tiers | `ssh root@pastebin.xvm.mit.edu 'systemctl list-unit-files --no-legend --no-pager'` (the one allowed command) | Sketch changes. If most units are outside the vendor directory, C4's benefit shrinks. |
| Vendor-directory units are dpkg-owned on pastebin | Needs a second read-only command, not covered by the brief's allowance: `dpkg -S` per file | Many unowned files would make C4 and C2′ noisy. |
| Primary name and effective file resolve for templates and non-loaded units | Prototype; I recall `systemctl show` may reject a bare template name | C.3 step 2 needs another method, such as reading the load path. Schema shape is unaffected. |
| Number of owning packages | Probe | Reason 3's "small" claim weakens. |
| Generated and sysv units on Debian 13 | Probe | E2's noise estimate changes. |
| Ubuntu snap behaviour | CI VM | Residue 5 only. |
| Debian package-name pattern | Debian Policy §5.6.1, not fetched | Regex changes. |
| All regexes and lint behaviour | Run the lint | Corrections before the PR. |
| Book coverage of this question | `bm` and `book-kb` not run | The design relies on no book claim. |

DONE
