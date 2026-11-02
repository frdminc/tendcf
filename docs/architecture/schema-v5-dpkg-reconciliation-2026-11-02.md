# Schema v5: Debian package claims and the unit namespace (Q9, 2026-11-02)

Status: **spec, rulings taken; not yet frontier-reviewed.** This document is the contract
the v5 slices implement. It changes no schema, lint or fixture. It supersedes its three
inputs, which stay frozen as written: [the Opus 5.5 draft](schema-v5-opinion-opus-draft.md),
the [astra review](schema-v5-opinion-astra.md) ("unsound as specified") and the
[Fable 5.1 review](schema-v5-opinion-fable.md) ("sound with changes"). Where an input is
wrong, §8 says so; the inputs are not corrected in place. Q9 is the open item
[schema v4](schema-v4-reconciliation-2026-10-31.md) left in its §1 and §7.

**What was run for this document (2026-11-02), and what was not:**
1. **One read-only pastebin probe** (§2.4). Its `dpkg-query` half answered for 2 units only, so most package attributions are **inferred from Debian's published index, not read from pastebin's database**.
2. **An assembled v5 schema, in memory, outside the repository.** It applied §2.1 to the real schemas and used the real `schema_evidence` from `bin/schema_lint.py`. The goal-family cross-file rules of §2.2 were prototyped beside it. Every schema regex, class token and overlap row below comes from that run unless marked. Case 145 was not run.
3. **The live v4 lint and a real `cf-agent`,** for the hazard in §2.2(4).
4. **Not run:** no detector or classifier exists, and nothing in §3 has run on a systemd host. The `systemctl show` and `dpkg-query` behaviour §3 depends on is listed in §3.5 for slice S1 to prove.

## 1. Rulings (djbclark, 2026-11-02)

| # | Ruling |
|---|---|
| R1 | Package claims (C4), with both reviews' fixes. (Declaring a dpkg package covers the units it ships; a new unit inside a declared package does not surface; a new package does.) |
| R2 | As Fable proposes: service, socket, timer and path files count; generated units are judged via their source (SourcePath); transient units are out of scope (residue). A local drop-in or mask on a vendor unit is clean only when an exact non-cfengine name claim covers the unit name, otherwise "two-writers"; a cfengine claim on a name whose vendor fragment exists is always "two-writers" (shadowing is the deferred externally-written-unit feature). |
| R3 | Accept all four: (a) new writer value `tendcf-install` for tendcf's own installed unit (tendcf-execd.service); (b) threat model is accidents only, as R-S3-4: ownership from the dpkg database, no file-hash verification; (c) one unit namespace per host: detection runs across all domains' claims, a unit is extra only if no claim in any domain covers it; (d) a scan that cannot enumerate completely reports "incomplete", never zero extras. |

## 2. Schema deltas

All three goal-family schemas (`goal-file`, `goal-diff`, `approval-record`) change
`schema_version` from `"const": 4` to `"const": 5`. v5 carries Q9 alone. Distro family, `scope` and
externally-written units stay deferred ([linux-targets](linux-targets.md) row 4; v4 Q5).

**Terms used from here on.** An *artifact* is a file the manager reads for a unit: a fragment, a drop-in, a link (alias or mask), or a generated unit's source. *Owned* means the dpkg database names at least one package for that path. A *vendor fragment* is an owned fragment for that unit name in any load-path directory, including one a local file hides. *Local* means not owned. A package-shipped mask or drop-in is therefore **not** local, wherever it sits (Fable F1).

### 2.1 `goal-file.schema.json`

1. **One key regex, not `anyOf`** (Fable F7). Replace the `unit_writer_map.propertyNames` pattern:

   ```json
   "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._-]*@?\\.(?:service|socket|timer|path)|[A-Za-z0-9._-]+[.-]\\*)$"
   ```

   - **Exact keys** carry one of the four type suffixes and may be templates (`getty@.service`), never instances.
   - **Prefix keys** have a trailing star only, directly after `.` or `-`.
   - **Run:** accepts `ssh.service`, `sshd@.service`, `dbus-org.freedesktop.login1.service`, `tendcf-execd.service`, `e2scrub_all.service`, `systemd-*`, `tendcf.canary.*`, `com.tendcf.caddy.*`, `ab.*`. Rejects `*`, `ssh*`, `ssh*.service`, `getty@tty1.service`, `com.tendcf.caddy`, `foo.target`, `foo.mount`, `a.*`, `a-*`, `.service`, `@.service`, `-foo.service`, `foo@bar@.service`. All 230 in-scope names on pastebin match.
   - **No length cap.** v4 has none on these keys, and a shared cap would narrow launchd and runit (astra A6).
2. **Add the kind** to `state_entries`: `"unit-package": {"$ref": "#/$defs/unit_package_map"}`, with:

   ```json
   "unit_package_map": {
     "type": "object",
     "propertyNames": {"type": "string", "pattern": "^[a-z0-9][a-z0-9+.-]+$"},
     "additionalProperties": {
       "type": "object",
       "properties": {"state": {"const": "present"}, "writer": {"enum": ["dpkg"]}},
       "required": ["state", "writer"],
       "additionalProperties": false
     },
     "minProperties": 1
   }
   ```

   The name pattern is Debian Policy 5.6.1 as fetched: lower case, digits, `+`, `-`, `.`, at least two characters, alphanumeric first. The description must state these semantics (Fable F10):
   - A declared package that is not installed is not a finding, like a prefix with no units.
   - `state: present` means the claim is present, not the package.
   - The id is a **binary** package name. Units of one source are split across binaries and each must be named: on pastebin `systemd`, `udev`, `systemd-timesyncd` and `systemd-zram-generator`, and `dbus` with `dbus-system-bus-common`.
   - The id covers that package on every architecture (§3.3).
   - It is detector data and does not project. It is not the `package` kind that `state_entries` names as an omission: it says who may write units, not what should be installed.
3. **Writer enum.** In `unit_writer_entry.writer`, remove `dpkg` and add `tendcf-install` (R3a): `["cfengine", "mise", "nix-darwin", "tendcf-install", "homebrew", "apple", "third-party"]`. A package claim is the only spelling of dpkg ownership, following the Q7 precedent. **Two writers on one name stay expressible in the file:** `"ssh.service": {"writer": "cfengine"}` with `"openssh-server": {"writer": "dpkg"}` validates and lints clean (run), because no lint can know what a package ships. The device reports it (§3.4; Fable F4).
4. **`allOf` members,** inside each `then` under `domains.additionalProperties.properties.entries.properties`:
   - **nixos:** add `"unit-package": false` to the per-kind list (R2 of v4).
   - **launchd and runit:** `"unit-package": false`, and `unit-writer` keeps the complete v4 language (astra A6), with no `tendcf-install`:

     ```json
     "unit-writer": {
       "propertyNames": {"pattern": "^[a-z][a-z0-9]*(\\.[A-Za-z0-9][A-Za-z0-9_-]*)+\\.\\*$"},
       "additionalProperties": {"properties": {"writer": {"not": {"const": "tendcf-install"}}}}
     }
     ```

     Run: 200,000 generated v4 keys all match the new base regex, so the base does not narrow them. `tendcf-install` is excluded because the installer is Linux-only (`deploy/linux/tendcf-install.sh`).
   - **systemd:** a blanket claim has no evidence behind it, so a prefix belongs to cfengine alone:

     ```json
     "unit-writer": {"patternProperties": {"\\*$": {"properties": {"writer": {"const": "cfengine"}}}}}
     ```
5. **Descriptions** to update: `state_entries`, `unit_writer_map`, `unit_writer_entry`, `service_map`, `trust_domain`, `supervisor_map`. `state_entries` must say that "comprehensive" on a systemd host now means **described by name or by ownership, for the four unit types** (Fable's case against C4; astra A9).

### 2.2 Lint (`bin/schema_lint.py`, `check_goal_file_cross_file`)

1. **Replace the two `startswith` matchers** (`:1571`, `:1586`). Reusing them would wrongly flag `foo.service` against `foo.service.*`. The rule, as run:

   ```python
   TEMPLATE = re.compile(r"^(.+@)\.(service|socket|timer|path)$")

   def covers(key, name):
       if key.endswith("*"):
           return name.startswith(key[:-1])
       if name == key:
           return True
       m = TEMPLATE.match(key)
       if m:
           anchor, suffix = m.group(1), "." + m.group(2)
           return name.startswith(anchor) and name.endswith(suffix) and len(name) > len(anchor) + len(suffix)
       return False

   def overlap(a, b):
       a_star, b_star = a.endswith("*"), b.endswith("*")
       if a_star and b_star:
           return a[:-1].startswith(b[:-1]) or b[:-1].startswith(a[:-1])
       if a_star:
           m = TEMPLATE.match(b)
           return b.startswith(a[:-1]) or bool(m and m.group(1).startswith(a[:-1]))
       if b_star:
           return overlap(b, a)
       return a == b
   ```

   A template key covers its instances (Fable F5). `covers` matches services and `overlap` compares claim pairs; they are not interchangeable (astra B1). Literal overlap is not semantic overlap: it says nothing about aliases, package contents or layered configuration (astra B2). That is the device's job (§3).
2. **Overlap truth table** (run, in both directions). There is no `tests/**/*.py` harness in this repository, so this joins the in-lint self-tests (`check_claim_selftest`, `check_projector_properties`):

   | Pair | Overlap? |
   |---|---|
   | `foo.service` / `foo.service.*` | No |
   | `foo.*` / `foo.bar.*` | Yes |
   | `foo-*` / `foo-bar.service` | Yes |
   | `foo-*` / `foo-w@.service` | Yes |
   | `fo-*` / `foo@.service` | No |
   | `foo.service` / `foo.socket` | No |
   | `foo@.service` / `foo@.socket` | No |
   | `foo@.service` / `foo.service` | No |
   | `tendcf.canary.*` / `tendcf-execd.service` | No |
3. **Package ids are unique across domains,** as a new rule on the model of case 65 (astra A8). It is not covered by the unit-writer rule.
4. **Tombstone rule, needed today** (Fable F3, astra A3). Every `state: absent` service in `supervision`, in any coverage that admits entries, must be covered by a same-domain `unit-writer` key with `writer: cfengine`.
   - `supervision` is the one projecting domain (`bin/projector.py`, `PROJECTING_DOMAIN`). The adapter's teardown checks neither coverage nor writer (`policy/tendcf_services.cf:240-245`, `:275-278`).
   - **Run against the live v4 lint:** the canary goal file plus `"sshd.service": {"state": "absent"}` raises no schema error and no cross-file finding, under `comprehensive` and under `not-yet-migrated`. `sshd.service` exists on pastebin as an alias (§2.4). If its link is in `/etc/systemd/system`, as Fable says and pastebin's probe does not show, teardown would run `systemctl disable --now` on it.
   - **Run against a real `cf-agent`** (3.29.0a Mac dev build): `fileexists` is true for a plain file, a symlink, a symlink to `/dev/null` and a dangling symlink, while `isplain` is true only for the plain file. The book names `fileexists` (ch. 27) and not `isplain`, and covers 3.12 only, so this is from running.
   - This rule does not make removal safe by itself. See §7 item 3.
5. **`tendcf-install` names one unit.** A `unit-writer` entry with that writer must have the key `tendcf-execd.service`. Otherwise the value is a second `third-party`.
6. **Unchanged:** a present comprehensive-domain service still needs a same-domain cfengine claim (`:1577-1599`, through `covers`). Duplicate and overlap checks stay global. Comprehensive-domain services under another writer stay refused, because managing an externally written unit stays deferred.

### 2.3 Other schemas

1. **`launchd-writers.schema.json`:** remove `dpkg` from the writer enum. No live instance uses it, and `contract_version` stays 1 on the v4 §2.2 no-bump precedent. Reword `:12` to the D16(d) reading: an extra is anything absent from the domain's description, so `launchd-writers` and `common.schema.json:117` stop disagreeing (draft finding A.3).
2. **`report-row.schema.json`** (R3d, Fable F10d). `extra_entries` is a required counter today and cannot say "not known". In `domain_coverage_row`:

   ```json
   "extra_scan": {"enum": ["complete", "incomplete", "not-run"]},
   "two_writers": {"type": "integer", "minimum": 0},
   "unmet_absence": {"type": "integer", "minimum": 0},
   "if": {"properties": {"extra_scan": {"const": "complete"}}, "required": ["extra_scan"]},
   "then": {"required": ["extra_entries", "two_writers", "unmet_absence"]},
   "else": {"properties": {"extra_entries": false, "two_writers": false, "unmet_absence": false}}
   ```

   `extra_scan` joins `required` and `extra_entries` leaves it. **An incomplete scan cannot carry a zero, because it cannot carry a count.** `report-row` has no version axis, and nothing writes rows yet. This data shape was not put to the operator; see §7 item 13.
3. **`goal-diff.schema.json`:** no shape change. Its hunks do not enumerate kinds (`:68-87`), so `(supervision, unit-package, <pkg>)` is an ordinary address. Ceremony stays `ordinary` (`derive_ceremony_class`). Rendering: an add reads "Debian package X may supply its own units; they stop being reported as extras", and a remove reads "writer declaration dropped; its units are reported as extras; nothing is stopped".
4. **The projection is unchanged.** `PROJECTING_KINDS` stays `service` and `interlock`, so existing projections stay byte-identical. Report-only classification does not prevent competing writes, and the spec must not be read as saying it does (astra B6).

### 2.4 Pastebin's v5 `supervision` domain, from real data

The one authorized probe, run 2026-11-02:

```
ssh root@pastebin.xvm.mit.edu 'systemctl list-unit-files --no-legend --no-pager; dpkg-query -S /lib/systemd/system/*.service 2>/dev/null | head -200'
```

**What came back.** 332 unit-file rows, and **two** ownership lines:

```
tailscale: /lib/systemd/system/tailscale-wait-online.service
tailscale: /lib/systemd/system/tailscaled.service
```

Every other vendor service got no answer. That is what literal path lookup predicts when the database records the `/usr/lib` spelling. `dpkg-query -S` performs a "literal path lookup" for a path with no wildcard (man page), and the remote shell had already expanded the glob. The suppressed stderr hides the misses, so that reading is not proven by this probe. It is why §3.3 queries both spellings: **one host's database holds both.**

| Unit type | Rows | R2 |
|---|---|---|
| service | 186 | judged |
| timer | 22 | judged |
| socket | 20 | judged |
| path | 2 | judged |
| target, mount, scope, slice, swap, automount | 79, 10, 5, 5, 2, 1 | out of scope (§7 item 5) |

Among the 230 judged names, states are static 128, enabled 48, disabled 33, alias 10, masked 6, generated 2, enabled-runtime 2, indirect 1. All 5 `transient` rows are `session-*.scope`, so none reaches the detector anyway.

**Attribution method.** Only tailscale is measured. For the rest, `dists/trixie/main/Contents-{all,amd64}.gz` from `deb.debian.org` maps each name to the Debian packages that ship it under `usr/lib/systemd/system/`, or under `etc/init.d/` for a generated unit. **This says what Debian ships under that name, not what is installed or who wrote pastebin's file,** and it covers `main` only. Every line below is a candidate for S1 to confirm.

**All 230 names are accounted for:** 204 package tier, 22 name claims, 1 `tendcf-install`, 1 under the `cfengine` prefix, 2 enable-created aliases. The sketch below (37 packages, 24 name claims) validates against the assembled v5 schema and raises no cross-file finding (run).

**`unit-package`, each `{"state": "present", "writer": "dpkg"}`:**

| Package (judged names) | Evidence |
|---|---|
| `tailscale` (2) | **measured** |
| `systemd` (128), `udev` (8), `sysstat` (7), `e2fsprogs` (5), `apt` (4), `atop` (4), `openssh-server` (4), `apt-listchanges` (2), `certbot` (2), `console-setup-linux` (2), `dpkg` (2), `logrotate` (2), `lynis` (2), `man-db` (2), `plocate` (2), `systemd-timesyncd` (2), `util-linux` (2), `apparmor` (1), `cron` (1), `dbus` (1), `dbus-system-bus-common` (1), `fail2ban` (1), `grub-common` (1), `libpam-modules-bin` (1), `nftables` (1), `nginx-common` (1), `nullmailer` (1), `openafs-client` (1), `rsync` (1), `systemd-zram-generator` (1), `tinyproxy` (1), `unattended-upgrades` (1) | index, single owner |
| `ifupdown` (4) | index; `ifup@` and `networking` have alternatives (`ifupdown2`, `ifupdown-ng-compat`), but `ifupdown-pre` and `ifupdown-wait-online` are `ifupdown` alone |
| `sudo` (1) | index; `sudo-ldap` ships the same name, a guess between the two |
| `exim4-base` (1) | index, via `etc/init.d/exim4`. `exim4.service` is `generated`, yet the index has `exim4-daemon-*` shipping that fragment, so those daemons look absent, and `nullmailer` is enabled. **A leftover conffile of a removed package is one reading; unproven** (§3.5) |
| `zephyr-clients` (1) | index, via `etc/init.d/zhm`; `zhm.service` is `generated` |

**`unit-writer`:**

```json
"tendcf-execd.service": {"state": "present", "writer": "tendcf-install"},
"tendcf.canary.*":      {"state": "present", "writer": "cfengine"}
```

plus 22 exact `third-party` candidates, the names Debian's `main` index does not ship:

```
athena-src-update.service  athena-src-update.timer  athena-tgt-renew.service  athena-tgt-renew.timer
et.service  failure-mail@.service  oauth2-proxy.service  wastebin.service
pb-resource-check.service  pb-resource-check.timer  pb-wastebin-dump.service  pb-wastebin-dump.timer
pbstats-sample.service  pbstats-sample.timer  pbstats-weekly.service  pbstats-weekly.timer
tinyproxy-searxng.service  tinyproxy-vpsrelay.service  screen-cleanup.service
determinate-nixd.socket  nix-daemon.service  nix-daemon.socket
```

Each of those is a package claim instead if `dpkg` owns it, as it does tailscale, which is also absent from `main`. `nix-daemon.*` is in the index (`nix-setup-systemd`), but `determinate-nixd.socket` beside it suggests an installer wrote them; that is a guess.

**What the real data changes:**
1. **The draft's falsifier does not fire.** 204 of 230 names fall in the package tier by index, so C4 is not noise-dominated by units outside it.
2. **"Small" means 37 packages against 230 names,** not a handful (Fable F10c).
3. **Fable's alias rule needs ownership first.** 8 of the 10 `alias` rows are in the index as shipped links (`autovt@`, `kmod`, `procps`, `udev`, and the `hostname1`, `locale1`, `login1` and `timedate1` D-Bus names). For seven of them the usual target is `static` in the same probe (not `autovt@`, whose usual target `getty@` is enabled; the link targets were not read on the host). `systemctl` defines `static` as having no provision for enabling in `[Install]`, so an `Alias=` test would call those seven extra. Only `sshd.service` and `dbus-org.freedesktop.timesync1.service` are not in the index, so those two look enable-created (§3.2).
4. **"Mask" needs ownership first too.** 5 of the 6 masked names are in the index as shipped (`cryptdisks`, `cryptdisks-early`, `hwclock` and `x11-common` under `systemd`; `sudo`). They are package-tier files, not R2's local masks. `screen-cleanup.service` is the exception: not in the index, so it needs a name claim. `dpkg-query -S` "will not list extra files created by maintainer scripts" (man page), which is one way to get there.

**Not visible in this probe:** drop-ins, the location of any file, shadowed vendor fragments, and the real owner of anything but tailscale. A local drop-in on any vendor unit adds a name claim. A local copy of a vendor fragment cannot be made clean at all (§3.4).

## 3. Detector contract

No detector exists; this is what one must do. It reads and reports, and it never removes (reconciliation 2026-08-15; the tombstone is the only actuated removal path). It is threat-modelled for accidents only (R3b): database ownership, no hash verification. Where it runs is not ruled (§7 item 13); the contract does not depend on it.

### 3.1 Gate

| Condition | `extra_scan` |
|---|---|
| `supervision.coverage` is not `comprehensive`, or `supervisor` is not `systemd` | `not-run` |
| Gate passes but the manager is unreachable (`/run/systemd/system` absent) | `incomplete` |
| Gate passes but the dpkg database cannot be queried | `incomplete` |
| Every in-scope unit resolved with evidence | `complete` |

`supervisor: systemd` does not establish that dpkg exists (astra B4). Other domains' `coverage` switches nothing on or off (Fable F6). Their rows say `not-run`, and unit findings appear on the `supervision` row only.

**The registry is the union of every domain's `unit-writer`, `unit-package` and `service` entries** (R3c). A claim in a non-comprehensive domain counts. This reads service entries across domains, where the lint in §2.2 stays same-domain: lint keeps the stricter authoring rule, and the device judges one namespace.

### 3.2 Enumerate through the manager, never by walking directories

1. **Names.** `systemctl list-unit-files` and `systemctl list-units --all`, for the four types (R2). Then, per unit: `Id`, `Names`, `LoadState`, `UnitFileState`, `FragmentPath`, `SourcePath`, `DropInPaths`.
2. **Provenance is recorded before anything is resolved** (astra A2). Keep the lookup name and the link path; a mask resolved to `/dev/null` has lost its identity.
3. **Not artifacts:** `.wants/` and `.requires/` entries are dependencies, never classified (Fable F2; §7 item 6). Transient units are out of scope (R2).
4. **Artifacts of a unit,** each classified on its own:
   - the effective fragment, or for `UnitFileState=generated` its `SourcePath` (R2). An empty `SourcePath` on a generated unit is unverifiable;
   - every `DropInPaths` entry, which covers template, instance and type-wide scopes;
   - a mask;
   - an alias link: see below;
   - any same-named file in a later load-path directory. Only this step looks at directories, for an exact name from the manager's enumeration, because `FragmentPath` shows the winner only. It is what makes a shadowed vendor fragment visible.
5. **A link's final target is an artifact too,** except `/dev/null`. An owned link to an unowned target does not launder the target (astra A5).
6. **Aliases.** An owned alias link is an owned artifact (§2.4 item 3). An unowned one is clean only if its name appears in the target fragment's `[Install] Alias=`; any other name is extra. This is what stops `evil.service -> ssh.service` collapsing into `ssh.service` (Fable F2). A clean alias counts as its target, once.

### 3.3 Ownership decides the tier

For each artifact, ask the database about the path under both the `/usr/lib` and `/lib` spellings (§2.4), and take the union (Fable F1).

| Answer | Treatment |
|---|---|
| Lookup succeeded, one or more owners | Package tier |
| Lookup succeeded, no owner | Name tier. Not a failure (astra A5 said unverifiable; §8) |
| Lookup failed, output unparseable, or a diversion the detector cannot resolve | Unverifiable |

Owner names may carry an architecture qualifier. `unit-package` ids cover every architecture of a package: `systemd:amd64` maps to `systemd` by this explicit rule, not by a silent strip (astra A5). Database ownership establishes recorded provenance. It does not establish integrity or authorship (R3b).

### 3.4 Verdict per unit

Take the first row that applies, top down, across the unit's artifacts:

| # | Condition | Verdict |
|---|---|---|
| 1 | Any artifact is unverifiable | scan `incomplete` |
| 2 | A cfengine claim covers the name and a vendor fragment exists (R2; Fable E6) | `two-writers` |
| 3 | A local fragment hides a vendor fragment, whatever the claim (Fable F4: R2 admits only drop-ins and masks) | `two-writers` |
| 4 | A local drop-in or mask on a vendor unit, with no exact non-cfengine claim on the name (R2). A template key counts as exact for its instances | `two-writers` |
| 5 | A local drop-in or mask under a cfengine claim, with no vendor fragment (CFEngine renders fragments only) | `two-writers` |
| 6 | A cfengine-claimed local fragment whose service entry is a tombstone (astra A3) | `unmet-absence` |
| 7 | A cfengine-claimed local fragment with no service entry in any domain (D16(d)) | `extra` |
| 8 | An owned artifact with any owner not in `unit-package`, co-owners included (astra A5) | `extra` |
| 9 | A local artifact no claim in any domain covers (R3c) | `extra` |
| 10 | Otherwise | `clean` |

Verdicts count into `two_writers`, `unmet_absence` and `extra_entries`. A name claim that covers nothing, and a package claim that owns nothing, are not findings. **`extra_entries` keeps D16(d) as its meaning; the two new counters keep skew from being reported as a bare extra** (astra A3).

**Incomplete (R3d).** One unverifiable artifact or a failed enumeration makes the whole scan `incomplete`: no `extra_entries`, `two_writers` or `unmet_absence` on the row. The per-unit evidence goes to the detector's log line, because `report-row` is a counter row. A partial count is never reported as a total.

### 3.5 Behaviour S1 must prove before the shape freezes

None of this has been run. The draft's F.3 and the reviews rest on recall here too:
1. `systemctl show` on a bare template name (the draft recalls a refusal) and on non-loaded units.
2. `FragmentPath` on a masked unit: the link path or `/dev/null`.
3. `SourcePath` on a sysv-generated unit. The D-Bus API documents the property; its value on `exim4.service` and `zhm.service` is unread.
4. `dpkg-query -S` for a conffile whose package is removed but not purged (pastebin's `exim4` candidate). The contract's reading is that the database's answer stands whatever the package's status, so a declared `exim4-base` makes the unit clean. Change that here if the prototype shows otherwise.
5. `dpkg-query -S` output for multiple owners, architecture qualifiers and diversions, and its exit status with no match.
6. Whether a type-wide drop-in such as `/etc/systemd/system/service.d/` appears in every unit's `DropInPaths`. If it does, each covered unit is `two-writers`, which is correct and loud.

## 4. Migration (one PR, S2)

Enumerate from disk; these counts are not a substitute. Corrections to the draft are in §8.

1. **Ceremony** (astra A8). A bare `version_bump` is valid only for a baseline that remains valid at v5 and whose rendered content changes solely in `schema_version`. Audit each one for retired `dpkg` claims and tombstone ownership, and re-adopt otherwise. **Audit, run:** at v5 `examples/goal-file.json`, `goal-file-baseline.json`, both canary files and the passthrough fixture all validate and pass the §2.2 rules. No file uses `writer: dpkg` outside case 98. No device baseline exists, because the agent is unbuilt. Declaring pastebin's units is a separate later diff (S4).
2. **Hashes and overlays.** Bump goal-family overlays, regenerate `examples/goal-diff.json`, every approval record and diff or record overlay, regenerate `broken-bytes` 44-48, bump `58-not-json.json`, and re-embed projection case 75. Case 13 claims `6`.
3. **Case 98** uses `writer: dpkg`. Change it to `third-party`, or it also fires `enum`. Run: with `third-party` it fires `if/then` alone.
4. **Case 64** has a tombstone under `homebrew`. Delete that tombstone. Otherwise the new rule also fires in `goal cross-file`, and deleting the present-service rule leaves the case green. Run: without it, only the present-service finding fires. Cases 35, 36 and 73 also trip the new rule, but they declare a `schema` class, so they still discriminate.
5. **Case 35** keeps ``schema (`pattern`)``: run under the single regex, the evidence holds `pattern` (Fable F7). Its host is launchd, so `if/then` fires beside it.
6. **Lint and counts.** §2.2. `EXPECTED_BROKEN` 83 to 115 (`bin/schema_lint.py:87`); `EXPECTED_PROJECTION` 27 to 28 (`:89`); "eighty-three" (`:36`, `examples/broken/README.md:3`); the case ranges in that README; the root `README.md` total; the "claims version N" notes.
7. **Report rows.** `examples/report-rows.yml` has one `domain_coverage` row. It gets `extra_scan: complete`, `two_writers` and `unmet_absence`.
8. **Happy fixture.** `deploy/linux/canary/goal-file-debian.json` with its projection, wired into `check.py` `PAIRS` (`:31-39`). Reword the comment at `:34-37`, because `unit-package` joins the non-projecting kinds.
9. **Prose.** `bin/projector.py:434-438`; the writer-prefix wording in §2.1(5) and §2.3(1); `linux-targets.md` row 4, noting v5.
10. **One-writer amendment** (astra A1). R2 admits one layered form, so these stop being literally true and must be amended in the same PR: `architecture-DEFINITIVE-v3.md:188-190` ("exactly one writer per unit-name prefix ... Two writers on one unit is a lint failure") and `docs/paper/tendcf-architecture-guide.md:166`. New meaning: one writer per unit name in the goal file's name claims, a package claim for what a package ships, and a local drop-in or mask on a vendor unit admitted only under an exact non-cfengine claim. Lint proves uniqueness among name claims and package ids only. The device detects the rest.
11. **nix2cf.** `GOAL_FILE_SCHEMA_VERSION` is `4` (`nix2cf/compile.py:42`), and `scripts/check_schema_version.py` fails CI when it differs from tendcf's const. Bump it to `5` and regenerate goldens. nix2cf renders no `unit-package` yet, and the Site Model has no systemd writer registry (§7 item 12). Grep finds no `dpkg` reference in its package or README.
12. **Discrimination (F8; astra A8).** For each new rule, record the expected witness set and verify those fixtures are unexpectedly accepted when the rule is deleted. One defect per fixture does not imply one fixture per rule. Run `bin/flag_coverage.py` where it applies.

## 5. Negative cases (113-145)

The series is shared across fixture directories. `broken/` ends at 112 and `broken-projection/` at 92, so new cases start at 113. Each row has one defect. Unless stated, the base is the canary goal file at v5 (systemd). Class tokens are from the prototype run; take exact messages from the real lint and correct the README row to match.

| # | Directory | Broken input | Class |
|---|---|---|---|
| 113 | `113-unit-writer-bare-star` | key `*`, replacing `tendcf.canary.*` so overlap stays quiet | schema (`pattern`) |
| 114 | `114-unit-writer-mid-glob` | key `ssh*.service` | schema (`pattern`) |
| 115 | `115-unit-writer-instance-key` | key `getty@tty1.service` | schema (`pattern`) |
| 116 | `116-unit-writer-no-separator` | key `ssh*` | schema (`pattern`) |
| 117 | `117-unit-writer-non-code-suffix` | key `foo.target` (Fable F9a) | schema (`pattern`) |
| 118 | `118-exact-under-prefix` | `tendcf.canary.service` beside `tendcf.canary.*` | goal cross-file |
| 119 | `119-template-under-prefix` | `foo-w@.service` beside `foo-*` (Fable F5) | goal cross-file |
| 120 | `120-launchd-single-label-key` | launchd happy file; key `ssh.service` | schema (`if/then`) |
| 121 | `121-runit-single-label-key` | runit base (happy file, supervisor `runit`, no service or interlock); key `ssh.service` | schema (`if/then`) |
| 122 | `122-writer-dpkg-on-name` | `ssh.service` with `writer: dpkg` | schema (`enum`) |
| 123 | `123-launchd-writers-dpkg-writer` | Site Model `launchd-writers.yml` with `writer: dpkg` (astra A8) | schema (`enum`) |
| 124 | `124-third-party-prefix` | `local-*` with `third-party` | schema (`if/then`) |
| 125 | `125-tendcf-install-other-unit` | `foo.service` with `tendcf-install` (R3a) | goal cross-file |
| 126 | `126-tendcf-install-launchd` | launchd happy file; `org.example.x.*` with `tendcf-install` | schema (`if/then`) |
| 127 | `127-tendcf-install-runit` | runit base; the same entry | schema (`if/then`) |
| 128 | `128-service-exact-non-cfengine` | present `foo.service` under exact `third-party`. A regression of `covers` on exact keys and a variant of 64; it would not catch a return to `startswith` (Fable F9), which the template row in the positive list does | goal cross-file |
| 129 | `129-tombstone-no-claim` | comprehensive; tombstone `ssh.service`, no claim | goal cross-file |
| 130 | `130-tombstone-non-cfengine-claim` | tombstone `ssh.service` under exact `third-party` (astra A8) | goal cross-file |
| 131 | `131-tombstone-not-yet-migrated` | `not-yet-migrated`; tombstone `ssh.service`, no claim (Fable F3) | goal cross-file |
| 132 | `132-nixos-unit-package` | passthrough base; domain `packaging` with `unit-package` | schema (`if/then`) |
| 133 | `133-launchd-unit-package` | launchd happy file with `unit-package` | schema (`if/then`) |
| 134 | `134-runit-unit-package` | runit base with `unit-package` | schema (`if/then`) |
| 135 | `135-unit-package-bad-name` | id `Open_SSH` | schema (`pattern`) |
| 136 | `136-unit-package-wrong-writer` | `writer: cfengine` | schema (`enum`) |
| 137 | `137-unit-package-empty` | `unit-package: {}` | schema (`minProperties`) |
| 138 | `138-unit-package-tombstone` | `state: absent` | schema (`const`) |
| 139 | `139-unit-package-no-writer` | entry without `writer` (Fable F9b) | schema (`required`) |
| 140 | `140-unit-package-no-state` | entry without `state` (astra A8) | schema (`required`) |
| 141 | `141-unit-package-extra-key` | entry with an extra key (Fable F9b) | schema (`additionalProperties`) |
| 142 | `142-unit-package-twice` | one package in two domains | goal cross-file |
| 143 | `143-incomplete-with-count` | `report-rows.yml`: `extra_scan: incomplete` with `extra_entries: 0` (R3d) | schema (`if/else`) |
| 144 | `144-complete-without-count` | `report-rows.yml`: `extra_scan: complete` without `extra_entries` | schema (`if/then`) |
| 145 | `broken-projection/145-unit-package-under-vars.json` | `vars/unit_package`. Not run; it exercises the existing closed-container rule, not a new one (astra A8) | projection |

No case tests "unsupported domain placement" (astra A8): R3c makes every ordinary domain legal. No case tests a key-length boundary, because v5 sets none.

**Positive witnesses** (run: no schema error, no cross-file finding):
1. A cfengine template key `tendcf-w@.service` with a present `tendcf-w@1.service`. This is the one that goes red if `covers` regresses.
2. An exact `third-party` declaration.
3. `tendcf-execd.service` with `tendcf-install`.
4. `foo-*` with `cfengine`.
5. The disjoint pair `foo-*` and `foo.service`.
6. A `unit-package` in a second domain.
7. `openssh-server` with a cfengine `ssh.service` (statically clean, a device `two-writers`).
8. All retained v4 keys.
9. The §2.4 sketch.

## 6. Slices

All slices use worktrees, absolute paths and Sonnet 5.5 `high` or better. Every PR gets a cross-model frontier review before merge (`AGENTS.md`, standing rule).

| Slice | Repo | Content | Depends on |
|---|---|---|---|
| S0 | tendcf | The live tombstone hazard at v4: §2.2(4)'s rule, cases 129 and 131, case 64's cleanup; `isplain` instead of `fileexists` at `policy/tendcf_services.cf:241`, so teardown never deletes a link it did not render, with a `tests/policy/run.sh` check | spec merged |
| S1 | tendcf | Read-only classifier prototype of §3 (`linux-targets.md` row 4 calls for a bump from a prototype): §3.5, and the fixtures below | spec merged |
| S2 | tendcf | §2, §4, §5 in one PR; a bump cannot be split | S0, S1's results read |
| S3 | nix2cf | §4(11) | S2 merged |
| S4 | tendcf | The real pastebin declaration, as an ordinary diff on a real owner list | S2; a second probe (§7 item 13) |
| S5 | tendcf | The detector proper | §7 item 13 ruled |

**S1 fixtures,** on a ubuntu VM (`TENDCF_TEST_SYSTEMD=1`). Each states its result independently (astra A2, A5). Rows naming a vendor unit assume its package is declared unless they say otherwise:

| Fixture | Expected |
|---|---|
| Rogue `/etc/systemd/system/systemd-rogue.service`, no claim | `extra` |
| Unowned file in the vendor directory, no claim | `extra` |
| Unit of an undeclared package; undeclared co-owner | `extra` |
| Declared package, its fragment only | `clean` |
| Enable-created alias `sshd.service`, package declared | `clean`, counted once |
| Shipped alias `kmod.service`; shipped mask `hwclock.service`; package declared | `clean` |
| `evil.service -> ssh.service` | `extra` |
| Local drop-in on `ssh.service`: no claim / exact `third-party` | `two-writers` / `clean` |
| Persistent mask and runtime mask on `ssh.service`: no claim / exact `third-party` / cfengine claim | `two-writers` / `clean` / `two-writers` |
| Package-shipped drop-in under `/etc`, declared | `clean` |
| `getty@tty1.service.d/x.conf`: no claim / exact `getty@.service` `third-party` | `two-writers` / `clean` |
| Local copy of `ssh.service` in `/etc`, exact `third-party` | `two-writers` |
| Cfengine claim and present service on `ssh.service`, no local file | `two-writers` |
| Tombstone under a cfengine claim, the regular file surviving | `unmet-absence` |
| Claim only in a `not-yet-migrated` domain | `clean` (R3c) |
| Generated unit from an owned source: declared / undeclared | `clean` / `extra` |
| Generated unit with empty `SourcePath` | `incomplete` |
| `systemd-run` transient | not judged |
| Successful lookup, no owner; multiple owners; architecture-qualified output; merged-`/usr` spelling; vendor symlink to a target outside the tree | as §3.3 and §3.2(5) |
| A diversion on the path | `incomplete` |
| `dpkg-query` removed from `PATH`; no `/run/systemd/system` | `incomplete`, no counts |
| `supervision` not comprehensive | `not-run` |

Then read-only on pastebin, results recorded. That is a further action on a live host and needs the operator's go.

## 7. Residue, recorded rather than fixed

**Open points astra raised that the rulings leave as residue:**
1. **Layered ownership is admitted, not proven safe** (A1). R2 admits a local drop-in or mask under an exact non-cfengine claim, and §4(10) amends the one-writer text to say so. Two parties still shape one unit. Lint cannot see it.
2. **New units inside a declared package do not surface** (A7, A10; R1). A declared package gains a daemon in an upgrade and no consent hunk shows. C3's per-unit consent was the stronger signal; R1 traded it for a stable file. C4 reports units of an undeclared package, not "every newly installed daemon".
3. **`state: absent` cannot be honoured for a name with a vendor fragment** (A3; R2). Removing `/etc/systemd/system/ssh.service` reveals the vendor unit, and disabled is not absent. The device reports `two-writers` and the §2.2(4) rule does not catch it, since a cfengine claim satisfies it. Withdrawal versus absence belongs to the deferred externally-written-unit feature.
4. **Ownership misses accidental edits** (A5; R3b). A hand-edited package-owned file still counts as owned. R3b chose no hash verification; `dpkg --verify` is the path if that changes. This limits "accidents only" too: not every accident is detected. A deliberate forgery of the database is out of scope.
5. **Comprehensive means four types on systemd** (A9; R2). On pastebin 102 of 332 rows are not judged. Target dependency edges can activate services and mount operations can run helpers, so excluded types are not harmless, only undescribed.
6. **Activation links are not classified** (A2; Fable F2). A hand-made `.wants/` link starts a unit without any artifact the detector judges.
7. **Report-only** (B6). No part of v5 prevents a competing write. The adapter cannot enforce these claims, since they do not project.

**Other residue:**

8. **Signed meaning depends on an unsigned local database** (Fable). Two devices with one goal file can cover different unit sets, and any `apt install` on a general-purpose host moves `extra_entries`. Report-only and a fixed-role host make that payable.
9. **Names outside the grammar.** systemd permits names the key regex does not, such as `\` escapes in a non-template name. A unit with such a name is permanently `extra`. None of pastebin's 230 is affected.
10. **A hand-made alias has no clean spelling** (§3.2(6)), and a local copy of a vendor fragment has none under any claim (§3.4). Both surface on a host that has them; pastebin's count is unknown.
11. **Other scopes.** User managers, and any systemd host without dpkg, which can only ever be `incomplete`. rpm would widen the `unit-package` writer enum in a counted bump. Ubuntu snap units need exact claims, unverified.
12. **The Site Model has no systemd writer registry** (draft C.5). `launchd-writers` is launchd-only and `services.schema.json` has no writer data, so nix2cf has no source for these claims. A step 6 question under Q8.
13. **For the operator:**
    - Where the detector lives, and whether §2.3(2) is the row shape (Fable Q-B). The rulings do not cover this. §2.3(2) is the lead's proposal, because R3d needs some shape and `extra_entries` cannot express it.
    - A second read-only pastebin probe before S4, to replace §2.4's inferences: `dpkg-query -S` over both spellings of the unit directories, and `/etc/systemd/system` for local files and drop-ins. The brief allowed one command, so it was not run.
    - The canary's `comprehensive` is false today (draft A.2) and stays so until a detector exists. A retreat ceremony on pastebin buys nothing checkable now, so C5 is deferred, not a stopgap (Fable F11).

## 8. Where the inputs were wrong, and how each finding was resolved

**Where they were wrong:**
1. **Draft C.3 partitioned by directory.** A package-shipped file under `/etc` had no legal spelling (Fable F1).
2. **Draft "why this keeps one writer per unit" is false.** Choosing an effective file picks a winner; it does not remove the other writer (astra A1, Fable F4).
3. **Draft C.3 step 4 accepted a tombstone as "an entry in `service`"** (astra A3).
4. **Draft A.4 dated the tombstone hazard to v5.** It is live at v4, shown by running it (§2.2(4)).
5. **Draft's `maxLength: 128` narrowed v4 keys** (astra A6), and its `anyOf` was needless (Fable F7).
6. **Draft sketch used `third-party` for `tendcf-execd.service`.** R3a.
7. **Draft D.3 numbering is superseded.** Draft 113-116 keep their numbers; 117 to 118; 118 to 120; 119 to 121; 120 to 122; 121 to 124; 122 to 128; 123 to 129; 124-126 to 132-134; 127-130 to 135-138; 131 to 142; 132 to 145.
8. **Fable F2's alias rule, taken alone, would flag shipped links.** It names `dbus-org.freedesktop.login1.service` as postinst-created; Debian's index ships it in `usr/lib/systemd/system`. §3.2(6) puts ownership first. `syslog.service`, its other example, is not on pastebin at all.
9. **astra A5 made zero owners unverifiable.** With Fable F1's partition, a successful empty answer is the name tier. Only a failed lookup is unverifiable. Both stay never-clean.
10. **astra A3 and A4 asked for same-domain authorization at the device.** R3c rules otherwise; lint stays same-domain.

**Every finding:**

| Finding | Resolution |
|---|---|
| astra A1 one-writer proof false | Adopted. §3 replaces the proof; R2 allows the layered form; §4(10) amends the architecture; §7 item 1 |
| astra A2 configuration inputs omitted | Adopted. §3.2; fixtures in §6 |
| astra A3 tombstones authorize clean; shadow removal | Adopted. §3.4 row 6, `unmet_absence`; §2.2(4); shadowing §7 item 3 |
| astra A4 domain scope inconsistent | Settled by R3c. §3.1; every ordinary domain is legal; lint unchanged. Overrules "must not silently authorize" |
| astra A5 ownership needs a nonempty, unambiguous result | Adopted except zero owners (above). §3.3; §7 item 4 |
| astra A6 grammar and cap | Adopted. No cap; launchd and runit keep v4; instances covered through templates by Fable F5, not refused |
| astra A7 candidate comparison | Adopted as a stated tradeoff; R1 chose C4. §7 item 2 |
| astra A8 migration and cases | Adopted. §4(1), §4(12), §5 (123, 130, 140), positive witnesses |
| astra A9 enumeration scope | R2 chose four types; the restriction is stated, not excused. §2.1(5), §7 item 5 |
| astra A10 factual overreach | Adopted. §7 item 2; NixOS rests on its ruling, not on the symlink; D36 cited as `:188-190` |
| astra B1-B6 | B1 §2.2(1); B2 §2.2(1); B3 §2.1(4); B4 §3.1; B5 §7 item 2; B6 §2.3(4), §7 item 7 |
| astra's six further rulings | One writer: R2 and §4(10). Claim placement: R3c. New units in a package: R1. Instances, generated, transient: F5, R2. Meaning of `absent`: identity, unchanged, §7 item 3. Incomplete: R3d |
| Fable F1 ownership decides the tier | Adopted. §3.3 |
| Fable F2 enumerate through the manager | Adopted with the alias correction above. §3.2 |
| Fable F3 tombstone rule in any coverage | Adopted and verified by running. §2.2(4), cases 129-131, S0 with `isplain` |
| Fable F4 one-writer across kinds | Adopted. §2.1(3), §3.4 rows 2-5 |
| Fable F5 template keys cover instances | Adopted and run. §2.2(1), case 119, positive witness 1 |
| Fable F6 detection scope | Adopted through R3c. §3.1 |
| Fable F7 single regex | Adopted and run. §2.1(1); case 35 keeps `pattern` |
| Fable F8 migration gaps | Adopted. `EXPECTED_PROJECTION` §4(6); nix2cf §4(11); `linux-targets.md` §4(9); `check.py` §4(8); projector prose §4(9); case 35 §4(5); truth table §2.2(2) |
| Fable F9 missing cases | Adopted. 117, 139, 141, 131, 119; 128 labelled as a regression |
| Fable F10 `unit-package` semantics | Adopted. §2.1(2); (c) measured in §2.4; (d) §2.3(2) |
| Fable F11 C5 | Adopted. §7 item 13 |
| Fable F12 accuracy checks | Nothing to do; several re-run here |
| Fable case against C4 | Recorded. §2.1(5), §7 item 8 |
| Fable E1-E7 | R1 (E1); R2 (E2, E5, E6); R3a (E3); R3b (E4); E7: v5 carries Q9 alone, §2 |
| Fable Q-A | R3c |
| Fable Q-B | **Open.** §7 item 13 |
| Draft C.5 items 1-9 | 1: §7 item 2. 2: §7 item 3. 3: §7 item 4. 4: fixed by F5. 5: §7 item 11. 6: §3.3, §3.5. 7: §7 item 11. 8: §2.2(6). 9: §7 item 12 |
| Draft F.3 unverified list | pastebin list, package-name pattern, regexes and lint: done here. Ownership, resolution, generated units, snap: §3.5, §7 item 13, §7 item 11 |
