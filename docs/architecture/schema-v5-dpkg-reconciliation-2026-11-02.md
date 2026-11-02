# Schema v5: Debian package claims and the unit namespace (Q9, 2026-11-02)

Status: **spec, rulings taken; reviewed by astra and Fable, both "sound with changes", and every
finding applied (§8). Operator points R4-R8 are settled (§1); ~~only a later tendcf-agent takeover of the detector stays open.~~ Amended 2026-11-02 by D45 ([`architecture-DEFINITIVE-v3.md`](architecture-DEFINITIVE-v3.md)): takeover by tendcf-agent on Linux is closed; possible reassignment to another command remains open (§7 item 13).** This document is the contract
the v5 slices implement. As written (2026-11-02) it changed no schema, lint or fixture; slice S2 (same day) implemented §2, §4 and §5 (§6). It supersedes its three
inputs, which stay frozen as written: [the Opus 5.5 draft](schema-v5-opinion-opus-draft.md),
the [astra review](schema-v5-opinion-astra.md) ("unsound as specified") and the
[Fable 5.1 review](schema-v5-opinion-fable.md) ("sound with changes"). Where an input is
wrong, §8 says so; the inputs are not corrected in place. Q9 is the open item
[schema v4](schema-v4-reconciliation-2026-10-31.md) left in its §1 and §7.

**What was run for this document (2026-11-02), and what was not:**
1. **Two read-only reads of pastebin** (§2.4): a probe for the unit list and states, and the lead's ownership query over the unit directories. Package attributions are **read from pastebin's database**, except two rows that stay index-based and say so.
2. **An assembled v5 schema, in memory, outside the repository.** It applied §2.1 to the real schemas and used the real `schema_evidence` from `bin/schema_lint.py`. The goal-family cross-file rules of §2.2 were prototyped beside it. Every schema regex, class token and overlap row below comes from that run unless marked. The spec-review changes (`overlap`, §2.2(5), cases 126, 127, 129-131 and the report-row cases) were re-run the same way, with cases 129-131 also against the v4 schema on disk. Case 145 was not run.
3. **The live v4 lint and a real `cf-agent`,** for the hazard in §2.2(4).
4. **Not run when this document was written:** no detector or classifier existed, and nothing in §3 had run on a systemd host. Slice S1 has since run §3.5 and the §6 fixtures on three ubuntu systemd hosts: §3.6 records the results, and slice S2 folded every place where the contract changed into §3 (the K list in §3.6 is the record; K5 and K13, generator output, stay open for an operator decision). Nothing has run on Debian 13 or on pastebin, bar R8's read-only probe of pastebin (§3.6).

## 1. Rulings (djbclark, 2026-11-02; R4-R8 the same day, after the spec reviews)

| # | Ruling |
|---|---|
| R1 | Package claims (C4), with both reviews' fixes. (Declaring a dpkg package covers the units it ships; a new unit inside a declared package does not surface; a new package does.) |
| R2 | As Fable proposes: service, socket, timer and path files count; generated units are judged via their source (SourcePath); transient units are out of scope (residue). A local drop-in or mask on a vendor unit is clean only when an exact non-cfengine name claim covers the unit name, otherwise "two-writers"; a cfengine claim on a name whose vendor fragment exists is always "two-writers" (shadowing is the deferred externally-written-unit feature). |
| R3 | Accept all four: (a) new writer value `tendcf-install` for tendcf's own installed unit (tendcf-execd.service); (b) threat model is accidents only, as R-S3-4: ownership from the dpkg database, no file-hash verification; (c) one unit namespace per host: detection runs across all domains' claims, a unit is extra only if no claim in any domain covers it; (d) a scan that cannot enumerate completely reports "incomplete", never zero extras. |
| R4 | The detector lives in the CFEngine policy bundle, as a report-only promise set. It writes report rows in the §2.3(2) shape. ~~Whether tendcf-agent should later take it over is a separate discussion, still open.~~ *Amended 2026-11-02 by D45: takeover by tendcf-agent on Linux is closed; possible reassignment to another command remains open (§7 item 13).* |
| R5 | Contradictory service states for one unit identity across domains (present in one, absent in another) are rejected in lint, by a cross-domain check with its own negative case. A detector that still sees one reports `incomplete`. |
| R6 | After CI and review, S0 merges and is deployed to pastebin with the installer, then the canary is checked. |
| R7 | Confirmed: an exact name claim on a template key covers its instances' drop-ins (`getty@.service` covers `getty@tty1.service.d/`), as §3.4 row 4 reads R2. |
| R8 | One further read-only probe of pastebin is allowed before S4, for the points §2.4 lists as unmeasured. |

## 2. Schema deltas

All three goal-family schemas (`goal-file`, `goal-diff`, `approval-record`) change
`schema_version` from `"const": 4` to `"const": 5`. v5 carries Q9 alone. Distro family, `scope` and
externally-written units stay deferred ([linux-targets](linux-targets.md) row 4; v4 Q5).

**Terms used from here on.** An *artifact* is a file the manager reads for a unit: a fragment, a drop-in, a link (alias or mask), or a generated unit's source. *Owned* means the dpkg database names at least one package for that path. A *vendor fragment* is an owned fragment for that unit name, or for an instance its applicable template, in any load-path directory, including one a local file or mask hides. A generated unit whose source is owned counts as having one, because R2 judges it via that source. *Local* means not owned. A package-shipped mask or drop-in is therefore **not** local, wherever it sits (Fable F1).

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

1. **Replace the two `startswith` matchers** (`:1571`, `:1586`; S2 found a third, §9 item 2, and replaced all three). Reusing them would wrongly flag `foo.service` against `foo.service.*`. The rule, as run:

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
           return b.startswith(a[:-1])
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
   - **Run against the live v4 lint:** the canary goal file plus `"sshd.service": {"state": "absent"}` raises no schema error and no cross-file finding, under `comprehensive` and under `not-yet-migrated`. On pastebin `/etc/systemd/system/sshd.service` is an unowned link (measured, §2.4), so `fileexists` is true there. By the policy as read (`:313`, not run on a host), teardown would run `systemctl disable --now` on it and then delete the link.
   - **The launchd adapter's tombstone is equally writer-blind and has no existence gate** (`policy/tendcf_services.cf:269-271`, `:285-287`). There a plist is a plain file whoever wrote it, so this lint rule is the only guard. Case 130 is its launchd witness.
   - **Run against a real `cf-agent`** (3.29.0a Mac dev build): `fileexists` is true for a plain file, a symlink, a symlink to `/dev/null` and a dangling symlink, while `isplain` is true only for the plain file. The book names `fileexists` (ch. 27) and not `isplain`, and covers 3.12 only, so this is from running.
   - This rule does not make removal safe by itself. See §7 item 3.
5. **`tendcf-install` names one unit.** On a `systemd` host, a `unit-writer` entry with that writer must have the key `tendcf-execd.service`. Otherwise the value is a second `third-party`. Other supervisors reject the writer in schema (§2.1(4)), and this rule does not duplicate that rejection, so cases 126 and 127 discriminate.
6. **Unchanged:** a present comprehensive-domain service still needs a same-domain cfengine claim (`check_goal_file_cross_file`, through `unit_key_covers`). Duplicate and overlap checks stay global. Comprehensive-domain services under another writer stay refused, because managing an externally written unit stays deferred.
7. **Cross-domain contradiction (R5).** One unit identity (the service id's spelling; no lint can know aliases) must not be a present service in one domain and a tombstone in another. Same-domain rules cannot see it, and the detector can only report `incomplete` on it (§3.1). Negative case 155; implemented in S2 beside the other service rules.

### 2.3 Other schemas

1. **`launchd-writers.schema.json`:** remove `dpkg` from the writer enum. No live instance uses it, and `contract_version` stays 1 on the v4 §2.2 no-bump precedent. Reword `:12` to the D16(d) reading: an extra is anything absent from the domain's description, so `launchd-writers` and `common.schema.json:117` stop disagreeing (draft finding A.3).
2. **`report-row.schema.json`** (R3d, Fable F10d). `extra_entries` is a required counter today and cannot say "not known". The change has three locations in `domain_coverage_row`.

   Merge into its `properties`, keeping the existing fields:

   ```json
   "extra_scan": {"enum": ["complete", "incomplete", "not-run"]},
   "two_writers": {"type": "integer", "minimum": 0},
   "unmet_absence": {"type": "integer", "minimum": 0}
   ```

   Add as siblings of `properties`, not inside it:

   ```json
   "if": {"properties": {"extra_scan": {"const": "complete"}}, "required": ["extra_scan"]},
   "then": {"required": ["extra_entries", "two_writers", "unmet_absence"]},
   "else": {"properties": {"extra_entries": false, "two_writers": false, "unmet_absence": false}}
   ```

   In its top-level `required`, add `extra_scan` and remove `extra_entries`. The row's description says the two new counters are defined for every supervisor's extra scan and are zero where the detector has no such verdict, because a complete launchd row must carry them too. **An incomplete scan cannot carry a zero, because it cannot carry a count.** `report-row` has no version axis, and nothing writes rows yet. This row shape is adopted by R4.
3. **`goal-diff.schema.json`:** no shape change. Its hunks do not enumerate kinds (`:68-87`), so `(supervision, unit-package, <pkg>)` is an ordinary address. Ceremony stays `ordinary` (`derive_ceremony_class`). Rendering: an add reads "Debian package X may supply its own units; they stop being reported as extras", and a remove reads "writer declaration dropped; its units are reported as extras; nothing is stopped".
4. **The projection is unchanged.** `PROJECTING_KINDS` stays `service` and `interlock`, so existing projections stay byte-identical. Report-only classification does not prevent competing writes, and the spec must not be read as saying it does (astra B6).

### 2.4 Pastebin's v5 `supervision` domain, from real data

Two read-only reads of the host, both 2026-11-02.

**The unit list, with a first ownership attempt:**

```
ssh root@pastebin.xvm.mit.edu 'systemctl list-unit-files --no-legend --no-pager; dpkg-query -S /lib/systemd/system/*.service 2>/dev/null | head -200'
```

332 unit-file rows, and two ownership lines:

```
tailscale: /lib/systemd/system/tailscale-wait-online.service
tailscale: /lib/systemd/system/tailscaled.service
```

**Measured ownership, run by the lead:** `pastebin-ownership.tsv`, 384 rows of path, owning binary package or `-`, and file or link, over `/usr/lib/systemd/system/*`, `/etc/systemd/system/*` and `/etc/systemd/system/*.d/*`. The lead also reports that `/lib` is a symlink to `usr/lib`. The data file sits in the run's state directory, outside this repository, and does not record the query text. This document uses its rows as given.

| Directory | Owned | Unowned |
|---|---|---|
| `/usr/lib/systemd/system` | 308 (286 file, 22 link) | 6 (5 file, 1 link) |
| `/etc/systemd/system` | 0 | 70 (68 file, 2 link) |

"File" includes the `*.d` and `*.wants` directories. **Nothing under `/etc/systemd/system` is owned.** The rows hold 39 distinct owner strings, which are 36 packages once the three multi-owner strings are split. All three multi-owner rows are `.wants` directories: no unit file has two owners, and no owner carries an architecture qualifier. Of those 36, `systemd-cryptsetup` owns only targets and `.wants` directories here, so it is not declared; `tailscale` is the 36th below instead.

| Unit type | Rows | R2 |
|---|---|---|
| service | 186 | judged |
| timer | 22 | judged |
| socket | 20 | judged |
| path | 2 | judged |
| target, mount, scope, slice, swap, automount | 79, 10, 5, 5, 2, 1 | out of scope (§7 item 5) |

Among the 230 judged names, states are static 128, enabled 48, disabled 33, alias 10, masked 6, generated 2, enabled-runtime 2, indirect 1. All 5 `transient` rows are `session-*.scope`, so none reaches the detector anyway.

**All 230 names are accounted for, and no name has a row in both directories:**

| Names | Treatment | Evidence |
|---|---|---|
| 201 | package tier | owned at the `/usr/lib` spelling |
| 2 | package tier, `tailscale` | owned at the `/lib` spelling only (below) |
| 2 | package tier, `exim4-base` and `zephyr-clients` | **not measured** (below) |
| 21 | exact `third-party` | 20 unowned regular files in `/etc`; `screen-cleanup.service`, an unowned link in `/usr/lib` |
| 1 | `tendcf-install` | unowned file in `/etc` |
| 1 | `cfengine` prefix | unowned file in `/etc` |
| 2 | enable-created aliases, no claim (§3.2(6)) | unowned links in `/etc`: `sshd.service`, `dbus-org.freedesktop.timesync1.service` |

A further 11 of those names need an exact claim because of a local drop-in (item 5 below). The sketch (38 packages; 34 `unit-writer` keys, 32 of them `third-party`) validates against the assembled v5 schema and raises no cross-file finding (run).

**`unit-package`, each `{"state": "present", "writer": "dpkg"}`:**

| Package (judged names) | Evidence |
|---|---|
| `systemd` (128), `udev` (8), `sysstat` (7), `e2fsprogs` (5), `apt` (4), `atop` (4), `ifupdown` (4), `openssh-server` (4), `apt-listchanges` (2), `certbot` (2), `console-setup-linux` (2), `dpkg` (2), `logrotate` (2), `lynis` (2), `man-db` (2), `plocate` (2), `systemd-timesyncd` (2), `util-linux` (2), `apparmor` (1), `cron` (1), `dbus` (1), `dbus-system-bus-common` (1), `et` (1), `fail2ban` (1), `grub-common` (1), `libpam-modules-bin` (1), `nftables` (1), `nginx-common` (1), `nullmailer` (1), `openafs-client` (1), `rsync` (1), `sudo` (1), `systemd-zram-generator` (1), `tinyproxy` (1), `unattended-upgrades` (1) | measured at `/usr/lib` |
| `tailscale` (2) | measured at `/lib` |
| `exim4-base` (1), `zephyr-clients` (1) | **Debian's trixie `main` `Contents` index only,** via `etc/init.d/exim4` and `etc/init.d/zhm`. A candidate for S1 |

**`tailscale` is dpkg-owned under a different path, not installed outside dpkg.** The lead's query has `-` for `/usr/lib/systemd/system/tailscaled.service` and `tailscale-wait-online.service`; the first read has `tailscale` for both under `/lib`. With `/lib` a symlink these are the same files, so the database records this package under `/lib` and the other packages' units under `/usr/lib`: **one host's database holds both spellings.** `dpkg-query -S` performs a "literal path lookup" for a path with no wildcard (man page), which is why each query missed the other's set. The package is absent from Debian `main`, so it comes from elsewhere, most likely Tailscale's own apt repository; the apt source was not read. A query of the `/usr/lib` spelling alone would call `tailscaled.service`, which is enabled, unowned, hence §3.3. `tailscale-online.target` is also `-`; it is outside the four types, and its `/lib` answer was not read.

**The two generated units.** `exim4.service` and `zhm.service` are `generated` in the probe and have no row in either directory, so no fragment lies in the directories queried. Their sources presumably lie in `/etc/init.d`, which the query did not cover. With no `exim4` fragment in `/usr/lib`, the index's `exim4-daemon-*` packages look absent, and `nullmailer` is enabled. **A leftover conffile of a removed package is one reading; unproven** (§3.5).

**`unit-writer`:**

```json
"tendcf-execd.service": {"state": "present", "writer": "tendcf-install"},
"tendcf.canary.*":      {"state": "present", "writer": "cfengine"}
```

plus exact `third-party` claims for the 21 local names:

```
athena-src-update.service  athena-src-update.timer  athena-tgt-renew.service  athena-tgt-renew.timer
failure-mail@.service  oauth2-proxy.service  wastebin.service
pb-resource-check.service  pb-resource-check.timer  pb-wastebin-dump.service  pb-wastebin-dump.timer
pbstats-sample.service  pbstats-sample.timer  pbstats-weekly.service  pbstats-weekly.timer
tinyproxy-searxng.service  tinyproxy-vpsrelay.service  screen-cleanup.service
determinate-nixd.socket  nix-daemon.service  nix-daemon.socket
```

and for the 11 names with a local drop-in and no local fragment:

```
apt-daily-upgrade.service  apt-daily.service  certbot.service  fail2ban.service  logrotate.service
nftables.service  nginx.service  openafs-client.service  ssh.service  systemd-tmpfiles-clean.timer
zhm.service
```

**What the real data changes:**
1. **The draft's falsifier does not fire.** 203 of 230 names are measured in the package tier, so C4 is not noise-dominated by units outside it.
2. **"Small" means 38 packages against 230 names,** not a handful (Fable F10c).
3. **Fable's alias rule needs ownership first.** 8 of the 10 `alias` rows are owned links in `/usr/lib`: `autovt@`, `kmod`, `procps` and the `hostname1`, `locale1`, `login1` and `timedate1` D-Bus names under `systemd`, and `udev` under `udev`. For seven of them the usual target is `static` in the same probe (not `autovt@`, whose usual target `getty@` is enabled; the link targets were not read on the host). `systemctl` defines `static` as having no provision for enabling in `[Install]`, so an `Alias=` test would call those seven extra. The other two are the unowned `/etc` links in the table above.
4. **"Mask" needs ownership first too, and location does not decide it.** 5 of the 6 masked names are owned links in `/usr/lib` (`cryptdisks`, `cryptdisks-early`, `hwclock` and `x11-common` under `systemd`; `sudo` under `sudo`). They are package-tier files, not R2's local masks. `screen-cleanup.service` is an unowned link in that same directory, so it needs a name claim. `dpkg-query -S` "will not list extra files created by maintainer scripts" (man page), which is one way to get there. No mask is in `/etc`.
5. **R2's drop-in rule has real load.** `/etc` holds 16 unowned drop-ins on 15 units: `onfailure-mail.conf` on 14, plus `nftables.service.d/ts.conf` and `systemd-tmpfiles-clean.timer.d/override.conf`. Four of the units are already name-claimed. The other 11 report `two-writers` unless they get the exact claims above, ten on owned fragments and `zhm.service` on a generated unit (§2).
6. **No local copy of a vendor fragment** appears between these two directories, and `/etc` has no type-wide drop-in directory.

**Not measured:**
1. `/etc/init.d`, and so the two generated units' sources and owners.
2. The targets of the two `/etc` alias links and the `[Install] Alias=` lines §3.2(6) tests.
3. The contents of the 8 owned `*.d` directories in `/usr/lib` (for example `user@.service.d`) and of the 15 `*.wants` directories in `/etc`.
4. Other load-path directories, such as `/usr/local/lib/systemd/system` and `/run/systemd/system`.
5. Who wrote any unowned file. "Unowned" says only that the database names no package.

## 3. Detector contract

No detector exists; this is what one must do. It reads and reports, and it never removes (reconciliation 2026-08-15; the tombstone is the only actuated removal path). It is threat-modelled for accidents only (R3b): database ownership, no hash verification. It runs in the CFEngine policy bundle as a report-only promise set (R4); ~~whether tendcf-agent later takes it over is open~~ (amended 2026-11-02 by D45: takeover by tendcf-agent on Linux is closed; possible reassignment to another command remains open, §7 item 13), and the contract does not depend on it.

### 3.1 Gate

| Condition | `extra_scan` |
|---|---|
| `supervision.coverage` is not `comprehensive`, or `supervisor` is not `systemd` | `not-run` |
| Gate passes but the manager is unreachable (`/run/systemd/system` absent) | `incomplete` |
| Gate passes but the dpkg database cannot be queried | `incomplete` |
| Every in-scope unit resolved with evidence | `complete` |

**S2 and the markers.** S1 observed behaviour that differs from the contract as first written (§3.6). Slice S2 (2026-11-02) folded those observations into the text below and removed their `[S2 K<n>]` markers, except K5 and K13: an operator decision on how generator output is attributed is pending, so their text, K5's inline note and K13's entry in §3.6, stays exactly as S1 left it. §3.6 remains the evidence record, with the K list and the observations behind each change.

`supervisor: systemd` does not establish that dpkg exists (astra B4). Other domains' `coverage` switches nothing on or off (Fable F6). Their rows say `not-run`, and unit findings appear on the `supervision` row only.

   - **"Cannot be queried" is tested with a positive control.** `dpkg-query -S` on a missing or empty admindir exits 1 with "no path found", exactly as for a missing path in a healthy database (§3.6), so a zero-owner answer proves nothing. Ask for paths that must be owned (`/usr/bin/dpkg-query`, `/usr/bin/dpkg`, both spellings, §3.3); no owner for any of them is `incomplete`.

**The registry is the union of every domain's `unit-writer`, `unit-package` and `service` entries** (R3c). A claim in a non-comprehensive domain counts. This reads service entries across domains, where the lint in §2.2 stays same-domain: lint keeps the stricter authoring rule, and the device judges one namespace.

**Contradictory service states are not settled by R3c** (spec review astra A3). Keep every `(domain, id, entry)` service declaration; never overwrite a duplicate id. The lint's same-domain rules (§2.2(4), (6)) constrain `supervision` and each comprehensive domain on its own, so before R5 a present entry in `supervision` and a tombstone for the same id in another domain both validated. R5 closes that in lint (§2.2(7), negative case 155), and the detector keeps its own defence for a goal file that did not pass lint: a detector that meets contradictory states reports `incomplete` with the conflicting addresses, and never selects a declaration by iteration order.

### 3.2 Enumerate through the manager, never by walking directories

1. **Names.** `systemctl list-unit-files` and `systemctl list-units --all`, for the four types (R2). Then, per unit: `Id`, `Names`, `LoadState`, `UnitFileState`, `FragmentPath`, `SourcePath`, `DropInPaths`, `Transient`.
   - **`systemctl show` is never called for a bare template name.** It exits 1 ("neither a valid invocation ID nor unit name"), and one template among several names fails the whole call with no output. A template's artifacts come from the probe alone (item 4). An instance is shown normally: its `FragmentPath` is the template's. A name the manager does not know shows `LoadState=not-found` with empty paths.
   - **An instance is enumerated only while the manager holds it loaded** (`list-unit-files` lists the template only; `list-units --all` lists an instance while it is loaded). A drop-in directory of an unloaded instance is the orphan case of §7 item 14 and is never judged.
2. **Provenance is recorded before anything is resolved** (astra A2). Keep the lookup name and the link path; a mask resolved to `/dev/null` has lost its identity.
3. **Not artifacts:** `.wants/` and `.requires/` entries are dependencies, never classified (Fable F2; §7 item 6). A unit with `Transient=yes` is out of scope (R2) and is dropped before classification. `Transient=yes` from `systemctl show` is the only test: `list-unit-files` does list a transient unit (state `transient`), so that state alone, in either direction, decides nothing.
4. **Artifacts of a unit,** each classified on its own:
   - the effective fragment, or for `UnitFileState=generated` its `SourcePath` (R2). An empty `SourcePath` on a generated unit is unverifiable;
     - `[S2 K5]` S1 found stock generated units with an empty `SourcePath` on ubuntu 26.04 (`netplan-ovs-cleanup.service`, `sshd-unix-local.socket`). The rule stands and makes a stock 26.04 scan `incomplete`; see §3.6 K5 for the open question.
   - every `DropInPaths` entry, which covers template, instance and type-wide scopes;
   - a mask;
   - an alias link: see below;
   - a shadowed fragment, from the probe below.

   **The probe is the only directory access: a name lookup, never a walk.** `FragmentPath` shows the winner only, is the mask link's own path for a mask (`/etc/systemd/system/x.service` with `UnitFileState=masked`, or `/run/systemd/system/x.service` with `masked-runtime`; never `/dev/null`), and is the target's for an alias name, so the manager cannot supply these paths. Obtain and record the ordered system-manager load path from `systemd-analyze unit-paths`; do not assume `/etc` and `/usr/lib` exhaust it. In each directory, without following links, look for:
   - each of the unit's names and the lookup name and, for an instance, its applicable template (`getty@tty1.service` also looks for `getty@.service`);
   - `<name>.d/*.conf` for each of those, the dash-truncated directories (`foo-bar.service` also reads `foo-.service.d/`; `systemd.unit(5)`, read at upstream v257) and the type-wide `<type>.d/*.conf`.
   - for a template, which `show` refuses, nothing but the probe: the template's artifacts are the files found here.

   This yields the mask link, the alias link and any shadowed fragment. `FragmentPath` and `DropInPaths` are then cross-checked against it, one way: a `DropInPaths` entry the probe does not find is unverifiable. The probe also finds drop-ins `DropInPaths` omits, because a same-named `*.conf` in a higher-precedence directory shadows them; those are judged as artifacts, not disagreements. A drop-in link to `/dev/null` is listed in `DropInPaths` and is an artifact. For an instance, a package-owned applicable template counts as a vendor fragment even when a local instance file or mask keeps it from being selected. If the candidates or their provenance cannot be established, the scan is `incomplete`.
5. **A link's final target is an artifact too,** except `/dev/null`. An owned link to an unowned target does not launder the target (astra A5). A chain with no final target (dangling, a cycle, or more than ten hops) is unverifiable.
   - **The target keeps the role of the chain that reached it.** A **fragment** link's target is a fragment: an owned link to an unowned fragment is one fragment chain, not two fragments. The owned link is not a vendor fragment on its own, the unowned target is a local artifact, and §3.4 row 3 does not fire. With no claim the unit is `extra` (row 10), and with an exact `third-party` claim it is `clean`. Reading row 3 literally would call the pair `two-writers` under any claim, which astra A5 does not ask for.
   - A **drop-in** link's target is part of the layer: it is judged for ownership on its own (an owned target of an undeclared package is row 8), but it is never a vendor or a local fragment, so it cannot trigger row 3 or establish that a vendor fragment exists. A local drop-in link to an unowned file under an exact `third-party` claim is therefore `clean`, not `two-writers`; without the claim it is row 4.
   - One file can be reached through both chains (a vendor fragment that an `/etc` drop-in also links to): the scan keeps one record per (path, chain), so the file stays a vendor fragment whichever load-path directory is scanned first, and a local override of it is still row 3. A detector's JSON `artifacts` records carry `role` (`dropin` on drop-in records and their link targets, `fragment` otherwise) and, on a link target, `via` (the link that leads to it); one path can appear twice, so a consumer keys by (path, kind, role). An owned link to an unowned fragment is one chain whichever directory is scanned first: the fragment record keeps the `via` of the link.
6. **Aliases: one rule.** An alias keeps its lookup name, link artifact, target identity and claims until classification is complete.
   - An owned alias link follows the package tier (§2.4 item 3).
   - An unowned alias link is **authorized** only when its name appears in the target's effective `[Install] Alias=`: the fragment plus the target's `<name>.d` and its template's `.d` drop-ins. `systemctl enable` reads only those, and acts on no `Alias=` from a dash-truncated or type-wide drop-in, although `systemctl cat` prints them too, so the classifier reads `systemctl cat` and keeps only those blocks. An exact name claim does not otherwise authorize it: an unauthorized alias is `extra` even under a claim. This is what stops `evil.service -> ssh.service` collapsing into `ssh.service` (Fable F2).
   - Authorization covers the link only. The target and every other artifact pass classification on their own.
   - Evaluate claims on the alias name and R2's vendor-fragment rule first. Only then does a clean alias count as its target, once.

### 3.3 Ownership decides the tier

**Canonicalise through the merge, then ask under both spellings** (§2.4; Fable F1). `/lib` is a symlink to `usr/lib` on a merged host, so one file has two spellings, and `dpkg-query -S` looks up the literal path. Resolve the artifact's directory through that symlink, so that a path reported as `/lib/...` and one reported as `/usr/lib/...` are one artifact. Never resolve the last component: that would lose the alias or mask identity §3.2(2) keeps. For a canonical path under `/usr/lib`, query both `/usr/lib/...` and `/lib/...`, and take the union. **Canonicalising to `/usr/lib` alone is not enough:** pastebin's database records most units there and tailscale's under `/lib`, so that query calls `tailscaled.service` unowned. A miss under one spelling with a hit under the other is the package tier. Where `/lib` is not that symlink, the spellings are different files, and only the literal path is asked.

| Answer | Treatment |
|---|---|
| Lookup succeeded, one or more owners | Package tier |
| Lookup succeeded, no owner | Name tier. Not a failure (astra A5 said unverifiable; §8) |
| Lookup failed, output unparseable, or a diversion the detector cannot resolve | Unverifiable |

Owner names may carry an architecture qualifier. `unit-package` ids cover every architecture of a package: `systemd:amd64` maps to `systemd` by this explicit rule, not by a silent strip (astra A5). Database ownership establishes recorded provenance. It does not establish integrity or authorship (R3b).

**Parse rules for `dpkg-query -S`** (observed by S1, §3.6 item 5). Owner lines read `pkg: /path` (several owners `a, b: /path`, in no fixed order, so owners are sets) or `pkg:arch: /path` (a `Multi-Arch: same` package only; a plain package has no qualifier); a directory lists every package that has it. No match is exit 1 with stderr `no path found matching pattern`, the other arguments' lines still on stdout. A diversion prints `diversion by <pkg> from: <path>` and `diversion by <pkg> to: <path>` (`local diversion` for a local one) before the owner line: a diversion line naming a queried path, as `from` or `to`, makes that path unverifiable even when an owner line follows. A path with `*?[\` is a pattern unless escaped with a backslash. An unrecognised stdout line, or an exit status other than 0 or 1, fails the whole query, and the scan is `incomplete`.

### 3.4 Verdict per unit

Take the first row that applies, top down, across the unit's artifacts:

| # | Condition | Verdict |
|---|---|---|
| 1 | Any artifact is unverifiable, or the unit's service declarations contradict (§3.1) | scan `incomplete` |
| 2 | A cfengine claim covers the name, an alias name included, and a vendor fragment exists, an alias target's included (R2; Fable E6) | `two-writers` |
| 3 | A local fragment hides a vendor fragment, whatever the claim (Fable F4: R2 admits only drop-ins and masks) | `two-writers` |
| 4 | A local drop-in or mask on a vendor unit, with no exact non-cfengine claim on the unit's `Id` or, for an instance, on its template (R2). A template key counts as exact for its instances. A claim on an alias name does not license a drop-in on the unit; row 2's cfengine side still counts every name of the unit, an alias name included | `two-writers` |
| 5 | A local drop-in or mask under a cfengine claim, with no vendor fragment (CFEngine renders fragments only) | `two-writers` |
| 6 | A cfengine-claimed local fragment whose service entry is a tombstone (astra A3) | `unmet-absence` |
| 7 | A cfengine-claimed local fragment with no service entry in any domain (D16(d)) | `extra` |
| 8 | An owned artifact with any owner not in `unit-package`, co-owners included (astra A5) | `extra` |
| 9 | An unowned alias link §3.2(6) does not authorize, whatever the claim | `extra` |
| 10 | A local artifact no claim in any domain covers (R3c). An authorized alias link is exempt; its target and other artifacts are not | `extra` |
| 11 | Otherwise | `clean` |

A name claim covers local artifacts only; a package claim covers owned ones (§2.1(3)). An exact `third-party` claim on a vendor unit therefore licenses its local drop-in or mask (R2) and nothing about the fragment, which still needs its package declared. Verdicts count into `two_writers`, `unmet_absence` and `extra_entries`. A name claim that covers nothing, and a package claim that owns nothing, are not findings. **`extra_entries` keeps D16(d) as its meaning; the two new counters keep skew from being reported as a bare extra** (astra A3).

**Incomplete (R3d).** One unverifiable artifact, a failed enumeration or contradictory service declarations makes the whole scan `incomplete`: no `extra_entries`, `two_writers` or `unmet_absence` on the row. The per-unit evidence goes to the detector's log line, because `report-row` is a counter row. A partial count is never reported as a total.

Evidence the scan cannot establish is never skipped, never a crash and never a zero. Each of these makes the scan `incomplete`, with no counters:
1. a unit whose probe raises, or a `show` that fails for a non-template;
2. a link chain with no final target (dangling, a cycle, or more than ten hops, `/dev/null` excepted);
3. `systemd-analyze unit-paths` output with a record that is not an absolute path, or with no record at all (an unknown load path);
4. a `list-unit-files` or `list-units` record that is not a unit name of the four types with its state fields (an empty listing stays legitimate, and is a complete scan of no units);
5. any command that fails or exceeds its time bound (120 s by default; the classifier reports it as exit 124).

### 3.5 Behaviour S1 must prove before the shape freezes

As written, before S1, none of this had been run; the draft's F.3 and the reviews rested on recall here too. **S1 has now run every item below: the results, with the systemd and dpkg versions, are in §3.6.**
1. `systemctl show` on a bare template name (the draft recalls a refusal) and on non-loaded units.
2. `FragmentPath` on a masked unit: the link path or `/dev/null`.
3. `SourcePath` on a sysv-generated unit. The D-Bus API documents the property; its value on `exim4.service` and `zhm.service` is unread.
4. `dpkg-query -S` for a conffile whose package is removed but not purged (pastebin's `exim4` candidate, one of the two attributions still index-based in §2.4). The contract's reading is that the database's answer stands whatever the package's status, so a declared `exim4-base` makes the unit clean. Change that here if the prototype shows otherwise.
5. `dpkg-query -S` output for multiple owners, architecture qualifiers and diversions, and its exit status with no match.
6. Whether a type-wide drop-in such as `/etc/systemd/system/service.d/` appears in every unit's `DropInPaths`. If it does, each covered unit is `two-writers`, which is correct and loud. Pastebin's `/etc` has none (§2.4), so this needs a fixture.
7. `systemd-analyze unit-paths` output, and whether `DropInPaths` lists files the probe does not find, or the reverse.
8. `Transient` and `FragmentPath` on a `systemd-run` unit, and `FragmentPath` and `Names` on an alias name.
9. `Alias=` set in a drop-in. `systemctl enable` loads drop-ins for its `[Install]` reading (upstream v257 `src/shared/install.c:1596-1633`, `:2825`; read, not run). That search names `<name>.d` and the template's directory only, so S1 must show whether `systemctl cat` can print an `Alias=` that `enable` would not act on.

### 3.6 Results of §3.5 and of the §6 fixtures (S1, 2026-11-02)

Everything here was run, by `bin/unit_classifier.py` and `tests/unit_classifier/` (`s1_probe.py` records raw output; `test_fixtures.py` is the fixtures; `test_logic.py` is the canned-output verdict table). The probe's full raw output is the `s1-probe-<runner>` artifact of each CI run below. Observed on three GitHub runners:

| Runner | systemd | dpkg |
|---|---|---|
| ubuntu-24.04 (amd64) | 255 (255.4-1ubuntu8.18) | 1.22.6 |
| ubuntu-24.04-arm (arm64) | 255 (255.4-1ubuntu8.18) | 1.22.6 |
| ubuntu-26.04 (amd64) | 259 (259.9-0ubuntu0.1) | 1.23.7 |

All three have `/lib -> usr/lib`, and the host database records `ssh.service` under `/usr/lib` only (a `/lib` query misses it). The arm64 runner differs from amd64 only in the architecture. ubuntu-26.04 differs in these ways, none affecting a verdict: it ships `sshd.service -> ssh.service` as an owned link in `/usr/lib` (24.04 has none, so `systemctl enable` creates it); `systemctl cat` annotates an empty `.conf` and a `/dev/null` drop-in alike "is a mask"; `systemctl enable` quotes its link paths; a multi-owner line orders the owners differently. Debian 13 (pastebin) was **not** measured: there is no systemd manager in the `debian:13` CI container, and R8's probe is the lead's.

**§3.5 items, as observed.**

| # | Observed |
|---|---|
| 1 | `systemctl show getty@.service` exits 1: "Failed to get properties: Unit name getty@.service is neither a valid invocation ID nor unit name." One template among several names fails the whole call with no output. A non-existent name exits 0 with `LoadState=not-found` and empty `FragmentPath`, `SourcePath`, `DropInPaths` and `UnitFileState`. An instance (`getty@tty63.service`) shows normally: `FragmentPath` is the template's, `Names` includes the instance's alias names (`autovt@tty63.service`), and `UnitFileState` is the template's. `list-unit-files` lists the template only; an instance appears in `list-units --all` only while loaded. An instance that is only a `.wants` link of a loaded target stays loaded (`loaded inactive dead`). An instance with only a `.d` directory is not listed, and a `show` of it does not keep it loaded. |
| 2 | A mask's `FragmentPath` is the link's own path: `/etc/systemd/system/x.service` (`UnitFileState=masked`) or `/run/systemd/system/x.service` (`masked-runtime`), never `/dev/null`. `LoadState=masked`; `systemctl cat` prints "# Unit x.service is masked."; `list-unit-files` says `masked` or `masked-runtime`. The vendor fragment under the mask is not reported by the manager. |
| 3 | A generated unit has `UnitFileState=generated`, `FragmentPath` in `/run/systemd/generator`, `generator.early` or `generator.late`, and `SourcePath` as the generator wrote it. Real `systemd-sysv-generator` (present on both releases): `SourcePath=/etc/init.d/<name>`, `FragmentPath=/run/systemd/generator.late/<name>.service`. A generator of our own (`/run/systemd/system-generators/`) works the same, and its units survive `daemon-reload` (regenerated). **Stock ubuntu 26.04 has two generated units with an empty `SourcePath`:** `netplan-ovs-cleanup.service` and `sshd-unix-local.socket`. 24.04 has none. |
| 4 | Removed but not purged (`deinstall ok config-files`): `dpkg-query -S` still names the package for its conffile and no longer for its program files; after purge, for neither. `info/<pkg>.list` keeps only the conffile paths. The contract's reading stands: a declared `exim4-base` makes a unit with such a conffile source clean. **Not shown:** that pastebin's `exim4` is in this state (§2.4); that needs R8's read. |
| 5 | Output: `pkg: /path`; several owners `a, b: /path` in no fixed order; `pkg:arch: /path` for a `Multi-Arch: same` package only (`tendcf-s1-m:amd64: ...`; a plain package has no qualifier); a directory lists every package that has it. No match: exit 1 and stderr `dpkg-query: no path found matching pattern /p`, with the other arguments' lines still printed on stdout. Diversion: `diversion by <pkg> from: <path>` and `diversion by <pkg> to: <path>` (`local diversion from:` and `to:` for a local one) before the owner line; querying the diversion's target prints the diversion lines only, with exit 0. A path with `*?[\` is a pattern unless escaped with a backslash; the escaped literal matches. `dpkg --force-overwrite` moves a file to the later package, so two packages share a path in the database only through a database that already lists both (a hand-written `info/*.list`, `s1lib.TestDb`, prints the same forms as real dpkg). **A missing admindir exits 1 "no path found", not an error.** |
| 6 | A type-wide `/etc/systemd/system/service.d/x.conf` is in `DropInPaths` of every service (`ssh.service`, `cron.service`, `systemd-journald.service`, a synthetic unit, an instance). Each covered unit is `two-writers`, loud as the contract says (fixture `test_type_wide_dropin_lands_on_every_unit_item_6`). |
| 7 | `systemd-analyze unit-paths`, with or without `--system`, prints twelve directories in precedence order, existing or not: `/etc/systemd/system.control`, `/run/systemd/system.control`, `/run/systemd/transient`, `/run/systemd/generator.early`, `/etc/systemd/system`, `/etc/systemd/system.attached`, `/run/systemd/system`, `/run/systemd/system.attached`, `/run/systemd/generator`, `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`, `/run/systemd/generator.late`. `DropInPaths` lists name, dash-truncated, template and type-wide drop-ins, empty `.conf` files, and an `/etc` `*.conf` link to `/dev/null`; it omits a same-named `*.conf` shadowed by a higher-precedence directory (including the one an `/etc` `/dev/null` link masks) and any file not ending `.conf`. In every case tried the probe found everything `DropInPaths` lists, and the probe found more only where shadowing explains it. |
| 8 | A `systemd-run --remain-after-exit` unit: `Transient=yes`, `UnitFileState=transient`, `FragmentPath=/run/systemd/transient/<unit>.service`; **`list-unit-files` does list it** (state `transient`), against §3.2(3). An alias name (`show sshd.service`): `Id` is the target's, `Names` has both, `FragmentPath` is the target's fragment, and `list-unit-files` has a row for the alias name with state `alias`. A vendor-directory link whose target lies in a subdirectory of a lookup directory loads as `bad` (not found); a target outside the tree (`/var/tmp/...`) loads, with `FragmentPath` the link's own path. `systemctl link` of an outside file creates `/etc/systemd/system/<name> -> <file>`. |
| 9 | `systemctl enable` creates the alias link for an `Alias=` in `<name>.d/*.conf` (`tendcfs1p9-viadropin.service`) and ignores one in a dash-truncated `tendcfs1p9-.service.d` and one in a type-wide `service.d`, while `systemctl cat` prints all three. |

**Contract changes for S2.** Each was folded into §3 by slice S2 (2026-11-02), except K5 and K13, which stay open and keep their text and K5's inline `[S2 K5]` note. The classifier already follows the observed behaviour:

1. **K1** §3.2(3): transient units do appear in `list-unit-files`. `Transient=yes` is still the only test.
2. **K2** §3.2(1), §3.2(4): `systemctl show` is never called for a template (it fails the call). A template's artifacts come from the probe alone; an instance is shown normally.
3. **K3** §3.2(4): a mask's `FragmentPath` is the link's path, not `/dev/null`. The mask is found by the probe.
4. **K4** §3.2(4): the `FragmentPath`/`DropInPaths` cross-check runs one way. `DropInPaths` entries the probe does not find are unverifiable. Probe-found drop-ins that `DropInPaths` omits are shadowed copies, judged as artifacts. This is the contract's "disagreement" made exact.
5. **K5** §3.2(4): a generated unit with an empty `SourcePath` stays `incomplete`, but stock ubuntu 26.04 has two, so a stock 26.04 host can never scan `complete`. **Open for the lead/S2:** accept this, or attribute such a unit through its generator (not done: the manager gives no link from a unit to its generator, and no generator header was checked). Debian 13 was not measured. The classifier keeps the contract.
6. **K6** §3.2(6): "effective `[Install] Alias=`" is the fragment plus `<name>.d` and the template's `.d`. A dash-truncated or type-wide drop-in is excluded, because `enable` ignores it (item 9). The classifier reads `systemctl cat` and keeps only those blocks.
7. **K7** §3.1, §3.3: "the dpkg database cannot be queried" needs a positive control, because a missing or empty database answers like a miss. The classifier queries `/usr/bin/dpkg-query` and `/usr/bin/dpkg` under both spellings and needs an owner for at least one.
8. **K8** §3.3: parse rules for `dpkg-query -S` are as item 5. A diversion line naming a queried path (`from` or `to`) makes that path unverifiable even when an owner line follows. Owner order is unspecified: use sets. An unrecognised stdout line, or an exit status other than 0 or 1, fails the whole query and the scan is `incomplete`.
9. **K9** §3.2(1), §7 item 14: an instance is enumerated only while the manager holds it loaded. A drop-in directory of an unloaded instance is the orphan case of §7 item 14, and is never judged.
10. **K10** §3.2(5), §3.4 row 3: an owned link to an unowned target is one fragment chain, not two fragments. The owned link is not a vendor fragment on its own, the unowned target is a local artifact, and rule 3 does not fire; with no claim the unit is `extra` (row 10), with an exact `third-party` claim it is `clean`. Reading row 3 literally would call the pair `two-writers` under any claim, which the astra A5 rule ("an owned link does not launder its target") does not ask for. This is the **fragment chain** only: the final target of a **drop-in** link keeps the drop-in's role (K14).
11. **K11** §3.4 row 4: "exact non-cfengine claim on the name" is read as the unit's `Id` or, for an instance, its template. A claim on an alias name does not license a drop-in on the unit. (Row 2's cfengine side still counts every name of the unit, an alias name included, as written.)
12. **K12** §3.2(1), §3.2(4-5), §3.1, R3d: evidence the scan cannot establish is never skipped, never a crash and never a zero. Each of these makes the scan `incomplete`, with no counters: a unit whose probe raises, or a `show` that fails for a non-template; a link chain with no final target (dangling, a cycle, or more than ten hops, `/dev/null` excepted); `systemd-analyze unit-paths` output with a record that is not an absolute path, or with no record at all (an unknown load path); a `list-unit-files` or `list-units` record that is not a unit name of the four types with its state fields (an empty listing stays legitimate, and is a complete scan of no units); and any command that fails or exceeds its time bound (120 s by default; the classifier reports it as exit 124).
13. **K13** §3.2(4), §3.4 row 4 (found on pastebin, below): a drop-in a generator writes under `/run/systemd/generator*` is unowned, so rule 4 calls the unit `two-writers` even when the generator belongs to a declared package. pastebin's `systemd-zram-setup@zram0.service` has `/run/systemd/generator/systemd-zram-setup@zram0.service.d/bindings.conf`, written by `systemd-zram-generator`. This is K5's family: generator output has no link back to its generator. **Open for S2, with K5:** attribute generator-directory artifacts through the generator, or accept the loud verdict and require an exact claim. No fixture covers it yet; the classifier keeps the contract.
14. **K14** §3.2(5), §3.4 rows 3-5: a link's final target keeps the role of the chain that reached it. A **fragment** link's target is a fragment (K10). A **drop-in** link's target is part of the layer: it is judged for ownership on its own (an owned target of an undeclared package is row 8), but it is never a vendor or a local fragment, so it cannot trigger row 3 or establish that a vendor fragment exists. A local drop-in link to an unowned file under an exact `third-party` claim is therefore `clean`, not `two-writers`; without the claim it is row 4. One file can be reached through both chains (a vendor fragment that an `/etc` drop-in also links to): the scan keeps one record per (path, chain), so the file stays a vendor fragment whichever load-path directory is scanned first, and a local override of it is still row 3. The JSON `artifacts` records therefore carry `role` (`dropin` on drop-in records and their link targets, `fragment` otherwise) and, on a link target, `via` (the link that leads to it); one path can appear twice, so a consumer keys by (path, kind, role). An owned link to an unowned fragment is one K10 chain whichever directory is scanned first: the fragment record keeps the `via` of the link.

**Fixture results.** `tests/unit_classifier/test_fixtures.py`, one independent test per row or variant, each with its own files and its own copy of the dpkg database, gated like policy check 6 (Linux booted by systemd, root, `TENDCF_TEST_SYSTEMD=1`). Fixtures write only under `/etc/systemd/system`, `/run/systemd/system` and `/usr/lib/systemd/system`, plus `/run/systemd/system-generators` (the generated-unit rows), and `/var/tmp` (the private dpkg databases, the outside-the-tree link target and the claims files). Ownership is arranged with synthetic packages in a private copy of the host's database; the real `ssh.service`, `kmod.service` and `hwclock.service` are used where the table names them, and a synthetic template `tendcf-s1-getty@.service` stands in for `getty@.service` (the real one has no instance a fixture can hold loaded without starting a getty). Results on all three runners, from [run 41506950654](https://github.com/frdminc/tendcf/actions/runs/41506950654) (branch workflow) and [run 41507052944](https://github.com/frdminc/tendcf/actions/runs/41507052944) (`linux.yml`, job `vm`): 57 tests, all passing on each. Mutation check: [run 41506077208](https://github.com/frdminc/tendcf/actions/runs/41506077208) with every unowned alias link authorized: exactly three fixtures went red on all three runners (`test_hand_made_alias_to_ssh_no_claim_is_extra`, `test_hand_made_alias_to_ssh_exact_third_party_is_still_extra`, `test_alias_named_only_by_a_dash_truncated_dropin_is_not_authorized`) and the other 54 stayed green. The same mutant also fails `test_logic.VerdictTable.test_unauthorized_alias_is_extra_even_under_exact_claim`.

| §6 row | Tests | Verdict asserted |
|---|---|---|
| Rogue `/etc` unit, no claim | `Ownership.test_rogue_etc_unit_no_claim_is_extra` | `extra` |
| Unowned file in the vendor directory | `test_unowned_file_in_vendor_dir_no_claim_is_extra` | `extra` |
| Undeclared package; undeclared co-owner | `test_unit_of_undeclared_package_is_extra`, `test_undeclared_coowner_is_extra_and_both_declared_is_clean` | `extra`; `extra`, then `clean` when both declared |
| Declared package, fragment only | `test_declared_package_fragment_only_is_clean`, `test_real_ssh_service_declared_is_clean` | `clean` |
| Enable-created alias `sshd.service` | `Aliases.test_enable_created_alias_authorized_by_target_alias_clean_counted_once` | `clean`, one unit record |
| `Alias=` from a drop-in on the target | `test_alias_authorized_by_dropin_on_the_target_is_clean`, and the K6 case `test_alias_named_only_by_a_dash_truncated_dropin_is_not_authorized` | `clean`; `extra` |
| Cfengine claim on the alias name | `test_cfengine_claim_on_the_alias_name_over_a_vendor_fragment_is_two_writers` | `two-writers` |
| Shipped alias `kmod.service`, shipped mask `hwclock.service` | `test_shipped_alias_and_shipped_mask_real_kmod_and_hwclock_are_clean`, `..._synthetic_are_clean` | `clean` |
| `evil.service -> ssh.service`, no claim / exact `third-party` | `test_hand_made_alias_to_ssh_no_claim_is_extra`, `..._exact_third_party_is_still_extra` | `extra` / `extra` |
| Local drop-in on `ssh.service` | `Layers.test_local_dropin_on_ssh_no_claim_is_two_writers`, `..._exact_third_party_is_clean` | `two-writers` / `clean` |
| Dash-truncated drop-in | `test_dash_truncated_dropin_no_claim_is_two_writers`, `..._exact_third_party_is_clean` | `two-writers` / `clean` |
| Drop-in on a generated unit from an owned source | `test_dropin_on_generated_unit_from_owned_source_no_claim_is_two_writers`, `..._exact_third_party_is_clean` | `two-writers` / `clean` |
| Persistent and runtime mask on `ssh.service` | six tests `test_persistent_mask_*`, `test_runtime_mask_*` (no claim / exact `third-party` / cfengine) | `two-writers` / `clean` / `two-writers`, each |
| Package-shipped drop-in under `/etc` | `test_package_shipped_dropin_under_etc_declared_is_clean` | `clean` |
| Instance drop-in, no claim / template `third-party` | `Instances.test_instance_dropin_no_claim_is_two_writers`, `..._exact_template_third_party_is_clean` | `two-writers` / `clean` |
| Local copy of `ssh.service` in `/etc`, exact `third-party` | `test_local_copy_of_ssh_in_etc_exact_third_party_is_two_writers` | `two-writers` |
| Local instance fragment under a template `third-party` claim | `test_local_instance_fragment_under_template_third_party_is_two_writers` | `two-writers` |
| Instance mask, persistent and runtime, three claims each | six tests `test_persistent_instance_mask_*`, `test_runtime_instance_mask_*` | `two-writers` / `clean` / `two-writers`, each |
| Cfengine claim and present service on `ssh.service`, no local file | `Claims.test_cfengine_claim_and_present_service_on_ssh_no_local_file_is_two_writers` | `two-writers` |
| Tombstone under a cfengine claim, file surviving | `test_tombstone_with_surviving_regular_file_is_unmet_absence` | `unmet-absence` |
| Claim only in a `not-yet-migrated` domain | `test_claim_only_in_a_not_yet_migrated_domain_is_clean` | `clean` |
| Present and tombstone across domains | `test_present_in_supervision_and_tombstone_in_another_domain_is_incomplete_naming_both` | `incomplete`, both addresses named |
| Generated unit from an owned source | `Generated.test_generated_unit_from_owned_source_declared_is_clean`, `..._undeclared_is_extra` | `clean` / `extra` |
| Generated unit, empty `SourcePath` | `test_generated_unit_with_empty_sourcepath_is_incomplete` | `incomplete`, no counts |
| `systemd-run` transient | `Transient.test_systemd_run_transient_unit_is_not_judged` | not judged |
| Owner under `/lib` only | `Ownership.test_owner_recorded_under_lib_only_is_package_tier` | package tier: `clean` declared, `extra` undeclared |
| No owner; multiple owners; arch-qualified; vendor symlink outside the tree | `test_successful_lookup_with_no_owner_is_name_tier_not_a_failure`, `test_undeclared_coowner_*`, `test_architecture_qualified_owner_maps_to_the_package`, `test_vendor_symlink_to_target_outside_the_tree` | `clean` with a claim; as above; `clean`; `extra` (target unclaimed) or `clean` (exact claim) |
| A diversion on the path | `test_a_diversion_on_the_path_is_incomplete` | `incomplete`, no counts |
| `dpkg-query` removed from `PATH`; no `/run/systemd/system` | `Gates.test_dpkg_query_removed_from_path_is_incomplete_without_counts`, `test_no_run_systemd_system_is_incomplete_without_counts` (a private mount namespace with a tmpfs over `/run/systemd`) | `incomplete`, no counters |
| `supervision` not comprehensive | `Claims.test_supervision_not_comprehensive_is_not_run` | `not-run` |
| Review fixes (K12, K14, sandbox) | `DropinLinks` (five rows: local and owned drop-in targets, with and without an exact claim), `UnresolvedLinks` (dangling, shadowed dangling, cycle, over-limit, `/dev/null` exempt), `Gates` (unit-paths and list records malformed; empty listings legitimate), `SandboxRestore` (a regular file masked and restored on the real manager; `/dev/null` untouched; setuid/setgid and a foreign owner survive a root restore), `DropinLinks` shared-path rows (a vendor file that is also an `/etc` drop-in's target stays a fragment: rule 3). The sandbox, probe-exit-status and classifier-logic regressions run without root: `test_sandbox.py`, `test_probe.py`, `test_logic.py` | |
| Added by S1 | `Baseline` (a clean host scans complete, or incomplete only for stock generated units, K5), `Layers.test_type_wide_dropin_lands_on_every_unit_item_6`, `Gates.test_unusable_dpkg_database_is_incomplete_not_zero_owners` (K7), `ReadOnly.test_a_scan_changes_nothing_on_disk_or_in_the_manager` | |

**Read-only.** `Env.run` refuses every argv outside `systemctl show|cat|list-units|list-unit-files`, `systemd-analyze unit-paths` and `dpkg-query -S` (`test_logic.ReadOnly`). A scan's only filesystem calls are `lstat`, `readlink` and listing the drop-in directories of a unit's own names. `systemctl show NAME` makes the manager load NAME; that is inherent in enumerating through the manager, and it never starts, stops, enables or reloads anything. Every command is bounded (K12).

**pastebin (R8, the one allowed read-only probe, 2026-11-02).** It ran unprivileged (`ssh pastebin.xvm.mit.edu python3 - --claims-json …` with `tests/unit_classifier/pastebin-claims.json`); nothing was written on the host. Result: `extra_scan` **`complete`**, 249 units judged: 247 `clean`, 1 `extra`, 1 `two-writers`, `unmet_absence` 0, no conflicts, nothing incomplete. Debian 13 does not hit K5.
1. **The two index-based attributions are measured now:** `/etc/init.d/exim4` is owned by `exim4-base` and `/etc/init.d/zhm` by `zephyr-clients`, both read from pastebin's database. Both units are `clean`, and §2.4 needs no change for them.
2. **`tendcf.canary.service` is `extra` (rule 7).** The verdict is correct for the input. The claims file carries §2.4's `tendcf.canary.*` cfengine claim, but not the canary goal file's `service` entry. On the host, R3c's union over all domains supplies it, so S4's declaration must include that entry, or point the classifier at both files.
3. **`systemd-zram-setup@zram0.service` is `two-writers` (rule 4).** This is K13 above.

**Not proven.** Only `.service` units have fixtures. `.socket`, `.timer` and `.path` take the same code path, and the 26.04 baseline judges `sshd-unix-local.socket`, but no fixture asserts a verdict on one. Generator-written drop-ins have no fixture; K13 was seen only on pastebin. Also unmeasured: `snap` units, user managers, and the full-scan time on a unit-heavy host.

## 4. Migration (one PR, S2)

Enumerate from disk; these counts are not a substitute. Corrections to the draft are in §8.

1. **Ceremony** (astra A8). A bare `version_bump` is valid only for a baseline that remains valid at v5 and whose rendered content changes solely in `schema_version`. Audit each one for retired `dpkg` claims, tombstone ownership and non-cfengine prefix keys on a systemd host (§2.1(4)), and re-adopt otherwise. **Audit, run:** at v5 `examples/goal-file.json`, `goal-file-baseline.json`, both canary files and the passthrough fixture all validate and pass the §2.2 rules. No file uses `writer: dpkg` outside case 98. No device baseline exists, because the agent is unbuilt. Declaring pastebin's units is a separate later diff (S4).
2. **Hashes and overlays.** Bump goal-family overlays, regenerate `examples/goal-diff.json`, every approval record and diff or record overlay, regenerate `broken-bytes` 44-48, bump `58-not-json.json`, and re-embed projection case 75. Case 13 claims `6`.
3. **Case 98** uses `writer: dpkg`. Change it to `third-party`, or it also fires `enum`. Run: with `third-party` it fires `if/then` alone.
4. **Case 64** has a tombstone under `homebrew`. Delete that tombstone, in S0 with the rule (§6). Otherwise the new rule also fires in `goal cross-file`, and deleting the present-service rule leaves the case green. Run: without it, only the present-service finding fires. Cases 35, 36 and 73 also trip the new rule, but they declare a `schema` class, so they still discriminate.
5. **Case 35** keeps ``schema (`pattern`)``: run under the single regex, the evidence holds `pattern` (Fable F7). Its host is launchd, so `if/then` fires beside it.
6. **Lint and counts.** §2.2. `EXPECTED_BROKEN` 86 (S0, §6) to **125** (`bin/schema_lint.py`; recomputed from disk in S2): the 38 cases of §5 that live in `broken/` (113-128 and 132-154, less 145, which is a projection case) make 124, and R5's case 155 makes 125, so the spec's 124 omitted R5's case; `EXPECTED_PROJECTION` 27 to 28 (case 145); "eighty-six" to "one hundred twenty-five" (the lint docstring, `examples/broken/README.md`); the case ranges in that README; the root `README.md` total (125 + 6 + 28 = 159); the "claims version N" notes (case 13 claims 6).
7. **Report rows.** `examples/report-rows.yml` has one `domain_coverage` row. It gets `extra_scan: complete`, `two_writers: 0` and `unmet_absence: 0` (§2.3(2)).
8. **Happy fixture.** `deploy/linux/canary/goal-file-debian.json` with its projection, wired into `check.py` `PAIRS` (`:31-39`). Reword the comment at `:34-37`, because `unit-package` joins the non-projecting kinds.
9. **Prose.** `bin/projector.py:434-438`; the writer-prefix wording in §2.1(5) and §2.3(1); `linux-targets.md` row 4, noting v5.
10. **One-writer amendment** (astra A1). R2 admits one layered form, so these stop being literally true and must be amended in the same PR: `architecture-DEFINITIVE-v3.md:188-190` ("exactly one writer per unit-name prefix ... Two writers on one unit is a lint failure") and `docs/paper/tendcf-architecture-guide.md:166`. New meaning: one writer per unit name in the goal file's name claims, a package claim for what a package ships, and a local drop-in or mask on a vendor unit admitted only under an exact non-cfengine claim. Lint proves uniqueness among name claims and package ids only. The device detects the rest.
11. **nix2cf.** `GOAL_FILE_SCHEMA_VERSION` is `4` (`nix2cf/compile.py:42`), and `scripts/check_schema_version.py` fails CI when it differs from tendcf's const. Bump it to `5` and regenerate goldens. nix2cf renders no `unit-package` yet, and the Site Model has no systemd writer registry (§7 item 12). Grep finds no `dpkg` reference in its package or README.
12. **Discrimination (F8; astra A8).** For each new rule, record the expected witness set and verify those fixtures are unexpectedly accepted when the rule is deleted. One defect per fixture does not imply one fixture per rule. Run `bin/flag_coverage.py` where it applies.

## 5. Negative cases (113-155)

The series is shared across fixture directories. `broken/` ends at 112 and `broken-projection/` at 92, so new cases start at 113. Cases 129-131 land first, at v4, in S0 (§6). R5's cross-domain rule (§2.2(7)) takes the next free number, 155. Each row has one defect. Unless stated, the base is the canary goal file at v5 (systemd). Class tokens are from the prototype run; take exact messages from the real lint and correct the README row to match.

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
| 126 | `126-tendcf-install-launchd` | launchd happy file; `org.example.x.*` with `tendcf-install`. Run: with the supervisor's writer prohibition deleted, the full pipeline accepts it | schema (`if/then`) |
| 127 | `127-tendcf-install-runit` | runit base; the same entry and the same run | schema (`if/then`) |
| 128 | `128-service-exact-non-cfengine` | present `foo.service` under exact `third-party`. A regression of `covers` on exact keys and a variant of 64; it would not catch a return to `startswith` (Fable F9), which the template row in the positive list does | goal cross-file |
| 129 | `129-tombstone-no-claim` | comprehensive; tombstone `ssh.service`, no claim | goal cross-file |
| 130 | `130-tombstone-non-cfengine-claim` | launchd happy file; tombstone `org.example.retired` under `org.example.*` with `third-party` (astra A8). A retained v4 key, so it holds at v4 and v5, and the launchd witness of §2.2(4) | goal cross-file |
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
| 146 | `146-row-no-extra-scan` | `report-rows.yml`: a `not-run` row without `extra_scan` (astra's spec review, A4; Fable's optional case) | schema (`required`) |
| 147 | `147-row-bad-extra-scan` | `extra_scan: partial`, no counters | schema (`enum`) |
| 148 | `148-complete-no-two-writers` | `extra_scan: complete` without `two_writers` | schema (`if/then`) |
| 149 | `149-complete-no-unmet-absence` | `extra_scan: complete` without `unmet_absence` | schema (`if/then`) |
| 150 | `150-incomplete-two-writers` | `extra_scan: incomplete` with `two_writers: 0` | schema (`if/else`) |
| 151 | `151-incomplete-unmet-absence` | `extra_scan: incomplete` with `unmet_absence: 0` | schema (`if/else`) |
| 152 | `152-not-run-extra-entries` | `extra_scan: not-run` with `extra_entries: 0` | schema (`if/else`) |
| 153 | `153-not-run-two-writers` | `extra_scan: not-run` with `two_writers: 0` | schema (`if/else`) |
| 154 | `154-not-run-unmet-absence` | `extra_scan: not-run` with `unmet_absence: 0` | schema (`if/else`) |
| 155 | `155-service-present-and-tombstone-across-domains` | canary file; domain `apps` (`not-yet-migrated`) holds a tombstone for `tendcf.canary.service`, which `supervision` declares present (R5; §2.2(7)) | goal cross-file |

Each report-row case, 143 and 144 included, starts from an otherwise valid row. Run: all eleven are rejected, and each is accepted once the one clause it exercises is deleted. The rows' evidence also holds the `oneOf` tokens of the row union.

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
| S0 | tendcf | The live tombstone hazard at v4, on both tombstone paths: §2.2(4)'s rule, cases 129-131, case 64's cleanup; `isplain` instead of `fileexists` at `policy/tendcf_services.cf:241`, with a `tests/policy/run.sh` check. Details below | spec merged |
| S1 | tendcf | Read-only classifier prototype of §3 (`linux-targets.md` row 4 calls for a bump from a prototype): §3.5, and the fixtures below | spec merged |
| S2 | tendcf | §2, §4, §5 in one PR; a bump cannot be split | S0; S1's results read and incorporated; R5's cross-domain lint rule implemented (the row shape and the contradiction ruling are settled by R4 and R5) |
| S3 | nix2cf | §4(11) | S2 merged |
| S4 | tendcf | The real pastebin declaration from §2.4, as an ordinary diff, re-read at that time because the list moves with `apt` | S2; S1's reading of the two index-based rows (§7 item 13) |
| S5 | tendcf | The detector proper | §7 item 13 ruled |

**S0's scope:**
1. **systemd.** `isplain` guards direct teardown of a symlink path. It does not establish who rendered a regular file, prevent vendor shadowing, or guarantee that `systemctl disable` removes no other activation links. The `tests/policy/run.sh` check covers regular-file teardown and refusal on alias, mask and dangling-link paths.
2. **launchd.** `isplain` is systemd-only by design, because a plist is a plain file whoever wrote it. S0's PR states that launchd relies on the lint rule alone (§2.2(4)).
3. **Witnesses, all at v4.** 129 and 131 use the canary goal file; 130 uses the launchd happy file. Run against the v4 schema on disk: no schema error, and only the new rule fires. Case 64 without its tombstone fires only the present-service rule.
4. **Interim counts.** `EXPECTED_BROKEN` goes 83 to 86 in S0, and 86 to 124 in S2. "Eighty-three" becomes "eighty-six" (`bin/schema_lint.py:36`, `examples/broken/README.md:3`). The README's goal-file case list (`:8`) gains 129-131 and says 113-128 are reserved until S2.
5. **Deployment.** S0 is the one slice that changes live-host behaviour. Per R6 it merges after CI and review and is deployed to pastebin with the installer, and the canary is checked afterwards.

**S1 fixtures,** on a ubuntu VM (`TENDCF_TEST_SYSTEMD=1`). Each states its result independently (astra A2, A5). Rows naming a vendor unit assume its package is declared unless they say otherwise:

| Fixture | Expected |
|---|---|
| Rogue `/etc/systemd/system/systemd-rogue.service`, no claim | `extra` |
| Unowned file in the vendor directory, no claim | `extra` |
| Unit of an undeclared package; undeclared co-owner | `extra` |
| Declared package, its fragment only | `clean` |
| Enable-created alias `sshd.service`, authorized by the target's `Alias=`, package declared, no name claim | `clean`, counted once |
| `Alias=` supplied by a drop-in on the target, link present | `clean` |
| Cfengine claim on the alias name `sshd.service`, target a vendor fragment | `two-writers` |
| Shipped alias `kmod.service`; shipped mask `hwclock.service`; package declared | `clean` |
| `evil.service -> ssh.service`: no claim / exact `third-party` | `extra` / `extra` |
| Local drop-in on `ssh.service`: no claim / exact `third-party` | `two-writers` / `clean` |
| Dash-truncated drop-in `foo-.service.d/x.conf` on a declared package's `foo-bar.service`: no claim / exact `third-party` | `two-writers` / `clean` |
| Local drop-in on a generated unit from an owned source (pastebin's `zhm.service` shape): no claim / exact `third-party` | `two-writers` / `clean` |
| Persistent mask and runtime mask on `ssh.service`: no claim / exact `third-party` / cfengine claim | `two-writers` / `clean` / `two-writers` |
| Package-shipped drop-in under `/etc`, declared | `clean` |
| `getty@tty1.service.d/x.conf`: no claim / exact `getty@.service` `third-party` | `two-writers` / `clean` |
| Local copy of `ssh.service` in `/etc`, exact `third-party` | `two-writers` |
| `getty@.service` owned and declared; local `getty@tty1.service` fragment under a `getty@.service` `third-party` claim | `two-writers` |
| The same; instance mask, persistent and runtime: no claim / `getty@.service` `third-party` / covering cfengine claim | `two-writers` / `clean` / `two-writers` |
| Cfengine claim and present service on `ssh.service`, no local file | `two-writers` |
| Tombstone under a cfengine claim, the regular file surviving | `unmet-absence` |
| Claim only in a `not-yet-migrated` domain | `clean` (R3c) |
| Present in `supervision`, tombstone for the same id in another domain | `incomplete`, naming both addresses |
| Generated unit from an owned source: declared / undeclared | `clean` / `extra` |
| Generated unit with empty `SourcePath` | `incomplete` |
| `systemd-run` transient service (`Transient=yes`) | not judged |
| Owner recorded under `/lib` only, for a file reported under `/usr/lib` (pastebin's `tailscale` shape) | package tier |
| Successful lookup, no owner; multiple owners; architecture-qualified output; vendor symlink to a target outside the tree | as §3.3 and §3.2(5) |
| A diversion on the path | `incomplete` |
| `dpkg-query` removed from `PATH`; no `/run/systemd/system` | `incomplete`, no counts |
| `supervision` not comprehensive | `not-run` |

Then read-only on pastebin, results recorded. This is the one further read-only probe R8 allows before S4.

## 7. Residue, recorded rather than fixed

**Open points astra raised that the rulings leave as residue:**
1. **Layered ownership is admitted, not proven safe** (A1). R2 admits a local drop-in or mask under an exact non-cfengine claim, and §4(10) amends the one-writer text to say so. Two parties still shape one unit. Lint cannot see it.
2. **New units inside a declared package do not surface** (A7, A10; R1). A declared package gains a daemon in an upgrade and no consent hunk shows. C3's per-unit consent was the stronger signal; R1 traded it for a stable file. C4 reports units of an undeclared package, not "every newly installed daemon".
3. **`state: absent` cannot be honoured for a name with a vendor fragment** (A3; R2). Removing `/etc/systemd/system/ssh.service` reveals the vendor unit, and disabled is not absent. The device reports `two-writers` and the §2.2(4) rule does not catch it, since a cfengine claim satisfies it. Withdrawal versus absence belongs to the deferred externally-written-unit feature.
4. **Ownership misses accidental edits** (A5; R3b). A hand-edited package-owned file still counts as owned. R3b chose no hash verification; `dpkg --verify` is the path if that changes. This limits "accidents only" too: not every accident is detected. A deliberate forgery of the database is out of scope.
5. **Comprehensive means four types on systemd** (A9; R2). On pastebin 102 of 332 rows are not judged. Target dependency edges can activate services and mount operations can run helpers, so excluded types are not harmless, only undescribed.
6. **Activation links are not classified** (A2; Fable F2). A hand-made `.wants/` link starts a unit without any artifact the detector judges. Pastebin's `/etc` has 15 `*.wants` directories whose contents were not read.
7. **Report-only** (B6). No part of v5 prevents a competing write. The adapter cannot enforce these claims, since they do not project.

**Other residue:**

8. **Signed meaning depends on an unsigned local database** (Fable). Two devices with one goal file can cover different unit sets, and any `apt install` on a general-purpose host moves `extra_entries`. Report-only and a fixed-role host make that payable.
9. **Names outside the grammar.** systemd permits names the key regex does not, such as `\` escapes in a non-template name. They can still be covered by package ownership or an applicable prefix or template. An unowned unit that needs a non-cfengine exact claim, and has no representable covering template, has no clean spelling under v5. None of pastebin's 230 listed names is affected.
10. **A hand-made alias has no clean spelling** (§3.2(6)), and a local copy of a vendor fragment has none under any claim (§3.4). Both surface on a host that has them. On pastebin the second count is zero between `/etc` and `/usr/lib`. The first turns on two links whose targets and `Alias=` lines were not read (§2.4).
11. **Other scopes.** User managers, and any systemd host without dpkg, which can only ever be `incomplete`. rpm would widen the `unit-package` writer enum in a counted bump. Ubuntu snap units need exact claims, unverified.
12. **The Site Model has no systemd writer registry** (draft C.5). `launchd-writers` is launchd-only and `services.schema.json` has no writer data, so nix2cf has no source for these claims. A step 6 question under Q8.
13. **Detector ownership after the first implementation.** R4 assigns the detector to the CFEngine policy bundle. Amended 2026-11-02 by `architecture-DEFINITIVE-v3.md` D45: a later takeover by tendcf-agent on Linux is closed, because tendcf-agent is Android-only. Open is whether another command ever takes the detector over from the policy bundle (map §12 item 8). Superseded text, kept: ~~**For the operator:** settled by R4-R8 (§1). One point is still open: whether tendcf-agent later takes over the detector (R4).~~ Also still open, and to be settled in S2 before the shape freezes: how generator output is attributed (K5 and K13, §3.6).
    - The canary's `comprehensive` is false today (draft A.2) and stays so until a detector exists. A retreat ceremony on pastebin buys nothing checkable now, so C5 is deferred, not a stopgap (Fable F11).
14. **Orphan drop-in directories.** A `<x>.service.d/` with no unit loaded is invisible to the manager, hence never judged. On pastebin, all 15 `/etc` drop-in directories name a listed unit.

## 8. Where the inputs were wrong, and how each finding was resolved

**Where they were wrong:**
1. **Draft C.3 partitioned by directory.** A package-shipped file under `/etc` had no legal spelling (Fable F1).
2. **Draft "why this keeps one writer per unit" is false.** Choosing an effective file picks a winner; it does not remove the other writer (astra A1, Fable F4).
3. **Draft C.3 step 4 accepted a tombstone as "an entry in `service`"** (astra A3).
4. **Draft A.4 dated the tombstone hazard to v5.** It is live at v4, shown by running it (§2.2(4)).
5. **Draft's `maxLength: 128` narrowed v4 keys** (astra A6), and its `anyOf` was needless (Fable F7).
6. **Draft sketch used `third-party` for `tendcf-execd.service`.** R3a.
7. **Draft D.3 numbering is superseded.** Draft 113-116 keep their numbers; 117 to 118; 118 to 120; 119 to 121; 120 to 122; 121 to 124; 122 to 128; 123 to 129; 124-126 to 132-134; 127-130 to 135-138; 131 to 142; 132 to 145.
8. **Fable F2's alias rule, taken alone, would flag shipped links.** It names `dbus-org.freedesktop.login1.service` as postinst-created; on pastebin that is a `systemd`-owned link in `/usr/lib/systemd/system` (measured). §3.2(6) puts ownership first. `syslog.service`, its other example, is not on pastebin at all.
9. **astra A5 made zero owners unverifiable.** With Fable F1's partition, a successful zero-owner lookup enters the name tier, and it is clean when a name claim covers its local artifacts under §3.4. A failed or unparseable lookup is unverifiable and makes the scan incomplete.
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
| Fable Q-B | Ruled: R4, the policy bundle. ~~Whether tendcf-agent takes it over later is still open.~~ Amended 2026-11-02 by D45: takeover by tendcf-agent on Linux is closed; possible reassignment to another command remains open (§7 item 13). |
| Draft C.5 items 1-9 | 1: §7 item 2. 2: §7 item 3. 3: §7 item 4. 4: fixed by F5. 5: §7 item 11. 6: §3.3, §3.5. 7: §7 item 11. 8: §2.2(6). 9: §7 item 12 |
| Draft F.3 unverified list | pastebin list, pastebin ownership in the unit directories, package-name pattern, regexes and lint: done here. Resolution, generated units, snap: §3.5, §7 item 13, §7 item 11 |

**The spec reviews (2026-11-02).** astra (`SA`) reviewed commit `973c0a6`; Fable (`SF`) reviewed the same document. Both returned "sound with changes", and neither reopened R1-R3. Their reports are in the run's state directory, outside this repository, and this table is the record here. Both recomputed §2.4 from the data file and agree with it. Neither ran a regex, lint, schema or policy, nor any systemd or dpkg behaviour; §3.5 stands.

| Finding | Resolution |
|---|---|
| SA1 alias exceptions contradict the verdict table | Adopted, one rule with SF1 and SF9. §3.2(6); §3.4 rows 2, 9, 10; §6 fixtures |
| SF1 §3.2 cannot locate a mask or alias link | Adopted, merged with SA2 into one probe. §3.2(4), §3.5 item 7. **Added here:** the dash-truncated drop-in directories, because otherwise the cross-check calls a legal drop-in a disagreement and the whole scan incomplete. Pastebin's `user-.slice.d` shows the shape |
| SF9 effective `[Install]`, not the fragment's | Adopted in §3.2(6). Checked against upstream v257 `install.c`, read, not run; §3.5 item 9 |
| SA2 hidden vendor fragment through a template | Adopted. §2 terms, §3.2(4), §6 fixtures |
| SA3 contradictory service states across domains | Ruled: R5, rejected in lint with a defensive `incomplete` in the detector. §3.1, §3.4 row 1, §6 fixture and S2's dependency |
| SA4 report-row patch mixes properties and keywords | Adopted. §2.3(2) in three explicit locations; cases 146-154, all run with a deletion mutant. Case 146's base is a `not-run` row: with counters present, the `else` branch would keep it rejected when `required` is deleted |
| SA5 cases 126-127 cannot discriminate | Adopted. §2.2(5), §5; run |
| SA6 two residue statements contradict the classifier | Adopted. §7 item 9, §8 item 9 |
| SA section D: S0 witness, `isplain` claim, S2's dependency | Adopted. §5 case 130, §6 |
| SF2 transient units not identified | Adopted. §3.2(1), §3.2(3), §3.5 item 8, §6 fixture |
| SF3 launchd tombstone path | Adopted, with one correction. §2.2(4), §6. SF3 names case 64 as the launchd witness, but §4(4), which SF's own §1 endorses, deletes that tombstone. **Case 130 is the witness instead:** moved to the launchd file with a retained v4 key, which also meets SA section D. Run at v4 and v5 |
| SF3 S0 deployment | Ruled: R6, deploy after merge. §6 |
| SF4 a name claim never covers an owned artifact | Adopted. §3.4 |
| SF5 dead disjunct in `overlap` | Adopted by deletion. §2.2(1); truth table re-run, both directions, unchanged |
| SF6 §8 item 9 contradicts §3.4 | Adopted, merged with SA6. §8 item 9 |
| SF7 §4(1) omits the prefix-writer restriction | Adopted. §4(1) |
| SF8 S0 lands cases before 113-128 exist | Interim counts stated, without renumbering. §6. The count is 86, not SF8's 85, because case 130 also lands in S0 |
| SF10 counters on every complete row | Adopted as the description's wording. §2.3(2); the row shape is adopted by R4 |
| SF section 5: orphan drop-in directories; a row with no `extra_scan` | Adopted. §7 item 14; case 146 |
| SF section 6: template key reading of R2 | Confirmed: R7 |

## 9. S2 as implemented: corrections and checks (2026-11-02)

Slice S2 implemented §2, §4 and §5 in one PR. Items 1-3 and 6 are corrections to this document, made in the text above; the rest are checks S2 ran.

1. **The count was one short.** §4(6) said `EXPECTED_BROKEN` 86 to 124. The 38 cases of §5 that live in `broken/` (113-128, 132-154, less 145) make 124, and R5's cross-domain case, which the spec reserves no number for, is the 39th: `EXPECTED_BROKEN` is **125**, the case is **155**. §4(6), §5 and the README were corrected.
2. **Three `startswith` matchers, not two.** §2.2(1) named two (`:1571`, `:1586`); S0 had added a third, in the tombstone rule. All three now go through `unit_key_covers`, and the nesting check through `unit_keys_overlap`. The line references in §2.2 and §3.1 no longer point at anything; the symbols are named instead.
3. **The line references of §4(10) were stale.** The one-writer sentence is at `architecture-DEFINITIVE-v3.md:191-193` after D45's amendments and `tendcf-architecture-guide.md:168-171`. Both are amended with the superseded text struck through.
4. **Every new case was run through the full pipeline.** Each fires its declared class; the only other findings are the family layer's on a goal-file overlay (exempt by design), and 35 and 36 fire their schema classes beside the cross-file ones, as §4(4) says. Case 113 replaces `tendcf.canary.*` with `*`, as §5 says, so the service stays covered and only the schema fires; 118 and 119 fire only the overlap rule.
5. **Rows 126 and 127 hold as written.** With the supervisor's `tendcf-install` prohibition deleted from schema, the full pipeline raises nothing but the family layer's noise, so the case discriminates.
6. **Case 145 was run** (the status block's item 2 said not): it fails the closed-container rule of `validate_projection()`.
7. **Positive witnesses 1-6 and 9 live in `deploy/linux/canary/goal-file-debian.json`** (checked by `deploy/linux/canary/check.py`); witnesses 7 and 8 were run and are not a fixture, because a cfengine claim on `ssh.service` beside `openssh-server` is statically clean but semantically a device `two-writers`, which a happy file should not claim.
8. **S1's K1-K12 and K14 are folded into §3;** K5 and K13 (generator output) are left as S1 wrote them, pending the operator.

Discrimination (§4(12)), run in S2 by deleting one clause at a time: each new lint rule (`unit_keys_overlap` use, the cross-domain rule, package uniqueness, the `tendcf-install` rule, the present-service writer rule) turns exactly its cases red; each new schema clause (the key regex, the three supervisor members' `unit-writer` and `unit-package` rules, the nixos `unit-package` ban, the package map's `pattern`, `enum`, `minProperties`, `const`, `required` x2 and `additionalProperties`, and the report row's `if/then/else` and `required`, one property at a time) turns exactly its cases green. `bin/flag_coverage.py` covers `check_projection()` only and was not affected.
