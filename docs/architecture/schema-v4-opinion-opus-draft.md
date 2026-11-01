STATUS: recovered by acp-dispatch from the agent's final message (the agent did not write the report file)
Reading the schema lint's negative-case table and the passthrough/canary goal files next.Checking report-row's validator version field, the projector, and the passthrough/canary goal files.Checking whether an inventory schema exists and how the goal-diff header is handled, since that decides where `supervisor` can live.I couldn't write the report file or its `.done` marker: this run is read-only. So the whole design document is below, and acp-dispatch saves it to `/Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md`.

STATUS: complete (read-only run; delivered as final message)

# tendcf Stage D design: `supervisor: nixos`, schema_version 4, consent diff

Design lead: Opus 5.5 high. Repo read: `/Users/djbclark/src/tendcf-review-policy-wt` at branch `review-policy-rule` (9118bb1).

**What I could not do.** I had no shell in this run. That means I did not run `book-kb`, `graft`, `bin/schema_lint.py`, `check.py`, `nix` or anything on get. Every CFEngine claim below comes from repo code or comments, not from the book, and is marked [code]. Every jsonschema error string is written from memory and marked [mem]. Settled facts 1–4 are taken from the brief as given.

## A. Problem, and what D1–D3 require

The reverse-DNS unit-writer prefix pattern (`goal-file.schema.json:243`) cannot name any NixOS unit. The passthrough goal file's `org.nixos.*` matches none of get's 116 units (fact 1). The rulings require:

- **D2.** A host-level `supervisor: nixos` fact, added in schema_version 4. It claims the host's whole unit namespace with no per-unit prefix. Nix2cf step 6 reads it.
- **D3.** On a nixos-supervisor host, tendcf actuates nothing. It reports and refuses, and cf-execd stays off. The schema must make service actuation unrepresentable there, tombstones included.
- **D1.** The consent artifact for a Nix host shows three things:
  - the flake.lock diff plus the Nix-side diff, as the authority;
  - the evaluated-options JSON, as a readable summary;
  - `nix store diff-closures`, which already exists.

**Questions for the operator.** The rulings leave these open. I recommend an answer for each but do not decide them.

- **Q1 — required or optional.** Is `supervisor` required on every v4 goal file, with the closed set `launchd|systemd|runit|nixos` and a lint forcing unit flavour to match? Or is it optional and `nixos`-only?
  - Recommend required. The house rule is "every scalar is required with its explicit value" (`goal-file.schema.json:5`). An optional fact whose absence means "the prefix scheme governs" is a hidden default.
  - The cost: a lint is needed to keep `supervisor` from becoming a second spelling of the unit flavour. Reconciliation §7 rejected a platform field for exactly that reason (`goal-file-schema-reconciliation-2026-08-15.md:380-383`).
- **Q2 — where it lives.** Is it a singleton `device-trust` kind (recommended) or a literal top-level header field? See B.1.
- **Q3 — supervision coverage on a nixos host.** Should it be `deliberately-unmanaged` (recommended) or `comprehensive` with no entries?
  - `deliberately-unmanaged` gets "no entries" from the existing `if/then` (`goal-file.schema.json:47-51`), and leaving it later is a privileged ceremony (`bin/schema_lint.py:1502`).
  - The cost: the device runs no extra-entry detection on that domain.
- **Q4 — binding the Nix side.** Does v4 bind the Nix side into the signed goal file, for example a flake.lock digest in the way `policy-tree` binds policy bytes? Or is the D1 consent diff display-only?
  - Recommend display-only for v4. Under D3 tendcf actuates nothing Nix-side, so a bound digest would be a claim nobody enforces.
  - Binding it later is its own bump. **This is a data-shape choice; a wrong answer means another bump.**
- **Q5 — distro family.** Does it ride along in v4 (one bump instead of two), or stay deferred? It is the other deferred "slice B" field. Not ruled; no recommendation.
- **Q6 — who approves.** With no tendcf-agent and get deployed by its own image pipeline, who approves the D1 artifact, and where? Recommend a required PR check and artifact on the host-flake repository (get / site-djbclark) that gates merge.
- **Q7 — the `nixos` writer value.** Drop `nixos` from the goal-file `writer` enum in v4 (recommended: it has no legitimate use left; see B.3)? Leave Site Model `launchd-writers` alone, since it is versioned by contract_version (`schema/launchd-writers.schema.json:9`), not by the goal-file family.

## B. Schema change for schema_version 4

### B.1 Where `supervisor` lives

**Recommendation: a fifth `device-trust` kind, singleton.**

```json
"supervisor": { "host": { "state": "present", "name": "nixos" } }
```

Reasons:

1. **There is precedent.** `trust_tier` is a Site Model inventory fact (`architecture-DEFINITIVE-v3.md:178-180`). In the goal file it became a `device-trust` entry, explicitly "rather than a header field … the diff schema needs no header-hunk machinery" (`goal-file.schema.json:321`; reconciliation `:374-383`). `supervisor` is the same kind of thing: an inventory fact that sets privilege scope.
2. **The header is closed.** The diff can change exactly one header thing, `version_bump` (`goal-diff.schema.json:26`). A top-level `supervisor` could not be changed by any diff. Every change would force a new first-adoption ceremony, and `apply_diff` (`bin/schema_lint.py:1509ff`) could not reproduce one.
3. **Privilege comes for free.** Any hunk under `device-trust` is privileged (`bin/schema_lint.py:1498-1499`). So nixos → systemd, which unlocks CFEngine unit writes, can never pass as an ordinary ceremony.
4. **It never reaches the device.** The projector excludes `device-trust` (`bin/projector.py:23-36`), so `{"vars":{}}` is unchanged.
5. **The trust-region property test covers it.** `check_trust_inexpressible` iterates whatever trust kinds the happy fixture carries (`bin/schema_lint.py:1841`), so a fifth kind is covered once `examples/goal-file.json` has it.

The literal "host-level" wording in D2 could also mean a top-level header field. That is why Q2 exists.

### B.2 Exact deltas: `goal-file.schema.json`

(a) `schema_version` changes from `"const": 3` to `"const": 4` (line 11). Make the same change in `goal-diff.schema.json:10` and in approval-record. The approval-record line is unread, but the family shares one version (reconciliation `:298-301`).

(b) In `trust_domain.entries.properties` (lines 272-277), add:

```json
"supervisor": { "$ref": "#/$defs/supervisor_map" }
```

Add `"supervisor"` to the `required` array at line 278 (if Q1 = required).

(c) New `$defs`:

```json
"supervisor_map": {
  "description": "The host's unit-namespace authority (inventory `supervisor`, resolved). Singleton. `nixos`: every unit is written by the NixOS configuration; tendcf actuates no unit and no domain carries a state entry (D2, D3). `launchd`/`systemd`/`runit`: the manager CFEngine renders for; per-prefix unit-writer entries govern, and every present service's unit flavour equals this value (lint). A change is a device-trust hunk, therefore privileged.",
  "type": "object",
  "propertyNames": { "const": "host" },
  "additionalProperties": {
    "type": "object",
    "properties": {
      "state": { "const": "present" },
      "name": { "enum": ["launchd", "systemd", "runit", "nixos"] }
    },
    "required": ["state", "name"],
    "additionalProperties": false
  },
  "minProperties": 1
}
```

(d) Top-level `allOf`, a sibling of `required` at line 29. This is the nixos rule:

```json
"allOf": [{
  "if": { "properties": { "domains": { "properties": { "device-trust": { "properties": { "entries": { "properties": { "supervisor": { "properties": { "host": { "properties": { "name": { "const": "nixos" } }, "required": ["name"] } }, "required": ["host"] } }, "required": ["supervisor"] } }, "required": ["entries"] } }, "required": ["device-trust"] } }, "required": ["domains"] },
  "then": { "properties": { "domains": {
    "required": ["supervision"],
    "properties": {
      "device-trust": true,
      "supervision": { "properties": { "coverage": { "const": "deliberately-unmanaged" } } }
    },
    "additionalProperties": { "properties": { "entries": false } }
  } } }
}]
```

Three details matter here:

- **`"device-trust": true` is needed.** Without it, the `then`'s `additionalProperties` would also apply to device-trust, which must carry `entries`. That would make every nixos file invalid.
- **`entries: false`, not `not: required`.** Case 57's precedent is that the `false`-schema form names the offending member. The `not` form prints the whole document (`examples/broken/README.md:193-198`).
- **Supervision needs no `entries: false` of its own.** The coverage const plus the existing `state_domain` `if/then` (`:47-51`) already forbid entries there.

(e) `unit_writer_entry.writer` (line 255): remove `"nixos"`, if Q7 is approved. Update the description at line 254. `nix-darwin` stays a per-prefix writer: nix-darwin shares the launchd namespace with Apple, Homebrew and CFEngine labels.

(f) Update the `trust_domain` description (line 263, "four kinds"), the `unit_writer_map` description (line 239), and the `service_map` propertyNames description (line 77) to mention the supervisor rule.

### B.3 How it interacts with unit-writer, and the two-writers invariant

- **On a nixos host** there are no `unit-writer` entries in any domain; (d) forbids every domain's entries. The supervisor entry *is* the whole-namespace claim. No wildcard entry exists, as the operator ruled.
  - "Two writers on one namespace" holds structurally: there is exactly one writer, and the schema refuses a second declaration anywhere. The lint is not involved.
  - The prefix nesting rule (`bin/schema_lint.py:1431-1441`) is unchanged and vacuous on such a host. It finds no prefixes.
- **On launchd/systemd/runit hosts** nothing changes: the prefix pattern, nesting and the cfengine-writer rules (`:1443-1465`) stay as they are.
- **New goal cross-file rule** (if Q1 = required), in `check_goal_file_cross_file` after line 1465. For a supervisor in `{launchd, systemd, runit}`, every present service's single `unit` key must equal the supervisor name. Message:

  `"{label}: domains/{d}/entries/service/{id} has unit flavour {f!r} but the host supervisor is {s!r} — one host, one manager"`

  This turns the second spelling into a checked one, which is reconciliation §7's objection answered.
- **`nixos` as a writer value** has no remaining use after (d): on a nixos host unit-writer is forbidden, and on any other host nixos writes no units. Keeping it would be a second way to say "nixos owns these units". Hence Q7.

## C. Fail-closed analysis

1. **An old validator (ceiling 3) reading a v4 file** is refused twice:
   - `schema_version` is a `const`, so 4 fails structurally (`:9-12`); case 13 already proves this at 4.
   - The trust `entries` object is `additionalProperties: false` (`:279`), so the `supervisor` kind is refused even if the version check were bypassed.

   The schema description promises "version-above-ceiling reported distinctly from schema-invalid" (`:10`). I found no code doing that dispatch in `schema_lint.py`; no grep hit for "ceiling" near validation. tendcf-agent does not exist (`bin/projector.py:14-15`). So today this is a schema-const refusal only. **Unverified that anything implements the distinct report.**
2. **D44 render rule.** `device_convergence.schema_ceiling` is an integer with minimum 1 and no maximum (`schema/report-row.schema.json:118-122`). The compiler refuses to render version N for a host whose reported ceiling is below N (reconciliation `:314-318`). A never-reported host renders at its enrolled version (`:309-313`). No report-row change is needed.
   - get has never reported, there is no Linux row writer (`linux-targets.md:49`, D18 open), and no enrollment ceremony exists.
   - **DECIDED (conservative):** get's first adoption, when it happens, enrolls at 4. No v3 baseline exists anywhere to migrate from.
3. **Downgrade.**
   - A nixos-supervisor host has **no faithful v3 rendering**. The only v3 spelling was the placeholder that matches nothing. The compiler must refuse to render it below 4 rather than fall back to `org.nixos.*`.
   - Non-nixos hosts render at 3 by dropping the supervisor entry. That loses the fact only, and the v3 rules did not depend on it.
   - Two-phase order is unchanged: ship the v4 validator as an `agent` hunk under v3 (`goal-file.schema.json:357`), then v4 content.
   - Pre-existing problem: §9.4's "empty apart from the bump" cannot hold literally for a bump that adds a required field. v2 had the same property ("every fixture and digest regenerated", `linux-targets.md:36`). It is moot while no device holds a baseline.
4. **An unknown supervisor value** fails the closed `enum` (case 93). An unknown trust kind fails `additionalProperties`.
5. **On the device itself**, refusal does not depend on the goal file. cf-agent sees only `{"vars":{}}`. The bundle's filesystem guard refuses any systemd entry where `/etc/systemd/system` is a symlink (`policy/tendcf_services.cf:172-185,317-318`) [code].
   - **Gap found:** a *tombstone* on such a host is neither actuated nor reported. Teardown is gated on `tendcf_systemd_host` (`:229-232`), and `_refused` requires `_present` (`:200`). It is silent, not harmful. v4 makes it unrepresentable in a goal file, but hand-written CMDB data would still hit it. See slice S0.

## D. Consent diff for D1

**Where it is produced:** CI in the host-flake repository, on the PR that changes get's flake (forgejo djbclark/get, or site-djbclark's `nixos-cfengine-build.yml`).

- **Not the device.** D3 actuates nothing, there is no agent, and get should not evaluate its own successor.
- **Not nix2cf.** Nix2cf emits goal files for path 2 only (`linux-targets.md:38,70-76`); passthrough is path 1.

It runs three steps on the base and head commits:

1. **Lock diff.** `git diff` of `flake.lock`, reduced to `(input, type, rev, narHash)` per changed node.
2. **Options summary.**

   ```
   nix eval --json <flakeref>#nixosConfigurations.<get-attr>.config.services.cfengine-tendcf \
     --apply 'c: { enable = c.enable; execd.enable = c.execd.enable; package = "${c.package}"; }'
   ```

   The output is JCS-canonicalized so equal options give equal bytes. **The `<get-attr>` attribute name is unverified.** The option names `enable`, `package` and `execd.enable` are verified (`site-public-djbclark/nixos/modules/cfengine-tendcf.nix:21,23,30`).
3. **`nix store diff-closures base head`**, which Stage B already produces.

**Rendered example.** Real values: get `bf3bc63`, site-djbclark `035fd137` as a non-flake input, package version `3.29.0a.b8abf2840`. Values in `<>` are placeholders I could not read: I had no access to get's lock.

```
get.sipb.cloud — proposed Nix change bf3bc63 → <head>

AUTHORITY: flake.lock
  site-djbclark  (non-flake input; module imported by path)
    rev      035fd137 → <newrev>
    narHash  <sha256-old> → <sha256-new>
  all other inputs unchanged

SUMMARY: settings tendcf watches (services.cfengine-tendcf)
  - {"enable":true,"execd":{"enable":false},"package":"/nix/store/<h1>-cfengine-tendcf-3.29.0a.b8abf2840"}
  + {"enable":true,"execd":{"enable":false},"package":"/nix/store/<h2>-cfengine-tendcf-<ver>"}

CLOSURE (diff-closures)
  cfengine-tendcf: 3.29.0a.b8abf2840 → <ver>, <±size>
```

**What a person is asked**, in ordinary language:

> "This changes get's NixOS configuration. Its site-djbclark source moves from 035fd137 to <newrev>. CFEngine stays installed, its scheduler stays off, and its package changes to <ver>. tendcf will still change nothing on this host: it only reports. Approve this change?"

Two CI checks should be hard failures, not just display:

- `execd.enable` becomes `true` while D3 stands.
- Any options key outside the summary appears.

Both turn D3 into a check rather than prose. They live in that repository's CI, which is outside this repo.

## E. Migration

1. **`deploy/linux/passthrough/goal-file.json`.** Set `schema_version` to 4. Add `device-trust.entries.supervisor = {"host":{"name":"nixos","state":"present"}}`. Set `supervision` to `{"coverage":"deliberately-unmanaged"}`, deleting the `org.nixos.*` unit-writer. The file stays JCS.
   - The projection is **unchanged at `{"vars":{}}`**. The projector reads only `supervision`'s `service` and `interlock` (`bin/projector.py:120-121`), and there are none. This is reasoned from code, not run; `check.py` verifies it (`deploy/linux/canary/check.py:37,64-66`).
   - The `check.py` comment at lines 34-36 needs rewording.
2. **Canary goal files** (`deploy/linux/canary/goal-file.json` and `goal-file-absent.json`): add supervisor `systemd`; nothing else changes. `host_specific*.json` stay byte-identical. I read `goal-file.json` but not `goal-file-absent.json`.
3. **`examples/goal-file.json` and `goal-file-baseline.json`** (launchd): add supervisor `launchd`. Regenerate `goal-diff.json` and the approval-record hashes. `host_specific.json` is unchanged.
4. **All 63 `examples/broken/*` goal-family overlays** are full alternate files (`README.md:50-53`). Each needs `schema_version` 4 and the supervisor entry, or it fails for a second reason. The harness tolerates extra findings only if the declared class also fires (`README.md:11-18`), but parenthetical claims are checked (`:163-167`), so fix them all. Also update:
   - case 13 to claim `5`;
   - `EXPECTED_BROKEN` (`bin/schema_lint.py:87`) from 63 to 72;
   - "Sixty-three" (`README.md:3`; `schema_lint.py:36`);
   - "cases 13-73" (`README.md:9`).
5. **Docs:**
   - `linux-targets.md` step 4 (`:36`) and step 8 (`:40`), and §5 item 4 (`:90`): resolved by D1.
   - `nixos-passthrough-plan.md` §4 (`:92-107`) and §5 item 2 (`:113-114`).
   - The `tendcf_services.cf:165-169` comment can cite the fact.
   - AGENTS.md: no change. It carries no schema facts.
6. **Nix2cf step 6 fields.**
   - From inventory: host key, `trust_tier` → `trust-policy`, `supervisor` → `device-trust.supervisor`.
   - Renderer choice is a function of supervisor: `launchd` → launchd unit, `systemd` → systemd unit, `runit` → runit unit, `nixos` → no service rendering at all. A service record bound to a nixos host is a compile-time refusal: "host is nixos-supervised; its units are the Nix configuration's".
   - Still deferred: distro family (Q5), `scope`, externally-written unit (`linux-targets.md:36`).

## F. Test plan

**Numbering.** The brief's "cases 70-72 are the latest" is stale:

- Case 73 exists (`README.md:225`).
- The numbering is "one series across both directories" (`README.md:282-283`), and broken-projection already runs to 92 (`:336-338`).
- Numbers 70-73 are already used twice, once in broken/ and once in broken-projection/. This is pre-existing (`:73-75,225` vs `:316-319`).

New cases therefore start at **93**. All overlay `goal-file.json`.

| # | Case | Broken input | Expected refusal [mem wording] | Caught by |
|---|---|---|---|---|
| 93 | `93-unknown-supervisor` | supervisor `name: openrc` | `'openrc' is not one of ['launchd', 'systemd', 'runit', 'nixos']` | schema (`enum`) |
| 94 | `94-missing-supervisor` | device-trust without `supervisor` | `'supervisor' is a required property` | schema (`required`) |
| 95 | `95-supervisor-not-singleton-id` | supervisor id `main` | const failure on `'main'` | schema (`propertyNames`) |
| 96 | `96-nixos-supervision-comprehensive` | nixos; supervision `comprehensive`, no entries | `'deliberately-unmanaged' was expected` | schema (`if/then`) |
| 97 | `97-nixos-tombstone-elsewhere` | nixos; second domain `apps` (`not-yet-migrated`) holding a `service` tombstone | `False schema does not allow {...}` at `domains/apps/entries` | schema (`if/then`) |
| 98 | `98-nixos-unit-writer-elsewhere` | nixos; domain `packaging` with `org.nixos.*` writer `cfengine` | as 97, at `domains/packaging/entries` | schema (`if/then`) |
| 99 | `99-nixos-no-supervision-domain` | nixos; `supervision` absent | `'supervision' is a required property` | schema (`if/then`) |
| 100 | `100-nixos-writer-retired` | systemd host; writer `nixos` on a prefix | enum failure listing 7 writers | schema (`enum`) |
| 101 | `101-flavour-not-supervisor` | supervisor `systemd`; a `launchd` service | the new cross-file message in B.3 | goal cross-file |

Notes on the table:

- Case 101 exists only if Q1 = required.
- Case 100 exists only if Q7 is approved.
- **Unverified:** whether the lint's `$defs` recovery attributes a top-level `allOf/if/then` failure as `if/then` (it does for `state_domain`, `README.md:181-182`). Confirm on the first run and correct the cells.
- **Unverified:** whether fixture discovery handles 3-digit directory names. The README row regex `^\|\s*\d+\s*\|` does accept them (`bin/schema_lint.py:416`).

**Positive cases:**

- The passthrough v4 goal file is valid and projects to `{"vars":{}}` (`check.py`).
- The canary and the examples are valid with supervisor `systemd` / `launchd`.
- `check_trust_inexpressible` passes with five kinds.

**Discrimination.** For each new rule, delete it on its own and confirm its case goes red alone (F8, `bin/flag_coverage.py`). Run one mutant at a time through `bg`.

**No change** to `tests/policy/*`: the fixtures are CMDB data, not goal files; grep for `schema_version` in tests/ gave no hits. **S0 adds** check 7b: a tombstone on the symlinked layout must produce a report line.

## G. Risks, rejected alternatives, plan

**Risks**

1. On the device, refusal still rests on the filesystem guard; the fact never reaches cf-agent. The tombstone gap is in C.5.
2. The bump touches every family fixture and digest. Any external v3 consumer, such as a nix2cf checkout pinned to v3, breaks. **I did not check the nix2cf repo.**
3. `deliberately-unmanaged` switches off extra-entry detection on Nix hosts (Q3).
4. The prefix pattern defect also hits `dpkg`: Debian units such as `ssh.service` are not reverse-DNS. D2 does not fix that; it needs its own ruling.
5. Schema errors from a top-level `if/then` may report the path as `<root>` (`README.md:199-200`), which is a message-quality risk under D16(a).

**Rejected alternatives**

- **Whole-namespace wildcard unit-writer entry** (operator-rejected). It needs no new kind, but:
  - every other prefix nests inside it, so the nesting lint would need a special case;
  - it puts a host privilege fact into detector data in an ordinary domain. Deleting it would be an *ordinary* hunk that unlocks CFEngine writes, a privilege downgrade without a privileged ceremony.
- **Top-level header field.** The header is fixed at `schema_version` + `host` (reconciliation `:380`). It would need header-hunk machinery, or force re-adoption on every change.
- **Domain-level property on `supervision`.** It needs a dedicated domain def and new diff machinery, and a change would be ordinary-class.
- **Widening the pattern to bare names.** That means 116 entries per host, churn on every NixOS change, and still two spellings of ownership.
- **Projecting `supervisor` into `vars`.** It breaks `{"vars":{}}`, P-1 and the exclusion of device-trust.
- **`nix-darwin` in the supervisor set.** It shares the launchd namespace, and the bundle has no nix-darwin guard, so it stays a prefix writer.

**Implementation plan (PR-sized slices)**

- **S0 (independent, small).** In `policy/tendcf_services.cf`, report a tombstone on a symlinked-units host by name (the D3 "report"), and add a test check.
- **S1 (one PR; a bump cannot be split without an unsafe interim shape).** Schema v4 B.2(a)-(f) across the family, the B.3 lint rule, regenerated fixtures and digests, cases 93-101, the count and README updates, and the passthrough and canary migration.
- **S2.** Doc updates from E.5.
- **S3 (host-flake repo).** The D1 consent artifact and the two hard CI checks from D.
- **S4.** Nix2cf step 6 consumes `supervisor`.

Every PR gets the cross-vendor review that AGENTS.md:40-44 requires.

## H. Evidence table

| Claim | Source read |
|---|---|
| Unit-writer prefix pattern; nesting description | `schema/goal-file.schema.json:239-247` |
| Writer enum includes `nixos` | `goal-file.schema.json:253-256` |
| `schema_version` const 3; "dispatch first" promise | `goal-file.schema.json:9-12` |
| Header has `additionalProperties: false` | `goal-file.schema.json:29-30` |
| `deliberately-unmanaged` forbids entries | `goal-file.schema.json:47-51` |
| `state_entries` kinds closed | `goal-file.schema.json:55-63` |
| Trust kinds closed; consent tier as an entry, not the header | `goal-file.schema.json:271-279,321` |
| Diff can change one header thing, `version_bump` | `schema/goal-diff.schema.json:25-26` |
| Header fixed at `schema_version` + `host`; platform rejected | `docs/architecture/goal-file-schema-reconciliation-2026-08-15.md:374-383` |
| Render rule; never-reported host | reconciliation `:309-318` |
| `schema_ceiling` is an integer with no maximum | `schema/report-row.schema.json:118-122` |
| Nesting rule; cfengine-writer rule | `bin/schema_lint.py:1431-1465` |
| Privileged derivation | `bin/schema_lint.py:1496-1506` |
| `EXPECTED_BROKEN = 63` | `bin/schema_lint.py:87` |
| Trust property test | `bin/schema_lint.py:1787-1846` |
| Projector reads `supervision` `service`/`interlock` only | `bin/projector.py:23-25,120-121` |
| tendcf-agent does not exist | `bin/projector.py:14-15` |
| Passthrough file uses `org.nixos.*`; projection `{"vars":{}}` | `deploy/linux/passthrough/goal-file.json:1`, `host_specific.json:1` |
| Canary shape | `deploy/linux/canary/goal-file.json:1` |
| `check.py` pairs | `deploy/linux/canary/check.py:31-38,55-66` |
| Numbering | `examples/broken/README.md:9,73-75,225,282-283,316-338` |
| Parentheticals are checked; `false`-schema precedent | `examples/broken/README.md:163-198` |
| Bundle guard and tombstone gating | `policy/tendcf_services.cf:172-185,200,225-232,314-318` |
| Inventory holds `trust_tier`; supervisor selects adapter | `docs/architecture/architecture-DEFINITIVE-v3.md:178-180,282-283` |
| Step 4/6/8 status | `docs/architecture/linux-targets.md:36,38,40,90` |
| Stage C result; open question | `docs/architecture/nixos-passthrough-plan.md:69-85,92-107` |
| Module options | `~/ops/site-public-djbclark/nixos/modules/cfengine-tendcf.nix:21-45` |
| Design rulings need astra + Fable | `AGENTS.md:45-49` |

**Unverified:**

- Every jsonschema error string [mem].
- How the harness attributes a top-level `if/then`.
- 3-digit fixture directory handling.
- `<get-attr>` and get's real lock contents (narHash, the input URL type).
- That nix-darwin labels use `org.nixos.*`. This is from memory, and the design does not depend on it.
- That approval-record's version is a const of 3 (not read).
- `canary/goal-file-absent.json` contents.
- Whether any code implements distinct version-above-ceiling reporting.
- The nix2cf repository's v3 pins.
- All CFEngine semantics: taken from repo comments, not the book.

DECIDED:

- get enrolls at v4.
- New case numbering starts at 93.
- `nix-darwin` is excluded from the supervisor set.
- Site Model `launchd-writers` is left alone.

DONE
