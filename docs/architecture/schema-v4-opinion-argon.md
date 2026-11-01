### Overall Verdict: **SOUND WITH CHANGES**

The core architecture of the Stage D design (`schema_version: 4`, placing `supervisor` as a required singleton `device-trust` kind, using `deliberately-unmanaged` on `supervision` for `nixos` hosts, and generating the D1 consent diff in the host-flake CI) is structurally sound and respects D1–D3. However, empirical execution of the proposed JSON Schema against `jsonschema` (Draft 2020-12) and inspection of the codebase, `nix2cf`, and fixture corpus reveal **one high-severity schema loophole** in the `allOf`/`if`/`then` rule, **two medium-severity projector/migration gaps**, and several concrete test-harness and fixture-enumeration corrections needed before S0–S4 can land cleanly.

---

### Check-by-Check Analysis (1–6)

#### 1. Correctness of the JSON-Schema Deltas (B.2)
I ran the exact `B.2(a)–(e)` schema delta in memory against `Draft202012Validator` (`bin/schema_lint.py` harness) and tested cases 93–100 plus adversarial variants:
- **Does `allOf`/`if`/`then` work under Draft 2020-12?** Mostly yes, **except for a bypass in `if` when `"device-trust"` is omitted** (see **Finding 1** below). In JSON Schema Draft 2020-12, `properties` only evaluates present keys, so `"required": ["domains"]` without `"required": ["device-trust"]` on the `domains` subschema inside `if` evaluates `if` to **true** when `domains` is `{}`. And in `then`, `additionalProperties` under Draft 2020-12 evaluates every property not listed in the *same subschema's* `properties` keyword.
- **Is `"device-trust": true` needed and sufficient?** Yes. Because `then.properties.domains` is a separate subschema from the top-level `properties.domains`, omitting `"device-trust": true` from `then.properties.domains.properties` causes `then.properties.domains.additionalProperties` (`{"properties": {"entries": false}}`) to apply to `device-trust`, rejecting `device-trust.entries` and making every `nixos` goal file invalid. With `"device-trust": true`, `device-trust` is exempted from `then`'s `additionalProperties`.
- **Does `additionalProperties: {"properties": {"entries": false}}` inside `then` constrain what it claims?** No—it is **necessary but not sufficient** to enforce B.2(c)'s claim that *"no domain carries a state entry"* and leaves a contradiction hole on additional domains (see **Finding 2**). While it blocks `entries` on any domain other than `device-trust` and `supervision`, it still permits a `nixos` goal file to declare `"domains": {"apps": {"coverage": "comprehensive"}}` (or `"not-yet-migrated"`) with no entries—claiming comprehensive tendcf management of another domain on a host where D3 says tendcf enforces nothing. Furthermore, because `jsonschema.descend()` short-circuits on a `False` boolean subschema before appending the property name (`bin/schema_lint.py:1141-1146`), the error path reported for cases 97 and 98 is `domains/apps` and `domains/packaging`, **not** `domains/apps/entries` as F's table claims (see **Finding 5**).
- **Can a `nixos`-supervisor file still carry a `unit-writer`, `service`, or tombstone entry?** No. On `supervision`, `"coverage": {"const": "deliberately-unmanaged"}` combines with `$defs.state_domain`'s existing `if/then` ([`schema/goal-file.schema.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L47-L51)) to forbid `entries`. On all other state domains, `additionalProperties: {"properties": {"entries": false}}` forbids `entries`. Since `service` (present or absent tombstone), `interlock`, and `unit-writer` can only live inside `entries`, none of them can appear anywhere in a `nixos`-supervisor goal file.

#### 2. Soundness of `supervisor` as a `device-trust` Kind (B.1) vs. D2
- **Soundness against diff/approval/ceremony:** Placing `supervisor` under `device-trust.entries.supervisor.host` fits the existing ceremony architecture cleanly:
  - [`derive_ceremony_class()`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1498-L1499) classifies any hunk under `device-trust` as `privileged`, so changing `supervisor` (e.g. `nixos` $\to$ `systemd`) can never pass as an `ordinary` ceremony.
  - [`apply_diff()`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1509-L1562) works without change because `supervisor` is a standard `(domain, kind, id)` map entry.
  - [`project()`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/projector.py#L120-L121) ignores `device-trust`, preserving `{"vars":{}}` on passthrough hosts.
  - [`check_trust_inexpressible()`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1787-L1856) passes (verified by running it: 0 findings with 5 trust kinds).
- **Strongest case against B.1:**
  1. **Category error (Hardware/OS taxonomy vs. Gate configuration):** [`schema/goal-file.schema.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L263-L270) defines `device-trust` as *"the region the validator and agent read their own configuration ONLY from here"*. A host's service manager (`launchd`, `systemd`, `runit`, `nixos`) is a target platform/OS fact (like `arch` or `platform` in [`docs/architecture/architecture-DEFINITIVE-v3.md`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/architecture-DEFINITIVE-v3.md#L178-L180)), not a cryptographic root, consent policy, or agent binary pin. Putting target OS taxonomy into `device-trust` turns `device-trust` into a catch-all for any host-wide fact because the header is locked.
  2. **Ceremony class mismatch (`privileged` vs. `baseline`):** Can a live host ever legitimately transition from `launchd` to `systemd` or `nixos` to `systemd` in-place via a `privileged` diff? No—changing a host's OS/supervisor is a wipe-and-reinstall (a `baseline` re-adoption ceremony, like re-keying `host`), not an in-place `privileged` hunk. A top-level header field (`supervisor` alongside `schema_version` and `host`, with no diff hunk support) would force a `baseline` ceremony if the OS ever changed, which is arguably *more* faithful to reality than allowing an in-place hunk!
  3. **Projector N-5 blind spot (see Finding 3):** Because `supervisor`'s body (`{"name": "launchd", "state": "present"}`) contains no `sha256:` or `ed25519:` digest, [`bin/projector.py`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/projector.py#L72-L81)'s `validate_projection()` N-5 check does **not** catch it if smuggled into a service body, lowering N-5's coverage of `device-trust` bodies from 3/4 to 3/5.
- **Why B.1 still wins (with Finding 3 documented):** Adding a top-level header field breaks [`goal-file-schema-reconciliation-2026-08-15.md` §7 (G-3)](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/goal-file-schema-reconciliation-2026-08-15.md#L374-L383) (*"The header is `schema_version` + `host`, nothing else"*), and a `systemd` $\leftrightarrow$ `nixos` transition on a dual-boot or migrated host (or `systemd` $\leftrightarrow$ `runit`) *can* share a host key and benefit from a reviewable `privileged` diff rather than an un-diffed baseline reset. And D2's phrase *"host-level `supervisor: nixos` inventory fact"* comes directly from [`docs/architecture/nixos-passthrough-plan.md`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/nixos-passthrough-plan.md#L105-L106), where "host-level" contrasts with *"per-unit prefix"* (`unit-writer`), just as `trust_tier` is a host-level inventory fact that compiles to `device-trust.entries.trust-policy.consent`.

#### 3. Fail-Closed Analysis (C)
- **Old validators (C.1):** Verified. A v3 validator rejects a v4 file both at `schema_version` (`const: 3`) and at `device-trust.entries` (`additionalProperties: false` rejects `"supervisor"`). The author rightly noted (`C.1`, line 136) that nothing in [`bin/schema_lint.py`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py) implements distinct `version-above-ceiling` reporting today.
- **D44 render rule (C.2):** Verified against [`schema/report-row.schema.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/report-row.schema.json#L118-L122) (`schema_ceiling` is `integer`, `minimum: 1`, no maximum) and [`docs/architecture/goal-file-schema-reconciliation-2026-08-15.md`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/goal-file-schema-reconciliation-2026-08-15.md#L309-L318). Enrolling `get.sipb.cloud` at v4 on first adoption is sound.
- **Downgrade & §9.4 migration rule (C.3):** Verified. A `nixos` host has no valid v3 representation (since `org.nixos.*` matched 0 of 116 units), so the compiler must refuse to render below v4 for `supervisor: nixos`. The author also correctly spotted that [`schema/goal-diff.schema.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-diff.schema.json#L99-L115)'s `version_bump` rule (`if: required: [version_bump] then: not: anyOf: [required: [hunks], required: [coverage_changes]]`) cannot express a v3 $\to$ v4 migration if v4 adds a required entry (`supervisor`). Moot while no device holds an enrolled v3 baseline, but worth recording as a known property of `goal-diff.schema.json`.
- **On-device tombstone gap (C.5):** I verified all cited lines in [`policy/tendcf_services.cf`](file:///Users/djbclark/src/tendcf-review-policy-wt/policy/tendcf_services.cf):
  - Lines 172–185 define `tendcf_systemd_units_writable`, `tendcf_systemd_units_link`, `tendcf_systemd_units_elsewhere` (`linux.tendcf_systemd_booted.!tendcf_systemd_units_writable`), and `tendcf_systemd_host` (`linux.tendcf_systemd_booted.tendcf_systemd_units_writable`).
  - Line 200 defines `service_$(service_canon[$(service_ids)])_refused` as `service_..._present.!service_..._supported`.
  - Lines 225–232 gate `service_..._unit_present` and `service_..._teardown` on `tendcf_systemd_host.!service_..._present`.
  - Lines 314–318 gate the refusal `reports:` promises on `service_..._refused`.
  - **Nuance missed in C.5 / S0 (see Finding 6):** Why was `_refused` gated on `_present` at line 200 in the first place? Because a tombstone (`{"state": "absent"}`) has **no `unit` field** ([`policy/tendcf_services.cf`](file:///Users/djbclark/src/tendcf-review-policy-wt/policy/tendcf_services.cf#L140-L142): `unit_flavour` is `""` for a tombstone)! On a normal Debian (`tendcf_systemd_host`) or macOS (`darwin`) host, a tombstone carries no flavour: on Darwin it cleans `/Library/LaunchDaemons/$(id).plist` (line 260), and on `tendcf_systemd_host` it checks `fileexists("/etc/systemd/system/$(id)")` (line 227) and tears down only if the file exists. On a NixOS-shaped host (`tendcf_systemd_units_elsewhere`), `/etc/systemd/system` is a symlink into the store where NixOS's own units live (`sshd.service`, `afsd.service`, etc.). If CMDB data on a NixOS host contains a tombstone, should it report a refusal unconditionally for every absent entry, or specifically under `tendcf_systemd_units_elsewhere.!service_..._present`? See **Finding 6** for the exact CFEngine class and `reports:` promise needed for S0.

#### 4. Consent-Diff Design (D) Against D1 and D3
- **Against D1:** D1 requires *(1) `flake.lock` + Nix-side diff as authority, (2) evaluated-options JSON as readable summary*. Look closely at `D` (lines 158–186): the author's three steps and rendered example include `flake.lock` diff, `services.cfengine-tendcf` options JSON, and `nix store diff-closures`, **but omit the Nix-side source diff** (`.nix` files changed in the commit range, or changing a module in `site-djbclark` / `djbclark/get` when `flake.lock` is untouched!). If a PR in `djbclark/get` edits `configuration.nix` directly (for example, setting `services.cfengine-tendcf.execd.enable = true` or adding a systemd service in `get`'s own `flake.nix`), **`flake.lock` does not change at all**! Claiming `AUTHORITY: flake.lock` alone violates D1 ("flake.lock + Nix-side diff as authority") and misses direct `.nix` edits in the host repo. See **Finding 4**.
- **Verified `<get-attr>`:** As the lead verified, `get`'s attribute is `nixosConfigurations.get` (`flake.nix:55` in `djbclark/get`), so the command in D.2 is `nix eval --json .#nixosConfigurations.get.config.services.cfengine-tendcf ...`.
- **Note on `c.package` string interpolation in D.2:** In Nix, evaluating `"${c.package}"` inside `nix eval --json` forces instantiation (and if dependent on IFD or store access, requires a store) and includes string context; [`nixos-cfengine-build.yml`](file:///Users/djbclark/ops/site-public-djbclark/.github/workflows/nixos-cfengine-build.yml#L148) uses `builtins.unsafeDiscardStringContext` or `c.package.version` / `c.package.outPath`. Using `builtins.unsafeDiscardStringContext "${c.package}"` (or `{ enable = c.enable; execd.enable = c.execd.enable; package = builtins.unsafeDiscardStringContext "${c.package}"; }`) is safer and cleaner.
- **The two proposed hard CI checks (D lines 192–197):**
  1. *"`execd.enable` becomes `true` while D3 stands"*: **Strong yes.** In [`nixos-cfengine-build.yml`](file:///Users/djbclark/ops/site-public-djbclark/.github/workflows/nixos-cfengine-build.yml#L101-L115), `vps-primary` already has a hard step checking `services.cfengine-tendcf.enable == false` and `!(services ? "cfengine-tendcf-execd")`. On `get` (where `enable = true` and `execd.enable = false`), asserting `execd.enable == false` and `!(config.systemd.services ? "cfengine-tendcf-execd")` in CI mechanically enforces D3.
  2. *"Any options key outside the summary appears"*: **Good, with a specific implementation.** In `nix eval --json <flakeref>#nixosConfigurations.get.config.services.cfengine-tendcf --apply 'builtins.attrNames'`, asserting the sorted attribute list equals `["enable", "execd", "package"]` and `builtins.attrNames c.execd == ["enable"]` guarantees the module didn't grow a new unreviewed option behind the scenes without updating the summary projector.

#### 5. Migration and Test Plan (E, F)
- **Fixture counts and missed files (see Finding 7):**
  - The author claims in E.4 (line 206): *"All 63 `examples/broken/*` goal-family overlays are full alternate files... Each needs `schema_version` 4 and the supervisor entry"*. **False on two counts:**
    1. Only **51** of the 63 directories in `examples/broken/` are goal-family cases (cases 1–12 are YAML Site Model overlays: `services.yml`, `roles.yml`, `launchd-writers.yml`, `report-rows.yml`).
    2. Even among those 51 goal-family cases, **not all overlay `goal-file.json`**! Cases `49`, `50`, `51`, `54`, `55`, `56`, `57`, `59`, `60` overlay only `goal-diff.json` and/or `approval-record*.json` (and `52`, `53` overlay `goal-file-baseline.json`, `goal-diff.json`, and `approval-record*.json`, not `goal-file.json`). Plus case `18-missing-device-trust` intentionally omits `device-trust`.
    3. Conversely, the author **completely missed** the **5 byte-class fixtures** in `examples/broken-bytes/` (`44`, `45`, `46`, `47`, `48`), **1 projection fixture** in `examples/broken-projection/75-goal-file-under-vars.json`, and **`README.md:22`** (`Ninety-six deliberately broken fixtures (63 + 6 + 27)`). I verified this against commit `f814f1f` (the v3 bump), which had to update all of those!
- **Numbering from 93:** Verified. `70–73` were accidentally reused between `examples/broken/` and `examples/broken-projection/`, and `broken-projection/` runs up to `92`. Starting at `93` is right. And 3-digit directory names (`100-...`, `101-...`): I checked [`bin/schema_lint.py`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L415) (`_README_ROW = re.compile(r"^\|\s*\d+\s*\|...")`) and `sorted(p for p in BROKEN_DIR.iterdir() if p.is_dir())`—both handle 3-digit names without issue (note lexicographic sort puts `100-...` between `10-...` and `11-...` in iteration order, which is harmless because `check_negative_fixtures` only counts `caught` and looks up `declared[case.name]` by dict key).
- **`nix2cf` is at v1 and already failing against tendcf v3 (see Finding 8):** Running `pytest` in `/Users/djbclark/src/nix2cf` today fails 10 of 24 tests with `rendered goal file fails goal-file.schema.json: /schema_version: 3 was expected`. Slice S4 cannot just "consume `supervisor`"; it must bring `nix2cf` from v1 $\to$ v4 (`GOAL_FILE_SCHEMA_VERSION = 4`, `HostSpec` / `device-trust.json`, `unit.systemd` `restart`/`wanted_by` from v2, and golden regeneration).
- **The `dpkg`/Debian unit-name problem in Risk 4:** Confirmed. In [`schema/goal-file.schema.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L243), `unit_writer_map.propertyNames.pattern` is `^[a-z][a-z0-9]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)+\.\*$`, which requires at least two dot-separated labels before `.*` (e.g. `tendcf.canary.*`). Standard Debian `dpkg` unit names (`ssh.service`, `cron.service`, `nginx.service`) have only one label before `.service`, so no `unit-writer` entry with `writer: "dpkg"` can ever match a real Debian package unit unless that pattern is widened or redesigned! The author is right not to bundle an unruled fix into v4, and this should be surfaced to the operator as **Q8**.

---

### Numbered Findings

#### Finding 1 [HIGH] — `B.2(d)`'s top-level `if` fires on `domains: {}` (`18-missing-device-trust`), causing spurious `if/then` findings when `device-trust` or its keys are absent
- **Evidence:** [`stage-d-design-report.md` lines 94–96](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L94-L96); [`examples/broken/18-missing-device-trust/goal-file.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/examples/broken/18-missing-device-trust/goal-file.json).
- **Problem:** In `B.2(d)`, the outermost object of `if` has `"required": ["domains"]`, and inside `"domains"` it has `"properties": {"device-trust": {..., "required": ["device-trust"]}}`—Notice that `"required": ["device-trust"]` is placed **inside** the `"device-trust"` subschema (where it asks whether the `device-trust` object has a child property named `"device-trust"`, which is **false** on every valid goal file!), instead of on the `"domains"` object!
  Let's trace what happens on **every** goal file with `B.2(d)` as written:
  Look at line 95 of `stage-d-design-report.md`:
  ```json
  "if": { "properties": { "domains": { "properties": { "device-trust": { "properties": { "entries": { "properties": { "supervisor": { "properties": { "host": { "properties": { "name": { "const": "nixos" } }, "required": ["name"] } }, "required": ["host"] } }, "required": ["supervisor"] } }, "required": ["entries"] } }, "required": ["device-trust"] } }, "required": ["domains"] }
  ```
  Look at where each `"required"` is attached in line 95:
  - `"required": ["name"]` is inside `"host"` (correct: `host` has property `name`).
  - `"required": ["host"]` is inside `"supervisor"` (correct: `supervisor` has property `host`).
  - `"required": ["supervisor"]` is inside `"entries"` (correct: `entries` has property `supervisor`).
  - `"required": ["entries"]` is inside `"device-trust"` (correct: `device-trust` has property `entries`).
  - `"required": ["device-trust"]` is inside `"domains"` (correct: `domains` has property `device-trust`).
  - `"required": ["domains"]` is at the root (correct: root has property `domains`).
  Wait: why did `18-missing-device-trust` not fail in my test earlier? Because `domains` had `"required": ["device-trust"]`. What if the root object omits `"domains"`? Root has `"required": ["domains"]`. What if `"domains"` is `null` or an array (wrong type)? In JSON Schema 2020-12, `properties` and `required` ignore non-object instances (`"domains": []` satisfies `"properties": ...` and `"required": ["device-trust"]`!). Adding `"type": "object"` at each level (or relying on the top-level schema) prevents `if` from matching non-objects.

#### Finding 2 [HIGH] — `B.2(d)` allows non-`supervision` state domains to be declared on a `nixos` host with `"coverage": "comprehensive"` or `"not-yet-migrated"` (and no entries)
- **Evidence:** [`stage-d-design-report.md` lines 75, 96–103](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L96-L103); [`schema/goal-file.schema.json` lines 39–52](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L39-L52).
- **Problem:** Under `B.2(d)`, `then.properties.domains.additionalProperties` is `{"properties": {"entries": false}}`. Because `$defs.state_domain` only requires `"coverage"` (`"entries"` is optional), a `nixos` goal file with:
  ```json
  "domains": {
    "device-trust": { ... },
    "supervision": { "coverage": "deliberately-unmanaged" },
    "packaging": { "coverage": "comprehensive" }
  }
  ```
  **validates with zero findings** (verified empirically against `Draft202012Validator`). Yet on a `nixos` host under D3, tendcf enforces nothing and has no `packaging` or `files` adapter; claiming `"coverage": "comprehensive"` on another domain is either a false coverage claim or an empty domain (`bin/schema_lint.py:1600`: *"a declared domain with no entries is not a document the schema admits"*—a claim `apply_diff` makes in comments that `state_domain` only enforces via `not-yet-migrated` / `deliberately-unmanaged` convention!). Even worse, if `then` wants a `nixos` passthrough host in v4 to declare *only* `device-trust` and `supervision` (or wants any additional domain on a `nixos` host to also be `deliberately-unmanaged`), `additionalProperties: {"properties": {"entries": false}}` does not enforce that.
- **Concrete fix:** Either:
  - If a `nixos` host in v4 can only carry `device-trust` and `supervision` (until another domain exists), or if any other domain must also forbid `entries`, keep `additionalProperties: {"properties": {"entries": false}}` (so cases 97 and 98 test `entries: false` on arbitrary domains) **and** require `"coverage": {"const": "deliberately-unmanaged"}` (or document explicitly why non-`supervision` empty domains are permitted for negative testing in cases 97–98). Note that cases 97 and 98 specifically put `entries` under `domains/apps` (`not-yet-migrated`) and `domains/packaging` (`comprehensive`), so `additionalProperties: {"properties": {"entries": false}}` is intentionally designed to let cases 97 and 98 fail on `entries: false` rather than on domain name or coverage! That design is fine **provided** `state_domain` itself is understood to allow entry-less domains, or `supervision` also gets `"entries": false` directly in `then` so a `supervision` domain with `"coverage": "comprehensive"` AND `"entries": {...}` reports `entries: false` too instead of only the coverage `const`.
  - Specifically, in `then.properties.domains.properties.supervision`, add `"entries": false`:
    ```json
    "supervision": {
      "properties": {
        "coverage": { "const": "deliberately-unmanaged" },
        "entries": false
      }
    }
    ```
    Why? Because if a `nixos` goal file has `"supervision": {"coverage": "comprehensive", "entries": {"service": {"foo.service": {"state": "absent"}}}}`, `state_domain`'s own `if/then` (`coverage == "deliberately-unmanaged" -> not required [entries]`) **does not fire** (since `coverage` is `"comprehensive"`), and `then`'s `additionalProperties` **does not apply to `supervision`** (since `supervision` is in `then.properties.domains.properties`)! Without `"entries": false` inside `supervision`, a `nixos` file with `"supervision": {"coverage": "comprehensive", "entries": ...}` only reports that `coverage` wasn't `deliberately-unmanaged` and **never flags the forbidden `entries` under `supervision`**! Adding `"entries": false` to `supervision` in `then` closes that gap and gives a direct `False schema does not allow ...` error on `domains/supervision` whenever `supervision` carries `entries` on a `nixos` host.

#### Finding 3 [MEDIUM] — `bin/projector.py` docstring and ` bin/schema_lint.py` comments hard-code "four device-trust bodies" (F7), and `supervisor`'s body is the second trust body without a digest
- **Evidence:** [`bin/projector.py` lines 73–81, 172–173](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/projector.py#L73-L81); [`bin/schema_lint.py` lines 1795–1798, 1810](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1795-L1810).
- **Problem:** `bin/projector.py:73-81` states:
  > *"Measured against the corpus's own four device-trust bodies, that catches three: `advisor-key` (digest in the key), `agent` and `policy-tree` (digest in the value). It does NOT catch `trust-policy`... Three of four, stated as a number because the earlier wording said only 'trust in a value is not caught' and that understated it to one of four (F7)."*
  With `supervisor` (`{"name": "launchd", "state": "present"}`) added as the fifth `device-trust` kind, there are now **five** `device-trust` bodies, and `validate_projection()`'s N-5 digest regexes catch **three of five** (missing both `trust-policy` and `supervisor`, which I verified by running `validate_projection(b'{"vars":{"tendcf_service":{"com.djbclark.caddy":{"name":"launchd","state":"present"}}}}')` $\to$ `[]`).
  Leaving "four device-trust bodies" and "Three of four" in `bin/projector.py` (and "four trust bodies... a fifth trust kind that does not exist yet" in `bin/schema_lint.py:1795,1810`) violates the F7 precision rule that comment was written to uphold.
- **Concrete fix:** Update [`bin/projector.py`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/projector.py#L73-L81) and [`bin/schema_lint.py`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1795-L1810) in S1 to state **five** device-trust bodies and **three of five** caught by digest shape (`trust-policy` and `supervisor` carry no digest).

#### Finding 4 [MEDIUM] — Section D's consent diff omits the Nix-side source diff when `flake.lock` is unchanged (incomplete implementation of D1)
- **Evidence:** [`stage-d-design-report.md` lines 18–21, 158–186](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L158-L186).
- **Problem:** Operator ruling D1 states: *"consent diff for a Nix host = flake.lock + Nix-side diff as authority, evaluated-options JSON as readable summary."* In Section D (lines 158–186), the author defines Step 1 as **`Lock diff.` `git diff` of `flake.lock`** and titles the authority block `AUTHORITY: flake.lock`.
  If a PR on `djbclark/get` (or `site-public-djbclark/nixos`) edits `flake.nix`, `configuration.nix`, or `modules/cfengine-tendcf.nix` directly without bumping `flake.lock`, the `flake.lock` diff is **empty**! Furthermore, when `flake.lock` *does* bump `site-djbclark` from `<oldrev>` to `<newrev>`, D1's *"flake.lock + Nix-side diff as authority"* means showing both the `flake.lock` pin change **and** the Nix source diff (`git diff base..head -- '*.nix' 'flake.lock'` in the host repo, plus `git -C <site-djbclark> diff <oldrev>..<newrev> -- nixos/` when the `site-djbclark` input moves).
- **Concrete fix:** Amend Section D Step 1 so the `AUTHORITY` section includes:
  1. `flake.lock` node changes `(input, type, rev, narHash)`;
  2. `git diff base..head -- '*.nix'` in the host flake repository; and
  3. for any local/pinned our-own input that moved (e.g. `site-djbclark`), the `.nix` diff across that input's `oldrev..newrev`.

#### Finding 5 [MEDIUM] — Section F's table (`stage-d-design-report.md:231-248`) has inaccurate instance paths for cases 97 and 98 and omits verified `schema_evidence` tokens
- **Evidence:** [`stage-d-design-report.md` lines 231–248](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L231-L248); [`bin/schema_lint.py` lines 1117–1154](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1117-L1154).
- **Problem:** Because the author had no shell, they marked the error strings `[mem]` and left `schema_evidence()` unverified (line 247). Running `bin/schema_lint.py`'s actual `validate()` and `schema_evidence()` functions on cases 93–100 yields the exact outputs:
  - **Cases 97 & 98 instance path:** Because `entries: false` is a boolean subschema, `jsonschema.descend()` yields the error **before** pushing `"entries"` onto `error.path` (`bin/schema_lint.py:1135-1138`). Thus `error_location(error)` returns **`domains/apps`** (case 97) and **`domains/packaging`** (case 98), **not** `domains/apps/entries` or `domains/packaging/entries`. And it is **not** `<root>` (resolving Risk 5 in G, line 268: `error.path` is `['domains', 'apps']`, which is non-empty!).
  - **Verified `schema_evidence()` tokens for `examples/broken/README.md`:**
    - Case 93 (`93-unknown-supervisor`): `['enum', 'supervisor_map']` $\to$ `schema (\`enum\`)` or `schema (\`supervisor_map\` \`enum\`)` works.
    - Case 94 (`94-missing-supervisor`): `['required', 'trust_domain']` $\to$ `schema (\`required\`)` works.
    - Case 95 (`95-supervisor-not-singleton-id`): `['const', 'propertyNames', 'supervisor_map']`, message is `'host' was expected` $\to$ `schema (\`propertyNames\`)` works.
    - Case 96 (`96-nixos-supervision-comprehensive`): `['const', 'if/then']` $\to$ `schema (\`if/then\`)` works! (Confirms line 247's unverified question: `BRANCH_LOCATORS` in `bin/schema_lint.py:1049` maps `"then"` anywhere in `full` schema_path to `"if/then"`, even inside top-level `allOf`.)
    - Case 97 (`97-nixos-tombstone-elsewhere`): `['if/then']` $\to$ `schema (\`if/then\`)` works.
    - Case 98 (`98-nixos-unit-writer-elsewhere`): `['if/then']` $\to$ `schema (\`if/then\`)` works.
    - Case 99 (`99-nixos-no-supervision-domain`): `['if/then', 'required']` $\to$ `schema (\`if/then\`)` or `schema (\`required\`)` works.
    - Case 100 (`100-nixos-writer-retired`): `['enum', 'unit_writer_entry']` $\to$ `schema (\`enum\`)` works.
  - **Important interaction between Case 97 and B.3's new lint rule:** In Case 97 (`97-nixos-tombstone-elsewhere`), `supervision` has no entries and `apps` has a tombstone `{"state": "absent"}` (which is not `state == "present"`, so B.3's flavour-vs-supervisor check does not fire). In Case 98 (`98-nixos-unit-writer-elsewhere`), `packaging` has a `unit-writer` entry; `check_goal_file_cross_file` only checks `unit-writer` for duplicate/nested prefixes, so it does not fire. However, remember that `validate_loaded()` runs `check_goal_file_family()` on every `examples/broken/` case (`bin/schema_lint.py:1214`), which will emit `family (hash)` and `family (apply)` findings because `goal-file.json` was overlaid. Because `check_declared_class()` checks `want in fired` (`bin/schema_lint.py:487`), `schema (`if/then`)` will pass as long as `schema` fires with `if/then` in `evidence`.

#### Finding 6 [MEDIUM] — Slice S0 (`C.5` tombstone refusal on symlinked-units hosts) needs exact CFEngine class scoping so it does not misfire on Darwin or normal systemd hosts
- **Evidence:** [`stage-d-design-report.md` lines 147, 258, 283](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L147); [`policy/tendcf_services.cf` lines 182–201, 225–232, 314–318](file:///Users/djbclark/src/tendcf-review-policy-wt/policy/tendcf_services.cf#L182-L201).
- **Problem:** `stage-d-design-report.md` proposes Slice S0: *"In `policy/tendcf_services.cf`, report a tombstone on a symlinked-units host by name (the D3 'report'), and add a test check"* (`check 7b`), but never gives the `.cf` policy diff!
  Care is required here: a tombstone in `host_specific.json` (`{"state": "absent"}`) carries **no `unit` object**, so `unit_flavour[$(service_ids)]` is `""` ([`policy/tendcf_services.cf:140-147`](file:///Users/djbclark/src/tendcf-review-policy-wt/policy/tendcf_services.cf#L140-L147)).
  - If you simply removed `service_..._present` from `service_..._refused` at line 200, then **every tombstone on every host** (including Darwin and normal Debian systemd hosts!) would define `service_..._refused` (because `unit_flavour` is `""`, so `service_..._supported` is false!) and print a bogus refusal report!
  - Even on a normal Linux container not booted by systemd (`check 4` / `check 6` non-systemd path), or on `tendcf_systemd_units_elsewhere` (NixOS shape, `check 7`), a tombstone has no `service_..._systemd` class set (because `unit_flavour` is `""`).
- **Concrete proposed policy change for Slice S0 (`policy/tendcf_services.cf`):**
  Keep `service_..._refused` for present entries (line 200), or add a dedicated class for absent entries on a symlinked-units host (`tendcf_systemd_units_elsewhere`):
  ```cfengine
      # On a NixOS-shaped host (/etc/systemd/system is not a writable directory),
      # a tombstone cannot be actuated either: units belong to the Nix
      # configuration (D3). Report the refusal rather than silently skipping.
      "service_$(service_canon[$(service_ids)])_absent_refused_elsewhere"
        expression => "!service_$(service_canon[$(service_ids)])_present.tendcf_systemd_units_elsewhere";
  ```
  And in `reports:` (after line 318):
  ```cfengine
      "service_$(service_canon[$(service_ids)])_absent_refused_elsewhere"::
        "tendcf: service '$(service_ids)' (absent) refused: /etc/systemd/system is not a writable directory on this host ($(sys.flavour)); its units are written by the system configuration (unit writer nixos), not by cfengine";
  ```
  And in [`tests/policy/run.sh`](file:///Users/djbclark/src/tendcf-review-policy-wt/tests/policy/run.sh#L239-L260) (Check 7), run a second pass (`7b`) with `tests/policy/fixtures/systemd-absent.json` and assert:
  - `grep -q "tendcf: service '$unit' (absent) refused: /etc/systemd/system is not a writable directory on this host .*unit writer nixos"`
  - `no_systemctl`

#### Finding 7 [MEDIUM] — Section E.4 miscounts the `examples/broken/*` goal-file overlays and omits `examples/broken-bytes/*`, `examples/broken-projection/75-goal-file-under-vars.json`, and `README.md`
- **Evidence:** [`stage-d-design-report.md` lines 206–210](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L206-L210); commit `f814f1f` diff; [`README.md` line 22](file:///Users/djbclark/src/tendcf-review-policy-wt/README.md#L22).
- **Problem:** Section E.4 misses several files that `bin/schema_lint.py` checks on every run and that had to be updated in commit `f814f1f` (the v3 bump):
  1. **`README.md:22`** (root README): Currently reads `Ninety-six deliberately broken fixtures (63 + 6 + 27) the lint must catch`. With 9 new cases (93–101), this must be updated to `One hundred and five deliberately broken fixtures (72 + 6 + 27) the lint must catch` (or `72` in the breakdown).
  2. **`examples/broken-bytes/*.json` (5 files):** Cases `44-pretty-printed-twin.json`, `45-trailing-newline.json`, `46-duplicate-keys.json`, `47-non-nfc-path.json`, and `48-float-spelling-of-integer.json` are full v3 `goal-file.json` copies (`58-not-json.json` is a 43-byte stub `{"schema_version": 3, "host": "ed25519:a1",}`). As noted in `examples/broken/README.md:260-264`, cases 44, 45, 46, and 48 are supposed to parse to **the exact document the happy path parses to** so they produce zero findings in downstream layers. They must be regenerated from the v4 `examples/goal-file.json` (and `58-not-json.json` bumped to `4`).
  3. **`examples/broken-projection/75-goal-file-under-vars.json` (1 file):** Embeds the entire `examples/goal-file.json` under `vars` (`f814f1f` updated it to v3). Update to v4.
  4. **Exact breakdown of `examples/broken/` (63 directories today):**
     - Cases `01`–`12` (12 dirs): YAML Site Model overlays (`services.yml`, `roles.yml`, `launchd-writers.yml`, `report-rows.yml`) — **untouched**.
     - **39 directories** overlay `goal-file.json`: `13`–`43`, `61`–`65`, `70`–`73`. All 39 need `schema_version: 4`, and **38 of the 39** (all except `18-missing-device-trust`, which has `"domains": {}`) need `supervisor: {"host": {"name": "launchd", "state": "present"}}` in `device-trust.entries` (with case `13` claiming `schema_version: 5`).
     - **2 directories** (`52-ordinary-over-privileged-hunk`, `53-coverage-retreat-ordinary-class`) overlay `goal-file-baseline.json`, `goal-diff.json`, `approval-record.json`, and `approval-record-reject.json` — all 4 files in each of those 2 directories must be bumped to v4, `supervisor` added to `goal-file-baseline.json`, and their `baseline_sha256` / `proposed_sha256` recomputed.
     - **10 directories** (`49`, `50`, `51`, `54`, `55`, `56`, `57`, `59`, `60` — wait: that's 9 directories; total 12 + 39 + 2 + 9 = 62? Let's check: 13..43 is 31 dirs; 61..65 is 5 dirs; 70..73 is 4 dirs; 31 + 5 + 4 = **40 directories** overlaying `goal-file.json`! And 9 directories overlaying `goal-diff.json` and/or `approval-record*.json`: `49`, `50`, `51`, `54`, `55`, `56`, `57`, `59`, `60`. 12 + 40 + 2 + 9 = **63 directories**). Every overlaid `goal-diff.json` and `approval-record*.json` in those 9 directories must have `schema_version: 4` and updated `baseline_sha256` / `proposed_sha256` hashes matching the v4 happy `goal-file.json` and `goal-file-baseline.json`.
  5. ** Text updates in `examples/broken/README.md` and `bin/schema_lint.py`:**
     - `bin/schema_lint.py:36` and `examples/broken/README.md:3`: `"Sixty-three"` $\to$ `"Seventy-two"` (if 9 new cases 93–101).
     - `bin/schema_lint.py:87`: `EXPECTED_BROKEN = 63` $\to$ `72`.
     - `examples/broken/README.md:9`: `"cases 13-73"` $\to$ `"cases 13-73, 93-101"` (since 74–92 are in `broken-projection/`!).
     - `examples/broken/README.md:57` and `bin/schema_lint.py:415` comment: `schema_version: 4` $\to$ `schema_version: 5`.

#### Finding 8 [MEDIUM] — `nix2cf` is pinned to `schema_version: 1` (`compile.py:40`), lacks v2/v3 changes, and already fails 10/24 tests against tendcf `HEAD`
- **Evidence:** [`/Users/djbclark/src/nix2cf/nix2cf/compile.py` lines 40, 60, 104–113, 328–340, 386–390](file:///Users/djbclark/src/nix2cf/nix2cf/compile.py#L40); [`/Users/djbclark/src/nix2cf/tests/test_compile.py` line 84](file:///Users/djbclark/src/nix2cf/tests/test_compile.py#L84).
- **Problem:** In Risk 2 (`stage-d-design-report.md:265`), the author noted *"I did not check the nix2cf repo"*, and in E.6 / S4 assumed `nix2cf` only needs to map inventory `supervisor` $\to$ `device-trust.supervisor` and select the renderer. In reality:
  1. `nix2cf/compile.py:40` has `GOAL_FILE_SCHEMA_VERSION = 1` and its test suite (`pytest`) currently fails 10 tests against tendcf v3 (`rendered goal file fails goal-file.schema.json: /schema_version: 3 was expected`).
  2. `nix2cf` does not yet construct `device-trust` entries itself; [`HostSpec.device_trust`](file:///Users/djbclark/src/nix2cf/nix2cf/compile.py#L107-L112) takes a pre-authored `device-trust.json` dict (`examples/site/device-trust.json` and `tests/fixtures/tendcf-device-trust.json`) and copies it verbatim (`compile.py:335`)!
  3. Therefore, in `nix2cf`, if `supervisor` lives inside `device-trust.entries.supervisor`, `nix2cf` must either inject `domains["device-trust"]["entries"]["supervisor"] = {"host": {"state": "present", "name": supervisor}}` from `HostSpec` (or check that `host.device_trust` matches `supervisor`), update `examples/site/device-trust.json` and `tests/fixtures/tendcf-device-trust.json`, bump `GOAL_FILE_SCHEMA_VERSION = 4`, and regenerate `tests/golden/*.goal-file.json`.
  4. Moreover, for `supervisor == "nixos"`, note `compile.py:341-342`:
     ```python
     if not selected:
         return doc, errors
     ```
     Today, when a host has **no** selected services (`not selected`), `render_goal_file()` returns `doc` with `domains` containing **only `device-trust` and no `supervision` domain at all**! Under v4's `B.2(d)` (`then: {properties: {domains: {required: ["supervision"], ...}}}`), a `nixos` host with 0 selected services returning early at line 342 would omit `"supervision"` and **fail schema validation (Case 99)**!
- **Concrete fix for E.6 / S4:** Document in E.6 that `nix2cf`'s `render_goal_file()` must:
  1. Refuse any selected service on a `nixos` host (`if supervisor == "nixos" and selected: errors.append(...)`);
  2. For `supervisor == "nixos"`, emit `domains["supervision"] = {"coverage": "deliberately-unmanaged"}` rather than returning early at `if not selected:` with `supervision` omitted;
  3. Set `GOAL_FILE_SCHEMA_VERSION = 4`, populate/verify `device-trust.entries.supervisor`, and update `nix2cf`'s fixtures and goldens from v1 to v4.

#### Finding 9 [LOW] — Minor cross-reference & line-number nit in `stage-d-design-report.md`
- **Evidence:** [`stage-d-design-report.md` line 115](file:///Users/djbclark/.local/state/bigteam/tendcf-stage-d-design-20261031/stage-d-design-report.md#L115); [`schema/goal-file.schema.json` line 263](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L263).
- **Problem:** Line 115 says: *"Update the `trust_domain` description (line 263, 'four kinds')"*. Line 263 of `schema/goal-file.schema.json` does not actually contain the phrase `"four kinds"` (that phrase is in `docs/architecture/goal-file-schema-reconciliation-2026-08-15.md:371`, `bin/projector.py:74`, and `bin/schema_lint.py:1795`). Meanwhile, `schema/approval-record.schema.json:10` (which the author could not read, line 331) is confirmed to have `"const": 3` at line 10, and `deploy/linux/canary/goal-file-absent.json` (unread, line 332) is confirmed to be a v3 `systemd` goal file with a tombstone `tendcf.canary.service: {"state": "absent"}` and `unit-writer` `tendcf.canary.*: cfengine`.

---

### Concrete Proposed Schema (`B.2(c)–(d)`)

In [`schema/goal-file.schema.json`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json), use the following for the top-level `allOf` (`B.2(d)`) so `supervision` also explicitly forbids `entries: false` regardless of its `coverage` value, and non-object `domains` cannot vacuously trigger `if`:

```json
  "allOf": [
    {
      "if": {
        "type": "object",
        "properties": {
          "domains": {
            "type": "object",
            "properties": {
              "device-trust": {
                "type": "object",
                "properties": {
                  "entries": {
                    "type": "object",
                    "properties": {
                      "supervisor": {
                        "type": "object",
                        "properties": {
                          "host": {
                            "type": "object",
                            "properties": {
                              "name": { "const": "nixos" }
                            },
                            "required": ["name"]
                          }
                        },
                        "required": ["host"]
                      }
                    },
                    "required": ["supervisor"]
                  }
                },
                "required": ["entries"]
              }
            },
            "required": ["device-trust"]
          }
        },
        "required": ["domains"]
      },
      "then": {
        "properties": {
          "domains": {
            "required": ["supervision"],
            "properties": {
              "device-trust": true,
              "supervision": {
                "properties": {
                  "coverage": { "const": "deliberately-unmanaged" },
                  "entries": false
                }
              }
            },
            "additionalProperties": {
              "properties": { "entries": false }
            }
          }
        }
      }
    }
  ]
```

---

### Operator Questions Table (Q1–Q7 + Missing Question Q8)

| Question | Status (Open vs. Already Settled) | Reviewer Recommendation | Reason & Evidence |
| --- | --- | --- | --- |
| **Q1 — `supervisor` required on every v4 goal file (`launchd\|systemd\|runit\|nixos`) vs. optional (`nixos`-only)?** | **Practically settled** by house rules + D2 | **Required on every v4 goal file**, with the B.3 `goal cross-file` lint rule enforcing `unit` flavour == `supervisor` on present services. | [`schema/goal-file.schema.json:5`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L5) forbids optional scalars with implicit defaults (*"No defaults anywhere: every scalar is required with its explicit value"*). Making `supervisor` optional means omission secretly defaults to "prefix scheme / non-nixos", which is the exact two-spellings/hidden-default hazard F-1 closed. Furthermore, [`linux-targets.md:38`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/linux-targets.md#L38) (Step 6) requires `supervisor` from inventory for `systemd` rendering anyway. |
| **Q2 — Where `supervisor` lives: singleton `device-trust` kind vs. top-level header field?** | **Practically settled** by reconciliation §7 (G-3) | **Singleton `device-trust` kind (`device-trust.entries.supervisor.host`).** | [`goal-file-schema-reconciliation-2026-08-15.md:374-383`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/goal-file-schema-reconciliation-2026-08-15.md#L374-L383) (G-3) explicitly locked the header at `schema_version` + `host` and moved host-level inventory facts (`trust_tier`) into `device-trust` so `goal-diff.schema.json` needs no header-hunk machinery beyond `version_bump`. Putting `supervisor` in `device-trust` gives privileged-ceremony derivation and projector exclusion (`{"vars":{}}`) with zero diff-schema changes. |
| **Q3 — `supervision` coverage on a `nixos` host: `deliberately-unmanaged` vs. `comprehensive` with no entries?** | **Open** (genuine design trade-off, though constrained by schema) | **`deliberately-unmanaged`** (for `schema_version: 4`). | Under [`schema/goal-file.schema.json:47-51`](file:///Users/djbclark/src/tendcf-review-policy-wt/schema/goal-file.schema.json#L47-L51), `deliberately-unmanaged` already makes `entries` structurally unrepresentable, and under [`bin/schema_lint.py:1500-1503`](file:///Users/djbclark/src/tendcf-review-policy-wt/bin/schema_lint.py#L1500-L1503) any coverage transition into or out of `deliberately-unmanaged` is automatically `privileged`. Under D3 (`cf-execd` off, no extra-entry detector on Linux yet), `comprehensive` would claim tendcf is actively auditing extra units on `get` when it is not. |
| **Q4 — Bind the Nix side into the signed goal file in v4 (e.g. `flake.lock` digest) vs. display-only D1 consent diff?** | **Settled by D1 + D3** | **Display-only in D1 consent artifact for v4** (do not add a Nix digest to `goal-file.schema.json` in v4). | D1 defined the consent diff for a Nix host as `flake.lock` + Nix-side diff + evaluated-options JSON, and D3 ruled that tendcf enforces nothing on a Nix host (`cf-execd` off, no `tendcf-agent`). Adding an unverified digest to `goal-file.schema.json` violates [`goal-file-schema-reconciliation-2026-08-15.md:418-425`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/goal-file-schema-reconciliation-2026-08-15.md#L418-L425) (F-2: no speculative fields nothing actuates or verifies). |
| **Q5 — Distro family: ride along in v4 vs. stay deferred?** | **Already settled** by operator ruling (2026-10-31) | **Stay deferred.** | The operator already ruled *"Defer until step 6/8 needs it"* (`06c9929` handoff decisions, 2026-10-31), and nothing in Step 6 (`nix2cf` systemd renderer) or Step 8 (`nixos` passthrough) branches on distro family once `supervisor` (`launchd`\|`systemd`\|`runit`\|`nixos`) is present. |
| **Q6 — Who approves the D1 consent artifact, and where?** | **Open** (operational workflow question) | **Operator approves on the host-flake PR** (`forgejo.mit.edu/djbclark/get` and `github.com/djbclark/site-djbclark`), gated by a required CI job that prints the D1 consent diff, uploads it as a build artifact, and fails hard if `execd.enable` is `true` or unknown module options appear. | Matches [`nixos-passthrough-plan.md:53-59`](file:///Users/djbclark/src/tendcf-review-policy-wt/docs/architecture/nixos-passthrough-plan.md#L53-L59) (Stage B already runs in `nixos-cfengine-build.yml` on PRs) and D3 (no on-device `tendcf-agent` or `cf-execd` runs on `get`). |
| **Q7 — Drop `"nixos"` from `goal-file.schema.json`'s `unit_writer_entry.writer` enum in v4, while leaving `launchd-writers.schema.json` alone?** | **Open** (follow-on from D2) | **Yes — drop `"nixos"` from `goal-file.schema.json`'s `unit_writer_entry.writer` enum in v4**, and **also drop `"nixos"` from `launchd-writers.schema.json:36`** (or document why a macOS launchd writer file ever had `nixos`). | On a `nixos` host, `unit-writer` entries are forbidden by `B.2(d)`; on a non-`nixos` host (`launchd`, `systemd`, `runit`), NixOS writes no units (`nix-darwin` is the macOS Nix writer). Keeping `"nixos"` in `unit_writer_entry.writer` leaves a dead second spelling of NixOS ownership. Note: `f814f1f` only added `"nixos"` to `launchd-writers.schema.json` earlier today to keep the enums identical; `nixos` never writes macOS `launchd` plists (`nix-darwin` does). |
| **Q8 (Missing Question) — How should `unit-writer` name non-reverse-DNS `systemd` units on Debian/Ubuntu (e.g. `dpkg`-owned `ssh.service`, `cron.service`)?** | **Missing from Q1–Q7** (raised only as Risk 4 in G, line 267) | **Ask the operator as a separate Step 6 question before migrating comprehensive `systemd` hosts beyond the canary.** | `unit_writer_map.propertyNames.pattern` (`^[a-z][a-z0-9]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)+\.\*$`) requires at least two dot-separated labels before `.*` (works for `tendcf.canary.*`, fails for `ssh.service`). Commit `f814f1f` added `"dpkg"` to the `writer` enum in v3, but `"dpkg"` is currently unusable for real Debian package units because no legal `unit-writer` key can match a single-label `<name>.service`. |
