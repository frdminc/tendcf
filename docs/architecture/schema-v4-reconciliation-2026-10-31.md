# Schema v4: `supervisor`, the NixOS passthrough host, and the Nix consent diff (2026-10-31)

Status: **spec, rulings taken.** This document is the contract the v4 slices implement.
It supersedes its three inputs, which stay frozen as written:
[the Opus 5.5 draft](schema-v4-opinion-opus-draft.md), the
[Fable 5.1 review](schema-v4-opinion-fable.md) and the
[Gemini 4 Argon review](schema-v4-opinion-argon.md). Argon took the seat that the
standing rule in `AGENTS.md` gives to astra, because astra was short (Codex had 45%
left, below the 60% `codex:frontier` estimate floor). Where an input is wrong, this
document says so in §8 and is not corrected in place.

## 1. Rulings (djbclark, 2026-10-31)

| # | Ruling |
|---|---|
| D1 | For a Nix host, the consent diff shows the flake lock and the Nix-side diff as the **authority**. The evaluated-options JSON is a readable **summary** under it. |
| D2 | Add a host-level `supervisor` fact and bump `schema_version` to 4. On a `nixos` host that fact claims the whole unit namespace, with no per-unit prefix. The whole-namespace wildcard unit-writer was rejected. |
| D3 | On a Nix host, tendcf enforces nothing for now. It only reports and refuses, and `cf-execd` stays off. |
| Q1 | `supervisor` is **required** on every v4 goal file. Its value comes from the closed set `launchd`, `systemd`, `runit`, `nixos`. |
| Q2 | It is a fifth `device-trust` kind and a singleton. Reconciliation §7 G-3 closed the header, so this was not open. |
| Q3 | On a `nixos` host, `supervision` is `deliberately-unmanaged`. |
| Q4 | In v4 the Nix side is **display-only**: the goal file carries no lock digest. Binding it later takes its own bump. |
| Q5 | Distro family stays deferred, under the standing ruling "Defer until step 6/8 needs it". Neither step reads it. |
| Q6 | djbclark approves the D1 diff **on the host-flake PR**, behind a required CI job (§5). That job is the interim consent channel. It has no nonce, sequence number or signature, so it is not an approval record. |
| Q7 | `nixos` is dropped from the `writer` enum in **both** `goal-file.schema.json` and `launchd-writers.schema.json`. |
| R2 | On a `nixos` host, the other domains forbid only the `service`, `interlock` and `unit-writer` kinds, listed **per kind**. A future files or lockfile kind then needs no bump to be allowed. |
| R3 | "The unit flavour equals the supervisor" is enforced **in the schema**, with one `allOf` member per manager. The redundancy is named as residue (§7). |
| Q8 | No inventory exists yet. In nix2cf, `supervisor` is a host input next to `platform`; an inventory schema is its own later design. |
| Q9 | The prefix pattern cannot name Debian units (`ssh.service` under `dpkg`). That needs a separate ruling and design, and v4 leaves it alone. |
| Q10 | `deploy/linux/passthrough/goal-file.json` is a **fixture**, not get's goal file. It carries the example key and digests and is labelled as a fixture until get has a real key. |

## 2. Schema deltas

All three goal-family schemas (`goal-file`, `goal-diff`, `approval-record`) change
`schema_version` from `"const": 3` to `"const": 4`.

### 2.1 `goal-file.schema.json`

1. In `trust_domain.entries.properties`, add `"supervisor": {"$ref": "#/$defs/supervisor_map"}`.
   Append `"supervisor"` to that object's `required` list.
2. Add a new `$defs.supervisor_map`. Its key is the singleton id `host`:

   ```json
   "supervisor_map": {
     "type": "object",
     "propertyNames": {"const": "host"},
     "additionalProperties": {
       "type": "object",
       "properties": {
         "state": {"const": "present"},
         "name": {"enum": ["launchd", "systemd", "runit", "nixos"]}
       },
       "required": ["state", "name"],
       "additionalProperties": false
     },
     "minProperties": 1
   }
   ```

   The description must say four things:
   - It is the host's unit-namespace authority, taken from inventory `supervisor`.
   - On `nixos`, the NixOS configuration writes every unit, so no domain may carry a service, interlock or unit-writer entry.
   - On the other three values, the per-prefix unit-writer entries still govern, and every present service's unit flavour must equal this value.
   - The residue in §7.1.
3. Add a top-level `allOf` as a sibling of `required`, with four members. Each `if` sets
   `"type": "object"` and `required` at every level, so a file without `supervisor`
   never enters a `then`.

   - **nixos member.**
     - `if`: `supervisor.host.name` is `"nixos"`.
     - `then` on `domains`:
       - `required: ["supervision"]`
       - `properties`:
         - `"device-trust": true`
         - `"supervision": {"properties": {"coverage": {"const": "deliberately-unmanaged"}, "entries": false}}`
       - `additionalProperties: {"properties": {"entries": {"properties": {"service": false, "interlock": false, "unit-writer": false}}}}`

     The explicit `entries: false` on `supervision` must not depend on how `supervision` is routed (Fable F1). The per-kind form is R2.
   - **launchd, systemd, runit members, one each.**
     - `if`: `supervisor.host.name` is the manager X.
     - `then`: every service with `state: present`, in every domain except `device-trust`, has a `unit` with key X.

       Spelled out:

       ```
       domains.additionalProperties.properties.entries.properties.service.additionalProperties:
         {"if": {"properties": {"state": {"const": "present"}}, "required": ["state"]},
          "then": {"properties": {"unit": {"required": [X]}}}}
       ```

       `unit` is already `oneOf` with exactly one flavour, so `required: [X]` is sufficient.
4. In `unit_writer_entry.writer`, remove `"nixos"`. Rewrite the description so it no longer names `nixos` as a writer. `nix-darwin` stays: it writes labels in the launchd namespace that Apple, Homebrew and CFEngine share.
5. Update every description that counts trust kinds or names the old passthrough mechanism. These include `trust_domain`, `unit_writer_map`, `unit_writer_entry` and `service_map`.

### 2.2 Other schemas and text

1. `launchd-writers.schema.json`: remove `"nixos"` from the writer enum (Q7). That file is versioned on its own `contract_version` axis, so follow its existing bump rule.
2. In `goal-diff.schema.json`, add to the `version_bump` description: "valid alone only when the baseline rendered at `new` differs from the baseline in `schema_version` only. A bump that adds required content, as v4 does, is a re-adoption (baseline ceremony)." `derive_ceremony_class` already returns `baseline` for `version_bump`; this records the rule (Fable F5). Mirror the sentence in `goal-file-schema-reconciliation-2026-08-15.md` §9.4.
3. Counts that are stated as measured facts must be corrected:
   - `bin/projector.py` (N-5 digest coverage): from "three of four" device-trust bodies to "three of five". Neither `trust-policy` nor `supervisor` carries a digest.
   - `bin/schema_lint.py`: the comments that say "four trust bodies".

## 3. Migration (one PR, S1)

Enumerate the files from disk; never use the counts below as a substitute for enumeration. Both reviews corrected the draft's counts. On disk today, `examples/broken/` has 63 cases:
- 12 YAML Site Model cases (01–12), which are untouched;
- 40 that overlay `goal-file.json` (13–43, 61–65, 70–73);
- the rest, which overlay `goal-file-baseline.json`, `goal-diff.json` or approval records (49–57, 59, 60).

1. **Happy corpus.**
   - `examples/goal-file.json` and `examples/goal-file-baseline.json` get the entry `supervisor: {"host": {"name": "launchd", "state": "present"}}`.
   - Regenerate `examples/goal-diff.json` and every approval record. Their `baseline_sha256` and `proposed_sha256` change.
   - `host_specific.json` stays byte-identical.
2. **Negative overlays.**
   - Every goal-family overlay gets `schema_version: 4`.
   - Every overlaid goal file or baseline that has a `device-trust` domain also gets the launchd supervisor entry. Case 18 has `"domains": {}` and gets none.
   - Case 13 now claims `5`.
   - Diff and record overlays get recomputed hashes.
3. **`examples/broken-bytes/`.**
   - Cases 44–48 are derived from the happy goal file (`examples/broken/README.md` says so). Regenerate them from the v4 file so that claim stays true.
   - Bump `58-not-json.json` to `4`.
4. **`examples/broken-projection/75-goal-file-under-vars.json`:** re-embed the v4 happy file.
5. **Deploy goal files.**
   - `deploy/linux/canary/goal-file.json` and `goal-file-absent.json` get supervisor `systemd`.
   - `deploy/linux/passthrough/goal-file.json` gets:
     - supervisor `nixos`;
     - `supervision: {"coverage": "deliberately-unmanaged"}`, with the `org.nixos.*` unit-writer deleted;
     - `schema_version: 4`.
   - All three stay JCS.
   - The passthrough projection must remain exactly `{"vars":{}}`. Prove it by running `deploy/linux/canary/check.py`, not by reasoning about it.
   - Reword the comment at `check.py:34-36`. Label the passthrough file a fixture in that comment and in `deploy/linux/passthrough/` (Q10).
6. **Counts and prose.**
   - `EXPECTED_BROKEN` (`bin/schema_lint.py`) and the "Sixty-three" in `bin/schema_lint.py` and `examples/broken/README.md`.
   - The case ranges in `examples/broken/README.md` ("cases 13-73" becomes "13-73, 93-102").
   - The root `README.md` fixture total.
   - The "claims version N" notes in the README and the lint.
7. **Policy strings.** In `policy/tendcf_services.cf`, the refusal message says "unit writer nixos". It becomes "supervisor nixos". This lands in S0 (§6), not S1.

## 4. Negative cases (93–102)

The series is shared across both fixture directories. `broken/` ends at 73 and
`broken-projection/` ends at 92, so new cases start at 93. Each row names its finding
class. Take the exact message and location from a real run of the lint, and correct the
README row to match.

| # | Directory | Broken input | Class (location) |
|---|---|---|---|
| 93 | `93-unknown-supervisor` | supervisor `name: openrc` | schema `enum` (`domains/device-trust/entries/supervisor/host/name`) |
| 94 | `94-missing-supervisor` | device-trust without `supervisor` | schema `required` |
| 95 | `95-supervisor-not-singleton-id` | supervisor id `main` | schema `propertyNames` (`'host' was expected`) |
| 96 | `96-nixos-supervision-comprehensive` | nixos; `supervision` `comprehensive` with one service entry | schema `if/then` (const on coverage; `entries` false) |
| 97 | `97-nixos-tombstone-elsewhere` | nixos; domain `apps` (`not-yet-migrated`) with a service tombstone | schema `if/then` (`domains/apps/entries`, per-kind form) |
| 98 | `98-nixos-unit-writer-elsewhere` | nixos; domain `packaging` with a unit-writer entry | schema `if/then` |
| 99 | `99-nixos-no-supervision-domain` | nixos; `supervision` absent | schema `if/then` (`required`) |
| 100 | `100-nixos-writer-retired` | supervisor `systemd`; a unit-writer with `writer: nixos` | schema `enum` |
| 101 | `101-flavour-not-supervisor` | supervisor `systemd`; a present service with a `launchd` unit | schema `if/then` (R3) |
| 102 | `102-supervisor-hunk-ordinary` | a diff whose hunk changes `device-trust/supervisor/host`, with the approval record claiming `ordinary` | `family (ceremony)` |

Positive checks:
1. The happy corpus, the canary files and the passthrough fixture are valid.
2. `check_trust_inexpressible` passes with five kinds.
3. The passthrough projection is `{"vars":{}}`.

Discrimination (F8): delete each new schema rule on its own. Its case must go red alone. Run `bin/flag_coverage.py` where it applies.

## 5. The D1 consent diff (S3, host-flake repositories)

**Where it runs.** CI on the PR that changes get's flake (`forgejo.mit.edu/djbclark/get`), and on site-djbclark PRs that touch `nixos/` (`nixos-cfengine-build.yml`). It never runs on the device, which actuates nothing under D3. It is never produced by nix2cf, because nix2cf emits path-2 goal files only.

**Authority** (D1, corrected per Fable F6 and Argon Finding 4):
1. the PR's own diff of the host-flake repository, `flake.lock` included. Each changed lock node is reduced to `(input, type, rev, narHash)`;
2. for each changed git input that the host imports, `git diff <oldrev>..<newrev>`, restricted to the imported paths (`nixos/` for site-djbclark).

A lock diff alone shows nothing when the host's own `.nix` files change.

**Summary.** Run this on base and head and diff the two JCS outputs:

```
nix eval --json .#nixosConfigurations.get.config.services.cfengine-tendcf --apply 'c: { enable = c.enable; execd.enable = c.execd.enable; version = c.package.version; package = builtins.unsafeDiscardStringContext "${c.package}"; }'
```

`version` keeps a no-op rebuild readable, since the store path alone changes on every rebuild (Fable F8).

**Effect.** `nix store diff-closures base head`, which stage B already produces.

**Hard checks.** Each one fails the job:
1. On the evaluated host config, `config.systemd.services` has no `cfengine-tendcf-execd`. No unit or timer runs `cf-execd` or `cf-agent`. This checks the effect, not the knob.
2. The **declared** option set under `options.services.cfengine-tendcf` equals `{enable, package, execd.enable}`. A module that grows an option fails until the summary covers it. The draft's version of this check could never fire, because `--apply` projects exactly three keys (Fable F7).

**The question put to djbclark** on the PR, in plain words: "This changes get's NixOS configuration: <authority summary>. CFEngine stays installed and its scheduler stays off; tendcf will still change nothing on this host. Approve?"

## 6. Slices

All slices use worktrees, absolute paths and Sonnet 5.5 `high` or better. Every PR gets a cross-model frontier review before merge (`AGENTS.md`, standing rule).

| Slice | Repo | Content | Depends on |
|---|---|---|---|
| S0 | tendcf | Tombstone report on a symlinked-units host (§6.1); check 7b; policy strings to "supervisor nixos" | none |
| S1 | tendcf | §2 and §3 and §4 in one PR; a bump cannot be split without an unsafe interim shape | spec merged |
| S3 | site-djbclark, get | §5 | spec merged |
| S4 | nix2cf | v1→v4 catch-up (§6.2) | S1 merged |

### 6.1 S0

`policy/tendcf_services.cf` has a gap:
- `_refused` requires `_present` (`:199-200`).
- teardown requires `tendcf_systemd_host` (`:229-232`).

As a result, a tombstone on a host where `/etc/systemd/system` is not a writable directory produces no output. Add a class:

```
"service_$(service_canon[$(service_ids)])_tombstone_elsewhere"
  expression => "tendcf_systemd_units_elsewhere.!service_$(service_canon[$(service_ids)])_present";
```

Add a report that names the service, the layout and `$(sys.flavour)`. The report must not fire on Darwin or on a normal systemd host. Add check 7b to `tests/policy/run.sh` with a `systemd-absent` fixture under the read-only-store shape (opt-in, `TENDCF_TEST_NIXOS_SHAPE=1`). It asserts:
- the report line appears;
- `systemctl` is never run;
- nothing is written.

Test the negative too: on a normal systemd host, the class must not fire.

### 6.2 S4 (nix2cf)

The current state:
- nix2cf renders `schema_version: 1` (`nix2cf/compile.py:40`), and its tests fail against tendcf v3.
- It refuses every non-macOS host.
- It copies `device-trust` verbatim.
- `platform` is a CLI flag.

The slice brings it to v4:
1. the v2 systemd `restart`/`wanted_by` fields and the argv alphabet, and the v3 writer vocabulary;
2. a `supervisor` host input next to `platform` (Q8), written into `device-trust.entries.supervisor`, with a refusal when a supplied `device-trust` document disagrees;
3. on a `nixos` host:
   - a refusal of any selected service ("host is nixos-supervised; its units are the Nix configuration's");
   - `supervision: {"coverage": "deliberately-unmanaged"}` instead of the early return that omits `supervision`;
4. regenerated goldens;
5. a CI check that fails when `GOAL_FILE_SCHEMA_VERSION` differs from tendcf's schema const.

The systemd renderer itself stays step 6 proper.

## 7. Residue, recorded rather than fixed

1. **Second spelling.** On a launchd, systemd or runit host, a service's unit flavour now always equals `supervisor`. R3 makes the equality checked. Collapsing `unit` so the flavour is implied would take a later bump.
2. **The version-above-ceiling report is not implemented.** The description of `goal-file.schema.json` `schema_version` promises it, but no code dispatches on the version. This predates v4.
3. **The N-5 projection guard covers three of five trust bodies.** `trust-policy` and `supervisor` carry no digest.
4. **No inventory schema exists** (Q8). **The dpkg prefix pattern defect is open** (Q9).
5. **`deliberately-unmanaged` turns off extra-entry detection on Nix hosts** (Q3). The NixOS configuration is the one writer there.
6. **The Q6 consent channel is not cryptographic.** It is a PR review, and it is not an approval record.

## 8. Where the inputs were wrong

1. **Draft E.4 counted 63 goal-family overlays that each need a supervisor entry.** 63 is the total number of cases. The correct breakdown is in §3, from both reviews. The draft also missed `broken-bytes`, projection case 75 and the root README count (Argon Finding 7).
2. **Draft D used the lock diff alone as the authority.** That misses changes to the host's own files (§5).
3. **Draft D's hard check 2 could never fire** (§5).
4. **Draft F placed case 97 at `domains/apps/entries`.** The draft's blanket form actually reports `domains/apps`. The per-kind form adopted here (R2) reports `domains/apps/entries`.
5. **Argon Q5 says the operator already ruled on distro family.** That is correct, and it is the standing "Defer until step 6/8 needs it" ruling of 2026-10-31.
6. **Argon Finding 1 (HIGH) retracts its own trace.** The `required` placements in the draft's `if` are correct. What survives is the advice to add `"type": "object"` at each level, which §2.1(3) adopts.
