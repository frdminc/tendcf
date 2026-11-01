STATUS: recovered by acp-dispatch from the agent's final message (the agent did not write the report file)
I'll start by reading the design document and AGENTS.md.Now the schemas, lint, projector, and policy in one batch.One contract item left before writing: check the inbox for lead messages.STATUS: complete (read-only run; delivered as final message)

# Stage D design review (Fable 5.1, independent seat 2 of 2)

Design read whole; repo read at `review-policy-rule` (cd7cb26). Verified by reading, not running: `bin/schema_lint.py` paths cited below, the installed jsonschema 4.26.0 in the schema-lint uv env, all four schemas, the policy bundle, both deploy goal-file sets, nix2cf `compile.py`/`cli.py`, the NixOS module. Not run: the lint, check.py, cf-agent, nix. Not read: get's flake/lock (not on this machine).

**Verdict: sound with changes.** The schema delta (B.2) does what it claims under 2020-12; the device-trust placement (B.1) is the right one and D2 is satisfied in substance. The consent-diff section (D) has two defects that must be fixed before S3, the migration plan (E) miscounts the regeneration set and misses nix2cf's real state, and three doc/message details are wrong by one step.

## 1. Schema deltas (B.2)

Correct, with evidence:

- `then.properties.domains.additionalProperties` applies to every member of `domains` not named in that same subschema's `properties` (2020-12 semantics; jsonschema `find_additional_properties` reads the sibling `properties`). So **`"device-trust": true` is needed** (else `entries: false` hits device-trust, which requires `entries` at `goal-file.schema.json:300`) **and sufficient** (device-trust's kind set is closed at `:279`, so it can carry no state kind).
- `supervision` is matched by `then.properties`, so it escapes `additionalProperties`; the `const` on coverage plus base `domains.additionalProperties → state_domain` (`:26`, `:47-51`) forbids its `entries`. True today.
- No route remains for a service, tombstone, unit-writer or interlock on a nixos file: device-trust (closed), supervision (coverage const → no entries), every other domain (`entries: false`). Domain names are still held to `propertyNames` (`:21`).
- The `if` chain uses `required` at every level, so a file without `supervisor` never enters `then`. Right direction.
- Attribution: `if_` descends with `schema_path="then"` (`_keywords.py:386`), `if` itself is skipped (`validators.py:440`), `BRANCH_LOCATORS` maps `then`→`if/then` (`schema_lint.py:960`). Cases 96–99 can claim `if/then`. Verified, not [mem].

**F1 (Low, schema).** B.2(d)'s "supervision needs no `entries: false` of its own" rests on supervision being routed through base `additionalProperties`. If supervision ever gets its own def under base `properties`, the nixos rule silently loses its entries prohibition. Add it explicitly; it costs nothing and names the member:
```json
"supervision": { "properties": { "coverage": { "const": "deliberately-unmanaged" }, "entries": false } }
```

**F2 (Medium, schema shape).** Blanket `entries: false` on other domains says more than D3 ("enforce nothing *for now*") and more than the repo's stated future for such hosts: nixos-passthrough-plan.md:86-88 names files and the report channel as the only enforceable things there, and linux-targets.md:66-68 makes the lockfile/consent diff tendcf's job on a passthrough host (Q4's eventual binding). Both would be non-trust entries that this `then` forbids. Today `state_entries` has exactly three kinds (`:57-61`), so the two forms are equivalent; the per-kind form reads as D3 and survives a kind addition:
```json
"additionalProperties": { "properties": { "entries": { "properties": { "service": false, "interlock": false, "unit-writer": false } } } }
```
Operator's call; I prefer per-kind.

**F3 (Low, message).** jsonschema returns a False-schema error *before* appending path/schema_path (`validators.py:406-414` vs `:442-445`). Case 97's finding is located at `domains/apps`, not `domains/apps/entries` as the table says, and prints the whole entries object. Per-kind (F2) gives `domains/apps/entries` and prints only the offending kind map. Risk 5 (`<root>`) does not occur for any of 93–101: each has a non-empty instance path.

## 2. `supervisor` as a device-trust kind (B.1)

Sound against the diff/approval/ceremony model: `derive_ceremony_class` is positional (`schema_lint.py:1498-1499`), `apply_diff` handles any trust kind generically (`:1531-1570`), `refused` paths address `hunks/device-trust/supervisor/host` (`:1651-1654`), `check_trust_inexpressible` iterates whatever kinds `examples/goal-file.json` carries (`:1841`) and smuggles both kind and body (`:1857-1875`): the body `{"name","state"}` fails every state kind (service oneOf, interlock required set, unit-writer `additionalProperties:false`). Projector exclusion is by domain name (`projector.py:120`), so `{"vars":{}}` holds.

Strongest case against, stated honestly: (i) `trust_domain`'s charter is "the validator and agent read their own configuration ONLY from here" (`:263`); `supervisor` is read by the compiler and lint, never by the device, so it is the first trust kind whose consumer is off-device. (ii) D2's literal "host-level" names the header. (iii) The tightening direction (systemd→nixos) is made privileged though it removes privilege. Answers: (i) the entry's job is to *gate* unit-writer legality, which is gate machinery, and §7 puts gate machinery nowhere but device-trust; (ii) reconciliation §7 G-3 (`:374-383`) closed the header for exactly this class of fact and gave the diff-machinery reason, so "host-level" can only mean per-host; (iii) same cost trust-tier already pays. **D2 satisfied.** Q2 is therefore not open (see table).

**F4 (Medium, second spelling).** With Q1=required, flavour and supervisor are always equal on launchd/systemd/runit hosts: the redundancy the schema's own text forbids (`:34` "unrepresentable instead of if/then-guarded"; reconciliation `:380-383`). B.3's lint is that if/then-guard in Python. Accept the redundancy as *named residue* in the `supervisor_map` description ("`unit`'s flavour is redundant with this fact on a non-nixos host; collapsing `unit` is a later bump"), and express the rule where the corpus puts such rules, in the schema, so the harness's `schema (if/then)` discipline covers it: three `allOf` members, one per manager, each `if supervisor.host.name == X then every domains/*/entries/service/* with state present has unit required [X]`. The lint form is acceptable if the operator prefers its message; either way the residue must be written down.

## 3. Fail-closed (C)

- C.1 correct: `const` (`:11`) and closed trust kinds (`:279`); case 13 claims 4 today (verified). The "distinct version-above-ceiling report" is **not implemented anywhere** (grep `ceiling` in `bin/` hits only the projector's 5 MiB rule); `:10` promises it. Pre-existing; record in the bump PR as residue, not fixed here.
- C.2 correct (`report-row.schema.json:118-122`; reconciliation `:309-318`).
- **F5 (Medium, pre-existing, must be written down).** A `version_bump` diff cannot exist in the corpus for *any* bump: `apply_diff` ignores `version_bump` (`:1521-1523`) and the family check compares applied bytes to the proposed file (`:1713-1719`), which differ at least in `schema_version`. v2 and v3 were therefore re-adoptions in practice; v4 (adds required content) is one in principle. `derive_ceremony_class` already returns `baseline` for `version_bump` (`:1496-1497`), so the class is right and only the rule is unstated. Proposed text for `goal-diff.schema.json` `version_bump` description and reconciliation §9.4: "`version_bump` alone is valid only when the baseline rendered at `new` is byte-identical to the baseline apart from `schema_version`; a bump that adds or changes required content is a re-adoption: a baseline ceremony with no diff object." C.3's "ship the validator as an agent hunk under v3" is moot while no agent exists; say so.
- C.5 confirmed line by line: `_unit_present` `:227-229` and `_teardown` `:231-232` need `tendcf_systemd_host` (`:184-185`, writable dir), `_refused` `:199-200` needs `_present`, reports `:314-318` need `_refused`, launchd cleanup `:256-258`/`:272-274` is `darwin`-gated. A tombstone on a symlinked-units host is silent. S0 is right. Check 7 (`tests/policy/run.sh:247-276`) runs only `systemd-present.json`; 7b needs a `systemd-absent.json` pass under the shape. Proposed class and report:
  ```
  "service_$(service_canon[$(service_ids)])_tombstone_elsewhere"
    expression => "tendcf_systemd_units_elsewhere.!service_$(service_canon[$(service_ids)])_present";
  reports: "service_..._tombstone_elsewhere":: "tendcf: service '$(service_ids)' tombstone not actuated: /etc/systemd/system is not a writable directory on this host ($(sys.flavour)); its units are the system configuration's (supervisor nixos)";
  ```
  After Q7, `:168`, `:318` and the plan's "unit writer nixos" wording should say "supervisor nixos".

## 4. Consent diff (D)

**F6 (High).** The AUTHORITY block is the lock diff only. A lock diff shows `(input, rev, narHash)`; it does not show what changed in the input, and it shows *nothing* for a change to get's own flake files (its configuration is in the get repo, not an input). D1's "flake.lock + Nix-side diff" must be read as: the PR's own diff of the host-flake repo (flake.lock included), plus, for each changed git input, `git diff <oldrev>..<newrev>` of that input restricted to the paths the host imports (`nixos/` for site-djbclark, per nixos-passthrough-plan.md:16). `diff-closures` is the *effect*, not the authority; keep it as the third block. Proposed D step 1: "Authority = the PR diff of the host-flake repository, with `flake.lock` reduced to `(input, type, rev, narHash)` per changed node, followed by the source diff of each changed input at the imported paths."

**F7 (High).** Hard check 2, "any options key outside the summary appears", cannot fire: `--apply` projects exactly three keys, so nothing else can appear in its output. What is wanted is: the *declared* option set under `options.services.cfengine-tendcf` on head equals `{enable, package, execd.enable}`; a module that grows an option fails CI until the summary is extended. Implement with `nix eval --json .#nixosConfigurations.get.options.services.cfengine-tendcf --apply` over `lib.attrNames` recursively (or `lib.collect lib.isOption`). Hard check 1 should be stated against the evaluated host config and strengthened to the effect, not the knob: assert `config.systemd.services` has no `cfengine-tendcf-execd` (module `:40-49`) and no unit or timer whose `ExecStart` references `${config.services.cfengine-tendcf.package}`; a user's own `systemd.services.x` running cf-agent bypasses the option.

**F8 (Low).** `package = "${c.package}"` is a store path whose hash changes on any rebuild, so a no-op rebuild shows a changed summary line. Use `c.package.version` (the compiled-in `3.29.0a.<fork>` stamp, plan `:45-46`) beside the path. The `nix eval` form and the `--apply` interpolation are otherwise right; the attribute is `nixosConfigurations.get` (lead-verified).

D's "not the device", "not nix2cf" are correct (`projector.py:14-15`; linux-targets.md:38). Note nix2cf *does* produce the nixos host's (service-less) goal file at S4; only the Nix-side diff is out of its scope.

## 5. Migration and tests (E, F)

**F9 (Medium, counts).** "All 63 goal-family overlays … each needs the supervisor entry" is wrong. 63 is the case total. Verified on disk: 40 cases overlay `goal-file.json` (13–43, 61–65, 70–73), 2 overlay `goal-file-baseline.json` (52, 53), and 12 overlay `goal-diff.json`/approval records (49–57, 59, 60). `examples/goal-file-baseline.json` carries only device-trust (verified), so it gains `supervisor` too; both happy hashes change, so every diff/record fixture needs `schema_version: 4` **and recomputed `baseline_sha256`/`proposed_sha256`**, not a supervisor entry. `broken-bytes/44-48` are derived from the happy file; the byte layer never checks derivation (`schema_lint.py:613-630`), so they pass untouched, but README:275 claims "the happy goal file, indented"; regenerate them for honesty. The lint catches every miss (`EXPECTED_BROKEN`, hash rails), so this is effort, not correctness; script the regeneration.

**F10 (Medium, nix2cf).** nix2cf is at v1 (`compile.py:40`; `tests/test_compile.py:84`; v1 goldens), refuses every non-macos host (`compile.py:60`, `:328-333`), and copies device-trust verbatim from an operator-supplied document (`cli.py:71,91`; `compile.py:335`); `platform` is a CLI flag (`cli.py:153`), and there is no inventory file or schema (`compile.py:96-112` TODO; tendcf `schema/` has none). S4 is therefore a v1→v4 catch-up (v2 `restart`/`wanted_by` + alphabet, v3 writers, v4 supervisor + nixos refusal + goldens), not "consume supervisor". Add a cross-repo pin check so nix2cf's `GOAL_FILE_SCHEMA_VERSION` drifting from tendcf's const is red, like `overlay/fork.json`. And D2's "inventory fact" has no inventory to live in: Q8.

**F11 (Low).** Numbering from 93 is right (73 at README:225, projection 92 at `:338`, 70–73 duplicated across directories at `:73-75`/`:316-319`). 3-digit names: `_README_ROW` `\d+` (`:416`) and `sorted(iterdir())` (`:1220`) never parse the number; fine. [mem] error strings all match 4.26.0: `_keywords.py:87` (const), `:271` (enum), `:309` (required); `validators.py:408` (False schema). Case 95 reads `'host' was expected` at `domains/device-trust/entries/supervisor` (propertyNames descends without a path, `:33`).

**F12 (Low).** Add one family case: a supervisor hunk approved `ordinary` → `family (ceremony)`. Case 52 already uses a `policy-tree` hunk (verified), so B.1(3)'s load-bearing claim has no fixture of its own; 102 costs one overlay set.

**F13 (Low, doc counts).** "four kinds" is not at `goal-file.schema.json:263`; the count lives at reconciliation `:369-373`, `schema_lint.py:1795,1810`, `projector.py:74,79,81,172`. `projector.py:72-81` states a *measured* "three of four" for N-5; the supervisor body has no digest, so v4 makes it three of five. Add to E.5.

**F14 (Low, Q7 spillover).** `launchd-writers.schema.json:36` still lists `nixos`; `examples/launchd-writers.yml:30-32` uses `nix-darwin` for `org.nixos.*`. A launchd writer named `nixos` is meaningless; dropping it there too (contract_version axis) avoids a Site Model writer the goal file cannot carry. No lint compares the two enums today.

E.1/E.2/E.3 otherwise check out: projections unchanged by P-1; `goal-file-absent.json` (I read it) needs only the supervisor entry; `check.py:34-36` reword; `host_specific*.json` byte-identical.

**F15 (Low, risk 4 is a question).** Confirmed pre-existing: `:243` requires two dot-labels before `.*`, so `ssh.service` under `dpkg` is undeclarable and pastebin's comprehensive domain would report every Debian unit as extra once detection exists. It touches the same def v4 edits; a second bump for it is the cost the design elsewhere avoids. Q9.

**F16 (Low).** The passthrough file's host key and trust digests are the `examples/` placeholders (verified identical). It is a fixture, not get's consent object; D's "what a person is asked" reads as if it were. Label it so in `check.py`/README until get has a key. Q10.

## Q1–Q7

| Q | Recommendation | Reason / status |
|---|---|---|
| Q1 | **Required**, closed enum | Optional-absent = hidden default (`:5`). Open. Carry F4's residue. |
| Q2 | device-trust | **Not open**: reconciliation §7 G-3 closed the header (`:380`) with the trust-tier precedent; D2's "host-level" means per-host. Reopening G-3 is a separate ruling. |
| Q3 | `deliberately-unmanaged` | Passthrough is permanent by design (linux-targets §5), not backlog; `comprehensive`-empty asserts tendcf describes the domain completely, which is false, and would count 116 units as extra (report-row `:87` is a two-writers signal, and there is one writer, declared by the fact). Leaving it is privileged (`:1502`). Open. |
| Q4 | Display-only in v4 | No verifier exists. But linux-targets.md:66-68 makes the lockfile tendcf's job on passthrough hosts, so name the future shape as residue and keep v4's `then` from precluding it (F2). Open. |
| Q5 | Defer | Nothing reads it; step 6 needs supervisor, not distro family; §8 rule "carry only what is actuated"; regeneration is scripted (F9). Open. |
| Q6 | Required human review + CI artifact on the host-flake PR | Write it into nixos-passthrough-plan.md as the interim consent channel under D3; it has no nonce/seq/signature and is not the approval record. Open. |
| Q7 | Drop `nixos` writer | Plus F14 and the policy strings in F-C.5. Open. |

Missing: **Q8** where `supervisor` is authored (no inventory schema or file exists; F10). **Q9** the dpkg prefix defect in the same def (F15). **Q10** whether `deploy/linux/passthrough/goal-file.json` is get's goal file or a fixture, and who computes get's real device-trust values with no agent to hold a key (F16).

DECIDED: none needed; nothing blocking. Severity order for the lead: F6, F7 (before S3); F9, F10, F5, F2, F4 (in S1/S2 text); the rest are one-line edits.

DONE
