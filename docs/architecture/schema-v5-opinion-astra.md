STATUS: recovered by acp-dispatch from the agent's final message (the agent did not write the report file)
I’ll read the repository instructions and full design, then check its schema, enforcement assumptions, and negative cases against the local contract. I’ll keep this review read-only and return the report here for the harness to save.
The main concern is the ownership model: choosing one effective unit file does not establish one writer for the unit’s drop-ins, aliases, masks, or future replacements. I’m checking that against the existing schema and adapter before distinguishing blocking changes from documented limits.
I found three concrete gaps: the detector would accept a CFEngine-owned file even when its service entry is a tombstone; the proposed 128-character cap rejects some valid v4 writer keys; and vendor shadowing conflicts with the current “must not exist” tombstone contract. Section E also contains seven questions, so I’ll address all seven.
STATUS: complete

Verdict: **unsound as specified**. C4 is a promising direction, but its central one-writer proof is false, and its detector can label conflicting or undesired state clean. These are contract defects to resolve before freezing schema v5, not merely prototype details.

Reviewed the full design against local checkout `8ae56ad56076ac1827e310e2806c9a5fb3c6c053`. No network, remote commands, tests, builds, or intentional filesystem changes were performed. Existing untracked `opencode.json` was left untouched. Graft attempted an automatic cache refresh; the sandbox refused it. Its reported savings total was approximately 67,604 tokens ($0.05).

References below use `design:L` for `/Users/djbclark/.local/state/bigteam/tendcf-q9-design-20261102/q9-design-report.md:L`; repository paths are relative to `/Users/djbclark/src/tendcf`.

## A. Findings

### A1. HIGH — Effective-file precedence does not establish one writer per namespace

**References:** design:189–197, 215–216, 314–315; `docs/architecture/architecture-DEFINITIVE-v3.md:188–190`; `schema/goal-file.schema.json:510`.

C4 permits an `openssh-server` package claim alongside a CFEngine claim and service entry for `ssh.service`. The package continues supplying the vendor file while CFEngine writes the override. Selecting the effective fragment chooses a winner; it does not eliminate the other writer or its future writes.

Likewise, a package-owned base fragment and a locally written drop-in jointly determine one unit. E5 explicitly proposes permitting this with an exact claim, contradicting the claimed unchanged one-writer invariant.

The requested property—validation cannot succeed while violating one-writer-per-namespace—is therefore not met. JSON Schema cannot determine package membership from this document alone, and the proposed lint does not attempt it.

**Exact proposed replacement for design:197:**

> “The directory partition selects a classification rule; it does not prove one writer per unit namespace. Static validation proves uniqueness only among literal name claims and uniqueness of package identifiers. The device must detect overlapping authorities, including vendor fragments shadowed by local fragments, aliases, and effective drop-ins. Under the existing one-writer contract, unresolved or conflicting authority is reported as conflict and never clean. Allowing layered ownership requires an explicit amendment to the architecture and a separately specified ownership model before schema v5 freezes.”

Do not accept E5/E6 as harmless residue while asserting that D36’s associated one-writer contract remains unchanged.

### A2. HIGH — C.3 omits configuration inputs that can change effective behavior

**References:** design:187–197, 298, 314.

C.3 examines one primary name and effective file. It does not specify classification of effective drop-ins, template/instance drop-ins, aliases, masks, or activation links. A declared vendor fragment plus an undeclared `/etc/systemd/system/ssh.service.d/override.conf` follows step 3 and is clean under the written algorithm.

Resolving aliases before checking their provenance can also discard an undeclared locally created alias. Resolving a mask to `/dev/null` loses the identity and location of the mask itself. Generated and transient units cannot universally be treated as ordinary resolvable persistent files.

**Exact proposed addition after design:188:**

> “Enumeration must preserve the unit’s lookup names and provenance. For each unit, inspect its selected fragment, effective drop-ins, alias links and masks, including relevant template, instance and broader drop-in scopes. Record links before resolving their targets. Enumerate both installed unit files and manager-known generated/transient units; deduplicate identities without discarding configuration inputs. Each relevant input must have an authorized provenance. Missing evidence, unsupported input forms, enumeration failure or conflicting provenance makes the result unverifiable or conflicting, never clean.”

**Exact proposed addition to D.4:**

> “Separate detector fixtures cover an undeclared drop-in on a declared vendor unit; a local alias to a declared vendor unit; a persistent mask; a runtime mask; a template with an instance drop-in; a generated unit; and a transient unit without a persistent fragment. Each fixture states its expected classification independently.”

This is a prerequisite to assessing E5, not an implementation detail that leaves the schema shape certainly unaffected.

### A3. HIGH — Tombstones can authorize “clean” state, and vendor shadow removal violates absence semantics

**References:** design:192, 216, 242, 263; `schema/goal-file.schema.json:322–323`; `policy/tendcf_services.cf:238–245`, `:275–278`, `:312–314`.

Step 4 requires “an entry in `service`.” A tombstone is such an entry. A surviving CFEngine-owned file can therefore be classified clean even though the goal says it must not exist.

The new lint rule requiring a CFEngine claim for tombstones does not fix this. It also cannot establish that removing `/etc/systemd/system/ssh.service` makes `ssh.service` absent: the vendor fragment remains. “Disabled” is neither “absent” nor a guarantee against activation.

**Exact proposed replacement for design:192:**

> “A match with writer `cfengine` requires a same-domain service entry with `state: present`. A matching `state: absent` entry never authorizes a present unit; report it as unmet desired absence. The reporting contract must distinguish this condition from an undescribed extra.”

**Exact proposed replacement for design:216:**

> “Vendor shadowing is unsupported under the current tombstone contract. Removing a local override can reveal a vendor unit, so the existing adapter cannot implement `state: absent` for that unit identity. Supporting shadowing requires a separate definition and implementation of withdrawal versus absence, with lifecycle tests. Disabling a unit is not equivalent to making it absent.”

Tombstone writer validation should be considered for every coverage mode that admits actuated entries. The adapter does not limit tombstone actuation to comprehensive domains.

### A4. HIGH — Domain scope is inconsistent between schema, lint and detector

**References:** design:118–143, 165–166, 185, 209; `bin/schema_lint.py:1531–1549`, `:1577–1599`; `schema/goal-file.schema.json:294–319`.

The new kind is permitted in every ordinary state domain, and package duplication is checked globally. Yet C.3 operates only in `supervision`, with consent addresses likewise assuming that domain.

A package claim in `packaging` is structurally legal on systemd. The report does not say whether it authorizes units observed by the supervision detector. Neither answer is harmless: ignoring it makes legal signed content inert; accepting it creates cross-domain authorization and coverage interactions that are not specified.

The existing service lint uses writer claims from the service’s own domain, so silently switching to global claims would also change established behavior.

**Exact proposed addition to C.1/C.3:**

> “Domain placement is part of the contract and must be settled before implementation. Either constrain `unit-package` to `supervision` and define how other domains’ service/writer entries participate in supervision detection, or specify domain assignment and coverage semantics for every observed unit. A claim in a non-comprehensive domain must not silently authorize state in a comprehensive domain. Same-domain service authorization remains required unless explicitly changed.”

This is a missing design question, not a choice an implementer should make conservatively.

### A5. MEDIUM — Package ownership requires a nonempty, unambiguous result and explicit provenance limits

**References:** design:189, 195, 202, 217, 220.

“Every owning package is declared” is vacuously true for an empty owner set. The intended unowned-file negative demonstrates that this is not the desired rule.

`dpkg-query -S` establishes database claims about paths, not which actor last wrote the contents. Multiarch-qualified output, diversions, symlinks and merged-/usr spellings need specified handling. Package-maintainer-generated files may lack a normal file-list ownership record. These are not all simply malformed output.

A path located beneath the vendor directory is also not automatically trustworthy provenance when it is a link elsewhere.

**Exact proposed replacement for design:189:**

> “Vendor classification requires a nonempty, successfully parsed and unambiguous ownership result for the actual relevant artifact. Every owner must map to a declared package identity. Zero owners, unresolved diversions, ambiguous identity normalization, inconsistent path aliases or an unsupported symlink/provenance chain are unverifiable and never clean. Define whether package identities aggregate architecture-qualified instances; do not silently strip architecture qualifiers. Database ownership establishes recorded provenance, not file integrity or authorship.”

**Exact proposed addition to D.4:**

> “Add distinct fixtures for successful lookup with no owner, multiple owners, an undeclared co-owner, architecture-qualified output, a diversion, merged-/usr path spelling, and a vendor-directory symlink whose target is outside the vendor tree.”

Ownership-only detection can be an explicit product limit, but should not be described as detecting all accidental edits.

### A6. MEDIUM — The grammar is a restricted naming subset, and the new cap breaks v4 compatibility

**References:** design:109–115, 141, 167, 218, 289; `schema/goal-file.schema.json:497–499`, `:330–336`.

The existing writer-key schema has no length limit. The proposed common `maxLength: 128` therefore rejects some valid v4 launchd/runit prefixes. “These hosts see no widening” does not establish that their accepted language is unchanged.

The exact-name grammar deliberately excludes instances and other valid systemd naming forms. This matters particularly for non-package units, where exact claims are the only permitted non-CFEngine spelling.

The assertion that lint refuses instance IDs is too broad: `foo-*` can cover `foo-worker@instance.service`. Exact template keys do not match instances, but eligible prefixes can.

**Exact proposed replacement for design:141:**

> “Launchd and runit retain the complete v4 writer-key language, including its existing length behavior. Apply systemd-specific naming restrictions in the systemd conditional rather than imposing a new shared cap. Any intentional narrowing must be enumerated as a migration change.”

**Exact proposed replacement for design:167:**

> “Exact template claims do not cover instance identities. Instance keys are forbidden by this proposed grammar, although an eligible CFEngine prefix may cover an instance service ID. Non-package instance units cannot be declared with exact third-party claims. This representational limit requires a ruling or a grammar change before comprehensive coverage is advertised.”

The displayed fragments use valid Draft 2020-12 concepts, but they are patches, not a complete executable schema. Preserve `type`, `additionalProperties`, entry requirements and `minProperties` when merging them. Validate the assembled schema and examples before claiming schema validity.

### A7. MEDIUM — Candidate comparison understates the strongest alternative to C4

**References:** design:50–58, 82–90, 201, 215, 310.

C1 is rejected partly using `ssh*`, which C1’s referenced grammar itself rejects. More importantly, name claims can be checked against package provenance; C4 does not have exclusive access to that evidence.

C3 is said to offer “no gain” over package claims. It offers a clear gain: newly introduced units within an already authorized package remain visible. C4 explicitly loses that signal.

C4’s strongest objection is that a declaration of a package grants open-ended authorization for future units, while its origin partition still does not solve layered ownership. Its compactness is useful, but it is also a deliberate reduction in consent granularity.

**Exact proposed replacement for design:90:**

> “C3 preserves per-unit consent and reports newly added units even inside an already declared package. With package-provenance verification it can also check origin. Its cost is larger goal files and additional review churn. C4 trades that precision for stable package-level authorization; this tradeoff requires an operator ruling.”

**Exact proposed addition to C1:**

> “A verified variant restricts dpkg name claims to package-owned artifacts and rejects local overrides. Compare this variant explicitly; the unverified variant alone does not exhaust the candidate.”

C2’s rejection and C5’s status as a stopgap are reasonable. C2′ is a credible alternative only if automatic authorization of every qualifying installed package is expressly desired.

### A8. MEDIUM — Migration and cases 113–132 do not yet establish the claimed contract

**References:** design:239–279; `schema/goal-diff.schema.json:26`; `bin/schema_lint.py:1630–1640`.

The overall migration inventory is useful, including case 98, broken bytes, embedded projection case 75 and version-family hashes. However, absence of new required fields does not itself make a version-only migration valid. Every existing baseline must remain valid apart from its version, including writer vocabulary, key length and tombstone restrictions.

Case 123 does not distinguish a missing writer claim from an existing non-CFEngine claim. Case 131 requires new package-specific duplicate lint; it is not covered merely by analogy to case 65. No case protects removal of `dpkg` from the Site Model enum. Cases are sketches, so their single-defect status remains unproved.

**Exact proposed replacement for design:246:**

> “A bare version bump is valid only for a baseline that remains valid at v5 and whose rendered content changes solely in schema_version. Audit each baseline for retired dpkg name claims, naming restrictions and newly required tombstone ownership. Otherwise use re-adoption under the existing migration contract. Declaring additional units is a separate content change.”

**Exact proposed addition to D.3/D.4:**

> “Retain 113–132 provisionally and add separate witnesses for a tombstone under a non-CFEngine claim, retired dpkg in launchd-writers, missing package writer/state, extra package-entry properties, unsupported domain placement, and the chosen key-length boundary. Add positive witnesses for exact CFEngine authorization, exact third-party declaration, template handling, disjoint exact/prefix pairs and all retained v4 keys. For negative fixtures, remove unrelated services or provide valid same-manager services and claims so the intended defect is isolated.”

**Exact proposed replacement for design:279:**

> “For each rule mutation, record the expected witness set and verify that those fixtures are unexpectedly accepted. Every new rule needs a discriminating witness; a shared rule may legitimately have several witnesses. One defect per fixture does not imply one fixture per rule.”

Case 132 tests the existing closed projection-container rule; it should not be presented as discriminating a new package-specific projection rule.

### A9. MEDIUM — Enumeration scope is justified incorrectly

**References:** design:187, 311.

“Targets, mounts and slices don’t start a program of their own” is not a sound boundary for comprehensive supervision. Mount operations can execute helpers; target dependency edges can activate services. Even a type with no direct process changes supervision behavior.

This review did not independently fetch systemd documentation or probe Debian, as network and remote commands were forbidden. Those semantics need explicit verification in the required prototype.

**Exact proposed replacement for design:311:**

> “Which system-manager unit types are in the declared supervision namespace? Recommend inventorying every supported unit type, with explicit unsupported/unverifiable results. Do not infer that excluded types are harmless from whether they directly carry ExecStart. If v5 deliberately covers only service, socket, timer and path, state that restricted coverage explicitly rather than describing the whole supervision namespace as comprehensive.”

### A10. LOW — Several factual claims exceed the repository evidence

**References:** design:17–19, 67, 201, 310; `docs/architecture/architecture-DEFINITIVE-v3.md:1027`; `docs/architecture/schema-v4-reconciliation-2026-10-31.md:21–38`.

The schema demonstrably cannot express the cited Debian names. It does not establish that *no* real Debian unit can satisfy a reverse-DNS prefix.

A read-only `/etc/systemd/system` symlink alone is not proof that every systemd input is Nix-owned. The NixOS behavior rests on an explicit host-level architectural ruling.

Finally, C4 reports a new unit-owning package, not necessarily every newly installed daemon: an already declared package can gain a daemon silently.

**Exact proposed corrections:**

> “The v4 grammar cannot describe the cited Debian unit names and therefore cannot adequately represent the intended Debian namespace.”

> “NixOS has an explicit host-level namespace-authority ruling; the read-only units-directory shape supports the adapter’s refusal behavior but is not independently a proof of complete runtime provenance.”

> “C4 reports units belonging to an undeclared package. It does not report a new unit merely because an already declared package gained it.”

D36 itself labels supervisors generic; cite architecture lines 188–190 for the precise one-writer requirement.

## B. Schema and contract assessment

B1. The `covers`/`overlap` algorithm is correct for literal exact strings and trailing-star string prefixes. Equality across domains must still be caught by duplicate checks. Use `overlap` for claim pairs and `covers` for service matching; they are not interchangeable.

B2. Literal overlap is not semantic overlap through aliases, templates, package membership or layered configuration. The design must state this boundary.

B3. The proposed nixos per-kind ban fits R2. Its placement must cover every ordinary domain; `supervision` remains independently constrained by `entries: false`, and `device-trust` excludes the new kind through its closed shape.

B4. Launchd/runit prohibitions and the systemd prefix-writer restriction should extend the existing supervisor-conditioned branches, retaining their required selectors. A supervisor value of `systemd` does not establish that dpkg exists; detector failure must remain explicit.

B5. Ordinary ceremony for ordinary-domain writer/package changes matches current derivation. That is a repository fact, not evidence that the operator has accepted package-wide future authorization.

B6. Keeping unit ownership data outside the projection is consistent with current architecture. It also means the CFEngine adapter cannot enforce these claims merely because the schema PR lands. Do not describe report-only classification as preventing competing writes.

## C. Operator questions

The actual §E contains **seven**, rather than five, questions. All seven are addressed here.

| Question | Recommendation | Reason / whether open |
|---|---|---|
| E1 — Should a newly installed Debian daemon surface? | Prefer visibility; choose C4 only after explicitly accepting future units from already declared packages. | The question currently conflates new packages with new units. Per-unit verification remains a stronger alternative. |
| E2 — Which unit types count? | Inventory all system-manager unit types, or explicitly narrow the meaning of coverage. | The four-type boundary is not justified by execution behavior. This remains open. |
| E3 — Who writes installer/local units? | Use an explicit installer writer value if that distinction is operationally useful; otherwise exact `third-party` is an honest interim declaration. | The installer already writes `tendcf-execd.service`; that fact is not open. Vocabulary and provenance requirements are open. A new enum value alone proves no authorship. |
| E4 — Accidents-only threat model? | Exclude malicious-root resistance explicitly, but do not equate that with accepting every accidental modification. | R-S3-4 applies to specific Nix hard checks. Extending it to this detector requires a ruling. Ownership-only checks miss accidental edits to package-owned files. |
| E5 — Local drop-in/mask on vendor unit? | Report it unless an explicitly approved layered-ownership model accounts for it. | An exact name claim alone does not preserve the existing one-writer invariant. This is a structural design decision. |
| E6 — May CFEngine shadow vendor units? | Defer support under v5’s current absence contract. | Existing teardown can reveal the vendor unit. Resolve withdrawal, absence, conflict and lifecycle semantics first. |
| E7 — Anything else in this bump? | Keep unrelated features deferred; include all semantics necessary for Q9 to be truthful. | Distro-family deferral is already ruled. Domain placement, provenance, templates and conflict semantics are necessary Q9 work, not unrelated additions. |

Additional rulings needed:

1. Does “one writer” mean one authority for a unit identity, or separately authorized writers for its constituent artifacts? If the latter, amend the architecture and define composition/conflict rules.
2. Where may package claims live, and how does each observed unit acquire a domain and coverage policy?
3. Are new units within a declared package intentionally authorized without another consent diff?
4. Are non-package instances, generated units and transient units representable, or explicitly unsupported?
5. Is `state: absent` about the unit identity or only the locally managed fragment? The existing contract says the former.
6. What does an incomplete scan report? It must not imply a complete zero-extra inventory when enumeration fails.

DECIDED: No reviewer coordination, remote verification, prototype execution, or filesystem modifications were undertaken. The recommendations above are proposed rulings, not recorded operator approvals. This review establishes static contract defects; it does not certify Debian detector behavior or an assembled v5 schema.

DONE
