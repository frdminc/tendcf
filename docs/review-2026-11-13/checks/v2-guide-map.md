# Verification of 02-response-guide.md and 03-response-map.md

Checker: Opus 5.5, read-only. Repo `the review worktree`. Its HEAD is `c3ae530`; that commit only adds the two `docs/review-2026-11-13/` files on top of `eefea3c` (`git diff --stat eefea3c c3ae530`), so the target documents were read at `eefea3c` (`git show eefea3c:<path>`).
Method: a script pulled every quoted anchor phrase out of each item's **Target** line and matched it against the target at `eefea3c`, with markdown and curly quotes normalised (results below). I then read the cited spans with `gsed -n`, ran `rg` over the repo, and used `gh` for the GitHub state of PRs and forks.
Sources consulted: exempt: verification of given documents against the repo. I used GitHub only for facts the items rest on: the fork lineage of `frdminc/ShizukuTendCF`, PR #41/#42 state, and the commits at the fork's pinned revision.

## Anchor check (all items)

Every quoted anchor matched the target at `eefea3c` except two, and neither is a real defect.
1. M-§9-03 is anchored on "Output is one scan report". That bullet exists only in M-§9-02's *proposed* §9.12, so M-§9-03 cannot merge before M-§9-02.
2. M-§13-02 quotes "Android under the Site Model | Same vocabulary." That phrase is in the **guide** §18 (guide:1364), not in the map. The match failed only because the script checked it against the map.

Items with positional anchors only ("after R13", "§20, append", "after D46") resolve: R13 is at map:124 and D46 at map:1246. The G-§20-0x and M-§16-03 appends resolve as well.

## Verdicts

Every blocks-goal and misleads item in both reports is listed. Improves items marked (spot) are the sample: 11 of 21 guide items and 8 of 13 map items.

| Item | Verdict | Evidence (one line) | Correction to apply |
|---|---|---|---|
| G-§0-01 | confirmed | guide:8-16, "this guide wins" with no higher reference | Merge already flags where the goal file lives |
| G-§0-02 | weakened | guide:27-28 already says "apart from a canary service on one operator host"; the omissions are root `cf-execd`, the fail-open (validate-proposal:1017-1023) and get.sipb.cloud | Finding wording; see Corrections |
| G-§1-01 | weakened | guide:47-50 lists Macs first, not "Linux and Termux first"; the multi-operator claim checks out (guide:1257-1261) | Finding sentence, plus one proposed-text error (Nix on devices); see Corrections |
| G-§3-01 | confirmed | guide:189-198; `compiler/examples/site/site.nix:4-7` ("No nixpkgs, no `lib`, no module system") | none (Merge flags the D12 ruling) |
| G-§5-01 | confirmed | guide:330-338 ("synced via git") | none (ruling bracketed) |
| G-§5-02 | weakened | `rg serverd deploy/linux/tendcf-install.sh`: no hits. But there are two live hosts (CLAUDE.md; linux-targets T3, T5), not "the only live host" | Title and proposed parenthesis; see Corrections |
| G-§6-01 | confirmed | guide:409-414 has only a best-effort observability push; code has no JSONL writer (`rg -il jsonl` outside docs: only `schema/report-row.schema.json`) | none |
| G-§6-03 | confirmed | `rg -i 'island\|insular\|work profile' docs/paper docs/architecture`: 0 hits; guide:88 "Shizuku"; ShizukuTendCF README line 1-2: "a fork of thejaustin/ShizukuPlus" (GitHub's fork parent is `thedjchi/Shizuku`: it was rebased) | none |
| G-§7-01 | confirmed | guide:568-573 semantic layer "never authorizes"; no scoring text anywhere | Merge should also name the owner-set auto-refuse floor as needing a ruling, not only the cap rule |
| G-§7-02 | confirmed | guide:245-246, 444-450, 846; `operator`: no local yes | none (ruling flagged) |
| G-§7-03 | confirmed | `upstream-overlay.md:50-56`, `linux-targets.md:22-23`; pinned fork `b8abf284` history has merges of `simulate-json-*` and `simulate-keep-chroot` | none. Caveat: the Mac today runs Homebrew upstream 3.29.0, not the fork |
| G-§8-01 | confirmed | guide:598-600 two-party framing | none |
| G-§8-02 | confirmed | guide:624 "None of this surface is built yet" | none (scaffold ruling flagged) |
| G-§16-01 | weakened | Finding is right (guide:303-305 vs 891-895; `compile.py:463 render_goal_file`). Proposed text says "a shape no code emits", but the plist in A is what the bundle renders and the JSON is what the projector emits | Proposed text; see Corrections |
| G-§16-02 | confirmed | `policy/tendcf_services.cf:1` "launchd on darwin, systemd on Linux"; :148-183 flavour guard and `islink("/etc/systemd/system")` | none |
| G-§16-03 | confirmed | validate-proposal:1017-1023; tendcf PRs #41 and #42 OPEN, checks SUCCESS/SKIPPED/NEUTRAL (`gh pr view`) | Write the PRs as full URLs when merging (the repo's link rule) |
| G-§17-01 | confirmed | guide:1191-1193; map:37 | none |
| G-§18-01 | confirmed | `deploy/linux/tendcf-install.sh`; `linux.yml` matrix ubuntu-24.04/26.04/24.04-arm plus a debian:13 container; no macOS job; `tests/unit_classifier` has 19+74+78+15 = 186 tests; `cli.py:150` eval-nix | none |
| G-§18-02 | weakened | Reuse claims check out (`schema_lint.py:1791,1821`; `roles.schema.json` backups/peers; termux flavour; fixture). But "follows D22 as it stood" is wrong: the guide table has Android at Step 2 with no deferral (guide:1364; `rg -i defer` in the guide: 0 hits). Merge also understates what needs a ruling | Finding sentence and Merge; see Corrections |
| G-§20-03 | weakened | Questions are fair. The evidence paraphrase says high-water covers "replay and downgrade", but guide:550-552 says "replay, freeze, and downgrade" | Evidence wording; see Corrections |
| G-§20-04 | confirmed | guide:1049-1053 free-text `description` in the Site Model | none |
| G-§4-01 (spot) | confirmed | guide:236-239, 251-252 | none (D46 ruling flagged) |
| G-§4-02 (spot) | confirmed | rerun: `command -v nix` prints nothing; `/opt/homebrew/bin/cf-agent --version` gives `CFEngine Core 3.29.0` | none |
| G-§8-03 (spot) | confirmed | `overlay/`, `bin/overlay.py` exist; guide:620-622 | none |
| G-§10-01 (spot) | confirmed | `compile.py:18` "inference — NOT implemented"; guide:689-693 | none (ruling flagged) |
| G-§13-01 (spot) | confirmed | ShizukuTendCF README: headless broadcasts `af.shizuku.plus.api.HEADLESS_STATUS` | none; ADB-after-reboot stays inferred, as the item says |
| G-§14-01 (spot) | confirmed | guide:845 Release row | Conflicts with M-§10-02 (see Disagreements) |
| G-§17-02 (spot) | confirmed | guide:1231-1236; "next-but-two" correctly names the threat-model bullet | none |
| G-§17-03 (spot) | confirmed | guide:1257-1261 | none |
| G-§19-02 (spot) | weakened | guide:1422-1425 says three defects "stop a run before it evaluates a single promise — dropping the host to failsafe", not that they "crash" it | one word; see Corrections |
| G-§20-02 (spot) | confirmed | guide §20 Q1-Q16 match the description | none |
| G-§20-05 (spot) | confirmed | guide:9-12 floor; guide:547-549 2-of-3 | none |
| M-§0-01 | weakened | map:37-39 confirmed. The finding's "that ranking is what put consent at Step 9" is an unverified causal claim | Drop that sentence; see Corrections |
| M-§0-02 | weakened | map:28-30; map §13 (1152-1176) has no "token" (§14 at 1180 is "Premium-token residue", so the pointer probably meant §14). "Minimal and safe" there is a design-taste maxim; calling it "the opposite of G4" overstates. The replacement rewrites an operator principle and needs his ruling | Finding and Merge; see Corrections |
| M-§0-03 | confirmed | map:31-36; linux-targets T3 Debian 13; `goal-file.schema.json` `unit_package_map` writer enum `["dpkg"]` | none |
| M-§2-02 | confirmed | map:105-108 | Proposed "every user profile" goes slightly beyond G5's "works with Island/Insular profiles" (note only) |
| M-§2-03 | weakened | handoff 601f:215-219, :350 confirm "`dpm set-device-owner` is a hard no". Extending that to the "profile-owner slot" is the reviewer's own extrapolation, not a recorded ruling | Proposed text; see Corrections |
| M-§2-04 | confirmed | map:116-117; linux-targets T4, T5 are NixOS | none |
| M-§2-05 | weakened | map:118-120 and 963 confirm "auto-review" is one of two modes **the person chooses**, not a default. Whether owner-chosen delegation breaches G4 is the open ruling, so blocks-goal overstates | Weight misleads; Finding wording in Corrections |
| M-§2-08 | weakened | map:917-920 push/pull only. The proposed R14 states the handshake as "mutual authentication by device public keys", a settled answer, while Merge says it needs a ruling (README rule 4) | Bracket it; see Corrections |
| M-§2-09 | confirmed | map:460-462 "optional best-effort" | none |
| M-§2-10 | confirmed | map:938; guide:846 | none (ruling flagged) |
| M-§2-11 | confirmed | `rg -i '\bTUI\b' docs` hits only the review dir and deprecated notes | none |
| M-§2-13 | confirmed | map:1211 D12 "Two equal frontends"; site.nix plain attrset | none |
| M-§4-01 | weakened | map:212-213, 248-250 confirmed. "182 broken fixtures" is wrong: `examples/broken` 125 + `broken-bytes` 6 + `broken-projection` 28 = 159, matching guide:1309. 1,555 schema lines is right | Number; see Corrections |
| M-§8-01 | weakened | map:460-462 and the "nothing writes report rows" anchor confirmed. But the proposed text settles D45 item 7 (map:1130, listed "Open, for the operator") with no ruling flag | Merge; see Corrections |
| M-§9-02 | confirmed | map:910-915; `approval-record.schema.json` `briefing_sha256` "binds the record to the briefing bytes the person actually saw" | none |
| M-§9-05 | confirmed | map:959-963 advisor key, auto-review | Merge should name D39 ("Their AI, their key") as superseded |
| M-§9-07 | weakened | map:372-374 and 917-920 confirmed; installer has no cf-serverd. The proposed text settles peer mutual-key admission despite "needs ruling" | Bracket it; see Corrections |
| M-§10-01 | weakened | The finding is right (map:938). The proposed row's "standing approval ... applies" does not fit the existing approval record: `required` includes `proposed_sha256`, `nonce`, `approval_seq` (per-change, DC-2 single use) | Proposed row; see Corrections |
| M-§12-01 | confirmed | map:986-988 "Dry-run default"; map:1170-1171 | none |
| M-§12-02 | confirmed | `ls deploy` gives `linux/` only; installer `unit=tendcf-execd.service`; no macOS CI job | none |
| M-§12-03 | confirmed | `compile.py:82-85` android refused; R6 at deprecated v2:183, absent from v3 §2 | none |
| M-§12-04 | confirmed | 0 Island/Insular hits in docs, schema, compiler or policy; the standing rule requires two frontier reviews for a schema_version bump | none |
| M-§12-05 | weakened | `const: 5` and projector `requires-python >=3.11` confirmed; `/usr/bin/python3` is 3.9.6 here. But map:1121-1125 says this "does not establish the version supplied by a CLT-only installation", so "effectively forces" overstates | Wording; see Corrections |
| M-§12-07 | confirmed | map:997-999; handoff f34c:94 "Leave it running as the standing proof"; #41/#42 green | "unblocks D46" not verified |
| M-§13-01 | weakened | It is right that the current order cannot reach state 1. The proposal has four flaws: (a) Step 3 verifies the "release signature and high-water mark", but the signed release is built only at Step 5; (b) inference (D16) is dropped silently, appearing nowhere in Steps 0-13+; (c) G5's Linux server (4) and Linux client (5) are merged into one step; (d) Step 0's single schema bump bundles answers to open questions Q19 and Q20 and the scan-report shape | See Corrections and Disagreements |
| M-§13-02 | confirmed | guide:1364 vs map:1160; the guide has no deferral text | none |
| M-§15-01 | confirmed | map:1209 D8 "Sovereignty is the point" | none (ruling flagged). Note that the goal's own framing ("user's freedom to control their own computing devices") is close to sovereignty, so "supersedes" is the reviewer's reading |
| M-§15-02 | weakened | D22 at map:1221 confirmed. The draft D48 attributes to "Operator, 2026-11-13" a clause the goal does not contain ("Linux-only design work waits for G8 state 2") | Split the attribution; see Corrections |
| M-§15-03 | weakened | D49, under "Operator, 2026-11-13", asserts "`schema/` remains the authority over the data form". That reverses map:248-250 ("JSON Schema is generated from the module options"), which the report's own M-§4-01 leaves open (Q23). The "YAML twin stays as the test" clause is not in the goal either | See Corrections |
| M-§15-04 | weakened | D50 says it "confirms D14", but D14 (map:1214) is "Git-synced policy; `cf-serverd` on every host", which G3 amends. Merge flags only the handshake, not the supersession of the §9.11 push rule and D14 | See Corrections |
| M-§16-02 | confirmed | map:1292-1301 | Weight is closer to improves (note only) |
| M-§16-03 | weakened | Every cross-reference exists. But map:1252 says §16 follows the guide's "order and numbering", while the guide report numbers its new questions 17-26 with different content (G-§20-03..05). Merging both as written breaks that rule | See Corrections |
| M-§12-08 | confirmed | map:1004 vs linux-targets T4 "not in the first milestone", T5 "the first NixOS host" | none |
| M-§12-09 | confirmed | map:1104 vs `goal-file.schema.json:11` `"const": 5` | none |
| M-§2-12 (spot) | confirmed | goal G4 "borrowed" scaffold | none |
| M-§9-03 (spot) | weakened | Its anchor is M-§9-02's proposed text, not the target | Merge should say "after M-§9-02 is merged" |
| M-§9-04 (spot) | confirmed | map:879-893, 904-908; guide:9-12 floor | none (ruling flagged); its proposed "D42's pre-grant is withdrawn" is a ruling and is flagged as one |
| M-§9-06 (spot) | confirmed | map:684 "due before the consent surface (Step 9)" | none |
| M-§10-02 (spot) | weakened | The proposed Delivery default ("Any device whose public key my trust policy lists") narrows G3's "any other device" and conflicts with G-§14-01 | Bracket it; see Corrections |
| M-§12-06 (spot) | confirmed | map:1031-1037 | none |
| M-§15-05 (spot) | weakened | D51's "advises, never authorizes (§9.12)" and D55's "§13 is ordered against them" are put under "Operator, 2026-11-13", but neither is in the goal | See Corrections |
| M-§16-01 (spot) | confirmed | map:1263-1280, Q2, Q5, Q6, Q9 | none |

Counts: 74 rows checked. 49 confirmed, 25 weakened, 0 refuted, 0 unverifiable.
By report: guide 32 checked (25 confirmed, 7 weakened); map 42 checked (24 confirmed, 18 weakened).

## Corrections

**G-§0-02.** Replace the Finding's first sentence with: "The sentence names the canary but not what runs it, and leaves two things out. pastebin runs a scheduled root `cf-execd` over a projection installed with `tendcf-install.sh install --data`, and the interlock path there has a documented fail-open. get.sipb.cloud has the fork installed as a NixOS module, with nothing scheduled." The proposed text stands.

**G-§1-01.**
1. In the Finding, replace "puts Linux and Termux first" with "names an ordinary Linux distribution as a goal and reaches Android only through Termux (no ShizukuPlus, no Island/Insular)".
2. In the proposed text, replace "Nix runs where configuration is written, not on the managed device." with: "Nix runs where configuration is written; on a managed device it runs only where it is already that host's configuration system (NixOS, nix-darwin), or as the owner's authoring tool (§4)." This keeps it consistent with guide §4 (guide:321-324) and with G-§4-02.

**G-§5-02.**
1. Change the title to: "'Its own `cf-serverd`' is true of neither live host, and may be the handshake".
2. Replace the proposed parenthesis with: "(Today pastebin runs `cf-execd` only, and get.sipb.cloud schedules nothing.)"

**G-§16-01.** Replace the proposed text with:
> In **A** and **B** the outputs are hand-authored. Some of their shapes are now emitted by code: the compiler renders the goal file, `bin/projector.py` its projection, and the generic bundle the launchd plist. But nothing derives ordering edges (§10), and B's per-bundle promise sketch is illustrative: the generic bundle, not per-bundle CFEngine text, enforces interlocks (§16.C).

**G-§18-02.**
1. Replace the Finding's first sentence with: "The table is the order from before 2026-10-29: macOS adapter, then Android, compiler, Linux, signing at Step 6 and consent at Step 9. It does not record D22's Android deferral, which the map's table does."
2. Replace the Merge with: "needs the operator's ruling first. It supersedes D22 and the 2026-10-29 Linux-first ruling (`linux-targets.md`), defers D16's inference, and may amend D45 (the Android validator). Within it, rule on step order 3-7, in particular whether signing (step 4) may follow the validator (step 3). The map's §13 changes in the same commit."

**G-§20-03.** Replace the evidence parenthesis with: "(guide:550-552: the high-water mark rejects replay, freeze and downgrade; whether freeze detection works for a device that hears from one intermittent relay is the open part)".

**G-§19-02.** In the proposed text, replace "three of them crash a run before any promise is evaluated" with "three of them stop a run before any promise is evaluated, dropping the host to failsafe".

**M-§0-01.** Delete "and that ranking is what put consent at Step 9 behind everything else" from the Finding. The proposed text stands.

**M-§0-02.**
1. Replace the Finding's first sentence with: "Read literally, 'minimal and safe' losing to 'interesting' sits badly with G4 for a tool strangers adopt, though the maxim was about design ambition, not device safety."
2. Add: "The pointer '(§13)' has no token text; §14 'Premium-token residue' is probably what was meant."
3. Change the Merge to: "needs the operator's ruling first (it rewrites an operator principle)".

**M-§2-03.** Replace the proposed sentence "tendcf never takes the device-owner or profile-owner slot, which Island/Insular need;" with: "tendcf never takes the device-owner slot, which Island/Insular need (operator, 2026-08-13: '`dpm set-device-owner` is a hard no'); [whether this extends to the profile-owner slot: operator's ruling];". Add to the Merge: "the profile-owner extension needs the operator's ruling".

**M-§2-05.** Change the Weight to misleads. Replace the Finding's second sentence with: "Auto-review is a mode the person chooses, not a default. In it the person's AI signs the yes, so a change can apply that the owner never saw; whether an owner-chosen delegation satisfies G4 is the ruling."

**M-§2-08.** In the proposed R14, replace "The receiving device admits a peer only after the handshake: mutual authentication by device public keys against its own trust policy (§10, Delivery axis)." with: "The receiving device accepts a release only after the handshake [what it covers, release signature, peer authentication or both, is §16 Q17, operator's ruling]."

**M-§4-01.** Replace "eight schemas and 182 broken fixtures" with "eight schemas and 159 broken fixtures (125 schema-level, 6 byte-level, 28 projection-level)".

**M-§8-01.** Change the Merge to: "insert after it; the clause placing the fleet-wide SQLite index with the archive answers D45 item 7, an open operator item (map:1130), so it needs his ruling first".

**M-§9-07.** In the proposed text, replace "The receiver admits the peer only after mutual key authentication against its Delivery axis (§10), with explicit key lists rather than address-based trust, then verifies" with: "The receiver completes the handshake [scope: §16 Q17, operator's ruling; if it includes peer authentication, by explicit key lists rather than CFEngine's address-based trust], then verifies".

**M-§10-01.** Replace the proposed row with:
> | **Consent** | Do I also need a local yes? | Every tier: the owner sees the device-computed diff and its scan and may refuse it (G4, R16). `operator`: [per-change yes, a hold window, or an owner-enrolled standing approval: §16 Q19, operator's ruling; a standing approval needs an approval-record shape without a per-change nonce, which is a schema change]. `consented`: an explicit yes per change. `managed`: operator-chosen within that floor |

**M-§12-05.** Replace "Item 6's CLT Python (3.9.6 < 3.11) effectively forces a bundled interpreter on macOS." with: "On item 6, the review machine's `/usr/bin/python3` is 3.9.6, below the projector's `>=3.11`. The map notes this does not establish what a CLT-only install supplies, so a bundled interpreter is the likely, not the forced, answer." In the proposed text, change "on macOS, a bundled interpreter" to "on macOS, likely a bundled interpreter".

**M-§13-01.** Make four changes to the proposed table, and add one line to the Merge.
1. Step 3: move "Release signature and high-water mark" out of Step 3 into Step 5. Alternatively, swap Steps 3 and 5 and say which.
2. Add to "13+ Demand": "ordering inference (D16; deferred, operator's ruling)".
3. Split Step 10 into "10 Linux as server (pastebin through the full gate; systemd renderer; unit-writer detector)" and "10b Linux as client; NixOS passthrough beyond reporting; distro default", to keep G5's order 4 then 5.
4. Step 0: replace "the Android profile model (§16 Q20) ... and the scan-report shape" with "whatever of these has been ruled by then (Q19, Q20, scan-report shape); unruled items ride a later bump".
5. Add to the Merge: "also amends D16 (inference) and D22".

**M-§15-02.** In D48, end the operator text at "...and Android deferral ([`linux-targets.md`](linux-targets.md))." Move "Linux work already done stays: pastebin's canary keeps running as the standing proof (operator, 2026-10-31), and Linux-only design work waits for G8 state 2" into a separate sentence marked "Proposed, needs ruling:". The standing-proof part is the operator's 2026-10-31 ruling; the deferral of Linux-only design work is not.

**M-§15-03.** In D49, replace "The byte-identical YAML twin stays as the frontend's test. `schema/` remains the authority over the data form (direction of generation: §16 Q23)." with: "Open, needs the operator's ruling: whether `schema/` or the Nix module options is the schema authority (map §4.1 currently says JSON Schema is generated from the module options; §16 Q23), and whether a byte-identical YAML twin stays as the frontend's test."

**M-§15-04.** Replace "(confirms D14, D33)" with "(confirms D33; amends D14's git-synced policy)". Change the Merge to: "needs the operator's ruling first: it amends D14 and §9.11's push rule, and the handshake definition is open (§16 Q17)".

**M-§15-05.**
1. In D51, replace "The scan is semantic-layer output (D29): it advises, never authorizes (§9.12)." with "Proposed, consistent with D29: the scan advises and never authorizes (§9.12)."
2. In D55, replace "§13 is ordered against them." with "(Ordering §13 against them is proposed in M-§13-01 and needs the ruling.)"
3. Change the title to "(none supersedes an entry; two clauses are proposals)".

**M-§16-03.** Add to the Merge: "renumber to the guide's §20 numbering once both lists are ruled; map:1252 says §16 keeps the guide's order and numbering, and the guide response's new questions 17-26 differ in content".

**M-§10-02.** Replace the proposed default with: "[Any device (G3's 'any other device'), or only devices my trust policy lists: §16 Q17, operator's ruling]; delivery grants no authority".

**M-§9-03.** Change the Merge to: "insert after the 'Output is one scan report' bullet of §9.12 once M-§9-02 is merged; needs the operator's ruling first on the cap values".

## Guide versus map: disagreements

### A. Build order (guide G-§18-02 versus map M-§13-01)

1. **First step on the Mac.** The guide starts with the fork on the Mac (1) and puts Nix authoring second (2). The map starts with the Nix frontend (1) and puts the Mac second (2). The repo slightly favours the guide: the Mac today runs Homebrew upstream CFEngine 3.29.0, which §19 says carries the data-path defects, so nothing can converge safely on it until the fork does. The two steps are otherwise independent.
2. **Step 0.** The map adds a Step 0: merge #41 and #42, do the D46 restructure, and make one schema bump carrying the owner key, roles, the Android profile model, the agent id and the scan-report shape. The guide has no schema step. The map is better supported on #41/#42: both PRs touch only platform-neutral files (`overlay/fork.json`, `policy/tendcf_services.cf`, `tests/policy/*`), so they close the interlock fail-open on the Mac too. That also makes guide Idea 10's "mostly Linux-specific" wrong for them. On the bump, the map bundles still-open questions (Q19, Q20), which the repo's ceremony cost argues against bumping before they are ruled.
3. **Validator and signing.** The guide builds a validator first with operator-tier CLI review (3), then signing and the handshake (4), and flags the order for a ruling. The map's Step 3, the "full gate", includes release-signature verification, but signed releases arrive only at Step 5. That is an internal inconsistency. The guide is better on this point.
4. **Safety scan and TUI.** The guide puts all scanning, AI and rules together, plus the TUI, at Step 7 inside state 1. The map puts mechanical scanning and the CLI at Step 4 and the AI scanner and TUI at Step 8 ("1→2"). G8.1's text does not list scanning, so both fit G8. G4 says AI is among the scanners, so the map's state 1 ships a partial G4. The map's "1→2" label is ambiguous.
5. **Owner signature.** The map has an owner key sign at Step 4, which supersedes D39 (M-§9-05). The guide's Step 3 takes accept or refuse with no key specified. The repo's approval record already requires a `signature`, so the map is more concrete; it needs the D39 ruling.
6. **Peer actions.** The guide schedules ShizukuPlus start-over-ADB as a state-1 step (6). The map has no peer-action step at all. The guide is better supported: guide §13 uses this case as its example, and the ShizukuTendCF headless broadcasts exist.
7. **Monitoring.** The guide puts the monitor role in state 1 (Step 6). The map puts it at Step 9, in state 2. The map matches G8.1's literal content, which names only the log archive.
8. **Extra-entry reporting before retirement.** The guide has a separate step (10) with launchd and Android detectors, then migration (11). The map has only the Linux unit-writer detector (Step 10) before "Retire `~/ops`". The guide is better: retiring the old stack needs `not-yet-migrated` counts on macOS and Android too.
9. **Linux.** The guide splits Linux server (12) from Linux client plus NixOS passthrough (13), matching G5's order 4 then 5. The map merges both into Step 10 and moves nix-darwin passthrough into Step 9. The guide matches G5.
10. **Inference.** The guide defers it explicitly to "Later" and flags a ruling (G-§10-01). The map drops it silently, which amends D16 unflagged. The guide is better.
11. **macOS CI.** The map names "a macOS CI job (ruling)" in Step 2. The guide's Step 1 says only "the CI build action", leaving the CI question to Idea 6. The map is more explicit, and the operator's CI policy does require his say.
12. **State 3.** The guide has extraction of the publishable layer and a root ceremony a novice can complete (14), then the consented tier (15). The map has public docs, the authoring guide, first non-operator enrolment, the TUF emergency role and advisor delegation (12). These are complementary rather than contradictory. The map's TUF emergency-role deferral (M-§9-04) is a ruling the guide does not propose.
13. **When state 1 is reached.** The guide requires that each device refuse both a release failing the handshake and a diff its owner refused. The map requires only an "unsigned or unhandshaken update in a test". The guide's test is closer to G4.

### B. "Operator: no local yes" against G4 (G-§7-02 versus M-§10-01, M-§2-10 and Q19)

1. **What replaces it.** The guide has the operator explicitly accept, from one place, each diff every device computed, with each device checking that the acceptance names its own diff. The map offers three options (a local yes on every tier, a hold window, an enrolled standing approval) and proposes a row that allows an owner-enrolled standing approval, "still shown and refusable before apply".
2. **Which fits the repo.** The guide's design fits the existing approval record, whose required fields include `proposed_sha256`, `nonce` and `approval_seq` with DC-2 single use. The map's standing approval or hold window would need a new approval shape. The guide is better supported by the repo; the map is closer to a literal reading of G4's "can see and refuse".
3. **Common ground.** Both route the question to the operator. Both identify the same three places in the guide (§4's parenthesis, §7, the §14 row).

### C. Other disagreements

1. **Handshake and carrier.** The guide (G-§5-01, G-§14-01) has a release accepted from *any* device, with the handshake checking the release, and leaves sender authentication bracketed for a ruling. The map (M-§2-08, M-§9-07, M-§10-02) has the peer admitted by mutual key authentication against a trust-policy list. The map narrows G3's "any other device" and states it as settled. The guide is better supported: map §9.11 itself says TUF "authenticates the release".
2. **New question numbering.** The guide's new §20 questions are 17-26 (G-§20-03..05). The map's new §16 questions are 17-27 with different content. Map:1252 requires the map to follow the guide's numbering.
3. **Plugins.** The guide's G-§4-01 cuts out-of-tree entry points (amends D46). The map's Step 0 does the D46 restructure as decided. This needs one ruling covering both.
4. **Android validator.** The guide's Step 5 assumes the agent's validator (D45), with the Termux-Python alternative named in its Merge. The map's M-§12-06 and Step 6 leave it open. The two are consistent in substance.

## Not checked

1. Live hosts: no SSH to pastebin or get.sipb.cloud.
2. CI: not re-run. PR check state was read with `gh` only.
3. Whether the fork builds on macOS outside the dev build, or under Termux. ShizukuPlus behaviour across work profiles.
4. The F-Droid Insular quote and the other external URLs in both reports: not fetched.
5. The Learning CFEngine `trustkeysfrom` citation in M-§9-07.
6. Guide items G-§2-01, §3-02, §6-02, §9-01, §16-04, §17-04..07, §19-01, §20-01: spot-check sample not taken. Map items M-§1-01, §2-06, §2-07, §2-14, §9-01: not spot-checked.
7. "s5 detector design (873 lines)" and "unblocks D46" (M-§12-07). The "70k vs 5k lines" and "240 of 398 commits" figures in the two reports' Ideas sections. The Nits tables of both reports, beyond the number cross-checked in M-§4-01.

Last search run: exempt: verification of given review documents against the repository (no search could change a repo-state verdict). GitHub was queried for the fork lineage, PR state and the fork's pinned commits.

