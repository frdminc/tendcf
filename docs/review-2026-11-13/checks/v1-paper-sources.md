# v1. Verification of 01 (paper response) and 06 (sources check)

Checker: independent refutation pass. Repo read-only at `the review worktree` (anchors at `eefea3c`). 06 was re-read at the end: its STATUS line still says `partial`, it has items s01-s27 and claims T1-T59, and its last line is `DONE`.

## Summary

1. Report 01. All 35 items weighted `blocks-goal` or `misleads` were checked. 23 are confirmed and 12 are weakened. None is refuted. Every anchor phrase was found in the paper.
2. Report 01, `improves` items. 10 of the 22 were spot-checked: 6 confirmed, 1 weakened (a nit) and 3 resting on inference.
3. Report 06. All 12 items weighted `misleads` and all 20 claims with a `wrong` or `overstated` verdict were checked, and 11 of its 15 `improves`/`nit` items were spot-checked. Five are weakened: T10 (with s08/s09 text), T16/s12, T22/s14 (section label), T25/s16 and T39/s19 (proposed text). The rest are confirmed. None is refuted.
4. Anchors in 06. Every anchor phrase was found, with three exceptions:
   1. P-§3-s14 is labelled §3, but its text is in §2.7, at paper line 900.
   2. The "§3" targets of P-§3-s19 and P-§3-s20 are in §3.2, items 9 and 1.
   3. P-§5.3-s10's anchor differs from the paper only in quote style.
5. Proposed texts. Eight of them would merge new errors. They are listed under Corrections.

## A. Verdict table

| Item | Verdict | Evidence (one line) | Correction to apply |
|---|---|---|---|
| P-Abs-01 | confirmed | paper:49-50 "now open as pull requests"; paper:1554 "count upstream is zero" | none |
| P-Abs-02 | confirmed | withdrawn plan language in the abstract against D46 (`architecture-DEFINITIVE-v3.md:1244`) | none |
| P-Abs-03 | weakened | finding holds; proposed text garbles the Android sentence and narrows the compiler to "launchd hosts" (`compile.py:95` limits only service units) | C1 |
| P-§1-01 | confirmed | paper §1 "more than one trusted operator"; goal G1 | none |
| P-§1.1-01 | weakened | "required" is an inference; a TUF root is already enrolled out of band (paper:475-477); G3/G4 imply only that anchors and consent policy sit beyond the release path | C2 |
| P-§1.1-02 | weakened | the bullet ties threshold signing to §1's multi-operator site, not to adoption; it needs a change only if P-§1-01 lands | C3 |
| P-§2.1-01 | confirmed | paper "may" against G2; `cli.py:179-205` eval-nix wraps `nix-instantiate --eval --strict --json` | C4 (text) |
| P-§2.1-02 | weakened | ruling of 2026-10-29 (`linux-targets.md:63-99`) already settles passthrough on NixOS/nix-darwin hosts | C5 |
| P-§2.2-01 | confirmed | `compiler/pyproject.toml:18` gives `nix2cf`; there is no `tendcf compile` command; D46 | none |
| P-§2.2-02 | confirmed | paper:314 "launchd-only" against paper:1727-1728 (systemd branch since 2026-10-31) | none |
| P-§2.2-03 | weakened | stale sentence confirmed; but `linux-targets.md:99` says "The nix-darwin passthrough adapter is required either way" | C6 |
| P-§2.3-01 | confirmed | `rg -c cf-serverd deploy/ docs/architecture/linux-targets.md`: no hits; `linux-targets.md:39` installer-copied policy | none |
| P-§2.3-02 | weakened | the purpose claim is unsupported (markburgess.org FAQ: PT "emerged from the software CFEngine"); "conflicts with G7" is overstated; 06 weights it `improves` | C7 |
| P-§2.3-03 | confirmed | paper:400 "no equivalent to phone home to" against G8.1 log archive | none |
| P-§2.4-01 | weakened | there is no D45/R4 conflict (`architecture-DEFINITIVE-v3.md:105-115`: R4 keeps CFEngine on Android; D45 makes only tendcf-agent Android-only); the cross-profile ShizukuPlus claim is unverified | C8 |
| P-§2.5-01 | confirmed | no score or review surface in the paper; goal G4 | C9 (text) |
| P-§2.5-02 | confirmed | author/advisor separation in paper §2.5 against G1 "own AI" | none |
| P-§2.5-03 | confirmed | paper's TUF single-root model; G3 "any other device"; goal difference 5 | none |
| P-§2.6-01 | confirmed | illustration uses flat attrsets, not `mkOption`/module style | none |
| P-§2.6-02 | confirmed | paper:875 "launchd-only" against paper:1727-1728 | none |
| P-§2.6-03 | confirmed | canary enforced, `linux-targets.md:39` | none |
| P-§2.8-01 | confirmed | the `managed` tier waives consent for a non-owner; G4 | none |
| P-§3.2-01 | confirmed | item 3 critiques a warning the map no longer carries | none |
| P-§3.2-02 | weakened | item 5 has no citation, but item 3 also has none, so "every other item … carries a numbered reference" is false | C10 |
| P-§5.3-01 | weakened | finding holds; proposed text repeats the misattribution 06 T14 found (B08:2201 booklet §8.1, not LISA '05) and credits G8.1 with G3's monitoring | C11 |
| P-§6.4-01 | weakened | `linux-targets.md:39`: dry run 2026-10-29, enforcement 2026-10-31, so not "one-day"; overlaps 06 P-§6.4-s13 | C12 |
| P-§7.3-01 | weakened | finding holds (paper:1638-1646 stale). "Maintainers invited the next to be split" IS supported (`docs/handoffs/HANDOFF_standalone-3fd9_simulate-json-three-prs_2026-10-08_fab1.md:18-20`, larsewi on core#6332, 2026-09-23); "We send upstream only what the design cannot do without" is unsupported | C13 |
| P-§8-01 | confirmed | paper has no finish-line status; G8 | none |
| P-§8-02 | confirmed | canary enforced; module installed but unscheduled on a second host (`linux-targets.md:14`) | none |
| P-§9-01 | confirmed | 9.2 and 9.9 frame AI authorship as a hypothesis; G6 | none |
| P-§9-05 | weakened | same inference as P-§1.1-01; Merge should be "needs the operator's ruling first" | C2 |
| P-§9-06 | confirmed | handshake undefined; G3 | none |
| P-§9-07 | confirmed | score undefined; G4 | C9 (text) |
| P-§10-01 | confirmed | stale claims checked; one new error in the proposed text ("twenty-three defects in it") | C14 |
| P-§S-01 | confirmed | outline matches G1-G9; its §-numbers are new, and other items cite them | none |
| P-§0-01 (improves) | confirmed | `git log` shows 7 paper commits on 2026-11-13 | none |
| P-§1.1-03 (improves) | confirmed | `overlay/`: 6 patches; `check.yml` weekly drift cron | none |
| P-§2.1-03 (improves) | confirmed | D19 lockfile and `site.lock` exist | none |
| P-§2.4-02 (improves) | confirmed | paper "optional" against the G8.1 archive | none |
| P-§3.2-03 (improves) | confirmed, resolved | 06 T34 and my read of [13] Table 6: 65.0 / 26.5 / 1.5% | the check is done; close the item |
| P-§7-01 (improves) | weakened (nit) | §7 is 185 lines, not 180 | say "185 lines" |
| P-§S-03 (improves) | confirmed | §3.2 is 182 lines | none |
| P-§2.7-01 (improves) | inferred | rests on the ShizukuPlus README; not tested on a device | none |
| P-§9-04, P-§9-09 (improves) | inferred | reasoning from G5; no source to check | none |
| 06 P-§6.2-s01 / T5 | confirmed | BI "buildfile — Perform the entry binding process on a single entry"; B08:1648 | nit: the booklet pairs `build`, not `buildall`, with `compare` |
| 06 G-§4-s02 | confirmed | same evidence as T5 | none |
| 06 T6 | confirmed | B08:1645 `buildall` "frequently used to test server code upgrades"; diffing is `bcfg2-admin compare` | none |
| 06 P-§9.3-s03 / T8 | confirmed | B08:1049-1054 tutorial output "Over time, we will reduce this number"; no dedicated role in B05/B08 | none |
| 06 G-§18-s04 | confirmed | same as T8 | none |
| 06 T7 (improves s05) | confirmed | same lines; it is a tutorial client | none |
| 06 T2 (improves s06) | confirmed | B03 "must be comprehensive"; B08:529 "By convention" | none |
| 06 P-§5.1-s08 / T9 | confirmed | Packages doc: "prerequisite resolution … automatically added", versionadded 1.0.0 | none |
| 06 T10 | weakened | "overstated" stands; the proposed text "dormant since about 2016" misstates the repo evidence | C15 |
| 06 G-§10-s09 | confirmed (with C15) | same as s08 | C15 |
| 06 P-§5.3-s10 / T14 | confirmed | B08:2201 "Set up the reporting system early"; B05:160 "culminated with … reporting" | none |
| 06 P-§6.4-s11 | confirmed | same as T14; collides with 01 P-§9-02 on §9.5 | merge with P-§9-02 (see D) |
| 06 P-§6.3-s12 / T16 | weakened | "wrong" is too strong: B06:246 maintenance-window cluster and B05 "between jobs" make "always-on" loose, not false | C16 |
| 06 P-§6.4-s13 / T19 | confirmed | B05:139-144 cluster nodes applied "between jobs" | coordinate with P-§6.4-01 (C12) |
| 06 P-§3-s14 / T22 | weakened (label) | B06:201, 211 mitigations confirmed; target text is §2.7 (paper:900), not §3 | relabel to P-§2.7-s14 |
| 06 G-§12-s15 / T24 | confirmed | LISA '06 text has no "Actions"; B08:2296 §A.2.1 does | none |
| 06 P-refs-s16 / T25 | weakened | 4-vs-6 inconsistency real; guide:131-133 can be read as six ideas (Actions and bundle scope count as two), so "five listed" is a miscount | C17 |
| 06 P-§3.1-s18 / T33 | confirmed | [13] Table 6: CRF 7.0% of technical errors; 47.6% of intent errors | none |
| 06 P-§3-s19 / T39 | weakened (text) | [17]: −0.5 / −2 points, p 0.87 / 0.37; target is §3.2 item 9; LLM-vs-developer p = 0.038 on CTXbench only | C18 |
| 06 P-§3-s20 / T35 (improves) | confirmed | [15]: "simply providing the documentation … does not help"; "Once w/ whole doc yields the best results"; target is §3.2 item 1 | relabel target §3.2 |
| 06 P-§2.3-s21 / T27 (improves) | confirmed | markburgess.org promises page has no "specifically to rule out" purpose | none |
| 06 X-s22 (improves) | confirmed | quote at B05:45-47 | none |
| 06 P-§3.1-s23 / T45 (improves) | confirmed | Tratt: "often generates high-quality local … but often struggles", "at least as it stands right now" | none |
| 06 P-refs-s24 / T47 (nit) | confirmed | post stamp "2026-06-30 10:50" | none |
| 06 P-§3.2-s25 / T48 (improves) | confirmed (abstract only) | arXiv 2502.05111 v2: "17.71x faster offline preprocessing"; no production claim; "tens of minutes" | none |
| 06 P-§2.3-s26 / T54 (improves) | confirmed (docs only) | balena docs: offline update "involves preloading an image and reflashing it"; "all data on the device is wiped"; cited blog unreachable (3 attempts incl. archive.org) | none |
| 06 G-§13-s27 (nit) | confirmed | BS altsrc page exists; guide:828 links the site root | none |
| 06 T30, T34, T36, T38 (accurate rows behind items) | confirmed | TUF spec "MUST ship with trusted root keys"; [13] Table 6; [15] "examples consistently outperform descriptions"; [17] cost +20% / +23% | none |

## B. Corrections

C1. P-Abs-03, proposed text. Replace two sentences.
1. Replace "We know of no comparable tool for Android: work profiles such as Island and Insular, and the user-space privilege of ShizukuPlus." with:
   > We know of no comparable tool for Android that works across Island and Insular work profiles and with ShizukuPlus's user-space privilege.
2. Replace "A compiler renders per-host goal files for launchd hosts, and" with:
   > A compiler renders per-host goal files, with service units for launchd only, and
3. "Bcfg2 supplies four load-bearing ideas (§6)" must take whatever count is settled under 06 P-refs-s16 (C17).

C2. P-§1.1-01 and P-§9-05. Change both Merge lines to: "needs the operator's ruling first (whether a device-local trust root is a requirement of G3/G4 or one design among several)". Replace P-§1.1-01's proposed sentence with:
> Until that exists the gate is an audit trail, not a boundary. Because every device must accept updates from any peer that completes the handshake (§2.3), what that handshake trusts, and the consent policy, must sit beyond the release path's reach; whether that takes a separate device-local root is open (§9.15).

C3. P-§1.1-02. Weight: `improves`. Merge: "only if P-§1-01 removes 'more than one trusted operator'; otherwise no change". Checked: inferred.

C4. P-§2.1-01, proposed text. Replace "an existing NixOS or nix-darwin configuration should mean the same thing here, and" with:
> a host already running NixOS or nix-darwin keeps its configuration unchanged through passthrough (linux-targets §5), and elsewhere

C5. P-§2.1-02, proposed text. Replace the first sentence with:
> Part of "carries over" is settled: on NixOS and nix-darwin hosts the existing configuration is used unchanged through passthrough (ruling of 2026-10-29, linux-targets §5). What is open is what carries over to a host without Nix: a Mac without nix-darwin, or an Android phone.

Narrow the Merge to: "needs the operator's ruling first (what G2's carry-over means on non-Nix hosts)".

C6. P-§2.2-03, proposed text. Replace "Which one tendcf does on the first Mac is open (§9.19)." with:
> On a Mac that runs nix-darwin, passthrough is the path (linux-targets §5: the adapter "is required either way"); whether the first Mac runs nix-darwin is open (§9.19).

Change Merge to "replace that sentence".

C7. P-§2.3-02. Weight: `improves`, to agree with 06 P-§2.3-s21. Cut "conflicts with G7" from the Finding. Replace the last clause of the proposed text, "and it is the main reason CFEngine is the current engine.", with:
> and it is one reason CFEngine is the current engine (§2.2).

C8. P-§2.4-01, proposed text. Replace the last sentence ("Whether a CFEngine agent runs on Android at all, or tendcf-agent applies the goal file itself, is open.") with:
> How CFEngine's agent runs on Android, as a native helper or behind a Termux reporter, is open (§2.4; the compiler does not yet offer an `android` platform).

Replace the Merge's "D45 against s5:666-668" with "how cf-agent runs on Android (map R4; `compiler/nix2cf/cli.py` --platform)". Mark "reaches the other profiles through ShizukuPlus's privileged process" as not checked: the ShizukuPlus README (https://github.com/thejaustin/ShizukuPlus) describes "a privileged process started with adb or root" and says nothing about work profiles.

C9. P-§2.5-01 and P-§9-07. Change Merge to "needs the operator's ruling first (how the score is computed)". The proposed texts state as settled a mechanical ceiling on the score, provenance counting and never showing 100%; none of these is in G4 (README rule 4).

C10. P-§3.2-02, Finding. Replace "Every other item in §3.2 carries a numbered reference" with:
> Every other item that reports an outside finding carries a numbered reference

C11. P-§5.3-01, proposed text. Replace the first two sentences with:
> We now have a consumer: the first milestone archives every device's logs on the Mac (G8.1), and the server role includes monitoring other devices (G3). That moves us toward the booklet's advice to set up reporting early [4, §8.1].

C12. P-§6.4-01, proposed text. Replace "went from a one-day dry run to enforcement" with:
> went from a dry run on 2026-10-29 to enforcement on 2026-10-31 of

Merge this with 06 P-§6.4-s13 into one edit of that sentence.

C13. P-§7.3-01, proposed text. Replace the second bullet's last two sentences with:
> After the August closures, one small pull request (core#6332, CFE-4742) was merged on 2026-09-02, and on 2026-09-23 a maintainer invited `--simulate-json` back if split into logical parts.

Evidence to add: `docs/handoffs/HANDOFF_standalone-3fd9_simulate-json-three-prs_2026-10-08_fab1.md:18-20`. Drop "We send upstream only what the design cannot do without", or cite its source.

C14. P-§10-01, proposed text. Replace "found twenty-three defects in it (Appendix B)" with:
> found twenty-three defects in the engine, ten of them in that path (Appendix B)

This matches paper:49-50 and paper:1924-1925. Also apply C4's limit to "bring what they already have": write "bring the language and module style they already use".

C15. 06 P-§5.1-s08 and G-§10-s09, proposed text. Replace "dormant since about 2016" with:
> effectively dormant (documentation last built in 2016, last repository push in November 2023)

Source: `docs/architecture/orchestration-research-2026-08-13.md:167`.

C16. 06 T16 and P-§6.3-s12. Verdict: overstated, not wrong. In the Finding, replace "Calling this 'always-on' is wrong" with:
> "Always-on" is loose: the division mixed workstations, servers and a cluster changed only in maintenance windows

C17. 06 T25 and P-refs-s16. In T25, replace "G 'Six ideas' (five listed)" with:
> G "Six ideas" (six if Actions and bundle scope count separately)

The finding stands as the inconsistency between four and six, plus the uncited fifth paper. 01 P-Abs-03 must use the same count.

C18. 06 P-§3-s19, target and text. The target is §3.2 item 9 (paper:1185). In the proposed text, qualify "significantly worse than developer-written ones" with:
> on one of the two benchmarks (p = 0.038)

## C. Where 01 and 06 disagree about the same passage

1. §2.3, Promise Theory. 01 P-§2.3-02 weights it `misleads`; 06 P-§2.3-s21 weights it `improves`. Use `improves` (C7) and one merged text.
2. §5.3, reporting early. 01 P-§5.3-01 keeps the LISA '05 attribution that 06 T14 / P-§5.3-s10 shows belongs to the booklet. Fixed by C11.
3. §9.5. 01 P-§9-02 replaces the whole question; 06 P-§6.4-s11 edits one phrase in it. Merge them into one edit carrying the booklet attribution.
4. §6.4, the posture sentence. 01 P-§6.4-01 and 06 P-§6.4-s13 edit the same sentence. Merge them (C12).
5. Bcfg2 idea count. 01 P-Abs-03 says "four"; 06 P-refs-s16 disputes the count. Settle the count once and use it in both (C17).
6. §3.2 item 4. 01 P-§3.2-03 asks for a check; 06 T34 supplies it. Close P-§3.2-03.

## Not checked

1. The 06 items P-refs-s17 (never-cited refs), G-§11-s07, G-§11-s05 text and X-s22's proposed text beyond the quote; T40, T44, T59 (06 itself marks them unverifiable).
2. The content of the balena blog post [24]: it failed three ways (direct, www redirect, archive.org). The comparison needs a browser fetch.
3. Burgess's 2005 autonomy papers, which 01 P-§2.3-02 suggests citing; the Promise Theory book [6] itself.
4. ShizukuPlus cross-profile behaviour, and Island/Insular behaviour on a real device (01 P-§2.4-01, P-§2.7-01, P-§9-09).
5. The 2008 booklet's section numbers as printed (I used line anchors in the extracted text); [14] beyond its abstract; [10]'s footnotes.
6. 01's claims that rest only on the phase-1 inventory or digests (inventory §D, §G, §H), other than those listed in the table; the schema dates in P-§10-01.
7. 12 of 01's 22 `improves` items: P-§1-02, P-§1.1-04, P-§2.2-04, P-§2.8-02, P-§3-01, P-§4.2-01, P-§8-03, P-§9-02, P-§9-03, P-§9-08, P-§9-10 and P-§S-02.

Sources consulted: paper and guide at eefea3c; `architecture-DEFINITIVE-v3.md`, `linux-targets.md`, `upstream-register.md`, `orchestration-research-2026-08-13.md`, the 2026-10-08 simulate-json handoff; `compiler/` (`pyproject.toml`, `cli.py`, `compile.py`), `policy/tendcf_services.cf`, `overlay/`, `.github/workflows/`, `schema/goal-file.schema.json`; local Bcfg2 texts B03, B05, B06, B08; fetched: docs.bcfg2.org bcfg2-info and Packages (http), markburgess.org promises/FAQ, TUF spec, arXiv 2512.14792 (full), 2509.19931 (full), 2602.11988 (full), 2502.05111 (abstract), the Tratt post, docs.balena.io offline-updates, the ShizukuPlus GitHub README.
Last search run: no general web search was used; all citations come from direct firecrawl scrapes. The balena blog post (direct, www and archive.org) failed, and is listed under Not checked.
