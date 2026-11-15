# Goal review, 2026-11-13

A review of the whole project against the goal agreed on 2026-11-13
(`00-goal-definition.md`). Every file here is new. No original document was
changed. Each response is written so it can be merged into its original later.

Base commit for every anchor: `eefea3c` (master).

## Where to start

Read `14-synthesis-and-rulings.md` first. Section B lists the rulings the
operator had to make, and each is now ruled (2026-11-14); its opening index
maps every line of the rulings record (L4 to L60) to its item and to the files
that carry it. Section C lists defects that need no ruling; section F is the
merge map. The rulings record itself is `rulings-record-2026-11-14.md`, and
`14-synthesis-and-rulings.md` lists the three questions the record still does
not answer under "Open items awaiting operator ruling (2026-11-14)"; the four
PR 62 review questions (Q1 to Q4) are ruled (record lines L57 to L60).

## Rulings of 2026-11-14

The operator ruled B1 to B13, their riders and sub-rulings, the seven smaller
items, the PR 52 follow-ups, the B11 round-2 items and the four PR 62 review
questions on 2026-11-14. Each
response item that the rulings decide carries a **Ruled** paragraph quoting
the chosen option exactly and citing it as `operator ruling, 2026-11-14,
<item>`; proposals that a ruling settled are rewritten and no longer read as
open. Three edits reached the goal text itself: the G4 figure sentence, the G8
lead sentence and G8 item 3 (`00-goal-definition.md`, "Later rulings"). A
ruled item that is not yet built says "ruled; implementation pending" (or the
exact status). A ruled item that is built says so with its dated outcome (for
example C-policy-01, implemented by PR 52, merged 2026-11-14 as `2c78680`).
An item the record leaves undecided says "open: awaiting operator ruling (the
question)" and is never decided by this directory.

## Files

| File | What it is | Merges into |
|---|---|---|
| `00-goal-definition.md` | The agreed goal, G1 to G9, and the rulings behind it | (reference) |
| `01-response-paper.md` | Response to the research paper | `docs/paper/tendcf-architecture-paper.md` |
| `02-response-guide.md` | Response to the guide | `docs/paper/tendcf-architecture-guide.md` |
| `03-response-map.md` | Response to the implementer map | `docs/architecture/architecture-DEFINITIVE-v3.md` |
| `04-response-plans.md` | Response to the plan documents | linux-targets, nixos-passthrough-plan, plugin-layout, the validate proposal, change-process, README |
| `05-response-code.md` | Response to the code, tests, CI and deploy scripts | code and its `AGENTS.md` files |
| `06-sources-check.md` | Check of how the paper and guide use their sources | the paper and the guide |
| `07-android-landscape.md` | Research: Android (G5) | new design material; map §12 |
| `08-nix-ecosystem.md` | Research: Nix authoring and carry-over (G2) | new design material; linux-targets §5 |
| `09-safety-score-and-tui.md` | Research: safety score and TUI (G4) | new design material; map §9 to §11 |
| `10-peer-updates-and-trust.md` | Research: peer updates and trust (G3) | new design material; map §9 to §10 |
| `11-engine-alternatives.md` | Research: the engine and the fork (G7) | overlay and fork documents |
| `12-fork-management.md` | Research: branch and fork management (G9) | new design material |
| `13-premortem-and-ideas.md` | Pre-mortem, tensions, process, ideas | (reference) |
| `14-synthesis-and-rulings.md` | Synthesis, rulings needed, defects, path to the first finish-line state | (reference) |
| `rulings-record-2026-11-14.md` | The operator's rulings record, lines L4 to L60, verbatim except that absolute local paths are replaced by a neutral phrase | (reference; the L-numbers in 14 point here) |
| `checks/v1` to `v7` | The independent checkers' verdict tables and corrections; v7 is the source re-fetch | (evidence; cited as "vN Cn"; v7's corrections are "v7 R1" to "R21") |

## How it was produced

1. Thirteen reviewing agents (Claude Opus) each wrote one report, 01 to 13.
2. Six independent checking agents (Claude Opus) tried to refute them. Their
   verdicts are in `checks/`.
3. Six agents applied the verdicts. A confirmed item says so in its
   **Checked:** line. A weakened item carries the corrected text. A refuted
   item is listed under "Withdrawn after checking" in its file.
4. One agent wrote the synthesis from the reports and the checks.
5. One agent (Claude Sonnet) re-fetched sources the first pass could not read,
   once the web and library tools were repaired; its corrections R1 to R21 are
   applied and its table is `checks/v7-refetch.md`.

Every reviewer and checker is the same model family. This is not the
cross-model frontier review the repository's standing rule requires before a
merge, and no adversary review had run when these files were written (the
rulings PR, PR 62, has since had its own cross-model and adversary reviews). Nothing here was built or executed, no
device or live host was touched, and nothing ran under Nix. Each file's "Not
checked" list says what its author did not verify.

## Response item format

Every finding is one item with a stable ID. The ID prefix names the target:
`P` paper, `G` guide, `M` map (`architecture-DEFINITIVE-v3.md`), `L`
linux-targets, `N` nixos-passthrough-plan, `PL` plugin-layout, `V`
tendcf-validate proposal, `C` code, `X` cross-cutting. Example: `P-§5.1-02`.

```markdown
### P-§5.1-02: short title

**Target:** `docs/paper/tendcf-architecture-paper.md` §5.1 "Section heading",
at the sentence beginning "first six words of it"
**Kind:** correct | add | cut | reword | move | question | ruling-drift
**Goal:** G3 (the paragraph of the goal this serves or conflicts with)
**Weight:** blocks-goal | misleads | improves | nit
**Finding:** what is wrong or missing, in two to five sentences.
**Evidence:** `file:line`, a URL, or the command run and what it printed.
**Proposed text:**

> Replacement or insertion text, ready to paste.

**Merge:** replace that sentence | insert after it | delete the paragraph |
needs the operator's ruling first (say which)
**Checked:** verified (how) | inferred | not checked
```

Rules for items:

1. Anchor by section number, heading text and a quoted phrase. Line numbers
   drift; a quoted phrase survives.
2. One change per item. A finding that touches three sections is three items
   that name each other.
3. `Proposed text` is in the original's own voice and style, so a merge is a
   paste.
4. An item that needs a decision says so in `Merge` and proposes nothing as
   settled.
5. A claim about the outside world carries a URL. A claim about this repo
   carries `file:line` at `eefea3c`.
