# Goal review, 2026-11-13

A review of the whole project against the goal agreed on 2026-11-13
(`00-goal-definition.md`). Every file here is new. No original document was
changed. Each response is written so it can be merged into its original later.

Base commit for every anchor: `eefea3c` (master).

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
