# Architecture

**Start here (current design):**
[`../paper/tendcf-architecture-guide.md`](../paper/tendcf-architecture-guide.md)

That guide is the vetted current-state description. Where any other
living document disagrees on the current design, **the guide wins**.

Implementer map (decisions, build order, protection):
[`architecture-DEFINITIVE-v3.md`](architecture-DEFINITIVE-v3.md).
It must agree with the guide.

Technical paper:
[`../paper/tendcf-architecture-paper.md`](../paper/tendcf-architecture-paper.md)

Contested vocabulary — words with two senses, or whose referent moved under
a decision: [`GLOSSARY.md`](GLOSSARY.md). It defines nothing; it points at
whichever document is authoritative for each term.

Two living design notes that the map and the guide point at:
[`change-process.md`](change-process.md) (lockfile, release, rollback, CI
gates — issue #2) and [`upstream-overlay.md`](upstream-overlay.md) (the
patch overlay on libntech / cfengine/core in [`../../overlay/`](../../overlay/)
— issue #3). [`upstream-register.md`](upstream-register.md) is the living
record of every CFEngine/libntech defect and contribution.

Site Model contract (JSON Schema, fixtures, lint):
[`../../schema/`](../../schema/), [`../../examples/`](../../examples/),
[`../../bin/schema_lint.py`](../../bin/schema_lint.py).

Older numbered versions and panel drafts live in
[`deprecated/`](deprecated/). Dated `*-2026-08-13.md` notes in this
directory are an evidence trail. Briefs (`*-BRIEF.md`) and
[`ideas-dump-claude.md`](ideas-dump-claude.md) are prompts or dumps that
produced archived drafts. None of those are current design; do not
rewrite them to “bring them up to date.” On conflict, the guide wins.
